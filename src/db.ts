import postgres, { type Sql } from 'postgres';
import { readdir, readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface DbClient { query<T = unknown>(sql: string, params?: unknown[]): Promise<{ rows: T[] }> }
export interface TxClient extends DbClient { release(): void }
export interface DbPool { connect(): Promise<TxClient>; end?: () => Promise<void> }

/**
 * Pin every reserved connection to the application's known schema set.  This
 * must not depend on the role's ALTER ROLE search_path (and is deliberately a
 * plain SET, not SECURITY DEFINER/dynamic SQL).
 */
export async function initializeReservedConnection(connection: { unsafe: (query: string) => Promise<unknown> }): Promise<void> {
  await connection.unsafe('SET search_path TO pg_catalog, public');
}

export function createPostgresPool(url = process.env.DATABASE_URL): DbPool {
  if (!url) throw new Error('DATABASE_URL_REQUIRED');
  const sql = postgres(url, { max: Number(process.env.DB_POOL_MAX || 10), idle_timeout: 20, connect_timeout: 10, prepare: false });
  return { connect: async () => {
    const reserved = await sql.reserve();
    await initializeReservedConnection(reserved);
    return { query: async <T>(text: string, params: unknown[] = []) => ({ rows: await reserved.unsafe(text, params as any) as T[] }), release: () => reserved.release() };
  }, end: () => sql.end({ timeout: 5 }) };
}
/**
 * Fixed advisory-lock key serializing schema migrations. Advisory locks are
 * scoped to one database, so every process/instance connected to the same
 * database (e.g. parallel cold starts) contends on the same key. The value is
 * arbitrary but must never be reused for an application-level lock.
 */
export const MIGRATION_LOCK_KEY = 742_001;

export async function runMigrations(pool: DbPool, dir = join(dirname(fileURLToPath(import.meta.url)), '../migrations')): Promise<void> {
  const files = (await readdir(dir)).filter(f => /^\d+_.+\.sql$/.test(f)).sort();
  await pool.connect().then(async db => { try {
    // Schema-qualified: reserved connections are pinned to `pg_catalog, public`
    // (initializeReservedConnection), so an unqualified CREATE would target
    // pg_catalog first and the least-privilege runtime role has no CREATE rights
    // there (`permission denied for schema pg_catalog`). The version table must
    // always live in public.
    await db.query('create table if not exists public.schema_migrations (version text primary key, applied_at timestamptz not null default now())');
    for (const file of files) {
      const sql = await readFile(join(dir, file), 'utf8');
      // F3: parallel cold starts used to race on check-then-apply — both saw
      // "not applied" and both ran the non-idempotent DDL of 001/005, so one
      // instance failed and its cold start died. Each migration now runs in a
      // single transaction that takes a transaction-scoped advisory lock BEFORE
      // the version check: the lock serializes the check+apply+record across
      // all processes sharing the database, and because the version row commits
      // atomically with the DDL, the loser of the lock simply re-checks under
      // the lock and skips the winner's version. pg_advisory_xact_lock (not the
      // session-level pg_advisory_lock) is pooler-safe: transaction-mode
      // poolers (e.g. Neon) reject session locks, and xact locks auto-release
      // on COMMIT/ROLLBACK, so a lock can never leak onto a pooled connection.
      await db.query('begin');
      try {
        // Migration bodies in this repo use unqualified DDL (e.g. `create table
        // cards`). On the runner's pinned pg_catalog-first search_path that DDL
        // would also hit pg_catalog and fail the same way as the version-table
        // CREATE did. Pin a public-first path scoped to THIS transaction (SET
        // LOCAL, exactly like the validate-retention/validate-wallet-revoke
        // harnesses), so bodies resolve like psql defaults (`"$user", public`)
        // and the setting auto-resets on COMMIT/ROLLBACK — no state leaks onto
        // the pooled connection. pg_catalog is still searched implicitly for
        // function/type resolution (pg_advisory_xact_lock).
        await db.query('set local search_path to public, pg_catalog');
        await db.query('select pg_advisory_xact_lock($1)', [MIGRATION_LOCK_KEY]);
        const done = await db.query<{version:string}>('select version from public.schema_migrations where version=$1', [file]);
        if (!done.rows.length) {
          await db.query(sql);
          // Idempotent registration: the PK can never abort the migration
          // transaction, even if a competing runner recorded the same version
          // between the check and the insert.
          await db.query('insert into public.schema_migrations(version) values($1) on conflict (version) do nothing', [file]);
        }
        await db.query('commit');
      } catch (e) { try { await db.query('rollback'); } catch { /* preserve the migration error */ } throw e; }
    }
  } finally { db.release(); } });
}
