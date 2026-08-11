import { test, expect, setDefaultTimeout } from 'bun:test';
import postgres from 'postgres';
import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { CardRepository, type DbPool, type TxClient } from '../src/repository';

// Deliberately no DATABASE_URL fallback: integration tests require an explicit disposable DB.
const url = process.env.TEST_DATABASE_URL;
const integration = url ? test : test.skip;
setDefaultTimeout(30_000);

// Bun's test timeout must never be the first timeout we hit. PostgreSQL's
// statement/lock settings protect the server, while this deadline also covers
// a client waiting for a pooled connection (which those settings cannot cover).
const DB_OPERATION_TIMEOUT_MS = 7_000;
const withDeadline = async <T>(operation: Promise<T>, label: string): Promise<T> => {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`TEST_DATABASE_BUSY:${label} timed out`)), DB_OPERATION_TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
};

type Queryable = { unsafe(query: string, values?: any[]): Promise<any[]> };

integration('database scenarios run in an isolated temporary schema', async () => {
  if (!url) return;
  if (url === process.env.DATABASE_URL) throw new Error('TEST_DATABASE_URL_MUST_NOT_EQUAL_DATABASE_URL');

  const schema = `test_${crypto.randomUUID().replaceAll('-', '')}`;
  // Keep every test connection bounded. A stale session or catalog lock in the
  // shared disposable database must fail the test, never leave Bun waiting.
  const sql = postgres(url, { max: 4, prepare: false, connect_timeout: 10, idle_timeout: 2, max_lifetime: 30 });
  const migrationDir = join(import.meta.dir, '../migrations');
  const configureConnection = async (db: Queryable) => {
    await db.unsafe("set statement_timeout = '10s'; set lock_timeout = '2s'");
  };
  const setPath = async (db: Queryable) => {
    await withDeadline(configureConnection(db), 'configure connection');
    await withDeadline(db.unsafe(`set search_path to "${schema}", public`), 'set search_path');
    const rows = await withDeadline(
      db.unsafe('select current_schema() as current_schema, current_setting($1) as search_path', ['search_path']),
      'verify search_path',
    ) as { current_schema: string; search_path: string }[];
    const searchPath = rows[0]?.search_path ?? '';
    const firstSearchPathEntry = searchPath.split(',')[0]?.trim();
    if (rows[0]?.current_schema !== schema || firstSearchPathEntry !== schema) {
      throw new Error(`SEARCH_PATH_NOT_CONFIGURED:${rows[0]?.current_schema}:${searchPath}`);
    }
  };
  const withSchema = async <T>(work: (db: Queryable) => Promise<T>): Promise<T> => {
    const db = await withDeadline(sql.reserve(), 'connection');
    try { await setPath(db); return await work(db); }
    finally { db.release(); }
  };
  const setup = await withDeadline(sql.reserve(), 'setup connection');
  let setupReleased = false;
  const assertParams = (label: string, params: unknown[]) => {
    const index = params.findIndex(value => value === undefined);
    if (index >= 0) throw new Error(`UNDEFINED_DB_PARAM:${label}:${index}`);
  };
  const q = async <T = any>(text: string, params: unknown[] = []): Promise<T[]> => {
    assertParams(text.slice(0, 80), params);
    return await withDeadline(setup.unsafe(text, params as any), text.slice(0, 48)) as T[];
  };
  const setTenant = (tenantId: string) => q('select set_config($1,$2,true)', ['app.tenant_id', tenantId]);

  try {
    // Migrations intentionally run on one dedicated setup connection, not the pool used by tests.
    await configureConnection(setup);
    // Each run owns a random schema, so no database-wide advisory lock is needed.
    // Keeping setup and cleanup scoped to this schema allows parallel/isolated runs
    // and ensures stale locks from an abandoned process cannot block this harness.
    await withDeadline(setup.unsafe(`create schema "${schema}"`), 'create schema');
    await setPath(setup);
    await q('create table if not exists schema_migrations (version text primary key, applied_at timestamptz not null default now())');
    // The harness is deliberately driven only by TEST_DATABASE_URL and this schema.
    // Keep discovery deterministic and guard registration against duplicate directory
    // entries/retries: each version is applied and recorded once in one transaction.
    const migrationFiles = [...new Set((await readdir(migrationDir)).filter(f => /^\d+_.+\.sql$/.test(f)).sort())];
    for (const file of migrationFiles) {
      const alreadyApplied = await q<{ version: string }>('select version from schema_migrations where version=$1', [file]);
      if (alreadyApplied.length) continue;
      console.error(`DB_PHASE:migration_start:${file}`);
      await q('begin');
      try {
        // SECURITY DEFINER migrations (008) deliberately fully-qualify
        // `public.` for a fixed search_path. The harness runs migrations in a
        // per-run schema, so that qualifier is mapped onto the per-run schema
        // here — keeping the resolver inside this isolated schema (production
        // runs migrations in `public`, where the qualifier resolves as-is).
        const migrationSql = (await Bun.file(join(migrationDir, file)).text()).replaceAll('public.', `"${schema}".`);
        await q(migrationSql);
        console.error(`DB_PHASE:migration_sql_done:${file}`);
        await q('insert into schema_migrations(version) values($1) on conflict (version) do nothing', [file]);
        await q('commit');
      } catch (error) {
        try { await q('rollback'); } catch { /* preserve the migration error */ }
        throw error;
      }
      console.error(`DB_PHASE:migration_recorded:${file}`);
    }
    console.error('DB_PHASE:verify_tables:start');
    const migrated = await q<{ tenants: string | null; users: string | null; cards: string | null; sessions: string | null }>(
      `select to_regclass($1 || '.tenants') as tenants, to_regclass($1 || '.users') as users, to_regclass($1 || '.cards') as cards, to_regclass($1 || '.sessions') as sessions`, [schema],
    );
    if (!migrated[0] || Object.values(migrated[0]).some(value => value === null)) throw new Error('MIGRATIONS_WRONG_SCHEMA');

    // The production plans are 500/1000. This local check is intentionally removed for a one-slot limit test.
    await q('alter table tenants drop constraint if exists tenants_customer_limit_check');
    const tenantA = (await q<{ id: string }>("insert into tenants(slug,legal_name,plan_code,customer_limit) values('tenant-a','Tenant A','up_to_500',1) returning id"))[0].id;
    const tenantB = (await q<{ id: string }>("insert into tenants(slug,legal_name,plan_code,customer_limit) values('tenant-b','Tenant B','up_to_500',1) returning id"))[0].id;
    const user = (await q<{ id: string }>("insert into users(email) values('db-test@example.invalid') returning id"))[0].id;
    await setTenant(tenantA);
    const memberA = (await q<{ id: string }>('insert into tenant_memberships(tenant_id,user_id,role) values($1,$2,\'staff\') returning id', [tenantA, user]))[0].id;
    const ruleA = (await q<{ id: string }>("insert into stamp_rules(tenant_id,name,stamps_required,reward_title,reward_description) values($1,'Rule A',1,'Coffee','Free coffee') returning id", [tenantA]))[0].id;
    const customerA = (await q<{ id: string }>("insert into customers(tenant_id,external_ref) values($1,'customer-a') returning id", [tenantA]))[0].id;
    const cardA = (await q<{ id: string }>("insert into cards(tenant_id,customer_id,rule_id,public_token_hash) values($1,$2,$3,'hash-a') returning id", [tenantA, customerA, ruleA]))[0].id;
    await setTenant(tenantB);
    const memberB = (await q<{ id: string }>('insert into tenant_memberships(tenant_id,user_id,role) values($1,$2,\'staff\') returning id', [tenantB, user]))[0].id;
    const ruleB = (await q<{ id: string }>("insert into stamp_rules(tenant_id,name,stamps_required,reward_title,reward_description) values($1,'Rule B',1,'Tea','Free tea') returning id", [tenantB]))[0].id;
    const customerB = (await q<{ id: string }>("insert into customers(tenant_id,external_ref) values($1,'customer-b') returning id", [tenantB]))[0].id;
    const cardB = (await q<{ id: string }>("insert into cards(tenant_id,customer_id,rule_id,public_token_hash) values($1,$2,$3,'hash-b') returning id", [tenantB, customerB, ruleB]))[0].id;
    void cardB;

    // Release setup before repository work; cleanup reserves a fresh connection.
    setup.release(); setupReleased = true;
    const pool: DbPool = { connect: async () => {
      const reserved = await withDeadline(sql.reserve(), 'repository connection');
      try {
        await setPath(reserved);
        return { query: async <T>(text: string, params: unknown[] = []) => {
          assertParams(text.slice(0, 120), params);
          return { rows: await reserved.unsafe(text, params as any) as T[] };
        }, release: () => reserved.release() } as TxClient;
      } catch (error) { reserved.release(); throw error; }
    }};
    const repo = new CardRepository(pool);

    expect(await repo.findByPublicTokenHash(tenantB, 'hash-a')).toBeNull();
    await expect(repo.stamp(tenantB, cardA, 1, memberB, 'cross-tenant')).rejects.toThrow('CARD_NOT_FOUND');
    const customerA2 = (await withSchema(db => db.unsafe("insert into customers(tenant_id,external_ref) values($1,'customer-a2') returning id", [tenantA])) as { id: string }[])[0].id;
    const attempts = await Promise.allSettled([repo.createCard(tenantA, customerA2, ruleA, 'hash-a2'), repo.createCard(tenantA, customerA2, ruleA, 'hash-a3')]);
    expect(attempts.filter(x => x.status === 'fulfilled')).toHaveLength(0);
    expect(attempts.filter(x => x.status === 'rejected' && x.reason?.message === 'CUSTOMER_LIMIT_REACHED')).toHaveLength(2);
    const first = await repo.stamp(tenantA, cardA, 1, memberA, 'same-event');
    const second = await repo.stamp(tenantA, cardA, 1, memberA, 'same-event');
    expect((first as any).card.stampCount).toBe(1); expect((second as any).idempotencyKey).toBe('same-event');
    expect((await withSchema(db => db.unsafe('select stamp_count from cards where id=$1', [cardA])) as any)[0].stamp_count).toBe(1);
    const rewardId = (first as any).reward.id;
    expect((await repo.redeem(tenantA, rewardId)).status).toBe('redeemed');
    await expect(repo.redeem(tenantA, rewardId)).rejects.toThrow('REWARD_ALREADY_REDEEMED');
    await expect(repo.redeem(tenantB, rewardId)).rejects.toThrow('REWARD_NOT_FOUND');
    await withSchema(db => db.unsafe('insert into sessions(user_id,tenant_id,token_hash,csrf_token_hash,expires_at) values($1,$2,$3,$4,now()+interval \'1 hour\')', [user, tenantA, 'session-token-hash', 'csrf']));
    await repo.revokeSession(user, 'session-token-hash');
    expect((await withSchema(db => db.unsafe('select revoked_at,mfa_verified from sessions where token_hash=$1', ['session-token-hash'])) as any)[0].revoked_at).not.toBeNull();
  } finally {
    if (!setupReleased) setup.release();
    try {
      const cleanup = await withDeadline(sql.reserve(), 'cleanup connection');
      try {
        await withDeadline(configureConnection(cleanup), 'configure cleanup connection');
        await withDeadline(cleanup.unsafe(`drop schema if exists "${schema}" cascade`), 'drop schema');
      } finally { cleanup.release(); }
    } catch { /* cleanup is best effort after setup failure */ }
    await sql.end({ timeout: 5 });
  }
});
