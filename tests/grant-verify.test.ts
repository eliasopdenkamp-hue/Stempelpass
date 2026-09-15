/**
 * Grant regression — 2026-09-15 incident pin (requires a disposable DB).
 *
 * Root cause of the production 500 (POST /staff/{tenantId}/cards): the
 * runtime role `stempelpass_runtime` had no INSERT grant on `customers`
 * (migration 014 omission; the expectation matrix in `REQUIRED_GRANTS`
 * mirrored that omission, so `rls-verify` passed while the write path broke).
 *
 * This integration test proves, against a real disposable database, that the
 * corrected expectation matrix (a) PASSES when migration 017 has applied the
 * missing grant and (b) FAILS with `customers:INSERT` when the grant is
 * revoked — the exact drift shape the production check must catch.
 *
 * Safety contract (mirrors db.integration.test.ts):
 *  - reads ONLY `TEST_DATABASE_URL`; refuses to run when it equals
 *    `DATABASE_URL` or is absent (test is skipped then),
 *  - everything runs in a throwaway temporary schema that is dropped at the
 *    end — never touches `public` or any other schema,
 *  - every statement is bounded by deadlines so a stale catalog lock fails
 *    the test instead of hanging Bun.
 */

import { test, expect, setDefaultTimeout } from 'bun:test';
import postgres from 'postgres';
import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { ALL_APP_TABLES, REQUIRED_GRANTS, REQUIRED_FUNCTION_GRANTS, verifyRls } from '../src/rls-verify';

const url = process.env.TEST_DATABASE_URL;
const integration = url ? test : test.skip;
setDefaultTimeout(300_000);

const RUNTIME_ROLE = 'stempelpass_runtime';
// Neon branches autosuspend; a cold start can take much longer than the
// 7s used by db.integration.test.ts. 30s keeps the per-statement budget tight
// while tolerating a genuine cold start.
const DB_OPERATION_TIMEOUT_MS = 30_000;
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

integration('grant matrix: migration 017 grants customers INSERT; the check catches its absence', async () => {
  if (!url) return;
  if (url === process.env.DATABASE_URL) throw new Error('TEST_DATABASE_URL_MUST_NOT_EQUAL_DATABASE_URL');

  const schema = `gv_${crypto.randomUUID().replaceAll('-', '')}`;
  const schemaSearchPath = `"${schema}", public`;
  const sql = postgres(url, {
    max: 4,
    prepare: false,
    connect_timeout: 10,
    idle_timeout: 2,
    max_lifetime: 30,
    connection: { search_path: schemaSearchPath },
  });
  const migrationDir = join(import.meta.dir, '../migrations');
  // Structural type matching postgres.js `unsafe` (same pattern as
  // db.integration.test.ts). NOT generic: a generic `unsafe<T>(...)` makes
  // `ReservedSql` unassignable here.
  type Queryable = { unsafe(query: string, values?: any[]): Promise<any[]>; release(): void };
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
  const setup = await withDeadline(sql.reserve(), 'setup connection') as unknown as Queryable;
  let setupReleased = false;
  const q = async <T = any>(text: string, params: unknown[] = []): Promise<T[]> => {
    return await withDeadline(setup.unsafe(text, params as any) as Promise<T[]>, text.slice(0, 48)) as T[];
  };

  try {
    await configureConnection(setup);
    await withDeadline(setup.unsafe(`create schema "${schema}"`), 'create schema');
    await setPath(setup);

    // The 017 migration grants only when the role already exists (same
    // convention as 008/009/010/014/016). Provision it up-front on any
    // disposable DB; on the established harness branch it already exists.
    await q(`do $$ begin if not exists (select 1 from pg_roles where rolname = '${RUNTIME_ROLE}') then create role ${RUNTIME_ROLE} nologin; end if; end $$;`);

    // Apply every migration (incl. 017) in the throwaway schema. Production
    // runs in `public`; here the `public.` qualifier maps onto this schema.
    await q('create table if not exists schema_migrations (version text primary key, applied_at timestamptz not null default now())');
    const migrationFiles = [...new Set((await readdir(migrationDir)).filter(f => /^\d+_.+\.sql$/.test(f)).sort())];
    for (const file of migrationFiles) {
      const alreadyApplied = await q<{ version: string }>('select version from schema_migrations where version=$1', [file]);
      if (alreadyApplied.length) continue;
      const migrationSql = (await Bun.file(join(migrationDir, file)).text()).replaceAll('public.', `"${schema}".`);
      await q('begin');
      try {
        await q(migrationSql);
        await q('insert into schema_migrations(version) values($1) on conflict (version) do nothing', [file]);
        await q('commit');
      } catch (error) {
        try { await q('rollback'); } catch { /* preserve the migration error */ }
        throw error;
      }
    }
    expect(await q<{ version: string }>('select version from schema_migrations where version=$1', ['017_customers_insert_grant.sql'])).toHaveLength(1);

    // MUST-HAVE 2 shape: information_schema.role_table_grants must show the
    // INSERT grant migration 017 applied for the runtime role on customers.
    const grants = await q<{ privilege_type: string }>(
      `select privilege_type from information_schema.role_table_grants
       where grantee = $1 and table_schema = $2 and table_name = 'customers'`,
      [RUNTIME_ROLE, schema],
    );
    expect(grants.map(r => r.privilege_type)).toContain('INSERT');
    expect(grants.map(r => r.privilege_type)).toContain('SELECT');
    expect(grants.map(r => r.privilege_type)).toContain('UPDATE');

    // Emulate the operator grant runbook (restore_grants.sql) for everything
    // except customers (which migration 017 now covers), so the full matrix
    // check can run against the runtime role in this schema.
    const grantStatements: string[] = [];
    for (const [table, privileges] of Object.entries(REQUIRED_GRANTS)) {
      if (table === 'customers') continue; // already granted by 017
      if (!ALL_APP_TABLES.includes(table)) continue;
      grantStatements.push(`grant ${privileges.join(', ')} on "${schema}".${table} to ${RUNTIME_ROLE}`);
    }
    grantStatements.push(`grant usage on schema "${schema}" to ${RUNTIME_ROLE}`);
    for (const fn of REQUIRED_FUNCTION_GRANTS) {
      grantStatements.push(`grant execute on function "${schema}".${fn.name}(${fn.identityArguments}) to ${RUNTIME_ROLE}`);
    }
    for (const stmt of grantStatements) await q(stmt);

    // -- Positive proof ----------------------------------------------------
    // Named-role check against the disposable schema: customers now has
    // INSERT (via 017) → the corrected matrix must PASS.
    const pass = await verifyRls({ url, schema, roleName: RUNTIME_ROLE });
    expect(pass.ok).toBe(true);
    expect(pass.checks.grantsComplete).toBe(true);
    expect(pass.checks.missingGrants).toEqual([]);
    expect(pass.errors).toEqual([]);

    // -- Negative proof (the drift class) ----------------------------------
    // Simulate the 2026-09-15 production state: remove INSERT on customers
    // and run the check again — it must FAIL and name customers:INSERT.
    await q(`revoke insert on "${schema}".customers from ${RUNTIME_ROLE}`);
    const fail = await verifyRls({ url, schema, roleName: RUNTIME_ROLE });
    expect(fail.ok).toBe(false);
    expect(fail.checks.missingGrants).toContain('customers:INSERT');

    // Restore, so the check passes once more (positive control after revoke).
    await q(`grant insert on "${schema}".customers to ${RUNTIME_ROLE}`);
    const restored = await verifyRls({ url, schema, roleName: RUNTIME_ROLE });
    expect(restored.ok).toBe(true);
    expect(restored.checks.missingGrants).toEqual([]);
  } finally {
    if (!setupReleased) setup.release();
    try {
      const cleanup = await withDeadline(sql.reserve(), 'cleanup connection') as unknown as Queryable;
      try {
        await withDeadline(configureConnection(cleanup), 'configure cleanup connection');
        await withDeadline(cleanup.unsafe(`drop schema if exists "${schema}" cascade`), 'drop schema');
      } finally { cleanup.release(); }
    } catch { /* cleanup is best effort after setup failure */ }
    await sql.end({ timeout: 5 });
  }
});