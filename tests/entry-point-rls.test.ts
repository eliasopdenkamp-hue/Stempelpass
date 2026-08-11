import { test, expect } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { CardRepository, type DbPool, type TxClient } from '../src/repository';
/**
 * DB-free contract tests for the RLS-safe /join/:publicKey resolution path
 * (migration 008 + CardRepository.resolveEntryPoint).
 *
 * Blocker (documented, not worked around): the production app role does not
 * exist in this workspace yet, so the SECURITY DEFINER function cannot be
 * verified end-to-end against a live database here (see RLS_AUTH_P1.md
 * Teil C). These tests pin the migration contract and the repository SQL
 * contract without a database; the live verification is the first step of
 * the pilot process once the app role exists.
 */
const PUBLIC_KEY = 'a'.repeat(32); // valid 32-hex public key
const TENANT = '11111111-1111-4111-8111-111111111111';

class FakePool implements DbPool {
  queries: Array<{ sql: string; params: unknown[] }> = [];
  constructor(private readonly script: unknown[][]) {}
  async connect(): Promise<TxClient> {
    const rec = this;
    return {
      async query<T = unknown>(sql: string, params: unknown[] = []): Promise<{ rows: T[] }> {
        rec.queries.push({ sql, params });
        return { rows: (rec.script.shift() ?? []) as T[] };
      },
      release() {},
    };
  }
}

test('resolveEntryPoint resolves through the SECURITY DEFINER function, never the raw table', async () => {
  const pool = new FakePool([[{ tenant_id: TENANT, join_path: `/join/${PUBLIC_KEY}` }]]);
  const repo = new CardRepository(pool);
  const entry = await repo.resolveEntryPoint(PUBLIC_KEY);
  expect(entry).toEqual({ tenant_id: TENANT, join_path: `/join/${PUBLIC_KEY}` });
  // The only query issued is a call to the minimal resolver function —
  // fully qualified, so no search_path-dependent resolution.
  expect(pool.queries.length).toBe(1);
  expect(pool.queries[0]?.sql).toContain('from public.resolve_entry_point($1)');
  expect(pool.queries[0]?.sql).not.toContain('from tenant_entry_points');
  expect(pool.queries[0]?.params).toEqual([PUBLIC_KEY]);
});

test('resolveEntryPoint returns null for an unknown key without leaking rows', async () => {
  const pool = new FakePool([[]]);
  const repo = new CardRepository(pool);
  expect(await repo.resolveEntryPoint('b'.repeat(32))).toBeNull();
  expect(pool.queries.length).toBe(1);
});

test('resolveEntryPoint rejects malformed keys before any database interaction', async () => {
  const pool = new FakePool([]);
  const repo = new CardRepository(pool);
  for (const bad of ['', 'short', 'a'.repeat(31), 'a'.repeat(33), 'g'.repeat(32), 'a'.repeat(32).toUpperCase() + '!']) {
    expect(await repo.resolveEntryPoint(bad)).toBeNull();
  }
  expect(pool.queries.length).toBe(0); // format guard: no DB query at all
});

test('entry point lookup selects exactly tenant_id and join_path — never select *', async () => {
  // Column minimization is enforced by the SQL, not by the repository: the
  // resolver query must name exactly the two allowed columns so a widened
  // function output could never surface extra fields.
  const pool = new FakePool([[{ tenant_id: TENANT, join_path: `/join/${PUBLIC_KEY}` }]]);
  const repo = new CardRepository(pool);
  const entry = await repo.resolveEntryPoint(PUBLIC_KEY);
  expect(Object.keys(entry ?? {}).sort()).toEqual(['join_path', 'tenant_id']);
  const sql = pool.queries[0]?.sql ?? '';
  expect(sql).toBe('select tenant_id,join_path from public.resolve_entry_point($1)');
  expect(sql).not.toMatch(/select \*/i);
});

test('migration 008 defines the minimal resolver contract (DB-free pin)', async () => {
  const m008 = await readFile(join(import.meta.dir, '..', 'migrations', '008_entry_point_resolver.sql'), 'utf8');
  expect(m008).toMatch(/create or replace function public\.resolve_entry_point\(p_public_key text\)/);
  expect(m008).toMatch(/returns table \(tenant_id uuid, join_path text\)/);
  expect(m008).toMatch(/\bsecurity definer\b/i);
  expect(m008).toMatch(/set search_path = pg_catalog/i);
  expect(m008).toMatch(/from public\.tenant_entry_points/);
  expect(m008).toMatch(/revoke all on function public\.resolve_entry_point\(text\) from public/);
  expect(m008).toMatch(/grant execute on function public\.resolve_entry_point\(text\) to app_role/);
});
