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

// ---------------------------------------------------------------------------
// joinContext (GET /join/:publicKey customer page) — same RLS-safe resolver,
// then a tenant-scoped read of branding/rule/controller for the join page
// (owner fix 2026-09-13: the join route renders branded HTML, no raw JSON).
// ---------------------------------------------------------------------------
test('joinContext resolves the entry point, sets tenant context, then reads branding/rule/controller', async () => {
  const pool = new FakePool([
    [], // begin
    [{ tenant_id: TENANT, join_path: `/join/${PUBLIC_KEY}` }], // resolve_entry_point
    [], // set_config app.tenant_id
    [{ cardTitle: 'Café', cardText: 'Treuekarte', primaryColor: '#123456', secondaryColor: '#ffffff', privacyEmail: 'ds@beispiel.de', version: 1 }], // tenant_branding
    [{ legal_name: 'Beispiel GmbH' }], // tenants
    [{ id: 'rule-1', tenantId: TENANT, name: 'R', stampsRequired: 8, rewardTitle: 'Kaffee', rewardDescription: 'Gratis', active: true, version: 1 }], // stamp_rules
    [], // commit
  ]);
  const repo = new CardRepository(pool);
  const ctx = await repo.joinContext(PUBLIC_KEY);
  expect(ctx).not.toBeNull();
  expect(ctx?.tenantId).toBe(TENANT);
  expect(ctx?.joinPath).toBe(`/join/${PUBLIC_KEY}`);
  expect(ctx?.branding?.cardTitle).toBe('Café');
  // The privacy email never leaks into the branding object — it is surfaced
  // only as the separate allowlisted privacyContact field.
  expect(ctx?.branding).not.toHaveProperty('privacyContact');
  expect(ctx?.rule?.stampsRequired).toBe(8);
  expect(ctx?.controllerName).toBe('Beispiel GmbH');
  expect(ctx?.privacyContact).toBe('ds@beispiel.de');
  const sqls = pool.queries.map(q => q.sql);
  const resolverIdx = sqls.findIndex(s => s.includes('resolve_entry_point'));
  const ctxIdx = sqls.findIndex(s => s.includes("set_config('app.tenant_id'"));
  const brandingIdx = sqls.findIndex(s => s.includes('from tenant_branding'));
  const ruleIdx = sqls.findIndex(s => s.includes('from stamp_rules'));
  const commitIdx = sqls.findIndex(s => s === 'commit');
  expect(ctxIdx).toBeGreaterThan(resolverIdx);
  expect(brandingIdx).toBeGreaterThan(ctxIdx);
  expect(ruleIdx).toBeGreaterThan(brandingIdx);
  expect(commitIdx).toBeGreaterThan(ruleIdx);
  // RLS-safe: never a direct tenant_entry_points table read.
  expect(sqls.some(s => s.includes('from tenant_entry_points'))).toBe(false);
  // Minimized view model: no public_key, no cards/customers/rewards rows.
  expect(JSON.stringify(ctx)).not.toContain('public_key');
  expect(JSON.stringify(ctx)).not.toContain('publicKey');
  expect(JSON.stringify(ctx)).not.toContain('customers');
});

test('joinContext aliases branding/rule columns snake_case→camelCase (no select *)', async () => {
  const pool = new FakePool([
    [], // begin
    [{ tenant_id: TENANT, join_path: `/join/${PUBLIC_KEY}` }],
    [], // set_config
    [{ cardTitle: 'Café', cardText: '', primaryColor: '#123456', secondaryColor: '#ffffff', privacyEmail: null, version: 1 }],
    [{ legal_name: null }],
    [{ id: 'rule-1', tenantId: TENANT, name: 'R', stampsRequired: 8, rewardTitle: 'K', rewardDescription: '', active: true, version: 1 }],
    [], // commit
  ]);
  const repo = new CardRepository(pool);
  const ctx = await repo.joinContext(PUBLIC_KEY);
  expect(ctx?.branding?.cardTitle).toBe('Café');
  expect(ctx?.controllerName).toBeNull();
  expect(ctx?.privacyContact).toBeNull();
  const brandingSql = pool.queries.find(q => q.sql.includes('from tenant_branding'));
  expect(brandingSql?.sql).toContain('card_title as "cardTitle"');
  expect(brandingSql?.sql).toContain('privacy_email as "privacyEmail"');
  expect(brandingSql?.sql).not.toMatch(/select \*/i);
  const ruleSql = pool.queries.find(q => q.sql.includes('from stamp_rules'));
  expect(ruleSql?.sql).toContain('stamps_required as "stampsRequired"');
  expect(ruleSql?.sql).not.toMatch(/select \*/i);
});

test('joinContext returns null for an unknown key without setting tenant context or reading branding', async () => {
  const pool = new FakePool([
    [], // begin
    [], // resolve_entry_point -> no row
    [], // rollback
  ]);
  const repo = new CardRepository(pool);
  expect(await repo.joinContext('b'.repeat(32))).toBeNull();
  expect(pool.queries.some(q => q.sql === 'rollback')).toBe(true);
  expect(pool.queries.some(q => q.sql.includes("set_config('app.tenant_id'"))).toBe(false);
  expect(pool.queries.some(q => q.sql.includes('from tenant_branding'))).toBe(false);
  expect(pool.queries.length).toBe(3);
});

test('joinContext rejects malformed keys before any database interaction', async () => {
  const pool = new FakePool([]);
  const repo = new CardRepository(pool);
  for (const bad of ['', 'short', 'a'.repeat(31), 'a'.repeat(33), 'g'.repeat(32), 'a'.repeat(32).toUpperCase() + '!']) {
    expect(await repo.joinContext(bad)).toBeNull();
  }
  expect(pool.queries.length).toBe(0); // format guard: no DB query at all
});
