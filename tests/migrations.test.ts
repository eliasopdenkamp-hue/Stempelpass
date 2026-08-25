/**
 * Migration-path checks — no database, no Neon.
 *
 * Pins the exact ordered migration set the runner (`src/db.ts` `runMigrations`)
 * will apply: every file matching `^\d+_.+\.sql$`, sorted lexically, executed
 * in order. Catches a migration that is missing from the directory or whose
 * filename breaks the sort (e.g. a new 007 that sorts before 006).
 */

import { expect, test } from 'bun:test';
import { readFile, readdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { MIGRATION_LOCK_KEY, runMigrations, type DbPool } from '../src/db';

const MIGRATIONS_DIR = join(import.meta.dir, '..', 'migrations');
const RUNNER_REGEX = /^\d+_.+\.sql$/;

const EXPECTED = [
  '001_init.sql',
  '002_security.sql',
  '003_auth.sql',
  '004_mfa.sql',
  '005_communication.sql',
  '006_pilot_onboarding.sql',
  '007_communication_source_allowlist.sql',
  '008_entry_point_resolver.sql',
  '009_sessions_rls_and_audit_split.sql',
  '010_membership_mfa_resolver.sql',
  '011_card_soft_delete.sql',
  '012_privacy_info.sql',
  '013_card_idempotency.sql',
  '014_app_role_grants.sql',
];

test('migration files: exact expected set, runner-compatible names, stable order', async () => {
  const files = (await readdir(MIGRATIONS_DIR)).filter(f => RUNNER_REGEX.test(f)).sort();
  expect(files).toEqual(EXPECTED);

  // Runner contract: `^\d+_.+\.sql$` and lexicographic order == numeric order.
  for (const f of files) {
    expect(f).toMatch(/^\d{3}_[a-z0-9_]+\.sql$/);
  }
  const prefixes = files.map(f => f.slice(0, 3));
  expect(new Set(prefixes).size).toBe(prefixes.length); // unique, no collisions
  for (let i = 1; i < prefixes.length; i++) {
    expect(Number(prefixes[i])).toBe(Number(prefixes[i - 1]) + 1); // contiguous
  }
});

test('007 constraint targets a table and column created by earlier migrations', async () => {
  const m005 = await readFile(join(MIGRATIONS_DIR, '005_communication.sql'), 'utf8');
  const m007 = await readFile(join(MIGRATIONS_DIR, '007_communication_source_allowlist.sql'), 'utf8');

  // 007 alters `communication_consent_events` and constrains `source`.
  expect(m007).toMatch(/alter table communication_consent_events/i);
  expect(m007).toMatch(/add constraint communication_consent_events_source_check/i);
  expect(m007).toMatch(/\bsource\b/);

  // 005 defines the table with a `source` column before 007 runs.
  expect(m005).toMatch(/create table communication_consent_events/);
  expect(m005).toMatch(/\bsource text not null\b/);
});
test('008 resolver function: minimal-privilege RLS-safe public-key lookup', async () => {
  const m006 = await readFile(join(MIGRATIONS_DIR, '006_pilot_onboarding.sql'), 'utf8');
  const m008 = await readFile(join(MIGRATIONS_DIR, '008_entry_point_resolver.sql'), 'utf8');
  // The table 008 resolves against is created and RLS-protected by 006.
  expect(m006).toMatch(/create table tenant_entry_points/);
  expect(m006).toMatch(/enable row level security/);
  // SECURITY DEFINER with a fixed, minimal search_path and no dynamic SQL.
  expect(m008).toMatch(/create or replace function public\.resolve_entry_point\(p_public_key text\)/);
  expect(m008).toMatch(/\bsecurity definer\b/i);
  expect(m008).toMatch(/set search_path = pg_catalog/i);
  // Fully qualified table reference; no search_path-dependent resolution.
  expect(m008).toMatch(/from public\.tenant_entry_points/);
  expect(m008).toMatch(/public\.tenant_entry_points\.tenant_id/);
  // Returns exactly (tenant_id, join_path) for the exact public key.
  expect(m008).toMatch(/returns table \(tenant_id uuid, join_path text\)/);
  expect(m008).toMatch(/where public\.tenant_entry_points\.public_key = p_public_key/);
  // Defense in depth: format guard in SQL as well as in the application.
  expect(m008).toMatch(/p_public_key ~ '\^\[a-f0-9\]\{32\}/);
  // Function body is a plain static SELECT: no dynamic SQL inside the body.
  const body = m008.match(/as \$\$\n?([\s\S]*?)\n?\$\$/)?.[1] ?? '';
  expect(body).not.toMatch(/\bexecute\b/i);
  expect(body).not.toMatch(/format\(/i);
  // No PUBLIC execution; explicit grant only to the app role.
  expect(m008).toMatch(/revoke all on function public\.resolve_entry_point\(text\) from public/);
  expect(m008).toMatch(/grant execute on function public\.resolve_entry_point\(text\) to app_role/);
  // The grant must be conditional (app role may not exist yet in this
  // workspace — RLS_AUTH_P1 Teil C documents the blocker) — never a bare,
  // unconditional GRANT that fails migrations where the role is absent.
  expect(m008).toMatch(/if exists \(select 1 from pg_roles where rolname = 'app_role'\)/);
});
test('008 resolver reads only tenant_entry_points', async () => {
  const m008 = await readFile(join(MIGRATIONS_DIR, '008_entry_point_resolver.sql'), 'utf8');
  // The only table the resolver reads is tenant_entry_points (from 006).
  const fromMatches = [...m008.matchAll(/\bfrom\s+([a-z_][a-z0-9_.]*)/gi)].map(m => m[1]);
  expect(fromMatches.some(ref => ref.includes('tenant_entry_points'))).toBe(true);
  // No other application table is read or written by the resolver.
  const tables = ['tenants', 'users', 'sessions', 'cards', 'rewards', 'stamp_rules', 'customers', 'audit_log', 'tenant_branding', 'stamp_events', 'tenant_memberships', 'communication_preferences', 'communication_consent_events', 'communication_message_logs'];
  for (const t of tables) {
    expect(m008).not.toMatch(new RegExp(`\\b${t}\\b`));
  }
});

test('009 enables RLS on sessions with the user-scoped app.user_id policy and no FORCE', async () => {
  const m009 = await readFile(join(MIGRATIONS_DIR, '009_sessions_rls_and_audit_split.sql'), 'utf8');
  // RLS is enabled, not FORCE: the table owner bypass must remain available
  // only to the SECURITY DEFINER identity bootstrap (see 009 resolver below);
  // the app role is a non-owner, so RLS applies to it regardless of FORCE.
  expect(m009).toMatch(/alter table sessions enable row level security/i);
  expect(m009).not.toMatch(/alter table\s+\w+\s+force row level security/i);
  // The policy is exactly the confirmed user-scoped expression, on both USING
  // and WITH CHECK (write path cannot create a session for another user).
  const policy = m009.match(/create policy sessions_user_isolation on sessions\s*using \(([\s\S]*?)\)\s*with check \(([\s\S]*?)\);/s);
  expect(policy).not.toBeNull();
  const expected = "user_id = nullif(current_setting('app.user_id', true), '')::uuid";
  expect(policy?.[1]?.replace(/\s+/g, ' ').trim()).toBe(expected);
  expect(policy?.[2]?.replace(/\s+/g, ' ').trim()).toBe(expected);
  // The policy must never fall back to tenant or token matching.
  const sessionPolicyStmt = m009.match(/create policy sessions_user_isolation on sessions[\s\S]*?;/)?.[0] ?? '';
  expect(sessionPolicyStmt).not.toMatch(/token_hash/);
  expect(sessionPolicyStmt).not.toMatch(/app\.tenant_id/);
});

test('009 session resolver: minimal SECURITY DEFINER bootstrap returning only user_id', async () => {
  const m009 = await readFile(join(MIGRATIONS_DIR, '009_sessions_rls_and_audit_split.sql'), 'utf8');
  expect(m009).toMatch(/create or replace function public\.resolve_session_user\(p_token_hash text\)/);
  expect(m009).toMatch(/returns table \(user_id uuid\)/);
  expect(m009).toMatch(/\bsecurity definer\b/i);
  expect(m009).toMatch(/set search_path = pg_catalog/i);
  // Fully qualified sessions reference; no search_path-dependent resolution.
  expect(m009).toMatch(/from public\.sessions/);
  expect(m009).toMatch(/public\.sessions\.user_id/);
  expect(m009).toMatch(/where public\.sessions\.token_hash = p_token_hash/);
  // Defense in depth: 64-hex token hash guard (hashSessionToken output format).
  expect(m009).toMatch(/p_token_hash ~ '\^\[a-f0-9\]\{64\}\$/);
  // No dynamic SQL in the body.
  const body = m009.match(/as \$\$\n?([\s\S]*?)\n?\$\$/)?.[1] ?? '';
  expect(body).not.toMatch(/\bexecute\b/i);
  expect(body).not.toMatch(/format\(/i);
  // No PUBLIC access; explicit conditional grant only to the app role.
  expect(m009).toMatch(/revoke all on function public\.resolve_session_user\(text\) from public/);
  expect(m009).toMatch(/grant execute on function public\.resolve_session_user\(text\) to app_role/);
  expect(m009).toMatch(/if exists \(select 1 from pg_roles where rolname = 'app_role'\)/);
});

test('009 resolver reads only sessions and never returns session secrets', async () => {
  const m009 = await readFile(join(MIGRATIONS_DIR, '009_sessions_rls_and_audit_split.sql'), 'utf8');
  const body = m009.match(/as \$\$\n?([\s\S]*?)\n?\$\$/)?.[1] ?? '';
  // Only the sessions table is read by the bootstrap.
  expect(body).toMatch(/from public\.sessions/);
  for (const t of ['tenants', 'users', 'cards', 'rewards', 'stamp_rules', 'customers', 'audit_log', 'tenant_branding', 'stamp_events', 'tenant_memberships', 'tenant_entry_points']) {
    expect(body).not.toMatch(new RegExp(`\\b${t}\\b`));
  }
  // The select list is exactly user_id — never csrf_token_hash, token_hash,
  // expires_at, revoked_at or any other session column.
  expect(body).not.toMatch(/csrf_token_hash/);
  expect(body).not.toMatch(/expires_at/);
  expect(body).not.toMatch(/revoked_at/);
  expect(body).not.toMatch(/select \*/i);
});

test('009 splits the 006 audit policy: tenant rows scoped, global rows context-free', async () => {
  const m006 = await readFile(join(MIGRATIONS_DIR, '006_pilot_onboarding.sql'), 'utf8');
  const m009 = await readFile(join(MIGRATIONS_DIR, '009_sessions_rls_and_audit_split.sql'), 'utf8');
  // 006 introduced the single OR-combined policy; 009 drops it.
  expect(m006).toMatch(/create policy audit_log_isolation on audit_log/);
  expect(m009).toMatch(/drop policy if exists audit_log_isolation on audit_log/);
  // Tenant rows: only in the matching tenant context (no `is null` fallback).
  const tenantPolicy = m009.match(/create policy audit_log_tenant_isolation on audit_log\s*using \(([\s\S]*?)\)\s*with check \(([\s\S]*?)\);/s);
  expect(tenantPolicy).not.toBeNull();
  expect(tenantPolicy?.[1]?.replace(/\s+/g, ' ').trim()).toBe("tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid");
  expect(tenantPolicy?.[2]?.replace(/\s+/g, ' ').trim()).toBe("tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid");
  // Global rows: only when NO tenant context is set at all.
  const globalPolicy = m009.match(/create policy audit_log_global_isolation on audit_log\s*using \(([\s\S]*?)\)\s*with check \(([\s\S]*?)\);/s);
  expect(globalPolicy).not.toBeNull();
  const globalExpr = "tenant_id is null and nullif(current_setting('app.tenant_id', true), '') is null";
  expect(globalPolicy?.[1]?.replace(/\s+/g, ' ').trim()).toBe(globalExpr);
  expect(globalPolicy?.[2]?.replace(/\s+/g, ' ').trim()).toBe(globalExpr);
  // Neither policy may reintroduce the 006 `tenant_id is null or ...` branch.
  expect(m009).not.toMatch(/tenant_id is null or tenant_id = nullif/);
});

test('009 leaves the /join resolver dependency (006 tenant_entry_points) untouched and unforced', async () => {
  const m006 = await readFile(join(MIGRATIONS_DIR, '006_pilot_onboarding.sql'), 'utf8');
  const m008 = await readFile(join(MIGRATIONS_DIR, '008_entry_point_resolver.sql'), 'utf8');
  const m009 = await readFile(join(MIGRATIONS_DIR, '009_sessions_rls_and_audit_split.sql'), 'utf8');
  // tenant_entry_points keeps its 006 tenant-isolation policy and stays
  // non-FORCE: the SECURITY DEFINER /join resolver (008) depends on the owner
  // bypass, so no FORCE ROW LEVEL SECURITY DDL may be introduced anywhere.
  expect(m006).toMatch(/create policy tenant_entry_points_isolation on tenant_entry_points/);
  expect(m006).not.toMatch(/alter table\s+\w+\s+force row level security/i);
  expect(m008).not.toMatch(/alter table\s+\w+\s+force row level security/i);
  expect(m009).not.toMatch(/alter table\s+\w+\s+force row level security/i);
  // 009 must not touch tenant_entry_points or resolve_entry_point at all.
  expect(m009).not.toMatch(/tenant_entry_points/);
  expect(m009).not.toMatch(/resolve_entry_point/);
});

test('010 MFA resolver: minimal SECURITY DEFINER membership-MFA lookup', async () => {
  const m004 = await readFile(join(MIGRATIONS_DIR, '004_mfa.sql'), 'utf8');
  const m010 = await readFile(join(MIGRATIONS_DIR, '010_membership_mfa_resolver.sql'), 'utf8');
  // The columns the resolver reads were added by 004 (mfa_required on users
  // and tenant_memberships) — the function may only run after 004.
  expect(m004).toMatch(/alter table users add column if not exists mfa_required/);
  expect(m004).toMatch(/alter table tenant_memberships add column if not exists mfa_required/);
  // Function signature: uuid parameter, scalar boolean return — EXISTS yields
  // true/false for every input, so the result is never NULL.
  expect(m010).toMatch(/create or replace function public\.membership_mfa_required\(p_user_id uuid\)/);
  expect(m010).toMatch(/returns boolean/);
  expect(m010).toMatch(/\bsecurity definer\b/i);
  expect(m010).toMatch(/set search_path = pg_catalog/i);
  // Fully qualified table references; no search_path-dependent resolution.
  expect(m010).toMatch(/from public\.tenant_memberships/);
  expect(m010).toMatch(/join public\.users/);
  // Semantics: EXISTS over active owner/admin memberships with MFA required at
  // membership OR user level (exact match of the pre-010 inline aggregate).
  expect(m010).toMatch(/m\.user_id = p_user_id/);
  expect(m010).toMatch(/m\.status = 'active'/);
  expect(m010).toMatch(/m\.role in \('owner', 'admin'\)/);
  expect(m010).toMatch(/\(m\.mfa_required or u\.mfa_required\)/);
  // No dynamic SQL in the body.
  const body = m010.match(/as \$\$\n?([\s\S]*?)\n?\$\$/)?.[1] ?? '';
  expect(body).not.toMatch(/\bexecute\b/i);
  expect(body).not.toMatch(/format\(/i);
  // No PUBLIC access; explicit conditional grant only to the app role.
  expect(m010).toMatch(/revoke all on function public\.membership_mfa_required\(uuid\) from public/);
  expect(m010).toMatch(/grant execute on function public\.membership_mfa_required\(uuid\) to app_role/);
  expect(m010).toMatch(/if exists \(select 1 from pg_roles where rolname = 'app_role'\)/);
});

test('010 resolver reads only tenant_memberships and users, never secrets', async () => {
  const m010 = await readFile(join(MIGRATIONS_DIR, '010_membership_mfa_resolver.sql'), 'utf8');
  const body = m010.match(/as \$\$\n?([\s\S]*?)\n?\$\$/)?.[1] ?? '';
  // Only tenant_memberships (m) and users (u) are read.
  expect(body).toMatch(/from public\.tenant_memberships/);
  expect(body).toMatch(/join public\.users/);
  for (const t of ['tenants', 'sessions', 'cards', 'rewards', 'stamp_rules', 'customers', 'audit_log', 'tenant_branding', 'stamp_events', 'tenant_entry_points', 'communication_preferences', 'communication_consent_events', 'communication_message_logs']) {
    expect(body).not.toMatch(new RegExp(`\\b${t}\\b`));
  }
  // The only projected columns are the membership role/status/MFA flags and
  // the user MFA flag — never email, password_hash or mfa_secret_ciphertext.
  expect(body).not.toMatch(/email/i);
  expect(body).not.toMatch(/password_hash/);
  expect(body).not.toMatch(/mfa_secret_ciphertext/);
  expect(body).not.toMatch(/select \*/i);
  // The result is a single scalar boolean (EXISTS), never a row with columns.
  expect(body).toMatch(/select exists/);
});

test('010 only creates the resolver function — no table/policy/FORCE changes', async () => {
  const m010 = await readFile(join(MIGRATIONS_DIR, '010_membership_mfa_resolver.sql'), 'utf8');
  // Exactly one object definition: the resolver function.
  expect(m010.match(/create or replace function/g)?.length).toBe(1);
  // Statements only (comments may legitimately mention the design); no DDL on
  // any table, no policy changes, no FORCE RLS anywhere.
  const stmts = m010.replace(/^--.*$/gm, '');
  expect(stmts).not.toMatch(/alter table/i);
  expect(stmts).not.toMatch(/create policy/i);
  expect(stmts).not.toMatch(/drop policy/i);
  expect(stmts).not.toMatch(/force row level security/i);
  // No GRANT/REVOKE other than the function-level EXECUTE controls.
  expect(stmts).not.toMatch(/grant select|grant insert|grant update|grant delete|grant all on table/i);
  expect(stmts).not.toMatch(/revoke all on table/i);
});

test('011 adds cards.deleted_at only — soft-delete column, no other schema change', async () => {
  const m001 = await readFile(join(MIGRATIONS_DIR, '001_init.sql'), 'utf8');
  const m011 = await readFile(join(MIGRATIONS_DIR, '011_card_soft_delete.sql'), 'utf8');
  // cards exists (001) and had no deleted_at before 011.
  expect(m001).toMatch(/create table cards/);
  expect(m001).toMatch(/create table customers[\s\S]*deleted_at timestamptz/);
  expect(m001).not.toMatch(/create table cards[\s\S]*deleted_at/);
  // 011 adds the soft-delete column (analog customers.deleted_at).
  expect(m011).toMatch(/alter table cards add column deleted_at timestamptz/);
  // Statements only: exactly ONE schema change, nothing else (no index,
  // no policy, no function, no GRANT/REVOKE, no FORCE RLS).
  const stmts = m011.replace(/^--.*$/gm, '').trim();
  expect(stmts).toMatch(/^alter table cards add column deleted_at timestamptz;$/);
  expect(m011).not.toMatch(/create index/i);
  expect(m011).not.toMatch(/create policy/i);
  expect(m011).not.toMatch(/create or replace function/i);
  expect(m011).not.toMatch(/grant|revoke/i);
  expect(m011).not.toMatch(/force row level security/i);
});

test('013 creates tenant-scoped encrypted idempotency storage with no raw-token column', async () => {
  const m013 = await readFile(join(MIGRATIONS_DIR, '013_card_idempotency.sql'), 'utf8');
  expect(m013).toMatch(/create table card_creation_idempotency/);
  expect(m013).toMatch(/tenant_id uuid not null references tenants\(id\)/i);
  expect(m013).toMatch(/primary key \(tenant_id, idempotency_key\)/i);
  expect(m013).toMatch(/request_fingerprint text not null/i);
  expect(m013).toMatch(/token_ciphertext text not null/i);
  expect(m013).toMatch(/enable row level security/i);
  expect(m013).toMatch(/create policy tenant_isolation on card_creation_idempotency/i);
  expect(m013.replace(/^--.*$/gm, '')).not.toMatch(/raw[_ ]?token/i);
});
test('014 grants the dedicated app role idempotency DML and resolver EXECUTE privileges without role changes', async () => {
  const m014 = await readFile(join(MIGRATIONS_DIR, '014_app_role_grants.sql'), 'utf8');
  const stmts = m014.replace(/^--.*$/gm, '');
  expect(stmts).toMatch(/if exists \(select 1 from pg_roles where rolname = 'app_role'\)/i);
  expect(stmts).toMatch(/execute 'grant usage on schema public to app_role'/i);
  expect(stmts).toMatch(/execute 'grant select, insert, update on table public\.card_creation_idempotency to app_role'/i);
  for (const [name, args] of [['resolve_entry_point', 'text'], ['resolve_session_user', 'text'], ['membership_mfa_required', 'uuid']]) {
    expect(stmts).toContain(`execute 'grant execute on function public.${name}(${args}) to app_role'`);
  }
  // GRANT is additive/idempotent; migration must not silently alter role
  // attributes or remove privileges.
  expect(stmts).not.toMatch(/\b(revoke|alter role|drop role|create role)\b/i);
  expect((stmts.match(/execute 'grant /gi) ?? []).length).toBe(5);
});

test('013 idempotency key is tenant-scoped and cannot create duplicate rows', async () => {
  const m013 = await readFile(join(MIGRATIONS_DIR, '013_card_idempotency.sql'), 'utf8');
  expect(m013).toMatch(/primary key \(tenant_id, idempotency_key\)/i);
  expect(m013).toMatch(/tenant_id uuid not null references tenants\(id\)/i);
  expect(m013).toMatch(/enable row level security/i);
  expect(m013).toMatch(/using \(tenant_id = nullif\(current_setting\('app\.tenant_id', true\), ''\)::uuid\)/i);
  expect(m013).toMatch(/with check \(tenant_id = nullif\(current_setting\('app\.tenant_id', true\), ''\)::uuid\)/i);
});

test('012 adds tenant_branding.privacy_email only — nullable Art. 13 contact, no other schema change', async () => {
  const m001 = await readFile(join(MIGRATIONS_DIR, '001_init.sql'), 'utf8');
  const m012 = await readFile(join(MIGRATIONS_DIR, '012_privacy_info.sql'), 'utf8');
  // tenant_branding exists (001) and had no privacy column before 012.
  expect(m001).toMatch(/create table tenant_branding/);
  expect(m001).not.toMatch(/privacy_email/);
  // 012 adds the nullable contact column (no NOT NULL — optional field).
  expect(m012).toMatch(/alter table tenant_branding add column privacy_email text/);
  expect(m012).not.toMatch(/not null/i);
  // Statements only: exactly ONE schema change, nothing else (no index,
  // no policy, no function, no GRANT/REVOKE, no FORCE RLS).
  const stmts = m012.replace(/^--.*$/gm, '').trim();
  expect(stmts).toMatch(/^alter table tenant_branding add column privacy_email text;$/);
  expect(m012).not.toMatch(/create index/i);
  expect(m012).not.toMatch(/create policy/i);
  expect(m012).not.toMatch(/create or replace function/i);
  expect(m012).not.toMatch(/grant|revoke/i);
  expect(m012).not.toMatch(/force row level security/i);
});

/* ------------------------------------------------------------------ *
 * runMigrations (src/db.ts) — DB-free fake-pool coverage of the F3 fix:
 * parallel cold starts are serialized with a transaction-scoped advisory
 * lock (pg_advisory_xact_lock), and the version insert is conflict-safe.
 * ------------------------------------------------------------------ */

interface FakeDbState {
  versions: Set<string>;
  queries: { sql: string; params: unknown[] }[];
  lockHeld: boolean;
  lockWaiters: (() => void)[];
  executed: Record<string, number>;
  releaseCount: number;
  failBody?: string;
}

/** Models one database shared by every "connection": the advisory lock is
 *  database-wide (like real PostgreSQL), the version table is shared, and
 *  COMMIT/ROLLBACK release the transaction-scoped lock. */
function createFakePool(state: FakeDbState): DbPool {
  return {
    connect: async () => ({
      query: async <T = unknown>(sql: string, params: unknown[] = []): Promise<{ rows: T[] }> => {
        state.queries.push({ sql, params });
        const norm = sql.trim().replace(/\s+/g, ' ').toLowerCase();
        if (norm === 'select pg_advisory_xact_lock($1)') {
          if (state.lockHeld) await new Promise<void>(resolve => state.lockWaiters.push(resolve));
          state.lockHeld = true;
          return { rows: [] as T[] };
        }
        if (norm === 'commit' || norm === 'rollback') {
          state.lockHeld = false;
          state.lockWaiters.splice(0).forEach(wake => wake());
          return { rows: [] as T[] };
        }
        if (norm.startsWith('select version from schema_migrations where version=$1')) {
          const version = String(params[0]);
          return { rows: (state.versions.has(version) ? [{ version }] : []) as T[] };
        }
        if (norm.startsWith('insert into schema_migrations(version) values($1) on conflict (version) do nothing')) {
          state.versions.add(String(params[0]));
          return { rows: [] as T[] };
        }
        if (norm.startsWith('create table if not exists schema_migrations') || norm === 'begin') {
          return { rows: [] as T[] };
        }
        // Anything else is a migration body (read verbatim from the file).
        if (state.failBody === sql) throw new Error('MIGRATION_FAILED');
        state.executed[sql] = (state.executed[sql] ?? 0) + 1;
        return { rows: [] as T[] };
      },
      release: () => { state.releaseCount++; },
    }),
  };
}

function freshState(): FakeDbState {
  return { versions: new Set(), queries: [], lockHeld: false, lockWaiters: [], executed: {}, releaseCount: 0 };
}

async function withMigrationDir(files: Record<string, string>, work: (dir: string) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), 'stempelpass-mig-'));
  try {
    for (const [name, body] of Object.entries(files)) await writeFile(join(dir, name), body, 'utf8');
    await work(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('runMigrations: F3 fix — advisory lock is taken before the version check, insert is conflict-safe, run commits', async () => {
  await withMigrationDir({
    '001_init.sql': 'create table alpha ();',
    '002_next.sql': 'create table beta ();',
  }, async dir => {
    const state = freshState();
    await runMigrations(createFakePool(state), dir);

    const lockQueries = state.queries.filter(q => q.sql.trim().replace(/\s+/g, ' ').toLowerCase() === 'select pg_advisory_xact_lock($1)');
    expect(lockQueries.length).toBe(2);
    for (const q of lockQueries) expect(q.params).toEqual([MIGRATION_LOCK_KEY]);

    // Order inside each migration transaction: begin → lock → check → DDL → insert → commit.
    const order = state.queries.map(q => q.sql.trim().replace(/\s+/g, ' ').toLowerCase());
    expect(order[0]).toMatch(/^create table if not exists schema_migrations/);
    expect(order.slice(1, 3)).toEqual(['begin', 'select pg_advisory_xact_lock($1)']);
    expect(order[3]).toMatch(/^select version from schema_migrations where version=\$1/);
    expect(order[4]).toBe('create table alpha ();');
    expect(order[5]).toContain('on conflict (version) do nothing');
    expect(order[6]).toBe('commit');
    expect(order[7]).toBe('begin');
    expect(order[8]).toBe('select pg_advisory_xact_lock($1)');

    // Both versions recorded exactly once, both bodies executed exactly once.
    expect([...state.versions].sort()).toEqual(['001_init.sql', '002_next.sql']);
    expect(state.executed['create table alpha ();']).toBe(1);
    expect(state.executed['create table beta ();']).toBe(1);
    expect(state.lockHeld).toBe(false);
    expect(state.releaseCount).toBe(1);
  });
});

test('runMigrations: idempotent re-run applies nothing and records nothing', async () => {
  await withMigrationDir({ '001_init.sql': 'create table alpha ();' }, async dir => {
    const state = freshState();
    const pool = createFakePool(state);
    await runMigrations(pool, dir);
    await runMigrations(pool, dir);

    expect(state.executed['create table alpha ();']).toBe(1);
    expect([...state.versions]).toEqual(['001_init.sql']);
    const inserts = state.queries.filter(q => q.sql.toLowerCase().includes('insert into schema_migrations'));
    expect(inserts.length).toBe(1); // only the first run inserted
    expect(state.releaseCount).toBe(2);
  });
});

test('runMigrations: two concurrent cold starts apply each migration exactly once (race pinned)', async () => {
  await withMigrationDir({
    '001_init.sql': 'create table alpha ();',
    '002_next.sql': 'create table beta ();',
    '003_last.sql': 'create table gamma ();',
  }, async dir => {
    const state = freshState();
    const pool = createFakePool(state);
    const [a, b] = await Promise.all([runMigrations(pool, dir), runMigrations(pool, dir)]);

    expect(a).toBeUndefined();
    expect(b).toBeUndefined();
    // The losing run re-checked under the lock and skipped — no double DDL.
    expect(state.executed['create table alpha ();']).toBe(1);
    expect(state.executed['create table beta ();']).toBe(1);
    expect(state.executed['create table gamma ();']).toBe(1);
    expect([...state.versions].sort()).toEqual(['001_init.sql', '002_next.sql', '003_last.sql']);
    // One version insert per file total (both runs share the versions table).
    const inserts = state.queries.filter(q => q.sql.toLowerCase().includes('insert into schema_migrations'));
    expect(inserts.length).toBe(3);
    expect(state.lockHeld).toBe(false);
    expect(state.releaseCount).toBe(2);
  });
});

test('runMigrations: failed migration rolls back, records no version, releases the lock and the connection', async () => {
  await withMigrationDir({
    '001_init.sql': 'create table alpha ();',
    '002_broken.sql': 'create table beta ();',
  }, async dir => {
    const state = freshState();
    state.failBody = 'create table beta ();';
    const pool = createFakePool(state);

    await expect(runMigrations(pool, dir)).rejects.toThrow('MIGRATION_FAILED');

    // The failing migration rolled back and was NOT recorded; 001 is intact.
    expect(state.executed['create table alpha ();']).toBe(1);
    expect(state.versions.has('002_broken.sql')).toBe(false);
    expect(state.versions.has('001_init.sql')).toBe(true);
    // rollback was issued after the failure and released the xact lock.
    const norm = state.queries.map(q => q.sql.trim().replace(/\s+/g, ' ').toLowerCase());
    expect(norm[norm.length - 1]).toBe('rollback');
    expect(state.lockHeld).toBe(false);
    expect(state.releaseCount).toBe(1);

    // A follow-up run (e.g. the next cold start) completes the pending migration.
    state.failBody = undefined;
    await runMigrations(pool, dir);
    expect(state.executed['create table beta ();']).toBe(1);
    expect([...state.versions].sort()).toEqual(['001_init.sql', '002_broken.sql']);
  });
});
