/**
 * RLS / production-role verification — unit tests, no database.
 *
 * The classifier (`classifyRlsReport`) and the query builders are pure and are
 * exercised directly. `verifyRls` runs against a scripted in-memory `RlsDb`
 * (never a real connection), proving the explicit read-only transaction
 * protocol (`BEGIN READ ONLY` → checks → `COMMIT`, `ROLLBACK` on failure),
 * the anonymization contract and the classification of the concrete Neon
 * failure causes:
 *
 *   - a verification query failing inside the read-only transaction reports
 *     `query:<name>` and rolls back (previously the driver's COMMIT on the
 *     aborted transaction collapsed this to `connect`);
 *   - failing to open the read-only transaction (connection-level) reports
 *     `connect` and never runs a check.
 */

import { describe, expect, test } from 'bun:test';
import {
  ALL_APP_TABLES,
  TENANT_SENSITIVE_TABLES,
  buildAsRoleQueries,
  buildNamedRoleQueries,
  classifyRlsReport,
  createRlsDb,
  resolveRlsEnv,
  rlsConnectionOptions,
  verifyRls,
  type RlsDb,
  type RlsRawInput,
  type RlsVerifyReport,
} from '../src/rls-verify';

// ---------------------------------------------------------------------------
// Synthetic raw input helpers
// ---------------------------------------------------------------------------

const okAttrs = { rolbypassrls: false, rolsuper: false, rolcreaterole: false, rolcreatedb: false, rolreplication: false };

function healthyInput(overrides: Partial<RlsRawInput> = {}): RlsRawInput {
  return {
    mode: 'as-role',
    roleAttrs: okAttrs,
    ownedTables: [],
    rlsRows: TENANT_SENSITIVE_TABLES.map(t => ({ table_name: t, rls_enabled: true, rls_forced: false })),
    grantRows: ALL_APP_TABLES.map(t => ({ table_name: t, sel: true, ins: true, upd: true, del: true })),
    schemaRow: { usage_ok: true, create_ok: true },
    rowSecurityRows: TENANT_SENSITIVE_TABLES.map(t => ({ table_name: t, active: true })),
    errors: [],
    ...overrides,
  };
}

function report(input: RlsRawInput): RlsVerifyReport {
  return classifyRlsReport(input);
}

// ---------------------------------------------------------------------------
// Query builder contract
// ---------------------------------------------------------------------------

describe('query builders (read-only, anonymized)', () => {
  for (const [mode, queries] of [
    ['as-role', buildAsRoleQueries('public')],
    ['named-role', buildNamedRoleQueries('app_role_x', 'public')],
  ] as const) {
    test(`${mode}: every statement is a bare SELECT`, () => {
      expect(queries.length).toBeGreaterThan(0);
      for (const q of queries) expect(q.sql.trim().toLowerCase().startsWith('select ')).toBe(true);
    });
    test(`${mode}: never selects current_user as output`, () => {
      for (const q of queries) {
        const selectList = q.sql.slice(q.sql.toLowerCase().indexOf('select') + 6, q.sql.toLowerCase().indexOf(' from '));
        expect(selectList).not.toMatch(/current_user/i);
      }
    });
  }

  test('named-role: role name is only ever a bind parameter, never inline', () => {
    const sql = buildNamedRoleQueries('app_role_x', 'public').map(q => q.sql).join('\n');
    expect(sql).not.toContain('app_role_x');
    expect(sql).not.toMatch(/current_user/i);
  });

  test('as-role: current_user appears only in predicates, never in select lists', () => {
    for (const q of buildAsRoleQueries('public')) {
      const selectList = q.sql.slice(q.sql.toLowerCase().indexOf('select') + 6, q.sql.toLowerCase().indexOf(' from '));
      expect(selectList).not.toMatch(/current_user/i);
    }
  });

  test('tables lists match the migration-derived constants', () => {
    expect(ALL_APP_TABLES).toContain('schema_migrations');
    for (const t of TENANT_SENSITIVE_TABLES) expect(ALL_APP_TABLES).toContain(t);
    expect(new Set(ALL_APP_TABLES).size).toBe(ALL_APP_TABLES.length);
    expect(new Set(TENANT_SENSITIVE_TABLES).size).toBe(TENANT_SENSITIVE_TABLES.length);
  });
});

// ---------------------------------------------------------------------------
// Classifier
// ---------------------------------------------------------------------------

describe('classifyRlsReport', () => {
  test('healthy non-owner app role passes', () => {
    const r = report(healthyInput());
    expect(r.ok).toBe(true);
    expect(r.roleClass).toBe('app-role');
    expect(r.checks.roleBypassRls).toBe(false);
    expect(r.checks.ownsAnyTable).toBe(false);
    expect(r.checks.rlsEnabledOnAllTenantTables).toBe(true);
    expect(r.checks.grantsComplete).toBe(true);
    expect(r.checks.rlsActiveForRole).toBe(true);
    expect(r.errors).toEqual([]);
  });

  test('rolbypassrls = true fails with privileged role class', () => {
    const r = report(healthyInput({ roleAttrs: { ...okAttrs, rolbypassrls: true } }));
    expect(r.ok).toBe(false);
    expect(r.roleClass).toBe('privileged');
    expect(r.checks.roleBypassRls).toBe(true);
  });

  test('superuser and role-creation flags fail as privileged', () => {
    expect(report(healthyInput({ roleAttrs: { ...okAttrs, rolsuper: true } })).ok).toBe(false);
    expect(report(healthyInput({ roleAttrs: { ...okAttrs, rolcreaterole: true } })).roleClass).toBe('privileged');
    expect(report(healthyInput({ roleAttrs: { ...okAttrs, rolcreatedb: true } })).ok).toBe(false);
    expect(report(healthyInput({ roleAttrs: { ...okAttrs, rolreplication: true } })).ok).toBe(false);
  });

  test('table ownership is an owner-like risk with table names for remediation', () => {
    const r = report(healthyInput({ ownedTables: ['cards', 'users'] }));
    expect(r.ok).toBe(false);
    expect(r.roleClass).toBe('owner-like');
    expect(r.checks.ownsAnyTable).toBe(true);
    expect(r.checks.ownedTables).toEqual(['cards', 'users']);
  });

  test('missing RLS on one tenant table fails and names it', () => {
    const rlsRows = TENANT_SENSITIVE_TABLES.map(t => ({ table_name: t, rls_enabled: t !== 'cards', rls_forced: false }));
    const r = report(healthyInput({ rlsRows }));
    expect(r.ok).toBe(false);
    expect(r.checks.rlsEnabledOnAllTenantTables).toBe(false);
    expect(r.checks.rlsMissing).toEqual(['cards']);
  });

  test('row_security_active false (owner/bypass style) fails in as-role mode', () => {
    const rowSecurityRows = TENANT_SENSITIVE_TABLES.map(t => ({ table_name: t, active: t !== 'rewards' }));
    const r = report(healthyInput({ rowSecurityRows }));
    expect(r.ok).toBe(false);
    expect(r.checks.rlsActiveForRole).toBe(false);
    expect(r.checks.rlsInactiveForRole).toEqual(['rewards']);
  });

  test('named-role mode reports rlsActiveForRole as null (not verifiable via admin connection)', () => {
    const r = report(healthyInput({ mode: 'named-role', rowSecurityRows: null }));
    expect(r.ok).toBe(true);
    expect(r.checks.rlsActiveForRole).toBe(null);
  });

  test('missing grants fail with classified table:PRIV entries', () => {
    const grantRows = ALL_APP_TABLES.map(t => ({ table_name: t, sel: true, ins: true, upd: true, del: true })).map(row =>
      row.table_name === 'cards' ? { ...row, upd: false } : row,
    );
    const r = report(healthyInput({ grantRows }));
    expect(r.ok).toBe(false);
    expect(r.checks.grantsComplete).toBe(false);
    expect(r.checks.missingGrants).toEqual(['cards:UPDATE']);
  });

  test('missing schema_migrations (schema not migrated) fails', () => {
    const grantRows = ALL_APP_TABLES.filter(t => t !== 'schema_migrations').map(t => ({
      table_name: t, sel: true, ins: true, upd: true, del: true,
    }));
    const r = report(healthyInput({ grantRows }));
    expect(r.ok).toBe(false);
    expect(r.tablesMissing).toEqual(['schema_migrations']);
  });

  test('schema USAGE denied fails', () => {
    const r = report(healthyInput({ schemaRow: { usage_ok: false, create_ok: false } }));
    expect(r.ok).toBe(false);
    expect(r.checks.schemaUsage).toBe(false);
  });

  test('role not found → unverified', () => {
    const r = report(healthyInput({ roleAttrs: null }));
    expect(r.ok).toBe(false);
    expect(r.roleClass).toBe('unverified');
    expect(r.errors).toContain('role-not-found');
  });
});

// ---------------------------------------------------------------------------
// Execution path (scripted RlsDb, no real connection)
// ---------------------------------------------------------------------------

/**
 * Scripted in-memory connection. `query` records every statement and matches
 * canned handlers by SQL substring; a handler with `error` throws (the real
 * driver would reject with a PostgresError — here with a fake message that
 * must never leak into a report).
 */
class FakeRlsDb implements RlsDb {
  statements: string[] = [];
  constructor(private readonly handlers: Record<string, { rows?: unknown[]; error?: string }>) {}
  async query<T>(sql: string, _params?: unknown[]): Promise<{ rows: T[] }> {
    this.statements.push(sql);
    for (const key of Object.keys(this.handlers)) {
      if (sql.includes(key)) {
        const h = this.handlers[key];
        if (h.error) throw new Error(h.error);
        return { rows: (h.rows ?? []) as T[] };
      }
    }
    throw new Error('unexpected statement');
  }
  async end() {}
}

const healthyHandlers = {
  'BEGIN READ ONLY': { rows: [] },
  'COMMIT': { rows: [] },
  'ROLLBACK': { rows: [] },
  'from pg_roles': { rows: [okAttrs] },
  'join pg_roles r': { rows: [] }, // no owned tables
  'relrowsecurity': { rows: TENANT_SENSITIVE_TABLES.map(t => ({ table_name: t, rls_enabled: true, rls_forced: false })) },
  'has_table_privilege': {
    rows: ALL_APP_TABLES.map(t => ({ table_name: t, sel: true, ins: true, upd: true, del: true })),
  },
  'has_schema_privilege': { rows: [{ usage_ok: true, create_ok: true }] },
  'row_security_active': { rows: TENANT_SENSITIVE_TABLES.map(t => ({ table_name: t, active: true })) },
};

describe('verifyRls (scripted RlsDb)', () => {
  test('healthy as-role run passes, is fully anonymized and uses the explicit tx protocol', async () => {
    const db = new FakeRlsDb(healthyHandlers);
    const url = 'postgresql://user:super-secret-pw@db.internal:5432/prod?sslmode=require';
    const r = await verifyRls({ url, db });
    expect(r.ok).toBe(true);
    const json = JSON.stringify(r);
    expect(json).not.toContain('super-secret-pw');
    expect(json).not.toContain('db.internal');
    expect(json).not.toContain('user:');
    expect(json).not.toContain('current_user');
    // Explicit transaction protocol: BEGIN READ ONLY first, COMMIT last, and
    // every statement in between is a bare SELECT.
    expect(db.statements[0]).toBe('BEGIN READ ONLY');
    expect(db.statements.at(-1)).toBe('COMMIT');
    expect(db.statements).not.toContain('ROLLBACK');
    for (const s of db.statements.slice(1, -1)) expect(s.trim().toLowerCase().startsWith('select ')).toBe(true);
    expect(db.statements.length).toBe(8); // BEGIN + 6 checks + COMMIT
  });

  test('named-role mode skips row_security_active and binds the role name', async () => {
    const db = new FakeRlsDb({ ...healthyHandlers });
    const r = await verifyRls({ url: 'postgresql://admin@db/p', roleName: 'sp_app', db });
    expect(r.mode).toBe('named-role');
    expect(r.checks.rlsActiveForRole).toBe(null);
    expect(db.statements.some(s => s.includes('row_security_active'))).toBe(false);
    for (const s of db.statements) expect(s).not.toContain('sp_app'); // role only as bind param
  });

  test('concrete cause: a failing check query reports query:<name>, rolls back, never commits', async () => {
    // This is the Neon failure shape: a verification query fails inside the
    // read-only transaction. The explicit tx rolls back (ROLLBACK) and the
    // classified code survives — previously the driver tried COMMIT on the
    // aborted transaction (25P02) and everything collapsed to `connect`.
    const db = new FakeRlsDb({
      ...healthyHandlers,
      'from pg_roles': { error: 'connection terminated user=postgres host=secret-db' },
    });
    const r = await verifyRls({ url: 'postgresql://x@y/p', db });
    expect(r.ok).toBe(false);
    expect(r.roleClass).toBe('unverified');
    expect(r.errors).toEqual(['query:role-attributes']);
    expect(db.statements[0]).toBe('BEGIN READ ONLY');
    expect(db.statements).toContain('ROLLBACK');
    expect(db.statements).not.toContain('COMMIT');
    expect(JSON.stringify(r)).not.toContain('secret-db');
    expect(JSON.stringify(r)).not.toContain('terminated');
  });

  test('a later failing query is named precisely (query:grants)', async () => {
    const db = new FakeRlsDb({
      ...healthyHandlers,
      'has_table_privilege': { error: 'permission denied for relation cards' },
    });
    const r = await verifyRls({ url: 'postgresql://u:p@host/db', db });
    expect(r.ok).toBe(false);
    expect(r.errors).toEqual(['query:grants']);
    expect(db.statements).toContain('ROLLBACK');
    expect(db.statements).not.toContain('COMMIT');
    expect(JSON.stringify(r)).not.toContain('permission denied');
  });

  test('named-role query failure is classified against the named-role step', async () => {
    const db = new FakeRlsDb({
      ...healthyHandlers,
      'has_schema_privilege': { error: 'permission denied for schema app' },
    });
    const r = await verifyRls({ url: 'postgresql://u:p@host/db', roleName: 'sp_app', db });
    expect(r.mode).toBe('named-role');
    expect(r.errors).toEqual(['query:schema-privileges']);
    expect(JSON.stringify(r)).not.toContain('permission denied');
    expect(JSON.stringify(r)).not.toContain('sp_app');
  });

  test('concrete cause: BEGIN READ ONLY failing reports connect and never runs a check', async () => {
    // The owner-facing Neon symptom: the read-only transaction cannot be
    // opened (proxy drop, cold start timeout, auth/TLS failure). It must be
    // reported as `connect` — and no check query may run.
    const db = new FakeRlsDb({
      ...healthyHandlers,
      'BEGIN READ ONLY': { error: 'FATAL: password authentication failed for user "sp" host=neon-proxy' },
    });
    const r = await verifyRls({ url: 'postgresql://u:p@secret-host.example/p', db });
    expect(r.ok).toBe(false);
    expect(r.roleClass).toBe('unverified');
    expect(r.errors).toEqual(['connect']);
    expect(db.statements).toEqual(['BEGIN READ ONLY']);
    const json = JSON.stringify(r);
    expect(json).not.toContain('secret-host');
    expect(json).not.toContain('password authentication');
    expect(json).not.toContain('u:p@');
  });

  test('COMMIT failing (connection died at the end) reports connect', async () => {
    const db = new FakeRlsDb({
      ...healthyHandlers,
      'COMMIT': { error: 'socket hang up' },
    });
    const r = await verifyRls({ url: 'postgresql://u:p@host/db', db });
    expect(r.ok).toBe(false);
    expect(r.errors).toEqual(['connect']);
    expect(JSON.stringify(r)).not.toContain('hang up');
  });

  test('invalid schema/role inputs fail before any statement', async () => {
    const db = new FakeRlsDb(healthyHandlers);
    expect((await verifyRls({ url: 'u', schema: 'bad schema;', db })).errors).toEqual(['invalid-schema']);
    expect((await verifyRls({ url: 'u', roleName: 'bad role', db })).errors).toEqual(['invalid-role']);
    expect(db.statements.length).toBe(0);
  });

  test('an end() failure is swallowed (best-effort close)', async () => {
    const db = new FakeRlsDb(healthyHandlers);
    db.end = async () => { throw new Error('close failed'); };
    const r = await verifyRls({ url: 'postgresql://u:p@host/db', db });
    expect(r.ok).toBe(true);
    expect(JSON.stringify(r)).not.toContain('close failed');
  });
});

// ---------------------------------------------------------------------------
// Connection hardening (Neon)
// ---------------------------------------------------------------------------

describe('rlsConnectionOptions (Neon hardening)', () => {
  test('dedicated single slot with a generous connect timeout for cold starts', () => {
    const o = rlsConnectionOptions();
    expect(o.max).toBe(1);
    expect(o.connect_timeout).toBeGreaterThanOrEqual(30);
    expect(o.prepare).toBe(false);
    // idle_timeout deliberately omitted → postgres.js default null (never
    // self-closes mid-transaction); max_lifetime disabled.
    expect('idle_timeout' in o).toBe(false);
    expect(o.max_lifetime).toBeNull();
  });

  test('session is pinned read-only (default_transaction_read_only)', () => {
    const o = rlsConnectionOptions();
    expect(o.connection.default_transaction_read_only).toBe(true);
  });

  test('createRlsDb exposes query/end and never the URL', () => {
    const db = createRlsDb('postgresql://u:secret@host/db?sslmode=require');
    expect(typeof db.query).toBe('function');
    expect(typeof db.end).toBe('function');
    expect(String(db).includes('secret')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Opt-in env contract
// ---------------------------------------------------------------------------

describe('resolveRlsEnv (explicit opt-in)', () => {
  test('refuses to run without RLS_VERIFY_DATABASE_URL (no DATABASE_URL fallback)', () => {
    expect(() => resolveRlsEnv({})).toThrow('RLS_VERIFY_DATABASE_URL_REQUIRED');
    expect(() => resolveRlsEnv({ DATABASE_URL: 'postgresql://x' })).toThrow('RLS_VERIFY_DATABASE_URL_REQUIRED');
    expect(() => resolveRlsEnv({ RLS_VERIFY_DATABASE_URL: '   ' })).toThrow('RLS_VERIFY_DATABASE_URL_REQUIRED');
  });

  test('accepts explicit URL and optional role/schema', () => {
    expect(resolveRlsEnv({ RLS_VERIFY_DATABASE_URL: ' postgresql://x ' })).toEqual({ url: 'postgresql://x', schema: 'public' });
    expect(resolveRlsEnv({ RLS_VERIFY_DATABASE_URL: 'postgresql://x', RLS_VERIFY_ROLE: 'sp_app', RLS_VERIFY_SCHEMA: 'app' })).toEqual({
      url: 'postgresql://x', roleName: 'sp_app', schema: 'app',
    });
  });
});
