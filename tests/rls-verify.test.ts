/**
 * RLS / production-role verification — unit tests, no database.
 *
 * The classifier (`classifyRlsReport`) and the query builders are pure and are
 * exercised directly. `verifyRls` runs against a scripted in-memory `RlsDb`
 * (never a real connection), proving the execution path, the anonymization
 * contract and the read-only guard without touching any PostgreSQL instance.
 */

import { describe, expect, test } from 'bun:test';
import {
  ALL_APP_TABLES,
  TENANT_SENSITIVE_TABLES,
  buildAsRoleQueries,
  buildNamedRoleQueries,
  classifyRlsReport,
  resolveRlsEnv,
  verifyRls,
  type RlsDb,
  type RlsRawInput,
  type RlsTx,
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

class FakeRlsDb implements RlsDb {
  queries: string[] = [];
  constructor(private readonly handlers: Record<string, { rows?: unknown[]; error?: string }>) {}
  async begin<T>(_mode: string, fn: (tx: RlsTx) => Promise<T>): Promise<T> {
    const tx: RlsTx = {
      unsafe: async (sql, _params) => {
        this.queries.push(sql);
        for (const key of Object.keys(this.handlers)) {
          if (sql.includes(key)) {
            const h = this.handlers[key];
            if (h.error) throw new Error(h.error);
            return { rows: (h.rows ?? []) as never[] };
          }
        }
        throw new Error('unexpected query');
      },
    };
    return fn(tx);
  }
  async end() {}
}

/**
 * Models the real postgres.js `begin()` semantics that previously caused the
 * misclassification: the driver runs BEGIN, executes the callback, and on ANY
 * error inside the transaction rolls back and rethrows. When the old code
 * swallowed a query error and returned a fail report, the transaction stayed
 * aborted and the driver's COMMIT failed — surfacing as `connect`. This fake
 * propagates callback errors out of `begin()` (with a rollback marker) like
 * the real driver, so the classification contract is tested under the exact
 * failure shape that happens in production.
 */
class PostgresLikeRlsDb implements RlsDb {
  queries: string[] = [];
  constructor(private readonly handlers: Record<string, { rows?: unknown[]; error?: string }>) {}
  async begin<T>(_mode: string, fn: (tx: RlsTx) => Promise<T>): Promise<T> {
    const tx: RlsTx = {
      unsafe: async (sql, _params) => {
        this.queries.push(sql);
        for (const key of Object.keys(this.handlers)) {
          if (sql.includes(key)) {
            const h = this.handlers[key];
            if (h.error) throw new Error(h.error);
            return { rows: (h.rows ?? []) as never[] };
          }
        }
        throw new Error('unexpected query');
      },
    };
    try {
      return await fn(tx);
    } catch (e) {
      this.queries.push('rollback'); // driver rolls back before rethrowing
      throw e;
    }
  }
  async end() {}
}

const healthyHandlers = {
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
  test('healthy as-role run passes and is fully anonymized', async () => {
    const db = new FakeRlsDb(healthyHandlers);
    const url = 'postgresql://user:super-secret-pw@db.internal:5432/prod?sslmode=require';
    const r = await verifyRls({ url, db });
    expect(r.ok).toBe(true);
    const json = JSON.stringify(r);
    expect(json).not.toContain('super-secret-pw');
    expect(json).not.toContain('db.internal');
    expect(json).not.toContain('user:');
    expect(json).not.toContain('current_user');
    expect(db.queries.every(q => q.trim().toLowerCase().startsWith('select '))).toBe(true);
  });

  test('named-role mode skips row_security_active and binds the role name', async () => {
    const db = new FakeRlsDb({
      ...healthyHandlers,
      'from pg_roles': { rows: [okAttrs] },
    });
    const r = await verifyRls({ url: 'postgresql://admin@db/p', roleName: 'sp_app', db });
    expect(r.mode).toBe('named-role');
    expect(r.checks.rlsActiveForRole).toBe(null);
    expect(db.queries.some(q => q.includes('row_security_active'))).toBe(false);
    for (const q of db.queries) expect(q).not.toContain('sp_app'); // role only as bind param
  });

  test('a failing catalog query maps to a classified error, never a driver message', async () => {
    const db = new FakeRlsDb({ ...healthyHandlers, 'from pg_roles': { error: 'connection terminated user=postgres host=secret-db' } });
    const r = await verifyRls({ url: 'postgresql://x@y/p', db });
    expect(r.ok).toBe(false);
    expect(r.roleClass).toBe('unverified');
    expect(JSON.stringify(r)).not.toContain('secret-db');
    expect(JSON.stringify(r)).not.toContain('terminated');
    expect(r.errors).toEqual(['query:role-attributes']);
  });

  test('query failure keeps query:<name> even when begin() rejects like the real driver', async () => {
    // postgres.js rolls the aborted transaction back and rethrows the callback
    // error out of begin() — the shape that previously collapsed to `connect`.
    const db = new PostgresLikeRlsDb({
      ...healthyHandlers,
      'from pg_roles': { error: 'psql: FATAL: password authentication failed for user "x"' },
    });
    const r = await verifyRls({ url: 'postgresql://u:p@secret-host.example/p', db });
    expect(r.ok).toBe(false);
    expect(r.roleClass).toBe('unverified');
    expect(r.errors).toEqual(['query:role-attributes']);
    expect(db.queries.at(-1)).toBe('rollback'); // driver rolled back before rethrowing
    const json = JSON.stringify(r);
    expect(json).not.toContain('secret-host');
    expect(json).not.toContain('password authentication');
    expect(json).not.toContain('u:p@');
  });

  test('a later failing query is named precisely (query:grants)', async () => {
    const db = new PostgresLikeRlsDb({
      ...healthyHandlers,
      'has_table_privilege': { error: 'permission denied for relation cards' },
    });
    const r = await verifyRls({ url: 'postgresql://u:p@host/db', db });
    expect(r.ok).toBe(false);
    expect(r.errors).toEqual(['query:grants']);
    expect(JSON.stringify(r)).not.toContain('permission denied');
  });

  test('named-role query failure is classified against the named-role step', async () => {
    const db = new PostgresLikeRlsDb({
      ...healthyHandlers,
      'has_schema_privilege': { error: 'permission denied for schema app' },
    });
    const r = await verifyRls({ url: 'postgresql://u:p@host/db', roleName: 'sp_app', db });
    expect(r.mode).toBe('named-role');
    expect(r.errors).toEqual(['query:schema-privileges']);
    expect(JSON.stringify(r)).not.toContain('permission denied');
    expect(JSON.stringify(r)).not.toContain('sp_app');
  });

  test('invalid schema/role inputs fail before any query', async () => {
    const db = new FakeRlsDb(healthyHandlers);
    expect((await verifyRls({ url: 'u', schema: 'bad schema;', db })).errors).toEqual(['invalid-schema']);
    expect((await verifyRls({ url: 'u', roleName: 'bad role', db })).errors).toEqual(['invalid-role']);
    expect(db.queries.length).toBe(0);
  });

  test('an unhandled begin() failure is classified as connect', async () => {
    const db = {
      begin: async () => { throw new Error('could not connect to db.internal'); },
      end: async () => {},
    };
    const r = await verifyRls({ url: 'postgresql://u:p@db.internal/x', db });
    expect(r.ok).toBe(false);
    expect(r.errors).toEqual(['connect']);
    expect(JSON.stringify(r)).not.toContain('db.internal');
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
