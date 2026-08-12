/**
 * DB-free tests for the DSGVO cleanup CLI (src/cleanup.ts, `bun run db:cleanup`).
 *
 * Covers exactly the surface that must not need a database:
 *   - env validation (CLEANUP_TENANT_ID format, VERCEL hard block)
 *   - retention constants (default draft, owner approval pending)
 *   - the operator-role guard (owner-like role required, never the app role)
 *   - inactivity DML via a scripted fake DbClient (cards only by default;
 *     customers only with CLEANUP_DELETE_INACTIVE_CUSTOMERS=1; audit rows
 *     counted but NEVER deleted)
 *   - the dbCleanup orchestrator via a fake pool (role guard → sessions
 *     cleanup → begin → advisory lock → inactivity → commit, exit codes,
 *     anonymized stdout)
 */
import { describe, expect, test } from 'bun:test';
import {
  AUDIT_RETENTION,
  CARD_INACTIVITY_RETENTION,
  CLEANUP_LOCK_KEY,
  dbCleanup,
  formatCleanupResult,
  isOperatorRole,
  OPERATOR_ROLE_CHECK,
  parseCleanupEnv,
  runInactivityCleanup,
} from '../src/cleanup';
import type { DbPool, TxClient } from '../src/repository';

const TENANT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

/** Fake DbClient serving canned rows by SQL substring and recording calls. */
class ScriptedDb {
  calls: { sql: string; params: unknown[] }[] = [];
  constructor(private readonly script: { match: string; rows: unknown[] }[]) {}
  async query<T = unknown>(sql: string, params: unknown[] = []): Promise<{ rows: T[] }> {
    this.calls.push({ sql, params });
    const hit = this.script.find(r => sql.includes(r.match));
    return { rows: (hit?.rows ?? []) as T[] };
  }
  release(): void {}
}

/** Fake pool: every connect() returns one ScriptedDb (calls shared). */
class FakePool implements DbPool {
  calls: { sql: string; params: unknown[] }[] = [];
  constructor(private readonly script: { match: string; rows: unknown[] }[]) {}
  async connect(): Promise<TxClient> {
    const db = new ScriptedDb(this.script);
    const self = this;
    const tracked: TxClient = {
      query: async <T = unknown>(sql: string, params: unknown[] = []) => {
        const out = await db.query<T>(sql, params);
        self.calls.push({ sql, params });
        return out;
      },
      release: () => db.release(),
    };
    return tracked;
  }
  async end(): Promise<void> {}
}

// ---------------------------------------------------------------------------
// Retention constants (Default-Entwurf, Owner-Freigabe offen)
// ---------------------------------------------------------------------------
describe('retention constants (default draft, owner approval pending)', () => {
  test('cards inactivity 12 months, audit retention 24 months', () => {
    expect(CARD_INACTIVITY_RETENTION).toBe('12 months');
    expect(AUDIT_RETENTION).toBe('24 months');
  });
});

// ---------------------------------------------------------------------------
// Env validation
// ---------------------------------------------------------------------------
describe('parseCleanupEnv', () => {
  test('VERCEL=1 is a hard block (cleanup never runs on the request path)', () => {
    const result = parseCleanupEnv({ VERCEL: '1' });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors).toEqual(['CLEANUP_NOT_ALLOWED_ON_VERCEL']);
  });
  test('no tenant id = all tenants; no customer flag = conservative card-only run', () => {
    const result = parseCleanupEnv({});
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.tenantId).toBeNull();
      expect(result.value.deleteInactiveCustomers).toBe(false);
    }
  });
  test('valid CLEANUP_TENANT_ID is kept; customer flag parsed', () => {
    const result = parseCleanupEnv({ CLEANUP_TENANT_ID: TENANT, CLEANUP_DELETE_INACTIVE_CUSTOMERS: '1' });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.tenantId).toBe(TENANT);
      expect(result.value.deleteInactiveCustomers).toBe(true);
    }
  });
  test('malformed CLEANUP_TENANT_ID is rejected with a stable code', () => {
    const result = parseCleanupEnv({ CLEANUP_TENANT_ID: 'not-a-uuid' });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors).toEqual(['INVALID_CLEANUP_TENANT_ID']);
  });
});

// ---------------------------------------------------------------------------
// Operator-role guard
// ---------------------------------------------------------------------------
describe('operator-role guard', () => {
  test('the check is a read-only catalog query that never selects role names or credentials', () => {
    expect(OPERATOR_ROLE_CHECK).toContain('pg_tables');
    expect(OPERATOR_ROLE_CHECK).toContain('pg_has_role(current_user, t.tableowner');
    expect(OPERATOR_ROLE_CHECK).not.toContain('select *');
    expect(OPERATOR_ROLE_CHECK).not.toContain('current_user as');
  });
  test('isOperatorRole returns true only when the role owns (or inherits) the tenants table', async () => {
    const yes = new FakePool([{ match: 'pg_tables', rows: [{ is_operator: true }] }]);
    expect(await isOperatorRole(yes)).toBe(true);
    const no = new FakePool([{ match: 'pg_tables', rows: [{ is_operator: false }] }]);
    expect(await isOperatorRole(no)).toBe(false);
    const empty = new FakePool([{ match: 'pg_tables', rows: [] }]);
    expect(await isOperatorRole(empty)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Inactivity DML
// ---------------------------------------------------------------------------
describe('runInactivityCleanup', () => {
  test('card-only run: soft-deletes inactive cards, counts audit rows, never deletes audit', async () => {
    const db = new ScriptedDb([
      { match: 'update cards set', rows: [{ id: 'c1' }, { id: 'c2' }] },
      { match: 'from audit_log', rows: [{ n: 7 }] },
    ]);
    const counts = await runInactivityCleanup(db, TENANT, false);
    expect(counts).toEqual({ cardsSoftDeleted: 2, customersSoftDeleted: 0, auditRetentionEligible: 7 });
    const cardUpdate = db.calls.find(q => q.sql.startsWith('update cards'));
    expect(cardUpdate?.sql).toContain('tenant_id=$1');
    expect(cardUpdate?.sql).toContain("status='inactive'");
    expect(cardUpdate?.sql).toContain('deleted_at=now()');
    expect(cardUpdate?.sql).toContain(`interval '${CARD_INACTIVITY_RETENTION}'`);
    expect(cardUpdate?.params).toEqual([TENANT]);
    const auditQuery = db.calls.find(q => q.sql.includes('from audit_log'));
    expect(auditQuery?.sql).toContain(`interval '${AUDIT_RETENTION}'`);
    expect(auditQuery?.params).toEqual([TENANT]);
    // append-only: no DELETE/UPDATE on audit_log, ever.
    expect(db.calls.some(q => /(delete|update)\s+from\s+audit_log/i.test(q.sql))).toBe(false);
  });
  test('without a tenant the statements run globally (no tenant filter, no context needed)', async () => {
    const db = new ScriptedDb([
      { match: 'update cards set', rows: [] },
      { match: 'from audit_log', rows: [{ n: 0 }] },
    ]);
    const counts = await runInactivityCleanup(db, null, false);
    expect(counts.cardsSoftDeleted).toBe(0);
    const cardUpdate = db.calls.find(q => q.sql.startsWith('update cards'));
    expect(cardUpdate?.sql).not.toContain('tenant_id');
    expect(cardUpdate?.params).toEqual([]);
  });
  test('with CLEANUP_DELETE_INACTIVE_CUSTOMERS=1 the customer and its cards are soft-deleted (FK order)', async () => {
    const db = new ScriptedDb([
      { match: 'update cards set', rows: [{ id: 'c1' }] },
      { match: 'customer_id in', rows: [{ id: 'c9' }] }, // cards of inactive customers
      { match: 'update customers set', rows: [{ id: 'c1' }, { id: 'c2' }] },
      { match: 'from audit_log', rows: [{ n: 1 }] },
    ]);
    const counts = await runInactivityCleanup(db, TENANT, true);
    expect(counts.customersSoftDeleted).toBe(2);
    const updates = db.calls.filter(q => q.sql.startsWith('update'));
    expect(updates.length).toBe(3);
    // FK-Reihenfolge: Karten (auch die der inaktiven Kunden) vor Kunden.
    expect(updates[0]?.sql.startsWith('update cards')).toBe(true);
    expect(updates[1]?.sql.startsWith('update cards')).toBe(true);
    expect(updates[1]?.sql).toContain('customer_id in');
    expect(updates[2]?.sql.startsWith('update customers')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------
describe('dbCleanup', () => {
  test('missing DATABASE_URL exits 1 without connecting', async () => {
    let connected = false;
    const pool = new FakePool([]);
    const code = await dbCleanup({}, () => { connected = true; return pool; });
    expect(code).toBe(1);
    expect(connected).toBe(false);
  });
  test('VERCEL=1 exits 1 with CLEANUP_NOT_ALLOWED_ON_VERCEL', async () => {
    const code = await dbCleanup({ VERCEL: '1', DATABASE_URL: 'postgres://x' }, () => new FakePool([]));
    expect(code).toBe(1);
  });
  test('a non-operator role is refused before any DML (CLEANUP_ROLE_NOT_OPERATOR)', async () => {
    const pool = new FakePool([{ match: 'pg_tables', rows: [{ is_operator: false }] }]);
    const code = await dbCleanup({ DATABASE_URL: 'postgres://x' }, () => pool);
    expect(code).toBe(1);
    expect(pool.calls.length).toBe(1); // only the role check ran
    expect(pool.calls[0]?.sql).toContain('pg_tables');
  });
  test('operator run: role guard → session cleanup → advisory-locked inactivity tx → anonymized output, exit 0', async () => {
    const script = [
      { match: 'pg_tables', rows: [{ is_operator: true }] }, // role guard (own connection)
      { match: 'delete from sessions', rows: [{ id: 's1' }, { id: 's2' }] }, // cleanupExpiredSessions (own connection)
      { match: 'update cards set', rows: [{ id: 'c1' }] }, // inactivity tx
      { match: 'from audit_log', rows: [{ n: 3 }] }, // audit count
    ];
    const pool = new FakePool(script);
    const lines: string[] = [];
    const originalLog = console.log;
    console.log = (line: string) => { lines.push(line); };
    try {
      const code = await dbCleanup({ DATABASE_URL: 'postgres://x' }, () => pool);
      expect(code).toBe(0);
    } finally {
      console.log = originalLog;
    }
    expect(lines[0]).toBe('cleanup_ok');
    expect(lines).toContain('sessions_deleted=2');
    expect(lines).toContain('cards_inactive_soft_deleted=1');
    expect(lines).toContain('customers_inactive_soft_deleted=0');
    expect(lines).toContain('audit_retention_eligible=3 retained_append_only');
    for (const line of lines) expect(line).not.toContain('postgres://');
    // Orchestration order: role guard before any DML; advisory lock in the tx.
    const lock = pool.calls.find(q => q.sql.includes('pg_advisory_xact_lock'));
    expect(lock?.params).toEqual([CLEANUP_LOCK_KEY]);
    expect(pool.calls.findIndex(q => q.sql.includes('pg_tables'))).toBeLessThan(pool.calls.findIndex(q => q.sql.startsWith('delete from sessions')));
    expect(pool.calls.some(q => q.sql === 'commit')).toBe(true);
  });
  test('tenant-scoped run sets app.tenant_id inside the inactivity transaction', async () => {
    const script = [
      { match: 'pg_tables', rows: [{ is_operator: true }] },
      { match: 'delete from sessions', rows: [{ id: 's1' }] },
      { match: 'update cards set', rows: [] },
      { match: 'from audit_log', rows: [{ n: 0 }] },
    ];
    const pool = new FakePool(script);
    const code = await dbCleanup({ DATABASE_URL: 'postgres://x', CLEANUP_TENANT_ID: TENANT }, () => pool);
    expect(code).toBe(0);
    const setConfig = pool.calls.find(q => q.sql.includes('set_config'));
    expect(setConfig?.params).toEqual([TENANT]);
    const sessionDelete = pool.calls.find(q => q.sql.startsWith('delete from sessions'));
    expect(sessionDelete?.sql).toContain('tenant_id=$1');
    expect(sessionDelete?.params).toEqual([TENANT]);
  });
  test('a failing step rolls back the inactivity transaction and exits 1 with a classified code', async () => {
    const pool = new ThrowingPool('update cards set');
    const code = await dbCleanup({ DATABASE_URL: 'postgres://x' }, () => pool);
    expect(code).toBe(1);
    // The sessions sweep committed on its own connection BEFORE the failure;
    // the inactivity transaction itself must have rolled back, never committed.
    expect(pool.calls.some(q => q.sql === 'rollback')).toBe(true);
    const commits = pool.calls.filter(q => q.sql === 'commit').length;
    expect(commits).toBe(1); // only the sessions cleanup commit
    expect(pool.calls[pool.calls.length - 1]?.sql).toBe('rollback');
  });
});

/** Fake pool that answers the guard/sessions queries and throws on one match. */
class ThrowingPool implements DbPool {
  calls: { sql: string; params: unknown[] }[] = [];
  constructor(private readonly failMatch: string) {}
  async connect(): Promise<TxClient> {
    const self = this;
    return {
      async query<T = unknown>(sql: string, params: unknown[] = []): Promise<{ rows: T[] }> {
        self.calls.push({ sql, params });
        if (sql.includes('pg_tables')) return { rows: [{ is_operator: true }] as T[] };
        if (sql.includes('delete from sessions')) return { rows: [] as T[] };
        if (sql.includes(self.failMatch)) throw new Error('boom');
        return { rows: [] as T[] };
      },
      release() {},
    };
  }
}

describe('formatCleanupResult', () => {
  test('output is anonymized counts only — never ids, tokens, emails or URLs', () => {
    const lines = formatCleanupResult(5, { cardsSoftDeleted: 2, customersSoftDeleted: 1, auditRetentionEligible: 9 });
    expect(lines).toEqual([
      'cleanup_ok',
      'sessions_deleted=5',
      'cards_inactive_soft_deleted=2',
      'customers_inactive_soft_deleted=1',
      'audit_retention_eligible=9 retained_append_only',
    ]);
    for (const line of lines) {
      expect(line).not.toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
      expect(line).not.toMatch(/postgres:\/\//);
      expect(line).not.toMatch(/@/);
    }
  });
});
