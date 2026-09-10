import { describe, expect, test } from 'bun:test';
import {
  CONSENT_EVENT_RETENTION_AFTER_REVOCATION,
  formatRetentionResult,
  MESSAGE_LOG_RETENTION,
  parseRetentionEnv,
  REVOKED_SESSION_RETENTION,
  runRetention,
  type RetentionCounts,
} from '../src/retention';
import type { TxClient } from '../src/repository';
import type { WalletAdapter } from '../src/wallet';

const TENANT = '11111111-1111-4111-8111-111111111111';
const OTHER_TENANT = '99999999-9999-4999-8999-999999999999';
const CUSTOMER = '22222222-2222-4222-8222-222222222222';
const CARD = '33333333-3333-4333-8333-333333333333';

class FakeDb implements TxClient {
  readonly queries: Array<{ sql: string; params: unknown[] }> = [];
  constructor(private readonly script: unknown[][]) {}
  async query<T = unknown>(sql: string, params: unknown[] = []): Promise<{ rows: T[] }> {
    this.queries.push({ sql, params });
    return { rows: (this.script.shift() ?? []) as T[] };
  }
  release() {}
}

type MessageFixture = { id: string; tenant_id: string; created_at: string };
type PreferenceFixture = { tenant_id: string; customer_id: string; withdrawn_at: string | null };
type ConsentFixture = { id: string; tenant_id: string; customer_id: string };

/** A DB-free fixture that applies the two standalone predicates to artificial timestamps. */
class RetentionFixtureDb implements TxClient {
  readonly queries: Array<{ sql: string; params: unknown[] }> = [];
  constructor(
    private readonly now: Date,
    private messageLogs: MessageFixture[],
    private preferences: PreferenceFixture[],
    private consentEvents: ConsentFixture[],
  ) {}

  async query<T = unknown>(sql: string, params: unknown[] = []): Promise<{ rows: T[] }> {
    this.queries.push({ sql, params });
    const tenantId = params[0] as string | undefined;
    if (sql.startsWith('delete from communication_message_logs') && sql.includes('created_at <= now()')) {
      const cutoff = new Date(this.now);
      cutoff.setUTCMonth(cutoff.getUTCMonth() - 24);
      const deleted = this.messageLogs.filter(row =>
        (!tenantId || row.tenant_id === tenantId) && new Date(row.created_at) <= cutoff,
      );
      this.messageLogs = this.messageLogs.filter(row => !deleted.includes(row));
      return { rows: deleted as T[] };
    }
    if (sql.startsWith('delete from communication_consent_events') && sql.includes('max(p.withdrawn_at)')) {
      const cutoff = new Date(this.now);
      cutoff.setUTCFullYear(cutoff.getUTCFullYear() - 3);
      const lastWithdrawal = new Map<string, number>();
      for (const preference of this.preferences) {
        if ((!tenantId || preference.tenant_id === tenantId) && preference.withdrawn_at !== null) {
          const key = `${preference.tenant_id}:${preference.customer_id}`;
          const timestamp = new Date(preference.withdrawn_at).getTime();
          lastWithdrawal.set(key, Math.max(lastWithdrawal.get(key) ?? Number.NEGATIVE_INFINITY, timestamp));
        }
      }
      const deleted = this.consentEvents.filter(row => {
        if (tenantId && row.tenant_id !== tenantId) return false;
        const withdrawal = lastWithdrawal.get(`${row.tenant_id}:${row.customer_id}`);
        return withdrawal !== undefined && withdrawal <= cutoff.getTime();
      });
      this.consentEvents = this.consentEvents.filter(row => !deleted.includes(row));
      return { rows: deleted as T[] };
    }
    // Sessions and hard-delete candidates are empty in this focused fixture.
    return { rows: [] as T[] };
  }
  messageLogIds(): string[] { return this.messageLogs.map(row => row.id); }
  consentEventIds(): string[] { return this.consentEvents.map(row => row.id); }
  release() {}
}

type SessionFixture = { id: string; tenant_id: string; created_at: string; expires_at: string; revoked_at: string | null };

/**
 * DB-free fixture that applies EXACTLY the session predicate of the retention
 * job (`src/retention.ts` runRetention) to artificial timestamps:
 *   - not revoked and expires_at <= now()        -> deleted at expiry (12h TTL),
 *   - revoked and revoked_at <= now() - 7 days   -> deleted 7 days after revocation.
 * `created_at` documents the session "age"; the job decides on expires_at /
 * revoked_at only (an "active" session cannot outlive 7 days under the 12h TTL).
 */
class SessionTtlFixtureDb implements TxClient {
  readonly queries: Array<{ sql: string; params: unknown[] }> = [];
  constructor(
    private readonly now: Date,
    private sessions: SessionFixture[],
  ) {}
  async query<T = unknown>(sql: string, params: unknown[] = []): Promise<{ rows: T[] }> {
    this.queries.push({ sql, params });
    const tenantId = params[0] as string | undefined;
    if (sql.startsWith('delete from sessions')) {
      const cutoff = new Date(this.now.getTime() - 7 * 24 * 60 * 60 * 1000);
      const deleted = this.sessions.filter(session => {
        if (tenantId && session.tenant_id !== tenantId) return false;
        if (session.revoked_at === null) return new Date(session.expires_at) <= this.now;
        return new Date(session.revoked_at) <= cutoff;
      });
      this.sessions = this.sessions.filter(session => !deleted.includes(session));
      return { rows: deleted as T[] };
    }
    return { rows: [] as T[] };
  }
  remainingSessionIds(): string[] { return this.sessions.map(session => session.id).sort(); }
  release() {}
}

const revokedWalletCards: string[] = [];
const wallet: WalletAdapter = {
  async issue() { throw new Error('not used'); },
  async refresh() { throw new Error('not used'); },
  async revoke(card) { revokedWalletCards.push(card.id); },
};

test('retention environment refuses Vercel and validates optional tenant scope', () => {
  expect(parseRetentionEnv({ VERCEL: '1' })).toEqual({ ok: false, errors: ['RETENTION_NOT_ALLOWED_ON_VERCEL'] });
  expect(parseRetentionEnv({ RETENTION_TENANT_ID: 'not-a-uuid' })).toEqual({ ok: false, errors: ['INVALID_RETENTION_TENANT_ID'] });
  expect(parseRetentionEnv({ RETENTION_TENANT_ID: TENANT })).toEqual({ ok: true, value: { tenantId: TENANT } });
});

test('standalone communication retention deletes old rows, keeps younger/null rows, and is idempotent', async () => {
  const oldCustomer = '44444444-4444-4444-8444-444444444444';
  const neverRevokedCustomer = '55555555-5555-4555-8555-555555555555';
  const recentRevocationCustomer = '66666666-6666-4666-8666-666666666666';
  const otherTenantCustomer = '77777777-7777-4777-8777-777777777777';
  const db = new RetentionFixtureDb(
    new Date('2026-09-01T00:00:00Z'),
    [
      { id: 'message-log-old', tenant_id: TENANT, created_at: '2024-08-31T23:59:59Z' },
      { id: 'message-log-young', tenant_id: TENANT, created_at: '2024-09-01T00:00:01Z' },
      { id: 'message-log-other-tenant', tenant_id: OTHER_TENANT, created_at: '2024-08-31T23:59:59Z' },
    ],
    [
      { tenant_id: TENANT, customer_id: oldCustomer, withdrawn_at: '2023-08-31T23:59:59Z' },
      { tenant_id: TENANT, customer_id: neverRevokedCustomer, withdrawn_at: null },
      { tenant_id: TENANT, customer_id: recentRevocationCustomer, withdrawn_at: '2023-09-01T00:00:01Z' },
      { tenant_id: OTHER_TENANT, customer_id: otherTenantCustomer, withdrawn_at: '2023-08-31T23:59:59Z' },
    ],
    [
      { id: 'consent-event-old', tenant_id: TENANT, customer_id: oldCustomer },
      { id: 'consent-event-never-revoked', tenant_id: TENANT, customer_id: neverRevokedCustomer },
      { id: 'consent-event-recent-revocation', tenant_id: TENANT, customer_id: recentRevocationCustomer },
      { id: 'consent-event-other-tenant', tenant_id: OTHER_TENANT, customer_id: otherTenantCustomer },
    ],
  );

  const counts = await runRetention(db, TENANT, wallet);
  expect(counts.messageLogsRetentionDeleted).toBe(1);
  expect(counts.consentEventsRetentionDeleted).toBe(1);
  expect(db.queries[1]?.sql).toContain(`created_at <= now() - interval '${MESSAGE_LOG_RETENTION}'`);
  expect(db.queries[2]?.sql).toContain(`max(p.withdrawn_at) <= now() - interval '${CONSENT_EVENT_RETENTION_AFTER_REVOCATION}'`);
  expect(db.queries[2]?.sql).toContain('max(p.withdrawn_at) is not null');
  expect(db.queries[2]?.sql).toContain('p.tenant_id = e.tenant_id');
  expect(db.queries[2]?.sql).toContain('p.customer_id = e.customer_id');

  // Tenant-scoped execution leaves younger, never-revoked, and other-tenant rows.
  const remainingMessageIds = db.messageLogIds();
  const remainingConsentIds = db.consentEventIds();
  expect(remainingMessageIds).toEqual(['message-log-young', 'message-log-other-tenant']);
  expect(remainingConsentIds).toEqual(['consent-event-never-revoked', 'consent-event-recent-revocation', 'consent-event-other-tenant']);

  const noOp = await runRetention(db, TENANT, wallet);
  expect(noOp.messageLogsRetentionDeleted).toBe(0);
  expect(noOp.consentEventsRetentionDeleted).toBe(0);
});

test('hard delete follows wallet then communication then card FK order and is idempotent', async () => {
  revokedWalletCards.length = 0;
  const db = new FakeDb([
    [{ id: 'expired-session' }], // sessions: expired/revoked-over-7-days
    [], // standalone message-log retention
    [], // standalone consent-event retention
    [{ id: CUSTOMER, tenant_id: TENANT }], // customer candidate: deleted_at > 30 days, hold=false
    [{ id: CARD }], // cards
    [{ id: 'message-log' }],
    [{ id: 'consent-event' }],
    [{ id: 'preference' }],
    [{ id: 'stamp-event' }],
    [{ id: 'reward' }],
    [{ id: 'idempotency-key' }],
    [{ id: CARD }],
    [{ id: CUSTOMER }],
  ]);
  const counts = await runRetention(db, null, wallet);
  expect(revokedWalletCards).toEqual([CARD]);
  expect(counts).toEqual({
    sessionsDeleted: 1, messageLogsRetentionDeleted: 0, consentEventsRetentionDeleted: 0,
    customersHardDeleted: 1, cardsHardDeleted: 1,
    communicationMessageLogsDeleted: 1, communicationConsentEventsDeleted: 1,
    communicationPreferencesDeleted: 1, stampEventsDeleted: 1, rewardsDeleted: 1,
    cardCreationIdempotencyDeleted: 1, walletRevocationAttempts: 1,
  });
  const mutationTables = db.queries
    .filter(q => q.sql.toLowerCase().startsWith('delete from'))
    .map(q => q.sql.match(/delete from\s+([a-z_]+)/i)?.[1]);
  expect(mutationTables).toEqual([
    'sessions', 'communication_message_logs', 'communication_consent_events',
    'communication_message_logs', 'communication_consent_events',
    'communication_preferences', 'stamp_events', 'rewards',
    'card_creation_idempotency', 'cards', 'customers',
  ]);
  expect(db.queries.find(q => q.sql.startsWith('select id, tenant_id from customers'))?.sql).toContain('legal_retention_hold = false');

  const rerun = new FakeDb([
    [], // no expired sessions
    [], // no old message logs
    [], // no old consent events
    [], // no eligible customers
  ]);
  const noOp = await runRetention(rerun, null, wallet);
  expect(noOp.customersHardDeleted).toBe(0);
  expect(noOp.cardsHardDeleted).toBe(0);
  expect(noOp.messageLogsRetentionDeleted).toBe(0);
  expect(noOp.consentEventsRetentionDeleted).toBe(0);
  expect(revokedWalletCards).toEqual([CARD]);
});

test('tenant scope is repeated on standalone retention and hard-delete candidate queries', async () => {
  const db = new FakeDb([[], [], [], []]);
  await runRetention(db, TENANT, wallet);
  expect(db.queries[0]?.params).toEqual([TENANT]);
  expect(db.queries[1]?.params).toEqual([TENANT]);
  expect(db.queries[1]?.sql).toContain('tenant_id = $1');
  expect(db.queries[2]?.params).toEqual([TENANT]);
  expect(db.queries[2]?.sql).toContain('e.tenant_id = $1');
  expect(db.queries[2]?.sql).toContain('p.tenant_id = e.tenant_id');
  expect(db.queries[3]?.params).toEqual([TENANT]);
  expect(db.queries[3]?.sql).toContain('tenant_id = $1');
  expect(db.queries[2]?.sql).not.toContain(OTHER_TENANT);
});

test('retention output is anonymous and includes all counts plus duration', () => {
  const counts: RetentionCounts = {
    sessionsDeleted: 1, messageLogsRetentionDeleted: 2, consentEventsRetentionDeleted: 3,
    customersHardDeleted: 4, cardsHardDeleted: 5,
    communicationMessageLogsDeleted: 6, communicationConsentEventsDeleted: 7,
    communicationPreferencesDeleted: 8, stampEventsDeleted: 9, rewardsDeleted: 10,
    cardCreationIdempotencyDeleted: 11, walletRevocationAttempts: 3,
  };
  const output = formatRetentionResult(counts, 12.4).join('\n');
  expect(output).toContain('duration_ms=12');
  expect(output).toContain('message_logs_retention_deleted=2');
  expect(output).toContain('consent_events_retention_deleted=3');
  expect(output).toContain('customers_hard_deleted=4');
  expect(output).not.toContain(CUSTOMER);
  expect(output).not.toContain('token');
});

describe('retention SQL contracts', () => {
  test('session retention includes active expiry and revoked seven-day cutoff', async () => {
    const db = new FakeDb([[], [], [], []]);
    await runRetention(db, null, wallet);
    expect(db.queries[0]?.sql).toContain('expires_at <= now()');
    expect(db.queries[0]?.sql).toContain("revoked_at <= now() - interval '7 days'");
  });

  test('consent retention uses the latest non-null withdrawal and never deletes never-revoked customers', async () => {
    const db = new FakeDb([[], [], [], []]);
    await runRetention(db, null, wallet);
    const sql = db.queries[2]?.sql ?? '';
    expect(sql).toContain('group by p.tenant_id, p.customer_id');
    expect(sql).toContain('having max(p.withdrawn_at) is not null');
    expect(sql).toContain(`max(p.withdrawn_at) <= now() - interval '${CONSENT_EVENT_RETENTION_AFTER_REVOCATION}'`);
    expect(sql).not.toContain('audit');
  });
});

test('session TTL matrix: active/expired/revoked x age <7d / >7d classifies exactly like the retention job', async () => {
  const NOW = new Date('2026-09-08T00:00:00Z');
  const daysAgo = (n: number) => new Date(NOW.getTime() - n * 24 * 60 * 60 * 1000).toISOString();
  const hoursAhead = (n: number) => new Date(NOW.getTime() + n * 60 * 60 * 1000).toISOString();
  const db = new SessionTtlFixtureDb(NOW, [
    // Status aktiv, Alter <7 Tage: noch im 12-Stunden-TTL-Fenster -> ERHALTEN.
    { id: 's-active-young', tenant_id: TENANT, created_at: daysAgo(0), expires_at: hoursAhead(6), revoked_at: null },
    // Status aktiv/abgelaufen, Alter >7 Tage: 12h-TTL längst abgelaufen -> GELÖSCHT.
    { id: 's-active-old', tenant_id: TENANT, created_at: daysAgo(9), expires_at: daysAgo(8), revoked_at: null },
    // Status abgelaufen, Alter <7 Tage: Löschung sofort bei Ablauf, keine 7-Tage-Schonfrist
    // (die 7-Tage-Frist gilt nur für widerrufene Sessions) -> GELÖSCHT.
    { id: 's-expired-young', tenant_id: TENANT, created_at: daysAgo(1), expires_at: daysAgo(1), revoked_at: null },
    // Status widerrufen, Alter <7 Tage: revoked_at vor 6 Tagen -> ERHALTEN.
    { id: 's-revoked-young', tenant_id: TENANT, created_at: daysAgo(3), expires_at: hoursAhead(6), revoked_at: daysAgo(6) },
    // Status widerrufen, Grenzwert: revoked_at genau 7 Tage (revoked_at <= now()-7d) -> GELÖSCHT.
    { id: 's-revoked-boundary', tenant_id: TENANT, created_at: daysAgo(8), expires_at: hoursAhead(6), revoked_at: daysAgo(7) },
    // Status widerrufen, Alter >7 Tage: revoked_at vor 8 Tagen -> GELÖSCHT.
    { id: 's-revoked-old', tenant_id: TENANT, created_at: daysAgo(9), expires_at: hoursAhead(6), revoked_at: daysAgo(8) },
    // Tenant-Isolation: identisch "widerrufen >7 Tage", aber anderer Tenant -> unberührt.
    { id: 's-other-tenant', tenant_id: OTHER_TENANT, created_at: daysAgo(9), expires_at: hoursAhead(6), revoked_at: daysAgo(8) },
  ]);

  const counts = await runRetention(db, TENANT, wallet);
  expect(counts.sessionsDeleted).toBe(4);
  expect(db.remainingSessionIds()).toEqual(['s-active-young', 's-other-tenant', 's-revoked-young']);
  expect(db.queries[0]?.sql).toContain("revoked_at <= now() - interval '7 days'");
  expect(db.queries[0]?.sql).toContain(`revoked_at <= now() - interval '${REVOKED_SESSION_RETENTION}'`);

  // Idempotenz: der zweite Lauf löscht nichts mehr.
  const again = await runRetention(db, TENANT, wallet);
  expect(again.sessionsDeleted).toBe(0);

  // Globaler Lauf (ohne Tenant-Scope) entfernt auch die andere-Tenant-Zeile,
  // lässt aber die beiden "Alive"-Sessions unangetastet.
  const global = await runRetention(db, null, wallet);
  expect(global.sessionsDeleted).toBe(1);
  expect(db.remainingSessionIds()).toEqual(['s-active-young', 's-revoked-young']);
});

test('CLI is operator-only, takes the retention advisory lock, and logs anonymous duration', async () => {
  const operator = new FakeDb([[{ is_operator: true }]]);
  const transaction = new FakeDb([[], [], [], [], [], [], []]); // begin, lock, sessions, message logs, consent events, candidates, commit
  const connections = [operator, transaction];
  const pool = {
    async connect() { const db = connections.shift(); if (!db) throw new Error('unexpected connection'); return db; },
    async end() {},
  };
  const originalLog = console.log;
  const originalError = console.error;
  const logs: string[] = [];
  console.log = (...args: unknown[]) => logs.push(args.join(' '));
  console.error = (...args: unknown[]) => logs.push(args.join(' '));
  try {
    const { dbRetention } = await import('../src/retention');
    const result = await dbRetention({ DATABASE_URL: 'postgresql://secret.invalid/db' }, () => pool, () => wallet);
    expect(result).toBe(0);
  } finally {
    console.log = originalLog;
    console.error = originalError;
  }
  expect(logs.join('\n')).toContain('retention_ok');
  expect(logs.join('\n')).toContain('duration_ms=');
  expect(logs.join('\n')).not.toContain('secret.invalid');
  expect(transaction.queries.some(q => q.sql.includes('pg_advisory_xact_lock'))).toBe(true);
});
