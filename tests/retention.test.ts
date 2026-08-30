import { describe, expect, test } from 'bun:test';
import { formatRetentionResult, parseRetentionEnv, runRetention, type RetentionCounts } from '../src/retention';
import type { TxClient } from '../src/repository';
import type { WalletAdapter } from '../src/wallet';

const TENANT = '11111111-1111-4111-8111-111111111111';
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

test('hard delete follows wallet then communication then card FK order and is idempotent', async () => {
  revokedWalletCards.length = 0;
  const db = new FakeDb([
    [{ id: 'expired-session' }], // sessions: expired/revoked-over-7-days
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
    sessionsDeleted: 1, customersHardDeleted: 1, cardsHardDeleted: 1,
    communicationMessageLogsDeleted: 1, communicationConsentEventsDeleted: 1,
    communicationPreferencesDeleted: 1, stampEventsDeleted: 1, rewardsDeleted: 1,
    cardCreationIdempotencyDeleted: 1, walletRevocationAttempts: 1,
  });
  const mutationTables = db.queries
    .filter(q => q.sql.toLowerCase().startsWith('delete from'))
    .map(q => q.sql.match(/delete from\s+([a-z_]+)/i)?.[1]);
  expect(mutationTables).toEqual([
    'sessions', 'communication_message_logs', 'communication_consent_events',
    'communication_preferences', 'stamp_events', 'rewards',
    'card_creation_idempotency', 'cards', 'customers',
  ]);
  expect(db.queries.find(q => q.sql.startsWith('select id, tenant_id from customers'))?.sql).toContain('legal_retention_hold = false');

  const rerun = new FakeDb([
    [], // no expired sessions
    [], // no eligible customers
  ]);
  const noOp = await runRetention(rerun, null, wallet);
  expect(noOp.customersHardDeleted).toBe(0);
  expect(noOp.cardsHardDeleted).toBe(0);
  expect(revokedWalletCards).toEqual([CARD]);
});

test('tenant scope is repeated on candidate and child DML', async () => {
  const db = new FakeDb([[], []]);
  await runRetention(db, TENANT, wallet);
  expect(db.queries[0]?.params).toEqual([TENANT]);
  expect(db.queries[1]?.params).toEqual([TENANT]);
  expect(db.queries[1]?.sql).toContain('tenant_id = $1');
});

test('retention output is anonymous and includes counts plus duration', () => {
  const counts: RetentionCounts = {
    sessionsDeleted: 1, customersHardDeleted: 2, cardsHardDeleted: 3,
    communicationMessageLogsDeleted: 4, communicationConsentEventsDeleted: 5,
    communicationPreferencesDeleted: 6, stampEventsDeleted: 7, rewardsDeleted: 8,
    cardCreationIdempotencyDeleted: 9, walletRevocationAttempts: 3,
  };
  const output = formatRetentionResult(counts, 12.4).join('\n');
  expect(output).toContain('duration_ms=12');
  expect(output).toContain('customers_hard_deleted=2');
  expect(output).not.toContain(CUSTOMER);
  expect(output).not.toContain('token');
});

describe('retention SQL contracts', () => {
  test('session retention includes active expiry and revoked seven-day cutoff', async () => {
    const db = new FakeDb([[], []]);
    await runRetention(db, null, wallet);
    expect(db.queries[0]?.sql).toContain('expires_at <= now()');
    expect(db.queries[0]?.sql).toContain("revoked_at <= now() - interval '7 days'");
  });
});

test('CLI is operator-only, takes the retention advisory lock, and logs anonymous duration', async () => {
  const operator = new FakeDb([[{ is_operator: true }]]);
  const transaction = new FakeDb([[], [], [], [], []]); // begin, lock, sessions, candidates, commit
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
