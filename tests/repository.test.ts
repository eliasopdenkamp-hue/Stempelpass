import { test, expect } from 'bun:test';
import { CardRepository, type DbPool, type TxClient } from '../src/repository';

const TENANT = '11111111-1111-4111-8111-111111111111';
const CUSTOMER = '22222222-2222-4222-8222-222222222222';
const OTHER_TENANT_CUSTOMER = '99999999-9999-4999-8999-999999999999';
const RULE = '33333333-3333-4333-8333-333333333333';
const TOKEN_HASH = 'a'.repeat(64);

/** Minimal in-memory DbPool: each query consumes the next canned row set. */
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

/** Keys that must never appear in any authenticated response payload. */
const INTERNAL_KEYS = ['customerId', 'publicTokenHash', 'tenantId', 'employeeMembershipId', 'quantity', 'reason', 'createdAt', 'customer_id', 'public_token_hash', 'tenant_id', 'employee_membership_id', 'cardId'];
function expectNoInternalFields(value: unknown) {
  const json = JSON.stringify(value);
  for (const key of INTERNAL_KEYS) expect(json).not.toContain(key);
}

test('createCard rejects a customer belonging to another tenant with CUSTOMER_NOT_FOUND and no insert', async () => {
  const pool = new FakePool([
    [], // begin
    [], // set_config app.tenant_id
    [{ customer_limit: 500 }], // tenants select
    [], // customers select -> row missing (foreign tenant)
  ]);
  const repo = new CardRepository(pool);
  await expect(repo.createCard(TENANT, OTHER_TENANT_CUSTOMER, RULE, TOKEN_HASH)).rejects.toThrow('CUSTOMER_NOT_FOUND');
  expect(pool.queries.some(q => q.sql.startsWith('insert into cards'))).toBe(false);
  const tenantContext = pool.queries.findIndex(q => q.sql.includes("set_config('app.tenant_id'"));
  const membershipOrTenantQuery = pool.queries.findIndex(q => q.sql.includes('from tenants'));
  expect(tenantContext).toBe(1);
  expect(pool.queries[tenantContext]?.params).toEqual([TENANT]);
  expect(membershipOrTenantQuery).toBeGreaterThan(tenantContext);
  const customerLookup = pool.queries.find(q => q.sql.includes('from customers'));
  expect(customerLookup?.params).toEqual([OTHER_TENANT_CUSTOMER, TENANT, 'active']);
  expect(pool.queries.some(q => q.sql === 'rollback')).toBe(true);
});

test('createCard rejects an inactive/deleted customer with CUSTOMER_NOT_FOUND', async () => {
  const pool = new FakePool([
    [], // begin
    [], // set_config
    [{ customer_limit: 500 }], // tenants select
    [], // customers select -> row missing (inactive/deleted)
  ]);
  const repo = new CardRepository(pool);
  await expect(repo.createCard(TENANT, CUSTOMER, RULE, TOKEN_HASH)).rejects.toThrow('CUSTOMER_NOT_FOUND');
  expect(pool.queries.some(q => q.sql.startsWith('insert into cards'))).toBe(false);
  // The lookup is tenant-scoped and requires active + not deleted.
  const customerLookup = pool.queries.find(q => q.sql.includes('from customers'));
  expect(customerLookup?.sql).toContain('tenant_id=$2');
  expect(customerLookup?.sql).toContain("status=$3");
  expect(customerLookup?.sql).toContain('deleted_at is null');
});

test('createCard rejects a malformed customer id with CUSTOMER_NOT_FOUND without touching the DB', async () => {
  const pool = new FakePool([]);
  const repo = new CardRepository(pool);
  await expect(repo.createCard(TENANT, 'not-a-uuid', RULE, TOKEN_HASH)).rejects.toThrow('CUSTOMER_NOT_FOUND');
  expect(pool.queries).toHaveLength(0);
});

test('createCard rejects a malformed rule id with RULE_NOT_FOUND without touching the DB', async () => {
  const pool = new FakePool([]);
  const repo = new CardRepository(pool);
  await expect(repo.createCard(TENANT, CUSTOMER, 'bad-rule', TOKEN_HASH)).rejects.toThrow('RULE_NOT_FOUND');
  expect(pool.queries).toHaveLength(0);
});

test('createCard succeeds for a valid active customer of the tenant and inserts the scoped card', async () => {
  const pool = new FakePool([
    [], // begin
    [], // set_config
    [{ customer_limit: 500 }], // tenants select
    [{ id: CUSTOMER }], // customers select -> found
    [{ count: '0' }], // used capacity
    [{ id: RULE }], // rule select
    [{ id: 'card-1', ruleId: RULE, stampCount: 0, revision: 1 }], // insert returning minimal projection
    [], // commit
  ]);
  const repo = new CardRepository(pool);
  const card = await repo.createCard(TENANT, CUSTOMER, RULE, TOKEN_HASH);
  expect(card).toEqual({ id: 'card-1', ruleId: RULE, stampCount: 0, revision: 1 });
  const insert = pool.queries.find(q => q.sql.startsWith('insert into cards'));
  expect(insert?.params).toEqual([TENANT, CUSTOMER, RULE, TOKEN_HASH]);
  expect(insert?.sql).toContain('returning id, rule_id as "ruleId", stamp_count as "stampCount", revision');
  expect(insert?.sql).not.toContain('returning *');
  // The client-facing projection never carries tenant/customer/token internals.
  expectNoInternalFields({ card });
  expect(pool.queries.some(q => q.sql === 'commit')).toBe(true);
});

test('stamp returns only the minimized card view and echoes the client idempotency key', async () => {
  const pool = new FakePool([
    [], // begin
    [], // set_config
    [], // idempotency lookup -> no replay
    [{ id: 'card-1', stampCount: 3, revision: 2, ruleId: RULE }], // card select for update
    [], // insert stamp_event
    [{ id: 'card-1', stampCount: 4, revision: 3 }], // update cards returning
    [{ id: RULE, stamps_required: 5 }], // rule select (threshold not reached)
    [], // commit
  ]);
  const repo = new CardRepository(pool);
  const result = await repo.stamp(TENANT, 'card-1', 1, 'member-1', 'client-key-1');
  expect(result).toEqual({ card: { id: 'card-1', stampCount: 4, revision: 3 }, idempotencyKey: 'client-key-1' });
  expectNoInternalFields(result);
});

test('stamp idempotency replay returns the same minimized shape and does not stamp twice', async () => {
  const pool = new FakePool([
    [], // begin
    [], // set_config
    [{ card_id: 'card-1' }], // idempotency lookup -> replay found
    [{ id: 'card-1', stampCount: 4, revision: 3 }], // replay card view
    [{ id: 'reward-1', status: 'issued' }], // replay reward view
    [], // commit
  ]);
  const repo = new CardRepository(pool);
  const result = await repo.stamp(TENANT, 'card-1', 1, 'member-1', 'client-key-1');
  expect(result).toEqual({ card: { id: 'card-1', stampCount: 4, revision: 3 }, reward: { id: 'reward-1', status: 'issued' }, idempotencyKey: 'client-key-1' });
  // No double stamp: no update on cards, no second stamp_event insert.
  expect(pool.queries.some(q => q.sql.startsWith('update cards'))).toBe(false);
  expect(pool.queries.some(q => q.sql.startsWith('insert into stamp_events'))).toBe(false);
  // The replay never wraps the raw stamp_event row into the response.
  expectNoInternalFields(result);
});

test('stamp without a client idempotency key never replays and stores a fresh unique key', async () => {
  const pool = new FakePool([
    [], // begin
    [], // set_config
    [{ id: 'card-1', stampCount: 0, revision: 1, ruleId: RULE }], // card select for update (no replay lookup at all)
    [], // insert stamp_event
    [{ id: 'card-1', stampCount: 1, revision: 2 }], // update cards returning
    [{ id: RULE, stamps_required: 1 }], // rule select -> threshold reached
    [{ id: 'reward-1', status: 'issued' }], // reward insert returning
    [], // commit
  ]);
  const repo = new CardRepository(pool);
  const result = await repo.stamp(TENANT, 'card-1', 1, 'member-1', null);
  expect(result).toEqual({ card: { id: 'card-1', stampCount: 1, revision: 2 }, reward: { id: 'reward-1', status: 'issued' } });
  // No idempotency key is echoed when the client did not send one.
  expect(result).not.toHaveProperty('idempotencyKey');
  expectNoInternalFields(result);
  // The stored key is a fresh UUID, never the old shared 'missing' sentinel.
  const insert = pool.queries.find(q => q.sql.startsWith('insert into stamp_events'));
  const storedKey = insert?.params?.[4] as string;
  expect(storedKey).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
  expect(storedKey).not.toBe('missing');
  // Without a client key the code must not consult the idempotency table at all.
  expect(pool.queries.some(q => q.sql.includes('from stamp_events'))).toBe(false);
});

test('redeem returns only rewardId and status, never the full reward row', async () => {
  const pool = new FakePool([
    [], // begin
    [], // set_config
    [{ id: 'reward-1', status: 'redeemed' }], // update rewards returning
    [], // commit
  ]);
  const repo = new CardRepository(pool);
  const result = await repo.redeem(TENANT, 'reward-1');
  expect(result).toEqual({ rewardId: 'reward-1', status: 'redeemed' });
  expectNoInternalFields(result);
  const update = pool.queries.find(q => q.sql.startsWith('update rewards'));
  expect(update?.sql).toContain('returning id,status');
  expect(update?.sql).not.toContain('returning *');
});

// ---------------------------------------------------------------------------
// configurePilot — entry-point upsert must return the ACTUALLY PERSISTED
// public_key/join_path (B12). Idempotent by default: a re-configure keeps the
// existing key so old join links never become invalid.
// ---------------------------------------------------------------------------
const ACTOR = '44444444-4444-4444-8444-444444444444';
const PILOT_INPUT = {
  cardTitle: 'Café Herz', cardText: 'Sammle Stempel',
  primaryColor: '#155e75', secondaryColor: '#f8fafc', stampsRequired: 8,
  rewardTitle: 'Gratis Kaffee', rewardDescription: 'Beim 9. Kaffee',
};

test('configurePilot returns the join path of the actually persisted entry point (first configure)', async () => {
  const PERSISTED_KEY = 'e'.repeat(32);
  const pool = new FakePool([
    [], // begin
    [], // set_config app.tenant_id
    [{ customer_limit: 500 }], // tenants for update
    [{ count: '0' }], // used capacity
    [], // update tenants
    [], // branding upsert
    [{ id: RULE }], // stamp_rules insert returning id
    [{ public_key: PERSISTED_KEY, join_path: `/join/${PERSISTED_KEY}` }], // entry-point upsert returning persisted row
    [], // audit
    [], // commit
  ]);
  const repo = new CardRepository(pool);
  const result = await repo.configurePilot(TENANT, ACTOR, { planCode: 'up_to_500', ...PILOT_INPUT });
  expect(result).toEqual({ tenantId: TENANT, planCode: 'up_to_500', customerLimit: 500, ruleId: RULE, joinPath: `/join/${PERSISTED_KEY}` });
  // Contract pin: the response joinPath is the row the upsert returned, and the
  // upsert reads the persisted columns back via RETURNING (never a stale local key).
  const upsert = pool.queries.find(q => q.sql.includes('insert into tenant_entry_points'));
  expect(upsert?.sql).toContain('on conflict(tenant_id) do update set updated_at=now() returning public_key,join_path');
  // The conflict path must never overwrite the existing key (old join links stay valid).
  expect(upsert?.sql).not.toContain('public_key=excluded');
  expect(upsert?.sql).not.toContain('join_path=excluded');
  expect(upsert?.params?.[0]).toBe(TENANT);
  expect(upsert?.params?.[1]).toMatch(/^[0-9a-f]{32}$/);
  expect(upsert?.params?.[2]).toBe(`/join/${upsert?.params?.[1]}`);
  expect(pool.queries.some(q => q.sql === 'commit')).toBe(true);
});

test('configurePilot on re-configure keeps and returns the EXISTING entry point (idempotent, no rotation)', async () => {
  const EXISTING_KEY = 'f'.repeat(32); // persisted by the first configure
  const pool = new FakePool([
    [], // begin
    [], // set_config
    [{ customer_limit: 1000 }], // tenants for update (re-configure: larger plan)
    [{ count: '0' }], // used capacity
    [], // update tenants
    [], // branding upsert
    [{ id: RULE }], // stamp_rules insert
    [{ public_key: EXISTING_KEY, join_path: `/join/${EXISTING_KEY}` }], // conflict → existing row returned
    [], // audit
    [], // commit
  ]);
  const repo = new CardRepository(pool);
  const result = await repo.configurePilot(TENANT, ACTOR, { planCode: 'up_to_1000', ...PILOT_INPUT, cardText: 'Neuer Text' });
  // The response must carry the PERSISTED join path — not the freshly generated
  // (un-persisted) key the upsert params carried. EXISTING_KEY is fixed, so any
  // leak of the random key fails this assertion.
  expect(result.joinPath).toBe(`/join/${EXISTING_KEY}`);
  expect(result.joinPath).toMatch(/^\/join\/[0-9a-f]{32}$/);
  expect(result.planCode).toBe('up_to_1000');
  expect(result.customerLimit).toBe(1000);
  const upsert = pool.queries.find(q => q.sql.includes('insert into tenant_entry_points'));
  expect(upsert?.sql).toContain('returning public_key,join_path');
  expect(upsert?.sql).not.toContain('public_key=excluded');
  // The upsert still attempted the insert with a fresh candidate key (harmless —
  // the conflict discards it in favor of the persisted row).
  expect(upsert?.params?.[1]).toMatch(/^[0-9a-f]{32}$/);
  expect(upsert?.params?.[1]).not.toBe(EXISTING_KEY);
});

test('configurePilot rejects an invalid configuration before any DB access', async () => {
  const pool = new FakePool([]);
  const repo = new CardRepository(pool);
  await expect(repo.configurePilot(TENANT, ACTOR, {
    planCode: 'up_to_500', cardTitle: '', cardText: '', primaryColor: 'red',
    secondaryColor: '#f8fafc', stampsRequired: 0, rewardTitle: '', rewardDescription: '',
  })).rejects.toThrow('INVALID_PILOT_CONFIGURATION');
  expect(pool.queries).toHaveLength(0);
});
