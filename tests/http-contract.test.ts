import { test, expect } from 'bun:test';
import { CardRepository, type DbPool, type TxClient } from '../src/repository';
import { cardResolveLimiter, hashPassword, hashSessionToken, loginAccountLimiter, loginIpLimiter, randomToken } from '../src/security';

/**
 * HTTP-level contract tests against the REAL fetchHandler.
 *
 * These tests exercise the actual request router, auth flow, CSRF checks,
 * response envelopes and contract mappers — not just the repository layer.
 * No database is used: the server module is imported with a scrubbed
 * environment (VERCEL=1, no DATABASE_URL/credentials), so it boots
 * NOT_CONFIGURED and never touches Neon; `withTestDependencies` then injects
 * a scripted in-memory DbPool. No real credentials or secrets are involved.
 *
 * CSRF contract pinned here (fixes discovered while writing these tests):
 *   - `csrfValid(req, expected)` compares the raw `x-csrf-token` header
 *     against the session's stored `csrf_token_hash` (see tests/security.test.ts).
 *   - Login returns `csrfToken` = the stored-hash value the client must
 *     submit verbatim in `x-csrf-token`.
 *   - Every mutating response that rotates the session (`stamps`, `redeem`)
 *     delivers the fresh CSRF value in the `x-csrf-token` RESPONSE header so
 *     the client can continue without re-login.
 */

// --- boot: scrub every secret/config var BEFORE importing the server module ---
const SCRUBBED_KEYS = [
  'DATABASE_URL', 'TEST_DATABASE_URL', 'SESSION_SECRET', 'MFA_ENCRYPTION_KEY',
  'GOOGLE_ISSUER_ID', 'GOOGLE_SERVICE_ACCOUNT_JSON', 'GOOGLE_SERVICE_ACCOUNT_EMAIL',
  'GOOGLE_PRIVATE_KEY', 'GOOGLE_EXTERNAL_ACCOUNT_JSON', 'GOOGLE_APPLICATION_CREDENTIALS',
  'VERCEL_OIDC_TOKEN', 'APPLE_TEAM_IDENTIFIER', 'APPLE_PASS_TYPE_IDENTIFIER', 'APPLE_PRIVATE_KEY',
  'TIGER_PUBLIC_KEY', 'TIGER_SECRET_KEY', 'TIGER_PROJECT_ID',
  'EMAIL_SMTP_HOST', 'EMAIL_SMTP_PORT', 'EMAIL_SMTP_USER', 'EMAIL_SMTP_PASSWORD', 'EMAIL_FROM',
  'COMMUNICATION_HASH_SECRET', 'PORT', 'PILOT_READY',
];
for (const key of SCRUBBED_KEYS) delete process.env[key];
process.env.VERCEL = '1';

const { fetchHandler, withTestDependencies } = await import('../src/server');

// --- fixtures ---
const TENANT = '11111111-1111-4111-8111-111111111111';
const OTHER_TENANT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const CUSTOMER = '22222222-2222-4222-8222-222222222222';
const RULE = '33333333-3333-4333-8333-333333333333';
const USER_ID = '44444444-4444-4444-8444-444444444444';
const MEMBERSHIP = '55555555-5555-4555-8555-555555555555';

const SESSION_TOKEN = randomToken();
const SESSION_HASH = hashSessionToken(SESSION_TOKEN);
/** The CSRF value the client holds — identical to the stored hash (see header comment). */
const CSRF_VALUE = hashSessionToken(randomToken());
const PASSWORD = 'correct horse battery staple';
const passwordHash = await hashPassword(PASSWORD);

/** Never allowed in any authenticated/public response payload. */
const AUTH_INTERNAL_MARKERS = [
  'customerId', 'publicTokenHash', 'tenantId', 'employeeMembershipId',
  'quantity', 'reason', 'createdAt', 'public_token_hash', 'customer_id',
  'tenant_id', 'employee_membership_id',
];

function expectNoInternalFields(value: unknown) {
  const raw = JSON.stringify(value);
  for (const marker of AUTH_INTERNAL_MARKERS) expect(raw).not.toContain(marker);
}

/** Scripted in-memory pool: first matching handler supplies the rows. */
interface FakeHandler {
  match: (sql: string, params: unknown[]) => boolean;
  rows: unknown[] | ((sql: string, params: unknown[]) => unknown[]);
}
class FakePool implements DbPool {
  queries: Array<{ sql: string; params: unknown[] }> = [];
  constructor(private readonly handlers: FakeHandler[]) {}
  async connect(): Promise<TxClient> {
    const self = this;
    return {
      async query<T = unknown>(sql: string, params: unknown[] = []): Promise<{ rows: T[] }> {
        self.queries.push({ sql, params });
        const handler = self.handlers.find((h) => h.match(sql, params));
        if (!handler) return { rows: [] };
        const rows = typeof handler.rows === 'function' ? handler.rows(sql, params) : handler.rows;
        return { rows: rows as T[] };
      },
      release() {},
    };
  }
}

const contains = (needle: string): FakeHandler['match'] => (sql) => sql.includes(needle);

function sessionRow(overrides: Record<string, unknown> = {}) {
  return {
    id: 'sess-1', user_id: USER_ID, csrf_token_hash: CSRF_VALUE, tenant_id: TENANT,
    role: 'staff', membership_id: MEMBERSHIP, mfa_required: false, mfa_verified: true,
    ...overrides,
  };
}

/** Base handlers for any authenticated route: identity bootstrap (migration
 *  009 resolver), session lookup + session rotation. The resolver handler MUST
 *  come first: it returns the owning user_id for the presented token hash and
 *  auth() fails fast (UNAUTHENTICATED) before any session row is read when it
 *  yields nothing. */
function sessionHandlers(sessionSource: (sql: string, params: unknown[]) => unknown[]): FakeHandler[] {
  return [
    { match: contains('resolve_session_user'), rows: (_sql, params) => params[0] === SESSION_HASH ? [{ user_id: USER_ID }] : [] },
    { match: contains('from sessions'), rows: sessionSource },
    { match: contains('update sessions set revoked_at=now() where token_hash'), rows: [] },
    { match: contains('insert into sessions'), rows: [] },
  ];
}

/** Standard valid-session source: row only when the presented token hash matches. */
const validSession: (sql: string, params: unknown[]) => unknown[] = (_sql, params) =>
  params[0] === SESSION_HASH ? [sessionRow()] : [];

function runWith(pool: DbPool, fn: () => Promise<unknown>): Promise<unknown> {
  const restore = withTestDependencies({ configured: true, pool, repository: new CardRepository(pool) });
  return fn().finally(restore);
}

function authedHeaders(overrides: Record<string, string> = {}): Headers {
  return new Headers({
    cookie: `__Host-sp_session=${SESSION_TOKEN}`,
    'x-csrf-token': CSRF_VALUE,
    'content-type': 'application/json',
    ...overrides,
  });
}

// ---------------------------------------------------------------------------
// (1) GET /health — only the generic status, no request id, no config details
// ---------------------------------------------------------------------------
test('GET /health over the real fetchHandler exposes only the generic status', async () => {
  const restore = withTestDependencies({ configured: false });
  try {
    const res = await fetchHandler(new Request('http://test.local/health'));
    expect(res.status).toBe(200);
    const raw = await res.text();
    expect(raw).toBe('{"status":"not_ready"}');
    expect(raw).not.toContain('request_id');
    expect(raw).not.toContain('DATABASE');
    expect(raw).not.toContain('SESSION');
    expect(raw).not.toContain('wallet');
    // Byte-stable across calls.
    expect(await (await fetchHandler(new Request('http://test.local/health'))).text()).toBe(raw);
  } finally {
    restore();
  }

  const restoreReady = withTestDependencies({ configured: true, pool: new FakePool([]), repository: new CardRepository(new FakePool([])) });
  try {
    const res = await fetchHandler(new Request('http://test.local/health'));
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('{"status":"ready"}');
  } finally {
    restoreReady();
  }
});

// ---------------------------------------------------------------------------
// (2) Public card JSON — never customerId / publicTokenHash
// ---------------------------------------------------------------------------
test('public card JSON exposes only allowlisted fields, never customerId/publicTokenHash', async () => {
  const fullCardRow = {
    id: 'card-1', tenantId: TENANT, customerId: CUSTOMER, publicTokenHash: 'f'.repeat(64),
    status: 'active', stampCount: 3, revision: 2, ruleId: RULE,
  };
  const pool = new FakePool([
    { match: contains('from cards where'), rows: [fullCardRow] },
    { match: contains('from tenant_branding'), rows: [{ cardTitle: 'StempelPass Demo', cardText: 'Deine Karte', primaryColor: '#155e75', secondaryColor: '#f8fafc', version: 1 }] },
    { match: contains('from stamp_rules'), rows: [{ id: RULE, tenantId: TENANT, name: 'R', stampsRequired: 5, rewardTitle: 'Prämie', rewardDescription: 'D', active: true, version: 1 }] },
    { match: contains('from rewards'), rows: [{ id: 'reward-1', status: 'issued', issuedAt: null, redeemedAt: null }] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/public/tenants/${TENANT}/cards/public-token-abc`));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { request_id: string; data: Record<string, unknown> };
    expect(Object.keys(body).sort()).toEqual(['data', 'request_id']);
    expect(body.data).toEqual({
      cardId: 'card-1', tenantId: TENANT, stampCount: 3, revision: 2,
      branding: { cardTitle: 'StempelPass Demo', cardText: 'Deine Karte', primaryColor: '#155e75', secondaryColor: '#f8fafc', version: 1 },
      rule: { id: RULE, tenantId: TENANT, name: 'R', stampsRequired: 5, rewardTitle: 'Prämie', rewardDescription: 'D', active: true, version: 1 },
      reward: { id: 'reward-1', status: 'issued', issuedAt: null, redeemedAt: null },
    });
    const raw = JSON.stringify(body);
    expect(raw).not.toContain('customerId');
    expect(raw).not.toContain('publicTokenHash');
    expect(raw).not.toContain('public_token_hash');
    expect(raw).not.toContain('customer_id');
    expect(raw).not.toContain('"status":"active"');
  });
});
// ---------------------------------------------------------------------------
// (2b) GET /join/:publicKey — RLS-safe resolution through the resolver function
// ---------------------------------------------------------------------------
const JOIN_KEY = 'c'.repeat(32); // valid 32-hex public key
test('GET /join/:publicKey returns exactly the join contract for the given key', async () => {
  const pool = new FakePool([
    { match: contains('resolve_entry_point'), rows: [{ tenant_id: TENANT, join_path: `/join/${JOIN_KEY}` }] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/join/${JOIN_KEY}`));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { request_id: string; data: Record<string, unknown> };
    expect(Object.keys(body).sort()).toEqual(['data', 'request_id']);
    expect(body.data).toEqual({
      tenantId: TENANT,
      joinPath: `/join/${JOIN_KEY}`,
      customerLoginRequired: false,
      customerAccountRequired: false,
    });
    const raw = JSON.stringify(body);
    expect(raw).not.toContain('public_key');
    expect(raw).not.toContain('resolve_entry_point');
  });
});
test('GET /join/:publicKey with an unknown key yields 404 ENTRY_POINT_NOT_FOUND', async () => {
  const pool = new FakePool([
    { match: contains('resolve_entry_point'), rows: [] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/join/${'d'.repeat(32)}`));
    expect(res.status).toBe(404);
    expect(((await res.json()) as { data: { error: string } }).data.error).toBe('ENTRY_POINT_NOT_FOUND');
  });
});
test('GET /join/:publicKey with a malformed key never touches the database', async () => {
  const pool = new FakePool([]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/join/not-a-valid-key'));
    expect(res.status).toBe(404);
    expect(((await res.json()) as { data: { error: string } }).data.error).toBe('ENTRY_POINT_NOT_FOUND');
    expect(pool.queries.length).toBe(0);
  });
});
test('GET /join/:publicKey database failure maps to INTERNAL_ERROR without leaking the message', async () => {
  const pool = new FakePool([
    { match: contains('resolve_entry_point'), rows: () => { throw new Error('resolve failed for tenant x@secret.internal dsn=postgres://u:p@h/db'); } },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/join/${JOIN_KEY}`));
    expect(res.status).toBe(500);
    const raw = await res.text();
    expect(((JSON.parse(raw)) as { data: { error: string } }).data.error).toBe('INTERNAL_ERROR');
    expect(raw).not.toContain('secret.internal');
    expect(raw).not.toContain('postgres://');
    expect(raw).not.toContain('u:p@');
  });
});
test('GET /join/:publicKey is rate limited per client+path (429 RATE_LIMITED)', async () => {
  cardResolveLimiter.clear();
  const pool = new FakePool([
    { match: contains('resolve_entry_point'), rows: [{ tenant_id: TENANT, join_path: `/join/${JOIN_KEY}` }] },
  ]);
  await runWith(pool, async () => {
    let statuses: number[] = [];
    for (let i = 0; i < 61; i++) {
      statuses.push((await fetchHandler(new Request(`http://test.local/join/${JOIN_KEY}`))).status);
    }
    expect(statuses.filter(s => s === 200)).toHaveLength(60);
    expect(statuses[60]).toBe(429);
    const body = (await (await fetchHandler(new Request(`http://test.local/join/${JOIN_KEY}`))).json()) as { data: { error: string } };
    expect(body.data.error).toBe('RATE_LIMITED');
  });
});

// ---------------------------------------------------------------------------
// (3) Login success — only csrfToken + mfaRequired, session cookie set
// ---------------------------------------------------------------------------
test('login success returns exactly the allowed fields and sets the session cookie', async () => {
  const pool = new FakePool([
    { match: contains('from users where'), rows: [{ id: USER_ID, password_hash: passwordHash, mfa_required: false, mfa_enabled: false, mfa_secret_ciphertext: null }] },
    { match: contains('membership_mfa_required'), rows: [{ required: false }] },
    { match: contains('update sessions set revoked_at=now() where user_id'), rows: [] },
    { match: contains('insert into sessions'), rows: [] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.10' },
      body: JSON.stringify({ email: 'owner@example.com', password: PASSWORD }),
    }));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { request_id: string; data: { csrfToken?: unknown; mfaRequired?: unknown; [k: string]: unknown } };
    expect(Object.keys(body).sort()).toEqual(['data', 'request_id']);
    expect(Object.keys(body.data).sort()).toEqual(['csrfToken', 'mfaRequired']);
    expect(body.data.csrfToken).toMatch(/^[0-9a-f]{64}$/); // stored-hash form the client submits verbatim
    expect(body.data.mfaRequired).toBe(false);
    const setCookie = res.headers.get('set-cookie') ?? '';
    expect(setCookie).toContain('__Host-sp_session=');
    expect(setCookie).toContain('HttpOnly');
    expect(setCookie).toContain('Secure');
    expect(setCookie).toContain('SameSite=Lax');
    expect(setCookie).toContain('Path=/');
    expect(setCookie).toContain('Max-Age=43200');
    // __Host- prefix contract: Secure + Path=/ + no Domain attribute, and no bare name.
    expect(setCookie).toMatch(/^__Host-sp_session=/);
    expect(setCookie).not.toContain('Domain=');
    expect(setCookie).not.toMatch(/(^|; )sp_session=/);
    const raw = JSON.stringify(body);
    expect(raw).not.toContain('owner@example.com');
    expect(raw).not.toContain(PASSWORD);
    expect(raw).not.toContain('password_hash');
  });
});

// ---------------------------------------------------------------------------
// (4) Login failures — unified INVALID_CREDENTIALS, no internal reason leak
// ---------------------------------------------------------------------------
test('login failures collapse to the single INVALID_CREDENTIALS contract', async () => {
  // Wrong password for an existing account.
  const wrongPasswordPool = new FakePool([
    { match: contains('from users where'), rows: [{ id: USER_ID, password_hash: passwordHash, mfa_required: false, mfa_enabled: false, mfa_secret_ciphertext: null }] },
  ]);
  await runWith(wrongPasswordPool, async () => {
    const res = await fetchHandler(new Request('http://test.local/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.11' },
      body: JSON.stringify({ email: 'owner@example.com', password: 'wrong password long enough' }),
    }));
    expect(res.status).toBe(400);
    const body = (await res.json()) as { request_id: string; data: { error: string } };
    expect(Object.keys(body).sort()).toEqual(['data', 'request_id']);
    expect(body.data.error).toBe('INVALID_CREDENTIALS');
    const raw = JSON.stringify(body);
    for (const code of ['MFA_NOT_CONFIGURED', 'MFA_INVALID', 'MFA_SECRET_DECRYPT_FAILED', 'MFA_BOOTSTRAP_UNVERIFIED', 'INVALID_CREDENTIALS_']) {
      expect(raw).not.toContain(code);
    }
  });

  // Unknown account (dummy-verify path): same unified response.
  const unknownPool = new FakePool([
    { match: contains('from users where'), rows: [] },
  ]);
  await runWith(unknownPool, async () => {
    const res = await fetchHandler(new Request('http://test.local/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.12' },
      body: JSON.stringify({ email: 'nobody@example.com', password: PASSWORD }),
    }));
    expect(res.status).toBe(400);
    const body = (await res.json()) as { request_id: string; data: { error: string } };
    expect(Object.keys(body).sort()).toEqual(['data', 'request_id']);
    expect(body.data.error).toBe('INVALID_CREDENTIALS');
    expect(JSON.stringify(body)).not.toContain('nobody@example.com');
  });
});

test('login with missing credentials is rejected before any account lookup', async () => {
  const pool = new FakePool([]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.13' },
      body: JSON.stringify({ email: 'owner@example.com' }),
    }));
    expect(res.status).toBe(400);
    expect(((await res.json()) as { data: { error: string } }).data.error).toBe('CREDENTIALS_REQUIRED');
    expect(pool.queries.some((q) => q.sql.includes('from users'))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// (5) Authenticated card creation — minimal projection, no internals
// ---------------------------------------------------------------------------
test('POST cards returns the minimal projection plus the one-time raw card token', async () => {
  const pool = new FakePool([
    ...sessionHandlers(validSession),
    { match: contains('from tenants'), rows: [{ customer_limit: 500 }] },
    { match: contains('from customers'), rows: [{ id: CUSTOMER }] },
    { match: contains('count(distinct customer_id)'), rows: [{ count: '0' }] },
    { match: contains('from stamp_rules'), rows: [{ id: RULE }] },
    { match: contains('insert into cards'), rows: [{ id: 'card-1', ruleId: RULE, stampCount: 0, revision: 1 }] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/cards`, {
      method: 'POST',
      headers: authedHeaders(),
      body: JSON.stringify({ customerId: CUSTOMER, ruleId: RULE }),
    }));
    expect(res.status).toBe(201);
    const body = (await res.json()) as { data: { card: Record<string, unknown>; cardToken: string } };
    expect(body.data.card).toEqual({ id: 'card-1', ruleId: RULE, stampCount: 0, revision: 1 });
    // Fresh raw token (32 random bytes, unpadded base64url) — usable as /card/:tenantId/:cardToken.
    expect(body.data.cardToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expectNoInternalFields(body);
    // Only the SHA-256 hash of the token may reach the database — never the raw token.
    const insert = pool.queries.find((q) => q.sql.startsWith('insert into cards'));
    expect(insert).toBeDefined();
    const stored = insert!.params[3] as string;
    expect(stored).toMatch(/^[a-f0-9]{64}$/);
    expect(stored).not.toBe(body.data.cardToken);
    expect(JSON.stringify(pool.queries)).not.toContain(body.data.cardToken);
  });
});

test('POST cards without customerId/ruleId is rejected with CARD_FIELDS_REQUIRED', async () => {
  const pool = new FakePool([...sessionHandlers(validSession)]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/cards`, {
      method: 'POST',
      headers: authedHeaders(),
      body: JSON.stringify({ quantity: 1 }),
    }));
    expect(res.status).toBe(400);
    expect(((await res.json()) as { data: { error: string } }).data.error).toBe('CARD_FIELDS_REQUIRED');
    expect(pool.queries.some((q) => q.sql.startsWith('insert into cards'))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// (6) Stamp — normal and idempotency replay return the identical minimal shape
// ---------------------------------------------------------------------------
const EXPECTED_STAMP_DATA = {
  card: { id: 'card-1', stampCount: 4, revision: 3 },
  reward: { id: 'reward-1', status: 'issued' },
  idempotencyKey: 'client-key-1',
};

test('stamp returns the minimal card/reward view, echoes the idempotency key and rotates the session', async () => {
  const pool = new FakePool([
    ...sessionHandlers(validSession),
    { match: contains('from stamp_events'), rows: [] }, // no replay
    { match: contains('from cards where'), rows: [{ id: 'card-1', stampCount: 3, revision: 2, ruleId: RULE }] },
    { match: contains('insert into stamp_events'), rows: [] },
    { match: contains('update cards set stamp_count'), rows: [{ id: 'card-1', stampCount: 4, revision: 3 }] },
    { match: contains('from stamp_rules'), rows: [{ id: RULE, stamps_required: 1 }] },
    { match: contains('insert into rewards'), rows: [{ id: 'reward-1', status: 'issued' }] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/cards/card-1/stamps`, {
      method: 'POST',
      headers: authedHeaders({ 'idempotency-key': 'client-key-1' }),
      body: JSON.stringify({ quantity: 1 }),
    }));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: unknown };
    expect(body.data).toEqual(EXPECTED_STAMP_DATA);
    expectNoInternalFields(body);
    // Session rotation: fresh Set-Cookie AND the fresh CSRF value the client must reuse.
    expect(res.headers.get('set-cookie')).toContain('__Host-sp_session=');
    const rotatedCsrf = res.headers.get('x-csrf-token');
    expect(rotatedCsrf).toMatch(/^[0-9a-f]{64}$/);
    expect(rotatedCsrf).not.toBe(CSRF_VALUE);
  });
});

test('stamp idempotency replay returns the identical minimal response without stamping twice', async () => {
  const pool = new FakePool([
    ...sessionHandlers(validSession),
    { match: contains('from stamp_events'), rows: [{ card_id: 'card-1' }] }, // replay found
    { match: contains('from cards where'), rows: [{ id: 'card-1', stampCount: 4, revision: 3 }] },
    { match: contains('from rewards'), rows: [{ id: 'reward-1', status: 'issued' }] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/cards/card-1/stamps`, {
      method: 'POST',
      headers: authedHeaders({ 'idempotency-key': 'client-key-1' }),
      body: JSON.stringify({ quantity: 1 }),
    }));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: unknown };
    expect(body.data).toEqual(EXPECTED_STAMP_DATA); // identical to the normal stamp
    expectNoInternalFields(body);
    // Replay must not write anything.
    expect(pool.queries.some((q) => q.sql.startsWith('update cards'))).toBe(false);
    expect(pool.queries.some((q) => q.sql.startsWith('insert into stamp_events'))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// (7) Redeem — minimal response, never a full rewards row
// ---------------------------------------------------------------------------
test('redeem returns only rewardId and status', async () => {
  const pool = new FakePool([
    ...sessionHandlers(validSession),
    { match: contains('update rewards set status'), rows: [{ id: 'reward-1', status: 'redeemed' }] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/rewards/reward-1/redeem`, {
      method: 'POST',
      headers: authedHeaders(),
    }));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: unknown };
    expect(body.data).toEqual({ rewardId: 'reward-1', status: 'redeemed' });
    expectNoInternalFields(body);
  });
});

// ---------------------------------------------------------------------------
// (8) Missing / invalid session
// ---------------------------------------------------------------------------
test('missing session cookie yields UNAUTHENTICATED without touching tenant data', async () => {
  const pool = new FakePool([]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/capacity`));
    expect(res.status).toBe(401);
    expect(((await res.json()) as { data: { error: string } }).data.error).toBe('UNAUTHENTICATED');
    expect(pool.queries).toHaveLength(0); // rejected before any DB query
  });
});

test('invalid/forged session token yields UNAUTHENTICATED', async () => {
  const pool = new FakePool([...sessionHandlers(validSession)]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/capacity`, {
      headers: { cookie: '__Host-sp_session=forged-session-value' },
    }));
    expect(res.status).toBe(401);
    expect(((await res.json()) as { data: { error: string } }).data.error).toBe('UNAUTHENTICATED');
    // The forged token never resolves to a user, so no session row is read
    // at all (auth fails at the identity bootstrap, before the RLS-scoped read).
    expect(pool.queries.some(q => q.sql.includes('from sessions'))).toBe(false);
  });
});

test('authenticated requests set the user context before any session row is read', async () => {
  const pool = new FakePool([
    ...sessionHandlers(validSession),
    { match: contains('from tenants'), rows: [{ plan_code: 'up_to_500', customer_limit: 500 }] },
    { match: contains('count(distinct customer_id)'), rows: [{ count: '0' }] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/capacity`, {
      headers: { cookie: `__Host-sp_session=${SESSION_TOKEN}` },
    }));
    expect(res.status).toBe(200);
    const sqls = pool.queries.map(q => q.sql);
    const resolverIdx = sqls.findIndex(s => s.includes('resolve_session_user'));
    const userCtxIdx = sqls.findIndex(s => s.includes("set_config('app.user_id'"));
    const sessionReadIdx = sqls.findIndex(s => s.includes('from sessions'));
    expect(resolverIdx).toBeGreaterThan(-1);
    expect(userCtxIdx).toBeGreaterThan(resolverIdx);
    expect(sessionReadIdx).toBeGreaterThan(userCtxIdx);
    // The user context carries exactly the resolved owning user id.
    expect(pool.queries[userCtxIdx]?.params).toEqual([USER_ID]);
    // The bootstrap only ever resolves user_id — never session secrets.
    expect(pool.queries[resolverIdx]?.sql).toBe('select user_id from public.resolve_session_user($1)');
    expect(pool.queries[resolverIdx]?.params).toEqual([SESSION_HASH]);
  });
});

test('login sets the user context before revoking/creating session rows', async () => {
  const pool = new FakePool([
    { match: contains('from users where'), rows: [{ id: USER_ID, password_hash: passwordHash, mfa_required: false, mfa_enabled: false, mfa_secret_ciphertext: null }] },
    { match: contains('membership_mfa_required'), rows: [{ required: false }] },
    { match: contains('update sessions set revoked_at=now() where user_id'), rows: [] },
    { match: contains('insert into sessions'), rows: [] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.20' },
      body: JSON.stringify({ email: 'owner@example.com', password: PASSWORD }),
    }));
    expect(res.status).toBe(200);
    const sqls = pool.queries.map(q => q.sql);
    const userCtxIdx = sqls.findIndex(s => s.includes("set_config('app.user_id'"));
    const revokeIdx = sqls.findIndex(s => s.includes('update sessions set revoked_at=now() where user_id'));
    const insertIdx = sqls.findIndex(s => s.includes('insert into sessions'));
    expect(userCtxIdx).toBeGreaterThan(-1);
    expect(revokeIdx).toBeGreaterThan(userCtxIdx);
    expect(insertIdx).toBeGreaterThan(revokeIdx);
    expect(pool.queries[userCtxIdx]?.params).toEqual([USER_ID]);
    expect(pool.queries.some(q => q.sql === 'commit')).toBe(true);
  });
});

test('logout revokes the session under the actor user context and clears the cookie', async () => {
  const pool = new FakePool([...sessionHandlers(validSession)]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/logout`, {
      method: 'POST',
      headers: authedHeaders(),
    }));
    expect(res.status).toBe(200);
    expect(((await res.json()) as { data: unknown }).data).toEqual({ loggedOut: true });
    expect(res.headers.get('set-cookie')).toContain('__Host-sp_session=;');
    const sqls = pool.queries.map(q => q.sql);
    const userCtxIdx = sqls.findIndex(s => s.includes("set_config('app.user_id'"));
    const revokeIdx = sqls.findIndex(s => s.includes('update sessions set revoked_at=now() where token_hash'));
    expect(userCtxIdx).toBeGreaterThan(-1);
    expect(revokeIdx).toBeGreaterThan(userCtxIdx);
    expect(pool.queries[revokeIdx]?.params).toEqual([SESSION_HASH]);
  });
});

// ---------------------------------------------------------------------------
// (9) CSRF protection
// ---------------------------------------------------------------------------
test('mutating requests without a CSRF token are rejected', async () => {
  const pool = new FakePool([...sessionHandlers(validSession)]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/cards/card-1/stamps`, {
      method: 'POST',
      headers: { cookie: `__Host-sp_session=${SESSION_TOKEN}`, 'content-type': 'application/json' },
      body: JSON.stringify({ quantity: 1 }),
    }));
    expect(res.status).toBe(400);
    expect(((await res.json()) as { data: { error: string } }).data.error).toBe('CSRF_INVALID');
    expect(pool.queries.some((q) => q.sql.startsWith('insert into stamp_events'))).toBe(false);
  });
});

test('mutating requests with a wrong CSRF token are rejected', async () => {
  const pool = new FakePool([...sessionHandlers(validSession)]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/cards/card-1/stamps`, {
      method: 'POST',
      headers: authedHeaders({ 'x-csrf-token': '0'.repeat(64) }),
      body: JSON.stringify({ quantity: 1 }),
    }));
    expect(res.status).toBe(400);
    expect(((await res.json()) as { data: { error: string } }).data.error).toBe('CSRF_INVALID');
    expect(pool.queries.some((q) => q.sql.startsWith('insert into stamp_events'))).toBe(false);
  });
});

test('read-only (GET) requests work without a CSRF token', async () => {
  const pool = new FakePool([
    ...sessionHandlers(validSession),
    { match: contains('from tenants'), rows: [{ plan_code: 'up_to_500', customer_limit: 500 }] },
    { match: contains('count(distinct customer_id)'), rows: [{ count: '1' }] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/capacity`, {
      headers: { cookie: `__Host-sp_session=${SESSION_TOKEN}` },
    }));
    expect(res.status).toBe(200);
    expect(((await res.json()) as { data: { plan: string; limit: number; used: number; remaining: number } }).data).toEqual({
      plan: 'up_to_500', limit: 500, used: 1, remaining: 499,
    });
  });
});

// ---------------------------------------------------------------------------
// (10) Cross-tenant protection
// ---------------------------------------------------------------------------
test('a session bound to another tenant is rejected (RLS-filtered session lookup → UNAUTHENTICATED)', async () => {
  // The real session query is tenant-scoped (m.tenant_id=$3), so a session from
  // another tenant yields no row at all — exactly like RLS filtering.
  const tenantScopedSession: (sql: string, params: unknown[]) => unknown[] = (_sql, params) =>
    params[0] === SESSION_HASH && params[2] === TENANT ? [sessionRow()] : [];
  const pool = new FakePool([...sessionHandlers(tenantScopedSession)]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/tenants/${OTHER_TENANT}/capacity`, {
      headers: { cookie: `__Host-sp_session=${SESSION_TOKEN}` },
    }));
    expect(res.status).toBe(401);
    expect(((await res.json()) as { data: { error: string } }).data.error).toBe('UNAUTHENTICATED');
  });
});

test('even if a lookup leaks a foreign session row, the tenant assertion blocks it (TENANT_CONTEXT_REQUIRED)', async () => {
  // Simulates a DB without RLS: the session query returns the row regardless of
  // the requested tenant, so assertTenant is the last line of defense.
  const leakySession: (sql: string, params: unknown[]) => unknown[] = (_sql, params) =>
    params[0] === SESSION_HASH ? [sessionRow()] : [];
  const pool = new FakePool([...sessionHandlers(leakySession)]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/tenants/${OTHER_TENANT}/capacity`, {
      headers: { cookie: `__Host-sp_session=${SESSION_TOKEN}` },
    }));
    expect(res.status).toBe(403);
    expect(((await res.json()) as { data: { error: string } }).data.error).toBe('TENANT_CONTEXT_REQUIRED');
  });
});

// ---------------------------------------------------------------------------
// (11) Role and MFA gates inside auth
// ---------------------------------------------------------------------------
test('a viewer session cannot stamp (FORBIDDEN)', async () => {
  const viewerSession: (sql: string, params: unknown[]) => unknown[] = (_sql, params) =>
    params[0] === SESSION_HASH ? [sessionRow({ role: 'viewer' })] : [];
  const pool = new FakePool([...sessionHandlers(viewerSession)]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/cards/card-1/stamps`, {
      method: 'POST',
      headers: authedHeaders(),
      body: JSON.stringify({ quantity: 1 }),
    }));
    expect(res.status).toBe(403);
    expect(((await res.json()) as { data: { error: string } }).data.error).toBe('FORBIDDEN');
    expect(pool.queries.some((q) => q.sql.startsWith('insert into stamp_events'))).toBe(false);
  });
});

test('an unverified MFA-required session is blocked (MFA_REQUIRED)', async () => {
  const mfaSession: (sql: string, params: unknown[]) => unknown[] = (_sql, params) =>
    params[0] === SESSION_HASH ? [sessionRow({ mfa_required: true, mfa_verified: false })] : [];
  const pool = new FakePool([...sessionHandlers(mfaSession)]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/capacity`, {
      headers: { cookie: `__Host-sp_session=${SESSION_TOKEN}` },
    }));
    expect(res.status).toBe(400);
    expect(((await res.json()) as { data: { error: string } }).data.error).toBe('MFA_REQUIRED');
  });
});

test('a session whose user is deactivated is rejected (status-scoped session lookup)', async () => {
  // The auth session query joins users and now filters u.status='active' ($4).
  // The fake models that DB filter: the row exists only when the server sends
  // the active-status parameter. A deactivated user yields no session row at
  // all → UNAUTHENTICATED, exactly like an RLS-filtered lookup.
  const statusScopedSession: (sql: string, params: unknown[]) => unknown[] = (_sql, params) =>
    params[0] === SESSION_HASH && params[3] === 'active' ? [sessionRow()] : [];
  const pool = new FakePool([
    ...sessionHandlers(statusScopedSession),
    { match: contains('from tenants'), rows: [{ plan_code: 'up_to_500', customer_limit: 500 }] },
    { match: contains('count(distinct customer_id)'), rows: [{ count: '1' }] },
  ]);
  await runWith(pool, async () => {
    // Active user: session row present → the request succeeds.
    const ok = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/capacity`, {
      headers: { cookie: `__Host-sp_session=${SESSION_TOKEN}` },
    }));
    expect(ok.status).toBe(200);
    // Contract pin: the auth session lookup must carry the user-status filter.
    const sessionQuery = pool.queries.find(q => q.sql.includes('from sessions'));
    expect(sessionQuery?.sql).toContain('u.status');
    expect(sessionQuery?.params).toEqual([SESSION_HASH, 'active', TENANT, 'active']);
    // Deactivated user: the DB filters the row out → UNAUTHENTICATED.
    const deactivatedPool = new FakePool([...sessionHandlers(() => [])]);
    const restore = withTestDependencies({ configured: true, pool: deactivatedPool, repository: new CardRepository(deactivatedPool) });
    try {
      const res = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/capacity`, {
        headers: { cookie: `__Host-sp_session=${SESSION_TOKEN}` },
      }));
      expect(res.status).toBe(401);
      expect(((await res.json()) as { data: { error: string } }).data.error).toBe('UNAUTHENTICATED');
    } finally {
      restore();
    }
  });
});

// ---------------------------------------------------------------------------
// (12) Unexpected errors never leak internal details
// ---------------------------------------------------------------------------
test('an internal database failure surfaces as INTERNAL_ERROR without leaking the message', async () => {
  const pool = new FakePool([
    {
      match: contains('from users where'),
      rows: () => { throw new Error('internal secret-db-dsn user=postgres host=db.internal'); },
    },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.14' },
      body: JSON.stringify({ email: 'owner@example.com', password: PASSWORD }),
    }));
    expect(res.status).toBe(500);
    const raw = await res.text();
    expect(((JSON.parse(raw)) as { data: { error: string } }).data.error).toBe('INTERNAL_ERROR');
    expect(raw).not.toContain('secret-db-dsn');
    expect(raw).not.toContain('db.internal');
    expect(raw).not.toContain('user=postgres');
  });
});

// ---------------------------------------------------------------------------
// (4b) Login MFA bootstrap — resolver-only query (migration 010), fail-closed
// ---------------------------------------------------------------------------
const resetLoginLimiters = () => { loginIpLimiter.clear(); loginAccountLimiter.clear(); };

test('login MFA bootstrap issues exactly the resolver call, never a raw tenant_memberships read', async () => {
  resetLoginLimiters();
  const pool = new FakePool([
    { match: contains('from users where'), rows: [{ id: USER_ID, password_hash: passwordHash, mfa_required: false, mfa_enabled: false, mfa_secret_ciphertext: null }] },
    { match: contains('membership_mfa_required'), rows: [{ required: false }] },
    { match: contains('update sessions set revoked_at=now() where user_id'), rows: [] },
    { match: contains('insert into sessions'), rows: [] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.31' },
      body: JSON.stringify({ email: 'mfa-owner-a@example.com', password: PASSWORD }),
    }));
    expect(res.status).toBe(200);
    const sqls = pool.queries.map(q => q.sql);
    const mfaIdx = sqls.findIndex(s => s.includes('membership_mfa_required'));
    expect(mfaIdx).toBeGreaterThan(-1);
    // The bootstrap is exactly the fully qualified SECURITY DEFINER call.
    expect(pool.queries[mfaIdx]?.sql).toBe('select public.membership_mfa_required($1) as required');
    expect(pool.queries[mfaIdx]?.params).toEqual([USER_ID]);
    // The login path must never read the RLS-protected membership table or the
    // old bool_or aggregate directly (RLS would NULL-filter both).
    expect(sqls.some(s => s.includes('from tenant_memberships'))).toBe(false);
    expect(sqls.some(s => s.includes('bool_or'))).toBe(false);
    expect(sqls.some(s => s.includes('join users'))).toBe(false);
  });
});

test('login fail-closed when the MFA bootstrap result is missing (no row)', async () => {
  resetLoginLimiters();
  const pool = new FakePool([
    { match: contains('from users where'), rows: [{ id: USER_ID, password_hash: passwordHash, mfa_required: false, mfa_enabled: false, mfa_secret_ciphertext: null }] },
    { match: contains('membership_mfa_required'), rows: [] }, // function/result missing
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.32' },
      body: JSON.stringify({ email: 'mfa-owner-b@example.com', password: PASSWORD }),
    }));
    expect(res.status).toBe(400);
    const body = (await res.json()) as { data: { error: string } };
    expect(body.data.error).toBe('INVALID_CREDENTIALS');
    expect(JSON.stringify(body)).not.toContain('MFA_BOOTSTRAP_UNVERIFIED');
    // Fail-closed: no session row may be created without a verified MFA answer.
    expect(pool.queries.some(q => q.sql.startsWith('insert into sessions'))).toBe(false);
  });
});

test('login fail-closed when the MFA bootstrap returns NULL', async () => {
  resetLoginLimiters();
  const pool = new FakePool([
    { match: contains('from users where'), rows: [{ id: USER_ID, password_hash: passwordHash, mfa_required: false, mfa_enabled: false, mfa_secret_ciphertext: null }] },
    { match: contains('membership_mfa_required'), rows: [{ required: null }] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.33' },
      body: JSON.stringify({ email: 'mfa-owner-c@example.com', password: PASSWORD }),
    }));
    expect(res.status).toBe(400);
    expect(((await res.json()) as { data: { error: string } }).data.error).toBe('INVALID_CREDENTIALS');
    expect(pool.queries.some(q => q.sql.startsWith('insert into sessions'))).toBe(false);
  });
});

test('login with MFA required (resolver true) takes the MFA gate and fails closed without a store', async () => {
  resetLoginLimiters();
  const pool = new FakePool([
    { match: contains('from users where'), rows: [{ id: USER_ID, password_hash: passwordHash, mfa_required: false, mfa_enabled: false, mfa_secret_ciphertext: null }] },
    { match: contains('membership_mfa_required'), rows: [{ required: true }] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.34' },
      body: JSON.stringify({ email: 'mfa-owner-d@example.com', password: PASSWORD }),
    }));
    expect(res.status).toBe(400);
    expect(((await res.json()) as { data: { error: string } }).data.error).toBe('INVALID_CREDENTIALS');
    // The MFA gate consumed the true result: no session row without verified MFA.
    expect(pool.queries.some(q => q.sql.startsWith('insert into sessions'))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// (13) Session rotation carries mfa_verified (B4) — never a downgrade
// ---------------------------------------------------------------------------
const STAMP_HANDLERS = [
  { match: contains('from stamp_events'), rows: [] }, // no replay
  { match: contains('from cards where'), rows: [{ id: 'card-1', stampCount: 3, revision: 2, ruleId: RULE }] },
  { match: contains('insert into stamp_events'), rows: [] },
  { match: contains('update cards set stamp_count'), rows: [{ id: 'card-1', stampCount: 4, revision: 3 }] },
  { match: contains('from stamp_rules'), rows: [{ id: RULE, stamps_required: 1 }] },
  { match: contains('insert into rewards'), rows: [{ id: 'reward-1', status: 'issued' }] },
];

test('session rotation of an MFA-verified session persists mfa_verified=true (no downgrade)', async () => {
  const mfaSession: (sql: string, params: unknown[]) => unknown[] = (_sql, params) =>
    params[0] === SESSION_HASH ? [sessionRow({ mfa_required: true, mfa_verified: true })] : [];
  const pool = new FakePool([...sessionHandlers(mfaSession), ...STAMP_HANDLERS]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/cards/card-1/stamps`, {
      method: 'POST', headers: authedHeaders(), body: JSON.stringify({ quantity: 1 }),
    }));
    expect(res.status).toBe(200);
    // The rotation insert must carry the OLD session's mfa_verified into the NEW
    // session row — otherwise the next request would bounce with MFA_REQUIRED.
    const insert = pool.queries.find(q => q.sql.startsWith('insert into sessions'));
    expect(insert?.sql).toContain('mfa_verified');
    expect(insert?.params).toEqual([USER_ID, expect.stringMatching(/^[0-9a-f]{64}$/), expect.stringMatching(/^[0-9a-f]{64}$/), true]);
  });
});

test('session rotation of a non-MFA session persists mfa_verified=false (exact carry-over)', async () => {
  const plainSession: (sql: string, params: unknown[]) => unknown[] = (_sql, params) =>
    params[0] === SESSION_HASH ? [sessionRow({ mfa_required: false, mfa_verified: false })] : [];
  const pool = new FakePool([...sessionHandlers(plainSession), ...STAMP_HANDLERS]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/cards/card-1/stamps`, {
      method: 'POST', headers: authedHeaders(), body: JSON.stringify({ quantity: 1 }),
    }));
    expect(res.status).toBe(200);
    const insert = pool.queries.find(q => q.sql.startsWith('insert into sessions'));
    expect(insert?.params?.[3]).toBe(false);
  });
});

test('redeem rotation of an MFA-verified session also persists mfa_verified=true', async () => {
  const mfaSession: (sql: string, params: unknown[]) => unknown[] = (_sql, params) =>
    params[0] === SESSION_HASH ? [sessionRow({ mfa_required: true, mfa_verified: true })] : [];
  const pool = new FakePool([
    ...sessionHandlers(mfaSession),
    { match: contains('update rewards set status'), rows: [{ id: 'reward-1', status: 'redeemed' }] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/rewards/reward-1/redeem`, {
      method: 'POST', headers: authedHeaders(),
    }));
    expect(res.status).toBe(200);
    const insert = pool.queries.find(q => q.sql.startsWith('insert into sessions'));
    expect(insert?.params).toEqual([USER_ID, expect.stringMatching(/^[0-9a-f]{64}$/), expect.stringMatching(/^[0-9a-f]{64}$/), true]);
  });
});

// ---------------------------------------------------------------------------
// (14) PUT pilot — entry-point upsert returns the PERSISTED join path (B12)
// ---------------------------------------------------------------------------
test('PUT pilot returns the persisted entry-point join path and keeps it across re-configure', async () => {
  const PERSISTED_KEY = 'e'.repeat(32);
  const adminSession: (sql: string, params: unknown[]) => unknown[] = (_sql, params) =>
    params[0] === SESSION_HASH ? [sessionRow({ role: 'admin' })] : [];
  const pool = new FakePool([
    ...sessionHandlers(adminSession),
    { match: contains('from tenants'), rows: [{ customer_limit: 500 }] },
    { match: contains('count(distinct customer_id)'), rows: [{ count: '0' }] },
    { match: contains('update tenants set'), rows: [] },
    { match: contains('insert into tenant_branding'), rows: [] },
    { match: contains('insert into stamp_rules'), rows: [{ id: RULE }] },
    { match: contains('insert into tenant_entry_points'), rows: [{ public_key: PERSISTED_KEY, join_path: `/join/${PERSISTED_KEY}` }] },
  ]);
  const body = {
    planCode: 'up_to_500', cardTitle: 'Café Herz', cardText: 'Sammle Stempel',
    primaryColor: '#155e75', secondaryColor: '#f8fafc', stampsRequired: 8,
    rewardTitle: 'Gratis Kaffee', rewardDescription: 'Beim 9. Kaffee',
  };
  await runWith(pool, async () => {
    // First configure.
    const first = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/pilot`, {
      method: 'PUT', headers: authedHeaders(), body: JSON.stringify(body),
    }));
    expect(first.status).toBe(200);
    expect(((await first.json()) as { data: Record<string, unknown> }).data).toEqual({
      tenantId: TENANT, planCode: 'up_to_500', customerLimit: 500, ruleId: RULE, joinPath: `/join/${PERSISTED_KEY}`,
    });
    // Re-configure: the response must carry the SAME persisted join path — the
    // old join link stays valid and no un-persisted key is ever advertised.
    const second = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/pilot`, {
      method: 'PUT', headers: authedHeaders(), body: JSON.stringify({ ...body, planCode: 'up_to_1000' }),
    }));
    expect(second.status).toBe(200);
    expect(((await second.json()) as { data: { joinPath?: string } }).data.joinPath).toBe(`/join/${PERSISTED_KEY}`);
    // Contract pin on both upserts: RETURNING reads back the persisted columns and
    // the conflict path never overwrites public_key/join_path.
    const upserts = pool.queries.filter(q => q.sql.includes('insert into tenant_entry_points'));
    expect(upserts).toHaveLength(2);
    for (const upsert of upserts) {
      expect(upsert.sql).toContain('on conflict(tenant_id) do update set updated_at=now() returning public_key,join_path');
      expect(upsert.sql).not.toContain('public_key=excluded');
      expect(upsert.sql).not.toContain('join_path=excluded');
      expect(upsert.params?.[0]).toBe(TENANT);
      expect(upsert.params?.[1]).toMatch(/^[0-9a-f]{32}$/);
      expect(upsert.params?.[2]).toBe(`/join/${upsert.params?.[1]}`);
    }
  });
});

test('PUT pilot by a staff member is rejected with FORBIDDEN (owner/admin only)', async () => {
  const pool = new FakePool([...sessionHandlers(validSession)]); // default role: staff
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/api/tenants/${TENANT}/pilot`, {
      method: 'PUT', headers: authedHeaders(),
      body: JSON.stringify({ planCode: 'up_to_500', cardTitle: 'Café', cardText: '', primaryColor: '#155e75', secondaryColor: '#f8fafc', stampsRequired: 8, rewardTitle: 'Kaffee', rewardDescription: '' }),
    }));
    expect(res.status).toBe(403);
    expect(((await res.json()) as { data: { error: string } }).data.error).toBe('FORBIDDEN');
    expect(pool.queries.some(q => q.sql.includes('insert into tenant_entry_points'))).toBe(false);
  });
});
