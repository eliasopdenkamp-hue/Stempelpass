/**
 * Password-reset ("Passwort vergessen") HTTP contract tests.
 *
 * Drives the REAL fetchHandler in-process against a scripted FakePool (no
 * database, no credentials) — the same pattern as tests/http-contract.test.ts.
 * Covers all three reset endpoints:
 *   POST /api/auth/reset/request  — neutral answer always (anti-enumeration),
 *                                   hashed token storage, SMTP not_configured
 *                                   and configured-send paths, rate limits,
 *                                   timing equalizer (dummy scrypt also runs
 *                                   for unknown emails);
 *   GET  /reset/:token            — form page vs neutral 404, format guard;
 *   POST /api/auth/reset/confirm  — password rotation through the SECURITY
 *                                   DEFINER function public.reset_user_password
 *                                   (scrypt hash stored, never the plaintext),
 *                                   atomic single-use consume (exactly ONE of
 *                                   two parallel confirms wins), ALL-session
 *                                   revoke, audit row, rate limits,
 *                                   short-password and invalid-token failures.
 */
import { test, expect, beforeEach, spyOn } from 'bun:test';
import { CardRepository, type DbPool, type TxClient } from '../src/repository';
import { SmtpEmailAdapter } from '../src/email';
import {
  hashPassword, hashSessionToken, loginAccountKey, randomToken, resetResolveKey, verifyPassword,
  resetConfirmIpLimiter, resetConfirmTokenLimiter, resetRequestAccountLimiter,
  resetRequestIpLimiter, resetResolveLimiter, verifyPasswordAgainstDummy,
} from '../src/security';
import * as securityModule from '../src/security';
import { loginPage } from '../src/staff-ui';

// --- boot: scrub every secret/config var BEFORE importing the server module ---
const SCRUBBED_KEYS = [
  'DATABASE_URL', 'TEST_DATABASE_URL', 'SESSION_SECRET', 'MFA_ENCRYPTION_KEY',
  'GOOGLE_ISSUER_ID', 'GOOGLE_SERVICE_ACCOUNT_JSON', 'GOOGLE_SERVICE_ACCOUNT_EMAIL',
  'GOOGLE_PRIVATE_KEY', 'GOOGLE_EXTERNAL_ACCOUNT_JSON', 'GOOGLE_APPLICATION_CREDENTIALS',
  'VERCEL_OIDC_TOKEN', 'APPLE_TEAM_IDENTIFIER', 'APPLE_PASS_TYPE_IDENTIFIER', 'APPLE_PRIVATE_KEY',
  'TIGER_PUBLIC_KEY', 'TIGER_SECRET_KEY', 'TIGER_PROJECT_ID',
  'EMAIL_SMTP_HOST', 'EMAIL_SMTP_PORT', 'EMAIL_SMTP_USER', 'EMAIL_SMTP_PASSWORD', 'EMAIL_FROM',
  'COMMUNICATION_HASH_SECRET', 'PORT', 'PILOT_READY', 'FRONTEND_ORIGIN',
  'FRONTEND_ORIGIN_DEV', 'PUBLIC_SITE_ORIGIN',
];
for (const key of SCRUBBED_KEYS) delete process.env[key];
process.env.FRONTEND_ORIGIN = 'https://a1e91d0731cfc57ecf5a508e37635a85.ctonew.app';
process.env.FRONTEND_ORIGIN_DEV = 'https://a1e91d0731cfc57ecf5a508e37635a85-dev.ctonew.app';
process.env.VERCEL = '1';

const { fetchHandler, withTestDependencies } = await import('../src/server');

// --- fixtures ---
const USER_ID = '44444444-4444-4444-8444-444444444444';
const OTHER_USER_ID = '66666666-6666-4666-8666-666666666666';
const RAW_TOKEN = randomToken();            // what the e-mail link would carry
const TOKEN_HASH = hashSessionToken(RAW_TOKEN);
const NEW_PASSWORD = 'neues passwort 123';

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

function runWith(pool: DbPool, fn: () => Promise<unknown>, emailFactory?: () => SmtpEmailAdapter): Promise<unknown> {
  const restore = withTestDependencies({ configured: true, pool, repository: new CardRepository(pool), emailFactory });
  return fn().finally(restore);
}

const resetJson = (body: unknown, ip = '203.0.113.50') => new Request('http://test.local/api/auth/reset/confirm', {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-forwarded-for': ip },
  body: JSON.stringify(body),
});

beforeEach(() => {
  resetRequestIpLimiter.clear();
  resetRequestAccountLimiter.clear();
  resetConfirmIpLimiter.clear();
  resetConfirmTokenLimiter.clear();
  resetResolveLimiter.clear();
});

// ---------------------------------------------------------------------------
// POST /api/auth/reset/request
// ---------------------------------------------------------------------------
test('reset request with an unknown email answers the neutral body, writes NO token and leaks nothing', async () => {
  const email = 'unbekannt@example.com';
  const pool = new FakePool([{ match: contains('from users where'), rows: [] }]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/api/auth/reset/request', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.51' },
      body: JSON.stringify({ email }),
    }));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { request_id: string; data: { status: string } };
    expect(body.data).toEqual({ status: 'requested' });
    expect(JSON.stringify(body)).not.toContain(email);
    expect(pool.queries.some(q => q.sql.includes('insert into password_reset_tokens'))).toBe(false);
    expect(pool.queries.some(q => q.sql.includes('from users where'))).toBe(true);
  });
});

test('reset request with an existing account stores ONLY the SHA-256 hash and answers the identical neutral body (SMTP not_configured)', async () => {
  const email = 'owner@example.com';
  // No EMAIL_SMTP_*/EMAIL_FROM in the scrubbed environment → adapter is
  // not_configured → the route still answers the neutral body (no leak).
  const pool = new FakePool([
    { match: contains('from users where'), rows: [{ id: USER_ID }] },
    { match: contains('insert into password_reset_tokens'), rows: [] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/api/auth/reset/request', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.52' },
      body: JSON.stringify({ email }),
    }));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: { status: string } };
    expect(body.data).toEqual({ status: 'requested' });
    expect(JSON.stringify(body)).not.toContain(email);

    // Token row: user_id + SHA-256 hex digest + 60-minute TTL expression.
    const insert = pool.queries.find(q => q.sql.includes('insert into password_reset_tokens'));
    expect(insert).toBeDefined();
    expect(insert!.params[0]).toBe(USER_ID);
    expect(String(insert!.params[1])).toMatch(/^[a-f0-9]{64}$/);
    expect(JSON.stringify(pool.queries)).toMatch(/interval '60 minutes'/);
    // app.user_id is set from the server-side lookup BEFORE the insert (RLS
    // user-scoped policy of migration 019) — the requester never supplies it.
    const setConfigIdx = pool.queries.findIndex(q => q.sql.includes("set_config('app.user_id'"));
    const insertIdx = pool.queries.findIndex(q => q.sql.includes('insert into password_reset_tokens'));
    expect(setConfigIdx).toBeGreaterThan(-1);
    expect(insertIdx).toBeGreaterThan(setConfigIdx);
  });
});

test('reset request with a malformed email is treated like an unknown account (neutral, no lookup, no token)', async () => {
  const pool = new FakePool([]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/api/auth/reset/request', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.53' },
      body: JSON.stringify({ email: 'keine-email' }),
    }));
    expect(res.status).toBe(200);
    expect(((await res.json()) as { data: { status: string } }).data.status).toBe('requested');
    expect(pool.queries.some(q => q.sql.includes('from users where'))).toBe(false);
    expect(pool.queries.some(q => q.sql.includes('insert into password_reset_tokens'))).toBe(false);
  });
});

test('reset request without an email is rejected before any lookup (CREDENTIALS_REQUIRED)', async () => {
  const pool = new FakePool([]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/api/auth/reset/request', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.54' },
      body: JSON.stringify({}),
    }));
    expect(res.status).toBe(400);
    expect(((await res.json()) as { data: { error: string } }).data.error).toBe('CREDENTIALS_REQUIRED');
  });
});

test('reset request with configured SMTP sends the reset e-mail with a /reset/<token> link; the raw token never reaches the DB', async () => {
  const email = 'owner@example.com';
  const sent: Array<{ to: string; subject: string; text: string; html: string }> = [];
  const adapter = new SmtpEmailAdapter({
    EMAIL_SMTP_HOST: 'smtp.example.test',
    EMAIL_SMTP_PORT: '587',
    EMAIL_SMTP_USER: 'mailer',
    EMAIL_SMTP_PASSWORD: 'secret',
    EMAIL_FROM: 'no-reply@example.test',
  }, { sendMail: async (message) => { sent.push(message as { to: string; subject: string; text: string; html: string }); return { messageId: 'test-1' }; } });
  const pool = new FakePool([
    { match: contains('from users where'), rows: [{ id: USER_ID }] },
    { match: contains('insert into password_reset_tokens'), rows: [] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/api/auth/reset/request', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.55' },
      body: JSON.stringify({ email }),
    }));
    expect(res.status).toBe(200);
    expect(sent.length).toBe(1);
    expect(sent[0].to).toBe(email);
    expect(sent[0].subject).toContain('Passwort zurücksetzen');
    const linkMatch = sent[0].html.match(/\/reset\/([A-Za-z0-9_-]{43})/);
    expect(linkMatch).not.toBeNull();
    const rawTokenInMail = linkMatch![1];
    expect(sent[0].text).toContain('/reset/' + rawTokenInMail);
    // Only the 64-hex hash may reach the database — never the raw token.
    const insert = pool.queries.find(q => q.sql.includes('insert into password_reset_tokens'));
    expect(String(insert!.params[1])).toMatch(/^[a-f0-9]{64}$/);
    expect(JSON.stringify(pool.queries)).not.toContain(rawTokenInMail);
    // The raw address is legitimate only as the user-lookup parameter — it
    // never appears as a limiter key, in the token insert, or in any log.
    const userLookup = pool.queries.find(q => q.sql.includes('from users where'));
    expect(userLookup!.params[0]).toBe(email);
    expect(JSON.stringify(insert!.params)).not.toContain(email);
  }, () => adapter);
});

test('reset request with an unknown email ALSO burns the dummy-scrypt timing budget (no response-time enumeration oracle)', async () => {
  // Security-Review 91292cdf, MITTEL: the known path spends a bounded
  // wall-clock budget on the mail; the unknown path must burn the same budget
  // class. Pin the equalizer: verifyPasswordAgainstDummy IS called for an
  // unknown account (DB-free spy on the security module).
  const spy = spyOn(securityModule, 'verifyPasswordAgainstDummy');
  try {
    const pool = new FakePool([{ match: contains('from users where'), rows: [] }]);
    await runWith(pool, async () => {
      const res = await fetchHandler(new Request('http://test.local/api/auth/reset/request', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.57' },
        body: JSON.stringify({ email: 'wer-auch-immer@example.com' }),
      }));
      expect(res.status).toBe(200);
    });
    expect(spy).toHaveBeenCalled();
  } finally {
    spy.mockRestore();
  }
});

test('reset request is rate-limited per hashed account key (4th request for the same email → 429)', async () => {
  const email = 'rate@example.com';
  const accountKey = loginAccountKey(email);
  const pool = new FakePool([{ match: contains('from users where'), rows: [{ id: USER_ID }] }]);
  await runWith(pool, async () => {
    let lastStatus = 0;
    for (let i = 0; i < 4; i++) {
      lastStatus = (await fetchHandler(new Request('http://test.local/api/auth/reset/request', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.56' },
        body: JSON.stringify({ email }),
      }))).status;
    }
    expect(lastStatus).toBe(429);
    // Different accounts share no budget.
    expect(resetRequestAccountLimiter.allow(loginAccountKey('andere@example.com'))).toBe(true);
    expect(accountKey.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// GET /reset and GET /reset/:token
// ---------------------------------------------------------------------------
test('GET /reset renders the email request page without any database access', async () => {
  const restore = withTestDependencies({ configured: false });
  try {
    const res = await fetchHandler(new Request('http://test.local/reset'));
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('<form id="reset-request-form">');
    expect(html).toContain('/api/auth/reset/request');
    expect(html).toContain('Wenn es dieses Konto gibt');
    expect(html).not.toContain('request_id');
  } finally {
    restore();
  }
});

test('GET /reset/:token with a valid token renders the new-password form carrying the token as a hidden field', async () => {
  const pool = new FakePool([{ match: contains('resolve_password_reset_user'), rows: [{ user_id: USER_ID }] }]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/reset/${RAW_TOKEN}`));
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('<form id="reset-confirm-form">');
    expect(html).toContain(`value="${RAW_TOKEN}"`);
    expect(html).toContain('mindestens 12 Zeichen');
    // Resolution went through the RLS-safe SECURITY DEFINER resolver with the
    // SHA-256 token hash — never a raw-token read.
    const sqls = pool.queries.map(q => q.sql);
    expect(sqls.some(s => s.includes('resolve_password_reset_user'))).toBe(true);
    expect(sqls.some(s => s.includes('from password_reset_tokens'))).toBe(false);
    const hashParam = pool.queries.find(q => q.sql.includes('resolve_password_reset_user'))!.params[0];
    expect(hashParam).toBe(TOKEN_HASH);
    expect(JSON.stringify(pool.queries)).not.toContain(RAW_TOKEN);
  });
});

test('GET /reset/:token with an unknown/expired/consumed token answers the neutral 404 page, never a form', async () => {
  const pool = new FakePool([{ match: contains('resolve_password_reset_user'), rows: [] }]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/reset/${RAW_TOKEN}`));
    expect(res.status).toBe(404);
    const html = await res.text();
    expect(html).toContain('Link ungültig oder abgelaufen');
    expect(html).not.toContain('reset-confirm-form');
  });
});

test('GET /reset/:token with a malformed token answers 404 without touching the database', async () => {
  const pool = new FakePool([]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/reset/not-a-valid-token'));
    expect(res.status).toBe(404);
    expect((await res.text())).toContain('Link ungültig oder abgelaufen');
    expect(pool.queries.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// POST /api/auth/reset/confirm
// ---------------------------------------------------------------------------
/** Handlers for a successful confirm (fresh operationId → no prior audit rows).
 *  Order matters: the audit INSERT contains "from audit_log where action"
 *  inside its NOT EXISTS subquery, so the INSERT handler MUST come first
 *  (first-match semantics of FakePool). The rotation runs through the SECURITY
 *  DEFINER function public.reset_user_password (migration 020) — a single
 *  atomic statement that resolves+consumes the token and writes the hash. */
function confirmSuccessHandlers(): FakePool['handlers'] {
  return [
    { match: contains('insert into audit_log(tenant_id'), rows: [{ id: 'audit-1' }] },
    { match: contains('select user_id from public.reset_user_password'), rows: [{ user_id: USER_ID }] },
    { match: contains('update sessions set revoked_at=now() where user_id'), rows: [] },
  ];
}

test('reset confirm rotates the password (scrypt hash stored, never the plaintext) and revokes ALL sessions of the user', async () => {
  const pool = new FakePool(confirmSuccessHandlers());
  await runWith(pool, async () => {
    const res = await fetchHandler(resetJson({ token: RAW_TOKEN, password: NEW_PASSWORD }));
    expect(res.status).toBe(200);
    expect(((await res.json()) as { data: { status: string } }).data.status).toBe('password_reset_confirmed');

    // The atomic SECURITY DEFINER rotation carries [token_hash, scrypt_hash] —
    // the plaintext password never reaches a query parameter or the DB.
    const rotate = pool.queries.find(q => q.sql.includes('select user_id from public.reset_user_password'));
    expect(rotate).toBeDefined();
    expect(rotate!.params[0]).toBe(TOKEN_HASH);
    const storedHash = String(rotate!.params[1]);
    expect(storedHash.startsWith('$scrypt$N=32768,r=8,p=1$')).toBe(true);
    expect(storedHash).not.toContain(NEW_PASSWORD);
    expect(storedHash).not.toBe(NEW_PASSWORD);
    // The stored digest verifies against the submitted password — the rotation
    // really landed a usable hash.
    expect(await verifyPassword(NEW_PASSWORD, storedHash)).toBe(true);

    // Sessions revoke (rotate-owner-password pattern) must target the user.
    const revoke = pool.queries.find(q => q.sql.includes('update sessions set revoked_at=now() where user_id'));
    expect(revoke).toBeDefined();
    expect(revoke!.params[0]).toBe(USER_ID);

    // Token is single-use: the CONSUME happens INSIDE the atomic function
    // (consumed_at is not a separate statement anymore, migration 020).
    expect(pool.queries.some(q => q.sql.includes('update password_reset_tokens set consumed_at'))).toBe(false);

    // Audit row: tenantId null (global-isolation branch 009), actor = user.
    const audit = pool.queries.find(q => q.sql.includes('insert into audit_log'));
    expect(audit).toBeDefined();
    expect(audit!.params[1]).toBe('user.password_reset_confirmed');
    expect(audit!.params[0]).toBe(USER_ID);
    expect(JSON.stringify(audit!.params[2])).toContain('operationId');
  });
});

test('reset confirm with an unknown/expired/consumed token answers RESET_TOKEN_INVALID and never writes', async () => {
  const pool = new FakePool([
    { match: contains('select user_id from public.reset_user_password'), rows: [] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(resetJson({ token: RAW_TOKEN, password: NEW_PASSWORD }));
    expect(res.status).toBe(400);
    expect(((await res.json()) as { data: { error: string } }).data.error).toBe('RESET_TOKEN_INVALID');
    expect(pool.queries.some(q => q.sql.includes('update users set password_hash'))).toBe(false);
    expect(pool.queries.some(q => q.sql.includes('update sessions set revoked_at'))).toBe(false);
    expect(pool.queries.some(q => q.sql.includes('insert into audit_log'))).toBe(false);
  });
});

test('reset confirm replay of a consumed token (second use) is rejected — single-use semantics', async () => {
  const pool = new FakePool(confirmSuccessHandlers());
  await runWith(pool, async () => {
    // First use succeeds; on replay the atomic function (consumed_at is null
    // guard inside 020) finds nothing → the same neutral RESET_TOKEN_INVALID.
    const first = await fetchHandler(resetJson({ token: RAW_TOKEN, password: NEW_PASSWORD }));
    expect(first.status).toBe(200);
    const replayPool = new FakePool([
      { match: contains('select user_id from public.reset_user_password'), rows: [] },
    ]);
    const restore = withTestDependencies({ configured: true, pool: replayPool, repository: new CardRepository(replayPool) });
    try {
      const second = await fetchHandler(resetJson({ token: RAW_TOKEN, password: NEW_PASSWORD }));
      expect(second.status).toBe(400);
      expect(((await second.json()) as { data: { error: string } }).data.error).toBe('RESET_TOKEN_INVALID');
      expect(replayPool.queries.some(q => q.sql.includes('update users set password_hash'))).toBe(false);
      expect(replayPool.queries.some(q => q.sql.includes('insert into audit_log'))).toBe(false);
    } finally {
      restore();
    }
  });
});

test('two parallel confirms of the same token — exactly one wins (atomic single-use consume, TOCTOU closed)', async () => {
  // The atomic SECURITY DEFINER statement (migration 020) consumes the token in
  // the same statement that rotates the password. Two concurrent confirms
  // serialize on the token row: exactly one gets the user_id back, the loser
  // sees 0 rows and answers RESET_TOKEN_INVALID. The stateful handler below
  // simulates that serialization (first call wins, every later call is empty).
  let rotationsLeft = 1;
  const pool = new FakePool([
    { match: contains('insert into audit_log(tenant_id'), rows: [{ id: 'audit-1' }] },
    {
      match: contains('select user_id from public.reset_user_password'),
      rows: () => (rotationsLeft-- > 0 ? [{ user_id: USER_ID }] : []),
    },
    { match: contains('update sessions set revoked_at=now() where user_id'), rows: [] },
  ]);
  await runWith(pool, async () => {
    const [a, b] = await Promise.all([
      fetchHandler(resetJson({ token: RAW_TOKEN, password: NEW_PASSWORD })),
      fetchHandler(resetJson({ token: RAW_TOKEN, password: NEW_PASSWORD })),
    ]);
    const statuses = [a.status, b.status].sort();
    expect(statuses).toEqual([200, 400]);
    // The winner committed exactly one rotation: one audit row, one session
    // revoke — the token was consumed at most once.
    expect(pool.queries.filter(q => q.sql.includes('select user_id from public.reset_user_password')).length).toBe(2);
    expect(pool.queries.filter(q => q.sql.includes('insert into audit_log')).length).toBe(1);
    expect(pool.queries.filter(q => q.sql.includes('update sessions set revoked_at')).length).toBe(1);
    expect(pool.queries.filter(q => q.sql.includes('update password_reset_tokens set consumed_at')).length).toBe(0);
  });
});

test('reset confirm with a short password is rejected with PASSWORD_TOO_SHORT before any database access', async () => {
  const pool = new FakePool([]);
  await runWith(pool, async () => {
    const res = await fetchHandler(resetJson({ token: RAW_TOKEN, password: 'kurz' }));
    expect(res.status).toBe(400);
    expect(((await res.json()) as { data: { error: string } }).data.error).toBe('PASSWORD_TOO_SHORT');
    expect(pool.queries.length).toBe(0);
  });
});

test('reset confirm with missing fields is rejected with CREDENTIALS_REQUIRED before any database access', async () => {
  const pool = new FakePool([]);
  await runWith(pool, async () => {
    const res = await fetchHandler(resetJson({ token: RAW_TOKEN }));
    expect(res.status).toBe(400);
    expect(((await res.json()) as { data: { error: string } }).data.error).toBe('CREDENTIALS_REQUIRED');
    expect(pool.queries.length).toBe(0);
  });
});

test('reset confirm with a malformed token hits RESET_TOKEN_INVALID before any database access', async () => {
  const pool = new FakePool([]);
  await runWith(pool, async () => {
    const res = await fetchHandler(resetJson({ token: 'kein-token', password: NEW_PASSWORD }));
    expect(res.status).toBe(400);
    expect(((await res.json()) as { data: { error: string } }).data.error).toBe('RESET_TOKEN_INVALID');
    expect(pool.queries.length).toBe(0);
  });
});

test('reset confirm is rate-limited per IP+token (6th attempt with the same token → 429)', async () => {
  const pool = new FakePool([
    { match: contains('select user_id from public.reset_user_password'), rows: [] }, // invalid-token path
  ]);
  await runWith(pool, async () => {
    let lastStatus = 0;
    for (let i = 0; i < 6; i++) {
      lastStatus = (await fetchHandler(resetJson({ token: RAW_TOKEN, password: NEW_PASSWORD }))).status;
    }
    expect(lastStatus).toBe(429);
    // A different token on the same IP shares no budget.
    const otherToken = randomToken();
    expect(resetConfirmTokenLimiter.allow(resetResolveKey(new Request('http://test.local/reset/x', { headers: { 'x-forwarded-for': '203.0.113.50' } }), otherToken))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// UI: login page links to the reset flow
// ---------------------------------------------------------------------------
test('login page contains the "Passwort vergessen" link below the form', () => {
  const html = loginPage();
  expect(html).toContain('<form id="login-form">');
  expect(html).toContain('Passwort vergessen');
  expect(html).toContain('<a href="/reset">Passwort vergessen?</a>');
});

// ---------------------------------------------------------------------------
// Hash-verification helper sanity (scrypt primitives used by confirm)
// ---------------------------------------------------------------------------
test('hashPassword produces a verifiable scrypt digest (primitive pin)', async () => {
  const hash = await hashPassword(NEW_PASSWORD);
  expect(hash.startsWith('$scrypt$N=32768,r=8,p=1$')).toBe(true);
  expect(hash).not.toContain(NEW_PASSWORD);
});