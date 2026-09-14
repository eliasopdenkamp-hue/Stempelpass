import { test, expect } from 'bun:test';
import { CardRepository, type DbPool, type TxClient } from '../src/repository';
import { hashSessionToken, randomToken, stampLimiter } from '../src/security';

/**
 * Staff web UI contract tests against the REAL fetchHandler — same DB-free
 * pattern as tests/http-contract.test.ts: scrubbed environment, VERCEL=1, and
 * a scripted in-memory FakePool injected via withTestDependencies. Covers the
 * new HTML routes: GET /login, GET /staff (session-based tenant resolution),
 * GET /staff/:tenantId dashboard, POST /staff/:tenantId/{stamp,redeem,logout},
 * CSRF/role/cross-tenant gates and HTML escaping. No database, no secrets.
 */

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
// The Vercel Node adapter: its toFetchRequest() is the normalization layer a
// legacy (req, res) invocation goes through before fetchHandler sees it.
const { toFetchRequest } = await import('../api/index');

// --- fixtures (valid UUID shapes) ---
const TENANT = '11111111-1111-4111-8111-111111111111';
const OTHER_TENANT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const CARD = '66666666-6666-4666-8666-666666666666';
const REWARD = '77777777-7777-4777-8777-777777777777';
const RULE = '33333333-3333-4333-8333-333333333333';
const USER_ID = '44444444-4444-4444-8444-444444444444';
const MEMBERSHIP = '55555555-5555-4555-8555-555555555555';

const SESSION_TOKEN = randomToken();
const SESSION_HASH = hashSessionToken(SESSION_TOKEN);
/** The CSRF value the client holds — identical to the stored hash. */
const CSRF_VALUE = hashSessionToken(randomToken());
/** Raw card token shape (base64url, as returned once at card creation). */
const CARD_TOKEN = 'M'.repeat(43);

interface FakeHandler { match: (sql: string, params: unknown[]) => boolean; rows: unknown[] | ((sql: string, params: unknown[]) => unknown[]); }
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
function sessionHandlers(sessionSource: (sql: string, params: unknown[]) => unknown[]): FakeHandler[] {
  return [
    { match: contains('resolve_session_user'), rows: (_s, p) => p[0] === SESSION_HASH ? [{ user_id: USER_ID }] : [] },
    { match: contains('from sessions'), rows: sessionSource },
    { match: contains('update sessions set revoked_at=now() where token_hash'), rows: [] },
    { match: contains('insert into sessions'), rows: [] },
  ];
}
const validSession: (sql: string, params: unknown[]) => unknown[] = (_s, p) =>
  p[0] === SESSION_HASH ? [sessionRow()] : [];

/** Query order for the /staff tenantless entry (no tenant context). */
function entryHandlers(tenants: Array<Record<string, unknown>>): FakeHandler[] {
  return [
    { match: contains('resolve_session_user'), rows: (_s, p) => p[0] === SESSION_HASH ? [{ user_id: USER_ID }] : [] },
    { match: contains('from sessions'), rows: (_s, p) => p[0] === SESSION_HASH ? [{ id: 'sess-1' }] : [] },
    { match: contains('resolve_user_tenants'), rows: tenants },
  ];
}

function runWith(pool: DbPool, fn: () => Promise<unknown>): Promise<unknown> {
  const restore = withTestDependencies({ configured: true, pool, repository: new CardRepository(pool) });
  return fn().finally(restore);
}
function authedHeaders(overrides: Record<string, string> = {}): Headers {
  return new Headers({
    cookie: `__Host-sp_session=${SESSION_TOKEN}`,
    'x-csrf-token': CSRF_VALUE,
    'content-type': 'application/x-www-form-urlencoded',
    ...overrides,
  });
}

/** Dashboard queries + preconditions shared by GET /staff/:tid and the
 *  re-rendered dashboard inside POST responses. The rule hander order keeps
 *  the repository.stamp() rule read (stamps_required from stamp_rules) apart
 *  from the dashboard rule read (created_at desc limit 1). */
function dashboardHandlers(overrides: { tenant?: unknown[]; cards?: unknown[]; events?: unknown[]; rewards?: unknown[]; branding?: unknown[]; stats?: { active?: unknown[]; redeemed?: unknown[]; trend?: unknown[]; fresh?: unknown[]; avg?: unknown[]; ready?: unknown[]; near?: unknown[] } } = {}): FakeHandler[] {
  return [
    { match: contains('from tenants where'), rows: overrides.tenant === undefined
      ? [{ id: TENANT, legalName: 'Beispiel GmbH', planCode: 'up_to_500', customerLimit: 500 }] : overrides.tenant },
    { match: contains('from tenant_branding'), rows: overrides.branding === undefined
      ? [{ cardTitle: 'Meine Karte', cardText: 'Sammel mit!', primaryColor: '#155e75', secondaryColor: '#f8fafc', version: 1 }] : overrides.branding },
    { match: contains('from stamp_rules'), rows: [{ id: RULE, tenantId: TENANT, name: 'Pilot-Regel', stampsRequired: 5, rewardTitle: 'Kaffee', rewardDescription: 'Ein Kaffee gratis', active: true, version: 1 }] },
    { match: contains('from tenant_entry_points'), rows: [{ joinPath: '/join/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }] },
    { match: contains('count(distinct customer_id)'), rows: [{ n: '1' }] },
    { match: contains('order by c.updated_at desc'), rows: overrides.cards === undefined
      ? [{ id: CARD, customerRef: 'Kunde-42', stampCount: 3, updatedAt: '2026-08-26T10:00:00.000Z' }] : overrides.cards },
    { match: contains('order by e.created_at desc'), rows: overrides.events === undefined
      ? [{ id: 'evt-1', cardId: CARD, customerRef: 'Kunde-42', quantity: 1, createdAt: '2026-08-26T10:00:00.000Z' }] : overrides.events },
    { match: contains('order by issued_at asc'), rows: overrides.rewards === undefined
      ? [{ id: REWARD, cardId: CARD, status: 'issued' }] : overrides.rewards },
    // staffStats aggregate reads (distinct match fragments; defaults mirror the
    // repository fixture: 2 active cards, 1 redeemed reward, +50% trend, 1 new
    // card, avg 2.5, 1 ready + 1 near reward). Each card-based aggregate shares
    // the 'from cards c where' fragment, so the active-card match additionally
    // excludes the avg/fresh queries.
    { match: (sql) => sql.includes('from cards c where') && !sql.includes('avg(') && !sql.includes('c.created_at'), rows: overrides.stats?.active === undefined ? [{ n: '2' }] : overrides.stats.active },
    { match: contains('from rewards where'), rows: overrides.stats?.redeemed === undefined ? [{ n: '1' }] : overrides.stats.redeemed },
    { match: contains('sum(quantity) filter'), rows: overrides.stats?.trend === undefined ? [{ last30: '12', prev30: '8' }] : overrides.stats.trend },
    { match: contains('c.created_at >= now()'), rows: overrides.stats?.fresh === undefined ? [{ n: '1' }] : overrides.stats.fresh },
    { match: contains('avg(c.stamp_count)'), rows: overrides.stats?.avg === undefined ? [{ avg: '2.5' }] : overrides.stats.avg },
    { match: contains('w.status=$3'), rows: overrides.stats?.ready === undefined ? [{ n: '1' }] : overrides.stats.ready },
    { match: contains('0.75 * r.stamps_required'), rows: overrides.stats?.near === undefined ? [{ n: '1' }] : overrides.stats.near },
  ];
}

/** Shared assertions: the dashboard HTML renders staff-relevant data and
 *  never leaks session/token internals. */
function expectDashboardHtml(html: string) {
  expect(html).toContain('Beispiel GmbH');
  expect(html).toContain('Meine Karte');
  expect(html).toContain('Kaffee');
  expect(html).toContain('Kunde-42');
  expect(html).toContain('/join/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  expect(html).toContain(`name="sp-csrf" content="`);
  expect(html).toContain(`data-action="logout"`);
  expect(html).toContain('/staff/11111111-1111-4111-8111-111111111111/stamp');
  // Statistics section (all roles see it, aggregates only).
  expect(html).toContain('<h2>Statistik</h2>');
  expect(html).toContain('Stempelaktivität als Verkaufsindikator.');
  for (const marker of ['publicTokenHash', 'public_token_hash', 'employeeMembershipId', 'employee_membership_id', 'csrf_token_hash']) {
    expect(html).not.toContain(marker);
  }
  expect(html).not.toContain(SESSION_TOKEN);
}

// ---------------------------------------------------------------------------
// (1) GET /login — static staff login form
// ---------------------------------------------------------------------------
test('GET /login renders the staff login form without any server state', async () => {
  const pool = new FakePool([]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/login'));
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');
    const html = await res.text();
    expect(html).toContain('<form id="login-form">');
    expect(html).toContain('name="email"');
    expect(html).toContain('type="password"');
    expect(html).toContain('name="mfaCode"');
    expect(html).toContain('/api/auth/login');
    expect(html).toContain('location.href = \'/staff\'');
    // No session/CSRF/secrets are ever embedded in the login page.
    expect(html).not.toContain('csrf');
    expect(html).not.toContain(SESSION_TOKEN);
    expect(pool.queries).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// (2) GET /staff — session-based tenant resolution
// ---------------------------------------------------------------------------
test('GET /staff without a session redirects to /login without touching the database', async () => {
  const pool = new FakePool([]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/staff'));
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/login');
    expect(pool.queries).toHaveLength(0);
  });
});

test('GET /staff with a valid single-tenant session redirects to the tenant dashboard', async () => {
  const pool = new FakePool([...entryHandlers([{ tenantId: TENANT, role: 'owner' }])]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/staff', { headers: { cookie: `__Host-sp_session=${SESSION_TOKEN}` } }));
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe(`/staff/${TENANT}`);
  });
});

test('GET /staff with multiple tenants renders a chooser with tenant names', async () => {
  const pool = new FakePool([
    ...entryHandlers([
      { tenantId: TENANT, role: 'owner' },
      { tenantId: OTHER_TENANT, role: 'staff' },
    ]),
    { match: contains('from tenants where id = any'), rows: [{ id: TENANT, legalName: 'Firma A' }, { id: OTHER_TENANT, legalName: 'Firma B' }] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/staff', { headers: { cookie: `__Host-sp_session=${SESSION_TOKEN}` } }));
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('Unternehmen wählen');
    expect(html).toContain(`href="/staff/${TENANT}"`);
    expect(html).toContain('Firma A');
    expect(html).toContain('Firma B');
  });
});

test('GET /staff with a session without tenants renders the no-access page', async () => {
  const pool = new FakePool([...entryHandlers([])]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/staff', { headers: { cookie: `__Host-sp_session=${SESSION_TOKEN}` } }));
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('Kein aktiver Zugang');
  });
});

test('GET /staff with an invalid session redirects to /login (no tenant data leaked)', async () => {
  const pool = new FakePool([...entryHandlers([])]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/staff', { headers: { cookie: '__Host-sp_session=forged' } }));
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/login');
  });
});

// ---------------------------------------------------------------------------
// (3) GET /staff/:tenantId — dashboard
// ---------------------------------------------------------------------------
test('GET /staff/:tenantId without a session redirects to /login', async () => {
  const pool = new FakePool([]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}`));
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/login');
  });
});

test('GET /staff/:tenantId renders the dashboard with tenant/branding/rule/cards/events and a CSRF meta', async () => {
  const pool = new FakePool([...sessionHandlers(validSession), ...dashboardHandlers()]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}`, { headers: { cookie: `__Host-sp_session=${SESSION_TOKEN}` } }));
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');
    const html = await res.text();
    expectDashboardHtml(html);
    // The CSRF meta carries exactly the stored hash the client must submit.
    expect(html).toContain(`name="sp-csrf" content="${CSRF_VALUE}"`);
    // Staff stamp form present (role staff can stamp).
    expect(html).toContain('data-staff-form');
    expect(html).toContain('Prämie einlösen');
  });
});

test('GET /staff/:tenantId escapes all dynamic values (XSS-safe HTML)', async () => {
  const pool = new FakePool([
    ...sessionHandlers(validSession),
    ...dashboardHandlers({
      tenant: [{ id: TENANT, legalName: '<script>alert(1)</script>', planCode: 'up_to_500', customerLimit: 500 }],
      branding: [{ cardTitle: 'Karte <b>fett</b>', cardText: 'Text "mit" \'quotes\' & mehr', primaryColor: '#155e75', secondaryColor: '#f8fafc', version: 1 }],
      cards: [{ id: CARD, customerRef: '<img src=x onerror=alert(1)>', stampCount: 1, updatedAt: null }],
    }),
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}`, { headers: { cookie: `__Host-sp_session=${SESSION_TOKEN}` } }));
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('Karte &lt;b&gt;fett&lt;/b&gt;');
    expect(html).not.toContain('<b>fett</b>');
    expect(html).toContain('Text &quot;mit&quot; &#39;quotes&#39; &amp; mehr');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(html).not.toContain('<img src=x');
  });
});

test('GET /staff/:tenantId for a foreign tenant session redirects to /login (tenant-scoped lookup)', async () => {
  const tenantScoped: (sql: string, params: unknown[]) => unknown[] = (_s, p) =>
    p[0] === SESSION_HASH && p[2] === TENANT ? [sessionRow()] : [];
  const pool = new FakePool([...sessionHandlers(tenantScoped)]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${OTHER_TENANT}`, { headers: { cookie: `__Host-sp_session=${SESSION_TOKEN}` } }));
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/login');
  });
});

test('GET /staff/:tenantId with a malformed tenant id answers a friendly 404', async () => {
  const pool = new FakePool([]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request('http://test.local/staff/not-a-uuid'));
    expect(res.status).toBe(404);
    expect((await res.text())).toContain('Unternehmen nicht gefunden oder deaktiviert.');
  });
});

test('GET /staff/:tenantId hides stamp actions for viewer roles', async () => {
  const viewerRow = sessionRow({ role: 'viewer' });
  const viewerSession: (sql: string, params: unknown[]) => unknown[] = (_s, p) => p[0] === SESSION_HASH ? [viewerRow] : [];
  const pool = new FakePool([...sessionHandlers(viewerSession), ...dashboardHandlers()]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}`, { headers: { cookie: `__Host-sp_session=${SESSION_TOKEN}` } }));
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('Diese Rolle kann keine Stempel vergeben');
    expect(html).not.toContain('data-action="stamp"');
    expect(html).not.toContain('data-action="redeem"');
    expect(html).not.toContain('<form data-staff-form');
  });
});

test('GET /staff/:tenantId renders the statistics section: KPIs, trend with German formatting and reward-progress rows (visible to every role)', async () => {
  const pool = new FakePool([...sessionHandlers(validSession), ...dashboardHandlers()]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}`, { headers: { cookie: `__Host-sp_session=${SESSION_TOKEN}` } }));
    expect(res.status).toBe(200);
    const html = await res.text();
    // KPI boxes (labels + values).
    expect(html).toContain('<div class="kpi"><div class="v">2</div><div class="l">Aktive Karten</div>');
    expect(html).toContain('<div class="kpi"><div class="v">1</div><div class="l">Eingelöste Prämien</div>');
    expect(html).toContain('<div class="kpi"><div class="v">2,5</div><div class="l">Ø Stempelstand</div>');
    expect(html).toContain('<div class="kpi"><div class="v">1</div><div class="l">Neue Karten (30 Tage)</div>');
    // Compact table: windows, trend (+50 % → German comma, signed), progress.
    expect(html).toContain('Stempelaktivität (letzte 30 Tage)</td><td><strong>12</strong>');
    expect(html).toContain('Stempelaktivität (30 Tage davor)</td><td><strong>8</strong>');
    expect(html).toContain('Trend</td><td><strong>+50,0 %</strong>');
    expect(html).toContain('Prämien bereit zur Einlösung</td><td><strong>1</strong>');
    expect(html).toContain('Kurz vor der Prämie</td><td><strong>1</strong>');
    // Hint text marks stamp activity as the sales indicator.
    expect(html).toContain('Stempelaktivität als Verkaufsindikator.');
  });
});

test('GET /staff/:tenantId renders an em dash trend when the previous 30-day window has no data', async () => {
  const pool = new FakePool([
    ...sessionHandlers(validSession),
    ...dashboardHandlers({ stats: { trend: [{ last30: '3', prev30: '0' }] } }),
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}`, { headers: { cookie: `__Host-sp_session=${SESSION_TOKEN}` } }));
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('Trend</td><td><strong>—</strong>');
    // The current window still shows its value.
    expect(html).toContain('Stempelaktivität (letzte 30 Tage)</td><td><strong>3</strong>');
  });
});

// ---------------------------------------------------------------------------
// (4) POST /staff/:tenantId/stamp — card id and card token, CSRF, rotation
// ---------------------------------------------------------------------------
function stampFlowHandlers(): FakeHandler[] {
  return [
    ...sessionHandlers(validSession),
    { match: contains('from stamp_events where'), rows: [] }, // no replay
    { match: contains('from cards where'), rows: [{ id: CARD, stampCount: 3, revision: 2, ruleId: RULE }] },
    { match: contains('insert into stamp_events'), rows: [] },
    { match: contains('update cards set stamp_count'), rows: [{ id: CARD, stampCount: 4, revision: 3 }] },
    { match: contains('stamps_required from stamp_rules'), rows: [{ id: RULE, stamps_required: 5 }] },
    { match: contains('(select 1 from rewards'), rows: [] }, // threshold not crossed
    ...dashboardHandlers(),
  ];
}

test('POST staff stamp by card id stamps once, rotates the session and re-renders the dashboard with the new count', async () => {
  stampLimiter.clear();
  const pool = new FakePool(stampFlowHandlers());
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}/stamp`, {
      method: 'POST',
      headers: authedHeaders(),
      body: new URLSearchParams({ cardId: CARD, quantity: '1' }),
    }));
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');
    const html = await res.text();
    // Flash shows the new stamp count.
    expect(html).toContain('Stempel vergeben');
    expect(html).toContain('hat jetzt 4 Stempel');
    // Session rotation: fresh cookie + fresh CSRF header + freshly embedded CSRF.
    expect(res.headers.get('set-cookie')).toContain('__Host-sp_session=');
    const rotatedCsrf = res.headers.get('x-csrf-token');
    expect(rotatedCsrf).toMatch(/^[0-9a-f]{64}$/);
    expect(rotatedCsrf).not.toBe(CSRF_VALUE);
    expect(html).toContain(`name="sp-csrf" content="${rotatedCsrf}"`);
    // Exactly one stamp_events insert with an idempotency key (fresh UUID).
    const inserts = pool.queries.filter(q => q.sql.startsWith('insert into stamp_events'));
    expect(inserts).toHaveLength(1);
    expect(String(inserts[0]!.params[4])).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    // Re-render keeps the dashboard exclusive fields.
    expectDashboardHtml(html);
  });
});

test('POST staff stamp by card token resolves through findByPublicTokenHash (hash only, never the raw token)', async () => {
  stampLimiter.clear();
  const pool = new FakePool([
    ...sessionHandlers(validSession),
    { match: contains('public_token_hash'), rows: [{ id: CARD, tenantId: TENANT, customerId: '22222222-2222-4222-8222-222222222222', publicTokenHash: 'f'.repeat(64), status: 'active', stampCount: 3, revision: 2, ruleId: RULE, createdAt: null, updatedAt: null }] },
    { match: contains('from stamp_events where'), rows: [] },
    { match: contains('from cards where'), rows: [{ id: CARD, stampCount: 3, revision: 2, ruleId: RULE }] },
    { match: contains('insert into stamp_events'), rows: [] },
    { match: contains('update cards set stamp_count'), rows: [{ id: CARD, stampCount: 4, revision: 3 }] },
    { match: contains('stamps_required from stamp_rules'), rows: [{ id: RULE, stamps_required: 5 }] },
    { match: contains('(select 1 from rewards'), rows: [] },
    ...dashboardHandlers(),
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}/stamp`, {
      method: 'POST',
      headers: authedHeaders(),
      body: new URLSearchParams({ cardId: CARD_TOKEN, quantity: '1' }),
    }));
    expect(res.status).toBe(200);
    // The lookup only ever saw the SHA-256 hash, never the raw token.
    const lookup = pool.queries.find(q => q.sql.includes('public_token_hash'));
    expect(lookup).toBeDefined();
    expect(String(lookup!.params[1])).toMatch(/^[a-f0-9]{64}$/);
    expect(String(lookup!.params[1])).not.toBe(CARD_TOKEN);
    expect(JSON.stringify(pool.queries)).not.toContain(CARD_TOKEN);
  });
});

test('POST staff stamp without a CSRF token is rejected with a friendly HTML 403 and no insert', async () => {
  const pool = new FakePool([...sessionHandlers(validSession), ...dashboardHandlers()]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}/stamp`, {
      method: 'POST',
      headers: { cookie: `__Host-sp_session=${SESSION_TOKEN}`, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ cardId: CARD }),
    }));
    expect(res.status).toBe(403);
    const html = await res.text();
    expect(html).toContain('Sitzung abgelaufen. Bitte neu anmelden.');
    expect(pool.queries.some(q => q.sql.startsWith('insert into stamp_events'))).toBe(false);
  });
});

test('POST staff stamp by a viewer is rejected with FORBIDDEN', async () => {
  const viewerRow = sessionRow({ role: 'viewer' });
  const viewerSession: (sql: string, params: unknown[]) => unknown[] = (_s, p) => p[0] === SESSION_HASH ? [viewerRow] : [];
  const pool = new FakePool([...sessionHandlers(viewerSession)]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}/stamp`, {
      method: 'POST',
      headers: authedHeaders(),
      body: new URLSearchParams({ cardId: CARD }),
    }));
    expect(res.status).toBe(403);
    expect(await res.text()).toContain('Keine Berechtigung für diese Aktion.');
    expect(pool.queries.some(q => q.sql.startsWith('insert into stamp_events'))).toBe(false);
  });
});

test('POST staff stamp without a card id is rejected with CARD_FIELDS_REQUIRED', async () => {
  stampLimiter.clear();
  const pool = new FakePool([...sessionHandlers(validSession)]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}/stamp`, {
      method: 'POST',
      headers: authedHeaders(),
      body: new URLSearchParams({ quantity: '1' }),
    }));
    expect(res.status).toBe(400);
    expect(await res.text()).toContain('Bitte eine Karten-ID oder einen Karten-Token angeben.');
  });
});

// ---------------------------------------------------------------------------
// (5) POST /staff/:tenantId/redeem
// ---------------------------------------------------------------------------
test('POST staff redeem issues the redemption and rotates the session', async () => {
  const pool = new FakePool([
    ...sessionHandlers(validSession),
    { match: contains('update rewards set status'), rows: [{ id: REWARD, status: 'redeemed', card_id: CARD }] },
    { match: contains('update cards set stamp_count=0'), rows: [] },
    // Post-redeem dashboard: the card counter is back to 0 (new collection round).
    ...dashboardHandlers({
      rewards: [{ id: REWARD, cardId: CARD, status: 'redeemed' }],
      cards: [{ id: CARD, customerRef: 'Kunde-42', stampCount: 0, updatedAt: '2026-08-26T10:00:00.000Z' }],
    }),
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}/redeem`, {
      method: 'POST',
      headers: authedHeaders(),
      body: new URLSearchParams({ rewardId: REWARD }),
    }));
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('Prämie erfolgreich eingelöst.');
    expect(res.headers.get('set-cookie')).toContain('__Host-sp_session=');
    expect(res.headers.get('x-csrf-token')).toMatch(/^[0-9a-f]{64}$/);
    expect(html).toContain('badge redeemed');
    // Owner fix 2026-09-13: redemption resets the counter — the dashboard shows
    // 0 / 5 instead of 5 / 5, so the next reward needs five fresh stamps.
    expect(html).toContain('0 / 5');
    const reset = pool.queries.find(q => q.sql.includes('update cards set stamp_count=0'));
    expect(reset?.params).toEqual([TENANT, CARD]);
  });
});

test('POST staff redeem of an already-redeemed reward answers a friendly 409 without rotation', async () => {
  const pool = new FakePool([
    ...sessionHandlers(validSession),
    { match: contains('update rewards set status'), rows: [] },
    { match: contains('select id,status from rewards'), rows: [{ id: REWARD, status: 'redeemed' }] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}/redeem`, {
      method: 'POST',
      headers: authedHeaders(),
      body: new URLSearchParams({ rewardId: REWARD }),
    }));
    expect(res.status).toBe(409);
    expect(await res.text()).toContain('Diese Prämie wurde bereits eingelöst.');
    expect(res.headers.get('set-cookie')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// (5b) Form-POST regression (Vercel runtime): for
// application/x-www-form-urlencoded (the exact content type the staff UI
// sends) the deployed runtime delivers an unusable body on BOTH higher-level
// readers while req.json() keeps working:
//   - req.formData() THROWS ('Could not parse content as FormData.'),
//   - req.text() returns an EMPTY string (live evidence: form-POST stamp
//     answers 400 CARD_FIELDS_REQUIRED and redeem 404 REWARD_NOT_FOUND — a
//     400/404, not a 500, so the read itself does not throw).
// The old parseBody blanket catch{} turned the formData throw into {}; the
// URLSearchParams-over-text variant (PR #19) turned the empty text into {} —
// same 400, verified live on the production alias. Simulate the broken
// runtime by patching Request.prototype.formData to throw AND
// Request.prototype.text to return '' , then drive the REAL fetchHandler with
// urlencoded bodies. Request.prototype.arrayBuffer() — the primitive read
// both methods are built on, and the one the working req.json() path reaches
// the buffered bytes through — is deliberately NOT patched, mirroring Vercel
// where urlencoded bodies are only readable at that primitive level.
// ---------------------------------------------------------------------------
async function withBrokenFormReaders(fn: () => Promise<unknown>): Promise<unknown> {
  const originalFormData = Request.prototype.formData;
  const originalText = Request.prototype.text;
  Request.prototype.formData = async function () {
    throw new TypeError('Could not parse content as FormData.');
  } as typeof originalFormData;
  Request.prototype.text = async function () { return ''; } as typeof originalText;
  try {
    return await fn();
  } finally {
    Request.prototype.formData = originalFormData;
    Request.prototype.text = originalText;
  }
}

test('POST staff stamp: urlencoded form body still stamps when req.formData()/req.text() are broken (Vercel regression)', async () => {
  stampLimiter.clear();
  const pool = new FakePool(stampFlowHandlers());
  await runWith(pool, async () => {
    await withBrokenFormReaders(async () => {
      const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}/stamp`, {
        method: 'POST',
        headers: authedHeaders(),
        body: new URLSearchParams({ cardId: CARD, quantity: '1' }),
      }));
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain('Stempel vergeben');
      expect(html).toContain('hat jetzt 4 Stempel');
      expect(res.headers.get('x-csrf-token')).toMatch(/^[0-9a-f]{64}$/);
    });
  });
});

test('POST staff redeem: urlencoded form body redeems, double redemption stays 409 when req.formData()/req.text() are broken (Vercel regression)', async () => {
  const successPool = new FakePool([
    ...sessionHandlers(validSession),
    { match: contains('update rewards set status'), rows: [{ id: REWARD, status: 'redeemed', card_id: CARD }] },
    { match: contains('update cards set stamp_count=0'), rows: [] },
    ...dashboardHandlers({ rewards: [{ id: REWARD, cardId: CARD, status: 'redeemed' }] }),
  ]);
  await runWith(successPool, async () => {
    await withBrokenFormReaders(async () => {
      const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}/redeem`, {
        method: 'POST',
        headers: authedHeaders(),
        body: new URLSearchParams({ rewardId: REWARD }),
      }));
      expect(res.status).toBe(200);
      expect(await res.text()).toContain('Prämie erfolgreich eingelöst.');
    });
  });
  const conflictPool = new FakePool([
    ...sessionHandlers(validSession),
    { match: contains('update rewards set status'), rows: [] },
    { match: contains('select id,status from rewards'), rows: [{ id: REWARD, status: 'redeemed' }] },
  ]);
  await runWith(conflictPool, async () => {
    await withBrokenFormReaders(async () => {
      const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}/redeem`, {
        method: 'POST',
        headers: authedHeaders(),
        body: new URLSearchParams({ rewardId: REWARD }),
      }));
      expect(res.status).toBe(409);
      expect(await res.text()).toContain('Diese Prämie wurde bereits eingelöst.');
    });
  });
});

// ---------------------------------------------------------------------------
// (5c) JSON action-POST regression (staff UI wire format, PR #21)
// The staff dashboard script now submits stamp/redeem/logout as JSON — the
// content type live-verified working on every runtime (the deployed Vercel
// Node runtime delivers urlencoded bodies unusably: live 400/404, while ALL
// JSON paths answer 200). These tests pin that the JSON payloads the UI
// produces (cardId | cardToken, quantity, rewardId — strings, exactly like
// the data-attributes/FormData the script collects) drive the REAL
// fetchHandler the same way the urlencoded tests do: stamp +1, redeem 200,
// second redemption 409, logout 302. The urlencoded tests above stay in
// place for native/curl form-POSTs (adapter layer rewrites them).
// ---------------------------------------------------------------------------
test('dashboard HTML embeds a JSON-only staff script (no urlencoded client fetch)', async () => {
  const pool = new FakePool([...sessionHandlers(validSession), ...dashboardHandlers()]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}`, { headers: { cookie: `__Host-sp_session=${SESSION_TOKEN}` } }));
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("'content-type': 'application/json'");
    expect(html).toContain('JSON.stringify(toObject(data || {}))');
    expect(html).not.toContain('new URLSearchParams');
  });
});

test('POST staff stamp with the UI JSON payload (cardId) stamps once and rotates the session', async () => {
  stampLimiter.clear();
  const pool = new FakePool(stampFlowHandlers());
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}/stamp`, {
      method: 'POST',
      headers: authedHeaders({ 'content-type': 'application/json' }),
      body: JSON.stringify({ cardId: CARD, quantity: '1' }),
    }));
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('Stempel vergeben');
    expect(html).toContain('hat jetzt 4 Stempel');
    const rotatedCsrf = res.headers.get('x-csrf-token');
    expect(rotatedCsrf).toMatch(/^[0-9a-f]{64}$/);
    expect(rotatedCsrf).not.toBe(CSRF_VALUE);
    expect(html).toContain(`name="sp-csrf" content="${rotatedCsrf}"`);
    const inserts = pool.queries.filter(q => q.sql.startsWith('insert into stamp_events'));
    expect(inserts).toHaveLength(1);
  });
});

test('POST staff stamp with the UI JSON payload (raw card token) resolves via token hash, never the raw token', async () => {
  stampLimiter.clear();
  const pool = new FakePool([
    ...sessionHandlers(validSession),
    { match: contains('public_token_hash'), rows: [{ id: CARD, tenantId: TENANT, customerId: '22222222-2222-4222-8222-222222222222', publicTokenHash: 'f'.repeat(64), status: 'active', stampCount: 3, revision: 2, ruleId: RULE, createdAt: null, updatedAt: null }] },
    { match: contains('from stamp_events where'), rows: [] },
    { match: contains('from cards where'), rows: [{ id: CARD, stampCount: 3, revision: 2, ruleId: RULE }] },
    { match: contains('insert into stamp_events'), rows: [] },
    { match: contains('update cards set stamp_count'), rows: [{ id: CARD, stampCount: 4, revision: 3 }] },
    { match: contains('stamps_required from stamp_rules'), rows: [{ id: RULE, stamps_required: 5 }] },
    { match: contains('(select 1 from rewards'), rows: [] },
    ...dashboardHandlers(),
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}/stamp`, {
      method: 'POST',
      headers: authedHeaders({ 'content-type': 'application/json' }),
      body: JSON.stringify({ cardId: CARD_TOKEN, quantity: '1' }),
    }));
    expect(res.status).toBe(200);
    const lookup = pool.queries.find(q => q.sql.includes('public_token_hash'));
    expect(lookup).toBeDefined();
    expect(String(lookup!.params[1])).toMatch(/^[a-f0-9]{64}$/);
    expect(String(lookup!.params[1])).not.toBe(CARD_TOKEN);
    expect(JSON.stringify(pool.queries)).not.toContain(CARD_TOKEN);
  });
});

test('POST staff redeem with the UI JSON payload issues the redemption and rotates the session', async () => {
  const pool = new FakePool([
    ...sessionHandlers(validSession),
    { match: contains('update rewards set status'), rows: [{ id: REWARD, status: 'redeemed', card_id: CARD }] },
    { match: contains('update cards set stamp_count=0'), rows: [] },
    ...dashboardHandlers({
      rewards: [{ id: REWARD, cardId: CARD, status: 'redeemed' }],
      cards: [{ id: CARD, customerRef: 'Kunde-42', stampCount: 0, updatedAt: '2026-08-26T10:00:00.000Z' }],
    }),
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}/redeem`, {
      method: 'POST',
      headers: authedHeaders({ 'content-type': 'application/json' }),
      body: JSON.stringify({ rewardId: REWARD }),
    }));
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('Prämie erfolgreich eingelöst.');
    expect(res.headers.get('x-csrf-token')).toMatch(/^[0-9a-f]{64}$/);
    // Owner fix 2026-09-13: the redeemed card renders 0 / 5 (new round).
    expect(html).toContain('0 / 5');
    const reset = pool.queries.find(q => q.sql.includes('update cards set stamp_count=0'));
    expect(reset?.params).toEqual([TENANT, CARD]);
  });
});

test('POST staff redeem with the UI JSON payload: second redemption stays 409 REWARD_ALREADY_REDEEMED', async () => {
  const pool = new FakePool([
    ...sessionHandlers(validSession),
    { match: contains('update rewards set status'), rows: [] },
    { match: contains('select id,status from rewards'), rows: [{ id: REWARD, status: 'redeemed' }] },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}/redeem`, {
      method: 'POST',
      headers: authedHeaders({ 'content-type': 'application/json' }),
      body: JSON.stringify({ rewardId: REWARD }),
    }));
    expect(res.status).toBe(409);
    expect(await res.text()).toContain('Diese Prämie wurde bereits eingelöst.');
    expect(res.headers.get('set-cookie')).toBeNull();
  });
});

test('POST staff logout with the UI JSON payload revokes the session, clears the cookie and redirects to /login', async () => {
  const pool = new FakePool([...sessionHandlers(validSession)]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}/logout`, {
      method: 'POST',
      headers: authedHeaders({ 'content-type': 'application/json' }),
      body: JSON.stringify({}),
    }));
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/login');
    const setCookie = res.headers.get('set-cookie') ?? '';
    expect(setCookie).toContain('__Host-sp_session=;');
    expect(setCookie).toContain('Max-Age=0');
    const revoke = pool.queries.find(q => q.sql.includes('update sessions set revoked_at=now() where token_hash'));
    expect(revoke).toBeDefined();
    expect(revoke!.params).toEqual([SESSION_HASH]);
  });
});

// ---------------------------------------------------------------------------
// (5d) Full production chain (the live-verified Vercel shape): the legacy
// Node request arrives with the urlencoded form PRE-PARSED as an OBJECT on
// `body` and NO `rawBody`. The adapter's toFetchRequest() must rebuild the
// urlencoded wire format (URLSearchParams), after which fetchHandler's form
// branch of parseBody parses the fields and stamps +1. Before the adapter
// fix this chain produced JSON text under a urlencoded content-type → the
// form branch parsed {} → live 400 CARD_FIELDS_REQUIRED.
// ---------------------------------------------------------------------------
test('production chain: legacy urlencoded req (object body, no rawBody) → adapter → fetchHandler stamps +1', async () => {
  stampLimiter.clear();
  const pool = new FakePool(stampFlowHandlers());
  await runWith(pool, async () => {
    const req = toFetchRequest({
      method: 'POST',
      url: `/staff/${TENANT}/stamp`,
      headers: {
        host: 'test.local',
        'x-forwarded-proto': 'https',
        cookie: `__Host-sp_session=${SESSION_TOKEN}`,
        'x-csrf-token': CSRF_VALUE,
        'content-type': 'application/x-www-form-urlencoded',
        'content-length': '999', // stale (rewritten) — must be dropped
      },
      body: { cardId: CARD, quantity: '1' }, // bridge parse; NO rawBody
    });
    const res = await fetchHandler(req);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('Stempel vergeben');
    expect(html).toContain('hat jetzt 4 Stempel');
    expect(res.headers.get('x-csrf-token')).toMatch(/^[0-9a-f]{64}$/);
    const inserts = pool.queries.filter(q => q.sql.startsWith('insert into stamp_events'));
    expect(inserts).toHaveLength(1);
  });
});

test('production chain: legacy urlencoded redeem req (object body, no rawBody) → adapter → fetchHandler redeems 200, second 409', async () => {
  const successPool = new FakePool([
    ...sessionHandlers(validSession),
    { match: contains('update rewards set status'), rows: [{ id: REWARD, status: 'redeemed' }] },
    ...dashboardHandlers({ rewards: [{ id: REWARD, cardId: CARD, status: 'redeemed' }] }),
  ]);
  const legacyRedeem = () => toFetchRequest({
    method: 'POST',
    url: `/staff/${TENANT}/redeem`,
    headers: {
      host: 'test.local',
      'x-forwarded-proto': 'https',
      cookie: `__Host-sp_session=${SESSION_TOKEN}`,
      'x-csrf-token': CSRF_VALUE,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: { rewardId: REWARD }, // bridge parse; NO rawBody
  });
  await runWith(successPool, async () => {
    const res = await fetchHandler(legacyRedeem());
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('Prämie erfolgreich eingelöst.');
  });
  const conflictPool = new FakePool([
    ...sessionHandlers(validSession),
    { match: contains('update rewards set status'), rows: [] },
    { match: contains('select id,status from rewards'), rows: [{ id: REWARD, status: 'redeemed' }] },
  ]);
  await runWith(conflictPool, async () => {
    const res = await fetchHandler(legacyRedeem());
    expect(res.status).toBe(409);
    expect(await res.text()).toContain('Diese Prämie wurde bereits eingelöst.');
  });
});

// ---------------------------------------------------------------------------
// (6) POST /staff/:tenantId/logout
// ---------------------------------------------------------------------------
test('POST staff logout revokes the session, clears the cookie and redirects to /login', async () => {
  const pool = new FakePool([...sessionHandlers(validSession)]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}/logout`, {
      method: 'POST',
      headers: authedHeaders(),
      body: new URLSearchParams({}),
    }));
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/login');
    const setCookie = res.headers.get('set-cookie') ?? '';
    expect(setCookie).toContain('__Host-sp_session=;');
    expect(setCookie).toContain('Max-Age=0');
    // The revoke ran under the actor user context.
    const revoke = pool.queries.find(q => q.sql.includes('update sessions set revoked_at=now() where token_hash'));
    expect(revoke).toBeDefined();
    expect(revoke!.params).toEqual([SESSION_HASH]);
  });
});

// ---------------------------------------------------------------------------
// (7) Error rendering — never internal details, request id only for 500s
// ---------------------------------------------------------------------------
test('staff routes render internal failures as friendly HTML 500 with a request id, no internals', async () => {
  const pool = new FakePool([
    ...sessionHandlers(validSession),
    { match: contains('from tenants where'), rows: () => { throw new Error('secret dsn postgres://u:p@host/db'); } },
  ]);
  await runWith(pool, async () => {
    const res = await fetchHandler(new Request(`http://test.local/staff/${TENANT}`, { headers: { cookie: `__Host-sp_session=${SESSION_TOKEN}` } }));
    expect(res.status).toBe(500);
    const html = await res.text();
    expect(html).toContain('Ein unerwarteter Fehler ist aufgetreten.');
    expect(html).toContain('Fehlerkennung:');
    expect(html).not.toContain('postgres://');
    expect(html).not.toContain('secret');
  });
});