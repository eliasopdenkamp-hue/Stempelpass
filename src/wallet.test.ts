import { test, expect } from 'bun:test';
import { GoogleWalletAdapter, GoogleWalletApiClassProvisioner, PrivateKeyJwtSigner, IamSignBlobJwtSigner, walletAdapter, googleWalletConfiguration, ensureGoogleWalletClass, tenantClassModel, DEFAULT_CLASS_LOGO_URI } from './wallet';
import { ExternalAccountCredentials, ServiceAccountJsonCredentials } from './gcp-credentials';
const card = { id:'card-1', tenantId:'tenant-1', customerId:'customer-1', publicTokenHash:'hash', status:'active' as const, stampCount:3, revision:2, ruleId:'rule-1', cardCode:'7F3D2A' };
const branding = { cardTitle:'Café', cardText:'Treuekarte', primaryColor:'#123456', secondaryColor:'#fff', version:1 };
const GOOGLE_ENV = ['GOOGLE_ISSUER_ID', 'GOOGLE_SERVICE_ACCOUNT_JSON', 'GOOGLE_SERVICE_ACCOUNT_EMAIL', 'GOOGLE_PRIVATE_KEY', 'GOOGLE_EXTERNAL_ACCOUNT_JSON', 'GOOGLE_APPLICATION_CREDENTIALS', 'VERCEL_OIDC_TOKEN'] as const;
function withCleanEnv<T>(fn: () => Promise<T>): Promise<T> {
  const old = Object.fromEntries(GOOGLE_ENV.map(name => [name, process.env[name]]));
  try {
    for (const name of GOOGLE_ENV) delete process.env[name];
    return fn();
  } finally {
    for (const name of GOOGLE_ENV) old[name] === undefined ? delete process.env[name] : process.env[name] = old[name]!;
  }
}

test('google adapter without credentials is honest', async () => withCleanEnv(async () => {
  const result = await walletAdapter('google').issue(card, branding);
  expect(result).toEqual({ provider: 'google', status: 'not_configured', message: 'google wallet is not configured; no pass was created.' });
  expect(result.artifact).toBeUndefined();
}));

test('apple adapter remains unavailable without credentials', async () => {
  const names = ['APPLE_PRIVATE_KEY', 'APPLE_TEAM_IDENTIFIER', 'APPLE_PASS_TYPE_IDENTIFIER'] as const;
  const old = Object.fromEntries(names.map(name => [name, process.env[name]]));
  try {
    for (const name of names) delete process.env[name];
    const result = await walletAdapter('apple').issue(card, branding);
    expect(result).toEqual({ provider: 'apple', status: 'not_configured', message: 'apple wallet is not configured; no pass was created.' });
    expect(result.artifact).toBeUndefined();
  } finally {
    for (const name of names) old[name] === undefined ? delete process.env[name] : process.env[name] = old[name]!;
  }
});

test('google adapter signs a loyalty JWT with supplied test key (fallback mode)', async () => {
  const key = await Bun.$`openssl genrsa 2048 2>/dev/null`.text();
  const adapter = new GoogleWalletAdapter('123', new PrivateKeyJwtSigner(key), 'test@example.invalid', 'service-account-json');
  const result = await adapter.issue(card, branding, { stampRequired: 10, rewardTitle: 'Gratis' });
  expect(result.status).toBe('issued');
  expect(result.message).toBe('Save to Google Wallet');
  expect(result.artifact?.split('.')).toHaveLength(3);
  const payload = JSON.parse(Buffer.from(result.artifact!.split('.')[1], 'base64url').toString('utf8'));
  expect(payload.iss).toBe('test@example.invalid');
  expect(payload.aud).toBe('google');
  expect(payload.typ).toBe('savetowallet');
  expect(payload.payload.loyaltyObjects[0].id).toBe('123.card-1');
});

test('walletAdapter resolves the classic fallback from GOOGLE_SERVICE_ACCOUNT_JSON', async () => withCleanEnv(async () => {
  const key = await Bun.$`openssl genrsa 2048 2>/dev/null`.text();
  process.env.GOOGLE_ISSUER_ID = '123';
  const calls: Array<{ url: string; init: RequestInit }> = [];
  process.env.GOOGLE_SERVICE_ACCOUNT_JSON = JSON.stringify({ client_email: 'sa@example.invalid', private_key: key });
  const result = await walletAdapter('google', { fetchFn: mockGoogleFetch(calls) }).issue(card, branding);
  expect(result.status).toBe('issued');
  expect(result.artifact?.split('.')).toHaveLength(3);
  // Deterministic provisioning chain: oauth token → GET class (exists) →
  // PATCH class with the tenant branding (class GET returns only {id}, so the
  // branding-relevant fields differ). The class id is the APPROVED pilot class.
  expect(calls.map(c => c.url)).toEqual([
    'https://oauth2.googleapis.com/token',
    'https://walletobjects.googleapis.com/walletobjects/v1/loyaltyClass/123.stempelpass_loyalty',
    'https://walletobjects.googleapis.com/walletobjects/v1/loyaltyClass/123.stempelpass_loyalty',
  ]);
  const classCalls = calls.filter(c => c.url.includes('/loyaltyClass/'));
  expect(classCalls.map(c => c.init?.method ?? 'GET')).toEqual(['GET', 'PATCH']);
}));

const EAC_CONFIG = JSON.stringify({
  type: 'external_account',
  audience: '//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/vercel/providers/vercel',
  subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
  token_url: 'https://sts.googleapis.com/v1/token',
  service_account_impersonation_url: 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/wallet-sa@project.iam.gserviceaccount.com:generateAccessToken',
});

/** Mock Google HTTP surface: STS exchange + impersonation + signBlob. No real network. */
function mockGoogleFetch(calls: Array<{ url: string; init: RequestInit }>): typeof fetch {
  const fakeFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    calls.push({ url, init: init ?? {} });
    if (url.endsWith('/token') && url.includes('sts.googleapis.com')) {
      return new Response(JSON.stringify({ access_token: 'sts-token', expires_in: 3600 }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    if (url === 'https://oauth2.googleapis.com/token') {
      return new Response(JSON.stringify({ access_token: 'oauth-token', expires_in: 3600, token_type: 'Bearer' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    if (url.includes('/loyaltyClass/')) {
      return new Response(JSON.stringify({ id: '123.stempelpass_loyalty' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    if (url.includes(':generateAccessToken')) {
      return new Response(JSON.stringify({ accessToken: 'sa-token', expireTime: new Date(Date.now() + 3600_000).toISOString() }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    if (url.includes(':signBlob')) {
      const body = JSON.parse(String(init?.body)) as { payload: string };
      const payload = Buffer.from(body.payload, 'base64');
      // Deterministic "signature": SHA-256 of the payload (not RSA, but enough to
      // verify the JWT assembly; no real Google call happens).
      const { createHash } = await import('node:crypto');
      return new Response(JSON.stringify({ keyId: 'test-key', signedBlob: createHash('sha256').update(payload).digest('base64') }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    if (url.includes('/loyaltyObject/')) {
      // PATCH surface: echo a minimal loyaltyObject like the Wallet API does.
      return new Response(JSON.stringify({ id: '123.card-1', state: 'ACTIVE' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    throw new Error(`unexpected URL in mock: ${url}`);
  };
  return fakeFetch as unknown as typeof fetch;
}

/** Classic fallback adapter with a mocked HTTP surface (oauth + loyaltyObject). */
function classicAdapter(calls: Array<{ url: string; init: RequestInit }>, key: string) {
  process.env.GOOGLE_ISSUER_ID = '123';
  process.env.GOOGLE_SERVICE_ACCOUNT_JSON = JSON.stringify({ client_email: 'sa@example.invalid', private_key: key });
  return walletAdapter('google', { fetchFn: mockGoogleFetch(calls) });
}

test('keyless external-account mode issues a signed JWT without any private key (mocked Google calls)', async () => withCleanEnv(async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  process.env.GOOGLE_ISSUER_ID = '123';
  process.env.GOOGLE_EXTERNAL_ACCOUNT_JSON = EAC_CONFIG;
  const adapter = walletAdapter('google', { oidcToken: 'vercel-oidc-token', fetchFn: mockGoogleFetch(calls) });
  const result = await adapter.issue(card, branding, { stampRequired: 10, rewardTitle: 'Gratis' });
  expect(result.status).toBe('issued');
  expect(result.message).toContain('keyless');
  const parts = result.artifact?.split('.');
  expect(parts).toHaveLength(3);
  const header = JSON.parse(Buffer.from(parts![0], 'base64url').toString('utf8'));
  expect(header).toEqual({ alg: 'RS256', typ: 'savetowallet' });
  const payload = JSON.parse(Buffer.from(parts![1], 'base64url').toString('utf8'));
  expect(payload.iss).toBe('wallet-sa@project.iam.gserviceaccount.com');
  expect(payload.aud).toBe('google');
  expect(parts![2].length).toBeGreaterThan(10);
  // Assert the exact Google sequence: STS exchange, impersonation, then signBlob.
  expect(calls.map(c => c.url)).toEqual([
    'https://sts.googleapis.com/v1/token',
    'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/wallet-sa@project.iam.gserviceaccount.com:generateAccessToken',
    'https://walletobjects.googleapis.com/walletobjects/v1/loyaltyClass/123.stempelpass_loyalty',
    'https://walletobjects.googleapis.com/walletobjects/v1/loyaltyClass/123.stempelpass_loyalty',
    'https://sts.googleapis.com/v1/token',
    'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/wallet-sa@project.iam.gserviceaccount.com:generateAccessToken',
    'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/wallet-sa@project.iam.gserviceaccount.com:signBlob',
  ]);
  const stsBody = JSON.parse(String(calls[0].init.body)) as Record<string, string>;
  expect(stsBody.subject_token).toBe('vercel-oidc-token');
  expect(stsBody.subject_token_type).toBe('urn:ietf:params:oauth:token-type:jwt');
  const signBlobAuth = (calls[6].init.headers as Record<string, string>).Authorization;
  expect(signBlobAuth).toBe('Bearer sa-token');
}));

test('external-account config without an OIDC token reports not_configured with the missing input', async () => withCleanEnv(async () => {
  process.env.GOOGLE_ISSUER_ID = '123';
  process.env.GOOGLE_EXTERNAL_ACCOUNT_JSON = EAC_CONFIG;
  const result = await walletAdapter('google').issue(card, branding);
  expect(result.status).toBe('not_configured');
  expect(result.message).toContain('OIDC token');
  expect(result.artifact).toBeUndefined();
}));

test('googleWalletConfiguration reports the configured credential mode', () => withCleanEnv(async () => {
  expect(googleWalletConfiguration({}).configured).toBe(false);
  expect(googleWalletConfiguration({ GOOGLE_ISSUER_ID: '123', GOOGLE_EXTERNAL_ACCOUNT_JSON: EAC_CONFIG }).mode).toBe('external-account');
  expect(googleWalletConfiguration({ GOOGLE_ISSUER_ID: '123', GOOGLE_SERVICE_ACCOUNT_EMAIL: 'a@b.c', GOOGLE_PRIVATE_KEY: 'x' }).mode).toBe('service-account-json');
}));

test('IamSignBlobJwtSigner and ExternalAccountCredentials work through the public API', async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const creds = new ExternalAccountCredentials(JSON.parse(EAC_CONFIG), () => 't', mockGoogleFetch(calls));
  const signer = new IamSignBlobJwtSigner(creds);
  const adapter = new GoogleWalletAdapter('123', signer, creds.clientEmail!, 'external-account');
  const result = await adapter.issue(card, branding);
  expect(result.status).toBe('issued');
  expect(result.artifact?.split('.')).toHaveLength(3);
  // Caching: a second access-token request must not hit STS again.
  await creds.getAccessToken();
  const stsCalls = calls.filter(c => c.url.includes('sts.googleapis.com'));
  expect(stsCalls).toHaveLength(1);
});

test('ServiceAccountJsonCredentials signs locally (fallback)', async () => {
  const key = await Bun.$`openssl genrsa 2048 2>/dev/null`.text();
  const creds = new ServiceAccountJsonCredentials('test@example.invalid', key);
  expect(creds.mode).toBe('service-account-json');
  const sig = await creds.signBlob(Buffer.from('hello'));
  expect(sig.length).toBeGreaterThan(0);
  const failingFetch = (async () => new Response('denied', { status: 403 })) as unknown as typeof fetch;
  const tokenCreds = new ServiceAccountJsonCredentials('test@example.invalid', key, failingFetch);
  await expect(tokenCreds.getAccessToken()).rejects.toThrow('GCP_TOKEN_FAILED_403');
});


test('Google Wallet class provisioning is idempotent (GET then CREATE on 404)', async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input); calls.push({ url, init: init ?? {} });
    if (url.includes('/loyaltyClass/')) return new Response('not found', { status: 404 });
    return new Response(JSON.stringify({ id: '123.stempelpass_loyalty' }), { status: 200 });
  }) as unknown as typeof fetch;
  const credentials = {
    mode: 'service-account-json' as const, clientEmail: 'sa@example.invalid', description: 'test',
    signBlob: async () => new Uint8Array(),
    getAccessToken: async (scope?: string) => { expect(scope).toBe('https://www.googleapis.com/auth/wallet_object.issuer'); return { token: 'access', expiresAt: Date.now() + 3_600_000 }; },
  };
  const provisioner = new GoogleWalletApiClassProvisioner(credentials, fetchFn);
  await provisioner.ensureClassExists({ id: '123.stempelpass_loyalty', issuerName: 'Stempelpass', programName: 'StempelPass', reviewStatus: 'UNDER_REVIEW', programLogo: { sourceUri: { uri: 'https://example.invalid/logo.png' } } });
  expect(calls.map(call => call.url)).toEqual([
    'https://walletobjects.googleapis.com/walletobjects/v1/loyaltyClass/123.stempelpass_loyalty',
    'https://walletobjects.googleapis.com/walletobjects/v1/loyaltyClass',
  ]);
  expect(JSON.parse(String(calls[1].init.body)).reviewStatus).toBe('UNDER_REVIEW');
});


// ---------------------------------------------------------------------------
// refresh(): REAL Wallet-API PATCH of the loyaltyObject balance + text module.
// ---------------------------------------------------------------------------
const WALLET_PATCH_URL = 'https://walletobjects.googleapis.com/walletobjects/v1/loyaltyObject/123.card-1';

test('refresh PATCHes the loyaltyObject with the new balance and text module (mocked Google calls)', async () => withCleanEnv(async () => {
  const key = await Bun.$`openssl genrsa 2048 2>/dev/null`.text();
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const adapter = classicAdapter(calls, key);
  const result = await adapter.refresh(card, ['loyaltyPoints', 'textModulesData'], { branding, stampRequired: 10, rewardTitle: 'Gratis' });
  expect(result.status).toBe('issued');
  expect(result.artifact).toBeUndefined();
  const patch = calls.find(c => c.url === WALLET_PATCH_URL);
  expect(patch).toBeDefined();
  expect(patch!.init.method).toBe('PATCH');
  const auth = (patch!.init.headers as Record<string, string>).Authorization;
  expect(auth).toBe('Bearer oauth-token');
  const body = JSON.parse(String(patch!.init.body)) as Record<string, any>;
  // Native points line (Owner-Entscheid 2026-10-19): label "Stempel" (plain
  // string, discovery-verified) rides along with the balance on every refresh.
  expect(body.loyaltyPoints).toEqual({ label: 'Stempel', balance: { int: card.stampCount } });
  // Card-front member-number line: accountId + accountIdLabel ride along with
  // every refresh so the front number stays in sync (owner wish, backlog #4).
  expect(body.accountId).toBe('K-7F3D2A');
  expect(body.accountIdLabel).toBe('Kartennummer');
  // Staff camera scan (2026-10-18): the CODE_128 barcode rides along with every
  // refresh so the pass stays scannable at the register (explicit `barcode`
  // field — Google renders a barcode ONLY from it, not from accountId).
  expect(body.barcode).toEqual({ type: 'CODE_128', value: 'K-7F3D2A', alternateText: 'K-7F3D2A' });
  // Branding flows through to the object: progress module FIRST ("X/N Stempel",
  // Owner-Entscheid 2026-10-19), then the reward line, then the cardText module;
  // the visible card code appears as its own Kartennummer module.
  expect(body.textModulesData).toEqual([
    { header: branding.cardTitle, body: '3/10 Stempel' },
    { header: branding.cardTitle, body: 'Prämie: Gratis' },
    { header: 'Kartennummer', body: 'K-7F3D2A' },
    { header: branding.cardTitle, body: branding.cardText },
  ]);
  // The PATCH is the ONLY loyaltyObject call: no GET, no class provisioning.
  expect(calls.filter(c => c.url.includes('/loyaltyObject/'))).toHaveLength(1);
}));

test('refresh without credentials is honest (not_configured, no fetch)', async () => withCleanEnv(async () => {
  const result = await walletAdapter('google').refresh(card, ['loyaltyPoints'], { branding });
  expect(result).toEqual({ provider: 'google', status: 'not_configured', message: 'google wallet is not configured; refresh skipped.' });
  expect(result.artifact).toBeUndefined();
}));

test('refresh treats a 404 loyaltyObject as a graceful no-op (card never saved to Wallet)', async () => withCleanEnv(async () => {
  const key = await Bun.$`openssl genrsa 2048 2>/dev/null`.text();
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input); calls.push({ url, init: init ?? {} });
    if (url === 'https://oauth2.googleapis.com/token') return new Response(JSON.stringify({ access_token: 'oauth-token', expires_in: 3600, token_type: 'Bearer' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    if (url === WALLET_PATCH_URL) return new Response('not found', { status: 404 });
    throw new Error(`unexpected URL in mock: ${url}`);
  }) as unknown as typeof fetch;
  process.env.GOOGLE_ISSUER_ID = '123';
  process.env.GOOGLE_SERVICE_ACCOUNT_JSON = JSON.stringify({ client_email: 'sa@example.invalid', private_key: key });
  const adapter = walletAdapter('google', { fetchFn });
  const result = await adapter.refresh(card, ['loyaltyPoints'], { branding, stampRequired: 10, rewardTitle: 'Gratis' });
  expect(result.status).toBe('issued'); // graceful no-op — never throws
  expect(calls.some(c => c.url === WALLET_PATCH_URL)).toBe(true);
}));

test('refresh propagates a non-404 API failure like issue() does (GOOGLE_WALLET_REFRESH_FAILED_<status>)', async () => withCleanEnv(async () => {
  const key = await Bun.$`openssl genrsa 2048 2>/dev/null`.text();
  const fetchFn = (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url === 'https://oauth2.googleapis.com/token') return new Response(JSON.stringify({ access_token: 'oauth-token', expires_in: 3600, token_type: 'Bearer' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    if (url === WALLET_PATCH_URL) return new Response('denied', { status: 500 });
    throw new Error(`unexpected URL in mock: ${url}`);
  }) as unknown as typeof fetch;
  process.env.GOOGLE_ISSUER_ID = '123';
  process.env.GOOGLE_SERVICE_ACCOUNT_JSON = JSON.stringify({ client_email: 'sa@example.invalid', private_key: key });
  const adapter = walletAdapter('google', { fetchFn });
  await expect(adapter.refresh(card, ['loyaltyPoints'], { branding })).rejects.toThrow('GOOGLE_WALLET_REFRESH_FAILED_500');
}));

test('refresh PATCHes with fallback branding/rule when no context is supplied', async () => withCleanEnv(async () => {
  const key = await Bun.$`openssl genrsa 2048 2>/dev/null`.text();
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const adapter = classicAdapter(calls, key);
  const result = await adapter.refresh(card, []);
  expect(result.status).toBe('issued');
  const body = JSON.parse(String(calls.find(c => c.url === WALLET_PATCH_URL)!.init.body)) as Record<string, any>;
  expect(body.textModulesData).toEqual([
    { header: 'StempelPass', body: '3/? Stempel' },
    { header: 'StempelPass', body: 'Prämie: Prämie' },
    { header: 'Kartennummer', body: 'K-7F3D2A' },
  ]);
}));

// ---------------------------------------------------------------------------
// Tenant branding: class model, object model, class provisioning (owner
// feature request 15.09.: companies customize the Wallet pass).
// ---------------------------------------------------------------------------
const LOGO_URL = 'https://cdn.example.invalid/cafe-logo.png';
const branded = { cardTitle: 'Café Herz', cardText: 'Sammle Stempel', primaryColor: '#123456', secondaryColor: '#f8fafc', logoUrl: LOGO_URL, version: 2 };

test('tenantClassModel reflects tenant branding (title, colors, logo) and keeps the APPROVED pilot class id', () => {
  const model = tenantClassModel('123', branded);
  // The class id stays on the APPROVED production class — never a new class id
  // that would orphan the owner's saved pass or force a new Google review.
  expect(model.id).toBe('123.stempelpass_loyalty');
  expect(model.programName).toBe('Café Herz');
  expect(model.issuerName).toBe('Stempelpass');
  expect(model.hexBackgroundColor).toBe('#123456');
  expect(model.programLogo?.sourceUri.uri).toBe(LOGO_URL);
  expect(model.reviewStatus).toBe('UNDER_REVIEW');
  // Unbranded/invalid values degrade deterministically to the platform defaults
  // and NEVER send invalid fields to Google (no hexBackgroundColor for 'rot').
  const fallback = tenantClassModel('123', { cardTitle: '', cardText: '', primaryColor: 'rot', secondaryColor: '', version: 1 });
  expect(fallback.programName).toBe('StempelPass');
  expect(fallback.hexBackgroundColor).toBeUndefined();
  expect(fallback.programLogo?.sourceUri.uri).toBe(DEFAULT_CLASS_LOGO_URI);
});

test('class suffix derives a tenant-specific class id without breaking the default', () => {
  const model = tenantClassModel('123', branded, 'tenant-1');
  expect(model.id).toBe('123.tenant-1');
  expect(model.programName).toBe('Café Herz');
});


test('issue() embeds branding in the object model: tenant class id + progress and cardText modules', async () => {
  const key = await Bun.$`openssl genrsa 2048 2>/dev/null`.text();
  const adapter = new GoogleWalletAdapter('123', new PrivateKeyJwtSigner(key), 'test@example.invalid', 'service-account-json', undefined, undefined, fetch, 'tenant-1');
  const result = await adapter.issue(card, branded, { stampRequired: 10, rewardTitle: 'Gratis Kaffee' });
  const payload = JSON.parse(Buffer.from(result.artifact!.split('.')[1], 'base64url').toString('utf8'));
  const obj = payload.payload.loyaltyObjects[0];
  expect(obj.id).toBe('123.card-1');
  expect(obj.classId).toBe('123.tenant-1');
  // Card-FRONT member-number line (backlog #4): accountId+accountIdLabel are
  // part of the save-to-wallet object, not only the details text module.
  expect(obj.accountId).toBe('K-7F3D2A');
  expect(obj.accountIdLabel).toBe('Kartennummer');
  // Staff camera scan: the save-to-wallet object also carries the scannable
  // CODE_128 barcode of the same visible code (decision note 2026-10-17).
  expect(obj.barcode).toEqual({ type: 'CODE_128', value: 'K-7F3D2A', alternateText: 'K-7F3D2A' });
  expect(obj.textModulesData).toEqual([
    { header: 'Café Herz', body: '3/10 Stempel' },
    { header: 'Café Herz', body: 'Prämie: Gratis Kaffee' },
    { header: 'Kartennummer', body: 'K-7F3D2A' },
    { header: 'Café Herz', body: 'Sammle Stempel' },
  ]);
});

test('issue and refresh payloads omit accountId/accountIdLabel when the card has no cardCode', async () => {
  // Keyless path (IamSignBlob + mocked Google surface) — no RSA key needed.
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const creds = new ExternalAccountCredentials(JSON.parse(EAC_CONFIG), () => 't', mockGoogleFetch(calls));
  const signer = new IamSignBlobJwtSigner(creds);
  const uncoded = { ...card, cardCode: undefined };
  // issue: the JWT loyaltyObject carries NO accountId, NO accountIdLabel and no
  // Kartennummer text module — the exact pre-021 object shape must be kept.
  const adapter = new GoogleWalletAdapter('123', signer, creds.clientEmail!, 'external-account', undefined, undefined, fetch, 'tenant-1');
  const result = await adapter.issue(uncoded, branding, { stampRequired: 10, rewardTitle: 'Gratis' });
  expect(result.status).toBe('issued');
  const payload = JSON.parse(Buffer.from(result.artifact!.split('.')[1], 'base64url').toString('utf8'));
  const obj = payload.payload.loyaltyObjects[0];
  expect(obj.id).toBe('123.card-1');
  expect(obj.classId).toBe('123.tenant-1');
  expect(obj.accountId).toBeUndefined();
  expect(obj.accountIdLabel).toBeUndefined();
  expect(obj.barcode).toBeUndefined();
  expect(obj.textModulesData).toEqual([
    { header: 'Café', body: '3/10 Stempel' },
    { header: 'Café', body: 'Prämie: Gratis' },
    { header: 'Café', body: 'Treuekarte' },
  ]);
  // refresh: the loyaltyObject PATCH body carries NO accountId/accountIdLabel
  // either — and no reviewStatus anywhere (that is CLASS-PATCH-only, PR #37).
  const patchCalls: Array<{ url: string; init: RequestInit }> = [];
  const refreshAdapter = new GoogleWalletAdapter('123', signer, creds.clientEmail!, 'external-account', undefined, creds, mockGoogleFetch(patchCalls));
  const refreshResult = await refreshAdapter.refresh(uncoded, ['loyaltyPoints', 'textModulesData'], { branding, stampRequired: 10, rewardTitle: 'Gratis' });
  expect(refreshResult.status).toBe('issued');
  const patch = patchCalls.find(c => c.url === WALLET_PATCH_URL);
  expect(patch).toBeDefined();
  expect(patch!.init.method).toBe('PATCH');
  const body = JSON.parse(String(patch!.init.body)) as Record<string, any>;
  expect(body).toEqual({ loyaltyPoints: { label: 'Stempel', balance: { int: 3 } }, textModulesData: [{ header: 'Café', body: '3/10 Stempel' }, { header: 'Café', body: 'Prämie: Gratis' }, { header: 'Café', body: 'Treuekarte' }] });
});

/** Reusable scripted Google credentials fixture (no real network). */
function mockCredentials() {
  return {
    mode: 'service-account-json' as const, clientEmail: 'sa@example.invalid', description: 'test',
    signBlob: async () => new Uint8Array(),
    getAccessToken: async (scope?: string) => { expect(scope).toBe('https://www.googleapis.com/auth/wallet_object.issuer'); return { token: 'access', expiresAt: Date.now() + 3_600_000 }; },
  };
}

test('class provisioning PATCHes an existing class only when branding differs (idempotent patch once)', async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  let stored = { id: '123.stempelpass_loyalty', issuerName: 'Stempelpass', programName: 'Alter Name', hexBackgroundColor: '#000000', programLogo: { sourceUri: { uri: 'https://old.example.invalid/logo.png' } }, reviewStatus: 'APPROVED' };
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input); calls.push({ url, init: init ?? {} });
    if (url.includes('/loyaltyClass/')) {
      if (init?.method === 'PATCH') {
        stored = { ...stored, ...(JSON.parse(String(init.body)) as Record<string, unknown>) };
        return new Response(JSON.stringify(stored), { status: 200 });
      }
      return new Response(JSON.stringify(stored), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    throw new Error(`unexpected URL in mock: ${url}`);
  }) as unknown as typeof fetch;
  const provisioner = new GoogleWalletApiClassProvisioner(mockCredentials(), fetchFn);
  const model = tenantClassModel('123', branded);
  await provisioner.ensureClassExists(model);
  await provisioner.ensureClassExists(model); // GET now matches → NO second PATCH
  const patches = calls.filter(c => c.init?.method === 'PATCH');
  expect(patches).toHaveLength(1);
  const body = JSON.parse(String(patches[0].init.body)) as Record<string, unknown>;
  // Partial-update body: branding fields PLUS the explicit review-status flip —
  // Google rejects a PATCH on an APPROVED class without reviewStatus=UNDER_REVIEW
  // (live-verified 400 "Invalid review status \"APPROVED\""). id stays excluded.
  expect(body).toEqual({ programName: 'Café Herz', hexBackgroundColor: '#123456', programLogo: { sourceUri: { uri: LOGO_URL } }, reviewStatus: 'UNDER_REVIEW' });
  expect(body.id).toBeUndefined();
  expect(stored.programName).toBe('Café Herz');
  expect(stored.programLogo).toEqual({ sourceUri: { uri: LOGO_URL } });
  expect(stored.reviewStatus).toBe('UNDER_REVIEW');
});

test('class provisioning PATCH body carries reviewStatus=UNDER_REVIEW so an APPROVED class is patchable (Google 400 regression, live-verified 2026-09-24)', async () => {
  // Mimics the real Wallet API: an APPROVED class rejects any PATCH whose body
  // does not contain reviewStatus=UNDER_REVIEW with 400 invalidResource.
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const stored = { id: '123.stempelpass_loyalty', issuerName: 'Stempelpass', programName: 'StempelPass', reviewStatus: 'APPROVED' };
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input); calls.push({ url, init: init ?? {} });
    if (url.includes('/loyaltyClass/')) {
      if (init?.method === 'PATCH') {
        const body = JSON.parse(String(init.body)) as Record<string, unknown>;
        if (body.reviewStatus !== 'UNDER_REVIEW') {
          return new Response(JSON.stringify({ error: { code: 400, message: 'Invalid review status "APPROVED". Use "UNDER_REVIEW" instead.', reason: 'invalidResource' } }), { status: 400 });
        }
        return new Response(JSON.stringify({ ...stored, ...body }), { status: 200 });
      }
      return new Response(JSON.stringify(stored), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    throw new Error(`unexpected URL in mock: ${url}`);
  }) as unknown as typeof fetch;
  const provisioner = new GoogleWalletApiClassProvisioner(mockCredentials(), fetchFn);
  const model = tenantClassModel('123', branded);
  // Must NOT reject: the body includes reviewStatus=UNDER_REVIEW.
  await expect(provisioner.ensureClassExists(model)).resolves.toBeUndefined();
  const patches = calls.filter(c => c.init?.method === 'PATCH');
  expect(patches).toHaveLength(1);
  expect((JSON.parse(String(patches[0].init.body)) as Record<string, unknown>).reviewStatus).toBe('UNDER_REVIEW');
});

test('class provisioning compares hex colors case-insensitively (Google serializes lowercase, branding keeps user casing)', async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const stored = { id: '123.stempelpass_loyalty', issuerName: 'Stempelpass', programName: 'Café Herz', hexBackgroundColor: '#AB12CD', programLogo: { sourceUri: { uri: LOGO_URL } }, reviewStatus: 'APPROVED' };
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input); calls.push({ url, init: init ?? {} });
    if (url.includes('/loyaltyClass/')) {
      if (init?.method === 'PATCH') return new Response(JSON.stringify(stored), { status: 200 });
      return new Response(JSON.stringify(stored), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    throw new Error(`unexpected URL in mock: ${url}`);
  }) as unknown as typeof fetch;
  const provisioner = new GoogleWalletApiClassProvisioner(mockCredentials(), fetchFn);
  // Model color #ab12cd vs stored #AB12CD: same color, different case → NO PATCH.
  await provisioner.ensureClassExists(tenantClassModel('123', { ...branded, primaryColor: '#ab12cd' }));
  expect(calls.filter(c => c.init?.method === 'PATCH')).toHaveLength(0);
});

test('class provisioning surfaces explicit errors: GET non-404 and PATCH failures', async () => {
  const denied = (async () => new Response('denied', { status: 403 })) as unknown as typeof fetch;
  await expect(new GoogleWalletApiClassProvisioner(mockCredentials(), denied).ensureClassExists(tenantClassModel('123', branded)))
    .rejects.toThrow('GOOGLE_WALLET_CLASS_GET_FAILED_403');
  const failPatch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.includes('/loyaltyClass/')) {
      return init?.method === 'PATCH' ? new Response('denied', { status: 500 }) : new Response(JSON.stringify({ id: '123.stempelpass_loyalty' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    throw new Error(`unexpected URL in mock: ${url}`);
  }) as unknown as typeof fetch;
  await expect(new GoogleWalletApiClassProvisioner(mockCredentials(), failPatch).ensureClassExists(tenantClassModel('123', branded)))
    .rejects.toThrow('GOOGLE_WALLET_CLASS_PATCH_FAILED_500');
});

test('class provisioning creates a fresh class on 404 with the branding-derived model (create body carries reviewStatus)', async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input); calls.push({ url, init: init ?? {} });
    // Class-specific GET (…/loyaltyClass/<id>) → 404 so the provisioner creates;
    // the collection POST (…/loyaltyClass) → 200 with the created class.
    if (url.includes('/loyaltyClass/')) return new Response('not found', { status: 404 });
    if (url.endsWith('/loyaltyClass')) return new Response(JSON.stringify({ id: '123.stempelpass_loyalty' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    throw new Error(`unexpected URL in mock: ${url}`);
  }) as unknown as typeof fetch;
  await new GoogleWalletApiClassProvisioner(mockCredentials(), fetchFn).ensureClassExists(tenantClassModel('123', branded));
  const create = calls.find(c => c.url === 'https://walletobjects.googleapis.com/walletobjects/v1/loyaltyClass' && c.init?.method === 'POST');
  expect(create).toBeDefined();
  const body = JSON.parse(String(create!.init.body)) as Record<string, unknown>;
  expect(body.id).toBe('123.stempelpass_loyalty');
  expect(body.programName).toBe('Café Herz');
  expect(body.hexBackgroundColor).toBe('#123456');
  expect(body.reviewStatus).toBe('UNDER_REVIEW');
});

test('ensureGoogleWalletClass syncs the class from env credentials and is a silent no-op without them', async () => withCleanEnv(async () => {
  await ensureGoogleWalletClass(branded); // no GOOGLE_ISSUER_ID → silent no-op
  const key = await Bun.$`openssl genrsa 2048 2>/dev/null`.text();
  const calls: Array<{ url: string; init: RequestInit }> = [];
  process.env.GOOGLE_ISSUER_ID = '123';
  process.env.GOOGLE_SERVICE_ACCOUNT_JSON = JSON.stringify({ client_email: 'sa@example.invalid', private_key: key });
  await ensureGoogleWalletClass(branded, { fetchFn: mockGoogleFetch(calls) });
  expect(calls.some(c => c.url.includes('/loyaltyClass/') && (c.init?.method ?? 'GET') === 'PATCH')).toBe(true);
}));
// ---------------------------------------------------------------------------
// imageModulesData (Owner-Entscheid 2026-10-18): visible stamp-raster grid.
// ---------------------------------------------------------------------------
async function withGridEnv(url: string | undefined, fn: () => Promise<void>): Promise<void> {
  const old = process.env.WALLET_IMAGE_BASE_URL;
  try {
    url === undefined ? delete process.env.WALLET_IMAGE_BASE_URL : process.env.WALLET_IMAGE_BASE_URL = url;
    await fn();
  } finally {
    old === undefined ? delete process.env.WALLET_IMAGE_BASE_URL : process.env.WALLET_IMAGE_BASE_URL = old;
  }
}
test('issue emits imageModulesData when WALLET_IMAGE_BASE_URL + card revision are present', async () => withCleanEnv(async () => withGridEnv('https://api.example.com', async () => {
  const key = await Bun.$`openssl genrsa 2048 2>/dev/null`.text();
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const result = await classicAdapter(calls, key).issue(card, branding, { stampRequired: 10, rewardTitle: 'Gratis' });
  expect(result.status).toBe('issued');
  const payload = JSON.parse(Buffer.from(result.artifact!.split('.')[1], 'base64url').toString('utf8'));
  expect(payload.payload.loyaltyObjects[0].imageModulesData).toEqual([{
    id: 'stempel-raster',
    mainImage: { sourceUri: { uri: 'https://api.example.com/wallet/grid/card-1.png?ts=2' }, contentDescription: { defaultValue: { language: 'de', value: '3/10 Stempel' } } },
  }]);
})));
test('refresh PATCH replaces imageModulesData as a whole; absent without config', async () => {
  await withCleanEnv(async () => {
    const key = await Bun.$`openssl genrsa 2048 2>/dev/null`.text();
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const adapter = classicAdapter(calls, key);
    await withGridEnv('https://api.example.com', async () => {
      await adapter.refresh(card, ['loyaltyPoints', 'textModulesData', 'imageModulesData'], { branding, stampRequired: 10, rewardTitle: 'Gratis' });
      const patch = calls.find(c => c.url === WALLET_PATCH_URL && c.init?.method === 'PATCH');
      expect(patch).toBeDefined();
      const body = JSON.parse(String(patch!.init.body)) as Record<string, unknown>;
      expect(body.imageModulesData).toEqual([{
        id: 'stempel-raster',
        mainImage: { sourceUri: { uri: 'https://api.example.com/wallet/grid/card-1.png?ts=2' }, contentDescription: { defaultValue: { language: 'de', value: '3/10 Stempel' } } },
      }]);
    });
    // Without the env var the PATCH body keeps the pre-18.10 shape (no image module).
    const calls2: Array<{ url: string; init: RequestInit }> = [];
    await classicAdapter(calls2, key).refresh(card, ['loyaltyPoints', 'textModulesData', 'imageModulesData'], { branding, stampRequired: 10, rewardTitle: 'Gratis' });
    const patch2 = calls2.find(c => c.url === WALLET_PATCH_URL && c.init?.method === 'PATCH');
    expect(JSON.parse(String(patch2!.init.body))).not.toHaveProperty('imageModulesData');
  });
});
test('issue without WALLET_IMAGE_BASE_URL keeps the exact pre-18.10 object shape', async () => withCleanEnv(async () => withGridEnv(undefined, async () => {
  const key = await Bun.$`openssl genrsa 2048 2>/dev/null`.text();
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const result = await classicAdapter(calls, key).issue(card, branding, { stampRequired: 10, rewardTitle: 'Gratis' });
  const payload = JSON.parse(Buffer.from(result.artifact!.split('.')[1], 'base64url').toString('utf8'));
  expect(payload.payload.loyaltyObjects[0].imageModulesData).toBeUndefined();
})));


// ---------------------------------------------------------------------------
// REGRESSION (2026-10-19, prod wallet refresh 400 root cause, post-#47):
// Google requires Image.contentDescription to be a LocalizedString object
// { defaultValue: { language, value } } — PR #47 sent a plain string, so the
// WHOLE loyaltyObject PATCH was rejected with 400 INVALID_ARGUMENT and the
// balance + stamp grid never reached the pass. These tests pin the fixed
// payload shape (both issue() and refresh() share objectModel).
// ---------------------------------------------------------------------------
const LOCALIZED_CD = { defaultValue: { language: 'de', value: '3/10 Stempel' } };
test('REGRESSION: issue() and refresh() send contentDescription as LocalizedString (payload shape)', async () => withCleanEnv(async () => {
  const key = await Bun.$`openssl genrsa 2048 2>/dev/null`.text();
  await withGridEnv('https://api.example.com', async () => {
    // issue(): the save-to-wallet JWT loyaltyObject must carry the object form.
    const issueCalls: Array<{ url: string; init: RequestInit }> = [];
    const issueResult = await classicAdapter(issueCalls, key).issue(card, branding, { stampRequired: 10, rewardTitle: 'Gratis' });
    expect(issueResult.status).toBe('issued');
    const payload = JSON.parse(Buffer.from(issueResult.artifact!.split('.')[1], 'base64url').toString('utf8'));
    const issuedCd = payload.payload.loyaltyObjects[0].imageModulesData[0].mainImage.contentDescription;
    expect(issuedCd).toEqual(LOCALIZED_CD);
    expect(typeof issuedCd).toBe('object');
    expect(typeof (issuedCd as { defaultValue: { value: string } }).defaultValue.value).toBe('string');
    // refresh(): the PATCH body used by syncWalletBalance after every stamp.
    const refreshCalls: Array<{ url: string; init: RequestInit }> = [];
    const refreshResult = await classicAdapter(refreshCalls, key).refresh(card, ['loyaltyPoints', 'textModulesData', 'imageModulesData'], { branding, stampRequired: 10, rewardTitle: 'Gratis' });
    expect(refreshResult.status).toBe('issued');
    const patch = refreshCalls.find(c => c.url === WALLET_PATCH_URL && c.init?.method === 'PATCH');
    expect(patch).toBeDefined();
    const body = JSON.parse(String(patch!.init.body)) as Record<string, any>;
    const patchCd = body.imageModulesData[0].mainImage.contentDescription;
    expect(patchCd).toEqual(LOCALIZED_CD);
    // The old plain-string value would NOT survive JSON round-trip as an object.
    expect(JSON.stringify(patchCd)).not.toBe(JSON.stringify('3/10 Stempel'));
  });
}));
test('REGRESSION: refresh with grid payload is accepted by a Google-contract mock that rejects plain-string contentDescription (replay A → 200)', async () => withCleanEnv(async () => {
  const key = await Bun.$`openssl genrsa 2048 2>/dev/null`.text();
  process.env.GOOGLE_ISSUER_ID = '123';
  process.env.GOOGLE_SERVICE_ACCOUNT_JSON = JSON.stringify({ client_email: 'sa@example.invalid', private_key: key });
  const calls: Array<{ url: string; init: RequestInit }> = [];
  // Mirror of the 19.10. production replay: Google answers 400
  // INVALID_ARGUMENT exactly when content_description is not a LocalizedString,
  // exactly like the diagnose (PROD_DIAGNOSE_WALLET_GRID_2026-10-19.md §4 A).
  const googleContractFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input); calls.push({ url, init: init ?? {} });
    if (url === 'https://oauth2.googleapis.com/token') {
      return new Response(JSON.stringify({ access_token: 'oauth-token', expires_in: 3600, token_type: 'Bearer' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    if (url.includes('/loyaltyObject/')) {
      const body = JSON.parse(String(init?.body)) as Record<string, any>;
      const cd = body.imageModulesData?.[0]?.mainImage?.contentDescription;
      if (typeof cd === 'string') {
        return new Response(JSON.stringify({ error: { code: 400, message: `Invalid value at 'resource.image_modules_data[0].main_image.content_description' (type.googleapis.com/google.walletobjects.v1.LocalizedString), \"${cd}\"`, status: 'INVALID_ARGUMENT' } }), { status: 400, headers: { 'Content-Type': 'application/json' } });
      }
      return new Response(JSON.stringify({ id: '123.card-1', state: 'ACTIVE' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    throw new Error(`unexpected URL in mock: ${url}`);
  }) as unknown as typeof fetch;
  await withGridEnv('https://api.example.com', async () => {
    const result = await walletAdapter('google', { fetchFn: googleContractFetch }).refresh(card, ['loyaltyPoints', 'textModulesData', 'imageModulesData'], { branding, stampRequired: 10, rewardTitle: 'Gratis' });
    expect(result.status).toBe('issued'); // no GOOGLE_WALLET_REFRESH_FAILED_400
    expect(result.message).toContain('updated');
  });
  // Contract sanity: the pre-fix plain-string payload hits exactly that 400.
  const plainReplay = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === 'https://oauth2.googleapis.com/token') return new Response(JSON.stringify({ access_token: 'x', expires_in: 3600 }), { status: 200 });
    if (url.includes('/loyaltyObject/')) return new Response(JSON.stringify({ error: { code: 400, status: 'INVALID_ARGUMENT' } }), { status: 400 });
    throw new Error(`unexpected URL in mock: ${url}`);
  }) as unknown as typeof fetch;
  const adapters = walletAdapter('google', { fetchFn: plainReplay });
  // A refresh whose payload kept the old string type must fail with the same
  // code the server logs as wallet_refresh_failed (GOOGLE_WALLET_REFRESH_FAILED_400).
  await expect(adapters.refresh(card, ['loyaltyPoints', 'textModulesData', 'imageModulesData'], { branding, stampRequired: 10, rewardTitle: 'Gratis' })).rejects.toThrow('GOOGLE_WALLET_REFRESH_FAILED_400');
}));

// ---------------------------------------------------------------------------
// REGRESSION (2026-10-19, Owner-Entscheid: stamp progress natively on the
// pass — loyaltyPoints.label + first text module "X/N Stempel"):
// The walletobjects v1 discovery document types LoyaltyPoints.label and
// TextModuleData.header/body as PLAIN STRINGS (the LocalizedString variants
// live in loyaltyPoints.localizedLabel and textModulesData localizedHeader/
// localizedBody). A { defaultValue: { language, value } } OBJECT at any of
// these string fields gets 400 INVALID_ARGUMENT from Google — the exact mirror
// of PR #48 (plain string at the LocalizedString contentDescription). These
// tests pin the string shape so a future "localization fix" cannot silently
// re-break the whole PATCH (syncWalletBalance only logs wallet_refresh_failed;
// the stamp still answers 200). Discovery evidence: fetched live 2026-10-19
// from https://walletobjects.googleapis.com/$discovery/rest?version=v1
// (schemas LoyaltyPoints.label, TextModuleData.header/.body).
// ---------------------------------------------------------------------------
test('REGRESSION: loyaltyPoints.label and textModule header/body are plain strings; progress line is the FIRST module (issue() + refresh())', async () => withCleanEnv(async () => {
  const key = await Bun.$`openssl genrsa 2048 2>/dev/null`.text();
  await withGridEnv(undefined, async () => {
    // issue(): the save-to-wallet JWT loyaltyObject carries the native points
    // line plus the split progress/reward modules.
    const issueCalls: Array<{ url: string; init: RequestInit }> = [];
    const issueResult = await classicAdapter(issueCalls, key).issue(card, branding, { stampRequired: 10, rewardTitle: 'Gratis' });
    expect(issueResult.status).toBe('issued');
    const payload = JSON.parse(Buffer.from(issueResult.artifact!.split('.')[1], 'base64url').toString('utf8'));
    const obj = payload.payload.loyaltyObjects[0];
    // label is a PLAIN STRING — never { defaultValue: … } (localizedLabel is
    // the LocalizedString variant; discovery-verified). balance.int unchanged.
    expect(obj.loyaltyPoints).toEqual({ label: 'Stempel', balance: { int: card.stampCount } });
    expect(typeof obj.loyaltyPoints.label).toBe('string');
    expect((obj.loyaltyPoints.label as string).length).toBeLessThanOrEqual(9); // Google's label length recommendation
    // Progress line FIRST, undisputed: textModulesData[0].body === "X/N Stempel",
    // textModulesData[1] === "Prämie: <Titel>" (split from the old combined body).
    expect(obj.textModulesData).toEqual([
      { header: branding.cardTitle, body: '3/10 Stempel' },
      { header: branding.cardTitle, body: 'Prämie: Gratis' },
      { header: 'Kartennummer', body: 'K-7F3D2A' },
      { header: branding.cardTitle, body: branding.cardText },
    ]);
    for (const m of obj.textModulesData as Array<{ header: unknown; body: unknown }>) {
      expect(typeof m.header).toBe('string');
      expect(typeof m.body).toBe('string');
    }
    // A LocalizedString-wrapped label would FAIL the string shape check — the
    // object form Google rejects at this string field.
    expect(JSON.stringify(obj.loyaltyPoints.label)).not.toBe(JSON.stringify({ defaultValue: { language: 'de', value: 'Stempel' } }));
    // refresh(): the PATCH body used by syncWalletBalance after every stamp.
    const refreshCalls: Array<{ url: string; init: RequestInit }> = [];
    const refreshResult = await classicAdapter(refreshCalls, key).refresh(card, ['loyaltyPoints', 'textModulesData'], { branding, stampRequired: 10, rewardTitle: 'Gratis' });
    expect(refreshResult.status).toBe('issued');
    const patch = refreshCalls.find(c => c.url === WALLET_PATCH_URL && c.init?.method === 'PATCH');
    expect(patch).toBeDefined();
    const body = JSON.parse(String(patch!.init.body)) as Record<string, any>;
    expect(body.loyaltyPoints).toEqual({ label: 'Stempel', balance: { int: card.stampCount } });
    expect(body.textModulesData[0]).toEqual({ header: branding.cardTitle, body: '3/10 Stempel' });
    expect(body.textModulesData[1]).toEqual({ header: branding.cardTitle, body: 'Prämie: Gratis' });
    for (const m of body.textModulesData as Array<{ header: unknown; body: unknown }>) {
      expect(typeof m.header).toBe('string');
      expect(typeof m.body).toBe('string');
    }
  });
}));
test('REGRESSION: Google-contract mock accepts the string shapes (200) and rejects a LocalizedString-wrapped label (400 INVALID_ARGUMENT) — refresh path', async () => withCleanEnv(async () => {
  const key = await Bun.$`openssl genrsa 2048 2>/dev/null`.text();
  process.env.GOOGLE_ISSUER_ID = '123';
  process.env.GOOGLE_SERVICE_ACCOUNT_JSON = JSON.stringify({ client_email: 'sa@example.invalid', private_key: key });
  const calls: Array<{ url: string; init: RequestInit }> = [];
  // Mirror of the 19.10. production replay style: Google answers 400
  // INVALID_ARGUMENT exactly when a string-typed field carries a non-string
  // value — here loyaltyPoints.label / textModulesData[].header / .body must
  // be plain strings (the reversed PR #48 type confusion: an object at a
  // string field instead of a string at an object field).
  const googleContractFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input); calls.push({ url, init: init ?? {} });
    if (url === 'https://oauth2.googleapis.com/token') {
      return new Response(JSON.stringify({ access_token: 'oauth-token', expires_in: 3600, token_type: 'Bearer' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    if (url.includes('/loyaltyObject/')) {
      const body = JSON.parse(String(init?.body)) as Record<string, any>;
      let badPath: string | null = null;
      for (const [i, m] of (body.textModulesData ?? []).entries()) {
        if (typeof m.header !== 'string') { badPath = `text_modules_data[${i}].header`; break; }
        if (typeof m.body !== 'string') { badPath = `text_modules_data[${i}].body`; break; }
      }
      if (badPath === null && typeof body.loyaltyPoints?.label !== 'string') badPath = 'loyalty_points.label';
      if (badPath !== null) {
        return new Response(JSON.stringify({ error: { code: 400, message: `Invalid value at 'resource.${badPath}' (type.googleapis.com/google.walletobjects.v1.String): object`, status: 'INVALID_ARGUMENT' } }), { status: 400, headers: { 'Content-Type': 'application/json' } });
      }
      return new Response(JSON.stringify({ id: '123.card-1', state: 'ACTIVE' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    throw new Error(`unexpected URL in mock: ${url}`);
  }) as unknown as typeof fetch;
  // Correct payload (the adapter's real objectModel output, issue() AND
  // refresh() share it) → 200, no silent GOOGLE_WALLET_REFRESH_FAILED_400.
  const result = await walletAdapter('google', { fetchFn: googleContractFetch }).refresh(card, ['loyaltyPoints', 'textModulesData'], { branding, stampRequired: 10, rewardTitle: 'Gratis' });
  expect(result.status).toBe('issued');
  expect(result.message).toContain('updated');
  // Contract sanity in both directions against the mock itself:
  // (i) the exact body the adapter sent is the 200 above and carries the
  //     native progress line;
  const sent = calls.find(c => c.url.includes('/loyaltyObject/'));
  expect(sent).toBeDefined();
  const sentBody = JSON.parse(String(sent!.init.body)) as Record<string, any>;
  expect(sentBody.loyaltyPoints).toEqual({ label: 'Stempel', balance: { int: 3 } });
  expect(sentBody.textModulesData[0]).toEqual({ header: 'Café', body: '3/10 Stempel' });
  // (ii) a LocalizedString-wrapped label (object at string field) is rejected
  //      with the same 400 the server logs as wallet_refresh_failed.
  const brokenReject = await googleContractFetch('https://walletobjects.googleapis.com/walletobjects/v1/loyaltyObject/123.card-1', { method: 'PATCH', body: JSON.stringify({ loyaltyPoints: { label: { defaultValue: { language: 'de', value: 'Stempel' } }, balance: { int: 3 } }, textModulesData: [{ header: 'Café', body: '3/10 Stempel' }] }) } as RequestInit);
  expect(brokenReject.status).toBe(400);
  const brokenJson = (await brokenReject.json()) as { error: { message: string; status: string } };
  expect(brokenJson.error.status).toBe('INVALID_ARGUMENT');
  expect(brokenJson.error.message).toContain('loyalty_points.label');
  // (iii) an adapter whose PATCH receives that 400 surfaces the exact
  //       server-logged code GOOGLE_WALLET_REFRESH_FAILED_400 instead of
  //       claiming success (the syncWalletBalance swallow regression).
  const failFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === 'https://oauth2.googleapis.com/token') return new Response(JSON.stringify({ access_token: 'x', expires_in: 3600 }), { status: 200 });
    if (url.includes('/loyaltyObject/')) return new Response(JSON.stringify({ error: { code: 400, status: 'INVALID_ARGUMENT' } }), { status: 400 });
    throw new Error(`unexpected URL in mock: ${url}`);
  }) as unknown as typeof fetch;
  await expect(walletAdapter('google', { fetchFn: failFetch }).refresh(card, ['loyaltyPoints', 'textModulesData'], { branding, stampRequired: 10, rewardTitle: 'Gratis' })).rejects.toThrow('GOOGLE_WALLET_REFRESH_FAILED_400');
}));
