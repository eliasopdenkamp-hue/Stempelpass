import { test, expect } from 'bun:test';
import { GoogleWalletAdapter, GoogleWalletApiClassProvisioner, PrivateKeyJwtSigner, IamSignBlobJwtSigner, walletAdapter, googleWalletConfiguration, ensureGoogleWalletClass, tenantClassModel, DEFAULT_CLASS_LOGO_URI } from './wallet';
import { ExternalAccountCredentials, ServiceAccountJsonCredentials } from './gcp-credentials';
const card = { id:'card-1', tenantId:'tenant-1', customerId:'customer-1', publicTokenHash:'hash', status:'active' as const, stampCount:3, revision:2, ruleId:'rule-1' };
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
  expect(body.loyaltyPoints).toEqual({ balance: { int: card.stampCount } });
  // Branding flows through to the object: progress module + cardText module.
  expect(body.textModulesData).toEqual([
    { header: branding.cardTitle, body: '3/10 Stempel · Gratis' },
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
  expect(body.textModulesData).toEqual([{ header: 'StempelPass', body: '3/? Stempel · Prämie' }]);
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
  expect(obj.textModulesData).toEqual([
    { header: 'Café Herz', body: '3/10 Stempel · Gratis Kaffee' },
    { header: 'Café Herz', body: 'Sammle Stempel' },
  ]);
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
  let stored = { id: '123.stempelpass_loyalty', issuerName: 'Stempelpass', programName: 'Alter Name', hexBackgroundColor: '#000000', programLogo: { sourceUri: { uri: 'https://old.example.invalid/logo.png' } } };
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
  // Partial-update body: branding fields ONLY — never reviewStatus or id.
  expect(body).toEqual({ programName: 'Café Herz', hexBackgroundColor: '#123456', programLogo: { sourceUri: { uri: LOGO_URL } } });
  expect(body.reviewStatus).toBeUndefined();
  expect(body.id).toBeUndefined();
  expect(stored.programName).toBe('Café Herz');
  expect(stored.programLogo).toEqual({ sourceUri: { uri: LOGO_URL } });
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