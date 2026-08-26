import { test, expect } from 'bun:test';
import { GoogleWalletAdapter, GoogleWalletApiClassProvisioner, PrivateKeyJwtSigner, IamSignBlobJwtSigner, walletAdapter, googleWalletConfiguration } from './wallet';
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
  expect(calls.map(c => c.url)).toEqual(['https://oauth2.googleapis.com/token', 'https://walletobjects.googleapis.com/walletobjects/v1/loyaltyClass/123.stempelpass_loyalty']);
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
    throw new Error(`unexpected URL in mock: ${url}`);
  };
  return fakeFetch as unknown as typeof fetch;
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
    'https://sts.googleapis.com/v1/token',
    'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/wallet-sa@project.iam.gserviceaccount.com:generateAccessToken',
    'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/wallet-sa@project.iam.gserviceaccount.com:signBlob',
  ]);
  const stsBody = JSON.parse(String(calls[0].init.body)) as Record<string, string>;
  expect(stsBody.subject_token).toBe('vercel-oidc-token');
  expect(stsBody.subject_token_type).toBe('urn:ietf:params:oauth:token-type:jwt');
  const signBlobAuth = (calls[5].init.headers as Record<string, string>).Authorization;
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
