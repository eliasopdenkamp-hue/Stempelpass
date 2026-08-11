import { describe, expect, test } from 'bun:test';
import {
  ExternalAccountCredentials,
  GcpCredentialsError,
  ServiceAccountJsonCredentials,
  parseExternalAccountConfig,
  resolveGcpCredentials,
  serviceAccountEmailFromImpersonationUrl,
  gcpCredentialMode,
} from '../src/gcp-credentials';

const EAC = {
  type: 'external_account',
  audience: '//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/vercel/providers/vercel',
  subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
  token_url: 'https://sts.googleapis.com/v1/token',
  service_account_impersonation_url:
    'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/wallet-sa@project.iam.gserviceaccount.com:generateAccessToken',
};
const EAC_JSON = JSON.stringify(EAC);

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function recordingFetch(calls: Array<{ url: string; init: RequestInit }>): typeof fetch {
  const fetchFn = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    calls.push({ url, init: init ?? {} });
    if (url.includes('sts.googleapis.com')) return jsonResponse({ access_token: 'sts-access', expires_in: 3600 });
    if (url.includes(':generateAccessToken')) return jsonResponse({ accessToken: 'sa-access', expireTime: new Date(Date.now() + 3600_000).toISOString() });
    if (url.includes(':signBlob')) return jsonResponse({ keyId: 'k1', signedBlob: Buffer.from('signed-bytes').toString('base64') });
    return jsonResponse({ error: 'not found' }, 404);
  };
  return fetchFn as unknown as typeof fetch;
}

describe('external-account credentials (Workload Identity Federation)', () => {
  test('exchanges the subject token for a service-account access token', async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const creds = new ExternalAccountCredentials(EAC, () => 'vercel-oidc-jwt', recordingFetch(calls));
    expect(creds.mode).toBe('external-account');
    expect(creds.clientEmail).toBe('wallet-sa@project.iam.gserviceaccount.com');
    const token = await creds.getAccessToken();
    expect(token.token).toBe('sa-access');
    expect(token.expiresAt).toBeGreaterThan(Date.now());
    expect(calls).toHaveLength(2);
    const stsBody = JSON.parse(String(calls[0].init.body)) as Record<string, string>;
    expect(stsBody.grant_type).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
    expect(stsBody.audience).toBe(EAC.audience);
    expect(stsBody.subject_token).toBe('vercel-oidc-jwt');
    expect(stsBody.subject_token_type).toBe('urn:ietf:params:oauth:token-type:jwt');
    expect(stsBody.scope).toBe('https://www.googleapis.com/auth/cloud-platform');
    const impHeaders = calls[1].init.headers as Record<string, string>;
    expect(impHeaders.Authorization).toBe('Bearer sts-access');
  });

  test('caches the access token until expiry', async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const creds = new ExternalAccountCredentials(EAC, () => 't', recordingFetch(calls));
    await creds.getAccessToken();
    await creds.getAccessToken();
    await creds.getAccessToken();
    expect(calls.filter(c => c.url.includes('sts.googleapis.com'))).toHaveLength(1);
  });

  test('signBlob signs through the IAM Credentials API with the impersonated token', async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const creds = new ExternalAccountCredentials(EAC, () => 't', recordingFetch(calls));
    const signature = await creds.signBlob(Buffer.from('header.payload', 'utf8'));
    expect(Buffer.from(signature).toString()).toBe('signed-bytes');
    const signCall = calls[calls.length - 1];
    expect(signCall.url).toBe(
      'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/wallet-sa@project.iam.gserviceaccount.com:signBlob',
    );
    const body = JSON.parse(String(signCall.init.body)) as { payload: string };
    expect(Buffer.from(body.payload, 'base64').toString('utf8')).toBe('header.payload');
    expect((signCall.init.headers as Record<string, string>).Authorization).toBe('Bearer sa-access');
  });

  test('rejects an empty subject token without contacting Google', async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const creds = new ExternalAccountCredentials(EAC, () => '', recordingFetch(calls));
    await expect(creds.getAccessToken()).rejects.toThrow('OIDC_TOKEN_MISSING');
    expect(calls).toHaveLength(0);
  });

  test('maps HTTP failures to stable codes without leaking response bodies', async () => {
    const failing = (async () => new Response('{"error":{"message":"secret detail"}}', { status: 403 })) as unknown as typeof fetch;
    const creds = new ExternalAccountCredentials(EAC, () => 't', failing);
    await expect(creds.getAccessToken()).rejects.toThrow('GCP_STS_FAILED_403');
  });

  test('signBlob without impersonation URL is refused', async () => {
    const noImpersonation = { ...EAC, service_account_impersonation_url: undefined };
    const creds = new ExternalAccountCredentials(noImpersonation, () => 't', recordingFetch([]));
    expect(creds.clientEmail).toBeNull();
    await expect(creds.signBlob(Buffer.from('x'))).rejects.toThrow('GCP_IMPERSONATION_URL_REQUIRED');
  });
});

describe('resolveGcpCredentials', () => {
  const EAC_JSON = JSON.stringify(EAC);

  test('prefers external-account credentials when configured with an OIDC token', () => {
    const resolution = resolveGcpCredentials(
      { GOOGLE_ISSUER_ID: '1', GOOGLE_EXTERNAL_ACCOUNT_JSON: EAC_JSON },
      { oidcToken: 'vercel-token' },
    );
    expect(resolution.provider?.mode).toBe('external-account');
    expect(resolution.missing).toEqual([]);
  });

  test('external-account config without an OIDC token reports the missing input', () => {
    const resolution = resolveGcpCredentials({ GOOGLE_EXTERNAL_ACCOUNT_JSON: EAC_JSON }, {});
    expect(resolution.provider).toBeNull();
    expect(resolution.missing.join(' ')).toContain('OIDC token');
  });

  test('falls back to service-account JSON when no external-account config exists', async () => {
    const key = await Bun.$`openssl genrsa 2048 2>/dev/null`.text();
    const resolution = resolveGcpCredentials({ GOOGLE_SERVICE_ACCOUNT_JSON: JSON.stringify({ client_email: 'a@b.c', private_key: key }) });
    expect(resolution.provider?.mode).toBe('service-account-json');
    expect(resolution.missing).toEqual([]);
    const sig = await resolution.provider!.signBlob(Buffer.from('data'));
    expect(sig.length).toBeGreaterThan(0);
  });

  test('supports the split email/key variables as fallback', () => {
    const resolution = resolveGcpCredentials({ GOOGLE_SERVICE_ACCOUNT_EMAIL: 'a@b.c', GOOGLE_PRIVATE_KEY: '-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----\n' });
    expect(resolution.provider?.mode).toBe('service-account-json');
  });

  test('returns no provider and a reason when nothing is configured', () => {
    const resolution = resolveGcpCredentials({});
    expect(resolution.provider).toBeNull();
    expect(resolution.missing).toEqual([]);
  });

  test('never leaks key material into the resolution or provider', () => {
    const key = '-----BEGIN PRIVATE KEY-----SECRETMATERIAL-----END PRIVATE KEY-----';
    const resolution = resolveGcpCredentials({ GOOGLE_SERVICE_ACCOUNT_EMAIL: 'a@b.c', GOOGLE_PRIVATE_KEY: key });
    expect(resolution.missing).toEqual([]);
    expect(JSON.stringify(resolution)).not.toContain('SECRETMATERIAL');
    expect(resolution.provider!.description).not.toContain('SECRETMATERIAL');
  });
});

describe('parsing helpers', () => {
  test('parseExternalAccountConfig accepts valid external-account JSON and rejects others', () => {
    expect(parseExternalAccountConfig(EAC_JSON)?.audience).toContain('workloadIdentityPools');
    expect(parseExternalAccountConfig('{invalid')).toBeNull();
    expect(parseExternalAccountConfig(JSON.stringify({ type: 'service_account' }))).toBeNull();
  });

  test('serviceAccountEmailFromImpersonationUrl extracts the email', () => {
    expect(serviceAccountEmailFromImpersonationUrl(EAC.service_account_impersonation_url)).toBe('wallet-sa@project.iam.gserviceaccount.com');
    expect(serviceAccountEmailFromImpersonationUrl('https://example.com')).toBeNull();
  });

  test('gcpCredentialMode reports the configured mode only', () => {
    expect(gcpCredentialMode({})).toBeNull();
    expect(gcpCredentialMode({ GOOGLE_EXTERNAL_ACCOUNT_JSON: EAC_JSON })).toBe('external-account');
    expect(gcpCredentialMode({ GOOGLE_SERVICE_ACCOUNT_EMAIL: 'a@b.c', GOOGLE_PRIVATE_KEY: 'x' })).toBe('service-account-json');
  });
});

describe('ServiceAccountJsonCredentials', () => {
  test('mode and description are honest', async () => {
    const key = await Bun.$`openssl genrsa 2048 2>/dev/null`.text();
    const creds = new ServiceAccountJsonCredentials('a@b.c', key);
    expect(creds.mode).toBe('service-account-json');
    expect(creds.description).toContain('fallback');
    await expect(creds.getAccessToken()).rejects.toBeInstanceOf(GcpCredentialsError);
  });
});
