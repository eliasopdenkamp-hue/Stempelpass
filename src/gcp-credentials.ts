/**
 * Provider-agnostic Google Cloud credential abstraction (keyless-first).
 *
 * Preferred mode: Google Application Default Credentials / external account
 * credentials (Workload Identity Federation). The workload exchanges a Vercel
 * OIDC token (x-vercel-oidc-token request header in Vercel Functions, or the
 * VERCEL_OIDC_TOKEN environment variable in builds/local development) for a
 * short-lived Google access token via the STS token exchange, then impersonates
 * a Google service account. No static service-account JSON key is required.
 *
 * Fallback mode (kept for environments where WIF is not available): classic
 * service-account JSON (GOOGLE_SERVICE_ACCOUNT_JSON) or the split
 * GOOGLE_SERVICE_ACCOUNT_EMAIL / GOOGLE_PRIVATE_KEY variables. In this mode the
 * private key is used directly with node:crypto to sign.
 *
 * Security invariants:
 * - Private key material is NEVER logged, never written to files by this code,
 *   and never included in error messages or status payloads.
 * - The external-account path never touches a private key at all: signing
 *   happens through the IAM Credentials `signBlob` API with Google-held keys.
 * - No real Google calls are made by the test suite; every HTTP interaction in
 *   this module goes through an injectable fetch function.
 */
import { createSign } from 'node:crypto';
import { readFileSync } from 'node:fs';

export type GcpCredentialMode = 'service-account-json' | 'external-account';

export interface GcpAccessToken {
  token: string;
  /** Milliseconds since epoch; 0 when unknown. */
  expiresAt: number;
}

export interface GcpCredentialProvider {
  readonly mode: GcpCredentialMode;
  /** Service-account email used as the `iss` claim of Wallet JWTs. Null when not derivable. */
  readonly clientEmail: string | null;
  /** Short, secret-free description used in status messages. */
  readonly description: string;
  /** Sign raw bytes with the service-account key (RS256). Never returns key material. */
  signBlob(input: Uint8Array): Promise<Uint8Array>;
  /** Obtain a short-lived Google access token for the requested API scope. */
  getAccessToken(scope?: string): Promise<GcpAccessToken>;
}

export interface GcpCredentialResolution {
  provider: GcpCredentialProvider | null;
  /** Human-readable names of the missing configuration inputs, for status messages. */
  missing: string[];
}

/** External-account credentials JSON as produced for Workload Identity Federation. */
export interface ExternalAccountConfig {
  type?: string;
  audience: string;
  subject_token_type?: string;
  token_url?: string;
  service_account_impersonation_url?: string;
  scope?: string;
}

export const CLOUD_PLATFORM_SCOPE = 'https://www.googleapis.com/auth/cloud-platform';
export const WALLET_OBJECT_SCOPE = 'https://www.googleapis.com/auth/wallet_object.issuer';
const STS_TOKEN_URL = 'https://sts.googleapis.com/v1/token';

function base64url(value: string | Uint8Array): string {
  return Buffer.from(value as Uint8Array).toString('base64url');
}
function base64(value: string | Uint8Array): string {
  return Buffer.from(value as Uint8Array).toString('base64');
}

export function parseExternalAccountConfig(raw: string): ExternalAccountConfig | null {
  try {
    const parsed = JSON.parse(raw) as ExternalAccountConfig;
    if (parsed.audience && parsed.audience.includes('workloadIdentityPools')) return parsed;
  } catch {
    /* invalid configuration is treated as absent */
  }
  return null;
}

/** Derive the impersonated service-account email from its impersonation URL. */
export function serviceAccountEmailFromImpersonationUrl(url: string): string | null {
  const match = /serviceAccounts\/([^:]+):generateAccessToken$/.exec(url);
  return match ? decodeURIComponent(match[1]) : null;
}

export class GcpCredentialsError extends Error {
  constructor(code: string) {
    super(code);
    this.name = 'GcpCredentialsError';
  }
}

/**
 * External-account (Workload Identity Federation) provider.
 * The subject token (Vercel OIDC token) is supplied per request via
 * `getSubjectToken`; it is never stored. All HTTP goes through `fetchFn`
 * so tests can substitute a mock and never touch the network.
 */
export class ExternalAccountCredentials implements GcpCredentialProvider {
  readonly mode: GcpCredentialMode = 'external-account';
  readonly clientEmail: string | null;
  readonly description = 'Google Workload Identity Federation (external account, keyless)';
  private readonly cached = new Map<string, GcpAccessToken>();
  private readonly scope: string;

  constructor(
    private readonly config: ExternalAccountConfig,
    private readonly getSubjectToken: () => string | Promise<string>,
    private readonly fetchFn: typeof fetch = fetch,
    private readonly now: () => number = Date.now,
  ) {
    this.clientEmail = config.service_account_impersonation_url
      ? serviceAccountEmailFromImpersonationUrl(config.service_account_impersonation_url)
      : null;
    this.scope = config.scope ?? CLOUD_PLATFORM_SCOPE;
  }

  async getAccessToken(scope = this.scope): Promise<GcpAccessToken> {
    const cached = this.cached.get(scope);
    if (cached && cached.expiresAt > this.now() + 60_000) return cached;
    const subjectToken = await this.getSubjectToken();
    if (!subjectToken) throw new GcpCredentialsError('OIDC_TOKEN_MISSING');
    const stsUrl = this.config.token_url ?? STS_TOKEN_URL;
    const stsResponse = await this.fetchFn(stsUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        audience: this.config.audience,
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        scope,
        subject_token: subjectToken,
        subject_token_type: this.config.subject_token_type ?? 'urn:ietf:params:oauth:token-type:jwt',
      }),
    });
    if (!stsResponse.ok) throw new GcpCredentialsError(`GCP_STS_FAILED_${stsResponse.status}`);
    const sts = (await stsResponse.json()) as { access_token?: string; expires_in?: number };
    if (!sts.access_token) throw new GcpCredentialsError('GCP_STS_NO_TOKEN');
    const stsExpiresAt = this.now() + (sts.expires_in ?? 3600) * 1000;

    if (!this.config.service_account_impersonation_url) {
      const token = { token: sts.access_token, expiresAt: stsExpiresAt };
      this.cached.set(scope, token);
      return token;
    }
    const impResponse = await this.fetchFn(this.config.service_account_impersonation_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${sts.access_token}` },
      body: JSON.stringify({ scope: [scope], lifetime: '3600s' }),
    });
    if (!impResponse.ok) throw new GcpCredentialsError(`GCP_IMPERSONATION_FAILED_${impResponse.status}`);
    const imp = (await impResponse.json()) as { accessToken?: string; expireTime?: string };
    if (!imp.accessToken) throw new GcpCredentialsError('GCP_IMPERSONATION_NO_TOKEN');
    const expiresAt = imp.expireTime ? Date.parse(imp.expireTime) : stsExpiresAt;
    const token = { token: imp.accessToken, expiresAt };
    this.cached.set(scope, token);
    return token;
  }

  async signBlob(input: Uint8Array): Promise<Uint8Array> {
    if (!this.clientEmail) throw new GcpCredentialsError('GCP_IMPERSONATION_URL_REQUIRED');
    const { token } = await this.getAccessToken(CLOUD_PLATFORM_SCOPE);
    const response = await this.fetchFn(
      `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${this.clientEmail}:signBlob`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ delegates: [], payload: base64(input) }),
      },
    );
    if (!response.ok) throw new GcpCredentialsError(`GCP_SIGNBLOB_FAILED_${response.status}`);
    const body = (await response.json()) as { signedBlob?: string };
    if (!body.signedBlob) throw new GcpCredentialsError('GCP_SIGNBLOB_NO_RESULT');
    return Buffer.from(body.signedBlob, 'base64');
  }
}

/**
 * Classic service-account JSON fallback. Holds the private key in memory only
 * (in a non-enumerable WeakMap so it never appears in JSON output, logs or
 * serialized status) and signs locally. Kept strictly as an optional fallback
 * for environments that cannot use Workload Identity Federation.
 */
const fallbackPrivateKeys = new WeakMap<ServiceAccountJsonCredentials, string>();
export class ServiceAccountJsonCredentials implements GcpCredentialProvider {
  readonly mode: GcpCredentialMode = 'service-account-json';
  readonly clientEmail: string;
  readonly description = 'classic service-account key (fallback mode)';
  private readonly cached = new Map<string, GcpAccessToken>();
  constructor(
    client_email: string,
    private_key: string,
    private readonly fetchFn: typeof fetch = fetch,
    private readonly now: () => number = Date.now,
  ) {
    this.clientEmail = client_email;
    fallbackPrivateKeys.set(this, private_key);
  }
  async signBlob(input: Uint8Array): Promise<Uint8Array> {
    const key = fallbackPrivateKeys.get(this);
    if (!key) throw new GcpCredentialsError('FALLBACK_KEY_UNAVAILABLE');
    const signer = createSign('RSA-SHA256');
    signer.update(input as Uint8Array);
    signer.end();
    return signer.sign(key);
  }
  async getAccessToken(scope = WALLET_OBJECT_SCOPE): Promise<GcpAccessToken> {
    const cached = this.cached.get(scope);
    if (cached && cached.expiresAt > this.now() + 60_000) return cached;
    const key = fallbackPrivateKeys.get(this);
    if (!key) throw new GcpCredentialsError('FALLBACK_KEY_UNAVAILABLE');
    const tokenUrl = 'https://oauth2.googleapis.com/token';
    const now = Math.floor(this.now() / 1000);
    const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
    const claims = base64url(JSON.stringify({ iss: this.clientEmail, scope, aud: tokenUrl, iat: now, exp: now + 3600 }));
    const signer = createSign('RSA-SHA256');
    signer.update(`${header}.${claims}`, 'utf8');
    signer.end();
    const assertion = `${header}.${claims}.${signer.sign(key, 'base64url')}`;
    const response = await this.fetchFn(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }),
    });
    if (!response.ok) throw new GcpCredentialsError(`GCP_TOKEN_FAILED_${response.status}`);
    const body = await response.json() as { access_token?: string; expires_in?: number };
    if (!body.access_token) throw new GcpCredentialsError('GCP_TOKEN_NO_ACCESS_TOKEN');
    const token = { token: body.access_token, expiresAt: this.now() + (body.expires_in ?? 3600) * 1000 };
    this.cached.set(scope, token);
    return token;
  }
}

export interface ResolveOptions {
  /** Vercel OIDC token from the x-vercel-oidc-token request header (Functions). */
  oidcToken?: string;
  /** Overridable for tests; never used to call real Google endpoints by default. */
  fetchFn?: typeof fetch;
}

function readExternalAccountFromFile(path: string): ExternalAccountConfig | null {
  try {
    return parseExternalAccountConfig(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
}

function serviceAccountFromFile(path: string): { client_email: string; private_key: string } | null {
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as { client_email?: string; private_key?: string; type?: string };
    if (parsed.type === 'service_account' && parsed.client_email && parsed.private_key) {
      return { client_email: parsed.client_email, private_key: parsed.private_key };
    }
  } catch {
    /* ignore */
  }
  return null;
}

/**
 * Resolve GCP credentials from the environment, preferring the keyless
 * external-account (Workload Identity Federation) path.
 *
 * Priority:
 *  1. GOOGLE_EXTERNAL_ACCOUNT_JSON (env) or GOOGLE_APPLICATION_CREDENTIALS
 *     pointing at an `external_account` JSON -> ExternalAccountCredentials.
 *  2. GOOGLE_SERVICE_ACCOUNT_JSON / GOOGLE_SERVICE_ACCOUNT_EMAIL +
 *     GOOGLE_PRIVATE_KEY / GOOGLE_APPLICATION_CREDENTIALS service_account file
 *     -> ServiceAccountJsonCredentials (fallback).
 */
export function resolveGcpCredentials(
  env: NodeJS.ProcessEnv = process.env,
  options: ResolveOptions = {},
): GcpCredentialResolution {
  const missing: string[] = [];
  const oidcToken = options.oidcToken ?? env.VERCEL_OIDC_TOKEN;

  const rawExternal = env.GOOGLE_EXTERNAL_ACCOUNT_JSON;
  const adcPath = env.GOOGLE_APPLICATION_CREDENTIALS;
  const externalConfig = rawExternal
    ? parseExternalAccountConfig(rawExternal)
    : adcPath
      ? readExternalAccountFromFile(adcPath)
      : null;

  if (externalConfig) {
    if (!oidcToken) {
      missing.push('OIDC token (x-vercel-oidc-token header in Vercel Functions or VERCEL_OIDC_TOKEN)');
      return { provider: null, missing };
    }
    const provider = new ExternalAccountCredentials(externalConfig, () => oidcToken, options.fetchFn ?? fetch);
    if (!provider.clientEmail) {
      missing.push('service_account_impersonation_url in GOOGLE_EXTERNAL_ACCOUNT_JSON');
      return { provider: null, missing };
    }
    return { provider, missing: [] };
  }

  const rawJson = env.GOOGLE_SERVICE_ACCOUNT_JSON;
  let parsedJson: { client_email?: string; private_key?: string } | null = null;
  if (rawJson) {
    try {
      parsedJson = JSON.parse(rawJson) as { client_email?: string; private_key?: string };
    } catch {
      /* invalid configuration is treated as absent */
    }
  }
  const fileSa = !parsedJson && adcPath ? serviceAccountFromFile(adcPath) : null;
  const email = parsedJson?.client_email ?? fileSa?.client_email ?? env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
  const key =
    parsedJson?.private_key ?? fileSa?.private_key ?? env.GOOGLE_PRIVATE_KEY?.replace(/\\n/g, '\n');
  if (email && key) return { provider: new ServiceAccountJsonCredentials(email, key, options.fetchFn ?? fetch), missing: [] };

  if (rawExternal || adcPath || rawJson || env.GOOGLE_SERVICE_ACCOUNT_EMAIL || env.GOOGLE_PRIVATE_KEY) {
    if (!email) missing.push('GOOGLE_SERVICE_ACCOUNT_EMAIL (or complete service-account JSON)');
    if (!key) missing.push('GOOGLE_PRIVATE_KEY (or complete service-account JSON)');
  }
  return { provider: null, missing };
}

/** Convenience for status/health endpoints: configuration mode without constructing a provider. */
export function gcpCredentialMode(env: NodeJS.ProcessEnv = process.env): GcpCredentialMode | null {
  const external = env.GOOGLE_EXTERNAL_ACCOUNT_JSON ? parseExternalAccountConfig(env.GOOGLE_EXTERNAL_ACCOUNT_JSON) : null;
  if (external) return 'external-account';
  const json = env.GOOGLE_SERVICE_ACCOUNT_JSON;
  if (json) {
    try {
      const parsed = JSON.parse(json) as { client_email?: string; private_key?: string };
      if (parsed.client_email && parsed.private_key) return 'service-account-json';
    } catch {
      /* ignore */
    }
  }
  if (env.GOOGLE_SERVICE_ACCOUNT_EMAIL && env.GOOGLE_PRIVATE_KEY) return 'service-account-json';
  return null;
}

export { base64url };
