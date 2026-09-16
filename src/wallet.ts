import type { Branding, Provider, WalletArtifact, WalletCardView } from './domain.js';
import { createSign } from 'node:crypto';
import { resolveGcpCredentials, gcpCredentialMode, base64url, WALLET_OBJECT_SCOPE, type GcpCredentialProvider } from './gcp-credentials.js';

export interface LoyaltyClass {
  id: string;
  issuerName: string;
  programName: string;
  reviewStatus?: 'UNDER_REVIEW' | 'APPROVED';
  programLogo?: { sourceUri: { uri: string } };
  /** Class-level card background color (Google Wallet LoyaltyClass.hexBackgroundColor). */
  hexBackgroundColor?: string;
  /** Class-level card text color (Google Wallet LoyaltyClass.hexFontColor). */
  hexFontColor?: string;
}
export interface LoyaltyObject {
  id: string;
  classId: string;
  state: 'ACTIVE' | 'INACTIVE';
  loyaltyPoints: { balance: { int: number } };
  textModulesData?: Array<{ header: string; body: string }>;
}
export interface WalletAdapter { issue(card: WalletCardView, branding: Branding, context?: { stampRequired?: number; rewardTitle?: string }): Promise<WalletArtifact>; refresh(card: WalletCardView, changedFields: string[], context?: { branding?: Branding; stampRequired?: number; rewardTitle?: string }): Promise<WalletArtifact>; revoke(card: WalletCardView): Promise<void>; }
/** Refresh context mirrors the issue() context plus the branding needed for the text module. */
export interface WalletRefreshContext { branding?: Branding; stampRequired?: number; rewardTitle?: string; }

/** Signs the UTF-8 bytes of `header.payload` and returns the base64url signature. */
export interface JwtSigner { sign(signingInput: string): Promise<string>; }

/** Classic local signing with the service-account private key (fallback mode). */
export class PrivateKeyJwtSigner implements JwtSigner {
  constructor(private readonly privateKey: string) {}
  async sign(signingInput: string): Promise<string> {
    const signer = createSign('RSA-SHA256');
    signer.update(signingInput, 'utf8');
    signer.end();
    return signer.sign(this.privateKey, 'base64url');
  }
}

/**
 * Keyless signing: constructs the Wallet JWT locally and asks the IAM
 * Credentials API to sign it with the service-account key held by Google.
 * The private key never exists in this process.
 */
export class IamSignBlobJwtSigner implements JwtSigner {
  constructor(private readonly credentials: GcpCredentialProvider) {}
  async sign(signingInput: string): Promise<string> {
    const signature = await this.credentials.signBlob(Buffer.from(signingInput, 'utf8'));
    return Buffer.from(signature).toString('base64url');
  }
}

class UnconfiguredWalletAdapter implements WalletAdapter {
  constructor(private provider: Provider, private readonly detail: string | null = null) {}
  async issue(_card: WalletCardView, _branding: Branding): Promise<WalletArtifact> {
    const base = `${this.provider} wallet is not configured; no pass was created.`;
    return { provider: this.provider, status: 'not_configured', message: this.detail ? `${base} Missing: ${this.detail}` : base };
  }
  async refresh(_card: WalletCardView, _changedFields: string[], _context?: WalletRefreshContext): Promise<WalletArtifact> { return { provider: this.provider, status: 'not_configured', message: `${this.provider} wallet is not configured; refresh skipped.` }; }
  async revoke(_card: WalletCardView) { /* no external call without credentials */ }
}

export interface GoogleWalletClassProvisioner {
  ensureClassExists(classModel: LoyaltyClass): Promise<void>;
}

/** Strict six-digit CSS hex, as the Wallet API expects for card colors. */
function brandHexColor(value: string | undefined): string | undefined {
  return value && /^#[0-9a-fA-F]{6}$/.test(value) ? value : undefined;
}
/** Google Wallet needs a PUBLICLY HOSTED image URL for programLogo. */
function brandHttpsUrl(value: string | undefined): string | undefined {
  return value && /^https:\/\/\S+$/i.test(value) && value.length <= 2048 ? value : undefined;
}
/** Fallback logo URL (platform default; used when the tenant set no logo yet). */
export const DEFAULT_CLASS_LOGO_URI = 'https://www.gstatic.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png';
/** Fallback branding mirrors the pre-branding adapter behaviour (StempelPass defaults). */
export const FALLBACK_BRANDING: Branding = { cardTitle: 'StempelPass', cardText: '', primaryColor: '', secondaryColor: '', version: 1 };

/**
 * Deterministic tenant-aware LoyaltyClass model built from tenant branding.
 *
 * Class id: `{issuerId}.{classSuffix}` — the PILOT tenant keeps the default
 * suffix `stempelpass_loyalty`, which is exactly the class id that is already
 * APPROVED in the production issuer account (`3388000000023180140.stempelpass_loyalty`),
 * so the owner's already-saved Wallet pass keeps working. A different suffix
 * (future multi-tenant) means a NEW class at Google that goes through review
 * again — deliberately NOT used for the pilot.
 *
 * Branding mapping (fields the Wallet API actually accepts at class level):
 * programName   ← branding.cardTitle (company card title)
 * hexBackgroundColor ← branding.primaryColor (validated #rrggbb)
 * programLogo   ← branding.logoUrl (must be a hosted https URL), else the
 *                 platform fallback logo (never omits programLogo).
 * issuerName stays the platform name 'Stempelpass' — Branding deliberately has
 * no legal-name field; a per-tenant issuer name is a documented follow-up.
 */
export function tenantClassModel(issuerId: string, branding: Branding, classSuffix = 'stempelpass_loyalty'): LoyaltyClass {
  const title = (branding.cardTitle ?? '').trim() || 'StempelPass';
  const logoUri = brandHttpsUrl(branding.logoUrl);
  const model: LoyaltyClass = {
    id: `${issuerId}.${classSuffix}`,
    issuerName: 'Stempelpass',
    programName: title,
    reviewStatus: 'UNDER_REVIEW',
    programLogo: { sourceUri: { uri: logoUri ?? DEFAULT_CLASS_LOGO_URI } },
  };
  const background = brandHexColor(branding.primaryColor);
  if (background) model.hexBackgroundColor = background;
  return model;
}

/** Idempotently provisions the issuer-wide LoyaltyClass before issuing a pass.
 *  GET → 404: POST create. GET 200: compare ONLY the branding-relevant fields;
 *  when any differs, PATCH the existing class with exactly those fields
 *  (partial update, no reviewStatus/id) — idempotent "patch once": after the
 *  first PATCH the GET returns the new values and no further PATCH is issued.
 *  Patching the APPROVED pilot class can push it back into Google review
 *  (documented in the PR); the owner's saved pass object is NOT affected —
 *  objects reference the class by id, which never changes. */
export class GoogleWalletApiClassProvisioner implements GoogleWalletClassProvisioner {
  constructor(private readonly credentials: GcpCredentialProvider, private readonly fetchFn: typeof fetch = fetch) {}

  async ensureClassExists(classModel: LoyaltyClass): Promise<void> {
    const { token } = await this.credentials.getAccessToken(WALLET_OBJECT_SCOPE);
    const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
    const url = `https://walletobjects.googleapis.com/walletobjects/v1/loyaltyClass/${encodeURIComponent(classModel.id)}`;
    const existing = await this.fetchFn(url, { headers });
    if (existing.ok) {
      let current: Partial<LoyaltyClass> = {};
      try { current = (await existing.json()) as Partial<LoyaltyClass>; } catch { /* non-JSON body: leave the class untouched */ return; }
      const patch: Partial<LoyaltyClass> = {};
      if ((current.issuerName ?? '') !== classModel.issuerName) patch.issuerName = classModel.issuerName;
      if ((current.programName ?? '') !== classModel.programName) patch.programName = classModel.programName;
      if (classModel.programLogo && (current.programLogo?.sourceUri?.uri ?? '') !== classModel.programLogo.sourceUri.uri) patch.programLogo = classModel.programLogo;
      if (classModel.hexBackgroundColor && (current.hexBackgroundColor ?? '') !== classModel.hexBackgroundColor) patch.hexBackgroundColor = classModel.hexBackgroundColor;
      if (Object.keys(patch).length === 0) return;
      const patched = await this.fetchFn(url, { method: 'PATCH', headers, body: JSON.stringify(patch) });
      if (!patched.ok) throw new Error(`GOOGLE_WALLET_CLASS_PATCH_FAILED_${patched.status}`);
      return;
    }
    if (existing.status !== 404) throw new Error(`GOOGLE_WALLET_CLASS_GET_FAILED_${existing.status}`);

    const create = await this.fetchFn('https://walletobjects.googleapis.com/walletobjects/v1/loyaltyClass', {
      method: 'POST', headers, body: JSON.stringify(classModel),
    });
    if (create.ok || create.status === 409) return;
    throw new Error(`GOOGLE_WALLET_CLASS_CREATE_FAILED_${create.status}`);
  }
}

export class GoogleWalletAdapter implements WalletAdapter {
  readonly classModel: LoyaltyClass;
  /**
   * @param issuerId   Numeric Google Wallet issuer id.
   * @param signer     JWT signer (local private-key or keyless IAM signBlob).
   * @param clientEmail Service-account email used as the JWT `iss` claim.
   * @param credentialMode 'service-account-json' (fallback) or 'external-account' (keyless/WIF).
   * @param classSuffix Class-id suffix after `{issuerId}.` — defaults to the
   *   pilot suffix `stempelpass_loyalty` (the APPROVED production class); a
   *   different suffix provisions a NEW class that needs Google review.
   */
  constructor(
    private readonly issuerId: string,
    private readonly signer: JwtSigner,
    private readonly clientEmail: string,
    private readonly credentialMode: 'service-account-json' | 'external-account',
    private readonly classProvisioner?: GoogleWalletClassProvisioner,
    private readonly credentials?: GcpCredentialProvider,
    private readonly fetchFn: typeof fetch = fetch,
    private readonly classSuffix: string = 'stempelpass_loyalty',
  ) {
    this.classModel = tenantClassModel(issuerId, FALLBACK_BRANDING, this.classSuffix);
  }
  /** Branding-derived LoyaltyClass (tenant-aware: card title, colors, logo). */
  classModelFor(branding: Branding): LoyaltyClass {
    return tenantClassModel(this.issuerId, branding, this.classSuffix);
  }
  private objectModel(classId: string, card: WalletCardView, branding: Branding, context?: { stampRequired?: number; rewardTitle?: string }): LoyaltyObject {
    const title = branding.cardTitle?.trim() || 'StempelPass';
    const modules: Array<{ header: string; body: string }> = [
      { header: title, body: `${card.stampCount}/${context?.stampRequired ?? '?'} Stempel · ${context?.rewardTitle ?? 'Prämie'}` },
    ];
    const cardText = branding.cardText?.trim();
    if (cardText) modules.push({ header: title, body: cardText });
    return { id: `${this.issuerId}.${card.id}`, classId, state: 'ACTIVE', loyaltyPoints: { balance: { int: card.stampCount } }, textModulesData: modules };
  }
  async issue(card: WalletCardView, branding: Branding, context?: { stampRequired?: number; rewardTitle?: string }): Promise<WalletArtifact> {
    const classModel = this.classModelFor(branding);
    if (this.classProvisioner) await this.classProvisioner.ensureClassExists(classModel);
    const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'savetowallet' }));
    const payload = base64url(JSON.stringify({ iss: this.clientEmail, aud: 'google', typ: 'savetowallet', iat: Math.floor(Date.now() / 1000), payload: { loyaltyObjects: [this.objectModel(classModel.id, card, branding, context)] } }));
    const signature = await this.signer.sign(`${header}.${payload}`);
    const message = this.credentialMode === 'external-account'
      ? 'Save to Google Wallet (keyless: signed via IAM Credentials; requires owner verification against real Wallet)'
      : 'Save to Google Wallet';
    return { provider: 'google', status: 'issued', message, artifact: `${header}.${payload}.${signature}` };
  }
  /**
   * PUSH a balance/text-module update to an already-saved Google Wallet object.
   *
   * Same auth/URL plumbing as revoke(): Bearer token from the issuer
   * credentials, PATCH `loyaltyObject/{issuerId}.{cardId}`. The PATCH body is
   * deliberately built from the card + branding + rule context (mirroring the
   * objectModel shape used by issue()) — the `changedFields` argument is
   * accepted for protocol compatibility but never used to construct the body.
   *
   * 404 means the object does not exist (the customer never saved the pass) —
   * treated as a graceful no-op, exactly like revoke() treats 404. Any other
   * non-OK status throws GOOGLE_WALLET_REFRESH_FAILED_<status> (consistent
   * with issue()/class provisioning error contract); callers that must not
   * fail the committed stamp/redeem wrap this in try/catch.
   */
  async refresh(card: WalletCardView, changedFields: string[], context?: WalletRefreshContext): Promise<WalletArtifact> {
    if (!this.credentials) return { provider: 'google', status: 'not_configured', message: 'Google Wallet wallet is not configured; refresh skipped.' };
    const branding: Branding = context?.branding ?? { cardTitle: 'StempelPass', cardText: '', primaryColor: '', secondaryColor: '', version: 1 };
    const model = this.objectModel(this.classModelFor(branding).id, card, branding, { stampRequired: context?.stampRequired, rewardTitle: context?.rewardTitle });
    const { token } = await this.credentials.getAccessToken(WALLET_OBJECT_SCOPE);
    const response = await this.fetchFn(
      `https://walletobjects.googleapis.com/walletobjects/v1/loyaltyObject/${encodeURIComponent(`${this.issuerId}.${card.id}`)}`,
      { method: 'PATCH', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ loyaltyPoints: model.loyaltyPoints, textModulesData: model.textModulesData }) },
    );
    if (!response.ok && response.status !== 404) throw new Error(`GOOGLE_WALLET_REFRESH_FAILED_${response.status}`);
    const message = response.status === 404
      ? 'Google Wallet object not saved yet; refresh skipped.'
      : `Google Wallet object updated (${changedFields.length === 0 ? card.id : changedFields.join(', ')}).`;
    return { provider: 'google', status: 'issued', message };
  }
  async revoke(card: WalletCardView): Promise<void> {
    if (!this.credentials) {
      console.error('wallet_revoke_failed code=GOOGLE_WALLET_CREDENTIALS_UNAVAILABLE');
      return;
    }
    try {
      const { token } = await this.credentials.getAccessToken(WALLET_OBJECT_SCOPE);
      const response = await this.fetchFn(
        `https://walletobjects.googleapis.com/walletobjects/v1/loyaltyObject/${encodeURIComponent(`${this.issuerId}.${card.id}`)}`,
        { method: 'PATCH', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ state: 'INACTIVE' }) },
      );
      if (!response.ok && response.status !== 404) throw new Error(`GOOGLE_WALLET_REVOKE_FAILED_${response.status}`);
    } catch (error) {
      const code = error instanceof Error && /^GOOGLE_WALLET_REVOKE_FAILED_[0-9]+$/.test(error.message)
        ? error.message : 'GOOGLE_WALLET_REVOKE_UNAVAILABLE';
      console.error(`wallet_revoke_failed code=${code}`);
    }
  }
}

export interface WalletAdapterOptions {
  /** Vercel OIDC token from the x-vercel-oidc-token request header (Vercel Functions). */
  oidcToken?: string;
  /** Test seam: substitute the HTTP client so tests never call Google. */
  fetchFn?: typeof fetch;
}

/**
 * Factory. The keyless (Workload Identity Federation) path is preferred and
 * works without GOOGLE_SERVICE_ACCOUNT_JSON; the classic service-account JSON
 * mode remains as an optional fallback. Without any credentials the adapter is
 * honest: status `not_configured`, no fake pass.
 */
export function walletAdapter(provider: Provider, options: WalletAdapterOptions = {}): WalletAdapter {
  const issuerId = process.env.GOOGLE_ISSUER_ID;
  if (provider === 'google' && issuerId) {
    const resolution = resolveGcpCredentials(process.env, { oidcToken: options.oidcToken, fetchFn: options.fetchFn });
    if (resolution.provider) {
      const creds = resolution.provider;
      if (!creds.clientEmail) return new UnconfiguredWalletAdapter(provider, 'service account email is not derivable from the configured credentials');
      const provisioner = new GoogleWalletApiClassProvisioner(creds, options.fetchFn);
      return new GoogleWalletAdapter(issuerId, new IamSignBlobJwtSigner(creds), creds.clientEmail, creds.mode, provisioner, creds, options.fetchFn);
    }
    return new UnconfiguredWalletAdapter(provider, resolution.missing.join(', ') || 'GOOGLE_ISSUER_ID');
  }
  return new UnconfiguredWalletAdapter(provider);
}

/**
 * Best-effort Google Wallet CLASS sync for the current tenant branding
 * (colors / program name / logo). Used after the Staff-UI branding form saves,
 * so the APPROVED pilot class reflects the new branding immediately instead of
 * waiting for the next save-to-wallet (issue()). GET-compare-PATCH semantics
 * make it idempotent; without GOOGLE_ISSUER_ID / credentials it is a silent
 * no-op (the class is patched anyway on the next issue()).
 */
export async function ensureGoogleWalletClass(branding: Branding, options: WalletAdapterOptions = {}): Promise<void> {
  const issuerId = process.env.GOOGLE_ISSUER_ID;
  if (!issuerId) return;
  const resolution = resolveGcpCredentials(process.env, { oidcToken: options.oidcToken, fetchFn: options.fetchFn });
  if (!resolution.provider || !resolution.provider.clientEmail) return;
  const provisioner = new GoogleWalletApiClassProvisioner(resolution.provider, options.fetchFn);
  await provisioner.ensureClassExists(tenantClassModel(issuerId, branding));
}

/** Health/status helper: which Google credential mode is configured (if any). */
export function googleWalletConfiguration(env: NodeJS.ProcessEnv = process.env): { configured: boolean; mode: string | null } {
  const mode = gcpCredentialMode(env);
  return { configured: Boolean(env.GOOGLE_ISSUER_ID && mode), mode };
}
