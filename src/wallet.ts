import type { Branding, Provider, WalletArtifact, WalletCardView } from './domain.js';
import { createSign } from 'node:crypto';
import { resolveGcpCredentials, gcpCredentialMode, base64url, type GcpCredentialProvider } from './gcp-credentials.js';

export interface LoyaltyClass {
  id: string;
  issuerName: string;
  programName: string;
  programLogo?: { sourceUri: { uri: string } };
}
export interface LoyaltyObject {
  id: string;
  classId: string;
  state: 'ACTIVE' | 'INACTIVE';
  loyaltyPoints: { balance: { int: number } };
  textModulesData?: Array<{ header: string; body: string }>;
}
export interface WalletAdapter { issue(card: WalletCardView, branding: Branding, context?: { stampRequired?: number; rewardTitle?: string }): Promise<WalletArtifact>; refresh(card: WalletCardView, changedFields: string[]): Promise<WalletArtifact>; revoke(card: WalletCardView): Promise<void>; }

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
  async refresh(_card: WalletCardView, _changedFields: string[]): Promise<WalletArtifact> { return { provider: this.provider, status: 'not_configured', message: `${this.provider} wallet is not configured; refresh skipped.` }; }
  async revoke(_card: WalletCardView) { /* no external call without credentials */ }
}

export class GoogleWalletAdapter implements WalletAdapter {
  readonly classModel: LoyaltyClass;
  /**
   * @param issuerId   Numeric Google Wallet issuer id.
   * @param signer     JWT signer (local private-key or keyless IAM signBlob).
   * @param clientEmail Service-account email used as the JWT `iss` claim.
   * @param credentialMode 'service-account-json' (fallback) or 'external-account' (keyless/WIF).
   */
  constructor(
    private readonly issuerId: string,
    private readonly signer: JwtSigner,
    private readonly clientEmail: string,
    private readonly credentialMode: 'service-account-json' | 'external-account',
  ) {
    this.classModel = { id: `${issuerId}.stempelpass_loyalty`, issuerName: 'StempelPass Deutschland', programName: 'StempelPass' };
  }
  private objectModel(card: WalletCardView, branding: Branding, context?: { stampRequired?: number; rewardTitle?: string }): LoyaltyObject {
    return { id: `${this.issuerId}.${card.id}`, classId: this.classModel.id, state: 'ACTIVE', loyaltyPoints: { balance: { int: card.stampCount } }, textModulesData: [{ header: branding.cardTitle, body: `${card.stampCount}/${context?.stampRequired ?? '?'} Stempel · ${context?.rewardTitle ?? 'Prämie'}` }] };
  }
  async issue(card: WalletCardView, branding: Branding, context?: { stampRequired?: number; rewardTitle?: string }): Promise<WalletArtifact> {
    const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'savetowallet' }));
    const payload = base64url(JSON.stringify({ iss: this.clientEmail, aud: 'google', typ: 'savetowallet', iat: Math.floor(Date.now() / 1000), payload: { loyaltyObjects: [this.objectModel(card, branding, context)] } }));
    const signature = await this.signer.sign(`${header}.${payload}`);
    const message = this.credentialMode === 'external-account'
      ? 'Save to Google Wallet (keyless: signed via IAM Credentials; requires owner verification against real Wallet)'
      : 'Save to Google Wallet';
    return { provider: 'google', status: 'issued', message, artifact: `${header}.${payload}.${signature}` };
  }
  async refresh(_card: WalletCardView, _changedFields: string[]) { return { provider: 'google' as const, status: 'issued' as const, message: 'Google Wallet object refresh is handled by the issuer API.' }; }
  async revoke(_card: WalletCardView) { /* issuer API integration follows credential verification */ }
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
      // Both modes expose signBlob(): external-account signs via IAM Credentials
      // (keyless), service-account-json signs locally with the private key.
      return new GoogleWalletAdapter(issuerId, new IamSignBlobJwtSigner(creds), creds.clientEmail, creds.mode);
    }
    return new UnconfiguredWalletAdapter(provider, resolution.missing.join(', ') || 'GOOGLE_ISSUER_ID');
  }
  return new UnconfiguredWalletAdapter(provider);
}

/** Health/status helper: which Google credential mode is configured (if any). */
export function googleWalletConfiguration(env: NodeJS.ProcessEnv = process.env): { configured: boolean; mode: string | null } {
  const mode = gcpCredentialMode(env);
  return { configured: Boolean(env.GOOGLE_ISSUER_ID && mode), mode };
}
