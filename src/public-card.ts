import type { Branding, Card, StampRule, WalletCardView } from './domain.js';
import type { JoinPageData, PublicReward } from './repository.js';
import { qrSvgDataUri } from './qr.js';

/** HTML-escape a dynamic value (same character set as the webcard/staff pages). */
export function esc(v: unknown): string {
  return String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}

/** Strictly safe six-digit CSS hex; invalid persisted values use stable defaults. */
export function safeCardColor(value: unknown, fallback: string): string {
  return typeof value === 'string' && /^#[0-9a-fA-F]{6}$/.test(value) ? value : fallback;
}

export const DEFAULT_PRIMARY_CARD_COLOR = '#155e75';
export const DEFAULT_SECONDARY_CARD_COLOR = '#f8fafc';

export function safeBranding(branding: Branding | null | undefined): Branding | null {
  if (!branding) return null;
  return { ...branding,
    primaryColor: safeCardColor(branding.primaryColor, DEFAULT_PRIMARY_CARD_COLOR),
    secondaryColor: safeCardColor(branding.secondaryColor, DEFAULT_SECONDARY_CARD_COLOR),
  };
}

export interface PublicCardResponse {
  cardId: string; tenantId: string; stampCount: number; revision: number;
  branding: Branding | null; rule: StampRule | null; reward: PublicReward | null;
  /** DSGVO Art. 13: controller display name (tenants.legal_name), null when unset. */
  controllerName: string | null;
  /** DSGVO Art. 13: optional contact for data-subject requests (tenant_branding.privacy_email). */
  privacyContact: string | null;
}
export interface PublicCardSource { card: Pick<Card, 'id' | 'stampCount' | 'revision'>; branding: Branding | null; rule: StampRule | null; reward: PublicReward | null; controllerName: string | null; privacyContact: string | null; }
export function toPublicCardResponse(result: PublicCardSource, tenantId: string): PublicCardResponse {
  return { cardId: result.card.id, tenantId, stampCount: result.card.stampCount, revision: result.card.revision, branding: safeBranding(result.branding), rule: result.rule, reward: result.reward, controllerName: result.controllerName ?? null, privacyContact: result.privacyContact ?? null };
}
export function toWalletCardView(card: Pick<Card, 'id' | 'stampCount'>): WalletCardView { return { id: card.id, stampCount: card.stampCount }; }

/**
 * Render the unauthenticated customer join page for GET /join/:publicKey
 * (Solution A — the card is created by staff at the register, so the join
 * page carries NO card token and therefore NO save-to-wallet button; it shows
 * the tenant branding, the stamp rule and a clear instruction instead). Same
 * visual style and identical DSGVO Art. 13 footer as the webcard route.
 * Every dynamic value is escaped; colors are sanitized via safeCardColor.
 */
export function joinPageHtml(data: JoinPageData, qrTarget?: string): string {
  const branding = safeBranding(data.branding) ?? {
    cardTitle: 'StempelPass', cardText: '', primaryColor: DEFAULT_PRIMARY_CARD_COLOR,
    secondaryColor: DEFAULT_SECONDARY_CARD_COLOR, version: 1,
  };
  const rule = data.rule;
  const primary = branding.primaryColor;
  const title = branding.cardTitle || 'StempelPass';
  const controller = data.controllerName || '<Tenant>';
  const ruleBlock = rule
    ? `<h2>Stempelregel</h2><p class="rule"><strong>${esc(rule.stampsRequired)} Stempel</strong> &rarr; ${esc(rule.rewardTitle)}${rule.rewardDescription ? ` &middot; ${esc(rule.rewardDescription)}` : ''}</p>`
    : '';
  // The join page is the customer entry point: render the entry path as a
  // scannable QR image (absolute target when the server knows its origin) so
  // the customer can open the page on their phone. No save-to-wallet button —
  // there is no card token on the join page yet (card is created by staff).
  const qrImg = `<img class="qr" src="${esc(qrSvgDataUri(qrTarget ?? data.joinPath))}" alt="QR-Code: ${esc(title)}-Stempelkarte öffnen" width="176" height="176">`;
  return `<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style>body{font:16px system-ui;margin:0;padding:2rem;background:${esc(branding.secondaryColor)};color:#172033}.card{max-width:28rem;margin:auto;padding:2rem;border-radius:1.5rem;background:white;border-top:1rem solid ${esc(primary)};box-shadow:0 8px 30px #0002}h1{margin:0 0 .25rem;font-size:1.5rem}h2{margin:1.5rem 0 .4rem;font-size:1.05rem;color:#334155}p{margin:.4rem 0;line-height:1.5;color:#334155}.tenant{font-size:.85rem;color:#475569}.rule{background:${esc(primary)}14;border-left:.35rem solid ${esc(primary)};padding:.8rem 1rem;border-radius:.6rem;margin:.6rem 0}.notice{background:#f1f5f9;border:1px solid #e2e8f0;border-radius:.75rem;padding:.9rem 1rem;margin-top:1.25rem;font-size:.95rem}.notice strong{display:block;margin-bottom:.25rem}.qr{display:block;margin:1rem auto 0;padding:.4rem;background:#fff;border:1px solid #e2e8f0;border-radius:.75rem}.privacy{margin-top:1.5rem;padding-top:1rem;border-top:1px solid #e2e8f0;font-size:.85rem;color:#475569}.privacy h3{margin:0 0 .4rem;font-size:inherit;color:#334155}.privacy p{margin:.4rem 0}</style><main class="card"><h1>${esc(title)}</h1>${branding.cardText ? `<p>${esc(branding.cardText)}</p>` : ''}${data.controllerName ? `<p class="tenant">${esc(controller)}</p>` : ''}${ruleBlock}<div class="notice"><strong>So sammeln Sie Stempel</strong>${qrImg}<p>Diese Karte wird an der Kasse erstellt. Zeigen Sie diesen QR an der Kasse vor. Nach der Erstellung erhalten Sie Ihren persönlichen Karten-Link und können die Karte direkt zu Google Wallet hinzufügen.</p></div><section class="privacy"><h3>Datenschutz</h3><p>${esc('Verantwortlich für die Verarbeitung: ' + controller)}</p><p>${esc('Diese Stempelkarte speichert nur den Stempelstand und den Fortschritt zur Prämie. StempelPass Deutschland verarbeitet die Daten als Auftragsverarbeiter (Art. 28 DSGVO).')}</p><p>${esc('Die Karte wird nach 12 Monaten ohne Stempelaktivität deaktiviert. Kundendaten werden 30 Tage nach der Soft-Löschung endgültig gelöscht. Falls Sie Kommunikationsnachrichten erhalten oder eine Einwilligung erteilen, wird die Kommunikationshistorie 24 Monate gespeichert; der Nachweis Ihrer Einwilligung wird für einen Zeitraum von 3 Jahren nach Ihrem Widerruf gespeichert. Audit-Aufzeichnungen werden zur Beweissicherung dauerhaft aufbewahrt.')}</p>${data.privacyContact ? '<p>'+esc('Sie haben das Recht auf Auskunft, Berichtigung, Löschung und Widerspruch. Kontakt für Anfragen: '+data.privacyContact)+'</p>' : ''}</section></main>`;
}
