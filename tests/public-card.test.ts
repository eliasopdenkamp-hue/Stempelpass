import { test, expect } from 'bun:test';
import { safeCardColor, safeBranding, toPublicCardResponse, toWalletCardView, joinPageHtml, DEFAULT_PRIMARY_CARD_COLOR, DEFAULT_SECONDARY_CARD_COLOR } from '../src/public-card';
import type { Card } from '../src/domain';
import type { JoinPageData } from '../src/repository';

const fullCard: Card = { id: 'card-1', tenantId: 'tenant-1', customerId: 'customer-1', publicTokenHash: 'deadbeef-public-token-hash', status: 'active', stampCount: 3, revision: 2, ruleId: 'rule-1' };
const branding = { cardTitle: 'Café', cardText: 'Treuekarte', primaryColor: '#123456', secondaryColor: '#ffffff', version: 1 };
const rule = { id: 'rule-1', tenantId: 'tenant-1', name: 'Regel', stampsRequired: 10, rewardTitle: 'Prämie', rewardDescription: '', active: true, version: 1 };
const reward = { id: 'reward-1', status: 'issued' as const, issuedAt: null, redeemedAt: null };

test('safeCardColor accepts exactly six-digit hex colors', () => {
  expect(safeCardColor('#123456', '#000000')).toBe('#123456');
  for (const invalid of ['red', '#fff', '#12345678', 'url(javascript:alert(1))', '#12; color:url(x)']) expect(safeCardColor(invalid, '#000000')).toBe('#000000');
  expect(safeCardColor(null, '#000000')).toBe('#000000');
});

test('invalid persisted branding colors are replaced with fixed defaults', () => {
  const safe = safeBranding({ ...branding, primaryColor: 'url(https://evil.invalid)', secondaryColor: '#fff' });
  expect(safe?.primaryColor).toBe(DEFAULT_PRIMARY_CARD_COLOR);
  expect(safe?.secondaryColor).toBe(DEFAULT_SECONDARY_CARD_COLOR);
});

test('public card response is strictly allowlisted (no customerId, no publicTokenHash, no DB row)', () => {
  const payload = toPublicCardResponse({ card: fullCard, branding, rule, reward, controllerName: 'Beispiel GmbH', privacyContact: 'datenschutz@beispiel.de' }, 'tenant-1');
  expect(Object.keys(payload).sort()).toEqual(['branding', 'cardId', 'controllerName', 'privacyContact', 'revision', 'reward', 'rule', 'stampCount', 'tenantId']);
  const serialized = JSON.stringify(payload); expect(serialized).not.toContain('customerId'); expect(serialized).not.toContain('customer-1'); expect(serialized).not.toContain('publicTokenHash'); expect(serialized).not.toContain('deadbeef-public-token-hash');
  expect(payload.cardId).toBe('card-1'); expect(payload.stampCount).toBe(3); expect(payload.revision).toBe(2); expect(payload.branding).toEqual(branding); expect(payload.rule).toEqual(rule); expect(payload.reward).toEqual(reward);
  // DSGVO Art. 13 fields: controller + optional privacy contact, nothing else new.
  expect(payload.controllerName).toBe('Beispiel GmbH');
  expect(payload.privacyContact).toBe('datenschutz@beispiel.de');
});
test('public card response keeps null branding/rule/reward without leaking card internals', () => { const payload = toPublicCardResponse({ card: fullCard, branding: null, rule: null, reward: null, controllerName: null, privacyContact: null }, 'tenant-1'); expect(payload.branding).toBeNull(); expect(payload.rule).toBeNull(); expect(payload.reward).toBeNull(); expect(payload.controllerName).toBeNull(); expect(payload.privacyContact).toBeNull(); expect(JSON.stringify(payload)).not.toContain('publicTokenHash'); expect(JSON.stringify(payload)).not.toContain('customer-1'); });
test('wallet card view carries exactly id and stampCount, never customer data', () => { const view = toWalletCardView(fullCard); expect(Object.keys(view).sort()).toEqual(['id', 'stampCount']); expect(view.id).toBe('card-1'); expect(view.stampCount).toBe(3); const serialized = JSON.stringify(view); expect(serialized).not.toContain('customerId'); expect(serialized).not.toContain('publicTokenHash'); });

// ---------------------------------------------------------------------------
// joinPageHtml (GET /join/:publicKey, owner fix 2026-09-13): branded customer
// landing page with the stamp rule, the register instruction and the identical
// DSGVO Art. 13 footer as the webcard — never raw JSON.
// ---------------------------------------------------------------------------
function joinData(overrides: Partial<JoinPageData> = {}): JoinPageData {
  return {
    tenantId: 'tenant-1',
    joinPath: '/join/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    branding,
    rule,
    controllerName: 'Beispiel GmbH',
    privacyContact: 'datenschutz@beispiel.de',
    ...overrides,
  };
}

test('joinPageHtml renders branding, rule and the register instruction with the DSGVO footer', () => {
  const html = joinPageHtml(joinData());
  expect(html).toContain('<!doctype html');
  expect(html).toContain('<meta name="viewport"');
  expect(html).toContain('<h1>Café</h1>');
  expect(html).toContain('Treuekarte');
  expect(html).toContain('Beispiel GmbH');
  expect(html).toContain('<strong>10 Stempel</strong> &rarr; Prämie');
  expect(html).toContain('Diese Karte wird an der Kasse erstellt. Zeigen Sie diesen QR an der Kasse vor.');
  expect(html).toContain('<section class="privacy">');
  expect(html).toContain('Verantwortlich für die Verarbeitung: Beispiel GmbH');
  expect(html).toContain('Kontakt für Anfragen: datenschutz@beispiel.de');
  // No card token exists on the join page -> no save-to-wallet button.
  expect(html).not.toContain('Zu Google Wallet hinzufügen');
});

test('joinPageHtml escapes every dynamic value and sanitizes colors', () => {
  const html = joinPageHtml(joinData({
    branding: { cardTitle: '<script>alert(1)</script>', cardText: 'a"b\'c&d', primaryColor: 'red', secondaryColor: 'url(x)', version: 1 },
    rule: { ...rule, rewardTitle: '<b>Prämie</b>', rewardDescription: 'x"y' },
    controllerName: '</p><p>evil',
    privacyContact: 'x@y.z"',
  }));
  // Escaped: no raw injection marker survives; the escaped form is present.
  expect(html).not.toContain('<script>alert(1)</script>');
  expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
  expect(html).not.toContain('</p><p>evil');
  expect(html).toContain('&lt;/p&gt;&lt;p&gt;evil');
  // Invalid colors fall back to the stable defaults.
  expect(html).toContain(DEFAULT_PRIMARY_CARD_COLOR);
  expect(html).toContain(DEFAULT_SECONDARY_CARD_COLOR);
  expect(html).not.toContain('url(x)');
  expect(html).not.toContain('color:red');
});

test('joinPageHtml falls back to neutral defaults without branding/rule/controller', () => {
  const html = joinPageHtml(joinData({ branding: null, rule: null, controllerName: null, privacyContact: null }));
  expect(html).toContain('<h1>StempelPass</h1>');
  expect(html).not.toContain('Stempelregel');
  expect(html).not.toContain('<p class="tenant">');
  // Escaped controller fallback inside the privacy footer (same as the webcard).
  expect(html).toContain('&lt;Tenant&gt;');
  expect(html).toContain('Diese Karte wird an der Kasse erstellt.');
});

test('joinPageHtml never leaks card/customer/token internals', () => {
  const html = joinPageHtml(joinData());
  for (const marker of ['customerId', 'publicTokenHash', 'public_token_hash', 'customer_id', 'cardId', 'stampCount', 'request_id']) {
    expect(html).not.toContain(marker);
  }
  expect(html).not.toContain('tenant-1');
});
