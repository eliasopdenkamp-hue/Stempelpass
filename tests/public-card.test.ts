import { test, expect } from 'bun:test';
import { safeCardColor, safeBranding, toPublicCardResponse, toWalletCardView, DEFAULT_PRIMARY_CARD_COLOR, DEFAULT_SECONDARY_CARD_COLOR } from '../src/public-card';
import type { Card } from '../src/domain';

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
