import type { Branding, Card, StampRule, WalletCardView } from './domain.js';
import type { PublicReward } from './repository.js';

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
}
export interface PublicCardSource { card: Pick<Card, 'id' | 'stampCount' | 'revision'>; branding: Branding | null; rule: StampRule | null; reward: PublicReward | null; }
export function toPublicCardResponse(result: PublicCardSource, tenantId: string): PublicCardResponse {
  return { cardId: result.card.id, tenantId, stampCount: result.card.stampCount, revision: result.card.revision, branding: safeBranding(result.branding), rule: result.rule, reward: result.reward };
}
export function toWalletCardView(card: Pick<Card, 'id' | 'stampCount'>): WalletCardView { return { id: card.id, stampCount: card.stampCount }; }
