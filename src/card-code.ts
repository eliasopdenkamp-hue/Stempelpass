import { randomBytes } from 'node:crypto';

/**
 * Visible card codes (owner wish, 2026-09-24).
 *
 * Every card gets a short, human-readable, tenant-unique code used purely as
 * an identification aid at the register (staff search + display on the webcard
 * and in the Google Wallet pass). It encodes NO data (no tenant, customer or
 * token material) and grants NO permission: stamping still requires an
 * authenticated staff session (the staff search runs inside the tenant RLS
 * transaction and returns only the code/id/balance/reward of a card that
 * belongs to the caller's tenant).
 *
 * Format: 6 characters from a confusion-safe alphabet (0/O/1/I are excluded),
 * displayed with the prefix K- (e.g. `K-7F3D2A`). The DATABASE stores only the
 * bare 6-character code (`7F3D2A`); the prefix is applied at display time.
 * 32^6 = 2^30 distinct codes per tenant; uniqueness is enforced per tenant by
 * the unique index cards_tenant_card_code_key (migration 021) and the
 * createCard path generates a fresh candidate on every insert — a collision is
 * a ~1e-9 event per insert and would surface as a retryable create error.
 */

/** Confusion-safe alphabet: no 0/O/1/I (verwechslungssicher). */
export const CARD_CODE_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
export const CARD_CODE_LENGTH = 6;
/** Display prefix — never stored, applied by formatCardCode(). */
export const CARD_CODE_PREFIX = 'K-';
/** Strict regex for a bare stored code (6 chars, confusion-safe alphabet). */
export const CARD_CODE_RE = /^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{6}$/;

/** Generate a random 6-char code. 256 % 32 === 0, so randomBytes(1) % 32 has
 *  zero modulo bias. */
export function generateCardCode(): string {
  let out = '';
  for (let i = 0; i < CARD_CODE_LENGTH; i++) {
    out += CARD_CODE_ALPHABET[randomBytes(1)[0]! % CARD_CODE_ALPHABET.length]!;
  }
  return out;
}

/** Display form: `7F3D2A` → `K-7F3D2A`. */
export function formatCardCode(code: string): string {
  return `${CARD_CODE_PREFIX}${code}`;
}

/**
 * Normalize staff/customer search input to the bare stored code, or null when
 * it is not a syntactically valid code. The optional `K-`/`k-` prefix is
 * stripped, surrounding whitespace trimmed and the remainder upper-cased —
 * `K-7f3d2a`, `k-7F3D2A` and `7f3d2a` all normalize to `7F3D2A`. The regex is
 * the single gate: anything containing an ambiguous character (0/O/1/I) or a
 * wrong length is rejected (the caller answers "Karte nicht gefunden" — never
 * a format error that would leak the alphabet).
 */
export function normalizeCardCode(input: string): string | null {
  let v = String(input ?? '').trim().toUpperCase();
  if (v.startsWith(CARD_CODE_PREFIX)) v = v.slice(CARD_CODE_PREFIX.length);
  return CARD_CODE_RE.test(v) ? v : null;
}