import type { CreatedCard, RedeemResult, StampResult } from './repository.js';

/**
 * Central response contracts for authenticated endpoints.
 *
 * server.ts never shapes these responses inline; it calls exactly these
 * builders. That keeps every client-facing payload allowlisted in one place and
 * makes a future contract change a single-file change that typecheck verifies
 * end to end. Nothing here copies tenant, customer, token, membership, audit or
 * timestamp fields into client payloads.
 */

/** POST .../cards/:cardId/stamps — normal and idempotency-replay share this shape. */
export interface StampResponse {
  card: { id: string; stampCount: number; revision: number };
  reward?: { id: string; status: 'issued' | 'redeemed' };
  /** Echoed only when the client sent an idempotency key. */
  idempotencyKey?: string;
}
export function toStampResponse(result: StampResult): StampResponse { return result; }

/**
 * POST .../cards — minimal projection of the created card plus the fresh raw
 * public token. The token is delivered exactly once, only in this 201 response
 * of the authenticated creation request: it is never logged, never persisted
 * (only its SHA-256 hash is stored as public_token_hash) and never present in
 * any public GET response. Clients build the public card URL as
 * /card/:tenantId/:cardToken (or the JSON equivalent
 * /api/public/tenants/:tenantId/cards/:cardToken).
 */
export interface CreateCardResponse {
  card: CreatedCard;
  /** Raw public card token — one-time, authenticated-response-only value. */
  cardToken: string;
}
export function toCreateCardResponse(card: CreatedCard, cardToken: string): CreateCardResponse { return { card, cardToken }; }

/** POST .../rewards/:rewardId/redeem — never a full rewards row. */
export interface RedeemResponse { rewardId: string; status: 'issued' | 'redeemed'; }
export function toRedeemResponse(result: RedeemResult): RedeemResponse { return result; }

/** POST /api/auth/login */
export interface LoginResponse { csrfToken: string; mfaRequired: boolean; }
export function toLoginResponse(csrfToken: string, mfaRequired: boolean): LoginResponse { return { csrfToken, mfaRequired }; }

/** PUT .../pilot — unchanged shape, centralized contract. */
export interface PilotResponse { tenantId: string; planCode: 'up_to_500' | 'up_to_1000'; customerLimit: number; ruleId: string; joinPath: string; }
export function toPilotResponse(value: PilotResponse): PilotResponse { return value; }

/** PUT .../staff — unchanged shape, centralized contract. */
export interface StaffResponse { membershipId: string; status: 'active' | 'inactive'; role: 'admin' | 'staff' | 'viewer'; }
export function toStaffResponse(value: StaffResponse): StaffResponse { return value; }

/** GET /join/:publicKey — unchanged shape, centralized contract. */
export interface JoinResponse { tenantId: string; joinPath: string; customerLoginRequired: boolean; customerAccountRequired: boolean; }
export function toJoinResponse(value: JoinResponse): JoinResponse { return value; }
