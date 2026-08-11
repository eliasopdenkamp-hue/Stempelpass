import { createHash } from 'node:crypto';

export type Role = 'owner' | 'admin' | 'staff' | 'viewer';
export type PlanCode = 'up_to_500' | 'up_to_1000';
export type Provider = 'apple' | 'google';

export const PLAN_LIMITS: Record<PlanCode, number> = { up_to_500: 500, up_to_1000: 1000 };
export interface Tenant { id: string; slug: string; planCode: PlanCode; customerLimit: number; }
export interface Branding { cardTitle: string; cardText: string; primaryColor: string; secondaryColor: string; iconAssetId?: string; logoAssetId?: string; version: number; }
export interface StampRule { id: string; tenantId: string; name: string; stampsRequired: number; rewardTitle: string; rewardDescription: string; active: boolean; version: number; }
export interface Card { id: string; tenantId: string; customerId: string; publicTokenHash: string; status: 'active'|'archived'; stampCount: number; revision: number; ruleId: string; }
/** Minimal card view for public/wallet output: never carries customerId or publicTokenHash. */
export type WalletCardView = Pick<Card, 'id' | 'stampCount'>;
export interface Reward { id: string; tenantId: string; cardId: string; ruleId: string; status: 'issued'|'redeemed'; }
export interface WalletArtifact { provider: Provider; status: 'not_configured'|'issued'; message: string; artifact?: string; }

export function assertTenant(requestTenantId: string, membershipTenantId: string): void {
  if (!requestTenantId || requestTenantId !== membershipTenantId) throw new Error('TENANT_CONTEXT_REQUIRED');
}
export function capacity(tenant: Tenant, activeCustomers: number) {
  const used = Math.max(0, activeCustomers); return { plan: tenant.planCode, limit: tenant.customerLimit, used, remaining: Math.max(0, tenant.customerLimit - used) };
}
export function canStamp(role: Role) { return role === 'owner' || role === 'admin' || role === 'staff'; }
export function hashToken(token: string): string { return createHash('sha256').update(token, 'utf8').digest('hex'); }
