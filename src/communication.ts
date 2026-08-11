import type { DbPool, TxClient } from './db.js';
import { recipientHash, type SmtpEmailAdapter } from './email.js';

export const CONSENT_SOURCES = ['web_form', 'unsubscribe_link', 'admin_action', 'system'] as const;
export type ConsentSource = typeof CONSENT_SOURCES[number];
const SOURCE_PATTERN = /^[a-z][a-z0-9_]{0,31}$/;

/** Validate before opening a transaction: consent provenance is a controlled enum, never user text. */
export function validateConsentSource(source: unknown): ConsentSource {
  if (typeof source !== 'string' || !SOURCE_PATTERN.test(source) || !(CONSENT_SOURCES as readonly string[]).includes(source)) {
    throw new Error('INVALID_CONSENT_SOURCE');
  }
  return source as ConsentSource;
}

export type CommunicationPurpose = 'service' | 'marketing';
export type CommunicationChannel = 'email';
export type ConsentAction = 'opt_in' | 'withdraw' | 'unsubscribe';
export type MessageStatus = 'not_configured' | 'queued' | 'sent' | 'failed' | 'blocked';

export interface CommunicationPreference {
  tenantId: string; customerId: string; purpose: CommunicationPurpose; channel: CommunicationChannel;
  optedIn: boolean; optedInAt: string | null; withdrawnAt: string | null;
}
export interface MessageCheck { allowed: boolean; reason: 'service_allowed' | 'marketing_opt_in_required' | 'marketing_withdrawn' | 'provider_not_configured'; }
export interface MessageLog { id: string; status: MessageStatus; }
export interface SendEmailInput { tenantId: string; customerId: string; purpose: CommunicationPurpose; messageType: string; to: string; subject: string; text?: string; html?: string; }
export interface SendEmailResult extends MessageLog { reason?: string; }

/** Provider-neutral communication persistence. It never sends messages itself. */
export class CommunicationRepository {
  constructor(private readonly pool: DbPool) {}
  private async tx<T>(tenantId: string, work: (db: TxClient) => Promise<T>): Promise<T> {
    if (!tenantId) throw new Error('TENANT_CONTEXT_REQUIRED');
    const db = await this.pool.connect();
    try { await db.query('begin'); await db.query("select set_config('app.tenant_id', $1, true)",[tenantId]); const value = await work(db); await db.query('commit'); return value; }
    catch (e) { try { await db.query('rollback'); } catch {} throw e; } finally { db.release(); }
  }
  async preference(tenantId: string, customerId: string, purpose: CommunicationPurpose, channel: CommunicationChannel = 'email'): Promise<CommunicationPreference | null> {
    return this.tx(tenantId, async db => (await db.query<CommunicationPreference>(`select tenant_id as "tenantId", customer_id as "customerId", purpose, channel, opted_in as "optedIn", opted_in_at as "optedInAt", withdrawn_at as "withdrawnAt" from communication_preferences where tenant_id=$1 and customer_id=$2 and purpose=$3 and channel=$4`, [tenantId, customerId, purpose, channel])).rows[0] ?? null);
  }
  async setMarketingOptIn(tenantId: string, customerId: string, source: ConsentSource): Promise<void> {
    const safeSource = validateConsentSource(source);
    await this.tx(tenantId, async db => { await db.query(`insert into communication_preferences(tenant_id,customer_id,purpose,channel,opted_in,opted_in_at,withdrawn_at) values($1,$2,'marketing','email',true,now(),null) on conflict (tenant_id,customer_id,purpose,channel) do update set opted_in=true,opted_in_at=now(),withdrawn_at=null,updated_at=now()`, [tenantId, customerId]); await db.query(`insert into communication_consent_events(tenant_id,customer_id,purpose,channel,action,source) values($1,$2,'marketing','email','opt_in',$3)`, [tenantId, customerId, safeSource]); });
  }
  async withdrawMarketing(tenantId: string, customerId: string, source: ConsentSource, action: 'withdraw' | 'unsubscribe' = 'unsubscribe'): Promise<void> {
    const safeSource = validateConsentSource(source);
    await this.tx(tenantId, async db => { await db.query(`insert into communication_preferences(tenant_id,customer_id,purpose,channel,opted_in,withdrawn_at) values($1,$2,'marketing','email',false,now()) on conflict (tenant_id,customer_id,purpose,channel) do update set opted_in=false,withdrawn_at=now(),updated_at=now()`, [tenantId, customerId]); await db.query(`insert into communication_consent_events(tenant_id,customer_id,purpose,channel,action,source) values($1,$2,'marketing','email',$3,$4)`, [tenantId, customerId, action, safeSource]); });
  }
  async log(tenantId: string, customerId: string | null, purpose: CommunicationPurpose, messageType: string, recipientHash: string, status: MessageStatus, failureCode?: string): Promise<MessageLog> {
    return this.tx(tenantId, async db => (await db.query<MessageLog>(`insert into communication_message_logs(tenant_id,customer_id,purpose,channel,message_type,recipient_hash,status,failure_code) values($1,$2,$3,'email',$4,$5,$6,$7) returning id,status`, [tenantId, customerId, purpose, messageType, recipientHash, status, failureCode ?? null])).rows[0]);
  }
}

export class CommunicationService {
  constructor(private readonly repository: CommunicationRepository, private readonly providerConfigured = false) {}
  async check(tenantId: string, customerId: string, purpose: CommunicationPurpose): Promise<MessageCheck> {
    if (purpose === 'service') return { allowed: true, reason: 'service_allowed' };
    const preference = await this.repository.preference(tenantId, customerId, 'marketing');
    if (!preference?.optedIn) return { allowed: false, reason: preference?.withdrawnAt ? 'marketing_withdrawn' : 'marketing_opt_in_required' };
    if (!this.providerConfigured) return { allowed: false, reason: 'provider_not_configured' };
    return { allowed: true, reason: 'service_allowed' };
  }
  /** Records a blocked/not_configured decision without sending anything. */
  async prepare(tenantId: string, customerId: string | null, purpose: CommunicationPurpose, messageType: string, recipientHashValue: string): Promise<MessageLog> {
    if (!tenantId || !purpose || !messageType || !recipientHashValue) throw new Error('COMMUNICATION_CONTEXT_REQUIRED');
    const check = customerId ? await this.check(tenantId, customerId, purpose) : (purpose === 'service' ? { allowed: true, reason: 'service_allowed' as const } : { allowed: false, reason: 'marketing_opt_in_required' as const });
    const status: MessageStatus = check.reason === 'provider_not_configured' ? 'not_configured' : (check.allowed ? 'queued' : 'blocked');
    return this.repository.log(tenantId, customerId, purpose, messageType, recipientHashValue, status, status === 'not_configured' ? 'PROVIDER_NOT_CONFIGURED' : (check.allowed ? undefined : check.reason));
  }

  /** Policy-gated send. No bulk behavior: one explicit recipient per call. */
  async sendEmail(input: SendEmailInput, adapter: SmtpEmailAdapter): Promise<SendEmailResult> {
    if (!input.tenantId || !input.customerId || !input.purpose || !input.messageType || !input.to) throw new Error('COMMUNICATION_CONTEXT_REQUIRED');
    // Never persist an address-derived value when the keyed pseudonymisation secret is absent.
    const hash = adapter.recipientHash(input.to);
    const check = await this.check(input.tenantId, input.customerId, input.purpose);
    if (!hash) {
      const log = await this.repository.log(input.tenantId, input.customerId, input.purpose, input.messageType, 'UNAVAILABLE', 'not_configured', 'COMMUNICATION_HASH_SECRET_REQUIRED');
      return { ...log, reason: 'communication_hash_secret_required' };
    }
    if (!check.allowed) {
      const log = await this.repository.log(input.tenantId, input.customerId, input.purpose, input.messageType, hash, 'blocked', check.reason);
      return { ...log, reason: check.reason };
    }
    if (!adapter.configured) {
      const log = await this.repository.log(input.tenantId, input.customerId, input.purpose, input.messageType, hash, 'not_configured', 'PROVIDER_NOT_CONFIGURED');
      return { ...log, reason: 'provider_not_configured' };
    }
    const delivery = await adapter.send({ to: input.to, subject: input.subject, text: input.text, html: input.html });
    const log = await this.repository.log(input.tenantId, input.customerId, input.purpose, input.messageType, hash, delivery.status, delivery.failureCode);
    return log;
  }
}
