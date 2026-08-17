import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import type { Branding, Card, StampRule } from './domain.js';

export interface PublicReward { id: string; status: 'issued' | 'redeemed'; issuedAt: string | null; redeemedAt: string | null; }

/** Minimal card view for authenticated responses: never carries tenant/customer/token data. */
export interface CardView { id: string; stampCount: number; revision: number; }
/** Minimal reward view for authenticated responses: never carries tenant/card/rule internals. */
export interface RewardView { id: string; status: 'issued' | 'redeemed'; }
/** Strictly minimized card-creation result (client-facing projection). */
export type CreatedCard = Pick<Card, 'id' | 'ruleId' | 'stampCount' | 'revision'>;
/** Strictly minimized redeem result; never a full rewards row. */
export interface RedeemResult { rewardId: string; status: 'issued' | 'redeemed'; }
/** Minimal soft-delete acknowledgement: only the deleted entity id, never a full row. */
export interface DeleteResult { id: string; }
/**
 * Strictly minimized stamp result. The normal and the idempotency-replay path
 * share this exact shape: {card:{id,stampCount,revision}}, an optional
 * {reward:{id,status}} and — only when the client sent one — the
 * idempotencyKey. No tenantId, customerId, publicTokenHash,
 * employeeMembershipId, quantity, reason or createdAt ever appear.
 */
export interface StampResult {
  card: CardView;
  reward?: RewardView;
  idempotencyKey?: string;
}

/** Deliberately minimal card shape safe for public rendering/wallet issuance. */
export interface PublicCard { id: string; stampCount: number; revision: number; ruleId: string; }

export interface DbClient { query<T = unknown>(sql: string, params?: unknown[]): Promise<{ rows: T[] }> }
export interface TxClient extends DbClient { release(): void }
export interface DbPool { connect(): Promise<TxClient> }

/** All tenant data access is scoped in a transaction; never call these with an untrusted tenant id. */
function idempotencySecret(): Buffer { const value=process.env.SESSION_SECRET; if(!value || value.length < 32) throw new Error('CONFIGURATION_REQUIRED'); return createHash('sha256').update(value).digest(); }
function encryptToken(token:string): string { const iv=randomBytes(12); const cipher=createCipheriv('aes-256-gcm',idempotencySecret(),iv); const body=Buffer.concat([cipher.update(token,'utf8'),cipher.final()]); return [iv,cipher.getAuthTag(),body].map(x=>x.toString('base64url')).join('.'); }
function decryptToken(value:string): string { const [iv,tag,body]=value.split('.').map(x=>Buffer.from(x,'base64url')); const decipher=createDecipheriv('aes-256-gcm',idempotencySecret(),iv); decipher.setAuthTag(tag); return Buffer.concat([decipher.update(body),decipher.final()]).toString('utf8'); }
export class CardRepository {
  constructor(private readonly pool: DbPool) {}
  async transaction<T>(tenantId: string, work: (db: TxClient) => Promise<T>): Promise<T> {
    if (!tenantId) throw new Error('TENANT_CONTEXT_REQUIRED');
    const db = await this.pool.connect();
    try { await db.query('begin'); await db.query("select set_config('app.tenant_id', $1, true)",[tenantId]); const value=await work(db); await db.query('commit'); return value; }
    catch(e){ try { await db.query('rollback'); } catch {} throw e; } finally { db.release(); }
  }
  /**
   * User-scoped transaction for `sessions` access (migration 009): sets
   * `app.user_id` transaction-locally so the sessions RLS policy
   * (user_id = app.user_id) permits exactly the owning user's rows. The
   * caller must already hold the user id (login, rotate, logout, revoke);
   * this helper never bypasses user/session RLS.
   */
  async userTransaction<T>(userId: string, work: (db: TxClient) => Promise<T>): Promise<T> {
    if (!userId) throw new Error('USER_CONTEXT_REQUIRED');
    const db = await this.pool.connect();
    try { await db.query('begin'); await db.query("select set_config('app.user_id', $1, true)",[userId]); const value=await work(db); await db.query('commit'); return value; }
    catch(e){ try { await db.query('rollback'); } catch {} throw e; } finally { db.release(); }
  }
  async findByPublicTokenHash(tenantId:string, hash:string):Promise<Card|null> { return this.transaction(tenantId,async db=>(await db.query<Card>('select id, tenant_id as "tenantId", customer_id as "customerId", public_token_hash as "publicTokenHash", status, stamp_count as "stampCount", revision, rule_id as "ruleId", created_at as "createdAt", updated_at as "updatedAt" from cards where tenant_id=$1 and public_token_hash=$2 and status=$3 and deleted_at is null',[tenantId,hash,'active'])).rows[0]??null); }
  async publicCard(tenantId:string, hash:string):Promise<{card:Card;branding:Branding|null;rule:StampRule|null;reward:PublicReward|null;controllerName:string|null;privacyContact:string|null}|null> { return this.transaction(tenantId,async db=>{ const c=(await db.query<Card>('select id, tenant_id as "tenantId", customer_id as "customerId", public_token_hash as "publicTokenHash", status, stamp_count as "stampCount", revision, rule_id as "ruleId", created_at as "createdAt", updated_at as "updatedAt" from cards where tenant_id=$1 and public_token_hash=$2 and status=$3 and deleted_at is null',[tenantId,hash,'active'])).rows[0]; if(!c) return null; const brandingRow=(await db.query<Branding & {privacyEmail?:string|null}>('select card_title as "cardTitle",card_text as "cardText",primary_color as "primaryColor",secondary_color as "secondaryColor",privacy_email as "privacyEmail",version from tenant_branding where tenant_id=$1',[tenantId])).rows[0] ?? null; const branding:Branding|null=brandingRow?{cardTitle:brandingRow.cardTitle,cardText:brandingRow.cardText,primaryColor:brandingRow.primaryColor,secondaryColor:brandingRow.secondaryColor,version:brandingRow.version}:null; const tenant=(await db.query<{legal_name:string|null}>('select legal_name from tenants where id=$1',[tenantId])).rows[0] ?? null; const rule=(await db.query<StampRule>('select id,tenant_id as "tenantId",name,stamps_required as "stampsRequired",reward_title as "rewardTitle",reward_description as "rewardDescription",active,version from stamp_rules where id=$1 and tenant_id=$2',[c.ruleId,tenantId])).rows[0] ?? null; const reward=(await db.query<PublicReward>('select id, status, issued_at as "issuedAt", redeemed_at as "redeemedAt" from rewards where tenant_id=$1 and card_id=$2 and status=$3',[tenantId,c.id,'issued'])).rows[0] ?? null; return {card:c,branding,rule,reward,controllerName:tenant?.legal_name||null,privacyContact:brandingRow?.privacyEmail||null}; }); }
  async createCard(tenantId:string, customerId:string, ruleId:string, tokenHash:string, idempotencyKey?:string, rawToken?:string):Promise<CreatedCard & {token?:string}>{ if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(customerId)) throw new Error('CUSTOMER_NOT_FOUND'); if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(ruleId)) throw new Error('RULE_NOT_FOUND'); const fingerprint=createHash('sha256').update(`${customerId}:${ruleId}`).digest('hex'); return this.transaction(tenantId,async db=>{ if(idempotencyKey){ const prior=await db.query<{request_fingerprint:string;card_id:string;token_ciphertext:string}>('select request_fingerprint,card_id,token_ciphertext from card_creation_idempotency where tenant_id=$1 and idempotency_key=$2 for update',[tenantId,idempotencyKey]); if(prior.rows[0]) { if(prior.rows[0].request_fingerprint!==fingerprint) throw new Error('IDEMPOTENCY_KEY_REUSED'); const card=(await db.query<CreatedCard>('select id,rule_id as "ruleId",stamp_count as "stampCount",revision from cards where tenant_id=$1 and id=$2',[tenantId,prior.rows[0].card_id])).rows[0]; if(!card) throw new Error('CARD_NOT_FOUND'); return {...card,token:decryptToken(prior.rows[0].token_ciphertext)}; } } const t=await db.query<{customer_limit:number}>('select customer_limit from tenants where id=$1 and status=$2 for update',[tenantId,'active']); if(!t.rows[0]) throw new Error('TENANT_NOT_FOUND'); const customer=await db.query('select id from customers where id=$1 and tenant_id=$2 and status=$3 and deleted_at is null',[customerId,tenantId,'active']); if(!customer.rows[0]) throw new Error('CUSTOMER_NOT_FOUND'); const used=await db.query<{count:string}>('select count(distinct customer_id) from cards where tenant_id=$1 and status=$2',[tenantId,'active']); if(Number(used.rows[0]?.count??0)>=t.rows[0].customer_limit) throw new Error('CUSTOMER_LIMIT_REACHED'); const rule=await db.query('select id from stamp_rules where id=$1 and tenant_id=$2 and active=true',[ruleId,tenantId]); if(!rule.rows[0]) throw new Error('RULE_NOT_FOUND'); const card=await db.query<CreatedCard>('insert into cards(tenant_id,customer_id,rule_id,public_token_hash) values($1,$2,$3,$4) returning id, rule_id as "ruleId", stamp_count as "stampCount", revision',[tenantId,customerId,ruleId,tokenHash]); const inserted=card.rows[0]; if(!inserted) throw new Error('CARD_CREATE_FAILED'); const token=rawToken ?? ''; if(idempotencyKey) await db.query('insert into card_creation_idempotency(tenant_id,idempotency_key,request_fingerprint,card_id,token_ciphertext) values($1,$2,$3,$4,$5)',[tenantId,idempotencyKey,fingerprint,inserted.id,encryptToken(token)]); return {...inserted,...(rawToken !== undefined ? {token} : {})}; }); }
  async capacity(tenantId:string){return this.transaction(tenantId,async db=>{const t=await db.query<{plan_code:string,customer_limit:number}>('select plan_code,customer_limit from tenants where id=$1',[tenantId]);if(!t.rows[0])throw new Error('TENANT_NOT_FOUND');const used=await db.query<{count:string}>('select count(distinct customer_id) from cards where tenant_id=$1 and status=$2',[tenantId,'active']);const n=Number(used.rows[0]?.count??0);return {plan:t.rows[0].plan_code,limit:t.rows[0].customer_limit,used:n,remaining:Math.max(0,t.rows[0].customer_limit-n)};});}
  async configurePilot(tenantId:string, actorUserId:string, input:{planCode:'up_to_500'|'up_to_1000';cardTitle:string;cardText:string;primaryColor:string;secondaryColor:string;iconAssetId?:string;logoAssetId?:string;stampsRequired:number;rewardTitle:string;rewardDescription:string}) {
    const limit = input.planCode === 'up_to_500' ? 500 : input.planCode === 'up_to_1000' ? 1000 : 0;
    if (!limit || !/^#[0-9a-f]{6}$/i.test(input.primaryColor) || !/^#[0-9a-f]{6}$/i.test(input.secondaryColor) || !Number.isInteger(input.stampsRequired) || input.stampsRequired < 1 || input.stampsRequired > 100 || !input.cardTitle.trim() || !input.rewardTitle.trim()) throw new Error('INVALID_PILOT_CONFIGURATION');
    return this.transaction(tenantId, async db => {
      const current=await db.query<{customer_limit:number}>('select customer_limit from tenants where id=$1 and status=$2 for update',[tenantId,'active']); if(!current.rows[0]) throw new Error('TENANT_NOT_FOUND');
      const used=await db.query<{count:string}>('select count(distinct customer_id) from cards where tenant_id=$1 and status=$2',[tenantId,'active']); if(Number(used.rows[0]?.count||0)>limit) throw new Error('PLAN_LIMIT_BELOW_USAGE');
      await db.query('update tenants set plan_code=$1,customer_limit=$2,updated_at=now() where id=$3',[input.planCode,limit,tenantId]);
      await db.query(`insert into tenant_branding(tenant_id,card_title,card_text,primary_color,secondary_color,icon_asset_id,logo_asset_id,version) values($1,$2,$3,$4,$5,$6,$7,1) on conflict(tenant_id) do update set card_title=excluded.card_title,card_text=excluded.card_text,primary_color=excluded.primary_color,secondary_color=excluded.secondary_color,icon_asset_id=excluded.icon_asset_id,logo_asset_id=excluded.logo_asset_id,version=tenant_branding.version+1,updated_at=now()`,[tenantId,input.cardTitle.trim(),input.cardText.trim(),input.primaryColor,input.secondaryColor,input.iconAssetId||null,input.logoAssetId||null]);
      const rule=(await db.query<{id:string}>('insert into stamp_rules(tenant_id,name,stamps_required,reward_title,reward_description) values($1,$2,$3,$4,$5) returning id',[tenantId,'Pilot-Regel',input.stampsRequired,input.rewardTitle.trim(),input.rewardDescription.trim()])).rows[0];
      // Idempotent entry-point upsert: on conflict the EXISTING public_key/join_path
      // is kept (old join links stay valid) and RETURNING yields the row that was
      // actually persisted — the response can never advertise an un-persisted key.
      const key=crypto.randomUUID().replaceAll('-',''); const entry=(await db.query<{public_key:string;join_path:string}>('insert into tenant_entry_points(tenant_id,public_key,join_path) values($1,$2,$3) on conflict(tenant_id) do update set updated_at=now() returning public_key,join_path',[tenantId,key,`/join/${key}`])).rows[0];
      await appendAudit(db,{tenantId,actorUserId,action:'pilot.configured',entityType:'tenant',entityId:tenantId,metadata:{planCode:input.planCode,customerLimit:limit,ruleId:rule.id}});
      return {tenantId,planCode:input.planCode,customerLimit:limit,ruleId:rule.id,joinPath:entry.join_path};
    });
  }
  async setStaff(tenantId:string, actorUserId:string, userId:string, role:'admin'|'staff'|'viewer', active:boolean):Promise<{membershipId:string;status:'active'|'inactive';role:'admin'|'staff'|'viewer'}> { if(!userId || !['admin','staff','viewer'].includes(role)) throw new Error('INVALID_STAFF'); return this.transaction(tenantId,async db=>{const m=await db.query<{id:string}>('update tenant_memberships set role=$1,status=$2 where tenant_id=$3 and user_id=$4 returning id',[role,active?'active':'inactive',tenantId,userId]); if(!m.rows[0]) { if(!active) throw new Error('MEMBERSHIP_NOT_FOUND'); const created=await db.query<{id:string}>('insert into tenant_memberships(tenant_id,user_id,role,status) values($1,$2,$3,$4) returning id',[tenantId,userId,role,'active']); m.rows.push(created.rows[0]); } await appendAudit(db,{tenantId,actorUserId,action:active?'staff.activated':'staff.deactivated',entityType:'membership',entityId:m.rows[0].id,metadata:{userId,role}}); return {membershipId:m.rows[0].id,status:active?'active':'inactive',role}; }); }
  async entryPoint(tenantId:string){return this.transaction(tenantId,async db=>{const r=await db.query<{public_key:string,join_path:string}>('select public_key,join_path from tenant_entry_points where tenant_id=$1',[tenantId]);if(!r.rows[0])throw new Error('ENTRY_POINT_NOT_CONFIGURED');return {joinPath:r.rows[0].join_path,publicKey:r.rows[0].public_key};});}
  /**
   * Public /join/:publicKey resolution — RLS-safe by construction.
   *
   * tenant_entry_points is tenant-isolation RLS protected (migration 006) and
   * this route has no tenant context, so a direct table read would return
   * nothing. Resolution goes through the SECURITY DEFINER function
   * public.resolve_entry_point (migration 008) instead: the app role holds no
   * table-level SELECT on tenant_entry_points, only EXECUTE on that function,
   * which returns exactly (tenant_id, join_path) for the exact public key.
   */
  async resolveEntryPoint(publicKey:string){if(!/^[a-f0-9]{32}$/i.test(publicKey)) return null; const db=await this.pool.connect(); try { const r=await db.query<{tenant_id:string;join_path:string}>('select tenant_id,join_path from public.resolve_entry_point($1)',[publicKey]); return r.rows[0]??null; } finally { db.release(); }}
  async stamp(tenantId:string,cardId:string,quantity:number,employeeMembershipId:string,idempotencyKey:string|null):Promise<StampResult>{if(!Number.isInteger(quantity)||quantity<1||quantity>10)throw new Error('INVALID_STAMP_QUANTITY');return this.transaction(tenantId,async db=>{
    // Idempotency replay runs only when the client supplied a key. The replay
    // returns the same minimized shape as a normal stamp — never the raw
    // stamp_event row.
    if(idempotencyKey){const old=await db.query<{card_id:string}>('select card_id from stamp_events where tenant_id=$1 and idempotency_key=$2',[tenantId,idempotencyKey]);if(old.rows[0])return this.replayStampResult(db,tenantId,old.rows[0].card_id,idempotencyKey);}
    const c=(await db.query<{id:string;stampCount:number;revision:number;ruleId:string}>('select id,stamp_count as "stampCount",revision,rule_id as "ruleId" from cards where tenant_id=$1 and id=$2 and status=$3 for update',[tenantId,cardId,'active'])).rows[0];if(!c)throw new Error('CARD_NOT_FOUND');
    // Without a client key there is no idempotency promise: a fresh unique key
    // satisfies the unique(tenant_id,idempotency_key) constraint without ever
    // replaying a different request.
    await db.query('insert into stamp_events(tenant_id,card_id,employee_membership_id,quantity,idempotency_key) values($1,$2,$3,$4,$5)',[tenantId,cardId,employeeMembershipId,quantity,idempotencyKey??crypto.randomUUID()]);
    const updated=(await db.query<{id:string;stampCount:number;revision:number}>('update cards set stamp_count=stamp_count+$1,revision=revision+1,updated_at=now() where tenant_id=$2 and id=$3 returning id,stamp_count as "stampCount",revision',[quantity,tenantId,cardId])).rows[0];
    const rule=(await db.query<{id:string;stamps_required:number}>('select id,stamps_required from stamp_rules where id=$1 and tenant_id=$2 and active=true',[c.ruleId,tenantId])).rows[0];let reward:RewardView|undefined;if(rule&&updated.stampCount>=rule.stamps_required){const r=await db.query<RewardView>(`insert into rewards(tenant_id,card_id,rule_id) select $1,$2,$3 where not exists (select 1 from rewards where tenant_id=$1 and card_id=$2 and status='issued') returning id,status`,[tenantId,cardId,rule.id]);if(r.rows[0])reward={id:r.rows[0].id,status:r.rows[0].status};}
    return {card:{id:updated.id,stampCount:updated.stampCount,revision:updated.revision},...(reward?{reward}:{}),...(idempotencyKey?{idempotencyKey}:{})};});}
  /** Replay of an already-applied stamp: minimized current state, never the raw event row. */
  private async replayStampResult(db:TxClient,tenantId:string,cardId:string,idempotencyKey:string):Promise<StampResult>{const card=(await db.query<CardView>('select id,stamp_count as "stampCount",revision from cards where tenant_id=$1 and id=$2',[tenantId,cardId])).rows[0];if(!card)throw new Error('CARD_NOT_FOUND');const reward=(await db.query<RewardView>("select id,status from rewards where tenant_id=$1 and card_id=$2 and status='issued'",[tenantId,cardId])).rows[0];return {card,...(reward?{reward}:{}),idempotencyKey};}
  async redeem(tenantId:string,rewardId:string):Promise<RedeemResult>{return this.transaction(tenantId,async db=>{const r=(await db.query<{id:string;status:'issued'|'redeemed'}>("update rewards set status='redeemed',redeemed_at=now() where tenant_id=$1 and id=$2 and status='issued' returning id,status",[tenantId,rewardId])).rows[0];if(!r){const exists=await db.query<{id:string;status:string}>('select id,status from rewards where tenant_id=$1 and id=$2',[tenantId,rewardId]);if(exists.rows[0]?.status==='redeemed')throw new Error('REWARD_ALREADY_REDEEMED');throw new Error('REWARD_NOT_FOUND');}return {rewardId:r.id,status:r.status};});}
  /** Revoke all of a user's sessions (login bootstrap). Runs under app.user_id RLS context. */
  async revokeSessions(userId:string,exceptHash?:string){return this.userTransaction(userId,async db=>{await db.query('update sessions set revoked_at=now() where user_id=$1 and revoked_at is null and ($2 is null or token_hash<>$2)',[userId,exceptHash??null]);})}
  /** Revoke one session by token hash (logout/rotation). Runs under app.user_id RLS context. */
  async revokeSession(userId:string,tokenHash:string){return this.userTransaction(userId,async db=>{await db.query('update sessions set revoked_at=now() where token_hash=$1',[tokenHash]);})}
  /**
   * Soft-delete a card (DSGVO Art. 17, BACKUP_RUNBOOK.md §3.2): the card is
   * hidden everywhere (status='inactive' + deleted_at) but NEVER hard-deleted —
   * stamp_events/rewards stay as append-only history. The public lookups
   * (publicCard / findByPublicTokenHash) filter `deleted_at is null`, so a
   * deleted card's public URL and wallet JSON resolve to 404. Already-deleted
   * or foreign cards yield CARD_NOT_FOUND (single UPDATE guarded by
   * `deleted_at is null`), never a destructive delete.
   */
  async deleteCard(tenantId:string, cardId:string):Promise<DeleteResult>{return this.transaction(tenantId,async db=>{const r=await db.query<{id:string}>("update cards set status='inactive',deleted_at=now(),updated_at=now() where tenant_id=$1 and id=$2 and deleted_at is null returning id",[tenantId,cardId]);if(!r.rows[0])throw new Error('CARD_NOT_FOUND');return {id:r.rows[0].id};});}
  /**
   * Soft-delete a customer and all of its active cards (DSGVO Art. 17,
   * BACKUP_RUNBOOK.md §3.3). FK-Reihenfolge: zuerst die Karten des Kunden
   * (Kinder), dann die Kundenzeile (Eltern) — alles in einer Tenant-
   * Transaktion. Keine hard deletes.
   *
   * Entscheidung aus dem Runbook (§3.3, offener Punkt §5 Nr. 10), hier als
   * Kommentar festgehalten: unique(tenant_id, external_ref) bleibt bestehen —
   * eine soft-gelöschte Zeile behält ihr external_ref und wird NICHT
   * wiederverwendet (kein Leeren des Felds, kein partieller Unique-Index).
   */
  async deleteCustomer(tenantId:string, customerId:string):Promise<DeleteResult>{return this.transaction(tenantId,async db=>{await db.query("update cards set status='inactive',deleted_at=now(),updated_at=now() where tenant_id=$1 and customer_id=$2 and deleted_at is null",[tenantId,customerId]);const r=await db.query<{id:string}>("update customers set status='inactive',deleted_at=now(),updated_at=now() where tenant_id=$1 and id=$2 and deleted_at is null returning id",[tenantId,customerId]);if(!r.rows[0])throw new Error('CUSTOMER_NOT_FOUND');return {id:r.rows[0].id};});}
  /**
   * Deactivate a tenant (Vertragsende, BACKUP_RUNBOOK.md §3.4): FK-Reihenfolge
   * Karten → Kunden soft-deleten, dann tenants.status='inactive'. Keine hard
   * deletes: stamp_events/rewards bleiben als Belege, audit_log ist append-only
   * und wird nie gelöscht, users sind global (tenant-übergreifend) und werden
   * nie mitgelöscht. Die App-Route erlaubt nur owner.
   */
  async deleteTenant(tenantId:string):Promise<DeleteResult>{return this.transaction(tenantId,async db=>{await db.query("update cards set status='inactive',deleted_at=now(),updated_at=now() where tenant_id=$1 and deleted_at is null",[tenantId]);await db.query("update customers set status='inactive',deleted_at=now(),updated_at=now() where tenant_id=$1 and deleted_at is null",[tenantId]);const r=await db.query<{id:string}>("update tenants set status='inactive',updated_at=now() where id=$1 and status='active' returning id",[tenantId]);if(!r.rows[0])throw new Error('TENANT_NOT_FOUND');return {id:r.rows[0].id};});}
  /**
   * Delete expired sessions (`revoked_at is null and expires_at <= now()`),
   * returning how many were deleted. Operator-only by design: the sessions RLS
   * (migration 009) is user-scoped, so a tenant context never sees rows of
   * other users — the normal caller is the cleanup CLI (src/cleanup.ts)
   * running as the table-owning operator role, which bypasses RLS. When
   * tenantId is provided the delete is additionally restricted to that
   * tenant's sessions (sessions.tenant_id is nullable and the login/rotate
   * paths currently leave it unset, so the global run is the usual operator
   * sweep); null = all tenants.
   */
  async cleanupExpiredSessions(tenantId:string|null):Promise<number>{const db=await this.pool.connect();try{await db.query('begin');if(tenantId)await db.query("select set_config('app.tenant_id', $1, true)",[tenantId]);const r=tenantId?await db.query<{id:string}>('delete from sessions where tenant_id=$1 and revoked_at is null and expires_at<=now() returning id',[tenantId]):await db.query<{id:string}>('delete from sessions where revoked_at is null and expires_at<=now() returning id');await db.query('commit');return r.rows.length;}catch(e){try{await db.query('rollback');}catch{}throw e;}finally{db.release();}}
}
export interface AuditEvent { tenantId?:string;actorUserId?:string;action:string;entityType:string;entityId?:string;metadata?:Record<string,unknown> }
export async function appendAudit(db:DbClient,event:AuditEvent){await db.query('insert into audit_log(tenant_id,actor_user_id,action,entity_type,entity_id,metadata) values($1,$2,$3,$4,$5,$6)',[event.tenantId??null,event.actorUserId??null,event.action,event.entityType,event.entityId??null,JSON.stringify(event.metadata??{})]);}
