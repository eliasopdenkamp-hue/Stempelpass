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
/**
 * Join-page view model for GET /join/:publicKey (unauthenticated customer
 * landing page, Solution A — the card itself is created by staff at the
 * register). Strictly minimized: never a customers/cards/rewards row and
 * never an entry-point public_key beyond the join path itself.
 */
export interface JoinPageData {
  tenantId: string;
  joinPath: string;
  branding: Branding | null;
  rule: StampRule | null;
  /** DSGVO Art. 13: controller display name (tenants.legal_name), null when unset. */
  controllerName: string | null;
  /** DSGVO Art. 13: optional contact for data-subject requests (tenant_branding.privacy_email). */
  privacyContact: string | null;
}
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

/** Staff-UI dashboard views (server-rendered HTML, staff-authenticated). */
export interface StaffDashboardCard { id: string; customerRef: string | null; stampCount: number; rewardId: string | null; rewardStatus: 'issued' | 'redeemed' | null; updatedAt: string | null; }
export interface StaffDashboardEvent { id: string; cardId: string; customerRef: string | null; quantity: number; createdAt: string | null; }
export interface StaffDashboardData {
  tenant: { id: string; legalName: string | null; planCode: string; customerLimit: number; usedCards: number } | null;
  branding: Branding | null;
  rule: StampRule | null;
  joinPath: string | null;
  cards: StaffDashboardCard[];
  events: StaffDashboardEvent[];
}
/**
 * Staff-dashboard statistics (server-rendered HTML only). Pure tenant-scoped
 * aggregates — never a row of any kind, so the shape carries no customer/card/
 * token/reward internals and no PII: only counts, sums, averages and one
 * percentage. `trendDeltaPct` is the percent change of stamp activity (last 30
 * days vs the 30 days before, rounded to one decimal) and is null when the
 * previous period has no data (division by zero is not representable).
 */
export interface StaffStats {
  /** cards with status='active' and deleted_at is null. */
  activeCards: number;
  /** rewards with status='redeemed' (all time). */
  redeemedRewards: number;
  /** sum(stamp_events.quantity) in the last 30 days (sales-indicator window). */
  stampsLast30d: number;
  /** sum(stamp_events.quantity) in the 30 days before that. */
  stampsPrev30d: number;
  /** Percent change stampsLast30d vs stampsPrev30d; null when prev30d is 0. */
  trendDeltaPct: number | null;
  /** Active cards created within the last 30 days. */
  newCardsLast30d: number;
  /** Average stamp_count across active cards, rounded to 1 decimal. */
  avgStampCount: number;
  /** Active cards at/above their rule's stamps_required with an open (issued) reward. */
  readyRewards: number;
  /** Active cards in the last quarter before the threshold (>= 0.75*required, below it). */
  nearReward: number;
}

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
  /**
   * Anonymous customer row for the staff "Neue Karte anlegen" flow (business
   * model: participation without a mandatory name/account/email). Inserts a
   * `customers` row with external_ref NULL — zero PII — inside the tenant RLS
   * transaction and returns the fresh customer id. The subsequent card insert
   * reuses the canonical `createCard` path (identical method to the tenant API
   * flow), so anonymous and named cards share one creation code path, one
   * capacity counter (count(distinct customer_id) from cards — one anonymous
   * card = one used slot) and one token-hash contract.
   */
  async createAnonymousCustomer(tenantId:string):Promise<string>{ return this.transaction(tenantId,async db=>{const t=await db.query<{id:string;customer_limit:number}>('select id, customer_limit from tenants where id=$1 and status=$2 for update',[tenantId,'active']);if(!t.rows[0])throw new Error('TENANT_NOT_FOUND');const used=await db.query<{count:string}>('select count(distinct customer_id) from cards where tenant_id=$1 and status=$2',[tenantId,'active']);if(Number(used.rows[0]?.count??0)>=t.rows[0].customer_limit)throw new Error('CUSTOMER_LIMIT_REACHED');const c=(await db.query<{id:string}>('insert into customers(tenant_id,external_ref) values($1,null) returning id',[tenantId])).rows[0];if(!c)throw new Error('CUSTOMER_NOT_FOUND');return c.id;});}
  /**
   * Raw token of the most recently created card, for the staff dashboard to
   * re-show the "Neue Karte" QR after a reload. The raw token is NEVER stored
   * in plaintext: only its SHA-256 hash lives on the cards row; the recoverable
   * copy reuses the existing encrypted-token store (migration 013 — the same
   * AES-256-GCM ciphertext the idempotent replay decrypts, keyed by
   * SESSION_SECRET). createCard writes that ciphertext whenever the caller
   * supplies an idempotency key, which the staff create-card action does.
   * Decryption failure (rotated SESSION_SECRET, corrupt row) degrades to null
   * — the dashboard then simply shows the card in the table without the QR.
   */
  async newestCardToken(tenantId:string):Promise<{cardId:string;token:string}|null>{
    return this.transaction(tenantId,async db=>{
      const row=(await db.query<{cardId:string;tokenCiphertext:string}>('select i.card_id as "cardId", i.token_ciphertext as "tokenCiphertext" from card_creation_idempotency i join cards c on c.id=i.card_id and c.tenant_id=i.tenant_id where i.tenant_id=$1 and c.status=$2 and c.deleted_at is null order by i.created_at desc limit 1',[tenantId,'active'])).rows[0];
      if(!row) return null;
      try{ return {cardId:row.cardId, token:decryptToken(row.tokenCiphertext)}; } catch { return null; }
    });
  }
  async createCard(tenantId:string, customerId:string, ruleId:string, tokenHash:string, idempotencyKey?:string, rawToken?:string):Promise<CreatedCard & {token?:string}>{ if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(customerId)) throw new Error('CUSTOMER_NOT_FOUND'); if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(ruleId)) throw new Error('RULE_NOT_FOUND'); const fingerprint=createHash('sha256').update(`${customerId}:${ruleId}`).digest('hex'); return this.transaction(tenantId,async db=>{ if(idempotencyKey){ const prior=await db.query<{request_fingerprint:string;card_id:string;token_ciphertext:string}>('select request_fingerprint,card_id,token_ciphertext from card_creation_idempotency where tenant_id=$1 and idempotency_key=$2 for update',[tenantId,idempotencyKey]); if(prior.rows[0]) { if(prior.rows[0].request_fingerprint!==fingerprint) throw new Error('IDEMPOTENCY_KEY_REUSED'); const card=(await db.query<CreatedCard>('select id,rule_id as "ruleId",stamp_count as "stampCount",revision from cards where tenant_id=$1 and id=$2',[tenantId,prior.rows[0].card_id])).rows[0]; if(!card) throw new Error('CARD_NOT_FOUND'); return {...card,token:decryptToken(prior.rows[0].token_ciphertext)}; } } const t=await db.query<{customer_limit:number}>('select customer_limit from tenants where id=$1 and status=$2 for update',[tenantId,'active']); if(!t.rows[0]) throw new Error('TENANT_NOT_FOUND'); const customer=await db.query('select id from customers where id=$1 and tenant_id=$2 and status=$3 and deleted_at is null',[customerId,tenantId,'active']); if(!customer.rows[0]) throw new Error('CUSTOMER_NOT_FOUND'); const used=await db.query<{count:string}>('select count(distinct customer_id) from cards where tenant_id=$1 and status=$2',[tenantId,'active']); if(Number(used.rows[0]?.count??0)>=t.rows[0].customer_limit) throw new Error('CUSTOMER_LIMIT_REACHED'); const rule=await db.query('select id from stamp_rules where id=$1 and tenant_id=$2 and active=true',[ruleId,tenantId]); if(!rule.rows[0]) throw new Error('RULE_NOT_FOUND'); const card=await db.query<CreatedCard>('insert into cards(tenant_id,customer_id,rule_id,public_token_hash) values($1,$2,$3,$4) returning id, rule_id as "ruleId", stamp_count as "stampCount", revision',[tenantId,customerId,ruleId,tokenHash]); const inserted=card.rows[0]; if(!inserted) throw new Error('CARD_CREATE_FAILED'); const token=rawToken ?? ''; if(idempotencyKey) await db.query('insert into card_creation_idempotency(tenant_id,idempotency_key,request_fingerprint,card_id,token_ciphertext) values($1,$2,$3,$4,$5)',[tenantId,idempotencyKey,fingerprint,inserted.id,encryptToken(token)]); return {...inserted,...(rawToken !== undefined ? {token} : {})}; }); }
  async capacity(tenantId:string){return this.transaction(tenantId,async db=>{const t=await db.query<{plan_code:string,customer_limit:number}>('select plan_code,customer_limit from tenants where id=$1',[tenantId]);if(!t.rows[0])throw new Error('TENANT_NOT_FOUND');const used=await db.query<{count:string}>('select count(distinct customer_id) from cards where tenant_id=$1 and status=$2',[tenantId,'active']);const n=Number(used.rows[0]?.count??0);return {plan:t.rows[0].plan_code,limit:t.rows[0].customer_limit,used:n,remaining:Math.max(0,t.rows[0].customer_limit-n)};});}
  /**
   * Configuration writers share the tenant-row-lock protocol used by the
   * create-tenant CLI: lock the tenant before inspecting or changing branding
   * or stamp rules, so concurrent writers cannot publish conflicting config.
   */
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
  /**
   * Public join-page context for GET /join/:publicKey — RLS-safe by
   * construction, single round trip.
   *
   * Resolution goes through the SECURITY DEFINER function
   * public.resolve_entry_point (migration 008) exactly like resolveEntryPoint
   * (never a direct tenant_entry_points read). Only AFTER the entry point
   * resolved to a tenant does the transaction set app.tenant_id to THAT
   * tenant — the caller is then able to read only the branding/rule/controller
   * rows of the tenant whose public key they presented (tenant_isolation RLS),
   * which is the same public-read trust model as the webcard route. The result
   * is minimized to what the public join page renders: no entry-point
   * public_key, no customers/cards/rewards rows.
   */
  async joinContext(publicKey:string):Promise<JoinPageData|null>{
    if(!/^[a-f0-9]{32}$/i.test(publicKey)) return null;
    const db=await this.pool.connect();
    try{
      await db.query('begin');
      const entry=(await db.query<{tenant_id:string;join_path:string}>('select tenant_id,join_path from public.resolve_entry_point($1)',[publicKey])).rows[0];
      if(!entry){await db.query('rollback');return null;}
      await db.query("select set_config('app.tenant_id', $1, true)",[entry.tenant_id]);
      const brandingRow=(await db.query<Branding & {privacyEmail?:string|null}>('select card_title as "cardTitle",card_text as "cardText",primary_color as "primaryColor",secondary_color as "secondaryColor",privacy_email as "privacyEmail",version from tenant_branding where tenant_id=$1',[entry.tenant_id])).rows[0] ?? null;
      const branding:Branding|null=brandingRow?{cardTitle:brandingRow.cardTitle,cardText:brandingRow.cardText,primaryColor:brandingRow.primaryColor,secondaryColor:brandingRow.secondaryColor,version:brandingRow.version}:null;
      const tenant=(await db.query<{legal_name:string|null}>('select legal_name from tenants where id=$1',[entry.tenant_id])).rows[0] ?? null;
      const rule=(await db.query<StampRule>('select id,tenant_id as "tenantId",name,stamps_required as "stampsRequired",reward_title as "rewardTitle",reward_description as "rewardDescription",active,version from stamp_rules where tenant_id=$1 and active=true order by created_at desc limit 1',[entry.tenant_id])).rows[0] ?? null;
      await db.query('commit');
      return {tenantId:entry.tenant_id,joinPath:entry.join_path,branding,rule,controllerName:tenant?.legal_name??null,privacyContact:brandingRow?.privacyEmail??null};
    }catch(e){try{await db.query('rollback');}catch{}throw e;}finally{db.release();}
  }
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
  /**
   * Redeem an issued reward. Owner decision (2026-09-13): a successful
   * redemption starts a NEW collection round — the card's stamp counter is
   * reset to 0 (revision bumped, mirroring stamp()) so the next reward only
   * appears after `stampsRequired` FRESH stamps. Without the reset a card at
   * 14/11 would keep satisfying `stampCount >= stampsRequired` after redeeming
   * and every further stamp would mint another instantly-redeemable reward
   * (the endless-rewards bug). The reset runs in the same tenant transaction
   * and RLS context (app.tenant_id) as the rewards update; the reward's
   * card_id belongs to this tenant, so the cards row is visible and updatable
   * under the tenant_isolation policy. The 409 behavior for an already
   * redeemed reward id (REWARD_ALREADY_REDEEMED) is unchanged and never
   * touches the card.
   */
  async redeem(tenantId:string,rewardId:string):Promise<RedeemResult>{return this.transaction(tenantId,async db=>{const r=(await db.query<{id:string;status:'issued'|'redeemed';card_id:string}>("update rewards set status='redeemed',redeemed_at=now() where tenant_id=$1 and id=$2 and status='issued' returning id,status,card_id",[tenantId,rewardId])).rows[0];if(!r){const exists=await db.query<{id:string;status:string}>('select id,status from rewards where tenant_id=$1 and id=$2',[tenantId,rewardId]);if(exists.rows[0]?.status==='redeemed')throw new Error('REWARD_ALREADY_REDEEMED');throw new Error('REWARD_NOT_FOUND');}await db.query('update cards set stamp_count=0,revision=revision+1,updated_at=now() where tenant_id=$1 and id=$2',[tenantId,r.card_id]);return {rewardId:r.id,status:r.status};});}
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
  async cleanupExpiredSessions(tenantId:string|null):Promise<number>{const db=await this.pool.connect();try{await db.query('begin');if(tenantId)await db.query("select set_config('app.tenant_id', $1, true)",[tenantId]);const r=tenantId?await db.query<{id:string}>(`delete from sessions where tenant_id=$1 and ((revoked_at is null and expires_at<=now()) or (revoked_at is not null and revoked_at<=now() - interval '7 days')) returning id`,[tenantId]):await db.query<{id:string}>("delete from sessions where (revoked_at is null and expires_at<=now()) or (revoked_at is not null and revoked_at<=now() - interval '7 days') returning id");await db.query('commit');return r.rows.length;}catch(e){try{await db.query('rollback');}catch{}throw e;}finally{db.release();}}

  /**
   * Staff-UI dashboard projection (server-rendered HTML only). All reads run
   * in ONE tenant transaction under the normal tenant-isolation RLS; the
   * returned shape carries only what the dashboard renders — never anything
   * about owners/employees/sessions and never raw card tokens (the DB stores
   * only public_token_hash). Customer display uses the tenant-chosen
   * customers.external_ref (staff-facing identifier, e.g. a loyalty number or
   * internal ref) — the staff legitimately needs it to identify a customer's
   * card; the public card/API payloads stay minimized as before.
   */
  async staffDashboard(tenantId:string):Promise<StaffDashboardData> { return this.transaction(tenantId, async db => {
    const t=(await db.query<{id:string;legalName:string;planCode:string;customerLimit:number}>('select id, legal_name as "legalName", plan_code as "planCode", customer_limit as "customerLimit" from tenants where id=$1 and status=$2',[tenantId,'active'])).rows[0];
    if(!t) return {tenant:null,branding:null,rule:null,joinPath:null,cards:[],events:[]};
    const b=(await db.query<Branding>('select card_title as "cardTitle",card_text as "cardText",primary_color as "primaryColor",secondary_color as "secondaryColor",version from tenant_branding where tenant_id=$1',[tenantId])).rows[0] ?? null;
    const rule=(await db.query<StampRule>('select id,tenant_id as "tenantId",name,stamps_required as "stampsRequired",reward_title as "rewardTitle",reward_description as "rewardDescription",active,version from stamp_rules where tenant_id=$1 and active=true order by created_at desc limit 1',[tenantId])).rows[0] ?? null;
    const entry=(await db.query<{joinPath:string}>('select join_path as "joinPath" from tenant_entry_points where tenant_id=$1',[tenantId])).rows[0] ?? null;
    const used=(await db.query<{n:string}>('select count(distinct customer_id) as n from cards where tenant_id=$1 and status=$2',[tenantId,'active'])).rows[0] ?? {n:'0'};
    const cards=(await db.query<{id:string;customerRef:string|null;stampCount:number;updatedAt:string|null}>('select c.id, cu.external_ref as "customerRef", c.stamp_count as "stampCount", c.updated_at as "updatedAt" from cards c join customers cu on cu.id=c.customer_id and cu.tenant_id=c.tenant_id where c.tenant_id=$1 and c.status=$2 and c.deleted_at is null order by c.updated_at desc limit $3',[tenantId,'active',100])).rows;
    const events=(await db.query<{id:string;cardId:string;customerRef:string|null;quantity:number;createdAt:string|null}>('select e.id, e.card_id as "cardId", e.quantity, e.created_at as "createdAt", cu.external_ref as "customerRef" from stamp_events e join cards c on c.id=e.card_id join customers cu on cu.id=c.customer_id where e.tenant_id=$1 order by e.created_at desc limit $2',[tenantId,20])).rows;
    // Latest reward per card (issued_at ascending → last write wins): the
    // dashboard shows the current reward status and the redeemable reward id.
    const rewards=(await db.query<{id:string;cardId:string;status:'issued'|'redeemed'}>('select id, card_id as "cardId", status from rewards where tenant_id=$1 order by issued_at asc',[tenantId])).rows;
    const lastReward=new Map<string,{id:string;status:'issued'|'redeemed'}>();
    for(const r of rewards) lastReward.set(r.cardId,{id:r.id,status:r.status});
    const viewCards=cards.map(c=>{const rw=lastReward.get(c.id);return {...c,rewardId:rw?.id??null,rewardStatus:rw?.status??null};});
    return {tenant:{id:t.id,legalName:t.legalName,planCode:t.planCode,customerLimit:t.customerLimit,usedCards:Number(used.n??0)},branding:b,rule,joinPath:entry?.joinPath??null,cards:viewCards,events};
  }); }

  /**
   * Staff-dashboard statistics — pure tenant-scoped aggregates in ONE tenant
   * transaction (muster like staffDashboard/joinContext: begin →
   * set_config('app.tenant_id') → reads → commit), so every row observed is
   * covered by the tenant_isolation RLS policy of the calling tenant. No PII:
   * only counts, sums, one average and one percentage. The 30-day windows use
   * the transaction's stable now(); `avg(stamp_count)` over active cards is
   * rounded to 1 decimal in JS; the trend delta is null (never a division by
   * zero) when the previous period has no data. Empty/no-data tenants return
   * zeros instead of errors.
   */
  async staffStats(tenantId:string):Promise<StaffStats> { return this.transaction(tenantId, async db => {
    const active=(await db.query<{n:string}>('select count(*) as n from cards c where c.tenant_id=$1 and c.status=$2 and c.deleted_at is null',[tenantId,'active'])).rows[0];
    const redeemed=(await db.query<{n:string}>('select count(*) as n from rewards where tenant_id=$1 and status=$2',[tenantId,'redeemed'])).rows[0];
    const trend=(await db.query<{last30:string;prev30:string}>(`select coalesce(sum(quantity) filter (where created_at >= now() - interval '30 days'),0) as last30, coalesce(sum(quantity) filter (where created_at >= now() - interval '60 days' and created_at < now() - interval '30 days'),0) as prev30 from stamp_events e where e.tenant_id=$1`,[tenantId])).rows[0];
    const fresh=(await db.query<{n:string}>(`select count(*) as n from cards c where c.tenant_id=$1 and c.status=$2 and c.deleted_at is null and c.created_at >= now() - interval '30 days'`,[tenantId,'active'])).rows[0];
    const avg=(await db.query<{avg:string|null}>('select avg(c.stamp_count) as avg from cards c where c.tenant_id=$1 and c.status=$2 and c.deleted_at is null',[tenantId,'active'])).rows[0];
    // Per-card rules: a card's progress band is defined by ITS stamp rule
    // (rule_id), not the tenant's currently active rule — defunct/inactive
    // rules keep their cards' thresholds valid.
    const ready=(await db.query<{n:string}>('select count(*) as n from cards c join stamp_rules r on r.id = c.rule_id where c.tenant_id=$1 and c.status=$2 and c.deleted_at is null and c.stamp_count >= r.stamps_required and exists (select w.id from rewards w where w.tenant_id = c.tenant_id and w.card_id = c.id and w.status=$3)',[tenantId,'active','issued'])).rows[0];
    const near=(await db.query<{n:string}>('select count(*) as n from cards c join stamp_rules r on r.id = c.rule_id where c.tenant_id=$1 and c.status=$2 and c.deleted_at is null and c.stamp_count >= 0.75 * r.stamps_required and c.stamp_count < r.stamps_required',[tenantId,'active'])).rows[0];
    const last30=Number(trend?.last30??0);
    const prev30=Number(trend?.prev30??0);
    return {
      activeCards:Number(active?.n??0),
      redeemedRewards:Number(redeemed?.n??0),
      stampsLast30d:last30,
      stampsPrev30d:prev30,
      trendDeltaPct:prev30>0?Math.round(((last30-prev30)/prev30)*1000)/10:null,
      newCardsLast30d:Number(fresh?.n??0),
      avgStampCount:avg?.avg==null?0:Math.round(Number(avg.avg)*10)/10,
      readyRewards:Number(ready?.n??0),
      nearReward:Number(near?.n??0),
    };
  }); }
}
export interface AuditEvent { tenantId?:string;actorUserId?:string;action:string;entityType:string;entityId?:string;metadata?:Record<string,unknown> }
export async function appendAudit(db:DbClient,event:AuditEvent){await db.query('insert into audit_log(tenant_id,actor_user_id,action,entity_type,entity_id,metadata) values($1,$2,$3,$4,$5,$6)',[event.tenantId??null,event.actorUserId??null,event.action,event.entityType,event.entityId??null,JSON.stringify(event.metadata??{})]);}
