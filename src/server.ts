import { assertTenant, canStamp, hashToken } from './domain.js';
import { cardResolveLimiter, clientIpKey, csrfValid, hashPassword, joinResolveKey, loginAccountKey, loginAccountLimiter, loginFailureReason, loginIpLimiter, resetConfirmIpLimiter, resetConfirmTokenLimiter, resetRequestAccountLimiter, resetRequestIpLimiter, resetResolveKey, resetResolveLimiter, stampLimiter, verifyPassword, verifyPasswordAgainstDummy, randomToken, hashSessionToken } from './security.js';
import { createPostgresPool, runMigrations, type DbPool } from './db.js';
import { CardRepository, type StaffDashboardData, type StaffStats } from './repository.js';
import { configurationStatus } from './config.js';
import { EncryptedMfaSecretStore, verifyTotp } from './mfa.js';
import { walletAdapter, ensureGoogleWalletClass } from './wallet.js';
import { classifyError } from './http-error.js';
import { DEFAULT_PRIMARY_CARD_COLOR, DEFAULT_SECONDARY_CARD_COLOR, joinPageHtml, safeBranding, toPublicCardResponse, toWalletCardView } from './public-card.js';
import { publicHealthResponse } from './health.js';
import { loginPage, resetPasswordPage, resetRequestPage, resetTokenInvalidPage, tenantChooserPage, noTenantPage, dashboardPage, staffErrorPage, type DashboardView } from './staff-ui.js';
import { SmtpEmailAdapter, passwordResetEmailHtml, passwordResetEmailText } from './email.js';
import { requireVerifiedMfaBootstrap } from './mfa-bootstrap.js';
import { toCreateCardResponse, toDeleteResponse, toLoginResponse, toPilotResponse, toRedeemResponse, toResetConfirmResponse, toResetRequestResponse, toStaffResponse, toStampResponse } from './contracts.js';
import type { Branding, StampRule } from './domain.js';
const config=configurationStatus(); let configured=config.ready;
/**
 * Credentialed CORS allowlist. FRONTEND_ORIGIN remains the required primary
 * origin; FRONTEND_ORIGIN_DEV optionally adds a second explicitly configured
 * origin for the separate dev site. PUBLIC_SITE_ORIGIN remains a legacy alias
 * for the primary origin.
 */
const configuredCorsOrigins = () => [
  process.env.FRONTEND_ORIGIN || process.env.PUBLIC_SITE_ORIGIN || '',
  process.env.FRONTEND_ORIGIN_DEV || '',
].map(origin => origin.trim()).filter(Boolean);
const corsHeaders = (req: Request): HeadersInit => {
  const headers: Record<string, string> = { Vary: 'Origin' };
  const requestOrigin = req.headers.get('origin');
  if (requestOrigin && configuredCorsOrigins().includes(requestOrigin)) {
    headers['Access-Control-Allow-Origin'] = requestOrigin;
    headers['Access-Control-Allow-Credentials'] = 'true';
    headers['Access-Control-Allow-Headers'] = 'Content-Type, x-csrf-token, idempotency-key';
    headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,PATCH,DELETE,OPTIONS';
  }
  return headers;
};
const sessionCookie = (value: string, maxAge: number) =>
  `__Host-sp_session=${value}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${maxAge}`;
let pool:DbPool|undefined; let repository:CardRepository|undefined;
/** Wallet-factory seam for tests; defaults to the real Google Wallet adapter factory. */
let walletFactory: typeof walletAdapter = walletAdapter;
/** E-mail-adapter seam for tests (password-reset mail); defaults to the real SMTP adapter. */
let emailFactory: (() => SmtpEmailAdapter) | undefined;
const mfaStore = process.env.MFA_ENCRYPTION_KEY ? new EncryptedMfaSecretStore() : undefined;
let initializationError: unknown;
let dbReady = false;
/**
 * Honest pilot-readiness declaration (default off, like RUN_MIGRATIONS_ON_START).
 *
 * The request path cannot verify — without a blocking database query, which
 * GET /health must never issue — that the out-of-band schema steps
 * (`bun run db:migrate`, dedicated app role, `bun run rls-verify`) have
 * actually been completed against the production database. So the operator
 * declares it: set PILOT_READY=1 in the deployment environment ONLY after
 * those steps succeeded. Without it, GET /health stays HTTP 200 (liveness —
 * the function is up and answering) but honestly reports
 * `{"status":"not_ready"}` — "function reachable" and "schema/pilot ready"
 * are distinct states.
 */
let pilotReady = process.env.PILOT_READY === '1';

/**
 * Database readiness gate (Vercel-504 fix).
 *
 * Module import NEVER awaits database work: constructing the postgres.js pool
 * opens no socket (connections are lazy per query), so even `configured`
 * deployments boot instantly. Migrations are deliberately NOT part of the
 * Vercel request/cold-start path by default — the schema is applied out-of-band
 * via `bun run db:migrate` (src/migrate.ts). Only an explicit
 * RUN_MIGRATIONS_ON_START=1 opt-in starts them in the background, and requests
 * wait at most DB_READINESS_TIMEOUT_MS for that background work before failing
 * fast with a classified DATABASE_UNAVAILABLE (503) — a hung migration (e.g. a
 * sleeping Neon compute) can no longer hold every non-/health route until the
 * platform kills the invocation (FUNCTION_INVOCATION_TIMEOUT / 504).
 */
const migrationsOnStart = process.env.RUN_MIGRATIONS_ON_START === '1';
const parsedReadinessTimeout = Number(process.env.DB_READINESS_TIMEOUT_MS ?? 3_000);
const readinessTimeoutMs = Number.isFinite(parsedReadinessTimeout) && parsedReadinessTimeout > 0 ? parsedReadinessTimeout : 3_000;
let readiness: Promise<void> = Promise.resolve();
if (configured) {
  pool = createPostgresPool();
  repository = new CardRepository(pool);
  if (migrationsOnStart) {
    // Background opt-in only. Failures are recorded (never rethrown, so module
    // init cannot die) and surfaced as DATABASE_UNAVAILABLE to requests and
    // `not_ready` on /health until a later start succeeds.
    readiness = runMigrations(pool).then(() => {
      dbReady = true;
    }, error => {
      initializationError = error;
      console.error('migration_failed', classifyError(error).detail ?? 'INTERNAL_ERROR');
    });
  } else {
    // Default: schema is applied by `bun run db:migrate` before the pilot; the
    // request path is never blocked by DDL, so a cold start cannot be held
    // hostage by a slow or sleeping database. dbReady=true here only means "do
    // not wait in the request path" (DB-backed routes fail fast with classified
    // errors); it says nothing about schema/pilot readiness, which the operator
    // declares separately via PILOT_READY.
    dbReady = true;
  }
}

/** Bounded wait for database readiness; throws DATABASE_UNAVAILABLE (503) fast. */
async function waitForReadiness(): Promise<void> {
  if (!configured || dbReady) return;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('DATABASE_UNAVAILABLE')), readinessTimeoutMs);
  });
  try {
    await Promise.race([readiness, timeout]);
    if (initializationError) throw new Error('DATABASE_UNAVAILABLE');
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
const json=(value:unknown,status=200,id=crypto.randomUUID(),headers:HeadersInit={})=>Response.json({request_id:id,data:value},{status,headers:{'Cache-Control':'no-store',...headers}});
function error(e:unknown,id:string){const {code,status,detail}=classifyError(e);if(detail)console.error(`request_failed request_id=${id} error=${detail}`);return json({error:code},status,id as `${string}-${string}-${string}-${string}-${string}`)}
function cookie(req:Request,name:string){return req.headers.get('cookie')?.split(';').map(x=>x.trim()).find(x=>x.startsWith(`${name}=`))?.slice(name.length+1)}
async function auth(req:Request,tenantId:string,mutating=true){if(!pool||!repository)throw new Error('DATABASE_REQUIRED');const token=cookie(req,'__Host-sp_session');if(!token)throw new Error('UNAUTHENTICATED');const db=await pool.connect();try{await db.query('begin');await db.query("select set_config('app.tenant_id', $1, true)",[tenantId]);const resolved=await db.query<{user_id:string}>('select user_id from public.resolve_session_user($1)',[hashSessionToken(token)]);if(!resolved.rows[0]?.user_id)throw new Error('UNAUTHENTICATED');await db.query("select set_config('app.user_id', $1, true)",[resolved.rows[0].user_id]);const rows=await db.query<{id:string,user_id:string,csrf_token_hash:string,tenant_id:string,role:string;membership_id:string;mfa_required:boolean;mfa_verified:boolean}>('select s.id,s.user_id,s.csrf_token_hash,s.mfa_verified,m.id as membership_id,m.tenant_id,m.role,(u.mfa_required or m.mfa_required) as mfa_required from sessions s join users u on u.id=s.user_id join tenant_memberships m on m.user_id=s.user_id and m.status=$2 where s.token_hash=$1 and s.revoked_at is null and s.expires_at>now() and m.tenant_id=$3 and u.status=$4',[hashSessionToken(token),'active',tenantId,'active']);const s=rows.rows[0];if(!s)throw new Error('UNAUTHENTICATED');if(s.mfa_required&&!s.mfa_verified)throw new Error('MFA_REQUIRED');if(mutating&&!csrfValid(req,s.csrf_token_hash)){const sent=req.headers.get('x-csrf-token');/* CSRF rejection split: a MISSING/EMPTY token keeps the hard 403 "Sitzung abgelaufen" (PR #29 contract — a broken/foreign client), while a PRESENT-but-stale token on an OTHERWISE VALID session is the owner's reproducible two-tab flow: the session row above resolved fine, so the user is authenticated — only the token lags because another tab rotated it. Throw the typed CsrfStaleError (message stays CSRF_INVALID so the JSON API keeps its 403 contract unchanged) and let the staff handler answer a retry envelope instead of a fake "session expired".*/if(!sent||!sent.trim())throw new Error('CSRF_INVALID');throw new CsrfStaleError({userId:s.user_id,token,mfaVerified:s.mfa_verified});}assertTenant(tenantId,s.tenant_id);const actor={userId:s.user_id,role:s.role as any,sessionId:s.id,membershipId:s.membership_id,token,mfaVerified:s.mfa_verified,csrfTokenHash:s.csrf_token_hash};await db.query('commit');return actor;}catch(e){try{await db.query('rollback');}catch{}throw e;}finally{db.release();}}
/** Typed error for "session valid, CSRF token stale" (another tab rotated the
 *  session). message stays CSRF_INVALID so classifyError keeps answering 403
 *  CSRF_INVALID for the JSON API — this type is only consumed by the staff
 *  mutation handlers, which turn it into a 409 retry envelope. */
class CsrfStaleError extends Error {
  constructor(readonly actor: { userId: string; token: string; mfaVerified: boolean }) { super('CSRF_INVALID'); }
}
async function rotate(a:{userId:string;token:string;mfaVerified:boolean}){if(!pool||!repository)throw new Error('DATABASE_REQUIRED');const db=await pool.connect();try{await db.query('begin');await db.query("select set_config('app.user_id', $1, true)",[a.userId]);await db.query('update sessions set revoked_at=now() where token_hash=$1',[hashSessionToken(a.token)]);const raw=randomToken(),csrf=randomToken();await db.query("insert into sessions(user_id,token_hash,csrf_token_hash,mfa_verified,expires_at) values($1,$2,$3,$4,now()+interval '12 hours')",[a.userId,hashSessionToken(raw),hashSessionToken(csrf),a.mfaVerified]);await db.query('commit');return {csrf,header:{'Set-Cookie':sessionCookie(raw, 43200),'x-csrf-token':hashSessionToken(csrf)}}}catch(e){try{await db.query('rollback');}catch{}throw e;}finally{db.release();}}
/**
 * Best-effort Google Wallet balance sync after a committed stamp/redeem.
 *
 * There is deliberately NO wallet-artifact column on cards: the only truth
 * about "was this card saved to Google Wallet" lives at Google (the
 * loyaltyObject id is deterministic: `{issuerId}.{cardId}`). A PATCH against
 * a never-saved object returns 404, which refresh() treats as a graceful
 * no-op, so calling refresh for every stamp/redeem is safe and idempotent.
 * A failing sync must NEVER fail the already-committed stamp/redeem request:
 * all errors are logged and suppressed. Logs carry only the error code
 * (mirroring revoke()), never card ids or other identifiers.
 */
async function syncWalletBalance(tenantId:string,card:{id:string;stampCount:number},oidcToken:string|null):Promise<void>{
  if(!repository)return;
  try{
    const ctx=await repository.cardWalletContext(tenantId,card.id);
    const adapter=walletFactory('google',{oidcToken:oidcToken??undefined});
    const result=await adapter.refresh(toWalletCardView(card),['loyaltyPoints','textModulesData'],{
      branding:safeBranding(ctx.branding)??{cardTitle:'StempelPass',cardText:'',primaryColor:DEFAULT_PRIMARY_CARD_COLOR,secondaryColor:DEFAULT_SECONDARY_CARD_COLOR,version:1},
      stampRequired:ctx.rule?.stampsRequired??undefined,
      rewardTitle:ctx.rule?.rewardTitle??undefined,
    });
    if(result.status==='not_configured')return;
  }catch(error){console.error(`wallet_refresh_failed code=${error instanceof Error?error.message:'GOOGLE_WALLET_REFRESH_UNAVAILABLE'}`)}
}
/** Strict tenant/card UUID format guard (early 404, avoids bad DB casts). */
const UUID_RE=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const htmlResponse=(html:string,status=200,headers:HeadersInit={})=>new Response(html,{status,headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store',...headers}});
const staffRedirect=(location:string,headers:HeadersInit={})=>new Response(null,{status:302,headers:{Location:location,'Cache-Control':'no-store',...headers}});
/** Friendly HTML error page for the staff UI (never internal details). */
function staffError(e:unknown,id:string):Response{const {code,status}=classifyError(e);return htmlResponse(staffErrorPage(status,code,id),status);}
/**
 * Staff mutation error handler with the stale-CSRF retry envelope.
 *
 * When auth() finds a VALID session carrying a PRESENT-but-stale CSRF token
 * (the owner's reproducible two-tab flow: tab A stamped and rotated the
 * session; tab B still holds the old meta token), the user is authenticated —
 * only the token lags. Instead of a fake "Sitzung abgelaufen" the server
 * rotates the session once (fresh cookie + fresh CSRF, exactly like a
 * successful mutation), performs NO business write (auth() threw BEFORE any
 * repository call), and answers 409 + `x-csrf-retry: 1` so the staff script
 * re-sends the SAME request once with the fresh token. The JSON API keeps its
 * plain 403 CSRF_INVALID (CsrfStaleError.message === 'CSRF_INVALID' →
 * classifyError → 403); only the staff HTML path consumes the envelope.
 */
async function staffMutationError(e:unknown,id:string):Promise<Response>{
  if(e instanceof CsrfStaleError){
    try{
      const rotated=await rotate(e.actor);
      return json({error:'CSRF_INVALID',retry:true},409,id as `${string}-${string}-${string}-${string}-${string}`,{...rotated.header,'x-csrf-retry':'1'});
    }catch{/* rotation failed → fall back to the normal error page */}
  }
  return staffError(e,id);
}
/** Parse a staff POST body: JSON or form-urlencoded, strings only. */
async function parseBody(req: Request): Promise<Record<string, string>> {
  const ct = req.headers.get('content-type') ?? '';
  if (ct.includes('application/json')) {
    try {
      const raw = await req.json() as Record<string, unknown>;
      const out: Record<string, string> = {};
      for (const [k, v] of Object.entries(raw)) out[k] = typeof v === 'string' ? v : (typeof v === 'number' || typeof v === 'boolean') ? String(v) : '';
      return out;
    } catch {
      // Malformed JSON is treated as an empty body so the caller's field
      // validation (CARD_FIELDS_REQUIRED / REWARD_NOT_FOUND) reports the
      // missing fields instead of leaking a parser detail.
      return {};
    }
  }
  // Form branch. The Request body stream is ONE-SHOT: text()/formData() and
  // arrayBuffer() all consume it, so a fallback chain of method calls would
  // double-read (the second read fails with "body already read"). Read the raw
  // bytes exactly once via arrayBuffer() — the primitive every other Body
  // reader is built on — and derive the urlencoded parse from that single
  // read. On the deployed (Vercel) runtime req.formData() throws and
  // req.text() returns an EMPTY body for application/x-www-form-urlencoded
  // (form-POST stamp then fails with CARD_FIELDS_REQUIRED, redeem with
  // REWARD_NOT_FOUND — verified live on the production alias) while
  // req.json() keeps working; arrayBuffer() reaches the same buffered bytes
  // the working json() path reads, bypassing whatever shadows the
  // higher-level readers. An empty or non-urlencoded body yields an empty
  // record and the caller's field validation applies unchanged. A genuine
  // read failure (stream already consumed/errored) propagates and surfaces
  // as a 500 — never silently becomes a misleading missing-field error.
  const raw = await req.arrayBuffer();
  const text = new TextDecoder().decode(raw);
  const out: Record<string, string> = {};
  for (const [k, v] of new URLSearchParams(text)) out[k] = v;
  return out;
}
/** Resolve a stamp target: card UUID directly, or a raw card token via the
 *  existing findByPublicTokenHash lookup (hashToken, never the raw token). */
async function resolveCardId(tenantId:string,input:string):Promise<string>{
  if(UUID_RE.test(input))return input;
  const card=await repository!.findByPublicTokenHash(tenantId,hashToken(input));
  if(!card)throw new Error('CARD_NOT_FOUND');
  return card.id;
}
function dashboardView(tenantId:string,role:string,dash:StaffDashboardData,stats:StaffStats,csrf:string,newCard:{id:string;url:string;token:string}|null=null):DashboardView{
  const branding=dash.branding;
  const rule=dash.rule;
  return {
    tenantId,
    legalName:dash.tenant?.legalName??null,
    planCode:dash.tenant?.planCode??'up_to_500',
    customerLimit:dash.tenant?.customerLimit??0,
    usedCards:dash.tenant?.usedCards??0,
    role,
    canStamp:canStamp(role as any),
    cardTitle:branding?.cardTitle??'StempelPass',
    cardText:branding?.cardText??'',
    primaryColor:branding?.primaryColor??DEFAULT_PRIMARY_CARD_COLOR,
    secondaryColor:branding?.secondaryColor??DEFAULT_SECONDARY_CARD_COLOR,
    logoUrl:branding?.logoUrl??'',
    ruleName:rule?.name??null,
    stampsRequired:rule?.stampsRequired??null,
    rewardTitle:rule?.rewardTitle??null,
    rewardDescription:rule?.rewardDescription??null,
    joinPath:dash.joinPath,
    csrf,
    cards:dash.cards,
    events:dash.events,
    stats,
    newCard,
  };
}
/**
 * Newest-card QR panel for the staff dashboard: only stamp-capable roles see
 * it, only when the encrypted token is still recoverable, and only for THEIR
 * tenant (newestCardToken runs under tenant RLS). The URL uses the request
 * origin so the QR opens the webcard on the customer's phone; the origin is
 * never logged and the token is delivered to staff only (never in logs).
 */
async function dashboardNewCard(req:Request,tenantId:string,role:string):Promise<{id:string;url:string;token:string}|null>{
  if(!canStamp(role as any))return null;
  const newest=await repository!.newestCardToken(tenantId);
  if(!newest)return null;
  const origin=new URL(req.url).origin;
  return {id:newest.cardId,url:`${origin}/card/${tenantId}/${newest.token}`,token:newest.token};
}
/**
 * Tenantless /staff entry: validate the session (user-scoped RLS, same
 * bootstrap as auth()) and list the user's ACTIVE tenants via the migration
 * 016 resolver. Returns null when the session is missing/invalid/expired —
 * the caller redirects to /login. Named lookups for the >1-tenant chooser use
 * tenants (no RLS) by the already-authorized membership ids.
 */
async function resolveStaffContext(req:Request):Promise<{userId:string;sessionId:string;tenants:{tenantId:string;role:string;legalName:string|null}[]}|null>{
  if(!pool||!repository)throw new Error('DATABASE_REQUIRED');
  const token=cookie(req,'__Host-sp_session');if(!token)return null;
  const db=await pool.connect();
  try{
    await db.query('begin');
    const resolved=await db.query<{user_id:string}>('select user_id from public.resolve_session_user($1)',[hashSessionToken(token)]);
    if(!resolved.rows[0]?.user_id){await db.query('rollback');return null;}
    await db.query("select set_config('app.user_id', $1, true)",[resolved.rows[0].user_id]);
    const s=await db.query<{id:string}>('select s.id from sessions s join users u on u.id=s.user_id where s.token_hash=$1 and s.revoked_at is null and s.expires_at>now() and u.status=$2',[hashSessionToken(token),'active']);
    if(!s.rows[0]){await db.query('rollback');return null;}
    const rows=await db.query<{tenantId:string;role:string}>('select tenant_id as "tenantId", role from public.resolve_user_tenants($1)',[resolved.rows[0].user_id]);
    let tenants:{tenantId:string;role:string;legalName:string|null}[]=rows.rows.map(r=>({tenantId:r.tenantId,role:r.role,legalName:null}));
    if(tenants.length>1){
      const names=await db.query<{id:string;legalName:string|null}>('select id, legal_name as "legalName" from tenants where id = any($1::uuid[])',[tenants.map(t=>t.tenantId)]);
      const byId=new Map(names.rows.map(r=>[r.id,r.legalName??null]));
      tenants=tenants.map(t=>({...t,legalName:byId.get(t.tenantId)??null}));
    }
    await db.query('commit');
    return {userId:resolved.rows[0].user_id,sessionId:s.rows[0].id,tenants};
  }catch(e){try{await db.query('rollback');}catch{}throw e;}finally{db.release();}
}
async function handleStaffEntry(req:Request,id:string):Promise<Response>{
  try{
    const ctx=await resolveStaffContext(req);
    if(!ctx)return staffRedirect('/login');
    if(ctx.tenants.length===0)return htmlResponse(noTenantPage());
    if(ctx.tenants.length===1)return staffRedirect(`/staff/${ctx.tenants[0].tenantId}`);
    return htmlResponse(tenantChooserPage(ctx.tenants));
  }catch(e){return staffMutationError(e,id);}
}
async function handleStaffDashboard(req:Request,tenantId:string,id:string):Promise<Response>{
  try{
    if(!UUID_RE.test(tenantId))return htmlResponse(staffErrorPage(404,'TENANT_NOT_FOUND',id),404);
    if(!pool||!repository)throw new Error('DATABASE_REQUIRED');
    const actor=await auth(req,tenantId,false);
    const dash=await repository.staffDashboard(tenantId);
    if(!dash.tenant)throw new Error('TENANT_NOT_FOUND');
    const stats=await repository.staffStats(tenantId);
    const newCard=await dashboardNewCard(req,tenantId,actor.role);
    return htmlResponse(dashboardPage(dashboardView(tenantId,actor.role,dash,stats,actor.csrfTokenHash,newCard)));
  }catch(e){
    if(e instanceof Error&&e.message==='UNAUTHENTICATED')return staffRedirect('/login');
    return staffError(e,id);
  }
}
async function handleStaffStamp(req:Request,tenantId:string,id:string):Promise<Response>{
  try{
    if(!UUID_RE.test(tenantId))return htmlResponse(staffErrorPage(404,'TENANT_NOT_FOUND',id),404);
    if(!pool||!repository)throw new Error('DATABASE_REQUIRED');
    const actor=await auth(req,tenantId,true);
    if(!canStamp(actor.role))throw new Error('FORBIDDEN');
    if(!stampLimiter.allow(`${tenantId}:${actor.userId}`))throw new Error('RATE_LIMITED');
    const body=await parseBody(req);
    const input=String(body.cardId??body.cardToken??'').trim();if(!input)throw new Error('CARD_FIELDS_REQUIRED');
    const quantityRaw=Number(body.quantity??1);const quantity=Number.isInteger(quantityRaw)?quantityRaw:1;
    const cardId=await resolveCardId(tenantId,input);
    const value=await repository.stamp(tenantId,cardId,quantity,actor.membershipId,crypto.randomUUID());
    const rotated=await rotate(actor);
    // Best-effort Google Wallet balance sync (same contract as the tenant API
    // routes): DB write first, then refresh the loyaltyObject {issuerId}.{cardId}
    // with the committed stamp result. The refreshed card id comes from the
    // stamp's UPDATE ... RETURNING — the exact card that was stamped. A Wallet
    // failure never fails the already-committed stamp (errors are suppressed
    // inside syncWalletBalance).
    await syncWalletBalance(tenantId,value.card,req.headers.get('x-vercel-oidc-token'));
    const dash=await repository.staffDashboard(tenantId);
    const stats=await repository.staffStats(tenantId);
    const newCard=await dashboardNewCard(req,tenantId,actor.role);
    const flash=`Stempel vergeben: Karte ${cardId.slice(0,8)} hat jetzt ${value.card.stampCount} Stempel.`+(value.reward?' Die Prämie ist jetzt einlösbar.':'');
    return htmlResponse(dashboardPage(dashboardView(tenantId,actor.role,dash,stats,rotated.header['x-csrf-token'],newCard),{kind:'ok',text:flash}),200,{'Set-Cookie':rotated.header['Set-Cookie'],'x-csrf-token':rotated.header['x-csrf-token']});
  }catch(e){return staffMutationError(e,id);}
}
async function handleStaffRedeem(req:Request,tenantId:string,id:string):Promise<Response>{
  try{
    if(!UUID_RE.test(tenantId))return htmlResponse(staffErrorPage(404,'TENANT_NOT_FOUND',id),404);
    if(!pool||!repository)throw new Error('DATABASE_REQUIRED');
    const actor=await auth(req,tenantId,true);
    if(!canStamp(actor.role))throw new Error('FORBIDDEN');
    const body=await parseBody(req);
    const rewardId=String(body.rewardId??'').trim();if(!rewardId)throw new Error('REWARD_NOT_FOUND');
    const value=await repository.redeem(tenantId,rewardId);
    const rotated=await rotate(actor);
    // Best-effort Google Wallet balance sync: refresh the loyaltyObject
    // {issuerId}.{cardId} to the RESET balance (0 stamps — new collection
    // round). Same contract as the API redeem route; failures stay suppressed.
    await syncWalletBalance(tenantId,value.card,req.headers.get('x-vercel-oidc-token'));
    const dash=await repository.staffDashboard(tenantId);
    const stats=await repository.staffStats(tenantId);
    const newCard=await dashboardNewCard(req,tenantId,actor.role);
    const flash=value.status==='redeemed'?'Prämie erfolgreich eingelöst.':'Prämie eingelöst.';
    return htmlResponse(dashboardPage(dashboardView(tenantId,actor.role,dash,stats,rotated.header['x-csrf-token'],newCard),{kind:'ok',text:flash}),200,{'Set-Cookie':rotated.header['Set-Cookie'],'x-csrf-token':rotated.header['x-csrf-token']});
  }catch(e){return staffMutationError(e,id);}
}
/**
 * Staff "Neue Karte anlegen": create an ANONYMOUS card (no customer name,
 * account or e-mail — business model) through the exact same createCard
 * repository path the tenant API uses, so the card gets its one-time token
 * with the identical hash/capacity/idempotency contract. The staff session
 * must be CSRF-valid (mutating), the role must be stamp-capable, and the
 * tenant must have an active stamp rule (the card is bound to the rule the
 * dashboard is showing). The response re-renders the dashboard with the QR
 * panel for the new card.
 */
async function handleStaffCreateCard(req:Request,tenantId:string,id:string):Promise<Response>{
  try{
    if(!UUID_RE.test(tenantId))return htmlResponse(staffErrorPage(404,'TENANT_NOT_FOUND',id),404);
    if(!pool||!repository)throw new Error('DATABASE_REQUIRED');
    const actor=await auth(req,tenantId,true);
    if(!canStamp(actor.role))throw new Error('FORBIDDEN');
    const dash=await repository.staffDashboard(tenantId);
    if(!dash.tenant)throw new Error('TENANT_NOT_FOUND');
    if(!dash.rule)throw new Error('RULE_NOT_FOUND');
    const customerId=await repository.createAnonymousCustomer(tenantId);
    const rawToken=randomToken();
    const created=await repository.createCard(tenantId,customerId,dash.rule.id,hashToken(rawToken),crypto.randomUUID(),rawToken);
    const rotated=await rotate(actor);
    // Best-effort Google Wallet balance sync for the fresh card: the
    // loyaltyObject {issuerId}.{cardId} is provisioned by issue() when the
    // customer saves the card — at that point the balance comes from the DB
    // (0 for a brand-new card). The refresh here keeps the staff create path
    // uniform with stamp/redeem; against a never-saved object it is a graceful
    // 404 no-op inside refresh().
    await syncWalletBalance(tenantId,{id:created.id,stampCount:created.stampCount??0},req.headers.get('x-vercel-oidc-token'));
    const dash2=await repository.staffDashboard(tenantId);
    const stats=await repository.staffStats(tenantId);
    const origin=new URL(req.url).origin;
    const newCard={id:created.id,url:`${origin}/card/${tenantId}/${created.token ?? rawToken}`,token:created.token ?? rawToken};
    const flash='Neue Karte angelegt — QR-Code und Link unten direkt weitergeben.';
    return htmlResponse(dashboardPage(dashboardView(tenantId,actor.role,dash2,stats,rotated.header['x-csrf-token'],newCard),{kind:'ok',text:flash}),200,{'Set-Cookie':rotated.header['Set-Cookie'],'x-csrf-token':rotated.header['x-csrf-token']});
  }catch(e){return staffMutationError(e,id);}
}
async function handleStaffBranding(req:Request,tenantId:string,id:string):Promise<Response>{
  try{
    if(!UUID_RE.test(tenantId))return htmlResponse(staffErrorPage(404,'TENANT_NOT_FOUND',id),404);
    if(!pool||!repository)throw new Error('DATABASE_REQUIRED');
    const actor=await auth(req,tenantId,true);
    if(actor.role!=='owner'&&actor.role!=='admin')throw new Error('FORBIDDEN');
    const dash=await repository.staffDashboard(tenantId);
    if(!dash.tenant)throw new Error('TENANT_NOT_FOUND');
    const body=await parseBody(req);
    // Branding-only edit through the existing configurePilot path: preserve the
    // current plan + stamp rule, replace the branding fields from the form.
    const currentBranding=dash.branding??{cardTitle:'',cardText:'',primaryColor:'',secondaryColor:'',version:0};
    const currentRule=dash.rule??{stampsRequired:10,rewardTitle:'Gratisartikel',rewardDescription:''};
    const newBranding: Branding={
      cardTitle:String(body.cardTitle??currentBranding.cardTitle??'StempelPass').trim(),
      cardText:String(body.cardText??currentBranding.cardText??'').trim(),
      primaryColor:String(body.primaryColor??currentBranding.primaryColor??DEFAULT_PRIMARY_CARD_COLOR),
      secondaryColor:String(body.secondaryColor??currentBranding.secondaryColor??DEFAULT_SECONDARY_CARD_COLOR),
      logoUrl:String(body.logoUrl??'').trim()||undefined,
      version:(currentBranding.version??0)+1,
    };
    await repository.configurePilot(tenantId,actor.userId,{
      planCode:dash.tenant.planCode as 'up_to_500'|'up_to_1000',
      cardTitle:newBranding.cardTitle,
      cardText:newBranding.cardText,
      primaryColor:newBranding.primaryColor,
      secondaryColor:newBranding.secondaryColor,
      logoUrl:newBranding.logoUrl,
      stampsRequired:Number(currentRule.stampsRequired??10),
      rewardTitle:String(currentRule.rewardTitle??'Gratisartikel').trim(),
      rewardDescription:String(currentRule.rewardDescription??'').trim(),
    });
    // Best-effort class sync: push the SAVED colors/name/logo onto the approved
    // Wallet class NOW (never fail the request — the class is patched anyway on
    // the next save-to-wallet issue()). Logged with the error code only.
    try{await ensureGoogleWalletClass(newBranding,{oidcToken:req.headers.get('x-vercel-oidc-token')??undefined});}catch(error){console.error(`wallet_class_sync_failed code=${error instanceof Error?error.message:'GOOGLE_WALLET_CLASS_SYNC_UNAVAILABLE'}`)}
    const rotated=await rotate(actor);
    const dash2=await repository.staffDashboard(tenantId);
    const stats=await repository.staffStats(tenantId);
    const newCard=await dashboardNewCard(req,tenantId,actor.role);
    const flash='Branding gespeichert — die Google-Wallet-Klasse wird bei der nächsten Kartenausstellung bzw. sofort aktualisiert.';
    return htmlResponse(dashboardPage(dashboardView(tenantId,actor.role,dash2,stats,rotated.header['x-csrf-token'],newCard),{kind:'ok',text:flash}),200,{'Set-Cookie':rotated.header['Set-Cookie'],'x-csrf-token':rotated.header['x-csrf-token']});
  }catch(e){return staffMutationError(e,id);}
}
async function handleStaffLogout(req:Request,tenantId:string,id:string):Promise<Response>{
  try{
    if(!UUID_RE.test(tenantId))return htmlResponse(staffErrorPage(404,'TENANT_NOT_FOUND',id),404);
    if(!pool||!repository)throw new Error('DATABASE_REQUIRED');
    const actor=await auth(req,tenantId,true);
    await repository.revokeSession(actor.userId,hashSessionToken(actor.token));
    return staffRedirect('/login',{'Set-Cookie':sessionCookie('',0)});
  }catch(e){return staffMutationError(e,id);}
}
/**
 * Password reset ("Passwort vergessen", owner wish).
 *
 * Flow: POST /api/auth/reset/request (email in, neutral answer always) →
 * e-mail with a raw one-time token → GET /reset/:token (new-password form) →
 * POST /api/auth/reset/confirm (token + new password). The raw token is a
 * randomToken() (32 random bytes base64url, 43 chars) and is NEVER stored or
 * logged — only its SHA-256 hex digest (hashSessionToken, exactly like session
 * tokens) lands in password_reset_tokens.token_hash. The SQL resolver
 * public.resolve_password_reset_user (migration 019) is the RLS-safe identity
 * bootstrap for the auth-less pages, mirroring resolve_session_user (009).
 */
const RESET_TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
const RESET_TOKEN_TTL_SQL = "now() + interval '60 minutes'";
/** Audit action for a confirmed reset; metadata.operationId is the idempotency anchor. */
const RESET_CONFIRM_AUDIT_ACTION = 'user.password_reset_confirmed';

/**
 * POST /api/auth/reset/request — always answers the SAME neutral body
 * ({status:'requested'}) for known accounts, unknown accounts, missing SMTP
 * (not_configured) and send failures: no enumeration, no mailbox probing.
 * Rate limits follow the login limiter split (per hashed IP + per hashed
 * normalized account key — the raw email never becomes a limiter key or a log
 * line). The token row is created only for an EXISTING active account, inside
 * a transaction that sets app.user_id from the server-side lookup (never from
 * client input) so the user-scoped RLS policy (migration 019) passes exactly
 * for the owning user. E-mail delivery is best-effort and happens outside the
 * transaction; it must never fail or change the request/response.
 */
async function handleResetRequest(req: Request, id: string): Promise<Response> {
  if (!pool) throw new Error('DATABASE_REQUIRED');
  if (!resetRequestIpLimiter.allow(clientIpKey(req))) throw new Error('RATE_LIMITED');
  const body = await req.json() as { email?: string };
  const email = String(body.email ?? '').trim();
  if (!email) throw new Error('CREDENTIALS_REQUIRED');
  const accountKey = loginAccountKey(email);
  if (!resetRequestAccountLimiter.allow(accountKey)) throw new Error('RATE_LIMITED');
  const emailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  const db = await pool.connect();
  let rawToken = '';
  try {
    await db.query('begin');
    let user: { id: string } | undefined;
    if (emailValid) user = (await db.query<{ id: string }>('select id from users where lower(email)=lower($1) and status=$2', [email, 'active'])).rows[0];
    if (user) {
      rawToken = randomToken();
      await db.query("select set_config('app.user_id', $1, true)", [user.id]);
      await db.query('insert into password_reset_tokens(user_id,token_hash,expires_at) values($1,$2,' + RESET_TOKEN_TTL_SQL + ')', [user.id, hashSessionToken(rawToken)]);
    }
    await db.query('commit');
  } catch (e) {
    try { await db.query('rollback'); } catch { /* preserve the original error */ }
    throw e;
  } finally {
    db.release();
  }
  if (rawToken) {
    const origin = new URL(req.url).origin;
    const link = origin + '/reset/' + rawToken;
    const adapter = emailFactory ? emailFactory() : new SmtpEmailAdapter();
    const result = await adapter.send({ to: email, subject: 'Passwort zurücksetzen – StempelPass', text: passwordResetEmailText(link), html: passwordResetEmailHtml(link) });
    // Neutral either way; logs carry only the hashed account key (never the
    // raw address) and the classified status (never provider details).
    if (result.status !== 'sent') console.warn('password_reset_email_not_sent request_id=' + id + ' status=' + result.status + ' account=' + accountKey);
  }
  return json(toResetRequestResponse(), 200, id as Parameters<typeof json>[2]);
}

/**
 * GET /reset/:token — the new-password form (public HTML; token in the URL is
 * the Bearer secret of the page, exactly like /card/:tenantId/:cardToken).
 * Rate-limited per IP+token (resetResolveKey). Unknown/expired/consumed tokens
 * and malformed tokens all answer the same neutral 404 page, never a form.
 */
async function handleResetPage(req: Request): Promise<Response> {
  const token = new URL(req.url).pathname.split('/').filter(Boolean)[1] ?? '';
  if (!RESET_TOKEN_RE.test(token)) return htmlResponse(resetTokenInvalidPage(), 404);
  if (!pool || !repository) throw new Error('DATABASE_REQUIRED');
  if (!resetResolveLimiter.allow(resetResolveKey(req, token))) throw new Error('RATE_LIMITED');
  const db = await pool.connect();
  try {
    const row = (await db.query<{ user_id: string }>('select user_id from public.resolve_password_reset_user($1)', [hashSessionToken(token)])).rows;
    if (!row[0]) return htmlResponse(resetTokenInvalidPage(), 404);
    return htmlResponse(resetPasswordPage(token), 200);
  } finally {
    db.release();
  }
}

/**
 * POST /api/auth/reset/confirm — token + new password. Pre-auth like the login
 * POST: no CSRF, rate limits + the token itself as secret. On success the
 * password_hash is replaced (migration 019 grants UPDATE on users to the
 * runtime role — WARNING 1 in PASSWORD_RESET_PREP), ALL sessions of the user
 * are revoked (rotate-owner-password.ts:126 pattern — the next login re-runs
 * MFA), the token is single-use (consumed_at) and an audit row (tenantId null,
 * global-isolation policy 009 — no app.tenant_id is ever set here) records the
 * rotation with a fresh operationId as idempotency anchor.
 */
async function handleResetConfirm(req: Request, id: string): Promise<Response> {
  if (!pool) throw new Error('DATABASE_REQUIRED');
  if (!resetConfirmIpLimiter.allow(clientIpKey(req))) throw new Error('RATE_LIMITED');
  const body = await req.json() as { token?: string; password?: string };
  const token = String(body.token ?? '').trim();
  const password = String(body.password ?? '');
  if (!token || !password) throw new Error('CREDENTIALS_REQUIRED');
  if (!RESET_TOKEN_RE.test(token)) throw new Error('RESET_TOKEN_INVALID');
  if (!resetConfirmTokenLimiter.allow(resetResolveKey(req, token))) throw new Error('RATE_LIMITED');
  if (password.length < 12) throw new Error('PASSWORD_TOO_SHORT');
  const passwordHash = await hashPassword(password);
  const operationId = crypto.randomUUID();
  const db = await pool.connect();
  try {
    await db.query('begin');
    // operationId-Idempotenz (rotate-owner-password pattern): the audit trail
    // is the source of truth; the guarded INSERT below refuses a duplicate
    // audit row for a replayed operation. The single-use token (consumed_at)
    // is the primary replay guard of this self-service flow.
    const prior = (await db.query<{ entity_id: string | null }>('select entity_id from audit_log where action = $1 and metadata->>\'operationId\' = $2 limit 2', [RESET_CONFIRM_AUDIT_ACTION, operationId])).rows;
    const resolved = (await db.query<{ user_id: string }>('select user_id from public.resolve_password_reset_user($1)', [hashSessionToken(token)])).rows;
    if (!resolved[0]?.user_id) throw new Error('RESET_TOKEN_INVALID');
    const userId = resolved[0].user_id;
    if (prior.length) {
      if (prior.some(r => r.entity_id !== userId)) throw new Error('RESET_TOKEN_INVALID');
      await db.query('commit');
      return json(toResetConfirmResponse(), 200, id as Parameters<typeof json>[2]);
    }
    // User context for the RLS-scoped writes below (session revoke + token
    // consume); app.tenant_id stays unset so the audit row lands in the
    // global-isolation branch (009 policy).
    await db.query("select set_config('app.user_id', $1, true)", [userId]);
    const updated = (await db.query<{ id: string }>('update users set password_hash=$1, updated_at=now() where id=$2 and status=\'active\' returning id', [passwordHash, userId])).rows;
    if (!updated[0]) throw new Error('RESET_TOKEN_INVALID');
    // Revoke ALL sessions — the reset itself bypasses MFA, so every existing
    // session dies and the next login must re-verify MFA (login flow requires
    // mfa_verified for memberships that need it).
    await db.query('update sessions set revoked_at=now() where user_id=$1 and revoked_at is null', [userId]);
    await db.query('update password_reset_tokens set consumed_at=now() where token_hash=$1 and consumed_at is null', [hashSessionToken(token)]);
    const audit = (await db.query<{ id: string }>('insert into audit_log(tenant_id,actor_user_id,action,entity_type,entity_id,metadata) select null, $1, $2, \'user\', $1, $3::jsonb where not exists (select 1 from audit_log where action = $2 and metadata->>\'operationId\' = $4) returning id', [userId, RESET_CONFIRM_AUDIT_ACTION, JSON.stringify({ operationId }), operationId])).rows;
    // Fail closed: a password change without an audit row must never commit
    // (RESET_AUDIT_FAILED is not a public code → INTERNAL_ERROR, tx rolled back).
    if (!audit[0]) throw new Error('RESET_AUDIT_FAILED');
    await db.query('commit');
    return json(toResetConfirmResponse(), 200, id as Parameters<typeof json>[2]);
  } catch (e) {
    try { await db.query('rollback'); } catch { /* preserve the original error */ }
    throw e;
  } finally {
    db.release();
  }
}

async function handleRequest(req: Request): Promise<Response> {const id=crypto.randomUUID();const headers=corsHeaders(req);if(req.method==='OPTIONS')return new Response(null,{status:204,headers});try{const u=new URL(req.url),parts=u.pathname.split('/').filter(Boolean);if(req.method==='GET'&&u.pathname==='/health')return publicHealthResponse(configured&&!initializationError&&dbReady&&pilotReady,headers);await waitForReadiness();
if(parts[0]==='api'&&parts[1]==='auth'&&parts[2]==='login'&&req.method==='POST'){if(!pool)throw new Error('DATABASE_REQUIRED');const ipKey=clientIpKey(req);if(!loginIpLimiter.allow(ipKey))throw new Error('RATE_LIMITED');const body=await req.json() as {email?:string,password?:string,mfaCode?:string};if(!body.email||!body.password)throw new Error('CREDENTIALS_REQUIRED');const accountKey=loginAccountKey(body.email);if(!loginAccountLimiter.allow(accountKey))throw new Error('RATE_LIMITED');const db=await pool.connect();try{await db.query('begin');const user=(await db.query<{id:string,password_hash:string,mfa_required:boolean,mfa_enabled:boolean,mfa_secret_ciphertext:string|null}>('select id,password_hash,mfa_required,mfa_enabled,mfa_secret_ciphertext from users where lower(email)=lower($1) and status=$2',[body.email,'active'])).rows[0];const passwordOk=user?.password_hash?await verifyPassword(body.password,user.password_hash):await verifyPasswordAgainstDummy(body.password);if(!user||!passwordOk)throw new Error('INVALID_CREDENTIALS');const mfaRow=(await db.query<{required:boolean|null}>('select public.membership_mfa_required($1) as required',[user.id])).rows[0];const required=requireVerifiedMfaBootstrap(mfaRow);if(required){if(!mfaStore||!user.mfa_secret_ciphertext)throw new Error('MFA_NOT_CONFIGURED');let secret:string;try{secret=await mfaStore.decrypt(user.mfa_secret_ciphertext);}catch{throw new Error('MFA_SECRET_DECRYPT_FAILED');}if(!body.mfaCode||!verifyTotp(secret,body.mfaCode))throw new Error('MFA_INVALID');}await db.query("select set_config('app.user_id', $1, true)",[user.id]);await db.query('update sessions set revoked_at=now() where user_id=$1 and revoked_at is null',[user.id]);const raw=randomToken(),csrf=randomToken();await db.query("insert into sessions(user_id,token_hash,csrf_token_hash,mfa_verified,expires_at) values($1,$2,$3,$4,now()+interval '12 hours')",[user.id,hashSessionToken(raw),hashSessionToken(csrf),required]);await db.query('commit');return json(toLoginResponse(hashSessionToken(csrf),required),200,id,{'Set-Cookie':sessionCookie(raw, 43200)});}catch(e){try{await db.query('rollback');}catch{}const reason=loginFailureReason(e);if(reason){console.warn(`login_failed request_id=${id} reason=${reason} account=${accountKey} ip=${ipKey}`);throw new Error('INVALID_CREDENTIALS');}throw e;}finally{db.release();}}
if(parts[0]==='api'&&parts[1]==='auth'&&parts[2]==='reset'&&parts[3]==='request'&&req.method==='POST')return await handleResetRequest(req,id);
if(parts[0]==='api'&&parts[1]==='auth'&&parts[2]==='reset'&&parts[3]==='confirm'&&req.method==='POST')return await handleResetConfirm(req,id);
if(parts[0]==='api'&&!configured)throw new Error('CONFIGURATION_REQUIRED');
// Public resolution requires the tenant in the URL; a token alone can never select across tenants.
    if(parts[0]==='api'&&parts[1]==='public'&&parts[2]==='tenants'&&parts[4]==='cards'&&req.method==='GET'){if(!repository||!cardResolveLimiter.allow(clientIpKey(req)))throw new Error(!repository?'DATABASE_REQUIRED':'RATE_LIMITED');const result=await repository.publicCard(parts[3],hashToken(parts[5]));if(!result)throw new Error('CARD_NOT_FOUND');
        if(parts[6]==='wallet'&&parts[7]==='google'&&parts[8]==='redirect'){const adapter=walletFactory('google',{oidcToken:req.headers.get('x-vercel-oidc-token')??undefined});const branding: Branding=safeBranding(result.branding) ?? {cardTitle:'StempelPass',cardText:'',primaryColor:DEFAULT_PRIMARY_CARD_COLOR,secondaryColor:DEFAULT_SECONDARY_CARD_COLOR,version:1};const rule: StampRule|null=result.rule;const value=await adapter.issue(toWalletCardView(result.card),branding,{stampRequired:rule?.stampsRequired,rewardTitle:rule?.rewardTitle});if(value.status!=='issued'||!value.artifact)throw new Error('WALLET_NOT_CONFIGURED');return new Response(null,{status:302,headers:{Location:`https://pay.google.com/gp/v/save/${encodeURIComponent(value.artifact)}`}});}
        if(parts[6]==='wallet'&&parts[7]==='google'){const artifact=walletAdapter('google',{oidcToken:req.headers.get('x-vercel-oidc-token')??undefined});const branding: Branding=safeBranding(result.branding) ?? {cardTitle:'StempelPass',cardText:'',primaryColor:DEFAULT_PRIMARY_CARD_COLOR,secondaryColor:DEFAULT_SECONDARY_CARD_COLOR,version:1};const rule: StampRule|null=result.rule;const value=await artifact.issue(toWalletCardView(result.card),branding,{stampRequired:rule?.stampsRequired,rewardTitle:rule?.rewardTitle});return json(value,200,id);}
        return json(toPublicCardResponse(result,parts[3]),200,id);}
    if(parts[0]==='card'&&parts.length===3&&req.method==='GET'){if(!repository||!cardResolveLimiter.allow(clientIpKey(req)))throw new Error(!repository?'DATABASE_REQUIRED':'RATE_LIMITED');const result=await repository.publicCard(parts[1],hashToken(parts[2]));if(!result)throw new Error('CARD_NOT_FOUND');const b: Branding=safeBranding(result.branding) ?? {cardTitle:'StempelPass',cardText:'',primaryColor:DEFAULT_PRIMARY_CARD_COLOR,secondaryColor:DEFAULT_SECONDARY_CARD_COLOR,version:1};const r: StampRule=result.rule ?? {id:'',tenantId:parts[1],name:'',stampsRequired:1,rewardTitle:'Prämie',rewardDescription:'',active:true,version:1};const esc=(v:unknown)=>String(v??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]!));const progress=Math.min(100,Math.round((result.card.stampCount/Math.max(1,Number(r.stampsRequired||1)))*100));return new Response(`<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(b.cardTitle||'StempelPass')}</title><style>body{font:16px system-ui;margin:0;padding:2rem;background:${esc(b.secondaryColor||'#f8fafc')};color:#172033}.card{max-width:28rem;margin:auto;padding:2rem;border-radius:1.5rem;background:white;border-top:1rem solid ${esc(b.primaryColor||'#155e75')};box-shadow:0 8px 30px #0002}progress{width:100%;accent-color:${esc(b.primaryColor||'#155e75')}}.privacy{margin-top:1.5rem;padding-top:1rem;border-top:1px solid #e2e8f0;font-size:.85rem;color:#475569}.privacy h3{margin:0 0 .4rem;font-size:inherit;color:#334155}.privacy p{margin:.4rem 0}</style><main class="card"><h1>${esc(b.cardTitle)}</h1><p>${esc(b.cardText)}</p><p><strong>${result.card.stampCount}</strong> / ${esc(r.stampsRequired)} Stempel</p><progress max="100" value="${progress}"></progress><h2>${esc(r.rewardTitle)}</h2><p>${esc(r.rewardDescription)}</p><a style="display:block;width:100%;box-sizing:border-box;text-align:center;background:${esc(b.primaryColor)};color:#fff;text-decoration:none;padding:.9rem 1rem;border-radius:.75rem;font-weight:600;margin-top:1.5rem" href="/api/public/tenants/${esc(parts[1])}/cards/${esc(parts[2])}/wallet/google/redirect">Zu Google Wallet hinzufügen</a><p style="margin:.5rem 0 0;font-size:.8rem;color:#475569;text-align:center">Auf dem Handy öffnen, um die Karte ins Wallet zu legen.</p><section class="privacy"><h3>Datenschutz</h3><p>${esc('Verantwortlich für die Verarbeitung: '+(result.controllerName||'<Tenant>'))}</p><p>${esc('Diese Stempelkarte speichert nur den Stempelstand und den Fortschritt zur Prämie. StempelPass Deutschland verarbeitet die Daten als Auftragsverarbeiter (Art. 28 DSGVO).')}</p><p>${esc('Die Karte wird nach 12 Monaten ohne Stempelaktivität deaktiviert. Kundendaten werden 30 Tage nach der Soft-Löschung endgültig gelöscht. Falls Sie Kommunikationsnachrichten erhalten oder eine Einwilligung erteilen, wird die Kommunikationshistorie 24 Monate gespeichert; der Nachweis Ihrer Einwilligung wird für einen Zeitraum von 3 Jahren nach Ihrem Widerruf gespeichert. Audit-Aufzeichnungen werden zur Beweissicherung dauerhaft aufbewahrt.')}</p>${result.privacyContact?'<p>'+esc('Sie haben das Recht auf Auskunft, Berichtigung, Löschung und Widerspruch. Kontakt für Anfragen: '+result.privacyContact)+'</p>':''}</section></main>`,{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'}});}
    if(parts[0]==='join'&&parts.length===2&&req.method==='GET'){if(!/^[a-f0-9]{32}$/i.test(parts[1]))throw new Error('ENTRY_POINT_NOT_FOUND');if(!repository||!cardResolveLimiter.allow(joinResolveKey(req,parts[1])))throw new Error(!repository?'DATABASE_REQUIRED':'RATE_LIMITED');const ctx=await repository.joinContext(parts[1]);if(!ctx)throw new Error('ENTRY_POINT_NOT_FOUND');const origin=new URL(req.url).origin;return htmlResponse(joinPageHtml(ctx,`${origin}${ctx.joinPath}`),200,{'Cache-Control':'public, max-age=60'});}
    if(parts[0]==='reset'&&parts.length===1&&req.method==='GET')return htmlResponse(resetRequestPage());
    if(parts[0]==='reset'&&parts.length===2&&req.method==='GET')return await handleResetPage(req);
    // -----------------------------------------------------------------
    // Staff web UI (server-rendered HTML, same auth/CSRF/rotation as the API)
    // -----------------------------------------------------------------
    if(parts[0]==='login'&&parts.length===1&&req.method==='GET')return new Response(loginPage(),{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'}});
    if(parts[0]==='staff'&&req.method==='GET'){
      if(parts.length===1)return handleStaffEntry(req,id);
      if(parts.length===2)return handleStaffDashboard(req,parts[1],id);
    }
    if(parts[0]==='staff'&&parts.length===3&&req.method==='POST'){
      if(parts[2]==='stamp')return handleStaffStamp(req,parts[1],id);
      if(parts[2]==='cards')return handleStaffCreateCard(req,parts[1],id);
      if(parts[2]==='redeem')return handleStaffRedeem(req,parts[1],id);
      if(parts[2]==='branding')return handleStaffBranding(req,parts[1],id);
      if(parts[2]==='logout')return handleStaffLogout(req,parts[1],id);
    }
    if(parts[0]!=='api'||parts[1]!=='tenants')return json({error:'NOT_FOUND'},404,id);const tenantId=parts[2];const actor=await auth(req,tenantId,req.method!=='GET');
    if(parts.length===3&&req.method==='DELETE'){if(actor.role!=='owner')throw new Error('FORBIDDEN');const value=await repository!.deleteTenant(tenantId);return json(toDeleteResponse(value),200,id);}
    if(parts[3]==='pilot'&&req.method==='PUT'){if(actor.role!=='owner'&&actor.role!=='admin')throw new Error('FORBIDDEN');const body=await req.json() as any;const value=await repository!.configurePilot(tenantId,actor.userId,{planCode:body.planCode,cardTitle:body.cardTitle||'',cardText:body.cardText||'',primaryColor:body.primaryColor||'',secondaryColor:body.secondaryColor||'',iconAssetId:body.iconAssetId,logoAssetId:body.logoAssetId,logoUrl:body.logoUrl,stampsRequired:body.stampsRequired,rewardTitle:body.rewardTitle||'',rewardDescription:body.rewardDescription||''});return json(toPilotResponse(value),200,id);}
    if(parts[3]==='entry-point'&&req.method==='GET')return json(await repository!.entryPoint(tenantId),200,id);
    if(parts[3]==='staff'&&req.method==='PUT'){if(actor.role!=='owner'&&actor.role!=='admin')throw new Error('FORBIDDEN');const body=await req.json() as {userId?:string;role?:'admin'|'staff'|'viewer';active?:boolean};const value=await repository!.setStaff(tenantId,actor.userId,body.userId||'',body.role||'staff',body.active!==false);return json(toStaffResponse(value),200,id);}
if(parts[3]==='logout'&&req.method==='POST'){await repository!.revokeSession(actor.userId,hashSessionToken(actor.token));return json({loggedOut:true},200,id,{'Set-Cookie':sessionCookie('', 0)});}
if(parts[3]==='capacity'&&req.method==='GET')return json(await repository!.capacity(tenantId),200,id);
if(parts[3]==='cards'&&parts.length===4&&req.method==='POST'){const body=await req.json() as {customerId?:string,ruleId?:string};if(!body.customerId||!body.ruleId)throw new Error('CARD_FIELDS_REQUIRED');const rawToken=randomToken();const idempotencyKey=req.headers.get('idempotency-key')?.trim()||undefined;const created=await repository!.createCard(tenantId,body.customerId,body.ruleId,hashToken(rawToken),idempotencyKey,rawToken);const {token, ...card}=created;return json(toCreateCardResponse(card,token ?? rawToken),201,id);}
if(parts[3]==='cards'&&parts.length===5&&req.method==='DELETE'){if(actor.role!=='owner'&&actor.role!=='admin')throw new Error('FORBIDDEN');const value=await repository!.deleteCard(tenantId,parts[4]);return json(toDeleteResponse(value),200,id);}
if(parts[3]==='customers'&&parts.length===5&&req.method==='DELETE'){if(actor.role!=='owner'&&actor.role!=='admin')throw new Error('FORBIDDEN');const value=await repository!.deleteCustomer(tenantId,parts[4]);return json(toDeleteResponse(value),200,id);}
if(parts[3]==='cards'&&parts[5]==='stamps'&&req.method==='POST'){if(!canStamp(actor.role))throw new Error('FORBIDDEN');if(!stampLimiter.allow(`${tenantId}:${actor.userId}`))throw new Error('RATE_LIMITED');const body=await req.json() as {quantity?:number};const idempotencyKey=req.headers.get('idempotency-key')||null;const value=await repository!.stamp(tenantId,parts[4],body.quantity??1,actor.membershipId,idempotencyKey);const rotated=await rotate(actor);await syncWalletBalance(tenantId,value.card,req.headers.get('x-vercel-oidc-token'));return json(toStampResponse(value),200,id,rotated.header);}
if(parts[3]==='rewards'&&parts[5]==='redeem'&&req.method==='POST'){if(!canStamp(actor.role))throw new Error('FORBIDDEN');const value=await repository!.redeem(tenantId,parts[4]);await syncWalletBalance(tenantId,value.card,req.headers.get('x-vercel-oidc-token'));const rotated=await rotate(actor);return json(toRedeemResponse(value),200,id,rotated.header);}
return json({error:'NOT_FOUND'},404,id);}catch(e){return error(e,id)}}

/** Apply response CORS after route handling so normal and error responses share the same policy. */
export async function fetchHandler(req: Request): Promise<Response> {
  const response = await handleRequest(req);
  const cors = corsHeaders(req);
  for (const [key, value] of Object.entries(cors)) response.headers.set(key, value);
  return response;
}

/**
 * Test-only dependency seam. Swaps the production database-backed runtime
 * (pool/repository) for an in-memory fake and optionally flips the configured
 * gate, then returns a restore function. Production behavior is byte-identical
 * while this is never called; the HTTP contract tests use it to drive the real
 * fetchHandler in-process against a scripted fake pool (no database, no
 * credentials). Never call this from application code.
 */
export function withTestDependencies(next: {
  configured?: boolean;
  pool?: DbPool | undefined;
  repository?: CardRepository | undefined;
  walletFactory?: typeof walletAdapter;
  emailFactory?: (() => SmtpEmailAdapter) | undefined;
}): () => void {
  const previous = { configured, pool, repository, dbReady, initializationError, pilotReady, walletFactory, emailFactory };
  if (next.configured !== undefined) configured = next.configured;
  pool = next.pool;
  repository = next.repository;
  if (next.walletFactory !== undefined) walletFactory = next.walletFactory;
  if (next.emailFactory !== undefined) emailFactory = next.emailFactory;
  // The seam injects an already-ready runtime (a scripted fake pool): bypass
  // the module-scope readiness gate so requests hit the fake pool directly.
  if (next.pool !== undefined) { dbReady = true; pilotReady = true; }
  return () => {
    configured = previous.configured;
    pool = previous.pool;
    repository = previous.repository;
    dbReady = previous.dbReady;
    initializationError = previous.initializationError;
    pilotReady = previous.pilotReady;
    walletFactory = previous.walletFactory;
  };
}

// Bun owns the long-running process; Vercel imports fetchHandler through api/index.ts.
if (process.env.VERCEL !== '1') {
  const server = Bun.serve({hostname:'0.0.0.0', port:Number(process.env.PORT||8787), fetch: fetchHandler});
  console.log(`StempelPass backend skeleton listening on ${server.url} (${configured?'POSTGRES':'NOT_CONFIGURED'})`);
}
