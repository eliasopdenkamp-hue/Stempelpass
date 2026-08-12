import { assertTenant, canStamp, hashToken } from './domain.js';
import { cardResolveLimiter, clientIpKey, csrfValid, joinResolveKey, loginAccountKey, loginAccountLimiter, loginFailureReason, loginIpLimiter, stampLimiter, verifyPassword, verifyPasswordAgainstDummy, randomToken, hashSessionToken } from './security.js';
import { createPostgresPool, runMigrations, type DbPool } from './db.js';
import { CardRepository } from './repository.js';
import { configurationStatus } from './config.js';
import { EncryptedMfaSecretStore, verifyTotp } from './mfa.js';
import { walletAdapter } from './wallet.js';
import { classifyError } from './http-error.js';
import { DEFAULT_PRIMARY_CARD_COLOR, DEFAULT_SECONDARY_CARD_COLOR, safeBranding, toPublicCardResponse, toWalletCardView } from './public-card.js';
import { publicHealthResponse } from './health.js';
import { requireVerifiedMfaBootstrap } from './mfa-bootstrap.js';
import { toCreateCardResponse, toJoinResponse, toLoginResponse, toPilotResponse, toRedeemResponse, toStaffResponse, toStampResponse } from './contracts.js';
import type { Branding, StampRule } from './domain.js';
const config=configurationStatus(); let configured=config.ready;
const corsOrigin = process.env.FRONTEND_ORIGIN || process.env.PUBLIC_SITE_ORIGIN || '';
/** Credentialed CORS is granted only to the one explicitly configured origin. */
const corsHeaders = (req: Request): HeadersInit => {
  const headers: Record<string, string> = { Vary: 'Origin' };
  const requestOrigin = req.headers.get('origin');
  if (corsOrigin && requestOrigin === corsOrigin) {
    headers['Access-Control-Allow-Origin'] = corsOrigin;
    headers['Access-Control-Allow-Credentials'] = 'true';
    headers['Access-Control-Allow-Headers'] = 'Content-Type, x-csrf-token, idempotency-key';
    headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,OPTIONS';
  }
  return headers;
};
let pool:DbPool|undefined; let repository:CardRepository|undefined;
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
async function auth(req:Request,tenantId:string,mutating=true){if(!pool||!repository)throw new Error('DATABASE_REQUIRED');const token=cookie(req,'__Host-sp_session');if(!token)throw new Error('UNAUTHENTICATED');const db=await pool.connect();try{await db.query('begin');await db.query("select set_config('app.tenant_id', $1, true)",[tenantId]);const resolved=await db.query<{user_id:string}>('select user_id from public.resolve_session_user($1)',[hashSessionToken(token)]);if(!resolved.rows[0]?.user_id)throw new Error('UNAUTHENTICATED');await db.query("select set_config('app.user_id', $1, true)",[resolved.rows[0].user_id]);const rows=await db.query<{id:string,user_id:string,csrf_token_hash:string,tenant_id:string,role:string;membership_id:string;mfa_required:boolean;mfa_verified:boolean}>('select s.id,s.user_id,s.csrf_token_hash,s.mfa_verified,m.id as membership_id,m.tenant_id,m.role,(u.mfa_required or m.mfa_required) as mfa_required from sessions s join users u on u.id=s.user_id join tenant_memberships m on m.user_id=s.user_id and m.status=$2 where s.token_hash=$1 and s.revoked_at is null and s.expires_at>now() and m.tenant_id=$3 and u.status=$4',[hashSessionToken(token),'active',tenantId,'active']);const s=rows.rows[0];if(!s)throw new Error('UNAUTHENTICATED');if(s.mfa_required&&!s.mfa_verified)throw new Error('MFA_REQUIRED');if(mutating&&!csrfValid(req,s.csrf_token_hash))throw new Error('CSRF_INVALID');assertTenant(tenantId,s.tenant_id);const actor={userId:s.user_id,role:s.role as any,sessionId:s.id,membershipId:s.membership_id,token,mfaVerified:s.mfa_verified};await db.query('commit');return actor;}catch(e){try{await db.query('rollback');}catch{}throw e;}finally{db.release();}}
async function rotate(a:{userId:string;token:string;mfaVerified:boolean}){if(!pool||!repository)throw new Error('DATABASE_REQUIRED');const db=await pool.connect();try{await db.query('begin');await db.query("select set_config('app.user_id', $1, true)",[a.userId]);await db.query('update sessions set revoked_at=now() where token_hash=$1',[hashSessionToken(a.token)]);const raw=randomToken(),csrf=randomToken();await db.query("insert into sessions(user_id,token_hash,csrf_token_hash,mfa_verified,expires_at) values($1,$2,$3,$4,now()+interval '12 hours')",[a.userId,hashSessionToken(raw),hashSessionToken(csrf),a.mfaVerified]);await db.query('commit');return {csrf,header:{'Set-Cookie':`__Host-sp_session=${raw}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=43200`,'x-csrf-token':hashSessionToken(csrf)}}}catch(e){try{await db.query('rollback');}catch{}throw e;}finally{db.release();}}
async function handleRequest(req: Request): Promise<Response> {const id=crypto.randomUUID();const headers=corsHeaders(req);if(req.method==='OPTIONS')return new Response(null,{status:204,headers});try{const u=new URL(req.url),parts=u.pathname.split('/').filter(Boolean);if(req.method==='GET'&&u.pathname==='/health')return publicHealthResponse(configured&&!initializationError&&dbReady&&pilotReady,headers);await waitForReadiness();
if(parts[0]==='api'&&parts[1]==='auth'&&parts[2]==='login'&&req.method==='POST'){if(!pool)throw new Error('DATABASE_REQUIRED');const ipKey=clientIpKey(req);if(!loginIpLimiter.allow(ipKey))throw new Error('RATE_LIMITED');const body=await req.json() as {email?:string,password?:string,mfaCode?:string};if(!body.email||!body.password)throw new Error('CREDENTIALS_REQUIRED');const accountKey=loginAccountKey(body.email);if(!loginAccountLimiter.allow(accountKey))throw new Error('RATE_LIMITED');const db=await pool.connect();try{await db.query('begin');const user=(await db.query<{id:string,password_hash:string,mfa_required:boolean,mfa_enabled:boolean,mfa_secret_ciphertext:string|null}>('select id,password_hash,mfa_required,mfa_enabled,mfa_secret_ciphertext from users where lower(email)=lower($1) and status=$2',[body.email,'active'])).rows[0];const passwordOk=user?.password_hash?await verifyPassword(body.password,user.password_hash):await verifyPasswordAgainstDummy(body.password);if(!user||!passwordOk)throw new Error('INVALID_CREDENTIALS');const mfaRow=(await db.query<{required:boolean|null}>('select public.membership_mfa_required($1) as required',[user.id])).rows[0];const required=requireVerifiedMfaBootstrap(mfaRow);if(required){if(!mfaStore||!user.mfa_secret_ciphertext)throw new Error('MFA_NOT_CONFIGURED');let secret:string;try{secret=await mfaStore.decrypt(user.mfa_secret_ciphertext);}catch{throw new Error('MFA_SECRET_DECRYPT_FAILED');}if(!body.mfaCode||!verifyTotp(secret,body.mfaCode))throw new Error('MFA_INVALID');}await db.query("select set_config('app.user_id', $1, true)",[user.id]);await db.query('update sessions set revoked_at=now() where user_id=$1 and revoked_at is null',[user.id]);const raw=randomToken(),csrf=randomToken();await db.query("insert into sessions(user_id,token_hash,csrf_token_hash,mfa_verified,expires_at) values($1,$2,$3,$4,now()+interval '12 hours')",[user.id,hashSessionToken(raw),hashSessionToken(csrf),required]);await db.query('commit');return json(toLoginResponse(hashSessionToken(csrf),required),200,id,{'Set-Cookie':`__Host-sp_session=${raw}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=43200`});}catch(e){try{await db.query('rollback');}catch{}const reason=loginFailureReason(e);if(reason){console.warn(`login_failed request_id=${id} reason=${reason} account=${accountKey} ip=${ipKey}`);throw new Error('INVALID_CREDENTIALS');}throw e;}finally{db.release();}}
if(parts[0]==='api'&&!configured)throw new Error('CONFIGURATION_REQUIRED');
// Public resolution requires the tenant in the URL; a token alone can never select across tenants.
    if(parts[0]==='api'&&parts[1]==='public'&&parts[2]==='tenants'&&parts[4]==='cards'&&req.method==='GET'){if(!repository||!cardResolveLimiter.allow(clientIpKey(req)))throw new Error(!repository?'DATABASE_REQUIRED':'RATE_LIMITED');const result=await repository.publicCard(parts[3],hashToken(parts[5]));if(!result)throw new Error('CARD_NOT_FOUND');
        if(parts[6]==='wallet'&&parts[7]==='google'){const artifact=walletAdapter('google',{oidcToken:req.headers.get('x-vercel-oidc-token')??undefined});const branding: Branding=safeBranding(result.branding) ?? {cardTitle:'StempelPass',cardText:'',primaryColor:DEFAULT_PRIMARY_CARD_COLOR,secondaryColor:DEFAULT_SECONDARY_CARD_COLOR,version:1};const rule: StampRule|null=result.rule;const value=await artifact.issue(toWalletCardView(result.card),branding,{stampRequired:rule?.stampsRequired,rewardTitle:rule?.rewardTitle});return json(value,200,id);}
        return json(toPublicCardResponse(result,parts[3]),200,id);}
    if(parts[0]==='card'&&parts.length===3&&req.method==='GET'){if(!repository||!cardResolveLimiter.allow(clientIpKey(req)))throw new Error(!repository?'DATABASE_REQUIRED':'RATE_LIMITED');const result=await repository.publicCard(parts[1],hashToken(parts[2]));if(!result)throw new Error('CARD_NOT_FOUND');const b: Branding=safeBranding(result.branding) ?? {cardTitle:'StempelPass',cardText:'',primaryColor:DEFAULT_PRIMARY_CARD_COLOR,secondaryColor:DEFAULT_SECONDARY_CARD_COLOR,version:1};const r: StampRule=result.rule ?? {id:'',tenantId:parts[1],name:'',stampsRequired:1,rewardTitle:'Prämie',rewardDescription:'',active:true,version:1};const esc=(v:unknown)=>String(v??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]!));const progress=Math.min(100,Math.round((result.card.stampCount/Math.max(1,Number(r.stampsRequired||1)))*100));return new Response(`<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(b.cardTitle||'StempelPass')}</title><style>body{font:16px system-ui;margin:0;padding:2rem;background:${esc(b.secondaryColor||'#f8fafc')};color:#172033}.card{max-width:28rem;margin:auto;padding:2rem;border-radius:1.5rem;background:white;border-top:1rem solid ${esc(b.primaryColor||'#155e75')};box-shadow:0 8px 30px #0002}progress{width:100%;accent-color:${esc(b.primaryColor||'#155e75')}}</style><main class="card"><h1>${esc(b.cardTitle)}</h1><p>${esc(b.cardText)}</p><p><strong>${result.card.stampCount}</strong> / ${esc(r.stampsRequired)} Stempel</p><progress max="100" value="${progress}"></progress><h2>${esc(r.rewardTitle)}</h2><p>${esc(r.rewardDescription)}</p></main>`,{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'}});}
    if(parts[0]==='join'&&parts.length===2&&req.method==='GET'){if(!/^[a-f0-9]{32}$/i.test(parts[1]))throw new Error('ENTRY_POINT_NOT_FOUND');if(!repository||!cardResolveLimiter.allow(joinResolveKey(req,parts[1])))throw new Error(!repository?'DATABASE_REQUIRED':'RATE_LIMITED');const entry=await repository.resolveEntryPoint(parts[1]);if(!entry)throw new Error('ENTRY_POINT_NOT_FOUND');return json(toJoinResponse({tenantId:entry.tenant_id,joinPath:entry.join_path,customerLoginRequired:false,customerAccountRequired:false}),200,id);}
    if(parts[0]!=='api'||parts[1]!=='tenants')return json({error:'NOT_FOUND'},404,id);const tenantId=parts[2];const actor=await auth(req,tenantId,req.method!=='GET');
    if(parts[3]==='pilot'&&req.method==='PUT'){if(actor.role!=='owner'&&actor.role!=='admin')throw new Error('FORBIDDEN');const body=await req.json() as any;const value=await repository!.configurePilot(tenantId,actor.userId,{planCode:body.planCode,cardTitle:body.cardTitle||'',cardText:body.cardText||'',primaryColor:body.primaryColor||'',secondaryColor:body.secondaryColor||'',iconAssetId:body.iconAssetId,logoAssetId:body.logoAssetId,stampsRequired:body.stampsRequired,rewardTitle:body.rewardTitle||'',rewardDescription:body.rewardDescription||''});return json(toPilotResponse(value),200,id);}
    if(parts[3]==='entry-point'&&req.method==='GET')return json(await repository!.entryPoint(tenantId),200,id);
    if(parts[3]==='staff'&&req.method==='PUT'){if(actor.role!=='owner'&&actor.role!=='admin')throw new Error('FORBIDDEN');const body=await req.json() as {userId?:string;role?:'admin'|'staff'|'viewer';active?:boolean};const value=await repository!.setStaff(tenantId,actor.userId,body.userId||'',body.role||'staff',body.active!==false);return json(toStaffResponse(value),200,id);}
if(parts[3]==='logout'&&req.method==='POST'){await repository!.revokeSession(actor.userId,hashSessionToken(actor.token));return json({loggedOut:true},200,id,{'Set-Cookie':'__Host-sp_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'});}
if(parts[3]==='capacity'&&req.method==='GET')return json(await repository!.capacity(tenantId),200,id);
if(parts[3]==='cards'&&parts.length===4&&req.method==='POST'){const body=await req.json() as {customerId?:string,ruleId?:string};if(!body.customerId||!body.ruleId)throw new Error('CARD_FIELDS_REQUIRED');const rawToken=randomToken();const card=await repository!.createCard(tenantId,body.customerId,body.ruleId,hashToken(rawToken));return json(toCreateCardResponse(card,rawToken),201,id);}
if(parts[3]==='cards'&&parts[5]==='stamps'&&req.method==='POST'){if(!canStamp(actor.role))throw new Error('FORBIDDEN');if(!stampLimiter.allow(`${tenantId}:${actor.userId}`))throw new Error('RATE_LIMITED');const body=await req.json() as {quantity?:number};const idempotencyKey=req.headers.get('idempotency-key')||null;const value=await repository!.stamp(tenantId,parts[4],body.quantity??1,actor.membershipId,idempotencyKey);const rotated=await rotate(actor);return json(toStampResponse(value),200,id,rotated.header);}
if(parts[3]==='rewards'&&parts[5]==='redeem'&&req.method==='POST'){if(!canStamp(actor.role))throw new Error('FORBIDDEN');const value=await repository!.redeem(tenantId,parts[4]);const rotated=await rotate(actor);return json(toRedeemResponse(value),200,id,rotated.header);}
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
}): () => void {
  const previous = { configured, pool, repository, dbReady, initializationError, pilotReady };
  if (next.configured !== undefined) configured = next.configured;
  pool = next.pool;
  repository = next.repository;
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
  };
}

// Bun owns the long-running process; Vercel imports fetchHandler through api/index.ts.
if (process.env.VERCEL !== '1') {
  const server = Bun.serve({hostname:'0.0.0.0', port:Number(process.env.PORT||8787), fetch: fetchHandler});
  console.log(`StempelPass backend skeleton listening on ${server.url} (${configured?'POSTGRES':'NOT_CONFIGURED'})`);
}
