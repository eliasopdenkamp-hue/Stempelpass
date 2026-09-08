/**
 * Generic full-onboarding CLI — `bun run db:create-tenant`.
 *
 * All tenant and owner data is supplied through environment variables. This is
 * deliberately a CLI-only path: it hashes the owner password before opening a
 * database connection, runs the complete onboarding in one locked transaction,
 * and emits only anonymized ids/statuses (plus the public join path).
 */
import { createPostgresPool, type DbPool } from './db.js';
import { appendAudit, type DbClient } from './repository.js';
import { hashPassword } from './security.js';

/** Transaction-scoped lock reserved for full tenant onboarding. */
export const CREATE_TENANT_LOCK_KEY = 742_003;

const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const COLOR_RE = /^#[0-9a-f]{6}$/i;
const MAX_NAME_LENGTH = 200;
const MAX_TEXT_LENGTH = 2000;
const MIN_PASSWORD_LENGTH = 12;
const SCRYPT_HASH_RE = /^\$scrypt\$N=32768,r=8,p=1\$[A-Za-z0-9_-]{22}\$[A-Za-z0-9_-]{43}$/;

export interface CreateTenantInput {
  tenantSlug: string;
  tenantLegalName: string;
  tenantPlanCode: 'up_to_500' | 'up_to_1000';
  ownerEmail: string;
  ownerPassword: string;
  cardTitle: string;
  cardText: string;
  primaryColor: string;
  secondaryColor: string;
  stampsRequired: number;
  rewardTitle: string;
  rewardDescription: string;
  iconAssetId: string | null;
  logoAssetId: string | null;
  customerRef: string | null;
}

export type ParseCreateTenantResult =
  | { ok: true; input: CreateTenantInput }
  | { ok: false; errors: string[] };

function required(env: NodeJS.ProcessEnv, key: string): string {
  return env[key]?.trim() ?? '';
}

/** Pure env parser. Error codes never contain input values or secrets. */
export function parseCreateTenantEnv(env: NodeJS.ProcessEnv = process.env): ParseCreateTenantResult {
  if (env.VERCEL === '1') return { ok: false, errors: ['CREATE_TENANT_NOT_ALLOWED_ON_VERCEL'] };
  const errors: string[] = [];
  const tenantSlug = required(env, 'TENANT_SLUG');
  const tenantLegalName = required(env, 'TENANT_LEGAL_NAME');
  const tenantPlanCode = required(env, 'TENANT_PLAN_CODE');
  const ownerEmail = required(env, 'OWNER_EMAIL');
  const ownerPassword = env.OWNER_PASSWORD ?? '';
  const cardTitle = required(env, 'CARD_TITLE');
  const cardText = required(env, 'CARD_TEXT');
  const primaryColor = required(env, 'PRIMARY_COLOR');
  const secondaryColor = required(env, 'SECONDARY_COLOR');
  const stampsText = required(env, 'STAMPS_REQUIRED');
  const rewardTitle = required(env, 'REWARD_TITLE');
  const rewardDescription = required(env, 'REWARD_DESCRIPTION');
  const iconAssetId = required(env, 'ICON_ASSET_ID');
  const logoAssetId = required(env, 'LOGO_ASSET_ID');
  const customerRef = required(env, 'CUSTOMER_REF');

  if (!tenantSlug) errors.push('TENANT_SLUG_REQUIRED');
  else if (tenantSlug.length > 63 || !SLUG_RE.test(tenantSlug)) errors.push('INVALID_TENANT_SLUG');
  if (!tenantLegalName) errors.push('TENANT_LEGAL_NAME_REQUIRED');
  else if (tenantLegalName.length > MAX_NAME_LENGTH) errors.push('INVALID_TENANT_LEGAL_NAME');
  if (!['up_to_500', 'up_to_1000'].includes(tenantPlanCode)) errors.push(tenantPlanCode ? 'INVALID_TENANT_PLAN_CODE' : 'TENANT_PLAN_CODE_REQUIRED');
  if (!ownerEmail) errors.push('OWNER_EMAIL_REQUIRED');
  else if (ownerEmail.length > 254 || !EMAIL_RE.test(ownerEmail)) errors.push('INVALID_OWNER_EMAIL');
  if (!ownerPassword.trim()) errors.push('OWNER_PASSWORD_REQUIRED');
  else if (ownerPassword.length < MIN_PASSWORD_LENGTH) errors.push('PASSWORD_TOO_SHORT');
  if (!cardTitle) errors.push('CARD_TITLE_REQUIRED');
  else if (cardTitle.length > MAX_NAME_LENGTH) errors.push('INVALID_CARD_TITLE');
  if (!cardText) errors.push('CARD_TEXT_REQUIRED');
  else if (cardText.length > MAX_TEXT_LENGTH) errors.push('INVALID_CARD_TEXT');
  if (!COLOR_RE.test(primaryColor)) errors.push('INVALID_PRIMARY_COLOR');
  if (!COLOR_RE.test(secondaryColor)) errors.push('INVALID_SECONDARY_COLOR');
  if (!/^\d+$/.test(stampsText)) errors.push(stampsText ? 'INVALID_STAMPS_REQUIRED' : 'STAMPS_REQUIRED_REQUIRED');
  else if (Number(stampsText) < 1 || Number(stampsText) > 100) errors.push('INVALID_STAMPS_REQUIRED');
  if (!rewardTitle) errors.push('REWARD_TITLE_REQUIRED');
  else if (rewardTitle.length > MAX_NAME_LENGTH) errors.push('INVALID_REWARD_TITLE');
  if (!rewardDescription) errors.push('REWARD_DESCRIPTION_REQUIRED');
  else if (rewardDescription.length > MAX_TEXT_LENGTH) errors.push('INVALID_REWARD_DESCRIPTION');
  if (iconAssetId && !UUID_RE.test(iconAssetId)) errors.push('INVALID_ICON_ASSET_ID');
  if (logoAssetId && !UUID_RE.test(logoAssetId)) errors.push('INVALID_LOGO_ASSET_ID');
  if (customerRef.length > MAX_NAME_LENGTH) errors.push('INVALID_CUSTOMER_REF');
  if (errors.length) return { ok: false, errors };

  return {
    ok: true,
    input: {
      tenantSlug,
      tenantLegalName,
      tenantPlanCode: tenantPlanCode as CreateTenantInput['tenantPlanCode'],
      ownerEmail,
      ownerPassword,
      cardTitle,
      cardText,
      primaryColor,
      secondaryColor,
      stampsRequired: Number(stampsText),
      rewardTitle,
      rewardDescription,
      iconAssetId: iconAssetId || null,
      logoAssetId: logoAssetId || null,
      customerRef: customerRef || null,
    },
  };
}

export interface CreateTenantResult {
  tenant: { id: string; status: 'created' | 'exists' };
  owner: { id: string; status: 'created' | 'exists' };
  membership: { id: string; status: 'created' | 'exists'; role: string; membershipStatus: string };
  branding: { status: 'upserted' };
  rule: { id: string; status: 'created' | 'updated' };
  entryPoint: { joinPath: string; publicKey: string; status: 'upserted' };
  customer: { id: string; status: 'created' | 'exists' } | null;
}

function planLimit(planCode: CreateTenantInput['tenantPlanCode']): number {
  switch (planCode) {
    case 'up_to_500': return 500;
    case 'up_to_1000': return 1000;
    default: throw new Error('INVALID_TENANT_PLAN_CODE');
  }
}

/**
 * Full idempotent onboarding DML on a caller-owned locked transaction.
 *
 * The tenant row lock is part of the onboarding protocol: every configuration
 * writer (including CardRepository.configurePilot) must lock the tenant row
 * before inspecting or changing tenant-scoped branding/rules.
 */
export async function createTenantData(db: DbClient, input: CreateTenantInput, passwordHash: string): Promise<CreateTenantResult> {
  if (!SCRYPT_HASH_RE.test(passwordHash)) throw new Error('INVALID_PASSWORD_HASH_FORMAT');
  const customerLimit = planLimit(input.tenantPlanCode);
  // Existing tenants are locked before any onboarding DML. INSERT already
  // holds the row lock for a newly created tenant.
  const existingTenant = (await db.query<{ id: string; status: string }>('select id, status from tenants where slug = $1 for update', [input.tenantSlug])).rows[0];
  let tenant: CreateTenantResult['tenant'];
  if (existingTenant) {
    tenant = { id: existingTenant.id, status: 'exists' };
  } else {
    const created = (await db.query<{ id: string; status: string }>(
      'insert into tenants(slug, legal_name, plan_code, customer_limit, status) values($1, $2, $3, $4, $5) returning id, status',
      [input.tenantSlug, input.tenantLegalName, input.tenantPlanCode, customerLimit, 'active'],
    )).rows[0];
    if (!created?.id) throw new Error('TENANT_CREATE_FAILED');
    tenant = { id: created.id, status: 'created' };
  }

  await db.query("select set_config('app.tenant_id', $1, true)", [tenant.id]);

  const existingUser = (await db.query<{ id: string; status: string; password_hash: string | null }>(
    'select id, status, password_hash from users where lower(email) = lower($1)',
    [input.ownerEmail],
  )).rows[0];
  let owner: CreateTenantResult['owner'];
  if (existingUser) {
    owner = { id: existingUser.id, status: 'exists' };
    if (!existingUser.password_hash) {
      await db.query('update users set password_hash = $1, updated_at = now() where id = $2 and password_hash is null', [passwordHash, existingUser.id]);
    }
  } else {
    const created = (await db.query<{ id: string; status: string }>(
      'insert into users(email, display_name, password_hash, status) values($1, $2, $3, $4) returning id, status',
      [input.ownerEmail, null, passwordHash, 'active'],
    )).rows[0];
    if (!created?.id) throw new Error('USER_CREATE_FAILED');
    owner = { id: created.id, status: 'created' };
  }

  const existingMembership = (await db.query<{ id: string; role: string; status: string }>(
    'select id, role, status from tenant_memberships where tenant_id = $1 and user_id = $2',
    [tenant.id, owner.id],
  )).rows[0];
  let membership: CreateTenantResult['membership'];
  if (existingMembership) {
    membership = { id: existingMembership.id, status: 'exists', role: existingMembership.role, membershipStatus: existingMembership.status };
  } else {
    const created = (await db.query<{ id: string; role: string; status: string }>(
      "insert into tenant_memberships(tenant_id, user_id, role, status) values($1, $2, 'owner', 'active') returning id, role, status",
      [tenant.id, owner.id],
    )).rows[0];
    if (!created?.id) throw new Error('MEMBERSHIP_CREATE_FAILED');
    membership = { id: created.id, status: 'created', role: created.role, membershipStatus: created.status };
  }

  await db.query(
    'insert into tenant_branding(tenant_id,card_title,card_text,primary_color,secondary_color,icon_asset_id,logo_asset_id,version) values($1,$2,$3,$4,$5,$6,$7,1) on conflict(tenant_id) do update set card_title=excluded.card_title,card_text=excluded.card_text,primary_color=excluded.primary_color,secondary_color=excluded.secondary_color,icon_asset_id=excluded.icon_asset_id,logo_asset_id=excluded.logo_asset_id,version=tenant_branding.version+1,updated_at=now()',
    [tenant.id, input.cardTitle, input.cardText, input.primaryColor, input.secondaryColor, input.iconAssetId, input.logoAssetId],
  );

  const activeRules = (await db.query<{ id: string }>(
    'select id from stamp_rules where tenant_id = $1 and active = true order by created_at asc, id asc for update',
    [tenant.id],
  )).rows;
  let rule: CreateTenantResult['rule'];
  if (activeRules[0]) {
    await db.query(
      'update stamp_rules set name=$1,stamps_required=$2,reward_title=$3,reward_description=$4,active=true,version=version+1,updated_at=now() where tenant_id=$5 and id=$6',
      ['Standard-Regel', input.stampsRequired, input.rewardTitle, input.rewardDescription, tenant.id, activeRules[0].id],
    );
    if (activeRules.length > 1) {
      await db.query('update stamp_rules set active=false,updated_at=now() where tenant_id=$1 and active=true and id<>$2', [tenant.id, activeRules[0].id]);
    }
    rule = { id: activeRules[0].id, status: 'updated' };
  } else {
    const created = (await db.query<{ id: string }>(
      'insert into stamp_rules(tenant_id,name,stamps_required,reward_title,reward_description,active) values($1,$2,$3,$4,$5,$6) returning id',
      [tenant.id, 'Standard-Regel', input.stampsRequired, input.rewardTitle, input.rewardDescription, true],
    )).rows[0];
    if (!created?.id) throw new Error('RULE_CREATE_FAILED');
    rule = { id: created.id, status: 'created' };
  }

  const key = crypto.randomUUID().replaceAll('-', '');
  const entry = (await db.query<{ public_key: string; join_path: string }>(
    'insert into tenant_entry_points(tenant_id,public_key,join_path) values($1,$2,$3) on conflict(tenant_id) do update set updated_at=now() returning public_key,join_path',
    [tenant.id, key, `/join/${key}`],
  )).rows[0];
  if (!entry?.public_key || !entry.join_path) throw new Error('ENTRY_POINT_CREATE_FAILED');

  let customer: CreateTenantResult['customer'] = null;
  if (input.customerRef) {
    const existingCustomer = (await db.query<{ id: string; status: string }>(
      'select id, status from customers where tenant_id = $1 and external_ref = $2',
      [tenant.id, input.customerRef],
    )).rows[0];
    if (existingCustomer) {
      customer = { id: existingCustomer.id, status: 'exists' };
    } else {
      const created = (await db.query<{ id: string; status: string }>(
        'insert into customers(tenant_id, external_ref, status) values($1, $2, $3) returning id, status',
        [tenant.id, input.customerRef, 'active'],
      )).rows[0];
      if (!created?.id) throw new Error('CUSTOMER_CREATE_FAILED');
      customer = { id: created.id, status: 'created' };
    }
  }

  await appendAudit(db, {
    tenantId: tenant.id,
    actorUserId: owner.id,
    action: 'tenant.configured',
    entityType: 'tenant',
    entityId: tenant.id,
    metadata: { planCode: input.tenantPlanCode, customerLimit, ruleId: rule.id },
  });

  return {
    tenant,
    owner,
    membership,
    branding: { status: 'upserted' },
    rule,
    entryPoint: { publicKey: entry.public_key, joinPath: entry.join_path, status: 'upserted' },
    customer,
  };
}

/** Mask an internal id; only a short prefix is suitable for operator output. */
export function maskCreateTenantId(id: string): string {
  if (!id) return 'unknown';
  return id.length <= 8 ? '••••' : `${id.slice(0, 8)}…`;
}

export function formatCreateTenantResult(result: CreateTenantResult): string[] {
  const lines = ['create_tenant_ok'];
  lines.push(`tenant id=${maskCreateTenantId(result.tenant.id)} status=${result.tenant.status}`);
  lines.push(`owner id=${maskCreateTenantId(result.owner.id)} status=${result.owner.status}`);
  lines.push(`membership id=${maskCreateTenantId(result.membership.id)} status=${result.membership.status} role=${result.membership.role} membership_status=${result.membership.membershipStatus}`);
  lines.push(`branding status=${result.branding.status}`);
  lines.push(`stamp_rule id=${maskCreateTenantId(result.rule.id)} status=${result.rule.status}`);
  lines.push(`entry_point status=${result.entryPoint.status} join_path=${result.entryPoint.joinPath}`);
  lines.push(result.customer ? `customer id=${maskCreateTenantId(result.customer.id)} status=${result.customer.status}` : 'customer status=skipped');
  return lines;
}

function errorCode(error: unknown): string {
  const message = error instanceof Error ? error.message : '';
  return /^[A-Z][A-Z0-9_]+$/.test(message) ? message : 'INTERNAL_ERROR';
}

/** CLI orchestrator. Pool and hash factories are injectable for DB-free tests. */
export async function dbCreateTenant(
  env: NodeJS.ProcessEnv = process.env,
  makePool: (url: string) => DbPool = createPostgresPool,
  hashPasswordFn: (password: string) => Promise<string> = hashPassword,
): Promise<number> {
  const parsed = parseCreateTenantEnv(env);
  if (!parsed.ok) {
    for (const code of parsed.errors) console.error(`create_tenant_failed ${code}`);
    return 1;
  }
  const url = env.DATABASE_URL?.trim();
  if (!url) {
    console.error('create_tenant_failed DATABASE_URL_REQUIRED');
    return 1;
  }

  // Hash before makePool/connect/BEGIN: no SQL can precede password hashing.
  let passwordHash: string;
  try {
    passwordHash = await hashPasswordFn(parsed.input.ownerPassword);
  } catch (error) {
    console.error(`create_tenant_failed ${errorCode(error)}`);
    return 1;
  }

  let pool: DbPool | undefined;
  try {
    pool = makePool(url);
    const db = await pool.connect();
    try {
      await db.query('begin');
      await db.query('select pg_advisory_xact_lock($1)', [CREATE_TENANT_LOCK_KEY]);
      const result = await createTenantData(db, parsed.input, passwordHash);
      await db.query('commit');
      for (const line of formatCreateTenantResult(result)) console.log(line);
      return 0;
    } catch (error) {
      try { await db.query('rollback'); } catch { /* preserve the onboarding error */ }
      throw error;
    } finally {
      db.release();
    }
  } catch (error) {
    console.error(`create_tenant_failed ${errorCode(error)}`);
    return 1;
  } finally {
    try { await pool?.end?.(); } catch { /* best-effort shutdown */ }
  }
}

if (import.meta.main) {
  process.exit(await dbCreateTenant());
}
