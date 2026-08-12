/**
 * One-time pilot seed CLI — `bun run db:seed-pilot`.
 *
 * Creates (idempotently) the pilot tenant, the owner user, the owner
 * membership and — only when PILOT_CUSTOMER_REF is provided — one test
 * customer. It reads EVERYTHING from the environment:
 *
 *   PILOT_TENANT_SLUG        required — tenant slug (lowercase, [a-z0-9-])
 *   PILOT_TENANT_LEGAL_NAME  required — tenant legal/business name
 *   PILOT_OWNER_EMAIL        required — owner login email
 *   PILOT_OWNER_PASSWORD     required — owner password (hashed, never stored
 *                            or printed; must be >= 12 chars)
 *   PILOT_CUSTOMER_REF       optional — external reference of one test customer
 *
 * Security contract (do not weaken):
 *   - The password is hashed with the application's `hashPassword` (scrypt,
 *     N=32768, r=8, p=1) before any SQL is issued and is never written to
 *     disk, committed, logged or printed. No default password exists.
 *   - No owner data is hardcoded; the runbook uses placeholders only.
 *   - The command NEVER runs on the Vercel request path: it is a pure CLI
 *     (`import.meta.main` guard) and additionally refuses to run when
 *     VERCEL=1 is set (defense in depth against a misconfigured deploy).
 *   - Output is anonymized: masked ids and statuses only. Slug, legal name,
 *     email, customer reference and the password never appear on stdout.
 *   - The seed runs under the operator/owner database connection (the same
 *     assumption as `bun run db:migrate`): a single transaction holding the
 *     transaction-scoped advisory lock PILOT_SEED_LOCK_KEY, with
 *     app.tenant_id set transaction-locally for consistency with application
 *     transactions. The owner role bypasses RLS; the seed never relies on a
 *     non-owner role.
 *   - Idempotency: an existing tenant/user/membership/customer is kept
 *     exactly as-is. The password hash is only written when the user has none
 *     yet — re-runs never silently reset an existing password.
 *
 * Runbook: see PILOT_ONBOARDING.md ("Einmaliger Pilot-Seed").
 */
import { createPostgresPool, type DbPool } from './db.js';
import { classifyError } from './http-error.js';
import { appendAudit, type DbClient } from './repository.js';
import { hashPassword } from './security.js';

/**
 * Transaction-scoped advisory lock serializing the one-time pilot seed. Must
 * never be reused for migrations (MIGRATION_LOCK_KEY = 742_001) or any other
 * application-level lock.
 */
export const PILOT_SEED_LOCK_KEY = 742_002;

export interface PilotSeedInput {
  tenantSlug: string;
  tenantLegalName: string;
  ownerEmail: string;
  ownerPassword: string;
  customerRef: string | null;
}

export type ParsePilotSeedResult =
  | { ok: true; input: PilotSeedInput }
  | { ok: false; errors: string[] };

const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_NAME_LENGTH = 200;
const MIN_PASSWORD_LENGTH = 12;

/**
 * Env validation — pure and DB-free. Errors are stable codes; no input value
 * is ever echoed back. `VERCEL=1` is a hard block: the seed must never run on
 * the Vercel request path.
 */
export function parsePilotSeedEnv(env: NodeJS.ProcessEnv = process.env): ParsePilotSeedResult {
  if (env.VERCEL === '1') return { ok: false, errors: ['SEED_NOT_ALLOWED_ON_VERCEL'] };
  const errors: string[] = [];
  const tenantSlug = env.PILOT_TENANT_SLUG?.trim() ?? '';
  const tenantLegalName = env.PILOT_TENANT_LEGAL_NAME?.trim() ?? '';
  const ownerEmail = env.PILOT_OWNER_EMAIL?.trim() ?? '';
  const ownerPassword = env.PILOT_OWNER_PASSWORD ?? '';
  const customerRef = env.PILOT_CUSTOMER_REF?.trim() ?? '';
  if (!tenantSlug) errors.push('PILOT_TENANT_SLUG_REQUIRED');
  else if (tenantSlug.length > 63 || !SLUG_RE.test(tenantSlug)) errors.push('INVALID_TENANT_SLUG');
  if (!tenantLegalName) errors.push('PILOT_TENANT_LEGAL_NAME_REQUIRED');
  else if (tenantLegalName.length > MAX_NAME_LENGTH) errors.push('INVALID_LEGAL_NAME');
  if (!ownerEmail) errors.push('PILOT_OWNER_EMAIL_REQUIRED');
  else if (ownerEmail.length > 254 || !EMAIL_RE.test(ownerEmail)) errors.push('INVALID_OWNER_EMAIL');
  if (!ownerPassword) errors.push('PILOT_OWNER_PASSWORD_REQUIRED');
  else if (ownerPassword.length < MIN_PASSWORD_LENGTH) errors.push('PASSWORD_TOO_SHORT');
  if (customerRef.length > MAX_NAME_LENGTH) errors.push('INVALID_CUSTOMER_REF');
  if (errors.length) return { ok: false, errors };
  return {
    ok: true,
    input: {
      tenantSlug,
      tenantLegalName,
      ownerEmail,
      ownerPassword,
      customerRef: customerRef || null,
    },
  };
}

export interface PilotSeedResult {
  tenant: { id: string; status: 'created' | 'exists' };
  owner: { id: string; status: 'created' | 'exists' };
  membership: { id: string; status: 'created' | 'exists'; role: string; membershipStatus: string };
  customer: { id: string; status: 'created' | 'exists' } | null;
}

/**
 * Idempotent seed DML. Runs on a caller-owned connection that must already be
 * inside the transaction holding PILOT_SEED_LOCK_KEY (see dbSeedPilot) —
 * mirroring the repository's transaction/RLS-operator assumption.
 *
 * The tenant plan is fixed to the released pilot configuration
 * (up_to_500 / 500 customers); `PUT /api/tenants/{id}/pilot` later adjusts
 * plan, branding and stamp rule through the authenticated API.
 */
export async function seedPilotData(db: DbClient, input: PilotSeedInput, passwordHash: string): Promise<PilotSeedResult> {
  // 1. Tenant (idempotent by slug). An existing tenant is kept as-is — the
  //    seed never changes plan, limit or status.
  const existingTenant = (await db.query<{ id: string; status: string }>('select id, status from tenants where slug = $1', [input.tenantSlug])).rows[0];
  let tenant: { id: string; status: 'created' | 'exists' };
  if (existingTenant) {
    tenant = { id: existingTenant.id, status: 'exists' };
  } else {
    const created = (await db.query<{ id: string; status: string }>(
      "insert into tenants(slug, legal_name, plan_code, customer_limit) values($1, $2, 'up_to_500', 500) returning id, status",
      [input.tenantSlug, input.tenantLegalName],
    )).rows[0];
    if (!created?.id) throw new Error('TENANT_CREATE_FAILED');
    tenant = { id: created.id, status: 'created' };
  }
  // Tenant-scoped context, consistent with application transactions (the
  // operator/owner connection bypasses RLS; the context keeps the audit write
  // and any future RLS-constrained run well-defined).
  await db.query("select set_config('app.tenant_id', $1, true)", [tenant.id]);
  // 2. Owner user (idempotent by lower(email), matching the login path).
  const existingUser = (await db.query<{ id: string; status: string; password_hash: string | null }>(
    'select id, status, password_hash from users where lower(email) = lower($1)',
    [input.ownerEmail],
  )).rows[0];
  let owner: { id: string; status: 'created' | 'exists' };
  if (existingUser) {
    owner = { id: existingUser.id, status: 'exists' };
    // Never overwrite an existing password; only fill the hash when the user
    // has none yet (e.g. a user row created without credentials).
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
  // 3. Owner membership (idempotent; existing role/status are never changed).
  const existingMembership = (await db.query<{ id: string; role: string; status: string }>(
    'select id, role, status from tenant_memberships where tenant_id = $1 and user_id = $2',
    [tenant.id, owner.id],
  )).rows[0];
  let membership: { id: string; status: 'created' | 'exists'; role: string; membershipStatus: string };
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
  // 4. Optional test customer (idempotent by tenant_id + external_ref).
  let customer: { id: string; status: 'created' | 'exists' } | null = null;
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
  // 5. Append-only audit, minimal metadata (no PII beyond internal ids).
  await appendAudit(db, {
    tenantId: tenant.id,
    actorUserId: owner.id,
    action: 'pilot.seeded',
    entityType: 'tenant',
    entityId: tenant.id,
    metadata: { planCode: 'up_to_500', customerLimit: 500, ownerUserId: owner.id },
  });
  return { tenant, owner, membership, customer };
}

/** Mask an internal id for anonymized console output (never full UUIDs). */
export function maskId(id: string): string {
  if (!id) return 'unknown';
  return id.length <= 8 ? '••••' : `${id.slice(0, 8)}…`;
}

/** Anonymized stdout lines: masked ids and statuses only. */
export function formatPilotSeedResult(result: PilotSeedResult): string[] {
  const lines = ['pilot_seed_ok'];
  lines.push(`tenant id=${maskId(result.tenant.id)} status=${result.tenant.status}`);
  lines.push(`owner id=${maskId(result.owner.id)} status=${result.owner.status}`);
  lines.push(
    `membership id=${maskId(result.membership.id)} status=${result.membership.status} role=${result.membership.role} membership_status=${result.membership.membershipStatus}`,
  );
  lines.push(result.customer
    ? `customer id=${maskId(result.customer.id)} status=${result.customer.status}`
    : 'customer status=skipped');
  return lines;
}

/**
 * CLI body. `makePool` is injectable so the DB-free unit tests can script a
 * fake pool; production always uses the real postgres.js pool factory.
 * Returns the process exit code (0 success, 1 failure).
 */
export async function dbSeedPilot(
  env: NodeJS.ProcessEnv = process.env,
  makePool: (url: string) => DbPool = createPostgresPool,
): Promise<number> {
  const parsed = parsePilotSeedEnv(env);
  if (!parsed.ok) {
    for (const code of parsed.errors) console.error(`pilot_seed_failed ${code}`);
    return 1;
  }
  const url = env.DATABASE_URL?.trim();
  if (!url) {
    console.error('pilot_seed_failed DATABASE_URL_REQUIRED');
    return 1;
  }
  let passwordHash: string;
  try {
    passwordHash = await hashPassword(parsed.input.ownerPassword);
  } catch (error) {
    console.error('pilot_seed_failed', seedErrorText(error));
    return 1;
  }
  let pool: DbPool | undefined;
  try {
    pool = makePool(url);
    const db = await pool.connect();
    try {
      await db.query('begin');
      await db.query('select pg_advisory_xact_lock($1)', [PILOT_SEED_LOCK_KEY]);
      const result = await seedPilotData(db, parsed.input, passwordHash);
      await db.query('commit');
      for (const line of formatPilotSeedResult(result)) console.log(line);
      return 0;
    } catch (error) {
      try { await db.query('rollback'); } catch { /* preserve the seed error */ }
      throw error;
    } finally {
      db.release();
    }
  } catch (error) {
    console.error('pilot_seed_failed', seedErrorText(error));
    return 1;
  } finally {
    try { await pool?.end?.(); } catch { /* best-effort shutdown */ }
  }
}

/** Sanitized one-liner for stderr: stable code, else redacted detail. */
function seedErrorText(error: unknown): string {
  const classified = classifyError(error);
  return classified.detail ?? classified.code;
}

if (import.meta.main) {
  process.exit(await dbSeedPilot());
}
