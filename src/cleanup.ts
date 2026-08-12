/**
 * DSGVO cleanup CLI — `bun run db:cleanup`.
 *
 * Operator-only housekeeping per BACKUP_RUNBOOK.md §3.5/§3.6 (Entwurf):
 *   1. Deletes expired sessions (`revoked_at is null and expires_at <= now()`)
 *      via CardRepository.cleanupExpiredSessions.
 *   2. Soft-deletes cards whose `updated_at` is older than the inactivity
 *      retention (default: 12 months) — `deleted_at` + `status='inactive'`,
 *      never a hard delete.
 *   3. Optionally (CLEANUP_DELETE_INACTIVE_CUSTOMERS=1) soft-deletes inactive
 *      customers AND their active cards with the same retention.
 *   4. Counts audit rows older than the audit retention (default: 24 months)
 *      and only REPORTS the count — audit_log is append-only
 *      (prevent_audit_mutation) and is deliberately NOT deleted.
 *
 * Guard rails (do not weaken):
 *   - Refuses to run when VERCEL=1 (never on the request path).
 *   - Refuses to run when the connected role is not the table-owning operator
 *     role (e.g. neondb_owner): the sessions cleanup needs the owner bypass of
 *     the user-scoped sessions RLS (migration 009). The app runtime role can
 *     never perform a global sessions delete.
 *   - Reads everything from the environment:
 *       CLEANUP_TENANT_ID                optional — restrict to one tenant
 *                                        (UUID); absent = all tenants
 *       CLEANUP_DELETE_INACTIVE_CUSTOMERS=1 — opt-in customer retention
 *   - Output is anonymized: counts and masked ids only, no tenant slug,
 *     no emails, no tokens, no full ids.
 *   - Runs under the transaction-scoped advisory lock CLEANUP_LOCK_KEY.
 *
 * Runbook: BACKUP_RUNBOOK.md §3.5 (Sessions), §5 Nr. 7 (Fristen-Entwurf).
 */
import { createPostgresPool, type DbPool } from './db.js';
import { classifyError } from './http-error.js';
import { CardRepository, type DbClient } from './repository.js';

/** Transaction-scoped advisory lock serializing cleanup runs. Must never be
 *  reused for migrations (742_001) or the pilot seed (742_002). */
export const CLEANUP_LOCK_KEY = 742_003;

/**
 * Default-Entwurf, Owner-Freigabe offen (BACKUP_RUNBOOK.md §5 Nr. 7):
 * Karten-Inaktivität 12 Monate, Audit-Belege 24 Monate. Die Fristen sind
 * Konstanten, keine Laufzeitparameter — eine Owner-Entscheidung ändert sie im
 * Code und nicht über die Umgebung (bewusst konservativ).
 */
export const CARD_INACTIVITY_RETENTION = '12 months';
export const AUDIT_RETENTION = '24 months';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface CleanupEnv {
  tenantId: string | null;
  deleteInactiveCustomers: boolean;
}

export type ParseCleanupResult = { ok: true; value: CleanupEnv } | { ok: false; errors: string[] };

/** Env validation — pure and DB-free. `VERCEL=1` is a hard block. */
export function parseCleanupEnv(env: NodeJS.ProcessEnv = process.env): ParseCleanupResult {
  if (env.VERCEL === '1') return { ok: false, errors: ['CLEANUP_NOT_ALLOWED_ON_VERCEL'] };
  const errors: string[] = [];
  const tenantId = env.CLEANUP_TENANT_ID?.trim() ?? '';
  if (tenantId && !UUID_RE.test(tenantId)) errors.push('INVALID_CLEANUP_TENANT_ID');
  const deleteInactiveCustomers = env.CLEANUP_DELETE_INACTIVE_CUSTOMERS === '1';
  if (errors.length) return { ok: false, errors };
  return { ok: true, value: { tenantId: tenantId || null, deleteInactiveCustomers } };
}

/**
 * Operator-role guard: the connected role must be (a member of) the owner of
 * the `tenants` table — i.e. the neondb_owner-like operator role, never the
 * RLS-bound app runtime role. The check is role-name agnostic (no role name
 * is ever printed) and only returns a boolean.
 */
export const OPERATOR_ROLE_CHECK = `select exists (
  select 1 from pg_tables t
   where t.schemaname = 'public' and t.tablename = 'tenants'
     and pg_has_role(current_user, t.tableowner, 'member')
) as is_operator`;

export async function isOperatorRole(pool: DbPool): Promise<boolean> {
  const db = await pool.connect();
  try {
    const r = await db.query<{ is_operator: boolean }>(OPERATOR_ROLE_CHECK);
    return r.rows[0]?.is_operator === true;
  } finally {
    db.release();
  }
}

/** Tenant-scoped variant of a statement (param 1 = tenant id). */
const CARD_INACTIVITY_TENANT = `update cards set status='inactive',deleted_at=now(),updated_at=now() where tenant_id=$1 and deleted_at is null and status='active' and updated_at < now() - interval '${CARD_INACTIVITY_RETENTION}' returning id`;
/** Global variant (operator connection bypasses RLS; no tenant context). */
const CARD_INACTIVITY_GLOBAL = `update cards set status='inactive',deleted_at=now(),updated_at=now() where deleted_at is null and status='active' and updated_at < now() - interval '${CARD_INACTIVITY_RETENTION}' returning id`;

const CUSTOMERS_INACTIVITY_TENANT = `update customers set status='inactive',deleted_at=now(),updated_at=now() where tenant_id=$1 and deleted_at is null and status='active' and updated_at < now() - interval '${CARD_INACTIVITY_RETENTION}' returning id`;
const CUSTOMERS_INACTIVITY_GLOBAL = `update customers set status='inactive',deleted_at=now(),updated_at=now() where deleted_at is null and status='active' and updated_at < now() - interval '${CARD_INACTIVITY_RETENTION}' returning id`;

/** Cards of the retained-inactive customers — same soft-delete semantics as
 *  deleteCustomer (FK-order: cards before customers). */
const CARDS_OF_INACTIVE_CUSTOMERS_TENANT = `update cards set status='inactive',deleted_at=now(),updated_at=now() where tenant_id=$1 and deleted_at is null and status='active' and customer_id in (select id from customers where tenant_id=$1 and deleted_at is null and status='active' and updated_at < now() - interval '${CARD_INACTIVITY_RETENTION}') returning id`;
const CARDS_OF_INACTIVE_CUSTOMERS_GLOBAL = `update cards set status='inactive',deleted_at=now(),updated_at=now() where deleted_at is null and status='active' and customer_id in (select id from customers where deleted_at is null and status='active' and updated_at < now() - interval '${CARD_INACTIVITY_RETENTION}') returning id`;

/** Audit rows beyond the retention — counted, reported, NEVER deleted
 *  (audit_log is append-only; deletion needs the documented out-of-band
 *  trigger procedure, BACKUP_RUNBOOK.md §3.5). */
const AUDIT_RETENTION_TENANT = `select count(*)::int as n from audit_log where tenant_id=$1 and created_at < now() - interval '${AUDIT_RETENTION}'`;
const AUDIT_RETENTION_GLOBAL = `select count(*)::int as n from audit_log where created_at < now() - interval '${AUDIT_RETENTION}'`;

export interface CleanupCounts {
  cardsSoftDeleted: number;
  customersSoftDeleted: number;
  auditRetentionEligible: number;
}

/**
 * Inactivity-retention DML on a caller-owned connection that must already be
 * inside the transaction holding CLEANUP_LOCK_KEY. Tenant-scoped statements
 * set `app.tenant_id` (consistent with application transactions); the global
 * mode relies on the operator role's owner bypass and runs without tenant
 * context. Conservative by default: customers are only touched when
 * `deleteInactiveCustomers` is explicitly set.
 */
export async function runInactivityCleanup(
  db: DbClient,
  tenantId: string | null,
  deleteInactiveCustomers: boolean,
): Promise<CleanupCounts> {
  const cardStmt = tenantId
    ? { sql: CARD_INACTIVITY_TENANT, params: [tenantId] }
    : { sql: CARD_INACTIVITY_GLOBAL, params: [] };
  const cards = await db.query<{ id: string }>(cardStmt.sql, cardStmt.params);
  let customersSoftDeleted = 0;
  if (deleteInactiveCustomers) {
    const customerCardsStmt = tenantId
      ? { sql: CARDS_OF_INACTIVE_CUSTOMERS_TENANT, params: [tenantId] }
      : { sql: CARDS_OF_INACTIVE_CUSTOMERS_GLOBAL, params: [] };
    await db.query<{ id: string }>(customerCardsStmt.sql, customerCardsStmt.params);
    const customerStmt = tenantId
      ? { sql: CUSTOMERS_INACTIVITY_TENANT, params: [tenantId] }
      : { sql: CUSTOMERS_INACTIVITY_GLOBAL, params: [] };
    const customers = await db.query<{ id: string }>(customerStmt.sql, customerStmt.params);
    customersSoftDeleted = customers.rows.length;
  }
  const auditStmt = tenantId
    ? { sql: AUDIT_RETENTION_TENANT, params: [tenantId] }
    : { sql: AUDIT_RETENTION_GLOBAL, params: [] };
  const audit = await db.query<{ n: number }>(auditStmt.sql, auditStmt.params);
  return { cardsSoftDeleted: cards.rows.length, customersSoftDeleted, auditRetentionEligible: Number(audit.rows[0]?.n ?? 0) };
}

/** Anonymized stdout lines: counts only (no ids at all). */
export function formatCleanupResult(sessionsDeleted: number, counts: CleanupCounts): string[] {
  const lines = ['cleanup_ok'];
  lines.push(`sessions_deleted=${sessionsDeleted}`);
  lines.push(`cards_inactive_soft_deleted=${counts.cardsSoftDeleted}`);
  lines.push(`customers_inactive_soft_deleted=${counts.customersSoftDeleted}`);
  lines.push(`audit_retention_eligible=${counts.auditRetentionEligible} retained_append_only`);
  return lines;
}

/**
 * CLI body. `makePool` is injectable so the DB-free unit tests can script a
 * fake pool; production always uses the real postgres.js pool factory.
 * Returns the process exit code (0 success, 1 failure).
 */
export async function dbCleanup(
  env: NodeJS.ProcessEnv = process.env,
  makePool: (url: string) => DbPool = createPostgresPool,
): Promise<number> {
  const parsed = parseCleanupEnv(env);
  if (!parsed.ok) {
    for (const code of parsed.errors) console.error(`cleanup_failed ${code}`);
    return 1;
  }
  const url = env.DATABASE_URL?.trim();
  if (!url) {
    console.error('cleanup_failed DATABASE_URL_REQUIRED');
    return 1;
  }
  let pool: DbPool | undefined;
  try {
    pool = makePool(url);
    // Operator-role guard BEFORE any DML: the app role must never run this.
    if (!(await isOperatorRole(pool))) {
      console.error('cleanup_failed CLEANUP_ROLE_NOT_OPERATOR');
      return 1;
    }
    const repository = new CardRepository(pool);
    // 1. Expired sessions (own transaction; operator bypasses user-scoped RLS).
    const sessionsDeleted = await repository.cleanupExpiredSessions(parsed.value.tenantId);
    // 2./3./4. Inactivity retention + audit count in one transaction.
    const db = await pool.connect();
    try {
      await db.query('begin');
      if (parsed.value.tenantId) await db.query("select set_config('app.tenant_id', $1, true)", [parsed.value.tenantId]);
      await db.query('select pg_advisory_xact_lock($1)', [CLEANUP_LOCK_KEY]);
      const counts = await runInactivityCleanup(db, parsed.value.tenantId, parsed.value.deleteInactiveCustomers);
      await db.query('commit');
      for (const line of formatCleanupResult(sessionsDeleted, counts)) console.log(line);
      return 0;
    } catch (error) {
      try { await db.query('rollback'); } catch { /* preserve the cleanup error */ }
      throw error;
    } finally {
      db.release();
    }
  } catch (error) {
    console.error('cleanup_failed', cleanupErrorText(error));
    return 1;
  } finally {
    try { await pool?.end?.(); } catch { /* best-effort shutdown */ }
  }
}

/** Sanitized one-liner for stderr: stable code, else redacted detail. */
function cleanupErrorText(error: unknown): string {
  const classified = classifyError(error);
  return classified.detail ?? classified.code;
}

if (import.meta.main) {
  process.exit(await dbCleanup());
}
