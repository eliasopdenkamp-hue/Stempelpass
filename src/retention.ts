/**
 * Operator-only, out-of-band retention hard-delete job.
 *
 * This module is intentionally not imported by the HTTP server. It is run with
 * `bun run db:retention` after the pilot operator has confirmed the applicable
 * legal-retention exceptions. It refuses Vercel request-path execution.
 */
import { createPostgresPool, type DbPool, type TxClient } from './db.js';
import { walletAdapter, type WalletAdapter } from './wallet.js';

export const RETENTION_LOCK_KEY = 742_005;
export const CUSTOMER_HARD_DELETE_RETENTION = '30 days';
export const REVOKED_SESSION_RETENTION = '7 days';
export const MESSAGE_LOG_RETENTION = '24 months';
export const CONSENT_EVENT_RETENTION_AFTER_REVOCATION = '3 years';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface RetentionEnv { tenantId: string | null }
export type ParseRetentionResult = { ok: true; value: RetentionEnv } | { ok: false; errors: string[] };

export function parseRetentionEnv(env: NodeJS.ProcessEnv = process.env): ParseRetentionResult {
  if (env.VERCEL === '1') return { ok: false, errors: ['RETENTION_NOT_ALLOWED_ON_VERCEL'] };
  const raw = env.RETENTION_TENANT_ID?.trim() ?? '';
  if (raw && !UUID_RE.test(raw)) return { ok: false, errors: ['INVALID_RETENTION_TENANT_ID'] };
  return { ok: true, value: { tenantId: raw || null } };
}

export const OPERATOR_ROLE_CHECK = `select exists (
  select 1 from pg_tables t
   where t.schemaname = 'public' and t.tablename = 'tenants'
     and pg_has_role(current_user, t.tableowner, 'member')
) as is_operator`;

export async function isOperatorRole(pool: DbPool): Promise<boolean> {
  const db = await pool.connect();
  try {
    const result = await db.query<{ is_operator: boolean }>(OPERATOR_ROLE_CHECK);
    return result.rows[0]?.is_operator === true;
  } finally { db.release(); }
}

interface RetentionCustomer { id: string; tenant_id: string }
interface RetentionCard { id: string }

const CANDIDATES_GLOBAL = `select id, tenant_id from customers
 where deleted_at is not null
   and deleted_at <= now() - interval '${CUSTOMER_HARD_DELETE_RETENTION}'
   and legal_retention_hold = false
 order by deleted_at, id`;
const CANDIDATES_TENANT = `select id, tenant_id from customers
 where tenant_id = $1
   and deleted_at is not null
   and deleted_at <= now() - interval '${CUSTOMER_HARD_DELETE_RETENTION}'
   and legal_retention_hold = false
 order by deleted_at, id`;

/** Counts only database rows actually removed; no ids are returned to callers. */
export interface RetentionCounts {
  sessionsDeleted: number;
  messageLogsRetentionDeleted: number;
  consentEventsRetentionDeleted: number;
  customersHardDeleted: number;
  cardsHardDeleted: number;
  communicationMessageLogsDeleted: number;
  communicationConsentEventsDeleted: number;
  communicationPreferencesDeleted: number;
  stampEventsDeleted: number;
  rewardsDeleted: number;
  cardCreationIdempotencyDeleted: number;
  walletRevocationAttempts: number;
}

const emptyCounts = (): RetentionCounts => ({
  sessionsDeleted: 0,
  messageLogsRetentionDeleted: 0,
  consentEventsRetentionDeleted: 0,
  customersHardDeleted: 0,
  cardsHardDeleted: 0,
  communicationMessageLogsDeleted: 0,
  communicationConsentEventsDeleted: 0,
  communicationPreferencesDeleted: 0,
  stampEventsDeleted: 0,
  rewardsDeleted: 0,
  cardCreationIdempotencyDeleted: 0,
  walletRevocationAttempts: 0,
});

async function deleteRows(db: TxClient, sql: string, params: unknown[]): Promise<number> {
  const result = await db.query<{ id: string | number }>(sql, params);
  return result.rows.length;
}

/**
 * Executes the retention DML on an already-open operator transaction holding
 * RETENTION_LOCK_KEY. Tenant predicates are repeated on every child delete so
 * a malformed/cross-tenant relationship can never widen the operation.
 */
export async function runRetention(db: TxClient, tenantId: string | null, wallet: WalletAdapter): Promise<RetentionCounts> {
  const counts = emptyCounts();
  const sessionSql = tenantId
    ? `delete from sessions where tenant_id = $1 and ((revoked_at is null and expires_at <= now()) or (revoked_at is not null and revoked_at <= now() - interval '${REVOKED_SESSION_RETENTION}')) returning id`
    : `delete from sessions where (revoked_at is null and expires_at <= now()) or (revoked_at is not null and revoked_at <= now() - interval '${REVOKED_SESSION_RETENTION}') returning id`;
  counts.sessionsDeleted = await deleteRows(db, sessionSql, tenantId ? [tenantId] : []);

  const messageLogsRetentionSql = tenantId
    ? `delete from communication_message_logs where tenant_id = $1 and created_at <= now() - interval '${MESSAGE_LOG_RETENTION}' returning id`
    : `delete from communication_message_logs where created_at <= now() - interval '${MESSAGE_LOG_RETENTION}' returning id`;
  counts.messageLogsRetentionDeleted = await deleteRows(db, messageLogsRetentionSql, tenantId ? [tenantId] : []);

  // Consent history is evidence of both opt-in and withdrawal. Retain it until
  // the customer's latest non-null withdrawal timestamp is older than the
  // owner-confirmed period; customers with no withdrawal remain untouched.
  const consentEventsRetentionSql = tenantId
    ? `delete from communication_consent_events e
 where e.tenant_id = $1
   and exists (
     select 1 from communication_preferences p
      where p.tenant_id = e.tenant_id
        and p.customer_id = e.customer_id
      group by p.tenant_id, p.customer_id
      having max(p.withdrawn_at) is not null
         and max(p.withdrawn_at) <= now() - interval '${CONSENT_EVENT_RETENTION_AFTER_REVOCATION}'
   )
 returning id`
    : `delete from communication_consent_events e
 where exists (
     select 1 from communication_preferences p
      where p.tenant_id = e.tenant_id
        and p.customer_id = e.customer_id
      group by p.tenant_id, p.customer_id
      having max(p.withdrawn_at) is not null
         and max(p.withdrawn_at) <= now() - interval '${CONSENT_EVENT_RETENTION_AFTER_REVOCATION}'
   )
 returning id`;
  counts.consentEventsRetentionDeleted = await deleteRows(
    db,
    consentEventsRetentionSql,
    tenantId ? [tenantId] : [],
  );

  const candidates = (tenantId
    ? await db.query<RetentionCustomer>(CANDIDATES_TENANT, [tenantId])
    : await db.query<RetentionCustomer>(CANDIDATES_GLOBAL)).rows;

  for (const customer of candidates) {
    const cards = (await db.query<RetentionCard>(
      'select id from cards where tenant_id = $1 and customer_id = $2 order by id',
      [customer.tenant_id, customer.id],
    )).rows;

    // External deactivation is deliberately before the database deletes. A
    // missing/offline Wallet API is non-fatal and revoke() logs only a stable
    // anonymous code. A later retry is safe (404 is treated as already absent).
    for (const card of cards) {
      counts.walletRevocationAttempts++;
      await wallet.revoke({ id: card.id, stampCount: 0 });
    }

    counts.communicationMessageLogsDeleted += await deleteRows(db,
      'delete from communication_message_logs where tenant_id = $1 and customer_id = $2 returning id',
      [customer.tenant_id, customer.id]);
    counts.communicationConsentEventsDeleted += await deleteRows(db,
      'delete from communication_consent_events where tenant_id = $1 and customer_id = $2 returning id',
      [customer.tenant_id, customer.id]);
    counts.communicationPreferencesDeleted += await deleteRows(db,
      'delete from communication_preferences where tenant_id = $1 and customer_id = $2 returning id',
      [customer.tenant_id, customer.id]);
    for (const card of cards) {
      counts.stampEventsDeleted += await deleteRows(db,
        'delete from stamp_events where tenant_id = $1 and card_id = $2 returning id',
        [customer.tenant_id, card.id]);
      counts.rewardsDeleted += await deleteRows(db,
        'delete from rewards where tenant_id = $1 and card_id = $2 returning id',
        [customer.tenant_id, card.id]);
      counts.cardCreationIdempotencyDeleted += await deleteRows(db,
        'delete from card_creation_idempotency where tenant_id = $1 and card_id = $2 returning idempotency_key',
        [customer.tenant_id, card.id]);
    }
    counts.cardsHardDeleted += await deleteRows(db,
      'delete from cards where tenant_id = $1 and customer_id = $2 returning id',
      [customer.tenant_id, customer.id]);
    counts.customersHardDeleted += await deleteRows(db,
      'delete from customers where tenant_id = $1 and id = $2 and legal_retention_hold = false returning id',
      [customer.tenant_id, customer.id]);
  }
  return counts;
}

export function formatRetentionResult(counts: RetentionCounts, durationMs: number): string[] {
  return [
    'retention_ok',
    `sessions_deleted=${counts.sessionsDeleted}`,
    `message_logs_retention_deleted=${counts.messageLogsRetentionDeleted}`,
    `consent_events_retention_deleted=${counts.consentEventsRetentionDeleted}`,
    `customers_hard_deleted=${counts.customersHardDeleted}`,
    `cards_hard_deleted=${counts.cardsHardDeleted}`,
    `communication_message_logs_deleted=${counts.communicationMessageLogsDeleted}`,
    `communication_consent_events_deleted=${counts.communicationConsentEventsDeleted}`,
    `communication_preferences_deleted=${counts.communicationPreferencesDeleted}`,
    `stamp_events_deleted=${counts.stampEventsDeleted}`,
    `rewards_deleted=${counts.rewardsDeleted}`,
    `card_creation_idempotency_deleted=${counts.cardCreationIdempotencyDeleted}`,
    `wallet_revoke_attempts=${counts.walletRevocationAttempts}`,
    `duration_ms=${Math.max(0, Math.round(durationMs))}`,
  ];
}

const SAFE_ERRORS = new Set([
  'DATABASE_URL_REQUIRED', 'RETENTION_ROLE_NOT_OPERATOR', 'RETENTION_NOT_ALLOWED_ON_VERCEL',
  'INVALID_RETENTION_TENANT_ID', 'RETENTION_FAILED',
]);
function safeRetentionError(error: unknown): string {
  const message = error instanceof Error ? error.message : '';
  return SAFE_ERRORS.has(message) ? message : 'RETENTION_FAILED';
}

export async function dbRetention(
  env: NodeJS.ProcessEnv = process.env,
  makePool: (url: string) => DbPool = createPostgresPool,
  makeWallet: () => WalletAdapter = () => walletAdapter('google'),
): Promise<number> {
  const started = Date.now();
  const parsed = parseRetentionEnv(env);
  if (!parsed.ok) {
    for (const code of parsed.errors) console.error(`retention_failed ${code} duration_ms=${Math.max(0, Date.now() - started)}`);
    return 1;
  }
  const url = env.DATABASE_URL?.trim();
  if (!url) {
    console.error(`retention_failed DATABASE_URL_REQUIRED duration_ms=${Math.max(0, Date.now() - started)}`);
    return 1;
  }
  let pool: DbPool | undefined;
  try {
    pool = makePool(url);
    if (!(await isOperatorRole(pool))) {
      console.error(`retention_failed RETENTION_ROLE_NOT_OPERATOR duration_ms=${Math.max(0, Date.now() - started)}`);
      return 1;
    }
    const db = await pool.connect();
    try {
      await db.query('begin');
      await db.query('select pg_advisory_xact_lock($1)', [RETENTION_LOCK_KEY]);
      const counts = await runRetention(db, parsed.value.tenantId, makeWallet());
      await db.query('commit');
      for (const line of formatRetentionResult(counts, Date.now() - started)) console.log(line);
      return 0;
    } catch (error) {
      try { await db.query('rollback'); } catch { /* preserve stable code */ }
      console.error(`retention_failed ${safeRetentionError(error)} duration_ms=${Math.max(0, Date.now() - started)}`);
      return 1;
    } finally { db.release(); }
  } catch (error) {
    console.error(`retention_failed ${safeRetentionError(error)} duration_ms=${Math.max(0, Date.now() - started)}`);
    return 1;
  } finally {
    try { await pool?.end?.(); } catch { /* best effort */ }
  }
}

if (import.meta.main) process.exit(await dbRetention());
