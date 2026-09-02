/**
 * Deterministisches, destruktives Retention-Harness fuer eine Wegwerf-DB.
 *
 * Sicherheitsvertrag:
 * - Es wird ausschliesslich TEST_DATABASE_URL gelesen.
 * - Pooler-Hostnamen werden auf eine Direct-Verbindung umgeschrieben.
 * - VERCEL=1 und fehlende Test-URL brechen vor jeder DB-Aktion ab.
 * - Fixtures verwenden feste UUIDs und werden vorab nur in diesen beiden
 *   Fixture-Tenants bereinigt. Niemals gegen eine Produktions-URL ausfuehren.
 *
 * Dieses Skript wird bewusst nicht automatisch ausgefuehrt. Ein Folgeauftrag
 * erstellt den Nachweis und dokumentiert die Lauf-Ergebnisse.
 */
import postgres from 'postgres';
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CONSENT_EVENT_RETENTION_AFTER_REVOCATION,
  CUSTOMER_HARD_DELETE_RETENTION,
  dbRetention,
  MESSAGE_LOG_RETENTION,
  RETENTION_LOCK_KEY,
  REVOKED_SESSION_RETENTION,
  runRetention,
  type RetentionCounts,
} from '../src/retention.js';
import type { DbPool, TxClient } from '../src/db.js';
import type { WalletAdapter } from '../src/wallet.js';

const TEST_ROLE = 'stempelpass_runtime';
const INVALID_ROLE = 'retention_invalid_role';
const STATEMENT_TIMEOUT_MS = 30_000;
const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), '../migrations');

const REQUIRED_GRANTS: Readonly<Record<string, readonly string[]>> = {
  tenants: ['SELECT', 'UPDATE'],
  users: ['SELECT'],
  sessions: ['SELECT', 'INSERT', 'UPDATE'],
  tenant_memberships: ['SELECT', 'INSERT', 'UPDATE'],
  customers: ['SELECT', 'UPDATE'],
  tenant_branding: ['SELECT', 'INSERT', 'UPDATE'],
  stamp_rules: ['SELECT', 'INSERT'],
  cards: ['SELECT', 'INSERT', 'UPDATE'],
  stamp_events: ['SELECT', 'INSERT'],
  rewards: ['SELECT', 'INSERT', 'UPDATE'],
  audit_log: ['INSERT'],
  tenant_entry_points: ['SELECT', 'INSERT', 'UPDATE'],
  communication_preferences: ['SELECT', 'INSERT', 'UPDATE'],
  communication_consent_events: ['SELECT', 'INSERT', 'UPDATE'],
  communication_message_logs: ['SELECT', 'INSERT', 'UPDATE'],
  schema_migrations: ['SELECT', 'INSERT'],
  card_creation_idempotency: ['SELECT', 'INSERT', 'UPDATE'],
};
const REQUIRED_FUNCTION_GRANTS = [
  'resolve_entry_point(text):EXECUTE',
  'resolve_session_user(text):EXECUTE',
  'membership_mfa_required(uuid):EXECUTE',
] as const;
const TABLES = [
  'sessions', 'communication_message_logs', 'communication_consent_events',
  'communication_preferences', 'stamp_events', 'rewards', 'cards', 'customers',
  'card_creation_idempotency',
] as const;
type CountTable = typeof TABLES[number];
type Row = Record<string, unknown>;

interface QueryConnection {
  unsafe<T = Row[]>(sql: string, params?: unknown[]): Promise<T>;
  release(): void;
}
interface HarnessSql {
  reserve(): Promise<QueryConnection>;
  end(options?: { timeout?: number }): Promise<void>;
}
interface FixtureSnapshot { [table: string]: number }
interface JobResult {
  exitCode: number;
  logs: string[];
  counts?: RetentionCounts;
  errorCode?: string;
}
interface Check { name: string; expected: unknown; actual: unknown; pass: boolean }

class HarnessFailure extends Error {
  constructor(readonly code: string, readonly details: unknown = undefined) {
    super(code);
  }
}

const IDS = {
  tenantA: '00000000-0000-4000-8000-000000000001',
  tenantB: '00000000-0000-4000-8000-000000000002',
  userA: '00000000-0000-4000-8000-000000000101',
  userB: '00000000-0000-4000-8000-000000000102',
  memberA: '00000000-0000-4000-8000-000000000201',
  memberB: '00000000-0000-4000-8000-000000000202',
  ruleA: '00000000-0000-4000-8000-000000000301',
  ruleB: '00000000-0000-4000-8000-000000000302',
  activeA: '00000000-0000-4000-8000-000000000401',
  soft29A: '00000000-0000-4000-8000-000000000402',
  staleA: '00000000-0000-4000-8000-000000000403',
  consentRecentA: '00000000-0000-4000-8000-000000000404',
  consentOldA: '00000000-0000-4000-8000-000000000405',
  consentNeverA: '00000000-0000-4000-8000-000000000406',
  staleB: '00000000-0000-4000-8000-000000000407',
  cardA: '00000000-0000-4000-8000-000000000501',
  cardB: '00000000-0000-4000-8000-000000000502',
  stampA: '00000000-0000-4000-8000-000000000601',
  rewardA: '00000000-0000-4000-8000-000000000701',
} as const;

function directUrl(raw: string): string {
  const url = new URL(raw.trim());
  url.hostname = url.hostname.replace(/-pooler(?=\.|$)/, '');
  url.searchParams.set('connect_timeout', '10');
  url.searchParams.set('statement_timeout', String(STATEMENT_TIMEOUT_MS));
  // Bound lock waits explicitly: a stale disposable-DB session must fail fast,
  // not leave the validation harness looking hung while holding its xact lock.
  url.searchParams.set('lock_timeout', '5000');
  return url.toString();
}

function openSql(rawUrl: string): HarnessSql {
  return postgres(directUrl(rawUrl), {
    max: 1,
    connect_timeout: 10,
    idle_timeout: 20,
    prepare: false,
  }) as unknown as HarnessSql;
}

async function query<T extends Row = Row>(db: QueryConnection, sql: string, params: unknown[] = []): Promise<T[]> {
  return await db.unsafe<T[]>(sql, params);
}
async function exec(db: QueryConnection, sql: string, params: unknown[] = []): Promise<void> {
  await db.unsafe(sql, params);
}
async function count(db: QueryConnection, table: CountTable, tenantIds: string[]): Promise<number> {
  const rows = await query<{ count: string | number }>(db, `select count(*)::int as count from ${table} where tenant_id = any($1::uuid[])`, [tenantIds]);
  return Number(rows[0]?.count ?? 0);
}
async function snapshot(db: QueryConnection, tenantIds: string[]): Promise<FixtureSnapshot> {
  const result: FixtureSnapshot = {};
  for (const table of TABLES) result[table] = await count(db, table, tenantIds);
  return result;
}
function minusDays(now: Date, days: number): Date {
  return new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
}
function minusMonths(now: Date, months: number): Date {
  const result = new Date(now);
  result.setUTCMonth(result.getUTCMonth() - months);
  return result;
}
function minusYears(now: Date, years: number): Date {
  const result = new Date(now);
  result.setUTCFullYear(result.getUTCFullYear() - years);
  return result;
}
function hash(value: string): string { return createHash('sha256').update(value).digest('hex'); }
function jsonEqual(left: unknown, right: unknown): boolean { return JSON.stringify(left) === JSON.stringify(right); }
function allZero(counts: RetentionCounts): boolean {
  return Object.values(counts).every(value => value === 0);
}
function quoteIdentifier(value: string): string { return `"${value.replaceAll('"', '""')}"`; }

/** Keep setup and grant checks on the authenticated admin context, never on a
 * role left behind by the negative-path CLI probe. */
async function resetHarnessContext(db: QueryConnection): Promise<void> {
  await exec(db, 'reset role');
  await exec(db, 'set search_path to public, pg_catalog');
}

async function prepareMigrations(db: QueryConnection): Promise<void> {
  await exec(db, 'set search_path to public, pg_catalog');
  await exec(db, 'create table if not exists schema_migrations (version text primary key, applied_at timestamptz not null default now())');
  const files = (await readdir(MIGRATIONS_DIR)).filter(file => /^\d+_.+\.sql$/.test(file)).sort();
  for (const file of files) {
    const done = await query<{ version: string }>(db, 'select version from schema_migrations where version = $1', [file]);
    if (done.length) continue;
    const migration = await readFile(join(MIGRATIONS_DIR, file), 'utf8');
    await exec(db, 'begin');
    try {
      await exec(db, 'set local search_path to public, pg_catalog');
      await exec(db, migration);
      await exec(db, 'insert into schema_migrations(version) values($1)', [file]);
      await exec(db, 'commit');
    } catch (error) {
      await exec(db, 'rollback').catch(() => undefined);
      throw new HarnessFailure(`MIGRATION_FAILED_${file}`, error instanceof Error ? undefined : undefined);
    }
  }
}

async function grantCheckContext(db: QueryConnection): Promise<{ currentUser: string; sessionUser: string; searchPath: string }> {
  const rows = await query<{ current_user: string; session_user: string; search_path: string }>(db, 'select current_user::text as current_user, session_user::text as session_user, current_setting(\'search_path\')::text as search_path');
  return { currentUser: rows[0]?.current_user ?? 'unknown', sessionUser: rows[0]?.session_user ?? 'unknown', searchPath: rows[0]?.search_path ?? 'unknown' };
}

async function checkGrant(
  db: QueryConnection,
  object: { kind: string; schema?: string; name: string; signature?: string },
  privilege: string,
  statement: string,
  params: unknown[],
): Promise<boolean> {
  const context = await grantCheckContext(db);
  try {
    const rows = await query<{ granted: boolean }>(db, statement, params);
    const granted = rows[0]?.granted === true;
    console.error(JSON.stringify({ retention_grant_check: { context, object, privilege, result: granted } }));
    return granted;
  } catch (error) {
    const code = typeof error === 'object' && error !== null && 'code' in error ? String((error as { code?: unknown }).code) : 'unknown';
    console.error(JSON.stringify({ retention_grant_check: { context, object, privilege, result: 'error', code } }));
    throw error;
  }
}

async function verifyRuntimeGrants(db: QueryConnection): Promise<void> {
  const roleRows = await query<{ exists: boolean }>(db, 'select exists(select 1 from pg_roles where rolname = $1) as exists', [TEST_ROLE]);
  if (!roleRows[0]?.exists) throw new HarnessFailure('RETENTION_RUNTIME_ROLE_MISSING', { role: TEST_ROLE });
  const missing: string[] = [];
  const tables = Object.entries(REQUIRED_GRANTS);
  for (const [table, privileges] of tables) {
    for (const privilege of privileges) {
      const granted = await checkGrant(db, { kind: 'table', schema: 'public', name: table }, privilege, 'select has_table_privilege($1::name, $2::text, $3::text) as granted', [TEST_ROLE, `public.${table}`, privilege]);
      if (!granted) missing.push(`${table}:${privilege}`);
    }
  }
  const schemaGranted = await checkGrant(db, { kind: 'schema', name: 'public' }, 'USAGE', 'select has_schema_privilege($1::name, $2::text, \'USAGE\') as granted', [TEST_ROLE, 'public']);
  if (!schemaGranted) missing.push('public:USAGE');
  for (const required of REQUIRED_FUNCTION_GRANTS) {
    const match = required.match(/^([^(:]+)\(([^)]*)\):EXECUTE$/)!;
    const signature = `public.${match[1]}(${match[2]})`;
    const granted = await checkGrant(db, { kind: 'function', schema: 'public', name: match[1], signature }, 'EXECUTE', 'select has_function_privilege($1::name, $2::text, \'EXECUTE\') as granted', [TEST_ROLE, signature]);
    if (!granted) missing.push(required);
  }
  if (missing.length) throw new HarnessFailure('RETENTION_RUNTIME_GRANTS_MISSING', { missing });
}

async function cleanupFixtures(db: QueryConnection): Promise<void> {
  const tenants = [IDS.tenantA, IDS.tenantB];
  for (const tenant of tenants) {
    for (const table of ['card_creation_idempotency', 'stamp_events', 'rewards', 'cards', 'communication_message_logs', 'communication_consent_events', 'communication_preferences', 'audit_log', 'sessions'] as const) {
      await exec(db, `delete from ${table} where tenant_id = $1`, [tenant]);
    }
    await exec(db, 'delete from customers where tenant_id = $1', [tenant]);
    await exec(db, 'delete from tenant_memberships where tenant_id = $1', [tenant]);
    await exec(db, 'delete from tenant_branding where tenant_id = $1', [tenant]);
    await exec(db, 'delete from stamp_rules where tenant_id = $1', [tenant]);
    await exec(db, 'delete from tenant_entry_points where tenant_id = $1', [tenant]);
    await exec(db, 'delete from tenants where id = $1', [tenant]);
  }
  await exec(db, 'delete from users where id = any($1::uuid[])', [[IDS.userA, IDS.userB]]);
}

async function insertFixtures(db: QueryConnection): Promise<void> {
  const now = new Date();
  const d29 = minusDays(now, 29);
  const d31 = minusDays(now, 31);
  const d6 = minusDays(now, 6);
  const d8 = minusDays(now, 8);
  const m23 = minusMonths(now, 23);
  const m25 = minusMonths(now, 25);
  const y2 = minusYears(now, 2);
  const y35 = minusYears(now, 3.5);
  const future = new Date(now.getTime() + 24 * 60 * 60 * 1000);

  await exec(db, 'insert into tenants(id, slug, legal_name, plan_code, customer_limit) values ($1,$2,$3,$4,$5),($6,$7,$8,$9,$10)', [
    IDS.tenantA, 'retention-validation-a', 'Retention Validation A', 'up_to_500', 500,
    IDS.tenantB, 'retention-validation-b', 'Retention Validation B', 'up_to_500', 500,
  ]);
  await exec(db, 'insert into users(id, email, display_name, auth_subject) values ($1,$2,$3,$4),($5,$6,$7,$8)', [
    IDS.userA, 'retention-validation-a@example.invalid', 'Validation A', 'retention-validation-a-subject',
    IDS.userB, 'retention-validation-b@example.invalid', 'Validation B', 'retention-validation-b-subject',
  ]);
  await exec(db, 'insert into tenant_memberships(id, tenant_id, user_id, role) values ($1,$2,$3,\'staff\'),($4,$5,$6,\'staff\')', [IDS.memberA, IDS.tenantA, IDS.userA, IDS.memberB, IDS.tenantB, IDS.userB]);
  await exec(db, 'insert into stamp_rules(id, tenant_id, name, stamps_required, reward_title, reward_description) values ($1,$2,\'Validation rule A\',10,\'Fixture reward\',\'Fixture only\'),($3,$4,\'Validation rule B\',10,\'Fixture reward\',\'Fixture only\')', [IDS.ruleA, IDS.tenantA, IDS.ruleB, IDS.tenantB]);
  await exec(db, 'insert into customers(id, tenant_id, external_ref, deleted_at) values ($1,$2,\'active-a\',null::timestamptz),($3,$2,\'soft-29-a\',$4::timestamptz),($5,$2,\'stale-a\',$6::timestamptz),($7,$2,\'consent-recent-a\',null::timestamptz),($8,$2,\'consent-old-a\',null::timestamptz),($9,$2,\'consent-never-a\',null::timestamptz),($10,$11,\'stale-b\',$6::timestamptz)', [
    IDS.activeA, IDS.tenantA, IDS.soft29A, d29, IDS.staleA, d31, IDS.consentRecentA, IDS.consentOldA, IDS.consentNeverA, IDS.staleB, IDS.tenantB,
  ]);
  await exec(db, 'insert into cards(id, tenant_id, customer_id, public_token_hash, status, stamp_count, rule_id, deleted_at) values ($1,$2,$3,$4,\'inactive\',2,$5,$6::timestamptz),($7,$8,$9,$10,\'inactive\',0,$11,$6::timestamptz)', [
    IDS.cardA, IDS.tenantA, IDS.staleA, hash('retention-validation-card-a'), IDS.ruleA, d31,
    IDS.cardB, IDS.tenantB, IDS.staleB, hash('retention-validation-card-b'), IDS.ruleB,
  ]);
  await exec(db, 'insert into stamp_events(id, tenant_id, card_id, employee_membership_id, quantity, idempotency_key, created_at) values ($1,$2,$3,$4,1,\'fixture-stamp-a\',$5::timestamptz)', [IDS.stampA, IDS.tenantA, IDS.cardA, IDS.memberA, d31]);
  await exec(db, 'insert into rewards(id, tenant_id, card_id, rule_id, status, issued_at) values ($1,$2,$3,$4,\'issued\',$5::timestamptz)', [IDS.rewardA, IDS.tenantA, IDS.cardA, IDS.ruleA, d31]);
  await exec(db, 'insert into card_creation_idempotency(tenant_id, idempotency_key, request_fingerprint, card_id, token_ciphertext, created_at) values ($1,\'fixture-card-a\',\'fixture-fingerprint\',$2,\'fixture-ciphertext\',$3::timestamptz)', [IDS.tenantA, IDS.cardA, d31]);

  await exec(db, 'insert into communication_preferences(tenant_id, customer_id, purpose, channel, opted_in, opted_in_at, withdrawn_at) values ($1,$2,\'marketing\',\'email\',false,null::timestamptz,$3::timestamptz),($1,$4,\'marketing\',\'email\',false,null::timestamptz,$5::timestamptz),($1,$6,\'marketing\',\'email\',false,null::timestamptz,null::timestamptz),($1,$7,\'marketing\',\'email\',true,$8::timestamptz,$9::timestamptz),($1,$10,\'marketing\',\'email\',true,$8::timestamptz,null::timestamptz)', [
    IDS.tenantA, IDS.staleA, y2, IDS.consentOldA, y35, IDS.consentNeverA, IDS.consentRecentA, y2, y2, IDS.activeA,
  ]);
  await exec(db, 'insert into communication_consent_events(tenant_id, customer_id, purpose, channel, action, source, occurred_at) values ($1,$2,\'marketing\',\'email\',\'withdraw\',\'admin_action\',$3::timestamptz),($1,$4,\'marketing\',\'email\',\'withdraw\',\'unsubscribe_link\',$5::timestamptz),($1,$6,\'marketing\',\'email\',\'opt_in\',\'web_form\',$7::timestamptz),($1,$8,\'marketing\',\'email\',\'withdraw\',\'system\',$9::timestamptz)', [
    IDS.tenantA, IDS.staleA, y2, IDS.consentOldA, y35, IDS.consentNeverA, now, IDS.consentRecentA, y2,
  ]);
  await exec(db, 'insert into communication_message_logs(tenant_id, customer_id, purpose, channel, message_type, recipient_hash, status, provider_message_id, created_at) values ($1,$2,\'marketing\',\'email\',\'fixture-23-month\',$3,\'sent\',\'fixture-provider-23\',$4::timestamptz),($1,$2,\'marketing\',\'email\',\'fixture-25-month\',$3,\'sent\',\'fixture-provider-25\',$5::timestamptz),($1,$6,\'service\',\'email\',\'fixture-customer\',$3,\'sent\',\'fixture-provider-customer\',$7::timestamptz),($8,$9,\'service\',\'email\',\'fixture-b-25-month\',$3,\'sent\',\'fixture-provider-b\',$5::timestamptz)', [
    IDS.tenantA, IDS.activeA, hash('fixture-recipient'), m23, m25, IDS.staleA, now, IDS.tenantB, IDS.staleB,
  ]);
  const sessionInsert = 'insert into sessions(id, user_id, tenant_id, token_hash, csrf_token_hash, expires_at, revoked_at) values ($1,$2,$3,$4,$5,$6::timestamptz,$7::timestamptz)';
  await exec(db, sessionInsert, [
    '00000000-0000-4000-8000-000000000801', IDS.userA, IDS.tenantA, hash('active-session'), hash('active-csrf'), future, null,
  ]);
  await exec(db, sessionInsert, [
    '00000000-0000-4000-8000-000000000802', IDS.userA, IDS.tenantA, hash('expired-session'), hash('expired-csrf'), minusDays(now, 1), null,
  ]);
  await exec(db, sessionInsert, [
    '00000000-0000-4000-8000-000000000803', IDS.userA, IDS.tenantA, hash('revoked-6-session'), hash('revoked-6-csrf'), future, d6,
  ]);
  await exec(db, sessionInsert, [
    '00000000-0000-4000-8000-000000000804', IDS.userA, IDS.tenantA, hash('revoked-8-session'), hash('revoked-8-csrf'), future, d8,
  ]);
}

const emptyCounts = (): RetentionCounts => ({
  sessionsDeleted: 0, messageLogsRetentionDeleted: 0, consentEventsRetentionDeleted: 0,
  customersHardDeleted: 0, cardsHardDeleted: 0, communicationMessageLogsDeleted: 0,
  communicationConsentEventsDeleted: 0, communicationPreferencesDeleted: 0,
  stampEventsDeleted: 0, rewardsDeleted: 0, cardCreationIdempotencyDeleted: 0,
  walletRevocationAttempts: 0,
});

function txClient(db: QueryConnection): TxClient {
  return {
    query: async <T = unknown>(sql: string, params: unknown[] = []) => ({ rows: await db.unsafe<T[]>(sql, params) }),
    release: () => undefined,
  };
}

async function invokeRetention(sql: HarnessSql, tenantId: string | null, wallet: WalletAdapter): Promise<JobResult> {
  const db = await sql.reserve();
  const logs: string[] = [];
  const started = Date.now();
  try {
    await exec(db, 'set search_path to public, pg_catalog');
    await exec(db, 'begin');
    // The lock belongs exclusively in this real job call, never in setup or gates.
    await exec(db, 'select pg_advisory_xact_lock($1)', [RETENTION_LOCK_KEY]);
    const counts = await runRetention(txClient(db), tenantId, wallet);
    await exec(db, 'commit');
    logs.push(`retention_ok duration_ms=${Math.max(0, Date.now() - started)}`);
    return { exitCode: 0, logs, counts };
  } catch {
    await exec(db, 'rollback').catch(() => undefined);
    logs.push('retention_failed RETENTION_FAILED');
    return { exitCode: 1, logs, errorCode: 'RETENTION_FAILED' };
  } finally {
    db.release();
  }
}

async function invokeCli(
  db: QueryConnection | undefined,
  url: string,
  tenantId: string | null,
  wallet: WalletAdapter,
  options: { vercel?: boolean; role?: string } = {},
): Promise<JobResult> {
  const logs: string[] = [];
  const capture = (...args: unknown[]) => logs.push(args.map(value => typeof value === 'string' ? value : JSON.stringify(value)).join(' '));
  const previousLog = console.log;
  const previousError = console.error;
  console.log = capture;
  console.error = capture;
  try {
    let exitCode: number;
    if (options.vercel) {
      exitCode = await dbRetention(
        { DATABASE_URL: url, RETENTION_TENANT_ID: tenantId ?? '', VERCEL: '1' },
        () => { throw new Error('Vercel gate must not create a pool'); },
        () => wallet,
      );
    } else {
      if (!db) throw new HarnessFailure('CLI_DATABASE_REQUIRED');
      const pool: DbPool = {
        connect: async () => {
          if (options.role) await exec(db, `set role ${quoteIdentifier(options.role)}`);
          return txClient(db);
        },
        end: async () => undefined,
      };
      exitCode = await dbRetention(
        { DATABASE_URL: url, RETENTION_TENANT_ID: tenantId ?? '' },
        () => pool,
        () => wallet,
      );
    }
    const errorCode = logs.find(log => log.startsWith('retention_failed '))?.split(' ')[1];
    return { exitCode, logs, errorCode };
  } finally {
    if (options.role && db) await exec(db, 'reset role').catch(() => undefined);
    console.log = previousLog;
    console.error = previousError;
  }
}

async function createInvalidRole(db: QueryConnection): Promise<void> {
  await exec(db, `drop role if exists ${quoteIdentifier(INVALID_ROLE)}`);
  await exec(db, `create role ${quoteIdentifier(INVALID_ROLE)} noinherit`);
  // Neon owner connections are not implicitly allowed to SET ROLE to a role
  // they created; grant membership so the negative-path probe reaches the
  // production operator-role check instead of failing with 42501.
  await exec(db, `grant ${quoteIdentifier(INVALID_ROLE)} to current_user`);
}
async function dropInvalidRole(db: QueryConnection): Promise<void> {
  await exec(db, `revoke ${quoteIdentifier(INVALID_ROLE)} from current_user`);
  await exec(db, `drop role if exists ${quoteIdentifier(INVALID_ROLE)}`);
}

function expectedA(): Partial<RetentionCounts> {
  return {
    sessionsDeleted: 2, messageLogsRetentionDeleted: 1, consentEventsRetentionDeleted: 1,
    customersHardDeleted: 1, cardsHardDeleted: 1, communicationMessageLogsDeleted: 1,
    communicationConsentEventsDeleted: 1, communicationPreferencesDeleted: 1,
    stampEventsDeleted: 1, rewardsDeleted: 1, cardCreationIdempotencyDeleted: 1,
    walletRevocationAttempts: 1,
  };
}
function selectedCounts(counts: RetentionCounts): Partial<RetentionCounts> { return { ...counts }; }

async function runHarness(url: string): Promise<{ checks: Check[]; tableCounts?: unknown; walletRevokeAttempts?: unknown; logs?: string[] }> {
  const sql = openSql(url);
  let db: QueryConnection | undefined;
  const checks: Check[] = [];
  const allLogs: string[] = [];
  const wallet = {
    revokeCalls: [] as string[],
    async issue() { return { provider: 'google' as const, status: 'not_configured' as const, message: 'fixture' }; },
    async refresh() { return { provider: 'google' as const, status: 'not_configured' as const, message: 'fixture' }; },
    async revoke(card: { id: string }) { this.revokeCalls.push(card.id); },
  } satisfies WalletAdapter & { revokeCalls: string[] };
  try {
    db = await sql.reserve();
    await resetHarnessContext(db);
    await prepareMigrations(db);
    await resetHarnessContext(db);
    await verifyRuntimeGrants(db);
    await cleanupFixtures(db);
    await insertFixtures(db);
    const before = await snapshot(db, [IDS.tenantA, IDS.tenantB]);
    const beforeB = await snapshot(db, [IDS.tenantB]);

    const scoped = await invokeRetention(sql, IDS.tenantA, wallet);
    allLogs.push(...scoped.logs);
    const afterScopedB = await snapshot(db, [IDS.tenantB]);
    checks.push({ name: 'tenant-scoped retention on A', expected: expectedA(), actual: scoped.counts ? selectedCounts(scoped.counts) : scoped.errorCode, pass: scoped.exitCode === 0 && jsonEqual(selectedCounts(scoped.counts ?? emptyCounts()), { ...emptyCounts(), ...expectedA() }) });
    checks.push({ name: 'tenant B unchanged by tenant-scoped run', expected: beforeB, actual: afterScopedB, pass: jsonEqual(beforeB, afterScopedB) });

    const second = await invokeRetention(sql, IDS.tenantA, wallet);
    allLogs.push(...second.logs);
    checks.push({ name: 'immediate second run is idempotent', expected: { exitCode: 0, counts: 'all zero' }, actual: { exitCode: second.exitCode, counts: second.counts ?? second.errorCode }, pass: second.exitCode === 0 && allZero(second.counts ?? emptyCounts()) });

    const global = await invokeRetention(sql, null, wallet);
    allLogs.push(...global.logs);
    checks.push({ name: 'global run cleans tenant B', expected: { customersHardDeleted: 1, messageLogsRetentionDeleted: 1 }, actual: global.counts ? { customersHardDeleted: global.counts.customersHardDeleted, messageLogsRetentionDeleted: global.counts.messageLogsRetentionDeleted } : global.errorCode, pass: global.exitCode === 0 && global.counts?.customersHardDeleted === 1 && global.counts.messageLogsRetentionDeleted === 1 });

    await createInvalidRole(db);
    try {
      const invalid = await invokeCli(db, url, null, wallet, { role: INVALID_ROLE });
      allLogs.push(...invalid.logs);
      checks.push({ name: 'non-operator gate', expected: 'RETENTION_ROLE_NOT_OPERATOR', actual: invalid.errorCode ?? 'none', pass: invalid.exitCode === 1 && invalid.errorCode === 'RETENTION_ROLE_NOT_OPERATOR' });
    } finally {
      await dropInvalidRole(db);
    }

    const vercel = await invokeCli(undefined, url, null, wallet, { vercel: true });
    allLogs.push(...vercel.logs);
    checks.push({ name: 'Vercel gate', expected: 'RETENTION_NOT_ALLOWED_ON_VERCEL', actual: vercel.errorCode ?? 'none', pass: vercel.exitCode === 1 && vercel.errorCode === 'RETENTION_NOT_ALLOWED_ON_VERCEL' });

    const after = await snapshot(db, [IDS.tenantA, IDS.tenantB]);
    checks.push({ name: 'wallet revoke exactly once per hard-deleted card', expected: 2, actual: wallet.revokeCalls.length, pass: wallet.revokeCalls.length === 2 && new Set(wallet.revokeCalls).size === 2 });
    const sensitiveLogPattern = /@|token|csrf|password|secret|postgres(?:ql)?:\/\/|Bearer\s|[a-f0-9]{64}/i;
    const unsafeLogs = allLogs.filter(log => sensitiveLogPattern.test(log));
    checks.push({ name: 'job logs contain no PII, tokens, or secrets', expected: [], actual: unsafeLogs, pass: unsafeLogs.length === 0 });
    return {
      checks,
      tableCounts: { before, after },
      walletRevokeAttempts: { before: 0, after: wallet.revokeCalls.length },
      logs: allLogs,
    };
  } finally {
    db?.release();
    await sql.end({ timeout: 5 }).catch(() => undefined);
  }
}

function redactDiagnostic(value: string): string {
  return value
    .replace(/postgres(?:ql)?:\/\/[^\s\"']+/gi, '[REDACTED_DATABASE_URL]')
    .replace(/((?:password|token|secret|authorization|cookie|api[_-]?key)[=:]\s*)[^\s,;]+/gi, '$1[REDACTED]')
    .replace(/\b[a-f0-9]{64}\b/gi, '[REDACTED_HASH]')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[REDACTED_EMAIL]');
}

function unexpectedErrorDetails(error: unknown): { name: string; message: string; stack?: string } {
  if (error instanceof Error) {
    const details: { name: string; message: string; stack?: string } = {
      name: redactDiagnostic(error.name),
      message: redactDiagnostic(error.message),
    };
    if (error.stack) details.stack = redactDiagnostic(error.stack);
    return details;
  }
  return { name: typeof error, message: redactDiagnostic(String(error)) };
}

async function main(): Promise<number> {
  const env = process.env;
  if (env.VERCEL === '1') {
    console.log(JSON.stringify({ checks: [{ name: 'Vercel gate', expected: 'RETENTION_NOT_ALLOWED_ON_VERCEL', actual: 'RETENTION_NOT_ALLOWED_ON_VERCEL', pass: true }], failures: [] }));
    return 2;
  }
  const url = env.TEST_DATABASE_URL?.trim();
  if (!url) {
    console.error('TEST_DATABASE_URL is required; no database action was performed.');
    console.log(JSON.stringify({ checks: [{ name: 'test database opt-in', expected: 'TEST_DATABASE_URL', actual: 'missing', pass: false }], failures: ['TEST_DATABASE_URL_REQUIRED'] }));
    return 2;
  }
  try {
    const result = await runHarness(url);
    const failures = result.checks.filter(check => !check.pass).map(check => check.name);
    console.log(JSON.stringify({ ...result, failures }, null, 2));
    return failures.length ? 1 : 0;
  } catch (error) {
    const failure = error instanceof HarnessFailure
      ? { kind: 'harness_failure', code: error.code, details: error.details }
      : { kind: 'unexpected_error', code: 'HARNESS_FAILED', error: unexpectedErrorDetails(error) };
    console.log(JSON.stringify({ checks: [{ name: 'harness execution', expected: 'ready', actual: failure, pass: false }], failures: ['harness execution'] }, null, 2));
    return 1;
  }
}

if (import.meta.main) process.exit(await main());
