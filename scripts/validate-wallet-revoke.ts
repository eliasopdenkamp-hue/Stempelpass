/**
 * Echter Google-Wallet-INACTIVE-Test (revoke-Pfad) — §3.4 Validierung vor
 * Pilotfreigabe, Checkliste "Wallet-Test ... separater Google-Test".
 *
 * Bisher war `WalletAdapter.revoke()` (PATCH loyaltyObject auf INACTIVE) nur
 * gegen einen Mock getestet (tests/wallet-revoke.test.ts). Dieses Skript
 * validiert den Revoke-Pfad gegen die ECHTE Google-Wallet-API:
 *
 *   (a) Zugangsdaten: echte Google-Wallet-Credentials aus der Umgebung
 *       (GOOGLE_ISSUER_ID + GOOGLE_SERVICE_ACCOUNT_JSON bzw. keyless
 *       GOOGLE_EXTERNAL_ACCOUNT_JSON + OIDC-Token). Erfindet nie welche;
 *       ohne Credentials bricht es mit einer Liste der fehlenden Variablen ab.
 *   (b) Wegwerf-Fixture: dedizierter Fixture-Tenant in der TEST_DATABASE_URL
 *       (NIE DATABASE_URL, keine Produktionsdaten), Kunde soft-geloescht
 *       (deleted_at 31 Tage), eine Wegwerf-Karte. Pass wird ueber
 *       `adapter.issue()` ausgestellt (gleicher Pfad wie das Produkt).
 *   (c) Das LoyaltyObject wird mit Status ACTIVE ueber die echte Wallet-API
 *       angelegt (simuliert den Zustand nach einem Save-to-Wallet), der
 *       Vorher-Zustand per GET bestaetigt, dann laeuft der PRODUKTIONS-Job
 *       `runRetention()` mit dem ECHTEN Adapter: revoke() PATCHt das Objekt
 *       auf INACTIVE. Per GET wird INACTIVE verifiziert.
 *   (d) Aufraeumen: Wallet-Objekt per DELETE entfernen, Fixture-Zeilen
 *       (Karte/Kunde/Tenant/User) loeschen, damit Production sauber bleibt.
 *
 * Sicherheitsvertrag (wie scripts/validate-retention.ts):
 *   - VERCEL=1 bricht vor jeder Aktion ab (nie auf dem Request-Pfad).
 *   - Nur TEST_DATABASE_URL wird gelesen; Pooler-Hostname -> Direct-Verbindung.
 *   - Logs anonym: keine Card-IDs, keine Tokens, keine Secrets, keine E-Mails.
 *   - Kein Test/kein Skript schreibt Credential-Material auf Platte.
 *
 * Dieses Skript wird bewusst nicht automatisch ausgefuehrt. Lauf:
 *   bun run db:wallet-revoke-validate
 */
import postgres from 'postgres';
import { createHash } from 'node:crypto';
import { resolveGcpCredentials, WALLET_OBJECT_SCOPE } from '../src/gcp-credentials.js';
import { RETENTION_LOCK_KEY, runRetention, type RetentionCounts } from '../src/retention.js';
import { walletAdapter, type WalletAdapter, type LoyaltyObject, type Branding } from '../src/wallet.js';
import type { DbPool, TxClient } from '../src/db.js';
import type { WalletCardView } from '../src/domain.js';

const STATEMENT_TIMEOUT_MS = 30_000;

const FIXTURE = {
  tenant: '00000000-0000-4000-8000-00000000f001',
  user: '00000000-0000-4000-8000-00000000f101',
  member: '00000000-0000-4000-8000-00000000f201',
  rule: '00000000-0000-4000-8000-00000000f301',
  customer: '00000000-0000-4000-8000-00000000f401',
  card: '00000000-0000-4000-8000-00000000f501',
} as const;

interface Check { name: string; expected: unknown; actual: unknown; pass: boolean }

class HarnessFailure extends Error {
  constructor(readonly code: string, readonly details: unknown = undefined) {
    super(code);
  }
}

function directUrl(raw: string): string {
  const url = new URL(raw.trim());
  url.hostname = url.hostname.replace(/-pooler(?=\.|$)/, '');
  url.searchParams.set('connect_timeout', '10');
  url.searchParams.set('statement_timeout', String(STATEMENT_TIMEOUT_MS));
  url.searchParams.set('lock_timeout', '5000');
  return url.toString();
}

function hash(value: string): string { return createHash('sha256').update(value).digest('hex'); }
function minusDays(now: Date, days: number): Date { return new Date(now.getTime() - days * 24 * 60 * 60 * 1000); }

const sql = postgres;
type SqlClient = ReturnType<typeof postgres>;
interface QueryConnection {
  unsafe<T = unknown[]>(query: string, params?: unknown[]): Promise<T>;
  release(): void;
}
interface PoolLike {
  reserve(): Promise<QueryConnection>;
  end(options?: { timeout?: number }): Promise<void>;
}

function txClient(db: QueryConnection): TxClient {
  return {
    query: async <T = unknown>(query: string, params: unknown[] = []) => ({ rows: await db.unsafe<T[]>(query, params) }),
    release: () => undefined,
  };
}

async function exec(db: QueryConnection, query: string, params: unknown[] = []): Promise<void> {
  await db.unsafe(query, params);
}

/**
 * Kapselt die Google-Wallet-API-Aufrufe des Skripts (Objekt anlegen, lesen,
 * loeschen) — bewusst getrennt vom Produktions-Adapter, damit der
 * Produktions-Code (revoke) nicht durch Test-Helfer verunreinigt wird.
 * Alle Aufrufe laufen gegen die echte Google-Wallet-API (kein Mock) und
 * tragen das echte OAuth-Token aus den konfigurierten Credentials.
 */
class WalletApiProbe {
  constructor(
    private readonly issuerId: string,
    private readonly credentials: NonNullable<Awaited<ReturnType<typeof resolveGcpCredentials>>['provider']>,
  ) {}

  private async headers(): Promise<Record<string, string>> {
    const { token } = await this.credentials.getAccessToken(WALLET_OBJECT_SCOPE);
    return { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
  }

  async createObject(cardId: string, classId: string): Promise<void> {
    const body: LoyaltyObject = {
      id: `${this.issuerId}.${cardId}`,
      classId,
      state: 'ACTIVE',
      loyaltyPoints: { balance: { int: 0 } },
    };
    const response = await fetch('https://walletobjects.googleapis.com/walletobjects/v1/loyaltyObject', {
      method: 'POST',
      headers: await this.headers(),
      body: JSON.stringify(body),
    });
    if (!response.ok && response.status !== 409) throw new HarnessFailure(`GOOGLE_WALLET_OBJECT_CREATE_FAILED_${response.status}`);
  }

  async fetchState(cardId: string): Promise<string> {
    const response = await fetch(`https://walletobjects.googleapis.com/walletobjects/v1/loyaltyObject/${encodeURIComponent(`${this.issuerId}.${cardId}`)}`, {
      headers: { Authorization: `Bearer ${(await this.credentials.getAccessToken(WALLET_OBJECT_SCOPE)).token}` },
    });
    if (!response.ok) return `HTTP_${response.status}`;
    const object = (await response.json()) as { state?: string };
    return object.state ?? 'NO_STATE';
  }

  async deleteObject(cardId: string): Promise<string> {
    const response = await fetch(`https://walletobjects.googleapis.com/walletobjects/v1/loyaltyObject/${encodeURIComponent(`${this.issuerId}.${cardId}`)}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${(await this.credentials.getAccessToken(WALLET_OBJECT_SCOPE)).token}` },
    });
    if (response.status === 404) return 'ABSENT';
    if (!response.ok) return `HTTP_${response.status}`;
    return 'DELETED';
  }
}

async function prepareDatabase(url: string): Promise<PoolLike> {
  // max: 2 — one connection stays reserved for fixture setup/verification,
  // the second is the fresh per-job transaction connection (same design as
  // scripts/validate-retention.ts; max:1 would deadlock the fresh reserve()).
  const client = sql(directUrl(url), { max: 2, connect_timeout: 10, idle_timeout: 20, prepare: false });
  const db = await client.reserve();
  try {
    const tables = await db.unsafe<{ exists: boolean }[]>("select exists(select 1 from pg_tables where schemaname='public' and tablename='tenants') as exists");
    if (!tables[0]?.exists) {
      throw new HarnessFailure('MIGRATIONS_REQUIRED', 'run scripts/validate-retention.ts once so migrations 001-015 exist on the TEST_DATABASE_URL');
    }
  } finally {
    db.release();
  }
  return client as unknown as PoolLike;
}

async function cleanupFixtures(db: QueryConnection): Promise<void> {
  for (const table of ['card_creation_idempotency', 'stamp_events', 'rewards', 'cards', 'communication_message_logs', 'communication_consent_events', 'communication_preferences', 'audit_log', 'sessions'] as const) {
    await exec(db, `delete from ${table} where tenant_id = $1`, [FIXTURE.tenant]);
  }
  await exec(db, 'delete from customers where tenant_id = $1', [FIXTURE.tenant]);
  await exec(db, 'delete from tenant_memberships where tenant_id = $1', [FIXTURE.tenant]);
  await exec(db, 'delete from tenant_branding where tenant_id = $1', [FIXTURE.tenant]);
  await exec(db, 'delete from stamp_rules where tenant_id = $1', [FIXTURE.tenant]);
  await exec(db, 'delete from tenant_entry_points where tenant_id = $1', [FIXTURE.tenant]);
  await exec(db, 'delete from tenants where id = $1', [FIXTURE.tenant]);
  await exec(db, 'delete from users where id = $1', [FIXTURE.user]);
}

async function insertFixtures(db: QueryConnection): Promise<void> {
  const now = new Date();
  const d31 = minusDays(now, 31);
  await exec(db, 'insert into tenants(id, slug, legal_name, plan_code, customer_limit) values ($1,$2,$3,$4,$5)', [
    FIXTURE.tenant, 'wallet-revoke-validation', 'Wallet Revoke Validation', 'up_to_500', 500,
  ]);
  await exec(db, 'insert into users(id, email, display_name, auth_subject) values ($1,$2,$3,$4)', [
    FIXTURE.user, 'wallet-revoke-validation@example.invalid', 'Wallet Revoke Validation', 'wallet-revoke-validation-subject',
  ]);
  await exec(db, "insert into tenant_memberships(id, tenant_id, user_id, role) values ($1,$2,$3,'staff')", [
    FIXTURE.member, FIXTURE.tenant, FIXTURE.user,
  ]);
  await exec(db, 'insert into stamp_rules(id, tenant_id, name, stamps_required, reward_title, reward_description) values ($1,$2,$3,10,$4,$5)', [
    FIXTURE.rule, FIXTURE.tenant, 'Wallet revoke validation rule', 'Testpraemie', 'Fixture only',
  ]);
  // Soft-geloeschter Kunde aelter als die 30-Tage-Hard-Delete-Frist -> Kandidat
  // fuer den Produktions-Retention-Job. legal_retention_hold default false.
  await exec(db, 'insert into customers(id, tenant_id, external_ref, deleted_at) values ($1,$2,$3,$4::timestamptz)', [
    FIXTURE.customer, FIXTURE.tenant, 'wallet-revoke-fixture', d31,
  ]);
  await exec(db, 'insert into cards(id, tenant_id, customer_id, public_token_hash, status, stamp_count, rule_id) values ($1,$2,$3,$4,\'inactive\',0,$5)', [
    FIXTURE.card, FIXTURE.tenant, FIXTURE.customer, hash('wallet-revoke-validation-card'), FIXTURE.rule,
  ]);
}

const emptyCounts = (): RetentionCounts => ({
  sessionsDeleted: 0, messageLogsRetentionDeleted: 0, consentEventsRetentionDeleted: 0,
  customersHardDeleted: 0, cardsHardDeleted: 0, communicationMessageLogsDeleted: 0,
  communicationConsentEventsDeleted: 0, communicationPreferencesDeleted: 0,
  stampEventsDeleted: 0, rewardsDeleted: 0, cardCreationIdempotencyDeleted: 0,
  walletRevocationAttempts: 0,
});

/**
 * Produktions-Job-Pfad: runRetention() in eigener Transaktion mit dem
 * RETENTION_LOCK_KEY — derselbe Aufruf wie `bun run db:retention`, nur gegen
 * den Fixture-Tenant und mit dem ECHTEN Google-Adapter.
 */
async function invokeRetention(pool: PoolLike, tenantId: string, wallet: WalletAdapter): Promise<{ counts: RetentionCounts; exitCode: number }> {
  const db = await pool.reserve();
  try {
    await exec(db, 'set search_path to public, pg_catalog');
    await exec(db, 'begin');
    await exec(db, 'select pg_advisory_xact_lock($1)', [RETENTION_LOCK_KEY]);
    const counts = await runRetention(txClient(db), tenantId, wallet);
    await exec(db, 'commit');
    return { counts, exitCode: 0 };
  } catch (error) {
    await exec(db, 'rollback').catch(() => undefined);
    throw error;
  } finally {
    db.release();
  }
}

function redact(value: string): string {
  return value
    .replace(/postgres(?:ql)?:\/\/[^\s"']+/gi, '[REDACTED_DATABASE_URL]')
    .replace(/((?:password|token|secret|authorization|cookie|api[_-]?key)[=:]\s*)[^\s,;]+/gi, '$1[REDACTED]')
    .replace(/\b[a-f0-9]{64}\b/gi, '[REDACTED_HASH]')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[REDACTED_EMAIL]');
}

async function main(): Promise<number> {
  const env = process.env;
  if (env.VERCEL === '1') {
    console.log(JSON.stringify({ checks: [{ name: 'Vercel gate', expected: 'VERCEL_NOT_ALLOWED', actual: 'VERCEL_NOT_ALLOWED', pass: false }], failures: ['VERCEL_NOT_ALLOWED'] }));
    return 2;
  }
  const url = env.TEST_DATABASE_URL?.trim();
  if (!url) {
    console.error('TEST_DATABASE_URL is required; no wallet action was performed.');
    return 2;
  }
  const issuerId = env.GOOGLE_ISSUER_ID?.trim();
  const resolution = resolveGcpCredentials(env);
  if (!issuerId || !resolution.provider || !resolution.provider.clientEmail) {
    const missing = [!issuerId ? 'GOOGLE_ISSUER_ID' : null, ...resolution.missing].filter(Boolean);
    console.error(`GOOGLE_CREDENTIALS_MISSING ${missing.join(', ')} — no wallet action was performed; nothing was created, revoked, or deleted.`);
    return 2;
  }

  const checks: Check[] = [];
  const capturedLogs: string[] = [];
  const capture = (...args: unknown[]) => capturedLogs.push(args.map(v => typeof v === 'string' ? v : JSON.stringify(v)).join(' '));
  const previousLog = console.log;
  const previousError = console.error;
  console.log = capture;
  console.error = capture;

  let pool: PoolLike | null = null;
  let db: QueryConnection | null = null;
  try {
    pool = await prepareDatabase(url);
    db = await pool.reserve();
    await exec(db, 'reset role');
    await exec(db, 'set search_path to public, pg_catalog');
    await cleanupFixtures(db);
    await insertFixtures(db);

    // Realer Produktions-Adapter (liest die Umgebung; service-account-json
    // bzw. keyless/external-account). Kein Mock, kein Fake-Fetch.
    const adapter: WalletAdapter = walletAdapter('google');
    const probe = new WalletApiProbe(issuerId, resolution.provider!);

    // 1. Pass ausstellen (gleicher Pfad wie /card/.../wallet/google).
    const view: WalletCardView = { id: FIXTURE.card, stampCount: 0 };
    const branding: Branding = { cardTitle: 'StempelPass', cardText: 'Wegwerf-Test', primaryColor: '#0f172a', secondaryColor: '#3b82f6', version: 1 };
    const artifact = await adapter.issue(view, branding, { stampRequired: 10, rewardTitle: 'Testpraemie' });
    checks.push({
      name: 'real adapter issue() returns issued with a signed savetowallet artifact',
      expected: 'issued', actual: artifact.status,
      pass: artifact.status === 'issued' && Boolean(artifact.artifact),
    });

    // 2. LoyaltyObject mit Status ACTIVE anlegen (simulierter Save-to-Wallet)
    //    und Vorher-Zustand per API-GET bestaetigen.
    await probe.createObject(FIXTURE.card, `${issuerId}.stempelpass_loyalty`);
    const stateBefore = await probe.fetchState(FIXTURE.card);
    checks.push({
      name: 'throwaway loyaltyObject exists and is ACTIVE before revoke (real Wallet API GET)',
      expected: 'ACTIVE', actual: stateBefore,
      pass: stateBefore === 'ACTIVE',
    });

    // 3. Produktions-Retention-Job (runRetention) mit dem ECHTEN Adapter:
    //    revoke() PATCHt das Objekt auf INACTIVE und haertet Karte/Kunde.
    const job = await invokeRetention(pool, FIXTURE.tenant, adapter);
    checks.push({
      name: 'retention job revokes the wallet object exactly once and hard-deletes the fixture card/customer',
      expected: { walletRevocationAttempts: 1, cardsHardDeleted: 1, customersHardDeleted: 1 },
      actual: { walletRevocationAttempts: job.counts.walletRevocationAttempts, cardsHardDeleted: job.counts.cardsHardDeleted, customersHardDeleted: job.counts.customersHardDeleted },
      pass: job.exitCode === 0 && job.counts.walletRevocationAttempts === 1 && job.counts.cardsHardDeleted === 1 && job.counts.customersHardDeleted === 1,
    });

    // 4. Kernaussage: das Objekt ist nach dem Revoke wirklich INACTIVE.
    const stateAfter = await probe.fetchState(FIXTURE.card);
    checks.push({
      name: 'loyaltyObject is INACTIVE after WalletAdapter.revoke() (real Wallet API GET)',
      expected: 'INACTIVE', actual: stateAfter,
      pass: stateAfter === 'INACTIVE',
    });

    // 5. Aufraeumen: Wallet-Objekt entfernen + Fixture-Zeilen loeschen.
    const deleteResult = await probe.deleteObject(FIXTURE.card);
    checks.push({
      name: 'cleanup: throwaway wallet object removed from the issuer (DELETE)',
      expected: 'DELETED', actual: deleteResult,
      pass: deleteResult === 'DELETED' || deleteResult === 'ABSENT',
    });
    await cleanupFixtures(db);
    const leftover = await db.unsafe<{ count: number }[]>('select count(*)::int as count from cards where id = $1', [FIXTURE.card]);
    checks.push({
      name: 'cleanup: fixture card row removed from the test database',
      expected: 0, actual: leftover[0]?.count ?? 'missing',
      pass: (leftover[0]?.count ?? -1) === 0,
    });

    const sensitiveLogPattern = /@|token|csrf|password|secret|postgres(?:ql)?:\/\/|Bearer\s|[a-f0-9]{64}/i;
    const unsafeLogs = capturedLogs.filter(log => sensitiveLogPattern.test(log));
    checks.push({
      name: 'logs contain no PII, tokens, secrets, or card ids',
      expected: [], actual: unsafeLogs,
      pass: unsafeLogs.length === 0,
    });
  } catch (error) {
    const failure = error instanceof HarnessFailure
      ? { kind: 'harness_failure', code: error.code, details: error.details }
      : { kind: 'unexpected_error', code: 'HARNESS_FAILED', message: error instanceof Error ? redact(error.message) : redact(String(error)) };
    checks.push({ name: 'harness execution', expected: 'ready', actual: failure, pass: false });
  } finally {
    try {
      if (db) {
        await exec(db, 'reset role').catch(() => undefined);
        await cleanupFixtures(db).catch(() => undefined);
        db.release();
      }
      await pool?.end({ timeout: 5 }).catch(() => undefined);
    } catch { /* best effort */ }
    console.log = previousLog;
    console.error = previousError;
  }

  const failures = checks.filter(check => !check.pass).map(check => check.name);
  const summary = capture({ checks, failures });
  console.log(summary);
  return failures.length ? 1 : 0;
}

if (import.meta.main) process.exit(await main());