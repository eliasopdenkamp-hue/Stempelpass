/**
 * RLS / production-role verification (opt-in, read-only, anonymized).
 *
 * This diagnostic checks a PostgreSQL connection for the properties that make
 * tenant isolation actually hold in production:
 *
 *   - the role must NOT have `rolbypassrls` (BYPASSRLS) or superuser and must
 *     not own tenant tables (table owners bypass RLS unless FORCE ROW SECURITY),
 *   - RLS must be enabled on every tenant-sensitive table,
 *   - the role must hold exactly the DML grants the application needs
 *     (checked against `REQUIRED_GRANTS`, derived from the repository/server
 *     code paths),
 *   - `row_security_active(...)` must be true for the role (as-role mode only).
 *
 * Safety contract (do not weaken):
 *   - Explicit opt-in: the CLI reads ONLY `RLS_VERIFY_DATABASE_URL`; there is
 *     no fallback to `DATABASE_URL` and running without it exits with code 2.
 *   - Read-only: the dedicated short-lived connection (max 1, never shared)
 *     opens an explicit `BEGIN READ ONLY` transaction — plain standard SQL,
 *     deliberately NOT the driver's `sql.begin('read only', ...)` helper (see
 *     `createRlsDb`/`verifyRls` below for why that helper misbehaves on
 *     Neon/proxied PostgreSQL) — and additionally pins
 *     `default_transaction_read_only=on` at session level. Every statement is
 *     a bare SELECT against catalog/system views (`pg_roles`, `pg_class`,
 *     `pg_namespace`, `information_schema`-style privilege helpers). No data
 *     table is read, nothing is written, no DDL is issued, and the connection
 *     is closed afterwards.
 *   - Anonymized output: the report contains only booleans and classified
 *     values. `current_user` is never printed, role names are never printed,
 *     and the connection URL (which may embed a password) is never logged or
 *     returned. Driver error messages are replaced with short classified codes
 *     (`query:<step>` / `connect`) — never raw error text. A failure inside a
 *     verification query is reported as `query:<name>`: the explicit
 *     transaction is rolled back (ROLLBACK) and the classified error is
 *     rethrown so the outer catch keeps the precise step. Only failures to
 *     open the connection, to start the read-only transaction, or to commit it
 *     are reported as `connect`.
 *   - No workaround mode: if the provided connection cannot verify the checks
 *     (e.g. no separate non-owner app role exists), the tool reports
 *     `ok:false` / `roleClass:"unverified"` and exits non-zero; it never
 *     fabricates results or "fixes" the database.
 */

import postgres from 'postgres';

// ---------------------------------------------------------------------------
// Expected schema (derived from migrations/001..007)
// ---------------------------------------------------------------------------

/** Tables that MUST have row-level security enabled: tenant-scoped tables
 *  (tenant_id RLS) plus `sessions` (user-scoped RLS, migration 009). */
export const TENANT_SENSITIVE_TABLES: readonly string[] = [
  'tenant_memberships',
  'customers',
  'tenant_branding',
  'stamp_rules',
  'cards',
  'stamp_events',
  'rewards',
  'communication_preferences',
  'communication_consent_events',
  'communication_message_logs',
  'tenant_entry_points',
  'audit_log',
  'sessions',
];

/** Every application table (owner-risk and grant checks cover all of them). */
export const ALL_APP_TABLES: readonly string[] = [
  'tenants',
  'users',
  ...TENANT_SENSITIVE_TABLES,
  'schema_migrations',
];

/**
 * Minimal DML the application role actually needs (derived from the current
 * repository/server SQL). Grants beyond this are not required for least
 * privilege; missing entries here fail the check.
 */
export const REQUIRED_GRANTS: Readonly<Record<string, readonly ('SELECT' | 'INSERT' | 'UPDATE' | 'DELETE')[]>> = {
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
};

// ---------------------------------------------------------------------------
// Queries (all SELECT-only; role names/schema/table lists are bind parameters;
// `current_user` appears only in predicates, never in the select list)
// ---------------------------------------------------------------------------

export interface RlsQuery { name: string; sql: string; params?: unknown[] }

const FROM_PG_CLASS = `from pg_class c join pg_namespace n on n.oid = c.relnamespace`;

/** as-role mode: the connection user IS the role to verify. */
export function buildAsRoleQueries(schema: string): RlsQuery[] {
  return [
    {
      name: 'role-attributes',
      sql: `select rolbypassrls, rolsuper, rolcreaterole, rolcreatedb, rolreplication from pg_roles where rolname = current_user`,
    },
    {
      name: 'table-ownership',
      sql: `select c.relname as table_name ${FROM_PG_CLASS} join pg_roles r on r.oid = c.relowner where n.nspname = $1 and c.relkind in ('r','p') and c.relname = any($2) and r.rolname = current_user`,
      params: [schema, [...ALL_APP_TABLES]],
    },
    {
      name: 'rls-flags',
      sql: `select c.relname as table_name, c.relrowsecurity as rls_enabled, c.relforcerowsecurity as rls_forced ${FROM_PG_CLASS} where n.nspname = $1 and c.relkind in ('r','p') and c.relname = any($2)`,
      params: [schema, [...TENANT_SENSITIVE_TABLES]],
    },
    {
      name: 'grants',
      sql: `select c.relname as table_name, has_table_privilege(c.oid, 'SELECT') as sel, has_table_privilege(c.oid, 'INSERT') as ins, has_table_privilege(c.oid, 'UPDATE') as upd, has_table_privilege(c.oid, 'DELETE') as del ${FROM_PG_CLASS} where n.nspname = $1 and c.relkind in ('r','p') and c.relname = any($2)`,
      params: [schema, [...ALL_APP_TABLES]],
    },
    {
      name: 'schema-privileges',
      sql: `select has_schema_privilege($1, 'USAGE') as usage_ok, has_schema_privilege($1, 'CREATE') as create_ok`,
      params: [schema],
    },
    {
      name: 'row-security-active',
      sql: `select c.relname as table_name, row_security_active(c.oid) as active ${FROM_PG_CLASS} where n.nspname = $1 and c.relkind in ('r','p') and c.relname = any($2)`,
      params: [schema, [...TENANT_SENSITIVE_TABLES]],
    },
  ];
}

/**
 * named-role mode: connect with an admin connection, verify a role given by
 * name. `row_security_active` is omitted because it evaluates the *connection*
 * user, not the named role — checking it here would be misleading.
 */
export function buildNamedRoleQueries(roleName: string, schema: string): RlsQuery[] {
  return [
    {
      name: 'role-attributes',
      sql: `select rolbypassrls, rolsuper, rolcreaterole, rolcreatedb, rolreplication from pg_roles where rolname = $1`,
      params: [roleName],
    },
    {
      name: 'table-ownership',
      sql: `select c.relname as table_name ${FROM_PG_CLASS} join pg_roles r on r.oid = c.relowner where n.nspname = $1 and c.relkind in ('r','p') and c.relname = any($2) and r.rolname = $3`,
      params: [schema, [...ALL_APP_TABLES], roleName],
    },
    {
      name: 'rls-flags',
      sql: `select c.relname as table_name, c.relrowsecurity as rls_enabled, c.relforcerowsecurity as rls_forced ${FROM_PG_CLASS} where n.nspname = $1 and c.relkind in ('r','p') and c.relname = any($2)`,
      params: [schema, [...TENANT_SENSITIVE_TABLES]],
    },
    {
      name: 'grants',
      sql: `select c.relname as table_name, has_table_privilege($3::name, c.oid, 'SELECT') as sel, has_table_privilege($3::name, c.oid, 'INSERT') as ins, has_table_privilege($3::name, c.oid, 'UPDATE') as upd, has_table_privilege($3::name, c.oid, 'DELETE') as del ${FROM_PG_CLASS} where n.nspname = $1 and c.relkind in ('r','p') and c.relname = any($2)`,
      params: [schema, [...ALL_APP_TABLES], roleName],
    },
    {
      name: 'schema-privileges',
      sql: `select has_schema_privilege($2::name, $1, 'USAGE') as usage_ok, has_schema_privilege($2::name, $1, 'CREATE') as create_ok`,
      params: [schema, roleName],
    },
  ];
}

// ---------------------------------------------------------------------------
// Classification (pure — unit-tested without a database)
// ---------------------------------------------------------------------------

export type RlsMode = 'as-role' | 'named-role';
export type RoleClass = 'app-role' | 'owner-like' | 'privileged' | 'unverified';

export interface RlsChecks {
  roleBypassRls: boolean;
  roleSuperuser: boolean;
  roleCanCreateRole: boolean;
  roleCanCreateDb: boolean;
  roleCanReplicate: boolean;
  ownsAnyTable: boolean;
  ownedTables: string[];
  rlsEnabledOnAllTenantTables: boolean;
  rlsForcedOnAllTenantTables: boolean;
  rlsActiveForRole: boolean | null;
  rlsMissing: string[];
  rlsInactiveForRole: string[];
  grantsComplete: boolean;
  missingGrants: string[];
  schemaUsage: boolean;
  schemaCreate: boolean;
}

export interface RlsVerifyReport {
  ok: boolean;
  mode: RlsMode;
  roleClass: RoleClass;
  tablesFound: string[];
  tablesMissing: string[];
  checks: RlsChecks;
  errors: string[];
}

export interface RlsRawInput {
  mode: RlsMode;
  roleAttrs: { rolbypassrls: boolean; rolsuper: boolean; rolcreaterole: boolean; rolcreatedb: boolean; rolreplication: boolean } | null;
  ownedTables: string[];
  rlsRows: { table_name: string; rls_enabled: boolean; rls_forced: boolean }[];
  grantRows: { table_name: string; sel: boolean; ins: boolean; upd: boolean; del: boolean }[];
  schemaRow: { usage_ok: boolean; create_ok: boolean } | null;
  rowSecurityRows: { table_name: string; active: boolean }[] | null;
  errors: string[];
}

export function classifyRlsReport(input: RlsRawInput): RlsVerifyReport {
  const errors = [...input.errors];
  if (!input.roleAttrs) errors.push('role-not-found');

  const tablesFound = input.grantRows.map(r => r.table_name);
  const tablesMissing = ALL_APP_TABLES.filter(t => !tablesFound.includes(t));
  if (tablesMissing.length > 0) errors.push('tables-missing');

  const rlsMissing = TENANT_SENSITIVE_TABLES.filter(
    t => tablesFound.includes(t) && !input.rlsRows.find(r => r.table_name === t)?.rls_enabled,
  );
  const rlsForcedMissing = TENANT_SENSITIVE_TABLES.filter(
    t => tablesFound.includes(t) && !input.rlsRows.find(r => r.table_name === t)?.rls_forced,
  );
  if (rlsMissing.length > 0) errors.push('rls-disabled');

  const missingGrants: string[] = [];
  for (const [table, privs] of Object.entries(REQUIRED_GRANTS)) {
    const row = input.grantRows.find(r => r.table_name === table);
    if (!row) continue; // presence handled by tablesMissing
    for (const priv of privs) {
      const granted = priv === 'SELECT' ? row.sel : priv === 'INSERT' ? row.ins : priv === 'UPDATE' ? row.upd : row.del;
      if (!granted) missingGrants.push(`${table}:${priv}`);
    }
  }
  if (missingGrants.length > 0) errors.push('grants-missing');
  if (input.schemaRow && !input.schemaRow.usage_ok) errors.push('schema-usage-denied');

  const rlsInactiveForRole = input.rowSecurityRows
    ? TENANT_SENSITIVE_TABLES.filter(
        t => tablesFound.includes(t) && input.rowSecurityRows!.find(r => r.table_name === t)?.active === false,
      )
    : [];
  if (input.rowSecurityRows && rlsInactiveForRole.length > 0) errors.push('rls-inactive-for-role');

  const attrs = input.roleAttrs;
  const checks: RlsChecks = {
    roleBypassRls: attrs?.rolbypassrls ?? false,
    roleSuperuser: attrs?.rolsuper ?? false,
    roleCanCreateRole: attrs?.rolcreaterole ?? false,
    roleCanCreateDb: attrs?.rolcreatedb ?? false,
    roleCanReplicate: attrs?.rolreplication ?? false,
    ownsAnyTable: input.ownedTables.length > 0,
    ownedTables: input.ownedTables,
    rlsEnabledOnAllTenantTables: rlsMissing.length === 0,
    rlsForcedOnAllTenantTables: rlsForcedMissing.length === 0,
    rlsActiveForRole: input.rowSecurityRows ? rlsInactiveForRole.length === 0 : null,
    rlsMissing,
    rlsInactiveForRole,
    grantsComplete: missingGrants.length === 0,
    missingGrants,
    schemaUsage: input.schemaRow?.usage_ok ?? false,
    schemaCreate: input.schemaRow?.create_ok ?? false,
  };

  const criticalFail =
    errors.length > 0 ||
    checks.roleBypassRls ||
    checks.roleSuperuser ||
    checks.roleCanCreateRole ||
    checks.roleCanCreateDb ||
    checks.roleCanReplicate ||
    checks.ownsAnyTable ||
    !checks.rlsEnabledOnAllTenantTables ||
    !checks.grantsComplete ||
    !checks.schemaUsage;

  const roleClass: RoleClass = errors.length > 0
    ? 'unverified'
    : checks.ownsAnyTable
      ? 'owner-like'
      : checks.roleBypassRls || checks.roleSuperuser || checks.roleCanCreateRole || checks.roleCanCreateDb || checks.roleCanReplicate
        ? 'privileged'
        : 'app-role';

  return {
    ok: !criticalFail,
    mode: input.mode,
    roleClass,
    tablesFound,
    tablesMissing,
    checks,
    errors,
  };
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/**
 * A single statement on the dedicated short-lived connection. `query` must
 * execute the statement and return `{ rows }`; it must never log or expose
 * driver error text (the caller only uses throw/not-throw for classification).
 */
export interface RlsDb {
  query<T>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
  /** Close the dedicated connection. */
  end(): Promise<void>;
}

/**
 * Classified failure for a single verification query. Carries ONLY the short
 * classified code (`query:<name>`); the driver message, SQL text and params
 * never leave this module. `verifyRls` throws this from inside the read-only
 * transaction; the transaction is rolled back explicitly (ROLLBACK) and the
 * error is rethrown, so the outer catch can distinguish a check-query failure
 * from a connection/BEGIN failure without ever printing driver error text.
 * (Returning a fail report instead would leave the transaction open and the
 * ROLLBACK/COMMIT path ambiguous.)
 */
export class RlsQueryFailure extends Error {
  readonly code: string;
  constructor(name: string) {
    super('query:' + name);
    this.name = 'RlsQueryFailure';
    this.code = 'query:' + name;
  }
}

/**
 * Connection options for the dedicated RLS-verify connection. `idle_timeout`
 * is deliberately omitted (postgres.js default `null`): the connection must
 * never self-close mid-transaction; it is closed explicitly via `end()`.
 */
export interface RlsConnectionOptions {
  max: number;
  connect_timeout: number;
  max_lifetime: number | null;
  prepare: boolean;
  connection: { default_transaction_read_only: boolean };
}

/** Neon-hardened options for the dedicated RLS-verify connection. */
export function rlsConnectionOptions(): RlsConnectionOptions {
  return {
    max: 1,                       // dedicated connection, never shared
    connect_timeout: 30,          // Neon autosuspend cold starts need headroom
    max_lifetime: null,
    prepare: false,               // plain protocol, no named prepared statements (pooler-safe)
    connection: { default_transaction_read_only: true }, // session-level write pin
  };
}

/** Dedicated short-lived connection: read-only, one slot, never shared. */
export function createRlsDb(url: string): RlsDb {
  const sql = postgres(url, rlsConnectionOptions());
  return {
    // Executes each statement on the pool's single connection; `max: 1`
    // guarantees BEGIN / checks / COMMIT / ROLLBACK all run on the SAME
    // physical connection, so the explicit transaction below is safe.
    query: <T>(q: string, params?: unknown[]) =>
      sql.unsafe<T[]>(q, (params ?? []) as never[]).then(rows => ({ rows })),
    end: () => sql.end({ timeout: 5 }),
  };
}

export interface VerifyRlsOptions {
  /** Explicitly provided connection string (RLS_VERIFY_DATABASE_URL). Never logged. */
  url: string;
  /** named-role mode: verify this role instead of the connection user. */
  roleName?: string;
  /** Schema holding the application tables (default 'public'). */
  schema?: string;
  /** Test seam: inject a fake RlsDb. */
  db?: RlsDb;
}

const SCHEMA_RE = /^[a-z_][a-z0-9_]*$/;

export async function verifyRls(opts: VerifyRlsOptions): Promise<RlsVerifyReport> {
  const schema = opts.schema ?? 'public';
  const mode: RlsMode = opts.roleName ? 'named-role' : 'as-role';
  if (!SCHEMA_RE.test(schema)) return failReport(mode, ['invalid-schema']);
  if (opts.roleName && !/^[a-zA-Z_][a-zA-Z0-9_$]*$/.test(opts.roleName)) return failReport(mode, ['invalid-role']);

  const db = opts.db ?? createRlsDb(opts.url);
  try {
    // Explicit read-only transaction on the dedicated connection: plain
    // standard SQL (`BEGIN READ ONLY`), supported by Neon and every
    // PostgreSQL. Deliberately NOT the driver's `sql.begin('read only', fn)`:
    // that helper COMMITs after the callback, and when a verification query
    // fails the transaction is aborted server-side — the driver's COMMIT then
    // fails (25P02) and surfaces as `connect`, indistinguishable from a real
    // connection failure even though the role can log in fine (exactly the
    // Neon report). Running BEGIN/COMMIT/ROLLBACK ourselves classifies
    // precisely: connection/BEGIN/COMMIT failures are `connect`, check-query
    // failures are `query:<name>`.
    try {
      await db.query('BEGIN READ ONLY');
    } catch {
      // Connection could not be established or the read-only transaction
      // could not be opened — a connectivity-level failure, never a check
      // failure. No driver message, URL or role is included.
      return failReport(mode, ['connect']);
    }

    const queries = mode === 'named-role'
      ? buildNamedRoleQueries(opts.roleName!, schema)
      : buildAsRoleQueries(schema);
    const results: Record<string, { rows: Array<Record<string, unknown>> }> = {};
    for (const q of queries) {
      if (!/^select\s/i.test(q.sql.trim())) return failReport(mode, ['read-only-violation']);
      try {
        results[q.name] = await db.query<Record<string, unknown>>(q.sql, q.params);
      } catch {
        // Classified code only; the ROLLBACK in the outer catch closes the
        // aborted transaction cleanly and the error is rethrown so the outer
        // catch keeps `query:<name>`.
        throw new RlsQueryFailure(q.name);
      }
    }
    const bool = (v: unknown) => v === true;
    const str = (v: unknown) => String(v ?? '');
    const report = classifyRlsReport({
      mode,
      roleAttrs: (results['role-attributes']?.rows[0] as never) ?? null,
      ownedTables: (results['table-ownership']?.rows ?? []).map(r => str(r.table_name)),
      rlsRows: (results['rls-flags']?.rows ?? []).map(r => ({
        table_name: str(r.table_name), rls_enabled: bool(r.rls_enabled), rls_forced: bool(r.rls_forced),
      })),
      grantRows: (results['grants']?.rows ?? []).map(r => ({
        table_name: str(r.table_name), sel: bool(r.sel), ins: bool(r.ins), upd: bool(r.upd), del: bool(r.del),
      })),
      schemaRow: results['schema-privileges']?.rows[0] as never ?? null,
      rowSecurityRows: results['row-security-active']
        ? (results['row-security-active'].rows ?? []).map(r => ({ table_name: str(r.table_name), active: bool(r.active) }))
        : null,
      errors: [],
    });
    try {
      await db.query('COMMIT');
    } catch {
      // A read-only transaction of bare SELECTs can only fail COMMIT if the
      // connection died — a connectivity-level failure.
      return failReport(mode, ['connect']);
    }
    return report;
  } catch (e) {
    // Best-effort rollback. A read-only transaction of bare SELECTs rolls
    // back cleanly even after a check-query failure (aborted transaction);
    // if the connection itself is gone the ROLLBACK fails silently.
    await db.query('ROLLBACK').catch(() => undefined);
    // `query:<name>` only for verification-query failures; everything else
    // (connection refused, auth failure, BEGIN failure, COMMIT failure,
    // dropped connection) collapses to `connect`. No driver message, URL,
    // role or PII is ever included in the report.
    if (e instanceof RlsQueryFailure) return failReport(mode, [e.code]);
    return failReport(mode, ['connect']);
  } finally {
    if (!opts.db) await db.end().catch(() => undefined);
  }
}

function failReport(mode: RlsMode, errors: string[]): RlsVerifyReport {
  return {
    ok: false,
    mode,
    roleClass: 'unverified',
    tablesFound: [],
    tablesMissing: [],
    checks: {
      roleBypassRls: false, roleSuperuser: false, roleCanCreateRole: false, roleCanCreateDb: false, roleCanReplicate: false,
      ownsAnyTable: false, ownedTables: [],
      rlsEnabledOnAllTenantTables: false, rlsForcedOnAllTenantTables: false, rlsActiveForRole: null,
      rlsMissing: [], rlsInactiveForRole: [],
      grantsComplete: false, missingGrants: [],
      schemaUsage: false, schemaCreate: false,
    },
    errors,
  };
}

// ---------------------------------------------------------------------------
// CLI (explicit opt-in; `bun run src/rls-verify.ts`)
// ---------------------------------------------------------------------------

export function resolveRlsEnv(env: Record<string, string | undefined>): { url: string; roleName?: string; schema: string } {
  const url = env.RLS_VERIFY_DATABASE_URL;
  if (!url || !url.trim()) throw new Error('RLS_VERIFY_DATABASE_URL_REQUIRED');
  return { url: url.trim(), roleName: env.RLS_VERIFY_ROLE || undefined, schema: env.RLS_VERIFY_SCHEMA || 'public' };
}

if (import.meta.main) {
  let report: RlsVerifyReport;
  let notRun = false;
  try {
    const { url, roleName, schema } = resolveRlsEnv(process.env as Record<string, string | undefined>);
    report = await verifyRls({ url, roleName, schema });
  } catch (e) {
    // Opt-in env missing/invalid: the tool did not run at all.
    report = failReport('as-role', [e instanceof Error ? e.message : 'invalid-env']);
    notRun = true;
  }
  console.log(JSON.stringify(report, null, 2));
  process.exit(report.ok ? 0 : notRun ? 2 : 1);
}
