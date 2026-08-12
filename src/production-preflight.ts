/**
 * Production preflight — static, read-only, anonymized.
 *
 * A pre-deployment gate that verifies everything about the production
 * configuration that can be checked WITHOUT a database connection, without
 * network calls and without printing a single secret value. It is the
 * counterpart to the opt-in live diagnostic `src/rls-verify.ts`: preflight
 * answers "is the deployment statically configured plausibly?", rls-verify
 * answers "does tenant isolation actually hold on the live database?".
 *
 * Safety contract (do not weaken):
 *   - NO database connection is ever opened. This module imports only pure
 *     helpers (`gcp-credentials.ts`, `email.ts`) and reads files from disk.
 *     It deliberately does NOT import `src/server.ts`, `src/db.ts` or the
 *     `postgres` package, so importing or running it can never touch Neon.
 *   - Secret-free output: the JSON report contains booleans, classified
 *     status values and error codes only. Env values are never echoed —
 *     not DATABASE_URL (which may embed a password), not SESSION_SECRET, not
 *     Google key material, not MFA/communication secrets. File paths are
 *     classified (e.g. GOOGLE_APPLICATION_CREDENTIALS_UNREADABLE), never
 *     printed.
 *   - Honest static gate: external-account (Workload Identity Federation)
 *     mode cannot verify the OIDC token statically — on Vercel Functions it
 *     arrives per request as the `x-vercel-oidc-token` header. The preflight
 *     reports the mode and adds a note; live issuer approval, Neon
 *     connectivity and app-role RLS remain pilot steps (see TESTING.md).
 *
 * Exit codes (CLI):
 *   0  all required checks passed,
 *   1  at least one required check failed (see `errors` in the report),
 *   2  the preflight could not complete (internal error; report contains
 *      only PREFLIGHT_INTERNAL_ERROR).
 *
 * Run with: `bun run production-preflight`
 */

import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import {
  parseExternalAccountConfig,
  serviceAccountEmailFromImpersonationUrl,
  type GcpCredentialMode,
} from './gcp-credentials.js';
import { communicationHashSecret, smtpConfiguration } from './email.js';

// ---------------------------------------------------------------------------
// IO seam (real fs by default; tests inject an in-memory tree)
// ---------------------------------------------------------------------------

export interface PreflightIo {
  readFile(path: string): Promise<string>;
  readdir(path: string): Promise<string[]>;
}

export const realIo: PreflightIo = {
  readFile: path => readFile(path, 'utf8'),
  readdir,
};

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

export interface EnvironmentCheck {
  databaseConfigured: boolean;
  sessionSecretConfigured: boolean;
  frontendOriginConfigured: boolean;
  frontendOriginValid: boolean | null; // null when not configured
  errors: string[];
}

/** Required production variables. Values are never returned — booleans only. */
export function environmentCheck(env: NodeJS.ProcessEnv): EnvironmentCheck {
  const errors: string[] = [];
  const databaseConfigured = Boolean(env.DATABASE_URL?.trim());
  if (!databaseConfigured) errors.push('DATABASE_URL_REQUIRED');

  const sessionSecret = env.SESSION_SECRET ?? '';
  const sessionSecretConfigured = sessionSecret.length >= 32;
  if (!sessionSecretConfigured) errors.push(sessionSecret ? 'SESSION_SECRET_TOO_SHORT' : 'SESSION_SECRET_REQUIRED');

  // CORS origin for the admin web surface. PUBLIC_SITE_ORIGIN is the legacy
  // alias; FRONTEND_ORIGIN takes precedence (see src/server.ts corsOrigin).
  const origin = env.FRONTEND_ORIGIN?.trim() || env.PUBLIC_SITE_ORIGIN?.trim() || '';
  const frontendOriginConfigured = origin.length > 0;
  let frontendOriginValid: boolean | null = null;
  if (!frontendOriginConfigured) errors.push('FRONTEND_ORIGIN_REQUIRED');
  else {
    // CORS origins never carry a path or trailing slash.
    frontendOriginValid = /^https?:\/\/[^\s/]+$/.test(origin);
    if (!frontendOriginValid) errors.push('FRONTEND_ORIGIN_INVALID');
  }

  return { databaseConfigured, sessionSecretConfigured, frontendOriginConfigured, frontendOriginValid, errors };
}

export interface GoogleWalletCheck {
  configured: boolean;
  issuerIdConfigured: boolean;
  mode: GcpCredentialMode | null;
  errors: string[];
  notes: string[];
}

function parseServiceAccountJson(raw: string): { client_email: string; private_key: string } | null {
  try {
    const parsed = JSON.parse(raw) as { client_email?: string; private_key?: string };
    if (parsed.client_email && parsed.private_key) return { client_email: parsed.client_email, private_key: parsed.private_key };
  } catch {
    /* invalid configuration is treated as absent */
  }
  return null;
}

/**
 * Google Wallet credential configuration (keyless-first). Mirrors
 * `resolveGcpCredentials` including the GOOGLE_APPLICATION_CREDENTIALS file
 * path, but deliberately does NOT require an OIDC token: on Vercel Functions
 * the token is a per-request header that cannot and must not be checked
 * statically.
 */
export async function googleWalletCheck(env: NodeJS.ProcessEnv, io: PreflightIo = realIo): Promise<GoogleWalletCheck> {
  const errors: string[] = [];
  const notes: string[] = [];

  const issuerIdConfigured = Boolean(env.GOOGLE_ISSUER_ID?.trim());
  if (!issuerIdConfigured) errors.push('GOOGLE_ISSUER_ID_REQUIRED');

  let mode: GcpCredentialMode | null = null;
  const rawExternal = env.GOOGLE_EXTERNAL_ACCOUNT_JSON;
  const adcPath = env.GOOGLE_APPLICATION_CREDENTIALS?.trim();
  const rawJson = env.GOOGLE_SERVICE_ACCOUNT_JSON;
  const email = env.GOOGLE_SERVICE_ACCOUNT_EMAIL?.trim();
  const key = env.GOOGLE_PRIVATE_KEY;

  if (rawExternal) {
    const cfg = parseExternalAccountConfig(rawExternal);
    if (cfg) {
      if (serviceAccountEmailFromImpersonationUrl(cfg.service_account_impersonation_url ?? '')) mode = 'external-account';
      else errors.push('GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATION_REQUIRED');
    } else errors.push('GOOGLE_EXTERNAL_ACCOUNT_JSON_INVALID');
  } else if (adcPath) {
    const content = await io.readFile(adcPath).catch(() => null);
    if (content === null) {
      errors.push('GOOGLE_APPLICATION_CREDENTIALS_UNREADABLE');
    } else {
      const cfg = parseExternalAccountConfig(content);
      if (cfg) {
        if (serviceAccountEmailFromImpersonationUrl(cfg.service_account_impersonation_url ?? '')) mode = 'external-account';
        else errors.push('GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATION_REQUIRED');
      } else if (parseServiceAccountJson(content)) {
        mode = 'service-account-json';
      } else errors.push('GOOGLE_APPLICATION_CREDENTIALS_INVALID');
    }
  } else if (rawJson) {
    if (parseServiceAccountJson(rawJson)) mode = 'service-account-json';
    else errors.push('GOOGLE_SERVICE_ACCOUNT_JSON_INVALID');
  } else if (email && key) {
    mode = 'service-account-json';
  } else {
    errors.push('GOOGLE_CREDENTIALS_REQUIRED');
  }

  if (mode === 'external-account') {
    notes.push('external-account mode: the OIDC token arrives per request as the x-vercel-oidc-token header on Vercel Functions and cannot be verified statically by this preflight');
  }

  return { configured: issuerIdConfigured && mode !== null, issuerIdConfigured, mode, errors, notes };
}

export interface MfaCheck {
  active: boolean;
  keyValid: boolean | null; // null when MFA is inactive
  errors: string[];
  notes: string[];
}

/**
 * MFA key validation. The key is only *required* once MFA is activated
 * (MFA_ENCRYPTION_KEY set -> the EncryptedMfaSecretStore is constructed in
 * src/server.ts). Validation mirrors src/mfa.ts exactly: 64-hex or base64
 * decoding to 32 bytes. The key value is never returned or printed.
 */
export function mfaCheck(env: NodeJS.ProcessEnv): MfaCheck {
  const errors: string[] = [];
  const notes: string[] = [];
  const encoded = env.MFA_ENCRYPTION_KEY;
  const active = Boolean(encoded);
  let keyValid: boolean | null = null;
  if (active) {
    const key = /^[0-9a-f]{64}$/i.test(encoded!) ? Buffer.from(encoded!, 'hex') : Buffer.from(encoded!, 'base64');
    keyValid = key.length === 32;
    if (!keyValid) errors.push('MFA_ENCRYPTION_KEY_INVALID');
  } else {
    notes.push('MFA not activated (no MFA_ENCRYPTION_KEY); the key becomes required the moment MFA is enabled');
  }
  notes.push('membership-level MFA enforcement (mfa_required) is stored in the database and invisible to this static check; set MFA_ENCRYPTION_KEY before any tenant enforces MFA');
  return { active, keyValid, errors, notes };
}

export interface CommunicationCheck {
  active: boolean;
  hashSecretConfigured: boolean | null; // null when communication is inactive
  errors: string[];
  notes: string[];
}

/**
 * Communication is "active" when all five EMAIL_SMTP_* values are present
 * (smtpConfiguration). Only then is the keyed recipient-pseudonymisation
 * secret (COMMUNICATION_HASH_SECRET, >= 32 chars) required.
 */
export function communicationCheck(env: NodeJS.ProcessEnv): CommunicationCheck {
  const errors: string[] = [];
  const notes: string[] = [];
  const active = smtpConfiguration(env) !== null;
  let hashSecretConfigured: boolean | null = null;
  if (active) {
    hashSecretConfigured = communicationHashSecret(env) !== null;
    if (!hashSecretConfigured) errors.push('COMMUNICATION_HASH_SECRET_REQUIRED');
  } else {
    const partiallyConfigured = ['EMAIL_SMTP_HOST', 'EMAIL_SMTP_PORT', 'EMAIL_SMTP_USER', 'EMAIL_SMTP_PASSWORD', 'EMAIL_FROM']
      .some(k => Boolean(env[k]));
    notes.push(partiallyConfigured
      ? 'SMTP partially configured: all five EMAIL_SMTP_* values are required together; communication stays inactive'
      : 'SMTP not configured; communication inactive');
  }
  return { active, hashSecretConfigured, errors, notes };
}

/** Exact ordered migration set the runner (`src/db.ts` runMigrations) applies. */
export const EXPECTED_MIGRATIONS: readonly string[] = [
  '001_init.sql',
  '002_security.sql',
  '003_auth.sql',
  '004_mfa.sql',
  '005_communication.sql',
  '006_pilot_onboarding.sql',
  '007_communication_source_allowlist.sql',
  '008_entry_point_resolver.sql',
  '009_sessions_rls_and_audit_split.sql',
  '010_membership_mfa_resolver.sql',
  '011_card_soft_delete.sql',
  '012_privacy_info.sql',
];

export interface MigrationCheck {
  ok: boolean;
  present: number;
  expected: number;
  files: string[];
  missing: string[];
  errors: string[];
}

/** Filesystem-only: 001–010 present, runner-compatible names, contiguous. */
export async function migrationCheck(dir: string, io: PreflightIo = realIo): Promise<MigrationCheck> {
  const errors: string[] = [];
  let files: string[] = [];
  try {
    files = (await io.readdir(dir)).filter(f => /^\d+_.+\.sql$/.test(f)).sort();
  } catch {
    errors.push('MIGRATIONS_DIR_UNREADABLE');
  }
  const missing = EXPECTED_MIGRATIONS.filter(f => !files.includes(f));
  const extra = files.filter(f => !EXPECTED_MIGRATIONS.includes(f));
  const badNames = files.filter(f => !/^\d{3}_[a-z0-9_]+\.sql$/.test(f));
  const prefixes = files.map(f => f.slice(0, 3));
  const contiguous = prefixes.length === EXPECTED_MIGRATIONS.length
    && prefixes.every((p, i) => p === String(i + 1).padStart(3, '0'));
  if (errors.length === 0 && (missing.length > 0 || extra.length > 0 || !contiguous || badNames.length > 0)) {
    errors.push('MIGRATIONS_INCOMPLETE');
  }
  return { ok: errors.length === 0, present: files.length, expected: EXPECTED_MIGRATIONS.length, files, missing, errors };
}

export interface VercelCheck {
  ok: boolean;
  entryPointPresent: boolean;
  entryPointImportsHandler: boolean;
  configPresent: boolean;
  /** Inline `functions.*.runtime` in vercel.json — the platform rejects this key, so it must be null. */
  runtime: string | null;
  region: string | null;
  rewritePresent: boolean;
  startScriptPresent: boolean;
  buildScriptPresent: boolean;
  errors: string[];
}

/**
 * Node.js version configured at the Vercel project level (project settings,
 * NOT vercel.json — the platform rejects `functions.runtime` in vercel.json).
 * Verified via the Vercel Projects API (GET /v9/projects/{id}) on 2026-08-09
 * for project `project-ywbp8` (team `od-k`): `nodeVersion: 24.x`.
 *
 * The preflight is static and offline, so it cannot re-query the project;
 * this constant only documents the version the platform actually runs and
 * must be kept in sync with the project setting. The check itself accepts
 * any project-level version — it only rejects a runtime declared inline.
 */
export const PROJECT_NODE_VERSION = '24.x';

/** Vercel serverless entry point and Node build wiring (api/index.ts, vercel.json, package.json). */
export async function vercelCheck(root: string, io: PreflightIo = realIo): Promise<VercelCheck> {
  const errors: string[] = [];

  const entryPointRaw = await io.readFile(join(root, 'api', 'index.ts')).catch(() => null);
  const entryPointPresent = entryPointRaw !== null;
  let entryPointImportsHandler = false;
  if (entryPointRaw) {
    entryPointImportsHandler = /from\s+['"]\.\.\/src\/server\.js['"]/.test(entryPointRaw) && /\bfetchHandler\b/.test(entryPointRaw);
    if (!entryPointImportsHandler) errors.push('ENTRY_POINT_INVALID');
  } else errors.push('ENTRY_POINT_MISSING');

  const vercelRaw = await io.readFile(join(root, 'vercel.json')).catch(() => null);
  const configPresent = vercelRaw !== null;
  let runtime: string | null = null;
  let region: string | null = null;
  let rewritePresent = false;
  if (!vercelRaw) errors.push('VERCEL_CONFIG_MISSING');
  else {
    try {
      const cfg = JSON.parse(vercelRaw) as {
        functions?: Record<string, { runtime?: string; regions?: string[] }>;
        rewrites?: { source?: string; destination?: string }[];
      };
      const fn = cfg.functions?.['api/index.ts'];
      runtime = fn?.runtime ?? null;
      // The Vercel platform rejects `functions.*.runtime` in vercel.json; the
      // Node.js version is a project-level setting only. An inline runtime is
      // a hard deployment blocker, so it fails the gate.
      if (runtime !== null) errors.push('VERCEL_RUNTIME_INLINE_REJECTED');
      region = fn?.regions?.[0] ?? null;
      if (region !== 'fra1') errors.push('VERCEL_REGION_INVALID');
      rewritePresent = Boolean(cfg.rewrites?.some(r => r.source === '/(.*)' && r.destination === '/api/index'));
      if (!rewritePresent) errors.push('VERCEL_REWRITE_MISSING');
    } catch {
      errors.push('VERCEL_CONFIG_INVALID');
    }
  }

  const pkgRaw = await io.readFile(join(root, 'package.json')).catch(() => null);
  let startScriptPresent = false;
  let buildScriptPresent = false;
  if (!pkgRaw) errors.push('PACKAGE_JSON_MISSING');
  else {
    try {
      const pkg = JSON.parse(pkgRaw) as { scripts?: Record<string, string> };
      startScriptPresent = Boolean(pkg.scripts?.start);
      buildScriptPresent = Boolean(pkg.scripts?.build);
    } catch {
      errors.push('PACKAGE_JSON_INVALID');
    }
  }
  if (!startScriptPresent) errors.push('START_SCRIPT_MISSING');
  if (!buildScriptPresent) errors.push('BUILD_SCRIPT_MISSING');

  return {
    ok: errors.length === 0,
    entryPointPresent,
    entryPointImportsHandler,
    configPresent,
    runtime,
    region,
    rewritePresent,
    startScriptPresent,
    buildScriptPresent,
    errors,
  };
}

// ---------------------------------------------------------------------------
// Report assembly + CLI
// ---------------------------------------------------------------------------

export interface PreflightReport {
  ok: boolean;
  noDatabaseConnectionOpened: true;
  checks: {
    environment: Omit<EnvironmentCheck, 'errors'>;
    googleWallet: Omit<GoogleWalletCheck, 'errors' | 'notes'>;
    mfa: Omit<MfaCheck, 'errors' | 'notes'>;
    communication: Omit<CommunicationCheck, 'errors' | 'notes'>;
    migrations: Omit<MigrationCheck, 'errors'>;
    vercel: Omit<VercelCheck, 'errors'> & { nodeVersion: string };
  };
  errors: string[];
  notes: string[];
}

export interface PreflightOptions {
  env?: NodeJS.ProcessEnv;
  /** Backend project root (defaults to the parent of src/). */
  root?: string;
  io?: PreflightIo;
}

export async function runPreflight(opts: PreflightOptions = {}): Promise<PreflightReport> {
  const env = opts.env ?? process.env;
  const root = opts.root ?? join(import.meta.dir, '..');
  const io = opts.io ?? realIo;

  const errors: string[] = [];
  const notes: string[] = [];

  const environment = environmentCheck(env);
  errors.push(...environment.errors);

  const googleWallet = await googleWalletCheck(env, io);
  errors.push(...googleWallet.errors);
  notes.push(...googleWallet.notes);

  const mfa = mfaCheck(env);
  errors.push(...mfa.errors);
  notes.push(...mfa.notes);

  const communication = communicationCheck(env);
  errors.push(...communication.errors);
  notes.push(...communication.notes);

  const migrations = await migrationCheck(join(root, 'migrations'), io);
  errors.push(...migrations.errors);

  const vercel = await vercelCheck(root, io);
  errors.push(...vercel.errors);
  if (vercel.runtime === null) {
    notes.push(`Node.js runtime is project-managed (${PROJECT_NODE_VERSION} in the Vercel project settings); vercel.json must not declare functions.runtime — the platform rejects it`);
  }

  return {
    ok: errors.length === 0,
    noDatabaseConnectionOpened: true,
    checks: {
      environment: {
        databaseConfigured: environment.databaseConfigured,
        sessionSecretConfigured: environment.sessionSecretConfigured,
        frontendOriginConfigured: environment.frontendOriginConfigured,
        frontendOriginValid: environment.frontendOriginValid,
      },
      googleWallet: {
        configured: googleWallet.configured,
        issuerIdConfigured: googleWallet.issuerIdConfigured,
        mode: googleWallet.mode,
      },
      mfa: { active: mfa.active, keyValid: mfa.keyValid },
      communication: { active: communication.active, hashSecretConfigured: communication.hashSecretConfigured },
      migrations: {
        ok: migrations.ok,
        present: migrations.present,
        expected: migrations.expected,
        files: migrations.files,
        missing: migrations.missing,
      },
      vercel: {
        ok: vercel.ok,
        entryPointPresent: vercel.entryPointPresent,
        entryPointImportsHandler: vercel.entryPointImportsHandler,
        configPresent: vercel.configPresent,
        runtime: vercel.runtime,
        nodeVersion: PROJECT_NODE_VERSION,
        region: vercel.region,
        rewritePresent: vercel.rewritePresent,
        startScriptPresent: vercel.startScriptPresent,
        buildScriptPresent: vercel.buildScriptPresent,
      },
    },
    errors,
    notes,
  };
}

if (import.meta.main) {
  try {
    const report = await runPreflight();
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.ok ? 0 : 1);
  } catch {
    // Never echo the internal error: it could carry environment-derived
    // details. A classified code is all the operator gets.
    console.log(JSON.stringify({ ok: false, noDatabaseConnectionOpened: true, errors: ['PREFLIGHT_INTERNAL_ERROR'] }, null, 2));
    process.exit(2);
  }
}
