/**
 * Production preflight — unit tests, no database, no network.
 *
 * Pins the static pre-deployment gate in `src/production-preflight.ts`:
 *   - every required-environment failure code (DATABASE_URL / SESSION_SECRET /
 *     FRONTEND_ORIGIN),
 *   - Google Wallet credential detection in all three shapes (external-account
 *     JSON, GOOGLE_APPLICATION_CREDENTIALS file, service-account JSON/split
 *     env) plus issuer requirement and the classified failure codes,
 *   - MFA key validation (64-hex / 32-byte base64, only when MFA is active),
 *   - communication activation (all five EMAIL_SMTP_* values) and the
 *     COMMUNICATION_HASH_SECRET requirement,
 *   - the exact migration set 001–014 (filesystem only) and Vercel entry
 *     point / Node build wiring,
 *   - the anonymization contract: NO secret value and no 'leak' marker may
 *     ever appear in the report, and the module must never import the DB.
 * Exit codes 0/1 are pinned end-to-end by spawning the real CLI with a
 * scrubbed environment (exit 1) and a complete fake environment (exit 0).
 */

import { describe, expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  EXPECTED_MIGRATIONS,
  PROJECT_NODE_VERSION,
  communicationCheck,
  environmentCheck,
  googleWalletCheck,
  mfaCheck,
  migrationCheck,
  runPreflight,
  vercelCheck,
  type PreflightIo,
} from '../src/production-preflight';

const ROOT = join(import.meta.dir, '..');

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const VALID_EXTERNAL_ACCOUNT_JSON = JSON.stringify({
  type: 'external_account',
  audience: '//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/preflight-pool/providers/preflight-provider',
  subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
  token_url: 'https://sts.googleapis.com/v1/token',
  service_account_impersonation_url:
    'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/preflight-sa@example.iam.gserviceaccount.com:generateAccessToken',
  scope: 'https://www.googleapis.com/auth/cloud-platform',
});

const VALID_SERVICE_ACCOUNT_JSON = JSON.stringify({
  type: 'service_account',
  client_email: 'preflight-sa@example.iam.gserviceaccount.com',
  private_key: '-----BEGIN PRIVATE KEY-----\nMIIFakeKey\n-----END PRIVATE KEY-----\n',
});

const HEX64 = 'deadbeef'.repeat(8);
const BASE64_32B = Buffer.alloc(32, 7).toString('base64');
const LONG_SECRET = 'x'.repeat(64);

function baseEnv(): Record<string, string> {
  return {
    DATABASE_URL: 'postgresql://user:pass@host/db?sslmode=require',
    SESSION_SECRET: LONG_SECRET,
    FRONTEND_ORIGIN: 'https://stempelpass.example',
    GOOGLE_ISSUER_ID: '1234567890',
    GOOGLE_EXTERNAL_ACCOUNT_JSON: VALID_EXTERNAL_ACCOUNT_JSON,
    MFA_ENCRYPTION_KEY: HEX64,
  };
}

/** In-memory filesystem seam: `missingDirs` make readdir throw. */
function fakeIo(files: Record<string, string>, opts: { missingDirs?: string[] } = {}): PreflightIo {
  const missingDirs = new Set(opts.missingDirs ?? []);
  return {
    readFile: async path => {
      const content = files[path];
      if (content === undefined) throw Object.assign(new Error(`ENOENT: ${path}`), { code: 'ENOENT' });
      return content;
    },
    readdir: async path => {
      if (missingDirs.has(path)) throw new Error('ENOENT');
      const prefix = path.endsWith('/') ? path : `${path}/`;
      return Object.keys(files)
        .filter(k => k.startsWith(prefix))
        .map(k => k.slice(prefix.length))
        .filter(n => !n.includes('/'))
        .sort();
    },
  };
}

// The platform rejects `functions.*.runtime` in vercel.json; the Node.js
// version is a project-level setting (project-ywbp8: 24.x). The fixture
// therefore declares NO runtime.
const VALID_VERCEL_JSON = JSON.stringify({
  version: 2,
  functions: { 'api/index.ts': { regions: ['fra1'] } },
  rewrites: [{ source: '/(.*)', destination: '/api/index' }],
});
const VALID_PACKAGE_JSON = JSON.stringify({ scripts: { start: 'bun run src/server.ts', build: 'bun run typecheck' } });
// The compiled package is Node ESM (package.json "type": "module"), so the
// entry point must import the compiled module via an ESM-resolvable `.js`
// specifier — Node cannot resolve `../src/server.ts` (only server.js exists
// in the function package) and extensionless relative imports also fail.
const VALID_ENTRY_POINT = "import { fetchHandler } from '../src/server.js';\nexport default async function handler(request: Request): Promise<Response> { return fetchHandler(request); }\n";

const VERCEL_FILES = (root: string, vercelJson = VALID_VERCEL_JSON, entry = VALID_ENTRY_POINT, pkg = VALID_PACKAGE_JSON) => ({
  [join(root, 'api', 'index.ts')]: entry,
  [join(root, 'vercel.json')]: vercelJson,
  [join(root, 'package.json')]: pkg,
});

// ---------------------------------------------------------------------------
// environmentCheck
// ---------------------------------------------------------------------------

describe('environmentCheck (required production variables)', () => {
  test('all required values present -> no errors', () => {
    const { errors, databaseConfigured, sessionSecretConfigured, frontendOriginConfigured, frontendOriginValid } =
      environmentCheck(baseEnv());
    expect(errors).toEqual([]);
    expect(databaseConfigured).toBe(true);
    expect(sessionSecretConfigured).toBe(true);
    expect(frontendOriginConfigured).toBe(true);
    expect(frontendOriginValid).toBe(true);
  });

  test('DATABASE_URL missing/blank -> DATABASE_URL_REQUIRED', () => {
    expect(environmentCheck({ ...baseEnv(), DATABASE_URL: '' }).errors).toEqual(['DATABASE_URL_REQUIRED']);
    expect(environmentCheck({ ...baseEnv(), DATABASE_URL: '   ' }).errors).toEqual(['DATABASE_URL_REQUIRED']);
    const { databaseConfigured } = environmentCheck({ ...baseEnv(), DATABASE_URL: undefined as never });
    expect(databaseConfigured).toBe(false);
  });

  test('SESSION_SECRET missing -> SESSION_SECRET_REQUIRED, too short -> SESSION_SECRET_TOO_SHORT', () => {
    expect(environmentCheck({ ...baseEnv(), SESSION_SECRET: undefined as never }).errors).toEqual(['SESSION_SECRET_REQUIRED']);
    expect(environmentCheck({ ...baseEnv(), SESSION_SECRET: 'short' }).errors).toEqual(['SESSION_SECRET_TOO_SHORT']);
    expect(environmentCheck({ ...baseEnv(), SESSION_SECRET: 'x'.repeat(32) }).errors).toEqual([]);
  });

  test('FRONTEND_ORIGIN missing -> FRONTEND_ORIGIN_REQUIRED (PUBLIC_SITE_ORIGIN alias accepted)', () => {
    expect(environmentCheck({ ...baseEnv(), FRONTEND_ORIGIN: undefined as never }).errors).toEqual(['FRONTEND_ORIGIN_REQUIRED']);
    const viaAlias = environmentCheck({ ...baseEnv(), FRONTEND_ORIGIN: undefined as never, PUBLIC_SITE_ORIGIN: 'https://alias.example' });
    expect(viaAlias.errors).toEqual([]);
    expect(viaAlias.frontendOriginConfigured).toBe(true);
  });

  test('FRONTEND_ORIGIN invalid -> FRONTEND_ORIGIN_INVALID (scheme, path, trailing slash)', () => {
    for (const bad of ['not-a-url', 'https://', 'ftp://x.example', 'https://x.example/path', 'https://x.example/']) {
      expect(environmentCheck({ ...baseEnv(), FRONTEND_ORIGIN: bad }).errors).toEqual(['FRONTEND_ORIGIN_INVALID']);
    }
    expect(environmentCheck({ ...baseEnv(), FRONTEND_ORIGIN: 'http://localhost:3000' }).errors).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// googleWalletCheck
// ---------------------------------------------------------------------------

describe('googleWalletCheck (keyless-first credential detection)', () => {
  test('GOOGLE_ISSUER_ID missing -> GOOGLE_ISSUER_ID_REQUIRED', async () => {
    const { errors, issuerIdConfigured } = await googleWalletCheck({ ...baseEnv(), GOOGLE_ISSUER_ID: undefined as never });
    expect(errors).toContain('GOOGLE_ISSUER_ID_REQUIRED');
    expect(issuerIdConfigured).toBe(false);
  });

  test('external-account JSON (preferred keyless mode) -> mode external-account, no credential error', async () => {
    const check = await googleWalletCheck(baseEnv());
    expect(check.mode).toBe('external-account');
    expect(check.configured).toBe(true);
    expect(check.errors).toEqual([]);
    expect(check.notes.some(n => n.includes('x-vercel-oidc-token'))).toBe(true);
  });

  test('external-account JSON without impersonation URL -> GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATION_REQUIRED', async () => {
    const broken = JSON.stringify({ ...JSON.parse(VALID_EXTERNAL_ACCOUNT_JSON), service_account_impersonation_url: undefined });
    const check = await googleWalletCheck({ ...baseEnv(), GOOGLE_EXTERNAL_ACCOUNT_JSON: broken });
    expect(check.errors).toEqual(['GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATION_REQUIRED']);
    expect(check.mode).toBeNull();
  });

  test('external-account JSON unparseable -> GOOGLE_EXTERNAL_ACCOUNT_JSON_INVALID', async () => {
    const check = await googleWalletCheck({ ...baseEnv(), GOOGLE_EXTERNAL_ACCOUNT_JSON: 'not json' });
    expect(check.errors).toEqual(['GOOGLE_EXTERNAL_ACCOUNT_JSON_INVALID']);
    expect(check.mode).toBeNull();
  });

  test('GOOGLE_APPLICATION_CREDENTIALS file path: external_account file detected', async () => {
    const io = fakeIo({ '/creds/external.json': VALID_EXTERNAL_ACCOUNT_JSON });
    const env = { ...baseEnv(), GOOGLE_EXTERNAL_ACCOUNT_JSON: undefined as never, GOOGLE_APPLICATION_CREDENTIALS: '/creds/external.json' };
    const check = await googleWalletCheck(env, io);
    expect(check.mode).toBe('external-account');
    expect(check.errors).toEqual([]);
  });

  test('GOOGLE_APPLICATION_CREDENTIALS file path: service_account file detected', async () => {
    const io = fakeIo({ '/creds/sa.json': VALID_SERVICE_ACCOUNT_JSON });
    const env = { ...baseEnv(), GOOGLE_EXTERNAL_ACCOUNT_JSON: undefined as never, GOOGLE_APPLICATION_CREDENTIALS: '/creds/sa.json' };
    const check = await googleWalletCheck(env, io);
    expect(check.mode).toBe('service-account-json');
    expect(check.errors).toEqual([]);
  });

  test('GOOGLE_APPLICATION_CREDENTIALS unreadable/invalid -> classified codes, never the path content', async () => {
    const unreadable = await googleWalletCheck(
      { ...baseEnv(), GOOGLE_EXTERNAL_ACCOUNT_JSON: undefined as never, GOOGLE_APPLICATION_CREDENTIALS: '/creds/missing.json' },
      fakeIo({}),
    );
    expect(unreadable.errors).toEqual(['GOOGLE_APPLICATION_CREDENTIALS_UNREADABLE']);
    const invalid = await googleWalletCheck(
      { ...baseEnv(), GOOGLE_EXTERNAL_ACCOUNT_JSON: undefined as never, GOOGLE_APPLICATION_CREDENTIALS: '/creds/bad.json' },
      fakeIo({ '/creds/bad.json': 'not json' }),
    );
    expect(invalid.errors).toEqual(['GOOGLE_APPLICATION_CREDENTIALS_INVALID']);
    expect(JSON.stringify(unreadable)).not.toContain('/creds/');
    expect(JSON.stringify(invalid)).not.toContain('/creds/');
  });

  test('service-account JSON (fallback) -> mode service-account-json', async () => {
    const check = await googleWalletCheck({ ...baseEnv(), GOOGLE_EXTERNAL_ACCOUNT_JSON: undefined as never, GOOGLE_SERVICE_ACCOUNT_JSON: VALID_SERVICE_ACCOUNT_JSON });
    expect(check.mode).toBe('service-account-json');
    expect(check.errors).toEqual([]);
  });

  test('service-account split env (EMAIL + PRIVATE_KEY) -> mode service-account-json', async () => {
    const check = await googleWalletCheck({
      ...baseEnv(),
      GOOGLE_EXTERNAL_ACCOUNT_JSON: undefined as never,
      GOOGLE_SERVICE_ACCOUNT_EMAIL: 'preflight-sa@example.iam.gserviceaccount.com',
      GOOGLE_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----\nMIIFakeKey\n-----END PRIVATE KEY-----\n',
    });
    expect(check.mode).toBe('service-account-json');
    expect(check.errors).toEqual([]);
  });

  test('service-account JSON incomplete -> GOOGLE_SERVICE_ACCOUNT_JSON_INVALID', async () => {
    const check = await googleWalletCheck({
      ...baseEnv(),
      GOOGLE_EXTERNAL_ACCOUNT_JSON: undefined as never,
      GOOGLE_SERVICE_ACCOUNT_JSON: JSON.stringify({ type: 'service_account' }),
    });
    expect(check.errors).toEqual(['GOOGLE_SERVICE_ACCOUNT_JSON_INVALID']);
  });

  test('no credentials at all -> GOOGLE_CREDENTIALS_REQUIRED', async () => {
    const check = await googleWalletCheck({ ...baseEnv(), GOOGLE_EXTERNAL_ACCOUNT_JSON: undefined as never });
    expect(check.errors).toEqual(['GOOGLE_CREDENTIALS_REQUIRED']);
    expect(check.mode).toBeNull();
    expect(check.configured).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// mfaCheck
// ---------------------------------------------------------------------------

describe('mfaCheck (key required only when MFA is active)', () => {
  test('no key -> inactive, no error', () => {
    const check = mfaCheck({ ...baseEnv(), MFA_ENCRYPTION_KEY: undefined as never });
    expect(check.active).toBe(false);
    expect(check.keyValid).toBeNull();
    expect(check.errors).toEqual([]);
  });

  test('64-hex and 32-byte base64 keys are valid', () => {
    expect(mfaCheck({ ...baseEnv(), MFA_ENCRYPTION_KEY: HEX64 })).toMatchObject({ active: true, keyValid: true, errors: [] });
    expect(mfaCheck({ ...baseEnv(), MFA_ENCRYPTION_KEY: BASE64_32B })).toMatchObject({ active: true, keyValid: true, errors: [] });
  });

  test('short / non-decoding keys -> MFA_ENCRYPTION_KEY_INVALID', () => {
    for (const bad of ['short', 'z'.repeat(64), '!'.repeat(44), HEX64.slice(0, 32)]) {
      expect(mfaCheck({ ...baseEnv(), MFA_ENCRYPTION_KEY: bad }).errors).toEqual(['MFA_ENCRYPTION_KEY_INVALID']);
    }
  });
});

// ---------------------------------------------------------------------------
// communicationCheck
// ---------------------------------------------------------------------------

const SMTP = { EMAIL_SMTP_HOST: 'smtp.example', EMAIL_SMTP_PORT: '587', EMAIL_SMTP_USER: 'u', EMAIL_SMTP_PASSWORD: 'p', EMAIL_FROM: 'a@b.c' };

describe('communicationCheck (hash secret required only when SMTP active)', () => {
  test('no SMTP -> inactive, no error', () => {
    const check = communicationCheck({ ...baseEnv(), ...SMTP, EMAIL_SMTP_HOST: undefined as never });
    expect(check.active).toBe(false);
    expect(check.hashSecretConfigured).toBeNull();
    expect(check.errors).toEqual([]);
  });

  test('partial SMTP -> inactive with explanatory note, no error', () => {
    const check = communicationCheck({ ...baseEnv(), EMAIL_SMTP_HOST: 'smtp.example' });
    expect(check.active).toBe(false);
    expect(check.errors).toEqual([]);
    expect(check.notes.some(n => n.includes('partially configured'))).toBe(true);
  });

  test('SMTP active + COMMUNICATION_HASH_SECRET >= 32 -> configured', () => {
    const check = communicationCheck({ ...baseEnv(), ...SMTP, COMMUNICATION_HASH_SECRET: 'c'.repeat(32) });
    expect(check.active).toBe(true);
    expect(check.hashSecretConfigured).toBe(true);
    expect(check.errors).toEqual([]);
  });

  test('SMTP active + missing/short hash secret -> COMMUNICATION_HASH_SECRET_REQUIRED', () => {
    const missing = communicationCheck({ ...baseEnv(), ...SMTP });
    expect(missing.errors).toEqual(['COMMUNICATION_HASH_SECRET_REQUIRED']);
    const short = communicationCheck({ ...baseEnv(), ...SMTP, COMMUNICATION_HASH_SECRET: 'too-short' });
    expect(short.errors).toEqual(['COMMUNICATION_HASH_SECRET_REQUIRED']);
  });
});

// ---------------------------------------------------------------------------
// migrationCheck
// ---------------------------------------------------------------------------

describe('migrationCheck (filesystem only, exact 001–014 set)', () => {
  test('real migrations directory: complete contiguous set', async () => {
    const check = await migrationCheck(join(ROOT, 'migrations'));
    expect(check.ok).toBe(true);
    expect(check.present).toBe(14);
    expect(check.expected).toBe(14);
    expect(check.missing).toEqual([]);
    expect(check.files).toEqual([...EXPECTED_MIGRATIONS]);
  });

  test('missing file -> MIGRATIONS_INCOMPLETE with missing name listed', async () => {
    const root = '/proj';
    const files: Record<string, string> = {};
    for (const f of EXPECTED_MIGRATIONS.slice(0, 11)) files[join(root, 'migrations', f)] = '-- sql';
    const check = await migrationCheck(join(root, 'migrations'), fakeIo(files));
    expect(check.ok).toBe(false);
    expect(check.errors).toEqual(['MIGRATIONS_INCOMPLETE']);
    expect(check.missing).toEqual(EXPECTED_MIGRATIONS.slice(11));
  });

  test('extra file beyond 014 -> MIGRATIONS_INCOMPLETE', async () => {
    const root = '/proj';
    const files: Record<string, string> = {};
    for (const f of EXPECTED_MIGRATIONS) files[join(root, 'migrations', f)] = '-- sql';
    files[join(root, 'migrations', '015_extra.sql')] = '-- sql';
    const check = await migrationCheck(join(root, 'migrations'), fakeIo(files));
    expect(check.ok).toBe(false);
    expect(check.errors).toEqual(['MIGRATIONS_INCOMPLETE']);
  });

  test('non-contiguous / malformed names -> MIGRATIONS_INCOMPLETE', async () => {
    const root = '/proj';
    const files: Record<string, string> = {};
    for (const f of EXPECTED_MIGRATIONS) files[join(root, 'migrations', f)] = '-- sql';
    files[join(root, 'migrations', '0010_extra.sql')] = '-- sql';
    const check = await migrationCheck(join(root, 'migrations'), fakeIo(files));
    expect(check.ok).toBe(false);
    expect(check.errors).toEqual(['MIGRATIONS_INCOMPLETE']);
  });

  test('unreadable directory -> MIGRATIONS_DIR_UNREADABLE', async () => {
    const check = await migrationCheck('/nope/migrations', fakeIo({}, { missingDirs: ['/nope/migrations'] }));
    expect(check.ok).toBe(false);
    expect(check.errors).toEqual(['MIGRATIONS_DIR_UNREADABLE']);
  });
});

// ---------------------------------------------------------------------------
// vercelCheck
// ---------------------------------------------------------------------------

describe('vercelCheck (entry point + Node build wiring)', () => {
  test('real project files -> ok', async () => {
    const check = await vercelCheck(ROOT);
    expect(check.ok).toBe(true);
    expect(check.entryPointPresent).toBe(true);
    expect(check.entryPointImportsHandler).toBe(true);
    expect(check.configPresent).toBe(true);
    expect(check.runtime).toBeNull();
    expect(check.region).toBe('fra1');
    expect(check.rewritePresent).toBe(true);
    expect(check.startScriptPresent).toBe(true);
    expect(check.buildScriptPresent).toBe(true);
  });

  test('missing api/index.ts -> ENTRY_POINT_MISSING', async () => {
    const root = '/proj';
    const io = fakeIo({ [join(root, 'vercel.json')]: VALID_VERCEL_JSON, [join(root, 'package.json')]: VALID_PACKAGE_JSON });
    const check = await vercelCheck(root, io);
    expect(check.ok).toBe(false);
    expect(check.errors).toContain('ENTRY_POINT_MISSING');
  });

  test('entry point without fetchHandler import -> ENTRY_POINT_INVALID', async () => {
    const root = '/proj';
    const io = fakeIo(VERCEL_FILES(root, VALID_VERCEL_JSON, 'export default () => new Response("hi");\n'));
    const check = await vercelCheck(root, io);
    expect(check.errors).toContain('ENTRY_POINT_INVALID');
  });

  test('inline runtime / wrong region / missing rewrite -> classified codes', async () => {
    const root = '/proj';
    // The platform rejects functions.*.runtime in vercel.json entirely — any
    // inline runtime is a hard deployment blocker, whatever the version.
    const inlineRuntime = JSON.stringify({ version: 2, functions: { 'api/index.ts': { runtime: 'nodejs24.x', regions: ['fra1'] } }, rewrites: [{ source: '/(.*)', destination: '/api/index' }] });
    const r0 = await vercelCheck(root, fakeIo(VERCEL_FILES(root, inlineRuntime)));
    expect(r0.errors).toEqual(['VERCEL_RUNTIME_INLINE_REJECTED']);

    const badRegion = JSON.stringify({ version: 2, functions: { 'api/index.ts': { regions: ['iad1'] } }, rewrites: [{ source: '/(.*)', destination: '/api/index' }] });
    const r1 = await vercelCheck(root, fakeIo(VERCEL_FILES(root, badRegion)));
    expect(r1.errors).toEqual(['VERCEL_REGION_INVALID']);

    const noRewrite = JSON.stringify({ version: 2, functions: { 'api/index.ts': { regions: ['fra1'] } } });
    const r2 = await vercelCheck(root, fakeIo(VERCEL_FILES(root, noRewrite)));
    expect(r2.errors).toEqual(['VERCEL_REWRITE_MISSING']);
  });

  test('missing/invalid vercel.json and package.json -> classified codes', async () => {
    const root = '/proj';
    const r1 = await vercelCheck(root, fakeIo({ ...VERCEL_FILES(root), [join(root, 'vercel.json')]: 'not json' }));
    expect(r1.errors).toContain('VERCEL_CONFIG_INVALID');
    const r2 = await vercelCheck(root, fakeIo({}));
    expect(r2.errors).toEqual(expect.arrayContaining(['VERCEL_CONFIG_MISSING', 'PACKAGE_JSON_MISSING']));
    const r3 = await vercelCheck(root, fakeIo(VERCEL_FILES(root, VALID_VERCEL_JSON, VALID_ENTRY_POINT, JSON.stringify({ scripts: { start: 'x' } }))));
    expect(r3.errors).toEqual(['BUILD_SCRIPT_MISSING']);
    const r4 = await vercelCheck(root, fakeIo(VERCEL_FILES(root, VALID_VERCEL_JSON, VALID_ENTRY_POINT, JSON.stringify({ scripts: { build: 'x' } }))));
    expect(r4.errors).toEqual(['START_SCRIPT_MISSING']);
  });
});

// ---------------------------------------------------------------------------
// runPreflight end to end (real files, fake env)
// ---------------------------------------------------------------------------

describe('runPreflight (report assembly)', () => {
  test('complete fake environment against the real project -> ok, exit-0 shape', async () => {
    const report = await runPreflight({ env: baseEnv(), root: ROOT });
    expect(report.ok).toBe(true);
    expect(report.errors).toEqual([]);
    expect(report.noDatabaseConnectionOpened).toBe(true);
    expect(report.checks.environment.databaseConfigured).toBe(true);
    expect(report.checks.googleWallet.mode).toBe('external-account');
    expect(report.checks.mfa.keyValid).toBe(true);
    expect(report.checks.communication.active).toBe(false);
    expect(report.checks.migrations.ok).toBe(true);
    expect(report.checks.vercel.ok).toBe(true);
    expect(report.checks.vercel.runtime).toBeNull();
    expect(report.checks.vercel.nodeVersion).toBe(PROJECT_NODE_VERSION);
    expect(report.notes.some(n => n.includes('project-managed'))).toBe(true);
  });

  test('single-fault envs map to exactly their error code', async () => {
    const cases: Array<[Partial<Record<string, string>>, string]> = [
      [{ DATABASE_URL: '' }, 'DATABASE_URL_REQUIRED'],
      [{ SESSION_SECRET: 'short' }, 'SESSION_SECRET_TOO_SHORT'],
      [{ FRONTEND_ORIGIN: '' }, 'FRONTEND_ORIGIN_REQUIRED'],
      [{ GOOGLE_ISSUER_ID: '' }, 'GOOGLE_ISSUER_ID_REQUIRED'],
      [{ GOOGLE_EXTERNAL_ACCOUNT_JSON: '' }, 'GOOGLE_CREDENTIALS_REQUIRED'],
      [{ MFA_ENCRYPTION_KEY: 'bad' }, 'MFA_ENCRYPTION_KEY_INVALID'],
    ];
    for (const [mut, code] of cases) {
      const report = await runPreflight({ env: { ...baseEnv(), ...mut }, root: ROOT });
      expect(report.ok).toBe(false);
      expect(report.errors).toContain(code);
    }
  });

  test('combined faults collect all codes (communication active, google broken, mfa invalid)', async () => {
    const report = await runPreflight({
      env: {
        ...baseEnv(),
        ...SMTP,
        GOOGLE_EXTERNAL_ACCOUNT_JSON: undefined as never,
        MFA_ENCRYPTION_KEY: 'bad',
      },
      root: ROOT,
    });
    expect(report.errors).toEqual(expect.arrayContaining(['GOOGLE_CREDENTIALS_REQUIRED', 'MFA_ENCRYPTION_KEY_INVALID', 'COMMUNICATION_HASH_SECRET_REQUIRED']));
  });
});

// ---------------------------------------------------------------------------
// Anonymization contract
// ---------------------------------------------------------------------------

describe('anonymization contract (no secret values, no DB import)', () => {
  test('report serialization never contains any env value, even with every secret set', async () => {
    const leakEnv: Record<string, string> = {
      DATABASE_URL: 'postgresql://leakuser:leakpass99@leakdb.example/leakdb?sslmode=require',
      SESSION_SECRET: 'SESSIONLEAKSECRET-0123456789012345',
      FRONTEND_ORIGIN: 'https://leak-origin.example',
      GOOGLE_ISSUER_ID: '42424242',
      GOOGLE_EXTERNAL_ACCOUNT_JSON: VALID_EXTERNAL_ACCOUNT_JSON,
      GOOGLE_SERVICE_ACCOUNT_EMAIL: 'leak-sa@example.iam.gserviceaccount.com',
      GOOGLE_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----LEAKPRIVATEKEY-----END PRIVATE KEY-----',
      MFA_ENCRYPTION_KEY: HEX64,
      EMAIL_SMTP_HOST: 'leak-smtp.example',
      EMAIL_SMTP_PORT: '587',
      EMAIL_SMTP_USER: 'leak-user',
      EMAIL_SMTP_PASSWORD: 'leak-smtp-pass',
      EMAIL_FROM: 'leak-from@example.com',
      COMMUNICATION_HASH_SECRET: 'communication-leak-secret-0123456789abcdef',
      GOOGLE_APPLICATION_CREDENTIALS: '/home/leak/creds.json',
    };
    const report = await runPreflight({ env: leakEnv, root: ROOT });
    const serialized = JSON.stringify(report);
    for (const token of [
      'leakpass99', 'leakuser', 'leakdb', 'SESSIONLEAKSECRET', 'leak-origin', '42424242',
      'LEAKPRIVATEKEY', 'deadbeef', 'leak-smtp', 'leak-user', 'leak-smtp-pass',
      'leak-from@', 'communication-leak-secret', '/home/leak/creds.json', 'leak-sa@',
    ]) {
      expect(serialized).not.toContain(token);
    }
    // Catch-all: the fixed report vocabulary contains no 'leak' marker at all.
    expect(serialized.toLowerCase()).not.toContain('leak');
  });

  test('module source never imports the database layer', async () => {
    const src = await readFile(join(ROOT, 'src', 'production-preflight.ts'), 'utf8');
    expect(src).not.toMatch(/from\s+['"]\.\/server['"]/);
    expect(src).not.toMatch(/from\s+['"]\.\/db['"]/);
    expect(src).not.toMatch(/from\s+['"]postgres['"]/);
    expect(src).not.toMatch(/createPostgresPool|new Pool\b|postgres\(/);
  });
});

// ---------------------------------------------------------------------------
// CLI end to end (spawned with scrubbed env; exit codes 0/1)
// ---------------------------------------------------------------------------

const SCRUBBED_KEYS = [
  'DATABASE_URL', 'TEST_DATABASE_URL', 'SESSION_SECRET', 'FRONTEND_ORIGIN', 'PUBLIC_SITE_ORIGIN',
  'GOOGLE_ISSUER_ID', 'GOOGLE_EXTERNAL_ACCOUNT_JSON', 'GOOGLE_APPLICATION_CREDENTIALS',
  'GOOGLE_SERVICE_ACCOUNT_JSON', 'GOOGLE_SERVICE_ACCOUNT_EMAIL', 'GOOGLE_PRIVATE_KEY',
  'MFA_ENCRYPTION_KEY', 'COMMUNICATION_HASH_SECRET', 'EMAIL_SMTP_HOST', 'EMAIL_SMTP_PORT',
  'EMAIL_SMTP_USER', 'EMAIL_SMTP_PASSWORD', 'EMAIL_FROM', 'APPLE_TEAM_IDENTIFIER',
  'APPLE_PASS_TYPE_IDENTIFIER', 'APPLE_PRIVATE_KEY', 'TIGER_PUBLIC_KEY', 'TIGER_SECRET_KEY',
  'TIGER_PROJECT_ID', 'VERCEL_OIDC_TOKEN',
];

function childEnv(overrides: Record<string, string>): Record<string, string> {
  const env: Record<string, string> = { PATH: process.env.PATH ?? '' };
  for (const [k, v] of Object.entries(process.env)) if (!SCRUBBED_KEYS.includes(k)) env[k] = v ?? '';
  Object.assign(env, overrides);
  return env;
}

describe('CLI (bun run production-preflight)', () => {
  test('scrubbed environment -> exit 1, classified errors, no secrets', () => {
    const res = Bun.spawnSync([process.execPath, 'run', 'src/production-preflight.ts'], {
      cwd: ROOT,
      env: childEnv({}),
      stdout: 'pipe',
      stderr: 'pipe',
    });
    expect(res.exitCode).toBe(1);
    const out = res.stdout.toString();
    const report = JSON.parse(out) as { ok: boolean; errors: string[]; noDatabaseConnectionOpened: boolean };
    expect(report.ok).toBe(false);
    expect(report.noDatabaseConnectionOpened).toBe(true);
    expect(report.errors).toEqual(expect.arrayContaining([
      'DATABASE_URL_REQUIRED',
      'SESSION_SECRET_REQUIRED',
      'FRONTEND_ORIGIN_REQUIRED',
      'GOOGLE_ISSUER_ID_REQUIRED',
      'GOOGLE_CREDENTIALS_REQUIRED',
    ]));
    const neonUrl = process.env.TEST_DATABASE_URL;
    if (neonUrl) expect(out).not.toContain(neonUrl);
  });

  test('complete environment -> exit 0, and the DATABASE_URL value never appears', () => {
    const res = Bun.spawnSync([process.execPath, 'run', 'src/production-preflight.ts'], {
      cwd: ROOT,
      env: childEnv({
        DATABASE_URL: 'postgresql://cli-user:cli-pass@cli-host/cli-db?sslmode=require',
        SESSION_SECRET: LONG_SECRET,
        FRONTEND_ORIGIN: 'https://stempelpass.example',
        GOOGLE_ISSUER_ID: '1234567890',
        GOOGLE_EXTERNAL_ACCOUNT_JSON: VALID_EXTERNAL_ACCOUNT_JSON,
      }),
      stdout: 'pipe',
      stderr: 'pipe',
    });
    expect(res.exitCode).toBe(0);
    const out = res.stdout.toString();
    expect(JSON.parse(out).ok).toBe(true);
    expect(out).not.toContain('cli-user');
    expect(out).not.toContain('cli-pass');
    expect(out).not.toContain('cli-host');
  });
});
