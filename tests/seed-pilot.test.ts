/**
 * DB-free tests for the one-time pilot seed CLI (src/seed-pilot.ts).
 *
 * Covers exactly the surface that must not need a database:
 *   - env validation (required vars, formats, VERCEL hard block)
 *   - anonymized output (masked ids/status only, no owner data)
 *   - password hash format ($scrypt$... from hashPassword, never plaintext)
 *   - idempotent DML via a scripted fake DbClient (create/exists runs,
 *     password-only-when-null, tenant-scoped context, audit write)
 *   - the dbSeedPilot orchestrator via a fake pool (begin → advisory lock →
 *     seed → commit, rollback on failure, exit codes, anonymized stdout)
 */
import { afterEach, describe, expect, test } from 'bun:test';
import { dbSeedPilot, formatPilotSeedResult, maskId, parsePilotSeedEnv, PILOT_SEED_LOCK_KEY, seedPilotData, type PilotSeedInput } from '../src/seed-pilot';
import { hashPassword, verifyPassword } from '../src/security';

const TENANT_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const USER_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const MEMBERSHIP_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const CUSTOMER_ID = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';

const VALID_ENV = {
  PILOT_TENANT_SLUG: 'stempelpass',
  PILOT_TENANT_LEGAL_NAME: 'Stempelpass GmbH',
  PILOT_OWNER_EMAIL: 'owner@example.com',
  PILOT_OWNER_PASSWORD: 'correct horse battery staple',
};

/** PilotSeedInput shape as produced by parsePilotSeedEnv for VALID_ENV. */
const VALID_INPUT: PilotSeedInput = {
  tenantSlug: 'stempelpass',
  tenantLegalName: 'Stempelpass GmbH',
  ownerEmail: 'owner@example.com',
  ownerPassword: 'correct horse battery staple',
  customerRef: null,
};

/** Fake DbClient recording calls and serving canned rows by SQL substring. */
class ScriptedDb {
  calls: { sql: string; params: unknown[] }[] = [];
  constructor(private readonly script: { match: string; rows: unknown[] }[]) {}
  async query<T = unknown>(sql: string, params: unknown[] = []): Promise<{ rows: T[] }> {
    this.calls.push({ sql, params });
    const hit = this.script.find(r => sql.includes(r.match));
    return { rows: (hit?.rows ?? []) as T[] };
  }
  release(): void {}
}

const CREATED_SCRIPT = [
  { match: 'from tenants where slug', rows: [] },
  { match: 'insert into tenants(', rows: [{ id: TENANT_ID, status: 'active' }] },
  { match: 'set_config', rows: [] },
  { match: 'from users where lower(email)', rows: [] },
  { match: 'insert into users(', rows: [{ id: USER_ID, status: 'active' }] },
  { match: 'from tenant_memberships where tenant_id', rows: [] },
  { match: 'insert into tenant_memberships(', rows: [{ id: MEMBERSHIP_ID, role: 'owner', status: 'active' }] },
  { match: 'from customers where tenant_id', rows: [] },
  { match: 'insert into customers(', rows: [{ id: CUSTOMER_ID, status: 'active' }] },
  { match: 'insert into audit_log', rows: [] },
];

const EXISTS_SCRIPT = [
  { match: 'from tenants where slug', rows: [{ id: TENANT_ID, status: 'active' }] },
  { match: 'set_config', rows: [] },
  { match: 'from users where lower(email)', rows: [{ id: USER_ID, status: 'active', password_hash: '$scrypt$N=32768,r=8,p=1$c2FsdHNhbHRzYWx0c2FsdHNhbHQ$ZGlnZXN0ZGlnZXN0ZGlnZXN0ZGlnZXN0ZGlnZXN0ZGlnZXN0' }] },
  { match: 'from tenant_memberships where tenant_id', rows: [{ id: MEMBERSHIP_ID, role: 'owner', status: 'active' }] },
  { match: 'from customers where tenant_id', rows: [{ id: CUSTOMER_ID, status: 'active' }] },
  { match: 'insert into audit_log', rows: [] },
];

const SCRYPT_HASH_RE = /^\$scrypt\$N=32768,r=8,p=1\$[A-Za-z0-9_-]{22}\$[A-Za-z0-9_-]{43}$/;

// ---------------------------------------------------------------------------
// Env validation
// ---------------------------------------------------------------------------

describe('parsePilotSeedEnv', () => {
  test('rejects every missing required variable with a stable code', () => {
    const result = parsePilotSeedEnv({});
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors).toContain('PILOT_TENANT_SLUG_REQUIRED');
      expect(result.errors).toContain('PILOT_TENANT_LEGAL_NAME_REQUIRED');
      expect(result.errors).toContain('PILOT_OWNER_EMAIL_REQUIRED');
      expect(result.errors).toContain('PILOT_OWNER_PASSWORD_REQUIRED');
      expect(result.errors.length).toBe(4);
    }
  });

  test('hard-blocks VERCEL=1 even with otherwise valid input', () => {
    const result = parsePilotSeedEnv({ ...VALID_ENV, VERCEL: '1' });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors).toEqual(['SEED_NOT_ALLOWED_ON_VERCEL']);
  });

  test('accepts valid input and trims whitespace', () => {
    const result = parsePilotSeedEnv({
      PILOT_TENANT_SLUG: '  stempelpass  ',
      PILOT_TENANT_LEGAL_NAME: '  Stempelpass GmbH  ',
      PILOT_OWNER_EMAIL: '  owner@example.com  ',
      PILOT_OWNER_PASSWORD: 'correct horse battery staple',
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.input).toEqual({ tenantSlug: 'stempelpass', tenantLegalName: 'Stempelpass GmbH', ownerEmail: 'owner@example.com', ownerPassword: 'correct horse battery staple', customerRef: null });
    }
  });

  test('accepts optional PILOT_CUSTOMER_REF and normalizes empty to null', () => {
    expect(parsePilotSeedEnv({ ...VALID_ENV, PILOT_CUSTOMER_REF: 'test-kunde-1' })).toEqual({ ok: true, input: { ...VALID_INPUT, customerRef: 'test-kunde-1' } });
    expect(parsePilotSeedEnv({ ...VALID_ENV, PILOT_CUSTOMER_REF: '   ' })).toEqual({ ok: true, input: { ...VALID_INPUT, customerRef: null } });
  });

  test('rejects invalid slug formats', () => {
    for (const slug of ['Stempelpass', 'bad slug', 'slug_underscore', '-nope', 'nope-', 'x'.repeat(64)]) {
      const result = parsePilotSeedEnv({ ...VALID_ENV, PILOT_TENANT_SLUG: slug });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.errors).toContain('INVALID_TENANT_SLUG');
    }
  });

  test('rejects invalid email formats', () => {
    for (const email of ['not-an-email', 'a@b', 'a b@c.de', 'x'.repeat(255) + '@example.com']) {
      const result = parsePilotSeedEnv({ ...VALID_ENV, PILOT_OWNER_EMAIL: email });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.errors).toContain('INVALID_OWNER_EMAIL');
    }
  });

  test('rejects short passwords (hashPassword contract is >= 12 chars)', () => {
    const result = parsePilotSeedEnv({ ...VALID_ENV, PILOT_OWNER_PASSWORD: 'short' });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors).toContain('PASSWORD_TOO_SHORT');
  });

  test('rejects overlong legal name and customer ref', () => {
    const longName = 'x'.repeat(201);
    const longRef = 'y'.repeat(201);
    const r1 = parsePilotSeedEnv({ ...VALID_ENV, PILOT_TENANT_LEGAL_NAME: longName });
    expect(r1.ok).toBe(false);
    if (!r1.ok) expect(r1.errors).toContain('INVALID_LEGAL_NAME');
    const r2 = parsePilotSeedEnv({ ...VALID_ENV, PILOT_CUSTOMER_REF: longRef });
    expect(r2.ok).toBe(false);
    if (!r2.ok) expect(r2.errors).toContain('INVALID_CUSTOMER_REF');
  });

  test('never echoes input values in validation errors', () => {
    const secret = 'super-secret-password-42';
    const result = parsePilotSeedEnv({ ...VALID_ENV, PILOT_OWNER_PASSWORD: secret, PILOT_TENANT_SLUG: 'Bad Slug!' });
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result)).not.toContain(secret);
    expect(JSON.stringify(result)).not.toContain('Bad Slug!');
  });
});

// ---------------------------------------------------------------------------
// Hash format
// ---------------------------------------------------------------------------

describe('pilot seed password hashing', () => {
  test('hashPassword produces the $scrypt$ format with base64url salt/digest', async () => {
    const hash = await hashPassword('correct horse battery staple');
    expect(hash).toMatch(SCRYPT_HASH_RE);
  });

  test('verifyPassword round-trips true and rejects wrong passwords', async () => {
    const password = 'correct horse battery staple';
    const hash = await hashPassword(password);
    expect(await verifyPassword(password, hash)).toBe(true);
    expect(await verifyPassword('wrong password 123', hash)).toBe(false);
  });

  test('hashPassword rejects passwords shorter than 12 chars', async () => {
    await expect(hashPassword('short')).rejects.toThrow('PASSWORD_TOO_SHORT');
  });
});

// ---------------------------------------------------------------------------
// seedPilotData — idempotent DML on a scripted DbClient
// ---------------------------------------------------------------------------

describe('seedPilotData', () => {
  test('first run creates tenant, owner, membership, customer and audit row', async () => {
    const db = new ScriptedDb(CREATED_SCRIPT);
    const result = await seedPilotData(db, { ...VALID_INPUT, customerRef: 'test-kunde-1' }, '$scrypt$N=32768,r=8,p=1$AAAAAAAAAAAAAAAAAAAAAA$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB');

    expect(result).toEqual({
      tenant: { id: TENANT_ID, status: 'created' },
      owner: { id: USER_ID, status: 'created' },
      membership: { id: MEMBERSHIP_ID, status: 'created', role: 'owner', membershipStatus: 'active' },
      customer: { id: CUSTOMER_ID, status: 'created' },
    });

    const sqls = db.calls.map(c => c.sql);
    // Transaction context is set AFTER the tenant exists (tenant id known).
    const setConfigIdx = sqls.findIndex(s => s.includes('set_config'));
    const tenantInsertIdx = sqls.findIndex(s => s.includes('insert into tenants('));
    expect(setConfigIdx).toBeGreaterThan(tenantInsertIdx);
    expect(db.calls[setConfigIdx].params).toEqual([TENANT_ID]);
    // Audit write present and tenant/user scoped.
    const audit = db.calls.find(c => c.sql.includes('insert into audit_log'));
    expect(audit).toBeDefined();
    expect(audit!.params[0]).toBe(TENANT_ID);
    expect(audit!.params[1]).toBe(USER_ID);
    expect(audit!.params[2]).toBe('pilot.seeded');
  });

  test('the password reaches the DB only as a scrypt hash, never plaintext', async () => {
    const password = 'correct horse battery staple';
    const db = new ScriptedDb(CREATED_SCRIPT);
    await seedPilotData(db, { ...VALID_INPUT, customerRef: null }, await hashPassword(password));
    const all = JSON.stringify(db.calls);
    expect(all).not.toContain(password);
    const userInsert = db.calls.find(c => c.sql.includes('insert into users('));
    expect(userInsert).toBeDefined();
    expect(userInsert!.params[2]).toMatch(SCRYPT_HASH_RE);
  });

  test('second run is a no-op for existing rows (no inserts, status exists)', async () => {
    const db = new ScriptedDb(EXISTS_SCRIPT);
    const result = await seedPilotData(db, { ...VALID_INPUT, customerRef: 'test-kunde-1' }, '$scrypt$N=32768,r=8,p=1$AAAAAAAAAAAAAAAAAAAAAA$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB');

    expect(result).toEqual({
      tenant: { id: TENANT_ID, status: 'exists' },
      owner: { id: USER_ID, status: 'exists' },
      membership: { id: MEMBERSHIP_ID, status: 'exists', role: 'owner', membershipStatus: 'active' },
      customer: { id: CUSTOMER_ID, status: 'exists' },
    });
    const sqls = db.calls.map(c => c.sql);
    expect(sqls.some(s => s.includes('insert into tenants('))).toBe(false);
    expect(sqls.some(s => s.includes('insert into users('))).toBe(false);
    expect(sqls.some(s => s.includes('insert into tenant_memberships('))).toBe(false);
    expect(sqls.some(s => s.includes('insert into customers('))).toBe(false);
    // Existing password is never overwritten: no UPDATE users statement.
    expect(sqls.some(s => s.includes('update users'))).toBe(false);
  });

  test('fills the password hash only when the existing user has none', async () => {
    const db = new ScriptedDb([
      { match: 'from tenants where slug', rows: [{ id: TENANT_ID, status: 'active' }] },
      { match: 'set_config', rows: [] },
      { match: 'from users where lower(email)', rows: [{ id: USER_ID, status: 'active', password_hash: null }] },
      { match: 'from tenant_memberships where tenant_id', rows: [{ id: MEMBERSHIP_ID, role: 'owner', status: 'active' }] },
      { match: 'from customers where tenant_id', rows: [] },
      { match: 'insert into customers(', rows: [{ id: CUSTOMER_ID, status: 'active' }] },
      { match: 'insert into audit_log', rows: [] },
    ]);
    await seedPilotData(db, { ...VALID_INPUT, customerRef: null }, '$scrypt$N=32768,r=8,p=1$AAAAAAAAAAAAAAAAAAAAAA$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB');
    const update = db.calls.find(c => c.sql.includes('update users'));
    expect(update).toBeDefined();
    expect(update!.params[0]).toMatch(SCRYPT_HASH_RE);
    expect(update!.params[1]).toBe(USER_ID);
  });

  test('without PILOT_CUSTOMER_REF no customer query runs and result customer is null', async () => {
    const db = new ScriptedDb(CREATED_SCRIPT);
    const result = await seedPilotData(db, { ...VALID_INPUT, customerRef: null }, '$scrypt$N=32768,r=8,p=1$AAAAAAAAAAAAAAAAAAAAAA$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB');
    expect(result.customer).toBeNull();
    expect(db.calls.some(c => c.sql.includes('customers'))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Anonymization
// ---------------------------------------------------------------------------

describe('formatPilotSeedResult / maskId', () => {
  test('maskId keeps only the first 8 chars plus ellipsis', () => {
    expect(maskId('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')).toBe('aaaaaaaa…');
    expect(maskId('abc')).toBe('••••');
    expect(maskId('')).toBe('unknown');
  });

  test('output contains masked ids and statuses only — never owner data or full UUIDs', () => {
    const result = {
      tenant: { id: TENANT_ID, status: 'created' as const },
      owner: { id: USER_ID, status: 'exists' as const },
      membership: { id: MEMBERSHIP_ID, status: 'created' as const, role: 'owner', membershipStatus: 'active' },
      customer: { id: CUSTOMER_ID, status: 'created' as const },
    };
    const lines = formatPilotSeedResult(result);
    const output = lines.join('\n');
    expect(lines[0]).toBe('pilot_seed_ok');
    expect(output).toContain('tenant id=aaaaaaaa… status=created');
    expect(output).toContain('owner id=bbbbbbbb… status=exists');
    expect(output).toContain('membership id=cccccccc… status=created role=owner membership_status=active');
    expect(output).toContain('customer id=dddddddd… status=created');
    for (const id of [TENANT_ID, USER_ID, MEMBERSHIP_ID, CUSTOMER_ID]) expect(output).not.toContain(id);
    for (const secret of ['stempelpass', 'Stempelpass GmbH', 'owner@example.com', 'test-kunde-1', 'correct horse battery staple']) {
      expect(output).not.toContain(secret);
    }
  });

  test('skipped customer renders as customer status=skipped', () => {
    const lines = formatPilotSeedResult({
      tenant: { id: TENANT_ID, status: 'exists' },
      owner: { id: USER_ID, status: 'exists' },
      membership: { id: MEMBERSHIP_ID, status: 'exists', role: 'owner', membershipStatus: 'active' },
      customer: null,
    });
    expect(lines).toContain('customer status=skipped');
  });
});

// ---------------------------------------------------------------------------
// dbSeedPilot orchestrator (fake pool)
// ---------------------------------------------------------------------------

interface FakePoolRecord { sql: string; params: unknown[] }

function fakePool(script: { match: string; rows: unknown[] }[], failOnMatch?: string) {
  const calls: FakePoolRecord[] = [];
  const pool = {
    calls,
    value: {
      connect: async () => ({
        query: async <T = unknown>(sql: string, params: unknown[] = []) => {
          calls.push({ sql, params });
          if (failOnMatch && sql.includes(failOnMatch)) throw new Error('db exploded');
          const hit = script.find(r => sql.includes(r.match));
          return { rows: (hit?.rows ?? []) as T[] };
        },
        release: () => {},
      }),
      end: async () => {},
    },
  };
  return pool;
}

describe('dbSeedPilot', () => {
  const origLog = console.log;
  const origError = console.error;
  const lines: string[] = [];
  afterEach(() => {
    console.log = origLog;
    console.error = origError;
    lines.length = 0;
  });
  function captureConsole() {
    console.log = (...a: unknown[]) => { lines.push(a.join(' ')); };
    console.error = (...a: unknown[]) => { lines.push(a.join(' ')); };
  }

  test('missing env fails fast with exit 1 and never connects', async () => {
    captureConsole();
    const pool = fakePool(CREATED_SCRIPT);
    const code = await dbSeedPilot({}, () => pool.value);
    expect(code).toBe(1);
    expect(pool.calls.length).toBe(0);
    expect(lines.join('\n')).toContain('pilot_seed_failed PILOT_TENANT_SLUG_REQUIRED');
  });

  test('VERCEL=1 fails fast with exit 1 and never connects', async () => {
    captureConsole();
    const pool = fakePool(CREATED_SCRIPT);
    const code = await dbSeedPilot({ ...VALID_ENV, VERCEL: '1' }, () => pool.value);
    expect(code).toBe(1);
    expect(pool.calls.length).toBe(0);
    expect(lines.join('\n')).toContain('pilot_seed_failed SEED_NOT_ALLOWED_ON_VERCEL');
  });

  test('success exits 0, holds the advisory lock, commits and prints anonymized lines', async () => {
    captureConsole();
    const pool = fakePool(CREATED_SCRIPT);
    const code = await dbSeedPilot(
      { ...VALID_ENV, PILOT_CUSTOMER_REF: 'test-kunde-1', DATABASE_URL: 'postgresql://fake/db' },
      () => pool.value,
    );
    expect(code).toBe(0);
    const sqls = pool.calls.map(c => c.sql);
    expect(sqls[0]).toBe('begin');
    expect(sqls[1]).toContain('pg_advisory_xact_lock');
    expect(pool.calls[1].params).toEqual([PILOT_SEED_LOCK_KEY]);
    expect(sqls[sqls.length - 1]).toBe('commit');
    expect(sqls.some(s => s.includes('rollback'))).toBe(false);
    const output = lines.join('\n');
    expect(output).toContain('pilot_seed_ok');
    expect(output).toContain('tenant id=aaaaaaaa… status=created');
    expect(output).toContain('customer id=dddddddd… status=created');
    for (const secret of ['stempelpass', 'Stempelpass GmbH', 'owner@example.com', 'test-kunde-1', 'correct horse battery staple']) {
      expect(output).not.toContain(secret);
    }
  });

  test('failure rolls back and exits 1 with a sanitized error', async () => {
    captureConsole();
    const pool = fakePool(CREATED_SCRIPT, 'insert into tenants(');
    const code = await dbSeedPilot(
      { ...VALID_ENV, DATABASE_URL: 'postgresql://fake/db' },
      () => pool.value,
    );
    expect(code).toBe(1);
    const sqls = pool.calls.map(c => c.sql);
    expect(sqls).toContain('begin');
    expect(sqls).toContain('rollback');
    expect(sqls).not.toContain('commit');
    expect(lines.join('\n')).toContain('pilot_seed_failed');
    expect(lines.join('\n')).not.toContain('correct horse battery staple');
  });

  test('missing DATABASE_URL exits 1 without hashing or connecting', async () => {
    captureConsole();
    const pool = fakePool(CREATED_SCRIPT);
    const code = await dbSeedPilot({ ...VALID_ENV }, () => pool.value);
    expect(code).toBe(1);
    expect(pool.calls.length).toBe(0);
    expect(lines.join('\n')).toContain('pilot_seed_failed DATABASE_URL_REQUIRED');
  });
});
