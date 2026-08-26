import { afterEach, describe, expect, test } from 'bun:test';
import {
  dbRotateOwnerPassword,
  parseOwnerPasswordRotationEnv,
  rotateOwnerPassword,
  OWNER_PASSWORD_ROTATION_LOCK_KEY,
  type PasswordReader,
} from '../src/rotate-owner-password';
import { verifyPassword } from '../src/security';

const TENANT_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const USER_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const OWNER_EMAIL = 'owner@example.com';
const PASSWORD = 'throwaway-password-2026';

class FakeDb {
  calls: { sql: string; params: unknown[] }[] = [];
  operator = true;
  prior: { tenant_id: string; entity_id: string }[] = [];
  async query<T = unknown>(sql: string, params: unknown[] = []): Promise<{ rows: T[] }> {
    this.calls.push({ sql, params });
    if (sql.includes('pg_tables')) return { rows: [{ is_operator: this.operator }] as T[] };
    if (sql.includes('from tenants t')) return { rows: [{ tenantId: TENANT_ID, userId: USER_ID, ownerEmail: OWNER_EMAIL }] as T[] };
    if (sql.includes("action = 'operator.owner_password_rotated'") && sql.startsWith('select')) return { rows: this.prior as T[] };
    if (sql.startsWith('update users')) return { rows: [{ id: USER_ID }] as T[] };
    if (sql.startsWith('insert into audit_log')) return { rows: this.prior.length ? [] : [{ id: '1' }] as T[] };
    return { rows: [] as T[] };
  }
  release() {}
}

function poolFor(db: FakeDb) {
  return { connect: async () => db, end: async () => {} };
}

const env = {
  DATABASE_URL: 'postgresql://operator.invalid/db',
  OWNER_PASSWORD_ROTATION_TENANT_SLUG: 'stempelpass',
  OWNER_PASSWORD_ROTATION_OWNER_EMAIL: OWNER_EMAIL,
  OWNER_PASSWORD_ROTATION_ID: 'test-rotation-1',
  OWNER_PASSWORD_ROTATION_PASSWORD: PASSWORD,
};

describe('parseOwnerPasswordRotationEnv', () => {
  test('requires target fields and blocks Vercel', () => {
    expect(parseOwnerPasswordRotationEnv({})).toEqual({ ok: false, errors: [
      'OWNER_PASSWORD_ROTATION_TENANT_SLUG_REQUIRED',
      'OWNER_PASSWORD_ROTATION_OWNER_EMAIL_REQUIRED',
    ] });
    expect(parseOwnerPasswordRotationEnv({ ...env, VERCEL: '1' })).toEqual({ ok: false, errors: ['OWNER_PASSWORD_ROTATION_NOT_ALLOWED_ON_VERCEL'] });
  });

  test('does not echo input values in validation errors', () => {
    const result = parseOwnerPasswordRotationEnv({ ...env, OWNER_PASSWORD_ROTATION_TENANT_SLUG: 'bad slug!' });
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result)).not.toContain(PASSWORD);
    expect(JSON.stringify(result)).not.toContain('bad slug!');
  });
});

describe('rotateOwnerPassword', () => {
  test('updates hash, revokes sessions, and appends one operator audit event', async () => {
    const db = new FakeDb();
    const hash = '$scrypt$N=32768,r=8,p=1$AAAAAAAAAAAAAAAAAAAAAA$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
    const result = await rotateOwnerPassword(db, { tenantSlug: 'stempelpass', ownerEmail: OWNER_EMAIL, operationId: 'rotation-1' }, hash);
    expect(result).toBe('rotated');
    const update = db.calls.find(call => call.sql.startsWith('update users'));
    expect(update?.params[0]).toBe(hash);
    expect(update?.params).not.toContain(PASSWORD);
    expect(db.calls.some(call => call.sql.startsWith('update sessions'))).toBe(true);
    const audit = db.calls.find(call => call.sql.startsWith('insert into audit_log'));
    expect(audit).toBeDefined();
    expect(audit?.params).toContain(TENANT_ID);
    expect(audit?.params).toContain(USER_ID);
    expect(JSON.stringify(audit?.params)).toContain('rotation-1');
    expect(JSON.stringify(db.calls)).not.toContain(PASSWORD);
  });

  test('same operation id is idempotent and does not update or revoke again', async () => {
    const db = new FakeDb();
    db.prior = [{ tenant_id: TENANT_ID, entity_id: USER_ID }];
    const result = await rotateOwnerPassword(db, { tenantSlug: 'stempelpass', ownerEmail: OWNER_EMAIL, operationId: 'rotation-1' }, 'hash');
    expect(result).toBe('already_applied');
    expect(db.calls.some(call => call.sql.startsWith('update users'))).toBe(false);
    expect(db.calls.some(call => call.sql.startsWith('update sessions'))).toBe(false);
    expect(db.calls.some(call => call.sql.startsWith('insert into audit_log'))).toBe(false);
  });
});

describe('dbRotateOwnerPassword', () => {
  const output: string[] = [];
  const originalLog = console.log;
  const originalError = console.error;
  afterEach(() => {
    console.log = originalLog;
    console.error = originalError;
    output.length = 0;
  });

  test('hashes before DML, uses the operator guard and emits no password', async () => {
    console.log = (...args: unknown[]) => output.push(args.join(' '));
    console.error = (...args: unknown[]) => output.push(args.join(' '));
    const db = new FakeDb();
    const code = await dbRotateOwnerPassword(env, () => poolFor(db));
    expect(code).toBe(0);
    expect(output).toEqual(['owner_password_rotation_ok status=rotated']);
    expect(output.join('\n')).not.toContain(PASSWORD);
    expect(db.calls[0].sql).toContain('pg_tables');
    expect(db.calls.some(call => call.sql.includes('pg_advisory_xact_lock') && call.params[0] === OWNER_PASSWORD_ROTATION_LOCK_KEY)).toBe(true);
    const updateIndex = db.calls.findIndex(call => call.sql.startsWith('update users'));
    const targetIndex = db.calls.findIndex(call => call.sql.includes('from tenants t'));
    expect(updateIndex).toBeGreaterThan(targetIndex);
    const update = db.calls[updateIndex];
    const storedHash = String(update.params[0]);
    expect(storedHash).toMatch(/^\$scrypt\$/);
    expect(await verifyPassword(PASSWORD, storedHash)).toBe(true);
    expect(JSON.stringify(db.calls)).not.toContain(PASSWORD);
  });

  test('rejects the runtime role before any transaction or DML', async () => {
    console.error = (...args: unknown[]) => output.push(args.join(' '));
    const db = new FakeDb();
    db.operator = false;
    const code = await dbRotateOwnerPassword(env, () => poolFor(db));
    expect(code).toBe(1);
    expect(output.join('\n')).toContain('OWNER_PASSWORD_ROTATION_ROLE_NOT_OPERATOR');
    expect(db.calls).toHaveLength(1);
  });

  test('accepts an ephemeral stdin reader without putting it in output', async () => {
    console.log = (...args: unknown[]) => output.push(args.join(' '));
    const db = new FakeDb();
    const stdinReader: PasswordReader = async () => PASSWORD;
    const stdinEnv: NodeJS.ProcessEnv = { ...env };
    delete stdinEnv.OWNER_PASSWORD_ROTATION_PASSWORD;
    const code = await dbRotateOwnerPassword(stdinEnv, () => poolFor(db), stdinReader);
    expect(code).toBe(0);
    expect(output.join('\n')).not.toContain(PASSWORD);
  });
});
