import { afterEach, describe, expect, test } from 'bun:test';
import {
  CREATE_TENANT_LOCK_KEY,
  createTenantData,
  dbCreateTenant,
  formatCreateTenantResult,
  maskCreateTenantId,
  parseCreateTenantEnv,
  type CreateTenantInput,
} from '../src/create-tenant';
import { hashPassword } from '../src/security';

const TENANT_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const USER_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const MEMBERSHIP_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const RULE_ID = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const CUSTOMER_ID = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const PUBLIC_KEY = '0123456789abcdef0123456789abcdef';
const PASSWORD = 'correct horse battery staple';
const HASH = '$scrypt$N=32768,r=8,p=1$AAAAAAAAAAAAAAAAAAAAAA$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

const VALID_ENV = {
  TENANT_SLUG: 'pro-pet-koller',
  TENANT_LEGAL_NAME: 'Pro Pet Koller GmbH',
  TENANT_PLAN_CODE: 'up_to_500',
  OWNER_EMAIL: 'owner@example.com',
  OWNER_PASSWORD: PASSWORD,
  CARD_TITLE: 'Pro Pet Treuekarte',
  CARD_TEXT: 'Sammle Stempel und erhalte eine Prämie.',
  PRIMARY_COLOR: '#123456',
  SECONDARY_COLOR: '#ffffff',
  STAMPS_REQUIRED: '10',
  REWARD_TITLE: 'Gratis Kauartikel',
  REWARD_DESCRIPTION: 'Ein Kauartikel nach zehn Stempeln.',
};

const VALID_INPUT: CreateTenantInput = {
  tenantSlug: 'pro-pet-koller', tenantLegalName: 'Pro Pet Koller GmbH', tenantPlanCode: 'up_to_500',
  ownerEmail: 'owner@example.com', ownerPassword: PASSWORD, cardTitle: 'Pro Pet Treuekarte',
  cardText: 'Sammle Stempel und erhalte eine Prämie.', primaryColor: '#123456', secondaryColor: '#ffffff',
  stampsRequired: 10, rewardTitle: 'Gratis Kauartikel', rewardDescription: 'Ein Kauartikel nach zehn Stempeln.',
  iconAssetId: null, logoAssetId: null, customerRef: null,
};

class ScriptedDb {
  calls: { sql: string; params: unknown[] }[] = [];
  constructor(private readonly script: { match: string; rows: unknown[] }[]) {}
  async query<T = unknown>(sql: string, params: unknown[] = []): Promise<{ rows: T[] }> {
    this.calls.push({ sql, params });
    const hit = this.script.find(item => sql.includes(item.match));
    return { rows: (hit?.rows ?? []) as T[] };
  }
  release() {}
}

const CREATED_SCRIPT = [
  { match: 'from tenants where slug', rows: [] },
  { match: 'insert into tenants(', rows: [{ id: TENANT_ID, status: 'active' }] },
  { match: 'set_config', rows: [] },
  { match: 'from users where lower(email)', rows: [] },
  { match: 'insert into users(', rows: [{ id: USER_ID, status: 'active' }] },
  { match: 'from tenant_memberships where tenant_id', rows: [] },
  { match: 'insert into tenant_memberships(', rows: [{ id: MEMBERSHIP_ID, role: 'owner', status: 'active' }] },
  { match: 'insert into tenant_branding(', rows: [] },
  { match: 'select id from stamp_rules', rows: [] },
  { match: 'insert into stamp_rules(', rows: [{ id: RULE_ID }] },
  { match: 'insert into tenant_entry_points(', rows: [{ public_key: PUBLIC_KEY, join_path: `/join/${PUBLIC_KEY}` }] },
  { match: 'from customers where tenant_id', rows: [] },
  { match: 'insert into customers(', rows: [{ id: CUSTOMER_ID, status: 'active' }] },
  { match: 'insert into audit_log', rows: [] },
];

const EXISTS_SCRIPT = [
  { match: 'from tenants where slug', rows: [{ id: TENANT_ID, status: 'active' }] },
  { match: 'set_config', rows: [] },
  { match: 'from users where lower(email)', rows: [{ id: USER_ID, status: 'active', password_hash: HASH }] },
  { match: 'from tenant_memberships where tenant_id', rows: [{ id: MEMBERSHIP_ID, role: 'owner', status: 'active' }] },
  { match: 'insert into tenant_branding(', rows: [] },
  { match: 'select id from stamp_rules', rows: [{ id: RULE_ID }] },
  { match: 'insert into tenant_entry_points(', rows: [{ public_key: PUBLIC_KEY, join_path: `/join/${PUBLIC_KEY}` }] },
  { match: 'from customers where tenant_id', rows: [{ id: CUSTOMER_ID, status: 'active' }] },
  { match: 'insert into audit_log', rows: [] },
];

function expectNoSecrets(text: string) {
  for (const value of [
    'pro-pet-koller', 'Pro Pet Koller GmbH', 'owner@example.com', PASSWORD,
    'test-customer', 'postgresql://fake/db', 'CUSTOMER_REF', 'DATABASE_URL',
  ]) expect(text).not.toContain(value);
}

describe('parseCreateTenantEnv', () => {
  test('rejects missing values with stable codes and no echoed values', () => {
    const result = parseCreateTenantEnv({});
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors).toContain('TENANT_SLUG_REQUIRED');
      expect(result.errors).toContain('TENANT_PLAN_CODE_REQUIRED');
      expect(result.errors).toContain('OWNER_PASSWORD_REQUIRED');
      expect(result.errors).toContain('CARD_TITLE_REQUIRED');
      expect(result.errors).toContain('STAMPS_REQUIRED_REQUIRED');
      expect(result.errors.length).toBeGreaterThan(10);
    }
    expect(JSON.stringify(result)).not.toContain(PASSWORD);
  });

  test('hard-blocks VERCEL=1 before parsing or connecting', () => {
    expect(parseCreateTenantEnv({ ...VALID_ENV, VERCEL: '1' })).toEqual({ ok: false, errors: ['CREATE_TENANT_NOT_ALLOWED_ON_VERCEL'] });
  });

  test('trims text fields, keeps password exact, and parses optional values', () => {
    const result = parseCreateTenantEnv({ ...VALID_ENV, TENANT_SLUG: '  pro-pet-koller ', CARD_TITLE: '  Karte  ', CUSTOMER_REF: ' test-1 ', ICON_ASSET_ID: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.input.tenantSlug).toBe('pro-pet-koller');
      expect(result.input.cardTitle).toBe('Karte');
      expect(result.input.ownerPassword).toBe(PASSWORD);
      expect(result.input.customerRef).toBe('test-1');
    }
  });

  test('rejects unsupported plans, invalid colors, and non-integer stamp counts', () => {
    for (const [key, value, code] of [
      ['TENANT_PLAN_CODE', 'unlimited', 'INVALID_TENANT_PLAN_CODE'],
      ['PRIMARY_COLOR', 'blue', 'INVALID_PRIMARY_COLOR'],
      ['SECONDARY_COLOR', '#12345', 'INVALID_SECONDARY_COLOR'],
      ['STAMPS_REQUIRED', '1.5', 'INVALID_STAMPS_REQUIRED'],
      ['STAMPS_REQUIRED', '101', 'INVALID_STAMPS_REQUIRED'],
    ] as const) {
      const result = parseCreateTenantEnv({ ...VALID_ENV, [key]: value });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.errors).toContain(code);
    }
  });

  test('rejects whitespace-only required fields and malformed optional asset ids', () => {
    const result = parseCreateTenantEnv({ ...VALID_ENV, CARD_TEXT: ' ', REWARD_DESCRIPTION: '', LOGO_ASSET_ID: 'not-an-id' });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors).toEqual(expect.arrayContaining(['CARD_TEXT_REQUIRED', 'REWARD_DESCRIPTION_REQUIRED', 'INVALID_LOGO_ASSET_ID']));
  });
});

describe('createTenantData', () => {
  test('creates every onboarding component, sets tenant context, and audits without plaintext password', async () => {
    const db = new ScriptedDb(CREATED_SCRIPT);
    const result = await createTenantData(db, { ...VALID_INPUT, customerRef: 'test-customer' }, HASH);
    expect(result).toEqual({
      tenant: { id: TENANT_ID, status: 'created' }, owner: { id: USER_ID, status: 'created' },
      membership: { id: MEMBERSHIP_ID, status: 'created', role: 'owner', membershipStatus: 'active' },
      branding: { status: 'upserted' }, rule: { id: RULE_ID, status: 'created' },
      entryPoint: { publicKey: PUBLIC_KEY, joinPath: `/join/${PUBLIC_KEY}`, status: 'upserted' },
      customer: { id: CUSTOMER_ID, status: 'created' },
    });
    const tenantLookup = db.calls.find(call => call.sql.includes('from tenants where slug'));
    expect(tenantLookup?.sql).toContain('for update');
    expect(tenantLookup?.params).toEqual([VALID_INPUT.tenantSlug]);
    const setConfig = db.calls.find(call => call.sql.includes('set_config'));
    expect(setConfig?.params).toEqual([TENANT_ID]);
    const tenantInsert = db.calls.find(call => call.sql.includes('insert into tenants('));
    expect(tenantInsert?.params).toEqual([VALID_INPUT.tenantSlug, VALID_INPUT.tenantLegalName, 'up_to_500', 500, 'active']);
    const audit = db.calls.find(call => call.sql.includes('insert into audit_log'));
    expect(audit?.params[2]).toBe('tenant.configured');
    expect(JSON.stringify(db.calls)).not.toContain(PASSWORD);
  });

  test('re-run updates existing branding/rule but does not recreate tenant, user, membership, or customer', async () => {
    const db = new ScriptedDb(EXISTS_SCRIPT);
    const result = await createTenantData(db, { ...VALID_INPUT, customerRef: 'test-customer' }, HASH);
    expect(result.tenant.status).toBe('exists');
    expect(result.owner.status).toBe('exists');
    expect(result.membership.status).toBe('exists');
    expect(result.rule).toEqual({ id: RULE_ID, status: 'updated' });
    expect(result.customer).toEqual({ id: CUSTOMER_ID, status: 'exists' });
    const sqls = db.calls.map(call => call.sql);
    expect(sqls.some(sql => sql.includes('insert into tenants('))).toBe(false);
    expect(sqls.some(sql => sql.includes('insert into users('))).toBe(false);
    expect(sqls.some(sql => sql.includes('update users'))).toBe(false);
    expect(sqls.some(sql => sql.includes('insert into tenant_memberships('))).toBe(false);
    expect(sqls.some(sql => sql.includes('insert into customers('))).toBe(false);
    const entryPoint = db.calls.find(call => call.sql.includes('insert into tenant_entry_points('));
    expect(entryPoint?.sql).toContain('on conflict(tenant_id) do update set updated_at=now() returning public_key,join_path');
    expect(entryPoint?.sql).not.toContain('public_key=');
    expect(entryPoint?.sql).not.toContain('join_path=');
    expect(entryPoint?.params[2]).toMatch(/^\/join\/[0-9a-f]{32}$/);
    expect(result.entryPoint).toEqual({ publicKey: PUBLIC_KEY, joinPath: `/join/${PUBLIC_KEY}`, status: 'upserted' });
  });

  test('fills a missing existing password hash but never replaces a non-null hash', async () => {
    const db = new ScriptedDb([
      { match: 'from tenants where slug', rows: [{ id: TENANT_ID, status: 'active' }] },
      { match: 'set_config', rows: [] },
      { match: 'from users where lower(email)', rows: [{ id: USER_ID, status: 'active', password_hash: null }] },
      { match: 'update users', rows: [] },
      { match: 'from tenant_memberships where tenant_id', rows: [{ id: MEMBERSHIP_ID, role: 'owner', status: 'active' }] },
      { match: 'insert into tenant_branding(', rows: [] },
      { match: 'select id from stamp_rules', rows: [{ id: RULE_ID }] },
      { match: 'update stamp_rules set name=', rows: [] },
      { match: 'insert into tenant_entry_points(', rows: [{ public_key: PUBLIC_KEY, join_path: `/join/${PUBLIC_KEY}` }] },
      { match: 'insert into audit_log', rows: [] },
    ]);
    await createTenantData(db, VALID_INPUT, HASH);
    const updates = db.calls.filter(call => call.sql.includes('update users'));
    expect(updates).toHaveLength(1);
    expect(updates[0]?.params).toEqual([HASH, USER_ID]);
    expect(updates[0]?.sql).toContain('password_hash is null');
  });

  test('rejects invalid password hashes before any DML', async () => {
    const db = new ScriptedDb(CREATED_SCRIPT);
    await expect(createTenantData(db, VALID_INPUT, PASSWORD)).rejects.toThrow('INVALID_PASSWORD_HASH_FORMAT');
    expect(db.calls).toHaveLength(0);
  });

  test('rejects unknown plan codes instead of defaulting to the larger limit', async () => {
    const db = new ScriptedDb(CREATED_SCRIPT);
    await expect(createTenantData(db, { ...VALID_INPUT, tenantPlanCode: 'unknown' as CreateTenantInput['tenantPlanCode'] }, HASH)).rejects.toThrow('INVALID_TENANT_PLAN_CODE');
    expect(db.calls).toHaveLength(0);
  });

  test('deactivates every extra pre-existing active rule and keeps exactly one active', async () => {
    const secondRuleId = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
    const db = new ScriptedDb([
      { match: 'from tenants where slug', rows: [{ id: TENANT_ID, status: 'active' }] },
      { match: 'set_config', rows: [] },
      { match: 'from users where lower(email)', rows: [{ id: USER_ID, status: 'active', password_hash: HASH }] },
      { match: 'from tenant_memberships where tenant_id', rows: [{ id: MEMBERSHIP_ID, role: 'owner', status: 'active' }] },
      { match: 'insert into tenant_branding(', rows: [] },
      { match: 'select id from stamp_rules', rows: [{ id: RULE_ID }, { id: secondRuleId }] },
      { match: 'update stamp_rules set name=', rows: [] },
      { match: 'update stamp_rules set active=false', rows: [] },
      { match: 'insert into tenant_entry_points(', rows: [{ public_key: PUBLIC_KEY, join_path: `/join/${PUBLIC_KEY}` }] },
      { match: 'insert into audit_log', rows: [] },
    ]);
    const result = await createTenantData(db, VALID_INPUT, HASH);
    expect(result.rule).toEqual({ id: RULE_ID, status: 'updated' });
    const deactivate = db.calls.find(call => call.sql.includes('update stamp_rules set active=false'));
    expect(deactivate?.params).toEqual([TENANT_ID, RULE_ID]);
    expect(deactivate?.sql).toContain('active=true and id<>$2');
  });

  test('does not query or create a customer when CUSTOMER_REF is absent', async () => {
    const db = new ScriptedDb(CREATED_SCRIPT);
    const result = await createTenantData(db, VALID_INPUT, HASH);
    expect(result.customer).toBeNull();
    expect(db.calls.some(call => call.sql.includes('customers'))).toBe(false);
  });
});

describe('formatCreateTenantResult and dbCreateTenant', () => {
  test('masks ids and prints only the public join path', () => {
    expect(maskCreateTenantId(TENANT_ID)).toBe('aaaaaaaa…');
    expect(maskCreateTenantId('abc')).toBe('••••');
    const output = formatCreateTenantResult({
      tenant: { id: TENANT_ID, status: 'created' }, owner: { id: USER_ID, status: 'exists' },
      membership: { id: MEMBERSHIP_ID, status: 'created', role: 'owner', membershipStatus: 'active' }, branding: { status: 'upserted' },
      rule: { id: RULE_ID, status: 'created' }, entryPoint: { publicKey: PUBLIC_KEY, joinPath: `/join/${PUBLIC_KEY}`, status: 'upserted' }, customer: null,
    }).join('\n');
    expect(output).toContain('create_tenant_ok');
    expect(output).toContain(`/join/${PUBLIC_KEY}`);
    for (const id of [TENANT_ID, USER_ID, MEMBERSHIP_ID, RULE_ID]) expect(output).not.toContain(id);
    expectNoSecrets(output);
  });

  const originalLog = console.log;
  const originalError = console.error;
  const lines: string[] = [];
  afterEach(() => { console.log = originalLog; console.error = originalError; lines.length = 0; });
  const capture = () => { console.log = (...args: unknown[]) => lines.push(args.join(' ')); console.error = (...args: unknown[]) => lines.push(args.join(' ')); };

  test('success takes new lock, commits, and emits anonymized output', async () => {
    capture();
    const calls: { sql: string; params: unknown[] }[] = [];
    const pool = {
      calls,
      connect: async () => ({
        query: async <T = unknown>(sql: string, params: unknown[] = []) => {
          calls.push({ sql, params });
          const hit = CREATED_SCRIPT.find(item => sql.includes(item.match));
          return { rows: (hit?.rows ?? []) as T[] };
        }, release() {},
      }), end: async () => {},
    };
    const code = await dbCreateTenant({ ...VALID_ENV, DATABASE_URL: 'postgresql://fake/db', CUSTOMER_REF: 'test-customer' }, () => pool);
    expect(code).toBe(0);
    expect(calls[0]?.sql).toBe('begin');
    expect(calls[1]?.sql).toContain('pg_advisory_xact_lock');
    expect(calls[1]?.params).toEqual([CREATE_TENANT_LOCK_KEY]);
    expect(calls.at(-1)?.sql).toBe('commit');
    expectNoSecrets(lines.join('\n'));
  });

  test('hashes the owner password before invoking the pool factory', async () => {
    const order: string[] = [];
    const pool = {
      connect: async () => ({
        query: async <T = unknown>(sql: string, params: unknown[] = []) => {
          const hit = CREATED_SCRIPT.find(item => sql.includes(item.match));
          return { rows: (hit?.rows ?? []) as T[] };
        }, release() {},
      }),
      end: async () => {},
    };
    const code = await dbCreateTenant(
      { ...VALID_ENV, DATABASE_URL: 'postgresql://fake/db' },
      () => { order.push('makePool'); return pool; },
      async () => { order.push('hashPassword'); return HASH; },
    );
    expect(code).toBe(0);
    expect(order).toEqual(['hashPassword', 'makePool']);
  });

  test('missing DATABASE_URL and VERCEL guard fail without connecting', async () => {
    capture();
    let connects = 0;
    const makePool = () => { connects++; throw new Error('must not connect'); };
    expect(await dbCreateTenant(VALID_ENV, makePool)).toBe(1);
    expect(await dbCreateTenant({ ...VALID_ENV, VERCEL: '1', DATABASE_URL: 'postgresql://fake/db' }, makePool)).toBe(1);
    expect(connects).toBe(0);
    expect(lines.join('\n')).toContain('DATABASE_URL_REQUIRED');
    expect(lines.join('\n')).toContain('CREATE_TENANT_NOT_ALLOWED_ON_VERCEL');
  });

  test('database failure rolls back and returns a stable error code', async () => {
    capture();
    const calls: string[] = [];
    const pool = {
      connect: async () => ({ query: async (sql: string) => { calls.push(sql); if (sql.includes('insert into tenants(')) throw new Error('database provider detail'); return { rows: [] }; }, release() {} }),
      end: async () => {},
    };
    expect(await dbCreateTenant({ ...VALID_ENV, DATABASE_URL: 'postgresql://fake/db', CUSTOMER_REF: 'test-customer' }, () => pool)).toBe(1);
    expect(calls).toContain('rollback');
    expect(lines.join('\n')).toContain('create_tenant_failed INTERNAL_ERROR');
    expectNoSecrets(lines.join('\n'));
  });

  test('hashPassword uses scrypt format before any DML', async () => {
    const hash = await hashPassword(PASSWORD);
    expect(hash).toMatch(/^\$scrypt\$N=32768,r=8,p=1\$/);
  });
});
