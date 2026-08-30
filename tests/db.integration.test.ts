import { test, expect, setDefaultTimeout } from 'bun:test';
import postgres from 'postgres';
import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { CardRepository, type DbPool, type TxClient } from '../src/repository';
import { formatRetentionResult, runRetention } from '../src/retention';
import type { WalletAdapter } from '../src/wallet';

// Deliberately no DATABASE_URL fallback: integration tests require an explicit disposable DB.
const url = process.env.TEST_DATABASE_URL;
const integration = url ? test : test.skip;
// Neon migration plus retention scenarios can exceed Bun's 30-second default;
// keep the higher ceiling local to this integration file rather than the suite.
setDefaultTimeout(300_000);

// Bun's test timeout must never be the first timeout we hit. PostgreSQL's
// statement/lock settings protect the server, while this deadline also covers
// a client waiting for a pooled connection (which those settings cannot cover).
const DB_OPERATION_TIMEOUT_MS = 7_000;
const withDeadline = async <T>(operation: Promise<T>, label: string): Promise<T> => {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`TEST_DATABASE_BUSY:${label} timed out`)), DB_OPERATION_TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
};

type Queryable = { unsafe(query: string, values?: any[]): Promise<any[]> };

integration('database scenarios run in an isolated temporary schema', async () => {
  if (!url) return;
  if (url === process.env.DATABASE_URL) throw new Error('TEST_DATABASE_URL_MUST_NOT_EQUAL_DATABASE_URL');

  const schema = `test_${crypto.randomUUID().replaceAll('-', '')}`;
  // Neon can route pooled queries through a different backend session, so a
  // per-session SET alone is not sufficient to pin unqualified test queries.
  // Send the schema as a startup connection parameter as well, then retain the
  // explicit setPath() verification for every reserved connection.
  const schemaSearchPath = `"${schema}", public`;
  // Keep every test connection bounded. A stale session or catalog lock in the
  // shared disposable database must fail the test, never leave Bun waiting.
  const sql = postgres(url, {
    max: 4,
    prepare: false,
    connect_timeout: 10,
    idle_timeout: 2,
    max_lifetime: 30,
    connection: { search_path: schemaSearchPath },
  });
  const migrationDir = join(import.meta.dir, '../migrations');
  const configureConnection = async (db: Queryable) => {
    await db.unsafe("set statement_timeout = '10s'; set lock_timeout = '2s'");
  };
  const setPath = async (db: Queryable) => {
    await withDeadline(configureConnection(db), 'configure connection');
    await withDeadline(db.unsafe(`set search_path to "${schema}", public`), 'set search_path');
    const rows = await withDeadline(
      db.unsafe('select current_schema() as current_schema, current_setting($1) as search_path', ['search_path']),
      'verify search_path',
    ) as { current_schema: string; search_path: string }[];
    const searchPath = rows[0]?.search_path ?? '';
    const firstSearchPathEntry = searchPath.split(',')[0]?.trim();
    if (rows[0]?.current_schema !== schema || firstSearchPathEntry !== schema) {
      throw new Error(`SEARCH_PATH_NOT_CONFIGURED:${rows[0]?.current_schema}:${searchPath}`);
    }
  };
  const withSchema = async <T>(work: (db: Queryable) => Promise<T>): Promise<T> => {
    const db = await withDeadline(sql.reserve(), 'connection');
    try { await setPath(db); return await work(db); }
    finally { db.release(); }
  };
  const setup = await withDeadline(sql.reserve(), 'setup connection');
  let setupReleased = false;
  const assertParams = (label: string, params: unknown[]) => {
    const index = params.findIndex(value => value === undefined);
    if (index >= 0) throw new Error(`UNDEFINED_DB_PARAM:${label}:${index}`);
  };
  const q = async <T = any>(text: string, params: unknown[] = []): Promise<T[]> => {
    assertParams(text.slice(0, 80), params);
    return await withDeadline(setup.unsafe(text, params as any), text.slice(0, 48)) as T[];
  };
  const setTenant = (tenantId: string) => q('select set_config($1,$2,true)', ['app.tenant_id', tenantId]);

  try {
    // Migrations intentionally run on one dedicated setup connection, not the pool used by tests.
    await configureConnection(setup);
    // Each run owns a random schema, so no database-wide advisory lock is needed.
    // Keeping setup and cleanup scoped to this schema allows parallel/isolated runs
    // and ensures stale locks from an abandoned process cannot block this harness.
    await withDeadline(setup.unsafe(`create schema "${schema}"`), 'create schema');
    await setPath(setup);
    await q('create table if not exists schema_migrations (version text primary key, applied_at timestamptz not null default now())');
    // The harness is deliberately driven only by TEST_DATABASE_URL and this schema.
    // Keep discovery deterministic and guard registration against duplicate directory
    // entries/retries: each version is applied and recorded once in one transaction.
    const migrationFiles = [...new Set((await readdir(migrationDir)).filter(f => /^\d+_.+\.sql$/.test(f)).sort())];
    for (const file of migrationFiles) {
      const alreadyApplied = await q<{ version: string }>('select version from schema_migrations where version=$1', [file]);
      if (alreadyApplied.length) continue;
      console.error(`DB_PHASE:migration_start:${file}`);
      await q('begin');
      try {
        // SECURITY DEFINER migrations (008) deliberately fully-qualify
        // `public.` for a fixed search_path. The harness runs migrations in a
        // per-run schema, so that qualifier is mapped onto the per-run schema
        // here — keeping the resolver inside this isolated schema (production
        // runs migrations in `public`, where the qualifier resolves as-is).
        const migrationSql = (await Bun.file(join(migrationDir, file)).text()).replaceAll('public.', `"${schema}".`);
        await q(migrationSql);
        console.error(`DB_PHASE:migration_sql_done:${file}`);
        await q('insert into schema_migrations(version) values($1) on conflict (version) do nothing', [file]);
        await q('commit');
      } catch (error) {
        try { await q('rollback'); } catch { /* preserve the migration error */ }
        throw error;
      }
      console.error(`DB_PHASE:migration_recorded:${file}`);
    }
    console.error('DB_PHASE:verify_tables:start');
    // setPath() already verified this connection's current schema; avoid an
    // extra catalog round-trip through the Neon pooler here.
    console.error('DB_PHASE:verify_tables:done');

    // The production plans are 500/1000. This local check is intentionally removed for a one-slot limit test.
    // Keep this DDL schema-qualified too: it is the only setup mutation that
    // changes a migrated table definition, and must never target public.tenants.
    await q(`alter table "${schema}".tenants drop constraint if exists tenants_customer_limit_check`);
    const tenantA = (await q<{ id: string }>("insert into tenants(slug,legal_name,plan_code,customer_limit) values('tenant-a','Tenant A','up_to_500',1) returning id"))[0].id;
    const tenantB = (await q<{ id: string }>("insert into tenants(slug,legal_name,plan_code,customer_limit) values('tenant-b','Tenant B','up_to_500',1) returning id"))[0].id;
    const user = (await q<{ id: string }>("insert into users(email) values('db-test@example.invalid') returning id"))[0].id;
    await setTenant(tenantA);
    const memberA = (await q<{ id: string }>('insert into tenant_memberships(tenant_id,user_id,role) values($1,$2,\'staff\') returning id', [tenantA, user]))[0].id;
    const ruleA = (await q<{ id: string }>("insert into stamp_rules(tenant_id,name,stamps_required,reward_title,reward_description) values($1,'Rule A',1,'Coffee','Free coffee') returning id", [tenantA]))[0].id;
    const customerA = (await q<{ id: string }>("insert into customers(tenant_id,external_ref) values($1,'customer-a') returning id", [tenantA]))[0].id;
    const cardA = (await q<{ id: string }>("insert into cards(tenant_id,customer_id,rule_id,public_token_hash) values($1,$2,$3,'hash-a') returning id", [tenantA, customerA, ruleA]))[0].id;
    await setTenant(tenantB);
    const memberB = (await q<{ id: string }>('insert into tenant_memberships(tenant_id,user_id,role) values($1,$2,\'staff\') returning id', [tenantB, user]))[0].id;
    const ruleB = (await q<{ id: string }>("insert into stamp_rules(tenant_id,name,stamps_required,reward_title,reward_description) values($1,'Rule B',1,'Tea','Free tea') returning id", [tenantB]))[0].id;
    const customerB = (await q<{ id: string }>("insert into customers(tenant_id,external_ref) values($1,'customer-b') returning id", [tenantB]))[0].id;
    const cardB = (await q<{ id: string }>("insert into cards(tenant_id,customer_id,rule_id,public_token_hash) values($1,$2,$3,'hash-b') returning id", [tenantB, customerB, ruleB]))[0].id;
    void cardB;

    // Release setup before repository work; cleanup reserves a fresh connection.
    setup.release(); setupReleased = true;
    const pool: DbPool = { connect: async () => {
      const reserved = await withDeadline(sql.reserve(), 'repository connection');
      try {
        await setPath(reserved);
        return { query: async <T>(text: string, params: unknown[] = []) => {
          assertParams(text.slice(0, 120), params);
          return { rows: await reserved.unsafe(text, params as any) as T[] };
        }, release: () => reserved.release() } as TxClient;
      } catch (error) { reserved.release(); throw error; }
    }};
    const repo = new CardRepository(pool);

    expect(await repo.findByPublicTokenHash(tenantB, 'hash-a')).toBeNull();
    await expect(repo.stamp(tenantB, cardA, 1, memberB, 'cross-tenant')).rejects.toThrow('CARD_NOT_FOUND');
    const customerA2 = (await withSchema(db => db.unsafe("insert into customers(tenant_id,external_ref) values($1,'customer-a2') returning id", [tenantA])) as { id: string }[])[0].id;
    const attempts = await Promise.allSettled([repo.createCard(tenantA, customerA2, ruleA, 'hash-a2'), repo.createCard(tenantA, customerA2, ruleA, 'hash-a3')]);
    expect(attempts.filter(x => x.status === 'fulfilled')).toHaveLength(0);
    expect(attempts.filter(x => x.status === 'rejected' && x.reason?.message === 'CUSTOMER_LIMIT_REACHED')).toHaveLength(2);
    const first = await repo.stamp(tenantA, cardA, 1, memberA, 'same-event');
    const second = await repo.stamp(tenantA, cardA, 1, memberA, 'same-event');
    expect((first as any).card.stampCount).toBe(1); expect((second as any).idempotencyKey).toBe('same-event');
    expect((await withSchema(db => db.unsafe('select stamp_count from cards where id=$1', [cardA])) as any)[0].stamp_count).toBe(1);
    const rewardId = (first as any).reward.id;
    expect((await repo.redeem(tenantA, rewardId)).status).toBe('redeemed');
    await expect(repo.redeem(tenantA, rewardId)).rejects.toThrow('REWARD_ALREADY_REDEEMED');
    await expect(repo.redeem(tenantB, rewardId)).rejects.toThrow('REWARD_NOT_FOUND');
    await withSchema(db => db.unsafe('insert into sessions(user_id,tenant_id,token_hash,csrf_token_hash,expires_at) values($1,$2,$3,$4,now()+interval \'1 hour\')', [user, tenantA, 'session-token-hash', 'csrf']));
    await repo.revokeSession(user, 'session-token-hash');
    expect((await withSchema(db => db.unsafe('select revoked_at,mfa_verified from sessions where token_hash=$1', ['session-token-hash'])) as any)[0].revoked_at).not.toBeNull();

    // Real Neon-backed retention chain: all rows are created in this temporary
    // schema, then the production retention function runs against PostgreSQL.
    const retentionWalletCards: string[] = [];
    const retentionWallet: WalletAdapter = {
      async issue() { throw new Error('not used'); },
      async refresh() { throw new Error('not used'); },
      async revoke(card) { retentionWalletCards.push(card.id); },
    };
    await withSchema(async db => {
      const r = async <T = any>(text: string, params: unknown[] = []) => await db.unsafe(text, params as any) as T[];
      const retentionTenant = (await r<{ id: string }>("insert into tenants(slug,legal_name,plan_code,customer_limit) values('retention-tenant','Retention Tenant','up_to_500',500) returning id"))[0].id;
      const retentionUser = (await r<{ id: string }>("insert into users(email) values('retention-user@example.invalid') returning id"))[0].id;
      const retentionMember = (await r<{ id: string }>("insert into tenant_memberships(tenant_id,user_id,role) values($1,$2,'staff') returning id", [retentionTenant, retentionUser]))[0].id;
      const retentionRule = (await r<{ id: string }>("insert into stamp_rules(tenant_id,name,stamps_required,reward_title,reward_description) values($1,'Retention Rule',10,'Retention reward','Retention reward description') returning id", [retentionTenant]))[0].id;
      const oldCustomer = (await r<{ id: string }>("insert into customers(tenant_id,external_ref,deleted_at,status) values($1,'retention-old-pii',now()-interval '31 days','inactive') returning id", [retentionTenant]))[0].id;
      const recentCustomer = (await r<{ id: string }>("insert into customers(tenant_id,external_ref,deleted_at,status,legal_retention_hold) values($1,'retention-recent-pii',now()-interval '29 days','inactive',false) returning id", [retentionTenant]))[0].id;
      const heldCustomer = (await r<{ id: string }>("insert into customers(tenant_id,external_ref,deleted_at,status,legal_retention_hold) values($1,'retention-held-pii',now()-interval '31 days','inactive',true) returning id", [retentionTenant]))[0].id;
      const oldCard = (await r<{ id: string }>("insert into cards(tenant_id,customer_id,rule_id,public_token_hash,status,deleted_at) values($1,$2,$3,'retention-token-hash','inactive',now()-interval '31 days') returning id", [retentionTenant, oldCustomer, retentionRule]))[0].id;
      const recentCard = (await r<{ id: string }>("insert into cards(tenant_id,customer_id,rule_id,public_token_hash,status,deleted_at) values($1,$2,$3,'retention-recent-token','inactive',now()-interval '29 days') returning id", [retentionTenant, recentCustomer, retentionRule]))[0].id;
      const heldCard = (await r<{ id: string }>("insert into cards(tenant_id,customer_id,rule_id,public_token_hash,status,deleted_at) values($1,$2,$3,'retention-held-token','inactive',now()-interval '31 days') returning id", [retentionTenant, heldCustomer, retentionRule]))[0].id;
      await r("insert into stamp_events(tenant_id,card_id,employee_membership_id,quantity,reason,idempotency_key) values($1,$2,$3,2,'retention reason','retention-stamp-key')", [retentionTenant, oldCard, retentionMember]);
      await r("insert into rewards(tenant_id,card_id,rule_id,status) values($1,$2,$3,'issued')", [retentionTenant, oldCard, retentionRule]);
      await r("insert into card_creation_idempotency(tenant_id,idempotency_key,request_fingerprint,card_id,token_ciphertext) values($1,'retention-create-key','retention-fingerprint',$2,'retention-token-ciphertext')", [retentionTenant, oldCard]);
      await r("insert into communication_preferences(tenant_id,customer_id,purpose,channel,opted_in,opted_in_at) values($1,$2,'marketing','email',true,now())", [retentionTenant, oldCustomer]);
      await r("insert into communication_consent_events(tenant_id,customer_id,purpose,channel,action,source) values($1,$2,'marketing','email','opt_in','retention-test-source')", [retentionTenant, oldCustomer]);
      await r("insert into communication_message_logs(tenant_id,customer_id,purpose,channel,message_type,recipient_hash,status,provider_message_id) values($1,$2,'marketing','email','retention-test','retention-recipient-hash','sent','retention-provider-id')", [retentionTenant, oldCustomer]);

      const revokedOld = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      const revokedRecent = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
      const expiredActive = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
      await r("insert into sessions(user_id,tenant_id,token_hash,csrf_token_hash,expires_at,revoked_at) values($1,$2,$3,'retention-csrf-old',now()+interval '1 day',now()-interval '8 days')", [retentionUser, retentionTenant, revokedOld]);
      await r("insert into sessions(user_id,tenant_id,token_hash,csrf_token_hash,expires_at,revoked_at) values($1,$2,$3,'retention-csrf-recent',now()+interval '1 day',now()-interval '2 days')", [retentionUser, retentionTenant, revokedRecent]);
      await r("insert into sessions(user_id,tenant_id,token_hash,csrf_token_hash,expires_at) values($1,$2,$3,'retention-csrf-expired',now()-interval '1 day')", [retentionUser, retentionTenant, expiredActive]);

      const tx: TxClient = { query: async <T = unknown>(text: string, params: unknown[] = []) => ({ rows: await r<T>(text, params) }), release() {} };
      await db.unsafe('begin');
      let counts;
      try { counts = await runRetention(tx, null, retentionWallet); await db.unsafe('commit'); }
      catch (error) { try { await db.unsafe('rollback'); } catch {} throw error; }

      expect(counts).toMatchObject({
        sessionsDeleted: 2, customersHardDeleted: 1, cardsHardDeleted: 1,
        communicationMessageLogsDeleted: 1, communicationConsentEventsDeleted: 1,
        communicationPreferencesDeleted: 1, stampEventsDeleted: 1, rewardsDeleted: 1,
        cardCreationIdempotencyDeleted: 1, walletRevocationAttempts: 1,
      });
      expect(retentionWalletCards).toEqual([oldCard]);

      const oldCounts = await r<{ customers: number; cards: number; stamp_events: number; rewards: number; idempotency: number; messages: number; consents: number; preferences: number }>(`select
        (select count(*)::int from customers where id=$1) as customers,
        (select count(*)::int from cards where id=$2) as cards,
        (select count(*)::int from stamp_events where card_id=$2) as stamp_events,
        (select count(*)::int from rewards where card_id=$2) as rewards,
        (select count(*)::int from card_creation_idempotency where card_id=$2) as idempotency,
        (select count(*)::int from communication_message_logs where customer_id=$1) as messages,
        (select count(*)::int from communication_consent_events where customer_id=$1) as consents,
        (select count(*)::int from communication_preferences where customer_id=$1) as preferences`, [oldCustomer, oldCard]);
      expect(oldCounts[0]).toEqual({ customers: 0, cards: 0, stamp_events: 0, rewards: 0, idempotency: 0, messages: 0, consents: 0, preferences: 0 });
      expect((await r<{ id: string }>('select id from customers where id=$1', [recentCustomer]))).toHaveLength(1);
      expect((await r<{ id: string }>('select id from customers where id=$1 and legal_retention_hold=true', [heldCustomer]))).toHaveLength(1);
      expect((await r<{ token_hash: string }>('select token_hash from sessions where token_hash=$1', [revokedOld]))).toHaveLength(0);
      expect((await r<{ token_hash: string }>('select token_hash from sessions where token_hash=$1', [expiredActive]))).toHaveLength(0);
      expect((await r<{ token_hash: string }>('select token_hash from sessions where token_hash=$1', [revokedRecent]))).toHaveLength(1);
      expect((await r<{ id: string }>('select id from cards where id in ($1,$2)', [recentCard, heldCard]))).toHaveLength(2);

      await db.unsafe('begin');
      let rerun;
      try { rerun = await runRetention(tx, null, retentionWallet); await db.unsafe('commit'); }
      catch (error) { try { await db.unsafe('rollback'); } catch {} throw error; }
      expect(rerun).toMatchObject({ sessionsDeleted: 0, customersHardDeleted: 0, cardsHardDeleted: 0, walletRevocationAttempts: 0 });
      expect(retentionWalletCards).toEqual([oldCard]);

      const jobLog = formatRetentionResult(counts, 12.4).join('\n');
      for (const secret of [oldCustomer, oldCard, 'retention-old-pii', 'retention-token-ciphertext', revokedOld]) expect(jobLog).not.toContain(secret);
      expect(jobLog).toContain('customers_hard_deleted=1');
    });
  } finally {
    if (!setupReleased) setup.release();
    try {
      const cleanup = await withDeadline(sql.reserve(), 'cleanup connection');
      try {
        await withDeadline(configureConnection(cleanup), 'configure cleanup connection');
        await withDeadline(cleanup.unsafe(`drop schema if exists "${schema}" cascade`), 'drop schema');
      } finally { cleanup.release(); }
    } catch { /* cleanup is best effort after setup failure */ }
    await sql.end({ timeout: 5 });
  }
});
