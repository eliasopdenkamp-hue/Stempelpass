import { test, expect } from 'bun:test';
import { CardRepository, appendAudit, type DbPool, type TxClient } from '../src/repository';

/**
 * DB-free contract tests for the user-scoped session helpers (migration 009
 * + CardRepository.userTransaction / revokeSession / revokeSessions) and the
 * appendAudit contract the audit policy split must keep intact.
 *
 * No database: every helper is driven against a scripted in-memory DbPool.
 * The RLS policy semantics themselves are pinned statically in
 * tests/migrations.test.ts (009 policy expressions). The live RLS
 * enforcement against a non-owner app role remains a pilot step (see
 * RLS_AUTH_P1.md Teil C/E).
 */
const USER_ID = '44444444-4444-4444-8444-444444444444';
const TENANT_ID = '11111111-1111-4111-8111-111111111111';
const TOKEN_HASH = 'a'.repeat(64);

class FakePool implements DbPool {
  queries: Array<{ sql: string; params: unknown[] }> = [];
  constructor(private readonly script: unknown[][]) {}
  async connect(): Promise<TxClient> {
    const rec = this;
    return {
      async query<T = unknown>(sql: string, params: unknown[] = []): Promise<{ rows: T[] }> {
        rec.queries.push({ sql, params });
        return { rows: (rec.script.shift() ?? []) as T[] };
      },
      release() {},
    };
  }
}

test('revokeSession revokes by token hash inside a transaction that sets app.user_id first', async () => {
  const pool = new FakePool([[], [], [], []]); // begin, set_config, update, commit
  const repo = new CardRepository(pool);
  await repo.revokeSession(USER_ID, TOKEN_HASH);
  const [begin, userCtx, update, commit] = pool.queries.map(q => q.sql);
  expect(begin).toBe('begin');
  expect(userCtx).toBe("select set_config('app.user_id', $1, true)");
  expect(pool.queries[1]?.params).toEqual([USER_ID]);
  expect(update).toBe('update sessions set revoked_at=now() where token_hash=$1');
  expect(pool.queries[2]?.params).toEqual([TOKEN_HASH]);
  expect(commit).toBe('commit');
});

test('revokeSessions revokes all sessions of a user (except an optional hash) under user context', async () => {
  const pool = new FakePool([[], [], [], []]); // begin, set_config, update, commit
  const repo = new CardRepository(pool);
  await repo.revokeSessions(USER_ID, TOKEN_HASH);
  expect(pool.queries[0]?.sql).toBe('begin');
  expect(pool.queries[1]?.sql).toBe("select set_config('app.user_id', $1, true)");
  expect(pool.queries[1]?.params).toEqual([USER_ID]);
  expect(pool.queries[2]?.sql).toContain('update sessions set revoked_at=now() where user_id=$1 and revoked_at is null and ($2 is null or token_hash<>$2)');
  expect(pool.queries[2]?.params).toEqual([USER_ID, TOKEN_HASH]);
  expect(pool.queries[3]?.sql).toBe('commit');
});

test('session helpers refuse to run without a user context (USER_CONTEXT_REQUIRED, no queries)', async () => {
  const pool = new FakePool([]);
  const repo = new CardRepository(pool);
  await expect(repo.revokeSession('', TOKEN_HASH)).rejects.toThrow('USER_CONTEXT_REQUIRED');
  await expect(repo.revokeSessions('')).rejects.toThrow('USER_CONTEXT_REQUIRED');
  expect(pool.queries).toHaveLength(0);
});

test('transaction helpers roll back on failure (no dangling user/tenant context)', async () => {
  // Public path: stamp() opens a tenant transaction (begin + set_config); a
  // failed card lookup must roll back. userTransaction follows the identical
  // pattern, so this pins the shared begin/rollback discipline.
  const stampPool = new FakePool([[], [], []]); // begin, set_config app.tenant_id, card select -> no rows
  const stampRepo = new CardRepository(stampPool);
  await expect(stampRepo.stamp(TENANT_ID, 'card-x', 1, 'member-x', null)).rejects.toThrow('CARD_NOT_FOUND');
  expect(stampPool.queries[0]?.sql).toBe('begin');
  expect(stampPool.queries[1]?.sql).toBe("select set_config('app.tenant_id', $1, true)");
  expect(stampPool.queries.some(q => q.sql === 'rollback')).toBe(true);
  expect(stampPool.queries.some(q => q.sql === 'commit')).toBe(false);
});

test('appendAudit keeps the tenant-scoped insert contract the policy split must preserve', async () => {
  // Normal appendAudit calls (configurePilot/setStaff) run inside
  // repository.transaction(tenantId, ...) with app.tenant_id set; the insert
  // must keep exactly this shape so the tenant WITH CHECK passes.
  const queries: Array<{ sql: string; params: unknown[] }> = [];
  const db: TxClient = {
    async query<T = unknown>(sql: string, params: unknown[] = []): Promise<{ rows: T[] }> {
      queries.push({ sql, params });
      return { rows: [] as T[] };
    },
    release() {},
  };
  await appendAudit(db, {
    tenantId: TENANT_ID,
    actorUserId: USER_ID,
    action: 'staff.activated',
    entityType: 'membership',
    entityId: '55555555-5555-4555-8555-555555555555',
    metadata: { userId: USER_ID, role: 'staff' },
  });
  expect(queries).toHaveLength(1);
  expect(queries[0]?.sql).toBe('insert into audit_log(tenant_id,actor_user_id,action,entity_type,entity_id,metadata) values($1,$2,$3,$4,$5,$6)');
  expect(queries[0]?.params).toEqual([
    TENANT_ID, USER_ID, 'staff.activated', 'membership', '55555555-5555-4555-8555-555555555555',
    JSON.stringify({ userId: USER_ID, role: 'staff' }),
  ]);
});
