import { test, expect } from 'bun:test';
import { createHash } from 'node:crypto';
import type { CardRepository, StaffSearchCard } from '../src/repository';
import type { Card } from '../src/domain';

/**
 * DB-free unit tests for the shared staff resolver resolveStampTarget
 * (UUID | card code | raw token). The resolver is exported from src/server.ts
 * as a test seam (behavior-neutral in production); the module-level
 * `repository` is injected through withTestDependencies with a scripted stub
 * so the resolution ORDER, the code normalization (prefix/case) and the
 * null-for-everything-missing contract are pinned WITHOUT a database.
 */

// --- boot: scrub every secret/config var BEFORE importing the server module ---
const SCRUBBED_KEYS = [
  'DATABASE_URL', 'TEST_DATABASE_URL', 'SESSION_SECRET', 'MFA_ENCRYPTION_KEY',
  'GOOGLE_ISSUER_ID', 'GOOGLE_SERVICE_ACCOUNT_JSON', 'GOOGLE_SERVICE_ACCOUNT_EMAIL',
  'GOOGLE_PRIVATE_KEY', 'GOOGLE_EXTERNAL_ACCOUNT_JSON', 'GOOGLE_APPLICATION_CREDENTIALS',
  'VERCEL_OIDC_TOKEN', 'APPLE_TEAM_IDENTIFIER', 'APPLE_PASS_TYPE_IDENTIFIER', 'APPLE_PRIVATE_KEY',
  'TIGER_PUBLIC_KEY', 'TIGER_SECRET_KEY', 'TIGER_PROJECT_ID',
  'EMAIL_SMTP_HOST', 'EMAIL_SMTP_PORT', 'EMAIL_SMTP_USER', 'EMAIL_SMTP_PASSWORD', 'EMAIL_FROM',
  'COMMUNICATION_HASH_SECRET', 'PORT', 'PILOT_READY', 'FRONTEND_ORIGIN',
  'FRONTEND_ORIGIN_DEV', 'PUBLIC_SITE_ORIGIN',
];
for (const key of SCRUBBED_KEYS) delete process.env[key];
process.env.FRONTEND_ORIGIN = 'https://a1e91d0731cfc57ecf5a508e37635a85.ctonew.app';
process.env.FRONTEND_ORIGIN_DEV = 'https://a1e91d0731cfc57ecf5a508e37635a85-dev.ctonew.app';
process.env.VERCEL = '1';

const { resolveStampTarget, withTestDependencies } = await import('../src/server');

// --- fixtures (valid UUID shapes, mirroring staff-ui.test.ts) ---
const TENANT = '11111111-1111-4111-8111-111111111111';
const OTHER_TENANT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const CARD = '66666666-6666-4666-8666-666666666666';
const CARD_TOKEN = 'M'.repeat(43); // raw token shape (base64url, 32 bytes)

const richCard: StaffSearchCard = {
  id: CARD, cardCode: '7F3D2A', stampCount: 3, stampsRequired: 5,
  rewardId: '77777777-7777-4777-8777-777777777777', rewardStatus: 'issued',
  customerRef: 'Kunde-42', updatedAt: '2026-08-26T10:00:00.000Z',
};
const plainCard: Card = {
  id: CARD, tenantId: TENANT, customerId: '22222222-2222-4222-8222-222222222222',
  publicTokenHash: 'f'.repeat(64), status: 'active', stampCount: 3, revision: 2,
  ruleId: '33333333-3333-4333-8333-333333333333', cardCode: '7F3D2A',
};

interface Calls { findCardById: Array<[string, string]>; findByCardCode: Array<[string, string]>; findByPublicTokenHash: Array<[string, string]>; }
/**
 * Scripted repository stub: records every invocation and answers per-method
 * canned values (null by default — everything missing/foreign → null). Cast
 * through the CardRepository type: the resolver only ever calls the three
 * documented lookup methods.
 */
function stubRepo(answers: {
  findCardById?: (tenantId: string, id: string) => Promise<StaffSearchCard | null>;
  findByCardCode?: (tenantId: string, code: string) => Promise<StaffSearchCard | null>;
  findByPublicTokenHash?: (tenantId: string, hash: string) => Promise<Card | null>;
} = {}): { repository: CardRepository; calls: Calls } {
  const calls: Calls = { findCardById: [], findByCardCode: [], findByPublicTokenHash: [] };
  const repository = {
    findCardById: async (tenantId: string, id: string) => { calls.findCardById.push([tenantId, id]); return answers.findCardById ? answers.findCardById(tenantId, id) : null; },
    findByCardCode: async (tenantId: string, code: string) => { calls.findByCardCode.push([tenantId, code]); return answers.findByCardCode ? answers.findByCardCode(tenantId, code) : null; },
    findByPublicTokenHash: async (tenantId: string, hash: string) => { calls.findByPublicTokenHash.push([tenantId, hash]); return answers.findByPublicTokenHash ? answers.findByPublicTokenHash(tenantId, hash) : null; },
  } as unknown as CardRepository;
  return { repository, calls };
}

function runWith(repository: CardRepository, fn: () => Promise<unknown>): Promise<unknown> {
  const restore = withTestDependencies({ configured: true, repository });
  return fn().finally(restore);
}

test('empty or whitespace input resolves to null without any repository lookup', async () => {
  const { repository, calls } = stubRepo();
  await runWith(repository, async () => {
    for (const input of ['', '   ', null as unknown as string, undefined as unknown as string]) {
      expect(await resolveStampTarget(TENANT, input)).toBeNull();
    }
    expect(calls.findCardById).toHaveLength(0);
    expect(calls.findByCardCode).toHaveLength(0);
    expect(calls.findByPublicTokenHash).toHaveLength(0);
  });
});

test('(a) an exact card UUID resolves via findCardById — the ONLY lookup', async () => {
  const { repository, calls } = stubRepo({ findCardById: async () => richCard });
  await runWith(repository, async () => {
    expect(await resolveStampTarget(TENANT, `  ${CARD}  `)).toBe(richCard);
    // Trimmed input, tenant passed through; code/token lookups never ran.
    expect(calls.findCardById).toEqual([[TENANT, CARD]]);
    expect(calls.findByCardCode).toHaveLength(0);
    expect(calls.findByPublicTokenHash).toHaveLength(0);
  });
});

test('(a) an unknown UUID resolves to null (findCardById → null), no fall-through', async () => {
  const { repository, calls } = stubRepo(); // findCardById → null
  await runWith(repository, async () => {
    expect(await resolveStampTarget(TENANT, CARD)).toBeNull();
    expect(calls.findCardById).toEqual([[TENANT, CARD]]);
    expect(calls.findByPublicTokenHash).toHaveLength(0);
  });
});

test('(b) a card code resolves via findByCardCode — prefix optional: K-7F3D2A, k-7f3d2a, 7f3d2a and whitespace all normalize to 7F3D2A', async () => {
  const { repository, calls } = stubRepo({ findByCardCode: async () => richCard });
  await runWith(repository, async () => {
    for (const input of ['K-7F3D2A', 'k-7f3d2a', '7f3d2a', ' K-7F3D2A ', 'k-7F3D2A']) {
      expect(await resolveStampTarget(TENANT, input)).toBe(richCard);
    }
    // Every variant normalized to the bare upper-case stored code.
    expect(calls.findByCardCode).toEqual([
      [TENANT, '7F3D2A'], [TENANT, '7F3D2A'], [TENANT, '7F3D2A'],
      [TENANT, '7F3D2A'], [TENANT, '7F3D2A'],
    ]);
    expect(calls.findCardById).toHaveLength(0);
    expect(calls.findByPublicTokenHash).toHaveLength(0);
  });
});

test('(b) a well-formed but unknown code resolves to null — and NEVER falls through to the token lookup', async () => {
  const { repository, calls } = stubRepo(); // findByCardCode → null
  await runWith(repository, async () => {
    expect(await resolveStampTarget(TENANT, 'ZZZZZZ')).toBeNull();
    expect(calls.findByCardCode).toEqual([[TENANT, 'ZZZZZZ']]);
    // Codes (6 chars) and tokens (43 chars) are syntactically disjoint: a
    // valid code format ends the resolution without a pointless token lookup.
    expect(calls.findByPublicTokenHash).toHaveLength(0);
  });
});

test('(c) a raw customer token resolves via the existing findByPublicTokenHash (SHA-256 hash only) and is re-read via findCardById for the rich shape', async () => {
  const { repository, calls } = stubRepo({
    findByPublicTokenHash: async () => plainCard,
    findCardById: async () => richCard,
  });
  await runWith(repository, async () => {
    expect(await resolveStampTarget(TENANT, CARD_TOKEN)).toBe(richCard);
    // The hash lookup only ever saw the SHA-256 hash of the raw token...
    expect(calls.findByPublicTokenHash).toHaveLength(1);
    const hashParam = calls.findByPublicTokenHash[0]![1];
    expect(hashParam).toBe(createHash('sha256').update(CARD_TOKEN, 'utf8').digest('hex'));
    expect(hashParam).toMatch(/^[a-f0-9]{64}$/);
    expect(hashParam).not.toBe(CARD_TOKEN);
    // ...and the rich display card is re-read by the resolved card id.
    expect(calls.findCardById).toEqual([[TENANT, CARD]]);
  });
});

test('(c) an unknown token resolves to null (hash lookup → null, findCardById never runs)', async () => {
  const { repository, calls } = stubRepo(); // findByPublicTokenHash → null
  await runWith(repository, async () => {
    expect(await resolveStampTarget(TENANT, CARD_TOKEN)).toBeNull();
    expect(calls.findByPublicTokenHash).toHaveLength(1);
    expect(calls.findCardById).toHaveLength(0);
  });
});

test('foreign tenant: identical inputs return null — the tenant is passed through to every lookup', async () => {
  const { repository, calls } = stubRepo(); // stub answers null for ANY tenant
  await runWith(repository, async () => {
    expect(await resolveStampTarget(OTHER_TENANT, CARD)).toBeNull();
    expect(await resolveStampTarget(OTHER_TENANT, '7F3D2A')).toBeNull();
    expect(await resolveStampTarget(OTHER_TENANT, CARD_TOKEN)).toBeNull();
    // The caller's tenant travelled into the scoped lookups (RLS applies
    // inside the repository); every miss is the same null, never an error.
    expect(calls.findCardById).toEqual([[OTHER_TENANT, CARD]]);
    expect(calls.findByCardCode).toEqual([[OTHER_TENANT, '7F3D2A']]);
    expect(calls.findByPublicTokenHash).toEqual([[OTHER_TENANT, createHash('sha256').update(CARD_TOKEN, 'utf8').digest('hex')]]);
  });
});

test('garbage input resolves to null — hash fallback returns nothing, identical neutral answer', async () => {
  const { repository, calls } = stubRepo(); // all lookups → null
  await runWith(repository, async () => {
    // 'K-0F3D2A': ambiguous character (0) → normalizeCardCode rejects it.
    // 'XYZ', '12345', '!!!': wrong length/characters → rejected. None of them
    // is a UUID or a valid code, so they fall through to the (null-safe,
    // tenant-scoped) token hash lookup — there is deliberately NO token format
    // gate (tokens are opaque), the lookup is the single neutral path.
    for (const input of ['K-0F3D2A', 'XYZ', '12345', '!!!', 'token', CARD_TOKEN.toLowerCase()]) {
      expect(await resolveStampTarget(TENANT, input)).toBeNull();
    }
    expect(calls.findCardById).toHaveLength(0);
    expect(calls.findByCardCode).toHaveLength(0);
    // Every garbage input hit the hash fallback exactly once.
    expect(calls.findByPublicTokenHash).toHaveLength(6);
    for (const [, hash] of calls.findByPublicTokenHash) expect(hash).toMatch(/^[a-f0-9]{64}$/);
  });
});