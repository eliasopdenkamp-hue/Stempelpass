/**
 * Operator-only owner-password SET/ROTATE CLI.
 *
 * Usage is deliberately out-of-band (`bun run db:rotate-owner-password`), never
 * on the Vercel request path. Configure the target with:
 *   OWNER_PASSWORD_ROTATION_TENANT_SLUG
 *   OWNER_PASSWORD_ROTATION_OWNER_EMAIL
 *   OWNER_PASSWORD_ROTATION_ID (optional; reuse for a safe retry)
 *
 * Supply the replacement password through OWNER_PASSWORD_ROTATION_PASSWORD or
 * piped stdin. It is hashed with the application's scrypt primitive before any
 * password/session/audit DML. Plaintext is never logged, returned, or stored.
 */
import { createPostgresPool, type DbPool, type TxClient } from './db.js';
import { hashPassword } from './security.js';

export const OWNER_PASSWORD_ROTATION_LOCK_KEY = 742_004;
const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const OPERATION_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;

export interface OwnerPasswordRotationInput {
  tenantSlug: string;
  ownerEmail: string;
  operationId: string;
}

export type ParseOwnerPasswordRotationResult =
  | { ok: true; input: OwnerPasswordRotationInput }
  | { ok: false; errors: string[] };

export function parseOwnerPasswordRotationEnv(env: NodeJS.ProcessEnv = process.env): ParseOwnerPasswordRotationResult {
  if (env.VERCEL === '1') return { ok: false, errors: ['OWNER_PASSWORD_ROTATION_NOT_ALLOWED_ON_VERCEL'] };
  const errors: string[] = [];
  const tenantSlug = env.OWNER_PASSWORD_ROTATION_TENANT_SLUG?.trim() ?? '';
  const ownerEmail = env.OWNER_PASSWORD_ROTATION_OWNER_EMAIL?.trim() ?? '';
  const operationId = env.OWNER_PASSWORD_ROTATION_ID?.trim() || crypto.randomUUID();
  if (!tenantSlug) errors.push('OWNER_PASSWORD_ROTATION_TENANT_SLUG_REQUIRED');
  else if (tenantSlug.length > 63 || !SLUG_RE.test(tenantSlug)) errors.push('INVALID_OWNER_PASSWORD_ROTATION_TENANT_SLUG');
  if (!ownerEmail) errors.push('OWNER_PASSWORD_ROTATION_OWNER_EMAIL_REQUIRED');
  else if (ownerEmail.length > 254 || !EMAIL_RE.test(ownerEmail)) errors.push('INVALID_OWNER_PASSWORD_ROTATION_OWNER_EMAIL');
  if (!OPERATION_ID_RE.test(operationId)) errors.push('INVALID_OWNER_PASSWORD_ROTATION_ID');
  if (errors.length) return { ok: false, errors };
  return { ok: true, input: { tenantSlug, ownerEmail, operationId } };
}

/** The operator connection must own (or be a member of the owner of) tenants. */
export const OPERATOR_ROLE_CHECK = `select exists (
  select 1 from pg_tables t
   where t.schemaname = 'public' and t.tablename = 'tenants'
     and pg_has_role(current_user, t.tableowner, 'member')
) as is_operator`;

async function isOperatorRole(pool: DbPool): Promise<boolean> {
  const db = await pool.connect();
  try {
    const result = await db.query<{ is_operator: boolean }>(OPERATOR_ROLE_CHECK);
    return result.rows[0]?.is_operator === true;
  } finally {
    db.release();
  }
}

export type PasswordReader = () => Promise<string>;

/** Read one password from piped stdin without echoing or printing it. */
export async function readPasswordFromStdin(): Promise<string> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of process.stdin) chunks.push(typeof chunk === 'string' ? new TextEncoder().encode(chunk) : chunk);
  const value = Buffer.concat(chunks.map(chunk => Buffer.from(chunk))).toString('utf8');
  return value.endsWith('\n') ? value.slice(0, -1).replace(/\r$/, '') : value;
}

/** Environment first, stdin fallback. The environment value is cleared when running against process.env. */
export async function readOwnerPassword(env: NodeJS.ProcessEnv = process.env, readStdin: PasswordReader = readPasswordFromStdin): Promise<string> {
  const value = env.OWNER_PASSWORD_ROTATION_PASSWORD;
  if (value !== undefined) {
    if (env === process.env) delete env.OWNER_PASSWORD_ROTATION_PASSWORD;
    return value;
  }
  return readStdin();
}

interface RotationTarget {
  tenantId: string;
  userId: string;
  ownerEmail: string;
}

const TARGET_QUERY = `select t.id as "tenantId", u.id as "userId", u.email as "ownerEmail"
  from tenants t
  join tenant_memberships m on m.tenant_id = t.id and m.role = 'owner' and m.status = 'active'
  join users u on u.id = m.user_id and u.status = 'active'
 where t.slug = $1 and t.status = 'active' and lower(u.email) = lower($2)
 for update`;

const EXISTING_OPERATION_QUERY = `select tenant_id, entity_id
  from audit_log
 where action = 'operator.owner_password_rotated'
   and metadata->>'operationId' = $1
 limit 2`;

/**
 * Apply one rotation on a transaction held by the operator role. This function
 * never creates users or memberships and does not accept a plaintext password.
 */
export async function rotateOwnerPassword(
  db: TxClient,
  input: OwnerPasswordRotationInput,
  passwordHash: string,
): Promise<'rotated' | 'already_applied'> {
  const target = (await db.query<RotationTarget>(TARGET_QUERY, [input.tenantSlug, input.ownerEmail])).rows;
  if (target.length === 0) throw new Error('OWNER_NOT_FOUND');
  if (target.length > 1) throw new Error('OWNER_AMBIGUOUS');
  const owner = target[0];

  const prior = (await db.query<{ tenant_id: string; entity_id: string }>(EXISTING_OPERATION_QUERY, [input.operationId])).rows;
  if (prior.some(row => row.tenant_id !== owner.tenantId || row.entity_id !== owner.userId)) throw new Error('OWNER_PASSWORD_ROTATION_ID_REUSED');
  if (prior.length) return 'already_applied';

  const updated = await db.query<{ id: string }>(
    'update users set password_hash = $1, updated_at = now() where id = $2 and status = \'active\' returning id',
    [passwordHash, owner.userId],
  );
  if (!updated.rows[0]) throw new Error('OWNER_UPDATE_FAILED');
  await db.query('update sessions set revoked_at = now() where user_id = $1 and revoked_at is null', [owner.userId]);
  const audit = await db.query<{ id: string }>(`insert into audit_log(tenant_id,actor_user_id,action,entity_type,entity_id,metadata)
    select $1, null, 'operator.owner_password_rotated', 'user', $2, $3::jsonb
     where not exists (
       select 1 from audit_log
        where action = 'operator.owner_password_rotated'
          and metadata->>'operationId' = $4
     )
    returning id`, [owner.tenantId, owner.userId, JSON.stringify({ operationId: input.operationId }), input.operationId]);
  if (!audit.rows[0]) throw new Error('OWNER_AUDIT_FAILED');
  return 'rotated';
}

const SAFE_ERRORS = new Set([
  'OWNER_NOT_FOUND', 'OWNER_AMBIGUOUS', 'OWNER_PASSWORD_ROTATION_ID_REUSED',
  'OWNER_UPDATE_FAILED', 'OWNER_AUDIT_FAILED', 'PASSWORD_TOO_SHORT',
]);
function safeErrorCode(error: unknown): string {
  const message = error instanceof Error ? error.message : '';
  return SAFE_ERRORS.has(message) ? message : 'OWNER_PASSWORD_ROTATION_FAILED';
}

/** CLI body. Returns process exit code; output contains status only. */
export async function dbRotateOwnerPassword(
  env: NodeJS.ProcessEnv = process.env,
  makePool: (url: string) => DbPool = createPostgresPool,
  readPassword: PasswordReader = () => readOwnerPassword(env),
): Promise<number> {
  const parsed = parseOwnerPasswordRotationEnv(env);
  if (!parsed.ok) {
    for (const code of parsed.errors) console.error(`owner_password_rotation_failed ${code}`);
    return 1;
  }
  const url = env.DATABASE_URL?.trim();
  if (!url) {
    console.error('owner_password_rotation_failed DATABASE_URL_REQUIRED');
    return 1;
  }
  let pool: DbPool | undefined;
  try {
    pool = makePool(url);
    if (!(await isOperatorRole(pool))) {
      console.error('owner_password_rotation_failed OWNER_PASSWORD_ROTATION_ROLE_NOT_OPERATOR');
      return 1;
    }
    const db = await pool.connect();
    try {
      await db.query('begin');
      await db.query('select pg_advisory_xact_lock($1)', [OWNER_PASSWORD_ROTATION_LOCK_KEY]);
      // Resolve the exact existing owner before hashing; never create a second user.
      const target = (await db.query<RotationTarget>(TARGET_QUERY, [parsed.input.tenantSlug, parsed.input.ownerEmail])).rows;
      if (target.length === 0) throw new Error('OWNER_NOT_FOUND');
      if (target.length > 1) throw new Error('OWNER_AMBIGUOUS');
      let plaintext = await readPassword();
      let passwordHash: string;
      try {
        passwordHash = await hashPassword(plaintext);
      } finally {
        // Drop our reference as soon as the hash has been produced.
        // The CLI never prints or persists this value.
        plaintext = '';
      }
      const result = await rotateOwnerPassword(db, parsed.input, passwordHash);
      await db.query('commit');
      console.log(`owner_password_rotation_ok status=${result}`);
      return 0;
    } catch (error) {
      try { await db.query('rollback'); } catch { /* preserve the stable error */ }
      console.error(`owner_password_rotation_failed ${safeErrorCode(error)}`);
      return 1;
    } finally {
      db.release();
    }
  } catch (error) {
    console.error(`owner_password_rotation_failed ${safeErrorCode(error)}`);
    return 1;
  } finally {
    try { await pool?.end?.(); } catch { /* best effort */ }
  }
}

if (import.meta.main) process.exit(await dbRotateOwnerPassword());
