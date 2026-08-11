/** Security primitives. Secrets are supplied by deployment environment only. */
import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
const SCRYPT_OPTIONS = { N: 32_768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 } as const;
const scrypt = (password: string, salt: Buffer, keylen: number): Promise<Buffer> => new Promise((resolve, reject) => {
  scryptCallback(password, salt, keylen, SCRYPT_OPTIONS, (error, derivedKey) => {
    if (error) reject(error); else resolve(derivedKey as Buffer);
  });
});
const PASSWORD_PREFIX = '$scrypt$N=32768,r=8,p=1$';

export function requireConfig(env: NodeJS.ProcessEnv = process.env): void {
  if (!env.DATABASE_URL || !env.SESSION_SECRET) throw new Error('CONFIGURATION_REQUIRED');
  if (env.SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET_TOO_SHORT');
}

/**
 * Node 22-compatible password hashing. scrypt is memory-hard and keeps the
 * same async API shape as the former Bun implementation without runtime lock-in.
 */
export async function hashPassword(password: string): Promise<string> {
  if (password.length < 12) throw new Error('PASSWORD_TOO_SHORT');
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, 32) as Buffer;
  return `${PASSWORD_PREFIX}${salt.toString('base64url')}$${derived.toString('base64url')}`;
}

export async function verifyPassword(password: string, encoded: string): Promise<boolean> {
  try {
    if (!encoded.startsWith(PASSWORD_PREFIX)) return false;
    const [saltText, digestText] = encoded.slice(PASSWORD_PREFIX.length).split('$');
    if (!saltText || !digestText) return false;
    const salt = Buffer.from(saltText, 'base64url');
    const expected = Buffer.from(digestText, 'base64url');
    if (salt.length !== 16 || expected.length !== 32) return false;
    const actual = await scrypt(password, salt, expected.length) as Buffer;
    return timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

export interface Session { id: string; userId: string; tenantId?: string; expiresAt: number; csrfToken: string }
const b64 = (v: ArrayBuffer | ArrayBufferView) => Buffer.from(v instanceof ArrayBuffer ? new Uint8Array(v) : Array.from(new Uint8Array(v.buffer, v.byteOffset, v.byteLength))).toString('base64url');
export function randomToken(bytes = 32): string { return b64(randomBytes(bytes)); }
export function hashSessionToken(token: string): string { return createHash('sha256').update(token, 'utf8').digest('hex'); }
export async function signSession(session: Omit<Session, 'id'>, secret = process.env.SESSION_SECRET): Promise<string> {
  if (!secret) throw new Error('CONFIGURATION_REQUIRED');
  const payload = b64(new TextEncoder().encode(JSON.stringify(session)));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return `${payload}.${b64(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload)))}`;
}
export async function verifySession(token: string, secret = process.env.SESSION_SECRET): Promise<Session | null> {
  try {
    if (!secret) return null; const [payload, sig] = token.split('.'); if (!payload || !sig) return null;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify('HMAC', key, Buffer.from(sig, 'base64url'), new TextEncoder().encode(payload)); if (!ok) return null;
    const value = JSON.parse(Buffer.from(payload, 'base64url').toString()) as Session; return value.expiresAt > Date.now() ? value : null;
  } catch { return null; }
}
export function csrfValid(req: Request, expected: string): boolean {
  if (!['POST','PUT','PATCH','DELETE'].includes(req.method)) return true;
  return req.headers.get('x-csrf-token') === expected;
}

/**
 * Fixed-window in-memory rate limiter.
 *
 * IMPORTANT: these limits are per process/instance only. They are not shared
 * across instances, so a horizontally scaled (distributed) deployment MUST
 * replace them with a central limiter (e.g. Redis) using the same keys and
 * limits. See RATE_LIMITING.md.
 */
export class RateLimiter {
  private buckets = new Map<string, { count: number; reset: number }>();
  private calls = 0;
  /**
   * @param max          maximum allowed calls per window per key
   * @param windowMs     window length in milliseconds
   * @param maxEntries   upper bound on tracked keys; when reached, expired
   *                     buckets are swept and the soonest-resetting bucket is
   *                     evicted so attacker-controlled keys cannot grow memory
   *                     without bound (default: unbounded, keeps old behavior)
   */
  constructor(private readonly max: number, private readonly windowMs: number, private readonly maxEntries = Infinity) {}
  allow(key: string, now = Date.now()): boolean {
    // Full sweep is amortized (every 128th call) so a large key table does not
    // make every request O(n); the eviction path below also drops expired keys.
    if ((++this.calls & 0x7f) === 0) this.sweep(now);
    if (this.buckets.size >= this.maxEntries) {
      let earliestKey: string | undefined; let earliestReset = Infinity;
      for (const [k, b] of this.buckets) {
        if (b.reset <= now) { this.buckets.delete(k); continue; }
        if (b.reset < earliestReset) { earliestReset = b.reset; earliestKey = k; }
      }
      if (this.buckets.size >= this.maxEntries && earliestKey !== undefined) this.buckets.delete(earliestKey);
    }
    const old = this.buckets.get(key); if (!old || old.reset <= now) { this.buckets.set(key, { count: 1, reset: now + this.windowMs }); return true; } if (old.count >= this.max) return false; old.count++; return true;
  }
  private sweep(now: number): void { for (const [k, b] of this.buckets) if (b.reset <= now) this.buckets.delete(k); }
  clear(): void { this.buckets.clear(); }
  get size(): number { return this.buckets.size; }
}

/**
 * Normalized, hashed login-account key. The raw email is never used as a
 * limiter key and never logged; only this digest is stored/logged.
 */
export function loginAccountKey(email: string): string {
  const normalized = String(email ?? '').trim().toLowerCase();
  return `acct:${createHash('sha256').update(normalized, 'utf8').digest('hex')}`;
}

const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const IPV6_RE = /^[0-9a-fA-F:.]+$/;
function isIpLike(value: string): boolean {
  if (IPV4_RE.test(value)) return value.split('.').every(octet => Number(octet) <= 255);
  return IPV6_RE.test(value) && value.includes(':');
}

/**
 * Safe client-identity key for rate limiting.
 *
 * `x-forwarded-for` is attacker-controlled unless a trusted proxy overwrites
 * it, so it is never used as the sole identity (the login path additionally
 * limits per hashed account key). The first entry is used only when it looks
 * like a real IP; anything else (missing, malformed, header injection) falls
 * back to a single shared `unknown` bucket. The value is hashed so raw
 * addresses never appear in limiter keys or memory.
 */
export function clientIpKey(req: Request): string {
  const forwarded = (req.headers.get('x-forwarded-for') ?? '').split(',')[0]?.trim() ?? '';
  const candidate = forwarded && isIpLike(forwarded) ? forwarded : 'unknown';
  return `ip:${createHash('sha256').update(candidate, 'utf8').digest('hex')}`;
}

/**
 * Per-path /join resolution limiter key: hashed client IP plus SHA-256 of the
 * public key. Binds the budget to one client + one entry point (a shared
 * office cannot exhaust a single global bucket) and keeps raw public keys out
 * of limiter keys and memory, mirroring the hashed login-account key.
 */
export function joinResolveKey(req: Request, publicKey: string): string {
  return `${clientIpKey(req)}:join:${createHash('sha256').update(String(publicKey ?? ''), 'utf8').digest('hex')}`;
}

/**
 * Internal-only login failure reasons. The login route maps every one of these
 * to the single stable external code INVALID_CREDENTIALS so that responses do
 * not reveal whether an account exists, whether its password matched, or what
 * its MFA state is. The reason is used only for server-side audit logging.
 */
export const LOGIN_FAILURE_CODES: ReadonlySet<string> = new Set([
  'INVALID_CREDENTIALS',
  'MFA_NOT_CONFIGURED',
  'MFA_INVALID',
  'MFA_SECRET_DECRYPT_FAILED',
  'MFA_BOOTSTRAP_UNVERIFIED',
]);

/** Returns the internal audit reason for a thrown login error, or null when it is not a credential/MFA failure. */
export function loginFailureReason(e: unknown): string | null {
  return e instanceof Error && LOGIN_FAILURE_CODES.has(e.message) ? e.message : null;
}

// Dummy scrypt hash: verifying against it takes the same time as a real hash
// check, so "account not found" cannot be distinguished from "wrong password"
// by response timing.
const dummyPasswordHash: Promise<string> = hashPassword(randomToken(16));
/** Timing-equalizing password check for unknown accounts (always returns false). */
export async function verifyPasswordAgainstDummy(password: string): Promise<boolean> {
  try { return await verifyPassword(password, await dummyPasswordHash); } catch { return false; }
}

/**
 * Login limits. The IP limiter alone is spoofable (see clientIpKey), so the
 * account limiter binds per normalized account regardless of spoofed IPs, and
 * the IP limiter additionally caps per source. MFA failures flow through the
 * same login path and therefore consume the same budget. Per-instance only.
 */
export const loginIpLimiter = new RateLimiter(20, 15 * 60_000, 50_000);
export const loginAccountLimiter = new RateLimiter(5, 15 * 60_000, 50_000);
export const cardResolveLimiter = new RateLimiter(60, 60_000, 50_000);
export const stampLimiter = new RateLimiter(30, 60_000, 50_000);
