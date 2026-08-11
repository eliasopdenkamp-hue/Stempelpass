import { test, expect } from 'bun:test';
import {
  RateLimiter,
  clientIpKey,
  loginAccountKey,
  loginFailureReason,
  LOGIN_FAILURE_CODES,
  verifyPasswordAgainstDummy,
} from '../src/security';

test('login account key normalizes and hashes, never contains the raw email', () => {
  const a = loginAccountKey('Owner@Example.COM');
  const b = loginAccountKey('  owner@example.com ');
  expect(a).toBe(b);
  expect(a).toStartWith('acct:');
  expect(a).toMatch(/^acct:[0-9a-f]{64}$/);
  expect(a).not.toContain('owner');
  expect(a).not.toContain('example');
  expect(a).not.toContain('@');
  expect(loginAccountKey('other@example.com')).not.toBe(a);
  expect(loginAccountKey('')).toStartWith('acct:');
});

test('clientIpKey uses the first x-forwarded-for entry, hashed, never raw', () => {
  const req = (xff: string | null) =>
    new Request('https://x/api/auth/login', {
      method: 'POST',
      headers: xff === null ? {} : { 'x-forwarded-for': xff },
    });
  const v4 = clientIpKey(req('203.0.113.7'));
  expect(v4).toStartWith('ip:');
  expect(v4).toMatch(/^ip:[0-9a-f]{64}$/);
  expect(v4).not.toContain('203.0.113.7');
  // First entry wins when a chain is present.
  expect(clientIpKey(req('203.0.113.7, 10.0.0.1'))).toBe(v4);
  // IPv6 is accepted.
  expect(clientIpKey(req('2001:db8::1'))).toStartWith('ip:');
  // Missing, empty, or malformed headers share one conservative 'unknown' bucket.
  const unknown = clientIpKey(req(null));
  expect(unknown).toBe(clientIpKey(req('')));
  expect(unknown).toBe(clientIpKey(req('garbage, 203.0.113.7')));
  expect(unknown).toBe(clientIpKey(req('10.0.0.999'))); // invalid octet
  expect(unknown).not.toBe(v4);
});

test('login failures are recognized only for the unified credential/MFA reasons', () => {
  expect(loginFailureReason(new Error('INVALID_CREDENTIALS'))).toBe('INVALID_CREDENTIALS');
  expect(loginFailureReason(new Error('MFA_NOT_CONFIGURED'))).toBe('MFA_NOT_CONFIGURED');
  expect(loginFailureReason(new Error('MFA_INVALID'))).toBe('MFA_INVALID');
  expect(loginFailureReason(new Error('MFA_SECRET_DECRYPT_FAILED'))).toBe('MFA_SECRET_DECRYPT_FAILED');
  expect(loginFailureReason(new Error('MFA_BOOTSTRAP_UNVERIFIED'))).toBe('MFA_BOOTSTRAP_UNVERIFIED');
  // Non-login failures must NOT be treated as login failures: they keep their own mapping.
  expect(loginFailureReason(new Error('CREDENTIALS_REQUIRED'))).toBeNull();
  expect(loginFailureReason(new Error('RATE_LIMITED'))).toBeNull();
  expect(loginFailureReason(new Error('MFA_REQUIRED'))).toBeNull();
  expect(loginFailureReason(new Error('boom'))).toBeNull();
  expect(loginFailureReason('INVALID_CREDENTIALS')).toBeNull();
  expect(loginFailureReason(undefined)).toBeNull();
  expect([...LOGIN_FAILURE_CODES].sort()).toEqual(
    ['INVALID_CREDENTIALS', 'MFA_INVALID', 'MFA_NOT_CONFIGURED', 'MFA_SECRET_DECRYPT_FAILED', 'MFA_BOOTSTRAP_UNVERIFIED'].sort(),
  );
});

test('dummy verification always fails but accepts a well-formed password (timing equalizer)', async () => {
  expect(await verifyPasswordAgainstDummy('a sufficiently long password')).toBe(false);
  expect(await verifyPasswordAgainstDummy('another sufficiently long password')).toBe(false);
});

test('RateLimiter caps tracked keys and keeps enforcing limits after eviction', () => {
  const r = new RateLimiter(2, 60_000, 3);
  expect(r.allow('a', 0)).toBe(true);
  expect(r.allow('b', 1)).toBe(true);
  expect(r.allow('c', 2)).toBe(true); // at capacity
  // New key evicts the soonest-resetting bucket ('a', reset at 60000) and is allowed.
  expect(r.allow('d', 3)).toBe(true);
  expect(r.size).toBe(3);
  // 'a' was evicted: it gets a fresh bucket and is allowed again.
  expect(r.allow('a', 4)).toBe(true);
  // Limits still hold per surviving key: 'd' was already counted once.
  expect(r.allow('d', 5)).toBe(true);
  expect(r.allow('d', 6)).toBe(false);
  // Expired buckets are swept.
  expect(r.allow('e', 120_001)).toBe(true);
  expect(r.size).toBeLessThanOrEqual(3);
});

test('RateLimiter default remains unbounded for existing behavior', () => {
  const r = new RateLimiter(5, 1000);
  for (let i = 0; i < 10_000; i++) r.allow(`k${i}`, 0);
  expect(r.size).toBe(10_000);
});
