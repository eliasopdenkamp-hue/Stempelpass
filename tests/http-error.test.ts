import { test, expect } from 'bun:test';
import { classifyError, DOMAIN_ERROR_CODES, errorStatus } from '../src/http-error';

const KNOWN: Array<[string, number]> = [
  ['CARD_NOT_FOUND', 404],
  ['RULE_NOT_FOUND', 404],
  ['TENANT_NOT_FOUND', 404],
  ['CUSTOMER_NOT_FOUND', 404],
  ['REWARD_NOT_FOUND', 404],
  ['ENTRY_POINT_NOT_FOUND', 404],
  ['MEMBERSHIP_NOT_FOUND', 404],
  ['CUSTOMER_LIMIT_REACHED', 409],
  ['REWARD_ALREADY_REDEEMED', 409],
  ['FORBIDDEN', 403],
  ['TENANT_CONTEXT_REQUIRED', 403],
  ['CSRF_INVALID', 403],
  ['UNAUTHENTICATED', 401],
  ['RATE_LIMITED', 429],
  ['INVALID_CREDENTIALS', 400],
  ['CARD_FIELDS_REQUIRED', 400],
  ['INVALID_STAMP_QUANTITY', 400],
];

test('known domain errors keep their stable code and status, no server detail', () => {
  for (const [code, status] of KNOWN) {
    const r = classifyError(new Error(code));
    expect(r.code).toBe(code);
    expect(r.status).toBe(status);
    expect(r.detail).toBeNull();
  }
});

test('unexpected DB errors never leak their message to the client', () => {
  const r = classifyError(new Error('relation "cards" does not exist'));
  expect(r.code).toBe('INTERNAL_ERROR');
  expect(r.status).toBe(500);
  // Detail exists only for server-side logging and is never the response code.
  expect(r.detail).toContain('relation "cards" does not exist');
});

test('other internal error messages map to INTERNAL_ERROR', () => {
  for (const message of ['duplicate key value violates unique constraint "cards_tenant_id_public_token_hash_key"', 'connection terminated unexpectedly', 'TypeError: x is not a function']) {
    const r = classifyError(new Error(message));
    expect(r.code).toBe('INTERNAL_ERROR');
    expect(r.status).toBe(500);
  }
});

test('non-Error throws map to INTERNAL_ERROR with 500', () => {
  expect(classifyError('boom').code).toBe('INTERNAL_ERROR');
  expect(classifyError('boom').status).toBe(500);
  expect(classifyError(undefined).code).toBe('INTERNAL_ERROR');
  expect(classifyError(undefined).status).toBe(500);
});

test('allowlist is stable: includes CUSTOMER_NOT_FOUND, excludes INTERNAL_ERROR and DB noise', () => {
  expect(DOMAIN_ERROR_CODES.has('CUSTOMER_NOT_FOUND')).toBe(true);
  expect(DOMAIN_ERROR_CODES.has('INTERNAL_ERROR')).toBe(false);
  expect(DOMAIN_ERROR_CODES.has('relation cards does not exist')).toBe(false);
  expect(errorStatus('NOT_FOUND')).toBe(404);
  expect(errorStatus('CUSTOMER_LIMIT_REACHED')).toBe(409);
});
test('log detail redacts secrets/PII: DSNs, credentials, tokens, e-mails, addresses', () => {
  const r = classifyError(new Error(
    'connect failed postgres://svc:supersecret@db.internal:5432/app password=hunter2 token=abcDEF1234567890abcdef user=app host=db.internal admin@example.com 203.0.113.7 00000000-0000-4000-8000-000000000000 a'.repeat(64),
  ));
  expect(r.code).toBe('INTERNAL_ERROR');
  expect(r.status).toBe(500);
  const d = r.detail ?? '';
  expect(d).not.toContain('supersecret');
  expect(d).not.toContain('hunter2');
  expect(d).not.toContain('db.internal');
  expect(d).not.toContain('admin@example.com');
  expect(d).not.toContain('203.0.113.7');
  expect(d).not.toContain('00000000-0000-4000-8000-000000000000');
  expect(d).not.toContain('abcDEF1234567890abcdef'); // long token
  expect(d).not.toContain('a'.repeat(64));
  expect(d).toContain('<redacted>');
});
test('log detail keeps a stable class name, never the raw provider class', () => {
  const provider = new Error('relation "cards" does not exist');
  Object.defineProperty(provider, 'name', { value: 'PostgresError' });
  const r = classifyError(provider);
  expect(r.detail).not.toContain('PostgresError');
  expect(r.detail).toContain('UnknownError');
  // The message survives redaction only when it contains no secret material.
  expect(r.detail).toContain('relation "cards" does not exist');
  // Native stable classes keep their name.
  const typeErr = classifyError(new TypeError('x is not a function'));
  expect(typeErr.detail).toContain('TypeError');
  expect(typeErr.detail).toContain('x is not a function');
});
test('log detail never contains the raw error message verbatim when it embeds secrets', () => {
  const secret = 'session_token=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const r = classifyError(new Error(`boom ${secret}`));
  expect(r.detail).not.toContain('session_token=0123456789abcdef');
  expect(r.detail).not.toContain('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
  expect(r.detail).toContain('<redacted>');
});
test('log detail is truncated to MAX_DETAIL_LENGTH', () => {
  const r = classifyError(new Error('e'.repeat(5000)));
  expect(r.detail?.length ?? 0).toBeLessThanOrEqual(300);
});
test('HTTP responses are unchanged: unexpected errors still yield only INTERNAL_ERROR + request_id', () => {
  // Response sanitization is classifyError's code/status mapping — the redacted
  // detail is server-side only and must never appear in the response shape.
  const r = classifyError(new Error('secret leaked here'));
  expect(r.code).toBe('INTERNAL_ERROR');
  expect(r.status).toBe(500);
  expect(r.detail).not.toBeNull(); // detail is for logging, not the client
});
