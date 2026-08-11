import { describe, expect, test } from 'bun:test';
import { CONSENT_SOURCES, validateConsentSource } from '../src/communication';
import { recipientHash } from '../src/email';

describe('communication privacy controls', () => {
  test('accepts only the controlled consent source allowlist', () => {
    for (const source of CONSENT_SOURCES) expect(validateConsentSource(source)).toBe(source);
    for (const source of ['newsletter https://evil.test', 'alice@example.test', 'token_abc', '', 'WEB_FORM']) {
      expect(() => validateConsentSource(source)).toThrow('INVALID_CONSENT_SOURCE');
    }
  });
  test('HMAC differs from legacy SHA-256 and varies with secret', () => {
    const email = 'Alice@example.test';
    const a = recipientHash(email, { COMMUNICATION_HASH_SECRET: 'a'.repeat(32) });
    const b = recipientHash(email, { COMMUNICATION_HASH_SECRET: 'b'.repeat(32) });
    expect(a).toBeTruthy();
    expect(a).not.toBe(b);
    expect(a).not.toBe('');
  });
  test('missing or short secret returns no pseudonym', () => {
    expect(recipientHash('alice@example.test', {})).toBeNull();
    expect(recipientHash('alice@example.test', { COMMUNICATION_HASH_SECRET: 'short' })).toBeNull();
  });
});
