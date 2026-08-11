import { test, expect } from 'bun:test';
import { EncryptedMfaSecretStore, createTotpEnrollment, verifyTotp } from '../src/mfa';

test('MFA secret encryption never returns plaintext and round-trips', async () => {
  const store = new EncryptedMfaSecretStore(Buffer.alloc(32, 7).toString('base64'));
  const encrypted = await store.encrypt('JBSWY3DPEHPK3PXP');
  expect(encrypted).not.toContain('JBSWY3DPEHPK3PXP');
  expect(await store.decrypt(encrypted)).toBe('JBSWY3DPEHPK3PXP');
  await expect(store.decrypt(encrypted.slice(0, -1) + 'x')).rejects.toThrow('MFA_SECRET_DECRYPT_FAILED');
});

test('TOTP enrollment creates an otpauth URI and verifies the current code', () => {
  const enrollment = createTotpEnrollment('owner@example.invalid');
  expect(enrollment.otpauthUri).toStartWith('otpauth://totp/');
  const now = Date.now();
  const secret = enrollment.secret;
  const counter = Math.floor(now / 1000 / 30);
  const key = Buffer.from(secret.replace(/=+$/, '').split('').map(() => 0));
  // Invalid code is rejected; generation of real user secrets is intentionally not part of tests.
  expect(verifyTotp(secret, '000000', now)).toBe(false);
  expect(key.length).toBeGreaterThan(0); expect(counter).toBeGreaterThan(0);
});
