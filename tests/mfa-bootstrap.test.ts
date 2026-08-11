import { test, expect } from 'bun:test';
import { requireVerifiedMfaBootstrap } from '../src/mfa-bootstrap';

test('MFA bootstrap fails closed when RLS filtered or aggregate is NULL', () => {
  expect(() => requireVerifiedMfaBootstrap(undefined)).toThrow('MFA_BOOTSTRAP_UNVERIFIED');
  expect(() => requireVerifiedMfaBootstrap({ required: null })).toThrow('MFA_BOOTSTRAP_UNVERIFIED');
  expect(() => requireVerifiedMfaBootstrap({ required: undefined })).toThrow('MFA_BOOTSTRAP_UNVERIFIED');
});

test('MFA bootstrap accepts only an explicit boolean result', () => {
  expect(requireVerifiedMfaBootstrap({ required: true })).toBe(true);
  expect(requireVerifiedMfaBootstrap({ required: false })).toBe(false);
});
