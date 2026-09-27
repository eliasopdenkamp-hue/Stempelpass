import { test, expect } from 'bun:test';
import {
  CARD_CODE_ALPHABET, CARD_CODE_LENGTH, CARD_CODE_PREFIX, CARD_CODE_RE,
  generateCardCode, formatCardCode, normalizeCardCode,
} from '../src/card-code';

test('alphabet is confusion-safe: no 0/O/1/I and 32 distinct characters', () => {
  expect(CARD_CODE_ALPHABET).toHaveLength(32);
  expect(CARD_CODE_ALPHABET).not.toMatch(/[0O1I]/);
  expect(new Set(CARD_CODE_ALPHABET).size).toBe(32);
  expect(CARD_CODE_LENGTH).toBe(6);
  expect(CARD_CODE_PREFIX).toBe('K-');
});

test('generated codes match the strict format and the alphabet bounds', () => {
  for (let i = 0; i < 200; i++) {
    const code = generateCardCode();
    expect(code).toMatch(CARD_CODE_RE);
    expect(code).toHaveLength(6);
    for (const ch of code) expect(CARD_CODE_ALPHABET).toContain(ch);
  }
});

test('generated codes are unique in bulk (collision probability below 1e-9)', () => {
  const seen = new Set<string>();
  for (let i = 0; i < 5000; i++) {
    const code = generateCardCode();
    expect(seen.has(code)).toBe(false);
    seen.add(code);
  }
  expect(seen.size).toBe(5000);
});

test('formatCardCode renders the K- display prefix consistently', () => {
  expect(formatCardCode('7F3D2A')).toBe('K-7F3D2A');
  expect(formatCardCode('ABCDEF')).toBe('K-ABCDEF');
  expect(`${CARD_CODE_PREFIX}${generateCardCode()}`).toMatch(/^K-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{6}$/);
});

test('normalizeCardCode accepts bare codes, with prefix, lower-case and whitespace', () => {
  expect(normalizeCardCode('7F3D2A')).toBe('7F3D2A');
  expect(normalizeCardCode('K-7F3D2A')).toBe('7F3D2A');
  expect(normalizeCardCode('k-7f3d2a')).toBe('7F3D2A'); // lower-case input + prefix
  expect(normalizeCardCode('  k-7f3d2a  ')).toBe('7F3D2A'); // surrounding whitespace
  expect(normalizeCardCode('7f3d2a')).toBe('7F3D2A'); // lower-case without prefix
});

test('normalizeCardCode rejects ambiguous/bad input (0/O/1/I, wrong length, junk)', () => {
  for (const bad of ['', ' ', '0F3D2A', '7F3D21', 'OF3D2A', '7F3D2I', '7F3D2', '7F3D2AA', 'K-', 'K-7F3D2', 'K-07F3D2', 'K-XWZ1', '7F3D2A!', 'K-7F3D2A-', '7f3d2a-']) {
    expect(normalizeCardCode(bad)).toBeNull();
  }
  // The prefix is only accepted at the very start: an interior K- is junk.
  expect(normalizeCardCode('7F3D-K-2A')).toBeNull();
});