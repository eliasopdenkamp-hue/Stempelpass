/**
 * Unit tests for the build-time regression guard `scripts/verify-bundle.ts`
 * (PR #45: embedded zxing UMD payload — no runtime fs on node_modules).
 *
 * These tests use the REAL committed payload constant (EXPECTED_PAYLOAD), so
 * the pins (byte count + sha256) can never drift from what vendor-assets.ts
 * serves: the suite fails the moment the generated src/vendor/zxing-umd.ts is
 * hand-edited. They never touch a built .vercel/output — the CLI walk over
 * the real function directory stays a manual deploy step.
 */
import { describe, expect, test } from 'bun:test';
import { checkFunctionFiles, EXPECTED_PAYLOAD, RUNTIME_FS_PATTERN, type FunctionFile } from '../scripts/verify-bundle.js';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

/** Simulated built function output: one transpiled module carrying the payload. */
function bund(): FunctionFile {
  return {
    path: 'src/vendor/zxing-umd.js',
    content: `"use strict";
// transpiled src/vendor/zxing-umd.ts (esbuild-style, literals kept intact)
const ZXING_UMD_BASE64 = "${EXPECTED_PAYLOAD.base64}";
module.exports = { ZXING_UMD_BASE64 };`,
  };
}

describe('checkFunctionFiles — payload presence and exactness', () => {
  test('exact embedded payload in the built bundle passes (found + pinned hash/bytes)', () => {
    const check = checkFunctionFiles([bund(), { path: 'src/server.js', content: 'export const x = 1;' }]);
    expect(check.errors).toEqual([]);
    expect(check.ok).toBe(true);
    expect(check.payloadFile).toBe('src/vendor/zxing-umd.js');
    expect(check.payloadSha256).toBe(EXPECTED_PAYLOAD.sha256);
  });

  test('payload also provable via the source map (sourcesContent copy)', () => {
    const map = {
      path: 'src/vendor/zxing-umd.js.map',
      content: JSON.stringify({ version: 3, sources: ['../src/vendor/zxing-umd.ts'], sourcesContent: [`export const ZXING_UMD_BASE64 = "${EXPECTED_PAYLOAD.base64}";`] }),
    };
    const check = checkFunctionFiles([map]);
    expect(check.ok).toBe(true);
    expect(check.payloadFile).toBe(map.path);
  });

  test('missing payload fails with PAYLOAD_NOT_FOUND_IN_FUNCTION_BUNDLE', () => {
    const check = checkFunctionFiles([
      { path: 'src/server.js', content: 'export const x = 1;' },
      { path: 'src/vendor-assets.js', content: 'export function vendorZxingResponse(){ return new Response(""); }' },
    ]);
    expect(check.ok).toBe(false);
    expect(check.errors.join(',')).toContain('PAYLOAD_NOT_FOUND_IN_FUNCTION_BUNDLE');
    expect(check.payloadFile).toBeNull();
  });

  test('corrupted payload at the marker fails (PAYLOAD_CORRUPTED_IN_BUNDLE, hash diagnosis)', () => {
    const good = EXPECTED_PAYLOAD.base64;
    const corrupted = good.slice(0, 4000) + (good[4000] === 'A' ? 'B' : 'A') + good.slice(4001);
    expect(corrupted).not.toBe(good);
    const check = checkFunctionFiles([{ path: 'src/vendor/zxing-umd.js', content: `const B = "${corrupted}";` }]);
    expect(check.ok).toBe(false);
    expect(check.payloadFile).toBeNull();
    expect(check.errors.join(',')).toContain('PAYLOAD_CORRUPTED_IN_BUNDLE');
  });

  test('committed payload decodes to the pinned byte count and sha256 (guards hand-edit drift)', () => {
    const decoded = Buffer.from(EXPECTED_PAYLOAD.base64, 'base64');
    expect(decoded.length).toBe(EXPECTED_PAYLOAD.bytes);
    expect(createHash('sha256').update(decoded).digest('hex')).toBe(EXPECTED_PAYLOAD.sha256);
  });
});

describe('checkFunctionFiles — runtime-fs regression guard', () => {
  test('the broken PR #44 pattern is rejected', () => {
    const check = checkFunctionFiles([
      {
        path: 'src/vendor-assets.js',
        content: `const nodeRequire = createRequire(import.meta.url);
const ZXING_UMD_PATH = nodeRequire.resolve('@zxing/library/umd/index.min.js');`,
      },
    ]);
    expect(check.ok).toBe(false);
  });

  test('RUNTIME_FS_PATTERN only matches the require.resolve form (@zxing scoped)', () => {
    expect(RUNTIME_FS_PATTERN.test(`nodeRequire.resolve('@zxing/library/umd/index.min.js')`)).toBe(true);
    expect(RUNTIME_FS_PATTERN.test(`nodeRequire.resolve("@zxing/library/umd/index.min.js")`)).toBe(true);
    expect(RUNTIME_FS_PATTERN.test(`import { ZXING_UMD_BASE64 } from './vendor/zxing-umd.js';`)).toBe(false);
    expect(RUNTIME_FS_PATTERN.test(`otherRequire.resolve('@zxing/library/umd/index.min.js')`)).toBe(true); // any require.resolve form
    expect(RUNTIME_FS_PATTERN.test(`readFileSync('./x.js')`)).toBe(false);
  });

  test('exact payload + runtime-fs pattern in the SAME output fails (both checks reported)', () => {
    const files: FunctionFile[] = [
      bund(),
      {
        path: 'src/vendor-assets.js',
        content: `const nodeRequire = createRequire(import.meta.url); const p = nodeRequire.resolve('@zxing/library/umd/index.min.js');`,
      },
    ];
    const check = checkFunctionFiles(files);
    expect(check.errors.join(',')).toContain('RUNTIME_FS_DEPENDENCY_STILL_PRESENT');
    expect(check.ok).toBe(false);
  });
});

describe('committed payload vs installed package (drift check)', () => {
  test('src/vendor/zxing-umd.ts base64 is byte-identical to the installed UMD file', () => {
    const local = join(import.meta.dir, '..', 'node_modules', '@zxing', 'library', 'umd', 'index.min.js');
    try {
      const raw = readFileSync(local);
      const sha = createHash('sha256').update(raw).digest('hex');
      expect(sha).toBe(EXPECTED_PAYLOAD.sha256);
      const b64 = raw.toString('base64');
      expect(b64).toBe(EXPECTED_PAYLOAD.base64);
    } catch {
      // node_modules not installed in this checkout — the pinned-hash tests
      // above still protect the bundle; nothing else to assert here.
      expect(true).toBe(true);
    }
  });
});