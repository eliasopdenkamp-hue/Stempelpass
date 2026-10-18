/**
 * Post-build regression guard for the embedded zxing UMD payload (PR #45).
 *
 * The PR #44 cold-start crash (FUNCTION_INVOCATION_FAILED on ALL routes) was
 * caused by a runtime `readFileSync(require.resolve('@zxing/library/umd/
 * index.min.js'))` whose file @vercel/nft never traced into the serverless
 * function bundle. The old deploy check ("grep the build output for
 * `umd/index.min.js`") was worthless: the string sat in a source comment, so
 * the grep passed while the asset was missing.
 *
 * This guard inspects the BUILT function output (`.vercel/output/functions/
 * api/index.func`), NOT the repo source and NOT `.vercel/output/static` (the
 * platform's static copy of the repo would fool a source grep again), and
 * proves:
 *   1. PAYLOAD PRESENT — the exact committed base64 payload (the bytes of
 *      node_modules/@zxing/library/umd/index.min.js, embedded build-time in
 *      src/vendor/zxing-umd.ts) appears inside the function bundle.
 *   2. PAYLOAD EXACT — decoding that base64 yields the pinned byte size and
 *      SHA-256 (ZXING_UMD_BYTES / ZXING_UMD_SHA256 of the same generated
 *      module — they are produced together and cannot drift).
 *   3. NO RUNTIME-FS DEPENDENCY — no `require.resolve('@zxing/library/umd/…`
 *      anywhere in the function output (a future re-introduction of the
 *      broken pattern fails the gate before deploy).
 *
 * Usage (in the deploy checklist, between `vercel build --prod` and
 * `vercel deploy --prebuilt --prod`):
 *   bun run verify-bundle
 *
 * Exit codes:
 *   0  all checks passed — the function bundle carries the exact decoder
 *   1  at least one check failed (see errors in the report; DO NOT DEPLOY)
 *   2  the guard could not run (missing/unreadable function output — run
 *      `vercel build --prod` first)
 *
 * The check core (`checkFunctionFiles`) is pure and unit-tested in
 * tests/verify-bundle.test.ts (positive, missing payload, corrupted payload,
 * runtime-fs regression).
 */
import { readFile, readdir, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join, relative } from 'node:path';
import { ZXING_UMD_BASE64, ZXING_UMD_BYTES, ZXING_UMD_SHA256 } from '../src/vendor/zxing-umd.js';

export interface ExpectedPayload {
  /** The committed base64 of the original UMD file. */
  base64: string;
  /** Original byte size (ZXING_UMD_BYTES). */
  bytes: number;
  /** SHA-256 of the original bytes (ZXING_UMD_SHA256). */
  sha256: string;
}

export const EXPECTED_PAYLOAD: ExpectedPayload = {
  base64: ZXING_UMD_BASE64,
  bytes: ZXING_UMD_BYTES,
  sha256: ZXING_UMD_SHA256,
};

/**
 * The broken PR #44 pattern: module-load fs access into node_modules. The
 * regex only matches the runtime-fs form; the payload string itself (a value,
 * not a require call) is allowed everywhere. Note that PR #44 called it on a
 * `nodeRequire` variable (capital R), so the pattern anchors on `.resolve(`,
 * never on the variable name.
 */
export const RUNTIME_FS_PATTERN = /\.resolve\(\s*['"]@zxing\/library\/umd\//;

export interface FunctionFile {
  /** Path relative to the function root (e.g. `src/vendor-assets.js`). */
  path: string;
  content: string;
}

export interface BundleCheck {
  ok: boolean;
  /** Relative path of the first file that proved the payload (null = missing). */
  payloadFile: string | null;
  /** sha256 of the payload as embedded in the built bundle (hex, null = missing). */
  payloadSha256: string | null;
  errors: string[];
  notes: string[];
}

/**
 * Pure check over the BUILT function output files. Fails when the exact
 * payload is absent, when a different base64 run sits at the payload marker
 * (corrupted/partial embed), when the found payload does not decode to the
 * pinned hash/byte count, or when a runtime require.resolve-of-zxing pattern
 * is still present.
 */
export function checkFunctionFiles(files: FunctionFile[], expected: ExpectedPayload = EXPECTED_PAYLOAD): BundleCheck {
  const errors: string[] = [];
  const notes: string[] = [];
  let payloadFile: string | null = null;
  let payloadSha256: string | null = null;

  // A 96-char prefix is unique to this payload; the longest base64 run at that
  // marker is extracted from the BUILT file (not from the expected constant),
  // so a present-but-corrupted embed is detected, not just a missing one.
  const marker = expected.base64.slice(0, 96);
  const BASE64_RUN = /[A-Za-z0-9+/]{200,}={0,2}/;

  let corruptCandidate: { path: string; candidate: string } | null = null;

  for (const f of files) {
    if (RUNTIME_FS_PATTERN.test(f.content)) {
      errors.push(`RUNTIME_FS_DEPENDENCY_STILL_PRESENT:${f.path}`);
    }
    if (payloadFile !== null) continue;
    const idx = f.content.indexOf(marker);
    if (idx < 0) continue;
    const run = BASE64_RUN.exec(f.content.slice(idx));
    if (!run) continue;
    const candidate = run[0];
    if (candidate === expected.base64) {
      payloadFile = f.path;
    } else if (corruptCandidate === null) {
      corruptCandidate = { path: f.path, candidate };
    }
  }

  if (payloadFile !== null) {
    notes.push(`payload found in ${payloadFile}`);
    // The build check only accepted the exact committed base64 string; decode
    // it and pin against the committed metadata, so the built bundle is proven
    // to carry the exact original bytes of the UMD file.
    try {
      const decoded = Buffer.from(expected.base64, 'base64');
      payloadSha256 = createHash('sha256').update(decoded).digest('hex');
      if (decoded.length !== expected.bytes) {
        errors.push(`PAYLOAD_BYTE_COUNT_MISMATCH:embedded=${decoded.length},expected=${expected.bytes}`);
      }
      if (payloadSha256 !== expected.sha256) {
        errors.push('PAYLOAD_SHA256_MISMATCH');
      }
    } catch {
      errors.push('PAYLOAD_BASE64_INVALID');
    }
  } else if (corruptCandidate !== null) {
    // A different base64 run sits at the payload marker — the build carries
    // wrong bytes. Decode it for a classified length/hash diagnosis.
    try {
      const decoded = Buffer.from(corruptCandidate.candidate, 'base64');
      const hash = createHash('sha256').update(decoded).digest('hex');
      errors.push(
        `PAYLOAD_CORRUPTED_IN_BUNDLE:${corruptCandidate.path} (${corruptCandidate.candidate.length}b64 chars, ${decoded.length} bytes, sha256=${hash})`,
      );
    } catch {
      errors.push(`PAYLOAD_CORRUPTED_IN_BUNDLE:${corruptCandidate.path} (not decodable base64)`);
    }
  } else {
    errors.push('PAYLOAD_NOT_FOUND_IN_FUNCTION_BUNDLE');
  }

  return {
    ok: errors.length === 0,
    payloadFile,
    payloadSha256,
    errors,
    notes,
  };
}

/** Walk a directory tree and return every regular file's relative path+content. */
export async function readFunctionTree(funcDir: string): Promise<FunctionFile[]> {
  const out: FunctionFile[] = [];
  async function walk(dir: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === 'node_modules') continue; // traced runtime deps only; irrelevant to the payload
      const full = join(dir, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (entry.isFile()) {
        const info = await stat(full);
        if (info.size === 0) continue;
        out.push({ path: relative(funcDir, full), content: await readFile(full, 'utf8') });
      }
    }
  }
  await walk(funcDir);
  return out;
}

const DEFAULT_FUNC_DIR = join(import.meta.dir, '..', '.vercel', 'output', 'functions', 'api', 'index.func');

if (import.meta.main) {
  try {
    const funcDir = process.argv[2] ?? DEFAULT_FUNC_DIR;
    let files: FunctionFile[];
    try {
      files = await readFunctionTree(funcDir);
    } catch {
      console.log(
        JSON.stringify(
          {
            ok: false,
            errors: ['FUNCTION_OUTPUT_UNAVAILABLE: run `vercel build --prod` first (verifies .vercel/output/functions/api/index.func)'],
            notes: [`expected function dir: ${funcDir}`],
          },
          null,
          2,
        ),
      );
      process.exit(2);
    }
    const check = checkFunctionFiles(files);
    console.log(
      JSON.stringify(
        {
          ok: check.ok,
          inspectedFiles: files.length,
          payloadFile: check.payloadFile,
          payloadSha256: check.payloadSha256,
          expectedBytes: EXPECTED_PAYLOAD.bytes,
          errors: check.errors,
          notes: check.notes,
          exitCode: check.ok ? 0 : 1,
        },
        null,
        2,
      ),
    );
    process.exit(check.ok ? 0 : 1);
  } catch {
    console.log(JSON.stringify({ ok: false, errors: ['VERIFY_BUNDLE_INTERNAL_ERROR'] }, null, 2));
    process.exit(2);
  }
}