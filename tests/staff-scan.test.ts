/**
 * Staff camera scan unit tests (2026-10-18) — DB-free.
 *
 * What CAN be tested without a camera/device:
 *  - scanned-value normalization (trim, webcard-URL reduction),
 *  - the EXACT embedded copy of normalizeScannedTarget inside the generated
 *    page script (Bun's Function.prototype.toString returns the transpiled
 *    JS — verified: no TS annotations leak into the browser — so the embedded
 *    function is parseable and behaves identically),
 *  - decoder wiring (BarcodeDetector branch / zxing fallback / file-input
 *    fallback presence), the on-device privacy note, the ≥44px button, the
 *    vendor asset (UMD bundle non-empty, exposes the ZXing global).
 *
 * What needs a real device and is honestly documented in
 * STAFF_SCAN_DEPLOY_*.md / the PR: live camera frames, getUserMedia
 * permission UX, BarcodeDetector on Android Chrome, decode on iOS Safari,
 * photo fallback UX.
 */
import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { normalizeScannedTarget, scanFieldHtml, scanModalHtml, staffScanScript } from '../src/staff-scan.js';
import { zxingSource, zxingSourceStats } from '../src/vendor-assets.js';
import { ZXING_UMD_BYTES, ZXING_UMD_SHA256 } from '../src/vendor/zxing-umd.js';

/** Read the (generated) vendor-assets.ts source for the no-runtime-fs pin. */
const vendorAssetsSource = (): string =>
  readFileSync(join(import.meta.dir, '..', 'src', 'vendor-assets.ts'), 'utf8');

/** Evaluate the EXACT embedded function copy shipped in the page script. */
function embeddedNormalize(): (raw: unknown) => string {
  const script = staffScanScript();
  const marker = 'function normalizeScannedTarget';
  const start = script.indexOf(marker);
  if (start < 0) throw new Error('embedded normalizeScannedTarget not found');
  const end = script.indexOf('\n}', start);
  if (end < 0) throw new Error('embedded normalizeScannedTarget not closed');
  const src = script.slice(start, end + 2); // includes final "}"
  // https://eslint.org/docs/latest/rules/no-implied-eval — deliberate: our own static source
  const fn = new Function(`${src}; return normalizeScannedTarget;`)() as (raw: unknown) => string;
  return fn;
}

describe('normalizeScannedTarget (TS export)', () => {
  test('passes card codes through unchanged (trimmed)', () => {
    expect(normalizeScannedTarget('K-7F3D2A')).toBe('K-7F3D2A');
    expect(normalizeScannedTarget('  k-7f3d2a  ')).toBe('k-7f3d2a'); // case is the server resolver's job
    expect(normalizeScannedTarget('7F3D2A')).toBe('7F3D2A');
  });
  test('reduces a webcard URL QR to its final path segment (the customer token)', () => {
    expect(normalizeScannedTarget('https://example.test/card/11111111-1111-4111-8111-111111111111/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ab_')).toBe('AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ab_');
    expect(normalizeScannedTarget('http://localhost:8787/card/t/u-x')).toBe('u-x');
  });
  test('leaves non-/card/ URLs unchanged (the search answers "nicht gefunden")', () => {
    expect(normalizeScannedTarget('https://example.test/other/path')).toBe('https://example.test/other/path');
  });
  test('empty/whitespace/null input yields empty string (no search triggered)', () => {
    expect(normalizeScannedTarget('')).toBe('');
    expect(normalizeScannedTarget('   ')).toBe('');
    expect(normalizeScannedTarget(null)).toBe('');
    expect(normalizeScannedTarget(undefined)).toBe('');
  });
});

describe('staffScanScript() — embedded copy and decoder wiring', () => {
  test('embedded normalizeScannedTarget parses as plain JS (no TS annotations) and behaves like the export', () => {
    const script = staffScanScript();
    // Bun's toString() returns transpiled JS — pin that no annotation leaked.
    const embeddedSrc = script.slice(script.indexOf('function normalizeScannedTarget'), script.indexOf('\n}', script.indexOf('function normalizeScannedTarget')) + 2);
    expect(embeddedSrc).not.toContain(': string');
    expect(embeddedSrc).not.toContain('unknown');
    const emb = embeddedNormalize();
    expect(emb('K-7F3D2A')).toBe('K-7F3D2A');
    expect(emb('https://example.test/card/t/tok-1')).toBe('tok-1');
    expect(emb('')).toBe('');
  });
  test('script contains both decoder branches and the on-device guarantee', () => {
    const s = staffScanScript();
    expect(s).toContain('window.BarcodeDetector');
    expect(s).toContain("formats: ['code_128', 'qr_code']");
    expect(s).toContain('/vendor/zxing.min.js');
    expect(s).toContain('ZXing.BrowserMultiFormatReader');
    expect(s).toContain('decodeFromVideoElement');
    expect(s).toContain('decodeFromImageElement');
    expect(s).toContain('sp-scan-file');
    expect(s).toContain("facingMode: { ideal: 'environment' }");
    // No raw </script> inside the JS body (only the real closing tag at the end)
    const body = s.slice(0, s.lastIndexOf('</script>'));
    expect(body).not.toContain('</script');
  });
  test('fills the existing search/stamp inputs and submits the EXISTING search form', () => {
    const s = staffScanScript();
    expect(s).toContain("byId('sp-code-input')");
    expect(s).toContain('form.stamp-form input[name="cardId"]');
    expect(s).toContain("byId('sp-code-search')");
    expect(s).toContain("form.dispatchEvent(ev)");
  });
});

describe('scan modal + scan field markup', () => {
  test('modal: dialog, video, file fallback, privacy note', () => {
    const m = scanModalHtml();
    expect(m).toContain('id="sp-scan-modal"');
    expect(m).toContain('id="sp-scan-video"');
    expect(m).toContain('id="sp-scan-file"');
    expect(m).toContain('accept="image/*"');
    expect(m).toContain('ausschließlich auf diesem Gerät verarbeitet');
  });
  test('scan field wraps an input plus an accessible ≥44px camera button', () => {
    const f = scanFieldHtml('<input name="cardId">');
    expect(f).toContain('class="sp-scan-field"');
    expect(f).toContain('class="ghost sp-scan-btn"');
    expect(f).toContain('aria-label="Kartencode per Kamera scannen"');
    expect(f).toContain('<input name="cardId">');
  });
});

describe('vendor asset (client-side decoder, served via GET /vendor/zxing.min.js)', () => {
  test('embedded payload decodes to the exact UMD bytes and exposes the ZXing global', () => {
    const stats = zxingSourceStats();
    // Exact byte count of the ORIGINAL minified UMD (pinned in the generated
    // src/vendor/zxing-umd.ts) — not just a loose "> 100 KB" bound.
    expect(stats.bytes).toBe(ZXING_UMD_BYTES);
    expect(stats.bytes).toBeGreaterThan(100_000);
    expect(stats.hasGlobal).toBe(true);
  });

  test('decoded payload matches the pinned SHA-256 (no hand-edit drift)', () => {
    const decoded = Buffer.from(zxingSource(), 'utf8');
    expect(createHash('sha256').update(decoded).digest('hex')).toBe(ZXING_UMD_SHA256);
  });

  test('vendor-assets.ts has NO runtime fs/node_modules access (PR #44 root cause pinned)', () => {
    const source = vendorAssetsSource();
    // The prose comment deliberately describes the PR #44 failure (it names
    // readFileSync/require.resolve), so the pin targets the actual import
    // vectors of a runtime-fs regression: node:fs and node:module. The
    // BUILT-bundle anti-pattern check (verify-bundle, RUNTIME_FS_PATTERN
    // anchored on .resolve('@zxing/…) covers the call itself.
    expect(source).not.toContain('node:fs');
    expect(source).not.toContain('node:module');
    expect(source).not.toContain("from 'node:");
  });
});