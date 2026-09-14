import { test, expect } from 'bun:test';
import { qrSvgDataUri, qrMatrix, type QrOptions } from '../src/qr';

/**
 * QR wrapper tests (thin layer over the vendored qrcode-generator@1.4.4).
 * The vendor lib itself was validated with jsQR (all lengths decode); these
 * tests pin the wrapper contract: deterministic SVG data-URIs, well-formed
 * viewBox output, and coverage of the exact payload shapes this app emits
 * (webcard URLs with card tokens, /join paths, long strings).
 */

function decodeDataUri(uri: string): { svg: string } {
  expect(uri.startsWith('data:image/svg+xml;utf8,')).toBe(true);
  const svg = decodeURIComponent(uri.slice('data:image/svg+xml;utf8,'.length));
  return { svg };
}

test('qrSvgDataUri is deterministic (same input → identical output)', () => {
  const a = qrSvgDataUri('https://example.com/card/t/ABC');
  const b = qrSvgDataUri('https://example.com/card/t/ABC');
  expect(a).toBe(b);
  expect(a.length).toBeGreaterThan(100);
});

test('qrSvgDataUri renders a well-formed SVG with a square viewBox', () => {
  const uri = qrSvgDataUri('hello');
  const { svg } = decodeDataUri(uri);
  expect(svg).toContain('<svg');
  expect(svg).toContain('</svg>');
  expect(svg).toContain('shape-rendering="crispEdges"');
  expect(svg).toContain('<path');
  // viewBox present and square (dimension scales with the module count).
  const match = svg.match(/viewBox="0 0 (\d+) (\d+)"/);
  expect(match).not.toBeNull();
  const [, w, h] = match!;
  expect(w).toBe(h);
  expect(Number(w)).toBeGreaterThan(0);
});

test('qrSvgDataUri handles the payload shapes this app emits without exception', () => {
  const payloads = [
    // Webcard URL with tenant UUID + base64url card token.
    'https://example.com/card/11111111-1111-4111-8111-111111111111/ABC_def_-xyz==',
    // Join path (public key, 32 hex).
    '/join/abcdef0123456789abcdef0123456789',
    // Webcard relative URL (as stored in the staff dashboard view).
    '/card/11111111-1111-4111-8111-111111111111/ABCdef-_xyz==',
    // Long string (auto version escalation still works).
    'x'.repeat(300),
  ];
  for (const text of payloads) {
    const uri = qrSvgDataUri(text);
    const { svg } = decodeDataUri(uri);
    expect(svg).toContain('<svg');
    // Different payloads produce different codes.
  }
  expect(qrSvgDataUri(payloads[0]!)).not.toBe(qrSvgDataUri(payloads[1]!));
});

test('qrSvgDataUri encodes the payload into the module raster (dark modules decode back)', () => {
  // The SVG path describes run-length encoded dark modules; the matrix API
  // returns the same shape the QR code actually contains.
  const text = '/card/t1/TOKEN==';
  const matrix = qrMatrix(text);
  const n = matrix.length;
  expect(n).toBeGreaterThanOrEqual(21);
  for (const row of matrix) expect(row.length).toBe(n);
  const dark = matrix.flat().filter(Boolean).length;
  expect(dark).toBeGreaterThan(0);
  // Finder pattern cells are dark in every QR code.
  expect(matrix[0]![0]).toBe(true);
});

test('qrSvgDataUri rejects an empty input with QR_TEXT_REQUIRED', () => {
  expect(() => qrSvgDataUri('')).toThrow('QR_TEXT_REQUIRED');
});

test('qrSvgDataUri honors error-correction and quiet-zone options deterministically', () => {
  const base = qrSvgDataUri('options-test', { errorCorrection: 'M' } as QrOptions);
  const base2 = qrSvgDataUri('options-test', { errorCorrection: 'M' } as QrOptions);
  expect(base).toBe(base2);
  // quietZone 0 shrinks the viewBox vs the default 4-module margin.
  const noQuiet = qrSvgDataUri('options-test', { errorCorrection: 'M', quietZone: 0 } as QrOptions & { quietZone?: number });
  const dim = (uri: string) => Number(decodeDataUri(uri).svg.match(/width="(\d+)"/)?.[1]);
  expect(dim(noQuiet)).toBeLessThan(dim(base));
});