/**
 * QR Code SVG data-URI wrapper around the vendored `qrcode-generator@1.4.4`
 * (MIT, Kazuhiko Arase — see the license/copyright header in
 * src/vendor/qrcode.js; vendored because the dependency is browser/Bun
 * compatible, dependency-free and tiny, and an earlier self-written encoder
 * produced codes that jsQR could not decode at any length).
 *
 * The wrapper is deliberately thin: it only renders the module raster of the
 * vendored encoder as an SVG data URI (`data:image/svg+xml;utf8,`). SVG needs
 * no zlib/Canvas, so this runs anywhere the backend runs. Browsers rasterize
 * it in an <img>, and phone camera scanners see a regular QR.
 *
 * API (kept compatible with the previous self-contained module):
 *   - `qrMatrix(text, opts?)`      → boolean[][] row-major dark-module matrix
 *   - `qrSvgDataUri(text, opts?)`  → `data:image/svg+xml;utf8,` URI
 *
 * Throws `QR_TEXT_REQUIRED` for an empty input; the vendored encoder throws
 * its own "code length overflow" when the text does not fit version 40.
 */
import qrcodeFactory from './vendor/qrcode.js';

export type QrErrorCorrection = 'L' | 'M' | 'Q' | 'H';
export interface QrOptions {
  errorCorrection?: QrErrorCorrection;
  /** ISO four-module quiet zone; set 0 to omit it (inline embedding). */
  quietZone?: number;
  /** Swap dark/light modules (white on dark background). */
  invert?: boolean;
  /** Pixel size of one module for the rendered SVG (default 8). */
  scale?: number;
}

const DEFAULT_ERROR_CORRECTION: QrErrorCorrection = 'M';

/** Build a QRCode instance for `text` (type 0 = automatic version selection). */
function makeQr(text: string, opts: QrOptions): ReturnType<typeof qrcodeFactory> {
  if (!text) throw new Error('QR_TEXT_REQUIRED');
  const qr = qrcodeFactory(0, opts.errorCorrection ?? DEFAULT_ERROR_CORRECTION);
  qr.addData(text);
  qr.make();
  return qr;
}

/** Row-major dark-module matrix of the encoded text (versions 1–40, auto). */
export function qrMatrix(text: string, opts: QrOptions = {}): boolean[][] {
  const qr = makeQr(text, opts);
  const size = qr.getModuleCount();
  const matrix: boolean[][] = [];
  for (let r = 0; r < size; r++) {
    const row: boolean[] = [];
    for (let c = 0; c < size; c++) row.push(qr.isDark(r, c));
    matrix.push(row);
  }
  return matrix;
}

/** SVG data URI of a scannable QR for `text` (deterministic per input). */
export function qrSvgDataUri(text: string, opts: QrOptions & { quietZone?: number; invert?: boolean; scale?: number } = {}): string {
  const qr = makeQr(text, opts);
  const size = qr.getModuleCount();
  const quiet = opts.quietZone ?? 4;
  const scale = opts.scale ?? 8;
  const dim = (size + quiet * 2) * scale;
  const fg = opts.invert ? '#fff' : '#000';
  const bg = opts.invert ? '#000' : '#fff';
  const parts: string[] = [];
  for (let r = 0; r < size; r++) {
    let runStart = -1;
    for (let c = 0; c <= size; c++) {
      const dark = c < size && qr.isDark(r, c);
      if (dark && runStart < 0) runStart = c;
      if (!dark && runStart >= 0) {
        parts.push(`M${(runStart + quiet) * scale} ${(r + quiet) * scale}h${(c - runStart) * scale}v${scale}h${-(c - runStart) * scale}z`);
        runStart = -1;
      }
    }
  }
  const path = parts.join('');
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${dim}" height="${dim}" viewBox="0 0 ${dim} ${dim}" shape-rendering="crispEdges"><rect width="${dim}" height="${dim}" fill="${bg}"/><path fill="${fg}" d="${svgXml(path)}"/></svg>`;
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

/** The `d` attribute of a run-length path: module coordinates are plain
 *  integers/spaces, so no XML escaping is needed — kept as a named function
 *  so the intent is explicit and the output stays deterministic. */
function svgXml(path: string): string {
  return path;
}