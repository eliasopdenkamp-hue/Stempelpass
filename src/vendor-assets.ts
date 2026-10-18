/**
 * Static client-side decoder asset for the staff camera scan.
 *
 * @zxing/library (Apache-2.0) UMD bundle, served at GET /vendor/zxing.min.js
 * and lazy-loaded by the staff scan script ONLY on browsers without a native
 * BarcodeDetector (iOS Safari, Firefox, desktop Chrome — Android Chrome and
 * desktop Chrome-with-flag use the built-in detector and never download this).
 * It decodes Code-128 (the Google Wallet card barcode) and QR (the webcard
 * code QR) entirely in the browser — no image ever leaves the device.
 *
 * The 362 KB minified bundle is read ONCE at module load and served from
 * memory. `require.resolve` is used (instead of a relative path) so
 * @vercel/nft traces the file into the serverless function bundle; the
 * deployed function therefore carries the asset itself — verified in the
 * deploy script by grepping the function output for `umd/index.min.js`.
 */
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const nodeRequire = createRequire(import.meta.url);
const ZXING_UMD_PATH = nodeRequire.resolve('@zxing/library/umd/index.min.js');
const ZXING_SOURCE = readFileSync(ZXING_UMD_PATH, 'utf8');

/** GET /vendor/zxing.min.js — public, no auth, no DB, immutable 1 h cache. */
export function vendorZxingResponse(): Response {
  return new Response(ZXING_SOURCE, {
    headers: {
      'Content-Type': 'application/javascript; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

/** Exposed for the unit test (file exists, non-empty, contains the UMD hook). */
export function zxingSourceStats(): { bytes: number; hasGlobal: boolean } {
  return { bytes: ZXING_SOURCE.length, hasGlobal: ZXING_SOURCE.includes('ZXing') };
}