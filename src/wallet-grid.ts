/**
 * Stamp-raster PNG for the Google Wallet pass (Owner-Entscheid 2026-10-18).
 *
 * The Wallet Loyalty API has NO native progress element: `LoyaltyPoints`
 * carries only a bare number balance (`balance.int`), so the visible grid is
 * rendered server-side as a PNG and embedded in the pass via
 * `imageModulesData` (see src/wallet.ts). This module is deliberately
 * dependency-free: a ~90-line PNG encoder (node:zlib + own CRC-32) instead of
 * a canvas/pngjs dependency — pure data, no fonts, deterministic output.
 *
 * The image is public by design: it contains only what the pass itself shows
 * (stamp count, rule threshold, tenant colors, reward-ready). No PII, no
 * token, no customer data. Google fetches the URL with no session, so the
 * route (src/server.ts GET /wallet/grid/:cardUuid.png) is unauthenticated but
 * rate-limited like the other public card routes.
 */
import { deflateSync } from 'node:zlib';

/** Raster image size: wide, "100% width image module" friendly (~2:1). */
export const GRID_IMAGE_WIDTH = 900;
export const GRID_IMAGE_HEIGHT = 450;
/** Empty (still-to-collect) stamp circle. */
export const EMPTY_CELL_COLOR = '#E2E8F0';
/** Subtle edge for empty cells so the slots read as stamp positions. */
export const EMPTY_CELL_BORDER = '#CBD5E1';
/** Default fill color when the tenant set none (matches webcard default). */
export const DEFAULT_GRID_PRIMARY = '#155e75';
/** Warm, subtle background tint once the card is FULL and a reward is issued
 *  ("voll + dezenter Zustand"). Redeem itself resets the counter to 0
 *  (existing logic), so the tint marks the reward-ready round. */
export const REWARD_READY_BACKGROUND = '#FFFBEB';

/** Strict six-digit CSS hex (accepts both casings, as the Wallet API does). */
function parseHexColor(value: string | undefined | null): [number, number, number] | null {
  const match = /^#([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2})$/.exec(value ?? '');
  if (!match) return null;
  return [parseInt(match[1]!, 16), parseInt(match[2]!, 16), parseInt(match[3]!, 16)];
}

/** Grid geometry for a stamp target of `total` fields. */
export function gridLayout(total: number): { cols: number; rows: number } {
  const n = Math.max(1, Math.floor(Number.isFinite(total) ? total : 1));
  if (n <= 5) return { cols: n, rows: 1 };
  let cols = Math.ceil(n / 2); // wide two-row grid for classic cards (5×2 at 10)
  if (cols > 10) cols = Math.ceil(Math.sqrt(n)); // e.g. N=100 → 10×10
  return { cols, rows: Math.ceil(n / cols) };
}

export interface StampGridInput {
  /** Current stamp count. */
  stampCount: number;
  /** Rule threshold (stamps required for the reward). */
  stampsRequired: number;
  /** Tenant primary color (#rrggbb) — filled cells. Defaults when unset. */
  primaryColor?: string;
  /** Tenant secondary color (#rrggbb) — unused (white canvas reads better on
   *  the class-colored card), accepted for future customization. */
  secondaryColor?: string;
  /** Full + reward issued → subtle warm background (dezent). */
  rewardReady?: boolean;
}

/* ------------------------------------------------------------------ *
 * Minimal PNG encoder (8-bit RGBA, filter 0, zlib-deflated IDAT).
 * ------------------------------------------------------------------ */
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of buf) crc = CRC_TABLE[(crc ^ byte) & 0xff]! ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type: string, data: Buffer): Buffer {
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, 'ascii');
  data.copy(out, 8);
  out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
  return out;
}

/** Encode an RGBA canvas (width × height × 4 bytes) as a PNG buffer. */
export function encodeRgbaPng(width: number, height: number, rgba: Buffer): Buffer {
  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0; // filter type 0 = None (per scanline)
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // color type 6 = RGBA
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace
  return Buffer.concat([
    PNG_SIGNATURE,
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', deflateSync(raw, { level: 9 })),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

/* ------------------------------------------------------------------ *
 * Grid drawing.
 * ------------------------------------------------------------------ */
export function renderStampGridPng(input: StampGridInput): Buffer {
  const w = GRID_IMAGE_WIDTH;
  const h = GRID_IMAGE_HEIGHT;
  const stampCount = Math.max(0, Math.floor(Number.isFinite(input.stampCount) ? input.stampCount : 0));
  const required = Math.max(1, Math.floor(Number.isFinite(input.stampsRequired) ? input.stampsRequired : 1));
  const filled = Math.min(stampCount, required);
  const primary = parseHexColor(input.primaryColor) ?? parseHexColor(DEFAULT_GRID_PRIMARY)!;
  const empty = parseHexColor(EMPTY_CELL_COLOR)!;
  const emptyBorder = parseHexColor(EMPTY_CELL_BORDER)!;
  const canvas = Buffer.alloc(w * h * 4);
  // Background: warm tint only when the card is full AND the reward is open.
  const rewardReady = Boolean(input.rewardReady) && stampCount >= required;
  const background = rewardReady ? parseHexColor(REWARD_READY_BACKGROUND)! : [255, 255, 255] as [number, number, number];

  const { cols, rows } = gridLayout(required);
  const marginX = Math.round(w * 0.07);
  const marginY = Math.round(h * 0.16);
  const availW = w - 2 * marginX;
  const availH = h - 2 * marginY;
  const cellW = availW / cols;
  const cellH = availH / rows;
  const radius = Math.min(cellW, cellH) * 0.32;

  const blend = (dst: Buffer, i: number, color: [number, number, number], alpha: number) => {
    const a = Math.max(0, Math.min(1, alpha));
    const inv = 1 - a;
    dst[i] = Math.round(color[0] * a + dst[i] * inv);
    dst[i + 1] = Math.round(color[1] * a + dst[i + 1] * inv);
    dst[i + 2] = Math.round(color[2] * a + dst[i + 2] * inv);
    dst[i + 3] = 255;
  };

  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const i = (y * w + x) * 4;
      canvas[i] = background[0];
      canvas[i + 1] = background[1];
      canvas[i + 2] = background[2];
      canvas[i + 3] = 255;
      for (let cell = 0; cell < required; cell++) {
        const col = cell % cols;
        const row = Math.floor(cell / cols);
        const cx = marginX + cellW * (col + 0.5);
        const cy = marginY + cellH * (row + 0.5);
        const dist = Math.hypot(x - cx, y - cy);
        if (dist > radius + 1.5) continue;
        const isFilled = cell < filled;
        // Anti-aliased coverage for the filled disk and the empty-cell ring.
        if (isFilled && dist <= radius - 0.5) {
          canvas[i] = primary[0]; canvas[i + 1] = primary[1]; canvas[i + 2] = primary[2]; canvas[i + 3] = 255;
        } else if (isFilled) {
          const cover = Math.max(0, Math.min(1, radius + 0.5 - dist));
          blend(canvas, i, primary, cover);
        } else if (dist <= radius - 0.5) {
          canvas[i] = empty[0]; canvas[i + 1] = empty[1]; canvas[i + 2] = empty[2]; canvas[i + 3] = 255;
        } else if (dist <= radius + 1.5 && dist >= radius - 0.5) {
          // Ring: darken the empty-cell edge so slots are visible on white.
          const cover = Math.max(0, Math.min(1, 1 - (dist - radius)));
          blend(canvas, i, emptyBorder, cover * 0.6);
        }
      }
    }
  }
  return encodeRgbaPng(w, h, canvas);
}

/* ------------------------------------------------------------------ *
 * Public URL for the raster image (embedded in imageModulesData).
 * ------------------------------------------------------------------ */
/**
 * Hosted base URL for Wallet pass images (env `WALLET_IMAGE_BASE_URL`).
 * Must be an absolute https URL without trailing slash. Optional: when unset
 * or invalid, the pass is built without the raster image (graceful no-op,
 * same philosophy as the unconfigured wallet adapter).
 */
export function walletImageBaseUrl(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const raw = env.WALLET_IMAGE_BASE_URL?.trim();
  if (!raw || !/^https:\/\/\S+$/i.test(raw) || raw.length > 2048) return undefined;
  return raw.replace(/\/+$/, '');
}

/**
 * Deterministic image URL for one card state. `revision` is the card revision
 * (bumped on every stamp AND on redeem — monotonic, never reuses a value, so
 * the URL is a safe cache key even though the count resets 10 → 0 after a
 * redeem). The `ts` query parameter is the cache-buster: Google caches the
 * PNG immutably per URL, and a changed revision always yields a changed URL.
 */
export function walletGridImageUrl(baseUrl: string, cardUuid: string, revision: number): string {
  const base = baseUrl.replace(/\/+$/, '');
  return `${base}/wallet/grid/${encodeURIComponent(cardUuid)}.png?ts=${encodeURIComponent(String(revision))}`;
}