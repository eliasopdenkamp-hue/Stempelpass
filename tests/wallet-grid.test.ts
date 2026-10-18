import { test, expect } from 'bun:test';
import { inflateSync } from 'node:zlib';
import {
  GRID_IMAGE_WIDTH, GRID_IMAGE_HEIGHT, EMPTY_CELL_COLOR, DEFAULT_GRID_PRIMARY, REWARD_READY_BACKGROUND,
  gridLayout, renderStampGridPng, walletGridImageUrl, walletImageBaseUrl,
  type StampGridInput,
} from '../src/wallet-grid';

/** Minimal PNG reader for assertions: signature + IHDR + single IDAT (filter 0). */
function decodePng(buf: Buffer): { width: number; height: number; raw: Buffer; stride: number } {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  expect(buf.subarray(0, 8).equals(sig)).toBe(true);
  expect(buf.readUInt32BE(16)).toBe(GRID_IMAGE_WIDTH); // IHDR width
  expect(buf.readUInt32BE(20)).toBe(GRID_IMAGE_HEIGHT); // IHDR height
  expect(buf[24]).toBe(8);  // bit depth
  expect(buf[25]).toBe(6);  // RGBA
  // IDAT starts at offset 8 + 12 (IHDR chunk) ... scan chunks
  let pos = 8;
  let idat = Buffer.alloc(0);
  while (pos < buf.length) {
    const len = buf.readUInt32BE(pos);
    const type = buf.toString('ascii', pos + 4, pos + 8);
    const data = buf.subarray(pos + 8, pos + 8 + len);
    if (type === 'IDAT') idat = Buffer.concat([idat, data]);
    if (type === 'IEND') break;
    pos += 12 + len;
  }
  const raw = inflateSync(idat);
  const stride = GRID_IMAGE_WIDTH * 4;
  expect(raw.length).toBe((stride + 1) * GRID_IMAGE_HEIGHT);
  // Every scanline starts with filter byte 0 (None).
  for (let y = 0; y < GRID_IMAGE_HEIGHT; y++) expect(raw[y * (stride + 1)]).toBe(0);
  return { width: GRID_IMAGE_WIDTH, height: GRID_IMAGE_HEIGHT, raw, stride };
}

function pixel(decoded: ReturnType<typeof decodePng>, x: number, y: number): [number, number, number] {
  const i = y * (decoded.stride + 1) + 1 + x * 4;
  return [decoded.raw[i]!, decoded.raw[i + 1]!, decoded.raw[i + 2]!];
}

/** Re-implements the renderer's grid geometry for cell-center probes. */
function cellCenters(total: number): Array<[number, number]> {
  const { cols, rows } = gridLayout(total);
  const marginX = Math.round(GRID_IMAGE_WIDTH * 0.07);
  const marginY = Math.round(GRID_IMAGE_HEIGHT * 0.16);
  const cellW = (GRID_IMAGE_WIDTH - 2 * marginX) / cols;
  const cellH = (GRID_IMAGE_HEIGHT - 2 * marginY) / rows;
  const centers: Array<[number, number]> = [];
  for (let cell = 0; cell < total; cell++) {
    centers.push([Math.floor(marginX + cellW * ((cell % cols) + 0.5)), Math.floor(marginY + cellH * (Math.floor(cell / cols) + 0.5))]);
  }
  return centers;
}

const hex = (c: string): [number, number, number] => [parseInt(c.slice(1, 3), 16), parseInt(c.slice(3, 5), 16), parseInt(c.slice(5, 7), 16)];

test('gridLayout: classic and extreme shapes', () => {
  expect(gridLayout(1)).toEqual({ cols: 1, rows: 1 });
  expect(gridLayout(4)).toEqual({ cols: 4, rows: 1 });
  expect(gridLayout(5)).toEqual({ cols: 5, rows: 1 });
  expect(gridLayout(6)).toEqual({ cols: 3, rows: 2 });
  expect(gridLayout(10)).toEqual({ cols: 5, rows: 2 }); // the classic 5×2
  expect(gridLayout(12)).toEqual({ cols: 6, rows: 2 });
  expect(gridLayout(20)).toEqual({ cols: 10, rows: 2 });
  expect(gridLayout(25)).toEqual({ cols: 5, rows: 5 }); // caps at 10 cols → square
  expect(gridLayout(100)).toEqual({ cols: 10, rows: 10 });
});

test('renderStampGridPng: valid PNG, correct dimensions, small payload', () => {
  const png = renderStampGridPng({ stampCount: 3, stampsRequired: 10, primaryColor: '#155e75' });
  expect(png.length).toBeLessThan(300 * 1024); // economical (< 300 KB)
  expect(png.length).toBeGreaterThan(100); // real data, not an empty stub
  decodePng(png); // asserts signature, IHDR, IDAT decodability, RGBA, filter bytes
});

test('renderStampGridPng: 0/N shows all empty cells', () => {
  const decoded = decodePng(renderStampGridPng({ stampCount: 0, stampsRequired: 10, primaryColor: '#155e75' }));
  const emptyHex = hex(EMPTY_CELL_COLOR);
  for (const [x, y] of cellCenters(10)) {
    expect(pixel(decoded, x, y)).toEqual(emptyHex);
  }
  // Corner probe stays white (no reward-ready tint).
  expect(pixel(decoded, 6, 6)).toEqual([255, 255, 255]);
});

test('renderStampGridPng: partial fill uses tenant primary color for the first N cells', () => {
  const decoded = decodePng(renderStampGridPng({ stampCount: 3, stampsRequired: 10, primaryColor: '#0EA5E9' }));
  const filled = hex('#0EA5E9');
  const emptyHex = hex(EMPTY_CELL_COLOR);
  const centers = cellCenters(10);
  for (let i = 0; i < 10; i++) {
    const expected = i < 3 ? filled : emptyHex;
    expect(pixel(decoded, centers[i]![0], centers[i]![1])).toEqual(expected);
  }
});

test('renderStampGridPng: default primary when tenant set none', () => {
  const decoded = decodePng(renderStampGridPng({ stampCount: 1, stampsRequired: 2 }));
  expect(pixel(decoded, ...cellCenters(2)[0]!)).toEqual(hex(DEFAULT_GRID_PRIMARY));
});

test('renderStampGridPng: count above N caps at the full grid (no overflow cells)', () => {
  const decoded = decodePng(renderStampGridPng({ stampCount: 12, stampsRequired: 10, primaryColor: '#155e75' }));
  for (const [x, y] of cellCenters(10)) {
    expect(pixel(decoded, x, y)).toEqual(hex('#155e75'));
  }
});

test('renderStampGridPng: full + reward-ready shows the subtle warm background', () => {
  const decoded = decodePng(renderStampGridPng({ stampCount: 10, stampsRequired: 10, primaryColor: '#155e75', rewardReady: true }));
  expect(pixel(decoded, 6, 6)).toEqual(hex(REWARD_READY_BACKGROUND));
  const centers = cellCenters(10);
  for (const [x, y] of centers) expect(pixel(decoded, x, y)).toEqual(hex('#155e75'));
  // Full WITHOUT the reward flag keeps the white background.
  const plain = decodePng(renderStampGridPng({ stampCount: 10, stampsRequired: 10, primaryColor: '#155e75', rewardReady: false }));
  expect(pixel(plain, 6, 6)).toEqual([255, 255, 255]);
});

test('renderStampGridPng: identical input yields byte-identical output', () => {
  const input: StampGridInput = { stampCount: 6, stampsRequired: 10, primaryColor: '#155e75' };
  expect(renderStampGridPng(input).equals(renderStampGridPng(input))).toBe(true);
});

test('walletGridImageUrl: absolute URL with revision as cache-busting ts', () => {
  expect(walletGridImageUrl('https://api.example.com', '11111111-2222-3333-4444-555555555555', 7))
    .toBe('https://api.example.com/wallet/grid/11111111-2222-3333-4444-555555555555.png?ts=7');
  // Trailing slashes on the base are normalized.
  expect(walletGridImageUrl('https://api.example.com/', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 1))
    .toBe('https://api.example.com/wallet/grid/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.png?ts=1');
});

test('walletImageBaseUrl: acceptance rules', () => {
  const old = process.env.WALLET_IMAGE_BASE_URL;
  try {
    delete process.env.WALLET_IMAGE_BASE_URL;
    expect(walletImageBaseUrl()).toBeUndefined();
    process.env.WALLET_IMAGE_BASE_URL = ' https://api.example.com/ ';
    expect(walletImageBaseUrl()).toBe('https://api.example.com'); // trimmed + no trailing slash
    process.env.WALLET_IMAGE_BASE_URL = 'http://api.example.com'; // http rejected
    expect(walletImageBaseUrl()).toBeUndefined();
    process.env.WALLET_IMAGE_BASE_URL = 'not-a-url';
    expect(walletImageBaseUrl()).toBeUndefined();
    process.env.WALLET_IMAGE_BASE_URL = 'https://api.example.com/' + 'x'.repeat(2048);
    expect(walletImageBaseUrl()).toBeUndefined(); // length cap
  } finally {
    old === undefined ? delete process.env.WALLET_IMAGE_BASE_URL : process.env.WALLET_IMAGE_BASE_URL = old;
  }
});