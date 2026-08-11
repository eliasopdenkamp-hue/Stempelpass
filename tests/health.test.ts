import { test, expect, afterAll } from 'bun:test';
import { spawn, type ChildProcess } from 'node:child_process';
import net from 'node:net';
import { join } from 'node:path';
import { publicHealthResponse, publicHealthStatus } from '../src/health';

/**
 * Security P2: GET /health must expose ONLY the generic stable status. These
 * tests pin the allowed response shape and assert that no internal config
 * flag, error code, wallet/credential detail, or request id can appear in the
 * body — both at the response-builder level and over real HTTP against the
 * running server (spawned with a scrubbed environment, no database).
 */

const LEAK_MARKERS = [
  'DATABASE_URL',
  'SESSION_SECRET',
  'databaseConfigured',
  'sessionConfigured',
  'walletConfigured',
  'wallet',
  'GOOGLE',
  'APPLE',
  'TIGER',
  'credential',
  'MFA',
  'request_id',
  'NOT_CONFIGURED',
];

test('public health status exposes only the generic status value', () => {
  expect(publicHealthStatus(true)).toEqual({ status: 'ready' });
  expect(publicHealthStatus(false)).toEqual({ status: 'not_ready' });
  expect(Object.keys(publicHealthStatus(true)).sort()).toEqual(['status']);
});

test('health response is byte-stable across calls (no request id)', async () => {
  const headers = { 'Access-Control-Allow-Origin': 'null' };
  const a = await publicHealthResponse(true, headers).text();
  const b = await publicHealthResponse(true, headers).text();
  expect(a).toBe(b);
  expect(JSON.parse(a)).toEqual({ status: 'ready' });
  expect(a).not.toContain('request_id');
});

test('health response never exposes config flags, error codes or credential details', async () => {
  for (const ready of [true, false]) {
    const res = publicHealthResponse(ready);
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(res.headers.get('content-type')).toInclude('application/json');
    const raw = await res.text();
    expect(Object.keys(JSON.parse(raw))).toEqual(['status']);
    expect(['ready', 'not_ready']).toContain(JSON.parse(raw).status);
    for (const marker of LEAK_MARKERS) expect(raw).not.toContain(marker);
  }
});

// --- end-to-end: real GET /health on the running server, scrubbed env ---

const children: ChildProcess[] = [];
afterAll(() => {
  for (const c of children) c.kill();
});

/** Kernel-assigned free port (listen(0)) to avoid collisions. */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address() as net.AddressInfo;
      srv.close(() => resolve(port));
    });
  });
}

/**
 * Environment without any database/session/wallet/credential values, so the
 * server boots in NOT_CONFIGURED state and never touches the database. VERCEL
 * is removed too: otherwise the module skips Bun.serve and the probe fails.
 */
function scrubEnv(port: number): Record<string, string> {
  const blocked = new Set([
    'DATABASE_URL', 'TEST_DATABASE_URL', 'SESSION_SECRET', 'MFA_ENCRYPTION_KEY',
    'GOOGLE_ISSUER_ID', 'GOOGLE_SERVICE_ACCOUNT_JSON', 'GOOGLE_SERVICE_ACCOUNT_EMAIL',
    'GOOGLE_PRIVATE_KEY', 'GOOGLE_EXTERNAL_ACCOUNT_JSON', 'GOOGLE_APPLICATION_CREDENTIALS',
    'VERCEL_OIDC_TOKEN', 'APPLE_TEAM_IDENTIFIER', 'APPLE_PASS_TYPE_IDENTIFIER', 'APPLE_PRIVATE_KEY',
    'TIGER_PUBLIC_KEY', 'TIGER_SECRET_KEY', 'TIGER_PROJECT_ID',
    'EMAIL_SMTP_HOST', 'EMAIL_SMTP_PORT', 'EMAIL_SMTP_USER', 'EMAIL_SMTP_PASSWORD', 'EMAIL_FROM',
    'VERCEL', 'PORT', 'PILOT_READY',
  ]);
  const env: Record<string, string> = { PATH: process.env.PATH ?? '/usr/bin:/bin' };
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined && !blocked.has(k)) env[k] = v;
  }
  env.PORT = String(port);
  return env;
}

async function spawnHealthServer(): Promise<{ base: string; child: ChildProcess }> {
  const backendRoot = join(import.meta.dir, '..');
  for (let attempt = 0; attempt < 3; attempt++) {
    const port = await freePort();
    const child = spawn(process.execPath, ['run', 'src/server.ts'], {
      cwd: backendRoot,
      env: scrubEnv(port),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    children.push(child);
    const logs: string[] = [];
    child.stdout?.on('data', (d: Buffer) => logs.push(d.toString()));
    child.stderr?.on('data', (d: Buffer) => logs.push(d.toString()));
    const base = `http://127.0.0.1:${port}`;
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
      if (child.exitCode !== null) {
        if (logs.join('').includes('EADDRINUSE')) break; // retry with a fresh port
        throw new Error(`health server exited early (code ${child.exitCode})\n${logs.join('')}`);
      }
      try {
        const res = await fetch(`${base}/health`, { signal: AbortSignal.timeout(2000) });
        await res.arrayBuffer(); // drain
        return { base, child };
      } catch {
        await Bun.sleep(150);
      }
    }
    if (child.exitCode === null) child.kill();
  }
  throw new Error('could not start health probe server on three ports');
}

test('GET /health over HTTP returns only the generic status, no internal details', async () => {
  const { base, child } = await spawnHealthServer();
  try {
    const res = await fetch(`${base}/health`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toInclude('application/json');
    expect(res.headers.get('cache-control')).toBe('no-store');

    const raw = await res.text();
    expect(raw).toBe('{"status":"not_ready"}'); // scrubbed env → generic status only
    expect(Object.keys(JSON.parse(raw))).toEqual(['status']);

    // Stable across calls: no request id, no counters, no timestamps.
    const raw2 = await (await fetch(`${base}/health`)).text();
    expect(raw2).toBe(raw);

    for (const marker of LEAK_MARKERS) expect(raw).not.toContain(marker);

    // The rest of the API still behaves normally for unconfigured servers.
    const notFound = await fetch(`${base}/api/tenants/x`);
    expect(notFound.status).toBe(400);
  } finally {
    child.kill();
  }
}, 30_000);
