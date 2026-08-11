/**
 * Migration-off-by-default + bounded-readiness tests — no database, no Neon.
 *
 * Pins the Vercel-504 fix in src/server.ts:
 *   1. DEFAULT: migrations never run in the request/cold-start path. A server
 *      booted with DATABASE_URL (but WITHOUT RUN_MIGRATIONS_ON_START) must not
 *      attempt a migration at all: /health is `ready` immediately and
 *      DB-backed routes fail fast with a classified error (no hang, no 504).
 *   2. OPT-IN: with RUN_MIGRATIONS_ON_START=1 the migration runs in the
 *      background, and requests wait at most DB_READINESS_TIMEOUT_MS before
 *      getting a classified DATABASE_UNAVAILABLE (503). A hung database (a
 *      black-hole TCP server that accepts but never answers the PostgreSQL
 *      handshake) must produce a fast 503, never an infinite hang.
 *   3. The new migration CLI (src/migrate.ts, `bun run db:migrate`) exits
 *      nonzero on failure and never prints the connection URL.
 *
 * The server subprocess tests use unreachable/black-hole databases only —
 * nothing is ever migrated against a real PostgreSQL instance.
 */

import { test, expect, afterAll } from 'bun:test';
import { spawn, type ChildProcess } from 'node:child_process';
import net from 'node:net';
import { join } from 'node:path';
import { dbMigrate, runMigrationsOnPool } from '../src/migrate';
import type { DbPool } from '../src/db';

const BACKEND_ROOT = join(import.meta.dir, '..');
const children: ChildProcess[] = [];
const servers: net.Server[] = [];

/** configurationStatus() requires DATABASE_URL + SESSION_SECRET (>= 32 chars) for `ready`. */
const CONFIGURED_ENV = { SESSION_SECRET: 'test-session-secret-0123456789abcdef' };

afterAll(() => {
  for (const c of children) c.kill();
  for (const s of servers) s.close();
});

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

/** Environment without any real secret/credential values. */
const BLOCKED_ENV = new Set([
  'DATABASE_URL', 'TEST_DATABASE_URL', 'SESSION_SECRET', 'MFA_ENCRYPTION_KEY',
  'GOOGLE_ISSUER_ID', 'GOOGLE_SERVICE_ACCOUNT_JSON', 'GOOGLE_SERVICE_ACCOUNT_EMAIL',
  'GOOGLE_PRIVATE_KEY', 'GOOGLE_EXTERNAL_ACCOUNT_JSON', 'GOOGLE_APPLICATION_CREDENTIALS',
  'VERCEL_OIDC_TOKEN', 'APPLE_TEAM_IDENTIFIER', 'APPLE_PASS_TYPE_IDENTIFIER', 'APPLE_PRIVATE_KEY',
  'TIGER_PUBLIC_KEY', 'TIGER_SECRET_KEY', 'TIGER_PROJECT_ID',
  'EMAIL_SMTP_HOST', 'EMAIL_SMTP_PORT', 'EMAIL_SMTP_USER', 'EMAIL_SMTP_PASSWORD', 'EMAIL_FROM',
  'COMMUNICATION_HASH_SECRET', 'VERCEL', 'PORT', 'RUN_MIGRATIONS_ON_START', 'DB_READINESS_TIMEOUT_MS',
]);

function baseEnv(): Record<string, string> {
  const env: Record<string, string> = { PATH: process.env.PATH ?? '/usr/bin:/bin' };
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined && !BLOCKED_ENV.has(k)) env[k] = v;
  }
  return env;
}

/** Wait for the server to answer ANY response on /health, then return base+logs. */
async function spawnServer(env: Record<string, string>): Promise<{ base: string; child: ChildProcess; logs: () => string }> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const port = await freePort();
    const child = spawn(process.execPath, ['run', 'src/server.ts'], {
      cwd: BACKEND_ROOT,
      env: { ...baseEnv(), ...env, PORT: String(port) },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    children.push(child);
    const logLines: string[] = [];
    child.stdout?.on('data', (d: Buffer) => logLines.push(d.toString()));
    child.stderr?.on('data', (d: Buffer) => logLines.push(d.toString()));
    const base = `http://127.0.0.1:${port}`;
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
      if (child.exitCode !== null) {
        if (logLines.join('').includes('EADDRINUSE')) break; // retry with a fresh port
        throw new Error(`server exited early (code ${child.exitCode})\n${logLines.join('')}`);
      }
      try {
        const res = await fetch(`${base}/health`, { signal: AbortSignal.timeout(2000) });
        await res.arrayBuffer(); // drain
        return { base, child, logs: () => logLines.join('') };
      } catch {
        await Bun.sleep(150);
      }
    }
    if (child.exitCode === null) child.kill();
  }
  throw new Error('could not start server on three ports');
}

/** Run `bun run src/migrate.ts` with the given env additions; returns exit code + output. */
async function runMigrateCli(extra: Record<string, string>): Promise<{ code: number | null; output: string }> {
  const child = spawn(process.execPath, ['run', 'src/migrate.ts'], {
    cwd: BACKEND_ROOT,
    env: { ...baseEnv(), ...extra },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.push(child);
  let output = '';
  child.stdout?.on('data', (d: Buffer) => (output += d.toString()));
  child.stderr?.on('data', (d: Buffer) => (output += d.toString()));
  const code: number | null = await new Promise(resolve => {
    const timer = setTimeout(() => {
      child.kill();
      resolve(child.exitCode);
    }, 10_000);
    child.on('exit', c => {
      clearTimeout(timer);
      resolve(c);
    });
  });
  return { code, output };
}

// ---------------------------------------------------------------------------
// (1) Default: migrations are OFF the request/cold-start path
// ---------------------------------------------------------------------------

test('default: no RUN_MIGRATIONS_ON_START → no migration attempt, /health ready, DB errors classified fast', async () => {
  const dbPort = await freePort(); // nothing listens → connection refused, immediate
  const { base, child, logs } = await spawnServer({
    ...CONFIGURED_ENV,
    DATABASE_URL: `postgres://user:pass@127.0.0.1:${dbPort}/db?sslmode=require`,
  });
  try {
    // Boot is healthy even though the database is unreachable: the request path
    // no longer depends on schema DDL, so no migration was started.
    const health = await (await fetch(`${base}/health`)).text();
    expect(health).toBe('{"status":"ready"}');

    // A route that touches the database fails fast with a classified
    // INTERNAL_ERROR (connection refused) — no readiness gate hang, no 504.
    const started = Date.now();
    const res = await fetch(`${base}/join/${'a'.repeat(32)}`);
    const body = await res.text();
    expect(Date.now() - started).toBeLessThan(3_000);
    expect(res.status).toBe(500);
    expect(JSON.parse(body).data.error).toBe('INTERNAL_ERROR');

    // And an auth route answers immediately without any DB round trip.
    const authRes = await fetch(`${base}/api/tenants/11111111-1111-4111-8111-111111111111`);
    expect(authRes.status).toBe(401);

    // Crucially: the unreachable database produced NO migration_failed log —
    // the migration runner was never invoked on the request path.
    expect(logs()).not.toContain('migration_failed');
  } finally {
    child.kill();
  }
}, 20_000);

// ---------------------------------------------------------------------------
// (2) Opt-in RUN_MIGRATIONS_ON_START=1
// ---------------------------------------------------------------------------

test('opt-in with unreachable DB → /health honestly not_ready, requests get 503 DATABASE_UNAVAILABLE fast', async () => {
  const dbPort = await freePort(); // connection refused → migration fails fast
  const { base, child, logs } = await spawnServer({
    ...CONFIGURED_ENV,
    DATABASE_URL: `postgres://user:pass@127.0.0.1:${dbPort}/db?sslmode=require`,
    RUN_MIGRATIONS_ON_START: '1',
    DB_READINESS_TIMEOUT_MS: '500',
  });
  try {
    // The background migration failed → readiness is honestly not_ready.
    expect(await (await fetch(`${base}/health`)).text()).toBe('{"status":"not_ready"}');

    // Requests fail fast with the classified 503 — never a hang.
    const started = Date.now();
    const res = await fetch(`${base}/api/tenants/11111111-1111-4111-8111-111111111111`);
    const body = await res.text();
    expect(Date.now() - started).toBeLessThan(3_000);
    expect(res.status).toBe(503);
    expect(JSON.parse(body).data.error).toBe('DATABASE_UNAVAILABLE');
    expect(logs()).toContain('migration_failed');
  } finally {
    child.kill();
  }
}, 20_000);

test('opt-in with a hung DB → bounded readiness timeout yields 503, never an infinite hang', async () => {
  // Black-hole TCP server: accepts connections but never answers the PostgreSQL
  // handshake, so a naive migration wait would block forever.
  const blackhole = net.createServer(socket => socket.on('error', () => {}));
  servers.push(blackhole);
  await new Promise<void>((resolve, reject) => blackhole.listen(0, '127.0.0.1', () => resolve()));
  const dbPort = (blackhole.address() as net.AddressInfo).port;

  const { base, child } = await spawnServer({
    ...CONFIGURED_ENV,
    DATABASE_URL: `postgres://user:pass@127.0.0.1:${dbPort}/db`,
    RUN_MIGRATIONS_ON_START: '1',
    DB_READINESS_TIMEOUT_MS: '400',
  });
  try {
    // Migration is still pending (hung) → honest not_ready.
    expect(await (await fetch(`${base}/health`)).text()).toBe('{"status":"not_ready"}');

    // The request waits for the bounded window, then fails with 503. Without
    // the hard timeout this fetch would hang past the platform invocation cap.
    const started = Date.now();
    const res = await fetch(`${base}/api/tenants/11111111-1111-4111-8111-111111111111`);
    const body = await res.text();
    const elapsed = Date.now() - started;
    expect(elapsed).toBeGreaterThanOrEqual(300); // it did wait for the readiness window
    expect(elapsed).toBeLessThan(5_000);         // ...but the cap enforced it
    expect(res.status).toBe(503);
    expect(JSON.parse(body).data.error).toBe('DATABASE_UNAVAILABLE');
  } finally {
    child.kill();
  }
}, 20_000);

// ---------------------------------------------------------------------------
// (3) Migration CLI (src/migrate.ts / `bun run db:migrate`)
// ---------------------------------------------------------------------------

/** Scripted in-memory pool that "applies" every pending migration body. */
function fakeApplyingPool(): { pool: DbPool; applied: string[] } {
  const versions = new Set<string>();
  const applied: string[] = [];
  const pool: DbPool = {
    connect: async () => ({
      query: async <T = unknown>(sql: string, params: unknown[] = []): Promise<{ rows: T[] }> => {
        const norm = sql.trim().replace(/\s+/g, ' ').toLowerCase();
        if (norm.startsWith('select version from schema_migrations where version=$1')) {
          return { rows: (versions.has(String(params[0])) ? [{ version: params[0] }] : []) as T[] };
        }
        if (norm.startsWith('insert into schema_migrations(version) values($1) on conflict (version) do nothing')) {
          versions.add(String(params[0]));
          return { rows: [] as T[] };
        }
        if (norm === 'begin' || norm === 'commit' || norm === 'rollback'
          || norm.startsWith('create table if not exists schema_migrations')
          || norm === 'select pg_advisory_xact_lock($1)') {
          return { rows: [] as T[] };
        }
        applied.push(sql);
        return { rows: [] as T[] };
      },
      release() {},
    }),
    end: async () => {},
  };
  return { pool, applied };
}

test('dbMigrate: missing DATABASE_URL exits 1 and never constructs a pool', async () => {
  const code = await dbMigrate({}, () => {
    throw new Error('POOL_MUST_NOT_BE_CREATED');
  });
  expect(code).toBe(1);
});

test('dbMigrate: applies all pending migrations via the pool and exits 0', async () => {
  const { pool, applied } = fakeApplyingPool();
  const code = await dbMigrate({ DATABASE_URL: 'postgres://user:pass@example.invalid/db' }, () => pool);
  expect(code).toBe(0);
  // The real migrations directory holds exactly 001–010; all applied once.
  expect(applied.length).toBe(10);
});

test('runMigrationsOnPool: rejects when the pool fails (caller maps to exit 1)', async () => {
  const pool: DbPool = {
    connect: async () => {
      throw new Error('connection refused');
    },
    end: async () => {},
  };
  await expect(runMigrationsOnPool(pool)).rejects.toThrow();
});

test('dbMigrate: failure exits 1 and the URL/credentials never reach the output', async () => {
  const original = console.error;
  const logs: string[] = [];
  console.error = (...args: unknown[]) => logs.push(args.map(String).join(' '));
  try {
    const pool: DbPool = {
      connect: async () => {
        throw new Error('connection refused');
      },
      end: async () => {},
    };
    const code = await dbMigrate(
      { DATABASE_URL: 'postgres://admin:sekret-password@db.internal.example:5432/stempel?sslmode=require' },
      () => pool,
    );
    expect(code).toBe(1);
  } finally {
    console.error = original;
  }
  const output = logs.join('\n');
  expect(output).toContain('migration_failed');
  expect(output).not.toContain('sekret-password');
  expect(output).not.toContain('db.internal.example');
  expect(output).not.toContain('admin:');
});

test('db:migrate CLI subprocess: missing DATABASE_URL exits 1 with DATABASE_URL_REQUIRED', async () => {
  const { code, output } = await runMigrateCli({});
  expect(code).toBe(1);
  expect(output).toContain('DATABASE_URL_REQUIRED');
});

test('db:migrate CLI subprocess: unreachable DB exits 1 and never echoes the URL', async () => {
  const dbPort = await freePort(); // nothing listens → connection refused, immediate
  const { code, output } = await runMigrateCli({
    DATABASE_URL: `postgres://user:sekret-pass@127.0.0.1:${dbPort}/db?sslmode=require`,
  });
  expect(code).toBe(1);
  expect(output).toContain('migration_failed');
  expect(output).not.toContain('sekret-pass');
  expect(output).not.toContain('127.0.0.1');
});
