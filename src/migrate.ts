/**
 * Migration CLI — the safe, explicit way to apply schema migrations.
 *
 * The Vercel request/cold-start path NEVER runs migrations by default (see the
 * readiness gate in src/server.ts): schema changes are applied out-of-band with
 * this script against the real database, then the deployment is released. This
 * keeps cold starts fast and guarantees a hung or slow database cannot turn
 * requests into platform timeouts.
 *
 *   bun run db:migrate          # reads DATABASE_URL from the environment
 *
 * Behavior:
 *   - Reads the connection string exclusively from DATABASE_URL (never baked
 *     in, never logged). Requires the operator to provide it.
 *   - Applies every pending migration under the transaction-scoped advisory
 *     lock (F3: parallel runners serialize; see src/db.ts runMigrations).
 *   - Exits 0 on success, 1 on any failure (missing DATABASE_URL, connection
 *     failure, SQL error). Error details are sanitized/redacted exactly like
 *     request errors (classifyError) — no URL, password or SQL text is printed.
 *
 * To opt the server into migrations-on-start (not recommended for Vercel;
 * useful for a single long-running Bun process), set RUN_MIGRATIONS_ON_START=1.
 */

import { createPostgresPool, runMigrations, type DbPool } from './db.js';
import { classifyError } from './http-error.js';

/**
 * Testable core: apply pending migrations on an already-created pool.
 * Throws on failure; the caller decides the exit code.
 */
export async function runMigrationsOnPool(pool: DbPool): Promise<void> {
  await runMigrations(pool);
}

/**
 * CLI body. `makePool` is injectable so the DB-free unit tests can script a
 * fake pool; production always uses the real postgres.js pool factory.
 * Returns the process exit code (0 success, 1 failure).
 */
export async function dbMigrate(
  env: NodeJS.ProcessEnv = process.env,
  makePool: (url: string) => DbPool = createPostgresPool,
): Promise<number> {
  const url = env.DATABASE_URL?.trim();
  if (!url) {
    console.error('DATABASE_URL_REQUIRED: set DATABASE_URL to run migrations');
    return 1;
  }
  let pool: DbPool | undefined;
  try {
    pool = makePool(url);
    await runMigrationsOnPool(pool);
    console.log('migrations_applied');
    return 0;
  } catch (error) {
    console.error('migration_failed', classifyError(error).detail ?? 'INTERNAL_ERROR');
    return 1;
  } finally {
    try {
      await pool?.end?.();
    } catch {
      // Best-effort shutdown; the exit code is decided by the migration outcome.
    }
  }
}

if (import.meta.main) {
  process.exit(await dbMigrate());
}
