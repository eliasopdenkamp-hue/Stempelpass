/** Environment configuration. Secrets are read from the process environment only. */
export interface AppConfigStatus {
  databaseConfigured: boolean;
  sessionConfigured: boolean;
  tigerConfigured: boolean;
  ready: boolean;
  error: string | null;
}

/**
 * DATABASE_URL is deliberately the only database connection input. Tiger Cloud's
 * public/secret/project values are project/API credentials, not a PostgreSQL
 * connection string and must never be interpolated into one.
 */
export function configurationStatus(env: NodeJS.ProcessEnv = process.env): AppConfigStatus {
  const databaseConfigured = Boolean(env.DATABASE_URL?.trim());
  const sessionConfigured = Boolean(env.SESSION_SECRET && env.SESSION_SECRET.length >= 32);
  const tigerConfigured = Boolean(env.TIGER_PUBLIC_KEY && env.TIGER_SECRET_KEY && env.TIGER_PROJECT_ID);
  let error: string | null = null;
  if (!databaseConfigured) error = tigerConfigured ? 'DATABASE_URL_REQUIRED_TIGER_CONNECTION_STRING' : 'DATABASE_URL_REQUIRED';
  else if (!env.SESSION_SECRET) error = 'SESSION_SECRET_REQUIRED';
  else if (env.SESSION_SECRET.length < 32) error = 'SESSION_SECRET_TOO_SHORT';
  return { databaseConfigured, sessionConfigured, tigerConfigured, ready: !error, error };
}

export function requireConfiguration(env: NodeJS.ProcessEnv = process.env): void {
  const status = configurationStatus(env);
  if (!status.ready) throw new Error(status.error || 'CONFIGURATION_REQUIRED');
}
