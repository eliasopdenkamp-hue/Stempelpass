import { describe, expect, test } from 'bun:test';
import { configurationStatus } from '../src/config';

describe('configuration status', () => {
  test('requires DATABASE_URL even when Tiger project credentials exist', () => {
    const status = configurationStatus({ TIGER_PUBLIC_KEY: 'public', TIGER_SECRET_KEY: 'secret', TIGER_PROJECT_ID: 'project', SESSION_SECRET: '12345678901234567890123456789012' });
    expect(status.tigerConfigured).toBe(true);
    expect(status.databaseConfigured).toBe(false);
    expect(status.error).toBe('DATABASE_URL_REQUIRED_TIGER_CONNECTION_STRING');
    expect(status.ready).toBe(false);
  });

  test('accepts DATABASE_URL as the primary connection input', () => {
    const status = configurationStatus({ DATABASE_URL: 'postgres://user:pass@host/db?sslmode=require', SESSION_SECRET: '12345678901234567890123456789012' });
    expect(status.databaseConfigured).toBe(true);
    expect(status.ready).toBe(true);
  });
});
