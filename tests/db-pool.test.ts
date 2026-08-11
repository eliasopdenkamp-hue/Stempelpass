import { test, expect } from 'bun:test';
import { initializeReservedConnection } from '../src/db';

test('reserved postgres connections pin search_path before use', async () => {
  const queries: string[] = [];
  await initializeReservedConnection({ unsafe: async (query: string) => { queries.push(query); } });
  expect(queries).toEqual(['SET search_path TO pg_catalog, public']);
  expect(queries[0]).not.toContain('$1');
});
