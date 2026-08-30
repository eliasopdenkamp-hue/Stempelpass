import { expect, test } from 'bun:test';
import { GoogleWalletAdapter } from '../src/wallet';

const card = { id: 'card-uuid', stampCount: 4 };
const credentials = {
  mode: 'service-account-json' as const,
  clientEmail: 'wallet@example.invalid',
  description: 'test',
  signBlob: async () => new Uint8Array(),
  getAccessToken: async () => ({ token: 'access-token', expiresAt: Date.now() + 3_600_000 }),
};

test('Google Wallet revoke PATCHes the card object to INACTIVE using issuer.card id', async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(input), init: init ?? {} });
    return new Response('{}', { status: 200 });
  }) as unknown as typeof fetch;
  const adapter = new GoogleWalletAdapter('issuer-123', { sign: async () => 'signature' }, 'wallet@example.invalid', 'service-account-json', undefined, credentials, fetchFn);
  await adapter.revoke(card);
  expect(calls).toHaveLength(1);
  expect(calls[0]?.url).toBe('https://walletobjects.googleapis.com/walletobjects/v1/loyaltyObject/issuer-123.card-uuid');
  expect(calls[0]?.init.method).toBe('PATCH');
  expect(JSON.parse(String(calls[0]?.init.body))).toEqual({ state: 'INACTIVE' });
  expect((calls[0]?.init.headers as Record<string, string>).Authorization).toBe('Bearer access-token');
});

test('Google Wallet revoke treats an already absent object as a successful idempotent retry', async () => {
  const fetchFn = (async () => new Response('missing', { status: 404 })) as unknown as typeof fetch;
  const adapter = new GoogleWalletAdapter('issuer-123', { sign: async () => 'signature' }, 'wallet@example.invalid', 'service-account-json', undefined, credentials, fetchFn);
  await expect(adapter.revoke(card)).resolves.toBeUndefined();
});

test('Google Wallet revoke failures are non-fatal and do not log card ids or tokens', async () => {
  const fetchFn = (async () => { throw new Error('network details with issuer-123.card-uuid and access-token'); }) as unknown as typeof fetch;
  const adapter = new GoogleWalletAdapter('issuer-123', { sign: async () => 'signature' }, 'wallet@example.invalid', 'service-account-json', undefined, credentials, fetchFn);
  const original = console.error;
  const messages: string[] = [];
  console.error = (...args: unknown[]) => messages.push(args.join(' '));
  try { await expect(adapter.revoke(card)).resolves.toBeUndefined(); }
  finally { console.error = original; }
  expect(messages).toEqual(['wallet_revoke_failed code=GOOGLE_WALLET_REVOKE_UNAVAILABLE']);
});
