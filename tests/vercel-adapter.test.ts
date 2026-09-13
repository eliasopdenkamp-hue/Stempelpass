import { test, expect } from 'bun:test';

/**
 * DB-free tests for the Vercel Node req/res adapter (api/index.ts).
 *
 * The adapter must NOT return a Response (Vercel's Node runtime ignores it —
 * "default export returned a Response"); it must write status, headers
 * (including multiple Set-Cookie values) and body/empty-body onto the Node
 * `res` object and resolve to `undefined`. No database and no credentials:
 * the server module is imported with a scrubbed environment (VERCEL=1, no
 * DATABASE_URL), so it boots NOT_CONFIGURED and /health answers without any
 * database access.
 */

// --- boot: scrub every secret/config var BEFORE importing the server module ---
const SCRUBBED_KEYS = [
  'DATABASE_URL', 'TEST_DATABASE_URL', 'SESSION_SECRET', 'MFA_ENCRYPTION_KEY',
  'GOOGLE_ISSUER_ID', 'GOOGLE_SERVICE_ACCOUNT_JSON', 'GOOGLE_SERVICE_ACCOUNT_EMAIL',
  'GOOGLE_PRIVATE_KEY', 'GOOGLE_EXTERNAL_ACCOUNT_JSON', 'GOOGLE_APPLICATION_CREDENTIALS',
  'VERCEL_OIDC_TOKEN', 'APPLE_TEAM_IDENTIFIER', 'APPLE_PASS_TYPE_IDENTIFIER', 'APPLE_PRIVATE_KEY',
  'TIGER_PUBLIC_KEY', 'TIGER_SECRET_KEY', 'TIGER_PROJECT_ID',
  'EMAIL_SMTP_HOST', 'EMAIL_SMTP_PORT', 'EMAIL_SMTP_USER', 'EMAIL_SMTP_PASSWORD', 'EMAIL_FROM',
  'COMMUNICATION_HASH_SECRET', 'PORT', 'PILOT_READY',
];
for (const key of SCRUBBED_KEYS) delete process.env[key];
process.env.VERCEL = '1';

interface AdapterModule {
  default: (req: unknown, res: unknown) => Promise<void>;
  writeNodeResponse: (res: unknown, response: Response) => Promise<void>;
  toFetchRequest: (req: Record<string, unknown>) => Request;
}
const adapter = (await import('../api/index')) as AdapterModule;

/** Fake Node `http.ServerResponse`: records status/headers/body instead of sending. */
class FakeNodeResponse {
  statusCode = 200;
  headers: Array<[string, string | string[]]> = [];
  ended = false;
  chunks: Buffer[] = [];
  endCallCount = 0;

  setHeader(name: string, value: string | string[]): void {
    this.headers.push([name, value]);
  }

  end(chunk?: unknown): void {
    this.endCallCount += 1;
    this.ended = true;
    if (chunk !== undefined && chunk !== null) {
      this.chunks.push(chunk instanceof Uint8Array ? Buffer.from(chunk) : Buffer.from(String(chunk)));
    }
  }

  header(name: string): string | string[] | undefined {
    const entry = this.headers.find(([n]) => n.toLowerCase() === name.toLowerCase());
    return entry?.[1];
  }

  bodyText(): string {
    return Buffer.concat(this.chunks).toString('utf8');
  }
}

function vercelGetRequest(url = '/health'): Record<string, unknown> {
  return { method: 'GET', url, headers: { host: 'stempelpass.example', 'x-forwarded-proto': 'https' } };
}

test('default export resolves to undefined (never returns a Response)', async () => {
  const res = new FakeNodeResponse();
  const result = await adapter.default(vercelGetRequest(), res);
  expect(result).toBeUndefined();
});

test('GET /health is written to the Node res: 200, JSON headers and body', async () => {
  const res = new FakeNodeResponse();
  await adapter.default(vercelGetRequest('/health'), res);
  expect(res.ended).toBe(true);
  expect(res.statusCode).toBe(200);
  expect(res.header('content-type')).toContain('application/json');
  expect(res.header('cache-control')).toBe('no-store');
  const body = JSON.parse(res.bodyText());
  expect(body.status).toBe('not_ready'); // scrubbed env -> NOT_CONFIGURED boot
});

test('unknown route yields 404 NOT_FOUND through the Node res', async () => {
  const res = new FakeNodeResponse();
  await adapter.default(vercelGetRequest('/nope'), res);
  expect(res.statusCode).toBe(404);
  const body = JSON.parse(res.bodyText());
  // Error envelope: { request_id, data: { error } }
  expect(body.data.error).toBe('NOT_FOUND');
});

test('writeNodeResponse maps status, headers and text body onto the Node res', async () => {
  const res = new FakeNodeResponse();
  const response = new Response('hello', {
    status: 201,
    headers: { 'content-type': 'text/plain', 'x-request-id': 'abc' },
  });
  await adapter.writeNodeResponse(res, response);
  expect(res.statusCode).toBe(201);
  expect(res.header('content-type')).toBe('text/plain');
  expect(res.header('x-request-id')).toBe('abc');
  expect(res.bodyText()).toBe('hello');
  expect(res.endCallCount).toBe(1);
});

test('writeNodeResponse handles an empty body (204 no content)', async () => {
  const res = new FakeNodeResponse();
  await adapter.writeNodeResponse(res, new Response(null, { status: 204 }));
  expect(res.statusCode).toBe(204);
  expect(res.chunks.length).toBe(0);
  expect(res.endCallCount).toBe(1);
});

test('writeNodeResponse preserves multiple Set-Cookie values as an array', async () => {
  const res = new FakeNodeResponse();
  const headers = new Headers();
  headers.append('set-cookie', 'a=1; Path=/; HttpOnly');
  headers.append('set-cookie', 'b=2; Path=/; Secure');
  headers.append('vary', 'Origin');
  const response = new Response(null, { status: 200, headers });
  await adapter.writeNodeResponse(res, response);
  // Node emits one Set-Cookie header per array element — the adapter must pass
  // the array through, not a comma-joined string.
  expect(res.header('set-cookie')).toEqual(['a=1; Path=/; HttpOnly', 'b=2; Path=/; Secure']);
  expect(res.header('vary')).toBe('Origin');
});

test('writeNodeResponse passes a single Set-Cookie as a plain string', async () => {
  const res = new FakeNodeResponse();
  const response = new Response(null, {
    status: 200,
    headers: { 'set-cookie': '__Host-sp_session=x; HttpOnly; Secure; Path=/' },
  });
  await adapter.writeNodeResponse(res, response);
  expect(res.header('set-cookie')).toBe('__Host-sp_session=x; HttpOnly; Secure; Path=/');
});
// ---------------------------------------------------------------------------
// toFetchRequest body normalization (Vercel form-POST quirk)
//
// The Vercel Node runtime delivers the legacy request with BOTH a
// content-type-specific parse on `body` and the untouched wire bytes on
// `rawBody`. `body` wins in the current adapter, so a urlencoded request
// whose bridge-parsed body is an OBJECT gets re-serialized to JSON while the
// ORIGINAL `content-type: application/x-www-form-urlencoded` header stays in
// place — the shared parseBody then reads JSON text through its form branch
// and yields an empty record (the live 400 CARD_FIELDS_REQUIRED on staff
// stamp, while JSON requests keep working). These tests pin that the RAW
// bytes always take precedence so the wire format survives into the fetch
// Request unchanged.
// ---------------------------------------------------------------------------
const URLENCODED = 'cardId=66666666-6666-4666-8666-666666666666&quantity=1';
function vercelFormPost(body: unknown, rawBody?: unknown): Record<string, unknown> {
  return {
    method: 'POST',
    url: '/staff/11111111-1111-4111-8111-111111111111/stamp',
    headers: {
      host: 'stempelpass.example',
      'x-forwarded-proto': 'https',
      'content-type': 'application/x-www-form-urlencoded',
      'content-length': '17',
    },
    body,
    ...(rawBody === undefined ? {} : { rawBody }),
  };
}
test('toFetchRequest: raw urlencoded bytes win over the bridge-parsed object (Vercel form-POST quirk)', async () => {
  const req = adapter.toFetchRequest(vercelFormPost(
    { cardId: '66666666-6666-4666-8666-666666666666', quantity: '1' }, // bridge parse (object)
    Buffer.from(URLENCODED, 'utf8'),                                    // untouched wire bytes
  ));
  expect(await req.text()).toBe(URLENCODED);
  expect(req.headers.get('content-type')).toBe('application/x-www-form-urlencoded');
  // The body was re-formulated from bytes → the stale header must not survive.
  expect(req.headers.get('content-length')).toBeNull();
});
test('toFetchRequest: urlencoded string body without rawBody passes through unchanged', async () => {
  const req = adapter.toFetchRequest(vercelFormPost(URLENCODED));
  expect(await req.text()).toBe(URLENCODED);
});
test('toFetchRequest: JSON request stays parseable when the bridge set both body and rawBody', async () => {
  const req = adapter.toFetchRequest({
    method: 'POST',
    url: '/api/auth/login',
    headers: { host: 'stempelpass.example', 'x-forwarded-proto': 'https', 'content-type': 'application/json' },
    body: { email: 'a@b.de', password: 'secret' },
    rawBody: Buffer.from('{"email":"a@b.de","password":"secret"}', 'utf8'),
  });
  expect(await req.json()).toEqual({ email: 'a@b.de', password: 'secret' });
  expect(req.headers.get('content-length')).toBeNull();
});
test('toFetchRequest: body-less request stays body-less', async () => {
  const req = adapter.toFetchRequest({ method: 'GET', url: '/health', headers: { host: 'stempelpass.example' } });
  expect(await req.text()).toBe('');
});
