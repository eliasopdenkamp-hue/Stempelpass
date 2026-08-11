/**
 * Vercel serverless adapter (Node req/res style).
 *
 * The Vercel Node.js runtime invokes the default export with a legacy
 * `(req, res)` signature and IGNORES a returned `Response` ("default export
 * returned a Response" warning, empty reply). This adapter therefore
 * normalizes the legacy request into a real fetch `Request`, keeps all HTTP
 * behavior in the shared `fetchHandler`, and writes the resulting `Response`
 * back through the Node `res` object (`statusCode`, `setHeader`, body chunk /
 * empty end). The handler returns `Promise<void>`, never a `Response`.
 *
 * The legacy request shape: `headers` is a plain object (no `.get()`),
 * `url` is path+query and a JSON body arrives pre-parsed on `body`/`rawBody`.
 */
import { fetchHandler } from '../src/server.js';

/**
 * Vercel function budget (seconds). This is NOT the fix for slow cold starts —
 * the real fix is that migrations no longer run in the request path and the
 * readiness gate fails fast with a classified 503. maxDuration only widens the
 * ceiling so a cold start plus a waking Neon compute has headroom before the
 * platform kills the invocation. 30s is within both Hobby and Pro limits.
 */
export const maxDuration = 30;

/** Minimal structural view of the legacy request Vercel passes. */
interface VercelRequestLike {
  method?: string;
  url?: string;
  headers?: Record<string, string | string[] | undefined>;
  body?: unknown;
  rawBody?: unknown;
}

/**
 * Minimal structural view of the Node `http.ServerResponse` — only the members
 * this adapter needs. Deliberately no @types/express / @types/node dependency:
 * the shape is tiny and Node's real response satisfies it structurally.
 */
interface VercelResponseLike {
  statusCode: number;
  setHeader(name: string, value: string | string[]): unknown;
  end(chunk?: unknown, encoding?: string, callback?: () => void): unknown;
}

/** Build the absolute URL the shared handler expects (`new URL(req.url)`). */
function absoluteUrl(vercelReq: VercelRequestLike): string {
  const rawUrl = vercelReq.url ?? '/';
  if (/^https?:\/\//i.test(rawUrl)) return rawUrl;
  const host = vercelReq.headers?.host;
  const authority = typeof host === 'string' && host.length > 0 ? host : 'localhost';
  return `https://${authority}${rawUrl.startsWith('/') ? rawUrl : `/${rawUrl}`}`;
}

/**
 * Normalize the legacy body. Vercel delivers a string, a raw Buffer/Uint8Array,
 * or a pre-parsed JSON value. The copy via `new Uint8Array(...)` decouples the
 * Request from any pooled Buffer memory the runtime may reuse.
 */
function normalizeBody(vercelReq: VercelRequestLike): BodyInit | null {
  const incoming = vercelReq.body ?? vercelReq.rawBody;
  if (incoming === undefined || incoming === null) return null;
  if (typeof incoming === 'string') return incoming;
  // Buffers subclass Uint8Array, so this branch covers both.
  if (incoming instanceof Uint8Array) return new Uint8Array(incoming) as BodyInit;
  // Pre-parsed JSON: re-serialize. The re-serialized length may differ from the
  // original header, so the caller must drop `content-length`.
  return JSON.stringify(incoming) as string;
}

function toFetchRequest(vercelReq: VercelRequestLike): Request {
  const method = (vercelReq.method ?? 'GET').toUpperCase();
  const headers = new Headers();
  for (const [key, value] of Object.entries(vercelReq.headers ?? {})) {
    if (value === undefined) continue;
    if (Array.isArray(value)) for (const v of value) headers.append(key, v);
    else headers.set(key, value);
  }
  const body = normalizeBody(vercelReq);
  if (body !== null) headers.delete('content-length'); // body may have been re-serialized
  return new Request(absoluteUrl(vercelReq), { method, headers, body: body ?? undefined });
}

/**
 * Collect every Set-Cookie value. The fetch spec keeps them separate;
 * Node's `setHeader` emits one header per array element, so pass an array.
 */
function collectSetCookies(headers: Headers): string[] {
  const withMethod = headers as Headers & { getSetCookie?: () => string[] };
  if (typeof withMethod.getSetCookie === 'function') return withMethod.getSetCookie();
  return [...headers.entries()]
    .filter(([name]) => name.toLowerCase() === 'set-cookie')
    .map(([, value]) => value);
}

/**
 * Write a fetch `Response` onto a Node `http.ServerResponse`. Exported for the
 * DB-free adapter tests; the Vercel entry point only uses the default export.
 */
export async function writeNodeResponse(nodeRes: VercelResponseLike, response: Response): Promise<void> {
  nodeRes.statusCode = response.status;
  const setCookies = collectSetCookies(response.headers);
  for (const [name, value] of response.headers.entries()) {
    if (name.toLowerCase() === 'set-cookie') continue; // handled below (Node joins arrays)
    nodeRes.setHeader(name, value);
  }
  if (setCookies.length === 1) nodeRes.setHeader('set-cookie', setCookies[0]);
  else if (setCookies.length > 1) nodeRes.setHeader('set-cookie', setCookies);
  const body = await response.arrayBuffer();
  if (body.byteLength > 0) nodeRes.end(Buffer.from(body));
  else nodeRes.end();
}

export default async function handler(
  vercelReq: VercelRequestLike,
  nodeRes: VercelResponseLike,
): Promise<void> {
  const response = await fetchHandler(toFetchRequest(vercelReq));
  await writeNodeResponse(nodeRes, response);
}
