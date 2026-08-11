/**
 * Vercel serverless adapter. Keep all HTTP behavior in the shared Fetch
 * handler. The Vercel Node runtime does NOT pass a Web-standard `Request` —
 * it invokes the default export with a legacy-shaped request object whose
 * `headers` is a plain object (no `.get()`), `url` is the path+query and the
 * JSON body arrives pre-parsed on `body`. This adapter normalizes that into
 * a real `fetch` Request so the shared handler can rely on the standard API
 * (`req.headers.get(...)`, `new URL(req.url)`, `req.json()`).
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

interface VercelRequestLike {
  method?: string;
  url?: string;
  headers?: Record<string, string | string[] | undefined>;
  body?: unknown;
  rawBody?: unknown;
}

export default async function handler(vercelReq: VercelRequestLike): Promise<Response> {
  const method = (vercelReq.method ?? 'GET').toUpperCase();

  // Vercel passes path+query (e.g. `/health`); the shared handler builds an
  // absolute URL via `new URL(req.url)`, so supply a scheme+host prefix.
  const rawUrl = vercelReq.url ?? '/';
  const url = /^https?:\/\//i.test(rawUrl)
    ? rawUrl
    : `https://${hostOf(vercelReq)}${rawUrl.startsWith('/') ? rawUrl : `/${rawUrl}`}`;

  const headers = new Headers();
  for (const [key, value] of Object.entries(vercelReq.headers ?? {})) {
    if (value === undefined) continue;
    if (Array.isArray(value)) for (const v of value) headers.append(key, v);
    else headers.set(key, value);
  }

  let body: BodyInit | null = null;
  const incoming = vercelReq.body ?? vercelReq.rawBody;
  if (incoming !== undefined && incoming !== null) {
    if (typeof incoming === 'string') body = incoming;
    // `incoming` narrows to Uint8Array<ArrayBufferLike>, which is not assignable
    // to BodyInit (TS 5.7+ typed arrays). The ArrayLike constructor copies into
    // a fresh Uint8Array<ArrayBuffer>, which is BodyInit-compatible and matches
    // the Buffer path below. Buffers subclass Uint8Array, so they land here too.
    else if (incoming instanceof Uint8Array) body = new Uint8Array(incoming);
    else if (typeof Buffer !== 'undefined' && Buffer.isBuffer(incoming)) body = new Uint8Array(incoming);
    else body = JSON.stringify(incoming); // JSON was pre-parsed by the runtime
    // The re-serialized body length may differ from the original header.
    headers.delete('content-length');
  }

  const request = new Request(url, { method, headers, body: body ?? undefined });
  return fetchHandler(request);
}

function hostOf(req: VercelRequestLike): string {
  const host = req.headers?.host;
  return typeof host === 'string' && host.length > 0 ? host : 'localhost';
}
