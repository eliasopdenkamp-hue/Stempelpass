/**
 * Public liveness/readiness endpoint (GET /health).
 *
 * Security P2: the response is deliberately generic. It exposes exactly one
 * stable field (`status`) and never internal configuration details — no
 * database/session configuration flags, no wallet credential modes, no
 * configuration error codes (e.g. `SESSION_SECRET_TOO_SHORT`), and no request
 * id. Monitoring should alert on the `status` field; internal diagnostics stay
 * in the server logs (startup `migration_failed` / `request_failed` lines).
 */

export type HealthStatus = 'ready' | 'not_ready';

export interface PublicHealthResponse {
  status: HealthStatus;
}

/** Maps internal readiness state to the single public status value. */
export function publicHealthStatus(ready: boolean): PublicHealthResponse {
  return { status: ready ? 'ready' : 'not_ready' };
}

/**
 * Stable response for monitoring: always HTTP 200 (liveness — the process is
 * up and answering) with a byte-constant body per readiness state (no request
 * id). `headers` are merged last so callers can add CORS/Vary without
 * overriding the no-store cache policy.
 */
export function publicHealthResponse(ready: boolean, headers: HeadersInit = {}): Response {
  return Response.json(publicHealthStatus(ready), {
    status: 200,
    headers: { 'Cache-Control': 'no-store', ...headers },
  });
}
