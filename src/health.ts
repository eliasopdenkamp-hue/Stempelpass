/**
 * Public liveness/readiness endpoint (GET /health).
 *
 * Always HTTP 200 while the function is up and answering — that is the
 * liveness signal ("function erreichbar"). The single `status` field is the
 * honest readiness signal: `ready` only when configuration is complete, no
 * initialization error occurred, the opt-in background migration (if
 * RUN_MIGRATIONS_ON_START=1) has finished, AND the operator declared the
 * schema/pilot steps done by setting PILOT_READY=1 (see src/server.ts).
 * Without that declaration the function is reachable but honestly reports
 * `not_ready`. GET /health NEVER queries the database: the out-of-band steps
 * (`bun run db:migrate`, app role, `bun run rls-verify`) cannot be verified
 * without a blocking query, so readiness is an operator declaration, not a
 * runtime probe.
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
