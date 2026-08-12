/**
 * HTTP error mapping. Only stable, controlled domain error codes are ever
 * surfaced to clients; anything else (DB errors, unexpected exceptions) maps to
 * INTERNAL_ERROR plus the request_id. Unexpected error details are only logged
 * server-side (sanitized) and never echoed into the response body.
 *
 * Login anti-enumeration: the login route deliberately maps every credential /
 * MFA failure (INVALID_CREDENTIALS, MFA_NOT_CONFIGURED, MFA_INVALID,
 * MFA_SECRET_DECRYPT_FAILED) to the single external code INVALID_CREDENTIALS
 * before it reaches classifyError. The MFA codes remain allowlisted here purely
 * as defense in depth for any future route that forgets that mapping.
 */

/** Stable domain error codes that may be returned to clients as-is. */
export const DOMAIN_ERROR_CODES: ReadonlySet<string> = new Set([
  'ACCESS_TOKEN_NOT_SUPPORTED_IN_FALLBACK_MODE',
  'CARD_FIELDS_REQUIRED',
  'CARD_NOT_FOUND',
  'COMMUNICATION_CONTEXT_REQUIRED',
  'CONFIGURATION_REQUIRED',
  'CREDENTIALS_REQUIRED',
  'CSRF_INVALID',
  'CUSTOMER_LIMIT_REACHED',
  'CUSTOMER_NOT_FOUND',
  'DATABASE_REQUIRED',
  'DATABASE_UNAVAILABLE',
  'DATABASE_URL_REQUIRED',
  'ENTRY_POINT_NOT_CONFIGURED',
  'ENTRY_POINT_NOT_FOUND',
  'FALLBACK_KEY_UNAVAILABLE',
  'FORBIDDEN',
  'GCP_IMPERSONATION_NO_TOKEN',
  'GCP_IMPERSONATION_URL_REQUIRED',
  'GCP_SIGNBLOB_NO_RESULT',
  'GCP_STS_NO_TOKEN',
  'INVALID_CREDENTIALS',
  'INVALID_PILOT_CONFIGURATION',
  'INVALID_STAFF',
  'INVALID_STAMP_QUANTITY',
  'MEMBERSHIP_NOT_FOUND',
  'MFA_ENCRYPTION_KEY_INVALID',
  'MFA_ENCRYPTION_KEY_REQUIRED',
  'MFA_INVALID',
  'MFA_NOT_CONFIGURED',
  'MFA_REQUIRED',
  'MFA_SECRET_DECRYPT_FAILED',
  'MFA_BOOTSTRAP_UNVERIFIED',
  'NOT_FOUND',
  'OIDC_TOKEN_MISSING',
  'PASSWORD_TOO_SHORT',
  'PLAN_LIMIT_BELOW_USAGE',
  'RATE_LIMITED',
  'REWARD_ALREADY_REDEEMED',
  'REWARD_NOT_FOUND',
  'RULE_NOT_FOUND',
  'SESSION_SECRET_TOO_SHORT',
  'TENANT_CONTEXT_REQUIRED',
  'TENANT_NOT_FOUND',
  'UNAUTHENTICATED',
]);

/** HTTP status for a known domain error code. */
export function errorStatus(code: string): number {
  if (code.includes('NOT_FOUND')) return 404;
  if (code === 'CUSTOMER_LIMIT_REACHED' || code === 'REWARD_ALREADY_REDEEMED') return 409;
  if (code === 'DATABASE_UNAVAILABLE') return 503;
  if (code === 'TENANT_CONTEXT_REQUIRED' || code === 'FORBIDDEN') return 403;
  if (code === 'UNAUTHENTICATED') return 401;
  if (code === 'RATE_LIMITED') return 429;
  // CSRF failures are a client-authentication problem, not a malformed
  // request: 403 Forbidden (semantically correct vs. the previous 400).
  if (code === 'CSRF_INVALID') return 403;
  return 400;
}

export interface ErrorClassification {
  /** Code to expose to the client (INTERNAL_ERROR for anything unexpected). */
  code: string;
  status: number;
  /** Sanitized detail for server-side logging; null when the code is a known domain error. */
  detail: string | null;
}

/** Maximum length of a logged error detail; details are never echoed to clients. */
const MAX_DETAIL_LENGTH = 300;
/**
 * Stable JS error classes that may appear verbatim in logs. Class names carry
 * no message content, but database-driver/provider classes (e.g.
 * PostgresError) and any application-specific class names are deliberately
 * collapsed to UnknownError so no provider or internal detail leaks.
 */
const STABLE_ERROR_CLASSES: ReadonlySet<string> = new Set([
  'Error', 'TypeError', 'RangeError', 'SyntaxError', 'ReferenceError',
  'URIError', 'EvalError', 'AggregateError',
]);
const REDACTED = '<redacted>';
/**
 * Redact PII/secrets from an error message before it reaches the server log.
 * Order matters: URLs/DSNs first, then key=value credentials, then opaque
 * tokens. Anything recognized is replaced by <redacted>; the surrounding
 * wording stays readable for operations.
 */
function redactDetail(value: string): string {
  let out = value
    // Connection strings / URLs with optional credentials: postgres://u:p@h/db
    .replace(/\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+/gi, REDACTED)
    // Authorization headers (value may contain spaces): Authorization: Bearer x
    .replace(/\bauthorization\s*[:=]\s*[^\s,;]+(?:\s+[^\s,;]+)*/gi, REDACTED)
    // Key=value / key: value credentials (case-insensitive, incl. compound
    // names like session_token / client_secret / database_url).
    .replace(/\b(password|passwd|pwd|secret|client[_-]?secret|token|session[_-]?token|refresh[_-]?token|access[_-]?token|auth[_-]?token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?|user(?:name)?|host|dsn|connection[_-]?string|database[_-]?url)\s*[:=]\s*[^\s,;]+/gi, '$1=' + REDACTED)
    // E-mail addresses.
    .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, REDACTED)
    // UUIDs.
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, REDACTED)
    // IPv4 addresses.
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, REDACTED)
    // Long opaque tokens (hashes, keys, JWTs segments, constraint names).
    .replace(/\b[A-Za-z0-9+/_-]{24,}\b/g, REDACTED);
  return out.replace(/\s+/g, ' ').trim();
}
/**
 * Build a sanitized server-side detail for an unexpected error. Only the
 * stable class name (from the allowlist above) and a redacted, truncated
 * message are logged — never a raw Error.message, DSN, credential or
 * database-provider detail. This value is never echoed to clients.
 */
function sanitizeDetail(e: unknown): string {
  const raw = e instanceof Error ? e.message : String(e);
  const redacted = redactDetail(raw);
  if (!redacted) return 'UnknownError';
  const name = e instanceof Error && STABLE_ERROR_CLASSES.has(e.name) ? e.name : 'UnknownError';
  return `${name}: ${redacted}`.slice(0, MAX_DETAIL_LENGTH);
}

/**
 * Classify an arbitrary thrown value. Known domain errors keep their stable
 * code and status; everything else (DB failures, unexpected exceptions) maps
 * to INTERNAL_ERROR/500 so no internal message reaches the client.
 */
export function classifyError(e: unknown): ErrorClassification {
  if (e instanceof Error && DOMAIN_ERROR_CODES.has(e.message)) {
    const code = e.message;
    return { code, status: errorStatus(code), detail: null };
  }
  return { code: 'INTERNAL_ERROR', status: 500, detail: sanitizeDetail(e) };
}
