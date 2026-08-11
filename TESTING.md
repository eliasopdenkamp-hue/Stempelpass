# Backend tests

## Public health endpoint (`GET /health`)

Security P2 contract — the response is deliberately generic and is the **only**
request-id-free, byte-stable endpoint:

```json
{ "status": "ready" }
```

Always HTTP 200 while the process is up (liveness). The `status` field is the
readiness signal: `ready` when configuration is complete and the database path
is usable (migrations are NOT part of the request path by default — schema is
applied out-of-band via `bun run db:migrate`; with the opt-in
`RUN_MIGRATIONS_ON_START=1`, readiness additionally requires the background
migration to have succeeded), `not_ready` otherwise. Monitoring should
alert on the `status` field, never on response body details — there are none:
no database/session configuration flags, no wallet credential modes, no
configuration error codes (`DATABASE_URL_REQUIRED`, `SESSION_SECRET_TOO_SHORT`,
…), and no request id are exposed here.

Internal diagnostics for operators live in the server logs, not in the public
response: the startup line reports `POSTGRES`/`NOT_CONFIGURED`, an opt-in
migration failure logs `migration_failed`, and per-request failures log
`request_failed request_id=…` with the sanitized reason. Correlation works via
the request_id that other (non-/health) responses still carry. If productive
readiness monitoring needs richer internal state later, add a separate
internal/diagnostic path that is not publicly reachable — do not extend the
public `/health` body.

`tests/health.test.ts` pins the allowed response shape (unit level) and probes
the real endpoint over HTTP with a scrubbed environment (no database) to prove
no internal details leak.

## Running the suite

`bun test` always runs unit/domain tests. The database integration harness in `tests/db.integration.test.ts` is **skipped unless `TEST_DATABASE_URL` is explicitly set**. It never reads or falls back to `DATABASE_URL`; it also refuses an identical value. The harness creates a unique temporary PostgreSQL schema and drops it in `finally`, so no production/test data is retained. No real users, credentials, or secrets are created by the test suite.

To opt in against a disposable database only:

```sh
TEST_DATABASE_URL='postgresql://.../disposable_test?sslmode=require' bun test tests/db.integration.test.ts
```

The integration test runs tenant-isolation, atomic capacity limits, idempotent stamping, reward redemption/double-redeem, session revocation, and MFA-column checks in one temporary schema. It applies all migrations there and drops the schema in `finally`; it must not be run against `DATABASE_URL`. Production MFA additionally requires a 32-byte `MFA_ENCRYPTION_KEY` (hex or base64) in the deployment secret manager; the test suite does not invent or persist this secret.

## Login security tests

`tests/login-security.test.ts` covers the P1 login fixes without a database:
account-key normalization/hashing (no raw email in keys), `clientIpKey` fallback
behavior (shared `unknown` bucket for missing/malformed headers), the unified
login-failure reason mapping (all credential/MFA failures collapse to
`INVALID_CREDENTIALS`), the dummy-verification timing equalizer, and the
`RateLimiter` key-cap/eviction bound. See `RATE_LIMITING.md` for the design and
the per-instance caveat for distributed deployments.

## HTTP contract tests
`tests/http-contract.test.ts` drives the real `fetchHandler` in-process against
a scripted in-memory `DbPool` (no database, no credentials — never touches the
Neon `TEST_DATABASE_URL`). It pins the wire contracts end to end:

- `GET /health` → only `{"status":...}`, no request id/config details.
- `GET /join/:publicKey` → RLS-safe resolution: exactly
  `{tenantId, joinPath, customerLoginRequired, customerAccountRequired}` for a
  valid key, 404 `ENTRY_POINT_NOT_FOUND` for unknown keys, no database query at
  all for malformed keys, and INTERNAL_ERROR sanitization on DB failure.
- Public card JSON → allowlisted fields only, never `customerId`/`publicTokenHash`.
- Login success → exactly `{csrfToken, mfaRequired}` + session cookie; login
  failures → always `INVALID_CREDENTIALS` (no internal MFA reason leak).
- `POST .../cards` → `{card:{id,ruleId,stampCount,revision}}` only.
- `POST .../cards/:id/stamps` normal and idempotency replay → identical minimal
  `{card, reward?, idempotencyKey?}` payload; replay writes nothing.
- `POST .../rewards/:id/redeem` → `{rewardId, status}` only.
- Missing/invalid session (401), CSRF (missing/wrong → `CSRF_INVALID`), role
  gate (403), MFA gate (`MFA_REQUIRED`), cross-tenant (401 via tenant-scoped
  session lookup, plus 403 via `assertTenant` defense in depth), and
  `INTERNAL_ERROR` sanitization (500 without leaking the internal message).

The suite imports `src/server.ts` after scrubbing all config/credential env
vars and setting `VERCEL=1`, then injects the fake pool through the test-only
seam `withTestDependencies(...)` (behavior-neutral in production). See the
header comment in the test file for details.

### CSRF contract (pinned by the suite)
The client submits the value the login response returns as `csrfToken`
verbatim in the `x-csrf-token` header; the server stores
`hashSessionToken(csrfToken)` per session and compares it to the header. After
a session rotation (every `stamps`/`redeem` response), the fresh value is
returned in the `x-csrf-token` response header alongside the new `Set-Cookie`,
so the client can continue without re-login. This contract was fixed while
writing the suite (see below); the old code hashed the submitted header and
compared the raw header to that hash, which is mathematically always false —
every mutating request failed with `CSRF_INVALID`.

### Production fixes shipped with the suite
Three small `src/server.ts` fixes were strictly required to make the
authenticated mutating contract testable (all pinned by the new tests):
1. `auth()` now validates the `x-csrf-token` header against the session's
   stored `csrf_token_hash` (was: an always-false raw-vs-hash comparison).
2. Login now returns the stored-hash form as `csrfToken`, and `rotate()`
   delivers the fresh CSRF value via the `x-csrf-token` response header.
3. `POST .../cards` is guarded with `parts.length===4`; without it the
   create-card branch shadowed the `.../cards/:id/stamps` route.

## Migrations are off the request path (`db:migrate` + bounded readiness)

Vercel-504 fix: migrations no longer run during module initialization on the
Vercel request/cold-start path. The schema is applied explicitly before a
pilot/release:

```sh
DATABASE_URL='postgresql://.../db?sslmode=require' bun run db:migrate
```

`src/migrate.ts` reads the connection string exclusively from `DATABASE_URL`
(never baked in), runs `runMigrations` under the F3 advisory lock and exits
nonzero on any failure (exit `0` = applied). Only an explicit
`RUN_MIGRATIONS_ON_START=1` opts the server into background migrations-on-start;
requests then wait at most `DB_READINESS_TIMEOUT_MS` (default 3000 ms) for
readiness and otherwise fail fast with the classified `503 DATABASE_UNAVAILABLE`
instead of hanging until the platform kills the invocation (504). `GET /health`
honestly reports `not_ready` while the opt-in migration is pending or failed.

`tests/server-migrations.test.ts` (9 tests, no database) pins all of this with
unreachable/black-hole databases only — nothing is ever migrated against a real
PostgreSQL instance:

- Default (DATABASE_URL set, no `RUN_MIGRATIONS_ON_START`): the server boots
  instantly, `/health` is `ready` even though the DB is unreachable, no
  `migration_failed` log appears (no migration attempted), and DB-backed routes
  fail fast with a classified error.
- Opt-in + unreachable DB: `/health` is `not_ready`, requests get
  `503 DATABASE_UNAVAILABLE` fast, `migration_failed` is logged.
- Opt-in + hung DB (black-hole TCP server): the bounded readiness timeout
  fires and the request returns `503` in ~`DB_READINESS_TIMEOUT_MS` — proven not
  to hang.
- CLI: missing `DATABASE_URL` exits 1 with `DATABASE_URL_REQUIRED`; an
  unreachable DB exits 1 and the connection URL/credentials never appear in the
  output; the success path is covered with an injected fake pool.

## RLS / production-role verification

`tests/rls-verify.test.ts` (27 tests, no database) pins the opt-in diagnostic
in `src/rls-verify.ts`:

- Query builders emit **only bare `SELECT`** statements against catalog views
  (`pg_roles`, `pg_class`/`pg_namespace`, privilege helpers); `current_user`
  appears only in predicates, never in a select list, and named-role mode never
  inlines the role name (bind parameter only).
- The classifier turns synthetic catalog rows into the anonymized report:
  `rolbypassrls`/superuser/createrole/createdb/replication flags,
  table-owner risk (`ownsAnyTable` + `ownedTables`), RLS enabled on every
  tenant-sensitive table (`rlsMissing`), `row_security_active` (as-role mode
  only; `null` in named-role mode), required DML grants (`missingGrants` like
  `cards:UPDATE`, derived from `REQUIRED_GRANTS` in the module), schema
  USAGE/CREATE and missing tables (incomplete schema → fail).
- `verifyRls` runs against a scripted in-memory `RlsDb` and proves the safety
  contract: the report never contains the connection URL (incl. passwords),
  role names or raw driver error text (classified codes only, e.g.
  `query:role-attributes` / `connect`), and invalid schema/role inputs fail
  before any query runs.
- `resolveRlsEnv` pins the explicit opt-in: only `RLS_VERIFY_DATABASE_URL`
  (no `DATABASE_URL` fallback); missing/blank → `RLS_VERIFY_DATABASE_URL_REQUIRED`.

`tests/migrations.test.ts` (12 tests, no database) pins the migration path the
runner in `src/db.ts` applies: exactly `001_init.sql` …
`010_membership_mfa_resolver.sql`, runner-compatible filenames
(`^\d{3}_[a-z0-9_]+\.sql`), contiguous unique numeric prefixes, that 007
constrains a table/column created by earlier migrations, and that 008 defines
the minimal-privilege resolver function (SECURITY DEFINER, fixed
`search_path = pg_catalog`, fully qualified `public.tenant_entry_points`, no
dynamic SQL in the body, `REVOKE ... FROM PUBLIC`, conditional `GRANT
EXECUTE ... TO app_role`, reads no other table). 009 is pinned to: RLS on
`sessions` with the exact user-scoped policy
`user_id = nullif(current_setting('app.user_id', true), '')::uuid` on USING
**and** WITH CHECK (no FORCE, no token/tenant fallback in the policy), the
minimal `resolve_session_user(text)` SECURITY DEFINER bootstrap (returns only
`user_id`, 64-hex format guard, fully qualified `public.sessions`,
`REVOKE ... FROM PUBLIC`, conditional app-role grant), the audit policy split
(tenant rows only in matching `app.tenant_id` context; global `tenant_id IS
NULL` rows only with **no** tenant context), and zero `FORCE ROW LEVEL
SECURITY` anywhere (the 008/009 resolvers rely on the owner bypass). 010 is
pinned to: the tenantless login MFA resolver `public.membership_mfa_required
(p_user_id uuid) returns boolean` (SECURITY DEFINER, fixed
`search_path = pg_catalog`, fully qualified `public.tenant_memberships` +
`public.users`, static `SELECT EXISTS` — never NULL, no dynamic SQL,
`REVOKE ... FROM PUBLIC`, conditional app-role grant, reads only the
MFA/role/status columns, no table/policy/FORCE changes). The login query
contract and fail-closed behavior (exactly `select
public.membership_mfa_required($1) as required`, never a raw
`tenant_memberships` read or `bool_or`; missing row / NULL →
`MFA_BOOTSTRAP_UNVERIFIED` → `INVALID_CREDENTIALS`; `required=true` takes
the MFA gate) live in `tests/http-contract.test.ts`. Run:

```sh
bun test tests/rls-verify.test.ts tests/migrations.test.ts tests/entry-point-rls.test.ts tests/sessions-rls.test.ts
```

`tests/entry-point-rls.test.ts` (5 tests, no database) pins the DB-free
contract of the RLS-safe `/join/:publicKey` resolution: the repository issues
exactly `select tenant_id,join_path from public.resolve_entry_point($1)` (never
a raw table read, never `select *`), returns null for unknown keys, rejects
malformed keys before any DB interaction, and the 008 migration keeps its
security properties. Route-level `/join` contracts (200 shape, 404,
no-DB-on-malformed-key, INTERNAL_ERROR sanitization) live in
`tests/http-contract.test.ts`.

The **live** diagnostic is a separate on-demand operator step, not part of the
unit suite and never part of `bun test` against Neon. Against a real database
(production or a migrated staging copy) with the app-role connection string:

```sh
RLS_VERIFY_DATABASE_URL='postgresql://<app-role>:...@host/db?sslmode=require' bun run rls-verify
```

Exit codes: `0` all critical checks passed, `1` verification failed (or
connection failed), `2` not run (opt-in variable missing). The tool opens its
own short-lived connection inside a `BEGIN READ ONLY` transaction, runs only
SELECTs on catalog views and prints an anonymized JSON report; it never
modifies anything. Full contract and the current blocker (no separate
non-owner app role exists in this workspace yet → no end-to-end run, no unsafe
workaround) are documented in `RLS_AUTH_P1.md` Teil C.

## Production preflight (`bun run production-preflight`)

`src/production-preflight.ts` is a static, read-only, **DB-free** gate to run
before any pilot/production deployment. It answers "is the deployment
configuration statically plausible?" without opening a database connection and
without printing a single secret value. The live counterpart (`rls-verify`)
still covers what a static check cannot: actual Neon connectivity, app-role RLS
and Google issuer approval.

```sh
bun run production-preflight
```

Exit codes:
- `0` — all required checks passed.
- `1` — at least one required check failed; the JSON report's `errors` array
  lists classified codes (below).
- `2` — the preflight could not complete (internal error); the report contains
  only `PREFLIGHT_INTERNAL_ERROR`.

What it checks (booleans/classified values only, never env values):

| Area | Check | Error codes |
|---|---|---|
| Environment | `DATABASE_URL` non-blank | `DATABASE_URL_REQUIRED` |
| | `SESSION_SECRET` ≥ 32 chars | `SESSION_SECRET_REQUIRED`, `SESSION_SECRET_TOO_SHORT` |
| | `FRONTEND_ORIGIN` (or legacy `PUBLIC_SITE_ORIGIN`), an `http(s)` origin without path/trailing slash | `FRONTEND_ORIGIN_REQUIRED`, `FRONTEND_ORIGIN_INVALID` |
| Google Wallet | `GOOGLE_ISSUER_ID` set | `GOOGLE_ISSUER_ID_REQUIRED` |
| | Credential mode: keyless external-account (env JSON or `GOOGLE_APPLICATION_CREDENTIALS` file) or service-account fallback (JSON, split email+key, or ADC file) | `GOOGLE_CREDENTIALS_REQUIRED`, `GOOGLE_EXTERNAL_ACCOUNT_JSON_INVALID`, `GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATION_REQUIRED`, `GOOGLE_APPLICATION_CREDENTIALS_UNREADABLE`, `GOOGLE_APPLICATION_CREDENTIALS_INVALID`, `GOOGLE_SERVICE_ACCOUNT_JSON_INVALID` |
| MFA | Only when `MFA_ENCRYPTION_KEY` is set: must be 64-hex or 32-byte base64 (mirrors `src/mfa.ts`) | `MFA_ENCRYPTION_KEY_INVALID` |
| Communication | Only when all five `EMAIL_SMTP_*` values are set: `COMMUNICATION_HASH_SECRET` ≥ 32 chars | `COMMUNICATION_HASH_SECRET_REQUIRED` |
| Migrations | Exact `001_init.sql` … `010_membership_mfa_resolver.sql` set, contiguous, runner-compatible names (filesystem only) | `MIGRATIONS_DIR_UNREADABLE`, `MIGRATIONS_INCOMPLETE` |
| Vercel/Node | `api/index.ts` exists and imports `fetchHandler` from `../src/server.js` (ESM-resolvable — Node cannot load `.ts` or extensionless specifiers from the compiled function package); `vercel.json` with NO `functions.runtime` (platform rejects it; Node 24.x is project-managed), `fra1`, rewrite to `/api/index`; `package.json` with `start` and `build` scripts | `ENTRY_POINT_MISSING`, `ENTRY_POINT_INVALID`, `VERCEL_CONFIG_MISSING`, `VERCEL_CONFIG_INVALID`, `VERCEL_RUNTIME_INLINE_REJECTED`, `VERCEL_REGION_INVALID`, `VERCEL_REWRITE_MISSING`, `PACKAGE_JSON_MISSING`, `PACKAGE_JSON_INVALID`, `START_SCRIPT_MISSING`, `BUILD_SCRIPT_MISSING` |

Safety contract (pinned by `tests/production-preflight.test.ts`, 40 tests, no
database):
- **No DB connection is ever opened.** The module imports only pure helpers
  (`gcp-credentials.ts`, `email.ts`) and reads files; it never imports
  `src/server.ts`, `src/db.ts` or `postgres` (pinned by a source-level test).
- **No secret values are printed.** The report contains booleans, classified
  codes and migration file names only. A test feeds a full set of distinctive
  fake secrets (DATABASE_URL with password, private key, MFA/communication
  secrets, ADC path) and asserts none of them — and not even the word `leak` —
  appears in the serialized report. `GOOGLE_APPLICATION_CREDENTIALS` paths are
  classified, never echoed.
- **Honest static gate:** in external-account mode the OIDC token cannot be
  verified statically (on Vercel Functions it arrives per request as the
  `x-vercel-oidc-token` header) — the report notes this instead of failing.
  Membership-level `mfa_required` lives in the database and is invisible here;
  the report notes that `MFA_ENCRYPTION_KEY` must be set before any tenant
  enforces MFA.

The CLI is also exercised end-to-end by spawning it with a scrubbed
environment (expects exit `1` + classified errors, never the Neon URL) and
with a complete fake environment (expects exit `0`, never the fake
`DATABASE_URL` value).

## Wallet / Google credentials tests

`src/wallet.test.ts` and `tests/gcp-credentials.test.ts` cover both Google
credential modes (keyless Workload Identity Federation and the classic
service-account fallback) with **mock credentials only**: ephemeral RSA keys
generated via `openssl`, fake OIDC tokens, and mocked STS/impersonation/
`signBlob` HTTP responses. No test performs a real Google call, and running the
suite requires no real credential. Never put real service-account JSON, private
keys, or OIDC tokens into the test files.
