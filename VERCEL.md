# Vercel-Free-Tier Deployment

The API has a Vercel adapter at `api/index.ts`. It imports the same Fetch-compatible
handler used by Bun, so there is no second routing implementation. `vercel.json`
selects the EU Frankfurt region (`fra1`) and rewrites the public origin to the
function. This is configuration only; no deployment or credentials are included.

## Commands

From this directory:

```sh
bun run production-preflight # static production-readiness gate (no DB, no secrets printed)
vercel build --prod           # local prebuilt production build (target=production)
vercel deploy --prebuilt --prod # deploy the prebuilt production output, requires VERCEL_TOKEN
```

Before any pilot/production deploy run `bun run production-preflight` and
require exit code `0`. It statically verifies the required environment
(`DATABASE_URL`, `SESSION_SECRET`, `FRONTEND_ORIGIN`), the configured Google
credential mode (external-account or service-account fallback),
`MFA_ENCRYPTION_KEY` only when MFA is active, `COMMUNICATION_HASH_SECRET` only
when SMTP is active, the exact migration set 001–010 and the Vercel entry
point/Node build wiring — without opening a database connection and without
printing any secret value. Exit codes and the classified error list are
documented in `TESTING.md`. The live diagnostics (Neon connectivity,
app-role RLS via `bun run rls-verify`, Google issuer approval) are separate
pilot steps a static preflight cannot cover.

The repository intentionally does **not** contain a `VERCEL_TOKEN`. Do not deploy
without one. Configure the project in Vercel with the **Node.js 24.x** runtime
and `fra1` region (project settings; the platform rejects `functions.runtime`
in `vercel.json`, so the Node version is project-managed only).

## Required environment variables

Set these in the Vercel project/environment (never commit values):

- `DATABASE_URL`: Neon PostgreSQL connection string, EU project, with TLS (`sslmode=require`).
- `SESSION_SECRET`: at least 32 random characters/bytes.
- `FRONTEND_ORIGIN`: exact published frontend origin, currently
  `https://a1e91d0731cfc57ecf5a508e37635a85.ctonew.app` (no trailing slash).

`MFA_ENCRYPTION_KEY` is optional until MFA is enabled; when enabled it must be a
32-byte base64 or 64-character hex secret.

## Google Wallet on Vercel (keyless, recommended)

The preferred path needs **no service-account JSON key**. It uses Vercel OIDC
federation to obtain short-lived Google credentials:

1. Enable *Secure backend access with OIDC federation* for the Vercel team
   (Settings → Security). OIDC is available on all plans.
2. Complete the one-time GCP Workload Identity Federation setup (pool,
   OIDC provider, service account with
   `roles/iam.serviceAccountTokenCreator`, Wallet issuer access) – exact steps
   in `GOOGLE_WALLET_SETUP.md`. This is console-only work the owner must do;
   the code cannot create the pool or grant roles.
3. Set these Vercel project environment variables:
   - `GOOGLE_ISSUER_ID`
   - `GOOGLE_EXTERNAL_ACCOUNT_JSON` (external-account credentials, no keys)
   - `GOOGLE_APPLICATION_CREDENTIALS` only if pointing at an external-account
     file; normally not needed on Vercel.

**OIDC token delivery**: in Vercel Functions the token arrives as the
`x-vercel-oidc-token` **request header** – the shared handler reads it per
request (`walletAdapter('google', { oidcToken })`). It is *not* an environment
variable in Functions and is *not* available at module load time, so do not try
to read it at import time. In Builds/local development it is provided as
`VERCEL_OIDC_TOKEN` (e.g. via `vercel env pull`).

The classic service-account fallback (`GOOGLE_SERVICE_ACCOUNT_JSON` or the
split `GOOGLE_SERVICE_ACCOUNT_EMAIL`/`GOOGLE_PRIVATE_KEY`) still works for
environments without OIDC. SMTP is optional: configure all
`EMAIL_SMTP_HOST`, `EMAIL_SMTP_PORT`, `EMAIL_SMTP_USER`,
`EMAIL_SMTP_PASSWORD`, and `EMAIL_FROM` together.

Other optional integrations are documented in `.env.example` and
`GOOGLE_WALLET_SETUP.md`. Vercel environment variables should be added separately
for Preview and Production. Never put secrets in `vercel.json`.

## Pilot readiness — operator sequence

`GET /health` always answers HTTP 200 while the function is up (liveness), but
`{"status":"ready"}` is only honest after the schema/pilot steps below really
happened against the **production** database. The request path cannot verify
them without a blocking query (which `/health` must never issue), so readiness
is an explicit operator declaration. Order matters:

1. **Set the production environment** in Vercel: `DATABASE_URL` (EU Neon,
   `sslmode=require`), `SESSION_SECRET` (≥ 32 chars), `FRONTEND_ORIGIN` (exact
   published origin, no trailing slash) and the Google Wallet variables
   (`GOOGLE_ISSUER_ID` + keyless `GOOGLE_EXTERNAL_ACCOUNT_JSON`, see below).
   **Do NOT set `RUN_MIGRATIONS_ON_START`** — migrations must never run in the
   Vercel request/cold-start path. Do NOT set `PILOT_READY` yet.
2. **Apply the schema once, out-of-band** against the production database:
   ```sh
   DATABASE_URL='postgresql://.../db?sslmode=require' bun run db:migrate
   ```
   Exit `0` = applied. Never run this from the Vercel request path.
3. **Seed the pilot tenant once, out-of-band** (CLI only — never on the
   request path; refuses to run when `VERCEL=1`):
   ```sh
   DATABASE_URL='postgresql://.../db?sslmode=require' \
   PILOT_TENANT_SLUG='stempelpass' \
   PILOT_TENANT_LEGAL_NAME='Stempelpass GmbH' \
   PILOT_OWNER_EMAIL='owner@example.com' \
   PILOT_OWNER_PASSWORD='<starkes Passwort, min. 12 Zeichen>' \
   bun run db:seed-pilot
   ```
   Reads only `PILOT_*` variables, hashes the password (scrypt, no
   plaintext stored/printed), creates tenant + owner + membership (+ optional
   `PILOT_CUSTOMER_REF` test customer) idempotently under the seed advisory
   lock and prints only anonymized ids/status. Exit `0` = ok. Full runbook:
   `PILOT_ONBOARDING.md` ("Einmaliger Pilot-Seed").
4. **Create the dedicated app role** (owner-side, per `RLS_AUTH_P1.md`) and
   verify RLS/role isolation read-only:
   ```sh
   RLS_VERIFY_DATABASE_URL='postgresql://<app-role>@.../db?sslmode=require' bun run rls-verify
   ```
   Exit `0` = pass. Until the app role exists, RLS enforcement cannot be
   exercised by the live API (documented blocker, `RLS_AUTH_P1.md`).
5. **Declare pilot readiness**: set `PILOT_READY=1` in the production
   environment (redeploy applies it). `/health` then reports
   `{"status":"ready"}`; before that it honestly reports `{"status":"not_ready"}`
   even though the function is reachable.

## Runtime notes / limitations

Vercel functions are stateless and may be reused between requests. The module-level
PostgreSQL pool is intentionally reused across warm invocations; Neon pooling and
`DB_POOL_MAX` should be sized for the Free tier.

**Migrations never run in the Vercel request/cold-start path.** The schema is
applied out-of-band with the dedicated CLI before a pilot/release:

```sh
DATABASE_URL='postgresql://.../db?sslmode=require' bun run db:migrate
```

The CLI reads the connection string exclusively from `DATABASE_URL` (never baked
in, never printed), applies pending migrations under the F3 advisory lock and
exits nonzero on any failure. The server starts instantly without touching the
database: requests fail fast with a classified error if the database is
unreachable. `GET /health` is the honest pilot signal: it is **always HTTP 200
while the function is up** (liveness), and its `status` field reports `ready`
only after the operator declares the schema/pilot steps done via `PILOT_READY=1`
(see below) — without that declaration it reports `not_ready` even though the
function is reachable. The endpoint never queries the database. To opt a single
long-running Bun process into migrations-on-start, set `RUN_MIGRATIONS_ON_START=1`;
requests then wait at most `DB_READINESS_TIMEOUT_MS` (default 3000) for the
background migration before returning `503 DATABASE_UNAVAILABLE` — a hung or
sleeping database can no longer hold the invocation until the platform
timeout (504).

The Bun local server remains available with `bun run dev`/`bun run start`. The
Vercel adapter is the supported serverless boundary; do not claim a public API URL
until a project is actually deployed with valid Vercel credentials.
