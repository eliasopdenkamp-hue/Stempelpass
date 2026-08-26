# Google Wallet Setup (Loyalty)

StempelPass uses Google Wallet Loyalty classes/objects, not Google Pay payments.
The adapter returns a server-signed `savetowallet` JWT only when a credential
source is configured. Before issuing it, the adapter idempotently GETs the
issuer-wide LoyaltyClass and creates it through the Google Wallet API when it
is missing. Without credentials it returns `status: not_configured` and no URL
or fake pass.

The "Save to Google Wallet" flow fundamentally requires the JWT to be signed
with a Google service-account private key. This project supports two ways to
obtain that signature:

| Mode | Key material | Signing | Requires `GOOGLE_SERVICE_ACCOUNT_JSON`? |
| --- | --- | --- | --- |
| **Workload Identity Federation (preferred)** | none – key stays with Google | IAM Credentials `signBlob` over the network | **No** |
| Classic service-account JSON (fallback) | in-process memory | local RSA-SHA256 | Yes (or split env vars) |

The keyless mode works on Vercel via OIDC federation and also supports local
development with `vercel env pull` (which downloads `VERCEL_OIDC_TOKEN`).

---

## Keyless mode (preferred): Vercel OIDC → GCP Workload Identity Federation

Flow per request:

1. Vercel Functions set the OIDC token on the request as the
   `x-vercel-oidc-token` header (Builds/local get it as the `VERCEL_OIDC_TOKEN`
   environment variable instead). The server route already reads the header and
   passes it to `walletAdapter('google', { oidcToken })` – no module-level access
   is possible in Functions, because the token only exists on the Request.
2. The backend exchanges the OIDC token at the Google STS endpoint
   (`https://sts.googleapis.com/v1/token`) for a short-lived access token
   (Workload Identity Federation, "external account" flow).
3. The backend impersonates a Google service account
   (`:generateAccessToken`).
4. The backend asks IAM Credentials to sign the Wallet JWT with that service
   account's Google-held key (`projects.serviceAccounts.signBlob`). The private
   key never exists in our process, is never logged and never written to disk.

### Environment (keyless)

- `GOOGLE_ISSUER_ID`: numeric issuer ID from Google Wallet API.
- `GOOGLE_EXTERNAL_ACCOUNT_JSON`: the external-account credentials JSON (see
  below). It contains the pool provider `audience` and the service-account
  impersonation URL – no private keys.
- The OIDC token itself is provided per request by Vercel
  (`x-vercel-oidc-token` header) or via `VERCEL_OIDC_TOKEN` (Builds/local). Do
  **not** store a token as a Vercel environment variable for Functions; it is
  injected per request.
- Optional `GOOGLE_APPLICATION_CREDENTIALS`: path to an `external_account` JSON
  file (local development convenience; read at runtime, never written).

Example `GOOGLE_EXTERNAL_ACCOUNT_JSON` (values are placeholders; the real
values come from the Google Cloud console after the owner setup below):

```json
{
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/1234567890/locations/global/workloadIdentityPools/vercel/providers/vercel",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_url": "https://sts.googleapis.com/v1/token",
  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/wallet@project.iam.gserviceaccount.com:generateAccessToken"
}
```

### Owner setup checklist (keyless production, no JSON private key)

The following is the complete input inventory. Values marked **Secret** must be
entered only in Vercel Environment Variables (or a local secret manager); the
other values are identifiers/configuration and contain no private key.

| Input | Required where | Secret? | Expected format / source |
|---|---|---:|---|
| `GOOGLE_ISSUER_ID` | Vercel Production (and Preview if used) | No | Decimal numeric issuer ID from Google Pay & Wallet Console; no spaces or URL. |
| `GOOGLE_EXTERNAL_ACCOUNT_JSON` | Vercel Production (and Preview if used) | No private secret | One-line or multiline JSON of type `external_account`; must contain the exact provider `audience` and `service_account_impersonation_url` (optionally `subject_token_type`, `token_url`, `scope`). Never put a private key in it. |
| `VERCEL_OIDC_TOKEN` | Local/build only | **Yes, short-lived** | JWT string. In a deployed Vercel Function it is injected per request as `x-vercel-oidc-token`; do not create a persistent Vercel env var for it. |
| `GOOGLE_APPLICATION_CREDENTIALS` | Local only (optional) | No | Filesystem path to an external-account JSON file; not a JSON value and normally not set on Vercel. |

The code requires only `GOOGLE_ISSUER_ID` + `GOOGLE_EXTERNAL_ACCOUNT_JSON` plus
the per-request OIDC token in keyless Vercel production. `GOOGLE_EXTERNAL_ACCOUNT_JSON`
is configuration, not a service-account key, but should still be access-restricted
because it identifies the workload pool and impersonated account. Do not configure
`GOOGLE_SERVICE_ACCOUNT_JSON`, `GOOGLE_SERVICE_ACCOUNT_EMAIL`, or
`GOOGLE_PRIVATE_KEY` for the keyless path; those are optional **fallback secrets**
only. `GOOGLE_APPLICATION_CREDENTIALS` is an alternative source for the same
external-account JSON when running locally, not an additional production input.

None of this can be done in code or verified without real credentials. It is a
one-time, console-only setup:

1. **Vercel side**: enable *Secure backend access with OIDC federation* for the
   team (Vercel → Settings → Security). Decide issuer mode:
   - **Team** (recommended): issuer URL `https://oidc.vercel.com/<TEAM_SLUG>`
   - **Global**: issuer URL `https://oidc.vercel.com`
2. **GCP: Workload Identity Pool** (IAM & Admin → Workload Identity
   Federation → Create Pool), e.g. pool id `vercel`.
3. **GCP: OIDC provider** in that pool (e.g. provider id `vercel`):
   - **Issuer URL**: the Vercel issuer URL from step 1 (must match exactly).
   - **Audience**: either
     - *Default audience* (recommended by Google) – GCP generates
       `https://iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/<POOL>/providers/<PROVIDER>`
       and this exact URL must be used as the `audience` in
       `GOOGLE_EXTERNAL_ACCOUNT_JSON`; **or**
     - *Allowed audiences* = `https://vercel.com/<TEAM_SLUG>` – matches the
       default `aud` claim of Vercel tokens and needs no custom audience code.
   - **Attribute mapping**: `google.subject` ← `assertion.sub`. Vercel `sub`
     claims look like `owner:<TEAM_SLUG>:project:<PROJECT_NAME>:environment:production`
     (and `:preview` / `:development`).
4. **GCP: service account** (e.g. `wallet-sa`). Note its email and grant IAM
   roles **on this service-account resource**:
   - `roles/iam.workloadIdentityUser` to the federated Vercel principal (or a
     restricted principal set), for example
     `principal://iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/<POOL>/subject/owner:<TEAM_SLUG>:project:<PROJECT_NAME>:environment:production`
     (add separate preview/development subjects only if those deployments are
     intended to use Wallet). This permits the external identity to impersonate
     the account; it is not a role granted to the pool by itself.
   - `roles/iam.serviceAccountTokenCreator` on the same service account for the
     impersonated service account identity. This authorizes IAM Credentials
     `signBlob` (`iam.serviceAccounts.signBlob`) and is mandatory for this
     implementation. Keep the grant as narrow as possible and verify the
     effective IAM policy before production.
5. **Google Wallet issuer access (separate console)**: in the Google Pay &
   Wallet Console, add the service-account email
   (`wallet-sa@...iam.gserviceaccount.com`) as a user of the issuer account
   with access level **Developer**. Without this, Wallet rejects the signed
   JWT even though the signature itself is valid.
6. **Enable APIs** on the GCP project: `Google Wallet API` and
   `IAM Credentials API`.
7. Put the pool provider values into the Vercel project as the environment
   variables shown above (only `GOOGLE_EXTERNAL_ACCOUNT_JSON` +
   `GOOGLE_ISSUER_ID` are required by the code).

> **Honesty note**: this keyless path is implemented and unit-tested against
> mocked Google endpoints, but it has **not** been verified against the real
> Google Wallet API. Do not claim productive function until the owner has
> completed steps 1–7 and a real end-to-end save was performed. The artifact
> message in keyless mode explicitly says so.

### Does the current Vercel adapter provide the OIDC token?

Yes, with two conditions:

- Vercel sets `x-vercel-oidc-token` on the Request **only in Vercel
  Functions**, and only when OIDC federation is enabled for the team. The
  current adapter (`api/index.ts`) receives the Request and the shared handler
  reads the header (`walletAdapter('google', { oidcToken: req.headers.get('x-vercel-oidc-token') })`).
- The token is **not available at module load time** (it changes per function
  invocation and is reused up to ~90 minutes; TTL 2 h). That is why the code
  resolves credentials per request, not at import time.
- Edge Functions / static paths do not get the header. Use the existing Node
  runtime serverless function.

---

## Fallback mode: classic service-account key

Kept for environments that cannot use Workload Identity Federation. The private
key exists only in process memory and is never logged or written by the code.

- `GOOGLE_ISSUER_ID`: numeric issuer ID.
- `GOOGLE_SERVICE_ACCOUNT_JSON`: service-account JSON containing `client_email`
  and `private_key` (preferred), **or**
- `GOOGLE_SERVICE_ACCOUNT_EMAIL` and `GOOGLE_PRIVATE_KEY` as separate secret
  values (PEM newlines may be encoded as `\n`).

Store values only in the deployment secret manager. Never commit JSON, PEM
material, or generated JWTs. The service account must be granted the
appropriate Google Wallet API issuer permissions (Developer in the Pay &
Wallet console) by the owner; this is not verifiable without owner credentials.

## Endpoints

- `GET /card/{tenantId}/{privateToken}`: tenant-bound HTML web card. The raw
  token is hashed immediately and is never logged or included in analytics.
- `GET /api/public/tenants/{tenantId}/cards/{privateToken}`: JSON card data
  including branding and reward progress.
- Append `/wallet/google` to the JSON path for the Google Wallet artifact.

`GET /health` reports `walletConfigured.google` and
`googleCredentialMode` (`external-account` | `service-account-json` | null).

## Tests

`src/wallet.test.ts` and `tests/gcp-credentials.test.ts` cover both modes with
**mock credentials only** (ephemeral RSA keys via `openssl`, fake OIDC tokens,
mocked STS/impersonation/signBlob responses). No test ever calls Google, and no
real credential is required to run the suite.

Apple remains an adapter placeholder and is not advertised as available. Apple
credentials are intentionally not required for this release.
