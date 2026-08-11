# Rate limiting & login security (backend)

This document describes how login and public-card rate limiting works after the
P1 login-security fixes, what is deliberately NOT trusted, and what a
distributed deployment must change.

## Threat model

- `x-forwarded-for` is **attacker-controlled** unless a trusted proxy
  overwrites it. In this codebase there is no trusted-proxy layer of its own, so
  the header is never used as the sole identity for a limit.
- Login endpoints are also attacked **per account** (credential stuffing):
  attackers rotate IPs, so an IP-only limit is bypassable.
- Limiter keys are attacker-influenced, so the number of tracked keys must be
  bounded or memory can be exhausted by unique keys.

## Keys (all hashed, never logged in plaintext)

| Key | Derivation |
| --- | --- |
| `acct:<sha256>` | sha256 of the trimmed, lowercased login email. The raw email is never a key and never logged. |
| `ip:<sha256>` | sha256 of the first `x-forwarded-for` entry, but only if it parses as an IPv4/IPv6 address. Missing, malformed, or non-IP values fall back to one shared `unknown` bucket (`ip:<sha256("unknown")>`), so attackers cannot generate unbounded keys by omitting the header. |

| `join:<sha256>` | sha256 of the public join key, combined with the hashed client IP (`ip:<sha256>:join:<sha256>`). The raw public key is never a key and never logged; the budget binds one client to one entry point. |
## Current limits (in-memory, per process)

| Limiter | Key | Limit | Window | Notes |
| --- | --- | --- | --- | --- |
| `loginIpLimiter` | `ip:` | 20 attempts | 15 min | Coarse per-source cap; generous because the fallback bucket is shared. |
| `loginAccountLimiter` | `acct:` | 5 attempts | 15 min | Binds per account regardless of spoofed IPs. This is the primary login defense. |
| `cardResolveLimiter` | `ip:` / `ip:join:` | 60 requests | 1 min | Public card/wallet resolution (per client) and `GET /join/:publicKey` (per client + hashed public key). Malformed join keys are rejected before the limiter and the database. |
| `stampLimiter` | `tenant:user` | 30 stamps | 1 min | Authenticated staff path, keyed by tenant+user (not IP). |

Login flow: the IP limiter is checked before the body is parsed (cheap flood
protection); after the body is parsed, the account limiter is checked before
any database or scrypt work. **MFA failures go through the same login path and
therefore consume the same budget** — a wrong TOTP code is one failed login
attempt against both limiters. There is no separate, bypassable MFA endpoint.

All limiters bound their key table (`maxEntries = 50_000`): expired buckets are
swept on every call and the soonest-resetting bucket is evicted when the cap is
hit, so spoofed keys cannot exhaust memory.

## Anti-enumeration on login

Every credential/MFA failure — `INVALID_CREDENTIALS`, `MFA_NOT_CONFIGURED`,
`MFA_INVALID`, `MFA_SECRET_DECRYPT_FAILED` — is mapped inside the login route to
the single external response `INVALID_CREDENTIALS` (HTTP 400). Clients cannot
distinguish "no such account", "wrong password", "MFA required but broken", or
"wrong TOTP code". Unknown accounts additionally run a dummy scrypt verification
so response timing does not reveal account existence.

Internal audit lines (server logs only) have the form:

```
login_failed request_id=<uuid> reason=<internal reason> account=<acct:sha256> ip=<ip:sha256>
```

No credentials, no raw email, no MFA secret, and no request body is ever logged.
`reason` is one of the four internal codes above.

## Distributed deployments (MUST DO)

The limiters are plain in-memory maps: **they are per instance and not shared**.
With more than one backend instance, an attacker can rotate instances to get N
times the per-instance budget, and the accounting is not global. A horizontally
scaled deployment must replace them with a central limiter (e.g. Redis with
`INCR`/`EXPIRE`, or a hosted rate-limit service) using the same keys and limits
above, and must ensure the trusted-proxy configuration (only the real proxy may
set `x-forwarded-for`) is in place before relying on the IP component.

## Operational notes

- Limits are intentionally conservative; tune via the constructor arguments in
  `src/security.ts` and re-run the login-security unit tests
  (`tests/login-security.test.ts`).
- The shared `unknown` IP bucket means clients that legitimately send no usable
  `x-forwarded-for` share a budget. On Vercel the header is always set, so in
  production this affects only direct/local connections.
- A future central limiter should keep the same hashed keys so no raw PII ever
  enters the rate-limit store.
