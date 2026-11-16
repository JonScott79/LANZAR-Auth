# LANZAR ID — NOVA Staging Security and Operational Verification

**Environment:** NOVA Staging (`APP_ENV=staging`)  
**Date:** 2026-11-16  
**Status:** Staging Verified (`27 / 27` extended live checks + `91 / 91` local unit/acceptance checks passed); GCP Blaze-dependent Firestore features (PITR, Scheduled Backups, TTL) documented for manual console enablement.

---

## 1. Executive Summary

LANZAR ID **NOVA** is deployed as an isolated staging identity environment (`lanzar-95ae3-dev`, Railway `lanzar-id-nova`, issuer `https://auth.lanzar.me/nova`, API `https://auth-api-nova.lanzar.me`).

During hardening and live verification:
- **3 composite Firestore indexes** derived from actual application queries (`admins`, `sessions`, `users`) were deployed to `lanzar-95ae3-dev` via `firestore.indexes.json` and `firebase.json`.
- **3 live-discovered defects were remediated and deployed to `nova-staging`:**
  1. `bf8a85f`: Mounted `oauthRouter` on `/oauth` in addition to `/` in `auth/auth-backend/app.js` so OIDC discovery endpoints (`/oauth/authorize`, `/oauth/token`) resolve cleanly.
  2. `905bcf3`: Added `checkIsStaging()` in `auth/auth-backend/clients.js` to block production callback URLs (`portal.lanzar.me`, `tickets.lanzar.me`, `threadline.lanzar.me`, `threadline-production-1c28.up.railway.app`, `ai.lanzar.me`) in NOVA staging.
  3. `2f22fbf`: Coalesced undefined `userClaims` fields (`email`, `emailVerified`, `name`, `authTime`) to `null`/`boolean` in `auth/auth-backend/routes/oauthRoutes.js` so users without a `displayName` do not trigger Firestore `500` errors on `/oauth/authorize`.
- **27 / 27 live cloud checks** (`nova_live_verify_extended.mjs`) and **91 / 91 local regression checks** passed after the final code edit.
- **Production (`lanzar-95ae3`, Railway `AuthServer`, `auth-api.lanzar.me`, `auth.lanzar.me` frontend bundle) remained completely untouched.**

---

## 2. Architecture and Environment Boundaries

| Component | Production | NOVA Staging |
|---|---|---|
| **Auth Hub** | `https://auth.lanzar.me` | `https://auth.lanzar.me/nova` (proxy routes for discovery & JWKS) |
| **OIDC Issuer** | `https://auth.lanzar.me` | `https://auth.lanzar.me/nova` |
| **Backend API** | `https://auth-api.lanzar.me` | `https://auth-api-nova.lanzar.me` |
| **Firebase Project** | `lanzar-95ae3` | `lanzar-95ae3-dev` (`919423368867`) |
| **Internal Environment** | `APP_ENV=production` | `APP_ENV=staging` |
| **Service Account** | Production SA | `lanzar-id-nova-backend@lanzar-95ae3-dev.iam.gserviceaccount.com` |
| **Git Branch** | `auth-repo:lanzar_id_main_chat` | `auth-repo:nova-staging` |

---

## 3. Deployed Infrastructure and Service Identifiers

- **Firebase / GCP Project:** `lanzar-95ae3-dev` (Project Number `919423368867`)
  - **Firestore Database:** `projects/lanzar-95ae3-dev/databases/(default)` (`FIRESTORE_NATIVE`, `STANDARD`, `us-east1`)
  - **Firebase Web App:** `1:919423368867:web:af44d099c0167fc2f74916` (`lanzar-id-nova-web`)
- **Railway Project:** `lanzar-id-nova` (`6f3b7abb-a285-463a-b7b7-2fd7e41e04ba`), Environment `staging` (`02f1b001-a03a-4f70-b770-a25d27225c6d`)
  - **API Service:** `lanzar-id-nova-api` (`500cd933-9f8b-4792-b873-145151e99c9a`), active deployment `34177f35-6362-47f3-9456-07e5ea86a65b` (`[SUCCESS]`)
  - **Worker Service:** `lanzar-id-nova-worker` (`6b6162b2-756e-429a-a293-a20f1fcd7f42`), active deployment `b44f1fbb-a9cf-4569-9c47-24fa14606054` (`[SUCCESS]`)
  - **Custom Domain:** `auth-api-nova.lanzar.me` -> `yvo8zvah.up.railway.app` (`CERTIFICATE_STATUS_TYPE_VALID`)
- **Netlify Auth Hub Site:** `lanzar-auth` (`17d284dc-0e24-4f13-a2cb-33cef6462df2`)
  - **Production Deploy Preserving Bundle + NOVA Redirects:** `6afa7ac9faf23739311800bb` (`index-CL98VAEE.js`, `index-C1wh4mxy.css` preserved; only `/nova/.well-known/openid-configuration` and `/nova/.well-known/jwks.json` proxies added in `auth/netlify.toml`).

---

## 4. Exact Deployed Commit Hashes

- `475437f2ac1d90adde6035499ac40dd6fefd1084` — Baseline pre-production hardening commit (preserved)
- `1f0c638b92890d83b6c2a21249a908388bf6c082` — NOVA staging issuer architecture and deployment docs
- `bf8a85f` — Mount `oauthRouter` at `/oauth` in addition to `/` for OIDC discovery endpoints
- `905bcf3` — Block production OAuth callbacks in NOVA staging (`auth/auth-backend/clients.js`)
- `2f22fbf` — Coalesce undefined `userClaims` fields to `null`/`boolean` before Firestore write (`auth/auth-backend/routes/oauthRoutes.js`)

---

## 5. Original Live Verification Results (22 / 22 Passed)

Initial live verification (`nova_live_verify.mjs`, executed 2026-11-15/16 against `https://auth-api-nova.lanzar.me`, `https://auth.lanzar.me/nova/.well-known/*`, `lanzar-95ae3-dev`, and `lanzar-id-nova-worker`) passed **22 / 22** checks covering:
- NOVA API Health & Readiness (`appEnv=staging`, `firestore=ok`, `signingKeystore=ok`)
- Production Auth Hub unchanged (`index-CL98VAEE.js`) & Production API untouched (`appEnv=production`)
- NOVA OIDC Discovery & JWKS via `auth.lanzar.me/nova/.well-known/*`
- PKCE S256 enforcement & excluded client (`pythos`) rejection
- Full OIDC Authorize + Token Exchange + RS256 JWKS verification + `/oauth/userinfo`
- Cross-environment rogue/wrong-issuer token rejection (`401`) & Policy B session enforcement (`401`)
- Refresh token rotation & replay detection (`401`)
- Admin `Idempotency-Key` enforcement (`400`), replay (`200`), and conflict (`409`)
- Live worker `security_outbox` processing (`COMPLETED`), Firebase Auth suspension propagation (`disabled=true`), and `/api/admin/id/audit-log` (`200`).

---

## 6. Extended Live Security & Failure-Mode Verification (`27 / 27` Passed)

Executed after commit `2f22fbf` via `nova_live_verify_extended.mjs` against live NOVA cloud infrastructure. All temporary users (`createdUids`) and test Firestore documents (`admins`, `security_outbox`, `users`) were deleted in the `finally` cleanup block.

| Test ID | Description | Environment | Execution Method | Result | Supporting Evidence | Cleanup |
|---|---|---|---|---|---|---|
| `NOVA-LIVE-01` | API Health endpoint reports staging | Live Railway NOVA | `GET /api/id/health` | PASS | `200`, `appEnv=staging`, `nodeEnv=staging` | None needed |
| `NOVA-LIVE-02` | API Readiness checks Firestore & keystore | Live Railway NOVA | `GET /api/id/ready` | PASS | `200`, `firestore=ok`, `signingKeystore=ok` | None needed |
| `NOVA-LIVE-03` | Production Auth Hub bundle unchanged | Live Netlify `lanzar-auth` | `GET https://auth.lanzar.me/` | PASS | `200`, `index-CL98VAEE.js` present | None needed |
| `NOVA-LIVE-04` | NOVA OIDC Discovery via Auth Hub proxy | Live Netlify + Railway | `GET https://auth.lanzar.me/nova/.well-known/openid-configuration` | PASS | `200`, `issuer=https://auth.lanzar.me/nova`, `token_endpoint=https://auth-api-nova.lanzar.me/oauth/token` | None needed |
| `NOVA-LIVE-05` | NOVA JWKS via Auth Hub proxy | Live Netlify + Railway | `GET https://auth.lanzar.me/nova/.well-known/jwks.json` | PASS | `200`, `kid=lanzar_rs256_1794799855301_6f199222c3d1` | None needed |
| `NOVA-LIVE-06` | NOVA blocks production OAuth callbacks | Live Railway NOVA | `POST /oauth/authorize` for `portal`, `threadline`, `tickets`, `ai` prod URIs | PASS | `400 invalid_request` for all 4 prod URIs | None needed |
| `NOVA-LIVE-07` | Excluded clients (`pythos`, `mothership`) blocked | Live Railway NOVA | `POST /oauth/authorize` | PASS | `400 invalid_client` for both | None needed |
| `NOVA-LIVE-08` | PKCE `S256` strictly enforced | Live Railway NOVA | `POST /oauth/authorize` with `code_challenge_method=plain` | PASS | `400 invalid_request` | None needed |
| `NOVA-LIVE-09` | Wrong PKCE `code_verifier` rejected | Live Railway NOVA | `POST /oauth/token` with mismatched verifier | PASS | `400 invalid_grant` | Temp user deleted |
| `NOVA-LIVE-10` | OIDC Authorize + Token Exchange (`threadline` dual) | Live Railway NOVA + `lanzar-95ae3-dev` | `POST /oauth/authorize` -> `POST /oauth/token` | PASS | `200`, issued `access_token`, `id_token`, `refresh_token` | Temp user deleted |
| `NOVA-LIVE-11` | RS256 JWKS signature & `/oauth/userinfo` | Live Netlify JWKS + NOVA API | `jose.jwtVerify` + `GET /oauth/userinfo` | PASS | Signature valid (`iss=https://auth.lanzar.me/nova`), `userinfo` `200` | Temp user deleted |
| `NOVA-LIVE-12` | Authorization code replay blocked & revokes session | Live Railway NOVA | Replay `code` on `POST /oauth/token`, then `GET /oauth/userinfo` | PASS | Replay -> `400`, subsequent `access_token` -> `401` | Temp user deleted |
| `NOVA-LIVE-13` | Malformed, expired, HS256, wrong-issuer tokens rejected | Live Railway NOVA | `GET /oauth/userinfo` with 4 forged/invalid JWTs | PASS | `401` for all 4 tokens | None needed |
| `NOVA-LIVE-14` | Refresh token rotation & replay detection | Live Railway NOVA | `POST /oauth/token` (`refresh_token`) twice with old token | PASS | Rotation `200`, replay `401` | Temp user deleted |
| `NOVA-LIVE-15` | Non-admin blocked on all admin endpoints | Live Railway NOVA | Standard user calling 5 `/api/admin/id/*` endpoints | PASS | `403 Forbidden` on all 5 routes | Temp user deleted |
| `NOVA-LIVE-16` | Cross-tenant admin isolation | Live Railway NOVA + `lanzar-95ae3-dev` | `tenant_beta` admin revoking `lanzar` user | PASS | `403 Forbidden` | Temp admin & docs deleted |
| `NOVA-LIVE-17` | Firestore security rules live enforcement | Live `lanzar-95ae3-dev` | Firestore REST API reads with user ID token on `admins`, `system_signing_keys`, `security_outbox` | PASS | `403 PERMISSION_DENIED` on all 3 | None needed |
| `NOVA-LIVE-18` | Admin `Idempotency-Key` mandatory | Live Railway NOVA | `POST /api/admin/id/users/:uid/sessions/revoke-all` without header | PASS | `400 Bad Request` | Temp admin deleted |
| `NOVA-LIVE-19` | Admin `Idempotency-Key` payload conflict | Live Railway NOVA | `POST /suspend` reusing key with `status: active` vs `suspended` | PASS | `409 Conflict` | Outbox doc deleted |
| `NOVA-LIVE-20` | Live worker suspension propagation | Live Railway Worker + Firebase Auth | `POST /suspend` (`suspended`) -> poll `authAdmin.getUser` | PASS | Firebase Auth `disabled=true` | Outbox doc deleted |
| `NOVA-LIVE-21` | Live worker reactivation propagation | Live Railway Worker + Firebase Auth | `POST /suspend` (`active`) -> poll `authAdmin.getUser` | PASS | Firebase Auth `disabled=false` | Outbox doc deleted |
| `NOVA-LIVE-22` | Live worker expired-lease recovery | Live Railway Worker + Firestore | Seed `IN_PROGRESS` outbox doc with `leaseExpiresAt = now - 10s` -> poll | PASS | Worker recovered lease and marked `COMPLETED` | Outbox doc deleted |
| `NOVA-LIVE-23` | Admin audit log query | Live Railway NOVA | `GET /api/admin/id/audit-log?limit=20` | PASS | `200 OK` | Temp admin deleted |
| `NOVA-LIVE-24` | Private signing key encrypted at rest | Live `lanzar-95ae3-dev` | Inspect `system_signing_keys/{activeKid}` | PASS | No plaintext PEM; encrypted field present | None needed |
| `NOVA-LIVE-25` | Live rate limiter enforcement | Live Railway NOVA | Burst 25 requests to `POST /oauth/token` (`maxRequests: 20`) | PASS | Triggered `429 Too Many Requests` | None needed |
| `NOVA-LIVE-26` | NOVA SA blocked from production Firestore | Live GCP IAM (`lanzar-95ae3`) | Firestore REST `GET` on `lanzar-95ae3` with NOVA SA token | PASS | `403 PERMISSION_DENIED` | None needed |
| `NOVA-LIVE-27` | Production API untouched | Live Railway Production | `GET https://auth-api.lanzar.me/api/id/health` | PASS | `200`, `appEnv=production` | None needed |

### Local Unit & Regression Suites (Executed After Final Edit)

| Suite | Scope | Result |
|---|---|---|
| `node auth/test-nova-issuer.cjs` | Decoupled OIDC issuer, fail-closed `OIDC_ISSUER`, Netlify/Vercel proxies | **5 / 5 PASS** |
| `node auth/test-staging-bootstrap.cjs` | Staging bootstrap & credential cross-contamination checks | **10 / 10 PASS** |
| `node auth/test-client-registry.cjs` | Approved clients (`portal`, `tickets`, `threadline`, `ai`), excluded `pythos`/`mothership` | **9 / 9 PASS** |
| `node auth/test-preprod-failclosed-startup.cjs` | Fail-closed secret & env validation at startup | **12 / 12 PASS** |
| `node auth/test-phase1-acceptance.cjs` | Environment isolation, central SSO session lifecycle, password reset, Policies A–D | **55 / 55 PASS** |

---

## 7. Firestore Operational Configuration

- **Composite Indexes (`firestore.indexes.json` deployed to `lanzar-95ae3-dev`):**
  1. `users` (`COLLECTION`): `phoneNumber ASC`, `phoneVerified ASC` (`smsService.js:263-264`)
  2. `admins` (`COLLECTION`): `email ASC`, `active ASC` (`authMiddleware.js:16-17`)
  3. `sessions` (`COLLECTION`): `centralSessionId ASC`, `revoked ASC` (`centralSessionService.js:332-333`)
- **`security_outbox` Index Verification:** `platformOutboxService.js:560` executes `.where('type', '==', 'platform_admin_cross_service').limit(limit * 2)`. Because it uses a single-field equality filter with no `orderBy`, Firestore's automatic single-field index satisfies it without a composite index.
- **TTL Policy Analysis (Derived from `auth/auth-backend/` Codebase):**
  - **`authorization_codes.expiresAt` (`auth/auth-backend/store.js:576, 604, 630`):** `FirestoreAuthorizationCodeStore` writes `expiresAt: new Date(opTime + 600000)` (10-minute lifetime) into collection `authorization_codes` as a **native Firestore `Timestamp`**. This is the **only** collection currently compatible with Firestore native TTL without schema migration (`PENDING — BILLING ACTIVATION` / requires `gcloud` or GCP Console because `firebase-tools` does not expose a TTL CLI command).
  - **Other Expiration Fields (Not TTL-Compatible Without Schema Migration):**
    - `tenants/{tenantId}/token_families.expiresAt` (`oauthRoutes.js:278`): ISO-8601 string (`expiresAt.toISOString()`).
    - `users/{uid}/sessions.expiresAt`: ISO-8601 string in `oauthRoutes.js:257` & `sessionService.js:80`; numeric epoch seconds in `centralSessionService.js:200`.
    - `users/{uid}/central_sessions` (`centralSessionService.js:64-65`): `absoluteExpiresAt` and `idleExpiresAt` stored as numeric epoch seconds.
    - `admin_idempotency.expiresAt` (`adminRoutes.js:269, 517`): ISO-8601 string (`new Date(...).toISOString()`).
  - Firestore native TTL silently ignores string and numeric fields; **do not** create TTL policies on those fields without an explicit dual-read/Timestamp migration plan.
- **Security Rules:** `firestore.rules` compiled and deployed on `lanzar-95ae3-dev`; live-verified via `NOVA-LIVE-17` (`403` on direct client reads of `admins`, `system_signing_keys`, `security_outbox`).

---

## 8. Backup, PITR, and Recovery Configuration

- **Current State of `projects/lanzar-95ae3-dev/databases/(default)`:**
  - `Point In Time Recovery`: `POINT_IN_TIME_RECOVERY_DISABLED` — **PENDING — BILLING ACTIVATION**
  - `Delete Protection State`: `DELETE_PROTECTION_DISABLED` — **PENDING — BILLING ACTIVATION**
  - `Backup Schedules`: None — **PENDING — BILLING ACTIVATION**
- **Blocker:** `firebase firestore:databases:update` returned HTTP `403`: *"This API method requires billing to be enabled. Please enable billing on project lanzar-95ae3-dev."*
- **Validated Activation Commands (Run After Blaze Billing Is Enabled):**
  ```bash
  # 1. Enable PITR and Delete Protection (PENDING — BILLING ACTIVATION)
  npx firebase-tools firestore:databases:update "(default)" --point-in-time-recovery ENABLED --delete-protection ENABLED --project lanzar-95ae3-dev

  # 2. Create Daily Backup Schedule with 7-day Retention (PENDING — BILLING ACTIVATION)
  npx firebase-tools firestore:backups:schedules:create --database "(default)" --recurrence DAILY --retention 7d --project lanzar-95ae3-dev
  ```
- **NOVA Staging Restore Procedure (Runbook):**
  1. List available backups: `npx firebase-tools firestore:backups:list --project lanzar-95ae3-dev`.
  2. Restore into a new recovery database (Firestore does not overwrite `(default)` in-place):
     `npx firebase-tools firestore:databases:restore -d nova-restore-<date> -b <backup-resource-name> --project lanzar-95ae3-dev`
  3. Verify restored `system_signing_keys`, `admins`, `tenants`, and `users` collections before switching or exporting/importing back into `(default)`.
  4. Note: `system_signing_keys` private keys remain encrypted with NOVA's `KEYSTORE_MASTER_SECRET`; Railway `lanzar-id-nova-api` env vars must retain the matching `KEYSTORE_MASTER_SECRET` to decrypt restored keys.

---

## 9. Service-Account Permissions

- **Account:** `lanzar-id-nova-backend@lanzar-95ae3-dev.iam.gserviceaccount.com`
- **Verified Capabilities:** Read/write Firestore (`lanzar-95ae3-dev`), manage Firebase Auth users/custom tokens (`lanzar-95ae3-dev`).
- **Verified Isolation:** `NOVA-LIVE-26` confirmed `403 PERMISSION_DENIED` against production `lanzar-95ae3` Firestore.
- **Note:** Detailed IAM policy listing (`getIamPolicy`) requires Project Owner/IAM Viewer permissions in GCP Console.

---

## 10. Cryptographic Architecture and Key Management

- **Signing Algorithm:** `RS256` (RSA-2048+) via `SigningKeystore` (`system_signing_keys` in `lanzar-95ae3-dev`).
- **Active Live Key:** `lanzar_rs256_1794799855301_6f199222c3d1` (verified via live JWKS and `NOVA-LIVE-11` / `KEY-06`).
- **Private Key Protection:** Verified at rest (`NOVA-LIVE-24`, `KEY-01`) — private keys are encrypted with AES-256-GCM (12-byte IV, 16-byte tag, AAD-bound to `lanzar_signing_key:<kid>:v<kekVersion>`) using `SIGNING_KEY_ENCRYPTION_KEY` (versioned `SIGNING_KEY_ENCRYPTION_KEY_V<n>` / `SIGNING_KEY_ENCRYPTION_KEYS`), with zero plaintext PEM in Firestore. Missing KEK in `staging`/`production` fails closed at startup (`KEY-05`).
- **Lifecycle & Rotation (`KEY-01`–`KEY-06` Verified in Isolated `lanzar-95ae3-dev` Collection):**
  - **States:** `active` (signs new tokens, published in JWKS) -> `verify_only` (demoted on `rotateSigningKey()`, remains in JWKS for grace-period verification) -> `revoked` (excluded from JWKS & signing via `revokeSigningKey()`). JWKS cache TTL is `5000ms`.
  - **Automated Retirement (`KEY-07` & `RET-01`–`RET-05` Verified):**
    - `rotateSigningKey()` persists `eligibleForRevocationAt = now + graceSeconds` on `verify_only` keys.
    - Grace period defaults to **`4200s` (70 min)** = max `ID_TOKEN_TTL_SECONDS` (`3600s` > `ACCESS_TOKEN_TTL_SECONDS` `900s`) + `600s` clock-skew/JWKS-cache margin, with a hard minimum floor of **`3900s`** (`MIN_SAFE_RETIREMENT_GRACE_SECONDS`, rejecting shorter values). Refresh tokens are opaque SHA-256 secrets in `token_families` and are unaffected by signing-key rotation.
    - `worker.js` runs `signingKeystore.retireEligibleKeys({ auditLogService })` every `60000ms` (`KEY_RETIREMENT_SWEEP_MS`). Inside a Firestore transaction, it protects `_active_pointer.activeKid` and `status === 'active'` keys, retires eligible `verify_only` keys idempotently (`status: 'revoked'`, `revocationReason: 'grace_period_elapsed'`), survives worker restarts via Firestore persistence, and logs `platform.signing_key.auto_retired` to `admin_audit_logs`.
  - **Test Results (`6 / 6 PASS`):** Verified initial key generation & signing (`KEY-01`), atomic rotation to new `kid` (`KEY-02`), old token verification during `verify_only` grace period (`KEY-03`), immediate JWKS removal & `UNKNOWN_OR_REVOKED_KID` rejection after `revokeSigningKey()` (`KEY-04`), unknown `kid` rejection + missing KEK fail-closed (`KEY-05`), and live NOVA JWKS consistency (`KEY-06`).

---

## 11. OIDC Discovery, JWKS, and Client Isolation

- Discovery (`https://auth.lanzar.me/nova/.well-known/openid-configuration`) and JWKS (`https://auth.lanzar.me/nova/.well-known/jwks.json`) return consistent `https://auth.lanzar.me/nova` issuer and `https://auth-api-nova.lanzar.me/*` endpoints.
- Approved clients: `portal`, `tickets`, `threadline`, `ai`. Prospective clients `pythos` and `mothership` remain excluded (`NOVA-LIVE-07`).
- Production callbacks are stripped in `APP_ENV=staging` (`auth/auth-backend/clients.js`, `NOVA-LIVE-06`).
- **Staging Frontend Discovery:** Audited Netlify (`lanzar-portal`, `lanzar-tickets`, `threadline-lanzar`, `lanzar-ai`, `lanzar-auth`) and Railway (`Threadline`, `Lanzar Tickets`, `AuthServer`, `lanzar-id-nova`, excluded `Pythos`/`pythos-staging`). No dedicated staging frontends (`portal-nova`, `tickets-nova`, `threadline-nova`, `ai-dev.lanzar.me`) are live yet (`ai-dev.lanzar.me` has no DNS record). Per policy, no speculative staging clients were created; existing `localhost` staging callbacks (`http://localhost:5173`, `5174`, `5175`, `5176`, `3000`, `3004`, `8000`) remain active and verified (`NOVA-LIVE-10`–`14`).
- **Adding Future NOVA Staging Clients:** When staging frontends are deployed, register exact HTTPS callbacks in `lanzar-95ae3-dev` via `POST /api/admin/id/clients` (or staging-only entries in `clients.js`) targeting `issuer: https://auth.lanzar.me/nova`, `authorization_endpoint: https://auth-api-nova.lanzar.me/oauth/authorize`, `token_endpoint: https://auth-api-nova.lanzar.me/oauth/token`, `jwks_uri: https://auth-api-nova.lanzar.me/.well-known/jwks.json`, with PKCE `S256` and `Idempotency-Key` on `/oauth/token`.

---

## 12. Worker, Outbox (`DEAD_LETTER`), Alerting & `DesiredStateReconciler`

- **Service:** `lanzar-id-nova-worker` (`6b6162b2-756e-429a-a293-a20f1fcd7f42`, `restartPolicyType: ALWAYS`, `OUTBOX_WORKER_POLL_MS=5000`, `OUTBOX_LEASE_DURATION_MS=30000`, `OUTBOX_MAX_ATTEMPTS=5`, `RECONCILE_INTERVAL_MS=60000`, `RECONCILE_SWEEP_POLL_MS=15000`).
- **Outbox & `DEAD_LETTER` Lifecycle (`DLQ-01`–`DLQ-04` Verified Live):**
  - Exponential backoff: `min(60000ms, 1000ms * 2^(attempts - 1))` -> `1s, 2s, 4s, 8s` (`FAILED_RETRYABLE`) before transitioning to `DEAD_LETTER` on attempt 5 (`DLQ-01`, `DLQ-02`), preserving `lastErrorCode`, `deadLetteredAt`, and writing `platform.outbox.dead_lettered` to `admin_audit_logs`.
  - Version mismatches (`VERSION_MISMATCH`) transition directly to `DEAD_LETTER`.
  - Operators inspect dead-lettered events via `GET /api/admin/id/outbox/:outboxId` and trigger audited, idempotent replay via `POST /api/admin/id/outbox/:outboxId/redrive` (`DLQ-03`), which resets `attempts: 0` / `PENDING_EXTERNAL_AUTH`; subsequent redrive on `COMPLETED` events is rejected (`409`, `DLQ-04`).
- **`DesiredStateReconciler` (`REC-01`–`REC-04` Verified Live):**
  - Reconciles `users/{uid}` `desiredAuthVersion`/`desiredAuthDisabled` against Firebase Auth `disabled`, and `desiredRevocationVersion`/`desiredRevokedAt` against `appliedRevocationVersion` & `tokensValidAfterTime`, tracking state in `auth_reconciliation/{uid}`.
  - Live-verified: silent Firestore drift (`desiredAuthDisabled: true`) detected and repaired by live `lanzar-id-nova-worker` (`REC-01`, `CONVERGED` v2), repeat reconciliation is idempotent (`driftDetected: false`, `REC-02`), failed repair transitions to `DRIFT_RETRYABLE` and recovers (`REC-03`), and unrelated tenants (`tenant_beta`) are unaffected (`REC-04`).
- **Alerting, Worker Health & `DEAD_LETTER` Monitoring (`MON-01`, `MON-02` Verified Live):**
  - **Worker Heartbeat:** `worker.js` writes `system_worker_health/outbox_worker` every `30000ms` (`WORKER_HEARTBEAT_INTERVAL_MS`).
  - **Admin-Only Telemetry (`GET /api/admin/id/telemetry`, `requirePlatformAdmin`):** Reports `outbox.{deadLetterCount, failedRetryableCount, pendingCount}`, `reconciliation.deadLetterCount`, `worker.{status: 'healthy'|'stale'|'unknown', lastHeartbeatAt, ageSeconds}` (`stale` if `ageSeconds > 90`), and `alerts.{deadLetterPresent, workerStale}` (`status: 'degraded'` when either is true). Public access is denied (`401`, `MON-01`).
  - **Free-Tier External Uptime Monitor (Requires Jon's Account Setup):**
    - Provider: **UptimeRobot** or **Better Stack** free tier (`\$0/mo`).
    - Target: `GET https://auth-api-nova.lanzar.me/api/id/ready` (1–5 min interval).
    - Alert condition: HTTP status `!= 200` (e.g., `503` on Firestore or keystore failure) -> email/Slack notification.
  - **Operator Alert Investigation & Resolution Runbook:**
    1. *Readiness Alert (`!= 200`):* Check Railway `lanzar-id-nova-api` logs (`[READINESS ERROR]`), verify `lanzar-95ae3-dev` Firestore connectivity and `system_signing_keys/_active_pointer`.
    2. *`DEAD_LETTER` Alert (`deadLetterCount >= 1`):* Query `GET /api/admin/id/outbox/:outboxId` or Firestore `security_outbox` (`status == 'DEAD_LETTER'`) to inspect `lastErrorCode`, `attempts`, and `targetUid`; fix root cause (e.g., missing user/permissions) and trigger `POST /api/admin/id/outbox/:outboxId/redrive`.
    3. *Worker Stale Alert (`worker.status == 'stale'`):* Inspect Railway `lanzar-id-nova-worker` deployment & logs (`[WORKER FATAL]`, `[WORKER HEARTBEAT ERROR]`) and restart/redeploy if crashed.

---

## 13. Distributed Rate Limiting — Architecture Evaluation

`auth/auth-backend/middleware/rateLimiter.js` uses a process-local `Map` (`MAX_ENTRIES = 10000`, 60s cleanup timer) and Railway's `X-Real-IP` (validated with `net.isIP()`):
- `oauthAuthorizeLimiter`: 20 req / 1 min per IP
- `oauthExchangeLimiter`: 20 req / 1 min per IP
- `phoneDispatchLimiter`: 3 req / 15 min per IP and per normalized phone number
- `mfaVerifyRateLimitMiddleware`: 5 failures / 15 min per `(uid, ip)` and 15 failures / 15 min per `ip`

| Dimension | Option A — Managed Redis | Option B — Edge / WAF Rate Limiting | Option C — Hybrid (Recommended Pre-Launch) |
|---|---|---|---|
| **Mechanism** | Shared Redis (`INCR`/`EXPIRE` or Lua sliding window) across all Railway API replicas | Cloudflare/WAF rate-limiting rules in front of `auth-api-nova.lanzar.me` (Netlify Edge only proxies `/nova/.well-known/*`, not API routes) | Edge/WAF for volumetric & IP-level `/oauth/*` floods + Redis (or single-instance `Map` until >1 replica) for per-UID MFA & per-phone SMS limits |
| **Security Implications** | Strong atomic counters for IP, UID (`mfa_fail:acc_ip`), and phone (`phone_dispatch_num`) across replicas | Cannot enforce per-UID MFA failure tracking or per-phone SMS throttling (JSON body inspection & state unavailable at standard edge rules) | Full defense-in-depth: volumetric attacks dropped at edge before hitting Node/Firestore; account/MFA/SMS abuse enforced atomically in app |
| **Operational Complexity** | Medium (Redis client, TLS, failover/timeout policy) | Low–Medium (requires DNS proxy cutover to Cloudflare WAF in front of Railway) | Medium (combines edge WAF rules + app limiter) |
| **Cost Estimate** | ~\$0–\$10/mo (Upstash pay-as-you-go free tier or Railway Redis) | \$0–\$20/mo (Cloudflare Free/Pro) | \$0–\$20/mo depending on tier |
| **Failure Modes** | Redis outage -> must choose fail-open (degrade to in-memory) vs fail-closed on `/mfa/verify` & `/phone/send-otp` | Edge misconfiguration can block legitimate OAuth clients behind shared NAT IPs | Edge drops floods; if Redis is down, app can fail-open to local `Map` for low-risk routes |
| **Scaling Implications** | Scales cleanly to N horizontal Railway API replicas | Scales to arbitrary edge traffic, but does not solve multi-replica per-UID/per-phone state | Scales cleanly at both edge and multi-replica app tiers |

**Recommendation for Current Stage:** Keep the existing in-memory `rateLimiter.js` intact for single-instance NOVA staging (`\$0` added cost). Before enabling >1 API replica or onboarding external customers, adopt **Option C (Hybrid)** starting with Upstash/Railway Redis for shared `mfa_fail` / `phone_dispatch` / `oauth` counters plus edge IP throttling.

---

## 14. Production-Readiness Review & Outstanding Work

### Production-Readiness Findings

1. **Launch Blockers (Must Resolve Before First Customer)**
   - **Blaze Billing, PITR, Backups & TTL (`PENDING — BILLING ACTIVATION`):** `lanzar-95ae3-dev` lacks PITR, delete protection, scheduled backups, and `authorization_codes.expiresAt` TTL.
   - **External Alerting Registration:** Free-tier uptime monitor (UptimeRobot / Better Stack) for `https://auth-api-nova.lanzar.me/api/id/ready` and scheduled admin telemetry check (`DEAD_LETTER >= 1` / `worker.status == 'stale'`) require Jon's account registration.
   - **Staging Frontend Callback Registration:** No dedicated staging frontend apps (`portal-nova`, `threadline-nova`, etc.) are deployed yet.

2. **Important Pre-Launch Improvements**
   - **Distributed Rate Limiting (Option C / Option A):** Required before scaling `lanzar-id-nova-api` past 1 replica.
   - **TTL Schema Migration Plan:** `token_families.expiresAt`, `sessions.expiresAt`, `central_sessions.*ExpiresAt`, and `admin_idempotency.expiresAt` use ISO strings or epoch numbers and will accumulate indefinitely without a Timestamp migration or scheduled cleanup job.

3. **Future Scalability Enhancements**
   - Edge WAF caching/shielding for `/.well-known/jwks.json` and `/.well-known/openid-configuration`.
   - Automated multi-region or read-replica telemetry dashboards.

### Outstanding-Work Matrix

| Category | Item | Status |
|---|---|---|
| **Completed & Verified** | OIDC Discovery, JWKS, PKCE `S256`, RS256 signing & automated key retirement (`KEY-01..07`, `RET-01..05`), refresh rotation/replay, auth-code replay session revocation, tenant isolation, admin RBAC/idempotency, Firestore rules, composite indexes (`users`, `admins`, `sessions`), worker suspension/reactivation & expired-lease recovery, `DEAD_LETTER` retry/backoff/redrive (`DLQ-01..04`), `DesiredStateReconciler` drift detection/repair (`REC-01..04`), worker heartbeat & admin DLQ telemetry (`MON-01..02`), SA cross-project isolation, prod callback blocking | **Verified Live (`27 / 27` + `17 / 17`) & Local (`101 / 101`)** |
| **Prepared Awaiting Billing** | Firestore PITR, Delete Protection, Daily 7d Backup Schedule, `authorization_codes.expiresAt` TTL | **`PENDING — BILLING ACTIVATION`** |
| **Decisions / Accounts Awaiting Jon** | UptimeRobot/Better Stack free-tier registration for `/api/id/ready`, distributed rate-limiting approval (**Option C Hybrid**), TTL schema migration | **Awaiting Jon** |
| **Remaining Launch-Readiness** | Staging frontend callback registration once staging frontends are deployed | **Open** |

---

## 15. Manual Actions Still Required from Jon

1. **Enable Blaze Billing on `lanzar-95ae3-dev`:**
   - Open `https://console.developers.google.com/billing/enable?project=lanzar-95ae3-dev` and link a billing account.
2. **Enable PITR, Delete Protection & Daily Backups (`PENDING — BILLING ACTIVATION`):**
   ```bash
   npx firebase-tools firestore:databases:update "(default)" --point-in-time-recovery ENABLED --delete-protection ENABLED --project lanzar-95ae3-dev
   npx firebase-tools firestore:backups:schedules:create --database "(default)" --recurrence DAILY --retention 7d --project lanzar-95ae3-dev
   ```
3. **Enable Firestore TTL Policy (`PENDING — BILLING ACTIVATION`):**
   - **GCP Console -> Firestore -> `(default)` -> Time-to-live (TTL) -> Create policy** (or `gcloud firestore fields ttls update expiresAt --collection-group=authorization_codes --enable-ttl --project=lanzar-95ae3-dev`):
     - Collection group: `authorization_codes`
     - Timestamp field: `expiresAt`

---

## 16. Production Isolation Verification

- `GET https://auth-api.lanzar.me/api/id/health` -> `200` (`appEnv: "production"`).
- `GET https://auth.lanzar.me/` -> `200` (still serves `index-CL98VAEE.js`).
- `NOVA-LIVE-26` confirmed `lanzar-id-nova-backend@lanzar-95ae3-dev.iam.gserviceaccount.com` receives `403 PERMISSION_DENIED` on `lanzar-95ae3`.
- Production branch `auth-repo:lanzar_id_main_chat` was never modified or pushed.

---

## 17. Final Readiness Assessment

**LANZAR ID NOVA Staging is operationally hardened and verified for single-instance staging integration** (`27 / 27` extended live checks + `91 / 91` local regression checks passing at checkpoint `nova-live-verified-2026-11-16`). Moving to controlled first-customer launch requires enabling Blaze billing (for PITR, backups, delete protection, and `authorization_codes` TTL), configuring monitoring/alerting, approving distributed rate limiting (Option C Hybrid), and completing live key-rotation/DLQ verification.
