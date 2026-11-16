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
- **TTL Policy Analysis (Derived from Code):**
  - `oauth_codes.expiresAt` (`auth/auth-backend/store.js:604,630`): Stored as a JS `Date` (Firestore `Timestamp`) -> **compatible with Firestore native TTL**.
  - `admin_idempotency.expiresAt` (`adminRoutes.js:269,517`) & `users/{uid}/sessions.expiresAt` (`sessionService.js:80`): Stored as ISO-8601 strings; `users/{uid}/central_sessions` (`centralSessionService.js:64-65`): Stored as numeric epoch seconds. Native Firestore TTL ignores non-Timestamp fields; converting those to Firestore `Timestamp` in a future schema pass would allow native TTL cleanup there as well.
- **Security Rules:** `firestore.rules` compiled and deployed on `lanzar-95ae3-dev`; live-verified via `NOVA-LIVE-17` (`403` on direct client reads of `admins`, `system_signing_keys`, `security_outbox`).

---

## 8. Backup, PITR, and Recovery Configuration

- Current state of `projects/lanzar-95ae3-dev/databases/(default)`:
  - `Point In Time Recovery`: `POINT_IN_TIME_RECOVERY_DISABLED`
  - `Delete Protection State`: `DELETE_PROTECTION_DISABLED`
  - `Backup Schedules`: None
- **Blocker:** Running `firebase firestore:databases:update` returned HTTP `403`: *"This API method requires billing to be enabled. Please enable billing on project lanzar-95ae3-dev."* PITR, scheduled backups, and native TTL policies all require the Firebase **Blaze (pay-as-you-go)** plan.

---

## 9. Service-Account Permissions

- **Account:** `lanzar-id-nova-backend@lanzar-95ae3-dev.iam.gserviceaccount.com`
- **Verified Capabilities:** Read/write Firestore (`lanzar-95ae3-dev`), manage Firebase Auth users/custom tokens (`lanzar-95ae3-dev`).
- **Verified Isolation:** `NOVA-LIVE-26` confirmed `403 PERMISSION_DENIED` against production `lanzar-95ae3` Firestore.
- **Note:** Detailed IAM policy listing (`getIamPolicy`) requires Project Owner/IAM Viewer permissions in GCP Console.

---

## 10. Cryptographic Architecture and Key Management

- **Signing Algorithm:** `RS256` via `SigningKeystore` (`system_signing_keys` in `lanzar-95ae3-dev`).
- **Active Key:** `lanzar_rs256_1794799855301_6f199222c3d1` (verified via live JWKS and `NOVA-LIVE-11`).
- **Private Key Protection:** Verified at rest (`NOVA-LIVE-24`) — private key material is encrypted with NOVA's dedicated `KEYSTORE_MASTER_SECRET`, with zero plaintext PEM stored in Firestore.

---

## 11. OIDC Discovery, JWKS, and Client Isolation

- Discovery (`https://auth.lanzar.me/nova/.well-known/openid-configuration`) and JWKS (`https://auth.lanzar.me/nova/.well-known/jwks.json`) return consistent `https://auth.lanzar.me/nova` issuer and `https://auth-api-nova.lanzar.me/*` endpoints.
- Approved clients: `portal`, `tickets`, `threadline`, `ai`. Prospective clients `pythos` and `mothership` remain excluded (`NOVA-LIVE-07`).
- Production callbacks are stripped in `APP_ENV=staging` (`auth/auth-backend/clients.js`, `NOVA-LIVE-06`).
- **Adding Future NOVA Staging Clients:** When staging frontends (e.g., `https://portal-nova.lanzar.me`) are provisioned, register them in `lanzar-95ae3-dev` via `POST /api/admin/id/clients` (using `ClientRegistryService` with exact HTTPS callback URIs) or add staging-only URIs to `clients.js` without modifying production `lanzar-95ae3` or `auth-repo:lanzar_id_main_chat`.

---

## 12. Worker and Outbox Reliability

- `lanzar-id-nova-worker` (`6b6162b2-756e-429a-a293-a20f1fcd7f42`, `restartPolicyType: ALWAYS`) actively polls `security_outbox` and `DesiredStateReconciler`.
- Live-verified:
  - Immediate suspension (`disabled=true`) and reactivation (`disabled=false`) propagation to Firebase Auth (`NOVA-LIVE-20`, `NOVA-LIVE-21`).
  - Expired `IN_PROGRESS` lease recovery (`NOVA-LIVE-22`).

---

## 13. Known Limitations and Unresolved Risks

1. **Per-Instance Rate Limiting (`auth/auth-backend/middleware/rateLimiter.js`):**
   - Uses a process-local `Map` (`MAX_ENTRIES = 10000`) for `oauthAuthorizeLimiter`, `oauthExchangeLimiter`, `phoneDispatchLimiter`, and `mfaVerifyRateLimitMiddleware`.
   - **Limitation:** Acceptable while `lanzar-id-nova-api` runs as a single Railway replica, but **not distributed** across horizontal replicas.
   - **Options & Recommendation:**
     - *Option A (Recommended for Production/Multi-Replica):* Provision managed Redis (e.g., Upstash / Railway Redis) and swap `rateLimitStore` for an atomic Redis sliding-window/Lua script store.
     - *Option B (Edge Layer):* Enforce IP-based rate limiting at Cloudflare / WAF in front of `auth-api-nova.lanzar.me` / `auth-api.lanzar.me`, keeping in-memory per-UID MFA throttling or pairing with Redis.
     - *Not Recommended:* Using Firestore per-request for rate limiting (adds latency, cost, and hot-document contention).
2. **Firestore Blaze-Dependent Features:** PITR, Delete Protection, Daily Backup Schedules, and `oauth_codes.expiresAt` TTL are blocked until billing is enabled on `lanzar-95ae3-dev`.

---

## 14. Manual Actions Still Required from Jon

1. **Enable Blaze Billing on `lanzar-95ae3-dev`:**
   - Open `https://console.developers.google.com/billing/enable?project=lanzar-95ae3-dev` and link a billing account.
2. **Enable PITR, Delete Protection & Daily Backups (once Blaze is active):**
   - Either run:
     ```bash
     npx firebase-tools firestore:databases:update "(default)" --point-in-time-recovery ENABLED --delete-protection ENABLED --project lanzar-95ae3-dev
     npx firebase-tools firestore:backups:schedules:create --recurrence DAILY --retention 7d --project lanzar-95ae3-dev
     ```
   - Or in **GCP Console -> Firestore -> `(default)` -> Settings / Backups**: enable **Point-in-time recovery**, **Delete protection**, and a **Daily** backup schedule (7-day retention).
3. **Enable Firestore TTL Policy:**
   - **GCP Console -> Firestore -> `(default)` -> Time-to-live (TTL) -> Create policy**:
     - Collection group: `oauth_codes`
     - Timestamp field: `expiresAt`

---

## 15. Production Isolation Verification

- `GET https://auth-api.lanzar.me/api/id/health` -> `200` (`appEnv: "production"`).
- `GET https://auth.lanzar.me/` -> `200` (still serves `index-CL98VAEE.js`).
- `NOVA-LIVE-26` confirmed `lanzar-id-nova-backend@lanzar-95ae3-dev.iam.gserviceaccount.com` receives `403 PERMISSION_DENIED` on `lanzar-95ae3`.
- Production branch `auth-repo:lanzar_id_main_chat` was never modified or pushed.

---

## 16. Final Readiness Assessment

**LANZAR ID NOVA Staging is operationally hardened and verified for staging integration.** All 27 extended live checks and 91 local regression checks pass after the final code change, production is completely isolated and untouched, and only Blaze-gated GCP Console settings (PITR, Delete Protection, Daily Backup Schedule, and `oauth_codes` TTL) remain for manual activation.
