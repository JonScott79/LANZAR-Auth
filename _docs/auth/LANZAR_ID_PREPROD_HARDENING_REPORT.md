# LANZAR ID — Pre-Production Hardening Report

**Project:** LANZAR ID  
**Branch:** `lanzar_id_main_chat`  
**Baseline Commits Preserved:**  
- M1.4: `5fb79411e0bf94131f60fb38d1d57a906067b8d9`  
- M1.5: `80c1dec6760a604badaa06e87549ba67e97ef51c`  

**Scope:** Local implementation and verification of Pre-Production Hardening Priorities 1–10.  
**Deployment / Production Testing:** None executed. Zero changes deployed to staging or production, and zero tests run against production Firestore.

---

## 1. Firestore Security Rules (Priority 1)

Updated `firestore.rules` to explicitly deny all client-side (`read`, `write`, `create`, `update`, `delete`) access to every M1.1–M1.5 server-only collection and subcollection:

- `/oauth_authorization_codes/{codeHash}` — `allow read, write: if false;`
- `/authorization_codes/{codeHash}` — `allow read, write: if false;`
- `/compromised_ceremonies/{ceremonyId}` — `allow read, write: if false;`
- `/security_outbox/{eventId}` — `allow read, write: if false;`
- `/system_signing_keys/{kid}` — `allow read, write: if false;`
- `/clients_index/{clientId}` — `allow read, write: if false;`
- `/tenants/{tenantId}/clients/{clientId}` — `allow read, write: if false;`
- `/tenants/{tenantId}/token_families/{familyId}` — `allow read, write: if false;`
- `/tenants/{tenantId}/admin_audit_logs/{auditId}` — `allow read, create, update, delete: if false;`

Existing user/session rules remain intact (`/users/{uid}` allowlisted self-update on `displayName`; `/users/{uid}/sessions/{sessionId}` client-denied). Verified live against the Cloud Firestore Emulator in `auth/test-firestore-rules-emulator.cjs` (`3/3` passing).

---

## 2. Firestore TTL & Data Lifecycle Inventory (Priority 2)

Before staging/production cutover, configure Firestore TTL policies in GCP/Firebase for ephemeral and bounded-retention collections:

| Collection / Path | Purpose | Recommended TTL Field / Retention Policy |
| :--- | :--- | :--- |
| `oauth_authorization_codes/{codeHash}` | Short-lived OAuth/PKCE authorization codes & encrypted receipts | `expiresAt` (short-lived ceremony window; TTL auto-purge) |
| `authorization_codes/{codeHash}` | Legacy/M1.1 authorization codes | `expiresAt` (TTL auto-purge) |
| `compromised_ceremonies/{ceremonyId}` | Replay-detection tombstones for compromised auth ceremonies | Bounded retention TTL (e.g. `expiresAt` / 30 days) |
| `tenants/{tenantId}/token_families/{familyId}` | Refresh-token families & rotation state | `expiresAt` after family revocation/expiry |
| `users/{uid}/sessions/{sessionId}` | Child/central session records | `expiresAt` after session expiration/revocation |
| `security_outbox/{eventId}` | Durable outbox events | Retain pending; purge completed/acknowledged records after retention window |
| `tenants/{tenantId}/admin_audit_logs/{auditId}` | Immutable administrative audit trail | **Do not auto-purge via short TTL**; archive/export to cold storage per compliance retention |
| `system_signing_keys/{kid}` | RS256 JWKS signing keys (`active`, `verify_only`, `revoked`) | **No automatic TTL**; managed via explicit key rotation and revocation lifecycle |
| `clients_index/{clientId}`, `tenants/{tenantId}/clients/{clientId}` | OAuth client registry & tenant index | **No automatic TTL**; managed via admin lifecycle (`disableClient`/`enableClient`) |

---

## 3. Admin Authorization Consistency (Priority 3)

Updated `auth/auth-backend/routes/adminRoutes.js` (`createAdminRouter`):

- Added `requirePlatformAdmin` middleware enforcing `req.isAdmin === true`, `req.adminContext`, and `req.adminContext.isPlatformAdmin === true`.
- Tenant-scoped administrators (`tenant_admin`) are explicitly rejected with HTTP `403 FORBIDDEN`.
- Sensitive platform-admin mutations (user status update/suspend, founder grant, and revoke-all sessions) record immutable audit events via `AuditLogService.recordAuditEvent` (`recordPlatformAudit`).
- `auth/auth-backend/app.js` wires `auditLogService` into `createAdminRouter({ db, authAdmin, auditLogService })`.

Verified via `PPH-01` in `auth/test-preprod-hardening.cjs`.

---

## 4. Cryptographic & Environment Configuration Inventory (Priority 4)

Verified fail-closed behavior in `validateSigningKeyEncryptionConfiguration` (`auth/auth-backend/services/signingKeystore.js`) and `validateReceiptKeyConfiguration` (`auth/auth-backend/store.js`) when `NODE_ENV` or `APP_ENV` is `production` or `staging` (`PPH-03`):

| Variable | Required in Staging/Prod | Purpose | Notes |
| :--- | :--- | :--- | :--- |
| `APP_ENV` / `NODE_ENV` | Yes (`staging` or `production`) | Environment mode | Triggers fail-closed key & redirect URI enforcement |
| `SIGNING_KEY_ENCRYPTION_KEY` | Yes | AES-256-GCM KEK for `system_signing_keys` private keys | Rejects missing or known dev KEKs in staging/prod |
| `ACTIVE_SIGNING_KEK_VERSION` | Optional (default `1`) | Active KEK version for key rotation | Must be positive integer |
| `RECEIPT_ENCRYPTION_KEY` (or `RECEIPT_ENCRYPTION_KEY_V{n}`) | Yes | AES-256-GCM key for token receipts | Rejects missing or known dev keys in staging/prod (`TOKEN_RECEIPT_KEY` is non-prod only) |
| `ACTIVE_RECEIPT_KEY_VERSION` | Optional (default `1`) | Active receipt key version | Must be positive integer |
| `OIDC_ISSUER` | Recommended / Prod | Canonical OIDC `iss` claim & discovery issuer | Required for deterministic multi-instance discovery/JWT `iss` |
| `MFA_ENCRYPTION_KEY` | Yes (if MFA enabled) | MFA secret encryption | Provision via Secret Manager |
| `TRUST_PROXY` | Recommended behind LB | Express `trust proxy` setting | Needed for accurate client IP / `X-Forwarded-*` behind proxy |
| `PORT` / `HOST` | Runtime | HTTP bind address | Managed by hosting runtime |
| `SESSION_CACHE_TTL_MS` | Optional | Session cache TTL override | Defaults safely in code |
| `SMS_LIVE_ENABLED` | Optional | Live SMS toggle | Keep disabled unless SMS provider configured |
| `FIRESTORE_EMULATOR_HOST`, `FIREBASE_AUTH_EMULATOR_HOST` | **Forbidden in Prod/Staging** | Local emulator routing | Local test/dev only |

**Secret Hygiene:** No real secrets, keys, or credentials are stored in this document or in repository source files. Staging and production secrets must be injected via GCP Secret Manager / hosting secret store.

---

## 5. Operational Reliability & Rate-Limiter Caveats (Priority 5)

Implemented in `auth/auth-backend/app.js`:

- **`GET /api/id/ready`:** Performs live Firestore readiness probe and `signingKeystore.getPublicJwks({ bypassCache: true })` check; returns `200` (`{ status: 'ready', checks: { firestore: 'ok', signingKeystore: 'ok' } }`) when healthy, or sanitized `503` without leaking internal connection strings/errors when unavailable (`PPH-02`).
- **`X-Correlation-ID` Propagation:** Middleware reads incoming `x-correlation-id` (or generates a UUID) and sets `X-Correlation-ID` on every response (`req.correlationId`, `PPH-04`).
- **Sanitized Terminal Error Handler:** Express 4-arg error handler logs the internal error server-side with `correlationId` and returns sanitized JSON (`{ error: 'INTERNAL_SERVER_ERROR', correlationId }`) without stack traces or internal secrets.

**Distributed Rate-Limiter Caveat:**  
Current rate limiting in the Express backend is in-memory per process. In a multi-instance / autoscaled Cloud Run or serverless deployment, per-instance counters do not share state across instances. Before high-traffic production rollout, front public OAuth/auth endpoints (`/oauth/authorize`, `/oauth/token`, `/api/id/session/*`, `/api/admin/*`) with edge/WAF rate limiting (e.g., Cloud Armor / CDN WAF) or a shared Redis/Memorystore rate-limit store.

---

## 6. Backup, Recovery & Incident Response Runbook (Priority 6)

- **Firestore Backups & PITR:** Enable Firestore Point-in-Time Recovery (PITR) and scheduled daily exports to a locked GCS bucket before production launch.
- **RS256 Key Compromise / Rotation:**
  1. Generate and promote a new signing key via `SigningKeystore.rotateSigningKey()` (keeps prior key `verify_only` for zero-downtime rollover, or mark compromised key `revoked` immediately to reject all tokens signed by it).
  2. Rotate `SIGNING_KEY_ENCRYPTION_KEY` / `ACTIVE_SIGNING_KEK_VERSION` in Secret Manager if KEK exposure is suspected.
- **Receipt Key Rotation:** Provision `RECEIPT_ENCRYPTION_KEY_V{n+1}` and update `ACTIVE_RECEIPT_KEY_VERSION` while keeping `V{n}` readable until in-flight auth codes expire.
- **Tenant / User Incident Containment:**
  - Disable compromised OAuth client via `ClientRegistryService.disableClient()` (blocks new authorizations, refreshes, and UserInfo immediately).
  - Revoke user sessions / advance `tokenVersion` via platform admin endpoints.
  - Inspect `/tenants/{tenantId}/admin_audit_logs` and structured logs by `correlationId`.

---

## 7. Controlled Staging Smoke-Test Plan (Priority 9)

Execute only after deploying to an isolated staging project with Secret Manager keys and `firestore.rules` deployed:

1. **Readiness & Discovery:** `GET /api/id/health` -> `200`; `GET /api/id/ready` -> `200` (`checks.firestore === 'ok'`, `checks.signingKeystore === 'ok'`); `GET /.well-known/openid-configuration` -> valid `issuer` & `jwks_uri`.
2. **JWKS Verification:** `GET /oauth/jwks` -> returns RS256 public key(s) only, zero private key material.
3. **OIDC Authorization Code + PKCE Flow:** Run `/oauth/authorize` -> `/oauth/token` (`authorization_code`) -> `/oauth/userinfo` -> `/oauth/token` (`refresh_token`) for an approved staging client (`portal`, `tickets`, `threadline`, or `ai`).
4. **Tenant & Admin Isolation:** Confirm `tenant_admin` cannot access `/api/admin/id/*` (`403`) or another tenant's `/api/admin/tenants/:tenantId/clients` (`403`), while `platform_admin` succeeds and writes an audit log.
5. **Client Lifecycle:** Disable a test staging client -> confirm `/oauth/authorize`, `/oauth/token` (`refresh_token`), and `/oauth/userinfo` fail closed; re-enable -> confirm recovery.
6. **Firestore Rules:** Confirm unauthenticated/client SDK reads to `tenants/*/clients/*`, `system_signing_keys/*`, `oauth_authorization_codes/*`, and `tenants/*/admin_audit_logs/*` return `PERMISSION_DENIED`.

---

## 8. Local & Emulator Verification Results (Priority 10)

All tests below were executed locally against in-memory test harnesses and the local Cloud Firestore Emulator. **Zero production Firestore tests were run.**

| Suite | Environment | Result |
| :--- | :--- | :--- |
| `node auth/test-preprod-hardening.cjs` | Local Node / In-Memory | **5 / 5** passed |
| `node auth/test-firestore-rules-emulator.cjs` | Cloud Firestore Emulator (`127.0.0.1:8093`) | **3 / 3** passed |
| `node auth/test-milestone-1-5.cjs` | Local Node / In-Memory | **6 / 6** passed |
| `node auth/test-milestone-1-5-emulator.cjs` | Cloud Firestore Emulator (`127.0.0.1:8092`) | **3 / 3** passed |
| `node auth/test-milestone-1-4.cjs` | Local Node / In-Memory | **10 / 10** passed |
| `node auth/test-milestone-1-3.cjs` | Local Node / In-Memory | **7 / 7** passed |
| `node auth/test-milestone-1-2.cjs` | Local Node / In-Memory | **11 / 11** passed |
| `node auth/test-milestone-1-1.cjs` | Local Node / In-Memory | **44 / 44** passed |
| `node auth/test-phase1-acceptance.cjs` | Local Node / In-Memory | **55 / 55** passed |
| `node auth/test-client-registry.cjs` | Local Node / In-Memory | **9 / 9** passed |
| **Total** | **Local + Firestore Emulator** | **153 / 153** passed (0 failed) |

---

## 9. Remaining Pre-Deployment Items

- Provision staging/production secrets (`SIGNING_KEY_ENCRYPTION_KEY`, `RECEIPT_ENCRYPTION_KEY`, `MFA_ENCRYPTION_KEY`, `OIDC_ISSUER`) in GCP Secret Manager.
- Deploy `firestore.rules` and configure Firestore TTL policies + PITR/daily backups in GCP.
- Configure edge/WAF or shared-store rate limiting for multi-instance production scaling.
- Execute the Controlled Staging Smoke-Test Plan (Section 7) after staging deployment.
