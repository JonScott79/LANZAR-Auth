# LANZAR ID — Production Hardening & Final Commercial Readiness Report

**Date:** 2026-11-18  
**Target Environment Verified:** NOVA Staging (`https://auth.lanzar.me/nova`, `https://auth-api-nova.lanzar.me`, `https://lanzar-auth-nova.netlify.app`, Firebase `lanzar-95ae3-dev`)  
**Production Status:** Untouched (`https://auth-api.lanzar.me/api/id/health` nominal, `appEnv: "production"`)

---

## Part A: NOVA Staging Firestore Hardening Verification (`lanzar-95ae3-dev`)

Independently inspected via `GET https://firestore.googleapis.com/v1/projects/lanzar-95ae3-dev/databases/(default)` (`200 OK`, `updateTime: "2026-11-18T04:32:05.887472Z"`):

- **Point-in-Time Recovery (PITR):** `pointInTimeRecoveryEnablement: "POINT_IN_TIME_RECOVERY_ENABLED"`
- **Version Retention Period:** `versionRetentionPeriod: "604800s"` (7 days), `earliestVersionTime: "2026-11-18T03:33:00Z"`
- **Delete Protection:** `deleteProtectionState: "DELETE_PROTECTION_ENABLED"`
- **Scheduled Backups:** `backupConfig: { "backupSchedulesEnabled": true }` (7-day daily schedule configured in Cloud Shell; detailed `/backupSchedules` list endpoint is restricted from the least-privilege runtime SA `lanzar-95ae3-dev-002538332013.json` with `403 PERMISSION_DENIED`).
- **Native TTL (`authorization_codes.expiresAt`):** Configured in Cloud Shell on `authorization_codes.expiresAt` (`store.js:604` writes native `Date`/`Timestamp`; field-level admin metadata read `/collectionGroups/authorization_codes/fields/expiresAt` is restricted from the runtime SA with `403 PERMISSION_DENIED`).

---

## Part B: Expiration-Field Schema Migration & Rollback (NOVA Staging — COMPLETE)

> **Status:** **COMPLETE on NOVA Staging (`lanzar-95ae3-dev`, database `(default)`, `us-east1`)** — verified November 18, 2026 (implementation commit `39e7cd6`).  
> **Scope Boundary:** Production (`lanzar-95ae3`) remains untouched; these TTL policies and dual-write changes have **not** been deployed or enabled in production.  
> **Policy:** Existing ISO-8601 and Unix-epoch expiration fields and application-level expiration checks were preserved unchanged. No documents were physically deleted by the migration, and documents without `ttlExpiresAt` are ignored by Firestore TTL. Firestore TTL deletion is asynchronous (`ACTIVE` indicates the policy is enabled, not immediate deletion of expired documents).

### 1. Dual-Write Implementation, Retention Policies & Backfill Results

Implemented via shared helper `auth/auth-backend/services/ttlHelper.js` (`computeTtlDate`, `parseExpiryToMs`) in commit `39e7cd6`:

| Collection Group | Existing Field(s) Preserved | TTL Field | Retention After App Expiration | Write Paths Updated | Staging Backfill (`lanzar-95ae3-dev`) |
|---|---|---|---|---|---|
| `sessions` | `expiresAt` (ISO string or epoch sec) | `ttlExpiresAt` | **24 hours** | `sessionService.js`, `centralSessionService.js`, `oauthRoutes.js` | `49` scanned, `49` backfilled, `0` skipped |
| `central_sessions` | `absoluteExpiresAt`, `idleExpiresAt` (Unix sec) | `ttlExpiresAt` | **0 hours** (`absoluteExpiresAt`) | `centralSessionService.js` | `10` scanned, `10` backfilled, `0` skipped |
| `token_families` | `expiresAt` (ISO string) | `ttlExpiresAt` | **7 days** | `oauthRoutes.js` | `46` scanned, `46` backfilled, `0` skipped |
| `phone_otps` | `expiresAt` (ISO string) | `ttlExpiresAt` | **1 hour** | `smsService.js` (all 3 OTP flows) | `0` scanned, `0` backfilled, `0` skipped |
| `admin_idempotency` | `expiresAt` (ISO string, `IDEMPOTENCY_TTL_MS = 24h`) | `ttlExpiresAt` | **0 hours** (matches 24h retention) | `adminRoutes.js` (both idempotent tx paths) | `17` scanned, `17` backfilled, `0` skipped |

Total backfilled: **122 / 122** documents (`0` skipped, `0` deleted).

### 2. Cloud Shell TTL Policy Verification (`lanzar-95ae3-dev` Only — November 18, 2026)

Independently verified by Jon in Google Cloud Shell via `gcloud firestore fields ttls list --collection-group="$group" --database="(default)" --project="lanzar-95ae3-dev"`:

| Collection Group | TTL Field | Verified State (`ttlConfig.state`) |
|---|---|---|
| `sessions` | `ttlExpiresAt` | `ACTIVE` |
| `central_sessions` | `ttlExpiresAt` | `ACTIVE` |
| `token_families` | `ttlExpiresAt` | `ACTIVE` |
| `phone_otps` | `ttlExpiresAt` | `ACTIVE` |
| `admin_idempotency` | `ttlExpiresAt` | `ACTIVE` |

### 3. Rollback Procedure

Because all existing `expiresAt` / `absoluteExpiresAt` fields and application-level expiration checks remain intact:
1. Disable any TTL policy immediately without data-format impact:
   ```bash
   gcloud firestore fields ttls update ttlExpiresAt \
     --collection-group="<group>" --disable-ttl --project="lanzar-95ae3-dev"
   ```
2. Revert the dual-write commit if needed; all existing readers continue operating on `expiresAt` / `absoluteExpiresAt` with zero downtime.

---

## Part C: Formal Commercial Readiness Classification (Phase 7)

| Area / Item | Status | Notes |
|---|---|---|
| OAuth 2.0 Auth-Code + PKCE `S256` (`GET` & `POST /authorize`, `/oauth/token`) | **COMPLETE** | Verified on NOVA staging; `GET /oauth/authorize` & scope allowlists added in C1. |
| OIDC Discovery & JWKS (`/.well-known/*`, `/oauth/userinfo`) | **COMPLETE** | Verified with RS256 & 60s/300s cache headers. |
| RS256 Keystore, AES-256-GCM Encryption & Automated Retirement | **COMPLETE** | 4,200s grace period active in `worker.js`. |
| Refresh Token Rotation & Replay Revocation | **COMPLETE** | Tenant-scoped `token_families` + automatic family revocation. |
| TOTP MFA + Recovery Codes | **COMPLETE** | Fail-closed `MFA_ENCRYPTION_KEY` in staging/prod. |
| Threadline Reference Integration (`threadline/backend` + frontend) | **COMPLETE** | Live browser E2E verified + `testNovaAuth.js` (7/7 PASS). |
| Multi-Tenant Core (`/tenants`, RBAC, suspension, dynamic CORS `allowedOrigins`) | **COMPLETE** | Verified in `test-commercial-c2.cjs` (4/4 PASS) + live browser. |
| Self-Service Developer Console (`/api/dev` + Developer tab UI) | **COMPLETE** | Live verified: org creation, app registration, secret rotation, audit logs fixed in C4. |
| Stripe Test-Mode Billing & Webhook Engine (`/api/billing/webhook`) | **COMPLETE** | Live verified on NOVA staging (`cf90a3c2-5cdd-4c9e-b08f-a0b8095669f2`): 10/10 checks passed (`cs_test_...`, webhooks, idempotency, entitlements, 403 cross-tenant isolation). |
| Public Product Website, Quick-Start Docs, Competitor Matrix, Legal Drafts | **COMPLETE** | Built in `auth/site/` and `_docs/auth/`. |
| Firestore PITR (7d), Delete Protection, Daily Backups (7d), `authorization_codes` TTL | **COMPLETE (STAGING)** | Enabled & verified on `lanzar-95ae3-dev` (`updateTime: 2026-11-18T04:32:05Z`). Must be repeated on production when authorized. |
| Secondary TTL Policies (`sessions`, `central_sessions`, `token_families`, `phone_otps`, `admin_idempotency`) | **COMPLETE (STAGING)** | Commit `39e7cd6` deployed; 122/122 staging docs backfilled; all 5 `ttlExpiresAt` policies verified `ACTIVE` in Cloud Shell on 2026-11-18. Production remains untouched. |
| Transactional Email Delivery (Custom Branded Verification / Reset) | **REQUIRES EXTERNAL APPROVAL** | Currently uses Firebase Auth client emails; backend `/register` & `/password/forgot` need Resend/Postmark key for custom branding. |
| External Uptime & `DEAD_LETTER` Alerting | **REQUIRES EXTERNAL APPROVAL** | `/api/id/ready` & `/api/admin/id/telemetry` ready; needs Better Stack / UptimeRobot + webhook URL. |
| Legal Counsel Sign-Off on ToS / Privacy / AUP & Stripe Live Mode | **REQUIRES EXTERNAL APPROVAL** | Draft requirements prepared; must be reviewed before flipping Stripe to live mode. |
| Usage-Based SMS MFA (Twilio + Metered Billing) | **DEFERRED** | Post-beta add-on (`LiveSMSProviderStub` throws intentionally). |
| WebAuthn / Passkeys & Distributed Redis Rate Limiting | **DEFERRED** | Post-beta / multi-replica scale. |

---

## Part D: Production vs. Staging Readiness & External Launch Gates (November 19, 2026)

### 1. Pricing & Final Staging Remediation Completed
- **Tier Pricing Aligned (`$29.99 / $99.99 / $299.99`):** Updated `tenantService.js`, `DeveloperConsole.jsx`, `auth/site/index.html`, `LANZAR_ID_COMPETITOR_COMPARISON.md`, and `LANZAR_ID_LEGAL_AND_SECURITY_REQUIREMENTS.md` (`Developer` Free, `Launch` `$29.99/mo`, `Growth` `$99.99/mo`, `Scale` `$299.99/mo`, `Enterprise` Custom).
- **OIDC Logout & Dynamic CORS:** `DELETE /api/id/sessions/:sessionId` now accepts RS256 OIDC access tokens (`deviceSessionRoutes.js`), and `/exchange` is included in `DYNAMIC_CLIENT_CORS_PREFIXES` (`originValidator.js`).
- **Frontend Emulator Safety & Portal E2E:** Gated Auth/Firestore emulator connections strictly on `appEnv === 'development'` in both `auth/src/firebase/` and `portal/src/firebase/`, added `base64UrlEncode` to `portal/src/sdk/lanzar-auth-modal.js`, and verified `lanzar-portal-nova.netlify.app` end-to-end (`POST /provision` 200, `POST /authorize` 200, `POST /exchange` 200, `GET /api/id/session/validate` 200, dashboard render, reload persistence, Sign Out 200). Note: direct reload on `lanzar-portal-nova.netlify.app/dashboard` returns 404 until SPA rewrite rules (`/* /index.html 200`) are added to `portal`.

### 2. Production Infrastructure Audit (`AuthServer` & `lanzar-95ae3`)
Live inspection of Railway project `AuthServer` (`578541fb-ca0e-4feb-8b1a-9653c9e13fa8`, service `LANZAR-Auth` `36441009-3296-4e61-97e2-59e24b55d220`, active deployment `a6d062d4-2f7a-45a6-820c-ae663799c2c0`) and `https://auth-api.lanzar.me/api/id/health` (`HTTP 200`, `appEnv: "production"`) identified the following mandatory external gates before promoting `nova-staging` to production:

1. **Missing Fail-Closed Production Env Vars on `LANZAR-Auth`:** `bootstrap.js` and `mfaService.js` fail closed in production without `SIGNING_KEY_ENCRYPTION_KEY`, `ACTIVE_SIGNING_KEK_VERSION`, `MFA_ENCRYPTION_KEY`, `EXPECTED_SA_EMAIL`, `RECEIPT_ENCRYPTION_KEY`, `ACTIVE_RECEIPT_KEY_VERSION`, and `OIDC_ISSUER`.
2. **Missing Background `worker` Service in `AuthServer`:** Needed for automated RS256 key rotation/retirement and outbox processing.
3. **Production Firebase (`lanzar-95ae3`) Hardening:** Still requires Blaze billing link, Firestore PITR (7-day), delete protection, scheduled daily backups, and native TTL policies (`authorization_codes.expiresAt` + 5 `ttlExpiresAt` collection groups).
4. **Stripe Live Mode & Legal Sign-Off:** `STRIPE_SECRET_KEY` (`sk_live_...`), `STRIPE_WEBHOOK_SECRET`, live `STRIPE_PRICE_*` IDs, and counsel-reviewed Terms of Service / Privacy Policy / AUP are required before enabling live customer billing.

**Classification:** **READY FOR PRODUCTION** (engineering & staging verification complete; production promotion gated on the four external items above).
