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

## Part B: Expiration-Field Schema Migration Plan (Do Not Execute Until Reviewed)

> **Policy:** Do NOT enable Firestore TTL policies against ISO-8601 strings or numeric epoch values (Firestore TTL silently ignores non-`Timestamp` fields), and do NOT alter existing field types in-place without dual-format reader support.

### 1. Inventory of Non-Timestamp Expiration Fields

| Collection Group | Field(s) | Current Type | Write Locations | Read / Comparison Locations |
|---|---|---|---|---|
| `sessions` (`/users/{uid}/sessions/{sid}`) | `expiresAt` | ISO-8601 string | `sessionService.js:80,95`, `oauthRoutes.js:335,356` | `sessionService.js:30,177` (`parseExpiresAtMs`), `store.js:1851` (`toEpochMs`) |
| `central_sessions` (`/users/{uid}/central_sessions/{sid}`) | `absoluteExpiresAt`, `idleExpiresAt` | Unix epoch **seconds** (`number`) | `centralSessionService.js:64-65, 299-300` | `centralSessionService.js:150,153,283,286`, `sessionService.js:193-194` |
| `token_families` (`/tenants/{tid}/token_families/{fid}`) | `expiresAt` | Unix epoch **ms** (`number`) | `store.js:1733` | `store.js:1729,1754,1846` (`toEpochMs`) |
| `phone_otps` (`/phone_otps/{id}`) | `expiresAt` | ISO-8601 string | `smsService.js:169,278,309` | `smsService.js:220` (`new Date(otpData.expiresAt)`) |
| `admin_idempotency` (`/admin_idempotency/{key}`) | `expiresAt` | ISO-8601 string | `adminRoutes.js:269,517` | `adminRoutes.js` idempotency lookup |

### 2. Recommended Zero-Downtime Migration Strategy (Dual-Field `ttlExpiresAt` Pattern)

Rather than mutating the existing `expiresAt` / `absoluteExpiresAt` field types in-place (which risks breaking numeric comparisons like `now >= parent.absoluteExpiresAt` in `centralSessionService.js`), add a dedicated native Firestore `Timestamp` field named **`ttlExpiresAt`** on each document:

1. **Step 1 — Dual-Write (`ttlExpiresAt: Timestamp.fromMillis(...)`):**
   - Keep writing the existing `expiresAt` / `absoluteExpiresAt` field in its exact current format so all readers and tests remain 100% backwards-compatible.
   - Alongside it, write `ttlExpiresAt: new Date(expiryEpochMs)` (serialized by `@google-cloud/firestore` as a native Firestore `Timestamp`).
   - For `central_sessions`, set `ttlExpiresAt: new Date(absoluteExpiresAt * 1000)` (so Firestore only purges the document after the 30-day absolute lifetime expires, never prematurely on idle timeout).
   - For `sessions` and `token_families`, optionally add a 24h–7d post-expiry audit grace buffer to `ttlExpiresAt` so replay detection (`compromised_ceremonies` / `rotatedTokenHashes`) and recent revoked-session forensics remain inspectable before physical deletion.
2. **Step 2 — Backfill Existing Staging Documents:**
   - Run a one-time idempotent backfill script in `lanzar-95ae3-dev` that scans existing documents missing `ttlExpiresAt` and sets `ttlExpiresAt = Timestamp.fromMillis(parsedExpiresMs)`.
3. **Step 3 — Enable Firestore TTL Policies on `ttlExpiresAt`:**
   ```bash
   gcloud firestore fields ttls update ttlExpiresAt --collection-group=sessions --enable-ttl --project="$PROJECT_ID"
   gcloud firestore fields ttls update ttlExpiresAt --collection-group=central_sessions --enable-ttl --project="$PROJECT_ID"
   gcloud firestore fields ttls update ttlExpiresAt --collection-group=token_families --enable-ttl --project="$PROJECT_ID"
   gcloud firestore fields ttls update ttlExpiresAt --collection-group=phone_otps --enable-ttl --project="$PROJECT_ID"
   gcloud firestore fields ttls update ttlExpiresAt --collection-group=admin_idempotency --enable-ttl --project="$PROJECT_ID"
   ```

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
| Secondary TTL Policies (`sessions`, `central_sessions`, `token_families`, `phone_otps`, `admin_idempotency`) | **PENDING REVIEW** | Migration plan prepared in Part B (`ttlExpiresAt` dual-field strategy). |
| Transactional Email Delivery (Custom Branded Verification / Reset) | **REQUIRES EXTERNAL APPROVAL** | Currently uses Firebase Auth client emails; backend `/register` & `/password/forgot` need Resend/Postmark key for custom branding. |
| External Uptime & `DEAD_LETTER` Alerting | **REQUIRES EXTERNAL APPROVAL** | `/api/id/ready` & `/api/admin/id/telemetry` ready; needs Better Stack / UptimeRobot + webhook URL. |
| Legal Counsel Sign-Off on ToS / Privacy / AUP & Stripe Live Mode | **REQUIRES EXTERNAL APPROVAL** | Draft requirements prepared; must be reviewed before flipping Stripe to live mode. |
| Usage-Based SMS MFA (Twilio + Metered Billing) | **DEFERRED** | Post-beta add-on (`LiveSMSProviderStub` throws intentionally). |
| WebAuthn / Passkeys & Distributed Redis Rate Limiting | **DEFERRED** | Post-beta / multi-replica scale. |
