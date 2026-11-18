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

## Part B: Expiration-Field Schema Migration & Rollback (NOVA Staging Executed)

> **Policy:** Existing ISO-8601 and Unix-epoch expiration fields and application-level expiration checks were preserved unchanged. No documents were physically deleted by the migration, and documents without `ttlExpiresAt` are ignored by Firestore TTL.

### 1. Dual-Write Implementation & Retention Policies

Implemented via shared helper `auth/auth-backend/services/ttlHelper.js` (`computeTtlDate`, `parseExpiryToMs`):

| Collection Group | Existing Field(s) Preserved | New Native Timestamp Field | Retention Policy | Write Paths Updated | Staging Backfill Results (`lanzar-95ae3-dev`) |
|---|---|---|---|---|---|
| `sessions` | `expiresAt` (ISO string or epoch sec) | `ttlExpiresAt` | Existing expiration **+ 24h grace** | `sessionService.js`, `centralSessionService.js`, `oauthRoutes.js` | `49` scanned, `49` backfilled, `0` skipped |
| `central_sessions` | `absoluteExpiresAt`, `idleExpiresAt` (Unix sec) | `ttlExpiresAt` | `absoluteExpiresAt` (**0 grace**) | `centralSessionService.js` | `10` scanned, `10` backfilled, `0` skipped |
| `token_families` | `expiresAt` (ISO string) | `ttlExpiresAt` | Existing expiration **+ 7d grace** | `oauthRoutes.js` | `46` scanned, `46` backfilled, `0` skipped |
| `phone_otps` | `expiresAt` (ISO string) | `ttlExpiresAt` | Existing expiration **+ 1h grace** | `smsService.js` (all 3 OTP flows) | `0` scanned, `0` backfilled, `0` skipped |
| `admin_idempotency` | `expiresAt` (ISO string, `IDEMPOTENCY_TTL_MS = 24h`) | `ttlExpiresAt` | Matches `24h` retention (**0 grace**) | `adminRoutes.js` (both idempotent tx paths) | `17` scanned, `17` backfilled, `0` skipped |

### 2. Enable Native TTL Policies in Cloud Shell (`lanzar-95ae3-dev` Only)

After verifying the backfill above (`122/122` documents populated, `0` skipped), run in Google Cloud Shell:

```bash
for group in sessions central_sessions token_families phone_otps admin_idempotency; do
  gcloud firestore fields ttls update ttlExpiresAt \
    --collection-group="$group" --enable-ttl --project="lanzar-95ae3-dev"
done
```

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
| Secondary TTL Policies (`sessions`, `central_sessions`, `token_families`, `phone_otps`, `admin_idempotency`) | **IN PROGRESS (BACKFILLED)** | Dual-write deployed + 122/122 staging docs backfilled with `ttlExpiresAt`; run Cloud Shell `--enable-ttl` loop to activate policies. |
| Transactional Email Delivery (Custom Branded Verification / Reset) | **REQUIRES EXTERNAL APPROVAL** | Currently uses Firebase Auth client emails; backend `/register` & `/password/forgot` need Resend/Postmark key for custom branding. |
| External Uptime & `DEAD_LETTER` Alerting | **REQUIRES EXTERNAL APPROVAL** | `/api/id/ready` & `/api/admin/id/telemetry` ready; needs Better Stack / UptimeRobot + webhook URL. |
| Legal Counsel Sign-Off on ToS / Privacy / AUP & Stripe Live Mode | **REQUIRES EXTERNAL APPROVAL** | Draft requirements prepared; must be reviewed before flipping Stripe to live mode. |
| Usage-Based SMS MFA (Twilio + Metered Billing) | **DEFERRED** | Post-beta add-on (`LiveSMSProviderStub` throws intentionally). |
| WebAuthn / Passkeys & Distributed Redis Rate Limiting | **DEFERRED** | Post-beta / multi-replica scale. |
