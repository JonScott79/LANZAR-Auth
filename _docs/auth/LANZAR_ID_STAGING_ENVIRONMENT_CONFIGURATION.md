# LANZAR ID — NOVA Staging Environment Configuration

**Project:** LANZAR ID  
**Staging Environment Name:** **NOVA** (`APP_ENV=staging`)  
**Baseline Commit:** `475437f2ac1d90adde6035499ac40dd6fefd1084` (`lanzar_id_main_chat`)  
**Parent Milestone:** M1.5 (`80c1dec6760a604badaa06e87549ba67e97ef51c`)  
**Status:** Preparation specification only — no staging resources provisioned, no secrets created, and no code modified.

---

## 1. Environment Isolation & NOVA Naming Matrix

> **Naming Rule:** **NOVA** is the branded public-facing staging environment name. All HTTP URL paths use lowercase `/nova` consistently. Internal configuration identifiers (`APP_ENV=staging`, `FIREBASE_PROJECT_ID=lanzar-95ae3-dev`) remain unchanged.

| Component / Setting | Production (`APP_ENV=production`) | Staging — **NOVA** (`APP_ENV=staging`) |
| :--- | :--- | :--- |
| **Auth Hub** | `https://auth.lanzar.me` | `https://auth.lanzar.me/nova` |
| **Identity Issuer (`iss`)** | `https://auth.lanzar.me` | `https://auth.lanzar.me/nova` |
| **Backend API** | `https://auth-api.lanzar.me` | `https://auth-api-nova.lanzar.me` |
| **Firebase / GCP Project ID** | `lanzar-95ae3` | `lanzar-95ae3-dev` |
| **Service Account Suffix** | `@lanzar-95ae3.iam.gserviceaccount.com` | `@lanzar-95ae3-dev.iam.gserviceaccount.com` |
| **Emulators** | `forbidden` | `forbidden` |
| **Session Cookie Name** | `__Host-lanzar_sess` | `__Host-lanzar_stg_sess` |
| **Stripe Key Prefix** | `sk_live_` | `sk_test_` |

### NOVA Implementation Status (Implemented Locally, Pending Staging Deployment)
1. **Discovery & JWKS Routes (`app.js`, `oidcRoutes.js`, `jwksRoutes.js`):** `/nova/.well-known/openid-configuration` (active when `issuer` ends with `/nova`) and `/nova/.well-known/jwks.json` are now mounted alongside `/.well-known/*`.
2. **Issuer & Endpoint Decoupling (`app.js`, `oidcTokenService.js`, `bootstrap.js`):** `OidcTokenService` now accepts `issuer` (`https://auth.lanzar.me/nova`) and `apiBaseUrl` (`https://auth-api-nova.lanzar.me`) independently, and `bootstrap.js` validates `OIDC_ISSUER` fail-closed.
3. **Environment Matrix (`environments.js`):** `ENV_CONFIGS.staging` now sets `apiBaseUrl: 'https://auth-api-nova.lanzar.me'`, `authHubUrl: 'https://auth.lanzar.me/nova'`, `oidcIssuer: 'https://auth.lanzar.me/nova'`, and `originMap['https://auth.lanzar.me'] = 'auth_hub'`.
4. **Auth Hub Hosting Rewrites (`auth/netlify.toml`, `auth/vercel.json`):** Explicit proxy rules for `/nova/.well-known/openid-configuration` and `/nova/.well-known/jwks.json` to `https://auth-api-nova.lanzar.me` are configured above the SPA catch-all.

---

## 2. Firebase / GCP Staging Infrastructure Requirements

1. **Dedicated Firebase Project (`lanzar-95ae3-dev`):** Isolated from `lanzar-95ae3` (separate Auth user pool, Firestore database, signing keys in `system_signing_keys`, service accounts, and Secret Manager).
2. **Firebase Authentication:** Enable Email/Password (and any configured OAuth/phone providers required for NOVA staging testing).
3. **Cloud Firestore Database:** Provision in Native mode.
4. **Firestore Security Rules (`firestore.rules`):** Deploy `firestore.rules` from commit `475437f`, explicitly denying client access to all server-only collections (`/users/*/sessions/*`, `/users/*/central_sessions/*`, `/users/*/session_slots/*`, `/users/*/founders/*`, `/authorization_codes/*`, `/oauth_authorization_codes/*`, `/oauth_codes/*`, `/compromised_ceremonies/*`, `/security_outbox/*`, `/admin_idempotency/*`, `/auth_reconciliation/*`, `/system_signing_keys/*`, `/clients_index/*`, `/tenants/*/clients/*`, `/tenants/*/token_families/*`, `/tenants/*/admin_audit_logs/*`, `/user_security/*`, `/security_logs/*`, `/mfa_factors/*`, `/phone_otps/*`, `/admins/*`, `/pythos/app/lanzar_id_accounts/**`, and catch-all `/{document=**}`).
5. **Required Composite Indexes:**
   - `security_outbox`: `(type ASC, status ASC, nextRetryAt ASC)`
6. **Firestore TTL Policies:**
   - `authorization_codes.expiresAt`, `oauth_authorization_codes.expiresAt`, `admin_idempotency.expiresAt` (24-hour TTL), plus `users/{uid}/sessions` & `tenants/{tenantId}/token_families` after expiry/revocation.
   - *Do NOT enable short TTL on:* `tenants/{tenantId}/admin_audit_logs`, `system_signing_keys`, `clients_index`, `tenants/{tenantId}/clients`.
7. **PITR & Scheduled Backups:** Enable Firestore PITR and daily exports to a dedicated staging GCS bucket.
8. **Service Account & IAM Permissions:** Dedicated `@lanzar-95ae3-dev.iam.gserviceaccount.com` service account with `roles/datastore.user`, `roles/firebaseauth.admin`, and `roles/secretmanager.secretAccessor`.

---

## 3. Required Secrets & Environment Variables (No Secret Values Included)

### Secrets (Secret Manager / Railway Encrypted Variables)
| Variable Name | Purpose | Validation Rule |
| :--- | :--- | :--- |
| `FIREBASE_SERVICE_ACCOUNT_KEY` | JSON credentials for `lanzar-95ae3-dev` | `project_id === 'lanzar-95ae3-dev'`, `client_email` ends with `@lanzar-95ae3-dev.iam.gserviceaccount.com` |
| `SESSION_SIGNING_SECRET` | Session signing secret | >= 32 bytes |
| `MFA_HMAC_SECRET` | MFA HMAC secret | >= 32 bytes; must not contain `dev` or `default` |
| `SIGNING_KEY_ENCRYPTION_KEY` | AES-256-GCM KEK for `system_signing_keys` | 32-byte key; rejects dev KEKs in staging |
| `RECEIPT_ENCRYPTION_KEY` | AES-256-GCM key for token receipts | 32-byte key; rejects dev keys in staging |
| `MFA_ENCRYPTION_KEY` | MFA factor encryption key | Required if MFA enrollment is active |
| `STRIPE_SECRET_KEY` | Stripe test key (if `FEATURE_STRIPE=enabled`) | Must start with `sk_test_` |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook secret (if `FEATURE_STRIPE=enabled`) | Required when Stripe enabled |

### Non-Secret Configuration Variables
| Variable Name | NOVA Staging Value | Notes |
| :--- | :--- | :--- |
| `APP_ENV` | `staging` | Internal env selector (`bootstrap.js`) |
| `NODE_ENV` | `staging` (or `production`) | Triggers fail-closed key checks |
| `FIREBASE_PROJECT_ID` | `lanzar-95ae3-dev` | Must match `ENV_CONFIGS.staging.projectId` |
| `EXPECTED_SA_EMAIL` | `<sa>@lanzar-95ae3-dev.iam.gserviceaccount.com` | Optional strict pinning |
| `FEATURE_STRIPE` | `disabled` or `enabled` | Explicit value required in staging |
| `OIDC_ISSUER` | `https://auth.lanzar.me/nova` | **Requires code update** in `app.js` / `oidcRoutes.js` / `jwksRoutes.js` before NOVA cutover |
| `ACTIVE_SIGNING_KEK_VERSION` | `1` | Positive integer |
| `ACTIVE_RECEIPT_KEY_VERSION` | `1` | Positive integer |
| `TRUST_PROXY` | `true` (behind Railway LB) | Verify Express `trust proxy` |
| `PORT` / `HOST` | Runtime-assigned (`server.js` only) | Railway injects `PORT` |
| `OUTBOX_WORKER_POLL_MS` | `5000` (default) | NOVA Worker only |
| `OUTBOX_LEASE_DURATION_MS` | `30000` (default) | NOVA Worker only |
| `OUTBOX_MAX_ATTEMPTS` | `5` (default) | NOVA Worker only |
| `RECONCILE_INTERVAL_MS` | `60000` (default) | NOVA Worker only |
| `RECONCILE_SWEEP_POLL_MS` | `15000` (default) | NOVA Worker only |
| `FIREBASE_AUTH_EMULATOR_HOST`, `FIRESTORE_EMULATOR_HOST` | **MUST BE UNSET** | Bootstrap aborts if set |
