# LANZAR ID — NOVA Controlled Staging Deployment Runbook

**Project:** LANZAR ID  
**Staging Environment Name:** **NOVA** (`APP_ENV=staging`)  
**Baseline Commit:** `475437f2ac1d90adde6035499ac40dd6fefd1084` (`lanzar_id_main_chat`)  
**Parent Milestone:** M1.5 (`80c1dec6760a604badaa06e87549ba67e97ef51c`)  
**Scope:** Step-by-step NOVA staging deployment procedure. **Do not execute until NOVA routing/code blockers are resolved and deployment is authorized.**

---

## 1. Pre-Deployment Gates & NOVA Blockers

1. **NOVA Routing & Issuer Ready:** `/nova/.well-known/openid-configuration`, `/nova/.well-known/jwks.json`, `OIDC_ISSUER` decoupling, `ENV_CONFIGS.staging` NOVA URLs, and `auth/netlify.toml` / `auth/vercel.json` proxy rules are implemented and verified (`216 / 216` local/emulator tests passing).
2. Confirm staging Firebase project `lanzar-95ae3-dev` is provisioned and completely isolated from production `lanzar-95ae3`.
4. Confirm no emulator variables (`FIREBASE_AUTH_EMULATOR_HOST`, `FIRESTORE_EMULATOR_HOST`) are set in Railway NOVA variables.

---

## 2. Step 1 — Firebase / GCP Staging Provisioning (`lanzar-95ae3-dev`)

1. Select or create Firebase project `lanzar-95ae3-dev`.
2. Enable Firebase Authentication and Cloud Firestore (Native mode).
3. Deploy `firestore.rules` to `lanzar-95ae3-dev` ONLY.
4. Create Firestore composite index on `security_outbox` (`type ASC, status ASC, nextRetryAt ASC`).
5. Configure Firestore TTL policies on `authorization_codes.expiresAt`, `oauth_authorization_codes.expiresAt`, and `admin_idempotency.expiresAt`.
6. Enable Firestore PITR and daily GCS backup exports.
7. Create staging service account (`*@lanzar-95ae3-dev.iam.gserviceaccount.com`) with `roles/datastore.user` and `roles/firebaseauth.admin`, and store its JSON key in Secret Manager / Railway (`FIREBASE_SERVICE_ACCOUNT_KEY`).

---

## 3. Step 2 — Railway Service A: `lanzar-id-nova-api` (`server.js`)

- **Root / Working Directory:** `auth/auth-backend`
- **Start Command:** `node server.js` (`npm start`)
- **Public API Domain:** `https://auth-api-nova.lanzar.me`
- **Health / Readiness Endpoints:**
  - Liveness: `GET /api/id/health` -> `200` (`{ status: 'healthy', appEnv: 'staging' }`)
  - Readiness: `GET /api/id/ready` -> `200` (`{ status: 'ready', checks: { firestore: 'ok', signingKeystore: 'ok' } }`)
- **Environment Variables:** `APP_ENV=staging`, `FIREBASE_PROJECT_ID=lanzar-95ae3-dev`, `OIDC_ISSUER=https://auth.lanzar.me/nova`, plus all secrets from `LANZAR_ID_STAGING_ENVIRONMENT_CONFIGURATION.md`.
- **Logging & Monitoring:** Capture structured stdout/stderr logs (`X-Correlation-ID`, `[READINESS ERROR]`, `[ADMIN ROUTE ERROR]`, `[UNHANDLED ERROR]`). Configure Railway healthcheck path to `/api/id/ready`.

---

## 4. Step 3 — Railway Service B: `lanzar-id-nova-worker` (`worker.js`)

- **Root / Working Directory:** `auth/auth-backend`
- **Start Command:** `node worker.js`
- **Public Networking:** **None** (internal background worker; no HTTP port exposed).
- **Responsibilities:**
  - `PlatformOutboxService` (`OUTBOX_WORKER_POLL_MS=5000`, `OUTBOX_LEASE_DURATION_MS=30000`, `OUTBOX_MAX_ATTEMPTS=5`)
  - `DesiredStateReconciler` (`RECONCILE_SWEEP_POLL_MS=15000`, `RECONCILE_INTERVAL_MS=60000`) for account-state and `tokensValidAfterTime` revocation reconciliation.
- **Shutdown & Restart Behavior:** `SIGTERM`/`SIGINT` stops both polling timers and exits `0`; expired leases (`OUTBOX_LEASE_DURATION_MS`) are automatically recovered on restart.
- **Environment Variables:** Same `APP_ENV=staging`, `FIREBASE_PROJECT_ID=lanzar-95ae3-dev`, secrets, and worker tuning variables.
- **Logging & Monitoring:** Alert on `[WORKER FATAL]`, `[OUTBOX WORKER ERROR]`, `[DESIRED STATE RECONCILER ERROR]`, and `DEAD_LETTER` documents in `security_outbox` / `auth_reconciliation`.

---

## 5. Step 4 — Post-Deploy Client Seeding & Verification

1. Seed approved staging clients (`portal`, `tickets`, `threadline`, `ai`), keeping `pythos` and `mothership` excluded.
2. Execute every check in `LANZAR_ID_STAGING_VERIFICATION_CHECKLIST.md`.
3. Do not proceed to production until all NOVA verification checks pass.
