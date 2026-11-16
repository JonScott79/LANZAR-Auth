# LANZAR ID — NOVA Staging Rollback Plan

**Project:** LANZAR ID  
**Staging Environment Name:** **NOVA** (`APP_ENV=staging`)  
**Baseline Commit:** `475437f2ac1d90adde6035499ac40dd6fefd1084` (`lanzar_id_main_chat`)  
**Parent Milestone:** M1.5 (`80c1dec6760a604badaa06e87549ba67e97ef51c`)

---

## 1. Rollback Triggers

Initiate NOVA staging rollback immediately if any of the following occur:
- `GET https://auth-api-nova.lanzar.me/api/id/ready` fails (`503`) after deployment.
- `lanzar-id-nova-worker` (`worker.js`) crashes repeatedly (`[WORKER FATAL]`) or generates unexpected `DEAD_LETTER` spikes.
- NOVA OIDC discovery/JWKS (`/nova/.well-known/openid-configuration`, `/nova/.well-known/jwks.json`), `iss` validation (`https://auth.lanzar.me/nova`), or admin isolation (`403`) fails verification.
- Any evidence of accidental cross-environment reference to production `lanzar-95ae3`.

---

## 2. Service Rollback Procedure (Railway)

1. **Stop Worker First (`lanzar-id-nova-worker` — `worker.js`):**
   - Scale Railway worker replicas to `0` (or stop deployment) to halt background outbox/reconciliation mutations cleanly (`SIGTERM` stops polling loops).
2. **Rollback API Service (`lanzar-id-nova-api` — `server.js`):**
   - Roll back the Railway API deployment to the previous known-good deployment/commit (or `80c1dec6760a604badaa06e87549ba67e97ef51c`), or scale to `0` if this is the initial NOVA deployment.
3. **Auth Hub Routing (`https://auth.lanzar.me/nova`):**
   - If edge/proxy rules on `auth.lanzar.me` were modified for `/nova/.well-known/*`, revert those proxy rules if rolling back NOVA.
4. **Verify Service State:**
   - Confirm `GET /api/id/health` and `GET /api/id/ready` match expected post-rollback state.

---

## 3. Data & Firestore Rules Rollback (`lanzar-95ae3-dev`)

- **Firestore Security Rules:** If `firestore.rules` caused unintended breakage in `lanzar-95ae3-dev`, redeploy the prior `firestore.rules` version from `80c1dec6760a604badaa06e87549ba67e97ef51c` to `lanzar-95ae3-dev` only (do **not** weaken server-only `if false;` denials).
- **Outbox / Reconciliation / Idempotency Collections:** `security_outbox`, `admin_idempotency`, and `auth_reconciliation` are additive collections in `lanzar-95ae3-dev` and do not break M1.5 code.
- **Signing Keys & Secrets:** Do **not** delete `system_signing_keys` documents while tokens are in flight; rotate/revoke via `SigningKeystore` if a NOVA staging key must be retired, and rotate any exposed secret in Secret Manager / Railway immediately.
