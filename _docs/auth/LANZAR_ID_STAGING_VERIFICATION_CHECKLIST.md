# LANZAR ID — NOVA Staging Verification Checklist

**Project:** LANZAR ID  
**Staging Environment Name:** **NOVA** (`APP_ENV=staging`)  
**Baseline Commit:** `475437f2ac1d90adde6035499ac40dd6fefd1084`  
**Target Endpoints:** Auth Hub & Issuer `https://auth.lanzar.me/nova` | Backend API `https://auth-api-nova.lanzar.me` | Firebase `lanzar-95ae3-dev`

---

## 1. Service Health, Readiness & NOVA OIDC Discovery

- [ ] **NOVA-SVC-01:** `GET https://auth-api-nova.lanzar.me/api/id/health` returns `200` with `appEnv: "staging"`.
- [ ] **NOVA-SVC-02:** `GET https://auth-api-nova.lanzar.me/api/id/ready` returns `200` with `checks.firestore === "ok"`, `checks.signingKeystore === "ok"`, and `keyCount >= 1`.
- [ ] **NOVA-SVC-03:** `GET https://auth.lanzar.me/nova/.well-known/openid-configuration` (and `https://auth-api-nova.lanzar.me/nova/.well-known/openid-configuration`) returns `200` with `issuer: "https://auth.lanzar.me/nova"` (not intercepted by Auth Hub SPA).
- [ ] **NOVA-SVC-04:** `GET https://auth.lanzar.me/nova/.well-known/jwks.json` returns `200` with public RS256 JWK(s) only (zero private key fields, distinct from `lanzar-95ae3` production keys).
- [ ] **NOVA-SVC-05:** `lanzar-id-nova-worker` (`worker.js`) logs startup banner with zero `[WORKER FATAL]` errors.

---

## 2. OAuth / OIDC & Client Registry Smoke Tests

- [ ] **NOVA-OIDC-01:** Execute full OIDC Authorization Code + PKCE flow (`/oauth/authorize` -> `/oauth/token` -> `/oauth/userinfo` -> `/oauth/token` `refresh_token`) and verify minted JWT `iss` claim equals `"https://auth.lanzar.me/nova"`.
- [ ] **NOVA-OIDC-02:** Confirm `verifyAccessToken` accepts `"https://auth.lanzar.me/nova"` and rejects tokens from production `"https://auth.lanzar.me"`.
- [ ] **NOVA-OIDC-03:** Confirm `pythos` and `mothership` are NOT registered or active in NOVA client registry.
- [ ] **NOVA-OIDC-04:** Confirm `X-Correlation-ID` header is echoed on responses.

---

## 3. Admin Authorization, Idempotency & Audit Integrity

- [ ] **NOVA-ADM-01:** Confirm `tenant_admin` receives `403` on `/api/admin/id/users`, `/api/admin/id/telemetry`, and `/api/admin/id/users/:uid/suspend`.
- [ ] **NOVA-ADM-02:** Confirm `POST /api/admin/id/users/:uid/suspend` without `Idempotency-Key` (or `< 16` chars) returns `400 invalid_idempotency_key`.
- [ ] **NOVA-ADM-03:** Confirm `POST /api/admin/id/users/:uid/suspend` with valid `Idempotency-Key` returns `200`, updates Firebase Auth `disabled: true`, writes `admin_audit_logs`, and replaying the same key returns `idempotentReplay: true` without incrementing `tokenVersion`.
- [ ] **NOVA-ADM-04:** Confirm replaying the same `Idempotency-Key` with a different payload returns `409 idempotency_key_conflict`.
- [ ] **NOVA-ADM-05:** Confirm `POST /api/admin/id/users/:uid/sessions/revoke-all` updates Firebase Auth `tokensValidAfterTime`, advances `appliedRevocationVersion`, and records `admin_audit_logs`.

---

## 4. Worker, Reconciliation & Firestore Security Rules

- [ ] **NOVA-WRK-01:** Verify `DesiredStateReconciler` converges `/auth_reconciliation/{testUid}` to `CONVERGED` without duplicate admin audits.
- [ ] **NOVA-SEC-01:** Confirm unauthenticated/client SDK requests to `/tenants/*/clients/*`, `/system_signing_keys/*`, `/security_outbox/*`, `/admin_idempotency/*`, `/auth_reconciliation/*`, and `/tenants/*/admin_audit_logs/*` in `lanzar-95ae3-dev` return `PERMISSION_DENIED`.
- [ ] **NOVA-SEC-02:** Confirm error responses on `4xx`/`5xx` do not expose raw internal error messages or secrets.
