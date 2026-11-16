# LANZAR ID — Phase 1 Production & Commercial Readiness Assessment
**Document ID:** `LID-REV-PHASE1-PROD`  
**Scope:** LANZAR ID Milestones 1.1–1.5  
**Date:** 2026-11-15  

---

## 1. Implemented Capabilities vs. Operational Gaps

| Area | Implemented (M1.1–M1.5) | Missing / Required for Production |
| :--- | :--- | :--- |
| **Environment & Secrets** | Staging/prod KEK and `TOKEN_RECEIPT_KEY` validation across `NODE_ENV` and `APP_ENV`; dev fallback rejected in staging/prod. | Secret Manager / KMS integration for `SIGNING_KEK_V*` and `TOKEN_RECEIPT_KEY`; automated startup config validation. |
| **Signing Key Rotation** | `SigningKeystore.rotateSigningKey()`, `revokeSigningKey()`, `_active_pointer` singleton transaction, 5s internal cache, 60s JWKS HTTP cache. | Automated scheduled rotation runbook/job and KEK version rotation procedure. |
| **Firestore Configuration** | Transactional dual-collection client registry, `create()`-only staging and audit logs, local Firestore Emulator verified. | **Zero production Firestore tests run.** Must deploy Firestore Security Rules, configure TTL policies on `oauth_authorization_codes`, `sessions`, and `token_families`, and verify composite indexes. |
| **Monitoring & Alerting** | `security_outbox` stages compromise/replay alerts; `AuditLogService` records structured admin events with `correlationId`; console error logging. | Outbox worker deployment, structured JSON logging sink (Cloud Logging), dead-letter alerting, and `AUDIT_WRITE_FAILED` / `REPLAY_DETECTED` PagerDuty/alert rules. |
| **Rate Limiting & Abuse** | In-memory `oauthAuthorizeLimiter` and `oauthExchangeLimiter` on `/authorize` and `/token`. | Distributed Redis/edge rate limiting (Cloudflare/Cloud Armor) for multi-instance deployments and admin endpoints. |
| **Health Checks & Availability** | `GET /api/id/health` returns `200` with `appEnv`/`nodeEnv`; `/jwks.json`, `/openid-configuration`, and `/userinfo` fail closed `503` when dependencies are unavailable. | Deep readiness probe (`/api/id/ready`) checking Firestore connectivity and active signing key availability without leaking secrets. |
| **Backup, DR & Audit Retention** | Append-only application writes to `/tenants/{t}/admin_audit_logs`. | Managed Firestore daily PITR/backups, documented DR/RTO runbook, and automated archival of `admin_audit_logs` to immutable Cloud Storage / BigQuery. |
| **Deployment & Rollback** | Clean Git checkpoints (`M1.4` `5fb79411...`, `M1.5` `80c1dec6...`), backward-compatible `compatibilityMode` adapter (`legacy_firebase`, `dual`, `oidc`). | Staging smoke-test pipeline against live Firebase project before production promotion; canary/rollback checklist. |

---

## 2. Commercial Multi-Tenant Readiness Assessment

> **Assessment Verdict:** LANZAR ID M1.1–M1.5 provides a **strong single-platform / early-tenant security core**, **NOT** commercial SaaS readiness. Automated tests (145/145) validate protocol and isolation invariants locally, but commercial onboarding requires additional identity, credential, billing, and operational layers.

| Commercial Dimension | Status | Current State & Gaps |
| :--- | :---: | :--- |
| **Tenant Onboarding** | **Missing** | No self-service or automated tenant provisioning workflow; tenants are implicit strings in `/tenants/{tenantId}/...`. |
| **Tenant Isolation** | **Implemented (Tokens/Clients/Audit)** | Clients, token families, tokens, sessions, and audit logs are strictly tenant-bound; **user accounts (`/users/{uid}`) remain global**. |
| **Developer / Client Registration** | **Partial** | Authenticated admin API (`POST /clients`, `PATCH /clients/:id`) exists; no self-service developer portal or quota limits. |
| **Credential Management** | **Partial** | `client_secret_post` with SHA-256 + `timingSafeEqual` exists; missing server-generated 256-bit secrets, one-time disclosure, and dual-secret rotation grace window. |
| **Client Lifecycle** | **Implemented (Basic)** | `disableClient()` / `enableClient()` with atomic audit logging; missing compromised-client cascading session/family revocation. |
| **User Identity & Membership** | **Partial** | Global Firebase Auth `uid`; no `/tenants/{tenantId}/memberships/{uid}` for per-tenant roles, suspension, or directory isolation. |
| **Administrative Roles** | **Implemented (Core)** | `platform_admin` vs. `tenant_admin` enforced in `authMiddleware.js` + `clientRegistryRoutes.js`; legacy `adminRoutes.js` still needs alignment. |
| **Auditability** | **Implemented (App-Layer)** | Atomic transactional `create()` + redaction + `GET /audit-logs`; requires Firestore Security Rules and external immutable log sink. |
| **Token Management** | **Implemented** | RS256 access/ID tokens, Discovery, JWKS, UserInfo, refresh rotation, replay compromise defense. |
| **Security Operations & Availability** | **Partial** | Outbox staging implemented; outbox consumer/alerting, distributed rate limiting, and Firestore TTL cleanup not yet deployed. |
| **Billing, Usage Limits & Support** | **Missing** | No Stripe/billing integration, per-tenant client/MAU/RPS quotas, or customer support/account recovery workflows per tenant. |
