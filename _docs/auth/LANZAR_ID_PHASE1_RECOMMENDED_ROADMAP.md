# LANZAR ID — Phase 1 Recommended Roadmap (Post-M1.5)
**Document ID:** `LID-REV-PHASE1-ROADMAP`  
**Baseline:** M1.1–M1.5 (`80c1dec6760a604badaa06e87549ba67e97ef51c`)  
**Date:** 2026-11-15  

---

## Priority 0 — Pre-Production Hardening (Required Before Any Live Staging/Prod Cutover)
1. **Firestore Security Rules & TTL Policies:**
   - Deploy deny-all client rules for `system_signing_keys`, `oauth_authorization_codes`, `security_outbox`, `compromised_ceremonies`, `clients_index`, `token_families`, and `admin_audit_logs` (`allow update, delete: if false;`).
   - Enable Firestore TTL policies on `expiresAt` for `oauth_authorization_codes`, `users/{uid}/sessions`, and `tenants/{t}/token_families`.
2. **Legacy `adminRoutes.js` Alignment:**
   - Scope `adminRoutes.js` endpoints (`/users`, `/audit-log`, `/telemetry`, `/clients`) using `req.adminContext` so tenant admins cannot invoke platform-wide endpoints.
3. **Production Readiness Probe & Outbox Worker:**
   - Add `/api/id/ready` verifying Firestore reachability and an active RS256 signing key.
   - Deploy the `security_outbox` consumer with alerting on `REPLAY_DETECTED` and `dead_letter` escalations.
4. **Live Staging Verification:**
   - Execute end-to-end smoke tests against the live staging Firebase project (distinct from local Firestore Emulator).

---

## Priority 1 — Phase 2 Commercial Credential & Lifecycle Hardening
1. **Server-Generated 256-Bit Client Secrets & Dual-Secret Rotation:**
   - Generate `crypto.randomBytes(32).toString('base64url')` secrets server-side with **one-time disclosure** at creation/rotation.
   - Add `POST /api/admin/id/clients/:clientId/rotate-secret` supporting `previousClientSecretHash` + `previousSecretExpiresAt` grace window so active refresh-token families are not abruptly broken during zero-downtime secret rotation.
2. **Compromised-Client Cascading Revocation:**
   - Add an administrative `revokeClientSessions` / `compromiseClient` operation that suspends the client and batch-revokes active `token_families` and `sessions` bound to `clientId`.
3. **Cleanup on Tenant Mismatch in `handleAuthorizationCodeGrant`:**
   - Call `safeCleanup('tenant_mismatch')` if `resolvedClient.tenantId !== record.tenantId` after `initiateRedemption()`.

---

## Priority 2 — Commercial Multi-Tenant Platform & SaaS Features
1. **Tenant Provisioning & Membership Model:**
   - Introduce `/tenants/{tenantId}` metadata documents and `/tenants/{tenantId}/memberships/{uid}` for per-tenant user roles, suspension, and directory isolation.
2. **Distributed Rate Limiting & Abuse Protection:**
   - Replace/augment in-memory `rateLimiter.js` with Redis/edge rate limiting and per-tenant quotas.
3. **OIDC Core Conformance Expansion (Optional / Customer-Driven):**
   - Add browser-based authorization/consent UI (`GET /oauth/authorize`), RP-initiated logout (`end_session_endpoint`), and `client_secret_basic` if third-party OIDC clients require them.
4. **Developer Portal, Billing & Audit Archival:**
   - Self-service tenant/client management UI, Stripe usage/plan enforcement, and automated export of `admin_audit_logs` to immutable Cloud Storage / BigQuery.
