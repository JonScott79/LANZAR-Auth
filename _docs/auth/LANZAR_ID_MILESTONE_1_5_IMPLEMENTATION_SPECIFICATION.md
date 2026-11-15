# LANZAR ID — Milestone 1.5 Implementation Specification
**Title:** Tenant Isolation, Client Lifecycle & Operational Hardening  
**Document ID:** `LID-SPEC-M1.5-AUTHORITATIVE`  
**Status:** Implemented & Locally Verified (Pending User Sign-Off)  
**Date:** 2026-11-15  

---

## 1. Scope & Objectives
Milestone 1.5 hardens the multi-tenant isolation, client lifecycle management, administrative auditability, and operational reliability of LANZAR ID on top of the M1.1–M1.4 architecture.

---

## 2. Tenant Context Enforcement & Identity Model
- **Global UID vs. Tenant-Scoped Records:**
  - Firebase Auth `uid` is globally unique per Firebase project; `/users/{uid}` and `/users/{uid}/sessions/{sessionId}` are keyed under global `uid`, while `/tenants/{tenantId}/clients/{clientId}`, `/tenants/{tenantId}/token_families/{familyId}`, and `/tenants/{tenantId}/admin_audit_logs/{auditId}` are tenant-scoped.
  - **Current Model & Limitation:** A single Firebase user account (`uid`) can authenticate to clients in different tenants, but each OAuth ceremony, session document (`sessionData.tenantId`), token family (`familyData.tenantId`), access token (`tenant_id`), and ID token (`tenant_id`) is strictly bound to one tenant and cannot be reused across tenant boundaries. Full per-tenant user isolation (tenant-scoped user profiles/memberships) is deferred to Phase 2.
- **Boundary Enforcement:**
  - `POST /oauth/authorize`: Derives `tenantId` strictly from the resolved client (`client.tenantId || 'lanzar'`).
  - `POST /oauth/token` (`authorization_code`): Verifies `resolvedClient.tenantId === record.tenantId`.
  - `POST /oauth/token` (`refresh_token`): Pre-validates `preClient.tenantId === tenantId` before `authorizeRefreshGrant()`, verifies `familyData.tenantId === tenantId` and `sessionData.tenantId === tenantId` transactionally, and verifies `boundClient.tenantId === authResult.tenantId`.
  - `GET /oauth/userinfo`: Requires `sessionData.tenantId === payload.tenant_id`, verifies `sessionData.clientId === payload.azp` when present, rejects cross-tenant `x-lanzar-tenant-id` / `query.tenant_id` (`403`), and checks live `client.enabled` via `clientRegistryService`.
  - `OidcTokenService.verifyAccessToken()`: Supports `options.expectedTenantId` (`TENANT_MISMATCH`).

---

## 3. Client Lifecycle Management
- **States:** `enabled: true` (`status: 'active'`) and `enabled: false` (`status: 'suspended'`), synchronized in both `/tenants/{tenantId}/clients/{clientId}` and `/clients_index/{clientId}`.
- **Endpoints (`auth/auth-backend/routes/clientRegistryRoutes.js`):**
  - `POST /api/admin/id/clients/:clientId/disable`
  - `POST /api/admin/id/clients/:clientId/enable`
  - No `DELETE` endpoint exists.
- **Disabled-Client Policy:**
  - Disabling a client immediately blocks new `/oauth/authorize`, `/oauth/token` (`authorization_code` and `refresh_token`), and `GET /oauth/userinfo` requests.
  - Existing session and token-family documents remain intact until expiration or explicit revocation; re-enabling a suspended client restores access for non-expired, unrevoked sessions.
  - **Deferred Capability:** Cascading revocation of all active sessions and refresh-token families for a compromised client is deferred to future operational tooling.

---

## 4. Administrative Audit Trail
- **Service:** `auth/auth-backend/services/auditLogService.js` (`AuditLogService`, `strictAudit: true` by default).
- **Storage:** Application-level append-only writes via `create()` (unique `auditId`, rejecting duplicates) in `/tenants/{targetTenantId}/admin_audit_logs/{auditId}`.
- **Integrity Distinction:** Application code enforces append-only writes and exposes no update/delete methods; true tamper-resistant immutability in Firestore additionally requires Firestore Security Rules denying `update` and `delete` on `/tenants/{tenantId}/admin_audit_logs/{auditId}`.
- **Fail-Closed Behavior:** Required mutation audit writes fail closed (`503 service_unavailable`) if the audit write fails.
- **Captured Fields:** `auditId`, `actorUid`, `actorEmail`, `actorTenantId`, `actorRole`, `targetTenantId`, `clientId`, `operation`, `outcome`, `reason`, `correlationId`, `metadata`, `immutable: true`, `timestamp`.
- **Credential Redaction:** Recursively redacts any key matching `/secret|password|token|hash|credential|private|key/i` with `'[REDACTED]'`.
- **Read Endpoint:** `GET /api/admin/id/audit-logs` (tenant admins restricted to their own tenant; platform admins may query any `?tenantId=`).

---

## 5. Operational Reliability & Deployment Requirements
- Firestore errors on `/oauth/userinfo` fail closed (`503`).
- `AuditLogService` supports `strictAudit: true` (`AUDIT_WRITE_FAILED`).
- **Required Firestore Rules / Indexes:**
  - `/tenants/{tenantId}/admin_audit_logs/{auditId}`: allow append-only `create` by backend Admin SDK only; deny client `update`/`delete`.
  - Single-field index on `timestamp` (`DESCENDING`) in `/tenants/{tenantId}/admin_audit_logs` (automatic in Firestore).
