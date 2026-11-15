# LANZAR ID — Milestone 1.5 Reconciliation Report
**Title:** Tenant Isolation, Client Lifecycle & Operational Hardening  
**Document ID:** `LID-REC-M1.5-AUTHORITATIVE`  
**Status:** Implemented & Locally Verified (Pending Review & Commit Authorization)  
**Date:** 2026-11-15  

---

## 1. Files Implemented & Modified
- `auth/auth-backend/services/auditLogService.js` — Append-only tenant-aware `AuditLogService` with recursive secret redaction.
- `auth/auth-backend/services/clientRegistryService.js` — Added `status` (`'active' | 'suspended'`) sync and `disableClient()` / `enableClient()`.
- `auth/auth-backend/routes/clientRegistryRoutes.js` — Added `POST /clients/:clientId/disable`, `POST /clients/:clientId/enable`, `GET /audit-logs`, and audit logging across all admin actions.
- `auth/auth-backend/services/oidcTokenService.js` — Added `expectedTenantId` verification in `verifyAccessToken()`.
- `auth/auth-backend/routes/oidcRoutes.js` — Enforced mandatory `sessionData.tenantId === payload.tenant_id`, `sessionData.clientId === payload.azp`, requested-tenant header/query check, and live `client.enabled` enforcement on `/oauth/userinfo`.
- `auth/auth-backend/routes/oauthRoutes.js` — Added `resolvedClient.tenantId === record.tenantId` on `authorization_code` redemption and `preClient.tenantId === tenantId` / `boundClient.tenantId === authResult.tenantId` on `refresh_token`.
- `auth/auth-backend/app.js` — Wired `AuditLogService` into `createClientRegistryRouter` and `clientRegistryService` into `createOidcRouter`.
- `auth/test-milestone-1-5.cjs` — 4-test Milestone 1.5 unit & HTTP integration suite (`M1.5-01`..`M1.5-04`).
- `auth/test-milestone-1-5-emulator.cjs` — 3-test Milestone 1.5 live Cloud Firestore Emulator suite (`EMU-M1.5-01`..`EMU-M1.5-03`).

---

## 2. Security Reconciliation & Verification Results

### 2.1 Audit & Mutation Atomicity Correction
- `AuditLogService` provides `buildAdminAuditRecord()` (pre-generating unique `aud_<ts>_<hex>` IDs outside transactions) and `writeInTransaction(tx, prepared)`.
- `ClientRegistryService` (`registerClient`, `updateClient`, `disableClient`, `enableClient`, `seedApprovedInternalClients`) executes the client mutation and the required audit-record `create()` **within the same Firestore `runTransaction()`**.
- If the audit write fails, the transaction rolls back so no client state is mutated without its audit record (`M1.5-05`); Firestore transaction retries reuse the pre-generated `auditId`, producing zero duplicate audit events (`M1.5-06`).
- **Accurate Limitation:** Application code enforces append-only writes and exposes no update/delete methods; database-level immutability requires Firestore Security Rules denying `update` and `delete` on `/tenants/{tenantId}/admin_audit_logs/{auditId}`.

### 2.2 Final Test Totals (145/145 Passing)

> **Environment Distinction:** All Firestore persistence tests ran against an in-memory simulation or the **local Cloud Firestore Emulator** (`127.0.0.1:8092`, project `demo-lanzar-id-m1-5-test`). **Zero tests were executed against production Cloud Firestore.**

| Suite | Command | Environment | Passed | Total | Status |
| :--- | :--- | :--- | :---: | :---: | :---: |
| M1.5 Unit & HTTP Suite | `node auth/test-milestone-1-5.cjs` | In-Memory | 6 | 6 | PASS |
| M1.5 Firestore Emulator Suite | `node auth/test-milestone-1-5-emulator.cjs` | Local Emulator (`8092`) | 3 | 3 | PASS |
| M1.4 Unit & HTTP Suite | `node auth/test-milestone-1-4.cjs` | In-Memory | 10 | 10 | PASS |
| M1.3 OIDC & Adapter Suite | `node auth/test-milestone-1-3.cjs` | In-Memory | 7 | 7 | PASS |
| M1.2 RS256 & JWKS Suite | `node auth/test-milestone-1-2.cjs` | In-Memory | 11 | 11 | PASS |
| M1.1 Store Simulation Suite | `node auth/test-milestone-1-1.cjs` | In-Memory | 44 | 44 | PASS |
| Phase 1 Acceptance Suite | `node auth/test-phase1-acceptance.cjs` | In-Memory | 55 | 55 | PASS |
| OAuth Client Registry Suite | `node auth/test-client-registry.cjs` | Static Registry | 9 | 9 | PASS |
| **Total** | | | **145** | **145** | **100.0%** |

---

## 3. Scope, Risks & Deferred Work
- Approved internal clients remain strictly `portal`, `tickets`, `threadline`, and `ai`; `pythos` and `mothership` remain excluded.
- **Remaining Risks / Deferred Work:**
  1. Firestore Security Rules must enforce `allow update, delete: if false;` on `/tenants/{tenantId}/admin_audit_logs/{auditId}` for database-level immutability.
  2. Compromised-client cascading revocation (batch-revoking all active sessions and refresh-token families for a compromised `clientId`) is deferred beyond M1.5.
  3. Per-tenant user directory/membership isolation, server-generated 256-bit client secrets with one-time disclosure, and dual-secret rotation grace periods remain deferred.
- M1.5 is **not committed**, pushed, or deployed; awaiting user review.
