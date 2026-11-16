# LANZAR ID — Pre-Production Security Corrective Report

**Project:** LANZAR ID  
**Branch:** `lanzar_id_main_chat`  
**Baseline Commits Preserved:**  
- M1.4: `5fb79411e0bf94131f60fb38d1d57a906067b8d9`  
- M1.5: `80c1dec6760a604badaa06e87549ba67e97ef51c`  

**Scope:** Corrective implementation and verification for findings **H-01**, **M-01**, **M-02**, and **L-01** from `LANZAR_ID_PREPRODUCTION_SECURITY_RECONCILIATION.md`.  
**Git / Deployment Status:** Local changes only. Nothing committed, amended, pushed, or deployed. Zero production tests executed.

---

## 1. Findings & Resolutions

### [HIGH] H-01 — Administrative Audit Logging (`adminRoutes.js`, `founderService.js`, `auditLogService.js`, `app.js`)
- **Resolution:**
  - Removed `strict: false` and removed the silent `if (!auditLogService) return;` bypass from `auth/auth-backend/routes/adminRoutes.js`.
  - Added `ensureAuditDependencies` requiring `auditLogService.buildAdminAuditRecord`, `auditLogService.writeInTransaction`, and `db.runTransaction`; missing dependencies fail closed with HTTP `503`.
  - Added optional deterministic `auditId` parameter to `AuditLogService.buildAdminAuditRecord` (`auth/auth-backend/services/auditLogService.js`) so Firestore transaction retries write to the same document ID without duplicating audit entries.
  - Preserved `actorUid`, `actorEmail`, `actorTenantId`, `actorRole: 'platform_admin'`, `targetTenantId: 'lanzar'`, `operation`, `outcome`, `correlationId`, `metadata.targetUid`, and `timestamp`.
  - Replaced all raw `err.message` error responses in `adminRoutes.js` with `handleAdminError(...)` (logs `err.message` server-side with `correlationId`, returns sanitized `error_description` + `correlationId`).
  - Passed `authAdmin` into `createAdminRouter` from `auth/auth-backend/app.js`.

- **Audit Failure Behavior:**
  - **Purely Firestore mutations (`POST /users/:uid/founders`, `DELETE /users/:uid/founders/:programId`):** `FounderService.grantFounderDesignation` and `FounderService.revokeFounderDesignation` (`auth/auth-backend/founderService.js`) execute the founder record write, `derivedBadges` recalculation on `/users/{uid}`, and `auditLogService.writeInTransaction(tx, auditPrepared)` inside a single `db.runTransaction(...)`. If the audit write fails, the transaction aborts, Firestore state is unchanged, and `adminRoutes.js` returns `503` (`audit_persistence_failed`).
  - **Cross-service mutations (`POST /users/:uid/suspend`, `POST /users/:uid/sessions/revoke-all`):** Phase 1 executes a single `db.runTransaction(...)` writing the Firestore state changes (`users/{uid}` status/`tokenVersion`, `sessions`, `central_sessions`), a durable `security_outbox/{outboxId}` record (`status: 'PENDING_EXTERNAL_AUTH'`), and the required `admin_audit_logs/{auditId}` record. If Phase 1 fails (including audit write failure), nothing in Firestore or Firebase Auth is modified, and the API returns `503` (`audit_persistence_failed`).

- **Cross-Service Recovery Behavior (`reconcilePlatformOutboxEvent`):**
  - After Phase 1 commits, `adminRoutes.js` invokes `reconcilePlatformOutboxEvent({ db, authAdmin, outboxId })` to execute the external Firebase Auth operation (`authAdmin.updateUser` / `authAdmin.revokeRefreshTokens`).
  - On Firebase Auth success: updates `security_outbox/{outboxId}` to `status: 'COMPLETED'` (`completedAt`, `attempts`) and returns `200 OK`.
  - On Firebase Auth failure: updates `security_outbox/{outboxId}` to `status: 'FAILED_RETRYABLE'` (`attempts`, sanitized `lastErrorCode`, `failedAt`) and returns `503` (`external_auth_sync_pending`) with `outboxId`, `auditId`, and `correlationId`. Re-running `reconcilePlatformOutboxEvent` once Firebase Auth recovers transitions the outbox record to `COMPLETED`.

### [MEDIUM] M-01 — Readiness Endpoint (`app.js`)
- **Resolution:** Updated `GET /api/id/ready` in `auth/auth-backend/app.js` to call `await signingKeystore.getPublicJwks({ bypassCache: true })`, ensuring readiness does not report `200 ready` from a stale in-memory JWKS cache when signing keys in Firestore are unavailable or deleted. Verified sanitized `503` error handling (`PPH-02`, `PPH-10`).

### [MEDIUM] M-02 — Expanded Test Coverage (`test-preprod-hardening.cjs`, `test-firestore-rules-emulator.cjs`)
- **Pre-Production Hardening Suite (`auth/test-preprod-hardening.cjs`, expanded from 5 to 10 tests):**
  - Preserved `PPH-01`..`PPH-05` (with `PPH-05` also asserting `/pythos/app/lanzar_id_accounts/{document=**}`).
  - Added `PPH-06`: Founder grant/revoke `tenant_admin` `403`, `platform_admin` `200` + atomic audit, and audit-write failure rollback (`503`, sanitized).
  - Added `PPH-07`: Revoke-all sessions `tenant_admin` `403`, `platform_admin` `200` + `COMPLETED` outbox + audit, and audit-write failure rollback (`503`, skipping Firebase Auth).
  - Added `PPH-08`: Cross-service outbox `FAILED_RETRYABLE` (`503`, sanitized) when Firebase Auth fails, and recovery to `COMPLETED` via `reconcilePlatformOutboxEvent`.
  - Added `PPH-09`: Missing/broken `auditLogService` fails closed (`503`) across all 4 mutating platform-admin routes without mutating Firestore or calling Firebase Auth.
  - Added `PPH-10`: `/api/id/ready` passes `{ bypassCache: true }` to `signingKeystore.getPublicJwks`.
- **Firestore Security Rules Emulator Suite (`auth/test-firestore-rules-emulator.cjs`, expanded from 3 to 7 tests):**
  - Preserved `RULES-01`..`RULES-03`.
  - Added `RULES-04`: Unauthenticated requests denied (`403`) on `/users/user_a` and server-only collections.
  - Added `RULES-05`: `/users/user_a` denies `create`, `delete`, disallowed fields (`status`, `tokenVersion`, `updatedAt`), and non-`https://` `avatarUrl`.
  - Added `RULES-06`: Legacy, nested, and `/pythos/app/lanzar_id_accounts/acc_1` paths (`/users/user_a/central_sessions/*`, `/users/user_a/session_slots/*`, `/users/user_a/founders/*`, `/user_security/*`, `/security_logs/*`, `/mfa_factors/*`, `/phone_otps/*`, `/admins/*`, `/pythos/app/lanzar_id_accounts/*`) denied (`403`) for GET/PATCH/DELETE.
  - Added `RULES-07`: Cross-tenant access to `/tenants/tenant_b/*` denied (`403`).

### [LOW] L-01 — Explicit Firestore Denial (`firestore.rules`)
- **Resolution:** Added explicit `match /pythos/app/lanzar_id_accounts/{document=**} { allow read, write: if false; }` in `firestore.rules` while preserving the catch-all `match /{document=**} { allow read, write: if false; }`. Verified in `PPH-05` and `RULES-06`.

---

## 2. Full Regression & Verification Results (162 / 162 Passed)

Zero production Firestore tests were executed.

### Cloud Firestore Emulator Suites (10 / 10 Passed)
| Suite | Endpoint | Result |
| :--- | :--- | :--- |
| `node auth/test-firestore-rules-emulator.cjs` | `127.0.0.1:8093` | **7 / 7** passed |
| `node auth/test-milestone-1-5-emulator.cjs` | `127.0.0.1:8092` | **3 / 3** passed |

### Local In-Memory / HTTP Suites (152 / 152 Passed)
| Suite | Environment | Result |
| :--- | :--- | :--- |
| `node auth/test-preprod-hardening.cjs` | Local Node / In-Memory | **10 / 10** passed |
| `node auth/test-milestone-1-5.cjs` | Local Node / In-Memory | **6 / 6** passed |
| `node auth/test-milestone-1-4.cjs` | Local Node / In-Memory | **10 / 10** passed |
| `node auth/test-milestone-1-3.cjs` | Local Node / In-Memory | **7 / 7** passed |
| `node auth/test-milestone-1-2.cjs` | Local Node / In-Memory | **11 / 11** passed |
| `node auth/test-milestone-1-1.cjs` | Local Node / In-Memory | **44 / 44** passed |
| `node auth/test-phase1-acceptance.cjs` | Local Node / In-Memory | **55 / 55** passed |
| `node auth/test-client-registry.cjs` | Local Node / In-Memory | **9 / 9** passed |

---

## 3. Remaining Risks & Pre-Staging Notes

- **Scheduled Outbox Worker:** `reconcilePlatformOutboxEvent` provides durable reconciliation for `FAILED_RETRYABLE` `security_outbox` records, but an automated background worker / Cloud Scheduler trigger should invoke it periodically in staging/production so transient Firebase Auth outages self-heal without manual intervention.
- **Distributed Rate Limiting:** In-memory Express rate limiting remains per-instance; front public endpoints with edge/WAF or Redis-backed rate limiting before multi-instance production scaling.
- **GCP Provisioning:** Staging/production secrets (`SIGNING_KEY_ENCRYPTION_KEY`, `RECEIPT_ENCRYPTION_KEY`, `MFA_ENCRYPTION_KEY`, `OIDC_ISSUER`), `firestore.rules` deployment, Firestore TTL policies, and PITR/backups must be provisioned in GCP before staging smoke testing.

---

## 4. Modified & Created Files

### Modified Files
- `firestore.rules`
- `auth/auth-backend/app.js`
- `auth/auth-backend/routes/adminRoutes.js`
- `auth/auth-backend/founderService.js`
- `auth/auth-backend/services/auditLogService.js`

### New / Expanded Test & Documentation Files
- `auth/test-preprod-hardening.cjs`
- `auth/test-firestore-rules-emulator.cjs`
- `_docs/auth/LANZAR_ID_PREPROD_HARDENING_REPORT.md`
- `_docs/auth/LANZAR_ID_PREPRODUCTION_SECURITY_RECONCILIATION.md`
- `_docs/auth/LANZAR_ID_PREPRODUCTION_SECURITY_CORRECTIVE_REPORT.md`

### Git Working-Tree Status (`git status --short`)
- Modified (`M`): `auth/auth-backend/app.js`, `auth/auth-backend/founderService.js`, `auth/auth-backend/routes/adminRoutes.js`, `auth/auth-backend/services/auditLogService.js`, `firestore.rules`
- Untracked (`??`): `.netlify/` (ignored/excluded), `_docs/auth/LANZAR_ID_PHASE1_*.md` (4 Phase 1 review docs), `_docs/auth/LANZAR_ID_PREPROD_HARDENING_REPORT.md`, `_docs/auth/LANZAR_ID_PREPRODUCTION_SECURITY_RECONCILIATION.md`, `_docs/auth/LANZAR_ID_PREPRODUCTION_SECURITY_CORRECTIVE_REPORT.md`, `auth/test-firestore-rules-emulator.cjs`, `auth/test-preprod-hardening.cjs`
