# LANZAR ID — Pre-Production Final Code Review

**Project:** LANZAR ID  
**Branch:** `lanzar_id_main_chat`  
**Review Type:** Read-only final code review (no files modified, no commits, no deployments)  
**Baseline Commits Preserved:**  
- M1.4: `5fb79411e0bf94131f60fb38d1d57a906067b8d9`  
- M1.5: `80c1dec6760a604badaa06e87549ba67e97ef51c`  

---

## Executive Recommendation

**Recommendation: ADDITIONAL CORRECTIONS REQUIRED (or explicit risk acceptance) before commit/staging.**

Audit atomicity for purely Firestore mutations (`founderService.js`) and Phase 1 of cross-service mutations (`adminRoutes.js`) is **sound and fail-closed**. However, the new cross-service outbox reconciler (`reconcilePlatformOutboxEvent`) is **manual-only** with **no background worker, no concurrency lease, no retry limit/dead-lettering, no recovery audit, and no HTTP `Idempotency-Key` protection** against client retries after `503 external_auth_sync_pending`.

---

## 1. Findings Ranked by Severity

### [HIGH] FR-01: Outbox Reconciler Lacks Automatic Execution, Concurrency Leases, Retry Limits, Dead-Lettering, and Recovery Auditing (`adminRoutes.js:13-68`)
- **Code References:** `auth/auth-backend/routes/adminRoutes.js` lines `13-68` (`reconcilePlatformOutboxEvent`), lines `273` and `421` (inline invocation only).
- **Details:**
  1. **Manual-only beyond inline call:** No background worker, Cloud Scheduler endpoint, or Firestore trigger in `app.js` or `auth/auth-backend` polls or sweeps `PENDING_EXTERNAL_AUTH` or `FAILED_RETRYABLE` records in `security_outbox`. If Phase 2 fails (`503 external_auth_sync_pending`), the event stays stuck until an operator or external script calls `reconcilePlatformOutboxEvent({ db, authAdmin, outboxId })`.
  2. **No persistent retry scheduling:** `reconcilePlatformOutboxEvent` increments `attempts` (`lines 30, 56, 62`) and sets `status: 'FAILED_RETRYABLE'` (`line 61`), but stores no `nextRetryAt` / backoff schedule.
  3. **No leases or concurrency protection:** `line 18` performs a plain `outboxRef.get()` followed by `authAdmin` calls and `outboxRef.update(...)` (`lines 54, 60`). Concurrent workers can both read the same `PENDING_EXTERNAL_AUTH` / `FAILED_RETRYABLE` event and execute `authAdmin` concurrently, with no `leaseOwner` / `leaseExpiresAt` claim or expired-lease recovery.
  4. **Stale-ordering hazard:** Because there is no sequence/version check against `users/{uid}`, a delayed retry of an older `suspend` (`disabled: true`) outbox event after a newer `activate` (`disabled: false`) event could revert Firebase Auth `disabled` state.
  5. **No retry cap or dead-letter state:** `attempts` increments unboundedly; no `maxAttempts` or `DEAD_LETTER` / `FAILED_PERMANENT` transition exists.
  6. **Recovery is not audited:** Successful reconciliation updates `security_outbox/{outboxId}` (`lines 54-59`) but writes **no** completion/recovery record to `/tenants/lanzar/admin_audit_logs` (the Phase 1 audit record permanently remains `outcome: 'pending_external_auth'`).

### [MEDIUM] FR-02: Missing `Idempotency-Key` / Retry Deduplication on Mutating `POST` Routes (`adminRoutes.js:192-436`)
- **Code References:** `auth/auth-backend/routes/adminRoutes.js` lines `109`, `204`, `381`.
- **Details:** Every `POST /users/:uid/suspend`, `POST /users/:uid/sessions/revoke-all`, and `POST /users/:uid/founders` generates fresh `outboxId = outbox_${crypto.randomUUID()}` and `auditId = aud_${crypto.randomUUID()}`. If a client receives `503 external_auth_sync_pending` and retries the `POST` request, the server executes a **second** Firestore transaction, increments `tokenVersion` again, and creates duplicate `security_outbox` and `admin_audit_logs` documents.
- **Safe Client Behavior Today:** Clients receiving `503 external_auth_sync_pending` must **not** blindly retry the `POST` mutation; they must treat the Firestore mutation as committed and reconcile via `outboxId` (though no HTTP reconciliation endpoint currently exists).

### [MEDIUM] FR-03: `adminRoutes.js` Transaction Behavior Only Tested Against `InMemoryFirestore`, Not Cloud Firestore Emulator (`test-preprod-hardening.cjs`)
- **Code References:** `auth/test-preprod-hardening.cjs` lines `14-90` (`InMemoryFirestore`), `260-480` (`PPH-06`..`PPH-09`); `auth/auth-backend/routes/adminRoutes.js` lines `222-265`, `390-415`.
- **Details:**
  1. `InMemoryFirestore.where()` (`line 70`) returns `this` without filtering (`revoked == false` is not filtered in memory).
  2. `FieldValue.increment(1)` and `FieldValue.serverTimestamp()` are stored as raw sentinel objects in `InMemoryFirestore` rather than evaluated by Firestore.
  3. `PPH-06` tests audit-write failure rollback on founder **grant**, but not on founder **revoke**.
  4. `PPH-08` tests basic failure -> `reconcilePlatformOutboxEvent` recovery, but does **not** test duplicate `reconcilePlatformOutboxEvent` calls (`alreadyCompleted: true`), partial failure (`updateUser` succeeds, `revokeRefreshTokens` fails), or crash-after-Auth-before-outbox-update recovery.

---

## 2. Outbox Lifecycle, Idempotency & Recovery Assessment

| Capability | Status | Evidence (`adminRoutes.js`) |
| :--- | :--- | :--- |
| Durable outbox creation in same tx as Firestore state + audit | **Implemented** | `lines 251-267`, `400-416` (`tx.create(db.collection('security_outbox')...)`) |
| Inline Phase 2 execution immediately after Phase 1 | **Implemented** | `lines 273`, `421` |
| Automatic background sweeping / persistent retry scheduler | **Not Implemented** | Exported helper only (`line 512`); no worker/cron/trigger |
| Worker leases & expired-lease recovery | **Not Implemented** | Plain `outboxRef.get()` + `outboxRef.update()` (`lines 18, 54, 60`) |
| Completed-event guard (`alreadyCompleted: true`) | **Implemented** | `lines 22-24` |
| Idempotency after partial Auth failure or post-Auth crash | **Partial** | `updateUser` + `revokeRefreshTokens` are idempotent in Firebase Auth for identical state (`lines 32-45`), but no sequence guard against newer conflicting operations |
| Retry limits & dead-letter handling | **Not Implemented** | `attempts` incremented without cap (`lines 30, 61`) |
| Recovery audit event in `admin_audit_logs` | **Not Implemented** | Only `security_outbox` is updated (`lines 54-59`) |

---

## 3. Administrative API Behavior

- **`POST /api/admin/id/users/:uid/suspend` (`adminRoutes.js:192-292`):** Validates `status`, enforces `requirePlatformAdmin` and `ensureAuditDependencies`, runs atomic Phase 1 (`users/{uid}`, `sessions`/`central_sessions` when suspending, `security_outbox`, `admin_audit_logs`), then Phase 2 (`authAdmin.updateUser` + `revokeRefreshTokens`). Returns `503 audit_persistence_failed` if Phase 1 fails (zero mutation), `503 external_auth_sync_pending` (with `outboxId`, `auditId`, `correlationId`) if Phase 2 fails, and `200` on full success. All error responses are sanitized.
- **`POST /api/admin/id/users/:uid/sessions/revoke-all` (`adminRoutes.js:375-441`):** Same Phase 1 + Phase 2 semantics (`503 audit_persistence_failed` on Phase 1 failure; `503 external_auth_sync_pending` with `outboxId`, `auditId`, `revokedSessionsCount`, `correlationId` on Phase 2 failure; `200` on success).
- **`POST /api/admin/id/users/:uid/founders` & `DELETE /api/admin/id/users/:uid/founders/:programId` (`adminRoutes.js:294-373`):** Purely Firestore; delegated to `FounderService` with `auditLogService` + `auditPrepared` inside `db.runTransaction(...)`. Returns `503 audit_persistence_failed` on audit/transaction failure with full rollback.

---

## 4. Audit Integrity Assessment

- **Founder Grant & Revoke (`founderService.js:103-128, 173-204`):** Confirmed atomic. Reads (`activeQuery`, `founderRef`) precede writes inside `db.runTransaction`; `founderRef`, `users/{uid}.derivedBadges`, and `admin_audit_logs/{auditId}` commit together. Audit failure aborts the transaction and prevents Firestore mutation.
- **Cross-Service Operations (`adminRoutes.js:218-269, 390-418`):** Confirmed atomic for Phase 1. `users/{uid}`, `sessions`, `central_sessions`, `security_outbox/{outboxId}`, and `admin_audit_logs/{auditId}` are written in the same `db.runTransaction`. Audit failure aborts Phase 1 before any Firestore write commits and before `authAdmin` is invoked.

---

## 5. Required / Recommended Corrections Before Commit

1. **[MUST FIX before staging / recommended before commit]** Harden `reconcilePlatformOutboxEvent` (`adminRoutes.js`):
   - Claim the outbox event atomically via `db.runTransaction` using a lease (`status: 'IN_PROGRESS'`, `leaseOwner`, `leaseExpiresAt`) and allow expired-lease recovery.
   - Enforce `maxAttempts` (e.g., `5`) transitioning to `DEAD_LETTER` after exhaustion.
   - Record an administrative recovery/completion audit event in `admin_audit_logs` when `reconcilePlatformOutboxEvent` transitions a `FAILED_RETRYABLE` (or reconciled) event to `COMPLETED`.
   - Support an optional `Idempotency-Key` header on `POST /users/:uid/suspend` and `POST /users/:uid/sessions/revoke-all` (or document explicit non-retry contract + expose a `platform_admin` `/outbox/:outboxId/reconcile` endpoint).
2. **[SHOULD FIX]** Add tests in `test-preprod-hardening.cjs` (and/or a Firestore Emulator integration test for `adminRoutes.js`) covering:
   - Duplicate `reconcilePlatformOutboxEvent` (`alreadyCompleted: true`), partial Auth failure (`updateUser` succeeds, `revokeRefreshTokens` fails), concurrent lease contention + expired lease recovery, max-attempts `DEAD_LETTER`, and founder revoke audit-failure rollback.
   - Real Cloud Firestore Emulator execution of `adminRoutes.js` transactions (`FieldValue.increment`, `serverTimestamp`, `.where('revoked', '==', false)`).
