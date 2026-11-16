# LANZAR ID — Desired-State Reconciliation Specification

**Project:** LANZAR ID  
**Branch:** `lanzar_id_main_chat`  
**Scope:** Authoritative `/users/{uid}` Desired State, Strict Freshness Invariant (`desiredAuthVersion === event.operationVersion`), and Durable Periodic Desired-State Reconciliation (`DesiredStateReconciler`).

---

## 1. Authoritative Desired State (`/users/{uid}`)

`/users/{uid}` is the single authoritative Firestore source of truth for the latest desired Firebase Authentication state of a user:

- `desiredAuthVersion` (strictly monotonic positive integer `1, 2, 3, ...`)
- `desiredAuthDisabled` (boolean: `true` for suspended, `false` for active)
- `desiredAuthRevokedAtIso` (ISO timestamp of latest global session revocation, when applicable)
- `desiredAuthUpdatedAt` (ISO timestamp of latest desired-state mutation)

All desired-state fields are committed atomically inside Phase 1 `db.runTransaction` alongside the `security_outbox/{outboxId}` event, `admin_idempotency/{idempotencyDocId}` record, and `/tenants/lanzar/admin_audit_logs/{auditId}` entry.

---

## 2. Strict Freshness Invariant (`desiredAuthVersion === event.operationVersion`)

In `auth/auth-backend/services/platformOutboxService.js` (`claimLease`, `_assertLeaseAndFreshness`, `_fencedPersist`):

- **Missing or inconsistent version (`!Number.isInteger(desiredAuthVersion) || desiredAuthVersion < 1 || desiredAuthVersion < event.operationVersion`):** Fails closed immediately (`DEAD_LETTER` with `MISSING_DESIRED_VERSION`, `MISSING_EVENT_VERSION`, or `VERSION_MISMATCH`) and writes `platform.outbox.version_mismatch` to `admin_audit_logs`.
- **Superseded (`desiredAuthVersion > event.operationVersion`):** Atomically marks the outbox event and `admin_idempotency` record `SUPERSEDED` and writes `platform.outbox.superseded` to `admin_audit_logs` without calling `authAdmin`.
- **Current (`desiredAuthVersion === event.operationVersion`):** Eligible to execute against Firebase Auth.

---

## 3. Desired-State Reconciliation Architecture (`DesiredStateReconciler`)

- **Implementation:** `auth/auth-backend/services/desiredStateReconciler.js` (`DesiredStateReconciler`), persisted in `/auth_reconciliation/{uid}` (explicitly client-denied in `firestore.rules`).
- **Topology Decision:** Runs inside the existing persistent Railway worker process (`auth/auth-backend/worker.js`) on its own independent sweep interval (`RECONCILE_SWEEP_POLL_MS`, default `15000ms`; per-user check interval `RECONCILE_INTERVAL_MS`, default `60000ms`), sharing the same Firebase Admin client and Secret Manager configuration without doubling Railway service operational overhead.
- **State Machine (`/auth_reconciliation/{uid}`):**
  - `IDLE` / `CONVERGED` -> `IN_PROGRESS` (via transactional lease claim with `leaseOwner`, `leaseExpiresAt`, and monotonic `fencingToken`).
  - `IN_PROGRESS` -> `CONVERGED` (no drift, or drift repaired via `authAdmin.updateUser` + `revokeRefreshTokens` when `disabled === true`, auditing `platform.reconciliation.drift_repaired`).
  - `IN_PROGRESS` -> `DRIFT_RETRYABLE` (exponential backoff `nextCheckAt = nowMs + backoffMs` on Firebase Auth outage).
  - `DRIFT_RETRYABLE` -> `DEAD_LETTER` (at `attempts >= maxAttempts`, auditing `platform.reconciliation.dead_lettered`).
  - `DEAD_LETTER` -> `IDLE` (via audited operator redrive `redriveUser(...)`, auditing `platform.reconciliation.redrive`).
- **Zero Duplicate Admin Operations:** When `authUser.disabled === desiredAuthDisabled`, the reconciler marks `CONVERGED` with zero `authAdmin` writes and zero audit log entries. When drift is repaired, it records `platform.reconciliation.drift_repaired` (distinct from user-facing `platform.user.status_update` admin actions).

---

## 4. Cross-Service Consistency Guarantees & Limits

- **No Cross-Service Atomicity:** Firestore and Firebase Authentication do not share a two-phase commit coordinator.
- **Discrepancy Window:** After Phase 1 commits, actual Firebase Auth state may differ from `/users/{uid}` during: (a) Phase 2 execution / outbox retry intervals, or (b) the microsecond race window where a stale in-flight `authAdmin.updateUser` RPC completes *after* a newer outbox event was already marked `COMPLETED`.
- **Detection & Healing:** The periodic reconciler sweeps `/users` where `desiredAuthVersion >= 1` every `RECONCILE_SWEEP_POLL_MS` (default `15s`) and compares `authAdmin.getUser(uid).disabled` against `desiredAuthDisabled` at most once per `RECONCILE_INTERVAL_MS` (default `60s`) per converged user. Therefore, under normal Firebase Auth availability, even a post-`COMPLETED` stale RPC discrepancy is detected and repaired within ~`RECONCILE_INTERVAL_MS + RETRY_DELAY`.
- **Firebase Auth Outage:** Discrepancies remain in `DRIFT_RETRYABLE` with exponential backoff up to `maxAttempts` (default `5`), then transition to `DEAD_LETTER` until an operator resolves the outage and invokes `redriveUser({ uid, actorUid, ... })`.
