# LANZAR ID — Independent Refresh-Token Revocation Specification

**Project:** LANZAR ID  
**Branch:** `lanzar_id_main_chat`  
**Scope:** Independent Account-State vs. Refresh-Token Revocation Dimensions, `tokensValidAfterTime` Verification, and Durable Reconciliation.

---

## 1. Independent Desired-State Dimensions (`/users/{uid}`)

| Dimension | Authoritative Fields | Mutating Endpoint(s) | Applied/Observed Tracking |
| :--- | :--- | :--- | :--- |
| **Account Disabled State** | `desiredAuthVersion`, `desiredAuthDisabled`, `desiredAuthUpdatedAt` | `POST /api/admin/id/users/:uid/suspend` | Verified against `authUser.disabled` in `DesiredStateReconciler` |
| **Refresh-Token Revocation** | `desiredRevocationVersion`, `desiredRevokedAt`, `desiredAuthUpdatedAt` | `POST /api/admin/id/users/:uid/sessions/revoke-all` (and `suspend` when `status === 'suspended'`) | `appliedRevocationVersion`, `observedTokensValidAfterTime` (written **only** after `getUser(uid)` verifies `tokensValidAfterTime`) |

- **Isolation Rule:** Activating an account (`status: 'active'`) increments `desiredAuthVersion` only; it **never** increments, supersedes, or clears `desiredRevocationVersion` or `desiredRevokedAt`.
- **Revoke-All Atomicity:** Every accepted `POST /users/:uid/sessions/revoke-all` atomically commits `desiredRevocationVersion`, `desiredRevokedAt`, `security_outbox` (`revocationVersion`), `admin_idempotency` (`revocationVersion`), and `admin_audit_logs` inside Phase 1 `db.runTransaction`.

---

## 2. Independent Outbox Freshness & Verification (`PlatformOutboxService`)

- **Dimension-Aware Freshness (`_evaluateDimensionVersion`):**
  - `platform.user.status_update` checks `desiredAuthVersion === event.operationVersion`.
  - `platform.user.sessions_revoke_all` checks `desiredRevocationVersion === event.revocationVersion`.
  - Therefore, a newer account activation (`desiredAuthVersion` bump) **cannot** supersede an outstanding `revoke-all` event. Only a newer `revoke-all` (`desiredRevocationVersion` bump) can supersede an older `revoke-all` event.
- **Post-Revocation Verification (`_executeExternalAuth` + `_fencedPersist`):**
  - After calling `authAdmin.revokeRefreshTokens(uid)`, the worker calls `authAdmin.getUser(uid)` and verifies `tokensValidAfterTime` meets `desiredRevokedAt`.
  - If verification fails (`auth/revocation-not-verified`), the worker retries (`FAILED_RETRYABLE`) and does **not** advance `appliedRevocationVersion` or mark `COMPLETED`.

---

## 3. Timestamp Precision & Comparison Semantics

- Firebase Authentication `UserRecord.tokensValidAfterTime` has **1-second UTC resolution** (truncated to whole seconds).
- Comparison is performed at 1-second floor granularity:
  `Math.floor(Date.parse(authUser.tokensValidAfterTime) / 1000) >= Math.floor(Date.parse(desiredRevokedAt) / 1000)`
- **Documented Limitation:** Two `revokeRefreshTokens` operations issued within the same 1-second wall-clock window share the same 1-second floor. `appliedRevocationVersion` (`appliedRevocationVersion >= desiredRevocationVersion`) provides per-user monotonic version tracking alongside the 1-second timestamp check, while `DesiredStateReconciler` guarantees that even if an outbox event is superseded or fails, any unapplied revocation (`appliedRevocationVersion < desiredRevocationVersion` or stale `tokensValidAfterTime`) is repaired and verified.

---

## 4. Desired-State Reconciliation (`DesiredStateReconciler`)

- `reconcileUser(uid)` evaluates `accountDrift` and `revocationOutstanding` independently under a single transactional lease on `/auth_reconciliation/{uid}`.
- If `revocationOutstanding` (`appliedRevocationVersion < desiredRevocationVersion` or `!_isRevocationVerified(authUser, desiredRevokedAt)`):
  - If `tokensValidAfterTime` already satisfies `desiredRevokedAt`, advances `appliedRevocationVersion` without duplicate `revokeRefreshTokens` RPCs or duplicate audit logs.
  - Otherwise executes `authAdmin.revokeRefreshTokens(uid)`, re-fetches `authAdmin.getUser(uid)`, verifies `tokensValidAfterTime`, and atomically updates `appliedRevocationVersion`, `observedTokensValidAfterTime`, and `platform.reconciliation.revocation_repaired` in `admin_audit_logs`.
- Bounded retries (`DRIFT_RETRYABLE`) -> `DEAD_LETTER` -> audited operator redrive (`redriveUser`).
