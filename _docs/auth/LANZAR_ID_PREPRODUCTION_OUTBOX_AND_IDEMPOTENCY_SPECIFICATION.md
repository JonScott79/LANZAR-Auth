# LANZAR ID — Pre-Production Outbox & Idempotency Specification

**Project:** LANZAR ID  
**Branch:** `lanzar_id_main_chat`  
**Scope:** Durable Transactional Outbox, Lease/Fencing Worker, Bounded Retries/Dead-Lettering, Audited Redrive, Partial-Progress Recovery, and Mandatory `Idempotency-Key` Handling for Cross-Service Platform-Admin Operations.

---

## 1. Consistency Guarantees (Honest Architectural Boundary)

Firestore and Firebase Authentication are **separate distributed systems** without a shared two-phase commit (2PC) coordinator:

- **Within Firestore:** Phase 1 atomically persists user/session state (`/users/{uid}`, `/users/{uid}/sessions/*`, `/users/{uid}/central_sessions/*`), the `security_outbox/{outboxId}` event, the `admin_idempotency/{idempotencyDocId}` record, and the `/tenants/lanzar/admin_audit_logs/{auditId}` entry inside a single `db.runTransaction(...)`. If any write (including the required audit log) fails, the entire Phase 1 transaction aborts with zero state change.
- **Across Firestore and Firebase Auth:** Consistency is **eventual convergence** driven by the durable outbox (`PlatformOutboxService` + `worker.js`), never claimed as cross-service atomicity. Because Firebase Auth `updateUser({ disabled })` and `revokeRefreshTokens(uid)` are desired-state/idempotent operations for a given target state, retries converge safely onto the intended final state.

---

## 2. Outbox State Machine (`security_outbox/{outboxId}`)

| State | Meaning | Transitions To |
| :--- | :--- | :--- |
| `PENDING_EXTERNAL_AUTH` | Phase 1 committed; awaiting Firebase Auth convergence | `IN_PROGRESS` |
| `IN_PROGRESS` | Claimed by a worker with `leaseOwner`, `leaseExpiresAt`, and `fencingToken` | `COMPLETED`, `FAILED_RETRYABLE`, `DEAD_LETTER`, or `IN_PROGRESS` (expired lease takeover) |
| `FAILED_RETRYABLE` | External Auth step failed; `attempts < maxAttempts`; waiting until `nextRetryAt` | `IN_PROGRESS`, or `PENDING_EXTERNAL_AUTH` (via admin redrive) |
| `DEAD_LETTER` | `attempts >= maxAttempts`; automatic worker sweeps ignore this record | `PENDING_EXTERNAL_AUTH` (via audited admin redrive only) |
| `COMPLETED` | External Auth converged; terminal success state | Terminal (re-execution returns `alreadyCompleted: true`) |

---

## 3. Worker Architecture & Deployment Topology

- **Implementation:** `auth/auth-backend/services/platformOutboxService.js` (`PlatformOutboxService`) + `auth/auth-backend/worker.js` (standalone persistent worker process).
- **Recommended Deployment Topology:** Run `worker.js` as a **separate Railway worker service** sharing the same GCP/Firebase project, Secret Manager environment variables (`bootstrap()`, `validateReceiptKeyConfiguration()`, `validateSigningKeyEncryptionConfiguration()`), and Firestore database as `server.js` (the HTTP API service).
  - *Why a separate Railway worker service:* HTTP request handlers (`server.js`) remain fast and stateless; pending events survive API restarts, client disconnects, and transient Firebase Auth outages without blocking HTTP threads or relying on in-process memory.
  - *Configuration:* `OUTBOX_WORKER_POLL_MS` (default `5000`), `OUTBOX_LEASE_DURATION_MS` (default `30000`), `OUTBOX_MAX_ATTEMPTS` (default `5`).
  - *Firestore Index Note:* For production scale, create a composite index on `security_outbox` (`type ASC`, `status ASC`, `nextRetryAt ASC`).

---

## 4. Lease, Fencing, Retry & Dead-Letter Policy

- **Transactional Lease Claim (`claimLease`):** Runs inside `db.runTransaction`. Rejects if `COMPLETED`, `DEAD_LETTER`, `IN_PROGRESS` with `leaseExpiresAt > nowMs`, or `FAILED_RETRYABLE` with `nextRetryAt > nowMs` (unless `ignoreBackoff: true` for explicit manual reconciliation). On claim (including expired-lease recovery when `leaseExpiresAt <= nowMs`), increments `fencingToken` (`+1`), sets `leaseOwner`, `leaseExpiresAt = nowMs + leaseDurationMs`, and `status = 'IN_PROGRESS'`.
- **Fenced Persistence (`_fencedPersist`):** Every completion, retryable failure, or dead-letter transition executes inside `db.runTransaction` and verifies `status === 'IN_PROGRESS' && leaseOwner === workerId && fencingToken === expectedToken`. A stale worker whose lease expired is fenced out (`STALE_FENCING_TOKEN`) and cannot overwrite a newer worker's state.
- **Bounded Retries & Backoff:** Exponential backoff `min(maxBackoffMs, baseBackoffMs * 2^(attempts - 1))` (defaults: `1000ms` base, `60000ms` max, `5` max attempts). At `attempts >= maxAttempts`, transitions to `DEAD_LETTER` and atomically writes `platform.outbox.dead_lettered` to `admin_audit_logs`.
- **Audited Administrative Redrive:** `POST /api/admin/id/outbox/:outboxId/redrive` (`requirePlatformAdmin`) calls `PlatformOutboxService.redriveEvent(...)`, which atomically resets `DEAD_LETTER` / `FAILED_RETRYABLE` to `PENDING_EXTERNAL_AUTH` (`attempts: 0`), writes `platform.outbox.redrive` to `admin_audit_logs`, and executes immediate reconciliation (writing `platform.outbox.completed` on convergence).

---

## 5. Partial Failure Recovery

For `platform.user.status_update`, `security_outbox/{outboxId}` persists a `progress` map:
- `progress.updateUserDone` (`boolean`)
- `progress.revokeRefreshTokensDone` (`boolean`)

If `authAdmin.updateUser` succeeds and `authAdmin.revokeRefreshTokens` fails, `progress.updateUserDone: true` is persisted with the `FAILED_RETRYABLE` transition. Subsequent worker retries (or a restarted worker) skip `updateUser` and execute only `revokeRefreshTokens`. If a worker crashes after `updateUser` succeeds but before persisting `progress.updateUserDone: true`, re-running `updateUser` with the same `disabled` boolean is idempotent and converges safely.

---

## 6. Durable Idempotency (`admin_idempotency/{idempotencyDocId}`)

- **Applicable Routes:** `POST /api/admin/id/users/:uid/suspend` and `POST /api/admin/id/users/:uid/sessions/revoke-all`.
- **Header Validation:** `Idempotency-Key` is mandatory (`8–128` characters matching `/^[A-Za-z0-9._:-]+$/`). Missing or malformed keys return `400 invalid_idempotency_key`.
- **Scoping & Document Key:** `sha256("${actorUid}:${actorTenantId}:${operation}:${targetUid}:${rawKey}")` prefixed with `idem_`.
- **Payload Verification:** Canonical request payload is hashed (`requestHash`). Reusing the same key with a different payload returns `409 idempotency_key_conflict` with zero state mutation.
- **Atomic Persistence:** `admin_idempotency/{idempotencyDocId}` is read and created inside the same Phase 1 `db.runTransaction` as the user/session mutation, `security_outbox` event, and `admin_audit_logs` record. Concurrent identical HTTP requests serialize via Firestore transactions: exactly one executes Phase 1 (and increments `tokenVersion` once), while duplicates replay without additional mutations, outbox events, or audit entries.
- **Replay Semantics:**
  - Outbox `COMPLETED` -> HTTP `200` (`{ ...responseSnapshot, idempotentReplay: true, externalAuthStatus: 'completed' }`).
  - Outbox `PENDING_EXTERNAL_AUTH` / `IN_PROGRESS` / `FAILED_RETRYABLE` -> HTTP `503` (`error: 'external_auth_sync_pending'`, `idempotentReplay: true`, `externalAuthStatus: 'pending'`).
  - Outbox `DEAD_LETTER` -> HTTP `503` (`error: 'external_auth_sync_dead_letter'`, `idempotentReplay: true`, `externalAuthStatus: 'dead_letter'`).
- **Retention & Cleanup:** Records store `expiresAt` (`createdAt + 24 hours`). Configure a Firestore TTL policy on `admin_idempotency.expiresAt` in GCP. Client access is explicitly denied in `firestore.rules` (`match /admin_idempotency/{keyHash} { allow read, write: if false; }`).

---

## 7. Operational Monitoring & Remaining Limitations

- **Monitoring:** Alert on `security_outbox` documents with `status == 'DEAD_LETTER'` or `status == 'FAILED_RETRYABLE'` older than `2 * leaseDurationMs`, and monitor `platform.outbox.dead_lettered` / `platform.outbox.redrive` events in `admin_audit_logs`.
- **Remaining Limitations:**
  - `worker.js` is implemented and ready to run as a separate Railway worker service, but is **not yet deployed**.
  - Cross-service outbox events do not enforce a causal sequence number against newer conflicting status updates (`suspend` followed immediately by `activate` while the first outbox event is still retrying); operators should inspect `GET /api/admin/id/outbox/:outboxId` before redriving stale `DEAD_LETTER` events.
