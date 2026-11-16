# LANZAR ID — Pre-Production Outbox & Idempotency Verification Report

**Project:** LANZAR ID  
**Branch:** `lanzar_id_main_chat`  
**Baseline Commits Preserved:**  
- M1.4: `5fb79411e0bf94131f60fb38d1d57a906067b8d9`  
- M1.5: `80c1dec6760a604badaa06e87549ba67e97ef51c`  

**Scope:** Implementation and verification of **FR-01** (Durable Outbox Processing & Worker), **FR-02** (Mandatory Scoped `Idempotency-Key` Handling), Cross-Service Operation Recovery, and **FR-03** (Live Cloud Firestore Emulator Test Coverage).  
**Git / Deployment Status:** Local working tree only. Nothing committed, amended, pushed, or deployed. Zero production tests executed.

---

## 1. Implemented Architecture Summary

- **Durable Outbox & Worker (`auth/auth-backend/services/platformOutboxService.js`, `auth/auth-backend/worker.js`):**
  - Transactional lease claim (`claimLease`) with `leaseOwner`, `leaseExpiresAt`, and monotonic `fencingToken` (`+1`), including expired-lease recovery.
  - Fenced persistence (`_fencedPersist`) rejecting stale workers (`STALE_FENCING_TOKEN`) inside `db.runTransaction`.
  - Bounded exponential-backoff retries (`FAILED_RETRYABLE` with `nextRetryAt`) transitioning to `DEAD_LETTER` at `maxAttempts` with `platform.outbox.dead_lettered` audit logging.
  - Durable `progress` markers (`updateUserDone`, `revokeRefreshTokensDone`) for partial Firebase Auth failure recovery across worker restarts.
  - Audited administrative redrive (`redriveEvent` + `POST /api/admin/id/outbox/:outboxId/redrive` + `GET /api/admin/id/outbox/:outboxId`) writing `platform.outbox.redrive` and `platform.outbox.completed` to `/tenants/lanzar/admin_audit_logs`.
- **Mandatory Scoped Idempotency (`auth/auth-backend/routes/adminRoutes.js`, `firestore.rules`):**
  - Enforced `Idempotency-Key` (`16–128` chars `[A-Za-z0-9._:-]`) on `POST /api/admin/id/users/:uid/suspend` and `POST /api/admin/id/users/:uid/sessions/revoke-all`.
  - Scoped to `(actorUid, actorTenantId, operation, targetUid, key)` hashed to `idem_<sha256>` in `/admin_idempotency/{keyHash}` (explicitly client-denied in `firestore.rules`), persisted atomically in Phase 1 `db.runTransaction` with user/session state, `security_outbox`, and `admin_audit_logs`.
  - Payload conflicts return `409 idempotency_key_conflict`; concurrent/sequential duplicate requests replay without extra mutations, outbox events, audit entries, or `tokenVersion` increments, returning `200` (`externalAuthStatus: 'completed' | 'superseded'`) or `503` (`externalAuthStatus: 'pending' | 'dead_letter'`).
- **Per-User Causal Ordering (`desiredAuthVersion` / `SUPERSEDED`):**
  - Phase 1 `db.runTransaction` reads `/users/{uid}` and assigns a strictly monotonic `operationVersion = desiredAuthVersion + 1`, persisted atomically on `/users/{uid}`, `security_outbox`, `admin_idempotency`, and `admin_audit_logs`.
  - `PlatformOutboxService` (`claimLease`, `_assertLeaseAndFreshness`, `_fencedPersist`) rejects stale events (`desiredAuthVersion > event.operationVersion`), marks them `SUPERSEDED` with `platform.outbox.superseded` audit logging, and prevents stale events from calling `authAdmin` or being redriven (`409 outbox_superseded`).

---

## 2. Exact Verification Results (172 / 172 Passed)

**Test Double Note:** In `test-outbox-idempotency-emulator.cjs` and `test-preprod-hardening.cjs`, Firestore transactions, queries, and `FieldValue` operations run against the **real Cloud Firestore Emulator** (in `test-outbox-idempotency-emulator.cjs`) or `InMemoryFirestore`, while Firebase Authentication (`authAdmin.updateUser`, `authAdmin.revokeRefreshTokens`) uses a deterministic in-process test double for fault injection. Zero tests were run against live production Firebase Auth or production Firestore.

### Cloud Firestore Emulator Suites (20 / 20 Passed)
| Suite | Endpoint | Result |
| :--- | :--- | :--- |
| `node auth/test-outbox-idempotency-emulator.cjs` | `127.0.0.1:8094` | **10 / 10** passed |
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

## 3. Recommended Deployment Topology

1. **API Service (`node auth/auth-backend/server.js`):** Serves HTTP endpoints, runs Phase 1 atomic Firestore transactions + inline Phase 2 best-effort sync.
2. **Persistent Worker Service (`node auth/auth-backend/worker.js`):** Deployed as a **separate Railway worker service** (no public HTTP port required) sharing the same GCP/Firebase project, Secret Manager keys, and Firestore database. Polls `security_outbox` every `OUTBOX_WORKER_POLL_MS` (default `5000ms`), recovers expired leases (`OUTBOX_LEASE_DURATION_MS`, default `30000ms`), and converges `FAILED_RETRYABLE` events up to `OUTBOX_MAX_ATTEMPTS` (default `5`).
3. **Firestore Configuration:** Deploy `firestore.rules`, create composite index `(type ASC, status ASC, nextRetryAt ASC)` on `security_outbox`, and configure Firestore TTL on `admin_idempotency.expiresAt`.

---

## 4. Modified & Created Files

- **Modified:** `firestore.rules`, `auth/auth-backend/app.js`, `auth/auth-backend/founderService.js`, `auth/auth-backend/routes/adminRoutes.js`, `auth/auth-backend/services/auditLogService.js`
- **Created (Code & Tests):** `auth/auth-backend/services/platformOutboxService.js`, `auth/auth-backend/worker.js`, `auth/test-outbox-idempotency-emulator.cjs`, `auth/test-firestore-rules-emulator.cjs`, `auth/test-preprod-hardening.cjs`
- **Created (Docs):** `_docs/auth/LANZAR_ID_PREPRODUCTION_OUTBOX_AND_IDEMPOTENCY_SPECIFICATION.md`, `_docs/auth/LANZAR_ID_PREPRODUCTION_OUTBOX_AND_IDEMPOTENCY_REPORT.md` (plus prior hardening/reconciliation/review reports under `_docs/auth/`)

---

## 5. Remaining Risks

- **No Causal Sequence Guard Across Conflicting Outbox Events:** Rapidly issuing `suspend` then `activate` while the first event is still retrying requires operator inspection (`GET /api/admin/id/outbox/:outboxId`) before redriving stale `DEAD_LETTER` events.
- **Real Firebase Auth Integration:** External Firebase Auth convergence was verified against a deterministic test double; verify live Firebase Auth IAM permissions in the controlled staging smoke test before production cutover.
- **Distributed Rate Limiting:** Express rate limiting remains per-instance; front public endpoints with edge/WAF or shared Redis rate limiting before multi-instance production scaling.
