# LANZAR ID — Desired-State Reconciliation Verification Report

**Project:** LANZAR ID  
**Branch:** `lanzar_id_main_chat`  
**Baseline Commits Preserved:**  
- M1.4: `5fb79411e0bf94131f60fb38d1d57a906067b8d9`  
- M1.5: `80c1dec6760a604badaa06e87549ba67e97ef51c`  

**Scope:** Authoritative `/users/{uid}` desired state, strict `desiredAuthVersion === event.operationVersion` freshness invariant, and durable `DesiredStateReconciler` with async-barrier emulator tests (`Race A`, `Race B`, missing/mismatch versions, idempotency, concurrency, outage/redrive).  
**Git / Deployment Status:** Local changes only. Nothing committed, amended, pushed, or deployed. Zero production tests executed.

---

## 1. Implemented Changes

- **`auth/auth-backend/routes/adminRoutes.js`:** Atomically persists `desiredAuthVersion`, `desiredAuthDisabled`, `desiredAuthUpdatedAt` (and `desiredAuthRevokedAtIso` on `revoke-all`) on `/users/{uid}` in Phase 1 `db.runTransaction`.
- **`auth/auth-backend/services/platformOutboxService.js`:** Enforces strict `desiredAuthVersion === event.operationVersion` across `claimLease`, `_assertLeaseAndFreshness`, and `_fencedPersist`; fails closed (`DEAD_LETTER` + `platform.outbox.version_mismatch` audit) when `desiredAuthVersion` or `event.operationVersion` is missing or inconsistent.
- **`auth/auth-backend/services/desiredStateReconciler.js`:** Implements `DesiredStateReconciler` against `/auth_reconciliation/{uid}` with transactional leases, fencing tokens, exponential backoff (`DRIFT_RETRYABLE`), `DEAD_LETTER`, audited drift repair (`platform.reconciliation.drift_repaired`), and audited operator redrive (`redriveUser`, `platform.reconciliation.redrive`).
- **`auth/auth-backend/worker.js`:** Runs `DesiredStateReconciler` alongside `PlatformOutboxService` in the persistent Railway worker service.
- **`firestore.rules`:** Explicitly denies client access to `/auth_reconciliation/{uid}` (`allow read, write: if false;`).

---

## 2. Exact Verification Results (177 / 177 Passed)

**Simulation vs. Real Integration:** Firestore transactions, security rules, queries, and `FieldValue` operations in the emulator suites execute against the **real Cloud Firestore Emulator**. External Firebase Auth calls (`getUser`, `updateUser`, `revokeRefreshTokens`) in `test-desired-state-reconciliation-emulator.cjs`, `test-outbox-idempotency-emulator.cjs`, and `test-preprod-hardening.cjs` use a **deterministic in-process Firebase Auth test double** with async barriers for fault/race injection. Zero tests were run against live Firebase Auth or production Firestore.

### Cloud Firestore Emulator Suites (25 / 25 Passed)
| Suite | Endpoint | Result |
| :--- | :--- | :--- |
| `node auth/test-desired-state-reconciliation-emulator.cjs` | `127.0.0.1:8095` | **5 / 5** passed (`EMU-REC-01`–`05`, Race A & Race B) |
| `node auth/test-outbox-idempotency-emulator.cjs` | `127.0.0.1:8094` | **10 / 10** passed (`EMU-OI-01`–`10`) |
| `node auth/test-firestore-rules-emulator.cjs` | `127.0.0.1:8093` | **7 / 7** passed (`RULES-01`–`07`) |
| `node auth/test-milestone-1-5-emulator.cjs` | `127.0.0.1:8092` | **3 / 3** passed (`EMU-M1.5-01`–`03`) |

### Local In-Memory / HTTP Suites (152 / 152 Passed)
| Suite | Result |
| :--- | :--- |
| `node auth/test-preprod-hardening.cjs` | **10 / 10** passed |
| `node auth/test-milestone-1-5.cjs` | **6 / 6** passed |
| `node auth/test-milestone-1-4.cjs` | **10 / 10** passed |
| `node auth/test-milestone-1-3.cjs` | **7 / 7** passed |
| `node auth/test-milestone-1-2.cjs` | **11 / 11** passed |
| `node auth/test-milestone-1-1.cjs` | **44 / 44** passed |
| `node auth/test-phase1-acceptance.cjs` | **55 / 55** passed |
| `node auth/test-client-registry.cjs` | **9 / 9** passed |

---

## 3. Remaining Limitations

- Live Firebase Auth IAM permissions and real network latency must be verified during the controlled staging smoke test before claiming staging or production readiness.
- Express rate limiting remains per-instance; front public endpoints with edge/WAF or Redis-backed rate limiting before multi-instance production scaling.
