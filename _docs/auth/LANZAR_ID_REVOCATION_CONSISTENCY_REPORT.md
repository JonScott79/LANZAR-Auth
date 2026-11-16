# LANZAR ID — Refresh-Token Revocation Consistency Report

**Project:** LANZAR ID  
**Branch:** `lanzar_id_main_chat`  
**Baseline Commits Preserved:**  
- M1.4: `5fb79411e0bf94131f60fb38d1d57a906067b8d9`  
- M1.5: `80c1dec6760a604badaa06e87549ba67e97ef51c`  

**Scope:** Implementation and verification of the independent refresh-token revocation dimension (`desiredRevocationVersion`, `desiredRevokedAt`, `appliedRevocationVersion`, `observedTokensValidAfterTime`), `tokensValidAfterTime` post-RPC verification, and independent `DesiredStateReconciler` coverage.  
**Git / Deployment Status:** Local changes only. Nothing committed, amended, pushed, or deployed. Zero production tests executed.

---

## 1. Exact Verification Results (184 / 184 Passed)

**Emulator vs. Simulated External Auth:** Firestore transactions, rules, queries, and `FieldValue` operations in the emulator suites ran against the **real Cloud Firestore Emulator**. External Firebase Auth calls (`getUser`, `updateUser`, `revokeRefreshTokens`) in the pre-production emulator and hardening suites used a **deterministic in-process Firebase Auth test double** with async barriers for fault and race injection. **Zero** tests ran against live Firebase Auth or production Firestore.

### Cloud Firestore Emulator Suites (32 / 32 Passed)
| Suite | Endpoint | Result |
| :--- | :--- | :--- |
| `node auth/test-revocation-consistency-emulator.cjs` | `127.0.0.1:8096` | **7 / 7** passed (`EMU-REV-01`–`10`) |
| `node auth/test-desired-state-reconciliation-emulator.cjs` | `127.0.0.1:8095` | **5 / 5** passed (`EMU-REC-01`–`05`) |
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

## 2. Modified & Created Files

- **Modified:** `auth/auth-backend/routes/adminRoutes.js`, `auth/auth-backend/services/platformOutboxService.js`, `auth/auth-backend/services/desiredStateReconciler.js`, `auth/test-outbox-idempotency-emulator.cjs`, `auth/test-desired-state-reconciliation-emulator.cjs`, `_docs/auth/LANZAR_ID_PREPRODUCTION_FINAL_SIGNOFF.md`
- **Created:** `auth/test-revocation-consistency-emulator.cjs`, `_docs/auth/LANZAR_ID_REVOCATION_CONSISTENCY_SPECIFICATION.md`, `_docs/auth/LANZAR_ID_REVOCATION_CONSISTENCY_REPORT.md`

---

## 3. Remaining Limitations

- Firebase Auth `tokensValidAfterTime` has 1-second resolution; two revocations within the same second rely on `appliedRevocationVersion` monotonicity rather than sub-second timestamp differences.
- Live Firebase Auth IAM permissions and `tokensValidAfterTime` behavior must be verified during the controlled staging smoke test before claiming staging or production readiness.
- Strict atomic consistency across Firestore and Firebase Auth is not claimed; cross-service consistency is eventual convergence via the durable outbox + `DesiredStateReconciler`.
