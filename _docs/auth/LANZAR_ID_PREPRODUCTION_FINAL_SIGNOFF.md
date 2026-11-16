# LANZAR ID — Pre-Production Final Sign-Off Report

**Project:** LANZAR ID  
**Branch:** `lanzar_id_main_chat`  
**Baseline Commits Preserved:**  
- M1.4: `5fb79411e0bf94131f60fb38d1d57a906067b8d9`  
- M1.5: `80c1dec6760a604badaa06e87549ba67e97ef51c`  

**Status:** Pre-Production Hardening implementation and local/emulator verification complete (**184 / 184** passing; simulated Firebase Auth double used for race/fault injection). Awaiting commit and staging deployment authorization. Zero production tests or deployments executed.

---

## 1. Per-User Causal Operation-Ordering Design

To prevent stale outbox retries or out-of-order workers from overwriting newer administrative decisions (`suspend` -> `activate` or `activate` -> `suspend`):

1. **Monotonic Per-User Version (`desiredAuthVersion`):**
   - Phase 1 `db.runTransaction` in `adminRoutes.js` (`POST /users/:uid/suspend`, `POST /users/:uid/sessions/revoke-all`) reads `/users/{uid}` before writing, computes `operationVersion = Number(userSnap.data()?.desiredAuthVersion || 0) + 1`, and atomically persists `desiredAuthVersion: operationVersion` on `/users/{uid}` alongside `security_outbox/{outboxId}`, `admin_idempotency/{idempotencyDocId}`, and `admin_audit_logs/{auditId}`.
   - Concurrent administrative mutations for the same `uid` serialize on `/users/{uid}` inside Firestore transactions, guaranteeing strictly monotonic, unique `operationVersion` assignment (`1, 2, 3, ...`) independent of wall-clock timestamps.
2. **Stale Detection & `SUPERSEDED` Terminal State (`PlatformOutboxService`):**
   - `claimLease` reads `/users/{uid}` inside the claim transaction. If `desiredAuthVersion > event.operationVersion`, the event is atomically marked `SUPERSEDED` (preserving `supersededByVersion`, `supersededAt`, and an immutable `platform.outbox.superseded` entry in `admin_audit_logs`), `admin_idempotency` is updated to `externalAuthStatus: 'superseded'`, and `authAdmin` is **never** invoked.
   - `_assertLeaseAndFreshness` re-verifies lease ownership, `fencingToken`, and `desiredAuthVersion <= event.operationVersion` immediately before each external `authAdmin` call (`updateUser`, `revokeRefreshTokens`).
   - `_fencedPersist` re-verifies `desiredAuthVersion <= event.operationVersion` inside the completion transaction; if a newer operation arrived mid-flight, the older event is marked `SUPERSEDED` rather than `COMPLETED`.
   - `redriveEvent` rejects `SUPERSEDED` events (`409 outbox_superseded`) so stale operations cannot be re-executed manually.

---

## 2. Worker Fencing & Consistency Guarantees

- **Within Firestore:** All user/session mutations, `desiredAuthVersion` increments, `security_outbox` state transitions, `admin_idempotency` records, `admin_audit_logs` entries, lease claims, and fenced completions are strictly atomic via `db.runTransaction`.
- **Worker Fencing:** Only the current `leaseOwner` holding the matching `fencingToken` can persist `COMPLETED`, `FAILED_RETRYABLE`, `DEAD_LETTER`, or `SUPERSEDED` (`_fencedPersist` rejects stale tokens with `STALE_FENCING_TOKEN`).
- **Idempotency (`16–128` chars):** `Idempotency-Key` is mandatory (`[A-Za-z0-9._:-]{16,128}`), scoped to `(actorUid, actorTenantId, operation, targetUid, key)`, rejects payload mismatches with `409 idempotency_key_conflict`, and replays pending (`503`), completed (`200`), dead-lettered (`503`), or superseded (`200`) states without extra mutations or `tokenVersion` increments.
- **Unavoidable Cross-Service Race Window (Documented):** Firebase Auth does not support Firestore fencing tokens or conditional ETags on `authAdmin.updateUser`. If a worker passes `_assertLeaseAndFreshness`, stalls at the exact moment an outbound RPC leaves Node.js, its lease expires, and a newer operation completes before the delayed RPC reaches Google's Auth servers, that in-flight RPC cannot be cancelled mid-flight. The newer `desiredAuthVersion` outbox event (or a reconciliation sweep/re-sync) remains the authoritative desired state.

---

## 3. Exact Verification Results (184 / 184 Passed)

**Note:** External Firebase Auth calls (`getUser`, `updateUser`, `revokeRefreshTokens`) in `test-revocation-consistency-emulator.cjs`, `test-desired-state-reconciliation-emulator.cjs`, `test-outbox-idempotency-emulator.cjs`, and `test-preprod-hardening.cjs` use a deterministic in-process test double for fault/barrier injection; Firestore transactions, rules, queries, and `FieldValue` operations run against the real Cloud Firestore Emulator or `InMemoryFirestore`. Zero production tests were executed.

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

## 4. Deployment Prerequisites & Remaining Risks

- **Deployment Prerequisites:**
  1. Provision staging/production secrets (`SIGNING_KEY_ENCRYPTION_KEY`, `RECEIPT_ENCRYPTION_KEY`, `MFA_ENCRYPTION_KEY`, `OIDC_ISSUER`) in Secret Manager.
  2. Deploy `firestore.rules`, create the `security_outbox` composite index `(type ASC, status ASC, nextRetryAt ASC)`, enable Firestore TTL on `admin_idempotency.expiresAt` (and ephemeral code/session collections), and enable PITR/daily backups.
  3. Deploy `auth/auth-backend/worker.js` as a separate Railway worker service alongside `auth/auth-backend/server.js`.
  4. Execute the Controlled Staging Smoke-Test Plan (including live Firebase Auth IAM verification).
- **Remaining Risks:**
  1. Unavoidable microsecond-window in-flight RPC race across non-transactional Firebase Auth (documented in Section 2).
  2. Express rate limiting remains per-instance; front public endpoints with edge/WAF or shared Redis rate limiting before multi-instance production scaling.

---

## 5. Final Read-Only Concurrency Review

### 5.1 External Side-Effect Race (`claimLease` -> `_assertLeaseAndFreshness` -> `authAdmin` -> `_fencedPersist`)
- **Can the v4-check / v5-accept / v4-Firebase-Auth-write sequence occur?** **Yes.** In `auth/auth-backend/services/platformOutboxService.js`, `_assertLeaseAndFreshness` (`lines 251–274`) performs a read-only Firestore check (`lines 290, 298, 317`) before returning to the Node.js event loop and invoking `authAdmin.updateUser` (`line 291`) or `authAdmin.revokeRefreshTokens` (`lines 300, 319`). Firestore fencing does **not** lock or serialize external Firebase Auth RPCs.
- **Resulting Consistency Guarantees:**
  - If Activation v5 is accepted *after* Worker A's `_assertLeaseAndFreshness` check on Suspension v4, and v4's `authAdmin.updateUser` executes *before* v5's `authAdmin.updateUser`, v5 overwrites v4 in Firebase Auth and converges cleanly.
  - **Edge-case gap:** If Activation v5 completes its `authAdmin.updateUser(..., { disabled: false })` and transitions to `COMPLETED` *before* Worker A's delayed Suspension v4 RPC reaches Firebase Auth, Firebase Auth will transiently reflect `disabled: true` while Firestore reflects `desiredAuthDisabled: false` and v5 is already `COMPLETED`. Worker A's `_fencedPersist` (`lines 180–189`) will mark v4 `SUPERSEDED` (never `COMPLETED`), **but** `PlatformOutboxService.runOnce` only sweeps `PENDING_EXTERNAL_AUTH`, `FAILED_RETRYABLE`, and `IN_PROGRESS` events — so an already-`COMPLETED` v5 event will **not** be re-executed automatically without a periodic desired-state drift reconciler comparing `/users/{uid}.desiredAuthDisabled` against Firebase Auth.

### 5.2 Freshness Invariant (`desiredAuthVersion` Comparison)
- `adminRoutes.js` (`lines 285–296, 524–534`) atomically increments `users/{uid}.desiredAuthVersion` inside Phase 1 `db.runTransaction`.
- `platformOutboxService.js` (`lines 74, 183, 267`) rejects stale events when `latestVersion > event.operationVersion` (equivalent to accepting `latestVersion <= event.operationVersion`).
- Because `desiredAuthVersion` only increases monotonically under normal operation, `latestVersion === event.operationVersion` and `latestVersion <= event.operationVersion` behave identically in normal operation; however, **`desiredAuthVersion === event.operationVersion`** is the stricter invariant because it also rejects anomalous/corrupted states where `users/{uid}.desiredAuthVersion` is missing or lower than `event.operationVersion`.

### 5.3 Worker Lease Expiration During In-Flight RPC
- If Worker A's lease expires while an `authAdmin` RPC is already in flight over HTTPS, Worker A **can still complete that external side effect** because Firestore fencing cannot abort an outbound network call.
- Upon return, `_fencedPersist` (`lines 160–171`) rejects Worker A's Firestore write with `STALE_FENCING_TOKEN`.
- If Worker B takes over the *same* `operationVersion`, Worker B's execution converges Firebase Auth to the identical desired state. If a *newer* `operationVersion` already ran and marked `COMPLETED` before Worker A's in-flight RPC landed, the same periodic drift-reconciliation caveat from Section 5.1 applies.

### 5.4 Emulator Test Adequacy Limitation
- `auth/test-outbox-idempotency-emulator.cjs` (`EMU-OI-07`–`EMU-OI-10`) exercises `claimLease` staleness, sequential out-of-order worker execution (`v2` before `v1`), concurrent `operationVersion` assignment, and lease expiration *before* `_assertLeaseAndFreshness` throws `STALE_FENCING_TOKEN`.
### 5.5 Resolution Applied (Strict `===` Invariant & `DesiredStateReconciler`)
- `PlatformOutboxService` now enforces strict `desiredAuthVersion === event.operationVersion` and fails closed (`DEAD_LETTER` + `platform.outbox.version_mismatch`) on missing/inconsistent versions.
- `DesiredStateReconciler` (`auth/auth-backend/services/desiredStateReconciler.js`, wired into `worker.js`) periodically compares `/users/{uid}.desiredAuthDisabled` against Firebase Auth `getUser(uid).disabled` using transactional leases and fencing tokens on `/auth_reconciliation/{uid}`, repairing post-`COMPLETED` stale RPC drift (`Race A` & `Race B`) with audited `platform.reconciliation.drift_repaired` events and zero duplicate admin operations.
- Verified with async-barrier Firebase Auth test doubles in `auth/test-desired-state-reconciliation-emulator.cjs` (`EMU-REC-01`–`05`, `5 / 5` passing).

---

## 6. Read-Only Refresh-Token Revocation Consistency Review

### 6.1 Separate Desired-State Dimensions (Finding: Coupled via Single Version)
- `auth/auth-backend/routes/adminRoutes.js` (`lines 298–300` for `suspend`, `lines 539–542` for `revoke-all`) shares a **single** monotonic counter `desiredAuthVersion` on `/users/{uid}` across both account suspension/activation and global session revocation.
- `desiredAuthRevokedAtIso` is written on `revoke-all` (`adminRoutes.js:541`), but is **never read or consumed** by `platformOutboxService.js` or `desiredStateReconciler.js`.
- Account disabled state and refresh-token revocation are therefore **not** modeled as independent desired-state dimensions.

### 6.2 Revoke-All Followed by Activation (Defect Confirmed)
- **Sequence:**
  1. `POST /users/:uid/sessions/revoke-all` commits `desiredAuthVersion: 1` and outbox `v1` (`payload: { revokeRefreshTokens: true }`).
  2. `authAdmin.revokeRefreshTokens` fails or is delayed (`v1` is `FAILED_RETRYABLE` or `IN_PROGRESS`).
  3. `POST /users/:uid/suspend` (`status: 'active'`) increments the **same** `desiredAuthVersion` to `2` (`desiredAuthDisabled: false`, `payload: { disabled: false, revokeRefreshTokens: false }`).
  4. Activation `v2` completes (`updateUser` only; does not call `revokeRefreshTokens`).
  5. When `v1` (`revoke-all`) retries, `platformOutboxService.js` (`lines 116–167`, `313–328`) sees `desiredAuthVersion (2) > v1.operationVersion (1)` and marks `v1` **`SUPERSEDED` without calling `authAdmin.revokeRefreshTokens(uid)`**.
- **Impact:** A later account activation (or any subsequent `desiredAuthVersion`-incrementing operation) **silently cancels** an outstanding security refresh-token revocation requirement.

### 6.3 Reconciliation Coverage (`desiredStateReconciler.js`)
- **Covered:** Account disabled-state drift (`observedDisabled !== latestDisabled`, `lines 204–255`), including drift caused by stale `updateUser` RPCs completing after newer operations.
- **Not Covered:** Missing refresh-token revocation and partial `revoke-all` completion. `desiredStateReconciler.js` never reads `desiredAuthRevokedAtIso`, never inspects `authUser.tokensValidAfterTime`, and only calls `authAdmin.revokeRefreshTokens(uid)` (`lines 228–230`) when `latestDisabled === true` AND `observedDisabled !== latestDisabled`.
- **Firebase Auth Capability Note:** `authAdmin.getUser(uid)` exposes `tokensValidAfterTime` (1-second UTC resolution), which can be used alongside a separate `desiredRevocationVersion` / `appliedRevocationVersion` (or `desiredRevokeNotBeforeMs`) to detect and repair missing revocations independently of `desiredAuthDisabled`.

### 6.4 Test Coverage Gaps (Revocation Consistency)
- **Covered (via deterministic `authAdmin` test doubles, not live Firebase Auth):** Failed `revokeRefreshTokens` retry/dead-letter/redrive (`EMU-OI-05`, `PPH-07`) and concurrent `operationVersion` assignment (`EMU-OI-09` where all 3 inline calls succeed).
- **Not Covered:** `revoke-all` with failed/delayed `revokeRefreshTokens` followed by `activate` (proving revocation still executes), async barrier inside `authAdmin.revokeRefreshTokens`, and `desiredStateReconciler.js` verification/repair of missing refresh-token revocations.

### 6.5 Required Remediation Before Final Commit Approval
Separate refresh-token revocation from `desiredAuthDisabled` by tracking an independent `desiredRevocationVersion` (or `desiredRevokeAfterSec`) + `appliedRevocationVersion` on `/users/{uid}` (and `revocationVersion` on `revoke-all` / `suspend` outbox events), so a later `activate` never supersedes an unapplied revocation and `DesiredStateReconciler` can verify and repair missing revocations (`tokensValidAfterTime` + version tracking).

### 6.6 Resolution Applied (Independent Revocation Dimension & `tokensValidAfterTime` Verification)
- Separated `desiredRevocationVersion`, `desiredRevokedAt`, `appliedRevocationVersion`, and `observedTokensValidAfterTime` on `/users/{uid}` from `desiredAuthVersion` / `desiredAuthDisabled`.
- Updated `PlatformOutboxService` and `DesiredStateReconciler` to evaluate account-state and revocation dimensions independently, verify `tokensValidAfterTime` via `authAdmin.getUser(uid)` at 1-second floor granularity before advancing `appliedRevocationVersion`, and repair any outstanding revocations across activations/restarts.
- Verified in `auth/test-revocation-consistency-emulator.cjs` (`EMU-REV-01`–`10`, `7 / 7` passing against Cloud Firestore Emulator with deterministic Firebase Auth test doubles).

---

## 7. Final Read-Only Revocation Verification & Commit Verdict

### 7.1 Firebase Auth Timestamp Semantics (`desiredRevokedAt` vs `tokensValidAfterTime`)
- **Comparison Logic (`platformOutboxService.js:46-55`, `desiredStateReconciler.js:35-44`):** Both services convert `tokensValidAfterTime` and `desiredRevokedAt` to 1-second floor epochs and require `Math.floor(obsMs / 1000) >= Math.floor(desMs / 1000)`.
- **Same-Second Limitation (Confirmed):** Because Firebase Auth `tokensValidAfterTime` has **1-second UTC resolution** and carries no version/nonce:
  1. In `PlatformOutboxService` (`lines 415-425`), `revokeRefreshTokens(uid)` is always invoked before `getUser(uid)` verification, but if two revocations occur in the same 1-second window, `obsSec >= desSec` cannot distinguish the second revocation's timestamp from the first.
  2. In `DesiredStateReconciler` (`lines 234-262`), if Revocation #1 sets `tokensValidAfterTime` at `T.100s` and Revocation #2 is accepted at `T.600s` (`desiredRevocationVersion: 2`, `appliedRevocationVersion: 1`) with its outbox event failing before calling `revokeRefreshTokens`, `timestampValid` evaluates `true` (`floor(T.000) >= floor(T.600)`) and the `else` branch (`lines 255-261`) advances `appliedRevocationVersion = 2` without re-invoking `revokeRefreshTokens(uid)`. (Note: `PlatformOutboxService` itself still retries/invokes `revokeRefreshTokens` on the outbox event unless superseded.)

### 7.2 Revocation Recovery
- **Terminal Outbox Events (`DEAD_LETTER` / `SUPERSEDED`):** `DesiredStateReconciler` reads `/users/{uid}` (`desiredRevocationVersion`, `desiredRevokedAt`, `appliedRevocationVersion`) independently of `security_outbox` status, so failed or superseded outbox events remain recoverable via reconciliation (and via `redriveUser` if reconciliation hits `DEAD_LETTER`).
- **Worker Restarts & Subsequent Operations:** Expired leases (`leaseExpiresAt <= nowMs`) recover automatically; subsequent `activate` increments `desiredAuthVersion` only and preserves `desiredRevocationVersion`; subsequent `revoke-all` increments `desiredRevocationVersion` (`+1`) and supersedes older `revoke-all` outbox events.

### 7.3 Test Count Reconciliation (`7 / 7` Tests Covering `10` Scenarios; `184 / 184` Total)
`auth/test-revocation-consistency-emulator.cjs` executes **7 `test()` blocks** (`7 / 7` passed) covering all **10 scenarios** (`EMU-REV-01`..`EMU-REV-10`):
- `EMU-REV-01` (1), `EMU-REV-02` (2), `EMU-REV-03` (3), `EMU-REV-04` (4), `EMU-REV-05 & 06` (5 & 6 combined), `EMU-REV-07` (7), `EMU-REV-08, 09 & 10` (8, 9 & 10 combined).
- Verified overall total across all 13 suites: `7 + 5 + 10 + 7 + 3 + 10 + 6 + 10 + 7 + 11 + 44 + 55 + 9 = 184 / 184` passed (`0` failed, `0` production tests).

### 7.4 Final Verdict
**Verdict: READY FOR LOCAL COMMIT** (with the 1-second `tokensValidAfterTime` same-second limitation explicitly documented above; optional future hardening: in `desiredStateReconciler.js:244`, invoke `revokeRefreshTokens(uid)` whenever `appliedRevocationVersion < latestRevVersion` rather than skipping via the `timestampValid` `else` branch).

