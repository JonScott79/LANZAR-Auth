# Milestone 1.1 Final Reconciliation & Verification Report

**Document ID:** LID-REP-M1.1-RECONCILIATION-REV9-FINAL  
**Date:** November 15, 2026  
**Status:** Verification Complete — 100% Pass Rate Across All Suites (151 / 151 Tests Passing)  
**Author:** Antigravity (Lead Systems Architect)  
**Target Specification:** [LANZAR_ID_MILESTONE_1_1_IMPLEMENTATION_SPECIFICATION.md](file:///C:/Users/jonny/.gemini/antigravity/brain/181f70b2-f3a3-4005-b91d-fd091daec5b7/LANZAR_ID_MILESTONE_1_1_IMPLEMENTATION_SPECIFICATION.md)  

---

## 1. Executive Summary & Resolution Overview

This report provides comprehensive technical verification that all remaining issues identified by the Lead Architect for Milestone 1.1 sign-off have been resolved in the codebase, confirmed via live Google Cloud Firestore Java Emulator transactions, and fully reconciled in the authoritative specification (`LID-SPEC-M1.1-STORE-REV9-AUTHORITATIVE`):

1. **Strict Fail-Closed Lease Validation & Invalid-Lease Fencing:** Replaced permissive lease checks across `initiateRedemption()`, `registerStagedRecords()`, and `finalizeRedemption()`. Any missing, null, zero, negative, malformed string, or non-finite lease expiration value on `REDEEMING` records immediately transitions the ceremony to `COMPROMISED` with `failureReason: 'invalid_lock_expiration'`, revokes companion records **only** after verifying ownership, ceremony ID, lock ID, fence token, tenant, and status via `canWorkerRevokeSession()` and `canWorkerRevokeFamily()`, stages a `CORRUPT_LEASE_METADATA_DEFENSE` audit event, and fails closed.
2. **Mandatory Finalization Code Pointer Validation:** In `finalizeRedemption()`, `relationshipValid` explicitly requires `codeData.issuedSessionId === issuedSessionId && codeData.issuedFamilyId === issuedFamilyId`. Any tampering or mismatch fails closed with `RECORD_RELATIONSHIP_MISMATCH` and zero document activation.
3. **Ambiguous Firestore Create Outcome Handling:** In `oauthRoutes.js`, `safeCleanup()` unconditionally passes known `sessionId` and `familyId` into `handleRedemptionFailure()`. In-flight document creations that commit in Cloud Firestore before a client network drop (`ETIMEDOUT` / `ECONNRESET`) are safely identified via fencing credentials and revoked without touching foreign or newer worker resources.
4. **Fail-Closed Replay Fencing, Invalid-Fence Ceremony Containment & Refresh Enforcement:** In `store.js`, `canReplayRevokeSession()` and `canReplayRevokeFamily()` require `Number.isInteger(codeData.fenceToken) && codeData.fenceToken > 0 && recordData.fenceToken === codeData.fenceToken` and verify `recordData.redemptionLockId` against `codeData.completedLockId || codeData.redemptionLockId` (preserved by `finalizeRedemption()`). When `codeData.fenceToken` is invalid on a `COMPLETED` replay, `canContainByCeremonyAndLock()` independently authenticates ownership via immutable `ceremonyId`, `completedLockId`, `uid`, `tenantId`, `clientId`, and `issuedSessionId`/`issuedFamilyId` so proven records are still revoked synchronously without touching foreign records. When ownership cannot be proven at all, potentially foreign records are left untouched and an atomic `compromised_ceremonies/{ceremonyId}` tombstone is written so `authorizeRefreshGrant()` still blocks refresh-token exchanges (`CEREMONY_COMPROMISED`).
5. **Unified Receipt Key Configuration & Strict Version Parsing:** `parseActiveReceiptKeyVersion()` rejects malformed `ACTIVE_RECEIPT_KEY_VERSION` values (`1.5`, `1junk`, `0`, `-1`) with `/^[1-9]\d*$/`, and `resolveRawReceiptKeyFromEnv()` unifies startup `validateReceiptKeyConfiguration()` and runtime `resolveReceiptKey()` so both follow the exact same fallback order (`RECEIPT_ENCRYPTION_KEYS[version]` -> `RECEIPT_ENCRYPTION_KEY_V{version}` -> `RECEIPT_ENCRYPTION_KEY` for version 1, with `TOKEN_RECEIPT_KEY` restricted strictly to non-production/non-staging development).
6. **HTTP Refresh-Route Integration, Authentication & Atomic Rotation (`POST /oauth/token`):** Implemented and verified `router.post('/token', oauthExchangeLimiter, ...)` in `auth/auth-backend/routes/oauthRoutes.js` as the sole `grant_type=refresh_token` endpoint, passing `refresh_token` into `codeStore.authorizeRefreshGrant()` inside a Firestore transaction (`db.runTransaction`). `authorizeRefreshGrant()` validates `lanzar_rt_<familyId>.<seq>.<64-hex>` token binding, compares SHA-256(`refresh_token`) in constant time (`timingSafeEqualHex`) against `currentActiveTokenHash` and `sequenceNumber`, enforces finite future `expiresAt` and ownership cross-references, atomically rotates `currentActiveTokenHash`, `sequenceNumber`, and `rotatedTokenHashes` (bounded to 50 entries) in the same transaction, and revokes the family/session + writes `compromised_ceremonies` on reuse of a previously rotated token or concurrent double-refresh. Verified `TOKEN_RECEIPT_KEY` has no other cryptographic usage in the repo and zero alternate refresh bypass paths exist.
7. **Authoritative Specification Reconciliation:** Reconciled `LANZAR_ID_MILESTONE_1_1_IMPLEMENTATION_SPECIFICATION.md` (`LID-SPEC-M1.1-STORE-REV9-AUTHORITATIVE`) so that Section 5.1 (`parseActiveReceiptKeyVersion()`, `resolveRawReceiptKeyFromEnv()`), Section 8.3 (concurrent refresh policy & bounded 50-entry `rotatedTokenHashes` semantics), `TC-42`, `EMU-25`, and test counts (`151 / 151`) are synchronized across Sections 5.1, 8, and 10.

---

## 2. Test Battery Summary (151 / 151 Tests Passing — 100%)

> **Environment Distinction:** All Milestone 1.1 distributed store transaction tests (`EMU-01` through `EMU-25`) were executed against the local **Google Cloud Firestore Java Emulator** (`127.0.0.1:8088`, project `demo-lanzar-id-store-test` in offline demo mode), **not** production Cloud Firestore. Zero production Firestore testing was performed.

| Test Suite | File / Scope | Total Executed | Passed | Failed | Pass Rate |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **In-Memory Simulation Suite** | [`auth/test-milestone-1-1.cjs`](file:///C:/Users/jonny/.gemini/antigravity/worktrees/lanzar/lanzar_id_main_chat/auth/test-milestone-1-1.cjs) | 44 | 44 | 0 | **100.0%** |
| **Live Firestore Emulator Suite** | [`auth/test-milestone-1-1-emulator.cjs`](file:///C:/Users/jonny/.gemini/antigravity/worktrees/lanzar/lanzar_id_main_chat/auth/test-milestone-1-1-emulator.cjs) | 25 | 25 | 0 | **100.0%** |
| **Client Registry Regression** | [`auth/test-client-registry.cjs`](file:///C:/Users/jonny/.gemini/antigravity/worktrees/lanzar/lanzar_id_main_chat/auth/test-client-registry.cjs) | 9 | 9 | 0 | **100.0%** |
| **Auth & MFA Regression** | [`auth/test-auth-and-mfa.cjs`](file:///C:/Users/jonny/.gemini/antigravity/worktrees/lanzar/lanzar_id_main_chat/auth/test-auth-and-mfa.cjs) | 6 | 6 | 0 | **100.0%** |
| **Legacy Bridge & SSO Regression** | [`auth/test-legacy-bridge-and-standalone.cjs`](file:///C:/Users/jonny/.gemini/antigravity/worktrees/lanzar/lanzar_id_main_chat/auth/test-legacy-bridge-and-standalone.cjs) | 12 | 12 | 0 | **100.0%** |
| **Phase 1 Acceptance Suite** | [`auth/test-phase1-acceptance.cjs`](file:///C:/Users/jonny/.gemini/antigravity/worktrees/lanzar/lanzar_id_main_chat/auth/test-phase1-acceptance.cjs) | 55 | 55 | 0 | **100.0%** |
| **Total Test Battery** | **Full Milestone 1.1 + Ecosystem Matrix** | **151** | **151** | **0** | **100.0%** |

---

## 3. Detailed Implementation Changes by Finding

### Finding 1: Strict Fail-Closed Lease Validation

#### `auth/auth-backend/store.js`
In `initiateRedemption()` (lines 738–795):
```javascript
if (data.status === 'REDEEMING') {
    const isLeaseValid = Number.isFinite(lockExpiresMs) && lockExpiresMs > 0;
    if (!isLeaseValid) {
        // Fail closed immediately on missing, zero, negative, malformed, or non-finite lease expiration
        const attemptSeq = (data.replayAttemptCount || 0) + 1;
        const eventId = `sec_invalid_lease_${codeHash.slice(0, 16)}_${attemptSeq}_${opTime}`;

        transaction.update(codeRef, {
            status: 'COMPROMISED',
            failureReason: 'invalid_lock_expiration',
            replayAttemptCount: attemptSeq,
            lastReplayAt: new Date(opTime)
        });

        const workerOpts = {
            targetSessionId: data.issuedSessionId,
            targetFamilyId: data.issuedFamilyId
        };
        if (sessionRef && canWorkerRevokeSession(sessionDoc, codeDoc, data.redemptionLockId, data.fenceToken, workerOpts)) {
            transaction.update(sessionRef, {
                status: 'revoked',
                revocationReason: 'invalid_lock_expiration',
                revokedAt: new Date(opTime)
            });
        }

        if (familyRef && canWorkerRevokeFamily(familyDoc, codeDoc, data.redemptionLockId, data.fenceToken, workerOpts)) {
            transaction.update(familyRef, {
                status: 'revoked',
                revocationReason: 'invalid_lock_expiration',
                revokedAt: new Date(opTime)
            });
        }

        transaction.set(this.db.collection('security_outbox').doc(eventId), {
            eventId,
            tenantId: data.tenantId,
            uid: data.uid,
            eventType: 'CORRUPT_LEASE_METADATA_DEFENSE',
            severity: 'CRITICAL',
            details: {
                ceremonyId: data.ceremonyId,
                clientId: data.clientId,
                codeHashPrefix: codeHash.slice(0, 16) + '...',
                rawLeaseValue: String(data.redemptionLockExpiresAt),
                parsedLeaseMs: lockExpiresMs
            },
            status: 'pending',
            retryCount: 0,
            nextRetryAt: new Date(opTime),
            createdAt: new Date(opTime)
        });

        return { status: 'REPLAY_DETECTED', errorDescription: 'Invalid redemption lock expiration metadata.' };
    }
```

In `registerStagedRecords()` (lines 1030–1045):
```javascript
const lockExpiresMs = toEpochMs(codeData.redemptionLockExpiresAt);
if (!Number.isFinite(lockExpiresMs) || lockExpiresMs <= 0) {
    transaction.update(codeRef, {
        status: 'COMPROMISED',
        failureReason: 'invalid_lock_expiration',
        lastReplayAt: new Date(opTime)
    });
    if (sessionDoc.exists && sessionData.redemptionLockId === redemptionLockId && sessionData.fenceToken === fenceToken && sessionData.status === 'pending_activation') {
        transaction.update(sessionRef, { status: 'revoked', revocationReason: 'invalid_lock_expiration', revokedAt: new Date(opTime) });
    }
    if (familyDoc.exists && familyData.redemptionLockId === redemptionLockId && familyData.fenceToken === fenceToken && familyData.status === 'pending_activation') {
        transaction.update(familyRef, { status: 'revoked', revocationReason: 'invalid_lock_expiration', revokedAt: new Date(opTime) });
    }
    return { success: false, reason: 'INVALID_LOCK_EXPIRATION' };
}
```

In `finalizeRedemption()` (lines 1236–1260):
```javascript
const lockExpiresMs = toEpochMs(codeData.redemptionLockExpiresAt);
if (!Number.isFinite(lockExpiresMs) || lockExpiresMs <= 0 || opTime > lockExpiresMs) {
    transaction.update(codeRef, {
        status: 'COMPROMISED',
        failureReason: !Number.isFinite(lockExpiresMs) || lockExpiresMs <= 0 ? 'invalid_lock_expiration' : 'lock_expired',
        lastReplayAt: new Date(opTime)
    });
    if (canWorkerRevokeSession(sessionDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
        transaction.update(sessionRef, { status: 'revoked', revocationReason: 'redemption_lock_expired', revokedAt: new Date(opTime) });
    }
    if (canWorkerRevokeFamily(familyDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
        transaction.update(familyRef, { status: 'revoked', revocationReason: 'redemption_lock_expired', revokedAt: new Date(opTime) });
    }
    return { success: false, reason: !Number.isFinite(lockExpiresMs) || lockExpiresMs <= 0 ? 'INVALID_LOCK_EXPIRATION' : 'LOCK_EXPIRED' };
}
```

---

### Finding 2: Mandatory Finalization Code Pointer Validation

#### `auth/auth-backend/store.js`
In `finalizeRedemption()` (lines 1290–1315):
```javascript
const relationshipValid =
    sessionData.uid === codeData.uid &&
    familyData.uid === codeData.uid &&
    sessionData.clientId === codeData.clientId &&
    familyData.clientId === codeData.clientId &&
    sessionData.ceremonyId === codeData.ceremonyId &&
    familyData.ceremonyId === codeData.ceremonyId &&
    sessionData.redemptionLockId === redemptionLockId &&
    sessionData.fenceToken === fenceToken &&
    familyData.redemptionLockId === redemptionLockId &&
    familyData.fenceToken === fenceToken &&
    // Mandatory authorization code registered session and family pointers
    codeData.issuedSessionId === issuedSessionId &&
    codeData.issuedFamilyId === issuedFamilyId;

if (!relationshipValid) {
    if (codeData.status === 'REDEEMING' && codeData.redemptionLockId === redemptionLockId) {
        transaction.update(codeRef, { status: 'COMPROMISED', failureReason: 'relationship_mismatch', lastReplayAt: new Date(opTime) });
    }
    if (canWorkerRevokeSession(sessionDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
        transaction.update(sessionRef, { status: 'revoked', revocationReason: 'relationship_mismatch', revokedAt: new Date(opTime) });
    }
    if (canWorkerRevokeFamily(familyDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
        transaction.update(familyRef, { status: 'revoked', revocationReason: 'relationship_mismatch', revokedAt: new Date(opTime) });
    }
    return { success: false, reason: 'RECORD_RELATIONSHIP_MISMATCH' };
}
```

---

### Finding 3: Ambiguous Firestore Create Outcomes

#### `auth/auth-backend/routes/oauthRoutes.js`
In `safeCleanup()` (lines 201–217):
```javascript
const safeCleanup = async (reason) => {
    try {
        await codeStore.handleRedemptionFailure({
            codeHash: claim.codeHash,
            redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken,
            uid: claim.record.uid,
            tenantId: claim.record.tenantId,
            // Pass known IDs unconditionally so handleRedemptionFailure inspects and revokes
            // any document that committed prior to a network timeout or connection reset.
            sessionId,
            familyId,
            errorReason: reason
        });
    } catch (cleanupErr) {
        console.error('[SECURITY ERROR] Critical failure during redemption rollback:', cleanupErr);
    }
};
```

---

### Finding 4: Fail-Closed Replay Fencing, Invalid-Fence Containment & Refresh Enforcement

#### `auth/auth-backend/store.js`
In `canContainByCeremonyAndLock()` (lines 458–480), `initiateRedemption()` Branch A (lines 692–742), and `authorizeRefreshGrant()` (lines 1749–1797):
```javascript
const codeFenceValid = Number.isInteger(data.fenceToken) && data.fenceToken > 0;
const sessionIndependentlyVerified = Boolean(
    sessionRef && (codeFenceValid ? canReplayRevokeSession(sessionDoc, codeDoc) : canContainByCeremonyAndLock(sessionDoc, codeDoc))
);
const familyIndependentlyVerified = Boolean(
    familyRef && (codeFenceValid ? canReplayRevokeFamily(familyDoc, codeDoc) : canContainByCeremonyAndLock(familyDoc, codeDoc))
);
const pairEligible = Boolean(
    codeFenceValid &&
    sessionIndependentlyVerified &&
    familyIndependentlyVerified &&
    canReplayRevokePair(sessionDoc, familyDoc, codeDoc)
);

if (sessionIndependentlyVerified) {
    transaction.update(sessionRef, {
        status: 'revoked',
        revocationReason: 'authorization_code_replay_compromise',
        revokedAt: new Date(opTime)
    });
}
if (familyIndependentlyVerified) {
    transaction.update(familyRef, {
        status: 'revoked',
        revocationReason: 'authorization_code_replay_compromise',
        revokedAt: new Date(opTime)
    });
}

if (!pairEligible && typeof data.ceremonyId === 'string' && data.ceremonyId) {
    transaction.set(this.db.collection('compromised_ceremonies').doc(data.ceremonyId), {
        ceremonyId: data.ceremonyId,
        codeHash,
        uid: data.uid,
        tenantId: data.tenantId,
        clientId: data.clientId,
        reason: !codeFenceValid ? 'invalid_code_fence_token_replay_compromise' : 'authorization_code_replay_compromise',
        compromisedAt: new Date(opTime)
    });
}
```

---

### Finding 5: Unified Receipt Key Fallback & Strict Version Parsing

#### `auth/auth-backend/store.js`
In `parseActiveReceiptKeyVersion()` and `resolveRawReceiptKeyFromEnv()` (lines 94–154), shared by `validateReceiptKeyConfiguration()` and `resolveReceiptKey()`:
```javascript
function parseActiveReceiptKeyVersion(rawValue) {
    if (rawValue === undefined || rawValue === null) return DEFAULT_RECEIPT_KEY_VERSION;
    const trimmed = String(rawValue).trim();
    if (trimmed === '') return DEFAULT_RECEIPT_KEY_VERSION;
    if (!/^[1-9]\d*$/.test(trimmed)) {
        throw new Error(`ACTIVE_RECEIPT_KEY_VERSION must be a positive integer, got "${rawValue}"`);
    }
    const parsed = Number(trimmed);
    if (!Number.isSafeInteger(parsed) || parsed < 1) {
        throw new Error(`ACTIVE_RECEIPT_KEY_VERSION must be a positive integer, got "${rawValue}"`);
    }
    return parsed;
}
```

---

### Finding 6: HTTP Refresh-Route Integration, Token Authentication & Atomic Rotation (`POST /oauth/token`)

#### `auth/auth-backend/routes/oauthRoutes.js` & `auth/auth-backend/store.js`
1. `router.post('/token', oauthExchangeLimiter, ...)` (`oauthRoutes.js` lines 337–401) is the sole `grant_type=refresh_token` endpoint, passing `refreshToken: refresh_token` into `codeStore.authorizeRefreshGrant()`.
2. `authorizeRefreshGrant()` (`store.js` lines 1758–1929) parses `lanzar_rt_<familyId>.<sequenceNumber>.<64-hex>`, rejects cross-family tokens (`TOKEN_FAMILY_MISMATCH`), computes `presentedHash = hashAuthorizationCode(refreshToken)`, and runs inside `this.db.runTransaction()`.
3. Inside the transaction, it verifies `familyData.status`, `sessionData.status`, ownership cross-references, `compromised_ceremonies/{ceremonyId}`, finite future `expiresAt`, and constant-time `timingSafeEqualHex(presentedHash, familyData.currentActiveTokenHash)` + `sequenceNumber`.
4. On match, `currentActiveTokenHash`, `sequenceNumber`, and `rotatedTokenHashes` update atomically in the same transaction. On reuse of a previously rotated token in `rotatedTokenHashes`, both family and session are atomically revoked, `compromised_ceremonies/{ceremonyId}` is written, and `REFRESH_TOKEN_REPLAY` (`401`) is returned.
5. **Intentional Concurrent Refresh Policy:** Two simultaneous requests presenting the same token serialize on `familyRef`; one succeeds (`200`) and the second triggers `REFRESH_TOKEN_REPLAY` (`401`), revoking the family/session. Because the server cannot cryptographically distinguish a stolen-token race from a legitimate client double-submit without weakening replay protection, this fail-closed policy is intentional; clients must serialize refresh calls.
6. **Bounded 50-Entry `rotatedTokenHashes` Window:** `rotatedTokenHashes` retains the 50 most recent rotated hashes (`.slice(-50)`). Reuse of a token rotated >50 rotations ago is rejected with `401 INVALID_REFRESH_TOKEN` (zero tokens issued) without triggering `REFRESH_TOKEN_REPLAY` or revoking the active family. Milestone 1.1 formally accepts this bounded window; durable subcollection history is deferred to a future milestone.
7. Verified `TOKEN_RECEIPT_KEY` has no other cryptographic usage in the repo and zero alternate refresh bypass paths exist.

---

## 4. Verification Evidence & Test Assertions

### TC-34 & EMU-17: Strict Lease Validation
- **Values tested:** `[null, undefined, 0, -5000, 'malformed_string', NaN, Infinity]` (plus `FieldValue.delete()` in emulator).
- **Assertions:**
  1. `store.initiateRedemption()` returns `{ status: 'REPLAY_DETECTED' }`.
  2. Firestore `authorization_codes` document transitions to `status: 'COMPROMISED'` with `failureReason: 'invalid_lock_expiration'`.
  3. `store.registerStagedRecords()` returns `{ success: false, reason: 'INVALID_LOCK_EXPIRATION' }`.
  4. `store.finalizeRedemption()` returns `{ success: false, reason: 'INVALID_LOCK_EXPIRATION' }`.
  5. Companion session and token-family documents are cleanly revoked without activating.

### TC-35 & EMU-18: Code Pointer Validation
- **Assertions:**
  1. Corrupting `issuedSessionId` on the authorization code causes `finalizeRedemption()` to fail with `{ success: false, reason: 'RECORD_RELATIONSHIP_MISMATCH' }`.
  2. Live session and family documents are verified: `sessSnap.data().status !== 'active'` and `famSnap.data().status !== 'active'`.
  3. Corrupting `issuedFamilyId` causes identical fail-closed rejection with zero activation.

### TC-36 & EMU-19: Ambiguous Create Handling
- **Assertions:**
  1. Simulating an ambiguous committed session before client timeout followed by `safeCleanup()` cleanly revokes the committed session document (`status === 'revoked'`, `revocationReason === 'ECONNRESET_during_create'`) and transitions the code to `COMPROMISED`.
  2. A stale worker attempting ambiguous cleanup against an active session belonging to a newer worker is safely rejected with `{ success: false, reason: 'STALE_WORKER_FENCED' }`, and the newer worker's active session remains strictly `active`.

### TC-40 & EMU-23: Fail-Closed Replay Fencing, Invalid-Fence Containment & Refresh Enforcement
- **Invalid `fenceToken` values tested:** `[undefined, null, 0, -1, 1.5, NaN, Infinity, -Infinity]` (using `FieldValue.delete()` in emulator for missing field).
- **Assertions (including `SessionService.checkSession()` and `store.authorizeRefreshGrant()` refresh-token exchange verification):**
  1. `canReplayRevokeSession()`, `canReplayRevokeFamily()`, and `canReplayRevokePair()` all return `false` for every invalid `fenceToken`.
  2. **Invalid `fenceToken` with valid companion records:** `canContainByCeremonyAndLock()` proves ceremony+lock ownership, revokes both session and family synchronously (`status: 'revoked'`), writes `compromised_ceremonies/{ceremonyId}`, and `store.authorizeRefreshGrant()` rejects refresh with `{ allowed: false, reason: 'FAMILY_REVOKED' }` (pre-replay refresh succeeded with an access token).
  3. **Invalid `fenceToken` with corrupted companion family:** Proven session is revoked, foreign/corrupt family remains untouched (`status: 'active'`), and `store.authorizeRefreshGrant()` rejects refresh.
  4. **Invalid `fenceToken` + missing `completedLockId` (unproven ownership):** Potentially foreign session and family remain untouched (`status: 'active'`), and `compromised_ceremonies/{ceremonyId}` tombstone still blocks `store.authorizeRefreshGrant()` with `{ allowed: false, reason: 'CEREMONY_COMPROMISED' }`, while an unrelated active ceremony's refresh still succeeds (`allowed: true`).
  5. **Missing/corrupt companion cases (3a–3f):** Independently verified companion records are revoked synchronously and refresh is blocked; untrustworthy/foreign records are untouched; `CRITICAL_SECURITY_RECORD_MISSING` or `CRITICAL_REPLAY_PAIR_INTEGRITY_FAILURE` is staged with exact verification/revocation flags.
  6. **Receipt key configuration parity (`TC-40`):** Rejects `ACTIVE_RECEIPT_KEY_VERSION` in `['1.5', '1junk', '0', '-2', 'abc']` and verifies identical fallback from `RECEIPT_ENCRYPTION_KEYS` (missing `2`) to `RECEIPT_ENCRYPTION_KEY_V2` in both `validateReceiptKeyConfiguration()` and `resolveReceiptKey()`.

### TC-41 & EMU-24: HTTP `POST /oauth/token` Refresh Integration
- **Assertions (real Express HTTP requests to `POST /oauth/token` with `grant_type=refresh_token`):**
  1. **Active family & active session:** Returns HTTP `200` with `access_token`, `token_type: 'Bearer'`, and rotated `refresh_token`.
  2. **Revoked family:** Returns HTTP `401` (`error: 'invalid_grant'`, `error_code: 'FAMILY_REVOKED'`), issuing zero tokens.
  3. **Revoked session:** Returns HTTP `401` (`error: 'invalid_grant'`, `error_code: 'SESSION_REVOKED'`), issuing zero tokens.
  4. **Compromised ceremony tombstone with active family & session:** Returns HTTP `401` (`error: 'invalid_grant'`, `error_code: 'CEREMONY_COMPROMISED'`), issuing zero tokens.
  5. **Unrelated active ceremony:** Returns HTTP `200` with `access_token` and rotated `refresh_token`.
  6. **Missing `authorizeRefreshGrant` capability (`TC-41`):** Returns HTTP `500` (`error: 'server_error'`) fail-closed without minting tokens.

### TC-42 & EMU-25: HTTP Refresh-Token Auth, Atomic Rotation, Replay & Concurrency
- **Assertions (real Express HTTP requests to `POST /oauth/token`):**
  1. **Atomic rotation (`1 -> 2 -> 3`):** Verifies `currentActiveTokenHash` updates to `SHA-256(newToken)` and `sequenceNumber` increments atomically in the same transaction while recording the prior hash in `rotatedTokenHashes`.
  2. **Incorrect / forged token:** Rejected with HTTP `401` (`INVALID_REFRESH_TOKEN`) and zero tokens issued.
  3. **Token from another family:** Rejected with HTTP `401` (`TOKEN_FAMILY_MISMATCH`) and zero tokens issued.
  4. **Client-supplied `uid` / `session_id` mismatch:** Rejected with HTTP `401` (`RELATIONSHIP_MISMATCH`) and zero tokens issued.
  5. **Expired refresh token:** Rejected with HTTP `401` (`REFRESH_TOKEN_EXPIRED`) and zero tokens issued.
  6. **Previously rotated token replay:** Returns HTTP `401` (`REFRESH_TOKEN_REPLAY`, `replay_detected: true`), revokes both family and session (`status: 'revoked'`), writes `compromised_ceremonies/{ceremonyId}`, and blocks subsequent use of the latest token (`FAMILY_REVOKED`).
  7. **Concurrent refresh (`Promise.all`):** Two simultaneous `POST /oauth/token` requests with the same token result in **1** HTTP `200` and **1** HTTP `401` (`REFRESH_TOKEN_REPLAY`) with zero tokens issued on the loser.

---

## 5. Verbatim Test Execution Outputs

### In-Memory Simulation Suite (`node auth/test-milestone-1-1.cjs`)
```
================================================================
LANZAR ID — Milestone 1.1 In-Memory Simulation Verification Suite
Target Specification: LID-SPEC-M1.1-STORE-REV9-AUTHORITATIVE
Timestamp: 2026-11-15T20:17:22.497Z
================================================================

  ✓ [PASS] TC-01: Completed Code + Wrong PKCE (Receipt NOT returned, PKCE validated first)
  ✓ [PASS] TC-02: Concurrent Legitimate Retry (Returns IN_PROGRESS, does not compromise)
  ✓ [PASS] TC-03: Concurrent Conflict Redemption (Marks COMPROMISED, revokes session and family)
  ✓ [PASS] TC-04: Pending Session & Family Inactivity (checkSession returns active: false)
  ✓ [PASS] TC-05: Replay Before Finalization (Finalization fails, revokes pending session & family)
  ✓ [PASS] TC-06: Replay After Finalization (Active session & family immediately revoked)
  ✓ [PASS] TC-07A: Stale Worker Fencing (Stale Worker 1 cleans up its OWN pending record)
  ✓ [PASS] TC-07B: Stale-Worker Safety: Stale worker CANNOT revoke a newer worker's active session or family
  ✓ [PASS] TC-08: Revoked Session API Block (checkSession returns active: false, reason: revoked)
  ✓ [PASS] TC-09: Refresh Attempts Against Compromised Family (Family doc status: revoked blocks grant)
  ✓ [PASS] TC-10: Crash After Finalization / Idempotent Recovery (Returns cached receipt with valid verifier)
  ✓ [PASS] TC-11: Outbox Worker Lease Recovery (Expired lease claimed by successor)
  ✓ [PASS] TC-12: Dead-Letter Escalation & Redrive (5 retries escalates to dead_letter, redrive resets)
  ✓ [PASS] TC-13: Concurrent Replay Load with Distinct Keys (Exactly 1 SUCCESS, 9 REPLAY_DETECTED)
  ✓ [PASS] TC-14: Exact Redirect URI Matching (Trailing slash rejected, code remains ISSUED)
  ✓ [PASS] TC-15: Missing Idempotency Key (Returns INVALID_REQUEST, requires 16-128 chars)
  ✓ [PASS] TC-16: Missing Session or Family During Finalization (Fails closed, marks code COMPROMISED, stages alert)
  ✓ [PASS] TC-17: Complete Relationship Validation: Detects cross-document link mismatches and fails closed
  ✓ [PASS] TC-18A: Expired-Lock Takeover: Matching key cleanly recovers and revokes old pending records
  ✓ [PASS] TC-18B: Expired-Lock Conflict: Different key triggers conflict compromise defense
  ✓ [PASS] TC-19: Firestore Read-Before-Write Compliance (Transaction engine throws if read follows write)
  ✓ [PASS] TC-20: AES-256-GCM Dimensions & AAD Binding (12-byte IV, 16-byte tag, tampered AAD throws)
  ✓ [PASS] TC-21: Token Minting Failure Cleanup (handleRedemptionFailure revokes pending session & family)
  ✓ [PASS] TC-22: Receipt Encryption Failure Cleanup (handleRedemptionFailure revokes pending state on GCM error)
  ✓ [PASS] TC-23: Failure-Handler Fencing: Stale failure handler CANNOT revoke a newer worker's active resources
  ✓ [PASS] TC-24: Receipt Key Validation: Fails closed in production on missing, short, or dev keys
  ✓ [PASS] TC-25: Multi-Version Receipt Key Rotation: Supports seamless rotation across key versions
  ✓ [PASS] TC-26: Fenced Pointer Registration: Stale worker cannot register staged pointers or overwrite newer worker records
  ✓ [PASS] TC-27: Create-Only Semantics: Reject duplicate session/family creation with ALREADY_EXISTS
  ✓ [PASS] TC-28: Strict Fail-Closed Lease Expiration: Missing, invalid, zero, or expired leases fail closed
  ✓ [PASS] TC-29: Three-Document Pre-Read Integrity: Reject pointer registration on mismatched or missing staged documents
  ✓ [PASS] TC-30: Route Fail-Closed: Missing create() or registerStagedRecords() returns 500 with zero token minting
[SECURITY ERROR] Distributed codeStore capabilities incomplete or unavailable
  ✓ [PASS] TC-31: Route Fail-Closed: Missing initiateRedemption returns HTTP 500 and cannot fall back to legacy flow
  ✓ [PASS] TC-32: Transaction Contention Retry Across Lease Expiration: Rejects commit with fresh opTime
  ✓ [PASS] TC-33: Granular Staging Failure Cleanup: Clean up code lock without revoking unrelated records
  ✓ [PASS] TC-34: Fail-Closed Lease Validation Across All Distributed Store Methods
  ✓ [PASS] TC-35: Finalization strictly validates authorization code pointers (issuedSessionId and issuedFamilyId)
  ✓ [PASS] TC-36: Ambiguous Firestore create outcomes: safeCleanup revokes committed documents without touching foreign resources
  ✓ [PASS] TC-37: Corrupt lease metadata in initiateRedemption() CANNOT revoke newer worker, active, or mismatched records
  ✓ [PASS] TC-38: Strict Authorization-Code Expiration rejects missing, null, malformed, zero, negative, non-finite, and expired timestamps
  ✓ [PASS] TC-39: Concurrent-conflict and completed-code replay fencing protects foreign, newer-worker, and unrelated active records
  ✓ [PASS] TC-40: Fail-Closed Replay Fencing & Paired Replay Relationship Validation
[SECURITY ERROR] Distributed codeStore refresh capability unavailable
  ✓ [PASS] TC-41: HTTP POST /oauth/token enforces authorizeRefreshGrant() across all refresh scenarios
  ✓ [PASS] TC-42: HTTP POST /oauth/token enforces refresh-token hash authentication, atomic rotation, replay revocation, and concurrency

================================================================
MILESTONE 1.1 IN-MEMORY SIMULATION TEST SUMMARY
Total Executed: 44
Passed:         44
Failed:         0
Success Rate:   100.0%
================================================================
```

### Live Firestore Emulator Suite (`node auth/test-milestone-1-1-emulator.cjs`)
```
================================================================
LANZAR ID — Milestone 1.1 Live Cloud Firestore Emulator Battery
Target Specification: LID-SPEC-M1.1-STORE-REV9-AUTHORITATIVE
Target Project:       demo-lanzar-id-store-test (Enforcing Offline Demo Mode)
Emulator Endpoint:    127.0.0.1:8088
Timestamp:            2026-11-15T20:25:23.519Z
================================================================

[EMULATOR] Spawning Java Cloud Firestore Emulator on port 8088...
  ✓ Cloud Firestore Emulator is healthy and accepting connections.

  ✓ [PASS] EMU-01: Real Firestore: Code creation persists document in /authorization_codes with SHA-256 key
  ✓ [PASS] EMU-02: Real Firestore: Atomic Two-Phase Redemption & GCM Receipt Recovery
  ✓ [PASS] EMU-03: Real Firestore: Stale worker CANNOT revoke a newer worker's active session or family
  ✓ [PASS] EMU-04: Real Firestore: Expired lock targeted by different key transitions to COMPROMISED
  ✓ [PASS] EMU-05: Real Firestore: Stale failure handler CANNOT revoke a newer worker's active resources
  ✓ [PASS] EMU-06: Real Firestore: Same-key expired-lock takeover cleanly revokes old pending records and fences stale worker
  ✓ [PASS] EMU-07: Real Firestore: Complete relationship validation rejects mismatched session tenant
  ✓ [PASS] EMU-08: Real Firestore: Concurrent transaction contention handles 10 parallel claims safely
  ✓ [PASS] EMU-09: Real Firestore: Multi-version key rotation recovers receipt encrypted under earlier key
  ✓ [PASS] EMU-10: Real Firestore: Stale worker cannot overwrite pointers after takeover; Worker B pointers remain intact
  ✓ [PASS] EMU-11: Real Firestore: Create-only semantics strictly reject duplicate session and family creation
  ✓ [PASS] EMU-12: Real Firestore: Missing, zero, invalid, or expired leases fail closed
  ✓ [PASS] EMU-13: Real Firestore: Three-document pre-read integrity rejects missing or mismatched staged docs
  ✓ [PASS] EMU-14: Real Firestore: Route fail-closed guard rejects missing capabilities without minting tokens
  ✓ [PASS] EMU-15: Real Firestore: Contention retry after lease expiration fails closed with fresh opTime
[SECURITY ERROR] Distributed codeStore capabilities incomplete or unavailable
  ✓ [PASS] EMU-16: Real Firestore: Missing initiateRedemption capability fails closed with HTTP 500 and zero tokens
  ✓ [PASS] EMU-17: Real Firestore: Fail-closed lease validation across all 3 methods with corrupt expiration values
  ✓ [PASS] EMU-18: Real Firestore: Finalization strictly validates authorization code pointers (issuedSessionId and issuedFamilyId)
  ✓ [PASS] EMU-19: Real Firestore: Ambiguous Firestore create outcomes: safeCleanup revokes committed documents without touching foreign resources
  ✓ [PASS] EMU-20: Real Firestore: Corrupt lease metadata in initiateRedemption() CANNOT revoke newer worker, active, or mismatched records
  ✓ [PASS] EMU-21: Real Firestore: Strict Authorization-Code Expiration rejects missing, null, malformed, zero, negative, non-finite, and expired timestamps
  ✓ [PASS] EMU-22: Real Firestore: Concurrent-conflict and completed-code replay fencing protects foreign, newer-worker, and unrelated active records
  ✓ [PASS] EMU-23: Live Firestore Fail-Closed Replay Fencing & Paired Relationship Validation
  ✓ [PASS] EMU-24: Live Firestore HTTP POST /oauth/token enforces authorizeRefreshGrant() across all refresh scenarios
  ✓ [PASS] EMU-25: Live Firestore HTTP POST /oauth/token enforces refresh-token hash authentication, atomic rotation, replay revocation, and concurrency

[EMULATOR] Terminating emulator process PID 18384...

================================================================
LIVE FIRESTORE EMULATOR TEST SUMMARY
Total Executed: 25
Passed:         25
Failed:         0
Success Rate:   100.0%
================================================================
```

---

## 6. Git Status & Working Tree Integrity

```
On branch lanzar_id_main_chat
Changes not staged for commit:
	modified:   _docs/auth/LANZAR_ID_SECURITY_MODEL.md
	modified:   auth/auth-backend/routes/oauthRoutes.js
	modified:   auth/auth-backend/server.js
	modified:   auth/auth-backend/sessionService.js
	modified:   auth/auth-backend/store.js
	modified:   auth/src/sdk/lanzar-auth-modal.js

Untracked files:
	.netlify/
	_docs/auth/LANZAR_ID_PRE_PRODUCTION_SECURITY_HARDENING.md
	auth/test-milestone-1-1-emulator.cjs
	auth/test-milestone-1-1.cjs
```

**Git Diff Summary:**
```
 _docs/auth/LANZAR_ID_SECURITY_MODEL.md  |   27 +
 auth/auth-backend/routes/oauthRoutes.js |  297 ++++-
 auth/auth-backend/server.js             |   10 +-
 auth/auth-backend/sessionService.js     |    4 +-
 auth/auth-backend/store.js              | 1916 +++++++++++++++++++++++++++++--
 auth/src/sdk/lanzar-auth-modal.js       |   14 +-
 6 files changed, 2153 insertions(+), 115 deletions(-)
```

---

## 7. Verification Status

All 151 tests across the six verification and regression suites pass against the `LID-SPEC-M1.1-STORE-REV9-AUTHORITATIVE` specification and final codebase (with Milestone 1.1 distributed store tests executed locally against the Cloud Firestore Java Emulator in offline demo mode `demo-lanzar-id-store-test`; no production Firestore testing was performed). Milestone 1.1 sign-off remains pending your review and authorization.
