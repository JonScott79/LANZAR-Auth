# LANZAR ID — Milestone 1.2 Reconciliation & Verification Report

**Date:** 2026-11-15  
**Target Specification:** `LID-SPEC-M1.2-JWKS-RS256-AUTHORITATIVE`  
**Status:** Remediations Applied & Verified Locally (Pending Sign-Off; Not Committed/Pushed/Deployed)  

---

## 1. Remediations Applied

| Item | Change Summary | Files Modified |
| :--- | :--- | :--- |
| **Singleton Active-Key Pointer** | Added `ACTIVE_POINTER_DOC_ID = '_active_pointer'` in `system_signing_keys`; `ensureActiveSigningKey()`, `rotateSigningKey()`, and `revokeSigningKey()` read/write `_active_pointer` inside Firestore transactions; `candidateRecord` generated outside `runTransaction()`; legacy active keys reconciled deterministically; revoked keys cannot be reactivated; `_active_pointer` excluded from `getPublicJwks()`. | `auth/auth-backend/services/signingKeystore.js` |
| **Staging KEK Validation** | Updated `isProductionOrStaging()` to match all 4 conditions: `NODE_ENV === 'production'`, `NODE_ENV === 'staging'`, `APP_ENV === 'production'`, `APP_ENV === 'staging'`. Dev KEK fallback remains restricted to non-production, non-staging environments. | `auth/auth-backend/services/signingKeystore.js` |
| **JWKS Cache & Revocation Policy** | Reduced HTTP `Cache-Control` from `public, max-age=300` to `public, max-age=60`; reduced `DEFAULT_JWKS_CACHE_TTL_MS` from `30000` ms to `5000` ms; documented 60-second external revocation exposure window. | `auth/auth-backend/routes/jwksRoutes.js`, `auth/auth-backend/services/signingKeystore.js` |
| **Verification Coverage** | Added unit & emulator tests for `NODE_ENV=staging` (with `APP_ENV` unset), `max-age=60`, 5s cache TTL, pre-transaction RSA generation under retry, legacy active-key reconciliation without `_active_pointer`, and non-reactivation of revoked keys. | `auth/test-milestone-1-2.cjs`, `auth/test-milestone-1-2-emulator.cjs` |
| **M1.1 Receipt-Key Staging Fix** | Updated `isProductionOrStaging(env)` in `store.js` to include `env.NODE_ENV === 'staging'` and reused it in `resolveRawReceiptKeyFromEnv()` and `validateReceiptKeyConfiguration()`, rejecting `TOKEN_RECEIPT_KEY` fallback when `NODE_ENV=staging` with `APP_ENV` unset. Added Subtest 24E in `TC-24`. | `auth/auth-backend/store.js`, `auth/test-milestone-1-1.cjs` |

---

## 2. Active-Key Pointer Consistency & Initial Test Run Explanation

- **Pointer Consistency:** All key lifecycle mutations (`ensureActiveSigningKey()`, `rotateSigningKey()`, and `revokeSigningKey()`) read and update `system_signing_keys/_active_pointer` inside `db.runTransaction(...)`. `_active_pointer.activeKid` always identifies the sole `active` key, or is `null` when the active key is revoked until a replacement is initialized.
- **Initial `test-milestone-1-2.cjs` Failure (Exit Code 1):** The first post-remediation run of `node auth/test-milestone-1-2.cjs` failed 3 of 11 tests (`M1.2-03`, `M1.2-09`, `M1.2-10`) because `MockKeystoreFirestore` stores documents in `db.docs` under `${collectionName}/${docId}` (`system_signing_keys/...`), whereas the new assertions in those 3 tests initially read/wrote bare keys (`'_active_pointer'`, `legacy1.kid`, `first.kid`) without the `system_signing_keys/` prefix. Production code in `signingKeystore.js` was unchanged; updating those 3 test assertions in `auth/test-milestone-1-2.cjs` to use the `system_signing_keys/` key prefix resolved all 3 failures (`11/11 PASS`).

---

## 3. Verification Results (Post-Final-Edit)

> **Environment Distinction:** Emulator tests ran against a local **Cloud Firestore Emulator** (`demo-lanzar-id-m1-2-test` on `127.0.0.1:8089`). **Zero production Cloud Firestore or deployed environment tests were executed.**

| Suite | Command | Result | Scope |
| :--- | :--- | :--- | :--- |
| **M1.2 Unit & HTTP Suite** | `node auth/test-milestone-1-2.cjs` | **11 / 11 PASS** | KEK validation (`production`/`staging`/`dev`), AES-256-GCM AAD, `_active_pointer` concurrency, RS256 sign/verify, rotation, revocation, `GET /.well-known/jwks.json` (`max-age=60`), legacy reconciliation, revoked-key non-reactivation, 5s cache TTL & retry-safe RSA generation. |
| **M1.2 Firestore Emulator Suite** | `node auth/test-milestone-1-2-emulator.cjs` | **7 / 7 PASS** | Local Firestore Emulator (`127.0.0.1:8089`): persistence, concurrent init (`_active_pointer`), rotation (`verify_only`), revocation, concurrent rotation contention, legacy active-key reconciliation, revoked-key non-reactivation. |
| **M1.1 Regression Suite** | `node auth/test-milestone-1-1.cjs` | **44 / 44 PASS** | Full M1.1 authorization code, refresh-token rotation, fencing, and replay containment regression. |
| **Phase 1 Acceptance Suite** | `node auth/test-phase1-acceptance.cjs` | **55 / 55 PASS** | Environment isolation, session lifecycle, password recovery, and authorization policies. |

---

## 4. External Revocation Exposure Disclosure

- **External HTTP/Relying-Party Cache:** `GET /.well-known/jwks.json` advertises `Cache-Control: public, max-age=60`. External relying parties and HTTP caches may validate tokens using cached public keys for up to **60 seconds** after a key is revoked.
- **Internal Instance Cache:** Non-mutating backend instances may hold cached JWKS for up to **5 seconds** (`DEFAULT_JWKS_CACHE_TTL_MS = 5000`).
- **Conclusion:** External revocation is **bounded to 60 seconds**, not instantaneous.
