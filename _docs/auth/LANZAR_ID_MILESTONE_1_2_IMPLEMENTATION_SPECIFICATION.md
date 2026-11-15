# LANZAR ID — Milestone 1.2 Implementation Specification

**Document ID:** `LID-SPEC-M1.2-JWKS-RS256-AUTHORITATIVE`  
**Status:** Remediated & Verified (Pre-Commit)  
**Scope:** Asymmetric RS256 Signing Keystore & Public JWKS Endpoint (`/.well-known/jwks.json`)  

---

## 1. Architecture Overview

Milestone 1.2 introduces asymmetric RS256 token signing and public key discovery via RFC 7517 JWKS while keeping private key material encrypted at rest in Firestore.

### Core Components
- **`auth/auth-backend/services/signingKeystore.js`**: Manages RSA-2048 key generation, AES-256-GCM private-key envelope encryption, Firestore transaction-safe initialization/rotation/revocation, JWT signing/verification, and sanitized JWKS generation.
- **`auth/auth-backend/routes/jwksRoutes.js`**: Exposes `GET /.well-known/jwks.json` with `Cache-Control: public, max-age=60` and fail-closed `503` when the keystore is unavailable.
- **`auth/auth-backend/app.js` & `auth/auth-backend/server.js`**: Mounts the JWKS router at `/` and enforces `validateSigningKeyEncryptionConfiguration(process.env)` during startup.

---

## 2. Singleton Active-Key Pointer (`_active_pointer`) & Transaction Safety

All signing keys live in the `system_signing_keys` Firestore collection, alongside a deterministic singleton pointer document `system_signing_keys/_active_pointer`.

### Concurrency & Retry Guarantees
1. **Deterministic Serialization:** Both `ensureActiveSigningKey()` and `rotateSigningKey()` read and write `_active_pointer` inside `db.runTransaction(...)` so concurrent initialization or rotation across instances serializes on the same document.
2. **Pre-Transaction Key Generation:** `candidateRecord = generateRsaSigningKeyRecord(...)` is executed **outside** the `db.runTransaction(...)` callback so Firestore contention retries never regenerate RSA-2048 key pairs.
3. **Read-Before-Write Discipline:** All `tx.get(...)` calls (`_active_pointer`, pointed key document, and `where('status', '==', 'active')` query) execute before any `tx.set(...)` or `tx.update(...)`.
4. **Revoked Key Protection:**
   - `ensureActiveSigningKey()` checks that the pointed-to key exists and has `status === 'active'`.
   - If `_active_pointer` points to a missing, `verify_only`, or `revoked` key, it never reactivates that key; it queries for any existing `active` key or activates the pre-generated `candidateRecord`.
   - `revokeSigningKey(kid)` atomically sets `status: 'revoked'` and clears `_active_pointer.activeKid = null` if `activeKid === kid`.
5. **Legacy Reconciliation:** If `active` key document(s) exist without `_active_pointer`, `ensureActiveSigningKey()` deterministically selects the newest active key (`activatedAt || createdAt` desc, `kid` asc), demotes any duplicate `active` keys to `verify_only`, and writes `_active_pointer` without creating a new key.
6. **Verify-Only Preservation:** Rotated keys transition to `status: 'verify_only'` and remain published in `getPublicJwks()` so previously minted RS256 tokens verify until natural expiration. `_active_pointer` and `revoked` keys are strictly excluded from `getPublicJwks()`.

---

## 3. Private Key Encryption & Environment KEK Validation

- **Envelope Encryption:** Private key PEMs are encrypted with AES-256-GCM (`12`-byte random IV, `16`-byte authentication tag) and AAD bound to `lanzar_signing_key:${kid}:v${keyVersion}`.
- **Key Scrubbing:** `sanitizePublicJwk()` emits only `{ kty: 'RSA', use: 'sig', alg: 'RS256', kid, n, e }`. Private key fields (`d`, `p`, `q`, `dp`, `dq`, `qi`, `encryptedPrivateKey`, `privateKey`) are never returned in JWKS responses.
- **Production & Staging Fail-Closed Validation:** `isProductionOrStaging()` returns `true` when any of the following hold:
  - `NODE_ENV === 'production'`
  - `NODE_ENV === 'staging'`
  - `APP_ENV === 'production'`
  - `APP_ENV === 'staging'`
  In all four cases, `SIGNING_KEY_ENCRYPTION_KEY` is mandatory, must be at least 32 bytes, must not match any known development/default KEK, and `ACTIVE_SIGNING_KEK_VERSION` (if set) must be a positive integer. Development fallback is permitted only in explicitly non-production, non-staging environments (e.g., `NODE_ENV=development` or `NODE_ENV=test`).

---

## 4. JWKS Cache Policy & Revocation Exposure

- **HTTP Response Caching:** `GET /.well-known/jwks.json` sets `Cache-Control: public, max-age=60`.
- **Instance Cache TTL:** `DEFAULT_JWKS_CACHE_TTL_MS` is `5000` ms (`5` seconds). `rotateSigningKey()` and `revokeSigningKey()` call `invalidateCache()` immediately on the mutating instance.
- **Revocation Exposure Window (Important Limitation):**
  - **Local / Same-Instance:** Key revocation immediately removes the key from future signing and from `getPublicJwks({ bypassCache: true })` / invalidated local cache.
  - **Cross-Instance:** Other backend instances may serve cached JWKS for up to **5 seconds** until their in-memory TTL expires.
  - **External Relying Parties & HTTP Caches:** External consumers and intermediate HTTP caches honoring `Cache-Control: public, max-age=60` may continue verifying tokens signed by a revoked key for up to **60 seconds** after revocation. **Instantaneous external revocation is not claimed or guaranteed.**
