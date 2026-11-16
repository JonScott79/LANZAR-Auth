# LANZAR ID — Pre-Production Security Reconciliation Report

**Project:** LANZAR ID  
**Branch:** `lanzar_id_main_chat`  
**Baseline Commits Preserved:**  
- M1.4: `5fb79411e0bf94131f60fb38d1d57a906067b8d9`  
- M1.5: `80c1dec6760a604badaa06e87549ba67e97ef51c`  

**Review Scope:** Uncommitted Pre-Production Hardening implementation (`firestore.rules`, `auth/auth-backend/routes/adminRoutes.js`, `auth/auth-backend/app.js`, `auth/test-preprod-hardening.cjs`, `auth/test-firestore-rules-emulator.cjs`) compared against the full `auth/auth-backend` Firestore data model and M1.5 security guarantees.  
**Status:** Reconciliation only — no code changes made during this review.

---

## Executive Verdict

**NOT YET READY TO ADVANCE TO STAGING** until the **High-severity** non-atomic/non-fail-closed platform-admin audit defect in `auth/auth-backend/routes/adminRoutes.js` is corrected and verified.

`firestore.rules` provides complete, non-overlapping client-side denial across all server-only collections (including M1.1–M1.5 collections and fallback paths), but `adminRoutes.js` currently violates M1.5's fail-closed atomic audit guarantee, `/api/id/ready` uses a cached JWKS check, and the new hardening/emulator test suites have specific negative-path coverage gaps.

---

## 1. Findings Ranked by Severity

### [HIGH] H-01: Non-Atomic, Non-Fail-Closed Platform-Admin Audit Logging (`adminRoutes.js`)
- **Location:** `auth/auth-backend/routes/adminRoutes.js` lines 31–48 (`recordPlatformAudit`) and lines 97–152 (`POST /users/:uid/suspend`, `POST /users/:uid/founders`, `DELETE /users/:uid/founders/:programId`, `POST /users/:uid/sessions/revoke-all`).
- **Evidence:**
  1. `recordPlatformAudit` passes `strict: false` (line 46) to `auditLogService.recordAdminEvent(...)`. In `auth/auth-backend/services/auditLogService.js` (lines 95–114), `strict: false` catches any Firestore write error, logs it to `console.error`, and returns `null` without throwing.
  2. Line 32 silently returns (`if (!auditLogService || typeof auditLogService.recordAdminEvent !== 'function') return;`) if `auditLogService` is not wired.
  3. All four mutating routes execute their Firestore state mutation (`profileService.setAccountStatus`, `founderService.grantFounderDesignation`, `founderService.revokeFounderDesignation`, `sessionService.revokeAllSessions`) **before** calling `recordPlatformAudit`, and **outside** any Firestore transaction.
- **Impact:** If the audit write fails (or `auditLogService` is missing), the administrative mutation has already committed to Firestore and the API returns `200 OK` with **no audit record**. This directly violates the atomic fail-closed audit standard established in M1.5 (`clientRegistryService.js` + `AuditLogService.writeInTransaction` inside `db.runTransaction`).
- **Secondary Defect in Same File:** `adminRoutes.js` catch blocks (lines 73, 93, 104, 123, 140, 150, 165, 203, 217) return `err.message` directly in `error_description`, which can leak internal Firestore/runtime error details. Also, `recordPlatformAudit` places `targetUid` in `clientId` (line 41) instead of `metadata.targetUid` / a dedicated field.

### [MEDIUM] M-01: `/api/id/ready` Uses Cached JWKS Without `bypassCache: true` (`app.js`)
- **Location:** `auth/auth-backend/app.js` lines 261–284 (specifically line 273).
- **Evidence:** `app.js:267` performs a live Firestore read (`await db.collection('system_signing_keys').doc('_active_pointer').get()`), which does verify Firestore connectivity. However, `app.js:273` calls `await signingKeystore.getPublicJwks()` **without** `{ bypassCache: true }`.
- **Impact:** If `signingKeystore` has a warm in-memory JWKS cache (`this._cachedJwks` within `cacheTtlMs`), `/api/id/ready` will report `200 ready` even if all signing keys in Firestore were revoked or deleted, until the cache expires. Additionally, `/api/id/ready` does not verify `validateReceiptKeyConfiguration()` at readiness time (though `FirestoreAuthorizationCodeStore` validates it at startup/construction).

### [MEDIUM] M-02: Hardening & Firestore Emulator Test Coverage Gaps
- **Location:** `auth/test-preprod-hardening.cjs` and `auth/test-firestore-rules-emulator.cjs`.
- **Evidence:**
  1. `PPH-01` only tests `POST /users/:uid/suspend` on the happy path; it does **not** test audit-write failure (fail-closed rollback), `POST /users/:uid/founders`, `DELETE /users/:uid/founders/:programId`, or `POST /users/:uid/sessions/revoke-all`.
  2. `PPH-02` overrides `getPublicJwks` on an `InMemoryFirestore` instance rather than verifying live cache bypass or deleted/revoked Firestore keys.
  3. `test-firestore-rules-emulator.cjs` (`RULES-01`..`RULES-03`) tests 9 M1.1–M1.5 server-only paths and `/users/{uid}` + `/users/{uid}/sessions/{sessionId}`, but does not test unauthenticated requests, `/users/{uid}` disallowed-field/create/delete rejections, or legacy/nested server-only paths (`/users/*/central_sessions/*`, `/users/*/session_slots/*`, `/users/*/founders/*`, `/user_security/*`, `/security_logs/*`, `/mfa_factors/*`, `/phone_otps/*`, `/admins/*`, `/entitlements/*`, `/pythos/app/lanzar_id_accounts/*`, `/tenants/*`).

### [LOW] L-01: Unreferenced/Implicitly-Denied Collection `/pythos/app/lanzar_id_accounts`
- **Location:** `auth/auth-backend/routes/accountRoutes.js:186` vs `firestore.rules`.
- **Evidence:** `accountRoutes.js:186` accesses `db.collection('pythos').doc('app').collection('lanzar_id_accounts')`. `firestore.rules` has no explicit `match /pythos/...` block, so it relies on the catch-all `match /{document=**} { allow read, write: if false; }` (lines 117–119). Client access is still denied, but an explicit rule + emulator test improves clarity and defense-in-depth.

---

## 2. Firestore Security Rules — Complete Coverage Matrix

Inspected the entire `firestore.rules` (lines 1–121) against every `.collection(...)` reference in `auth/auth-backend`.

- **Overlapping Rule Analysis:** `match /users/{userId}` (lines 22–27) grants `read` and allowlisted `update` (`displayName`, `avatarUrl`, `bio`, `notificationPreferences` only via `isValidProfileUpdate`) strictly to `request.auth.uid == userId`, and denies `create, delete`. In Firestore Rules, `match /users/{userId}` does **not** match subcollections. All other blocks in `firestore.rules` (lines 30–119) are explicit `if false;` denials, ending with `match /{document=**} { allow read, write: if false; }`. **No overlapping wildcard or parent match grants permissive access to any protected collection.**

| Collection / Document Path | Code Reference | Client Read Denied | Client Write Denied | Overlapping Grant? | Emulator Test Coverage | Remaining Uncertainty |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `/users/{userId}` | `profileService.js`, `authMiddleware.js` | Owner-only (`uid == userId`) | `create/delete` denied; `update` allowlisted (`isValidProfileUpdate`) | None | `RULES-01` (read + `displayName` update), `RULES-02` (cross-user read denied) | Disallowed fields (`status`, `role`, `tokenVersion`, `updatedAt`), `create`, `delete`, unauth not yet tested in emulator |
| `/users/{userId}/sessions/{sessionId}` | `sessionService.js`, `store.js`, `oidcRoutes.js` | Yes (`rules:41-43`) | Yes (`rules:41-43`) | None | `RULES-02` (GET, PATCH denied) | DELETE & unauth not explicitly tested |
| `/users/{userId}/central_sessions/{sessionId}` | `centralSessionService.js`, `commonVerifier.js` | Yes (`rules:35-37`) | Yes (`rules:35-37`) | None | None | Not yet covered in `test-firestore-rules-emulator.cjs` |
| `/users/{userId}/session_slots/{slotId}` | `centralSessionService.js:116` | Yes (`rules:38-40`) | Yes (`rules:38-40`) | None | None | Not yet covered in `test-firestore-rules-emulator.cjs` |
| `/users/{userId}/founders/{founderId}` | `founderService.js` | Yes (`rules:30-32`) | Yes (`rules:30-32`) | None | None | Not yet covered in `test-firestore-rules-emulator.cjs` |
| `/authorization_codes/{codeHash}` | `store.js:576` | Yes (`rules:91-93`) | Yes (`rules:91-93`) | None | `RULES-03` (GET, PATCH, DELETE) | Covered |
| `/oauth_authorization_codes/{codeHash}` | `firestore.rules:88-90` (legacy/alias) | Yes (`rules:88-90`) | Yes (`rules:88-90`) | None | `RULES-03` (GET, PATCH, DELETE) | Covered |
| `/oauth_codes/{codeHash}` | `firestore.rules:85-87` (legacy/alias) | Yes (`rules:85-87`) | Yes (`rules:85-87`) | None | None | Covered by explicit rule; not in emulator test |
| `/compromised_ceremonies/{ceremonyId}` | `store.js:773` | Yes (`rules:94-96`) | Yes (`rules:94-96`) | None | `RULES-03` (GET, PATCH, DELETE) | Covered |
| `/security_outbox/{eventId}` | `store.js:791,820` | Yes (`rules:97-99`) | Yes (`rules:97-99`) | None | `RULES-03` (GET, PATCH, DELETE) | Covered |
| `/system_signing_keys/{kid}` | `signingKeystore.js:270` | Yes (`rules:100-102`) | Yes (`rules:100-102`) | None | `RULES-03` (GET, PATCH, DELETE) | Covered |
| `/clients_index/{clientId}` | `clientRegistryService.js:108` | Yes (`rules:103-105`) | Yes (`rules:103-105`) | None | `RULES-03` (GET, PATCH, DELETE) | Covered |
| `/tenants/{tenantId}/clients/{clientId}` | `clientRegistryService.js:104` | Yes (`rules:106-108`) | Yes (`rules:106-108`) | None | `RULES-03` (GET, PATCH, DELETE) | Covered |
| `/tenants/{tenantId}/token_families/{familyId}` | `store.js:706`, `oauthRoutes.js:284` | Yes (`rules:109-111`) | Yes (`rules:109-111`) | None | `RULES-03` (GET, PATCH, DELETE) | Covered |
| `/tenants/{tenantId}/admin_audit_logs/{auditId}` | `auditLogService.js:76` | Yes (`rules:112-114`) | Yes (`create, update, delete: if false`) | None | `RULES-03` (GET, PATCH, DELETE, CREATE) | Covered |
| `/user_security/{userId}` | `centralSessionService.js`, `commonVerifier.js`, `policies.js` | Yes (`rules:46-48`) | Yes (`rules:46-48`) | None | None | Not yet covered in `test-firestore-rules-emulator.cjs` |
| `/security_logs/{logId}` | `auditService.js:62`, `adminRoutes.js:157` | Yes (`rules:49-51`) | Yes (`rules:49-51`) | None | None | Not yet covered in `test-firestore-rules-emulator.cjs` |
| `/mfa_factors/{userId}` | `profileService.js`, `mfaRoutes.js`, `oauthRoutes.js` | Yes (`rules:52-54`) | Yes (`rules:52-54`) | None | None | Not yet covered in `test-firestore-rules-emulator.cjs` |
| `/phone_otps/{otpId}` | `smsService.js` | Yes (`rules:55-57`) | Yes (`rules:55-57`) | None | None | Not yet covered in `test-firestore-rules-emulator.cjs` |
| `/admins/{adminId}` | `authMiddleware.js:9,15` | Yes (`rules:58-60`) | Yes (`rules:58-60`) | None | None | Not yet covered in `test-firestore-rules-emulator.cjs` |
| `/customers/{userId}`, `/mailing_list/{email}`, `/entitlements/{userId}/**`, `/subscriptions/{subId}`, `/stripe_*/*`, `/_lanzar_environment/{docId}` | `firestore.rules:61-84` | Yes (`rules:61-84`) | Yes (`rules:61-84`) | None | None | Not yet covered in `test-firestore-rules-emulator.cjs` |
| `/pythos/app/lanzar_id_accounts/{docId}` | `accountRoutes.js:186` | Yes (default-deny `rules:117-119`) | Yes (default-deny `rules:117-119`) | None | None | Relies on default-deny; add explicit `match /pythos/{document=**}` + test |
| `/tenants/{tenantId}` (parent doc) & all other paths | `firestore.rules:117-119` | Yes (`rules:117-119`) | Yes (`rules:117-119`) | None | None | Covered by default-deny |

---

## 3. Administrative Audit Guarantees (`adminRoutes.js` vs M1.5 Standard)

- **Authorization (`requirePlatformAdmin`, `adminRoutes.js:14-29`):** Correctly enforces `req.isAdmin && req.adminContext && isPlatformAdmin`, rejecting `tenant_admin` callers with `403 FORBIDDEN`.
- **Audit Record Fields (`recordPlatformAudit`, `adminRoutes.js:31-48` + `AuditLogService.buildAdminAuditRecord`):** Records `actorUid`, `actorEmail`, `actorTenantId`, `actorRole: 'platform_admin'`, `targetTenantId: 'lanzar'`, `operation`, `outcome`, `correlationId`, `metadata` (sanitized), `immutable: true`, and `timestamp`. However, `targetUid` is stored in `clientId` rather than `metadata.targetUid`.
- **Atomicity & Fail-Closed Defect:**
  - **M1.5 Standard (`clientRegistryService.js`):** Client mutations (`registerClient`, `updateClient`, `disableClient`, `enableClient`) build the audit record via `auditLogService.buildAdminAuditRecord(...)` and write it inside `db.runTransaction(...)` via `auditLogService.writeInTransaction(tx, prepared)` with deterministic retry-safe audit IDs. If the audit write fails, the entire transaction rolls back and returns `503`.
  - **Current `adminRoutes.js` Implementation:** Executes `setAccountStatus` / `grantFounderDesignation` / `revokeFounderDesignation` / `revokeAllSessions` first, then calls `recordPlatformAudit` with `strict: false` outside any transaction. If the audit write fails, the mutation **persists** and the endpoint returns `200 OK`.

---

## 4. Readiness Endpoint Assessment (`/api/id/ready`)

- **Location:** `auth/auth-backend/app.js` lines 261–284.
- **HTTP Status & Sanitization:** Returns `200` when Firestore read + non-empty JWKS succeed; returns `503` (`{ status: 'not_ready', checks, correlationId }`) when `db` is missing, Firestore throws, `signingKeystore` is missing, or `jwks.keys.length === 0`. Catches errors, logs internally with `correlationId`, and never leaks `err.message` or secrets in the HTTP response.
- **Firestore Read Behavior:** Performs a single lightweight document read (`db.collection('system_signing_keys').doc('_active_pointer').get()`).
- **Gap:** Calls `signingKeystore.getPublicJwks()` **without** `{ bypassCache: true }`, allowing a warm cache to mask key deletion/revocation in Firestore until cache TTL expiry. Also does not re-validate `validateReceiptKeyConfiguration()`.

---

## 5. Test Coverage Gaps

1. **`auth/test-preprod-hardening.cjs`:**
   - Missing negative test proving `POST /users/:uid/suspend`, `POST /users/:uid/founders`, `DELETE /users/:uid/founders/:programId`, and `POST /users/:uid/sessions/revoke-all` fail closed (`503`) and roll back (or leave state unchanged) when `auditLogService` fails or is missing.
   - Missing `tenant_admin` `403` and `platform_admin` `200` + audit assertions for `/users/:uid/founders`, `DELETE /users/:uid/founders/:programId`, and `/users/:uid/sessions/revoke-all`.
   - `PPH-02` should verify `/api/id/ready` with `bypassCache: true` against deleted/revoked keys in the keystore.
2. **`auth/test-firestore-rules-emulator.cjs`:**
   - Add unauthenticated request tests (`403`/`401` across `/users/user_a` and server-only collections).
   - Add `/users/user_a` negative write tests (`create`, `delete`, disallowed fields `status`, `role`, `tokenVersion`, `updatedAt`).
   - Add emulator `RULES` checks for remaining server-only collections (`/users/user_a/central_sessions/*`, `/users/user_a/session_slots/*`, `/users/user_a/founders/*`, `/user_security/*`, `/security_logs/*`, `/mfa_factors/*`, `/phone_otps/*`, `/admins/*`, `/pythos/app/lanzar_id_accounts/*`).

---

## 6. Required Corrective Actions (Before Staging)

1. **[MUST FIX — High]** Make `adminRoutes.js` mutating operations (`POST /users/:uid/suspend`, `POST /users/:uid/founders`, `DELETE /users/:uid/founders/:programId`, `POST /users/:uid/sessions/revoke-all`) **atomic and fail-closed** with their required audit log:
   - Require `auditLogService` (fail closed `503` if unavailable on mutating routes).
   - Execute the state mutation + `auditLogService.writeInTransaction(tx, prepared)` inside a single `db.runTransaction(...)` (with deterministic/idempotent audit ID per attempt so Firestore transaction retries do not create duplicates), or refactor the underlying `profileService`/`founderService`/`sessionService` methods to accept a transaction / `auditPrepared` callback.
   - Remove `strict: false`; record `targetUid` cleanly in `metadata.targetUid`.
   - Sanitize `500`/`400` error responses in `adminRoutes.js` so internal Firestore error strings are not returned to clients.
2. **[SHOULD FIX — Medium]** Update `/api/id/ready` in `auth/auth-backend/app.js` to call `await signingKeystore.getPublicJwks({ bypassCache: true })` so readiness cannot report `200` on stale cached keys.
3. **[SHOULD FIX — Medium]** Add an explicit `match /pythos/{document=**} { allow read, write: if false; }` block to `firestore.rules` for clarity.
4. **[MUST VERIFY — Medium]** Expand `auth/test-preprod-hardening.cjs` and `auth/test-firestore-rules-emulator.cjs` to cover all gaps listed in Section 5, and re-run with all M1.1–M1.5 regression suites.
