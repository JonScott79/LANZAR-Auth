# LANZAR ID — Complete API & Endpoint Specification
**Document ID:** LID-API-004  
**Classification:** Confidential — Internal Master API Reference  
**Status:** Authoritative Baseline (Phase 1 Approved)  
**Base URL (Prod):** `https://auth-api.lanzar.me` (CNAME `wtk9m980.up.railway.app`)  
**Base URL (Dev):** `http://localhost:4001`  
**Date:** November 8, 2026  
**Author:** Larry (Lead Systems Architect)  

---

## 1. Authentication Standards & Header Conventions

* **Bearer Token Authentication:** All protected endpoints require a cryptographically valid ID token:
  ```http
  Authorization: Bearer <firebase_id_token>
  ```
* **Client Identification Header:** Protected endpoints optionally accept:
  ```http
  X-Lanzar-Client-Id: <client_id>
  X-Lanzar-Tenant-Id: <tenant_id> (Defaults to "lanzar")
  ```
* **Error Envelope Format:** All non-2xx responses adhere to the standard OAuth2 / RFC 7807 error format:
  ```json
  {
    "error": "invalid_grant",
    "error_description": "The authorization code provided is expired or invalid.",
    "status_code": 400,
    "timestamp": "2026-11-08T22:00:00Z"
  }
  ```

---

## 2. Public Identity Authority Endpoints (`auth-api.lanzar.me`)

### 2.1 OAuth 2.0 / PKCE Authorization
#### `POST /authorize`
Validates client application credentials, verifies user authentication and MFA proofs, and generates a single-use authorization code.

* **Request Headers:** `Content-Type: application/json`
* **Request Body:**
  ```json
  {
    "idToken": "eyJhbGciOi...",
    "client_id": "portal",
    "redirect_uri": "https://portal.lanzar.me",
    "state": "random_csrf_token_string",
    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    "code_challenge_method": "S256",
    "mfa_proof": "optional_mfa_proof_jwt"
  }
  ```
* **Validation Rules:**
  1. `client_id` must match an active client in the application registry (`clients.js`).
  2. `redirect_uri` must strictly match one of the client's whitelisted redirect URIs.
  3. `code_challenge_method` must equal `'S256'`.
  4. User account must not be suspended (`status !== 'suspended'`).
  5. If user has MFA enabled or is an administrator, `mfa_proof` must be verified.
* **Success Response (200 OK):**
  ```json
  {
    "code": "auth_code_32_bytes_entropy_hex",
    "state": "random_csrf_token_string"
  }
  ```
* **MFA Required Challenge (403 Forbidden):**
  ```json
  {
    "error": "mfa_required",
    "error_description": "Multi-Factor Authentication required.",
    "mfa_required": true,
    "mfa_session": "signed_mfa_challenge_jwt",
    "methods": ["passkey", "totp", "recovery"]
  }
  ```

---

#### `POST /exchange`
Exchanges a single-use authorization code and PKCE `code_verifier` for a Firebase Custom Token.

* **Request Body:**
  ```json
  {
    "code": "auth_code_32_bytes_entropy_hex",
    "client_id": "portal",
    "redirect_uri": "https://portal.lanzar.me",
    "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  }
  ```
* **Validation Rules:**
  1. Code must exist, must be unexpired (`TTL <= 60 seconds`), and must be unused.
  2. SHA-256 hash of `code_verifier` must match stored `code_challenge`.
  3. `client_id` and `redirect_uri` must match authorization request parameters exactly.
* **Execution:**
  1. Marks code as `used: true` to prevent replay attacks.
  2. Generates a new `sessionId` in `/users/{uid}/sessions/{sessionId}`.
  3. Uses Firebase Admin SDK to mint a Firebase Custom Token with claims:
     ```json
     {
       "session_id": "sess_0192a8b7c6",
       "tenant_id": "lanzar",
       "tokenVersion": 1,
       "role": "customer"
     }
     ```
* **Success Response (200 OK):**
  ```json
  {
    "custom_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6...",
    "session_id": "sess_0192a8b7c6",
    "expires_in": 3600
  }
  ```

---

### 2.2 Registration & Password Recovery
#### `POST /register`
Self-service user registration.

* **Request Body:**
  ```json
  {
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "fullName": "Jane Doe",
    "businessName": "Acme Corp",
    "dispatchOptIn": false
  }
  ```
* **Validation Rules:**
  - Password minimum 8 characters, at least 1 digit and 1 symbol.
  - Email normalized and checked for existing accounts.
* **Execution:**
  - Creates Firebase Auth record (`admin.auth().createUser`).
  - Initializes `/users/{uid}` in Firestore with `derivedBadges: []`.
  - Dispatches email verification via Firebase Auth.
* **Response (200 OK):**
  ```json
  {
    "success": true,
    "uid": "usr_01928374",
    "email": "user@example.com",
    "emailVerified": false
  }
  ```

#### `POST /password/forgot`
Triggers rate-limited, single-use password recovery email.
* **Request Body:** `{ "email": "user@example.com" }`
* **Response (200 OK):** Always returns `{ "success": true, "message": "If an account exists, a reset link was dispatched." }` to prevent account enumeration.

---

### 2.3 Universal TOTP Authenticator Endpoints (Amendment #001)

#### `POST /mfa/totp/setup`
Initiates TOTP enrollment. Generates a cryptographically random Base32 secret, stages it in a 10-minute unconfirmed cache, and returns standard `otpauth://` URI compatible with **Microsoft Authenticator**, **Google Authenticator**, **1Password**, and **Bitwarden**.
* **Headers:** `Authorization: Bearer <id_token>`
* **Response (200 OK):**
  ```json
  {
    "success": true,
    "secret": "JBSWY3DPEHPK3PXP...",
    "otpauthUrl": "otpauth://totp/LANZAR%20ID:user@example.com?secret=JBSWY3DPEHPK3PXP...&issuer=LANZAR%20ID&algorithm=SHA1&digits=6&period=30"
  }
  ```

#### `POST /mfa/totp/enable`
Verifies the initial 6-digit code from the user's authenticator app, encrypts the secret using AES-256-GCM, stores it in `/mfa_factors/{uid}`, and returns 8 single-use recovery codes.
* **Request Body:** `{ "idToken": "...", "code": "123456" }`
* **Validation Rules:**
  - Code verified against staged secret with replay prevention.
  - Staged secret must not be expired (< 10 minutes).
* **Response (200 OK):**
  ```json
  {
    "success": true,
    "recoveryCodes": [
      "A1B2-C3D4",
      "E5F6-G7H8",
      "I9J0-K1L2",
      "M3N4-O5P6",
      "Q7R8-S9T0",
      "U1V2-W3X4",
      "Y5Z6-A7B8",
      "C9D0-E1F2"
    ]
  }
  ```

---

## 3. User Account Management APIs (`id.lanzar.me` & `lanzar.me`)

### 3.1 Profile & Avatar Management
#### `GET /api/id/profile`
Fetches authenticated user profile, active sessions summary, and derived badges.
* **Headers:** `Authorization: Bearer <id_token>`
* **Response (200 OK):**
  ```json
  {
    "uid": "usr_01928374",
    "tenantId": "lanzar",
    "email": "user@example.com",
    "emailVerified": true,
    "displayName": "Jane Doe",
    "avatarUrl": "https://storage.googleapis.com/.../avatar.webp",
    "derivedBadges": ["lanzar_id_founder", "pythos_founder"],
    "derivedEntitlements": { "pythos": "pro", "portal": "customer" },
    "mfa": { "totpEnabled": true, "passkeyCount": 2 },
    "tokenVersion": 1
  }
  ```

#### `PUT /api/id/profile`
Updates user-editable profile attributes (display name, bio).
* **Payload:** `{ "displayName": "Jane D.", "bio": "Software engineer" }`
* **Security Assertion:** Any attempt to submit `derivedBadges`, `role`, or `tokenVersion` is silently ignored by the server.

#### `POST /api/id/avatar`
Uploads and crops avatar image.
* **Content-Type:** `multipart/form-data` (Image file, max 2MB, JPEG/PNG/WebP).
* **Execution:** Sanitizes image, converts to WebP, uploads to Cloud Storage (`/avatars/{uid}.webp`), and updates `/users/{uid}.avatarUrl`.

---

### 3.2 Session & Security Controls
#### `GET /api/id/sessions`
Returns all active device sessions for the authenticated user.
* **Response (200 OK):**
  ```json
  {
    "sessions": [
      {
        "sessionId": "sess_0192a8",
        "deviceName": "MacBook Pro 16",
        "browser": "Chrome 131",
        "ipAddress": "72.229.28.185",
        "current": true,
        "createdAt": "2026-11-08T20:00:00Z"
      }
    ]
  }
  ```

#### `DELETE /api/id/sessions/:sessionId`
Revokes an individual device session.
* **Execution:** Updates session document in Firestore to `revoked: true`. The backend server gate will reject subsequent requests bearing this `session_id`.

#### `POST /api/id/sessions/revoke-all`
Global "Sign Out Everywhere" kill switch.
* **Execution:**
  1. `admin.auth().revokeRefreshTokens(uid)`
  2. Atomically increments `tokenVersion` on `/users/{uid}`.
  3. Marks all active sessions in `/users/{uid}/sessions` as `revoked: true`.

---

### 3.3 Phone Number Verification & Authentication Endpoints (Amendment #002)

#### `POST /api/id/phone/send-otp`
Initiates phone number verification for account settings.
* **Headers:** `Authorization: Bearer <id_token>`
* **Request Body:** `{ "phoneNumber": "+15085551234" }`
* **Validation Rules:**
  - Strict E.164 normalization.
  - Country code whitelisting (US/CA `+1`).
  - Rate limiting (max 1 per 60s per number, max 3 per IP per hour).
* **Response (200 OK):**
  ```json
  {
    "success": true,
    "phoneNumber": "+15085551234",
    "expiresInSeconds": 300,
    "liveSmsActive": false
  }
  ```

#### `POST /api/id/phone/verify`
Confirms the 6-digit OTP code and updates the user profile with verified phone status.
* **Headers:** `Authorization: Bearer <id_token>`
* **Request Body:** `{ "phoneNumber": "+15085551234", "code": "654321" }`
* **Validation Rules:**
  - Max 5 failed attempts before code burning.
  - 5-minute code expiration TTL.
* **Response (200 OK):**
  ```json
  {
    "success": true,
    "phoneNumber": "+15085551234",
    "phoneVerified": true
  }
  ```

---

## 4. Administrative Operations APIs (Portal Mission Control)

All administrative routes require verified administrative identity (`role: 'admin'`) and step-up MFA verification.

### 4.1 User Operations
#### `GET /api/admin/id/users`
Paginated search and filter across ecosystem identities.
* **Query Params:** `query=alex&status=active&badge=pythos_founder&page=1&limit=25`
* **Response (200 OK):** Returns array of user summaries with pagination metadata.

#### `GET /api/admin/id/users/:uid`
Deep inspection of an identity profile, active sessions, and authoritative founder records.
* **Security Concealment:** Completely excludes `/mfa_factors` secrets, hashes, and recovery codes.

#### `POST /api/admin/id/users/:uid/suspend`
Suspends an account or restores an active account.
* **Request Body:** `{ "status": "suspended", "reason": "Suspected payment fraud" }`
* **Execution:** Calls `admin.auth().updateUser(uid, { disabled: true })`, revokes all tokens, and logs an immutable security event.

---

### 4.2 Authoritative Founder Programs Management
#### `POST /api/admin/id/users/:uid/founders`
Authoritatively assigns a product-specific Founder designation.
* **Request Body:**
  ```json
  {
    "programId": "pythos_founder",
    "product": "pythos",
    "founderNumber": 105,
    "title": "Pythos Founding Scholar",
    "grantReason": "Pioneer curriculum contributor"
  }
  ```
* **Execution:**
  1. Writes document to `/users/{uid}/founders/pythos_founder`.
  2. Atomically recalculates `derivedBadges` on `/users/{uid}`.
  3. Dispatches event to `/security_logs`.

#### `DELETE /api/admin/id/users/:uid/founders/:programId`
Authoritatively revokes a founder designation.
* **Request Body:** `{ "revocationReason": "User requested account decoupling" }`
* **Execution:** Soft-deletes founder record, recalculates `derivedBadges` on `/users/{uid}`, and logs the revocation audit entry.

---

### 4.3 Emergency MFA Reset (Dual-Control)
#### `POST /api/admin/id/users/:uid/mfa/reset-request`
Initiates an emergency MFA recovery request.
* **Request Body:** `{ "verificationNotes": "Caller verified via out-of-band video call and tax ID" }`
* **Execution:** Creates a pending approval record. Requires a second distinct administrator to execute `POST /api/admin/id/users/:uid/mfa/reset-approve` before factors are wiped.
