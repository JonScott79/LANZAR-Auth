# LANZAR ID — Comprehensive Security & Threat Model
**Document ID:** LID-SEC-003  
**Classification:** Confidential — Internal Master Security Directive  
**Status:** Authoritative Baseline (Phase 1 Approved)  
**Date:** November 8, 2026  
**Author:** Larry (Lead Systems Architect)  

---

## 1. Threat Landscape & Core Security Objectives

LANZAR ID protects user identities, access credentials, and ecosystem data across public web portals and backend services. The system is engineered to satisfy three primary security invariants:
1. **Zero Unenforced Boundaries:** Client-side assertions are never trusted. All authorization, token validity, and session status checks are enforced server-side on every protected request.
2. **Deterministic Session Revocation:** Compromised credentials or revoked sessions can be terminated instantly across all ecosystem properties, without waiting for 1-hour JWT token expiration.
3. **Defense-in-Depth for Multi-Factor Authentication:** Multi-factor authentication (MFA) must resist credential replay, phishing, and administrator bypass.

---

## 2. Session Revocation Architecture

Session termination in LANZAR ID operates across three distinct operational layers. Each layer serves a specific security purpose and must not be conflated.

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 THREE-TIER SESSION SECURITY ARCHITECTURE                              │
├───────────────────────────────┬───────────────────────────────┬────────────────────────────────────────┤
│ Layer 1: Global Revocation   │ Layer 2: Individual Sessions  │ Layer 3: Account Suspension            │
│ (Refresh-Token Invalidation)  │ (Per-Device Server Gate)      │ (Immediate Ecosystem Blackout)         │
├───────────────────────────────┼───────────────────────────────┼────────────────────────────────────────┤
│ • Password change             │ • User revokes single laptop  │ • Security incident / fraud            │
│ • "Sign Out Everywhere"       │ • Admin kills suspect device  │ • Terms of service violation           │
│ • Suspected account takeover  │ • Session idle expiration     │ • Administrative lock                  │
├───────────────────────────────┼───────────────────────────────┼────────────────────────────────────────┤
│ Mechanism:                    │ Mechanism:                    │ Mechanism:                             │
│ 1. admin.auth()               │ 1. Device doc in Firestore:   │ 1. admin.auth().updateUser(uid, {      │
│    .revokeRefreshTokens(uid)  │    /users/{uid}/sessions/{id} │      disabled: true })                 │
│ 2. Increments tokenVersion    │    marked revoked: true       │ 2. revokeRefreshTokens(uid)            │
│ 3. Server checks:             │ 2. Every protected API        │ 3. /users/{uid} status = 'suspended'   │
│    verifyIdToken(token, true) │    middleware checks:         │ 4. All API requests return 403         │
│    against validAfterTime     │    sessionCache.isRevoked()   │    ACCOUNT_SUSPENDED                   │
└───────────────────────────────┴───────────────────────────────┴────────────────────────────────────────┘
```

### 2.1 Layer 1: Global Refresh-Token Revocation
* **Trigger Events:** User changes password, user clicks "Sign Out of All Devices", or an administrator clicks "Force Global Revocation".
* **Backend Execution:**
  1. The API calls `admin.auth().revokeRefreshTokens(uid)`. This updates Google's internal `validAfterTime` timestamp for that account.
  2. The API atomically increments `tokenVersion` in Firestore `/users/{uid}`.
* **Server-Side Enforcement:**
  - Standard Firebase verification (`verifyIdToken(token)`) only inspects cryptographic signatures locally and ignores revocation.
  - **Mandatory Policy:** Every protected backend endpoint across LANZAR properties (`auth-backend`, `tickets`, `pythos`, `portal`) MUST invoke:
    ```javascript
    const decodedToken = await admin.auth().verifyIdToken(idToken, /* checkRevoked */ true);
    ```
  - When `checkRevoked` is true, the Firebase Admin SDK checks Google's revocation cache. If the token's `auth_time` precedes `validAfterTime`, it throws `auth/id-token-revoked`, immediately returning HTTP 401 Unauthorized.

### 2.2 Layer 2: Individual Device Session Revocation
* **Crucial Architectural Mandate:** Client-side polling or local storage clearing is NOT a security control. Individual session revocation must be enforced by the server on every request.
* **Session Lifecycle:**
  1. Upon successful PKCE exchange, `auth-backend` creates a session document: `/users/{uid}/sessions/{sessionId}` with `revoked: false`, client ID, IP, user-agent, and expiration.
  2. The `sessionId` is embedded as a custom claim (`session_id`) inside the issued token.
* **Server-Side Enforcement Middleware:**
  - Every backend API route executes the `sessionValidationMiddleware`:
    ```javascript
    async function sessionValidationMiddleware(req, res, next) {
      const sessionId = req.tokenClaims?.session_id;
      if (!sessionId) return res.status(401).json({ error: 'invalid_session_claims' });

      // Fast-path in-memory bloom filter / Redis-compatible LRU cache with 60-second TTL
      const isRevoked = await sessionRegistry.isSessionRevoked(req.uid, sessionId);
      if (isRevoked) {
        return res.status(401).json({ 
          error: 'session_revoked', 
          error_description: 'This specific device session has been revoked.' 
        });
      }
      next();
    }
    ```
  - When a user revokes an individual session on `id.lanzar.me`, the document is marked `revoked: true`. The backend session registry immediately invalidates the cache for that `sessionId`, killing access on the subsequent API call.

### 2.3 Layer 3: Immediate Account Suspension
* When an administrator suspends an account via Portal Mission Control:
  1. `admin.auth().updateUser(uid, { disabled: true })` disables the core Firebase Auth user.
  2. `admin.auth().revokeRefreshTokens(uid)` immediately invalidates all active tokens.
  3. The Firestore profile `/users/{uid}` is marked `status: 'suspended'`.
  4. Any active request or subsequent login attempt fails with HTTP 403 `account_suspended`.

---

## 3. Multi-Factor Authentication (MFA) Architecture

### 3.1 Custom LANZAR MFA vs. Native Firebase MFA & Amendment #001 (Universal TOTP)
* **Native Firebase MFA (Google Identity Platform):** Requires upgrading the GCP project to Google Cloud Identity Platform (GCIP). While native, GCIP incurs immediate monthly costs (\$0.0055 per active user above 50k MAUs) and charges per SMS verification.
* **LANZAR-Managed MFA (Selected & Expanded via Amendment #001):** Runs directly on `auth-backend` (Node.js). Implements FIDO2 / WebAuthn Passkeys and RFC 6238 TOTP with zero external licensing fees.
* **Universal TOTP Compatibility (Amendment #001):**
  - Full standards compliance with **Google Authenticator**, **Microsoft Authenticator**, **1Password**, and **Bitwarden**.
  - Standard `otpauth://totp/LANZAR%20ID:{email}?secret={secret}&issuer=LANZAR%20ID&algorithm=SHA1&digits=6&period=30` URI formatting.
  - QR-code rendering and manual base32 secret presentation.
  - 6-digit codes on standard 30-second intervals.
  - **Unconfirmed Secret TTL:** Staged enrollment secrets expire after 10 minutes and are discarded if unverified. Secrets are only committed to `/mfa_factors/{uid}` after successful code verification.
  - **Authenticator Replacement Guard:** Disabling or replacing an active authenticator requires active session step-up verification.
  - **Password Reset Immunity:** Changing or resetting passwords NEVER disables or clears enrolled TOTP authenticators.

### 3.2 Key Management, Encryption at Rest & Key Rotation
* **Secret Storage:** TOTP base32 secret keys are NEVER stored in plaintext. Secrets are encrypted using **AES-256-GCM** before writing to `/mfa_factors/{uid}`.
* **Server Pepper / Encryption Key:** The AES-256 encryption key is supplied via environment variable `MFA_ENCRYPTION_KEY` (32 cryptographically random bytes).
* **Key Rotation Protocol:** The encryption envelope stores a key version indicator (`kv: 1`). During key rotation:
  1. The new key is provisioned as `MFA_ENCRYPTION_KEY_V2`.
  2. A background migration job decrypts secrets using V1 and re-encrypts using V2.
  3. V1 is deprecated and destroyed once all records report `kv: 2`.

### 3.3 Replay Protection & Account Lockouts
* **TOTP Replay Protection:** `auth-backend` maintains a time-window sliding cache (`totpReplayCache`) of consumed 6-digit tokens per user. If a valid token is resubmitted within the 30-second validity window, it is rejected as a replay attack.
* **WebAuthn Replay Protection:** The WebAuthn authentication ceremony stores the authenticator's cryptographic signature `counter` in Firestore. If an incoming assertion presents a counter equal to or lower than the stored value, the authenticator has been cloned or replayed, and the request is rejected immediately.
* **Brute-Force Lockout:** 
  - Max 5 failed MFA verification attempts within 10 minutes triggers a temporary 15-minute account lockout on MFA verification.
  - Rate limiting is enforced in memory and backed by Firestore attempt counters.

---

## 4. Formal MFA Recovery Procedure

To prevent social engineering and support impersonation attacks, **MFA recovery cannot be bypassed through ordinary password recovery or unilateral administrator clicks.**

```
                                [ MFA LOCKOUT / RECOVERY REQUEST ]
                                                │
                     ┌──────────────────────────┴──────────────────────────┐
                     ▼                                                     ▼
         [ SELF-SERVICE RECOVERY ]                             [ ASSISTED RECOVERY ]
       User presents single-use                              User contacts LANZAR Support
       cryptographic Recovery Code                                         │
                     │                                                     ▼
                     ▼                                       1. Step-Up Identity Check:
       Hash matched against stored                              Verified phone call + out-of-band
       recoveryCodes in /mfa_factors                            photo ID check against records
                     │                                                     │
                     ▼                                                     ▼
       Single-use code burned;                               2. Dual-Admin Approval:
       Temporary 1-hour session granted                         Primary Admin initiates reset;
       to enroll new authenticator.                             Secondary Admin signs off.
                                                                           │
                                                                           ▼
                                                             3. Immutable Audit Record:
                                                                Full justification logged
                                                                to /security_logs.
```

### 4.1 Tier 1: Self-Service Recovery Codes
* During MFA enrollment, the user is issued 8 single-use recovery codes.
* Codes are generated via CSPRNG (`crypto.randomBytes(5).toString('hex')` -> 10 hex characters).
* `auth-backend` stores only the SHA-256 hash of each code.
* Presenting a valid code marks that specific code as `used: true`, logs a security event, and permits entry with a mandatory prompt to re-enroll a new MFA factor.

### 4.2 Tier 2: Administrative Exceptional Reset (Dual-Control)
* If a user loses all authenticators and recovery codes:
  1. **Step-Up Verification:** The user must complete an out-of-band identity verification check (video call / verified corporate email challenge).
  2. **Dual-Admin Authorization:** The primary administrator submits an `MFA_RESET_REQUEST` in Portal Mission Control with attached verification notes. A secondary administrator or system owner must review and approve the request.
  3. **Mandatory Cooldown:** Once approved, an automated security warning is dispatched to the user's verified email and phone. A mandatory 24-hour hold is applied before MFA factors are wiped, allowing the legitimate account owner to cancel the request if fraudulent.

---

## 6. Phone Authentication Infrastructure & Security Model (Amendment #002)

### 6.1 Provider Abstraction & Deferred Live Activation
* **Modular Provider Interface:** `smsService.js` implements a provider-independent interface (`SMSProvider`).
* **Deferred Live Provider:** All live SMS sending is **strictly disabled** behind `SMS_LIVE_ENABLED=false`. No live provider credentials exist in production configuration, incurring \$0.00 in SMS delivery costs.
* **Development & Staging Simulation (`MockSMSProvider`):** OTP codes are generated via CSPRNG and simulated. Plaintext codes are displayed strictly in local/staging environments and are **never exposed in production logs**.

### 6.2 Distinct Phone Authentication Capabilities
To prevent privilege confusion and maintain secure recovery boundaries, phone capabilities are kept distinct:
1. **Registration Verification:** Verifies phone ownership during account creation.
2. **Settings Phone Verification:** Adds or verifies phone number on existing profiles.
3. **Phone-Number Login:** Authenticates a user by verified phone number + OTP challenge without password.
4. **Phone-Based MFA:** Supplemental second factor (not preferred over Passkeys or TOTP).
5. **Phone Replacement & Re-verification:** Replaces registered phone only after step-up authentication.

### 6.3 Anti-Abuse & Toll-Fraud Defenses
* **Strict E.164 Normalization:** Handled via regular expression and prefix validation (`+1...`).
* **Geographic Destination Whitelisting:** Default destination restricted to North America (`+1` US & Canada). International premium-rate prefixes are rejected at the normalization layer.
* **Throttling & Velocity Checks:**
  - Max 1 OTP dispatch per 60 seconds per phone number.
  - Max 3 requests per IP per hour.
  - Max 5 verification attempts before invalidating and burning the pending OTP.
  - 5-minute cryptographic expiration TTL.

Application-level append-only logic is insufficient to guarantee audit integrity. In a compromised backend environment, rogue code could execute `update()` or `delete()` on audit records.

### 5.1 Defense-in-Depth for `/security_logs`
1. **Firestore Security Rules Tamper-Resistance:**
   ```javascript
   match /security_logs/{eventId} {
     allow read: if request.auth != null && request.auth.token.role == 'admin';
     allow create: if request.auth != null;
     // STRICT TAMPER-PROOFING: Updates and Deletions are permanently forbidden
     allow update, delete: if false;
   }
   ```
2. **Role Separation (GCP IAM):** The runtime service account used by client frontends has zero permissions to alter Firestore rules or truncate collections.
3. **Automated Cloud Audit Export:** Every 24 hours, a scheduled Cloud Function streams all security logs from Firestore to an immutable Google Cloud Storage bucket configured with **Object Retention Lock (WORM - Write Once, Read Many)**. Even a project owner cannot delete logs within the retention window (minimum 365 days).
4. **Log Content Sanitization:** Log entries record actor UID, IP, user-agent, action name, and target resource, but NEVER record passwords, plaintext tokens, TOTP secrets, or recovery codes.
