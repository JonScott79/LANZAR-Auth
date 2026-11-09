# LANZAR ID — Authentication & Authorization Sequence Flows
**Document ID:** LID-FLOW-005  
**Classification:** Confidential — Internal Master Architecture Directive  
**Status:** Authoritative Baseline (Phase 1 Approved)  
**Date:** November 8, 2026  
**Author:** Larry (Lead Systems Architect)  

---

## 1. Primary OAuth 2.0 / PKCE Flow with Custom Token Exchange

This sequence illustrates an unauthenticated user accessing an ecosystem client (e.g., `portal.lanzar.me`), authenticating at the central Hub (`auth.lanzar.me`), and establishing a secure local session.

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Browser
    participant Client as Client SPA (portal.lanzar.me)
    participant Hub as Auth Hub (auth.lanzar.me)
    participant AuthAPI as Auth Backend (auth-api.lanzar.me)
    participant Firebase as Firebase Auth (lanzar-95ae3)
    participant Firestore as Cloud Firestore

    User->>Client: Navigates to portal.lanzar.me
    Client->>Client: Detects no active session
    Client->>Client: Generates code_verifier & code_challenge (S256)
    Client->>Client: Saves state & code_verifier to sessionStorage
    Client->>Hub: Redirects to /authorize?client_id=portal&code_challenge=...&state=...

    Hub->>Hub: Checks existing Hub session
    alt User has no active Hub session
        Hub->>User: Renders LANZAR ID Login / Register Modal
        User->>Hub: Submits Credentials (or Google OAuth)
        Hub->>Firebase: Authenticates & acquires Firebase ID Token
    end

    opt User has MFA Enabled or is Admin
        Hub->>User: Prompts for Passkey / TOTP
        User->>Hub: Submits MFA verification
        Hub->>AuthAPI: Validates MFA challenge & receives mfa_proof
    end

    Hub->>AuthAPI: POST /authorize (idToken, client_id, code_challenge, mfa_proof)
    AuthAPI->>Firebase: verifyIdToken(idToken, checkRevoked=true)
    AuthAPI->>Firestore: Validates client_id & redirect_uri against registry
    AuthAPI->>AuthAPI: Generates 60-second single-use Authorization Code
    AuthAPI-->>Hub: Returns { code, state }

    Hub->>Client: Redirects to portal.lanzar.me/callback?code=...&state=...
    Client->>Client: Validates state matches sessionStorage.state
    Client->>AuthAPI: POST /exchange (code, client_id, code_verifier, redirect_uri)
    AuthAPI->>AuthAPI: Validates code unexpired, unused & PKCE hash matches
    AuthAPI->>Firestore: Creates Session Record (/users/{uid}/sessions/{sessionId})
    AuthAPI->>Firebase: admin.auth().createCustomToken(uid, { session_id, tenant_id })
    AuthAPI-->>Client: Returns { custom_token, session_id }

    Client->>Firebase: signInWithCustomToken(custom_token)
    Firebase-->>Client: Establishes local IndexedDB session
    Client->>Client: Cleans URL & loads authorized dashboard
```

---

## 2. Mandatory Email Verification Workflow

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Browser
    participant Client as Ecosystem App (Pythos / Portal)
    participant AuthHub as auth.lanzar.me
    participant Firebase as Firebase Auth
    participant Mail as Email Service (Firebase Pipe)

    User->>AuthHub: Registers new account (email + password)
    AuthHub->>Firebase: createUser({ email, password })
    Firebase->>Mail: Dispatches verification email with cryptographically signed action link
    AuthHub-->>User: "Verification email sent. Please check your inbox."

    User->>Client: Attempts to open protected services
    Client->>Client: Inspects user.emailVerified
    alt emailVerified === false
        Client->>User: Displays persistent warning banner: "Email unverified"
        Client->>Client: Restricts access to paid/sensitive features
    end

    User->>Mail: Opens email & clicks verification link
    Mail->>Firebase: Processes oobCode & updates account to emailVerified=true
    Firebase-->>User: Confirms verification success in browser

    User->>Client: Refreshes application
    Client->>Firebase: user.getIdToken(/* forceRefresh */ true)
    Firebase-->>Client: Returns ID Token with email_verified: true
    Client->>User: Banner disappears; full ecosystem access unlocked
```

---

## 3. FIDO2 / WebAuthn Passkey Ceremony

### 3.1 Passkey Registration (Enrollment)
```mermaid
sequenceDiagram
    autonumber
    actor User as User / Device Biometrics
    participant App as Account Hub (id.lanzar.me)
    participant AuthAPI as Auth Backend (auth-api.lanzar.me)
    participant Vault as Firestore /mfa_factors

    User->>App: Clicks "Register New Passkey"
    App->>AuthAPI: POST /passkeys/register-options (Bearer token)
    AuthAPI->>AuthAPI: Generates cryptographic challenge via @simplewebauthn
    AuthAPI-->>App: Returns PublicKeyCredentialCreationOptions
    App->>User: Prompts browser navigator.credentials.create()
    User->>App: Scans TouchID / FaceID / Security Key
    App->>AuthAPI: POST /passkeys/register-verify (attestationResponse)
    AuthAPI->>AuthAPI: Verifies challenge, origin, and public key
    AuthAPI->>Vault: Stores credentialId, COSE publicKey, and counter=0
    AuthAPI-->>App: Confirms passkey enrolled successfully
```

### 3.2 Passkey Authentication (Login)
```mermaid
sequenceDiagram
    autonumber
    actor User as User / Device Biometrics
    participant Hub as Auth Hub (auth.lanzar.me)
    participant AuthAPI as Auth Backend
    participant Vault as Firestore /mfa_factors

    User->>Hub: Selects "Sign in with Passkey"
    Hub->>AuthAPI: POST /passkeys/auth-options (email)
    AuthAPI->>Vault: Retrieves user's registered passkey credential IDs
    AuthAPI->>AuthAPI: Generates challenge
    AuthAPI-->>Hub: Returns PublicKeyCredentialRequestOptions
    Hub->>User: Invokes navigator.credentials.get()
    User->>Hub: Completes biometric verification
    Hub->>AuthAPI: POST /passkeys/auth-verify (assertionResponse)
    AuthAPI->>Vault: Retrieves stored COSE public key & signature counter
    AuthAPI->>AuthAPI: Verifies signature & verifies newCounter > storedCounter
    AuthAPI->>Vault: Updates storedCounter with newCounter (Replay Defense)
    AuthAPI-->>Hub: Returns signed mfa_proof JWT
    Hub->>Hub: Unlocks authentication session
```

---

## 5. Universal TOTP Authenticator Enrollment & Verification (Amendment #001)

This flow details the universal RFC 6238 enrollment ceremony compatible with **Microsoft Authenticator**, **Google Authenticator**, **1Password**, and compliant TOTP applications.

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Authenticator App
    participant Client as Account Hub (id.lanzar.me)
    participant AuthAPI as Auth Backend (auth-api.lanzar.me)
    participant Vault as Firestore /mfa_factors

    User->>Client: Clicks "Enable Authenticator (TOTP)"
    Client->>AuthAPI: POST /mfa/totp/setup (Bearer token)
    AuthAPI->>AuthAPI: Generates 20-byte Base32 Secret
    AuthAPI->>AuthAPI: Stages in pendingEnrollmentCache (10-min TTL)
    AuthAPI->>AuthAPI: Constructs standard otpauth:// URI
    AuthAPI-->>Client: Returns { secret, otpauthUrl }

    Client->>User: Displays QR Code & Manual Base32 Key
    User->>User: Scans QR code with Microsoft Authenticator / Google Authenticator
    User->>User: App generates time-synchronized 6-digit code
    User->>Client: Enters 6-digit code
    Client->>AuthAPI: POST /mfa/totp/enable (idToken, code)
    AuthAPI->>AuthAPI: Retrieves staged secret from pendingEnrollmentCache
    alt Secret expired (> 10 mins) or not found
        AuthAPI-->>Client: 400 Bad Request: setup_expired
    else Secret found
        AuthAPI->>AuthAPI: verifyTOTP(secret, code, uid)
        alt Code invalid
            AuthAPI-->>Client: 400 Bad Request: invalid_code
        else Code valid
            AuthAPI->>AuthAPI: Encrypts secret with AES-256-GCM
            AuthAPI->>AuthAPI: Generates 8 single-use recovery codes
            AuthAPI->>Vault: Commits { enabled: true, totpSecret, recoveryCodes }
            AuthAPI->>AuthAPI: Clears pendingEnrollmentCache
            AuthAPI-->>Client: Returns { success: true, recoveryCodes }
            Client->>User: Renders single-use recovery codes with print/copy prompt
        end
    end
```

---

## 7. Phone Authentication & Verification Sequence (Amendment #002)

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Mobile Phone
    participant Client as Account Hub / Client App
    participant AuthAPI as Auth Backend (smsService.js)
    participant Provider as SMS Provider (MockSMSProvider / Future Live)
    participant Firestore as Cloud Firestore (/phone_otps)

    User->>Client: Enters phone number (+15085551234)
    Client->>AuthAPI: POST /api/id/phone/send-otp (phoneNumber, Bearer token)
    AuthAPI->>AuthAPI: E.164 normalization & Geo-whitelisting (+1 check)
    AuthAPI->>AuthAPI: Velocity check (max 1/60s phone, max 3/hr IP)
    AuthAPI->>AuthAPI: Generates 6-digit CSPRNG OTP & SHA-256 codeHash
    AuthAPI->>Firestore: Writes /phone_otps/+15085551234 (codeHash, 5-min TTL)
    AuthAPI->>Provider: sendOTP({ phoneNumber, code, purpose })
    Note over Provider: MockSMSProvider simulates delivery (Zero SMS charges)
    AuthAPI-->>Client: Returns { success: true, expiresInSeconds: 300 }

    User->>Client: Enters 6-digit verification code
    Client->>AuthAPI: POST /api/id/phone/verify (phoneNumber, code)
    AuthAPI->>Firestore: Reads /phone_otps/+15085551234
    AuthAPI->>AuthAPI: Hashes submitted code & compares with codeHash
    alt Code matches & unexpired
        AuthAPI->>Firestore: Burns OTP record (delete)
        AuthAPI->>Firestore: Updates /users/{uid}: { phoneNumber, phoneVerified: true }
        AuthAPI-->>Client: Returns { success: true, phoneVerified: true }
    else Code invalid (attempts < 5)
        AuthAPI->>Firestore: Increments attempts count
        AuthAPI-->>Client: 400 Bad Request: Verification code incorrect
    else Attempts >= 5
        AuthAPI->>Firestore: Burns OTP record
        AuthAPI-->>Client: 400 Bad Request: Too many attempts. Request new code.
    end
```

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Attacker
    participant ClientA as Device A (MacBook)
    participant ClientB as Device B (Compromised Tablet)
    participant IdHub as id.lanzar.me
    participant AuthAPI as Auth Backend
    participant Firestore as Cloud Firestore
    participant Firebase as Firebase Auth

    Note over User,ClientA: User notices unknown tablet in active sessions list
    User->>IdHub: Clicks "Revoke" on Device B (sessionId: sess_tablet_02)
    IdHub->>AuthAPI: DELETE /api/id/sessions/sess_tablet_02 (Bearer token)
    AuthAPI->>Firestore: Updates /users/{uid}/sessions/sess_tablet_02 -> revoked: true
    AuthAPI->>AuthAPI: Invalidates in-memory session cache
    AuthAPI-->>IdHub: Returns 200 OK (Session revoked)

    Note over ClientB: Attacker on Device B attempts protected API request
    ClientB->>AuthAPI: GET /api/data (Authorization: Bearer <existing_id_token>)
    AuthAPI->>AuthAPI: Extracts tokenClaims.session_id ("sess_tablet_02")
    AuthAPI->>AuthAPI: sessionRegistry.isSessionRevoked("sess_tablet_02")
    AuthAPI-->>ClientB: 401 Unauthorized: { error: "session_revoked" }
    ClientB->>ClientB: Clears local storage & redirects to auth.lanzar.me
```
