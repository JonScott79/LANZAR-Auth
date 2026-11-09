# LANZAR ID — Phase E: End-to-End Integration Audit Report

**Document ID:** LID-AUDIT-PHASE-E-001  
**Classification:** Authoritative Security, Contract & Integration Audit  
**Target Architecture:** Single Central Auth Hub (`auth.lanzar.me`), Ecosystem Services (`portal.lanzar.me`, `tickets.lanzar.me`, `threadline.lanzar.me`, `ai.lanzar.me`)  
**Audit Date:** 2026-11-09  
**Branch:** `lanzar_id_main_chat`  

---

## 1. Executive Summary

Phase E conducted a comprehensive, holistic integration audit of the LANZAR ID platform across the backend (`auth-backend`), frontend Auth Hub (`auth.lanzar.me`), and client integration SDK (`<lanzar-auth-modal>` / `LanzarAuth`).

The audit verified that the core security architecture—specifically RFC 7636 S256 PKCE generation and exchange, atomic authorization-code single-use consumption, AES-256-GCM encrypted TOTP factors, single-use recovery codes, fine-grained device session revocation, and fail-closed environment isolation—functions with high integrity.

A total of **8 automated test batteries** were executed, verifying **274 formal assertions + 15 lifecycle checks = 289 verification points with a 100.0% pass rate**.

This report details:
1. A rigorous **PKCE Security Review** tracing the code verifier lifecycle and `postMessage` handshake.
2. An **OAuth Client Registry Reconciliation** comparing approved domains against configured clients.
3. An **End-to-End Functional Validation** covering all 12 platform workflows.
4. A **Frontend & Backend Contract Review** identifying the schema divergence between `firestore.rules` and `profileService.js`.
5. A **Staging Readiness Review** verifying prerequisites for project `lanzar-95ae3-dev`.
6. A ranked list of **Security Findings** and **Unresolved Architectural Decisions** requiring approval.

---

## 2. PKCE Security Review (Highest Priority)

### 2.1 Code Verifier Isolation & Lifecycle Trace

RFC 7636 mandates that the cryptographically random `code_verifier` MUST originate on and remain with the initiating client application, never being exposed to intermediary authentication hubs, popups, or external servers prior to code exchange.

The data flow was traced through the codebase:

```mermaid
sequenceDiagram
    autonumber
    participant Client as Client Application (portal.lanzar.me)
    participant SDK as <lanzar-auth-modal> (Client Memory)
    participant Hub as Auth Hub (auth.lanzar.me)
    participant API as Auth API (auth-api.lanzar.me)

    Note over Client,SDK: Step 1: PKCE Pair Generation
    Client->>SDK: openWithPkce({ clientId: 'portal', redirectUri })
    SDK->>SDK: generatePkcePair(64)<br/>[stores codeVerifier in this._codeVerifier]
    SDK->>Hub: Loads iframe / popup URL<br/>?client_id=portal&code_challenge=SHA256&code_challenge_method=S256<br/>[code_verifier is NOT in URL]

    Note over Hub,API: Step 2: User Authentication & Code Issuance
    Hub->>Hub: User signs in (Firebase Auth ID Token)
    Hub->>API: POST /authorize<br/>{ idToken, client_id, redirect_uri, code_challenge, code_challenge_method: 'S256' }<br/>[code_verifier is NOT sent]
    API->>API: Validates client & S256 method<br/>Stores codeChallenge in AuthorizationCodeStore
    API-->>Hub: HTTP 200 { code: 'auth_code_xyz', state }

    Note over Hub,SDK: Step 3: Authorization Code Delivery
    Hub-->>SDK: window.location.replace(redirectUri?code=auth_code_xyz)<br/>[or targeted postMessage]

    Note over SDK,Client: Step 4: Local Verifier Binding
    SDK->>Client: Emits 'lanzar:authenticated'<br/>detail: { code: 'auth_code_xyz', codeVerifier: this._codeVerifier }

    Note over Client,API: Step 5: Direct Token Exchange
    Client->>API: POST /exchange<br/>{ code: 'auth_code_xyz', client_id, redirect_uri, code_verifier }
    API->>API: SHA256(code_verifier) === stored challenge<br/>Atomic CAS code invalidation<br/>Mints Custom Token with session_id
    API-->>Client: HTTP 200 { custom_token, session_id, expires_in }
```

### 2.2 Relevant Code References
1. **Client Verifier Generation & Memory Binding:**  
   [`auth/src/sdk/lanzar-auth-modal.js` #L384-L417](file:///C:/Users/jonny/.gemini/antigravity/worktrees/lanzar/lanzar_id_main_chat/auth/src/sdk/lanzar-auth-modal.js#L384-L417)
   - `const pkce = await generatePkcePair();` (64 bytes, RFC 7636 unreserved charset `[A-Za-z0-9\-._~]`).
   - `this._codeVerifier = pkce.codeVerifier;` — Stored strictly in the component instance memory on the client origin.
2. **Authorize URL Construction:**  
   [`auth/src/sdk/lanzar-auth-modal.js` #L154-L185](file:///C:/Users/jonny/.gemini/antigravity/worktrees/lanzar/lanzar_id_main_chat/auth/src/sdk/lanzar-auth-modal.js#L154-L185)
   - Only `code_challenge` and `code_challenge_method=S256` are appended to the URL query string.
   - `code_verifier` is **never** added to the authorize URL.
3. **Auth Hub Forwarding:**  
   [`auth/src/App.jsx` #L68-L79](file:///C:/Users/jonny/.gemini/antigravity/worktrees/lanzar/lanzar_id_main_chat/auth/src/App.jsx#L68-L79)
   - Auth Hub reads `code_challenge` and `code_challenge_method` from query parameters and posts them to `POST /authorize`.
   - The Auth Hub does not possess, generate, or forward `code_verifier`.
4. **Backend Challenge Persistence & Strict S256 Enforcement:**  
   [`auth/auth-backend/routes/oauthRoutes.js` #L19-L32, #L101-L108](file:///C:/Users/jonny/.gemini/antigravity/worktrees/lanzar/lanzar_id_main_chat/auth/auth-backend/routes/oauthRoutes.js#L19-L32)
   - Rejects requests missing `code_challenge_method` or specifying any method other than `S256` (HTTP 400 `invalid_request`).
   - Persists `codeChallengeMethod: 'S256'` in `codeStore`.
5. **Exchange Verification:**  
   [`auth/auth-backend/routes/oauthRoutes.js` #L143-L153](file:///C:/Users/jonny/.gemini/antigravity/worktrees/lanzar/lanzar_id_main_chat/auth/auth-backend/routes/oauthRoutes.js#L143-L153)
   - Verifies `crypto.createHash('sha256').update(code_verifier).digest('base64url') === record.codeChallenge`.
   - Rejects mismatched verifiers with HTTP 400 `invalid_grant`.
   - Atomically marks code used (single-use CAS semantics).

### 2.3 Finding: Modal/Popup Handshake Disconnect
- **Current State:** In `auth/src/App.jsx` lines 103–108, upon successful authorization code receipt, the Auth Hub executes:
  ```javascript
  const targetUrl = new URL(redirectUri)
  targetUrl.searchParams.set('code', data.code)
  if (data.state) targetUrl.searchParams.set('state', data.state)
  window.location.replace(targetUrl.toString())
  ```
  However, `<lanzar-auth-modal>` (`auth/src/sdk/lanzar-auth-modal.js` lines 439–467) implements an `_onMessage` listener expecting a `postMessage` event:
  ```javascript
  if (event.origin !== this._config.authHubUrl) return;
  if (data.type === 'lanzar:authenticated') { ... }
  ```
- **Architectural Impact:** When loaded inside an iframe modal or popup window, navigating the inner window via `window.location.replace` redirects the iframe rather than dispatching a message to `window.parent` / `window.opener`.
- **Proposed Minimal Safe Correction:**
  In `auth/src/App.jsx`, detect whether the application is running in an embedded context (`window.parent !== window`) or a popup window (`window.opener && !window.opener.closed`).
  If embedded/popup:
  1. Extract `targetOrigin = new URL(redirectUri).origin`.
  2. Verify `targetOrigin` matches the authorized client application domain (exact match).
  3. Dispatch `targetWindow.postMessage({ type: 'lanzar:authenticated', payload: { code: data.code, state: data.state } }, targetOrigin)`.
  4. If in top-level redirect mode, maintain existing `window.location.replace(targetUrl.toString())`.
  *(Note: Code change held pending review per phase boundaries).*

---

## 3. OAuth Client Registry & Domain Reconciliation

### 3.1 Approved Architecture vs. Configured Clients

| Domain | Role | Status in Architecture | Status in `clients.js` | Action Required |
| :--- | :--- | :--- | :--- | :--- |
| `auth.lanzar.me` | Central Identity Hub & IdP | **Approved** | Not a client (Server/Hub) | None (Authoritative) |
| `portal.lanzar.me` | Customer Portal & Mission Control | **Approved** | Registered (`portal`) | Retain |
| `tickets.lanzar.me` | Ticketing & Support Queue | **Approved** | Registered (`tickets`) | Retain |
| `threadline.lanzar.me` | Threadline Intelligence | **Approved** | Registered (`threadline`) | Retain |
| `ai.lanzar.me` | AI Platform | **Approved** | Registered (`ai`) | Retain |
| `pythos.lanzar.me` | Pythos Socratic Tutor | **Not Approved** as OAuth Client | Registered (`pythos`) | **Decision Required** (See §7.1) |
| `lanzar.me` | Marketing Site / Mothership | **Not Approved** as OAuth Client | Registered (`mothership`) | **Decision Required** (See §7.2) |
| `id.lanzar.me` | Legacy Central Account Hub | **Excised / Deprecated** | Registered (`id`) | **Candidate for Removal** |

### 3.2 Origin Validation Analysis (`originValidator.js`)
- **Validation Mechanism:** Backend origin validation in `auth/auth-backend/middleware/originValidator.js` executes an exact dictionary lookup:
  ```javascript
  const clientAppId = originMap[origin];
  if (!clientAppId) {
    return res.status(403).json({ error: ..., code: 'ORIGIN_NOT_ALLOWED' });
  }
  ```
- **Finding:** **Zero wildcard, substring, or regex-based origin trust exists on the backend.** Every allowed origin must be declared in `ENV_CONFIGS[appEnv].originMap`.
- **Redirect URI Validation:** In `auth/auth-backend/routes/oauthRoutes.js` lines 39–46, incoming `redirect_uri` is strictly checked against the client's registered array:
  `normalizedRedirect === clean || normalizedRedirect.startsWith(clean + '/')`.

---

## 4. End-to-End Functional Validation

To validate the platform as a coherent, working system, a new automated test battery [`auth/test-e2e-integration.cjs`](file:///C:/Users/jonny/.gemini/antigravity/worktrees/lanzar/lanzar_id_main_chat/auth/test-e2e-integration.cjs) was authored and executed.

### 4.1 E2E Integration Test Results (20/20 Passed)

| Test ID | Workflow Step / Verification Point | Execution Type | Result |
| :--- | :--- | :--- | :--- |
| **E2E-01** | Client SDK generates cryptographic PKCE pair with S256 challenge | Automated | **PASS** |
| **E2E-02** | Authorize URL encapsulates S256 challenge; verifier remains isolated on client | Automated | **PASS** |
| **E2E-03** | Auth Hub issues authorization code for valid S256 PKCE request (`POST /authorize`) | Automated | **PASS** |
| **E2E-04** | Token exchange verifies `code_verifier` and mints custom token with `session_id` | Automated | **PASS** |
| **E2E-05** | Replay of consumed authorization code is rejected with HTTP 400 `invalid_grant` | Automated | **PASS** |
| **E2E-06** | `POST /mfa/totp/setup` generates RFC 6238 Base32 secret (20 bytes / 32 chars) | Automated | **PASS** |
| **E2E-07** | `POST /mfa/totp/enable` activates factor and returns 8 single-use recovery codes | Automated | **PASS** |
| **E2E-08** | TOTP secret is stored encrypted under AES-256-GCM in Firestore (`encryptedSecret`) | Automated | **PASS** |
| **E2E-09** | Enrolled MFA user receives HTTP 403 `mfa_required` and signed challenge session | Automated | **PASS** |
| **E2E-10** | First recovery code validates successfully and mints signed `mfaProof` (10m TTL) | Automated | **PASS** |
| **E2E-11** | Replay of consumed recovery code is rejected with HTTP 401 `invalid_code` | Automated | **PASS** |
| **E2E-12** | `GET /api/id/sessions` returns active device session records | Automated | **PASS** |
| **E2E-13** | `DELETE /api/id/sessions/:id` successfully marks Device 1 session revoked | Automated | **PASS** |
| **E2E-14** | Device 1 session is revoked while Device 2 remains independently active | Automated | **PASS** |
| **E2E-15** | `POST /api/id/sessions/revoke-all` globally invalidates all user sessions | Automated | **PASS** |
| **E2E-16** | Global revocation advances user `tokenVersion` in Firestore | Automated | **PASS** |
| **E2E-17** | `GET /api/id/profile` returns profile data with MFA factor flags | Automated | **PASS** |
| **E2E-18** | `PUT /api/id/profile` updates allowlisted fields and strips privilege escalation (`role: admin`) | Automated | **PASS** |
| **E2E-19** | `postMessage` from unapproved origin (`evil-hacker.com`) is strictly discarded | Automated | **PASS** |
| **E2E-20** | Legitimate Auth Hub `postMessage` dispatches authenticated event with local `codeVerifier` | Automated | **PASS** |

### 4.2 Status Categorization Across Platform Functionality

- **Fully Implemented & Automated-Tested:**
  - RFC 7636 PKCE pair generation and S256 challenge creation.
  - Server-side authorization code creation, CAS single-use consumption, and replay prevention.
  - Custom token minting with embedded `session_id` and tenant claims.
  - RFC 6238 TOTP enrollment, Base32 key generation, and AES-256-GCM encryption at rest.
  - Single-use recovery code hashing, validation, and replay rejection.
  - Device session tracking, individual session revocation, and global kill switch (`revoke-all`).
  - Strict profile updates via API with anti-tampering privilege escalation protection.
  - Fail-closed environment bootstrap, service account pinning, and IPv4/IPv6 loopback parsing.
  - Level 3 Firestore security rules on port 8080 (53 test assertions).
- **Implemented & Verified in Browser / Build:**
  - Frontend React bundle compilation (`vite build` in 689ms).
  - Centralized environment configuration resolution (`auth/src/config/env.js`).
  - Visual layout for Login, Registration, MFA Enrollment, and Session Portal.
- **Unverified / Live External Dependencies (Intentionally Deferred per Instructions):**
  - Live SMS dispatch via Twilio (mock provider verified offline).
  - Live Stripe payment webhook callbacks (test key validation verified offline).
  - Physical FIDO2 / WebAuthn hardware token attestation (schema placeholder tested).

---

## 5. Frontend & Backend Contract Review

### 5.1 Profile Schema Reconciliation (`firestore.rules` vs. `profileService.js`)

A key finding during the audit is a divergence between the fields accepted by the backend API and the fields allowlisted in Firestore Security Rules:

| Field Name | `firestore.rules` (Client Direct) | `profileService.js` (Server API) | `MyLanzarAccount.jsx` (Frontend) | Authoritative Disposition |
| :--- | :--- | :--- | :--- | :--- |
| `displayName` | **Allowed** (string, 1–100 chars) | **Allowed** (trimmed, max 100) | Form Input (`displayName`) | **Consistent** across all tiers |
| `avatarUrl` | **Allowed** (HTTPS URL, max 2048) | **Allowed** (HTTPS URL, max 500) | Form Input (`avatarUrl`) | **Consistent** (Length difference noted) |
| `bio` | ❌ **DENIED** (Not in `allowedKeys`) | **Allowed** (string, max 280) | Form Input (`bio`) | ⚠️ **Divergence:** API allows; Direct Rules deny |
| `notificationPreferences` | **Allowed** (Map: newsletter, etc.) | ❌ **Dropped** (Not processed) | Not currently editable | ⚠️ **Divergence:** Rules allow; API drops |
| `role`, `status`, `derivedBadges` | ❌ **DENIED** (Strictly immutable) | ❌ **Stripped** (Anti-tampering) | Read-only badges display | **Consistent** (Immutable security fields) |

#### Analysis:
- In the LANZAR ID architecture, web clients update user profile information exclusively through `PUT /api/id/profile` (which invokes `profileService.js` via the Firebase Admin SDK). Admin SDK writes bypass Firestore client rules.
- Consequently, `bio` updates through the API succeed. However, if a client attempted a direct Firestore SDK call (`db.collection('users').doc(uid).update({ bio })`), `firestore.rules` would reject it.
- **Authoritative Schema Recommendation:** 
  1. Add `'bio'` to `allowedKeys` in `firestore.rules` line 8 with a string constraint `<= 280 chars` to align direct Firestore security rules with the API specification.
  2. Update `profileService.js` to accept and persist `notificationPreferences` when provided by the client.

### 5.2 Environment Resolution Safety
- `auth/src/config/env.js` was inspected. It resolves endpoints using the following hierarchy:
  1. `VITE_AUTH_API_URL` override if explicitly provided.
  2. `localhost` / `127.0.0.1` -> `http://localhost:4001` (Dev API) / `http://localhost:4000` (Dev Hub).
  3. Hostnames containing `-dev` or `staging` -> `https://auth-api-dev.lanzar.me` (Staging API) / `https://auth-dev.lanzar.me` (Staging Hub).
  4. Production hostnames -> `https://auth-api.lanzar.me` (Prod API) / `https://auth.lanzar.me` (Prod Hub).
- **Verification:** When running in staging (`auth-dev.lanzar.me`), the frontend **cannot** silently resolve to production endpoints.

---

## 6. Staging Readiness Review

### 6.1 Review of Staging Project `lanzar-95ae3-dev`
- **GCP/Firebase Provisioning Status:** Network probing of `lanzar-95ae3-dev.firebaseapp.com` returned standard Google Frontend HTTP 404. Neither GCP CLI tools (`gcloud`) nor Firebase CLI tools are installed on the local host environment.
- **Service Account Status:** The repository contains no service account credentials for `lanzar-95ae3-dev`. Mock credentials are used in test suites.
- **Risk Identified (Development Environment Configuration):**
  The file `auth/.env` currently contains:
  ```
  VITE_FIREBASE_PROJECT_ID=lanzar-95ae3
  VITE_FIREBASE_AUTH_DOMAIN=lanzar-95ae3.firebaseapp.com
  ```
  This points local development to the **production** Firebase project ID (`lanzar-95ae3`). While the backend has fail-closed guards preventing startup with mismatched credentials, running `npm run dev` in `auth/` causes the frontend Firebase client to initialize with production project attributes.

### 6.2 Staging Prerequisites Checklist (Before Live Deployment)
1. **GCP Project Provisioning:** Confirm `lanzar-95ae3-dev` is created in Google Cloud Console with Firebase Auth and Cloud Firestore enabled.
2. **Service Account Creation:** Create `lanzar-auth-api@lanzar-95ae3-dev.iam.gserviceaccount.com` with `roles/firebase.admin` and `roles/datastore.user`.
3. **Secret Manager Setup:** Store `FIREBASE_SERVICE_ACCOUNT_KEY` and `SESSION_SIGNING_SECRET` in Secret Manager in project `lanzar-95ae3-dev`.
4. **Environment File Separation:** Create `auth/.env.staging` containing staging Firebase web app configuration (`VITE_FIREBASE_PROJECT_ID=lanzar-95ae3-dev`), and replace `auth/.env` with local emulator configuration (`VITE_FIREBASE_PROJECT_ID=demo-lanzar-dev`).
5. **DNS & Certificate Routing:** Provision DNS records and TLS certificates for `auth-api-dev.lanzar.me`, `auth-dev.lanzar.me`, and `portal-dev.lanzar.me`.

---

## 7. Unresolved Architectural Decisions Requiring Jon's Approval

### 7.1 Disposition of `pythos.lanzar.me`
- **Context:** `clients.js` currently defines a client entry for `pythos`, and `founderService.js` awards `pythos_founder` badges. In addition, the Phase 1 Acceptance test suite (`test-phase1-acceptance.cjs`) uses `pythos` as its primary test client.
- **Decision Needed:** Should `pythos` be formally approved as an official OAuth client in the LANZAR ecosystem, or should it be removed from `clients.js` and replaced with `portal` across all legacy test fixtures?

### 7.2 Disposition of `lanzar.me` (`mothership`)
- **Context:** `clients.js` includes `mothership` (`https://lanzar.me`).
- **Decision Needed:** Should `lanzar.me` (the marketing site / mothership) be an authorized OAuth client, or does all authentication terminate at `portal.lanzar.me`?

### 7.3 Deprecation of Legacy `id` Client Entry in `clients.js`
- **Context:** `clients.js` still contains lines 22–34 declaring `id: 'LANZAR ID Central Account Hub'` for `https://id.lanzar.me`.
- **Decision Needed:** Confirm formal removal of this entry from `clients.js` now that `auth.lanzar.me` has been confirmed as the sole Identity Hub.

### 7.4 Profile Schema Harmonization
- **Context:** `firestore.rules` allows direct client updates to `displayName`, `avatarUrl`, and `notificationPreferences`. `profileService.js` accepts `displayName`, `avatarUrl`, and `bio`.
- **Decision Needed:** Approve adding `bio` (max 280 chars) to `firestore.rules` and adding `notificationPreferences` support to `profileService.js`.

---

## 8. Complete Verification Summary

A total of **8 test batteries** were executed in sequence:

```
===========================================================================================
LANZAR ID — FULL QUALITY GATE & INTEGRATION TEST AUDIT SUMMARY
===========================================================================================
Suite 1: Phase 1 Acceptance (test-phase1-acceptance.cjs)          55 / 55 Passed  (100.0%)
Suite 2: Phase 2 Core Services (test-phase2-core.cjs)             32 / 32 Passed  (100.0%)
Suite 3: Auth & MFA Lifecycle (test-auth-and-mfa.cjs)             15 / 15 Passed  (100.0%)
Suite 4: Phase 6 Security Penetration (test-phase6-security-pen)  89 / 89 Passed  (100.0%)
Suite 5: Level 3 Firestore Security Rules (test-level3-firestore) 53 / 53 Passed  (100.0%)
Suite 6: Client SDK Contract Suite (test-sdk-contract.cjs)        18 / 18 Passed  (100.0%)
Suite 7: Staging Bootstrap Safeguards (test-staging-bootstrap)     7 /  7 Passed  (100.0%)
Suite 8: End-to-End Integration Suite (test-e2e-integration.cjs)  20 / 20 Passed  (100.0%)
-------------------------------------------------------------------------------------------
Frontend Build: npm --prefix auth run build                       Compiled in 689ms
===========================================================================================
TOTAL VERIFICATION POINTS: 289 / 289 PASSED (100.0%)
ZERO FAILURES. ZERO PRODUCTION CREDENTIAL LEAKAGE.
===========================================================================================
```
