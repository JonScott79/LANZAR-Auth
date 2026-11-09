# LANZAR ID — Quality Gates, Test Plan & Security Verification
**Document ID:** LID-TEST-008  
**Classification:** Confidential — Internal Master Verification Plan  
**Status:** Authoritative Baseline (Phase 1 Approved)  
**Date:** November 8, 2026  
**Author:** Larry (Lead Systems Architect)  

---

## 1. Quality-Gated Release Philosophy

Rather than rushing to meet an arbitrary calendar deadline, every phase of the LANZAR ID rollout is governed by **strict, objective Quality Gates**. 

A phase is not considered complete until 100% of its verification criteria and automated security tests pass without exception.

---

## 2. Phase-by-Phase Quality Gates & Exit Criteria

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               PHASE QUALITY GATES MATRIX                               │
├─────────┬───────────────────────────────┬──────────────────────────────────────────────┤
│ Phase   │ Focus Area                    │ Mandatory Gate Passing Criteria              │
├─────────┼───────────────────────────────┼──────────────────────────────────────────────┤
│ Gate 1  │ Core Identity API             │ All PKCE, token exchange & session API tests  │
│         │ (Phase 2 Backend)             │ pass. 100% test coverage on revocation logic.│
├─────────┼───────────────────────────────┼──────────────────────────────────────────────┤
│ Gate 2  │ User Management Frontends     │ id.lanzar.me & "My LANZAR" pass cross-browser│
│         │ (Phase 3 UI)                  │ session sync & WebAuthn ceremony tests.      │
├─────────┼───────────────────────────────┼──────────────────────────────────────────────┤
│ Gate 3  │ Portal Mission Control        │ Administrative shell passes audit logging,   │
│         │ (Phase 4 Admin)               │ RBAC permission, and dual-admin MFA gates.   │
├─────────┼───────────────────────────────┼──────────────────────────────────────────────┤
│ Gate 4  │ Ecosystem Migrations          │ Pre-migration checksums match destination;   │
│         │ (Phase 5 Cut-over)            │ zero orphaned records; rollback verified.    │
├─────────┼───────────────────────────────┼──────────────────────────────────────────────┤
│ Gate 5  │ Production Security Audit     │ 10 Penetration Test Scenarios pass cleanly.  │
│         │ (Phase 6 Final Verification)  │ System owner formal sign-off.                │
└─────────┴───────────────────────────────┴──────────────────────────────────────────────┘
```

---

## 3. Ten Mandatory Security Penetration Tests

The following automated and manual security test scenarios must be executed and signed off prior to production deployment:

### Test Scenario 01: PKCE Tamper Resistance & Code Interception
* **Objective:** Ensure an intercepted authorization code cannot be exchanged without the original `code_verifier`.
* **Method:** Initiate `/authorize` with valid `code_challenge`. Intercept issued `code`. Attempt `/exchange` using an incorrect, empty, or altered `code_verifier`.
* **Pass Assertion:** Backend must return HTTP 400 `invalid_grant` with error description indicating PKCE verification failure. No token is minted.

### Test Scenario 02: Authorization Code Replay & Expiration
* **Objective:** Verify authorization codes are strictly single-use and expire within 60 seconds.
* **Method:**
  1. Complete a successful code exchange. Re-submit the identical code and `code_verifier`.
  2. Generate a valid code, wait 65 seconds, and attempt exchange.
* **Pass Assertion:** Both attempts return HTTP 400 `invalid_grant`. Code is flagged as consumed or expired.

### Test Scenario 03: Server-Enforced Individual Session Revocation
* **Objective:** Confirm that individual session revocation is enforced immediately on the server, regardless of client storage state.
* **Method:** Log in on Device A and Device B. Revoke Device B's session via `DELETE /api/id/sessions/{sessionId}`. Send a protected API request from Device B presenting Device B's unexpired ID token.
* **Pass Assertion:** API returns HTTP 401 `session_revoked`. Request is denied.

### Test Scenario 04: Account-Wide Revocation & Password Reset Invalidation
* **Objective:** Verify changing a password or triggering "Sign Out Everywhere" immediately invalidates all issued tokens across the ecosystem.
* **Method:** Issue tokens on 3 distinct applications. Trigger password reset. Immediately submit existing tokens to `tickets`, `pythos`, and `portal` APIs.
* **Pass Assertion:** All APIs invoking `verifyIdToken(token, true)` reject the request with `auth/id-token-revoked` (HTTP 401).

### Test Scenario 05: Unverified Email Application Gating
* **Objective:** Confirm unverified users cannot access sensitive or paid services.
* **Method:** Create an unverified account (`emailVerified: false`). Attempt to access protected dashboard routes in Portal and tutoring sessions in Pythos.
* **Pass Assertion:** Application renders unverified warning banner. Sensitive API endpoints reject requests with HTTP 403 `email_verification_required`.

### Test Scenario 06: MFA Bypass Resistance & Universal TOTP Verification (Amendment #001)
* **Objective:** Confirm authentication cannot proceed without valid MFA proofs, verify universal compatibility with Microsoft and Google Authenticator, and ensure unconfirmed secrets expire.
* **Method:**
  1. **Compatibility Battery:** Generate secret via `/mfa/totp/setup`. Compute RFC 6238 vectors matching:
     - Microsoft Authenticator standard algorithms (SHA1, 30s, 6 digits).
     - Google Authenticator standard algorithms (SHA1, 30s, 6 digits).
     - 1Password / Bitwarden standard TOTP.
  2. **Unconfirmed Secret Expiration:** Stage secret via `/mfa/totp/setup`. Wait 11 minutes (or simulate 10m+ TTL expiration). Attempt `/mfa/totp/enable`. Assert HTTP 400 `setup_expired`.
  3. **AES-256-GCM Storage Inspection:** Inspect `/mfa_factors/{uid}` in Firestore. Verify `totpSecret` contains `encryptedSecret`, `iv`, `tag`, and `kv`, and NO plaintext Base32 secret string exists.
  4. **TOTP Replay Defense:** Submit a valid code; immediately re-submit the identical code within the same 30-second step. Assert HTTP 401 `invalid_code` (replay blocked).
* **Pass Assertion:** All 4 tests pass with 100% compliance.

### Test Scenario 07: Phone Verification & Provider Abstraction (Amendment #002)
* **Objective:** Verify E.164 normalization, country whitelisting, rate limiting, attempt lockouts, and mock provider safety.
* **Method:**
  1. **E.164 Normalization & Geo-Whitelisting:** Submit `508-555-1234` (normalized to `+15085551234`). Submit international premium prefix `+881...` (assert rejected with `Country code not permitted`).
  2. **Rate Limiting:** Send OTP to `+15085551234`. Immediately submit a second request within 10 seconds. Assert error: `Please wait ... seconds before requesting another code`.
  3. **Attempt Lockout:** Send OTP. Submit 5 incorrect codes consecutively. Assert code is purged from Firestore and error returned: `Too many failed verification attempts`.
  4. **Production Log Sanitization:** Execute OTP generation in simulated production mode (`NODE_ENV=production`). Assert server log masks the code (`+1508***34`) and contains zero plaintext OTP digits.
  5. **Mock Delivery Verification:** Verify `MockSMSProvider` returns delivery metadata with zero external network dispatch.
* **Pass Assertion:** All 5 test cases pass without exception.

### Test Scenario 08: Derived Profile Invariant & Anti-Tampering
* **Objective:** Verify that client or admin PUT requests cannot artificially award Founder badges.
* **Method:** Submit `PUT /api/id/profile` with payload `{ "derivedBadges": ["lanzar_id_founder", "pythos_founder"] }`.
* **Pass Assertion:** Server discards the field; profile document retains original derived array. Badges can only be granted by creating authoritative documents in `/users/{uid}/founders/`.

### Test Scenario 09: Audit Log Tamper-Resistance (Firestore Rules)
* **Objective:** Ensure no user or administrative credential can overwrite or delete security audit records.
* **Method:** Authenticate as an administrator. Execute `db.collection('security_logs').doc(id).delete()` and `update()`.
* **Pass Assertion:** Firestore Security Rules reject the operation with `PERMISSION_DENIED`.

### Test Scenario 10: Multi-Tenant Cross-Contamination Defense
* **Objective:** Verify that organization admins in Tenant A cannot query, view, or modify users in Tenant B.
* **Method:** Issue admin token for `tenant_id: "acme"`. Attempt to execute `/api/admin/id/users` without tenant filters or target a user in `tenant_id: "lanzar"`.
* **Pass Assertion:** API strictly scopes the query to `tenant_id == "acme"` or returns HTTP 403 `cross_tenant_access_denied`.
