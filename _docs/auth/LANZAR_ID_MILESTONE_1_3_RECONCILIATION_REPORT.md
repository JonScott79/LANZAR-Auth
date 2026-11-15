# LANZAR ID — Milestone 1.3 Security & Compliance Reconciliation Report

**Date:** 2026-11-15  
**Target Specification:** `LID-SPEC-M1.3-OIDC-ADAPTER-AUTHORITATIVE`  
**Status:** OIDC-Compatible Implementation with Documented OIDC Core Limitations (Verified Locally; Not Committed/Pushed/Deployed)  

---

## 1. Review Findings Summary

| Area | Status | Key Code References & Resolution |
| :--- | :--- | :--- |
| **1. Client Registry Scope** | **PASS** (Remediated) | Removed unapproved prospective clients `pythos` and `mothership` from `auth/auth-backend/clients.js`. Updated `auth/test-client-registry.cjs` (`9/9 PASS`) to assert strictly `portal`, `tickets`, `threadline`, `ai` and confirm `pythos`/`mothership` are absent. |
| **2. OIDC ID Token Compliance** | **PASS** (with disclosed OIDC Core limitations) | `auth/auth-backend/services/oidcTokenService.js` sets `iss`, `aud`, `azp`, `sub`, `iat`, `exp`, `kid` (RS256), `nonce`, `auth_time`, and scope-filtered `email`/`profile` claims; `oidc` mode never calls `createCustomToken`. Fixed `store.js` (`initiateRedemption()` lines 1143–1145, 1202–1204) to forward `userClaims`. |
| **3. Authorization Code Grant** | **PASS** (Remediated) | `auth/auth-backend/routes/oauthRoutes.js` shares `handleAuthorizationCodeGrant()` across `/oauth/exchange` and `/oauth/token` (`grant_type=authorization_code`). Remediated `POST /oauth/authorize` (line 44) to exact `client.redirectUris.includes(redirect_uri)` and added `nonce` validation. |
| **4. Refresh Token Grant** | **PASS** (Remediated) | `POST /oauth/token` (`grant_type=refresh_token`) enforces `codeStore.authorizeRefreshGrant()`, validates `client_id` against `familyData.clientId` before rotation, locks compatibility mode, preserves `auth_time`, and omits `nonce` (OIDC Core §12.2). |
| **5. UserInfo & Discovery** | **PASS** (Remediated) | Access tokens carry `aud: [clientId, '${issuer}/oauth/userinfo']` + `azp: clientId`. `verifyAccessToken()` enforces `alg === 'RS256'`, exact `iss`, `token_use === 'access'`, `expectedAudience` (`${issuer}/oauth/userinfo`), multi-audience `azp` membership, and `tenant_id`. `oidcRoutes.js` enforces `sessionData.uid === uid` and `sessionData.tenantId === payload.tenant_id`. Discovery `scopes_supported` advertises strictly `['openid', 'profile', 'email']`. |
| **6. Unsupported OIDC Core Features** | **NEEDS DECISION** (Deferred / Disclosed) | `GET /oauth/authorize` (browser redirect), `prompt`/`max_age`/`acr_values`/`claims`, confidential client auth (deferred to M1.4), and OIDC Core §11 consent-gated `offline_access` are not implemented in M1.3. |

---

## 2. Initial Test Failures Explained

1. **First `node auth/test-milestone-1-3.cjs` run (Exit Code 1):**
   - **Cause:** `test-milestone-1-3.cjs` imported a non-existent helper `setReceiptKeyringOverride` from `auth/auth-backend/store.js` (which resolves keys from `process.env` / dev fallback in non-production environments).
   - **Resolution:** Removed the invalid import/call from `test-milestone-1-3.cjs`; `5/5` passed immediately.
2. **Post-review `M1.3-07` run (Exit Code 1, `6/7` passed):**
   - **Cause:** `FirestoreAuthorizationCodeStore.initiateRedemption()` in `auth/auth-backend/store.js` (Branch C & Branch E) omitted `userClaims` from its returned `record` object, leaving `record.userClaims` undefined during token minting (`auth_time` was `undefined` in `t1.id_token`).
   - **Resolution:** Added `userClaims: data.userClaims || null` to both `SUCCESS` return paths in `store.js` (`lines 1144, 1204`); `M1.3-07` and the full suite then passed `7/7`.

---

## 3. Final Verification Results (Post-Final-Edit)

> **Environment Distinction:** M1.1, M1.3 unit, Phase 1, and Client Registry suites ran against in-memory mocks; M1.2 emulator tests ran against the local **Cloud Firestore Emulator** (`demo-lanzar-id-m1-2-test` on `127.0.0.1:8089`); M1.3 emulator test (`EMU-M1.3-01`) ran against the local **Cloud Firestore Emulator** (`demo-lanzar-id-m1-3-test` on `127.0.0.1:8090`). **Zero production Cloud Firestore or deployed tests were run.**

| Suite | Command | Result |
| :--- | :--- | :--- |
| **M1.3 OIDC & Adapter Suite** | `node auth/test-milestone-1-3.cjs` | **7 / 7 PASS** |
| **M1.3 Firestore Emulator Suite (`EMU-M1.3-01`)** | `node auth/test-milestone-1-3-emulator.cjs` | **1 / 1 PASS** |
| **M1.2 Unit & HTTP Suite** | `node auth/test-milestone-1-2.cjs` | **11 / 11 PASS** |
| **M1.2 Firestore Emulator Suite** | `node auth/test-milestone-1-2-emulator.cjs` | **7 / 7 PASS** |
| **M1.1 Regression Suite** | `node auth/test-milestone-1-1.cjs` | **44 / 44 PASS** |
| **Phase 1 Acceptance Suite** | `node auth/test-phase1-acceptance.cjs` | **55 / 55 PASS** |
| **Client Registry Suite** | `node auth/test-client-registry.cjs` | **9 / 9 PASS** |
| **Combined Total** | — | **134 / 134 PASS** |
