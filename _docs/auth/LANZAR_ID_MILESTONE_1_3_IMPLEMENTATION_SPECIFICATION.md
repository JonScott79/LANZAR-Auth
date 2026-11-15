# LANZAR ID — Milestone 1.3 Implementation Specification

**Document ID:** `LID-SPEC-M1.3-OIDC-ADAPTER-AUTHORITATIVE`  
**Status:** Remediated & Verified Locally (Pending Sign-Off; Not Committed/Pushed/Deployed)  
**Scope:** OIDC-Compatible Token Engine, Discovery, UserInfo, and Scoped Compatibility Adapter (with documented OIDC Core limitations)  

---

## 1. Architecture Overview

Milestone 1.3 provides an OIDC-compatible token issuance, discovery, and UserInfo layer (with documented OIDC Core limitations in Section 4) on top of the Milestone 1.1 distributed authorization code store and Milestone 1.2 RS256 asymmetric keystore without breaking existing Firebase-backed internal applications.

### Core Components
- **`auth/auth-backend/services/oidcTokenService.js`**: Mints RS256 `access_token` (900s TTL) and `id_token` (3600s TTL), implements the Scoped Compatibility Adapter (`legacy_firebase` | `dual` | `oidc`), builds OIDC Discovery metadata, and enforces fail-closed RS256 access-token verification.
- **`auth/auth-backend/routes/oidcRoutes.js`**: Serves `GET /.well-known/openid-configuration` and `GET /oauth/userinfo`.
- **`auth/auth-backend/routes/oauthRoutes.js`**: Shares `handleAuthorizationCodeGrant()` across `POST /oauth/exchange` and `POST /oauth/token` (`grant_type=authorization_code`), and upgrades `POST /oauth/token` (`grant_type=refresh_token`) to mint rotated RS256 tokens for `dual` and `oidc` clients.
- **`auth/auth-backend/clients.js`**: Restricts active internal OAuth clients to the four approved applications (`portal`, `tickets`, `threadline`, `ai`), with prospective candidates (`pythos`, `mothership`) excluded.

---

## 2. Scoped Compatibility Adapter & Client Registry

| Client ID | `compatibilityMode` | Token Response Behavior |
| :--- | :--- | :--- |
| `portal` | `legacy_firebase` | Firebase `custom_token` + `refresh_token` |
| `tickets` | `legacy_firebase` | Firebase `custom_token` + `refresh_token` |
| `threadline` | `dual` | RS256 `access_token` + `id_token` + `custom_token` + `refresh_token` |
| `ai` | `legacy_firebase` | Firebase `custom_token` + `refresh_token` |
| *(OIDC / 3rd-party)* | `oidc` | RS256 `access_token` + `id_token` + `refresh_token` (**never** calls `createCustomToken`) |

- Prospective clients `pythos` and `mothership` are **not** registered in `clients.js`.
- `POST /oauth/authorize` enforces exact character-for-character `redirect_uri` matching (`client.redirectUris.includes(redirect_uri)`).

---

## 3. OIDC Token & Endpoint Security Guarantees

- **Authorization Code Grant (`POST /oauth/token` & `POST /oauth/exchange`):**
  - Enforces PKCE `S256`, exact `redirect_uri`, client binding, `Idempotency-Key`, and atomic two-phase Firestore redemption before the compatibility adapter runs.
  - Persists `scope`, `nonce`, and `userClaims` (`email`, `emailVerified`, `name`, `authTime`) across the code ceremony.
- **Refresh Token Grant (`POST /oauth/token` `grant_type=refresh_token`):**
  - Enforces `codeStore.authorizeRefreshGrant()` atomic rotation and replay containment.
  - Locks compatibility mode to the token family's persisted `clientId` and rejects `req.body.client_id` mismatches (`400 invalid_grant`).
  - Preserves original `auth_time` in refreshed ID tokens for `dual`/`oidc` clients and omits `nonce` per OIDC Core §12.2.
- **UserInfo (`GET /oauth/userinfo`):**
  - **Access-Token Audience Policy:** Minted access tokens include `aud: [clientId, '${issuer}/oauth/userinfo']` with `azp: clientId`.
  - `verifyAccessToken()` fails closed unless `header.alg === 'RS256'`, `token_use === 'access'`, `iss === this.issuer`, `aud` authorizes the target resource (`${issuer}/oauth/userinfo` for UserInfo), `azp` is valid and present in `aud` when multiple audiences exist, `tenant_id` is non-empty, and RS256 signature + `exp` verify against `SigningKeystore`.
  - Enforces online session status (`status === 'active' && revoked !== true`), subject (`sessionData.uid === uid`), and tenant (`sessionData.tenantId === payload.tenant_id`) in Firestore.
  - Filters returned claims (`email`, `email_verified`, `name`) strictly by granted `scope`.

---

## 4. Known OIDC Core Limitations (Explicit Disclosure)

1. **Authorization Endpoint Transport:** Auth Hub uses `POST /oauth/authorize` with an authenticated Firebase ID token; a browser redirect `GET /oauth/authorize` endpoint is not implemented in Milestone 1.3.
2. **Optional OIDC Parameters:** `prompt`, `max_age`, `acr_values`, `ui_locales`, and the `claims` request parameter are not implemented.
3. **Client Authentication:** Confidential client authentication (`client_secret_basic` / `client_secret_post` / `private_key_jwt`) is deferred to Milestone 1.4's dynamic client registry.
4. **Offline Access Semantics:** Discovery `scopes_supported` advertises only `['openid', 'profile', 'email']` (does not advertise `offline_access`), because OIDC Core §11 consent-gated `offline_access` is deferred alongside browser authorization; refresh tokens are issued for LANZAR ID's internal session-family continuity.
5. **Test Scope:** Milestone 1.3 tests ran against in-memory Firestore mocks (reusing M1.1 & M1.2 Firestore-emulator-verified primitives); zero production Cloud Firestore or deployed tests were run.
