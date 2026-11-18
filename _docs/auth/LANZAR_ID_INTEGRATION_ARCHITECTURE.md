# LANZAR ID — Integration Architecture

**Version:** 2.0 (NOVA Staging Verified)  
**Issuer (NOVA Staging):** `https://auth.lanzar.me/nova`  
**Issuer (Production):** `https://auth.lanzar.me`

---

## 1. Two Supported Integration Patterns

LANZAR ID intentionally supports two standards-based adapter patterns so internal Firebase-backed apps and external/SQLite SaaS apps integrate without forcing database rewrites:

### Pattern A: Standard OIDC + PKCE S256 (Recommended for External SaaS, Threadline, LANZAR AI, Resume)
1. **Frontend** generates PKCE `code_verifier` + `S256` `code_challenge`, cryptographic `state`, and `nonce`, then redirects to:
   - `GET ${AUTH_API}/oauth/authorize` (or Auth Hub UI `${AUTH_HUB}/?client_id=...`)
2. **Auth Hub** authenticates the user (email/password, Google, TOTP MFA) and returns `?code=...&state=...`.
3. **Frontend** exchanges `code` + `code_verifier` at `POST ${AUTH_API}/oauth/token` (with `Idempotency-Key`) and receives `{ access_token, id_token, refresh_token, expires_in: 900, session_id }`.
4. **Backend API** verifies `Authorization: Bearer <access_token>` locally using RS256 JWKS (`/.well-known/jwks.json`), enforcing `alg=RS256`, `iss`, `aud`, `exp`, `nbf`, and `sub` (as implemented in `threadline/backend/middleware/auth.js` and `AI/server/auth-verifier.js`).

### Pattern B: PKCE + Firebase Custom Token Bridge (Internal `lanzar-95ae3` Apps: Portal, Tickets)
1. **Frontend** completes PKCE S256 via `LanzarAuth` (`portal/src/sdk/lanzar-auth-modal.js`), exchanging at `POST /exchange` (or `/oauth/token`) for `{ custom_token, session_id }`.
2. **Frontend** calls `signInWithCustomToken(auth, custom_token)` so Firestore Security Rules (`request.auth.uid`) and backend `adminAuth.verifyIdToken(token, true)` continue working with **zero database migration**.
3. **Session Enforcement:** Frontend polls/validates `GET /api/id/session/validate` and revokes via `DELETE /api/id/sessions/:sessionId` + `POST /api/id/session/logout` on sign-out.

---

## 2. Multi-Tenant & External Developer Architecture

- **Tenant Root:** `/tenants/{tenantId}` (`plan`, `status`, `entitlements`, `billing`, `members/{uid}`).
- **Dynamic Client Registry:** `/tenants/{tenantId}/clients/{clientId}` + `/clients_index/{clientId}` (`redirectUris`, `allowedOrigins`, `allowedScopes`, `tokenEndpointAuthMethod`).
- **Scoped Dynamic CORS (`originValidator.js`):** Registered client `allowedOrigins` are permitted only on `/oauth/*`, `/.well-known/*`, `/nova/.well-known/*`, `/api/id/session/validate`, and `/api/id/sessions*`. Admin and internal session-establishment endpoints remain locked to `config.originMap`.
