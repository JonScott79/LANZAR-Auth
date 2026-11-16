# LANZAR ID — NOVA Issuer Architecture Specification

**Project:** LANZAR ID  
**Baseline Commit:** `475437f2ac1d90adde6035499ac40dd6fefd1084` (`lanzar_id_main_chat`)  
**Parent Milestone:** M1.5 (`80c1dec6760a604badaa06e87549ba67e97ef51c`)  
**Scope:** Technical specification for decoupling OIDC `issuer` from `apiBaseUrl` and supporting **NOVA** (`https://auth.lanzar.me/nova` / `https://auth-api-nova.lanzar.me` / `lanzar-95ae3-dev`) as an independently configured staging identity environment.  
**Status:** Specification only — no code, tests, secrets, or infrastructure modified.

---

## 1. Current Implementation Findings (Commit `475437f`)

Read-only inspection of `auth/auth-backend` and `auth/` identified the following gaps:

1. **`app.js:117` Ignores `OIDC_ISSUER`:** `createApp` instantiates `OidcTokenService` with `{ signingKeystore, issuer: config ? config.apiBaseUrl : undefined }`. `process.env.OIDC_ISSUER` is never passed in `app.js`.
2. **`OidcTokenService` Couples `issuer` and API Endpoints (`oidcTokenService.js:48, 55-67`):** `getUserinfoAudience()` and `getDiscoveryDocument()` derive `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, and `jwks_uri` from `this.issuer` (`${iss}/oauth/...`, `${iss}/.well-known/jwks.json`) instead of a separate `apiBaseUrl`.
3. **Missing `/nova` Discovery & JWKS Routes (`oidcRoutes.js:10`, `jwksRoutes.js:9`, `app.js:152-156`):** Only `GET /.well-known/openid-configuration` and `GET /.well-known/jwks.json` are mounted at `/`.
4. **Auth Hub SPA Catch-All (`auth/netlify.toml:5-8`, `auth/vercel.json:5-7`):** Both `netlify.toml` (`from = "/*" -> "/index.html"`) and `vercel.json` (`"/(.*)" -> "/index.html"`) swallow all paths, which would intercept `https://auth.lanzar.me/nova/.well-known/openid-configuration` unless an explicit proxy rule is placed above the catch-all.
5. **Obsolete Staging URLs in `environments.js` (`lines 40-70`) & `clients.js` (`lines 70-71`):** `ENV_CONFIGS.staging` still configures `auth-api-dev.lanzar.me`, `auth-dev.lanzar.me`, and `id-dev.lanzar.me` in `apiBaseUrl`, `authHubUrl`, `portalUrl`, `originMap`, and `continuationAllowlist`.

---

## 2. Proposed Architecture & Issuer/API Decoupling

| Environment | Auth Hub | Backend API (`apiBaseUrl`) | OIDC Issuer (`issuer` / `iss`) | Firebase Project | Internal `APP_ENV` |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Production** | `https://auth.lanzar.me` | `https://auth-api.lanzar.me` | `https://auth.lanzar.me` (unchanged) | `lanzar-95ae3` | `production` |
| **NOVA Staging** | `https://auth.lanzar.me/nova` | `https://auth-api-nova.lanzar.me` | `https://auth.lanzar.me/nova` | `lanzar-95ae3-dev` | `staging` |

### 2.1 `OidcTokenService` Decoupling (`oidcTokenService.js`)
Update `constructor({ signingKeystore, issuer, apiBaseUrl } = {})`:
- Store `this.issuer` (normalized, trailing slashes stripped) and `this.apiBaseUrl` (normalized, trailing slashes stripped; defaults to `this.issuer` only when `apiBaseUrl` is omitted in isolated unit tests).
- **Validation (Fail Closed):**
  - Both `issuer` and `apiBaseUrl` must be valid `https://` URLs in `staging` and `production` (no query string, no hash fragment, no uppercase `/NOVA` path).
  - In `APP_ENV=staging` (NOVA), reject any `issuer` equal to production `https://auth.lanzar.me` or `apiBaseUrl` equal to `https://auth-api.lanzar.me`.
  - In `APP_ENV=production`, reject any `issuer` containing `/nova` or `apiBaseUrl` containing `nova`.
- **JWT `iss` & Validation (`mintAccessToken`, `mintIdToken`, `verifyAccessToken`):**
  - Sign and verify `payload.iss === this.issuer` (`https://auth.lanzar.me/nova` in NOVA; `https://auth.lanzar.me` in production, or existing production `apiBaseUrl` if production keeps its current setting).
  - `getUserinfoAudience()` returns `${this.apiBaseUrl}/oauth/userinfo` so access tokens target the actual NOVA API resource server.

### 2.2 Discovery Document (`getDiscoveryDocument()`)
For **NOVA** (`issuer = "https://auth.lanzar.me/nova"`, `apiBaseUrl = "https://auth-api-nova.lanzar.me"`):
- `issuer`: `"https://auth.lanzar.me/nova"`
- `authorization_endpoint`: `"https://auth-api-nova.lanzar.me/oauth/authorize"`
- `token_endpoint`: `"https://auth-api-nova.lanzar.me/oauth/token"`
- `userinfo_endpoint`: `"https://auth-api-nova.lanzar.me/oauth/userinfo"`
- `jwks_uri`: `"https://auth-api-nova.lanzar.me/.well-known/jwks.json"`
- All other metadata fields (`response_types_supported`, `subject_types_supported`, `id_token_signing_alg_values_supported`, `scopes_supported`, `token_endpoint_auth_methods_supported`, `code_challenge_methods_supported`, `grant_types_supported`, `claims_supported`) remain unchanged.
- **Production Discovery:** Remains unchanged.

---

## 3. Routing & Frontend Hosting Rewrite Requirements

- **Backend API (`https://auth-api-nova.lanzar.me`):**
  - Continue serving `/.well-known/openid-configuration`, `/.well-known/jwks.json`, `/oauth/authorize`, `/oauth/token`, and `/oauth/userinfo` at `/`.
  - Also mount `GET /nova/.well-known/openid-configuration` (in `oidcRoutes.js`) when `APP_ENV === 'staging'` (or via `oidcRouter` alias) so proxied requests from `https://auth.lanzar.me/nova/.well-known/openid-configuration` succeed cleanly.
- **Auth Hub Hosting Proxy (`auth/netlify.toml` / `auth/vercel.json`):**
  - Both Netlify (`[[redirects]]` with `status = 200`, `force = true`) and Vercel (`rewrites`) support external destination proxies **above** the SPA catch-all:
    - Proxy `/nova/.well-known/openid-configuration` -> `https://auth-api-nova.lanzar.me/nova/.well-known/openid-configuration` (`200`).
    - Optionally proxy `/nova/.well-known/jwks.json` -> `https://auth-api-nova.lanzar.me/.well-known/jwks.json` (`200`), even though `jwks_uri` advertises `https://auth-api-nova.lanzar.me/.well-known/jwks.json` directly.
  - Do **not** proxy `/oauth/authorize`, `/oauth/token`, or `/oauth/userinfo` through the frontend host; OIDC clients call `https://auth-api-nova.lanzar.me` directly as advertised in the discovery document.

---

## 4. Exact Configuration Changes

1. **`auth/auth-backend/config/environments.js` (`ENV_CONFIGS.staging`):**
   - `apiBaseUrl`: `'https://auth-api-nova.lanzar.me'`
   - `authHubUrl`: `'https://auth.lanzar.me/nova'`
   - `oidcIssuer`: `'https://auth.lanzar.me/nova'` (add `oidcIssuer` field to `ENV_CONFIGS.production` and `ENV_CONFIGS.staging`; keep `development` `http://localhost:4001` untouched).
   - Update `originMap` and `continuationAllowlist` to include `'https://auth.lanzar.me'` (for `/nova` Auth Hub origin; note HTTP `Origin` headers only carry `scheme://host[:port]`, never path `/nova`) and approved staging app origins, removing obsolete `auth-api-dev.lanzar.me`, `auth-dev.lanzar.me`, and `id-dev.lanzar.me`.
2. **`auth/auth-backend/config/bootstrap.js`:**
   - Resolve `oidcIssuer = env.OIDC_ISSUER || spec.oidcIssuer || spec.apiBaseUrl`.
   - Validate `oidcIssuer` is `https://` in `staging`/`production`, rejects cross-environment issuer (`lanzar.me/nova` in prod, or prod issuer in staging), and freeze `oidcIssuer` on the returned `config` object.
3. **`auth/auth-backend/app.js`:**
   - Pass `{ signingKeystore, issuer: config ? config.oidcIssuer : process.env.OIDC_ISSUER, apiBaseUrl: config ? config.apiBaseUrl : undefined }` to `new OidcTokenService(...)`.
4. **`auth/auth-backend/services/oidcTokenService.js`:**
   - Decouple `this.issuer` and `this.apiBaseUrl`, update `getUserinfoAudience()` and `getDiscoveryDocument()`, and preserve exact `result.payload.iss === this.issuer` validation.
5. **`auth/auth-backend/clients.js`:**
   - Keep only the 4 approved clients (`portal`, `tickets`, `threadline`, `ai`), keep `pythos` and `mothership` excluded, and add/verify environment-appropriate NOVA staging redirect URIs without altering production redirect URIs.

---

## 5. Security Considerations

- **Project & Key Isolation:** `lanzar-95ae3-dev` maintains separate Firestore (`system_signing_keys`), RS256 private keys, `@lanzar-95ae3-dev.iam.gserviceaccount.com` credentials, `SIGNING_KEY_ENCRYPTION_KEY`, `RECEIPT_ENCRYPTION_KEY`, `SESSION_SIGNING_SECRET`, and `MFA_HMAC_SECRET`.
- **Cross-Environment Token Rejection:** `verifyAccessToken` enforces exact `payload.iss === this.issuer` and `payload.aud === ${this.apiBaseUrl}/oauth/userinfo`, ensuring production tokens are rejected by NOVA and NOVA tokens are rejected by production.
- **CORS / Origin & Redirect URI Isolation:** `originMap` and `clients.js` / `ClientRegistryService` enforce exact character-for-character redirect URI matching and environment-scoped origins; `pythos` and `mothership` remain excluded.

---

## 6. Required Test Plan

Add targeted unit and HTTP integration tests verifying:
1. **Production Issuer Unchanged:** `APP_ENV=production` preserves production issuer and discovery endpoints.
2. **NOVA Issuer Exact:** `APP_ENV=staging` with `OIDC_ISSUER=https://auth.lanzar.me/nova` advertises `issuer: "https://auth.lanzar.me/nova"` and `apiBaseUrl: "https://auth-api-nova.lanzar.me"` endpoints (`jwks_uri`, `token_endpoint`, `userinfo_endpoint`, `authorization_endpoint`).
3. **Discovery & JWKS Serving:** `GET /nova/.well-known/openid-configuration` returns the NOVA discovery document; `GET /.well-known/jwks.json` returns public RS256 keys.
4. **JWT `iss` & Validation:** Minted `access_token` and `id_token` carry `iss: "https://auth.lanzar.me/nova"`.
5. **Cross-Environment Rejection:** Production-signed/issued tokens fail `verifyAccessToken` on NOVA (`INVALID_ISSUER`), and NOVA tokens fail on production (`INVALID_ISSUER`).
6. **Fail-Closed Startup Validation:** Missing, non-HTTPS, uppercase `/NOVA`, or cross-environment `OIDC_ISSUER` throws in `bootstrap()` / `OidcTokenService`.
7. **Redirect URI & Client Restrictions:** Approved clients only; `pythos` and `mothership` remain excluded.

---

## 7. Risks, Unresolved Decisions & Implementation Sequence

- **Unresolved Decisions:**
  1. Confirm whether Auth Hub (`https://auth.lanzar.me`) is hosted on **Netlify** (`auth/netlify.toml`) or **Vercel** (`auth/vercel.json`) so the `/nova/.well-known/openid-configuration` rewrite is added to the active host config.
  2. Confirm exact NOVA staging client redirect URIs for `portal`, `tickets`, `threadline`, and `ai` (currently `clients.js` only has `https://ai-dev.lanzar.me` for staging).
  3. Confirm whether production `OIDC_ISSUER` remains `https://auth-api.lanzar.me` or `https://auth.lanzar.me` (keep production discovery unchanged unless explicitly authorized).
- **Implementation Sequence:**
  1. Update `environments.js`, `bootstrap.js`, `oidcTokenService.js`, `app.js`, `oidcRoutes.js`, and `clients.js`.
  2. Add NOVA issuer/discovery/cross-env rejection tests and run full regression suite (`184+` tests).
  3. Update active Auth Hub hosting config (`netlify.toml` or `vercel.json`) for `/nova/.well-known/*` proxy.
  4. Proceed to controlled NOVA staging deployment only after authorization.
