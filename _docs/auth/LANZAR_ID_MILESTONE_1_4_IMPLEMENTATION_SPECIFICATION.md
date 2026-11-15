# LANZAR ID — Milestone 1.4 Implementation Specification
**Title:** Dynamic Database-Backed OAuth Client Registry & Exact Whitelists  
**Document ID:** `LID-SPEC-M1.4-AUTHORITATIVE`  
**Status:** Implemented & Locally Verified (Pending User Sign-Off)  
**Date:** 2026-11-15  

---

## 1. Scope & Objectives
Milestone 1.4 replaces static-only OAuth client resolution with a dynamic, Firestore-backed OAuth client registry (`ClientRegistryService`) supporting multi-tenant client records, strict character-for-character redirect URI whitelists, confidential client authentication (`client_secret_post`), and an authenticated administrative CRUD API, while preserving deterministic fallback and idempotent seeding for the four approved internal clients (`portal`, `tickets`, `threadline`, `ai`). Prospective clients (`pythos`, `mothership`) remain strictly excluded.

---

## 2. Data Model & Dual-Collection Architecture

### 2.1 Primary Tenant Client Document
- **Path:** `/tenants/{tenantId}/clients/{clientId}`
- **Fields:**
  - `clientId` (string, `^[a-z0-9][a-z0-9_-]{1,63}$`)
  - `tenantId` (string, `^[a-z0-9][a-z0-9_-]{1,63}$`, default `'lanzar'`)
  - `name` (string, non-empty)
  - `redirectUris` (array of exact HTTP/HTTPS URI strings, no wildcards `*`, no fragments `#`)
  - `compatibilityMode` (`'legacy_firebase' | 'dual' | 'oidc'`)
  - `tokenEndpointAuthMethod` (`'none' | 'client_secret_post'`)
  - `clientSecretHash` (hex SHA-256 digest when `tokenEndpointAuthMethod === 'client_secret_post'`, `null` otherwise; stripped by `sanitizeClientForPublicRead()` from public/admin responses)
  - `enabled` (boolean)
  - `createdAt`, `updatedAt` (ISO-8601 timestamps)

### 2.2 Global Point-Lookup Index
- **Path:** `/clients_index/{clientId}`
- **Fields:** `clientId`, `tenantId`, `enabled`, `updatedAt`
- **Collision & Ownership Protection:**
  - `registerClient()` executes inside `db.runTransaction()`, reading both `clients_index/{clientId}` and `tenants/{tenantId}/clients/{clientId}` before writing. Any existing record across any tenant throws `CLIENT_ALREADY_EXISTS`.
  - `updateClient()` executes inside `db.runTransaction()`, verifying `!indexSnap.exists` -> `CLIENT_NOT_FOUND`, `indexSnap.data().tenantId !== tenantId` -> `TENANT_OWNERSHIP_MISMATCH`, and `!clientSnap.exists` -> `CLIENT_NOT_FOUND` before applying updates.

---

## 3. Exact Redirect URI Validation & Matching
Implemented in `auth/auth-backend/services/clientRegistryService.js`:
- **Registration/Update Validation (`validateRedirectUris`):**
  - Rejects empty arrays, non-string entries, wildcard characters (`*`), URL fragments (`#`), non-`http:`/`https:` schemes, and malformed URLs.
- **Runtime Matching (`isRedirectUriAuthorized`):**
  - Strict character-for-character equality (`client.redirectUris.includes(redirectUri)`) — no trailing-slash normalization, no prefix matching, and no wildcard matching.
- **Production Filtering (`resolveClient`):**
  - Uses `checkIsProduction()` exported from `auth/auth-backend/clients.js` (or an injected `isProduction` option/override) to strip `http://localhost*` and `http://127.0.0.1*` redirect URIs when running in production mode.

---

## 4. Client Authentication & OAuth Route Integration
- **Public PKCE Clients (`tokenEndpointAuthMethod: 'none'`):**
  - Authenticated via PKCE S256 (`code_challenge` / `code_verifier`).
- **Confidential Clients (`tokenEndpointAuthMethod: 'client_secret_post'`):**
  - Requires `clientSecret` at registration (minimum 16 characters), stored only as SHA-256 hex digest (`clientSecretHash`).
  - `verifyClientCredentials(client, presentedSecret)` uses constant-time comparison (`crypto.timingSafeEqual`).
- **OAuth Route Enforcement (`auth/auth-backend/routes/oauthRoutes.js`):**
  - `POST /oauth/authorize`: Resolves client asynchronously via `clientRegistryService.resolveClient(client_id)` (falling back to static `getClient` only when no `clientRegistryService` is configured), checks `isRedirectUriAuthorized(client, redirect_uri)`, and binds `tenantId: client.tenantId || 'lanzar'`.
  - `POST /oauth/token` (`authorization_code` and `refresh_token` grants): Verifies `resolvedClient && resolvedClient.enabled` and calls `verifyClientCredentials(resolvedClient, req.body?.client_secret)`, failing closed with `401 invalid_client` on invalid or missing credentials.

---

## 5. Internal Client Seeding & Admin API
- **Idempotent Seeding (`seedApprovedInternalClients`):**
  - Seeds strictly the 4 approved internal clients (`portal`, `tickets`, `threadline`, `ai`) from `auth/auth-backend/clients.js` into tenant `'lanzar'` if not already present. Prospective clients `pythos` and `mothership` are excluded.
- **Admin CRUD Router (`auth/auth-backend/routes/clientRegistryRoutes.js`):**
  - Mounted at `/api/admin/id` in `auth/auth-backend/app.js`, protected by `authenticateAdminMiddleware`:
    - `POST /api/admin/id/clients` — register dynamic client
    - `POST /api/admin/id/clients/seed-internal` — run idempotent seeding of approved internal clients
    - `GET /api/admin/id/clients/:clientId` — fetch sanitized client metadata (`clientSecretHash` omitted)
    - `PATCH /api/admin/id/clients/:clientId` — update client `name`, `redirectUris`, `compatibilityMode`, or `enabled`
