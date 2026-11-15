# LANZAR ID — Milestone 1.4 Security Reconciliation Report
**Title:** Dynamic Database-Backed OAuth Client Registry & Exact Whitelists  
**Document ID:** `LID-REC-M1.4-AUTHORITATIVE`  
**Status:** Security Reconciliation Complete — Awaiting User Sign-Off  
**Date:** 2026-11-15  

---

## 1. Security Findings Report

### Finding 1 — Tenant Authorization Bypass via Request-Body `tenantId` (HIGH — RESOLVED)
- **Original State:** `clientRegistryRoutes.js` read `tenantId` directly from `req.body.tenantId` on `POST /clients`, `POST /clients/seed-internal`, and `PATCH /clients/:clientId`, and `GET /clients/:clientId` performed no tenant check at all. Any authenticated admin could register, read, or modify clients in arbitrary tenants.
- **Remediation:** Added `getAdminRecord()` and `req.adminContext` / `req.adminRole` population in `auth/auth-backend/middleware/authMiddleware.js` (exclusively from server-verified `authAdmin.verifyIdToken()` claims + authoritative Firestore `admins` records, never headers or request body), and `resolveAdminTenantScope(req)` in `auth/auth-backend/routes/clientRegistryRoutes.js`:
  - Tenant identity is derived strictly from `req.adminContext.tenantId` / `req.user.tenantId` (defaulting to `'lanzar'` when unset; malformed tenant claims fail closed with `403 forbidden`).
  - Tenant-scoped admins attempting to register, read, update, or seed another tenant receive `403 forbidden` (`TENANT_AUTHORIZATION_DENIED`).
  - **Explicit Platform-Administrator Exception:** Admins with verified `platformAdmin === true` or `role === 'platform_admin'` are permitted to specify target `tenantId` values and inspect/manage clients across tenants.
- **Verification:** `M1.4-07`, `M1.4-10` (PASS).

### Finding 2 — Production Redirect URI Filtering Used Fragile String Prefixing (MEDIUM — RESOLVED)
- **Original State:** `ClientRegistryService.resolveClient()` filtered production redirect URIs using `!uri.startsWith('http://localhost') && !uri.startsWith('http://127.0.0.1')`, which missed `https://localhost`, `https://127.0.0.1`, other `127.0.0.0/8` addresses (e.g., `127.0.0.2`), IPv6 loopback (`[::1]`), and localhost subdomains (`*.localhost`).
- **Remediation:** Added URL-parsed `isLoopbackOrLocalhostUri(uri)` and `filterProductionRedirectUris(redirectUris)` in `auth/auth-backend/services/clientRegistryService.js` using `new URL(uri)` and `net.isIPv4`, stripping `localhost`, `*.localhost`, `127.0.0.0/8`, `::1`, and `0:0:0:0:0:0:0:1` across both `http:` and `https:` for both Firestore and static fallback clients.
- **Verification:** `M1.4-08` (PASS).

### Finding 3 — Confidential Client Secret Check on `refresh_token` Ran After Family Rotation & Only Inside `oidcTokenService` Block (MEDIUM — RESOLVED)
- **Original State:** In `auth/auth-backend/routes/oauthRoutes.js`, `POST /oauth/token` (`grant_type=refresh_token`) called `codeStore.authorizeRefreshGrant()` (which rotates the refresh-token family in Firestore) *before* checking `boundClient.enabled` and `verifyClientCredentials()`, and only performed those checks inside `if (oidcTokenService && typeof oidcTokenService.mintAccessToken === 'function')`.
- **Remediation:** Added a pre-authentication check when `req.body.client_id` is supplied before `authorizeRefreshGrant()`, and moved `boundClient` / `enabled` / `verifyClientCredentials` enforcement outside the `oidcTokenService` conditional so confidential client authentication and disabled-client checks always fail closed with `401 invalid_client` without rotating the token family.
- **Verification:** `M1.4-09` (PASS).

### Finding 4 — Client Secret Generation, Hashing, and Rotation (LOW / DOCUMENTED GAP)
- **Evidence:**
  - `registerClient()` accepts caller-supplied `clientSecret` (>= 16 chars), hashes it with unsalted SHA-256 (`hashClientSecret`), compares with `crypto.timingSafeEqual`, and strips `clientSecretHash` and `clientSecret` via `sanitizeClientForPublicRead()` in all API responses.
  - No server-side CSPRNG secret generator or secret-rotation endpoint/method is implemented in M1.4.
- **Assessment:** Unsalted SHA-256 is appropriate **only** for high-entropy CSPRNG secrets (>= 128–256 bits). For caller-chosen low-entropy secrets, SHA-256 without a per-client salt or slow KDF is weaker against offline brute-force if the database is leaked.
- **Effect on Refresh-Token Families:** Because `POST /oauth/token` (`refresh_token`) validates `client_secret` against the live `clientSecretHash` on `boundClient`, any future single-hash rotation will immediately reject existing refresh-token families until the client updates its deployed secret (unless a dual-secret / `previousClientSecretHash` grace window is introduced).

### Finding 5 — Internal Client Bootstrap & Prospective Client Exclusion (PASS)
- **Evidence:** `app.js` does not auto-seed on startup; bootstrap requires explicit `POST /api/admin/id/clients/seed-internal` (restricted to `'lanzar'` tenant or `platform_admin`) or `seedApprovedInternalClients()`. Before seeding, `resolveClient()` falls back to `clients.js`.
- **Scope:** Strictly `portal`, `tickets`, `threadline`, and `ai` are present and seeded. `pythos` and `mothership` remain absent.
- **Verification:** `M1.4-04`, `EMU-M1.4-02`, `REG-01`..`REG-09` (PASS).

### Finding 6 — Administrative API Surface & Response Sanitization (PASS)
- **Evidence:** `createClientRegistryRouter` exposes `POST /clients`, `POST /clients/seed-internal`, `GET /clients/:clientId`, and `PATCH /clients/:clientId`, all gated by `requireAdmin` (failing closed `503` if middleware is missing). No `DELETE` endpoint exists (clients are disabled via `PATCH` `{ enabled: false }`). All responses return `sanitizeClientForPublicRead()` output (`clientSecretHash` omitted).
- **Verification:** `M1.4-06`, `M1.4-07`, `M1.4-09` (PASS).

---

## 2. Actual Code Changes
- `auth/auth-backend/middleware/authMiddleware.js` — Added `getAdminRecord()` and populated `req.adminRole` / `req.adminContext` exclusively from server-verified ID tokens and authoritative Firestore `admins` records.
- `auth/auth-backend/clients.js` — Exported `checkIsProduction` alongside `getClient` and `clients`.
- `auth/auth-backend/services/clientRegistryService.js` — Reordered `updateClient()` existence vs. tenant-ownership checks; replaced string-prefix localhost filter with URL-parsed `isLoopbackOrLocalhostUri` / `filterProductionRedirectUris`; stripped `clientSecret` alongside `clientSecretHash` in `sanitizeClientForPublicRead()`.
- `auth/auth-backend/routes/clientRegistryRoutes.js` — Added `resolveAdminTenantScope(req)` enforcing claim-based tenant isolation with explicit `platform_admin` exception across all 4 admin endpoints.
- `auth/auth-backend/routes/oauthRoutes.js` — Integrated `clientRegistryService` on `/oauth/authorize` and `/oauth/token`; moved `refresh_token` confidential client authentication and `enabled` checks ahead of family rotation and outside `oidcTokenService` guard.
- `auth/auth-backend/app.js` — Instantiated `ClientRegistryService` and mounted `createClientRegistryRouter` at `/api/admin/id`.
- `auth/test-milestone-1-4.cjs` — Added `M1.4-01`..`M1.4-09` (including security regression tests `M1.4-07`, `M1.4-08`, `M1.4-09`).
- `auth/test-milestone-1-4-emulator.cjs` — Added `EMU-M1.4-01`..`EMU-M1.4-03` for live Cloud Firestore Emulator verification.

---

## 3. Verification Results (Final Working-Tree State)

> **Environment Distinction:** All Firestore persistence tests below ran against an in-memory simulation or the **local Cloud Firestore Emulator** (`127.0.0.1:8091`, project `demo-lanzar-id-m1-4-test`). **Zero tests were executed against production Cloud Firestore.**

| Suite | Command | Passed | Total | Status |
| :--- | :--- | :---: | :---: | :--- |
| M1.4 Unit & HTTP Suite | `node auth/test-milestone-1-4.cjs` | 10 | 10 | PASS |
| M1.4 Firestore Emulator Suite | `node auth/test-milestone-1-4-emulator.cjs` | 3 | 3 | PASS |
| M1.3 OIDC & Adapter Suite | `node auth/test-milestone-1-3.cjs` | 7 | 7 | PASS |
| M1.2 RS256 & JWKS Suite | `node auth/test-milestone-1-2.cjs` | 11 | 11 | PASS |
| M1.1 Store Simulation Suite | `node auth/test-milestone-1-1.cjs` | 44 | 44 | PASS |
| Phase 1 Acceptance Suite | `node auth/test-phase1-acceptance.cjs` | 55 | 55 | PASS |
| OAuth Client Registry Suite | `node auth/test-client-registry.cjs` | 9 | 9 | PASS |
| **Total** | | **139** | **139** | **100.0%** |

---

## 4. Explicit Unresolved Risks & Deferred Commercial Requirements
1. **Future Commercial Tenant Onboarding Requirements (Deferred):** Server-generated 256-bit CSPRNG client secrets, one-time secret disclosure at creation/rotation, and a dedicated secret-rotation endpoint with a dual-secret grace-period policy (`previousClientSecretHash`) are deferred beyond M1.4. Currently, caller-supplied secrets (`>= 16` chars) rely on unsalted SHA-256, and single-hash rotation would immediately invalidate active refresh-token families.
2. **Legacy `admins/{uid}` documents without `tenantId` or `platformAdmin` claims:** `resolveAdminTenantScope()` defaults admins lacking `req.user.tenantId` to `'lanzar'` (fail-closed for other tenants). Production `admins` documents or custom claims must explicitly set `platformAdmin: true` / `role: 'platform_admin'` for cross-tenant management.
3. **Production Firestore:** Zero tests have been executed against production Cloud Firestore.
