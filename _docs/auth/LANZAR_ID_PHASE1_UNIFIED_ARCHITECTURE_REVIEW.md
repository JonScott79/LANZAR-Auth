# LANZAR ID — Phase 1 Unified Architecture Review
**Document ID:** `LID-REV-PHASE1-ARCH`  
**Branch:** `lanzar_id_main_chat`  
**Checkpoints:** M1.4 `5fb79411e0bf94131f60fb38d1d57a906067b8d9` -> M1.5 `80c1dec6760a604badaa06e87549ba67e97ef51c`  
**Scope:** Milestones 1.1 through 1.5 (Architecture & Security Review Only)  
**Date:** 2026-11-15  

---

## 1. Executive Summary
Across Milestones 1.1–1.5, LANZAR ID has evolved from a Firebase-coupled OAuth 2.0/PKCE prototype into a coherent, transactionally hardened identity and authorization backend with:
- **Distributed two-phase authorization-code redemption and refresh-token family rotation** (`store.js`, M1.1).
- **Asymmetric RS256 signing and JWKS distribution** with AES-256-GCM key-at-rest encryption (`signingKeystore.js`, `jwksRoutes.js`, M1.2).
- **OIDC-compatible token issuance, Discovery, and online UserInfo** (`oidcTokenService.js`, `oidcRoutes.js`, M1.3).
- **Dynamic Firestore-backed OAuth client registry** with strict exact redirect-URI matching (`clientRegistryService.js`, `clientRegistryRoutes.js`, M1.4).
- **Tenant context enforcement, client disable/enable lifecycle, and atomic transactional audit logging** (`auditLogService.js`, `authMiddleware.js`, M1.5).

All 145 automated tests across M1.1–M1.5, Phase 1 acceptance, and client-registry suites pass locally (in-memory and local Cloud Firestore Emulator). **Zero tests have been run against production Cloud Firestore**, and key commercial SaaS capabilities (tenant-scoped user directories, server-generated 256-bit client secrets with dual-secret rotation, Firestore Security Rules deployment, and billing/onboarding) remain deferred.

---

## 2. Current Architecture & Component Relationships

```text
Clients (portal, tickets, threadline, ai, dynamic tenant clients)
   │
   ├── POST /oauth/authorize ──────────────────────► oauthRoutes.js
   ├── POST /oauth/token (authorization_code) ─────► oauthRoutes.js ──► store.js (FirestoreAuthorizationCodeStore)
   │                                                                └── oidcTokenService.js ──► signingKeystore.js
   ├── POST /oauth/token (refresh_token) ──────────► oauthRoutes.js ──► store.js (authorizeRefreshGrant)
   ├── GET  /oauth/userinfo ───────────────────────► oidcRoutes.js  ──► oidcTokenService.js + sessions + clientRegistryService
   ├── GET  /.well-known/openid-configuration ─────► oidcRoutes.js  ──► oidcTokenService.js
   ├── GET  /.well-known/jwks.json ────────────────► jwksRoutes.js  ──► signingKeystore.js
   └── /api/admin/id/clients* & /audit-logs ───────► clientRegistryRoutes.js ──► authMiddleware.js
                                                                              └── clientRegistryService.js + auditLogService.js
```

### Component Summary (M1.1–M1.5)
- **M1.1 (`store.js`, `oauthRoutes.js`):** SHA-256 hashed authorization codes, atomic two-phase redemption (`initiateRedemption` -> `registerStagedRecords` -> `finalizeRedemption`), lease/fence-token protection, AES-256-GCM encrypted idempotency receipts (`TOKEN_RECEIPT_KEY`), refresh-token family rotation (`authorizeRefreshGrant`), replay compromise fencing (`compromised_ceremonies`), and `security_outbox` alerting.
- **M1.2 (`signingKeystore.js`, `jwksRoutes.js`):** RSA-2048 signing keys in `system_signing_keys/{kid}` with `_active_pointer` singleton serialization; private keys encrypted with AES-256-GCM (`12B` IV, `16B` tag, AAD `lanzar_signing_key:<kid>:v<kekVersion>`); staging/production KEK enforcement across `NODE_ENV` and `APP_ENV`; 5s internal cache vs. `Cache-Control: public, max-age=60` on `/.well-known/jwks.json`; `503` fail-closed when unavailable.
- **M1.3 (`oidcTokenService.js`, `oidcRoutes.js`):** RS256 `access_token` (900s, `token_use: 'access'`, `tenant_id`, `session_id`, `family_id`, `aud: [clientId, userinfo]`, `azp`) and `id_token` (`token_use: 'id'`, `nonce`, `auth_time`, scope-gated `email`/`profile`). Scoped Compatibility Adapter (`legacy_firebase`, `dual`, `oidc`). Explicitly documented as **OIDC-compatible with documented OIDC Core limitations** (no browser consent screen, no RP-initiated logout, etc.).
- **M1.4 (`clientRegistryService.js`, `clientRegistryRoutes.js`, `clients.js`):** Dual-collection `/tenants/{tenantId}/clients/{clientId}` + `/clients_index/{clientId}` preventing cross-tenant `clientId` collisions; strict character-for-character redirect URI matching; URL-parsed loopback filtering in production (`localhost`, `*.localhost`, `127.0.0.0/8`, `::1`, IPv4-mapped IPv6); `client_secret_post` SHA-256 + `timingSafeEqual`; static fallback ONLY when `indexSnap.exists` is false (Firestore errors reject and fail closed, never silently falling back).
- **M1.5 (`auditLogService.js`, `authMiddleware.js`, `oidcRoutes.js`, `oauthRoutes.js`):** Server-verified `req.adminContext` / `req.adminRole` from `authAdmin.verifyIdToken()` + Firestore `admins` collection; claim-based tenant isolation with explicit `platform_admin` exception; `disableClient()` / `enableClient()` lifecycle; atomic single-transaction client mutation + audit log `create()` with pre-generated `auditId` outside `runTransaction()` to prevent duplicate audit records on retries.

---

## 3. Complete 17-Stage Identity Lifecycle Trace

| Stage | Primary Component | Bound Identities Verified | Consistency & Finding |
| :-: | :--- | :--- | :--- |
| 1. Client registration | `clientRegistryRoutes.js` -> `clientRegistryService.js` | `tenantId` (from `req.adminContext`), `clientId` | `clients_index/{clientId}` prevents cross-tenant collision; atomic audit `create()` in same transaction. |
| 2. Client resolution | `clientRegistryService.resolveClient()` | `clientId`, `tenantId` | Looks up `clients_index` -> `/tenants/{t}/clients/{c}`; Firestore errors propagate (no silent fallback). |
| 3. Authorization request | `oauthRoutes.js` (`POST /authorize`) | `client_id`, `tenantId = client.tenantId` | Enforces PKCE `S256`, `client.enabled`, exact `redirect_uri`, `nonce` validation. |
| 4. User authentication | `oauthRoutes.js` (`authAdmin.verifyIdToken`) | `uid`, `email`, `auth_time` | Checks `users/{uid}.status === 'suspended'` and admin/MFA proof. |
| 5. Authorization-code creation | `store.create()` | `codeHash`, `uid`, `tenantId`, `clientId`, `scope`, `nonce` | Persists ceremony in `oauth_authorization_codes/{codeHash}`. |
| 6. Authorization-code redemption | `oauthRoutes.js` -> `store.initiateRedemption()` | `client_id`, `client_secret`, `redirect_uri`, `code_verifier`, `idempotencyKey` | Verifies `resolvedClient.enabled`, `verifyClientCredentials`, `resolvedClient.tenantId === record.tenantId` before staging session/family. |
| 7. Session creation | `oauthRoutes.js` (`sessionRef.create`) | `sessionId`, `uid`, `tenantId`, `clientId`, `familyId`, `ceremonyId` | Created `pending_activation` with `create()`, then activated in `finalizeRedemption()`. |
| 8. Token-family creation | `oauthRoutes.js` (`familyRef.create`) | `familyId`, `tenantId`, `clientId`, `uid`, `sessionId`, `ceremonyId` | Stored under `/tenants/{tenantId}/token_families/{familyId}`. |
| 9. Access-token issuance | `oidcTokenService.mintAccessToken()` | `sub`, `aud`, `azp`, `tenant_id`, `session_id`, `family_id`, `kid` | Signed RS256 via active key in `signingKeystore`. |
| 10. Access-token verification | `oidcTokenService.verifyAccessToken()` | `iss`, `aud`, `azp`, `token_use`, `tenant_id`, `exp`, `alg: RS256` | Rejects `id_token`, missing `tenant_id`, wrong `aud`, or `expectedTenantId` mismatch. |
| 11. UserInfo access | `oidcRoutes.js` (`GET /oauth/userinfo`) | `uid`, `sessionId`, `tenant_id`, `azp` | Online check of session active status, `sessionData.tenantId === payload.tenant_id`, `sessionData.clientId === payload.azp`, and live `client.enabled`. |
| 12. Refresh-token rotation | `oauthRoutes.js` -> `store.authorizeRefreshGrant()` | `tenantId`, `familyId`, `uid`, `sessionId`, `clientId` | Pre-authenticates `client_id`/`client_secret`/`tenantId` before mutating family; atomic rotation + replay compromise fencing. |
| 13. Session revocation | `sessionService` / `store` | `uid`, `sessionId` | Sets `status: 'revoked', revoked: true`; immediately blocks UserInfo and refresh. |
| 14. Token-family revocation | `store` (`compromised_ceremonies` + `familyRef`) | `tenantId`, `familyId`, `ceremonyId` | Replay compromises ceremony, revoking family and session atomically. |
| 15. Client suspension | `clientRegistryService.disableClient()` | `tenantId`, `clientId` | Sets `enabled: false, status: 'suspended'` + atomic audit log; blocks authorize, token, refresh, UserInfo immediately. |
| 16. Client reactivation | `clientRegistryService.enableClient()` | `tenantId`, `clientId` | Sets `enabled: true, status: 'active'` + atomic audit log; restores non-expired, unrevoked sessions. |
| 17. Admin audit logging | `auditLogService.js` | `actorUid`, `actorRole`, `targetTenantId`, `clientId`, `correlationId` | Atomic `tx.create()` for mutations; `create()` for denied/error attempts; secret keys redacted. |

---

## 4. Consolidated Firestore Data Model

| Collection Path | Scope | Owner / Writer | Key & Security Fields | TTL / Lifecycle |
| :--- | :--- | :--- | :--- | :--- |
| `/users/{uid}` | Global | Backend / Auth | `uid`, `email`, `status` (`active`/`suspended`), `tokenVersion` | Persistent |
| `/users/{uid}/sessions/{sessionId}` | Global UID, Tenant-bound field | `oauthRoutes` / `sessionService` | `sessionId`, `uid`, `tenantId`, `clientId`, `familyId`, `ceremonyId`, `status`, `revoked`, `expiresAt` | 7d `expiresAt` (needs Firestore TTL policy) |
| `/admins/{uid}` | Global | Platform Ops | `email`, `active`, `role` (`platform_admin`/`tenant_admin`), `tenantId`, `platformAdmin` | Persistent |
| `/system_signing_keys/{kid}` | Global | `SigningKeystore` | `kid`, `status` (`active`/`verify_only`/`revoked`), `publicJwk`, `encryptedPrivateKey`, `iv`, `authTag`, `kekVersion` | Retained during token TTL, then retired |
| `/system_signing_keys/_active_pointer` | Global Singleton | `SigningKeystore` | `activeKid`, `updatedAt` | Persistent |
| `/oauth_authorization_codes/{codeHash}` | Global | `FirestoreAuthorizationCodeStore` | `codeHash`, `clientId`, `tenantId`, `uid`, `codeChallenge`, `status`, `redemptionLockId`, `fenceToken`, `encryptedReceipt`, `expiresAt` | Short-lived (minutes; needs Firestore TTL policy) |
| `/compromised_ceremonies/{ceremonyId}` | Global | `FirestoreAuthorizationCodeStore` | `ceremonyId`, `reason`, `detectedAt` | Persistent / long-TTL |
| `/security_outbox/{outboxId}` | Global | `FirestoreAuthorizationCodeStore` | `status`, `retries`, `leaseExpiresAt`, `payload` | Processed -> completed/dead_letter |
| `/clients_index/{clientId}` | Global Index | `ClientRegistryService` | `clientId`, `tenantId`, `enabled`, `status`, `updatedAt` | Persistent |
| `/tenants/{tenantId}/clients/{clientId}` | Tenant | `ClientRegistryService` | `clientId`, `tenantId`, `redirectUris`, `compatibilityMode`, `tokenEndpointAuthMethod`, `clientSecretHash`, `enabled`, `status` | Persistent |
| `/tenants/{tenantId}/token_families/{familyId}` | Tenant | `oauthRoutes` / `store` | `familyId`, `sessionId`, `uid`, `tenantId`, `clientId`, `currentActiveTokenHash`, `sequenceNumber`, `rotatedTokenHashes`, `status`, `expiresAt` | 7d `expiresAt` (needs Firestore TTL policy) |
| `/tenants/{tenantId}/admin_audit_logs/{auditId}` | Tenant | `AuditLogService` | `auditId`, `actorUid`, `actorRole`, `targetTenantId`, `clientId`, `operation`, `outcome`, `correlationId`, `metadata` (redacted), `immutable` | Retention policy (append-only via rules) |

### Data Model & Scaling Assessment
- **Can it support future commercial tenants without major migration?** Yes for client registries, token families, and admin audit logs (all tenant-partitioned under `/tenants/{tenantId}/...`). **Partial limitation:** `/users/{uid}` and `/users/{uid}/sessions/{sessionId}` are keyed by global Firebase `uid`, which works for shared ecosystem accounts but will need `/tenants/{tenantId}/memberships/{uid}` if commercial tenants require isolated per-tenant user profiles/roles.
- **Global bottlenecks:** `clients_index/{clientId}` enforces globally unique `clientId`s across tenants (acceptable for low-write OAuth client creation); `system_signing_keys/_active_pointer` serializes key rotation (rare).
- **Security Rules vs. Server-Side Auth:** Admin SDK bypasses Firestore Security Rules; Rules must deny all direct client SDK access to `system_signing_keys`, `oauth_authorization_codes`, `security_outbox`, `compromised_ceremonies`, `clients_index`, `token_families`, and `admin_audit_logs` (`allow update, delete: if false;` even for privileged non-Admin-SDK actors).

---

## 5. Integration Findings, Weaknesses & Technical Debt
1. **JWKS Public Cache vs. Immediate Key Revocation (Design Trade-off):** Internal `SigningKeystore` invalidates within `<= 5s` (`DEFAULT_JWKS_CACHE_TTL_MS`), while `GET /.well-known/jwks.json` sets `Cache-Control: public, max-age=60`. External relying parties using cached JWKS can validate a revoked key's tokens for up to 60s unless they also call `/oauth/userinfo` (which enforces online session + keystore validation).
2. **Client Secret Lifecycle Debt:** Caller-supplied secrets (`>= 16` chars) use unsalted SHA-256 (`hashClientSecret`). Server-generated 256-bit CSPRNG secrets, one-time secret disclosure, and dual-secret rotation (`previousClientSecretHash` grace window) are not yet implemented.
3. **Disabled Client Cascading Revocation:** Disabling a client blocks all new/existing OAuth operations immediately, but existing session/token-family docs remain in Firestore (restored if re-enabled). Compromised clients lack a batch session/family revocation job.
4. **In-Memory Rate Limiter:** `rateLimiter.js` is process-local; multi-instance Cloud Run / Railway deployments need Redis/distributed rate limiting.
5. **Dual Admin Routers:** `adminRoutes.js` (Phase 1 platform-wide `/users`, `/audit-log`, `/clients`) coexists with `clientRegistryRoutes.js` (M1.4/M1.5 tenant-scoped `/clients`, `/audit-logs`) under `/api/admin/id`. Legacy `adminRoutes.js` should be reconciled with `req.adminContext` before commercial rollout.
6. **Code-Store Failure Cleanup on Tenant Mismatch:** In `oauthRoutes.js` `handleAuthorizationCodeGrant()`, if `resolvedClient.tenantId !== record.tenantId` after `initiateRedemption()`, it returns `400 invalid_grant` without calling `safeCleanup`, leaving the code in `IN_PROGRESS` until lease expiry (harmless fail-closed, but calling `safeCleanup('tenant_mismatch')` is cleaner).
