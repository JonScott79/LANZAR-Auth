# LANZAR ID — Integration Readiness Matrix

**Last Updated:** 2026-11-18  
**Legend:** `Not Started` | `In Progress` | `Implemented` | `Verified` | `Blocked` | `Excluded (Marketing Only)`

---

| Application / Component | Readiness Status | Evidence & Environment | Remaining Blockers / Approval Gates |
|---|---|---|---|
| **LANZAR ID Core (`auth-api-nova`)** | **Verified (Staging)** | Live NOVA staging: OIDC Discovery/JWKS, PKCE `GET`/`POST /authorize`, `/oauth/token` refresh rotation, TOTP MFA, Multi-Tenant `/api/dev`, Stripe Test Mode (`10/10`), Firestore PITR/Backups/TTL (`5/5 ACTIVE`). | Blaze + Stripe Live Mode + Counsel ToS/Privacy + Uptime Alerting for **Production** promotion. |
| **Threadline (`nova-staging`)** | **Verified (Staging)** | Browser E2E login/signup/logout on `threadline-nova.netlify.app` + `testNovaAuth.js` (`7/7 PASS`) + `c936897` (`axios` Bearer interceptor, `import.js` ownership guard, `vite build` pass). | Optional `threadline-nova-api` Railway deploy (deferred for cost). |
| **LANZAR Portal (`portal/`)** | **Implemented (Staging Ready)** | PKCE `LanzarAuthModal`, `sessionManager.js` (`/api/id/session/validate`), `d687b4e` (`crypto.getRandomValues` state, removed client `users/{uid}` auto-provision bypass), `vite build` pass. | Legacy `Account.jsx` Firebase password reset & `DeckSecurity.jsx` mock cleanup. |
| **LANZAR AI (`AI/`)** | **Implemented (Local/Staging)** | `d687b4e`: Fail-closed `AuthVerifier` + OIDC RS256 JWKS (`test_ai_hardening.js` `3/3 PASS`), blocked `/data/` & `/server/` static leaks, origin allowlist, `auth-service.js` PKCE `S256`, XSS escaping. | Staging Netlify/Railway deployment & end-to-end browser test when hosted. |
| **LANZAR Tickets (`tickets/website`)** | **In Progress (`main` Protected)** | PKCE + silent SSO already active in prod `tickets.lanzar.me`; Stage 1 audit found `customers.js` auto-provision bypass, `accountId` rule gap, `req.user` vs `req.admin` crash, and `customerUid` mismatch. | Requires Jon's approval to branch/remediate on `tickets` `nova-staging`. |
| **Pythos (`C:\Projects\lanzar\pythos`)** | **Blocked (Approval & Uncommitted Work)** | 3-way hybrid auth (`Google` + `PKCE` + `scrypt`); `resolveCanonicalIdentity()` is dead code; uncommitted work in `staging/specialist-engines-integration`. | Excluded from NOVA/prod changes until Jon authorizes Pythos integration. |
| **LANZAR Resume (`resume/`)** | **Implemented (Skeleton)** | `d687b4e` restricted CORS in `resume/backend/server.js`. Greenfield app. | Register `'resume'` client & wire `LanzarAuth` when product features are built. |
| **LANZAR Homepage (`homepage/`)** | **Verified (Protected Prod)** | Optional `mothership` PKCE SSO drawer (`lanzar-id-mothership.js`). | Protected production property; keep untouched unless authorized. |
| **LANZAR IT (`IT/`) & Web (`web/`)** | **Excluded (Marketing Only)** | Verified static HTML/CSS/JS marketing sites with zero backend or protected routes. | None — do not add unnecessary login systems. |
