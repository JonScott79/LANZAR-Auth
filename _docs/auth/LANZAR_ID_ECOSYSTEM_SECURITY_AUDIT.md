# LANZAR ID — Ecosystem Security Audit & Remediation Log

**Audit Date:** 2026-11-18  
**Scope:** Security defects discovered during Stage One inspection across all LANZAR apps, with remediation status in `nova-staging`.

---

## 1. Remediated in `nova-staging` (Verified)

| ID | App | Severity | Original Defect & Root Cause | Implementation & Files Changed | Commit | Verification |
|---|---|---|---|---|---|---|
| **SEC-TL-01** | Threadline | **CRITICAL** | Frontend never sent `Authorization: Bearer` tokens (only `x-user-uid`), causing all API calls to fail with `401` in cloud/production mode. | Added `axios` request interceptor in `threadline/auth/AuthProvider.jsx` attaching Firebase ID token / OIDC `access_token`. | `c936897` | `npm run build` + `testNovaAuth.js` (7/7) |
| **SEC-TL-02** | Threadline | **HIGH** | `POST /api/import` (`ingestArchive`) accepted `targetThreadlineId` without verifying ownership, allowing cross-user data injection. | Added `isAuthorizedOwner(existing.owner_id, request.uid)` check in `threadline/backend/api/import.js`. | `c936897` | Code verified + build pass |
| **SEC-TL-03** | Threadline | **HIGH** | `AuthProvider.jsx` called `completePkceExchangeIfPresent()` without `await` before `onAuthStateChanged`, racing silent SSO and flashing `<Login />`. | Wrapped in async IIFE awaiting PKCE exchange before `onAuthStateChanged`. | `c936897` | `npm run build` pass |
| **SEC-TL-04** | Threadline | **MEDIUM** | `PUT /api/threadlines/:id` used strict `!==` instead of `isAuthorizedOwner`; `GET /api/admin/storage-status` allowed any authenticated user. | Updated `backend/api/threadlines.js` (`isAuthorizedOwner`) and `backend/api/admin.js` (require `database_restore` scope or admin role). | `c936897` | `npm run build` pass |
| **SEC-AI-01** | LANZAR AI | **CRITICAL** | `AuthVerifier.verify()` failed open when Firebase Admin was missing and trusted `test_*`/`user_*`/`mock_*` and `X-User-Id` headers unconditionally. | Rewrote `AI/server/auth-verifier.js` to fail closed (401), verify LANZAR ID OIDC RS256 JWKS (`aud=ai`), check Firebase `verifyIdToken(token, true)`, and gate test tokens behind `AI_ALLOW_TEST_TOKENS=true`. | `d687b4e` | `AI/tests/test_ai_hardening.js` (3/3 PASS) |
| **SEC-AI-02** | LANZAR AI | **CRITICAL** | `AI/dev-server.js` served `/data/*.json`, `/server/*`, and `.env` over HTTP with `Access-Control-Allow-Origin: *` and no inference rate limits. | Blocked `/data/`, `/server/`, `/engine/`, `/tests/`, `.env*`; fixed `ROOT_DIR + path.sep` traversal; added origin allowlist, route auth guards, and `/api/inference/*` rate limiter. | `d687b4e` | `node --check AI/dev-server.js` |
| **SEC-AI-03** | LANZAR AI | **CRITICAL** | `AI/js/ui/auth-modal.js` rendered fake identity buttons (`user_dr_vance`, etc.) and interpolated `displayName`/`email`/`uid` into `innerHTML` unescaped; `auth-service.js` stored tokens in `localStorage`. | Replaced fake buttons with real LANZAR ID PKCE `S256` (`AI/js/auth/auth-service.js`), added `escapeHtml()`, and moved session storage to `sessionStorage`. | `d687b4e` | Code verified |
| **SEC-PTL-01** | Portal | **HIGH** | `portal/src/firebase/customers.js` fell back to returning an in-memory `{ active: true }` customer even if Firestore `setDoc` failed or user was unprovisioned. | Removed client-side auto-provisioning fallback; returns `null` when Firestore `users/{uid}` is missing or `active !== true`. | `d687b4e` | `portal` Vite build pass |
| **SEC-PTL-02** | Portal | **MEDIUM** | `lanzar-auth-modal.js` and `portal/src/pages/Login.jsx` generated OAuth `state` with `Math.random()`. | Replaced with `crypto.getRandomValues` (`generateCryptoState`). | `d687b4e` | `portal` Vite build pass |
| **SEC-RSM-01** | Resume | **MEDIUM** | `resume/backend/server.js` used unrestricted `app.use(cors())`. | Restricted CORS via `RESUME_ALLOWED_ORIGINS` allowlist. | `d687b4e` | Syntax verified |

---

## 2. Identified Blockers Requiring Jon's Approval / Separate Staging Branch

| ID | App | Severity | Finding & Impact | Proposed Remediation |
|---|---|---|---|---|
| **SEC-TKT-01** | Tickets (`main`) | **CRITICAL** | `tickets/website/frontend/src/firebase/customers.js` has the same in-memory `{ active: true }` auto-provisioning bypass + `firestore.rules` allows any `request.auth != null` user to create tickets and spoof `accountId`. | Apply the same `customers.js` fix + tighten `firestore.rules` `accountId` check on a `tickets` `nova-staging` branch. |
| **SEC-TKT-02** | Tickets (`main`) | **HIGH** | `/api/admin/support/challenge` & `/verify` read `req.user` instead of `req.admin` (runtime `TypeError`); `SUPPORT_OTP_SECRET` has hardcoded fallback; `/api/billing/webhook` accepts unsigned payloads if `STRIPE_WEBHOOK_SECRET` is unset. | Fix `req.admin`, fail closed on missing secrets in prod. |
| **SEC-TKT-03** | Tickets (`main`) | **MEDIUM** | `/api/inquiries` & `/api/tickets/claim` write `customerUid` while `firestore.rules` checks `authUid`, making claimed tickets unreadable via client SDK. | Align field to `authUid` or update `firestore.rules`. |
| **SEC-PYT-01** | Pythos (`staging/...`) | **CRITICAL** | `lanzarIdService.resolveCanonicalIdentity()` is dead code (never called in `verifyAuthenticatedRequestUser` or `studentAuthMiddleware`), so suspended users aren't blocked and `pythosLegacyUid` isn't bridged. | Wire `resolveCanonicalIdentity()` into `verifyAuthenticatedRequestUser` once Pythos LANZAR ID integration is authorized. |
| **SEC-PYT-02** | Pythos (`staging/...`) | **HIGH** | Bidirectional password overwrite between local `scrypt` and Firebase Auth; stateless 7-day `lanzar.*` tokens lack revocation; `pythos_lanzar_id_token` stored in `localStorage`. | Retire local `scrypt` form in favor of central `auth.lanzar.me` PKCE + explicit account linking (see `LANZAR_ID_ACCOUNT_PRESERVATION_PLAN.md`). |
