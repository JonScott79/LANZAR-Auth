# LANZAR ID — Integration Readiness Matrix

**Last Updated:** 2026-11-18  
**Legend:** `Not Started` | `In Progress` | `Implemented` | `Verified` | `Blocked` | `Excluded (Marketing Only)`

---

| Application / Component | Code Status | Local Testing | Deployed Staging Verification | Production Status |
|---|---|---|---|---|
| **LANZAR ID Core (`auth-api-nova`)** | **Implemented** (`nova-staging`, `39e7cd6`) | `test-ttl-migration` (5/5), `test-nova-issuer` (5/5), `test-staging-bootstrap` (10/10), `test-phase1-acceptance` (55/55), `C1` (5/5), `C2` (4/4), `C3` (3/3) | **Verified:** `auth-api-nova.lanzar.me`, `lanzar-auth-nova.netlify.app`, Stripe Test Mode (10/10), Firestore PITR/Backups/TTL (`5/5 ACTIVE`) | Untouched (`auth.lanzar.me`, `auth-api.lanzar.me`, `lanzar-95ae3`) |
| **Threadline** | **Implemented** (`nova-staging`, `c936897`) | `testNovaAuth.js` (**7/7 PASS**), Vite build PASS | **Verified:** `threadline-nova.netlify.app` (`6afdd0e20502e3b0d7265dfd`) — PKCE login, `/oauth/token` 200, `page.reload()` persistence (`/api/id/session/validate` 200), Sign Out (`DELETE /sessions` + `/logout` 200). (`threadline-nova-api` deferred for cost.) | Untouched |
| **LANZAR Portal** | **Implemented** (`nova-staging`) | Vite build PASS (`650ms`); `base64UrlEncode` + `Idempotency-Key` + emulator guard fixes | **Verified:** `lanzar-portal-nova.netlify.app` (`6aff23875acb44d0479cce2f`) — `/provision` 200, `/authorize` 200, `/exchange` 200, `/session/validate` 200, dashboard & Sign Out 200. (Note: direct reload on `/dashboard` returns 404 until SPA rewrite is added.) | Untouched (`portal.lanzar.me`) |
| **LANZAR AI** | **Implemented** (`nova-staging`, `623edb7`) | `test_ai_hardening.js` (**3/3 PASS** + `AI_ALLOW_TEST_TOKENS` blocked in `NODE_ENV=production`) | **Verified (Frontend PKCE + OIDC Logout):** `lanzar-ai-nova.netlify.app` — PKCE redirect, `POST /oauth/token` 200, Auth modal & `DELETE /api/id/sessions/:id` 200. (Backend API not hosted on Railway to avoid cost.) | Untouched (`ai.lanzar.me`) |
| **LANZAR Tickets** | **Implemented** (`lanzar-tickets:nova-staging`, `a4a9e4e`) | `testTicketsSecurity.js` (**6/6 PASS**), `node --check server.js`, Vite build PASS (`844ms`) | Branch `nova-staging` pushed; not yet deployed to staging Netlify/Railway | Untouched (`main`, `tickets.lanzar.me`, `api.tickets.lanzar.me`) |
| **Pythos** | **Implemented (Local)** (`staging/specialist-engines-integration`, uncommitted preserved) | `test-lanzar-secret-lifecycle.js` (**8/8 PASS**), canonical identity & safe linking wired | Excluded from NOVA/prod OAuth changes pending Jon's review | Untouched (`master`, `pythos.lanzar.me`) |
| **LANZAR Resume** | **Implemented (Backend + App.jsx)** (`nova-staging`) | `testResumeAuth.js` (**2/2 PASS**) | `resume/backend` OIDC `/api/me` verified; `resume/frontend/src/App.jsx` written (lacks `package.json`/`index.html` in worktree) | None |
| **LANZAR Homepage (Mothership)** | **Implemented** (Protected Prod) | Inspected (`lanzar-id-mothership.js`) | Protected production property | Untouched (`lanzar.me`) |
| **LANZAR IT & Web** | **Excluded (Marketing Only)** | Verified static HTML/CSS/JS | N/A (No auth required) | Live static (`it.lanzar.me`, `web.lanzar.me`) |
