# LANZAR ID — Ecosystem Integration Roadmap

**Date:** 2026-11-18  
**Objective:** Sequence remaining ecosystem and commercial rollout steps safely without disrupting production.

---

## Phase 1 — Completed in NOVA Staging
1. **LANZAR ID Core Commercialization (Milestones C1–C4):** `GET /oauth/authorize`, scope allowlists, email verification fixes, multi-tenant `/api/dev` + Developer Console UI, dynamic client `allowedOrigins`, Stripe Test-Mode billing & webhooks, public product site (`auth/site/`), and Firestore hardening + `ttlExpiresAt` (`5/5 ACTIVE`).
2. **Threadline (`nova-staging`):** OIDC RS256 fallthrough, `axios` Bearer token interceptor, PKCE `useEffect` race fix, `ingestArchive` & `PUT` ownership enforcement, admin `storage-status` guard.
3. **LANZAR AI & Portal & Resume (`nova-staging`):** Fail-closed OIDC JWKS `AuthVerifier`, static `/data/` leak fix, PKCE frontend, Portal `crypto.getRandomValues` + removed client auto-provision bypass, Resume CORS allowlist.

## Phase 2 — Next Staging Remediation (Pending Approval for Separate Repos)
1. **LANZAR Tickets (`nova-staging` branch in `lanzar-tickets`):** Apply `customers.js` auto-provision fix, `firestore.rules` `accountId` validation, `req.admin` fix on `/api/admin/support/*`, and `authUid` alignment on claimed tickets.
2. **Pythos (`staging` after uncommitted work lands):** Wire `resolveCanonicalIdentity()` into `verifyAuthenticatedRequestUser()`, disable bidirectional password overwrite, and switch default login modal to central `auth.lanzar.me` PKCE with `POST /login/legacy-bridge` fallback.

## Phase 3 — Production Commercial Launch Gates (Requires Jon's Approval)
1. Enable Firebase Blaze + PITR + Backups + Delete Protection + TTL on production (`lanzar-95ae3`).
2. Attach Stripe Live Mode keys & price IDs (`FEATURE_STRIPE=enabled`) after counsel review of `LANZAR_ID_LEGAL_AND_SECURITY_REQUIREMENTS.md`.
3. Configure external uptime monitoring (`/api/id/ready`) + `DEAD_LETTER` alerting and transactional email provider (Resend/Postmark).
4. Promote verified `nova-staging` auth & portal changes to production.
