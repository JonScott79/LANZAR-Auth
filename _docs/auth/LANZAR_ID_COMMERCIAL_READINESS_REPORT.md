# LANZAR ID — Production Hardening & Final Commercial Readiness Report

**Date:** 2026-11-16  
**Target Environment Verified:** NOVA Staging (`https://auth.lanzar.me/nova`, `https://auth-api-nova.lanzar.me`, `https://lanzar-auth-nova.netlify.app`, Firebase `lanzar-95ae3-dev`)  
**Production Status:** Untouched (`https://auth-api.lanzar.me/api/id/health` nominal, `appEnv: "production"`)

---

## Part A: Billing-Dependent Production Hardening Runbook (Blaze Activation)

> **Do NOT run these commands until Blaze billing is explicitly approved and linked.**

Once Blaze is enabled on the target GCP/Firebase project (`PROJECT_ID`), execute:

```bash
# 1. Enable Firestore Point-in-Time Recovery (PITR) & Delete Protection
gcloud firestore databases update --database="(default)" --project="$PROJECT_ID" \
  --enable-pitr --enable-delete-protection

# 2. Configure Scheduled Daily Backups (7-day retention)
gcloud firestore backups schedules create --database="(default)" --project="$PROJECT_ID" \
  --retention=7d --recurrence=daily

# 3. Enable Native Firestore TTL on authorization_codes.expiresAt (already stores native Timestamp)
gcloud firestore fields ttls update expiresAt \
  --collection-group=authorization_codes --enable-ttl --project="$PROJECT_ID"
```

*Note: `token_families.expiresAt`, `sessions.expiresAt`, `central_sessions.*ExpiresAt`, and `admin_idempotency.expiresAt` currently store ISO strings or epoch numbers and require a dual-read/Timestamp migration before enabling Firestore TTL on those collections.*

---

## Part B: Formal Commercial Readiness Classification (Phase 7)

| Area / Item | Status | Notes |
|---|---|---|
| OAuth 2.0 Auth-Code + PKCE `S256` (`GET` & `POST /authorize`, `/oauth/token`) | **COMPLETE** | Verified on NOVA staging; `GET /oauth/authorize` & scope allowlists added in C1. |
| OIDC Discovery & JWKS (`/.well-known/*`, `/oauth/userinfo`) | **COMPLETE** | Verified with RS256 & 60s/300s cache headers. |
| RS256 Keystore, AES-256-GCM Encryption & Automated Retirement | **COMPLETE** | 4,200s grace period active in `worker.js`. |
| Refresh Token Rotation & Replay Revocation | **COMPLETE** | Tenant-scoped `token_families` + automatic family revocation. |
| TOTP MFA + Recovery Codes | **COMPLETE** | Fail-closed `MFA_ENCRYPTION_KEY` in staging/prod. |
| Threadline Reference Integration (`threadline/backend` + frontend) | **COMPLETE** | Live browser E2E verified + `testNovaAuth.js` (7/7 PASS). |
| Multi-Tenant Core (`/tenants`, RBAC, suspension, dynamic CORS `allowedOrigins`) | **COMPLETE** | Verified in `test-commercial-c2.cjs` (4/4 PASS) + live browser. |
| Self-Service Developer Console (`/api/dev` + Developer tab UI) | **COMPLETE** | Live verified: org creation, app registration, secret rotation, audit logs fixed in C4. |
| Stripe Test-Mode Billing & Webhook Engine (`/api/billing/webhook`) | **COMPLETE** | Verified in `test-commercial-c3.cjs` (3/3 PASS); `sk_live_` strictly blocked. |
| Public Product Website, Quick-Start Docs, Competitor Matrix, Legal Drafts | **COMPLETE** | Built in `auth/site/` and `_docs/auth/`. |
| Firestore PITR, Delete Protection, Daily Backups, Native TTL | **REQUIRES BILLING** | Blocked on Firebase Blaze activation. |
| Live Stripe Checkout / Paid Subscriptions | **REQUIRES EXTERNAL APPROVAL** | Requires Stripe test/live keys & price IDs in Railway env vars. |
| Transactional Email Delivery (Verification / Password Reset) | **REQUIRES EXTERNAL APPROVAL** | Currently uses Firebase Auth client emails; backend `/register` & `/password/forgot` need Resend/Postmark key for custom branding. |
| External Uptime & `DEAD_LETTER` Alerting | **REQUIRES EXTERNAL APPROVAL** | `/api/id/ready` & `/api/admin/id/telemetry` ready; needs Better Stack / UptimeRobot + webhook URL. |
| Legal Counsel Sign-Off on ToS / Privacy / AUP | **REQUIRES EXTERNAL APPROVAL** | Draft requirements prepared; must be reviewed before commercial launch. |
| Usage-Based SMS MFA (Twilio + Metered Billing) | **IN PROGRESS / DEFERRED** | Deferred to post-beta (`LiveSMSProviderStub` throws intentionally). |
| WebAuthn / Passkeys & Distributed Redis Rate Limiting | **DEFERRED** | Deferred to post-beta / multi-replica scale. |

---

## Part C: Executive Answers

1. **What prevents us from accepting our first paying customer?**  
   Attaching Stripe API/price keys, enabling Firebase Blaze (PITR + backups + delete protection), and publishing counsel-reviewed ToS/Privacy policies.
2. **What is essential before a limited beta (5–10 developers)?**  
   Deploy C4 fixes (`listTenantAuditLogs` fix + `AUTH_HUB_URL` env var on staging), attach free-tier external uptime monitoring to `/api/id/ready`, and enable Blaze on the live beta Firebase project.
3. **What can safely wait until after launch?**  
   Usage-based SMS MFA, WebAuthn/Passkeys, SAML/SCIM enterprise SSO, and Redis distributed rate limiting (until >1 API replica).
4. **What introduces additional recurring costs?**  
   Firebase Blaze (pay-as-you-go, ~$0–$5/mo at beta scale), transactional email once exceeding free tier (~$15–$20/mo), Twilio SMS (usage pass-through + markup), and Redis (~$5–$20/mo when horizontally scaling).
5. **What creates security or operational risk if skipped?**  
   Launching without Firestore PITR/backups/delete protection, launching without external `DEAD_LETTER`/uptime alerts, or claiming unverified compliance certifications.
6. **Shortest responsible path to our first paying customer:**  
   Enable Blaze + backups/PITR → attach Stripe Test → Live keys for `Developer (Free)` and `Launch ($29/mo)` → add free-tier Better Stack uptime monitor → publish reviewed ToS/Privacy + `auth/site/` → onboard first 5 beta SaaS teams using the Threadline Quick-Start.
