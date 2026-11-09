# LANZAR ID — Commercialization & Multi-Tenant IDaaS Roadmap
**Document ID:** LID-ROADMAP-006  
**Classification:** Confidential — Internal Master Strategic Blueprint  
**Status:** Authoritative Baseline (Phase 1 Approved)  
**Date:** November 8, 2026  
**Author:** Larry (Lead Systems Architect)  

---

## 1. Commercial Vision: LANZAR Identity as a Service (IDaaS)

While LANZAR ID is initially deployed to unify the internal LANZAR ecosystem (`portal`, `tickets`, `pythos`, `threadline`), the strategic long-term objective is to commercialize the platform into a multi-tenant Identity-as-a-Service (IDaaS) solution.

External businesses, educational institutions, SaaS developers, and partners will be able to license LANZAR's identity infrastructure, offloading authentication, compliance, session security, and user management.

---

## 2. Strict Architectural Boundaries (What NOT to Build Now)

To prevent premature over-engineering, Phase 1 through Phase 5 strictly observe the following implementation boundaries:

* **NO Automated Billing Engines:** We will not build complex subscription tiers, credit-card checkout flows, or automated recurring Stripe invoice charging for IDaaS tenants today.
* **NO Self-Service Commercial Onboarding:** External tenants will not have a public self-service signup portal during initial rollout.
* **NO Custom Domain SSL Automation:** We will not build multi-tenant automated Let's Encrypt SSL provisioning for custom third-party auth domains in Phase 1-5.
* **WHAT WE MUST DO TODAY:** Parameterize all schemas, APIs, tokens, and audit collections with `tenant_id` so that when commercialization launches, zero architectural rewriting of the core engine is required.

---

## 3. The Multi-Tenant Isolation Architecture

```
                                  [ LANZAR IDaaS PLATFORM ]
                                              │
         ┌────────────────────────────────────┼────────────────────────────────────┐
         ▼                                    ▼                                    ▼
┌──────────────────┐                 ┌──────────────────┐                 ┌──────────────────┐
│ ROOT SYSTEM      │                 │ COMMERCIAL       │                 │ COMMERCIAL       │
│ TENANT: "lanzar" │                 │ TENANT: "acme"   │                 │ TENANT: "edu_wpi"│
├──────────────────┤                 ├──────────────────┤                 ├──────────────────┤
│ Apps:            │                 │ Apps:            │                 │ Apps:            │
│ • portal         │                 │ • acme_saas_app  │                 │ • canvas_bridge  │
│ • tickets        │                 │ • acme_portal    │                 │ • student_lab    │
│ • pythos         │                 │ Users:           │                 │ Users:           │
│ • threadline     │                 │ • acme employees │                 │ • university org │
│ Users:           │                 │ Policy:          │                 │ Policy:          │
│ • LANZAR Clients │                 │ • Mandatory TOTP │                 │ • Passkey-first  │
└──────────────────┘                 └──────────────────┘                 └──────────────────┘
```

### 3.1 Tenant Data Partitioning Rules
1. **Logical Separation:** In Cloud Firestore, multi-tenant collections (clients, sessions, security logs) index on `tenant_id`. Queries must include `where('tenantId', '==', targetTenant)`.
2. **Global Identity vs. Tenant Membership:**
   - The human identity lives once in `/users/{uid}`.
   - The user's role, permissions, and status within a business live in `/memberships/{tenantId_uid}`.
   - A single user can be an administrator in `tenant: "lanzar"` and a standard member in `tenant: "acme_saas"`, with zero permission leakage between the two.
3. **Tenant Admin Boundary:** Organization administrators can only view, manage, and suspend memberships assigned to their specific `tenant_id`. They can never view global identity details from other tenants.

---

## 4. OIDC Provider Standards Roadmap (RFC 6749 / OIDC Core 1.0)

Today, LANZAR properties use an internal OAuth 2.0 PKCE bridge issuing Firebase Custom Tokens. For external commercial developers, LANZAR ID will expose a fully standards-compliant OpenID Connect Provider:

| Phase | Milestone | Deliverable |
| :--- | :--- | :--- |
| **Phase 1-5 (Current)** | Internal PKCE Bridge | Issues Firebase Custom Tokens for `*.lanzar.me` properties. |
| **Phase 6 (Preparation)** | OIDC Discovery & Metadata | Serves standard `/.well-known/openid-configuration`. |
| **Phase 7 (Commercial Alpha)** | RS256 JWKS Key Rotation | Serves rotating public RSA keys at `/oauth/jwks` for token validation. |
| **Phase 7 (Commercial Alpha)** | Standard OIDC ID & Access Tokens | Issues standards-compliant signed JWT `id_token` and scoped `access_token`. |
| **Phase 8 (Commercial Beta)** | Developer Console & API Keys | Self-service client application registration and webhook dispatcher. |

---

## 5. Future Monetization & Packaging Matrix

When commercial features are unlocked in Phase 7+, the platform will be packaged into three commercial tiers:

1. **Developer Tier:** Up to 2,500 Monthly Active Users (MAUs), standard email/password, social OAuth, hosted login, community support.
2. **Business Tier:** Up to 25,000 MAUs, custom branding, FIDO2 Passkeys, TOTP MFA, session revocation, organization management, 99.9% uptime SLA.
3. **Enterprise Tier:** Unlimited MAUs, dedicated database clusters, SAML 2.0 / Enterprise SSO (Okta, Azure AD), custom auth domain (`auth.customer.com`), dedicated audit export (SIEM/Splunk integration), 24/7 dedicated telephone support.
