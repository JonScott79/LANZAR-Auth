# LANZAR ID — Master Architecture Specification
**Document ID:** LID-ARCH-001  
**Classification:** Confidential — Internal Master Architecture Directive  
**Status:** Authoritative Baseline (Phase 1 Approved)  
**Target Authority:** `auth.lanzar.me`  
**Central Account Hub:** `id.lanzar.me`  
**Gateway & Mothership:** `lanzar.me`  
**Admin Operations Center:** `portal.lanzar.me` (Portal Mission Control)  
**Date:** November 8, 2026  
**Author:** Larry (Lead Systems Architect)  

---

## 1. Executive Summary & Architectural Mandate

LANZAR ID is the foundational identity, authentication, session management, and authorization infrastructure for the entire LANZAR ecosystem. It transitions the organization from fragmented, per-application authentication silos into a unified identity provider (IdP).

### 1.1 Core Axiom
**One LANZAR identity. One credential. One central security authority. Every LANZAR property.**

A user registers once, verifies their email once, establishes multi-factor authentication once, and seamlessly accesses all authorized services (`lanzar.me`, `portal.lanzar.me`, `tickets.lanzar.me`, `pythos.lanzar.me`, `threadline.lanzar.me`, and future commercial offerings) without fragmented logins or divergent passwords.

### 1.2 Non-Negotiable Architectural Principles
1. **Separation of Credential Authority & Identity Profiles:** Firebase Authentication (`lanzar-95ae3`) acts as the secure, low-level credential store (passwords, email verification pipeline, password reset tokens), while LANZAR ID (`auth.lanzar.me`) acts as the authoritative Identity Provider, issuing scoped tokens and managing profiles, sessions, and entitlements in Cloud Firestore.
2. **Server-Enforced Session Security:** Client-side checks are never considered security controls. Every protected backend endpoint verifies identity, account status, token validity, and active session status server-side on every request.
3. **Derived Profile Views:** Authoritative entitlement and founder records reside in their dedicated sub-collections. The global profile contains strictly derived summaries to prevent multi-master synchronization drift.
4. **Universal Standards-Based TOTP (Amendment #001):** Full compatibility with Microsoft Authenticator, Google Authenticator, and all RFC 6238-compliant applications via standard `otpauth://` provisioning and QR codes. Zero vendor-specific licenses or third-party fees.
5. **Phone Authentication Infrastructure with Deferred Provider Activation (Amendment #002):** Provider-abstracted SMS service (`smsService.js`) built and tested with `MockSMSProvider`. Live provider connectivity deferred behind `SMS_LIVE_ENABLED=false` until pricing and commercial logistics are authorized.
6. **Commercial IDaaS Multi-Tenancy from Day 1:** All schemas and token claims enforce tenant boundaries (`tenant_id`). The LANZAR ecosystem operates as root tenant `lanzar`, ensuring clean external customer isolation in future phases without database rewrites.
7. **Preservation of Functioning Infrastructure:** No production changes, secret rotations, credential migrations, or session invalidations occur without explicit approval and gated rollback rehearsals.

---

## 2. High-Level Ecosystem Topology

```
                                  [ MANAGED GOOGLE CLOUD / FIREBASE (lanzar-95ae3) ]
                             ┌──────────────────────────────────────────────────────────────┐
                             │  Authoritative Passwords (Managed PBKDF2/scrypt)             │
                             │  Google Identity Services | Transactional Reset/Verify Pipe  │
                             └──────────────────────────────┬───────────────────────────────┘
                                                            │
                                  [ LANZAR ID AUTHORITY (auth.lanzar.me / Railway) ]
                             ┌──────────────────────────────▼───────────────────────────────┐
                             │  OAuth 2.0 / PKCE Engine (/authorize, /exchange, /token)     │
                             │  FIDO2 / WebAuthn Passkeys & TOTP MFA (mfaService)           │
                             │  Server-Side Session Registry & Revocation Gatekeeper        │
                             │  Tenant & Entitlement Dispatcher (tenant_id: "lanzar")       │
                             └──────────────┬───────────────────────────────┬───────────────┘
                                            │                               │
             ┌──────────────────────────────┴───────────────┐               │
             ▼                                              ▼               ▼
┌───────────────────────────────┐ ┌───────────────────────────┐ ┌───────────────────────────┐
│      MOTHERSHIP GATEWAY       │ │  CENTRAL ACCOUNT MANAGER  │ │  PORTAL MISSION CONTROL   │
│       https://lanzar.me       │ │   https://id.lanzar.me    │ │ https://portal.lanzar.me  │
│ ───────────────────────────── │ │ ───────────────────────── │ │ ───────────────────────── │
│ • Public Marketing Experience │ │ • Shared Account Core     │ │ • Orbital Operations Deck │
│ • Authenticated "My LANZAR":  │ │ • Profile & Avatar Editor │ │ • Identity & Tenant Desk  │
│   - Unified Identity Bar      │ │ • Passkey & TOTP Admin    │ │ • Founder Programs Ledger │
│   - Connected App Launch Deck │ │ • Session Kill-Pad        │ │ • Security Audit Stream   │
│   - Founder Showcase Deck     │ │ • GDPR Data Portability   │ │ • App Registry & Scopes   │
└──────────────┬────────────────┘ └─────────────┬─────────────┘ └─────────────┬─────────────┘
               │                                │                             │
               └────────────────────────────────┴──────────────┬──────────────┘
                                                               │
                                  [ ECOSYSTEM SERVICE PROVIDERS (CLIENTS) ]
                             ┌─────────────────────────────────▼────────────────────────────┐
                             │ • pythos.lanzar.me (AI Tutor)                                │
                             │ • tickets.lanzar.me (Support & Billing)                      │
                             │ • threadline.lanzar.me (Enterprise Software)                 │
                             │ • Future Commercial IDaaS Clients (External Organizations)   │
                             └──────────────────────────────────────────────────────────────┘
```

---

## 3. The Three Architectural Tiers

### 3.1 Tier 1: Central Authentication Authority (`auth.lanzar.me`)
* **Hosting & Backend:** Netlify frontend with Express/Node.js backend hosted on Railway (`auth-api.lanzar.me` / `wtk9m980.up.railway.app`).
* **Responsibilities:**
  - User self-service registration and credential validation.
  - OAuth 2.0 Authorization Server implementing Proof Key for Code Exchange (PKCE) according to RFC 7636.
  - Step-up Multi-Factor Authentication (FIDO2 Passkeys, TOTP, Recovery Codes).
  - Issuance of single-use, 60-second authorization codes.
  - Exchange of codes for Firebase Custom Tokens enriched with verified claims (`sub`, `tenant_id`, `tokenVersion`, `role`).
  - Account suspension checks on authentication attempts.

### 3.2 Tier 2: Central Account Management (`id.lanzar.me` & `lanzar.me`)
* **Responsibilities:**
  - Self-service profile management (display name, avatar, bio).
  - Security settings: password changes, passkey registration, TOTP provisioning.
  - Active session monitoring and individual device revocation.
  - Global "Sign Out Everywhere" (increments `tokenVersion` and revokes refresh tokens).
  - Connected application permission inspection and revocation.
  - GDPR/CCPA personal data export and account erasure requests.
* **Shared Component Architecture:**
  - `id.lanzar.me` operates as a dedicated, standalone web application.
  - `lanzar.me` embeds the identical core management package (`@lanzar/id-ui`) into an authenticated slide-out/modal view ("My LANZAR").
  - Under no circumstances will profile management logic be implemented separately for the Mothership and the ID portal.

### 3.3 Tier 3: Client Applications (Service Providers)
* **Applications:** `portal.lanzar.me`, `tickets.lanzar.me`, `pythos.lanzar.me`, `threadline.lanzar.me`.
* **Integration Model:**
  - Client applications NEVER render raw username/password forms.
  - Unauthenticated access redirects the browser to `https://auth.lanzar.me/authorize` with registered `client_id`, `redirect_uri`, cryptographically random `state`, and PKCE `code_challenge`.
  - Upon return to `/callback`, client exchanges code and `code_verifier` at `https://auth-api.lanzar.me/exchange`.
  - Client consumes the returned Custom Token via `signInWithCustomToken(customToken)`, establishing an isolated local session in browser storage (IndexedDB).
  - Client backend APIs enforce token validity, revocation status, and session validity server-side on every request.

---

## 4. Multi-Tenancy Architecture (Foundation for Commercial IDaaS)

To allow future commercialization without restructuring internal data, LANZAR ID incorporates strict tenant partitioning from Day 1:

```
                                [ GLOBAL IDENTITY: usr_0192a8 ]
                                               │
                       ┌───────────────────────┴───────────────────────┐
                       ▼                                               ▼
       [ MEMBERSHIP: tenant: "lanzar" ]                [ MEMBERSHIP: tenant: "acme" ]
       - Role: "admin"                                 - Role: "user"
       - Entitlements: ["portal_admin", "tickets"]     - Entitlements: ["acme_billing"]
       - Status: "active"                              - Status: "active"
```

1. **Root Tenant:** The internal LANZAR ecosystem is assigned `tenant_id: "lanzar"`.
2. **Membership Model:** Users maintain a single global authentication profile in `/users/{uid}`, while authorization and roles are tracked in `/memberships/{tenantId_uid}`.
3. **Data Isolation:** All database collections supporting multi-tenant operations (clients, sessions, audit logs, entitlements) index and filter on `tenant_id`. Cross-tenant queries are blocked at both Firestore Security Rules and backend middleware.
4. **Commercial Boundary:** No billing engine, self-service onboarding, or external tenant consoles are built in Phase 1-5. The database and API schemas are simply parameterized to accept `tenant_id` to prevent retrofitting costs later.

---

## 5. Architectural Decision Matrix

| Dimension | Option A: Firebase Auth + LANZAR ID (Selected) | Option B: Custom Argon2id Authority (Rejected) |
| :--- | :--- | :--- |
| **Credential Security** | Managed by Google Infrastructure (PBKDF2/scrypt, brute-force mitigation). | Custom implementation required; liability for salt/hash handling. |
| **Email Deliverability** | Built-in verification and reset pipeline with Google SPF/DKIM. | Requires custom SMTP/Brevo infrastructure, deliverability warming, and per-email costs. |
| **Existing Compatibility** | Zero-downtime bridge; `portal`, `tickets`, and `auth` already share `lanzar-95ae3`. | Requires ripping out Firebase Admin SDK from all existing backends. |
| **MFA Support** | Self-managed FIDO2 Passkeys + TOTP in Node.js (Zero external license cost). | Custom WebAuthn/TOTP server required. |
| **Operating Cost** | \$0.00 additional monthly cost on current tiers. | Added database compute, storage, and transactional email costs. |

---

## 6. Document Governance & Traceability

This master architecture specification is complemented by 12 specialized architecture, security, and operations runbooks. Any proposed changes to system topology, credential ownership, or token lifecycle must be submitted as formal architectural revisions to this document.
