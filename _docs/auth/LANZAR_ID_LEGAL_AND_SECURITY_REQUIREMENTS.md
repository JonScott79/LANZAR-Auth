# LANZAR ID — Legal, Policy & Security Documentation Requirements

> **STATUS: DRAFT — REQUIRES LEGAL COUNSEL REVIEW BEFORE PUBLISHING OR ACCEPTING PAYING CUSTOMERS.**

---

## 1. Terms of Service (Requirements)
- **Service Scope & SLA:** Define LANZAR ID as a multi-tenant authentication and OIDC identity service; specify beta/best-effort availability during limited commercial beta (no formal 99.99% SLA until post-Blaze production hardening).
- **Customer Responsibilities:** Customers are responsible for securing their own `client_secret` values, configuring accurate `redirectUris` and `allowedOrigins`, and complying with applicable laws for their end users.
- **Billing & Plan Limits:** Cover `Developer` (Free), `Launch` ($29.99/mo), `Growth` ($99.99/mo), `Scale` ($299.99/mo), and `Enterprise` (Custom); specify Stripe subscription renewal, cancellation (downgrade at period end or immediate), and suspension behavior on prolonged payment failure.
- **Usage-Based SMS MFA (Future):** State clearly that SMS delivery is metered per message with markup and subject to carrier/anti-abuse caps (no unlimited SMS).
- **Limitation of Liability & Indemnification:** Standard SaaS liability cap (e.g., fees paid in prior 12 months) and customer indemnification for unlawful end-user data collection.

## 2. Privacy Policy (Requirements)
- **Data Collected:**
  - Developer/Account data: name, email, organization/tenant metadata, Stripe customer/subscription IDs (payment card details handled exclusively by Stripe, never stored by LANZAR).
  - End-user authentication data: UID, email, verification status, TOTP enrollment status (encrypted secrets), active session metadata, IP address (for rate limiting and security audit logs).
- **Data Retention & Erasure:** Document `ProfileService.eraseUserAccount` behavior (deletes Firebase Auth user, `mfa_factors`, `sessions`, `central_sessions`, `session_slots`, `founders`, `customers`, `users`) and audit-log retention windows.
- **Subprocessors:** List Firebase/Google Cloud (Auth & Firestore), Railway (API & worker hosting), Netlify (frontend hosting), Stripe (billing), and transactional email/SMS providers once attached.

## 3. Acceptable Use Policy (AUP)
- Prohibit phishing/impersonation apps, credential-stuffing/brute-force testing against live endpoints, unauthorized scraping, spamming via email verification/password reset/SMS OTP endpoints, and registering misleading `redirectUris` or brand names.
- Reserve right to immediately suspend offending tenants (`TenantService.updateTenantStatus(..., 'suspended')`).

## 4. Public Security Overview (Factual Claims Only)
- **Supported & Verified Controls:**
  - OAuth 2.0 Authorization Code + mandatory PKCE (`S256`).
  - RS256 asymmetric JWT signing with AES-256-GCM encrypted private keys at rest and automated 4,200s grace-period key rotation.
  - Refresh-token family rotation with automatic replay detection and session revocation.
  - RFC 6238 TOTP MFA with AES-256-GCM encrypted secrets and single-use SHA-256 recovery codes.
  - Strict tenant isolation, immutable tenant-scoped admin audit logs, and exact-match redirect URI / CORS origin validation.
- **Explicitly Do NOT Claim Yet:** Do **not** claim SOC 2 Type II, ISO 27001, HIPAA, FedRAMP, or PCI-DSS Level 1 certification until formal third-party audits are completed.
