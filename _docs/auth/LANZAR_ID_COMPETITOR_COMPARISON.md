# LANZAR ID — Competitor Comparison & Positioning

> **Scope:** Grounded strictly in verified LANZAR ID capabilities as of NOVA staging (Milestones C1–C3). No unsupported security certifications or unbuilt features are claimed.

---

## 1. Planned Commercial Pricing

| Plan | Monthly Price | Included Apps | Included MAU | Key Capabilities |
|---|---:|---:|---:|---|
| **Developer** | Free | 3 | 1,000 | OIDC + PKCE S256, RS256 JWKS, TOTP MFA, Refresh Rotation |
| **Launch** | $29/mo | 10 | 10,000 | Everything in Developer + SMS MFA (usage-billed) |
| **Growth** | $99/mo | 25 | 50,000 | Everything in Launch + Custom Domain support (planned) |
| **Scale** | $299/mo | 100 | 250,000 | Higher limits, priority support, multi-admin orgs |
| **Enterprise** | Custom | 1,000+ | Custom | Dedicated terms & SLA |

*Note: SMS MFA is billed strictly on usage with a transparent markup—never unlimited.*

---

## 2. Capability Matrix vs. Competitors

| Capability | LANZAR ID (Current) | Auth0 | WorkOS | Stytch | Descope | FusionAuth | Logto | Frontegg |
|---|---|---|---|---|---|---|---|---|
| **OIDC + PKCE S256 + RS256 JWKS** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| **Automated Signing-Key Rotation** | Yes (AES-256-GCM + 4,200s grace) | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| **Refresh Token Replay Detection** | Yes (family revocation) | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| **TOTP MFA + Recovery Codes** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| **Multi-Tenant Organizations & RBAC** | Yes (`/api/dev`) | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| **Self-Service Developer Console** | Yes (Launch UI) | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| **WebAuthn / Passkeys** | Not yet (roadmap) | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| **Enterprise SAML 2.0 / SCIM** | Not yet (roadmap) | Yes ($$$) | Yes ($125/conn) | Yes | Yes | Yes | Yes | Yes |
| **Usage-Based SMS MFA** | Post-beta add-on | Yes | Add-on | Yes | Yes | Bring Twilio | Bring Twilio | Yes |
| **Predictable Flat Entry Tier** | **$29/mo (10k MAU)** | Jumps steeply after 7.5k–10k MAU | $125/SAML conn | Usage-based | $249+ Pro tiers | Self-host or $100+ cloud | $16+ Pro | $99–$399+ |

---

## 3. Competitive Positioning

- **Where LANZAR ID Wins Today:**
  1. **Predictable SaaS Pricing:** Clear `$0 / $29 / $99 / $299` tiers without Auth0-style sudden enterprise-tier jumps or per-connection SAML taxes for early-stage SaaS teams.
  2. **Standards-First, Zero Vendor Lock-In:** Standard OIDC Discovery, RS256 JWKS, and PKCE S256—verified end-to-end with standard Node `crypto` (no proprietary SDK lock-in required).
  3. **Strong Token & Session Hygiene Out of the Box:** Automatic refresh-token family replay revocation, 4,200s zero-downtime key-retirement grace windows, per-device session management, and tenant-scoped audit logs.
- **Honest Current Limitations (Do Not Overclaim):**
  - No SAML 2.0 / SCIM directory sync yet (compared to WorkOS / Auth0 / Frontegg).
  - No WebAuthn / Passkeys yet.
  - No SOC 2 Type II / HIPAA / ISO 27001 certification yet—do not claim third-party certifications until audited.
