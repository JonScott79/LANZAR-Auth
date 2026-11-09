# LANZAR ID — Portal Mission Control UI & Telemetry Specification
**Document ID:** LID-UI-012  
**Classification:** Confidential — Internal Master Interface Specification  
**Status:** Authoritative Baseline (Phase 1 Approved)  
**Target:** `portal.lanzar.me/admin/*`  
**Date:** November 8, 2026  
**Author:** Larry (Lead Systems Architect)  

---

## 1. Executive Concept & Interface Philosophy

**LANZAR MISSION CONTROL** represents a radical departure from conventional web administration templates. It transforms the administrative interface of `portal.lanzar.me` into an **Orbital Operations Control Center** engineered specifically for the LANZAR ecosystem.

### 1.1 Aesthetic & Functional Principles
1. **Aerospace High-Precision Telemetry:** Monospace coordinates, crisp hairline borders, high-density telemetry readouts, atomic amber alerts, terminal emerald nominal indicators, and LANZAR aerospace gold highlights.
2. **Actionable Density with Zero Clutter:** Every pill, readout, counter, and indicator reflects live, verified system state. Decorative dummy numbers and inactive controls are strictly forbidden. If an integration is staged or mock, it carries an explicit `[STAGED]` diagnostic badge.
3. **Keyboard-First Workflow:** Full keyboard navigation via a Global Command Palette (`Cmd/Ctrl + K`) allowing operators to jump to any user, client app, or audit log instantly.
4. **Universal Responsive Shell:** Desktop-first high-resolution workstation layout scaling down seamlessly to tablet and mobile emergency interfaces.

---

## 2. Information Architecture & Navigation Shell

The existing `portal/src/admin` application shell is redesigned around an **Orbital Command Rail** (collapsible sidebar) providing instant access to 10 dedicated operational decks:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              MISSION CONTROL ARCHITECTURE                              │
├────────────────────┬───────────────────────────────────────────────────────────────────┤
│ Top Telemetry Bar  │ System Clock (UTC) | Health Status | Active Operator | Global Cmd │
├────────────────────┼───────────────────────────────────────────────────────────────────┤
│ Orbital Rail       │ 1. 🛰 Operations Overview    (Sector radar, token velocity)        │
│ (Collapsible Nav)  │ 2. 🔑 Identity Explorer      (Search, inspect, suspend, restore)   │
│                    │ 3. 🛡 Security Center        (MFA adoption, passkey metrics)       │
│                    │ 4. 📦 Application Registry   (OAuth clients, redirect whitelist)   │
│                    │ 5. 🏢 Organization Desk      (Multi-tenancy, org memberships)      │
│                    │ 6. 🎖 Founder Programs       (Authoritative badges & numbering)    │
│                    │ 7. ⚡ Product Entitlements   (Tiers, quotas, complimentary perks)  │
│                    │ 8. 📡 Infrastructure Monitor (Firebase, Railway, Netlify telemetry)│
│                    │ 9. 📜 Audit Center           (Immutable tamper-resistant stream)   │
│                    │ 10.⚙ System Configuration    (Emergency step-up, rate limits)      │
└────────────────────┴───────────────────────────────────────────────────────────────────┘
```

---

## 3. Specifications for the 10 Operational Decks

### Deck 01: Operations Overview (Sector Radar)
* **Real-Time Telemetry Counters:**
  - Total Active Identities across ecosystem.
  - Active Device Sessions across all subdomains.
  - Token Issuance Velocity (PKCE exchanges per hour).
  - MFA Enforcement Ratio (% of accounts with Passkey or TOTP).
* **System Incident Ticker:** Live stream of system warnings (e.g. rate limit trips, failed admin challenges).
* **Quick Action Launchers:** Emergency User Search, Emergency Global Revocation.

---

### Deck 02: Identity Explorer
* **Global Filterable User Table:**
  - Columns: UID, Normalized Email, Display Name, Role, MFA Factors, Verified Badges, Account Status, Last Seen.
  - Multi-attribute search bar (instant search by email, phone, UID, or company name).
  - Status filters (`All`, `Active`, `Suspended`, `Unverified`).
* **Identity Detail Slide-Over Drawer:**
  - Displays user profile, authoritative founder documents, active device sessions, and login geography.
  - Quick actions: Resend Verification Email, Dispatch Password Reset, Force Sign Out Everywhere, Suspend/Reactivate.

---

### Deck 03: Security Center
* **MFA Adoption Analytics:** Breakdown of enrolled factors (WebAuthn Passkeys vs. TOTP Authenticator vs. Recovery Codes).
* **Lockout & Challenge Desk:** Real-time view of accounts currently throttled due to failed MFA attempts.
* **Dual-Admin MFA Recovery Queue:** Approval interface for emergency MFA resets requiring secondary sign-off (SOP-05).

---

### Deck 04: Application Registry
* **Client App Inventory:** Cards for registered properties (`portal`, `tickets`, `pythos`, `threadline`, commercial partners).
* **Client Configuration Drawer:**
  - Client ID and display title.
  - Allowed Redirect URIs (strict whitelist validation).
  - Allowed CORS Origins.
  - Token issuance metrics and PKCE enforcement toggles.

---

### Deck 05: Organization & Multi-Tenancy Desk
* **Tenant Directory:** Overview of isolated organization partitions (`tenant_id: "lanzar"`, etc.).
* **Organization Detail View:**
  - Tenant administrators and assigned member accounts.
  - Domain routing and custom branding parameters.
  - Tenant-scoped audit stream filter.

---

### Deck 06: Founder Programs Ledger
* **Authoritative Program Cards:**
  - `LANZAR ID Founder`
  - `Pythos Founder`
  - `Portal Founder`
  - `Traveling Founder`
  - `Threadline Founder`
* **Founder Roster & Award Interface:**
  - Searchable list of awarded founders with sequential badge numbers and grant timestamps.
  - **"Award Founder Designation" Modal:** Product selection, sequential number assigner, mandatory audit justification input.
  - **Revocation Drawer:** Authoritative deactivation with mandatory operational reason logging.

---

### Deck 07: Product Entitlements Desk
* **Tier Management:** Assignment of service tiers (`free`, `student`, `pro`, `enterprise_managed`).
* **Complimentary Access Grants:** Interface to grant honorary/promotional access with optional expiration dates (`validUntil`).
* **Feature Flag Dispatcher:** Enable/disable beta features per account.

---

### Deck 08: Infrastructure Telemetry
* **Health Monitoring Gauges:**
  - Firebase Authentication API latency.
  - Cloud Firestore read/write operations and quota utilization.
  - Railway Identity API (`auth-api.lanzar.me`) container CPU, memory, and uptime.
  - Netlify build minute quota usage across properties.
* **Diagnostic Flags:** Real-time warnings when external APIs approach monthly quota thresholds.

---

### Deck 09: Audit Center (Security Stream)
* **Live Tamper-Resistant Log Stream:**
  - Timestamp, Actor UID/Email, Event Action Name, Target Resource, Originating IP, Success/Failure status.
  - Full-text search and JSON diff viewer showing previous vs. updated document states.
  - Read-only interface enforcing Firestore anti-tampering rules.

---

### Deck 10: System Configuration
* **Operational Control Panel:**
  - Session TTL parameters (authorization code lifespan, refresh token rules).
  - Emergency Global Step-Up Authentication toggle (forces re-auth during active security events).
  - Phone OTP Rate Limiting & Monthly Spending Guards.
  - Database backup trigger and export verification.

---

## 4. Design System & Component Library Tokens

```css
:root {
  /* Mission Control Palette */
  --mc-bg-deep: #080b11;            /* Deep Space Void */
  --mc-bg-surface: #0f1523;         /* Brushed Titanium Panel */
  --mc-bg-elevated: #161e31;        /* Command Deck Card */
  --mc-border-subtle: #1e293b;      /* Hairline Telemetry Border */
  --mc-border-active: #334155;      /* Active Border */
  
  /* Telemetry Signals */
  --mc-gold: #ffd700;               /* LANZAR Aerospace Gold */
  --mc-cyan: #06b6d4;               /* Phosphor Telemetry Cyan */
  --mc-amber: #f59e0b;              /* Warning / Challenge Amber */
  --mc-emerald: #10b981;            /* Nominal / Verified Emerald */
  --mc-rose: #f43f5e;               /* Alert / Revoked Rose */
  
  /* Monospace Readouts */
  --mc-font-mono: 'JetBrains Mono', 'Fira Code', monospace;
  --mc-font-sans: 'Inter', -apple-system, sans-serif;
}
```

---

## 5. Security & Safety Controls

1. **Destructive Action Confirmations:** Any operation that revokes sessions, suspends accounts, or modifies entitlements requires a two-step confirmation modal with explicit typing of the target email or action word (e.g. `CONFIRM SUSPEND`).
2. **Step-Up Authentication for Operators:** Administrative sessions require re-authentication if an operator attempts a sensitive mutation after 15 minutes of idle time.
3. **Zero Visual Surprise Bleed:** The finished design will be delivered complete and functional, integrated seamlessly into `portal/src/admin` without piecemeal aesthetic compromises.
