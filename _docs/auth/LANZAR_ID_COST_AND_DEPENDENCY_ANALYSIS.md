# LANZAR ID — Cost, Quota & Dependency Analysis
**Document ID:** LID-COST-013  
**Classification:** Confidential — Internal Master Financial & Infrastructure Reference  
**Status:** Authoritative Baseline (Phase 1 Approved)  
**Date:** November 8, 2026  
**Author:** Larry (Lead Systems Architect)  

---

## 1. Executive Cost Summary & Zero-Spend Mandate

All Phase 1 through Phase 5 engineering work is designed to operate **100% within our existing infrastructure allocations and free-tier quotas**. 

No paid service upgrades, paid Google Cloud Identity Platform (GCIP) activations, paid third-party SMS packages, or new cloud resource subscriptions may be activated without explicit written authorization from the project owner.

---

## 2. Infrastructure Inventory & Quota Reality Check

### 2.1 Google Cloud Platform & Firebase Authentication (`lanzar-95ae3`)
* **Core Credential Engine:** Standard Firebase Authentication (Spark Free Tier).
* **Monthly Active Users (MAU) Quota:**
  - Up to **50,000 MAUs per month at \$0.00 cost**.
  - Current Ecosystem MAU Estimate: < 1,500 MAUs.
  - Headroom: > 97% available headroom within the free tier.
* **Email Verification & Password Reset Real Quotas (CORRECTION INCORPORATED):**
  - **The "Unlimited" Myth Debunked:** Firebase transactional emails are NOT unlimited.
  - Standard unverified projects are rate-limited to **100 password reset & verification emails per day** across the entire project.
  - Once a custom sending domain (`auth.lanzar.me`) is verified in the Firebase console, the quota scales to approximately **1,000 emails per day** under fair-use monitoring.
  - **Spam & Bounces:** Google monitors bounce rates. If invalid registrations trigger a > 5% bounce rate, Google may temporarily suspend automated email dispatch.
  - **Future Custom SMTP / Brevo Transition:** When custom-branded HTML templates from `noreply@auth.lanzar.me` are required, Brevo's transactional tier costs \$0.00 for up to 300 emails/day, or \$25.00/month for up to 20,000 emails/month.

### 2.2 Self-Managed TOTP & WebAuthn Passkeys (Amendment #001 Cost Analysis)
* **The Universal TOTP Advantage (Amendment #001):**
  - **Zero SMS Delivery Cost:** By supporting standard RFC 6238 TOTP, users authenticate via free mobile applications (**Microsoft Authenticator**, **Google Authenticator**, **1Password**, **Bitwarden**).
  - **Zero Client Licensing Fees:** Supporting these apps requires no enterprise agreements, API keys, or licensing royalties paid to Microsoft or Google.
  - **Zero Provider Lock-In:** Standard `otpauth://` provisioning operates across any compliant app without vendor-specific SDKs.
* **Compute Footprint on Railway:**
  - WebAuthn cryptographic verification (`@simplewebauthn`) and AES-256-GCM encryption/decryption for TOTP keys introduce minimal CPU overhead (~1.2ms per verification).
  - Memory consumption of `consumedStepCache` and `pendingEnrollmentCache`: < 2 MB for up to 10,000 active concurrent authentications.
  - Fully contained within our existing \$5.00/month Railway base container.

### 2.3 Cloud Firestore Database (`lanzar-95ae3`)
* **Free Tier Allocation:**
  - Storage: 1 GB free.
  - Document Reads: 50,000 reads/day.
  - Document Writes: 20,000 writes/day.
  - Document Deletes: 20,000 deletes/day.
* **Current Utilization & Headroom:**
  - Current storage: ~45 MB across active collections.
  - Identity collection additions (`/users`, `/founders`, `/sessions`, `/security_logs`) will add ~1.2 KB per active user.
  - Projected identity reads on normal operations: < 8,000 reads/day. Zero budget overrun risk.

### 2.4 Railway Backend Compute (`wtk9m980.up.railway.app`)
* **Current Plan:** Railway Hobby / Pro container execution.
* **Monthly Cost:** Covered under existing \$5.00/month base allocation.
* **Usage:** `auth-backend` runs as a lightweight Express microservice consuming ~95MB RAM and < 2% CPU at idle.

### 2.5 Netlify Frontends Hosting (`lanzar.me`, `portal.lanzar.me`, `auth.lanzar.me`)
* **Monthly Quota:** 300 build minutes per month, 100 GB bandwidth.
* **Audit Finding:** The free tier monthly build minute cap was previously reached due to automated CI/CD churn.
* **Remediation Protocol:** To prevent build lockouts, developers will stage and bundle builds locally (`npm run build`) and deploy direct production artifacts via Netlify CLI or push only consolidated releases, completely avoiding unnecessary build minute burn.

---

## 3. Phone Verification (SMS) Cost & Quota Analysis (Amendment #002)

SMS delivery is a significant financial liability if not strictly controlled. Under **Architectural Amendment #002**, live SMS provider activation is **strictly deferred**.

| SMS Delivery Provider | Unit Cost (US/Canada `+1`) | Unit Cost (International) | Toll Fraud Defense | Status in LANZAR ID |
| :--- | :--- | :--- | :--- | :--- |
| **Mock SMS Provider** | **\$0.00 (Simulated)** | **\$0.00** | Immune | **ACTIVE & TESTED (DEFAULT)** |
| **Twilio Verify** | \$0.05 per successful verification | \$0.05 - \$0.25+ | Automated Fraud Guard | **DEFERRED (UNACTIVATED)** |
| **Brevo SMS** | \$0.015 per outbound SMS | \$0.04 - \$0.30+ | Manual Rate Limits | **DEFERRED (UNACTIVATED)** |

### Strict Operational & Spending Controls:
1. **Mock Mode Active:** The codebase default is `MockSMSProvider`. Zero external API calls are executed and zero carrier fees are incurred.
2. **Production Log Sanitization:** OTP codes are redacted from production server outputs to prevent shoulder-surfing or log leakage.
3. **Pre-Activation Requirements:** When live SMS activation is evaluated in a future directive:
   - A hard spending ceiling of **\$25.00/month** must be established in the provider console.
   - International destination whitelisting must restrict delivery exclusively to authorized countries (`+1`).
   - Rate limiting must strictly enforce max 1 OTP dispatch per 60 seconds per phone number and max 3 requests per IP per hour.

---

## 4. Cost Comparison: Standard Architecture vs. Upgraded GCIP

| Expense Category | Recommended Architecture (Phase 1-5) | Premature Upgrade to GCIP (Rejected) |
| :--- | :--- | :--- |
| **Authentication Core** | \$0.00 (Firebase Spark Free Tier) | \$0.00 (< 50k MAUs), then \$0.0055/MAU |
| **Native Multi-Tenancy** | \$0.00 (Firestore Logical Scoping) | \$0.0055/MAU across all active tenants |
| **MFA TOTP & Passkeys** | \$0.00 (Self-Managed Node.js) | \$0.0055/MAU + SMS gateway fees |
| **Identity Datastore** | \$0.00 (Within Firestore Free Quota) | \$0.00 |
| **Backend Compute** | \$5.00/mo (Existing Railway Base) | \$5.00/mo (Existing Railway Base) |
| **SMS Verification** | \$0.00 (Disabled / Staged) | Variable (\$0.05+ per verification) |
| **TOTAL MONTHLY RUN RATE** | **\$5.00 / month (Existing baseline)** | **\$50.00 - \$250.00+ / month** |

---

## 5. Decision & Operational Directive

We retain the **Standard Architecture**. We do not activate Google Cloud Identity Platform paid services or live SMS delivery. The system is engineered to provide enterprise-grade security and multi-tenancy without increasing operational infrastructure bills.
