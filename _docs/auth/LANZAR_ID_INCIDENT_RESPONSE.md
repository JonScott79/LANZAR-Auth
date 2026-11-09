# LANZAR ID — Incident Response & Emergency Procedures
**Document ID:** LID-INC-010  
**Classification:** Confidential — Internal Master Security Directive  
**Status:** Authoritative Baseline (Phase 1 Approved)  
**Date:** November 8, 2026  
**Author:** Larry (Lead Systems Architect)  

---

## 1. Incident Classification & Severity Matrix

Security events affecting LANZAR ID are classified into four severity tiers governing escalation and response time:

| Severity | Definition | Response Target | Escalation Path |
| :--- | :--- | :--- | :--- |
| **SEV-1 (Critical)** | Compromise of Firebase service account, Railway environment secrets, mass unauthorized credential modification, or active remote code execution. | **Immediate (< 15 mins)** | Lead Architect, Operations Director, Executive Team. |
| **SEV-2 (Major)** | Mass authentication failure, widespread token exchange failure, failure of email verification pipeline, or unauthorized elevation of administrative privileges. | **< 1 hour** | Lead Architect, On-Call Security Engineer. |
| **SEV-3 (Moderate)**| Targeted account takeover of a single customer profile, anomalous rate-limit spikes on phone OTP, or isolated session fixation attempts. | **< 4 hours** | Senior Support Engineer, Security Analyst. |
| **SEV-4 (Minor)** | Isolated brute-force attempts on single accounts mitigated by automated rate limiters, or individual user lockouts. | **Next Business Day**| Support Operations. |

---

## 2. Emergency Compromise Procedures

### 2.1 Firebase Admin Service Account Compromise
If a Firebase service account private key (`service-account.json` or Railway environment variable) is leaked or compromised:

1. **Immediate Revocation in Google Cloud Console:**
   - Log into Google Cloud Console > **IAM & Admin > Service Accounts**.
   - Locate the compromised service account (`lanzar-95ae3-firebase-adminsdk-...`).
   - Immediately delete the compromised key under the **Keys** tab.
2. **Issue Replacement Service Account Key:**
   - Generate a new JSON private key.
   - Update `FIREBASE_SERVICE_ACCOUNT_KEY` in the Railway Production Environment Dashboard (`wtk9m980.up.railway.app`).
   - Trigger an immediate redeployment of `auth-backend`.
3. **Mass Invalidation of Active Sessions:**
   - Run the emergency script `scripts/emergency-global-revocation.js` to trigger `admin.auth().revokeRefreshTokens()` across all active accounts.
4. **Audit Log Inspection:**
   - Query GCP Cloud Audit Logs (`cloudaudit.googleapis.com`) to identify any unauthorized Firestore read/write operations executed by the compromised key during the exposure window.

---

### 2.2 MFA Encryption Pepper Compromise
If the `MFA_ENCRYPTION_KEY` used to encrypt TOTP secrets is compromised:

1. **Provision Key V2:**
   - Generate a new 32-byte CSPRNG key.
   - Add `MFA_ENCRYPTION_KEY_V2` to the Railway production environment.
2. **Execute Re-encryption Migration:**
   - Run `scripts/rotate-mfa-encryption-keys.js`. The script iterates over `/mfa_factors`, decrypts secrets with V1, re-encrypts with V2, updates `kv: 2`, and writes back to Firestore.
3. **Decommission V1:**
   - Remove `MFA_ENCRYPTION_KEY` from the environment.
   - Promote `MFA_ENCRYPTION_KEY_V2` to primary.

---

### 2.3 Mass Targeted Account Takeover Defense
If an automated credential stuffing attack bypasses initial defenses:

1. **Activate Global Step-Up Mode:**
   - In Portal Mission Control > System Configuration, toggle **"Global Emergency Step-Up"**.
   - This enforces mandatory re-authentication and step-up challenges on all sessions interacting with sensitive API endpoints.
2. **IP Rate Limit Tightening:**
   - Deploy Railway WAF rule restricting `/authorize` and `/exchange` endpoints to max 5 requests per minute per IP address.
3. **Automated Account Protection:**
   - Accounts targeted by more than 10 failed credential submissions within 5 minutes are automatically transitioned to `status: 'locked_pending_verification'`.
   - Automated password reset notices are dispatched to affected users.

---

## 3. Breach Notification & Regulatory Obligations

If customer personal data (names, emails, phone numbers) is confirmed to have been accessed by an unauthorized entity:
1. **Regulatory Timelines:** Under GDPR / CCPA obligations, notice must be prepared for data protection supervisory authorities within **72 hours** of breach confirmation.
2. **User Notification Protocol:**
   - Notification must be dispatched in plain language detailing:
     - The nature of the incident and data fields involved.
     - Confirmation that raw passwords were NOT exposed (managed by Google PBKDF2/scrypt).
     - Remedial actions taken by LANZAR (session invalidation, secret rotation).
     - Recommended protective steps for users (password change, passkey enrollment).
3. **Post-Incident Review:** A comprehensive Root Cause Analysis (RCA) must be finalized within 5 business days and published internally to the documentation suite.
