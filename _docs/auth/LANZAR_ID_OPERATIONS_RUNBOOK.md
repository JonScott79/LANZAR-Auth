# LANZAR ID — Operations Runbook for Portal Mission Control
**Document ID:** LID-OPS-009  
**Classification:** Confidential — Internal Operational Runbook  
**Target Audience:** LANZAR Support Engineers, System Administrators, Mission Control Operators  
**Status:** Authoritative Baseline (Phase 1 Approved)  
**Date:** November 8, 2026  
**Author:** Larry (Lead Systems Architect)  

---

## 1. Mission Control Operational Principles

Operators managing identity through **Portal Mission Control** (`portal.lanzar.me`) hold high-trust credentials. All operations are subject to four inviolable rules:
1. **Mandatory Least Privilege:** Use standard customer support tools for lookup; escalate to administrative mutations only when authorized.
2. **Mandatory Justification Notes:** Every manual entitlement change, suspension, or founder badge assignment requires a detailed justification note recorded in the immutable audit stream.
3. **Dual-Control for Destructive Actions:** Account deletions and emergency MFA resets require two authorized administrators.
4. **Zero Credential Exposure:** Operators can never view user passwords, password hashes, or raw MFA secret keys.

---

### SOP-06: Phone Verification & Deferred SMS Operational Guidelines (Amendment #002)
* **Operational Status of SMS:**
  - Live SMS sending is **strictly unactivated** (`SMS_LIVE_ENABLED=false`).
  - All phone verification tests and staging workflows utilize `MockSMSProvider`.
  - Support operators cannot trigger real outbound SMS messages and must not promise automated SMS delivery to callers until a live provider contract is authorized.
* **Manual Caller Phone Verification:**
  - When a caller quotes their phone number, operators cross-reference the `phoneNumber` and `phoneVerified` status in Mission Control.
  - If a customer requires manual phone verification assistance, the operator executes SOP-01 (Caller Verification) and verifies ownership through out-of-band email challenge.

---

## 3. Summary of Operational Directives

### SOP-01: Inbound Support Caller Verification
When a customer contacts support by phone or chat requesting account assistance:
1. Navigate to **Portal Mission Control > Identity Explorer**.
2. Search for the caller using their **Normalized Email** or **E.164 Phone Number**.
3. Confirm identity via the **Caller Verification Protocol**:
   - Verify non-sensitive account attributes (e.g. registered company name, active services).
   - If sensitive operations are requested, click **"Trigger Verification Challenge"**. This sends a time-limited 6-digit challenge code to the customer's verified email or phone.
   - Caller must read back the code. Confirm code in Mission Control before proceeding.

---

### SOP-02: Managing Product-Specific Founder Designations
Founder badges confer lifetime prestige and product-specific perks. They must be managed with care:

#### Granting a Founder Designation:
1. Open the target user's record in Mission Control.
2. Navigate to the **Founder Programs Ledger** tab.
3. Click **"Award Founder Designation"**.
4. Select the specific product program:
   - `LANZAR ID Founder`
   - `Pythos Founder`
   - `Portal Founder`
   - `Traveling Founder`
   - `Threadline Founder`
5. Enter the sequential **Founder Number** (if applicable).
6. Enter a mandatory **Audit Justification Note** (e.g., *"Early beta participant - Approved by Jon Scott"*).
7. Click **"Confirm Award"**. The system authoritatively creates `/users/{uid}/founders/{programId}` and updates the derived badges on the user's profile.

#### Revoking a Founder Designation:
1. Locate the active badge in the user's Founder Ledger.
2. Click **"Revoke Designation"**.
3. Enter a mandatory **Revocation Reason** (e.g., *"Account consolidation into primary business profile"*).
4. Confirm revocation. The badge is deactivated and removed from the user's derived view.

---

### SOP-03: Session Inspection & Remote Revocation
When a customer reports an unrecognized login or suspicious device activity:
1. In the user detail drawer, select **"Active Device Sessions"**.
2. Inspect the list of active devices, IP addresses, browsers, and last seen timestamps.
3. To terminate a single suspicious device:
   - Click **"Revoke Session"** next to the target device. The server immediately rejects further requests from that device.
4. If account takeover is suspected:
   - Click **"Force Global Revocation (Sign Out Everywhere)"**.
   - This atomically increments the user's `tokenVersion` and revokes all Firebase refresh tokens across every device.
   - Advise the customer to execute a password reset immediately.

---

### SOP-04: Account Suspension & Reactivation
To temporarily lock an account due to non-payment, suspected fraud, or abuse:
1. In Mission Control, locate the user record.
2. Click **"Account Actions > Suspend Account"**.
3. Select the suspension reason code and enter operational notes.
4. Click **"Execute Suspension"**.
   - The user's status updates to `suspended`.
   - Core Firebase credentials are automatically disabled (`disabled: true`).
   - Active tokens are globally revoked.
5. To reactivate, click **"Restore Account"** and document the resolution justification.

---

### SOP-05: Emergency MFA Reset (Dual-Admin Approval)
If a user is completely locked out of their account due to lost devices and missing recovery codes:
1. **Primary Operator Action:**
   - Execute SOP-01 Caller Verification with identity document verification.
   - In Mission Control, click **"Security Center > Request Emergency MFA Reset"**.
   - Upload or reference the verification ticket evidence.
   - Submit request. A notification is sent to senior administration.
2. **Secondary Administrator Sign-Off:**
   - A secondary administrator (distinct from the requesting operator) logs into Mission Control.
   - Reviews the verification evidence in the **Pending Approvals Queue**.
   - Clicks **"Authorize MFA Reset"**.
3. **Execution & Notification:**
   - An automated security notice is dispatched to the user's email.
   - The user's `/mfa_factors` record is cleared, allowing them to log in with password and immediately re-enroll their authenticators.
