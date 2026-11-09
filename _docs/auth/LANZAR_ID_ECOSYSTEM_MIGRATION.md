# LANZAR ID — Ecosystem Migration & Project Consolidation Blueprint
**Document ID:** LID-MIGR-007  
**Classification:** Confidential — Internal Master Operations Plan  
**Status:** Authoritative Baseline (Phase 1 Approved)  
**Date:** November 8, 2026  
**Author:** Larry (Lead Systems Architect)  

---

## 1. Migration Mandate & Zero-Downtime Axiom

Migrating running production applications (`portal`, `tickets`, `pythos`, `threadline`) to LANZAR ID carries operational and data-loss risks. To guarantee zero disruption to customers:
1. **No Cold Cut-Overs:** Existing login mechanisms remain fully active until their LANZAR ID replacements are proven and tested in staging.
2. **Reversible Transitions:** Every migration step must have a documented, rehearsed rollback procedure capable of execution in under 5 minutes.
3. **Mandatory Identity Mapping & Checksum Verification:** No user record is moved without cryptographic integrity verification and collision handling policies.

---

## 2. Six-Step Migration Safety Protocol

Before any user accounts or database collections are migrated, the engineering team must execute the following 6-step protocol:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                          SIX-STEP MIGRATION SAFETY PROTOCOL                           │
├──────────────────┬──────────────────┬──────────────────┬──────────────────┬────────────┤
│ Step 1:          │ Step 2:          │ Step 3:          │ Step 4:          │ Step 5:    │
│ Pre-Migration    │ Identity Mapping │ Staging Dry-Run  │ Cryptographic    │ Rollback   │
│ Inventory & Hash │ & Conflict Rules │ Migration        │ Integrity Verify │ Rehearsal  │
└──────────────────┴──────────────────┴──────────────────┴──────────────────┴────────────┘
                                         │
                                         ▼
                           Step 6: Controlled Production Window
```

### Step 1: Pre-Migration Inventory & Checksums
* Generate complete JSON exports of all source collections:
  - Pythos: `reports/lanzar_id_store/accounts.json` and Firestore `pythos/app/lanzar_id_accounts`.
  - Threadline: Cloud Firestore collections in `lanzar-ba111` (`users`, `cases`, `transcripts`).
* Compute SHA-256 checksum of export manifests. Archive export manifests in immutable cold storage.

### Step 2: Canonical Identity Mapping & Conflict Resolution Matrix
When consolidating accounts across platforms, email collisions may occur (e.g., an email registered in Pythos also exists in Portal):

| Collision Scenario | Source A | Source B | Resolution Policy |
| :--- | :--- | :--- | :--- |
| **Identical Email & UID** | Portal (`lanzar-95ae3`) | Threadline (`lanzar-ba111`) | Merge records. Retain `lanzar-95ae3` UID. Link Threadline cases to canonical UID. |
| **Identical Email, Different UID** | Portal (`lanzar-95ae3`) | Pythos (`lanzar_...`) | The `lanzar-95ae3` UID becomes canonical. Pythos learning history and memory records are re-keyed to the canonical UID. |
| **Pythos Only (No Firebase Auth)** | Pythos `accounts.json` | None in Firebase Auth | Provision new Firebase Auth user; assign temporary random password and dispatch "Claim your LANZAR ID" verification email. |
| **Email Conflict on Different Humans**| Unverified vs Verified | Only the verified email holder retains ownership. Unverified account flagged for administrative review. |

### Step 3: Staging Environment Dry-Run
* Execute the complete import script against a staging Firebase project (`lanzar-staging`).
* Verify that 100% of accounts and relationships are imported without errors or orphaned foreign keys.

### Step 4: Cryptographic Integrity Verification
* Automated validation script verifies:
  1. Record count matches: `count(source) === count(destination)`.
  2. Data fidelity: Email, creation timestamps, and profile metadata match byte-for-byte.
  3. Relational integrity: Every imported case or memory record successfully resolves to an active user UID.

### Step 5: Rollback Rehearsal
* Simulate a production failure during cut-over.
* Revert the staging client application `.env` configurations to point back to the legacy authentication endpoints.
* Verify that the rollback completes and users can log in via legacy paths in under 3 minutes.

### Step 6: Controlled Production Execution
* Execute the production migration during a scheduled low-traffic maintenance window.
* Monitor live logs in Portal Mission Control for token exchange errors or access rejections.

---

## 3. Application-by-Application Migration Plans

### 3.1 Pythos (`pythos.lanzar.me`)
* **Current State:** Dual authentication. Uses local `scrypt` hashing in `lanzarIdService.js` and issues `lanzar.*` HMAC-SHA256 tokens.
* **Target State:** Consumes standard LANZAR ID tokens via `auth.lanzar.me`.
* **Execution Strategy:**
  1. Update `js/lanzarIdAuth.js` to open `https://auth.lanzar.me/authorize?client_id=pythos` when users click "Sign In".
  2. In `server/server.js`, update `studentAuthMiddleware` to validate Firebase ID tokens and extract `req.studentUid`.
  3. Run batch script to migrate records from `reports/lanzar_id_store/accounts.json` into canonical Firestore `/users/{uid}`.
  4. Retain legacy `lanzar.*` HMAC token verification in `studentAuthMiddleware` for 30 days to prevent logging out existing active student sessions.

### 3.2 Portal (`portal.lanzar.me`)
* **Current State:** React SPA with embedded login modal; already implements prototype PKCE exchange in `App.jsx`.
* **Target State:** Seamless redirect to `auth.lanzar.me`.
* **Execution Strategy:**
  1. Replace `pages/Login.jsx` with an automatic route interceptor that redirects unauthenticated visitors to `https://auth.lanzar.me/authorize?client_id=portal`.
  2. Maintain `/callback` route using `pkce.js` to exchange codes for Custom Tokens.
  3. Deploy the redesigned **Portal Mission Control** administrative shell.

### 3.3 Tickets (`tickets.lanzar.me`)
* **Current State:** React frontend with standalone Firebase Login modal (`Login.jsx`). Backend Express API verifies Firebase ID tokens.
* **Target State:** Centralized SSO via `auth.lanzar.me`.
* **Execution Strategy:**
  1. Remove standalone login form from frontend. Redirect to Auth Hub on sign-in.
  2. No changes required to backend API middleware (`authenticateUser`), as tickets already shares Firebase project `lanzar-95ae3` and validates standard Firebase ID tokens.

### 3.4 Threadline (`threadline.lanzar.me`) — Project Consolidation
* **Current State:** Isolated on Firebase project **`lanzar-ba111`**.
* **Target State:** Fully consolidated into **`lanzar-95ae3`**.
* **Execution Strategy:**
  1. **Data Export:** Run GCP Firestore managed export on `lanzar-ba111` targeting a Cloud Storage bucket: `gs://lanzar-ba111-migration-export/`.
  2. **Data Import:** Import case and evidence collections into `lanzar-95ae3` under namespaced collections (`threadline_cases`, `threadline_evidence`).
  3. **Identity Mapping:** Re-key case ownership from `lanzar-ba111` UIDs to canonical `lanzar-95ae3` UIDs using normalized email addresses.
  4. **Client Environment Update:** Update `threadline/website/.env` to point to `lanzar-95ae3`:
     ```env
     VITE_FIREBASE_PROJECT_ID=lanzar-95ae3
     VITE_FIREBASE_AUTH_DOMAIN=auth.lanzar.me
     ```
  5. **30-Day Safety Escrow:** Keep `lanzar-ba111` online in read-only mode for 30 days before decommissioning.
