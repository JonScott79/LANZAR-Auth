# LANZAR ID — Local Development & Testing Runbook
**Document Version:** 1.0.0  
**Status:** Approved Reference  
**Applicability:** Local Development & Testing (`demo-lanzar-dev`)  
**Target Branch:** `lanzar_id_main_chat`  

---

## 1. Local Environment Architecture & Port Allocation

The LANZAR ID local development stack runs completely offline using local loopback interfaces (`127.0.0.1` and `localhost`). Under no circumstances should local development connect to live Google Cloud Platform or production Firebase resources.

| # | Service Component | Local Port | Network Endpoint | Technology Stack | Configuration / Command |
| :---: | :--- | :---: | :--- | :--- | :--- |
| **1** | **Firebase Auth Emulator** | `9099` | `http://127.0.0.1:9099` | Firebase CLI (`v13.31.0`) | `npx firebase-tools@13.31.0 emulators:start --only auth,firestore --project demo-lanzar-dev` |
| **2** | **Firestore Database Emulator** | `8080` | `http://127.0.0.1:8080` | Firebase Emulator JAR (`v1.19.8`) | Governed by `firebase.json` and `firestore.rules` |
| **3** | **LANZAR ID Backend API** | `4001` | `http://localhost:4001` | Node.js Express 4 Operations Center | `node auth/auth-backend/server.js` |
| **4** | **Auth Hub Frontend** | `4000` | `http://localhost:4000` | Vite 8 + React 19 SPA | `npm --prefix auth run dev` |
| **5** | **Portal Mock Test Client** | `5173` | `http://localhost:5173` | Node.js HTTP Server (`<lanzar-auth-modal>`) | `node auth/portal-test-server.cjs` |

> [!IMPORTANT]
> Port 4000 is reserved exclusively for the Auth Hub Vite development server. To prevent port collisions, `firebase.json` must specify `"ui": { "enabled": false }`.

---

## 2. Prerequisites & Host Requirements

Before starting the local development stack, ensure the following prerequisites are installed:
- **Node.js:** v18.0.0+ (Tested on v22.14.0)
- **Java Runtime:** Java 17+ (Tested on `OpenJDK 17.0.12 LTS`)
- **Google Chrome:** Installed at standard path (`C:\Program Files\Google\Chrome\Application\chrome.exe`)
- **Git Branch:** `lanzar_id_main_chat` (strictly isolated; do not commit directly to `main`)

---

## 3. Environment Variables Reference

Local execution requires fail-closed emulator gating. Setting these variables guarantees that the backend and client SDK will refuse to connect to live cloud resources.

### Backend Environment Variables (`auth/auth-backend`)
```bash
# Mandatory Environment Selector (must be 'development' for local work)
APP_ENV="development"

# Mandatory Demo Project ID (enforces offline emulator isolation)
FIREBASE_PROJECT_ID="demo-lanzar-dev"

# Mandatory Loopback Emulator Endpoints
FIREBASE_AUTH_EMULATOR_HOST="127.0.0.1:9099"
FIRESTORE_EMULATOR_HOST="127.0.0.1:8080"

# Service Port & Signing Secrets
PORT="4001"
SESSION_SIGNING_SECRET="development_session_signing_secret_min_32_chars"

# Mock Providers (avoids real SMS charges or carrier dependencies)
SMS_LIVE_ENABLED="false"
MOCK_SMS_CARRIER="true"
```

### Frontend Configuration (`auth/.env`)
```bash
VITE_APP_ENV="development"
VITE_FIREBASE_PROJECT_ID="demo-lanzar-dev"
VITE_FIREBASE_AUTH_EMULATOR_HOST="127.0.0.1:9099"
VITE_FIRESTORE_EMULATOR_HOST="127.0.0.1:8080"
VITE_AUTH_API_BASE="http://localhost:4001"
VITE_AUTH_HUB_URL="http://localhost:4000"
```

---

## 4. Startup Procedure (Step-by-Step)

Execute the following commands in order, preferably in separate terminal sessions or background task daemons:

### Step 1: Start Firebase Auth & Firestore Emulators
```powershell
npx firebase-tools@13.31.0 emulators:start --only auth,firestore --project demo-lanzar-dev
```
*Verification:* Wait until the console outputs `All emulators ready! It is now safe to connect your app.`

### Step 2: Start LANZAR ID Backend Operations Center
```powershell
$env:APP_ENV="development"
$env:FIREBASE_PROJECT_ID="demo-lanzar-dev"
$env:FIREBASE_AUTH_EMULATOR_HOST="127.0.0.1:9099"
$env:FIRESTORE_EMULATOR_HOST="127.0.0.1:8080"
$env:PORT="4001"
$env:SESSION_SIGNING_SECRET="development_session_signing_secret_min_32_chars"
node auth/auth-backend/server.js
```
*Verification:* Look for `[LANZAR ID AUTH-BACKEND] Operations Center API listening on port 4001`.

### Step 3: Start Auth Hub Frontend (Vite)
```powershell
npm --prefix auth run dev
```
*Verification:* Output displays `Local: http://localhost:4000/`.

### Step 4: Start Portal Client Application
```powershell
node auth/portal-test-server.cjs
```
*Verification:* Output displays `[PORTAL TEST CLIENT] Portal mock application listening on http://localhost:5173`.

---

## 5. Automated Test Execution Commands

Once all four backend/frontend services are running, the full testing battery can be run.

### Complete Regression Battery (12 Test Suites)
Run each command sequentially. Every suite must report a 100% pass rate:

```powershell
# 1. Phase 1 Architecture & Session Acceptance (55 tests)
node auth/test-phase1-acceptance.cjs

# 2. Phase 2 Core Quality Gate & Amendments (38 tests)
node auth/test-phase2-core.cjs

# 3. Auth & MFA Provisioning Verification (15 tests)
node auth/test-auth-and-mfa.cjs

# 4. Phase 6 Security Penetration Suite (89 tests)
$env:APP_ENV="staging"; $env:FIREBASE_PROJECT_ID="lanzar-dev-staging"; node auth/test-phase6-security-penetration.cjs

# 5. Level 3 Firestore Security Rules (58 tests)
node auth/test-level3-firestore-rules.cjs

# 6. Client SDK Contract & PKCE Vectors (18 tests)
node auth/test-sdk-contract.cjs

# 7. Staging Bootstrap & Safeguards (7 tests)
node auth/test-staging-bootstrap.cjs

# 8. End-to-End API Integration Suite (20 tests)
node auth/test-e2e-integration.cjs

# 9. OAuth Client Registry Reconciliation (9 tests)
node auth/test-client-registry.cjs

# 10. Popup & Modal Handshake Origin Validation (10 tests)
node auth/test-popup-modal-handshake.cjs

# 11. Development Environment Isolation (8 tests)
node auth/test-dev-isolation.cjs

# 12. Real Browser Chrome CDP End-to-End Suite (30 tests)
node auth/test-browser-e2e.cjs

# 13. Production Frontend Bundle Build Verification
npm --prefix auth run build
```

---

## 6. Clean Shutdown Procedure

To cleanly stop the local environment and prevent orphaned background tasks or port lockouts, terminate all running processes:

### Windows PowerShell Shutdown Commands
```powershell
# Find and terminate Node.js processes bound to local ports
Get-NetTCPConnection -LocalPort 4000, 4001, 5173, 8080, 9099 -ErrorAction SilentlyContinue | 
  Select-Object -ExpandProperty OwningProcess -Unique | 
  ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
```

### Manual Service Process Names
- **Firebase Emulators:** Terminates Java process (`java.exe`) and Node wrapper.
- **Backend API:** Terminates `node.exe` hosting `server.js`.
- **Frontend Dev Server:** Terminates `node.exe` running Vite.
- **Portal Client Server:** Terminates `node.exe` running `portal-test-server.cjs`.

---

## 7. Troubleshooting & Diagnostics

### Issue 1: "Firebase Tools no longer supports Java version before 21"
- **Cause:** Latest `firebase-tools` (v15+) requires Java 21+.
- **Fix:** Pin the emulator execution to `firebase-tools@13.31.0` which is fully compatible with Java 17 LTS:
  ```powershell
  npx firebase-tools@13.31.0 emulators:start --only auth,firestore --project demo-lanzar-dev
  ```

### Issue 2: Port 4000 Collision on Emulator Startup
- **Cause:** Firebase Emulator UI attempts to bind to port 4000 by default, which conflicts with the Auth Hub frontend.
- **Fix:** In `firebase.json`, disable the Emulator UI:
  ```json
  "emulators": {
    "auth": { "port": 9099 },
    "firestore": { "port": 8080 },
    "ui": { "enabled": false }
  }
  ```

### Issue 3: CORS Preflight Failure on Profile Updates or Session Deletions
- **Cause:** Missing `PUT` or `DELETE` in `Access-Control-Allow-Methods`.
- **Fix:** Ensure `auth/auth-backend/middleware/originValidator.js` specifies:
  ```javascript
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  ```

### Issue 4: Chrome CDP Fails to Open Popup
- **Cause:** Chrome's headless mode blocks `window.open` calls by default.
- **Fix:** Launch Chrome with the `--disable-popup-blocking` flag in your test runner spawn args.

### Issue 5: External Analytics Calls During Local Development
- **Cause:** Unconditional `<script>` tag loading Google Tag Manager in `auth/index.html`.
- **Fix:** Ensure `index.html` restricts GTM initialization to production hostname `auth.lanzar.me`:
  ```html
  <script>
    if (window.location.hostname === 'auth.lanzar.me') {
      // Load GTM
    }
  </script>
  ```
