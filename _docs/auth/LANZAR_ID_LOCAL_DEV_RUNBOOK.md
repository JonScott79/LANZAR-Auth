# LANZAR ID — Local Development & Testing Runbook
**Document Version:** 1.1.0  
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

Before starting the local development stack, ensure the following prerequisites are installed and verified:

1. **Repository Root Directory:** All commands must be executed from the repository root (`lanzar_id_main_chat`).
2. **Node.js Runtime:** v18.0.0+ required (Tested and certified on `v22.14.0`).
3. **Java Runtime (JRE/JDK):** Java 17+ LTS required for Firestore emulator (Tested on `OpenJDK 17.0.12 LTS`). Verify with `java -version`.
4. **Google Chrome:** Installed at standard path (`C:\Program Files\Google\Chrome\Application\chrome.exe`) for CDP headless E2E tests.
5. **Git Branch:** `lanzar_id_main_chat` (strictly isolated; never push or merge directly to `main`).
6. **Local Dependencies Installed:** Ensure root and frontend node modules are installed:
   ```powershell
   npm install
   npm --prefix auth install
   ```

---

## 3. Fresh PowerShell Session Setup & Environment Inheritance

> [!IMPORTANT]
> **PowerShell Environment Variable Scope:** In PowerShell, `$env:VARIABLE = "value"` sets process-level environment variables valid **only for that specific terminal session**. If you open separate terminal tabs or windows for each service, you **must** set the environment variables in each new window before launching backend services or tests.

### Universal Session Setup Block (Copy-Paste Ready)
Paste this block into any fresh PowerShell session before running the backend or offline tests:

```powershell
# Set repository root if not already there
# cd C:\Users\jonny\.gemini\antigravity\worktrees\lanzar\lanzar_id_main_chat

# Mandatory Environment Selector
$env:APP_ENV = "development"

# Mandatory Demo Project ID (enforces offline emulator isolation)
$env:FIREBASE_PROJECT_ID = "demo-lanzar-dev"

# Mandatory Loopback Emulator Endpoints
$env:FIREBASE_AUTH_EMULATOR_HOST = "127.0.0.1:9099"
$env:FIRESTORE_EMULATOR_HOST = "127.0.0.1:8080"

# Service Port & Session Signing Secrets
$env:PORT = "4001"
$env:SESSION_SIGNING_SECRET = "development_session_signing_secret_min_32_chars"

# Mock Providers (avoids real SMS charges or external carrier dependencies)
$env:SMS_LIVE_ENABLED = "false"
$env:MOCK_SMS_CARRIER = "true"
```

### Frontend Configuration (`auth/.env`)
The Auth Hub frontend reads configuration from `auth/.env`, which is statically configured for local emulator execution:
```bash
VITE_APP_ENV="development"
VITE_FIREBASE_PROJECT_ID="demo-lanzar-dev"
VITE_FIREBASE_AUTH_EMULATOR_HOST="127.0.0.1:9099"
VITE_FIRESTORE_EMULATOR_HOST="127.0.0.1:8080"
VITE_AUTH_API_BASE="http://localhost:4001"
VITE_AUTH_HUB_URL="http://localhost:4000"
```

---

## 4. Startup Procedure

You can start the services using either a multi-terminal workflow (recommended for active debugging) or a single-session background workflow.

### Workflow A: Multi-Terminal Startup (Recommended)

#### Terminal 1: Firebase Emulators (Ports 9099 & 8080)
```powershell
npx firebase-tools@13.31.0 emulators:start --only auth,firestore --project demo-lanzar-dev
```
*Verification:* Wait until output confirms: `All emulators ready! It is now safe to connect your app.`

#### Terminal 2: LANZAR ID Backend Operations Center (Port 4001)
```powershell
# Paste the Universal Session Setup Block from Section 3, then:
node auth/auth-backend/server.js
```
*Verification:* Output displays `[LANZAR ID AUTH-BACKEND] Operations Center API listening on port 4001`.

#### Terminal 3: Auth Hub Frontend SPA (Port 4000)
```powershell
npm --prefix auth run dev
```
*Verification:* Output displays `Local: http://localhost:4000/`.

#### Terminal 4: Portal Client Mock Application (Port 5173)
```powershell
node auth/portal-test-server.cjs
```
*Verification:* Output displays `[PORTAL TEST CLIENT] Portal mock application listening on http://localhost:5173`.

---

### Workflow B: Single-Session Background Startup
If launching all services from a single PowerShell window, child processes spawned via `Start-Process` inherit the session environment variables:

```powershell
# 1. Initialize environment variables in the parent session
$env:APP_ENV = "development"
$env:FIREBASE_PROJECT_ID = "demo-lanzar-dev"
$env:FIREBASE_AUTH_EMULATOR_HOST = "127.0.0.1:9099"
$env:FIRESTORE_EMULATOR_HOST = "127.0.0.1:8080"
$env:PORT = "4001"
$env:SESSION_SIGNING_SECRET = "development_session_signing_secret_min_32_chars"
$env:SMS_LIVE_ENABLED = "false"
$env:MOCK_SMS_CARRIER = "true"

# 2. Spawn Emulators
Start-Process -NoNewWindow npx -ArgumentList "firebase-tools@13.31.0","emulators:start","--only","auth,firestore","--project","demo-lanzar-dev"

# Allow 5 seconds for emulator startup before backend connects
Start-Sleep -Seconds 5

# 3. Spawn Backend API (Port 4001)
Start-Process -NoNewWindow node -ArgumentList "auth/auth-backend/server.js"

# 4. Spawn Auth Hub Frontend (Port 4000)
Start-Process -NoNewWindow npm -ArgumentList "--prefix","auth","run","dev","--","--port","4000"

# 5. Spawn Portal Test Client (Port 5173)
Start-Process -NoNewWindow node -ArgumentList "auth/portal-test-server.cjs"
```

---

## 5. Automated Test Execution Commands

Once all backend and frontend services are running, execute the 12-suite regression battery. Every suite must report a 100% pass rate:

```powershell
# Ensure session variables are set
$env:APP_ENV = "development"
$env:FIREBASE_PROJECT_ID = "demo-lanzar-dev"
$env:FIREBASE_AUTH_EMULATOR_HOST = "127.0.0.1:9099"
$env:FIRESTORE_EMULATOR_HOST = "127.0.0.1:8080"

# 1. Phase 1 Architecture & Session Acceptance (55 tests)
node auth/test-phase1-acceptance.cjs

# 2. Phase 2 Core Quality Gate & Amendments (38 tests)
node auth/test-phase2-core.cjs

# 3. Auth & MFA Provisioning Verification (15 tests)
node auth/test-auth-and-mfa.cjs

# 4. Phase 6 Security Penetration Suite (89 tests) — See Section 5.1 for isolation analysis
node auth/test-phase6-security-penetration.cjs

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

### 5.1 Security Test Isolation Analysis (`test-phase6-security-penetration.cjs`)

> [!NOTE]
> **Complete Offline Isolation & Zero Cloud Reachability:**
> 
> 1. **Why the script requires `APP_ENV` and `FIREBASE_PROJECT_ID`:**
>    `test-phase6-security-penetration.cjs` implements the 10 mandatory penetration tests from LID-TEST-008. To prevent accidental execution against live production systems, the script enforces strict guardrails at lines 27–47 that require explicit environment variables and immediately terminate (`process.exit(1)`) if `APP_ENV=production` or `FIREBASE_PROJECT_ID` matches production (`lanzar-95ae3`, `production`, `prod`).
> 
> 2. **What infrastructure does it contact?**
>    **Zero cloud infrastructure.** The script:
>    - Uses an **in-memory** `MockFirestore` and `MockAuthAdmin` (lines 181–509) contained entirely within the test process memory.
>    - Boots an **ephemeral loopback HTTP server** on `127.0.0.1` on a dynamic OS-allocated port (`server.listen(0, '127.0.0.1')`) hosting `createApp()` (lines 586–588).
>    - Uses `MockSMSProvider` exclusively (`SMS_LIVE_ENABLED != true`).
>    - Makes HTTP calls only to `http://127.0.0.1:<random-port>`.
> 
> 3. **Can it ever reach a real cloud Firebase project?**
>    **No.** The script does not initialize the Google Cloud Firestore SDK or the live Firebase Admin SDK. All storage and token verification operations resolve to local in-memory JavaScript Maps.
> 
> 4. **Safe Local Offline Execution:**
>    It is completely safe to run in your local offline development session using the standard development environment variables:
>    ```powershell
>    node auth/test-phase6-security-penetration.cjs
>    ```
>    When `$env:APP_ENV="development"` and `$env:FIREBASE_PROJECT_ID="demo-lanzar-dev"` are active, all 89 assertions pass with 100% offline isolation and zero session mutation.

---

## 6. Safe Targeted Shutdown Procedure

> [!CAUTION]
> **Shutdown Safety Requirement:** Never use broad process termination commands like `Get-Process node | Stop-Process` or `Get-Process chrome | Stop-Process`, which risk killing unrelated developer tools, background workers, or open browser tabs.
>
> Always use the **targeted, port-based shutdown method** below, which inspects listening TCP ports and terminates *only* the specific processes bound to LANZAR ID ports.

### Safe PowerShell Port-Based Shutdown Script
Execute this command in PowerShell to cleanly shut down only LANZAR ID services:

```powershell
# Targeted Port-Based Termination: Ports 4000 (Auth Hub), 4001 (Backend API), 
# 5173 (Portal Client), 8080 (Firestore Emulator), 9099 (Auth Emulator), 9222 (Chrome CDP)
$targetPorts = @(4000, 4001, 5173, 8080, 9099, 9222)

$activeConnections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object { $targetPorts -contains $_.LocalPort }

if ($activeConnections) {
  $activePids = $activeConnections | Select-Object -ExpandProperty OwningProcess -Unique
  Write-Host "Safely terminating LANZAR ID service processes (PIDs: $($activePids -join ', '))..."
  Stop-Process -Id $activePids -Force -ErrorAction SilentlyContinue
  Write-Host "All LANZAR ID development services stopped."
} else {
  Write-Host "No active LANZAR ID services detected on ports $($targetPorts -join ', ')."
}
```

### Service Port Map for Verification
If terminating manually via Task Manager or `Stop-Process -Id <PID>`, use `netstat -ano | findstr <port>` to identify the specific PID:
- **Port 9099:** Firebase Auth Emulator (`node.exe` spawned by firebase-tools)
- **Port 8080:** Firestore Database Emulator (`java.exe` emulator JAR)
- **Port 4001:** LANZAR ID Backend (`node.exe` running `auth/auth-backend/server.js`)
- **Port 4000:** Auth Hub Frontend (`node.exe` running Vite)
- **Port 5173:** Portal Test Client (`node.exe` running `auth/portal-test-server.cjs`)
- **Port 9222:** Chrome CDP Headless test runner (if orphaned during interrupted test runs)

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

### Issue 3: Backend Exits with "Missing Firebase credentials in non-emulator environment"
- **Cause:** The backend was started in a fresh terminal session without setting `$env:FIREBASE_AUTH_EMULATOR_HOST` and `$env:FIRESTORE_EMULATOR_HOST`.
- **Fix:** Paste the Universal Session Setup Block from Section 3 before starting `node auth/auth-backend/server.js`.

### Issue 4: CORS Preflight Failure on Profile Updates or Session Deletions
- **Cause:** Missing `PUT` or `DELETE` in `Access-Control-Allow-Methods`.
- **Fix:** Ensure `auth/auth-backend/middleware/originValidator.js` specifies:
  ```javascript
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  ```

### Issue 5: Chrome CDP Fails to Open Popup
- **Cause:** Chrome's headless mode blocks `window.open` calls by default.
- **Fix:** Launch Chrome with the `--disable-popup-blocking` flag in your test runner spawn args.

### Issue 6: External Analytics Calls During Local Development
- **Cause:** Unconditional `<script>` tag loading Google Tag Manager in `auth/index.html`.
- **Fix:** Ensure `index.html` restricts GTM initialization to production hostname `auth.lanzar.me`:
  ```html
  <script>
    if (window.location.hostname === 'auth.lanzar.me') {
      // Load GTM
    }
  </script>
  ```
