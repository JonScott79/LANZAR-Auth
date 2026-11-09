# LANZAR ID — Staging Deployment Runbook

**Service:** LANZAR ID (`auth.lanzar.me`, `auth-backend`)  
**Target Environment:** Staging  
**Target Project:** `lanzar-95ae3-dev`  
**Hostnames:**
- Backend: `https://auth-api-dev.lanzar.me`
- Frontend Hub: `https://auth-dev.lanzar.me`
- Customer Portal: `https://portal-dev.lanzar.me`

---

## 1. Architectural Guardrails & Invariants

1. **Sole Identity Provider:** `auth.lanzar.me` (and `auth-dev.lanzar.me` in staging) is the sole identity and authentication provider.
2. **No `id.lanzar.me`:** There is no `id.lanzar.me` subdomain. Customer portal traffic routes to `portal-dev.lanzar.me`. User account management is accessed directly on `auth-dev.lanzar.me/account`.
3. **Fail-Closed Isolation:** `APP_ENV=staging` strictly requires project ID `lanzar-95ae3-dev`. If any production credentials, production project IDs, or emulator variables are detected, the container process exits with code 1.

---

## 2. Pre-Deployment Quality Gates

Before initiating deployment, execute all local verification test batteries:

```bash
# 1. Phase 1 Acceptance Suite (55 tests)
node auth/test-phase1-acceptance.cjs

# 2. Phase 2 Core Services Battery (32 tests)
node auth/test-phase2-core.cjs

# 3. Auth & MFA Full Lifecycle (15 validation checks)
node auth/test-auth-and-mfa.cjs

# 4. Phase 6 Security Penetration Suite (89 tests)
node auth/test-phase6-security-penetration.cjs

# 5. Level 3 Firestore Security Rules (53 tests)
node auth/test-level3-firestore-rules.cjs

# 6. Client SDK Contract Suite (18 tests)
node auth/test-sdk-contract.cjs

# 7. Staging Bootstrap Safeguard Suite (7 tests)
node auth/test-staging-bootstrap.cjs

# 8. Frontend Bundle Build
npm --prefix auth run build
```

**Quality Gate Requirement:** 100% pass across all test batteries (269 formal assertions + 15 validation checks = 284 verification points) with zero failures.

---

## 3. Backend Deployment (Cloud Run)

### 3.1 Container Build
```bash
gcloud builds submit auth/auth-backend \
  --project=lanzar-95ae3-dev \
  --tag=gcr.io/lanzar-95ae3-dev/auth-backend:staging
```

### 3.2 Service Deployment
Deploy to Cloud Run with environment variables and secrets mapped from Secret Manager:

```bash
gcloud run deploy auth-backend-staging \
  --project=lanzar-95ae3-dev \
  --region=us-central1 \
  --image=gcr.io/lanzar-95ae3-dev/auth-backend:staging \
  --platform=managed \
  --allow-unauthenticated \
  --set-env-vars="APP_ENV=staging,NODE_ENV=production,FIREBASE_PROJECT_ID=lanzar-95ae3-dev,EXPECTED_SA_EMAIL=lanzar-auth-api@lanzar-95ae3-dev.iam.gserviceaccount.com,FEATURE_STRIPE=disabled,SMS_LIVE_ENABLED=false" \
  --set-secrets="FIREBASE_SERVICE_ACCOUNT_KEY=lanzar-auth-staging-sa-key:latest,SESSION_SIGNING_SECRET=lanzar-auth-staging-session-secret:latest"
```

### 3.3 Custom Domain Mapping
Ensure `auth-api-dev.lanzar.me` is routed to the Cloud Run service `auth-backend-staging`.

---

## 4. Frontend Deployment (Firebase Hosting / Cloud Storage)

### 4.1 Build Production Bundle for Staging
```bash
cd auth
VITE_APP_ENV=staging \
VITE_AUTH_API_URL=https://auth-api-dev.lanzar.me \
VITE_AUTH_HUB_URL=https://auth-dev.lanzar.me \
npm run build
```

### 4.2 Deploy Static Assets to Firebase Hosting
```bash
firebase deploy \
  --project=lanzar-95ae3-dev \
  --only hosting:auth-staging
```

Verify `auth-dev.lanzar.me` renders the login UI cleanly and connects to `https://auth-api-dev.lanzar.me`.

---

## 5. Client SDK Distribution

Deploy `lanzar-auth-modal.js` to the staging SDK distribution path:
- URL: `https://auth-dev.lanzar.me/sdk/v1.0.0/lanzar-auth-modal.js`

Ensure CORS headers permit embedding from authorized staging origins:
- `https://portal-dev.lanzar.me`
- `https://tickets-dev.lanzar.me`
- `https://threadline-dev.lanzar.me`
- `https://pythos-dev.lanzar.me`

---

## 6. Post-Deployment Smoke Verification

1. **Health & Bootstrap Probe:**
   ```bash
   curl -I https://auth-api-dev.lanzar.me/
   ```
2. **PKCE Strict Authorization Check:**
   ```bash
   curl -X POST https://auth-api-dev.lanzar.me/authorize \
     -H "Content-Type: application/json" \
     -d '{"client_id":"portal","redirect_uri":"https://portal-dev.lanzar.me"}'
   ```
   *Expected Response:* HTTP 400 Bad Request with `{"error":"invalid_request"}` indicating missing `idToken`, `code_challenge`, and `code_challenge_method`.
3. **Origin Restriction Check:**
   ```bash
   curl -X OPTIONS https://auth-api-dev.lanzar.me/authorize \
     -H "Origin: https://malicious-attacker.com" \
     -H "Access-Control-Request-Method: POST"
   ```
   *Expected Response:* Origin rejected; CORS headers omitted.
4. **Account Management View:**
   Navigate to `https://auth-dev.lanzar.me/account`. Verify that authenticated users view session management and profile controls.

---

## 7. Emergency Rollback Plan

If health checks fail or an unhandled regression is observed:

1. **Cloud Run Rollback:**
   ```bash
   gcloud run services update-traffic auth-backend-staging \
     --project=lanzar-95ae3-dev \
     --region=us-central1 \
     --to-revisions=PREVIOUS_KNOWN_GOOD_REVISION=100
   ```
2. **Hosting Rollback:**
   In Firebase Console for `lanzar-95ae3-dev`, roll back the Hosting release to the previous deployment.
