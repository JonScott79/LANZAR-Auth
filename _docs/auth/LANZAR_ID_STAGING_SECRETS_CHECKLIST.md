# LANZAR ID — Staging Secrets & Environment Variable Checklist

**Target Environment:** Staging (`APP_ENV=staging`)  
**Target GCP Project:** `lanzar-95ae3-dev`  
**Target Hostnames:**
- Backend API: `https://auth-api-dev.lanzar.me`
- Auth Hub: `https://auth-dev.lanzar.me`
- Customer Portal: `https://portal-dev.lanzar.me`
- Ecosystem Services: `https://tickets-dev.lanzar.me`, `https://threadline-dev.lanzar.me`, `https://pythos-dev.lanzar.me`

---

## 1. Mandatory Staging Environment Variables

| Variable Name | Required Value / Specification | Validation Rule / Fail-Closed Safeguard |
| :--- | :--- | :--- |
| `APP_ENV` | `staging` | Must match entry in `ENV_CONFIGS`. If unset or different, startup throws `ConfigurationError`. |
| `NODE_ENV` | `production` | Ensures Express and React optimizations are active in staging runtime. |
| `FIREBASE_PROJECT_ID` | `lanzar-95ae3-dev` | Must match `lanzar-95ae3-dev` exactly. Mismatch throws fatal error immediately. |
| `FIREBASE_SERVICE_ACCOUNT_KEY` | Raw JSON string or path (`FIREBASE_SERVICE_ACCOUNT_PATH`) | Project ID inside JSON must be `lanzar-95ae3-dev`. Client email must end with `@lanzar-95ae3-dev.iam.gserviceaccount.com`. |
| `EXPECTED_SA_EMAIL` | `lanzar-auth-api@lanzar-95ae3-dev.iam.gserviceaccount.com` | Pinning check: fails closed if service account email does not match pinned value. |
| `SESSION_SIGNING_SECRET` | Cryptographically random secret (>= 32 bytes / 256 bits) | Fails closed on startup if < 32 bytes. Used for signing `__Host-lanzar_stg_sess` cookie tokens. |
| `FEATURE_STRIPE` | `disabled` (or `enabled`) | If `disabled`, boots without Stripe keys. If `enabled`, requires `sk_test_` key and webhook secret. |

---

## 2. Conditional / Secret Variables

### 2.1 Stripe Variables (Only when `FEATURE_STRIPE=enabled`)
| Variable Name | Requirement | Validation Rule |
| :--- | :--- | :--- |
| `STRIPE_SECRET_KEY` | Secret Key from Stripe Dashboard | Must strictly begin with `sk_test_`. If `sk_live_` is passed in staging, startup aborts immediately. |
| `STRIPE_WEBHOOK_SECRET` | Webhook Secret from Stripe Endpoint | Required when `FEATURE_STRIPE=enabled`. Validates incoming payment webhook payloads. |

### 2.2 SMS / Phone Verification Variables
| Variable Name | Requirement | Validation Rule |
| :--- | :--- | :--- |
| `SMS_LIVE_ENABLED` | `false` (in staging) | Default is `false`. When false, `MockSMSProvider` logs OTPs to server stdout and incurs zero carrier charges. |
| `TWILIO_ACCOUNT_SID` | Optional (only if live SMS authorized) | In staging, keep unset or disabled to prevent carrier billing. |
| `TWILIO_AUTH_TOKEN` | Optional (only if live SMS authorized) | Kept in Secret Manager if tested. |
| `TWILIO_FROM_NUMBER` | Optional (E.164 phone number) | Kept in Secret Manager if tested. |

---

## 3. Forbidden Variables in Live Staging

The following variables **MUST NOT** be set in staging. Presence of any emulator variable halts server startup immediately:

- `FIREBASE_AUTH_EMULATOR_HOST` — **FORBIDDEN** in `APP_ENV=staging`.
- `FIRESTORE_EMULATOR_HOST` — **FORBIDDEN** in `APP_ENV=staging`.

---

## 4. Frontend Environment Variables (`auth/.env.staging`)

For the Vite React build of `auth`:

```bash
VITE_APP_ENV=staging
VITE_AUTH_API_URL=https://auth-api-dev.lanzar.me
VITE_AUTH_HUB_URL=https://auth-dev.lanzar.me
```

---

## 5. Google Cloud Secret Manager Secret Names

In GCP Project `lanzar-95ae3-dev`:

| Secret Manager Secret ID | Intended Content |
| :--- | :--- |
| `lanzar-auth-staging-sa-key` | Service account JSON for `lanzar-auth-api@lanzar-95ae3-dev.iam.gserviceaccount.com` |
| `lanzar-auth-staging-session-secret` | 64-character hex or base64 cryptographic secret |
| `lanzar-auth-staging-stripe-secret` | `sk_test_...` (if Stripe enabled) |
| `lanzar-auth-staging-stripe-webhook` | `whsec_...` (if Stripe enabled) |

---

## 6. Pre-Flight Verification Script

Before deploying to staging, run the automated verification suite:

```bash
node auth/test-staging-bootstrap.cjs
```
All assertions must report `[PASS]` before deployment proceeds.
