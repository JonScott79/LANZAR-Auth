# LANZAR ID — Developer Quick-Start Guide (Threadline Reference)

> **Environment:** NOVA Staging (`https://auth.lanzar.me/nova`)  
> **Reference Implementation:** `JonScott79/threadline` (`auth/AuthProvider.jsx` & `backend/middleware/auth.js`)

---

## 1. Register & Create Your Organization

1. Sign in or create an account at **https://lanzar-auth-nova.netlify.app/?view=account**.
2. Open the **🛠 Developer** tab.
3. Under **Organization & Tenant Workspace**, enter your organization name (e.g., `Acme SaaS`) and optional slug (`acme-saas`), then click **+ CREATE TENANT**.
4. Note your tenant's OIDC endpoints:
   - **Issuer:** `https://auth.lanzar.me/nova`
   - **Discovery:** `https://auth.lanzar.me/nova/.well-known/openid-configuration`
   - **JWKS:** `https://auth.lanzar.me/nova/.well-known/jwks.json`
   - **Authorization Endpoint:** `https://auth-api-nova.lanzar.me/oauth/authorize`
   - **Token Endpoint:** `https://auth-api-nova.lanzar.me/oauth/token`
   - **UserInfo Endpoint:** `https://auth-api-nova.lanzar.me/oauth/userinfo`

## 2. Register Your Application

In the **🛠 Developer** tab:
1. Enter your **Application Name** and optional **Client ID** (e.g., `acme-web`).
2. Add your exact **Redirect URIs** (wildcards and `#` fragments are rejected), e.g., `https://app.acme.com/callback`.
3. Add your exact **Allowed CORS Origins**, e.g., `https://app.acme.com`.
4. Choose **Public SPA / Mobile (PKCE S256)** (`tokenEndpointAuthMethod: "none"`) or **Confidential Backend** (`client_secret_post` — save the one-time `clientSecret` immediately).

---

## 3. Frontend Integration (PKCE S256 — Threadline Pattern)

Threadline's `auth/AuthProvider.jsx` implements standard OAuth 2.0 Authorization Code + PKCE (`S256`) with `state` and `nonce` verification:

```js
// 1. Generate PKCE verifier + S256 challenge, state, and nonce
const verifier = base64Url(crypto.getRandomValues(new Uint8Array(32)));
const challengeBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
const codeChallenge = base64Url(new Uint8Array(challengeBuf));
const state = crypto.randomUUID();
const nonce = crypto.randomUUID();

sessionStorage.setItem('lanzar_pkce_verifier', verifier);
sessionStorage.setItem('lanzar_oauth_state', state);
sessionStorage.setItem('lanzar_oauth_nonce', nonce);

// 2. Redirect user to LANZAR ID Authorization Endpoint
const authUrl = new URL('https://auth-api-nova.lanzar.me/oauth/authorize');
authUrl.searchParams.set('client_id', 'YOUR_CLIENT_ID');
authUrl.searchParams.set('redirect_uri', window.location.origin);
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');
authUrl.searchParams.set('scope', 'openid profile email');
authUrl.searchParams.set('state', state);
authUrl.searchParams.set('nonce', nonce);
window.location.assign(authUrl.toString());
```

On callback (`?code=...&state=...`), verify `state` matches `sessionStorage`, then exchange the authorization code at `/oauth/token`:

```js
const res = await fetch('https://auth-api-nova.lanzar.me/oauth/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Idempotency-Key': crypto.randomUUID()
  },
  body: JSON.stringify({
    grant_type: 'authorization_code',
    code,
    client_id: 'YOUR_CLIENT_ID',
    redirect_uri: window.location.origin,
    code_verifier: sessionStorage.getItem('lanzar_pkce_verifier')
  })
});
const tokens = await res.json();
// tokens = { access_token, id_token, refresh_token, expires_in: 900, token_type: 'Bearer', ... }
```

Always validate `id_token` claims (`iss === 'https://auth.lanzar.me/nova'`, `aud === 'YOUR_CLIENT_ID'`, `nonce === savedNonce`, `exp > now`).

---

## 4. Backend API Verification (RS256 JWKS — Threadline Pattern)

Threadline's `backend/middleware/auth.js` verifies `Authorization: Bearer <access_token>` locally using Node's built-in `crypto` module and the cached JWKS endpoint (zero external JWT library required):

1. Fetch JWKS from `https://auth.lanzar.me/nova/.well-known/jwks.json` (cache for 60s; refresh on unknown `kid`).
2. Decode JWT header & payload; enforce `header.alg === 'RS256'` and match `header.kid` in JWKS.
3. Verify RSA-SHA256 signature using `crypto.createPublicKey({ key: jwk, format: 'jwk' })` and `crypto.verify('RSA-SHA256', ...)`.
4. Enforce `payload.iss === 'https://auth.lanzar.me/nova'`, `payload.aud === 'YOUR_CLIENT_ID'` (or `azp`), `payload.exp > nowSec`, `payload.nbf <= nowSec`, and non-empty `payload.sub`.

---

## 5. Refresh Token Rotation

Call `POST https://auth-api-nova.lanzar.me/oauth/token` with:

```json
{
  "grant_type": "refresh_token",
  "refresh_token": "<refresh_token>",
  "client_id": "YOUR_CLIENT_ID"
}
```

Each refresh token is **single-use**. Replaying an already-rotated refresh token automatically revokes the entire token family and associated session.
