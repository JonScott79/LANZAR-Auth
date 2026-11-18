/*
    auth-service.js

    Client-Side Authentication & User Identity Service for LANZAR AI.
    Uses OAuth 2.0 Authorization Code + PKCE S256 against LANZAR ID (NOVA staging / production).
*/

import { globalBus } from "../core/event-bus.js";
import { Analytics } from "../analytics.js";

const AUTH_STORAGE_KEY = "lanzar_ai_auth_session";
const PKCE_VERIFIER_KEY = "lanzar_ai_pkce_verifier";
const PKCE_STATE_KEY = "lanzar_ai_pkce_state";
const PKCE_NONCE_KEY = "lanzar_ai_pkce_nonce";

function getLanzarEndpoints() {
  const host = typeof window !== "undefined" ? window.location.hostname : "localhost";
  const isLocal = host === "localhost" || host === "127.0.0.1";
  if (isLocal && window.__LANZAR_AI_USE_LOCAL_AUTH === true) {
    return {
      authHubUrl: "http://localhost:4000",
      authApiUrl: "http://localhost:4001",
      expectedIssuer: "http://localhost:4001"
    };
  }
  return {
    authHubUrl: window.__LANZAR_AUTH_HUB_URL || "https://lanzar-auth-nova.netlify.app",
    authApiUrl: window.__LANZAR_AUTH_API_URL || "https://auth-api-nova.lanzar.me",
    expectedIssuer: window.__LANZAR_OIDC_ISSUER || "https://auth.lanzar.me/nova"
  };
}

function base64UrlEncode(bytes) {
  let str = "";
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeJwtPayload(token) {
  try {
    const parts = String(token).split(".");
    if (parts.length !== 3) return null;
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(b64));
  } catch (_) {
    return null;
  }
}

class AuthService {
  #currentUser = null;
  #isInitialized = false;

  constructor() {
    this.#loadPersistedSession();
  }

  #loadPersistedSession() {
    try {
      if (typeof sessionStorage !== "undefined") {
        const raw = sessionStorage.getItem(AUTH_STORAGE_KEY);
        if (raw) {
          this.#currentUser = JSON.parse(raw);
        }
      }
      if (typeof localStorage !== "undefined") {
        localStorage.removeItem(AUTH_STORAGE_KEY);
      }
    } catch (e) {
      this.#currentUser = null;
    }
  }

  #saveSession(user) {
    this.#currentUser = user;
    try {
      if (typeof sessionStorage !== "undefined") {
        if (user) {
          sessionStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(user));
        } else {
          sessionStorage.removeItem(AUTH_STORAGE_KEY);
        }
      }
    } catch (_) {}
  }

  async #completePkceCallbackIfPresent() {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");
    if (!code) return;

    const storedState = sessionStorage.getItem(PKCE_STATE_KEY);
    const verifier = sessionStorage.getItem(PKCE_VERIFIER_KEY);
    const storedNonce = sessionStorage.getItem(PKCE_NONCE_KEY);
    sessionStorage.removeItem(PKCE_STATE_KEY);
    sessionStorage.removeItem(PKCE_VERIFIER_KEY);
    sessionStorage.removeItem(PKCE_NONCE_KEY);

    params.delete("code");
    params.delete("state");
    const qs = params.toString();
    window.history.replaceState({}, document.title, window.location.pathname + (qs ? "?" + qs : "") + window.location.hash);

    if (!storedState || !state || storedState !== state || !verifier) {
      console.warn("[AuthService] PKCE state or verifier mismatch.");
      return;
    }

    const { authApiUrl, expectedIssuer } = getLanzarEndpoints();
    const res = await fetch(`${authApiUrl}/oauth/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": `ai_exch_${crypto.randomUUID()}`
      },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        client_id: "ai",
        redirect_uri: window.location.origin,
        code_verifier: verifier
      })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.access_token) return;

    const idClaims = data.id_token ? decodeJwtPayload(data.id_token) : null;
    if (idClaims) {
      const nowSec = Math.floor(Date.now() / 1000);
      if (
        String(idClaims.iss || "").replace(/\/+$/, "") !== expectedIssuer ||
        idClaims.aud !== "ai" ||
        !Number.isFinite(idClaims.exp) ||
        idClaims.exp <= nowSec ||
        (storedNonce && idClaims.nonce !== storedNonce)
      ) {
        console.warn("[AuthService] Invalid OIDC id_token claims.");
        return;
      }
    }

    this.#saveSession({
      uid: idClaims?.sub || "",
      displayName: idClaims?.name || idClaims?.email || "LANZAR User",
      email: idClaims?.email || "",
      photoURL: "",
      authenticated: true,
      isGuest: false,
      token: data.access_token,
      sessionId: data.session_id || null
    });
  }

  async init() {
    if (this.#isInitialized) return this.#currentUser;

    await this.#completePkceCallbackIfPresent().catch(() => {});

    try {
      const headers = this.getAuthHeaders();
      const res = await fetch('/api/auth/me', { headers });
      if (res.ok) {
        const data = await res.json();
        if (data.user && data.user.authenticated) {
          this.#saveSession({ ...this.#currentUser, ...data.user });
        } else {
          this.#currentUser = {
            uid: data.user?.uid || 'user_default',
            displayName: data.user?.displayName || 'Guest Pilot',
            email: '',
            photoURL: '',
            authenticated: false,
            isGuest: true,
            token: ''
          };
        }
      }
    } catch (err) {
      console.warn("[AuthService] Failed to verify session with backend:", err);
    }

    this.#isInitialized = true;
    globalBus.emit("auth:initialized", { user: this.#currentUser });
    return this.#currentUser;
  }

  getUser() { return this.#currentUser; }
  getUid() { return this.#currentUser ? this.#currentUser.uid : 'user_default'; }
  isAuthenticated() { return Boolean(this.#currentUser && this.#currentUser.authenticated && !this.#currentUser.isGuest); }
  getAuthHeaders() {
    return (this.#currentUser && this.#currentUser.token)
      ? { 'Authorization': `Bearer ${this.#currentUser.token}` }
      : {};
  }

  async signInWithLanzarId() {
    const verifierBytes = new Uint8Array(32);
    crypto.getRandomValues(verifierBytes);
    const verifier = base64UrlEncode(verifierBytes);
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    const challenge = base64UrlEncode(new Uint8Array(digest));
    const state = crypto.randomUUID();
    const nonce = crypto.randomUUID();

    sessionStorage.setItem(PKCE_VERIFIER_KEY, verifier);
    sessionStorage.setItem(PKCE_STATE_KEY, state);
    sessionStorage.setItem(PKCE_NONCE_KEY, nonce);

    const { authHubUrl } = getLanzarEndpoints();
    const target = new URL(authHubUrl);
    target.searchParams.set("client_id", "ai");
    target.searchParams.set("redirect_uri", window.location.origin);
    target.searchParams.set("code_challenge", challenge);
    target.searchParams.set("code_challenge_method", "S256");
    target.searchParams.set("scope", "openid profile email");
    target.searchParams.set("state", state);
    target.searchParams.set("nonce", nonce);
    window.location.assign(target.toString());
  }

  async signOut() {
    const prevUid = this.getUid();
    const token = this.#currentUser?.token;
    const sessionId = this.#currentUser?.sessionId;
    if (token && sessionId) {
      const { authApiUrl } = getLanzarEndpoints();
      fetch(`${authApiUrl}/api/id/sessions/${encodeURIComponent(sessionId)}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` }
      }).catch(() => {});
    }

    this.#currentUser = {
      uid: 'user_default',
      displayName: 'Guest Pilot',
      email: '',
      photoURL: '',
      authenticated: false,
      isGuest: true,
      token: ''
    };
    this.#saveSession(null);

    Analytics.track("Auth", "Logout", { prevUid });
    globalBus.emit("auth:changed", { user: this.#currentUser });
  }
}

export const authService = new AuthService();
