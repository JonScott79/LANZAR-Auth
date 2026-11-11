/**
 * LANZAR ID Client SDK — <lanzar-auth-modal> v1.0.0
 * Classification: Authoritative Client Authentication Component & PKCE Suite
 * Distribution Target: https://auth.lanzar.me/sdk/v1.0.0/lanzar-auth-modal.js
 * (LID-ARCH-REV-015 §8.1, §9.4)
 */

'use strict';

// Environment configurations
const STAGING_CONFIG = {
  appEnv: 'staging',
  authApiBase: 'https://auth-api-dev.lanzar.me',
  authHubUrl: 'https://auth-dev.lanzar.me',
  defaultPortalUrl: 'https://id-dev.lanzar.me/',
  continuationAllowlist: [
    'https://id-dev.lanzar.me/',
    'https://pythos-dev.lanzar.me/',
    'https://tickets-dev.lanzar.me/',
    'https://threadline-dev.lanzar.me/',
    'https://portal-dev.lanzar.me/'
  ]
};

const PRODUCTION_CONFIG = {
  appEnv: 'production',
  authApiBase: 'https://auth-api.lanzar.me',
  authHubUrl: 'https://auth.lanzar.me',
  defaultPortalUrl: 'https://portal.lanzar.me/',
  continuationAllowlist: [
    'https://portal.lanzar.me/',
    'https://tickets.lanzar.me/',
    'https://threadline.lanzar.me/',
    'https://ai.lanzar.me/',
    'https://pythos.lanzar.me/',
    'https://lanzar.me/'
  ]
};

const DEVELOPMENT_CONFIG = {
  appEnv: 'development',
  authApiBase: 'http://localhost:4001',
  authHubUrl: 'http://localhost:4000',
  defaultPortalUrl: 'http://localhost:5173/',
  continuationAllowlist: [
    'http://localhost:5173/',
    'http://localhost:5174/',
    'http://localhost:5175/',
    'http://localhost:5176/',
    'http://localhost:3000/',
    'http://localhost:3005/'
  ]
};

function getCrypto() {
  if (typeof globalThis !== 'undefined' && globalThis.crypto) {
    return globalThis.crypto;
  }
  return null;
}

/**
 * Generates an RFC 7636 unreserved URL-safe code_verifier string.
 * @param {number} length Length between 43 and 128 characters (default 64)
 * @returns {string}
 */
function generateCodeVerifier(length = 64) {
  if (length < 43 || length > 128) {
    throw new Error('Code verifier length must be between 43 and 128 characters.');
  }
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  const cryptoObj = getCrypto();
  if (cryptoObj && cryptoObj.getRandomValues) {
    const bytes = new Uint8Array(length);
    cryptoObj.getRandomValues(bytes);
    let verifier = '';
    for (let i = 0; i < length; i++) {
      verifier += charset[bytes[i] % charset.length];
    }
    return verifier;
  }
  // Node.js fallback
  try {
    const nodeCrypto = require('crypto');
    const bytes = nodeCrypto.randomBytes(length);
    let verifier = '';
    for (let i = 0; i < length; i++) {
      verifier += charset[bytes[i] % charset.length];
    }
    return verifier;
  } catch (e) {
    throw new Error('Cryptographically secure random number generator unavailable.');
  }
}

/**
 * Generates an RFC 7636 S256 code_challenge from a code_verifier string.
 * @param {string} verifier
 * @returns {Promise<string>} Base64URL-encoded SHA-256 digest
 */
async function generateCodeChallenge(verifier) {
  if (!verifier || typeof verifier !== 'string') {
    throw new Error('Invalid code_verifier: must be a non-empty string.');
  }
  const cryptoObj = getCrypto();
  if (cryptoObj && cryptoObj.subtle) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await cryptoObj.subtle.digest('SHA-256', data);
    const bytes = new Uint8Array(digest);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const base64 = typeof btoa === 'function' 
      ? btoa(binary) 
      : Buffer.from(binary, 'binary').toString('base64');
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  // Node.js fallback
  try {
    const nodeCrypto = require('crypto');
    return nodeCrypto.createHash('sha256').update(verifier).digest('base64url');
  } catch (e) {
    throw new Error('Cryptographic SHA-256 digest unavailable.');
  }
}

/**
 * Helper to generate a full RFC 7636 PKCE pair.
 * @param {number} length
 * @returns {Promise<{codeVerifier: string, codeChallenge: string, codeChallengeMethod: string}>}
 */
async function generatePkcePair(length = 64) {
  const codeVerifier = generateCodeVerifier(length);
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: 'S256'
  };
}

/**
 * Builds a validated authorize URL for LANZAR Auth Hub with explicit S256 PKCE.
 * @param {Object} options
 * @param {Object} config
 * @returns {string}
 */
function buildAuthorizeUrl(options = {}, config = STAGING_CONFIG) {
  const {
    clientId,
    redirectUri,
    codeChallenge,
    codeChallengeMethod = 'S256',
    state = '',
    view = null,
    mode = null
  } = options;

  if (!clientId) throw new Error('clientId is required to build authorize URL.');
  if (!redirectUri) throw new Error('redirectUri is required to build authorize URL.');
  if (!codeChallenge) throw new Error('codeChallenge is required for strict PKCE.');
  if (codeChallengeMethod !== 'S256') throw new Error('codeChallengeMethod must be S256.');

  const base = options.authHubUrl || config.authHubUrl;
  const url = new URL(base);
  if (view === 'account') {
    url.pathname = '/account';
  }
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('code_challenge', codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  if (state) url.searchParams.set('state', state);
  if (mode) url.searchParams.set('mode', mode);

  return url.href;
}

/**
 * Exchanges an authorization code and code_verifier for an authenticated session token.
 * @param {Object} options
 * @param {Object} config
 * @returns {Promise<{custom_token: string, session_id: string, expires_in: number}>}
 */
async function exchangeCodeForSession(options = {}, config = STAGING_CONFIG) {
  const { code, clientId, redirectUri, codeVerifier } = options;
  if (!code || !clientId || !redirectUri || !codeVerifier) {
    throw new Error('Missing required exchange parameters (code, clientId, redirectUri, codeVerifier).');
  }

  const apiBase = options.authApiBase || config.authApiBase;
  const timeoutMs = Number.isFinite(options.timeoutMs)
    ? options.timeoutMs
    : (config?.requestTimeoutMs || 15000);
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  let timedOut = false;
  const timerId = controller
    ? setTimeout(() => {
        timedOut = true;
        controller.abort();
      }, timeoutMs)
    : null;

  let res;
  try {
    res = await fetch(`${apiBase}/exchange`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code,
        client_id: clientId,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier
      }),
      ...(controller ? { signal: controller.signal } : {})
    });
  } catch (err) {
    if (timedOut) {
      const timeoutErr = new Error('Authorization exchange timed out while contacting LANZAR ID. Please try again.');
      timeoutErr.code = 'ERR_TIMEOUT';
      throw timeoutErr;
    }
    throw err;
  } finally {
    if (timerId !== null) clearTimeout(timerId);
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error_description || data.error || `Token exchange failed (HTTP ${res.status}).`);
    err.code = data.error || 'exchange_error';
    err.details = data;
    throw err;
  }
  return data;
}

/**
 * Validates a continuation URL against the environment allowlist.
 * Replaces unlisted or cross-environment URLs with the staging portal default (PWR-3A).
 */
function sanitizeContinuationUrl(rawUrl, config = STAGING_CONFIG) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return config.defaultPortalUrl;
  }
  try {
    const parsed = new URL(rawUrl);
    const isAllowed = config.continuationAllowlist.some((allowed) => {
      const allowedParsed = new URL(allowed);
      return parsed.origin === allowedParsed.origin && parsed.pathname.startsWith(allowedParsed.pathname);
    });
    return isAllowed ? parsed.href : config.defaultPortalUrl;
  } catch (e) {
    return config.defaultPortalUrl;
  }
}

/**
 * Initiates an authentication popup window using PKCE.
 * Keeps the code_verifier strictly in the client application scope.
 * Validates origin and source window on message receipt.
 */
async function openPopup(options = {}, config = STAGING_CONFIG) {
  const pkce = await generatePkcePair();
  const clientId = options.clientId || 'portal';
  const redirectUri = options.redirectUri || (typeof window !== 'undefined' ? window.location.href : '');
  const state = options.state || Math.random().toString(36).substring(2);

  const authUrl = buildAuthorizeUrl({
    clientId,
    redirectUri,
    codeChallenge: pkce.codeChallenge,
    codeChallengeMethod: 'S256',
    state,
    mode: options.mode || 'login'
  }, config);

  const width = options.width || 480;
  const height = options.height || 640;
  const left = typeof window !== 'undefined' && window.screen ? Math.max(0, (window.screen.width - width) / 2) : 100;
  const top = typeof window !== 'undefined' && window.screen ? Math.max(0, (window.screen.height - height) / 2) : 100;

  const popupWindow = typeof window !== 'undefined' && typeof window.open === 'function'
    ? window.open(authUrl, 'lanzar_auth_popup', `width=${width},height=${height},top=${top},left=${left},resizable=yes,scrollbars=yes`)
    : null;

  return new Promise((resolve, reject) => {
    let messageReceived = false;
    let timer = null;

    const cleanup = () => {
      if (typeof window !== 'undefined') {
        window.removeEventListener('message', onMessage);
      }
      if (timer) clearInterval(timer);
    };

    const onMessage = (event) => {
      // 1. Strict Origin Verification
      if (event.origin !== config.authHubUrl) return;
      // 2. Strict Source Window Verification
      if (popupWindow && event.source !== popupWindow) return;

      const data = event.data;
      if (data && data.type === 'lanzar:authenticated' && data.payload) {
        messageReceived = true;
        cleanup();
        resolve({
          code: data.payload.code,
          state: data.payload.state,
          codeVerifier: pkce.codeVerifier
        });
      }
    };

    if (typeof window !== 'undefined') {
      window.addEventListener('message', onMessage);
      timer = setInterval(() => {
        if (popupWindow && popupWindow.closed && !messageReceived) {
          cleanup();
          reject(new Error('User closed authentication popup window.'));
        }
      }, 500);
      if (timer && typeof timer.unref === 'function') {
        timer.unref();
      }
    } else {
      resolve({
        authUrl,
        codeVerifier: pkce.codeVerifier,
        state
      });
    }
  });
}

let template = null;
if (typeof document !== 'undefined') {
  template = document.createElement('template');
  template.innerHTML = `
    <style>
      :host {
        display: none;
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        z-index: 999999;
        box-sizing: border-box;
      }
      :host([open]) {
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .backdrop {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(10, 15, 29, 0.75);
        backdrop-filter: blur(8px);
      }
      .modal-card {
        position: relative;
        width: 100%;
        max-width: 460px;
        background: #0d1326;
        border: 1px solid rgba(0, 240, 255, 0.25);
        border-radius: 12px;
        box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6), 0 0 30px rgba(0, 240, 255, 0.15);
        overflow: hidden;
        z-index: 10;
        display: flex;
        flex-direction: column;
      }
      .modal-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 16px 20px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.08);
      }
      .modal-title {
        color: #e0f2fe;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        font-size: 16px;
        font-weight: 600;
        letter-spacing: 0.02em;
        margin: 0;
      }
      .close-btn {
        background: transparent;
        border: none;
        color: #94a3b8;
        font-size: 20px;
        cursor: pointer;
        padding: 4px;
        line-height: 1;
      }
      .close-btn:hover {
        color: #f1f5f9;
      }
      .iframe-container {
        width: 100%;
        height: 520px;
        border: none;
      }
      iframe {
        width: 100%;
        height: 100%;
        border: none;
      }
    </style>
    <div class="backdrop" id="backdrop"></div>
    <div class="modal-card">
      <div class="modal-header">
        <h3 class="modal-title">LANZAR ID</h3>
        <button class="close-btn" id="closeBtn" aria-label="Close modal">&times;</button>
      </div>
      <div class="iframe-container">
        <iframe id="authFrame" src="" title="LANZAR ID Login"></iframe>
      </div>
    </div>
  `;
}

const BaseElement = typeof HTMLElement !== 'undefined' ? HTMLElement : class {};

class LanzarAuthModal extends BaseElement {
  static get observedAttributes() {
    return ['open', 'continue-url', 'mode', 'client-id', 'redirect-uri'];
  }

  constructor() {
    super();
    if (typeof this.attachShadow === 'function') {
      this.attachShadow({ mode: 'open' });
      if (template) {
        this.shadowRoot.appendChild(template.content.cloneNode(true));
      }
    }
    this._config = STAGING_CONFIG;
    this._boundOnMessage = this._onMessage.bind(this);
    this._codeVerifier = null;
  }

  connectedCallback() {
    if (this.shadowRoot) {
      this.shadowRoot.getElementById('closeBtn')?.addEventListener('click', () => this.close());
      this.shadowRoot.getElementById('backdrop')?.addEventListener('click', () => this.close());
    }
    if (typeof window !== 'undefined') {
      window.addEventListener('message', this._boundOnMessage);
    }
  }

  disconnectedCallback() {
    if (typeof window !== 'undefined') {
      window.removeEventListener('message', this._boundOnMessage);
    }
  }

  attributeChangedCallback(name, oldValue, newValue) {
    if (name === 'open' && this.hasAttribute('open')) {
      this._loadAuthFrame();
    }
  }

  open() {
    if (typeof this.setAttribute === 'function') {
      this.setAttribute('open', '');
    }
  }

  close() {
    if (typeof this.removeAttribute === 'function') {
      this.removeAttribute('open');
    }
    const frame = this.shadowRoot?.getElementById('authFrame');
    if (frame) frame.src = '';
    if (typeof this.dispatchEvent === 'function') {
      const evt = typeof CustomEvent !== 'undefined' 
        ? new CustomEvent('lanzar:closed', { bubbles: true, composed: true })
        : { type: 'lanzar:closed' };
      this.dispatchEvent(evt);
    }
  }

  async openWithPkce(options = {}) {
    const pkce = await generatePkcePair();
    this._codeVerifier = pkce.codeVerifier;

    const clientId = options.clientId || this.getAttribute('client-id') || 'portal';
    const redirectUri = options.redirectUri || this.getAttribute('redirect-uri') || (typeof window !== 'undefined' ? window.location.href : '');
    const state = options.state || Math.random().toString(36).substring(2);

    const authUrl = buildAuthorizeUrl({
      clientId,
      redirectUri,
      codeChallenge: pkce.codeChallenge,
      codeChallengeMethod: 'S256',
      state,
      mode: options.mode || this.getAttribute('mode')
    }, this._config);

    const frame = this.shadowRoot?.getElementById('authFrame');
    if (frame) {
      frame.src = authUrl;
    }
    this.open();

    return {
      codeVerifier: pkce.codeVerifier,
      state
    };
  }

  _loadAuthFrame() {
    const frame = this.shadowRoot?.getElementById('authFrame');
    if (!frame) return;

    // If already loaded by openWithPkce, don't overwrite
    if (frame.src && frame.src !== 'about:blank' && frame.src !== '') {
      return;
    }

    const rawContinue = this.getAttribute('continue-url') || (typeof window !== 'undefined' ? window.location.href : '');
    const validatedContinue = sanitizeContinuationUrl(rawContinue, this._config);
    const mode = this.getAttribute('mode') || 'login';

    const url = new URL(this._config.authHubUrl);
    url.searchParams.set('continueUrl', validatedContinue);
    url.searchParams.set('mode', mode);

    frame.src = url.href;
  }

  _onMessage(event) {
    // 1. Strict Origin Verification
    if (event.origin !== this._config.authHubUrl) {
      return;
    }

    // 2. Strict Source Window Verification: ensure message originates from our iframe
    const frame = this.shadowRoot?.getElementById('authFrame');
    if (frame && frame.contentWindow && event.source !== frame.contentWindow) {
      return;
    }

    const data = event.data;
    if (!data || typeof data !== 'object') return;

    if (data.type === 'lanzar:authenticated') {
      const payload = {
        ...data.payload,
        codeVerifier: this._codeVerifier
      };

      if (typeof this.dispatchEvent === 'function') {
        const evt = typeof CustomEvent !== 'undefined'
          ? new CustomEvent('lanzar:authenticated', {
              detail: payload,
              bubbles: true,
              composed: true
            })
          : { type: 'lanzar:authenticated', detail: payload };
        this.dispatchEvent(evt);
      }
      this.close();
    } else if (data.type === 'lanzar:close') {
      this.close();
    }
  }

  // Static helper methods for testing and programmatic integration
  static sanitizeContinuationUrl(url, config) {
    return sanitizeContinuationUrl(url, config);
  }

  static generateCodeVerifier(length) {
    return generateCodeVerifier(length);
  }

  static generateCodeChallenge(verifier) {
    return generateCodeChallenge(verifier);
  }

  static generatePkcePair(length) {
    return generatePkcePair(length);
  }

  static buildAuthorizeUrl(options, config) {
    return buildAuthorizeUrl(options, config);
  }

  static exchangeCodeForSession(options, config) {
    return exchangeCodeForSession(options, config);
  }

  static openPopup(options, config) {
    return openPopup(options, config);
  }

  static get config() {
    return STAGING_CONFIG;
  }
}

// Programmatic LanzarAuth SDK Object
const LanzarAuth = {
  LanzarAuthModal,
  generateCodeVerifier,
  generateCodeChallenge,
  generatePkcePair,
  buildAuthorizeUrl,
  exchangeCodeForSession,
  sanitizeContinuationUrl,
  openPopup,
  configs: {
    staging: STAGING_CONFIG,
    production: PRODUCTION_CONFIG,
    development: DEVELOPMENT_CONFIG
  }
};

if (typeof customElements !== 'undefined' && !customElements.get('lanzar-auth-modal')) {
  customElements.define('lanzar-auth-modal', LanzarAuthModal);
}

// Expose to window for browser script tag usage
if (typeof window !== 'undefined') {
  window.LanzarAuthModal = LanzarAuthModal;
  window.LanzarAuth = LanzarAuth;
  window.sanitizeContinuationUrl = sanitizeContinuationUrl;
}

export { 
  LanzarAuthModal, 
  LanzarAuth,
  generateCodeVerifier,
  generateCodeChallenge,
  generatePkcePair,
  buildAuthorizeUrl,
  exchangeCodeForSession,
  sanitizeContinuationUrl, 
  openPopup,
  STAGING_CONFIG,
  PRODUCTION_CONFIG,
  DEVELOPMENT_CONFIG
};

export default LanzarAuthModal;
