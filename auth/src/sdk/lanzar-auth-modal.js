/**
 * LANZAR ID Client SDK — <lanzar-auth-modal> v1.0.0 (Staging Channel)
 * Classification: Authoritative Client Authentication Component
 * Distribution Target: https://auth-dev.lanzar.me/sdk/v1.0.0/lanzar-auth-modal.js
 * (LID-ARCH-REV-015 §8.1, §9.4)
 */

'use strict';

// Environment-specific configuration baked into build (Staging)
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
    return ['open', 'continue-url', 'mode'];
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
    this.setAttribute('open', '');
  }

  close() {
    this.removeAttribute('open');
    const frame = this.shadowRoot?.getElementById('authFrame');
    if (frame) frame.src = '';
    if (typeof this.dispatchEvent === 'function') {
      this.dispatchEvent(new CustomEvent('lanzar:closed', { bubbles: true, composed: true }));
    }
  }

  _loadAuthFrame() {
    const frame = this.shadowRoot?.getElementById('authFrame');
    if (!frame) return;
    const rawContinue = this.getAttribute('continue-url') || (typeof window !== 'undefined' ? window.location.href : '');
    const validatedContinue = sanitizeContinuationUrl(rawContinue, this._config);
    const mode = this.getAttribute('mode') || 'login';

    const url = new URL(this._config.authHubUrl);
    url.searchParams.set('continueUrl', validatedContinue);
    url.searchParams.set('mode', mode);

    frame.src = url.href;
  }

  _onMessage(event) {
    if (event.origin !== this._config.authHubUrl) {
      return;
    }
    const data = event.data;
    if (!data || typeof data !== 'object') return;

    if (data.type === 'lanzar:authenticated') {
      if (typeof this.dispatchEvent === 'function') {
        this.dispatchEvent(
          new CustomEvent('lanzar:authenticated', {
            detail: data.payload,
            bubbles: true,
            composed: true
          })
        );
      }
      this.close();
    } else if (data.type === 'lanzar:close') {
      this.close();
    }
  }

  // Static helper for testing and verification
  static sanitizeContinuationUrl(url, config) {
    return sanitizeContinuationUrl(url, config);
  }

  static get config() {
    return STAGING_CONFIG;
  }
}

if (typeof customElements !== 'undefined' && !customElements.get('lanzar-auth-modal')) {
  customElements.define('lanzar-auth-modal', LanzarAuthModal);
}

// Also expose to window for direct script tag usage
if (typeof window !== 'undefined') {
  window.LanzarAuthModal = LanzarAuthModal;
  window.sanitizeContinuationUrl = sanitizeContinuationUrl;
}

export { LanzarAuthModal, sanitizeContinuationUrl, STAGING_CONFIG };
export default LanzarAuthModal;

