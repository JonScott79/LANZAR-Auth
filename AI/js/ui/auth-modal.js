/*
    auth-modal.js

    Atomic Age Authentication & Identity Hub Modal for LANZAR AI.

    Responsibilities:
    - Present clean, in-character sign-in options (Google OAuth / LANZAR Auth Hub / Identity Switcher)
    - Display current authenticated identity (UID, display name, email)
    - Provide immediate identity switching for multi-user security verification
    - Coordinate with authService for login, logout, and session restoration
*/

import { authService } from "../auth/auth-service.js";
import { globalBus } from "../core/event-bus.js";

function escapeHtml(val) {
  return String(val ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export class AuthModalController {
  #container = null;

  constructor(containerElement) {
    this.#container = containerElement;
    this.#init();
  }

  #init() {
    if (!this.#container) return;
    this.#render();
    this.#bindEvents();

    globalBus.on("action:open-auth-modal", () => {
      this.open();
    });

    globalBus.on("auth:changed", () => {
      this.#render();
      this.#bindEvents();
    });
  }

  #render() {
    const user = authService.getUser();
    const isAuthenticated = authService.isAuthenticated();

    this.#container.innerHTML = `
      <div class="modal-backdrop" id="authBackdrop" role="dialog" aria-modal="true" aria-labelledby="authModalTitle">
        <div class="modal-window auth-modal-window">
          
          <header class="modal-header">
            <h2 class="modal-title" id="authModalTitle">🔐 LANZAR Auth Hub</h2>
            <button class="btn btn-icon" id="btnCloseAuth" aria-label="Close Auth Modal" style="background: rgba(0,0,0,0.06); color: var(--deep-navy);">
              ✕
            </button>
          </header>

          <div class="modal-body">
            
            ${isAuthenticated ? `
              <!-- Active Authenticated Profile -->
              <div class="auth-profile-card">
                <div class="auth-avatar-circle">
                  ${escapeHtml(user.displayName ? user.displayName.charAt(0).toUpperCase() : 'U')}
                </div>
                <div class="auth-profile-details">
                  <span class="auth-display-name">${escapeHtml(user.displayName || 'Authenticated Pilot')}</span>
                  <span class="auth-email">${escapeHtml(user.email || 'pilot@lanzar.me')}</span>
                  <span class="auth-uid-badge">UID: <code>${escapeHtml(user.uid)}</code></span>
                </div>
              </div>

              <div style="margin-top: 1rem; display: flex; flex-direction: column; gap: 0.5rem;">
                <p style="font-size: 0.8rem; color: var(--text-secondary);">
                  You are signed in with server-authoritative identity. All conversations and research projects are private to your UID.
                </p>
                <button type="button" class="btn btn-secondary" id="btnAuthSignOut" style="background: #e53e3e; align-self: flex-start; color: #fff;">
                  🚪 Sign Out
                </button>
              </div>
            ` : `
              <!-- Sign In Actions -->
              <div style="text-align: center; margin-bottom: 1.25rem;">
                <h3 style="font-family: var(--font-heading); font-size: 1.15rem; color: var(--deep-navy); margin-bottom: 0.35rem;">
                  Welcome to LANZAR AI
                </h3>
                <p style="font-size: 0.82rem; color: var(--text-secondary); line-height: 1.4;">
                  Sign in to access your private conversation threads, neural models, and isolated workspace memory.
                </p>
              </div>

              <div style="display: flex; flex-direction: column; gap: 0.75rem;">
                <button type="button" class="btn btn-primary" id="btnSignInLanzarId" style="width: 100%; justify-content: center; font-size: 0.9rem; padding: 0.75rem;">
                  Sign in with LANZAR ID
                </button>
              </div>
            `}

          </div>
        </div>
      </div>
    `;
  }

  open() {
    this.#render();
    this.#bindEvents();
    const backdrop = this.#container.querySelector("#authBackdrop");
    backdrop?.classList.add("open");
  }

  close() {
    const backdrop = this.#container.querySelector("#authBackdrop");
    backdrop?.classList.remove("open");
  }

  #bindEvents() {
    const btnClose = this.#container.querySelector("#btnCloseAuth");
    const backdrop = this.#container.querySelector("#authBackdrop");
    const btnSignOut = this.#container.querySelector("#btnAuthSignOut");
    const btnSignIn = this.#container.querySelector("#btnSignInLanzarId");

    btnClose?.addEventListener("click", () => this.close());
    backdrop?.addEventListener("click", (e) => {
      if (e.target === backdrop) this.close();
    });

    btnSignOut?.addEventListener("click", () => {
      authService.signOut();
      this.close();
    });

    btnSignIn?.addEventListener("click", () => {
      authService.signInWithLanzarId();
    });
  }
}
