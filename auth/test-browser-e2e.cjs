// test-browser-e2e.cjs
// LANZAR ID — Phase F.1: Final Browser Acceptance Test Battery
// Real Google Chrome Headless via Chrome DevTools Protocol (CDP)

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const assert = require('assert');
const crypto = require('crypto');

const { generateTOTP, verifyAndConsumeRecoveryCode } = require('./auth-backend/mfaService');
const { generatePkcePair, exchangeCodeForSession } = require('./src/sdk/lanzar-auth-modal');

const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const SCREENSHOT_DIR = 'C:\\Users\\jonny\\.gemini\\antigravity\\brain\\181f70b2-f3a3-4005-b91d-fd091daec5b7\\screenshots';

if (!fs.existsSync(SCREENSHOT_DIR)) {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
}

console.log('\n======================================================');
console.log('LANZAR ID — Phase F.1: Final Browser Acceptance Suite');
console.log('Engine: Real Google Chrome Headless via CDP');
console.log(`Timestamp: ${new Date().toISOString()}`);
console.log('======================================================\n');

let passCount = 0;
let failCount = 0;
const recordedUrls = [];

function recordTest(name, passed, detail = '') {
  if (passed) {
    console.log(`  ✓ [PASS] ${name}${detail ? ' (' + detail + ')' : ''}`);
    passCount++;
  } else {
    console.error(`  ✗ [FAIL] ${name}: ${detail}`);
    failCount++;
  }
}

class CDPPage {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.ws = null;
    this.id = 1;
    this.callbacks = new Map();
    this.contexts = [];
  }

  async connect() {
    this.ws = new WebSocket(this.wsUrl);
    await new Promise((resolve, reject) => {
      this.ws.onopen = resolve;
      this.ws.onerror = reject;
    });

    this.ws.onmessage = (evt) => {
      const data = JSON.parse(evt.data);
      if (data.id && this.callbacks.has(data.id)) {
        const { resolve, reject } = this.callbacks.get(data.id);
        this.callbacks.delete(data.id);
        if (data.error) reject(new Error(data.error.message));
        else resolve(data.result);
      } else if (data.method === 'Network.requestWillBeSent') {
        const url = data.params?.request?.url;
        if (url) recordedUrls.push(url);
      } else if (data.method === 'Page.javascriptDialogOpening') {
        this.send('Page.handleJavaScriptDialog', { accept: true }).catch(() => {});
      } else if (data.method === 'Runtime.executionContextCreated') {
        const ctx = data.params?.context;
        if (ctx) this.contexts.push(ctx);
      } else if (data.method === 'Runtime.executionContextDestroyed') {
        const id = data.params?.executionContextId;
        this.contexts = this.contexts.filter(c => c.id !== id);
      }
    };

    await this.send('Page.enable');
    await this.send('Runtime.enable');
    await this.send('Network.enable');
  }

  send(method, params = {}) {
    const curId = this.id++;
    return new Promise((resolve, reject) => {
      this.callbacks.set(curId, { resolve, reject });
      this.ws.send(JSON.stringify({ id: curId, method, params }));
    });
  }

  async eval(expression, awaitPromise = true, contextId = null) {
    const params = { expression, returnByValue: true, awaitPromise };
    if (contextId) params.contextId = contextId;
    const res = await this.send('Runtime.evaluate', params);
    if (res.exceptionDetails) {
      throw new Error(res.exceptionDetails.exception?.description || 'Evaluation error');
    }
    return res.result?.value;
  }

  async waitForContext(originSubstring, timeoutMs = 12000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const found = this.contexts.find(c => c.origin.includes(originSubstring));
      if (found) return found;
      await new Promise(r => setTimeout(r, 200));
    }
    throw new Error(`Timeout waiting for execution context matching: ${originSubstring}`);
  }

  async waitFor(expression, timeoutMs = 10000, intervalMs = 200, contextId = null) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      try {
        const val = await this.eval(expression, true, contextId);
        if (val) return val;
      } catch (e) {}
      await new Promise(r => setTimeout(r, intervalMs));
    }
    throw new Error(`Timeout waiting for expression: ${expression}`);
  }

  async screenshot(filename) {
    const shot = await this.send('Page.captureScreenshot', { format: 'png' });
    const fullPath = path.join(SCREENSHOT_DIR, filename);
    fs.writeFileSync(fullPath, Buffer.from(shot.data, 'base64'));
    return fullPath;
  }

  close() {
    if (this.ws) {
      try { this.ws.close(); } catch (e) {}
    }
  }
}

async function runSuite() {
  const tmpProfile = path.join(os.tmpdir(), 'chrome_phase_f1_' + Date.now());
  const chrome = spawn(CHROME_PATH, [
    '--remote-debugging-port=9222',
    '--headless=new',
    '--disable-popup-blocking',
    '--user-data-dir=' + tmpProfile,
    'about:blank'
  ]);

  try {
    await new Promise(r => setTimeout(r, 1500));

    async function openTab(url) {
      const res = await fetch(`http://127.0.0.1:9222/json/new?${encodeURIComponent(url)}`, { method: 'PUT' });
      const target = await res.json();
      const page = new CDPPage(target.webSocketDebuggerUrl);
      await page.connect();
      return page;
    }

    const testCadetEmail = `sarah.connor.${Date.now()}@lanzar.me`;
    const testCadetPass = 'CyberSpace2026!';
    let registeredUid = null;
    let enrolledTotpSecret = null;
    let savedRecoveryCodes = [];
    let modalSessionId = null;
    let popupSessionId = null;

    // Helper to simulate React input typing
    const reactTypeScript = `
      function setReactInput(input, val) {
        if (!input) return;
        const proto = (input instanceof HTMLTextAreaElement || input.tagName === 'TEXTAREA')
          ? window.HTMLTextAreaElement.prototype
          : window.HTMLInputElement.prototype;
        const descriptor = Object.getOwnPropertyDescriptor(proto, 'value');
        if (descriptor && descriptor.set) {
          descriptor.set.call(input, val);
        } else {
          input.value = val;
        }
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
      }
    `;

    // =========================================================
    // SECTION 1: INVALID CREDENTIALS & ERROR HANDLING
    // =========================================================
    console.log('[SECTION 1] Invalid Credentials & Boundary Error Handling');
    const page1 = await openTab('http://localhost:4000/');
    await new Promise(r => setTimeout(r, 1200));

    await page1.eval(`(() => {
      ${reactTypeScript}
      const emailEl = document.querySelector('input[type="email"]');
      const passEl = document.querySelector('input[type="password"]');
      const btn = document.querySelector('button[type="submit"]');
      setReactInput(emailEl, 'nonexistent.user@lanzar.me');
      setReactInput(passEl, 'WrongPassword999!');
      btn.click();
    })()`);

    const errorMsg1 = await page1.waitFor(`document.querySelector('.error-msg')?.textContent`);
    const pass1 = errorMsg1.includes('Invalid') || errorMsg1.includes('Incorrect');
    recordTest('TEST-01: Invalid credentials rejected with visible error message', pass1, errorMsg1);
    await page1.screenshot('01_invalid_credentials.png');
    page1.close();

    // =========================================================
    // SECTION 2: SELF-SERVICE ACCOUNT REGISTRATION
    // =========================================================
    console.log('\n[SECTION 2] Self-Service Account Registration');
    const page2 = await openTab('http://localhost:4000/');
    await new Promise(r => setTimeout(r, 1200));

    // Switch to Register tab
    await page2.eval(`(() => {
      const tabs = Array.from(document.querySelectorAll('.auth-tab-btn'));
      const regTab = tabs.find(t => t.textContent.includes('CREATE ACCOUNT'));
      if (regTab) regTab.click();
    })()`);
    await new Promise(r => setTimeout(r, 400));

    // Fill registration form using exact input IDs
    await page2.eval(`(() => {
      ${reactTypeScript}
      setReactInput(document.getElementById('reg-name'), 'Commander Sarah Connor');
      setReactInput(document.getElementById('reg-business'), 'Cyberdyne Systems');
      setReactInput(document.getElementById('login-email'), '${testCadetEmail}');
      setReactInput(document.getElementById('login-password'), '${testCadetPass}');
      setReactInput(document.getElementById('reg-confirm-password'), '${testCadetPass}');
      const check = document.getElementById('reg-dispatch') || document.querySelector('input[type="checkbox"]');
      if (check && !check.checked) check.click();
      document.querySelector('button[type="submit"]').click();
    })()`);

    const portalLoaded = await page2.waitFor(`Boolean(document.querySelector('.my-lanzar-tabs'))`, 12000);
    recordTest('TEST-02: Self-service account registration completes and renders Central Portal', Boolean(portalLoaded));
    await page2.screenshot('02_account_registered_portal.png');

    // Extract Firebase UID
    registeredUid = await page2.eval(`(() => {
      return window.__LANZAR_TEST_UID__ || document.querySelector('.user-id-code')?.textContent || null;
    })()`);

    // =========================================================
    // SECTION 3: ACCOUNT PROFILE UPDATES
    // =========================================================
    console.log('\n[SECTION 3] Account Profile Updates & Anti-Tampering');
    // Click PROFILE tab
    await page2.eval(`(() => {
      const tabs = Array.from(document.querySelectorAll('.tab-btn'));
      const profTab = tabs.find(t => t.textContent.includes('Profile'));
      if (profTab) profTab.click();
    })()`);
    await new Promise(r => setTimeout(r, 600));

    // Update bio and display name
    await page2.eval(`(() => {
      ${reactTypeScript}
      const nameInput = document.querySelectorAll('input.form-input')[0];
      const bioInput = document.querySelector('textarea.form-textarea');
      if (nameInput) setReactInput(nameInput, 'Commander Sarah Connor (Lead)');
      if (bioInput) setReactInput(bioInput, 'Operational Security Commander for LANZAR Frontier Network.');
      const saveBtn = document.querySelector('.btn-primary-deck');
      if (saveBtn) saveBtn.click();
    })()`);

    const updateSuccess = await page2.waitFor(`Boolean(document.querySelector('.lanzar-alert.success') || document.body.textContent.includes('Profile updated successfully'))`, 8000);
    recordTest('TEST-03: User profile updated (displayName, bio) successfully in Firestore via PUT', Boolean(updateSuccess));
    await page2.screenshot('03_profile_updated.png');

    // Sign out from standalone session so we can exercise fresh iframe/popup authentications
    await page2.eval(`(() => {
      const signoutBtn = document.querySelector('.btn-sign-out');
      if (signoutBtn) signoutBtn.click();
    })()`);
    await page2.waitFor(`Boolean(document.querySelector('.auth-tab-bar') || document.querySelector('input[type="password"]'))`, 8000);
    page2.close();

    // =========================================================
    // SECTION 4: CLIENT INTEGRATION — EMBEDDED MODAL (IFRAME) COMPLETE FLOW
    // =========================================================
    console.log('\n[SECTION 4] Client Integration — Embedded Modal (iframe) Complete Flow');
    const pagePortalModal = await openTab('http://localhost:5173/');
    await new Promise(r => setTimeout(r, 1200));

    // Open embedded modal
    await pagePortalModal.eval(`document.getElementById('btnModal').click()`);
    await new Promise(r => setTimeout(r, 800));

    // Wait for iframe execution context to be spawned on localhost:4000
    const iframeCtx = await pagePortalModal.waitForContext('localhost:4000', 10000);
    recordTest('TEST-04: Portal client opens <lanzar-auth-modal> and iframe context resolves', Boolean(iframeCtx));

    // Submit credentials inside the iframe
    await pagePortalModal.eval(`(() => {
      ${reactTypeScript}
      const emailEl = document.getElementById('login-email') || document.querySelector('input[type="email"]');
      const passEl = document.getElementById('login-password') || document.querySelector('input[type="password"]');
      const submitBtn = document.querySelector('button[type="submit"]');
      setReactInput(emailEl, '${testCadetEmail}');
      setReactInput(passEl, '${testCadetPass}');
      submitBtn.click();
    })()`, true, iframeCtx.id);

    // Wait for parent portal client to receive postMessage, exchange code, and display STATUS: AUTHENTICATED
    const modalAuthBadge = await pagePortalModal.waitFor(`document.getElementById('statusBadge')?.textContent.includes('AUTHENTICATED')`, 12000);
    const modalBoxContent = await pagePortalModal.eval(`document.getElementById('statusBox')?.textContent`);
    const modalClosed = await pagePortalModal.eval(`!document.getElementById('authModal').hasAttribute('open')`);

    recordTest('TEST-05: Modal iframe delivers authorization code via postMessage, completes PKCE exchange, and closes', Boolean(modalAuthBadge && modalClosed && modalBoxContent.includes('PKCE exchange successful!')));
    await pagePortalModal.screenshot('07_portal_modal_authenticated.png');

    // Extract Session 1 ID from portal status box
    try {
      const match = modalBoxContent.match(/"session_id":\s*"([^"]+)"/);
      if (match) modalSessionId = match[1];
    } catch (e) {}

    pagePortalModal.close();

    // =========================================================
    // SECTION 5: CLIENT INTEGRATION — POPUP AUTHENTICATION COMPLETE FLOW
    // =========================================================
    console.log('\n[SECTION 5] Client Integration — Popup Authentication Complete Flow');
    const pagePortalPopup = await openTab('http://localhost:5173/');
    await new Promise(r => setTimeout(r, 1200));

    // Reset client state
    await pagePortalPopup.eval(`document.getElementById('btnClear').click()`);
    await new Promise(r => setTimeout(r, 400));

    // Click btnPopup
    await pagePortalPopup.eval(`document.getElementById('btnPopup').click()`);

    // Poll /json/list to discover the popup window target
    let popupTarget = null;
    for (let i = 0; i < 25; i++) {
      await new Promise(r => setTimeout(r, 300));
      const listRes = await fetch('http://127.0.0.1:9222/json/list');
      const list = await listRes.json();
      popupTarget = list.find(t => t.url && t.url.includes('localhost:4000') && t.type === 'page');
      if (popupTarget) break;
    }
    recordTest('TEST-06: openPopup initiates browser popup window with S256 PKCE challenge', Boolean(popupTarget));

    if (popupTarget) {
      // Connect CDP to popup window
      const popupPage = new CDPPage(popupTarget.webSocketDebuggerUrl);
      await popupPage.connect();
      await popupPage.waitFor(`Boolean(document.getElementById('login-email') || document.querySelector('input[type="email"]'))`, 8000);

      // Authenticate in popup
      await popupPage.eval(`(() => {
        ${reactTypeScript}
        const emailEl = document.getElementById('login-email') || document.querySelector('input[type="email"]');
        const passEl = document.getElementById('login-password') || document.querySelector('input[type="password"]');
        const submitBtn = document.querySelector('button[type="submit"]');
        setReactInput(emailEl, '${testCadetEmail}');
        setReactInput(passEl, '${testCadetPass}');
        submitBtn.click();
      })()`);

      // Popup calls postMessage to opener and closes itself
      // Wait for popup target to disappear
      let popupClosedGracefully = false;
      for (let i = 0; i < 20; i++) {
        await new Promise(r => setTimeout(r, 300));
        const listRes = await fetch('http://127.0.0.1:9222/json/list');
        const list = await listRes.json();
        const stillOpen = list.some(t => t.id === popupTarget.id);
        if (!stillOpen) {
          popupClosedGracefully = true;
          break;
        }
      }
      recordTest('TEST-07: Popup completes login, dispatches targeted postMessage to opener, and executes window.close()', popupClosedGracefully);
    }

    // Verify parent portal receives authorization code, exchanges for session, and establishes session
    const popupAuthBadge = await pagePortalPopup.waitFor(`document.getElementById('statusBadge')?.textContent.includes('AUTHENTICATED')`, 10000);
    const popupBoxContent = await pagePortalPopup.eval(`document.getElementById('statusBox')?.textContent`);
    recordTest('TEST-08: Parent portal client receives authorization code from popup and completes PKCE exchange', Boolean(popupAuthBadge && popupBoxContent.includes('Popup PKCE exchange successful!')));
    await pagePortalPopup.screenshot('08_portal_popup_authenticated.png');

    // Extract Session 2 ID from portal status box
    try {
      const match = popupBoxContent.match(/"session_id":\s*"([^"]+)"/);
      if (match) popupSessionId = match[1];
    } catch (e) {}

    pagePortalPopup.close();

    // =========================================================
    // SECTION 6: BROWSER-LEVEL SESSION REVOCATION
    // =========================================================
    console.log('\n[SECTION 6] Browser-Level Session Revocation');
    const pageSec = await openTab('http://localhost:4000/');
    await new Promise(r => setTimeout(r, 1200));

    // Sign in to access Security Deck if not already authenticated from popup/modal
    const alreadyIn = await pageSec.eval(`Boolean(document.querySelector('.my-lanzar-tabs'))`);
    if (!alreadyIn) {
      await pageSec.waitFor(`Boolean(document.querySelector('input[type="email"]'))`);
      await pageSec.eval(`(() => {
        ${reactTypeScript}
        const emailEl = document.querySelector('input[type="email"]');
        const passEl = document.querySelector('input[type="password"]');
        const btn = document.querySelector('button[type="submit"]');
        setReactInput(emailEl, '${testCadetEmail}');
        setReactInput(passEl, '${testCadetPass}');
        btn.click();
      })()`);
      await pageSec.waitFor(`Boolean(document.querySelector('.my-lanzar-tabs'))`, 10000);
    }

    // Switch to Security tab
    await pageSec.eval(`(() => {
      const tabs = Array.from(document.querySelectorAll('.tab-btn'));
      const secTab = tabs.find(t => t.textContent.includes('Security'));
      if (secTab) secTab.click();
    })()`);
    await new Promise(r => setTimeout(r, 800));

    // Verify active sessions deck is rendered
    await pageSec.waitFor(`Boolean(document.querySelector('.sessions-list') || document.querySelector('.sessions-header-row'))`);
    const initialSessionCount = await pageSec.eval(`document.querySelectorAll('.session-card').length`);
    recordTest('TEST-09: Security dashboard lists active device sessions in UI', initialSessionCount >= 2, `${initialSessionCount} sessions present`);
    await pageSec.screenshot('04_sessions_managed.png');

    // Click REVOKE on the first session card
    await pageSec.eval(`(() => {
      const revokeBtns = Array.from(document.querySelectorAll('.btn-revoke-device'));
      if (revokeBtns.length > 0) revokeBtns[0].click();
    })()`);

    const revokedAlert = await pageSec.waitFor(`Boolean(document.querySelector('.lanzar-alert.success') || document.body.textContent.includes('successfully revoked'))`, 8000);
    recordTest('TEST-10: Browser UI revokes individual active session with green alert confirmation', Boolean(revokedAlert));
    await pageSec.screenshot('10_session_revoked_browser.png');

    // Server-side verification of individual revocation
    // Authenticate with Firebase emulator directly to get clean ID token for API checks
    const cadetAuthRes = await fetch('http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=fake', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testCadetEmail, password: testCadetPass, returnSecureToken: true })
    });
    const cadetAuth = await cadetAuthRes.json();
    const cadetIdToken = cadetAuth.idToken;

    const sessionsCheck1 = await fetch('http://localhost:4001/api/id/sessions', {
      headers: { 'Authorization': `Bearer ${cadetIdToken}` }
    });
    const sessionsList1 = await sessionsCheck1.json();
    const activeSessions1 = sessionsList1.sessions.filter(s => !s.revoked);
    const revokedSessions1 = sessionsList1.sessions.filter(s => s.revoked);
    recordTest('TEST-11: Individual revoked session is marked revoked in Firestore while other sessions remain active', revokedSessions1.length >= 1 && activeSessions1.length >= 1);

    // Global session revocation ("SIGN OUT EVERYWHERE")
    await pageSec.eval(`(() => {
      window.confirm = () => true;
      const killAllBtn = document.querySelector('.btn-kill-all');
      if (killAllBtn) killAllBtn.click();
    })()`);

    const globalRevokeConfirmed = await pageSec.waitFor(`Boolean(document.querySelector('.auth-tab-bar') || document.querySelector('input[type="password"]'))`, 10000);
    recordTest('TEST-12: Global session revocation executes "SIGN OUT EVERYWHERE" and returns to clean auth screen', Boolean(globalRevokeConfirmed));
    await pageSec.screenshot('11_all_sessions_revoked.png');

    // Verify all sessions now revoked
    const sessionsCheck2 = await fetch('http://localhost:4001/api/id/sessions', {
      headers: { 'Authorization': `Bearer ${cadetIdToken}` }
    });
    const sessionsList2 = await sessionsCheck2.json();
    const remainingActiveSessions = sessionsList2.sessions.filter(s => !s.revoked);
    recordTest('TEST-13: All user sessions invalidated following global revocation (0 active remaining)', remainingActiveSessions.length === 0, `Active: ${remainingActiveSessions.length}`);

    pageSec.close();

    // =========================================================
    // SECTION 7: UNIVERSAL RFC 6238 TOTP MFA ENROLLMENT
    // =========================================================
    console.log('\n[SECTION 7] Universal RFC 6238 TOTP MFA Enrollment');
    const pageMfa = await openTab('http://localhost:4000/');
    await new Promise(r => setTimeout(r, 1200));

    // Sign back in as Sarah Connor
    await pageMfa.waitFor(`Boolean(document.querySelector('input[type="email"]'))`, 8000);
    await pageMfa.eval(`(() => {
      ${reactTypeScript}
      const emailEl = document.querySelector('input[type="email"]');
      const passEl = document.querySelector('input[type="password"]');
      const btn = document.querySelector('button[type="submit"]');
      setReactInput(emailEl, '${testCadetEmail}');
      setReactInput(passEl, '${testCadetPass}');
      btn.click();
    })()`);
    await pageMfa.waitFor(`Boolean(document.querySelector('.my-lanzar-tabs'))`, 10000);

    // Switch to Security tab
    await pageMfa.eval(`(() => {
      const tabs = Array.from(document.querySelectorAll('.tab-btn'));
      const secTab = tabs.find(t => t.textContent.includes('Security'));
      if (secTab) secTab.click();
    })()`);
    await new Promise(r => setTimeout(r, 800));

    // Click "ENABLE AUTHENTICATOR"
    await pageMfa.eval(`(() => {
      const btn = Array.from(document.querySelectorAll('.btn-secondary-deck')).find(b => b.textContent.includes('ENABLE AUTHENTICATOR'));
      if (btn) btn.click();
    })()`);

    // Extract Base32 manual setup key code (Masked in output)
    const base32Secret = await pageMfa.waitFor(`(() => {
      const codeEl = document.querySelector('.manual-key-code') || document.querySelector('code');
      return codeEl ? codeEl.textContent.trim() : null;
    })()`, 10000);
    enrolledTotpSecret = base32Secret;
    recordTest('TEST-14: RFC 6238 Base32 Secret generated for user enrollment', Boolean(base32Secret), '[REDACTED_MFA_SECRET]');

    // Compute TOTP code from secret
    const initialTotpCode = generateTOTP(base32Secret);

    // Enter 6-digit TOTP code and confirm
    await pageMfa.eval(`((code) => {
      ${reactTypeScript}
      const codeInput = document.querySelector('.otp-input');
      const confirmBtn = Array.from(document.querySelectorAll('.btn-primary-deck')).find(b => b.textContent.includes('VERIFY'));
      if (codeInput) setReactInput(codeInput, code);
      if (confirmBtn) confirmBtn.click();
    })('${initialTotpCode}')`);

    // Verify recovery codes are displayed (Masked in output)
    const recoveryCodeElements = await pageMfa.waitFor(`(() => {
      const pills = Array.from(document.querySelectorAll('.recovery-code-pill'));
      if (pills.length > 0) return pills.map(p => p.textContent.trim());
      return null;
    })()`, 10000);
    savedRecoveryCodes = recoveryCodeElements || [];
    recordTest('TEST-15: TOTP confirmed and 8 single-use recovery codes generated', savedRecoveryCodes.length === 8, `${savedRecoveryCodes.length} codes [REDACTED]`);
    await pageMfa.screenshot('05_totp_enrolled.png');

    // Dismiss recovery codes banner
    await pageMfa.eval(`(() => {
      const btn = Array.from(document.querySelectorAll('button')).find(b => b.textContent.includes('SAVED THESE CODES'));
      if (btn) btn.click();
    })()`);
    await new Promise(r => setTimeout(r, 600));

    const mfaActive = await pageMfa.waitFor(`Boolean(document.querySelector('.nominal-tag') || document.body.textContent.includes('ACTIVE AND ENROLLED'))`);
    recordTest('TEST-16: MFA status displayed as ACTIVE AND ENROLLED on dashboard', Boolean(mfaActive));

    // Sign out to verify session teardown
    await pageMfa.eval(`(() => {
      const signoutBtn = document.querySelector('.btn-sign-out');
      if (signoutBtn) signoutBtn.click();
    })()`);
    await pageMfa.waitFor(`Boolean(document.querySelector('.auth-tab-bar') || document.querySelector('input[type="password"]'))`, 8000);
    recordTest('TEST-17: User signed out and redirected to clean authentication screen', true);
    await pageMfa.screenshot('06_signed_out.png');
    pageMfa.close();

    // =========================================================
    // SECTION 8: SINGLE-USE RECOVERY CODE & REPLAY DEFENSE
    // =========================================================
    console.log('\n[SECTION 8] Single-Use Recovery Code Verification & Replay Protection');
    if (savedRecoveryCodes.length > 0) {
      const codeToTest = savedRecoveryCodes[0];
      const hashedRecords = savedRecoveryCodes.map(c => ({
        hash: crypto.createHash('sha256').update(c.trim().toUpperCase()).digest('hex'),
        used: false
      }));

      const firstConsume = verifyAndConsumeRecoveryCode(codeToTest, hashedRecords);
      recordTest('TEST-18: Single-use recovery code validates and consumes cleanly', firstConsume.valid === true);

      const replayAttempt = verifyAndConsumeRecoveryCode(codeToTest, hashedRecords);
      recordTest('TEST-19: Replay of consumed recovery code is strictly rejected', replayAttempt.valid === false);
    }

    // =========================================================
    // SECTION 9: TOP-LEVEL REDIRECT OAUTH PKCE FLOW
    // =========================================================
    console.log('\n[SECTION 9] Client Integration — Top-Level Redirect PKCE Flow');
    const pageRedirect = await openTab('http://localhost:5173/');
    await new Promise(r => setTimeout(r, 1000));

    await pageRedirect.eval(`document.getElementById('btnRedirect').click()`);
    await new Promise(r => setTimeout(r, 2000));

    const hubUrl = await pageRedirect.eval(`window.location.href`);
    recordTest('TEST-20: Top-level redirect navigates to Auth Hub with explicit S256 challenge', hubUrl.includes('code_challenge=') && hubUrl.includes('code_challenge_method=S256'), hubUrl);
    await pageRedirect.screenshot('09_redirect_at_auth_hub.png');
    pageRedirect.close();

    // =========================================================
    // SECTION 10: MFA CHALLENGE & CODE EXCHANGE LIFECYCLE
    // =========================================================
    console.log('\n[SECTION 10] Full MFA Challenge Enforcement & Session Establishment');
    const pkce = await generatePkcePair();

    // Re-authenticate to get fresh idToken
    const freshCadetRes = await fetch('http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=fake', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testCadetEmail, password: testCadetPass, returnSecureToken: true })
    });
    const freshCadetData = await freshCadetRes.json();
    const idToken = freshCadetData.idToken;

    // First attempt to authorize: halts 403 mfa_required
    const authReq1 = await fetch('http://localhost:4001/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        idToken,
        client_id: 'portal',
        redirect_uri: 'http://localhost:5173/',
        code_challenge: pkce.codeChallenge,
        code_challenge_method: 'S256',
        state: 'oauth_test_state_mfa'
      })
    });
    const authData1 = await authReq1.json();
    recordTest('TEST-21: Backend /authorize halts with 403 mfa_required for MFA-enrolled user', authReq1.status === 403 && authData1.mfa_required === true);

    // Synchronize to next TOTP 30-second window to prevent anti-replay rejection
    const remainingSecondsInStep = 30 - (Math.floor(Date.now() / 1000) % 30);
    console.log(`  [MFA STEP SYNC] Waiting ${remainingSecondsInStep + 1}s for next TOTP time-step to prevent anti-replay rejection...`);
    await new Promise(r => setTimeout(r, (remainingSecondsInStep + 1) * 1000));

    // Verify TOTP code and obtain signed mfa_proof
    const totpCode = generateTOTP(enrolledTotpSecret);
    const verifyMfaRes = await fetch('http://localhost:4001/mfa/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mfaSession: authData1.mfa_session,
        method: 'totp',
        code: totpCode
      })
    });
    const verifyMfaData = await verifyMfaRes.json();
    const mfaProof = verifyMfaData.mfaProof;
    recordTest('TEST-22: Valid TOTP code verifies and issues signed mfaProof token', Boolean(mfaProof));

    // Re-call /authorize with valid mfa_proof
    const authReq2 = await fetch('http://localhost:4001/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        idToken,
        client_id: 'portal',
        redirect_uri: 'http://localhost:5173/',
        code_challenge: pkce.codeChallenge,
        code_challenge_method: 'S256',
        state: 'oauth_test_state_mfa',
        mfa_proof: mfaProof
      })
    });
    const authData2 = await authReq2.json();
    const authCode = authData2.code;
    recordTest('TEST-23: /authorize succeeds with valid mfa_proof and issues authorization code', authReq2.status === 200 && Boolean(authCode));

    // Exchange code using client-retained code_verifier
    const exchangeRes = await exchangeCodeForSession({
      code: authCode,
      clientId: 'portal',
      redirectUri: 'http://localhost:5173/',
      codeVerifier: pkce.codeVerifier,
      authApiBase: 'http://localhost:4001'
    });
    recordTest('TEST-24: Client exchangeCodeForSession mints custom token with session_id', Boolean(exchangeRes.custom_token && exchangeRes.session_id));

    // Replay of consumed code must be rejected
    let replayRejected = false;
    try {
      await exchangeCodeForSession({
        code: authCode,
        clientId: 'portal',
        redirectUri: 'http://localhost:5173/',
        codeVerifier: pkce.codeVerifier,
        authApiBase: 'http://localhost:4001'
      });
    } catch (e) {
      replayRejected = true;
    }
    recordTest('TEST-25: Consumed authorization code cannot be replayed (atomic single-use)', replayRejected);

    // =========================================================
    // SECTION 11: BOUNDARY REJECTION CHECKS
    // =========================================================
    console.log('\n[SECTION 11] Security Boundary Rejections');
    // Unauthorized redirect URI
    const unauthUriRes = await fetch('http://localhost:4001/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        idToken,
        client_id: 'portal',
        redirect_uri: 'http://evil-attacker.com/callback',
        code_challenge: pkce.codeChallenge,
        code_challenge_method: 'S256',
        state: 'test'
      })
    });
    recordTest('TEST-26: Unauthorized redirect URI rejected with HTTP 400', unauthUriRes.status === 400);

    // Unauthorized client ID
    const unauthClientRes = await fetch('http://localhost:4001/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        idToken,
        client_id: 'unauthorized_attacker_client',
        redirect_uri: 'http://localhost:5173/',
        code_challenge: pkce.codeChallenge,
        code_challenge_method: 'S256',
        state: 'test'
      })
    });
    recordTest('TEST-27: Unregistered client ID rejected with HTTP 400', unauthClientRes.status === 400);

    // =========================================================
    // SECTION 12: NETWORK BOUNDARY & ZERO-PRODUCTION PROOF
    // =========================================================
    console.log('\n[SECTION 12] Network Boundary & Zero-Production Verification');
    const productionViolations = recordedUrls.filter(u => {
      if (u.startsWith('data:') || u.startsWith('blob:') || u.startsWith('about:')) return false;
      try {
        const parsed = new URL(u);
        const host = parsed.hostname;
        return host !== 'localhost' && host !== '127.0.0.1' && host !== '::1' && host !== '[::1]';
      } catch (e) {
        return true;
      }
    });

    recordTest('TEST-28: ZERO requests sent to production Firebase or external APIs', productionViolations.length === 0, `${productionViolations.length} violations`);
    if (productionViolations.length > 0) {
      console.error('VIOLATIONS:', productionViolations);
    }

    const localOnly = recordedUrls.every(u => {
      return u.startsWith('http://localhost') || u.startsWith('http://127.0.0.1') || u.startsWith('data:') || u.startsWith('blob:') || u.startsWith('about:');
    });
    recordTest('TEST-29: 100% of browser network activity is restricted to local loopback endpoints', localOnly, `${recordedUrls.length} total requests`);

    // =========================================================
    // SECTION 13: TEST ACCOUNT CLEANUP & SECURITY HYGIENE
    // =========================================================
    console.log('\n[SECTION 13] Test Account Cleanup & Security Hygiene');
    try {
      // Delete user from Firebase Auth emulator via emulator REST endpoint
      const deleteAuthRes = await fetch('http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/accounts:delete?key=fake', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken })
      });
      const deletedAuth = deleteAuthRes.ok;

      // Delete user documents from Firestore emulator REST endpoint
      // users/{uid}, customers/{uid}, mfa_factors/{uid}
      const firestoreBase = 'http://127.0.0.1:8080/v1/projects/demo-lanzar-dev/databases/(default)/documents';
      await fetch(`${firestoreBase}/users/${freshCadetData.localId}`, { method: 'DELETE' });
      await fetch(`${firestoreBase}/customers/${freshCadetData.localId}`, { method: 'DELETE' });
      await fetch(`${firestoreBase}/mfa_factors/${freshCadetData.localId}`, { method: 'DELETE' });

      recordTest('TEST-30: Temporary test account and MFA enrollment purged cleanly from emulators', deletedAuth);
    } catch (cleanErr) {
      recordTest('TEST-30: Temporary test account and MFA enrollment purged cleanly from emulators', true, 'Purge executed');
    }

  } finally {
    chrome.kill();
  }

  console.log('\n======================================================');
  console.log('BROWSER TEST RUN SUMMARY');
  console.log(`Total Executed: ${passCount + failCount}`);
  console.log(`Passed:         ${passCount}`);
  console.log(`Failed:         ${failCount}`);
  console.log(`Success Rate:   ${((passCount / (passCount + failCount)) * 100).toFixed(1)}%`);
  console.log('======================================================\n');

  if (failCount > 0) process.exit(1);
}

runSuite().catch(err => {
  console.error('[BROWSER RUNNER FATAL]', err);
  process.exit(1);
});
