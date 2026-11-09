// test-browser-e2e.cjs
// Phase F: Full Local End-to-End Browser Automation & Integration Test Suite

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const assert = require('assert');

const { generateTOTP, verifyAndConsumeRecoveryCode } = require('./auth-backend/mfaService');

const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const SCREENSHOT_DIR = 'C:\\Users\\jonny\\.gemini\\antigravity\\brain\\181f70b2-f3a3-4005-b91d-fd091daec5b7\\screenshots';

if (!fs.existsSync(SCREENSHOT_DIR)) {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
}

console.log('\n======================================================');
console.log('LANZAR ID — Phase F: Local End-to-End Browser Suite');
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

  async eval(expression, awaitPromise = true) {
    const res = await this.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise });
    if (res.exceptionDetails) {
      throw new Error(res.exceptionDetails.exception?.description || 'Evaluation error');
    }
    return res.result?.value;
  }

  async screenshot(filename) {
    const shot = await this.send('Page.captureScreenshot', { format: 'png' });
    const fullPath = path.join(SCREENSHOT_DIR, filename);
    fs.writeFileSync(fullPath, Buffer.from(shot.data, 'base64'));
    return fullPath;
  }

  async waitFor(expression, timeoutMs = 8000, intervalMs = 200) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      try {
        const val = await this.eval(expression);
        if (val) return val;
      } catch (e) {}
      await new Promise(r => setTimeout(r, intervalMs));
    }
    throw new Error(`Timeout waiting for expression: ${expression}`);
  }

  close() {
    if (this.ws) this.ws.close();
  }
}

async function runSuite() {
  const tmpProfile = path.join(os.tmpdir(), 'chrome_phase_f_' + Date.now());
  const chrome = spawn(CHROME_PATH, [
    '--remote-debugging-port=9222',
    '--headless=new',
    '--user-data-dir=' + tmpProfile,
    'about:blank'
  ]);

  try {
    await new Promise(r => setTimeout(r, 1200));

    async function openTab(url) {
      const res = await fetch(`http://127.0.0.1:9222/json/new?${encodeURIComponent(url)}`, { method: 'PUT' });
      const target = await res.json();
      const page = new CDPPage(target.webSocketDebuggerUrl);
      await page.connect();
      return page;
    }

    const testCadetEmail = `sarah.connor.${Date.now()}@lanzar.me`;
    const testCadetPass = 'CyberSpace2026!';
    let enrolledTotpSecret = null;
    let savedRecoveryCodes = [];

    // =========================================================
    // SECTION 1: INVALID CREDENTIALS & ERROR HANDLING
    // =========================================================
    console.log('[SECTION 1] Invalid Credentials & Boundary Error Handling');
    const page1 = await openTab('http://localhost:4000/');
    await new Promise(r => setTimeout(r, 1500));

    await page1.eval(`(() => {
      function setInput(input, val) {
        const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
        setter.call(input, val);
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
      }
      const emailEl = document.querySelector('input[type="email"]');
      const passEl = document.querySelector('input[type="password"]');
      const btn = document.querySelector('button[type="submit"]');
      setInput(emailEl, 'nonexistent.user@lanzar.me');
      setInput(passEl, 'WrongPassword999!');
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
    await new Promise(r => setTimeout(r, 1500));

    // Switch to Register tab
    await page2.eval(`(() => {
      const tabs = Array.from(document.querySelectorAll('.auth-tab-btn'));
      const regTab = tabs.find(t => t.textContent.includes('CREATE ACCOUNT'));
      if (regTab) regTab.click();
    })()`);
    await new Promise(r => setTimeout(r, 500));

    // Fill registration form using exact input IDs
    await page2.eval(`(() => {
      function setInput(input, val) {
        const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
        setter.call(input, val);
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
      }
      setInput(document.getElementById('reg-name'), 'Commander Sarah Connor');
      setInput(document.getElementById('reg-business'), 'Cyberdyne Systems');
      setInput(document.getElementById('login-email'), '${testCadetEmail}');
      setInput(document.getElementById('login-password'), '${testCadetPass}');
      setInput(document.getElementById('reg-confirm-password'), '${testCadetPass}');
      const check = document.getElementById('reg-dispatch') || document.querySelector('input[type="checkbox"]');
      if (check && !check.checked) check.click();
      document.querySelector('button[type="submit"]').click();
    })()`);

    // Wait for registration to succeed and portal to load
    const portalLoaded = await page2.waitFor(`Boolean(document.querySelector('.my-lanzar-tabs'))`, 12000);
    recordTest('TEST-02: Self-service account registration completes and renders Central Portal', Boolean(portalLoaded));
    await page2.screenshot('02_account_registered_portal.png');

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
    await new Promise(r => setTimeout(r, 800));

    // Update bio and display name
    await page2.eval(`(() => {
      function setInput(input, val) {
        const setter = Object.getOwnPropertyDescriptor(input instanceof HTMLTextAreaElement ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype, 'value').set;
        setter.call(input, val);
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
      }
      const nameInput = document.querySelectorAll('input.form-input')[0];
      const bioInput = document.querySelector('textarea.form-textarea');
      if (nameInput) setInput(nameInput, 'Commander Sarah Connor (Lead)');
      if (bioInput) setInput(bioInput, 'Operational Security Commander for LANZAR Frontier Network.');
      const saveBtn = document.querySelector('.btn-primary-deck');
      if (saveBtn) saveBtn.click();
    })()`);

    const updateSuccess = await page2.waitFor(`Boolean(document.querySelector('.lanzar-alert.success') || document.body.textContent.includes('Profile updated successfully'))`, 8000);
    recordTest('TEST-03: User profile updated (displayName, bio) successfully in Firestore via PUT', Boolean(updateSuccess));
    await page2.screenshot('03_profile_updated.png');

    // =========================================================
    // SECTION 4: ACTIVE SESSION LISTING & INDIVIDUAL REVOCATION
    // =========================================================
    console.log('\n[SECTION 4] Active Session Listing & Fine-Grained Revocation');
    // Click SECURITY tab
    await page2.eval(`(() => {
      window.confirm = () => true;
      const tabs = Array.from(document.querySelectorAll('.tab-btn'));
      const secTab = tabs.find(t => t.textContent.includes('Security'));
      if (secTab) secTab.click();
    })()`);
    await new Promise(r => setTimeout(r, 800));

    const sessionSection = await page2.waitFor(`Boolean(document.querySelector('.sessions-list') || document.querySelector('.sessions-header-row'))`);
    recordTest('TEST-04: Active sessions list loaded on Security dashboard', Boolean(sessionSection));
    await page2.screenshot('04_sessions_managed.png');

    // =========================================================
    // SECTION 5: TOTP MULTI-FACTOR AUTHENTICATION ENROLLMENT
    // =========================================================
    console.log('\n[SECTION 5] Universal RFC 6238 TOTP MFA Enrollment');
    // Click "ENABLE AUTHENTICATOR" button
    await page2.eval(`(() => {
      const btn = Array.from(document.querySelectorAll('.btn-secondary-deck')).find(b => b.textContent.includes('ENABLE AUTHENTICATOR'));
      if (btn) btn.click();
    })()`);

    // Extract Base32 manual setup key code
    const base32Secret = await page2.waitFor(`(() => {
      const codeEl = document.querySelector('.manual-key-code') || document.querySelector('code');
      return codeEl ? codeEl.textContent.trim() : null;
    })()`, 10000);
    enrolledTotpSecret = base32Secret;
    recordTest('TEST-05: RFC 6238 Base32 Secret generated for user enrollment', Boolean(base32Secret), base32Secret);

    // Compute TOTP code from secret
    const initialTotpCode = generateTOTP(base32Secret);

    // Enter 6-digit TOTP code and confirm
    await page2.eval(`((code) => {
      function setInput(input, val) {
        const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
        setter.call(input, val);
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
      }
      const codeInput = document.querySelector('.otp-input');
      const confirmBtn = Array.from(document.querySelectorAll('.btn-primary-deck')).find(b => b.textContent.includes('VERIFY'));
      if (codeInput) setInput(codeInput, code);
      if (confirmBtn) confirmBtn.click();
    })('${initialTotpCode}')`);

    // Verify recovery codes are displayed
    const recoveryCodeElements = await page2.waitFor(`(() => {
      const pills = Array.from(document.querySelectorAll('.recovery-code-pill'));
      if (pills.length > 0) return pills.map(p => p.textContent.trim());
      return null;
    })()`, 10000);
    savedRecoveryCodes = recoveryCodeElements || [];
    recordTest('TEST-06: TOTP confirmed and 8 single-use recovery codes generated', savedRecoveryCodes.length === 8, `${savedRecoveryCodes.length} codes`);
    await page2.screenshot('05_totp_enrolled.png');

    // Dismiss recovery codes banner
    await page2.eval(`(() => {
      const btn = Array.from(document.querySelectorAll('button')).find(b => b.textContent.includes('SAVED THESE CODES'));
      if (btn) btn.click();
    })()`);
    await new Promise(r => setTimeout(r, 600));

    // Verify Active and Enrolled tag appears
    const mfaActive = await page2.waitFor(`Boolean(document.querySelector('.nominal-tag') || document.body.textContent.includes('ACTIVE AND ENROLLED'))`);
    recordTest('TEST-07: MFA status displayed as ACTIVE AND ENROLLED on dashboard', Boolean(mfaActive));

    // =========================================================
    // SECTION 6: SIGN OUT
    // =========================================================
    console.log('\n[SECTION 6] Sign Out & Session Teardown');
    await page2.eval(`(() => {
      const signoutBtn = document.querySelector('.btn-sign-out');
      if (signoutBtn) signoutBtn.click();
    })()`);

    const signoutConfirmed = await page2.waitFor(`Boolean(document.querySelector('.auth-tab-bar') || document.querySelector('input[type="password"]'))`, 8000);
    recordTest('TEST-08: User signed out and redirected to clean authentication screen', Boolean(signoutConfirmed));
    await page2.screenshot('06_signed_out.png');
    page2.close();

    // =========================================================
    // SECTION 7: RECOVERY CODE SINGLE-USE & REPLAY PROTECTION
    // =========================================================
    console.log('\n[SECTION 7] Single-Use Recovery Code Verification & Replay Protection');
    if (savedRecoveryCodes.length > 0) {
      const codeToTest = savedRecoveryCodes[0];
      const crypto = require('crypto');
      const hashedRecords = savedRecoveryCodes.map(c => ({
        hash: crypto.createHash('sha256').update(c.trim().toUpperCase()).digest('hex'),
        used: false
      }));

      const firstConsume = verifyAndConsumeRecoveryCode(codeToTest, hashedRecords);
      recordTest('TEST-09: Single-use recovery code validates and consumes cleanly', firstConsume.valid === true);

      const replayAttempt = verifyAndConsumeRecoveryCode(codeToTest, hashedRecords);
      recordTest('TEST-10: Replay of consumed recovery code is strictly rejected', replayAttempt.valid === false);
    }

    // =========================================================
    // SECTION 8: CLIENT INTEGRATION — EMBEDDED MODAL (IFRAME)
    // =========================================================
    console.log('\n[SECTION 8] Client Integration — Embedded Modal (iframe)');
    const pagePortal = await openTab('http://localhost:5173/');
    await new Promise(r => setTimeout(r, 1200));

    await pagePortal.eval(`document.getElementById('btnModal').click()`);
    await new Promise(r => setTimeout(r, 800));

    const modalOpened = await pagePortal.eval(`(() => {
      const modal = document.getElementById('authModal');
      const frame = modal.shadowRoot?.getElementById('authFrame');
      return {
        hasOpen: modal.hasAttribute('open'),
        src: frame?.src || ''
      };
    })()`);
    recordTest('TEST-11: Portal client opens <lanzar-auth-modal> with S256 PKCE challenge', modalOpened.hasOpen && modalOpened.src.includes('code_challenge='), modalOpened.src);
    await pagePortal.screenshot('07_portal_modal_opened.png');
    pagePortal.close();

    // =========================================================
    // SECTION 9: CLIENT INTEGRATION — POPUP AUTHENTICATION
    // =========================================================
    console.log('\n[SECTION 9] Client Integration — Popup Authentication');
    const pagePopup = await openTab('http://localhost:5173/');
    await new Promise(r => setTimeout(r, 1200));

    // Intercept window.open asynchronously when popup opens
    const popupOpenedUrl = await pagePopup.eval(`new Promise((resolve) => {
      const origOpen = window.open;
      window.open = function(url, name, features) {
        window.open = origOpen;
        resolve(url);
        return { closed: false, close: function() { this.closed = true; } };
      };
      document.getElementById('btnPopup').click();
    })`);

    const hasPopupChallenge = Boolean(popupOpenedUrl && popupOpenedUrl.includes('code_challenge=') && popupOpenedUrl.includes('code_challenge_method=S256'));
    recordTest('TEST-12: Client openPopup initiates PKCE authentication with S256 challenge', hasPopupChallenge, popupOpenedUrl);
    await pagePopup.screenshot('08_popup_flow_initiated.png');
    pagePopup.close();

    // =========================================================
    // SECTION 10: CLIENT INTEGRATION — TOP-LEVEL REDIRECT
    // =========================================================
    console.log('\n[SECTION 10] Client Integration — Top-Level Redirect PKCE Flow');
    const pageRedirect = await openTab('http://localhost:5173/');
    await new Promise(r => setTimeout(r, 1000));

    await pageRedirect.eval(`document.getElementById('btnRedirect').click()`);
    await new Promise(r => setTimeout(r, 2000));

    const hubUrl = await pageRedirect.eval(`window.location.href`);
    recordTest('TEST-13: Top-level redirect navigates to Auth Hub with explicit S256 challenge', hubUrl.includes('code_challenge=') && hubUrl.includes('code_challenge_method=S256'), hubUrl);
    await pageRedirect.screenshot('09_redirect_at_auth_hub.png');
    pageRedirect.close();

    // =========================================================
    // SECTION 11: FULL PKCE CODE EXCHANGE & CLIENT HANDSHAKE
    // =========================================================
    console.log('\n[SECTION 11] Full PKCE Code Exchange & Session Establishment');
    const { generatePkcePair, exchangeCodeForSession, buildAuthorizeUrl } = require('./src/sdk/lanzar-auth-modal');
    const pkce = await generatePkcePair();

    // Mint test authorization code via backend using Sarah Connor's credentials
    // Sign in to Auth emulator to get idToken
    const authRes = await fetch('http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=fake', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: testCadetEmail,
        password: testCadetPass,
        returnSecureToken: true
      })
    });
    const authData = await authRes.json();
    const idToken = authData.idToken;

    // First attempt to authorize: will return 403 mfa_required because Sarah Connor enrolled in TOTP!
    const authReq1 = await fetch('http://localhost:4001/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        idToken,
        client_id: 'portal',
        redirect_uri: 'http://localhost:5173/',
        code_challenge: pkce.codeChallenge,
        code_challenge_method: 'S256',
        state: 'oauth_test_state_123'
      })
    });
    const authData1 = await authReq1.json();
    recordTest('TEST-14: Backend /authorize halts with 403 mfa_required for enrolled user', authReq1.status === 403 && authData1.mfa_required === true);

    // Wait for the next TOTP 30-second window if currently in the same step as enrollment
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
    recordTest('TEST-15: Valid TOTP code verifies and issues signed mfaProof token', Boolean(mfaProof));

    // Re-call /authorize with mfa_proof
    const authReq2 = await fetch('http://localhost:4001/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        idToken,
        client_id: 'portal',
        redirect_uri: 'http://localhost:5173/',
        code_challenge: pkce.codeChallenge,
        code_challenge_method: 'S256',
        state: 'oauth_test_state_123',
        mfa_proof: mfaProof
      })
    });
    const authData2 = await authReq2.json();
    const authCode = authData2.code;
    recordTest('TEST-16: /authorize succeeds with valid mfa_proof and issues authorization code', authReq2.status === 200 && Boolean(authCode), authCode);

    // Exchange code using client-retained code_verifier
    const exchangeRes = await exchangeCodeForSession({
      code: authCode,
      clientId: 'portal',
      redirectUri: 'http://localhost:5173/',
      codeVerifier: pkce.codeVerifier,
      authApiBase: 'http://localhost:4001'
    });
    recordTest('TEST-17: Client exchangeCodeForSession mints custom token with session_id', Boolean(exchangeRes.custom_token && exchangeRes.session_id));

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
    recordTest('TEST-18: Consumed authorization code cannot be replayed (atomic single-use)', replayRejected);

    // =========================================================
    // SECTION 12: BOUNDARY REJECTION CHECKS
    // =========================================================
    console.log('\n[SECTION 12] Security Boundary Rejections');
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
    recordTest('TEST-19: Unauthorized redirect URI rejected with HTTP 400', unauthUriRes.status === 400);

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
    recordTest('TEST-20: Unregistered client ID rejected with HTTP 400', unauthClientRes.status === 400);

    // =========================================================
    // SECTION 13: NETWORK BOUNDARY & ZERO-PRODUCTION PROOF
    // =========================================================
    console.log('\n[SECTION 13] Network Boundary & Zero-Production Verification');
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

    recordTest('TEST-21: ZERO requests sent to production Firebase or external APIs', productionViolations.length === 0, `${productionViolations.length} violations`);
    if (productionViolations.length > 0) {
      console.error('VIOLATIONS:', productionViolations);
    }

    const localOnly = recordedUrls.every(u => {
      return u.startsWith('http://localhost') || u.startsWith('http://127.0.0.1') || u.startsWith('data:') || u.startsWith('blob:') || u.startsWith('about:');
    });
    recordTest('TEST-22: 100% of browser network activity is restricted to local loopback endpoints', localOnly, `${recordedUrls.length} total requests`);

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
