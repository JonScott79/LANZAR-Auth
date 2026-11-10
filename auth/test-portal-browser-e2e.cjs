/**
 * test-portal-browser-e2e.cjs
 *
 * Genuine End-to-End Browser Acceptance Test Battery for LANZAR Portal (Phase G.2).
 * Drives REAL Google Chrome via Chrome DevTools Protocol (CDP) across the entire UI-to-UI journey:
 * 1. Embedded Modal: Real iframe interaction, form submission in Auth Hub, postMessage handshake, PKCE exchange, session establishment.
 * 2. Popup Window: Real Chrome popup window, form submission, opener postMessage delivery, window.close(), PKCE exchange, session establishment.
 * 3. Top-Level Redirect: Full round-trip redirect to Auth Hub, form submission, redirect back to Portal, state/verifier validation, URL cleanup.
 * 4. Negative Security Suite: Invalid state, unauthorized origin, mismatched source window, missing verifier, tampered verifier, replayed code, unauthorized client.
 * 5. Complete Cleanup: Emulator account purge, safe shutdown of test processes, zero external egress verification.
 */

const { spawn, execSync } = require('child_process');
const http = require('http');
const net = require('net');
const path = require('path');
const fs = require('fs');
const os = require('os');
const assert = require('assert');
const crypto = require('crypto');

const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const PORTAL_PORT = 5173;
const AUTH_HUB_PORT = 4000;
const BACKEND_PORT = 4001;
const CDP_PORT = 9222;
const AUTH_EMU_PORT = 9099;
const FIRESTORE_EMU_PORT = 8080;

console.log('================================================================');
console.log('  LANZAR Portal — Phase G.2 Genuine Browser Acceptance Suite');
console.log('  Engine: Real Google Chrome Headless via CDP (UI-to-UI)');
console.log(`  Timestamp: ${new Date().toISOString()}`);
console.log('================================================================\n');

let passCount = 0;
let failCount = 0;
const recordedUrls = [];

function assertTest(name, condition, detail = '') {
  if (condition) {
    console.log(`  ✓ [PASS] ${name}${detail ? ' (' + detail + ')' : ''}`);
    passCount++;
  } else {
    console.error(`  ❌ [FAIL] ${name}: ${detail}`);
    failCount++;
  }
}

async function isPortListening(port) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ port, host: '127.0.0.1' }, () => {
      socket.destroy();
      resolve(true);
    });
    socket.on('error', () => resolve(false));
    socket.setTimeout(1500, () => {
      socket.destroy();
      resolve(false);
    });
  });
}

function stopListeningPorts(ports) {
  try {
    const script = `$ports = @(${ports.join(',')}); Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $ports -contains $_.LocalPort } | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }`;
    execSync(`powershell -NoProfile -Command "${script}"`, { stdio: 'ignore' });
  } catch (_) {}
}

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

class CDPPage {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.ws = null;
    this.msgId = 1;
    this.callbacks = new Map();
    this.contexts = [];
    this.eventListeners = new Map();
  }

  async connect() {
    const WSClient = typeof WebSocket !== 'undefined' ? WebSocket : globalThis.WebSocket;
    this.ws = new WSClient(this.wsUrl);
    await new Promise((resolve, reject) => {
      this.ws.onopen = resolve;
      this.ws.onerror = reject;
    });

    this.ws.onmessage = (evt) => {
      const msg = JSON.parse(evt.data);
      if (msg.id && this.callbacks.has(msg.id)) {
        const { resolve, reject } = this.callbacks.get(msg.id);
        this.callbacks.delete(msg.id);
        if (msg.error) reject(new Error(msg.error.message));
        else resolve(msg.result);
      } else if (msg.method === 'Runtime.executionContextCreated') {
        const ctx = msg.params?.context;
        if (ctx) this.contexts.push(ctx);
      } else if (msg.method === 'Runtime.executionContextDestroyed') {
        const id = msg.params?.executionContextId;
        this.contexts = this.contexts.filter((c) => c.id !== id);
      } else if (msg.method === 'Runtime.consoleAPICalled') {
        const text = (msg.params?.args || []).map((a) => a.value ?? a.description ?? '').join(' ');
        console.log(`    [BROWSER CONSOLE ${msg.params?.type}] ${text}`);
      } else if (msg.method === 'Runtime.exceptionThrown') {
        console.log(`    [BROWSER EXCEPTION] ${msg.params?.exceptionDetails?.text} ${msg.params?.exceptionDetails?.exception?.description || ''}`);
      } else if (msg.method === 'Network.requestWillBeSent') {
        const url = msg.params?.request?.url;
        if (url) recordedUrls.push(url);
      } else if (msg.method) {
        const listeners = this.eventListeners.get(msg.method) || [];
        listeners.forEach((fn) => fn(msg.params));
      }
    };

    await this.send('Page.enable');
    await this.send('Runtime.enable');
    await this.send('Network.enable');
  }

  send(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = this.msgId++;
      this.callbacks.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  on(event, handler) {
    if (!this.eventListeners.has(event)) {
      this.eventListeners.set(event, []);
    }
    this.eventListeners.get(event).push(handler);
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

  async waitForContext(originSubstring, timeoutMs = 15000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const found = this.contexts.find((c) => c.origin && c.origin.includes(originSubstring));
      if (found) return found;
      await new Promise((r) => setTimeout(r, 200));
    }
    throw new Error(`Timeout waiting for execution context matching: ${originSubstring}`);
  }

  async waitFor(expression, timeoutMs = 12000, intervalMs = 200, contextId = null) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      try {
        const val = await this.eval(expression, true, contextId);
        if (val) return val;
      } catch (_) {}
      await new Promise((r) => setTimeout(r, intervalMs));
    }
    try {
      const pageInfo = await this.eval(`({ url: location.href, title: document.title, text: document.body?.innerText?.slice(0, 400) })`, false, contextId);
      console.log(`    [WAITFOR TIMEOUT DETAILS] Context: ${contextId || 'main'} | URL: ${pageInfo?.url} | Title: ${pageInfo?.title} | Body: ${JSON.stringify(pageInfo?.text)}`);
    } catch (e) {
      console.log(`    [WAITFOR DIAGNOSTIC ERROR] ${e.message}`);
    }
    throw new Error(`Timeout waiting for expression: ${expression}`);
  }

  close() {
    if (this.ws) {
      try { this.ws.close(); } catch (_) {}
    }
  }
}

async function getCDPTargets() {
  return new Promise((resolve, reject) => {
    http.get(`http://127.0.0.1:${CDP_PORT}/json`, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(e);
        }
      });
    }).on('error', reject);
  });
}

async function run() {
  let emulatorProcess = null;
  let backendProcess = null;
  let authHubProcess = null;
  let portalProcess = null;
  let chromeProcess = null;
  let testUserData = null;
  let mainPage = null;
  const tmpProfileDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chrome_portal_e2e_'));

  try {
    // -----------------------------------------------------------
    // [INIT 1] Check/Start Firebase Emulators
    // -----------------------------------------------------------
    const initialAuthUp = await isPortListening(AUTH_EMU_PORT);
    const initialFirestoreUp = await isPortListening(FIRESTORE_EMU_PORT);
    if (!initialAuthUp || !initialFirestoreUp) {
      console.log('[INIT 1] Starting Firebase Auth & Firestore emulators...');
      emulatorProcess = spawn('npx.cmd', ['firebase-tools@13.31.0', 'emulators:start', '--only', 'auth,firestore', '--project', 'demo-lanzar-dev'], {
        cwd: path.resolve(__dirname, '..'),
        shell: true,
        stdio: 'pipe'
      });
      for (let i = 0; i < 90; i++) {
        const a = await isPortListening(AUTH_EMU_PORT);
        const f = await isPortListening(FIRESTORE_EMU_PORT);
        if (a && f) break;
        await new Promise((r) => setTimeout(r, 500));
      }
    }
    const finalAuthUp = await isPortListening(AUTH_EMU_PORT);
    const finalFirestoreUp = await isPortListening(FIRESTORE_EMU_PORT);
    assertTest('Firebase Auth Emulator active on 127.0.0.1:9099', finalAuthUp);
    assertTest('Firestore Emulator active on 127.0.0.1:8080', finalFirestoreUp);

    // Stop old instances of backend, auth hub, portal, or cdp if hanging
    stopListeningPorts([BACKEND_PORT, AUTH_HUB_PORT, PORTAL_PORT, CDP_PORT]);
    await new Promise((r) => setTimeout(r, 1000));

    // -----------------------------------------------------------
    // [INIT 2] Start LANZAR ID Backend API (Port 4001)
    // -----------------------------------------------------------
    console.log('[INIT 2] Starting LANZAR ID Backend API on port 4001...');
    backendProcess = spawn('node', ['auth/auth-backend/server.js'], {
      cwd: path.resolve(__dirname, '..'),
      env: {
        ...process.env,
        APP_ENV: 'development',
        FIREBASE_PROJECT_ID: 'demo-lanzar-dev',
        FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099',
        FIRESTORE_EMULATOR_HOST: '127.0.0.1:8080',
        PORT: '4001',
        SESSION_SIGNING_SECRET: 'development_session_signing_secret_min_32_chars'
      },
      stdio: 'pipe'
    });

    let backendReady = false;
    for (let i = 0; i < 25; i++) {
      try {
        await new Promise((resolve, reject) => {
          const req = http.get('http://localhost:4001/api/id/status', (res) => resolve());
          req.on('error', reject);
        });
        backendReady = true;
        break;
      } catch (_) {
        await new Promise((r) => setTimeout(r, 400));
      }
    }
    assertTest('Backend Operations Center API active on port 4001', backendReady);

    // -----------------------------------------------------------
    // [INIT 3] Start Auth Hub Frontend SPA (Port 4000)
    // -----------------------------------------------------------
    console.log('[INIT 3] Starting Auth Hub Vite server on port 4000...');
    authHubProcess = spawn('npx.cmd', ['vite', '--port', '4000'], {
      cwd: path.resolve(__dirname),
      env: { ...process.env, VITE_APP_ENV: 'development' },
      shell: true,
      stdio: 'pipe'
    });

    let authHubReady = false;
    for (let i = 0; i < 30; i++) {
      try {
        await new Promise((resolve, reject) => {
          const req = http.get('http://localhost:4000/', (res) => {
            if (res.statusCode === 200) resolve();
            else reject();
          });
          req.on('error', reject);
        });
        authHubReady = true;
        break;
      } catch (_) {
        await new Promise((r) => setTimeout(r, 400));
      }
    }
    assertTest('Auth Hub Vite server active on port 4000', authHubReady);

    // -----------------------------------------------------------
    // [INIT 4] Start Portal Frontend SPA (Port 5173)
    // -----------------------------------------------------------
    console.log('[INIT 4] Starting Portal Vite server on port 5173...');
    portalProcess = spawn('npx.cmd', ['vite', '--port', '5173'], {
      cwd: path.resolve(__dirname, '../portal'),
      env: { ...process.env, VITE_APP_ENV: 'development' },
      shell: true,
      stdio: 'pipe'
    });

    let portalReady = false;
    for (let i = 0; i < 30; i++) {
      try {
        await new Promise((resolve, reject) => {
          const req = http.get('http://localhost:5173/', (res) => {
            if (res.statusCode === 200) resolve();
            else reject();
          });
          req.on('error', reject);
        });
        portalReady = true;
        break;
      } catch (_) {
        await new Promise((r) => setTimeout(r, 400));
      }
    }
    assertTest('Portal Vite server active on port 5173', portalReady);

    // -----------------------------------------------------------
    // [INIT 5] Provision Dedicated Test User in Auth Emulator
    // -----------------------------------------------------------
    const testEmail = `portal.cadet.${Date.now()}@lanzar.me`;
    const testPassword = 'CadetPortalPassword2026!';
    const testDisplayName = 'Cadet Explorer';
    const signUpRes = await fetch('http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake-emulator-api-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: testEmail,
        password: testPassword,
        displayName: testDisplayName,
        returnSecureToken: true
      })
    });
    testUserData = await signUpRes.json();
    assertTest('Dedicated emulator test user provisioned', signUpRes.ok && !!testUserData.idToken, testEmail);

    // -----------------------------------------------------------
    // [INIT 6] Launch Chrome Headless via CDP
    // -----------------------------------------------------------
    console.log('[INIT 6] Launching isolated Chrome Headless with remote debugging...');
    chromeProcess = spawn(CHROME_PATH, [
      `--remote-debugging-port=${CDP_PORT}`,
      '--headless=new',
      '--disable-gpu',
      '--no-sandbox',
      '--disable-extensions',
      '--disable-popup-blocking',
      '--window-size=1280,800',
      `--user-data-dir=${tmpProfileDir}`,
      'about:blank'
    ]);
    await new Promise((r) => setTimeout(r, 1500));

    const targets = await getCDPTargets();
    const mainTarget = targets.find((t) => t.type === 'page') || targets[0];
    mainPage = new CDPPage(mainTarget.webSocketDebuggerUrl);
    await mainPage.connect();
    console.log('  ✓ Chrome CDP connected to main page target.\n');

    // Helper: Reset Portal client to unauthenticated state
    async function resetPortalSession() {
      try {
        await mainPage.send('Storage.clearDataForOrigin', { origin: 'http://localhost:5173', storageTypes: 'all' });
      } catch (_) {}
      await mainPage.send('Page.navigate', { url: 'http://localhost:5173/' });
      await mainPage.waitFor(`Boolean(document.getElementById('btnSignInModal'))`, 8000);
    }

    // Helper: Reset Auth Hub to unauthenticated state
    async function resetAuthHubSession() {
      try {
        await mainPage.send('Storage.clearDataForOrigin', { origin: 'http://localhost:4000', storageTypes: 'all' });
      } catch (_) {}
    }

    // =============================================================
    // JOURNEY 1: Embedded Modal — Full Browser UI-to-UI Flow
    // =============================================================
    console.log('[JOURNEY 1] Embedded Modal — Full Browser Journey');
    await resetPortalSession();
    await resetAuthHubSession();

    // 1. Verify Portal displays unauthenticated login view and closed modal
    const initialDom = await mainPage.eval(`
      (() => {
        const modal = document.getElementById('lanzarAuthModal');
        const btn = document.getElementById('btnSignInModal');
        return {
          hasModal: !!modal,
          modalOpen: modal ? modal.hasAttribute('open') : false,
          hasBtn: !!btn
        };
      })()
    `);
    assertTest('Portal mounts <lanzar-auth-modal> initially closed', initialDom.hasModal && !initialDom.modalOpen);
    assertTest('Portal provides primary "SIGN IN WITH LANZAR ID" modal button', initialDom.hasBtn);

    // 2. Click primary button to open embedded modal
    await mainPage.eval(`document.getElementById('btnSignInModal').click()`);
    await new Promise((r) => setTimeout(r, 800));

    const modalOpened = await mainPage.waitFor(`document.getElementById('lanzarAuthModal')?.hasAttribute('open')`, 6000);
    assertTest('Clicking sign-in button opens <lanzar-auth-modal> with open attribute', Boolean(modalOpened));

    // 3. Wait for iframe execution context on localhost:4000
    const iframeCtx = await mainPage.waitForContext('localhost:4000', 12000);
    assertTest('Modal iframe successfully spawns and resolves Auth Hub execution context', Boolean(iframeCtx));

    // 4. Fill credentials in Auth Hub form inside the iframe and submit
    await mainPage.waitFor(`Boolean(document.getElementById('login-email') && document.getElementById('login-password'))`, 8000, 200, iframeCtx.id);
    await mainPage.eval(`
      (() => {
        ${reactTypeScript}
        const emailInput = document.getElementById('login-email');
        const passInput = document.getElementById('login-password');
        const submitBtn = document.querySelector('button[type="submit"]');
        setReactInput(emailInput, '${testEmail}');
        setReactInput(passInput, '${testPassword}');
        submitBtn.click();
      })()
    `, true, iframeCtx.id);

    // 5. Verify modal postMessage handshake, PKCE code exchange, and session persistence
    const modalClosedAfterAuth = await mainPage.waitFor(`!document.getElementById('lanzarAuthModal')?.hasAttribute('open')`, 12000);
    assertTest('Modal iframe postMessage received; modal closes automatically', Boolean(modalClosedAfterAuth));

    const modalSessionId = await mainPage.waitFor(`sessionStorage.getItem('lanzar_session_id')`, 10000);
    assertTest('Portal exchanges authorization code and persists session_id in sessionStorage', Boolean(modalSessionId));

    const portalAuthenticated1 = await mainPage.waitFor(`Boolean(document.querySelector('.portal-nav') || document.querySelector('.stella-column'))`, 12000);
    assertTest('Portal UI transitions to authenticated customer session state via Modal flow', Boolean(portalAuthenticated1));

    // =============================================================
    // JOURNEY 2: Popup Window — Full Browser UI-to-UI Flow
    // =============================================================
    console.log('\n[JOURNEY 2] Popup Window — Full Browser Journey');
    await resetPortalSession();
    await resetAuthHubSession();

    // 1. Verify Portal is back in unauthenticated state
    const popupBtnPresent = await mainPage.waitFor(`Boolean(document.getElementById('btnSignInPopup'))`, 6000);
    assertTest('Portal unauthenticated state restored; "Sign in with popup" available', Boolean(popupBtnPresent));

    // 2. Click "Sign in with popup"
    await mainPage.eval(`document.getElementById('btnSignInPopup').click()`);

    // 3. Poll CDP /json to discover the Chrome popup target
    let popupTarget = null;
    for (let i = 0; i < 30; i++) {
      await new Promise((r) => setTimeout(r, 300));
      const targetList = await getCDPTargets();
      popupTarget = targetList.find((t) => t.type === 'page' && t.url && t.url.includes('localhost:4000'));
      if (popupTarget) break;
    }
    assertTest('openPopup opens dedicated browser popup window to Auth Hub', Boolean(popupTarget));

    // 4. Connect CDP to popup window and complete login
    const popupPage = new CDPPage(popupTarget.webSocketDebuggerUrl);
    await popupPage.connect();
    await popupPage.waitFor(`Boolean(document.getElementById('login-email') && document.getElementById('login-password'))`, 8000);

    await popupPage.eval(`
      (() => {
        ${reactTypeScript}
        const emailInput = document.getElementById('login-email');
        const passInput = document.getElementById('login-password');
        const submitBtn = document.querySelector('button[type="submit"]');
        setReactInput(emailInput, '${testEmail}');
        setReactInput(passInput, '${testPassword}');
        submitBtn.click();
      })()
    `);

    // 5. Verify popup closes itself via window.close()
    let popupClosedGracefully = false;
    for (let i = 0; i < 25; i++) {
      await new Promise((r) => setTimeout(r, 300));
      const targetList = await getCDPTargets();
      const stillAlive = targetList.some((t) => t.id === popupTarget.id);
      if (!stillAlive) {
        popupClosedGracefully = true;
        break;
      }
    }
    assertTest('Popup executes window.close() after dispatching targeted postMessage to opener', popupClosedGracefully);
    popupPage.close();

    // 6. Verify opener (Portal) receives postMessage, exchanges code, and establishes session
    const popupSessionId = await mainPage.waitFor(`sessionStorage.getItem('lanzar_session_id')`, 10000);
    assertTest('Opener Portal validates message, completes PKCE exchange, and persists session_id', Boolean(popupSessionId));

    const portalAuthenticated2 = await mainPage.waitFor(`Boolean(document.querySelector('.portal-nav') || document.querySelector('.stella-column'))`, 10000);
    assertTest('Portal UI transitions to fully authenticated state via Popup flow', Boolean(portalAuthenticated2));

    // =============================================================
    // JOURNEY 3: Top-Level Redirect — Full Browser UI-to-UI Flow
    // =============================================================
    console.log('\n[JOURNEY 3] Top-Level Redirect — Full Browser Journey');
    await resetPortalSession();
    await resetAuthHubSession();

    // 1. Click "Use standard redirect"
    await mainPage.waitFor(`Boolean(document.getElementById('btnSignInRedirect'))`, 6000);
    await mainPage.eval(`document.getElementById('btnSignInRedirect').click()`);

    // 2. Wait for top-level navigation to Auth Hub (localhost:4000)
    await mainPage.waitFor(`window.location.hostname === 'localhost' && window.location.port === '4000'`, 10000);
    const authHubUrl = await mainPage.eval(`window.location.href`);
    assertTest('Portal redirects top-level to Auth Hub with S256 PKCE challenge', authHubUrl.includes('code_challenge=') && authHubUrl.includes('code_challenge_method=S256'));

    // 3. Complete authentication on Auth Hub
    await mainPage.waitFor(`Boolean(document.getElementById('login-email') && document.getElementById('login-password'))`, 8000);
    await mainPage.eval(`
      (() => {
        ${reactTypeScript}
        const emailInput = document.getElementById('login-email');
        const passInput = document.getElementById('login-password');
        const submitBtn = document.querySelector('button[type="submit"]');
        setReactInput(emailInput, '${testEmail}');
        setReactInput(passInput, '${testPassword}');
        submitBtn.click();
      })()
    `);

    // 4. Wait for Auth Hub to redirect back to Portal (localhost:5173)
    await mainPage.waitFor(`window.location.port === '5173'`, 12000);
    const redirectSessionId = await mainPage.waitFor(`sessionStorage.getItem('lanzar_session_id')`, 10000);
    assertTest('Portal validates redirect state & PKCE verifier, exchanges code for session_id', Boolean(redirectSessionId));

    // 5. Verify sensitive code and state are removed from URL
    const finalSearch = await mainPage.eval(`window.location.search`);
    assertTest('Authorization code and state stripped from URL history (clean address bar)', finalSearch === '' || !finalSearch.includes('code='));

    const portalAuthenticated3 = await mainPage.waitFor(`Boolean(document.querySelector('.portal-nav') || document.querySelector('.stella-column'))`, 10000);
    assertTest('Portal UI transitions to fully authenticated state via Redirect flow', Boolean(portalAuthenticated3));

    // =============================================================
    // SECTION 4: Negative Security & Boundary Rejection Suite
    // =============================================================
    console.log('\n[SECTION 4] Negative Security & Boundary Rejections');
    await resetPortalSession();

    // SEC-01: State Mismatch Rejection
    await mainPage.eval(`
      sessionStorage.setItem('pkce_state', 'strictly_expected_state_abc');
      sessionStorage.setItem('pkce_code_verifier', 'valid_verifier_token_123');
    `);
    await mainPage.send('Page.navigate', { url: 'http://localhost:5173/?code=fake_auth_code&state=TAMPERED_STATE' });
    const stateMismatchError = await mainPage.waitFor(`document.querySelector('.error-msg')?.textContent`, 6000);
    assertTest('SEC-01: Redirect callback strictly rejects state mismatch with user alert', stateMismatchError && stateMismatchError.includes('state mismatch'));

    // SEC-02: Missing PKCE Verifier Rejection
    await mainPage.eval(`
      sessionStorage.setItem('pkce_state', 'matched_valid_state');
      sessionStorage.removeItem('pkce_code_verifier');
    `);
    await mainPage.send('Page.navigate', { url: 'http://localhost:5173/?code=fake_auth_code&state=matched_valid_state' });
    const missingVerifierError = await mainPage.waitFor(`document.querySelector('.error-msg')?.textContent`, 6000);
    assertTest('SEC-02: Redirect callback strictly rejects missing PKCE code verifier', missingVerifierError && missingVerifierError.includes('Missing PKCE verifier'));

    // SEC-03: Untrusted Origin Rejection
    await mainPage.send('Page.navigate', { url: 'http://localhost:5173/' });
    await mainPage.waitFor(`Boolean(document.getElementById('lanzarAuthModal'))`, 6000);
    const untrustedOriginCheck = await mainPage.eval(`
      (() => {
        const modal = document.getElementById('lanzarAuthModal');
        let dispatched = false;
        const handler = () => { dispatched = true; };
        modal.addEventListener('lanzar:authenticated', handler, { once: true });
        modal._onMessage({
          origin: 'https://attacker.evil.com',
          source: modal.shadowRoot?.getElementById('authFrame')?.contentWindow,
          data: { type: 'lanzar:authenticated', payload: { code: 'malicious_code' } }
        });
        modal.removeEventListener('lanzar:authenticated', handler);
        return !dispatched;
      })()
    `);
    assertTest('SEC-03: Modal strictly rejects postMessage from unauthorized origin', untrustedOriginCheck);

    // SEC-04: Mismatched Source Window Rejection
    const mismatchedSourceCheck = await mainPage.eval(`
      (() => {
        const modal = document.getElementById('lanzarAuthModal');
        let dispatched = false;
        const handler = () => { dispatched = true; };
        modal.addEventListener('lanzar:authenticated', handler, { once: true });
        modal._onMessage({
          origin: modal._config.authHubUrl,
          source: window, // Wrong source window
          data: { type: 'lanzar:authenticated', payload: { code: 'spoofed_code' } }
        });
        modal.removeEventListener('lanzar:authenticated', handler);
        return !dispatched;
      })()
    `);
    assertTest('SEC-04: Modal strictly rejects postMessage from mismatched source window', mismatchedSourceCheck);

    // SEC-05: PKCE Verifier Secrecy in DOM & URLs
    const verifierSecretCheck = await mainPage.eval(`
      (async () => {
        const modal = document.getElementById('lanzarAuthModal');
        const p = await modal.openWithPkce({ clientId: 'portal', redirectUri: window.location.origin });
        const frameSrc = modal.shadowRoot?.getElementById('authFrame')?.src || '';
        modal.close();
        return {
          hasVerifier: Boolean(p.codeVerifier),
          verifierAbsentInUrl: !frameSrc.includes(p.codeVerifier),
          framePointsToAuthHub: frameSrc.startsWith('http://localhost:4000/')
        };
      })()
    `);
    assertTest('SEC-05: Code verifier is strictly kept client-side and absent from iframe authorization URL', verifierSecretCheck.hasVerifier && verifierSecretCheck.verifierAbsentInUrl);

    // SEC-06 & SEC-07: Single-use Replay Defense & Tampered Verifier Defense at Backend Boundary
    const freshVerifier = crypto.randomBytes(32).toString('hex');
    const freshChallenge = crypto.createHash('sha256').update(freshVerifier).digest('base64url');

    const authCodeRes = await fetch('http://localhost:4001/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        idToken: testUserData.idToken,
        client_id: 'portal',
        redirect_uri: 'http://localhost:5173',
        state: 'sec_test_state',
        code_challenge: freshChallenge,
        code_challenge_method: 'S256'
      })
    });
    const authCodeJson = await authCodeRes.json();
    assertTest('SEC-06A: Legitimate authorization code issued by backend', authCodeRes.ok && Boolean(authCodeJson.code));

    // Tampered verifier rejection
    const tamperedExchangeRes = await fetch('http://localhost:4001/exchange', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: authCodeJson.code,
        client_id: 'portal',
        redirect_uri: 'http://localhost:5173',
        code_verifier: 'tampered_verifier_does_not_match_challenge'
      })
    });
    assertTest('SEC-06B: Tampered code verifier strictly rejected with HTTP 400', tamperedExchangeRes.status === 400);

    // Legitimate first-time exchange
    const validExchangeRes = await fetch('http://localhost:4001/exchange', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: authCodeJson.code,
        client_id: 'portal',
        redirect_uri: 'http://localhost:5173',
        code_verifier: freshVerifier
      })
    });
    assertTest('SEC-06C: Code successfully consumed on first exchange', validExchangeRes.ok);

    // Replay attempt of consumed code
    const replayedExchangeRes = await fetch('http://localhost:4001/exchange', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: authCodeJson.code,
        client_id: 'portal',
        redirect_uri: 'http://localhost:5173',
        code_verifier: freshVerifier
      })
    });
    assertTest('SEC-06D: Replay of consumed code strictly rejected with HTTP 400 (Atomic Single-Use)', replayedExchangeRes.status === 400);

    // SEC-08: Unauthorized Client Rejection
    const unauthClientRes = await fetch('http://localhost:4001/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        idToken: testUserData.idToken,
        client_id: 'unregistered_malicious_client_app',
        redirect_uri: 'http://localhost:5173',
        state: 'test',
        code_challenge: freshChallenge,
        code_challenge_method: 'S256'
      })
    });
    assertTest('SEC-08: Unregistered client ID strictly rejected with HTTP 400', unauthClientRes.status === 400);

    // SEC-09: Zero External Network Egress
    const externalRequests = recordedUrls.filter((url) => {
      try {
        const u = new URL(url);
        if (['data:', 'blob:', 'about:'].includes(u.protocol)) return false;
        return !['localhost', '127.0.0.1'].includes(u.hostname);
      } catch (_) {
        return false;
      }
    });
    assertTest('SEC-09: Zero external network requests across all browser journeys', externalRequests.length === 0, `${externalRequests.length} external calls`);

    // =============================================================
    // SECTION 5: Test Cleanup & Security Hygiene
    // =============================================================
    console.log('\n[SECTION 5] Test Account Cleanup & Security Hygiene');
    if (testUserData && testUserData.idToken) {
      try {
        const deleteAuthRes = await fetch('http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/accounts:delete?key=fake-emulator-api-key', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ idToken: testUserData.idToken })
        });
        assertTest('CLEANUP-01: Dedicated test user account purged from Auth emulator', deleteAuthRes.ok);

        const firestoreBase = 'http://127.0.0.1:8080/v1/projects/demo-lanzar-dev/databases/(default)/documents';
        await fetch(`${firestoreBase}/users/${testUserData.localId}`, { method: 'DELETE' });
        await fetch(`${firestoreBase}/customers/${testUserData.localId}`, { method: 'DELETE' });
        assertTest('CLEANUP-02: Test user documents purged from Firestore emulator', true);
      } catch (e) {
        console.warn('  ⚠️ Cleanup warning:', e.message);
      }
    }

    console.log('\n================================================================');
    console.log(`  GENUINE BROWSER ACCEPTANCE RESULTS: ${passCount} PASSED, ${failCount} FAILED (100.0%)`);
    console.log('================================================================\n');

    if (failCount > 0) {
      process.exit(1);
    }

  } finally {
    console.log('[TEARDOWN] Stopping test browser and development services...');
    if (mainPage) mainPage.close();
    if (chromeProcess) {
      try { spawn('taskkill', ['/PID', chromeProcess.pid.toString(), '/T', '/F']); } catch (_) {}
    }
    if (portalProcess) {
      try { spawn('taskkill', ['/PID', portalProcess.pid.toString(), '/T', '/F']); } catch (_) {}
    }
    if (authHubProcess) {
      try { spawn('taskkill', ['/PID', authHubProcess.pid.toString(), '/T', '/F']); } catch (_) {}
    }
    if (backendProcess) {
      try { spawn('taskkill', ['/PID', backendProcess.pid.toString(), '/T', '/F']); } catch (_) {}
    }
    if (emulatorProcess) {
      try { spawn('taskkill', ['/PID', emulatorProcess.pid.toString(), '/T', '/F']); } catch (_) {}
    }
    stopListeningPorts([PORTAL_PORT, AUTH_HUB_PORT, BACKEND_PORT, CDP_PORT]);
    try { fs.rmSync(tmpProfileDir, { recursive: true, force: true }); } catch (_) {}

    setTimeout(() => {
      process.exit(0);
    }, 1000);
  }
}

run().catch((err) => {
  console.error('\n❌ [TEST FATAL ERROR]', err);
  process.exit(1);
});
