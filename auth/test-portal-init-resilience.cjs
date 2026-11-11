/**
 * test-portal-init-resilience.cjs
 *
 * Regression suite for Portal post-OAuth initialization lifecycle, stage tracking,
 * request timeouts, fail-closed error handling, and user retry recovery.
 * Runs exclusively against local loopback Firebase Emulators, Auth Backend,
 * Portal Vite server, and headless Chrome via CDP. Zero cloud calls.
 */

const { spawn, execSync } = require('child_process');
const http = require('http');
const net = require('net');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

process.env.APP_ENV = process.env.APP_ENV || 'development';
const { createMfaSignedToken } = require('./auth-backend/mfaService');

const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const PORTAL_PORT = 5173;
const BACKEND_PORT = 4001;
const CDP_PORT = 9222;
const AUTH_EMU_PORT = 9099;
const FIRESTORE_EMU_PORT = 8080;

const API = `http://localhost:${BACKEND_PORT}`;
const PORTAL = `http://localhost:${PORTAL_PORT}`;
const EMU_AUTH = `http://127.0.0.1:${AUTH_EMU_PORT}/identitytoolkit.googleapis.com/v1`;
const FS = `http://127.0.0.1:${FIRESTORE_EMU_PORT}/v1/projects/demo-lanzar-dev/databases/(default)/documents`;
const OWNER = { Authorization: 'Bearer owner' };
const JSON_H = { 'Content-Type': 'application/json' };
const KEY = 'key=fake-emulator-api-key';
const PASSWORD = 'ResilienceTestPassword2026!';

console.log('================================================================');
console.log('  LANZAR Portal — Initialization Resilience & Recovery Suite');
console.log(`  Timestamp: ${new Date().toISOString()}`);
console.log('================================================================\n');

let passCount = 0;
let failCount = 0;
const pageExceptions = [];

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

class CDPPage {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.ws = null;
    this.msgId = 1;
    this.callbacks = new Map();
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
      } else if (msg.method === 'Runtime.exceptionThrown') {
        pageExceptions.push(`${msg.params?.exceptionDetails?.text} ${msg.params?.exceptionDetails?.exception?.description || ''}`);
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

  async eval(expression, awaitPromise = true) {
    const res = await this.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise });
    if (res.exceptionDetails) {
      throw new Error(res.exceptionDetails.exception?.description || 'Evaluation error');
    }
    return res.result?.value;
  }

  async waitFor(expression, timeoutMs = 15000, intervalMs = 150) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      try {
        const val = await this.eval(expression);
        if (val) return val;
      } catch (_) {}
      await new Promise((r) => setTimeout(r, intervalMs));
    }
    const pageInfo = await this.eval(`({ url: location.href, text: document.body?.innerText?.slice(0, 400) })`).catch(() => ({}));
    throw new Error(`Timeout waiting for (${expression}) | URL=${pageInfo?.url} | Body=${JSON.stringify(pageInfo?.text)}`);
  }

  close() {
    try { this.ws?.close(); } catch (_) {}
  }
}

async function getCDPTargets() {
  const res = await fetch(`http://127.0.0.1:${CDP_PORT}/json`);
  return res.json();
}

async function jfetch(url, opts = {}) {
  const res = await fetch(url, opts);
  let body = null;
  try { body = await res.json(); } catch (_) {}
  return { status: res.status, ok: res.ok, body };
}

async function emuSignUp(label) {
  const email = `init.${label}.${Date.now()}.${Math.floor(Math.random() * 1e6)}@lanzar.me`;
  const r = await jfetch(`${EMU_AUTH}/accounts:signUp?${KEY}`, {
    method: 'POST',
    headers: JSON_H,
    body: JSON.stringify({ email, password: PASSWORD, displayName: `Init ${label}`, returnSecureToken: true })
  });
  if (!r.ok) throw new Error(`signUp failed: ${JSON.stringify(r.body)}`);
  return { label, email, uid: r.body.localId, idToken: r.body.idToken };
}

async function emuSignIn(email) {
  const r = await jfetch(`${EMU_AUTH}/accounts:signInWithPassword?${KEY}`, {
    method: 'POST',
    headers: JSON_H,
    body: JSON.stringify({ email, password: PASSWORD, returnSecureToken: true })
  });
  if (!r.ok) throw new Error(`signIn failed: ${JSON.stringify(r.body)}`);
  return r.body.idToken;
}

function fv(v) {
  if (typeof v === 'boolean') return { booleanValue: v };
  return { stringValue: String(v) };
}

async function fsPatch(docPath, obj) {
  const mask = Object.keys(obj).map((k) => `updateMask.fieldPaths=${encodeURIComponent(k)}`).join('&');
  const fields = {};
  for (const [k, v] of Object.entries(obj)) fields[k] = fv(v);
  const r = await jfetch(`${FS}/${docPath}?${mask}`, {
    method: 'PATCH',
    headers: { ...JSON_H, ...OWNER },
    body: JSON.stringify({ fields })
  });
  if (!r.ok) throw new Error(`fsPatch failed: ${JSON.stringify(r.body)}`);
}

async function fsDelete(docPath) {
  return jfetch(`${FS}/${docPath}`, { method: 'DELETE', headers: OWNER });
}

async function createAuthCodeForUser(user, { admin = false } = {}) {
  const verifier = crypto.randomBytes(32).toString('hex');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const state = `st_${crypto.randomBytes(8).toString('hex')}`;
  const baseIdToken = await emuSignIn(user.email);
  const payload = {
    idToken: baseIdToken,
    client_id: 'portal',
    redirect_uri: PORTAL,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256'
  };
  if (admin) {
    payload.mfa_proof = createMfaSignedToken(
      { uid: user.uid, email: user.email, action: 'mfa_verified', verifiedAt: Date.now() },
      300000
    );
  }
  const r = await jfetch(`${API}/authorize`, { method: 'POST', headers: JSON_H, body: JSON.stringify(payload) });
  if (!r.ok) throw new Error(`authorize failed: ${r.status} ${JSON.stringify(r.body)}`);
  return { code: r.body.code, state, verifier };
}

async function waitHttp(url, tries = 40) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(url);
      if (r.status > 0) return true;
    } catch (_) {}
    await new Promise((r) => setTimeout(r, 400));
  }
  return false;
}

async function run() {
  let emulatorProcess = null;
  let backendProcess = null;
  let portalProcess = null;
  let chromeProcess = null;
  let page = null;
  const createdUsers = [];
  const tmpProfileDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chrome_portal_init_'));

  try {
    const authAlreadyUp = await isPortListening(AUTH_EMU_PORT);
    const fsAlreadyUp = await isPortListening(FIRESTORE_EMU_PORT);
    if (!authAlreadyUp || !fsAlreadyUp) {
      console.log('[INIT] Starting Firebase Auth & Firestore emulators (demo-lanzar-dev)...');
      emulatorProcess = spawn('npx.cmd', ['firebase-tools@13.31.0', 'emulators:start', '--only', 'auth,firestore', '--project', 'demo-lanzar-dev'], {
        cwd: __dirname,
        shell: true,
        stdio: 'ignore',
        detached: false
      });
      for (let i = 0; i < 45; i++) {
        if ((await isPortListening(AUTH_EMU_PORT)) && (await isPortListening(FIRESTORE_EMU_PORT))) break;
        await new Promise((r) => setTimeout(r, 1000));
      }
    }
    assertTest('Emulators active on 127.0.0.1:9099 and 127.0.0.1:8080',
      (await isPortListening(AUTH_EMU_PORT)) && (await isPortListening(FIRESTORE_EMU_PORT)));

    stopListeningPorts([BACKEND_PORT, PORTAL_PORT, CDP_PORT]);
    await new Promise((r) => setTimeout(r, 800));

    if (!(await isPortListening(BACKEND_PORT))) {
      console.log('[INIT] Starting Auth Backend on port 4001...');
      backendProcess = spawn('node', ['server.js'], {
        cwd: path.join(__dirname, 'auth-backend'),
        env: {
          ...process.env,
          APP_ENV: 'development',
          FIREBASE_PROJECT_ID: 'demo-lanzar-dev',
          FIREBASE_AUTH_EMULATOR_HOST: `127.0.0.1:${AUTH_EMU_PORT}`,
          FIRESTORE_EMULATOR_HOST: `127.0.0.1:${FIRESTORE_EMU_PORT}`,
          PORT: String(BACKEND_PORT),
          SESSION_SIGNING_SECRET: 'resilience_test_session_secret_32chars'
        },
        stdio: 'pipe'
      });
      if (backendProcess.stdout) backendProcess.stdout.resume();
      if (backendProcess.stderr) backendProcess.stderr.on('data', (d) => console.error('[BACKEND STDERR]', d.toString()));
      await waitHttp(`${API}/api/id/status`);
    }
    assertTest('Auth Backend active on port 4001', await isPortListening(BACKEND_PORT));

    let portalReady = await isPortListening(PORTAL_PORT);
    if (!portalReady) {
      console.log('[INIT] Starting Portal Vite server on port 5173...');
      portalProcess = spawn('npx.cmd', ['vite', '--port', String(PORTAL_PORT), '--strictPort'], {
        cwd: path.join(__dirname, '..', 'portal'),
        env: { ...process.env, VITE_APP_ENV: 'development' },
        shell: true,
        stdio: 'pipe'
      });
      if (portalProcess.stdout) portalProcess.stdout.resume();
      if (portalProcess.stderr) portalProcess.stderr.on('data', (d) => console.error('[PORTAL STDERR]', d.toString()));
      portalReady = await waitHttp(PORTAL);
    }
    assertTest('Portal Vite server active on port 5173', portalReady);

    chromeProcess = spawn(CHROME_PATH, [
      '--headless=new',
      '--disable-gpu',
      `--remote-debugging-port=${CDP_PORT}`,
      `--user-data-dir=${tmpProfileDir}`,
      '--no-first-run',
      '--no-default-browser-check',
      'about:blank'
    ], { stdio: 'ignore' });

    let targets = [];
    for (let i = 0; i < 30; i++) {
      try {
        targets = await getCDPTargets();
        if (targets.some((t) => t.type === 'page')) break;
      } catch (_) {}
      await new Promise((r) => setTimeout(r, 300));
    }
    const target = targets.find((t) => t.type === 'page');
    page = new CDPPage(target.webSocketDebuggerUrl);
    await page.connect();

    async function resetPortal() {
      await page.send('Page.navigate', { url: PORTAL });
      await page.waitFor(`document.readyState === 'complete'`);
      await page.eval(`(async () => {
        try {
          const authMod = await import('/src/firebase/auth.js');
          await authMod.signOutUser();
        } catch (_) {}
        sessionStorage.clear();
        localStorage.clear();
      })()`);
      await page.send('Page.navigate', { url: PORTAL });
      await page.waitFor(`Boolean(document.getElementById('btnSignInModal'))`);
    }

    // -----------------------------------------------------------------
    // TEST 1: Admin OAuth Redirect Callback (?code&state) -> No Hang, No Flash
    // -----------------------------------------------------------------
    console.log('\n[CASE 1] Admin OAuth Top-Level Redirect Callback (?code&state)');
    const adminUser = await emuSignUp('admin');
    createdUsers.push(adminUser);
    await fsPatch(`admins/${adminUser.uid}`, { active: true, email: adminUser.email, role: 'ADMIN' });
    await resetPortal();

    const adminCode = await createAuthCodeForUser(adminUser, { admin: true });
    await page.eval(`
      sessionStorage.setItem('pkce_state', ${JSON.stringify(adminCode.state)});
      sessionStorage.setItem('pkce_code_verifier', ${JSON.stringify(adminCode.verifier)});
      window.__sawAccessDeniedFlash = false;
      new MutationObserver(() => {
        if (document.body.innerText.includes('ACCESS DENIED')) window.__sawAccessDeniedFlash = true;
      }).observe(document.body, { childList: true, subtree: true, characterData: true });
    `);

    await page.send('Page.navigate', {
      url: `${PORTAL}/?code=${encodeURIComponent(adminCode.code)}&state=${encodeURIComponent(adminCode.state)}`
    });

    await page.waitFor(`Boolean(document.querySelector('.admin-dashboard, .mission-control, .admin-shell, nav')) || document.body.innerText.includes('MISSION CONTROL')`, 15000);
    const adminCheck = await page.eval(`({
      search: window.location.search,
      loadingStillVisible: Boolean(document.querySelector('.loading-screen')),
      sawAccessDeniedFlash: Boolean(window.__sawAccessDeniedFlash),
      hasSessionId: Boolean(sessionStorage.getItem('lanzar_session_id'))
    })`);
    assertTest('Admin redirect callback exits loading cleanly and mounts Admin dashboard', !adminCheck.loadingStillVisible && adminCheck.hasSessionId);
    assertTest('Redirect URL query string (?code&state) sanitized immediately', adminCheck.search === '');
    assertTest('No transient ACCESS DENIED flash while validating LANZAR ID session', !adminCheck.sawAccessDeniedFlash);

    // -----------------------------------------------------------------
    // TEST 2: Customer OAuth Redirect Callback (?code&state)
    // -----------------------------------------------------------------
    console.log('\n[CASE 2] Customer OAuth Top-Level Redirect Callback (?code&state)');
    const custUser = await emuSignUp('customer');
    createdUsers.push(custUser);
    await resetPortal();
    const custCode = await createAuthCodeForUser(custUser);
    await page.eval(`
      sessionStorage.setItem('pkce_state', ${JSON.stringify(custCode.state)});
      sessionStorage.setItem('pkce_code_verifier', ${JSON.stringify(custCode.verifier)});
    `);
    await page.send('Page.navigate', {
      url: `${PORTAL}/?code=${encodeURIComponent(custCode.code)}&state=${encodeURIComponent(custCode.state)}`
    });
    await page.waitFor(`Boolean(document.querySelector('.portal-nav'))`, 15000);
    assertTest('Customer redirect callback transitions smoothly into Customer Portal', true);

    // -----------------------------------------------------------------
    // TEST 3: OAuth ?error=... Callback Surfaces Clean Error & Never Hangs
    // -----------------------------------------------------------------
    console.log('\n[CASE 3] OAuth Error Query Callback (?error=access_denied)');
    await resetPortal();
    await page.send('Page.navigate', {
      url: `${PORTAL}/?error=access_denied&error_description=${encodeURIComponent('MFA verification cancelled')}`
    });
    await page.waitFor(`Boolean(document.getElementById('btnSignInModal')) && document.body.innerText.includes('MFA verification cancelled')`, 8000);
    const errSearch = await page.eval(`window.location.search`);
    assertTest('OAuth error callback cleans URL and surfaces clear error on Login', errSearch === '');

    // Single Fetch.requestPaused dispatcher reused across fault-injection cases
    let fetchInterceptor = null;
    page.on('Fetch.requestPaused', async (params) => {
      if (fetchInterceptor) {
        await fetchInterceptor(params);
      } else {
        await page.send('Fetch.continueRequest', { requestId: params.requestId });
      }
    });

    // -----------------------------------------------------------------
    // TEST 4: Unavailable / Failing /api/id/session/validate -> Fail Closed + Retry Recovery
    // -----------------------------------------------------------------
    console.log('\n[CASE 4] Session Validation Unavailable -> Fail Closed + User Retry Recovery');
    await resetPortal();
    const retryUser = await emuSignUp('retrycust');
    createdUsers.push(retryUser);
    const retryCode = await createAuthCodeForUser(retryUser);

    let blockSessionValidate = true;
    fetchInterceptor = async (params) => {
      if (blockSessionValidate && params.request.url.includes('/session/validate')) {
        await page.send('Fetch.fulfillRequest', {
          requestId: params.requestId,
          responseCode: 503,
          responseHeaders: [
            { name: 'Content-Type', value: 'application/json' },
            { name: 'Access-Control-Allow-Origin', value: PORTAL }
          ],
          body: Buffer.from(JSON.stringify({ error: 'service_unavailable' })).toString('base64')
        });
      } else {
        await page.send('Fetch.continueRequest', { requestId: params.requestId });
      }
    };
    await page.send('Fetch.enable', {
      patterns: [{ urlPattern: '*session/validate*', requestStage: 'Request' }]
    });

    await page.eval(`
      sessionStorage.setItem('pkce_state', ${JSON.stringify(retryCode.state)});
      sessionStorage.setItem('pkce_code_verifier', ${JSON.stringify(retryCode.verifier)});
    `);
    await page.send('Page.navigate', {
      url: `${PORTAL}/?code=${encodeURIComponent(retryCode.code)}&state=${encodeURIComponent(retryCode.state)}`
    });

    await page.waitFor(`Boolean(document.getElementById('btnRetryInit')) && document.body.innerText.includes('CONNECTION ISSUE')`, 15000);
    const recoveryUi = await page.eval(`({
      hasRetryBtn: Boolean(document.getElementById('btnRetryInit')),
      hasPortalNav: Boolean(document.querySelector('.portal-nav')),
      hasLoadingScreen: Boolean(document.querySelector('.loading-screen')),
      text: document.body.innerText
    })`);
    assertTest('Fail-closed recovery screen rendered without loading hang', recoveryUi.hasRetryBtn && !recoveryUi.hasPortalNav && !recoveryUi.hasLoadingScreen);

    // Heal backend path and click RETRY
    blockSessionValidate = false;
    await page.eval(`document.getElementById('btnRetryInit').click()`);
    await page.waitFor(`Boolean(document.querySelector('.portal-nav'))`, 15000);
    assertTest('Clicking RETRY recovers session without forcing full re-login', true);
    await page.send('Fetch.disable');

    // -----------------------------------------------------------------
    // TEST 5: Stalled /exchange Hits Request Timeout (15s) -> Clears Loading + Surfaces Error
    // -----------------------------------------------------------------
    console.log('\n[CASE 5] Stalled /exchange Network Request Hits 15s Timeout & Recovers');
    await resetPortal();
    const timeoutUser = await emuSignUp('timeout');
    createdUsers.push(timeoutUser);
    const timeoutCode = await createAuthCodeForUser(timeoutUser);

    fetchInterceptor = async (params) => {
      if (params.request.url.includes('/exchange')) {
        // Hold request open so Portal's AbortController 15s timeout fires in real time
        return;
      }
      await page.send('Fetch.continueRequest', { requestId: params.requestId });
    };
    await page.send('Fetch.enable', {
      patterns: [{ urlPattern: '*/exchange*', requestStage: 'Request' }]
    });

    await page.eval(`
      sessionStorage.setItem('pkce_state', ${JSON.stringify(timeoutCode.state)});
      sessionStorage.setItem('pkce_code_verifier', ${JSON.stringify(timeoutCode.verifier)});
    `);
    await page.send('Page.navigate', {
      url: `${PORTAL}/?code=${encodeURIComponent(timeoutCode.code)}&state=${encodeURIComponent(timeoutCode.state)}`
    });

    await page.waitFor(`Boolean(document.querySelector('.loading-screen[data-init-stage="oauth_exchange"]'))`, 5000);
    assertTest('Loading screen surfaces explicit oauth_exchange initialization stage while /exchange is pending', true);

    await page.waitFor(`Boolean(document.getElementById('btnSignInModal')) && document.body.innerText.toLowerCase().includes('timed out')`, 22000);
    const afterTimeout = await page.eval(`({
      hasLoadingScreen: Boolean(document.querySelector('.loading-screen')),
      hasError: Boolean(document.querySelector('.error-msg')),
      canRetryLogin: !document.getElementById('btnSignInModal')?.disabled
    })`);
    assertTest('15s exchange timeout clears loading state and unlocks Login with clear error message',
      !afterTimeout.hasLoadingScreen && afterTimeout.hasError && afterTimeout.canRetryLogin);
    await page.send('Fetch.disable');

    assertTest('Zero uncaught runtime page exceptions occurred', pageExceptions.length === 0, pageExceptions.join(' | '));
  } finally {
    if (page) page.close();
    for (const u of createdUsers) {
      await fetch(`${EMU_AUTH}/accounts:delete?${KEY}`, {
        method: 'POST', headers: JSON_H, body: JSON.stringify({ localId: u.uid })
      }).catch(() => {});
      await fsDelete(`admins/${u.uid}`).catch(() => {});
      await fsDelete(`users/${u.uid}`).catch(() => {});
    }
    try { fs.rmSync(tmpProfileDir, { recursive: true, force: true }); } catch (_) {}
    if (chromeProcess) try { chromeProcess.kill(); } catch (_) {}
    if (portalProcess) try { portalProcess.kill(); } catch (_) {}
    if (backendProcess) try { backendProcess.kill(); } catch (_) {}
    if (emulatorProcess) try { emulatorProcess.kill(); } catch (_) {}
    const portsToStop = [PORTAL_PORT, BACKEND_PORT, CDP_PORT];
    if (emulatorProcess) portsToStop.push(AUTH_EMU_PORT, FIRESTORE_EMU_PORT);
    stopListeningPorts(portsToStop);
  }

  console.log('\n================================================================');
  console.log(`  RESILIENCE RESULTS: ${passCount} PASSED, ${failCount} FAILED`);
  console.log('================================================================');
  process.exit(failCount > 0 ? 1 : 0);
}

run().catch((err) => {
  console.error('FATAL TEST ERROR:', err);
  stopListeningPorts([PORTAL_PORT, BACKEND_PORT, CDP_PORT, AUTH_EMU_PORT, FIRESTORE_EMU_PORT]);
  process.exit(1);
});
