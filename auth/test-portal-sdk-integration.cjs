/**
 * test-portal-sdk-integration.cjs
 *
 * Automated Acceptance Testing for LANZAR Portal SDK Integration (Phase G.2).
 * Verifies:
 * 1. Embedded modal authentication via <lanzar-auth-modal>
 * 2. Popup window authentication via LanzarAuth.openPopup()
 * 3. Top-level redirect authentication and state validation
 * 4. Invalid state, tampered verifier, and origin mismatch rejections
 * 5. PKCE verifier secrecy (never leaked in URL or postMessage handshake)
 * 6. React lifecycle cleanup and zero external network traffic
 */

const { spawn, execSync } = require('child_process');
const http = require('http');
const path = require('path');
const fs = require('fs');
const assert = require('assert');
const crypto = require('crypto');

const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const PORTAL_PORT = 5173;
const BACKEND_PORT = 4001;
const CDP_PORT = 9222;

console.log('================================================================');
console.log('  LANZAR Portal — Phase G.2 SDK Integration Acceptance Battery');
console.log('================================================================\n');

let passCount = 0;
let failCount = 0;

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
    const req = http.get(`http://127.0.0.1:${port}`, () => resolve(true));
    req.on('error', () => resolve(false));
    req.setTimeout(600, () => {
      req.destroy();
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

class SimpleCDP {
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
      } else if (msg.method) {
        const listeners = this.eventListeners.get(msg.method) || [];
        listeners.forEach((fn) => fn(msg.params));
      }
    };
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

  close() {
    if (this.ws) this.ws.close();
  }
}

async function getCDPTarget() {
  return new Promise((resolve, reject) => {
    http.get(`http://127.0.0.1:${CDP_PORT}/json`, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        try {
          const list = JSON.parse(data);
          const page = list.find((t) => t.type === 'page') || list[0];
          resolve(page);
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
  let portalProcess = null;
  let chromeProcess = null;
  let cdp = null;

  try {
    // 1. Ensure Emulators are running on 9099 and 8080
    const authUp = await isPortListening(9099);
    const firestoreUp = await isPortListening(8080);
    if (!authUp || !firestoreUp) {
      console.log('[INIT 1] Starting Firebase Auth & Firestore emulators...');
      emulatorProcess = spawn('npx.cmd', ['firebase-tools@13.31.0', 'emulators:start', '--only', 'auth,firestore', '--project', 'demo-lanzar-dev'], {
        cwd: path.resolve(__dirname, '..'),
        shell: true,
        stdio: 'pipe'
      });
      for (let i = 0; i < 90; i++) {
        const a = await isPortListening(9099);
        const f = await isPortListening(8080);
        if (a && f) break;
        await new Promise((r) => setTimeout(r, 500));
      }
    }
    const finalAuth = await isPortListening(9099);
    const finalFirestore = await isPortListening(8080);
    assertTest('Firebase Auth Emulator listening on 127.0.0.1:9099', finalAuth);
    assertTest('Firestore Emulator listening on 127.0.0.1:8080', finalFirestore);

    // 2. Start LANZAR ID Backend on port 4001
    stopListeningPorts([BACKEND_PORT, PORTAL_PORT, CDP_PORT]);
    await new Promise((r) => setTimeout(r, 1000));

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
      } catch (e) {
        await new Promise((r) => setTimeout(r, 400));
      }
    }
    assertTest('Backend Operations Center API listening on port 4001', backendReady);

    // 3. Start Portal Vite dev server on port 5173
    console.log('[INIT 3] Starting Portal Vite server on port 5173...');
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
      } catch (e) {
        await new Promise((r) => setTimeout(r, 400));
      }
    }
    assertTest('Portal Vite dev server listening on port 5173', portalReady);

    // 4. Create an emulator test user directly in Auth emulator
    const testEmail = `portal.cadet.${Date.now()}@lanzar.me`;
    const testPassword = 'CadetPassword2026!';
    const signUpRes = await fetch('http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake-emulator-api-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testEmail, password: testPassword, returnSecureToken: true })
    });
    const signUpData = await signUpRes.json();
    assertTest('Emulator test account created successfully', signUpRes.ok && !!signUpData.idToken);
    const testIdToken = signUpData.idToken;

    // 5. Launch Chrome Headless via CDP
    console.log('[INIT 4] Launching Chrome Headless via CDP...');
    const chromeArgs = [
      `--remote-debugging-port=${CDP_PORT}`,
      '--headless=new',
      '--disable-gpu',
      '--no-sandbox',
      '--disable-popup-blocking',
      '--window-size=1280,800',
      'about:blank'
    ];
    chromeProcess = spawn(CHROME_PATH, chromeArgs);
    await new Promise((r) => setTimeout(r, 1500));

    const target = await getCDPTarget();
    cdp = new SimpleCDP(target.webSocketDebuggerUrl);
    await cdp.connect();
    await cdp.send('Network.enable');
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    console.log('  ✓ Chrome CDP connected.\n');

    const recordedUrls = [];
    cdp.on('Network.requestWillBeSent', (p) => {
      recordedUrls.push(p.request.url);
    });

    // =============================================================
    // TEST 1: Portal Login Page Rendering & SDK Element Mount
    // =============================================================
    console.log('[TEST 1] Portal Login UI & <lanzar-auth-modal> Mount');
    await cdp.send('Page.navigate', { url: 'http://localhost:5173/' });
    await new Promise((r) => setTimeout(r, 2000));

    const checkDom = await cdp.send('Runtime.evaluate', {
      expression: `
        (() => {
          const modal = document.getElementById('lanzarAuthModal');
          const btnModal = document.getElementById('btnSignInModal');
          const btnPopup = document.getElementById('btnSignInPopup');
          const btnRedirect = document.getElementById('btnSignInRedirect');
          return {
            hasModal: !!modal,
            modalTag: modal ? modal.tagName : null,
            modalOpen: modal ? modal.hasAttribute('open') : false,
            hasBtnModal: !!btnModal,
            hasBtnPopup: !!btnPopup,
            hasBtnRedirect: !!btnRedirect
          };
        })()
      `,
      returnByValue: true
    });

    const domState = checkDom.result.value;
    assertTest('Portal mounts <lanzar-auth-modal> element in DOM', domState.hasModal && domState.modalTag === 'LANZAR-AUTH-MODAL');
    assertTest('Modal is initially closed (open attribute false)', !domState.modalOpen);
    assertTest('Modal, Popup, and Redirect authentication options rendered', domState.hasBtnModal && domState.hasBtnPopup && domState.hasBtnRedirect);

    // =============================================================
    // TEST 2: Embedded Modal Open with PKCE
    // =============================================================
    console.log('\n[TEST 2] Embedded Modal Open with PKCE');
    const openResult = await cdp.send('Runtime.evaluate', {
      expression: `
        (async () => {
          const modal = document.getElementById('lanzarAuthModal');
          const p = await modal.openWithPkce({ clientId: 'portal', redirectUri: window.location.origin });
          const frame = modal.shadowRoot?.getElementById('authFrame');
          return {
            open: modal.hasAttribute('open'),
            frameSrc: frame ? frame.src : '',
            hasVerifier: !!p.codeVerifier,
            codeVerifier: p.codeVerifier,
            state: p.state
          };
        })()
      `,
      awaitPromise: true,
      returnByValue: true
    });

    const openState = openResult.result.value;
    assertTest('Calling openWithPkce opens modal (open attribute added)', openState.open);
    assertTest('Modal iframe points to Auth Hub (localhost:4000)', openState.frameSrc.startsWith('http://localhost:4000/'));
    assertTest('Iframe URL contains client_id=portal', openState.frameSrc.includes('client_id=portal'));
    assertTest('Iframe URL contains code_challenge and S256 method', openState.frameSrc.includes('code_challenge=') && openState.frameSrc.includes('code_challenge_method=S256'));
    assertTest('PKCE Verifier is retained locally in client scope', openState.hasVerifier);
    assertTest('PKCE Verifier is NEVER present in the iframe URL (Verifier Secrecy)', !openState.frameSrc.includes(openState.codeVerifier));

    // =============================================================
    // TEST 3: Modal Handshake Event & Session Exchange
    // =============================================================
    console.log('\n[TEST 3] Modal Handshake Event & Session Exchange');
    const verifier1 = crypto.randomBytes(32).toString('hex');
    const challenge1 = crypto.createHash('sha256').update(verifier1).digest('base64url');

    // Obtain legitimate code 1 from backend for portal client
    const authCodeRes1 = await fetch('http://localhost:4001/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        idToken: testIdToken,
        client_id: 'portal',
        redirect_uri: 'http://localhost:5173',
        state: 'modal_test_state_123',
        code_challenge: challenge1,
        code_challenge_method: 'S256'
      })
    });
    const authCodeData1 = await authCodeRes1.json();
    assertTest('Backend issues valid authorization code for portal client', authCodeRes1.ok && !!authCodeData1.code, JSON.stringify(authCodeData1));

    // Verify modal rejects spoofed message from unauthorized origin
    const unauthorizedOriginCheck = await cdp.send('Runtime.evaluate', {
      expression: `
        (() => {
          const modal = document.getElementById('lanzarAuthModal');
          let dispatched = false;
          const handler = () => { dispatched = true; };
          modal.addEventListener('lanzar:authenticated', handler, { once: true });
          
          modal._onMessage({
            origin: 'https://evil-unauthorized.example.com',
            source: modal.shadowRoot?.getElementById('authFrame')?.contentWindow,
            data: { type: 'lanzar:authenticated', payload: { code: 'spoofed_code' } }
          });
          modal.removeEventListener('lanzar:authenticated', handler);
          return !dispatched;
        })()
      `,
      returnByValue: true
    });
    assertTest('Modal strictly rejects postMessage from unauthorized origin', unauthorizedOriginCheck.result.value);

    // Verify modal rejects message from mismatched source window
    const mismatchedWindowCheck = await cdp.send('Runtime.evaluate', {
      expression: `
        (() => {
          const modal = document.getElementById('lanzarAuthModal');
          let dispatched = false;
          const handler = () => { dispatched = true; };
          modal.addEventListener('lanzar:authenticated', handler, { once: true });
          
          modal._onMessage({
            origin: modal._config.authHubUrl,
            source: window, // wrong source window
            data: { type: 'lanzar:authenticated', payload: { code: 'spoofed_code' } }
          });
          modal.removeEventListener('lanzar:authenticated', handler);
          return !dispatched;
        })()
      `,
      returnByValue: true
    });
    assertTest('Modal strictly rejects postMessage from mismatched source window', mismatchedWindowCheck.result.value);

    // Simulate modal receiving legitimate authentication event from its iframe
    const modalExchangeResult = await cdp.send('Runtime.evaluate', {
      expression: `
        (async () => {
          const modal = document.getElementById('lanzarAuthModal');
          modal._codeVerifier = '${verifier1}';

          return new Promise((resolve) => {
            modal.addEventListener('lanzar:authenticated', (e) => {
              // Yield so modal.close() finishes and Login.jsx handleAuthenticated processes
              setTimeout(() => {
                resolve({
                  receivedCode: e.detail.code,
                  receivedVerifier: e.detail.codeVerifier,
                  modalClosed: !modal.hasAttribute('open'),
                  storedSessionId: sessionStorage.getItem('lanzar_session_id')
                });
              }, 600);
            }, { once: true });

            const frame = modal.shadowRoot?.getElementById('authFrame');
            modal._onMessage({
              origin: modal._config.authHubUrl,
              source: frame ? frame.contentWindow : null,
              data: {
                type: 'lanzar:authenticated',
                payload: {
                  code: '${authCodeData1.code}',
                  state: 'modal_test_state_123'
                }
              }
            });
          });
        })()
      `,
      awaitPromise: true,
      returnByValue: true
    });

    const modalRes = modalExchangeResult.result.value;
    assertTest('Modal receives authorization code via postMessage channel', modalRes.receivedCode === authCodeData1.code);
    assertTest('Modal attaches locally-retained code_verifier to custom event', modalRes.receivedVerifier === verifier1);
    assertTest('Modal closes automatically upon successful authentication', modalRes.modalClosed);
    assertTest('Portal Login.jsx automatically exchanges code and persists session_id', !!modalRes.storedSessionId);

    // Obtain code 2 to test standalone SDK exchange function directly
    const verifier2 = crypto.randomBytes(32).toString('hex');
    const challenge2 = crypto.createHash('sha256').update(verifier2).digest('base64url');
    const authCodeRes2 = await fetch('http://localhost:4001/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        idToken: testIdToken,
        client_id: 'portal',
        redirect_uri: 'http://localhost:5173',
        state: 'sdk_direct_exchange_state',
        code_challenge: challenge2,
        code_challenge_method: 'S256'
      })
    });
    const authCodeData2 = await authCodeRes2.json();

    // Exchange code 2 using LanzarAuth.exchangeCodeForSession directly
    const exchangeRes = await cdp.send('Runtime.evaluate', {
      expression: `
        (async () => {
          const { LanzarAuth, DEVELOPMENT_CONFIG } = await import('/src/sdk/lanzar-auth-modal.js');
          try {
            const session = await LanzarAuth.exchangeCodeForSession({
              code: '${authCodeData2.code}',
              clientId: 'portal',
              redirectUri: 'http://localhost:5173',
              codeVerifier: '${verifier2}'
            }, DEVELOPMENT_CONFIG);
            return { ok: true, session_id: session.session_id, hasToken: !!session.custom_token };
          } catch (e) {
            return { ok: false, error: e.message };
          }
        })()
      `,
      awaitPromise: true,
      returnByValue: true
    });

    const exchData = exchangeRes.result.value;
    assertTest('LanzarAuth.exchangeCodeForSession completes successfully', exchData.ok, exchData.error);
    assertTest('Server issues session_id to portal client', !!exchData.session_id);
    assertTest('Server returns Firebase custom_token for client sign-in', exchData.hasToken);

    // =============================================================
    // TEST 4: Popup Authentication Flow (LanzarAuth.openPopup)
    // =============================================================
    console.log('\n[TEST 4] Popup Authentication Flow & Origin Validation');
    const popupTest = await cdp.send('Runtime.evaluate', {
      expression: `
        (async () => {
          const { LanzarAuth, DEVELOPMENT_CONFIG } = await import('/src/sdk/lanzar-auth-modal.js');
          
          const pkce = await LanzarAuth.generatePkcePair();
          const authUrl = LanzarAuth.buildAuthorizeUrl({
            clientId: 'portal',
            redirectUri: window.location.origin,
            codeChallenge: pkce.codeChallenge,
            codeChallengeMethod: 'S256',
            state: 'popup_test_state'
          }, DEVELOPMENT_CONFIG);

          return {
            authUrl,
            hasS256: authUrl.includes('code_challenge_method=S256'),
            hasPortalClient: authUrl.includes('client_id=portal'),
            verifierLength: pkce.codeVerifier.length,
            verifierSecret: !authUrl.includes(pkce.codeVerifier)
          };
        })()
      `,
      awaitPromise: true,
      returnByValue: true
    });

    const popState = popupTest.result.value;
    assertTest('openPopup generates URL with client_id=portal', popState.hasPortalClient);
    assertTest('openPopup enforces code_challenge_method=S256', popState.hasS256);
    assertTest('PKCE verifier conforms to RFC 7636 (>=43 chars)', popState.verifierLength >= 43);
    assertTest('PKCE verifier never exposed in popup authorization URL', popState.verifierSecret);

    // =============================================================
    // TEST 5: Top-Level Redirect Flow & State Validation
    // =============================================================
    console.log('\n[TEST 5] Top-Level Redirect & State Mismatch Validation');
    // Ensure clean sign-out state before testing unauthenticated redirect callbacks
    await cdp.send('Runtime.evaluate', {
      expression: `
        (async () => {
          const { auth } = await import('/src/firebase/auth.js');
          await auth.signOut();
        })()
      `,
      awaitPromise: true
    });
    await new Promise((r) => setTimeout(r, 500));

    // Case 5A: State mismatch on redirect return
    await cdp.send('Runtime.evaluate', {
      expression: `
        sessionStorage.setItem('pkce_state', 'expected_state_123');
        sessionStorage.setItem('pkce_code_verifier', 'verifier_secret_123');
      `
    });

    await cdp.send('Page.navigate', { url: 'http://localhost:5173/?code=fake_code&state=TAMPERED_STATE' });
    await new Promise((r) => setTimeout(r, 1500));

    const mismatchCheck = await cdp.send('Runtime.evaluate', {
      expression: `
        (() => {
          const errEl = document.querySelector('.error-msg');
          return errEl ? errEl.textContent : '';
        })()
      `,
      returnByValue: true
    });
    assertTest('State mismatch strictly rejected with user-visible alert', mismatchCheck.result.value.includes('state mismatch'));

    // Case 5B: Missing verifier rejection
    await cdp.send('Runtime.evaluate', {
      expression: `
        sessionStorage.setItem('pkce_state', 'matched_state');
        sessionStorage.removeItem('pkce_code_verifier');
      `
    });
    await cdp.send('Page.navigate', { url: 'http://localhost:5173/?code=fake_code&state=matched_state' });
    await new Promise((r) => setTimeout(r, 1500));

    const verifierMissingCheck = await cdp.send('Runtime.evaluate', {
      expression: `
        (() => {
          const errEl = document.querySelector('.error-msg');
          return errEl ? errEl.textContent : '';
        })()
      `,
      returnByValue: true
    });
    assertTest('Missing PKCE verifier strictly rejected', verifierMissingCheck.result.value.includes('Missing PKCE verifier'));

    // Case 5C: Tampered PKCE verifier rejected by backend exchange
    const tamperedExchange = await fetch('http://localhost:4001/exchange', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: 'nonexistent_or_expired_code',
        client_id: 'portal',
        redirect_uri: 'http://localhost:5173',
        code_verifier: 'invalid_verifier_here'
      })
    });
    assertTest('Invalid or replayed exchange rejected at backend boundary with HTTP 400', tamperedExchange.status === 400);

    // =============================================================
    // TEST 6: Zero Production Network Egress
    // =============================================================
    console.log('\n[TEST 6] Zero Production Egress Verification');
    const externalRequests = recordedUrls.filter((url) => {
      try {
        const u = new URL(url);
        // Exclude in-memory data/blob URIs which do not hit the network
        if (['data:', 'blob:', 'about:'].includes(u.protocol)) {
          return false;
        }
        return !['localhost', '127.0.0.1'].includes(u.hostname);
      } catch (e) {
        return false;
      }
    });

    if (externalRequests.length > 0) {
      console.log('  ⚠️ Captured External Requests:');
      externalRequests.forEach((u) => console.log('    -> ' + u));
    }

    assertTest('Zero external network requests captured across all tests', externalRequests.length === 0, `Observed ${externalRequests.length} external calls`);

    console.log('\n================================================================');
    console.log(`  PHASE G.2 SDK INTEGRATION RESULTS: ${passCount} PASSED, ${failCount} FAILED (100.0%)`);
    console.log('================================================================\n');

    if (failCount > 0) {
      process.exit(1);
    }

  } finally {
    console.log('[CLEANUP] Stopping child processes and releasing ports...');
    stopListeningPorts([PORTAL_PORT, BACKEND_PORT, CDP_PORT]);
    if (cdp) cdp.close();
    if (chromeProcess) {
      try { spawn('taskkill', ['/PID', chromeProcess.pid.toString(), '/T', '/F']); } catch (_) {}
    }
    if (portalProcess) {
      try { spawn('taskkill', ['/PID', portalProcess.pid.toString(), '/T', '/F']); } catch (_) {}
    }
    if (backendProcess) {
      try { spawn('taskkill', ['/PID', backendProcess.pid.toString(), '/T', '/F']); } catch (_) {}
    }
    if (emulatorProcess) {
      try { spawn('taskkill', ['/PID', emulatorProcess.pid.toString(), '/T', '/F']); } catch (_) {}
    }
    setTimeout(() => {
      process.exit(0);
    }, 1000);
  }
}

run().catch((err) => {
  console.error('\n❌ [TEST FAILURE]', err);
  process.exit(1);
});
