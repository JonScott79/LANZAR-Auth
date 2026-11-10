/**
 * test-portal-session-security.cjs
 *
 * Phase G.3 - Application & Session Security acceptance suite (local only, demo-lanzar-dev).
 *   Section 1: backend HTTP security (session validation, admin authorization, revocation, expiry, suspension)
 *   Section 2: real Chrome (CDP) Portal behavior (route protection, restoration, revocation, logout)
 *   Section 3: complete test-data cleanup
 * Genuine LANZAR ID sessions are obtained through the real /authorize + PKCE /exchange + custom-token flow.
 * No cloud services are contacted; all traffic is loopback.
 */

const { spawn, execSync } = require('child_process');
const http = require('http');
const net = require('net');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const PORTAL_PORT = 5173;
const AUTH_HUB_PORT = 4000;
const BACKEND_PORT = 4001;
const CDP_PORT = 9222;
const AUTH_EMU_PORT = 9099;
const FIRESTORE_EMU_PORT = 8080;

console.log('================================================================');
console.log('  LANZAR Portal - Phase G.3 Application & Session Security Suite');
console.log('  Timestamp: ' + new Date().toISOString());
console.log('================================================================\n');

const recordedUrls = [];
const recordedResponses = [];
const pageExceptions = [];

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
      } else if (msg.method === 'Runtime.exceptionThrown') {
        pageExceptions.push(`${msg.params?.exceptionDetails?.text} ${msg.params?.exceptionDetails?.exception?.description || ''}`);
      } else if (msg.method === 'Network.responseReceived') {
        recordedResponses.push({ url: msg.params?.response?.url || '', status: msg.params?.response?.status });
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

// =====================================================================
// Test helpers (HTTP / emulator)
// =====================================================================
const API = 'http://localhost:4001';
const PORTAL = 'http://localhost:5173';
const EMU_AUTH = 'http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1';
const FS = 'http://127.0.0.1:8080/v1/projects/demo-lanzar-dev/databases/(default)/documents';
const OWNER = { Authorization: 'Bearer owner' };
const JSON_H = { 'Content-Type': 'application/json' };
const PASSWORD = 'SecTestPassword2026!';
const KEY = 'key=fake-emulator-api-key';

const { createMfaSignedToken } = require('./auth-backend/mfaService');

async function jfetch(url, opts = {}) {
  const res = await fetch(url, opts);
  let body = null;
  try { body = await res.json(); } catch (_) {}
  return { status: res.status, ok: res.ok, body };
}

const bearer = (t) => ({ Authorization: `Bearer ${t}` });

async function emuSignUp(label) {
  const email = `sec.${label}.${Date.now()}.${Math.floor(Math.random() * 1e6)}@lanzar.me`;
  const r = await jfetch(`${EMU_AUTH}/accounts:signUp?${KEY}`, {
    method: 'POST', headers: JSON_H,
    body: JSON.stringify({ email, password: PASSWORD, displayName: `Sec ${label}`, returnSecureToken: true })
  });
  if (!r.ok) throw new Error(`signUp failed for ${label}: ${JSON.stringify(r.body)}`);
  return { label, email, uid: r.body.localId, idToken: r.body.idToken };
}

async function emuSignIn(email) {
  const r = await jfetch(`${EMU_AUTH}/accounts:signInWithPassword?${KEY}`, {
    method: 'POST', headers: JSON_H,
    body: JSON.stringify({ email, password: PASSWORD, returnSecureToken: true })
  });
  if (!r.ok) throw new Error(`signIn failed: ${JSON.stringify(r.body)}`);
  return r.body.idToken;
}

async function emuSetClaims(uid, claims) {
  const r = await jfetch('http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/projects/demo-lanzar-dev/accounts:update', {
    method: 'POST', headers: { ...JSON_H, ...OWNER },
    body: JSON.stringify({ localId: uid, customAttributes: JSON.stringify(claims) })
  });
  if (!r.ok) throw new Error(`setClaims failed: ${JSON.stringify(r.body)}`);
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
    method: 'PATCH', headers: { ...JSON_H, ...OWNER }, body: JSON.stringify({ fields })
  });
  if (!r.ok) throw new Error(`fsPatch ${docPath} failed: ${JSON.stringify(r.body)}`);
}

async function fsGet(docPath) {
  return jfetch(`${FS}/${docPath}`, { headers: OWNER });
}

async function fsDelete(docPath) {
  return jfetch(`${FS}/${docPath}`, { method: 'DELETE', headers: OWNER });
}

async function fsList(collectionPath) {
  const out = [];
  let token = '';
  do {
    const r = await jfetch(`${FS}/${collectionPath}?pageSize=300${token ? `&pageToken=${token}` : ''}`, { headers: OWNER });
    if (!r.ok || !r.body) break;
    (r.body.documents || []).forEach((d) => out.push(d));
    token = r.body.nextPageToken || '';
  } while (token);
  return out;
}

// Full OAuth + PKCE journey against the real backend, then Firebase custom-token sign-in on the emulator.
// Produces a genuine LANZAR ID session (session_id claim embedded in the ID token).
async function lanzarSession(user, { admin = false } = {}) {
  const verifier = crypto.randomBytes(32).toString('hex');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const baseIdToken = await emuSignIn(user.email);
  const payload = {
    idToken: baseIdToken, client_id: 'portal', redirect_uri: PORTAL, state: 'sec_state',
    code_challenge: challenge, code_challenge_method: 'S256'
  };
  if (admin) {
    payload.mfa_proof = createMfaSignedToken({ uid: user.uid, email: user.email, action: 'mfa_verified', verifiedAt: Date.now() }, 300000);
  }
  const a = await jfetch(`${API}/authorize`, { method: 'POST', headers: JSON_H, body: JSON.stringify(payload) });
  if (!a.ok) throw new Error(`authorize failed for ${user.label}: ${a.status} ${JSON.stringify(a.body)}`);
  const x = await jfetch(`${API}/exchange`, {
    method: 'POST', headers: JSON_H,
    body: JSON.stringify({ code: a.body.code, client_id: 'portal', redirect_uri: PORTAL, code_verifier: verifier })
  });
  if (!x.ok) throw new Error(`exchange failed for ${user.label}: ${x.status} ${JSON.stringify(x.body)}`);
  const s = await jfetch(`${EMU_AUTH}/accounts:signInWithCustomToken?${KEY}`, {
    method: 'POST', headers: JSON_H, body: JSON.stringify({ token: x.body.custom_token, returnSecureToken: true })
  });
  if (!s.ok) throw new Error(`custom token sign-in failed: ${JSON.stringify(s.body)}`);
  return { sessionId: x.body.session_id, customToken: x.body.custom_token, idToken: s.body.idToken, createdAt: Date.now() };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// =====================================================================
// Test run
// =====================================================================
async function run() {
  let emulatorProcess = null;
  let backendProcess = null;
  let authHubProcess = null;
  let portalProcess = null;
  let chromeProcess = null;
  let mainPage = null;
  const createdUsers = [];
  const tmpProfileDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chrome_portal_sec_'));

  async function waitHttp(url, label, tries = 40) {
    let ok = false;
    for (let i = 0; i < tries; i++) {
      try {
        await new Promise((resolve, reject) => {
          const req = http.get(url, (res) => { res.resume(); resolve(); });
          req.on('error', reject);
        });
        ok = true; break;
      } catch (_) { await sleep(400); }
    }
    assertTest(label, ok);
  }

  try {
    // ---------------- INIT ----------------
    const authUp0 = await isPortListening(AUTH_EMU_PORT);
    const fsUp0 = await isPortListening(FIRESTORE_EMU_PORT);
    if (!authUp0 || !fsUp0) {
      console.log('[INIT] Starting Firebase Auth & Firestore emulators (demo-lanzar-dev)...');
      emulatorProcess = spawn('npx.cmd', ['firebase-tools@13.31.0', 'emulators:start', '--only', 'auth,firestore', '--project', 'demo-lanzar-dev'], {
        cwd: path.resolve(__dirname, '..'), shell: true, stdio: 'pipe'
      });
      for (let i = 0; i < 90; i++) {
        if ((await isPortListening(AUTH_EMU_PORT)) && (await isPortListening(FIRESTORE_EMU_PORT))) break;
        await sleep(500);
      }
    }
    assertTest('Firebase Auth Emulator active on 127.0.0.1:9099', await isPortListening(AUTH_EMU_PORT));
    assertTest('Firestore Emulator active on 127.0.0.1:8080', await isPortListening(FIRESTORE_EMU_PORT));

    stopListeningPorts([BACKEND_PORT, AUTH_HUB_PORT, PORTAL_PORT, CDP_PORT]);
    await sleep(1000);

    console.log('[INIT] Starting LANZAR ID backend (4001), Auth Hub (4000), Portal (5173)...');
    backendProcess = spawn('node', ['auth/auth-backend/server.js'], {
      cwd: path.resolve(__dirname, '..'),
      env: {
        ...process.env, APP_ENV: 'development', FIREBASE_PROJECT_ID: 'demo-lanzar-dev',
        FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099', FIRESTORE_EMULATOR_HOST: '127.0.0.1:8080',
        PORT: '4001', SESSION_SIGNING_SECRET: 'development_session_signing_secret_min_32_chars'
      },
      stdio: 'pipe'
    });
    await waitHttp(`${API}/api/id/health`, 'Backend API active on port 4001');

    authHubProcess = spawn('npx.cmd', ['vite', '--port', '4000'], {
      cwd: path.resolve(__dirname), env: { ...process.env, VITE_APP_ENV: 'development' }, shell: true, stdio: 'pipe'
    });
    await waitHttp('http://localhost:4000/', 'Auth Hub active on port 4000');

    portalProcess = spawn('npx.cmd', ['vite', '--port', '5173'], {
      cwd: path.resolve(__dirname, '../portal'), env: { ...process.env, VITE_APP_ENV: 'development' }, shell: true, stdio: 'pipe'
    });
    await waitHttp(`${PORTAL}/`, 'Portal active on port 5173');

    // ---------------- Provision identities ----------------
    console.log('\n[SETUP] Provisioning test identities (emulator only)...');
    const mk = async (label) => { const u = await emuSignUp(label); createdUsers.push(u); return u; };
    const custA = await mk('custA');       // valid customer (API + browser)
    const custB = await mk('custB');       // individual revocation
    const custC = await mk('custC');       // revoke-all
    const custD = await mk('custD');       // suspended
    const custE = await mk('custE');       // inactive
    const custF = await mk('custF');       // expired session
    const custG = await mk('custG');       // forged client claims
    const custH = await mk('custH');       // browser logout
    const custI = await mk('custI');       // browser revocation
    const custJ = await mk('custJ');       // browser revoke-all
    const adminU = await mk('admin');
    await fsPatch(`admins/${adminU.uid}`, { active: true, email: adminU.email, role: 'ADMIN' });
    assertTest('Test identities provisioned (10 customers + 1 administrator record)', createdUsers.length === 11);

    // Expired session created first so the backend's 30s revocation cache lapses during the run
    const sessF = await lanzarSession(custF);
    await fsPatch(`users/${custF.uid}/sessions/${sessF.sessionId}`, { expiresAt: new Date(Date.now() - 60000).toISOString() });

    // =============================================================
    // SECTION 1: Backend API security
    // =============================================================
    console.log('\n[SECTION 1] Backend session & administrator authorization (HTTP)');
    const sessA = await lanzarSession(custA);
    const sessAdmin = await lanzarSession(adminU, { admin: true });

    // 1.1 Valid customer
    const vA = await jfetch(`${API}/api/id/session/validate`, { headers: bearer(sessA.idToken) });
    assertTest('SEC-A1: Valid customer session validates (200, session_id bound to token)', vA.status === 200 && vA.body.valid === true && vA.body.session_id === sessA.sessionId);
    assertTest('SEC-A1b: Customer is_admin resolved false by server', vA.body.is_admin === false);

    // 1.2 Valid administrator
    const vAdm = await jfetch(`${API}/api/id/session/validate`, { headers: bearer(sessAdmin.idToken) });
    assertTest('SEC-A2: Administrator session validates with server-resolved is_admin=true', vAdm.status === 200 && vAdm.body.is_admin === true);
    const adminPaths = ['/api/admin/id/telemetry', '/api/admin/id/clients', '/api/admin/id/users', '/api/admin/id/audit-log'];
    const adminOk = [];
    for (const p of adminPaths) adminOk.push((await jfetch(`${API}${p}`, { headers: bearer(sessAdmin.idToken) })).status);
    assertTest('SEC-A2b: Administrator reaches all Mission Control admin APIs (200)', adminOk.every((s) => s === 200), adminOk.join(','));

    // 1.3 Customer attempting admin access
    const custAdminStatuses = [];
    for (const p of adminPaths) custAdminStatuses.push((await jfetch(`${API}${p}`, { headers: bearer(sessA.idToken) })).status);
    assertTest('SEC-A3: Customer session rejected from every admin GET API (403)', custAdminStatuses.every((s) => s === 403), custAdminStatuses.join(','));
    const custMutations = [
      await jfetch(`${API}/api/admin/id/users/${custB.uid}/suspend`, { method: 'POST', headers: { ...JSON_H, ...bearer(sessA.idToken) }, body: JSON.stringify({ status: 'suspended', reason: 'x' }) }),
      await jfetch(`${API}/api/admin/id/users/${custB.uid}/sessions/revoke-all`, { method: 'POST', headers: bearer(sessA.idToken) }),
      await jfetch(`${API}/api/admin/id/users/${custB.uid}/founders`, { method: 'POST', headers: { ...JSON_H, ...bearer(sessA.idToken) }, body: JSON.stringify({ programId: 'p', founderNumber: 1, title: 't', grantReason: 'r' }) })
    ].map((r) => r.status);
    assertTest('SEC-A3b: Customer session rejected from admin mutations (403)', custMutations.every((s) => s === 403), custMutations.join(','));

    // 1.4 Unauthenticated admin API calls
    const unauth = [
      await jfetch(`${API}/api/admin/id/telemetry`),
      await jfetch(`${API}/api/admin/id/telemetry`, { headers: { Authorization: 'Bearer mock_admin_dev_token' } }),
      await jfetch(`${API}/api/admin/id/telemetry`, { headers: { Authorization: 'Bearer ' } }),
      await jfetch(`${API}/api/admin/id/users`, { headers: { Authorization: 'Bearer not.a.real.token' } }),
      await jfetch(`${API}/api/admin/id/audit-log`, { headers: { Authorization: `Basic ${Buffer.from('a:b').toString('base64')}` } }),
      await jfetch(`${API}/api/id/session/validate`),
      await jfetch(`${API}/api/id/sessions/anything`, { method: 'DELETE' })
    ].map((r) => r.status);
    assertTest('SEC-A4: Unauthenticated / bypass-token / malformed admin & session API calls rejected (401)', unauth.every((s) => s === 401), unauth.join(','));

    // 1.5 Client-side role claims are not trusted
    await emuSetClaims(custG.uid, { admin: true, role: 'ADMIN', isAdmin: true, roles: ['admin'] });
    const forgedToken = await emuSignIn(custG.email);
    const forgedPayload = JSON.parse(Buffer.from(forgedToken.split('.')[1], 'base64url').toString('utf8'));
    assertTest('SEC-A5-pre: Forged admin claims present in client token', forgedPayload.admin === true && forgedPayload.role === 'ADMIN');
    const forgedAdmin = await jfetch(`${API}/api/admin/id/telemetry`, { headers: bearer(forgedToken) });
    const forgedValidate = await jfetch(`${API}/api/id/session/validate`, { headers: bearer(forgedToken) });
    assertTest('SEC-A5: Forged admin claims never grant administrator access (403, is_admin=false)', forgedAdmin.status === 403 && forgedValidate.body.is_admin === false);
    assertTest('SEC-A5b: Token without LANZAR ID session reports session_id=null (Portal treats as unauthenticated)', forgedValidate.status === 200 && forgedValidate.body.session_id === null);

    // 1.6 Individual session revocation
    const sessB1 = await lanzarSession(custB);
    const sessB2 = await lanzarSession(custB);
    const preRevoke = await jfetch(`${API}/api/id/session/validate`, { headers: bearer(sessB1.idToken) });
    const revokeB1 = await jfetch(`${API}/api/id/sessions/${sessB1.sessionId}`, { method: 'DELETE', headers: bearer(sessB1.idToken) });
    const postB1 = await jfetch(`${API}/api/id/session/validate`, { headers: bearer(sessB1.idToken) });
    const postB1Profile = await jfetch(`${API}/api/id/profile`, { headers: bearer(sessB1.idToken) });
    const siblingB2 = await jfetch(`${API}/api/id/session/validate`, { headers: bearer(sessB2.idToken) });
    assertTest('SEC-A6: Revoked session rejected by validate (401 session_revoked)', preRevoke.status === 200 && revokeB1.ok && postB1.status === 401 && postB1.body.error === 'session_revoked');
    assertTest('SEC-A6b: Revoked session rejected by other protected APIs (401)', postB1Profile.status === 401);
    assertTest('SEC-A6c: Sibling device session of same user unaffected by individual revocation', siblingB2.status === 200);

    // 1.7 Revoked administrator session
    const sessAdmin2 = await lanzarSession(adminU, { admin: true });
    const admPre = await jfetch(`${API}/api/admin/id/telemetry`, { headers: bearer(sessAdmin2.idToken) });
    await jfetch(`${API}/api/id/sessions/${sessAdmin2.sessionId}`, { method: 'DELETE', headers: bearer(sessAdmin2.idToken) });
    const admPost = await jfetch(`${API}/api/admin/id/telemetry`, { headers: bearer(sessAdmin2.idToken) });
    assertTest('SEC-A7: Revoked administrator session rejected on admin API (401 session_revoked)', admPre.status === 200 && admPost.status === 401 && admPost.body.error === 'session_revoked');

    // 1.8 Revoke-all
    const sessC1 = await lanzarSession(custC);
    const sessC2 = await lanzarSession(custC);
    const revAll = await jfetch(`${API}/api/id/sessions/revoke-all`, { method: 'POST', headers: bearer(sessC1.idToken) });
    const c1 = await jfetch(`${API}/api/id/session/validate`, { headers: bearer(sessC1.idToken) });
    const c2 = await jfetch(`${API}/api/id/session/validate`, { headers: bearer(sessC2.idToken) });
    assertTest('SEC-A8: Revoke-all invalidates every session and token for the user (401)', revAll.ok && c1.status === 401 && c2.status === 401, `${c1.body?.error}/${c2.body?.error}`);

    // 1.9 Suspended account
    const sessD = await lanzarSession(custD);
    await fsPatch(`users/${custD.uid}`, { status: 'suspended' });
    const dValidate = await jfetch(`${API}/api/id/session/validate`, { headers: bearer(sessD.idToken) });
    const dAuthorize = await jfetch(`${API}/authorize`, {
      method: 'POST', headers: JSON_H,
      body: JSON.stringify({ idToken: await emuSignIn(custD.email), client_id: 'portal', redirect_uri: PORTAL, state: 's', code_challenge: crypto.createHash('sha256').update('v').digest('base64url'), code_challenge_method: 'S256' })
    });
    assertTest('SEC-A9: Suspended account rejected on API (403 account_suspended) and cannot authorize', dValidate.status === 403 && dValidate.body.error === 'account_suspended' && dAuthorize.status === 403);

    // 1.10 Expired session (wait for backend revocation cache to lapse)
    const waitMs = Math.max(0, 31500 - (Date.now() - sessF.createdAt));
    if (waitMs > 0) { console.log(`    (waiting ${Math.ceil(waitMs / 1000)}s for server session-cache TTL to lapse...)`); await sleep(waitMs); }
    const fValidate = await jfetch(`${API}/api/id/session/validate`, { headers: bearer(sessF.idToken) });
    const fProfile = await jfetch(`${API}/api/id/profile`, { headers: bearer(sessF.idToken) });
    assertTest('SEC-A10: Expired session rejected (401 session_expired)', fValidate.status === 401 && fValidate.body.error === 'session_expired' && fProfile.status === 401, fValidate.body?.error);

    // =============================================================
    // SECTION 2: Real browser (Chrome) Portal behavior
    // =============================================================
    console.log('\n[SECTION 2] Portal browser behavior (real Chrome via CDP)');
    chromeProcess = spawn(CHROME_PATH, [
      `--remote-debugging-port=${CDP_PORT}`, '--headless=new', '--disable-gpu', '--no-sandbox',
      '--disable-extensions', '--window-size=1280,800', `--user-data-dir=${tmpProfileDir}`, 'about:blank'
    ]);
    await sleep(1500);
    const targets = await getCDPTargets();
    const mainTarget = targets.find((t) => t.type === 'page') || targets[0];
    mainPage = new CDPPage(mainTarget.webSocketDebuggerUrl);
    await mainPage.connect();

    const goto = async (url) => { await mainPage.send('Page.navigate', { url }); await sleep(400); };
    const gotoLogin = async (url = `${PORTAL}/`) => {
      await goto(url);
      await mainPage.waitFor(`Boolean(document.getElementById('btnSignInModal'))`, 15000);
    };
    // Reset Portal to a clean signed-out state
    const resetPortal = async () => {
      await goto(`${PORTAL}/`);
      await mainPage.waitFor(`document.readyState === 'complete'`, 10000);
      await mainPage.eval(`(async () => {
        try { sessionStorage.clear(); localStorage.clear(); } catch (_) {}
        try { const { auth } = await import('/src/firebase/auth.js'); await auth.signOut(); } catch (_) {}
      })()`);
      await gotoLogin();
    };
    // Complete a genuine LANZAR ID session in the Portal using the app's own Firebase module
    const injectSession = async (sess) => {
      await mainPage.eval(`(async () => {
        const m = await import('/src/firebase/auth.js');
        await m.signInWithCustomToken(${JSON.stringify(sess.customToken)});
      })()`);
    };
    const loginErrorText = () => mainPage.eval(`document.querySelector('.error-msg')?.innerText || ''`);
    const storedSessionId = () => mainPage.eval(`sessionStorage.getItem('lanzar_session_id')`);
    const fbUserUid = () => mainPage.eval(`(async () => { const { auth } = await import('/src/firebase/auth.js'); return auth.currentUser ? auth.currentUser.uid : null; })()`);
    // Status codes of non-preflight responses (204 = CORS preflight) recorded after index `from`
    const apiStatuses = (substr, from = 0) => recordedResponses.slice(from).filter((r) => r.url.includes(substr) && r.status !== 204).map((r) => r.status);
    const triggerRevalidation = () => mainPage.eval(`window.dispatchEvent(new Event('focus'))`);

    // 2.1 Direct navigation to protected routes while unauthenticated
    console.log('\n  -- Direct navigation / unauthenticated --');
    await resetPortal();
    const adminCallsBefore = recordedResponses.filter((r) => r.url.includes('/api/admin/')).length;
    const protectedRoutes = ['/admin', '/admin/identities', '/admin?preview=admin', '/admin/identities?preview=admin', '/billing', '/account'];
    let allLogin = true;
    for (const route of protectedRoutes) {
      await gotoLogin(`${PORTAL}${route}`);
      const hasAdminUi = await mainPage.eval(`Boolean(document.querySelector('.mc-rail-link') || document.querySelector('.portal-nav'))`);
      if (hasAdminUi) allLogin = false;
    }
    assertTest('SEC-B1: Direct navigation to protected & former preview-bypass routes shows login only (no Mission Control / customer UI)', allLogin);
    const adminCallsAfter = recordedResponses.filter((r) => r.url.includes('/api/admin/')).length;
    assertTest('SEC-B1b: Zero admin API requests issued while unauthenticated', adminCallsAfter === adminCallsBefore);

    // 2.2 Valid customer
    console.log('\n  -- Valid customer --');
    const bCust = await lanzarSession(custA);
    await injectSession(bCust);
    await mainPage.waitFor(`Boolean(document.querySelector('.portal-nav'))`, 15000);
    assertTest('SEC-B2: Valid customer reaches customer Portal', true);
    assertTest('SEC-B2b: Server-issued session_id persisted from validated session', (await storedSessionId()) === bCust.sessionId);
    assertTest('SEC-B2c: Customer sees no Mission Control UI', !(await mainPage.eval(`Boolean(document.querySelector('.mc-rail-link'))`)));

    // 2.3 Customer attempting administrator access
    await mainPage.eval(`(() => { history.pushState({}, '', '/admin/identities'); window.dispatchEvent(new PopStateEvent('popstate')); })()`);
    await sleep(800);
    const spaAdmin = await mainPage.eval(`({ rail: Boolean(document.querySelector('.mc-rail-link')), nav: Boolean(document.querySelector('.portal-nav')), path: location.pathname })`);
    assertTest('SEC-B3: Customer SPA navigation to /admin stays in customer app and is redirected', !spaAdmin.rail && spaAdmin.nav && spaAdmin.path === '/dashboard', spaAdmin.path);
    await goto(`${PORTAL}/admin/identities`);
    await mainPage.waitFor(`Boolean(document.querySelector('.portal-nav'))`, 15000);
    const fullAdmin = await mainPage.eval(`({ rail: Boolean(document.querySelector('.mc-rail-link')), path: location.pathname })`);
    assertTest('SEC-B3b: Customer direct (full-page) navigation to /admin/identities never shows Mission Control', !fullAdmin.rail && fullAdmin.path === '/dashboard', fullAdmin.path);
    const custApiCall = await mainPage.eval(`(async () => {
      const { auth } = await import('/src/firebase/auth.js');
      const t = await auth.currentUser.getIdToken();
      const out = [];
      for (const p of ['telemetry','users','audit-log','clients']) {
        const r = await fetch('http://localhost:4001/api/admin/id/' + p, { headers: { Authorization: 'Bearer ' + t } });
        out.push(r.status);
      }
      return out;
    })()`);
    assertTest('SEC-B3c: Customer browser token rejected by admin APIs (403)', custApiCall.every((s) => s === 403), custApiCall.join(','));

    // 2.4 Page refresh & restoration
    console.log('\n  -- Refresh / restoration --');
    await mainPage.send('Page.reload');
    await sleep(500);
    await mainPage.waitFor(`Boolean(document.querySelector('.portal-nav'))`, 15000);
    assertTest('SEC-B4: Page refresh restores authenticated customer session after server validation', true);
    assertTest('SEC-B4b: session_id still bound after refresh', (await storedSessionId()) === bCust.sessionId);

    // 2.5 Valid administrator + all decks
    console.log('\n  -- Valid administrator / Mission Control --');
    await resetPortal();
    const bAdmin = await lanzarSession(adminU, { admin: true });
    await injectSession(bAdmin);
    await mainPage.waitFor(`document.querySelectorAll('.mc-rail-link').length >= 10`, 15000);
    const railCount = await mainPage.eval(`document.querySelectorAll('.mc-rail-link').length`);
    assertTest('SEC-B5: Valid administrator reaches Mission Control (server-resolved)', railCount >= 10, `${railCount} navigation entries`);
    assertTest('SEC-B5b: Administrator session_id persisted', (await storedSessionId()) === bAdmin.sessionId);
    const exceptionsBefore = pageExceptions.length;
    const respStart = recordedResponses.length;
    const decks = ['/admin', '/admin/identities', '/admin/security', '/admin/apps', '/admin/orgs', '/admin/founders', '/admin/entitlements', '/admin/telemetry', '/admin/audit', '/admin/config'];
    for (const d of decks) {
      await mainPage.eval(`(() => { history.pushState({}, '', '${d}'); window.dispatchEvent(new PopStateEvent('popstate')); })()`);
      await sleep(900);
    }
    assertTest('SEC-B5c: All ten operational decks render without uncaught exceptions', pageExceptions.length === exceptionsBefore, pageExceptions.slice(exceptionsBefore).join(' | '));
    const deckApi = ['/api/admin/id/telemetry', '/api/admin/id/users', '/api/admin/id/clients', '/api/admin/id/audit-log'];
    const deckStatus = deckApi.map((p) => apiStatuses(p, respStart));
    assertTest('SEC-B5d: Deck data APIs called with genuine session and all succeeded (no 401/403)',
      deckStatus.every((arr) => arr.length > 0 && arr.every((s) => s === 200)), deckStatus.map((a) => a.join('/')).join(' | '));
    await goto(`${PORTAL}/admin/identities`);
    await mainPage.waitFor(`document.querySelectorAll('.mc-rail-link').length >= 10`, 15000);
    assertTest('SEC-B5e: Administrator direct navigation + refresh restores Mission Control', true);

    // 2.6 Revocation handling (admin: API-driven 401)
    console.log('\n  -- Revocation / expiry in the browser --');
    await resetPortal();
    const bAdminRev = await lanzarSession(adminU, { admin: true });
    await injectSession(bAdminRev);
    await mainPage.waitFor(`document.querySelectorAll('.mc-rail-link').length >= 10`, 15000);
    await jfetch(`${API}/api/id/sessions/${bAdminRev.sessionId}`, { method: 'DELETE', headers: bearer(bAdminRev.idToken) });
    await mainPage.eval(`(() => { history.pushState({}, '', '/admin/identities'); window.dispatchEvent(new PopStateEvent('popstate')); })()`);
    await mainPage.waitFor(`Boolean(document.getElementById('btnSignInModal'))`, 15000);
    assertTest('SEC-B6: Admin API 401 (revoked session) clears Portal auth state and returns to login', true);
    assertTest('SEC-B6b: Revoked-session message shown on login', (await loginErrorText()).includes('ended from another device'), await loginErrorText());
    assertTest('SEC-B6c: Stored session and Firebase user cleared', (await storedSessionId()) === null && (await fbUserUid()) === null);

    // 2.7 Revocation handling (customer: background validation)
    await resetPortal();
    const bI = await lanzarSession(custI);
    await injectSession(bI);
    await mainPage.waitFor(`Boolean(document.querySelector('.portal-nav'))`, 15000);
    await jfetch(`${API}/api/id/sessions/${bI.sessionId}`, { method: 'DELETE', headers: bearer(bI.idToken) });
    await triggerRevalidation();
    await mainPage.waitFor(`Boolean(document.getElementById('btnSignInModal'))`, 15000);
    assertTest('SEC-B7: Individually revoked customer session detected on revalidation; returned to login', (await loginErrorText()).includes('ended from another device') && (await storedSessionId()) === null && (await fbUserUid()) === null);

    // 2.8 Revoke-all
    await resetPortal();
    const bJ = await lanzarSession(custJ);
    await injectSession(bJ);
    await mainPage.waitFor(`Boolean(document.querySelector('.portal-nav'))`, 15000);
    await jfetch(`${API}/api/id/sessions/revoke-all`, { method: 'POST', headers: bearer(bJ.idToken) });
    await triggerRevalidation();
    await mainPage.waitFor(`Boolean(document.getElementById('btnSignInModal'))`, 15000);
    assertTest('SEC-B8: Revoke-all detected on revalidation; Portal auth state cleared with message', (await loginErrorText()).includes('Please sign in again') && (await storedSessionId()) === null && (await fbUserUid()) === null);

    // 2.9 Expired session
    await resetPortal();
    await injectSession(sessF);
    await mainPage.waitFor(`Boolean(document.getElementById('btnSignInModal')) && (document.querySelector('.error-msg')?.innerText || '').length > 0`, 15000);
    assertTest('SEC-B9: Expired session rejected on restoration; login shown with expiry message', (await loginErrorText()).includes('expired') && (await fbUserUid()) === null, await loginErrorText());

    // 2.10 Suspended / inactive accounts
    await resetPortal();
    await injectSession(sessD);
    await mainPage.waitFor(`(document.querySelector('.error-msg')?.innerText || '').length > 0`, 15000);
    await sleep(500);
    const susText = await loginErrorText();
    assertTest('SEC-B10: Suspended account denied with suspension message; no portal access', susText.includes('suspended') && !(await mainPage.eval(`Boolean(document.querySelector('.portal-nav'))`)), susText);

    await resetPortal();
    const sessE = await lanzarSession(custE);
    await fsPatch(`users/${custE.uid}`, { status: 'inactive' });
    await injectSession(sessE);
    await mainPage.waitFor(`document.body.innerText.includes('ACCESS DENIED')`, 15000);
    assertTest('SEC-B11: Inactive account shows Access Denied and is never auto-provisioned', !(await mainPage.eval(`Boolean(document.querySelector('.portal-nav'))`)));

    // 2.11 Firebase session without a LANZAR ID session
    await resetPortal();
    await mainPage.eval(`(async () => { const m = await import('/src/firebase/auth.js'); await m.signInWithEmail(${JSON.stringify(custG.email)}, ${JSON.stringify(PASSWORD)}); })()`);
    await mainPage.waitFor(`Boolean(document.getElementById('btnSignInModal')) && (document.querySelector('.error-msg')?.innerText || '').length > 0`, 15000);
    assertTest('SEC-B12: Firebase-only sign-in (no LANZAR ID session claim) rejected; Portal requires LANZAR ID', (await loginErrorText()).includes('LANZAR ID session is required') && (await fbUserUid()) === null);

    // 2.12 Logout
    console.log('\n  -- Logout --');
    await resetPortal();
    const bH = await lanzarSession(custH);
    await injectSession(bH);
    await mainPage.waitFor(`Boolean(document.querySelector('.portal-nav'))`, 15000);
    assertTest('SEC-B13-pre: Logout candidate session is active', (await storedSessionId()) === bH.sessionId);
    await mainPage.eval(`document.querySelector('.nav-button.logout').click()`);
    for (let i = 0; i < 100 && !recordedUrls.some((u) => u.includes('logout=true')); i++) await sleep(200);
    assertTest('SEC-B13-hub: Logout redirected through Auth Hub (logout=true)', recordedUrls.some((u) => u.includes('logout=true')));
    await sleep(1500);
    await mainPage.waitFor(`location.port === '5173' && document.readyState === 'complete' && Boolean(document.getElementById('btnSignInModal'))`, 20000);
    await sleep(800);
    const sessDoc = await fsGet(`users/${custH.uid}/sessions/${bH.sessionId}`);
    assertTest('SEC-B13: Logout revokes the LANZAR ID session server-side', sessDoc.ok && sessDoc.body?.fields?.revoked?.booleanValue === true);
    const replay = await jfetch(`${API}/api/id/session/validate`, { headers: bearer(bH.idToken) });
    assertTest('SEC-B13b: Logged-out session token rejected by backend (401)', replay.status === 401);
    assertTest('SEC-B13c: Portal storage and Firebase user cleared after logout', (await storedSessionId()) === null && (await fbUserUid()) === null);

    // 2.13 Egress
    const external = recordedUrls.filter((url) => {
      try {
        const u = new URL(url);
        if (['data:', 'blob:', 'about:', 'chrome:', 'devtools:'].includes(u.protocol)) return false;
        return !['localhost', '127.0.0.1'].includes(u.hostname);
      } catch (_) { return false; }
    });
    assertTest('SEC-B14: Zero external network requests across all browser tests', external.length === 0, `${external.length} external${external.length ? ': ' + external.slice(0, 3).join(', ') : ''}`);
    const srcs = await Promise.all(['/src/App.jsx', '/src/admin/decks/adminApi.js', '/src/session/sessionManager.js'].map((p) => fetch(PORTAL + p).then((r) => r.text())));
    assertTest('SEC-B15: Served Portal sources contain no mock admin token or bypass', srcs.every((s) => !s.includes('mock_admin')) && srcs.every((s) => s.length > 100));

    // =============================================================
    // SECTION 3: Cleanup
    // =============================================================
    console.log('\n[SECTION 3] Test data cleanup');
    const uids = new Set(createdUsers.map((u) => u.uid));
    for (const u of createdUsers) {
      for (const s of await fsList(`users/${u.uid}/sessions`)) await fsDelete(s.name.split('/documents/')[1]);
      for (const col of ['users', 'customers', 'admins', 'mfa_factors']) await fsDelete(`${col}/${u.uid}`);
      await jfetch(`http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/projects/demo-lanzar-dev/accounts:delete`, {
        method: 'POST', headers: { ...JSON_H, ...OWNER }, body: JSON.stringify({ localId: u.uid })
      });
    }
    let purgedLogs = 0;
    for (const d of await fsList('security_logs')) {
      const f = d.fields || {};
      const refs = [f.actorUid?.stringValue, f.targetUid?.stringValue];
      if (refs.some((r) => r && uids.has(r))) { await fsDelete(d.name.split('/documents/')[1]); purgedLogs++; }
    }
    const leftover = await jfetch(`${EMU_AUTH}/accounts:lookup?${KEY}`, { method: 'POST', headers: JSON_H, body: JSON.stringify({ idToken: custA.idToken }) });
    assertTest('CLEANUP: Test accounts, sessions, profile docs and audit entries purged from emulators', leftover.status !== 200, `${purgedLogs} audit entries purged`);

    console.log('\n================================================================');
    console.log(`  PHASE G.3 SESSION & APPLICATION SECURITY RESULTS: ${passCount} PASSED, ${failCount} FAILED`);
    console.log('================================================================\n');
    if (failCount > 0) process.exitCode = 1;
  } finally {
    console.log('[TEARDOWN] Stopping test browser and development services...');
    if (mainPage) mainPage.close();
    for (const p of [chromeProcess, portalProcess, authHubProcess, backendProcess, emulatorProcess]) {
      if (p) { try { spawn('taskkill', ['/PID', p.pid.toString(), '/T', '/F']); } catch (_) {} }
    }
    stopListeningPorts([PORTAL_PORT, AUTH_HUB_PORT, BACKEND_PORT, CDP_PORT]);
    try { fs.rmSync(tmpProfileDir, { recursive: true, force: true }); } catch (_) {}
    setTimeout(() => process.exit(process.exitCode || 0), 1000);
  }
}

run().catch((err) => {
  console.error('\n❌ [TEST FATAL ERROR]', err);
  process.exit(1);
});
