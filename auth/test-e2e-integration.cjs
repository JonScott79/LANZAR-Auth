// test-e2e-integration.cjs
// Automated End-to-End Functional Integration Verification Suite (Phase E)
// Validates complete workflow: PKCE authorization, code exchange, session management,
// TOTP/MFA lifecycle, recovery codes, profile updates, and popup/postMessage origin gating.

const http = require('http');
const crypto = require('crypto');
const assert = require('assert');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function recordTest(id, desc, passed, errDetail = null) {
  totalTests++;
  if (passed) {
    passedTests++;
    console.log(`  ✓ [PASS] ${id}: ${desc}`);
  } else {
    failedTests++;
    console.error(`  ✗ [FAIL] ${id}: ${desc}`);
    if (errDetail) console.error(`     Details: ${errDetail}`);
  }
}

// ==========================================
// In-Memory High-Fidelity Mock Firestore & Auth Admin
// ==========================================
class MockFirestore {
  constructor() {
    this.store = new Map();
  }

  _key(path) {
    return path.replace(/\/+/g, '/').replace(/^\/|\/$/g, '');
  }

  collection(colName) {
    return new MockCollectionReference(this, colName);
  }

  doc(docPath) {
    return new MockDocumentReference(this, docPath);
  }

  batch() {
    return new MockBatch(this);
  }

  async runTransaction(updateFn) {
    const tx = new MockTransaction(this);
    return await updateFn(tx);
  }
}

class MockBatch {
  constructor(db) {
    this.db = db;
    this.ops = [];
  }
  update(ref, data) {
    this.ops.push(() => ref.update(data));
  }
  async commit() {
    for (const op of this.ops) await op();
  }
}

class MockTransaction {
  constructor(db) {
    this.db = db;
  }
  async get(ref) {
    return await ref.get();
  }
  set(ref, data, opts) {
    ref.set(data, opts);
  }
  update(ref, data) {
    ref.update(data);
  }
  delete(ref) {
    ref.delete();
  }
}

class MockCollectionReference {
  constructor(db, path) {
    this.db = db;
    this.path = path;
  }

  doc(id) {
    return new MockDocumentReference(this.db, `${this.path}/${id}`);
  }

  where(field, op, val) {
    return new MockQuery(this.db, this.path, [{ field, op, val }]);
  }

  orderBy(field, dir = 'asc') {
    return new MockQuery(this.db, this.path, []);
  }

  limit(n) {
    return new MockQuery(this.db, this.path, []).limit(n);
  }

  async get() {
    return new MockQuery(this.db, this.path, []).get();
  }
}

class MockQuery {
  constructor(db, path, conditions) {
    this.db = db;
    this.path = path;
    this.conditions = conditions;
    this._limit = null;
  }

  where(field, op, val) {
    return new MockQuery(this.db, this.path, [...this.conditions, { field, op, val }]);
  }

  limit(n) {
    this._limit = n;
    return this;
  }

  orderBy(field, dir = 'asc') {
    return this;
  }

  async get() {
    let docs = [];
    const prefix = `${this.db._key(this.path)}/`;
    for (const [key, data] of this.db.store.entries()) {
      if (key.startsWith(prefix)) {
        const sub = key.slice(prefix.length);
        if (!sub.includes('/')) {
          let match = true;
          for (const cond of this.conditions) {
            if (cond.op === '==' && data[cond.field] !== cond.val) {
              match = false;
              break;
            }
          }
          if (match) {
            docs.push({
              id: sub,
              exists: true,
              data: () => ({ ...data }),
              ref: new MockDocumentReference(this.db, key)
            });
          }
        }
      }
    }
    if (this._limit && docs.length > this._limit) {
      docs = docs.slice(0, this._limit);
    }
    return {
      docs,
      empty: docs.length === 0,
      size: docs.length,
      forEach(fn) {
        docs.forEach(fn);
      }
    };
  }
}

class MockDocumentReference {
  constructor(db, path) {
    this.db = db;
    this.path = db._key(path);
    this.id = this.path.split('/').pop();
  }

  collection(subCol) {
    return new MockCollectionReference(this.db, `${this.path}/${subCol}`);
  }

  async get() {
    const data = this.db.store.get(this.path);
    return {
      id: this.id,
      exists: Boolean(data),
      data: () => (data ? { ...data } : undefined),
      ref: this
    };
  }

  async set(data, options = {}) {
    let merged = options.merge && this.db.store.has(this.path) ? { ...this.db.store.get(this.path) } : {};
    for (const [k, v] of Object.entries(data)) {
      if (v && typeof v === 'object' && v.constructor && v.constructor.name.includes('NumericIncrement')) {
        const inc = v.operand !== undefined ? v.operand : 1;
        merged[k] = (typeof merged[k] === 'number' ? merged[k] : 0) + inc;
      } else if (v && typeof v === 'object' && v.constructor && v.constructor.name.includes('ServerTimestamp')) {
        merged[k] = new Date().toISOString();
      } else {
        merged[k] = v;
      }
    }
    this.db.store.set(this.path, merged);
  }

  async update(data) {
    const existing = this.db.store.get(this.path);
    if (!existing) throw new Error(`Document ${this.path} does not exist`);
    this.db.store.set(this.path, { ...existing, ...data });
  }

  async delete() {
    this.db.store.delete(this.path);
  }
}

class MockAuthAdmin {
  constructor() {
    this.users = new Map();
    this.revokedTokens = new Set();
    this.customTokens = new Map();
  }

  async getUser(uid) {
    const u = this.users.get(uid);
    if (!u) {
      const err = new Error('User not found');
      err.code = 'auth/user-not-found';
      throw err;
    }
    return u;
  }

  async updateUser(uid, updates) {
    const u = this.users.get(uid) || { uid };
    this.users.set(uid, { ...u, ...updates });
  }

  async revokeRefreshTokens(uid) {
    // Mock no-op for refresh token revocation
    return;
  }

  async verifyIdToken(token, checkRevoked = false) {
    if (this.revokedTokens.has(token)) {
      const err = new Error('Token revoked');
      err.code = 'auth/id-token-revoked';
      throw err;
    }
    try {
      return JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
    } catch (e) {
      throw new Error('Invalid token format');
    }
  }

  async createCustomToken(uid, claims = {}) {
    const token = `ctok_${uid}_${crypto.randomBytes(8).toString('hex')}`;
    this.customTokens.set(token, { uid, ...claims });
    return token;
  }
}

function mintMockToken(payload) {
  const full = {
    uid: payload.uid || 'usr_test_cadet',
    email: payload.email || 'cadet@lanzar.me',
    name: payload.name || 'Test Cadet',
    auth_time: payload.auth_time || Math.floor(Date.now() / 1000),
    exp: payload.exp || Math.floor(Date.now() / 1000) + 3600,
    ...payload
  };
  return Buffer.from(JSON.stringify(full)).toString('base64');
}

// ==========================================
// HTTP Request Helper
// ==========================================
async function fetchJson(baseUrl, path, options = {}) {
  const url = `${baseUrl}${path}`;
  const res = await fetch(url, {
    method: options.method || 'GET',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    },
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  let data = null;
  try {
    data = await res.json();
  } catch (e) {}
  return {
    status: res.status,
    headers: Object.fromEntries(res.headers.entries()),
    data
  };
}

// ==========================================
// Main E2E Integration Test Runner
// ==========================================
async function runE2EIntegrationTests() {
  console.log('\n======================================================');
  console.log('LANZAR ID — End-to-End Integration Verification Suite');
  console.log('Target: Full Authentication Flow, Session & MFA Lifecycle');
  console.log('Timestamp: ' + new Date().toISOString());
  console.log('======================================================\n');

  const { createApp } = require('./auth-backend/app');
  const { bootstrap } = require('./auth-backend/config/bootstrap');
  const {
    LanzarAuthModal,
    LanzarAuth,
    generatePkcePair,
    buildAuthorizeUrl,
    exchangeCodeForSession,
    sanitizeContinuationUrl,
    PRODUCTION_CONFIG,
    STAGING_CONFIG
  } = await import('./src/sdk/lanzar-auth-modal.js');

  const db = new MockFirestore();
  const authAdmin = new MockAuthAdmin();

  const TEST_ENV = {
    APP_ENV: 'test',
    FIREBASE_PROJECT_ID: 'demo-lanzar-test',
    FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099',
    FIRESTORE_EMULATOR_HOST: '127.0.0.1:8080',
    SESSION_SIGNING_SECRET: 'test_session_secret_at_least_32_bytes_long_12345678',
    FEATURE_STRIPE: 'disabled'
  };
  const config = bootstrap(TEST_ENV);
  const { app } = createApp({ config, db, authAdmin });

  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const testUid = 'usr_alice_e2e';
    const testEmail = 'alice.cadet@lanzar.me';
    authAdmin.users.set(testUid, {
      uid: testUid,
      email: testEmail,
      displayName: 'Alice Cadet',
      emailVerified: true
    });
    await db.collection('users').doc(testUid).set({
      uid: testUid,
      displayName: 'Alice Cadet',
      email: testEmail,
      status: 'active',
      tokenVersion: 1,
      createdAt: new Date().toISOString()
    });

    const aliceToken = mintMockToken({ uid: testUid, email: testEmail, name: 'Alice Cadet' });

    // ----------------------------------------------------
    // 1. Client Authorization Initiation & PKCE Challenge
    // ----------------------------------------------------
    console.log('--- 1. Client Authorization Initiation & PKCE Generation ---');
    const pkce = await generatePkcePair();
    const isVerifierValid = pkce.codeVerifier.length === 64 && /^[A-Za-z0-9\-._~]+$/.test(pkce.codeVerifier);
    const isChallengeValid = Boolean(pkce.codeChallenge && pkce.codeChallengeMethod === 'S256');
    recordTest('E2E-01', 'Client SDK generates cryptographic PKCE pair with S256 challenge', isVerifierValid && isChallengeValid);

    const clientRedirectUri = 'https://portal.lanzar.me/auth/callback';
    const authUrl = buildAuthorizeUrl({
      clientId: 'portal',
      redirectUri: clientRedirectUri,
      codeChallenge: pkce.codeChallenge,
      codeChallengeMethod: 'S256',
      state: 'st_e2e_state_123'
    }, PRODUCTION_CONFIG);

    const parsedAuthUrl = new URL(authUrl);
    const isUrlWellFormed = 
      parsedAuthUrl.origin === 'https://auth.lanzar.me' &&
      parsedAuthUrl.searchParams.get('client_id') === 'portal' &&
      parsedAuthUrl.searchParams.get('code_challenge') === pkce.codeChallenge &&
      parsedAuthUrl.searchParams.get('code_challenge_method') === 'S256' &&
      !authUrl.includes(pkce.codeVerifier); // Verifier MUST NOT be in URL
    recordTest('E2E-02', 'Authorize URL encapsulates S256 challenge; verifier remains isolated on client', isUrlWellFormed);

    // ----------------------------------------------------
    // 2. Auth Hub Authorization & Code Issuance
    // ----------------------------------------------------
    console.log('\n--- 2. Auth Hub Authorization Endpoint (/authorize) ---');
    const authRes = await fetchJson(baseUrl, '/authorize', {
      method: 'POST',
      body: {
        idToken: aliceToken,
        client_id: 'portal',
        redirect_uri: clientRedirectUri,
        state: 'st_e2e_state_123',
        code_challenge: pkce.codeChallenge,
        code_challenge_method: 'S256'
      }
    });

    const isCodeIssued = authRes.status === 200 && Boolean(authRes.data && authRes.data.code);
    recordTest('E2E-03', 'Auth Hub issues authorization code for valid S256 PKCE request', isCodeIssued);
    const authCode = authRes.data?.code;

    // ----------------------------------------------------
    // 3. PKCE Code Exchange & Session Minting
    // ----------------------------------------------------
    console.log('\n--- 3. Code Exchange Endpoint (/exchange) ---');
    const exchangeRes = await fetchJson(baseUrl, '/exchange', {
      method: 'POST',
      headers: { 'User-Agent': 'E2E-Device-Agent-1' },
      body: {
        code: authCode,
        client_id: 'portal',
        redirect_uri: clientRedirectUri,
        code_verifier: pkce.codeVerifier
      }
    });

    const isExchanged = 
      exchangeRes.status === 200 &&
      Boolean(exchangeRes.data?.custom_token) &&
      Boolean(exchangeRes.data?.session_id);
    recordTest('E2E-04', 'Token exchange verifies code_verifier and mints custom token with session_id', isExchanged);
    const device1SessionId = exchangeRes.data?.session_id;

    // ----------------------------------------------------
    // 4. PKCE Single-Use Replay Protection & CAS Consumption
    // ----------------------------------------------------
    console.log('\n--- 4. Single-Use Replay & Tamper Resistance ---');
    const replayRes = await fetchJson(baseUrl, '/exchange', {
      method: 'POST',
      body: {
        code: authCode,
        client_id: 'portal',
        redirect_uri: clientRedirectUri,
        code_verifier: pkce.codeVerifier
      }
    });
    recordTest('E2E-05', 'Replay of consumed authorization code is rejected with HTTP 400 invalid_grant', replayRes.status === 400 && replayRes.data?.error === 'invalid_grant');

    // ----------------------------------------------------
    // 5. TOTP MFA Enrollment & Verification Lifecycle
    // ----------------------------------------------------
    console.log('\n--- 5. Universal RFC 6238 TOTP Multi-Factor Authentication ---');
    const totpSetupRes = await fetchJson(baseUrl, '/mfa/totp/setup', {
      method: 'POST',
      body: { idToken: aliceToken }
    });

    const isTotpSetupOk = totpSetupRes.status === 200 && Boolean(totpSetupRes.data?.secret);
    recordTest('E2E-06', 'POST /mfa/totp/setup generates RFC 6238 Base32 secret', isTotpSetupOk);
    const totpSecret = totpSetupRes.data?.secret;

    // Generate valid TOTP code
    const { generateTOTP } = require('./auth-backend/mfaService');
    const validTotpCode = generateTOTP(totpSecret);

    const totpEnableRes = await fetchJson(baseUrl, '/mfa/totp/enable', {
      method: 'POST',
      body: {
        idToken: aliceToken,
        secret: totpSecret,
        code: validTotpCode
      }
    });

    const isTotpEnabled = 
      totpEnableRes.status === 200 &&
      totpEnableRes.data?.success === true &&
      Array.isArray(totpEnableRes.data?.recoveryCodes) &&
      totpEnableRes.data.recoveryCodes.length === 8;
    recordTest('E2E-07', 'POST /mfa/totp/enable activates factor and returns 8 single-use recovery codes', isTotpEnabled);
    const recoveryCodes = totpEnableRes.data?.recoveryCodes || [];

    // Verify secret is encrypted in Firestore with AES-256-GCM
    const mfaDoc = await db.collection('mfa_factors').doc(testUid).get();
    const mfaData = mfaDoc.data();
    const isEncrypted = 
      mfaData &&
      mfaData.totpSecret &&
      Boolean(mfaData.totpSecret.encryptedSecret && mfaData.totpSecret.iv && mfaData.totpSecret.tag) &&
      mfaData.totpSecret.encryptedSecret !== totpSecret;
    recordTest('E2E-08', 'TOTP secret is stored encrypted under AES-256-GCM in Firestore', isEncrypted);

    // ----------------------------------------------------
    // 6. Recovery Code Verification & Single-Use Enforcement
    // ----------------------------------------------------
    console.log('\n--- 6. Recovery Code Verification & Single-Use Enforcement ---');
    // Request challenge session
    const mfaRequiredRes = await fetchJson(baseUrl, '/authorize', {
      method: 'POST',
      body: {
        idToken: aliceToken,
        client_id: 'portal',
        redirect_uri: clientRedirectUri,
        state: 'st_mfa_req',
        code_challenge: pkce.codeChallenge,
        code_challenge_method: 'S256'
      }
    });

    const mfaSession = mfaRequiredRes.data?.mfa_session;
    const isMfaChallenged = mfaRequiredRes.status === 403 && mfaRequiredRes.data?.mfa_required === true && Boolean(mfaSession);
    recordTest('E2E-09', 'User with active MFA factor receives HTTP 403 mfa_required and signed challenge session', isMfaChallenged);

    // Consume first recovery code
    const firstRecoveryCode = recoveryCodes[0];
    const verifyRecoveryRes = await fetchJson(baseUrl, '/mfa/verify', {
      method: 'POST',
      body: {
        mfaSession,
        code: firstRecoveryCode,
        method: 'recovery'
      }
    });
    recordTest('E2E-10', 'First recovery code validates successfully and mints signed mfaProof', verifyRecoveryRes.status === 200 && Boolean(verifyRecoveryRes.data?.mfaProof));

    // Replay the consumed recovery code
    const replayRecoveryRes = await fetchJson(baseUrl, '/mfa/verify', {
      method: 'POST',
      body: {
        mfaSession,
        code: firstRecoveryCode,
        method: 'recovery'
      }
    });
    recordTest('E2E-11', 'Replay of consumed recovery code is rejected with HTTP 401 invalid_code', replayRecoveryRes.status === 401 && replayRecoveryRes.data?.error === 'invalid_code');

    // ----------------------------------------------------
    // 7. Session Registry & Device Scoping
    // ----------------------------------------------------
    console.log('\n--- 7. Session Registry & Device Scoping ---');
    // List active sessions
    const sessionsRes = await fetchJson(baseUrl, '/api/id/sessions', {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${aliceToken}` }
    });
    const hasDevice1 = sessionsRes.status === 200 && sessionsRes.data?.sessions?.some(s => s.sessionId === device1SessionId);
    recordTest('E2E-12', 'GET /api/id/sessions returns active device session records', hasDevice1);

    // Create Device 2 session
    const pkce2 = await generatePkcePair();
    const authRes2 = await fetchJson(baseUrl, '/authorize', {
      method: 'POST',
      body: {
        idToken: aliceToken,
        client_id: 'portal',
        redirect_uri: clientRedirectUri,
        state: 'st_dev2',
        code_challenge: pkce2.codeChallenge,
        code_challenge_method: 'S256',
        mfa_proof: verifyRecoveryRes.data.mfaProof
      }
    });
    const exchangeRes2 = await fetchJson(baseUrl, '/exchange', {
      method: 'POST',
      headers: { 'User-Agent': 'E2E-Device-Agent-2' },
      body: {
        code: authRes2.data.code,
        client_id: 'portal',
        redirect_uri: clientRedirectUri,
        code_verifier: pkce2.codeVerifier
      }
    });
    const device2SessionId = exchangeRes2.data?.session_id;

    // ----------------------------------------------------
    // 8. Individual Session Revocation
    // ----------------------------------------------------
    console.log('\n--- 8. Individual Session Revocation ---');
    const revokeDev1Res = await fetchJson(baseUrl, `/api/id/sessions/${device1SessionId}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${aliceToken}` }
    });
    recordTest('E2E-13', 'DELETE /api/id/sessions/:id successfully marks Device 1 session revoked', revokeDev1Res.status === 200 && revokeDev1Res.data?.success === true);

    const dev1Doc = await db.collection('users').doc(testUid).collection('sessions').doc(device1SessionId).get();
    const dev2Doc = await db.collection('users').doc(testUid).collection('sessions').doc(device2SessionId).get();
    const isDev1RevokedAndDev2Active = dev1Doc.data()?.revoked === true && dev2Doc.data()?.revoked === false;
    recordTest('E2E-14', 'Device 1 is revoked while Device 2 remains independently active', isDev1RevokedAndDev2Active);

    // ----------------------------------------------------
    // 9. Global Revocation ("Sign Out Everywhere")
    // ----------------------------------------------------
    console.log('\n--- 9. Global Session Revocation (Sign Out Everywhere) ---');
    const revokeAllRes = await fetchJson(baseUrl, '/api/id/sessions/revoke-all', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${aliceToken}` }
    });
    recordTest('E2E-15', 'POST /api/id/sessions/revoke-all globally invalidates all sessions', revokeAllRes.status === 200 && revokeAllRes.data?.success === true);

    const updatedUserDoc = await db.collection('users').doc(testUid).get();
    recordTest('E2E-16', 'Global revocation advances user tokenVersion in Firestore', updatedUserDoc.data()?.tokenVersion === 2);

    // ----------------------------------------------------
    // 10. Profile Retrieval & Allowlisted Updates
    // ----------------------------------------------------
    console.log('\n--- 10. Profile Retrieval & Anti-Tampering Updates ---');
    const profileRes = await fetchJson(baseUrl, '/api/id/profile', {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${aliceToken}` }
    });
    recordTest('E2E-17', 'GET /api/id/profile returns profile data with MFA factor flags', profileRes.status === 200 && profileRes.data?.mfa?.enabled === true);

    const updateProfileRes = await fetchJson(baseUrl, '/api/id/profile', {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${aliceToken}` },
      body: {
        displayName: 'Alice Security Lead',
        bio: 'Leading cybersecurity and architecture.',
        avatarUrl: 'https://lanzar.me/assets/alice.png',
        role: 'admin', // Attack: Attempt client privilege escalation
        status: 'suspended' // Attack: Attempt client status tampering
      }
    });

    const updatedProfile = updateProfileRes.data;
    const isUpdatedCorrectly = 
      updateProfileRes.status === 200 &&
      updatedProfile?.displayName === 'Alice Security Lead' &&
      updatedProfile?.bio === 'Leading cybersecurity and architecture.' &&
      updatedProfile?.avatarUrl === 'https://lanzar.me/assets/alice.png' &&
      updatedProfile?.role === 'customer' && // Stripped: escalation blocked
      updatedProfile?.status === 'active';   // Stripped: tampering blocked
    recordTest('E2E-18', 'PUT /api/id/profile updates allowlisted fields and strips privilege escalation', isUpdatedCorrectly);

    // ----------------------------------------------------
    // 11. Popup / PostMessage Exact-Origin Handshake & Verifier Isolation
    // ----------------------------------------------------
    console.log('\n--- 11. Client SDK Modal/Popup Handshake & Origin Verification ---');
    const modal = new LanzarAuthModal();
    let authEventFired = false;
    let authEventDetail = null;

    modal._codeVerifier = pkce.codeVerifier;
    modal.dispatchEvent = (event) => {
      if (event.type === 'lanzar:authenticated') {
        authEventFired = true;
        authEventDetail = event.detail;
      }
    };

    // Attacker spoofing postMessage from unapproved origin
    modal._onMessage({
      origin: 'https://evil-hacker.com',
      data: { type: 'lanzar:authenticated', payload: { code: 'spoofed_code' } }
    });
    recordTest('E2E-19', 'postMessage from unapproved origin (evil-hacker.com) is strictly discarded', !authEventFired);

    // Legitimate postMessage from Auth Hub
    modal._onMessage({
      origin: modal._config.authHubUrl,
      data: {
        type: 'lanzar:authenticated',
        payload: { code: 'legit_auth_code_789', state: 'st_e2e_state_123' }
      }
    });

    const isHandshakeClean = 
      authEventFired &&
      authEventDetail?.code === 'legit_auth_code_789' &&
      authEventDetail?.codeVerifier === pkce.codeVerifier;
    recordTest('E2E-20', 'Legitimate Auth Hub postMessage dispatches authenticated event with original codeVerifier', isHandshakeClean);

  } finally {
    server.closeAllConnections?.();
    server.close();
  }

  // ----------------------------------------------------
  // Summary
  // ----------------------------------------------------
  console.log('\n======================================================');
  console.log('E2E INTEGRATION TEST SUMMARY');
  console.log(`Total Executed: ${totalTests}`);
  console.log(`Passed:         ${passedTests}`);
  console.log(`Failed:         ${failedTests}`);
  console.log(`Success Rate:   ${((passedTests / totalTests) * 100).toFixed(1)}%`);
  console.log('======================================================\n');

  if (failedTests > 0) {
    process.exit(1);
  }
}

runE2EIntegrationTests().catch(err => {
  console.error('[FATAL E2E ERROR]', err);
  process.exit(1);
});
