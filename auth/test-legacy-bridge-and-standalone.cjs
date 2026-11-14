// test-legacy-bridge-and-standalone.cjs
// Targeted verification for legacy Pythos scrypt credential bridging,
// standalone auth_hub session binding, and Central SSO <-> /api/id/* compatibility.

process.env.MFA_HMAC_SECRET = 'test_mfa_hmac_secret_at_least_32_bytes_long_1234567890';
process.env.SESSION_SIGNING_SECRET = 'prod_session_signing_secret_at_least_32_bytes_long_123456';

const http = require('http');
const crypto = require('crypto');
const util = require('util');
const { bootstrap } = require('./auth-backend/config/bootstrap');
const { createApp } = require('./auth-backend/app');
const { resetRateLimits } = require('./auth-backend/middleware/rateLimiter');

const scryptAsync = util.promisify(crypto.scrypt);

class MockFirestore {
  constructor() {
    this.store = new Map();
    this.txQueue = Promise.resolve();
  }

  _key(path) {
    return path.replace(/\/+/g, '/').replace(/^\/|\/$/g, '');
  }

  collection(colName) {
    return new MockCollectionReference(this, colName);
  }

  collectionGroup(colName) {
    return new MockCollectionGroupQuery(this, colName, []);
  }

  async runTransaction(updateFn) {
    return new Promise((resolve, reject) => {
      this.txQueue = this.txQueue.then(async () => {
        try {
          const tx = new MockTransaction(this);
          const res = await updateFn(tx);
          resolve(res);
        } catch (e) {
          reject(e);
        }
      });
    });
  }

  batch() {
    return new MockBatch(this);
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
    return new MockQuery(this.db, this.path, [], { field, dir });
  }

  limit(n) {
    return new MockQuery(this.db, this.path, [], null, n);
  }
}

class MockQuery {
  constructor(db, path, conditions = [], order = null, limitCount = null) {
    this.db = db;
    this.path = path;
    this.conditions = conditions;
    this.order = order;
    this.limitCount = limitCount;
  }

  where(field, op, val) {
    return new MockQuery(this.db, this.path, [...this.conditions, { field, op, val }], this.order, this.limitCount);
  }

  orderBy(field, dir = 'asc') {
    return new MockQuery(this.db, this.path, this.conditions, { field, dir }, this.limitCount);
  }

  limit(n) {
    return new MockQuery(this.db, this.path, this.conditions, this.order, n);
  }

  async get() {
    let docs = [];
    const prefix = `${this.db._key(this.path)}/`;
    for (const [key, data] of this.db.store.entries()) {
      if (key.startsWith(prefix)) {
        const sub = key.slice(prefix.length);
        if (!sub.includes('/')) {
          const match = this.conditions.every(c => c.op === '==' && data[c.field] === c.val);
          if (match) {
            docs.push({
              id: sub,
              data: () => ({ ...data }),
              ref: new MockDocumentReference(this.db, key)
            });
          }
        }
      }
    }
    if (this.order) {
      const { field, dir } = this.order;
      docs.sort((a, b) => {
        const va = a.data()[field];
        const vb = b.data()[field];
        if (va === vb) return 0;
        const cmp = va < vb ? -1 : 1;
        return dir === 'desc' ? -cmp : cmp;
      });
    }
    if (typeof this.limitCount === 'number') {
      docs = docs.slice(0, this.limitCount);
    }
    return {
      empty: docs.length === 0,
      size: docs.length,
      docs,
      forEach: (cb) => docs.forEach(cb)
    };
  }
}

class MockCollectionGroupQuery {
  constructor(db, colName, conditions = []) {
    this.db = db;
    this.colName = colName;
    this.conditions = conditions;
  }

  where(field, op, val) {
    return new MockCollectionGroupQuery(this.db, this.colName, [...this.conditions, { field, op, val }]);
  }

  limit() {
    return this;
  }

  async get() {
    const docs = [];
    const segment = `/${this.colName}/`;
    for (const [key, data] of this.db.store.entries()) {
      if (key.includes(segment)) {
        const match = this.conditions.every(c => c.op === '==' && data[c.field] === c.val);
        if (match) {
          docs.push({
            id: key.split('/').pop(),
            data: () => ({ ...data }),
            ref: new MockDocumentReference(this.db, key)
          });
        }
      }
    }
    return { empty: docs.length === 0, size: docs.length, docs, forEach: (cb) => docs.forEach(cb) };
  }
}

class MockDocumentReference {
  constructor(db, path) {
    this.db = db;
    this.path = db._key(path);
  }

  collection(subColName) {
    return new MockCollectionReference(this.db, `${this.path}/${subColName}`);
  }

  async get() {
    const data = this.db.store.get(this.path);
    return {
      exists: data !== undefined,
      data: () => (data !== undefined ? { ...data } : undefined),
      id: this.path.split('/').pop()
    };
  }

  async set(data, options = {}) {
    if (options.merge && this.db.store.has(this.path)) {
      this.db.store.set(this.path, { ...this.db.store.get(this.path), ...data });
    } else {
      this.db.store.set(this.path, { ...data });
    }
  }

  async update(data) {
    const current = this.db.store.get(this.path);
    if (!current) throw new Error(`Document not found for update: ${this.path}`);
    this.db.store.set(this.path, { ...current, ...data });
  }
}

class MockTransaction {
  constructor(db) {
    this.db = db;
  }
  async get(docRef) {
    return await docRef.get();
  }
  set(docRef, data, options = {}) {
    if (options.merge && this.db.store.has(docRef.path)) {
      this.db.store.set(docRef.path, { ...this.db.store.get(docRef.path), ...data });
    } else {
      this.db.store.set(docRef.path, { ...data });
    }
  }
  update(docRef, data) {
    const current = this.db.store.get(docRef.path);
    if (!current) throw new Error(`Document not found for update: ${docRef.path}`);
    this.db.store.set(docRef.path, { ...current, ...data });
  }
}

class MockBatch {
  constructor(db) {
    this.operations = [];
  }
  update(docRef, data) {
    this.operations.push(() => docRef.update(data));
  }
  async commit() {
    for (const op of this.operations) {
      await op();
    }
  }
}

class MockAuthAdmin {
  constructor() {
    this.usersByUid = new Map();
    this.usersByEmail = new Map();
    this.customTokenClaims = new Map();
    this.revokedUids = new Set();
  }

  seedUser(user) {
    const record = { disabled: false, emailVerified: false, ...user };
    this.usersByUid.set(record.uid, record);
    if (record.email) {
      this.usersByEmail.set(record.email.trim().toLowerCase(), record);
    }
    return record;
  }

  async getUserByEmail(email) {
    const u = this.usersByEmail.get(String(email).trim().toLowerCase());
    if (!u) {
      const err = new Error('User not found');
      err.code = 'auth/user-not-found';
      throw err;
    }
    return { ...u };
  }

  async getUser(uid) {
    const u = this.usersByUid.get(uid);
    if (!u) {
      const err = new Error('User not found');
      err.code = 'auth/user-not-found';
      throw err;
    }
    return { ...u };
  }

  async createUser(props) {
    const normalizedEmail = String(props.email).trim().toLowerCase();
    if (this.usersByEmail.has(normalizedEmail)) {
      const err = new Error('Email already exists');
      err.code = 'auth/email-already-exists';
      throw err;
    }
    if (props.uid && this.usersByUid.has(props.uid)) {
      const err = new Error('UID already exists');
      err.code = 'auth/uid-already-exists';
      throw err;
    }
    const uid = props.uid || `fb_${crypto.randomBytes(8).toString('hex')}`;
    const record = this.seedUser({
      uid,
      email: normalizedEmail,
      password: props.password,
      displayName: props.displayName || '',
      emailVerified: Boolean(props.emailVerified),
      disabled: Boolean(props.disabled)
    });
    return { ...record };
  }

  async updateUser(uid, updates) {
    const existing = this.usersByUid.get(uid);
    if (!existing) {
      const err = new Error('User not found');
      err.code = 'auth/user-not-found';
      throw err;
    }
    const updated = { ...existing, ...updates };
    this.usersByUid.set(uid, updated);
    if (updated.email) {
      this.usersByEmail.set(updated.email.trim().toLowerCase(), updated);
    }
    return { ...updated };
  }

  async createCustomToken(uid, developerClaims = {}) {
    const token = `custom_${uid}_${crypto.randomBytes(8).toString('hex')}`;
    this.customTokenClaims.set(token, { uid, ...developerClaims });
    return token;
  }

  async revokeRefreshTokens(uid) {
    this.revokedUids.add(uid);
  }

  async verifyIdToken(token, checkRevoked = false) {
    const payload = JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
    if (checkRevoked && this.revokedUids.has(payload.uid) && !payload._freshAfterRevoke) {
      const err = new Error('ID token revoked');
      err.code = 'auth/id-token-revoked';
      throw err;
    }
    return payload;
  }
}

function mintMockIdToken(payload) {
  const now = Math.floor(Date.now() / 1000);
  return Buffer.from(JSON.stringify({
    auth_time: now,
    iat: now,
    exp: now + 3600,
    ...payload
  })).toString('base64');
}

function requestJson(baseUrl, method, path, { headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, baseUrl);
    const req = http.request(url, { method, headers }, (res) => {
      let raw = '';
      res.on('data', chunk => { raw += chunk; });
      res.on('end', () => {
        let json = null;
        try { json = raw ? JSON.parse(raw) : null; } catch (_) {}
        resolve({ status: res.statusCode, headers: res.headers, json, raw });
      });
    });
    req.on('error', reject);
    if (body !== null) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

let passed = 0;
let failed = 0;
function check(id, name, ok, detail = '') {
  if (ok) {
    passed++;
    console.log(`  ✓ [PASS] ${id}: ${name}`);
  } else {
    failed++;
    console.error(`  ✗ [FAIL] ${id}: ${name} — ${detail}`);
  }
}

async function main() {
  resetRateLimits();
  const db = new MockFirestore();
  const authAdmin = new MockAuthAdmin();

  const config = bootstrap({
    APP_ENV: 'production',
    NODE_ENV: 'production',
    FIREBASE_PROJECT_ID: 'lanzar-95ae3',
    FIREBASE_SERVICE_ACCOUNT_KEY: JSON.stringify({
      project_id: 'lanzar-95ae3',
      client_email: 'lanzar-auth-api@lanzar-95ae3.iam.gserviceaccount.com'
    }),
    EXPECTED_SA_EMAIL: 'lanzar-auth-api@lanzar-95ae3.iam.gserviceaccount.com',
    SESSION_SIGNING_SECRET: process.env.SESSION_SIGNING_SECRET,
    MFA_HMAC_SECRET: process.env.MFA_HMAC_SECRET,
    FEATURE_STRIPE: 'disabled'
  });

  const { app } = createApp({ config, db, authAdmin });
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  try {
    console.log('\n=== Legacy Bridge, Standalone Session & SSO Interop Tests ===\n');

    // Seed Pythos scrypt account
    const email = 'Jon@Lanzar.me';
    const normalizedEmail = 'jon@lanzar.me';
    const password = 'CorrectHorseBattery99!';
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = (await scryptAsync(password, salt, 64)).toString('hex');
    const legacyUid = 'lanzar_' + crypto.createHash('sha256').update(normalizedEmail).digest('hex').slice(0, 20);
    const googleUid = 'google_uid_jon_001';

    // Existing Firebase user from Google Sign-In on Portal (same email, different UID than lanzar_...)
    authAdmin.seedUser({
      uid: googleUid,
      email: normalizedEmail,
      displayName: 'Jon Scott',
      emailVerified: true
    });

    await db.collection('pythos').doc('app').collection('lanzar_id_accounts').doc(legacyUid).set({
      uid: legacyUid,
      email: normalizedEmail,
      displayName: 'Jon Scott',
      passwordSalt: salt,
      passwordHash: hash,
      linkedGoogleUid: googleUid
    });

    // LB-1: Wrong password returns 401 and does not modify Firebase user password
    const badRes = await requestJson(baseUrl, 'POST', '/login/legacy-bridge', {
      headers: { 'Content-Type': 'application/json', Origin: 'https://auth.lanzar.me' },
      body: { email, password: 'WrongPassword!' }
    });
    const untouchedUser = await authAdmin.getUser(googleUid);
    check(
      'LB-1',
      'Wrong password returns 401 invalid_credentials without mutating Firebase Auth',
      badRes.status === 401 && badRes.json?.error === 'invalid_credentials' && untouchedUser.password === undefined,
      `status=${badRes.status} body=${badRes.raw}`
    );

    // LB-2: Valid Pythos password bridges existing Google user, reconciles /users & /customers, logs audit event
    const okRes = await requestJson(baseUrl, 'POST', '/login/legacy-bridge', {
      headers: { 'Content-Type': 'application/json', Origin: 'https://auth.lanzar.me' },
      body: { email, password }
    });
    const syncedUser = await authAdmin.getUser(googleUid);
    const usersSnap = await db.collection('users').doc(googleUid).get();
    const custSnap = await db.collection('customers').doc(googleUid).get();
    const hasBridgeAudit = Array.from(db.store.values()).some(
      (doc) => doc && doc.action === 'account.legacy_password_bridged' && doc.targetUid === googleUid
    );
    check(
      'LB-2',
      'Valid Pythos password syncs existing Firebase Auth UID, links legacy metadata, and audits event',
      okRes.status === 200 &&
        okRes.json?.bridged === true &&
        okRes.json?.uid === googleUid &&
        syncedUser.password === password &&
        usersSnap.exists &&
        usersSnap.data().pythosLegacyUid === legacyUid &&
        usersSnap.data().linkedGoogleUid === googleUid &&
        custSnap.exists &&
        hasBridgeAudit,
      `status=${okRes.status} body=${okRes.raw}`
    );

    // LB-3: Fresh user without prior Firebase account creates deterministic legacy UID
    const newEmail = 'fresh.legacy@lanzar.me';
    const newSalt = crypto.randomBytes(16).toString('hex');
    const newHash = (await scryptAsync('FreshPass123!', newSalt, 64)).toString('hex');
    await db.collection('pythos').doc('app').collection('lanzar_id_accounts').doc('custom_doc_non_deterministic').set({
      uid: 'lanzar_fresh_uid_01',
      email: newEmail,
      displayName: 'Fresh Legacy User',
      passwordSalt: newSalt,
      passwordHash: newHash
    });
    const createRes = await requestJson(baseUrl, 'POST', '/login/legacy-bridge', {
      headers: { 'Content-Type': 'application/json', Origin: 'https://auth.lanzar.me' },
      body: { email: newEmail, password: 'FreshPass123!' }
    });
    const createdFbUser = await authAdmin.getUserByEmail(newEmail).catch(() => null);
    check(
      'LB-3',
      'Email-fallback query creates Firebase Auth user preserving Pythos UID',
      createRes.status === 200 &&
        createRes.json?.uid === 'lanzar_fresh_uid_01' &&
        createdFbUser?.uid === 'lanzar_fresh_uid_01' &&
        createdFbUser?.password === 'FreshPass123!',
      `status=${createRes.status} body=${createRes.raw}`
    );

    // LB-4: Suspended user returns 403 account_suspended
    await db.collection('users').doc(googleUid).set({ status: 'suspended' }, { merge: true });
    const suspRes = await requestJson(baseUrl, 'POST', '/login/legacy-bridge', {
      headers: { 'Content-Type': 'application/json', Origin: 'https://auth.lanzar.me' },
      body: { email, password }
    });
    check(
      'LB-4',
      'Suspended user rejected with 403 account_suspended on legacy-bridge',
      suspRes.status === 403 && suspRes.json?.error === 'account_suspended',
      `status=${suspRes.status} body=${suspRes.raw}`
    );
    await db.collection('users').doc(googleUid).set({ status: 'active' }, { merge: true });

    // SS-1: Non-auth_hub origin blocked on /api/id/session/standalone
    const standardToken = mintMockIdToken({ uid: googleUid, email: normalizedEmail, name: 'Jon Scott' });
    const wrongOriginRes = await requestJson(baseUrl, 'POST', '/api/id/session/standalone', {
      headers: {
        Origin: 'https://pythos.lanzar.me',
        Authorization: `Bearer ${standardToken}`,
        'X-Lanzar-Client': 'id'
      }
    });
    check(
      'SS-1',
      'Non-auth_hub origin rejected with 403 client_app_not_permitted',
      wrongOriginRes.status === 403 && wrongOriginRes.json?.error === 'client_app_not_permitted',
      `status=${wrongOriginRes.status} body=${wrongOriginRes.raw}`
    );

    // SS-2: Standard Firebase ID token on auth_hub gets session_id-bound custom token
    const standaloneRes = await requestJson(baseUrl, 'POST', '/api/id/session/standalone', {
      headers: {
        Origin: 'https://auth.lanzar.me',
        Authorization: `Bearer ${standardToken}`,
        'X-Lanzar-Client': 'id'
      }
    });
    const standaloneSid = standaloneRes.json?.session_id;
    const standaloneSessDoc = standaloneSid
      ? await db.collection('users').doc(googleUid).collection('sessions').doc(standaloneSid).get()
      : null;
    check(
      'SS-2',
      'Standalone session endpoint issues session_id custom token and stores device session',
      standaloneRes.status === 200 &&
        typeof standaloneRes.json?.custom_token === 'string' &&
        standaloneRes.json?.customToken === standaloneRes.json?.custom_token &&
        Boolean(standaloneSid) &&
        standaloneSessDoc?.exists === true &&
        standaloneSessDoc.data().revoked === false,
      `status=${standaloneRes.status} body=${standaloneRes.raw}`
    );

    // SS-3: Token already bound to active session returns already_bound: true
    const boundToken = mintMockIdToken({
      uid: googleUid,
      email: normalizedEmail,
      session_id: standaloneSid
    });
    const alreadyBoundRes = await requestJson(baseUrl, 'POST', '/api/id/session/standalone', {
      headers: {
        Origin: 'https://auth.lanzar.me',
        Authorization: `Bearer ${boundToken}`,
        'X-Lanzar-Client': 'id'
      }
    });
    check(
      'SS-3',
      'Active bound token returns already_bound: true without minting duplicate session',
      alreadyBoundRes.status === 200 &&
        alreadyBoundRes.json?.already_bound === true &&
        alreadyBoundRes.json?.session_id === standaloneSid,
      `status=${alreadyBoundRes.status} body=${alreadyBoundRes.raw}`
    );

    // SS-4: Bound token with revoked session returns 401 session_revoked
    await db.collection('users').doc(googleUid).collection('sessions').doc(standaloneSid).update({
      revoked: true,
      revokedAt: new Date().toISOString()
    });
    const revokedBoundRes = await requestJson(baseUrl, 'POST', '/api/id/session/standalone', {
      headers: {
        Origin: 'https://auth.lanzar.me',
        Authorization: `Bearer ${boundToken}`,
        'X-Lanzar-Client': 'id'
      }
    });
    check(
      'SS-4',
      'Revoked session token cannot re-mint standalone session (401 session_revoked)',
      revokedBoundRes.status === 401 && revokedBoundRes.json?.error === 'session_revoked',
      `status=${revokedBoundRes.status} body=${revokedBoundRes.raw}`
    );

    // SSO-1: Establish central session -> exchange child token -> verify /api/id/session/validate & /api/id/sessions
    await db.collection('user_security').doc(googleUid).set({
      accountStatus: 'active',
      tokenVersion: 1
    });
    const establishRes = await requestJson(baseUrl, 'POST', '/api/id/session/establish', {
      headers: {
        Origin: 'https://auth.lanzar.me',
        Authorization: `Bearer ${standardToken}`,
        'X-Lanzar-Client': 'id',
        'Content-Type': 'application/json'
      }
    });
    const setCookieHeader = Array.isArray(establishRes.headers['set-cookie'])
      ? establishRes.headers['set-cookie'][0]
      : establishRes.headers['set-cookie'];
    const cookiePair = setCookieHeader ? setCookieHeader.split(';')[0] : '';

    const exchangeRes = await requestJson(baseUrl, 'POST', '/api/id/session/token', {
      headers: {
        Origin: 'https://portal.lanzar.me',
        Cookie: cookiePair,
        'X-Lanzar-Client': 'id',
        'Content-Type': 'application/json'
      }
    });
    const childClaims = authAdmin.customTokenClaims.get(exchangeRes.json?.customToken);
    const childSessSnap = exchangeRes.json?.sessionId
      ? await db.collection('users').doc(googleUid).collection('sessions').doc(exchangeRes.json.sessionId).get()
      : null;
    const childData = childSessSnap?.data();
    check(
      'SSO-1',
      'Central child exchange writes /api/id-compatible child doc and mints dual claims',
      establishRes.status === 200 &&
        exchangeRes.status === 200 &&
        exchangeRes.json?.custom_token === exchangeRes.json?.customToken &&
        exchangeRes.json?.session_id === exchangeRes.json?.sessionId &&
        childClaims?.session_id === exchangeRes.json?.sessionId &&
        childClaims?.lanzarSessionId === exchangeRes.json?.sessionId &&
        childClaims?.tenant_id === 'lanzar' &&
        childClaims?.client_id === 'mission_control' &&
        typeof childData?.expiresAt === 'number' &&
        childData?.sessionId === exchangeRes.json?.sessionId &&
        childData?.uid === googleUid &&
        childData?.clientId === 'mission_control',
      `status=${exchangeRes.status} claims=${JSON.stringify(childClaims)}`
    );

    // Verify child token (even with ONLY lanzarSessionId or dual claims) passes authenticateUserMiddleware
    const childIdToken = mintMockIdToken({
      uid: googleUid,
      email: normalizedEmail,
      name: 'Jon Scott',
      lanzarSessionId: childClaims?.lanzarSessionId,
      lanzarTokenVersion: childClaims?.lanzarTokenVersion,
      lanzarClientApp: childClaims?.lanzarClientApp
    });
    const validateRes = await requestJson(baseUrl, 'GET', '/api/id/session/validate', {
      headers: {
        Origin: 'https://portal.lanzar.me',
        Authorization: `Bearer ${childIdToken}`
      }
    });
    const listRes = await requestJson(baseUrl, 'GET', '/api/id/sessions', {
      headers: {
        Origin: 'https://portal.lanzar.me',
        Authorization: `Bearer ${childIdToken}`
      }
    });
    const listedChild = listRes.json?.sessions?.find((s) => s.sessionId === exchangeRes.json?.sessionId);
    check(
      'SSO-2',
      'Child token passes /api/id/session/validate and /api/id/sessions with normalized ISO dates',
      validateRes.status === 200 &&
        validateRes.json?.valid === true &&
        validateRes.json?.session_id === exchangeRes.json?.sessionId &&
        listRes.status === 200 &&
        typeof listedChild?.createdAt === 'string' &&
        listedChild.createdAt.includes('T'),
      `validate=${validateRes.status}:${validateRes.raw} list=${listRes.status}`
    );

    // SSO-3: Central logout immediately invalidates child session on /api/id/session/validate
    const logoutRes = await requestJson(baseUrl, 'POST', '/api/id/session/logout', {
      headers: {
        Origin: 'https://portal.lanzar.me',
        Cookie: cookiePair,
        'X-Lanzar-Client': 'id'
      }
    });
    const validateAfterLogout = await requestJson(baseUrl, 'GET', '/api/id/session/validate', {
      headers: {
        Origin: 'https://portal.lanzar.me',
        Authorization: `Bearer ${childIdToken}`
      }
    });
    check(
      'SSO-3',
      'Central session logout invalidates child session on /api/id/session/validate',
      logoutRes.status === 200 &&
        validateAfterLogout.status === 401 &&
        validateAfterLogout.json?.error === 'session_revoked',
      `logout=${logoutRes.status} validateAfter=${validateAfterLogout.status}:${validateAfterLogout.raw}`
    );

    // SSO-4: POST /api/id/sessions/revoke-all revokes both device sessions and central_sessions
    const establishRes2 = await requestJson(baseUrl, 'POST', '/api/id/session/establish', {
      headers: {
        Origin: 'https://auth.lanzar.me',
        Authorization: `Bearer ${standardToken}`,
        'X-Lanzar-Client': 'id'
      }
    });
    const cookie2 = (Array.isArray(establishRes2.headers['set-cookie'])
      ? establishRes2.headers['set-cookie'][0]
      : establishRes2.headers['set-cookie']).split(';')[0];
    const exchangeRes2 = await requestJson(baseUrl, 'POST', '/api/id/session/token', {
      headers: {
        Origin: 'https://portal.lanzar.me',
        Cookie: cookie2,
        'X-Lanzar-Client': 'id'
      }
    });
    const childIdToken2 = mintMockIdToken({
      uid: googleUid,
      email: normalizedEmail,
      _freshAfterRevoke: true,
      session_id: exchangeRes2.json.sessionId
    });
    const revokeAllRes = await requestJson(baseUrl, 'POST', '/api/id/sessions/revoke-all', {
      headers: {
        Origin: 'https://auth.lanzar.me',
        Authorization: `Bearer ${childIdToken2}`
      }
    });
    const meAfterRevokeAll = await requestJson(baseUrl, 'GET', '/api/id/session/me', {
      headers: {
        Origin: 'https://portal.lanzar.me',
        Cookie: cookie2
      }
    });
    check(
      'SSO-4',
      'revoke-all revokes parent central_sessions so /api/id/session/me fails with 401',
      revokeAllRes.status === 200 &&
        meAfterRevokeAll.status === 401 &&
        meAfterRevokeAll.json?.authenticated === false,
      `revokeAll=${revokeAllRes.status} me=${meAfterRevokeAll.status}:${meAfterRevokeAll.raw}`
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }

  console.log(`\nResults: ${passed} passed, ${failed} failed\n`);
  if (failed > 0) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
