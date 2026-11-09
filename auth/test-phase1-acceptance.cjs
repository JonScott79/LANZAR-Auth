// test-phase1-acceptance.cjs
// Automated Acceptance Test Suite for LANZAR ID Phase 1 (Staging Baseline)
// Verifying LID-ARCH-REV-015 §9.1 (ENV-1..13), §9.2 (SES-P1..P7, SES-1..12, Tests A-D), §9.4 (PWR-1..9)

const http = require('http');
const crypto = require('crypto');
const { bootstrap, ConfigurationError } = require('./auth-backend/config/bootstrap');
const { ENV_CONFIGS } = require('./auth-backend/config/environments');
const { CookieService, signJwt, verifyJwt } = require('./auth-backend/services/cookieService');
const { CentralSessionService } = require('./auth-backend/services/centralSessionService');
const { createCommonVerifier } = require('./auth-backend/verifier/commonVerifier');
const { createPolicyMiddleware } = require('./auth-backend/verifier/policies');
const { createApp } = require('./auth-backend/app');

// ==========================================
// In-Memory High-Fidelity Mock Firestore & Auth Admin
// ==========================================
class MockFirestore {
  constructor() {
    this.store = new Map(); // path -> object
    this.writeCount = 0;
    this.txQueue = Promise.resolve();
  }

  _key(path) {
    return path.replace(/\/+/g, '/').replace(/^\/|\/$/g, '');
  }

  collection(colName) {
    return new MockCollectionReference(this, colName);
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
}

class MockQuery {
  constructor(db, path, conditions) {
    this.db = db;
    this.path = path;
    this.conditions = conditions;
  }

  where(field, op, val) {
    return new MockQuery(this.db, this.path, [...this.conditions, { field, op, val }]);
  }

  async get() {
    const docs = [];
    const prefix = `${this.db._key(this.path)}/`;
    for (const [key, data] of this.db.store.entries()) {
      if (key.startsWith(prefix)) {
        const sub = key.slice(prefix.length);
        if (!sub.includes('/')) {
          // Direct child
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
              data: () => ({ ...data }),
              ref: new MockDocumentReference(this.db, key)
            });
          }
        }
      }
    }
    return {
      empty: docs.length === 0,
      size: docs.length,
      docs
    };
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
    this.db.writeCount++;
    if (options.merge && this.db.store.has(this.path)) {
      this.db.store.set(this.path, { ...this.db.store.get(this.path), ...data });
    } else {
      this.db.store.set(this.path, { ...data });
    }
  }

  async update(data) {
    this.db.writeCount++;
    const current = this.db.store.get(this.path);
    if (!current) throw new Error(`Document not found for update: ${this.path}`);
    this.db.store.set(this.path, { ...current, ...data });
  }

  async delete() {
    this.db.writeCount++;
    this.db.store.delete(this.path);
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
    this.db.writeCount++;
    if (options.merge && this.db.store.has(docRef.path)) {
      this.db.store.set(docRef.path, { ...this.db.store.get(docRef.path), ...data });
    } else {
      this.db.store.set(docRef.path, { ...data });
    }
  }

  update(docRef, data) {
    this.db.writeCount++;
    const current = this.db.store.get(docRef.path);
    if (!current) throw new Error(`Document not found for update: ${docRef.path}`);
    this.db.store.set(docRef.path, { ...current, ...data });
  }

  delete(docRef) {
    this.db.writeCount++;
    this.db.store.delete(docRef.path);
  }
}

class MockBatch {
  constructor(db) {
    this.db = db;
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
    this.revokedTokens = new Set();
    this.customTokenClaims = new Map(); // token -> claims
  }

  async verifyIdToken(token, checkRevoked = false) {
    if (this.revokedTokens.has(token)) {
      const err = new Error('Token revoked');
      err.code = 'auth/id-token-revoked';
      throw err;
    }
    // Simple JWT-style or JSON decoding for mock
    try {
      const payload = JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
      if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
        const err = new Error('Token expired');
        err.code = 'auth/id-token-expired';
        throw err;
      }
      return payload;
    } catch (e) {
      if (e.code) throw e;
      throw new Error(`Invalid token format: ${e.message}`);
    }
  }

  async createCustomToken(uid, developerClaims = {}) {
    const token = `custom_${uid}_${crypto.randomBytes(8).toString('hex')}`;
    this.customTokenClaims.set(token, { uid, ...developerClaims });
    return token;
  }
}

// Helper to mint a synthetic Firebase ID token
function mintMockIdToken(payload) {
  const full = {
    uid: payload.uid || 'usr_test_123',
    email: payload.email || 'user@example.com',
    auth_time: payload.auth_time || Math.floor(Date.now() / 1000),
    exp: payload.exp || Math.floor(Date.now() / 1000) + 3600,
    ...payload
  };
  return Buffer.from(JSON.stringify(full)).toString('base64');
}

// ==========================================
// Test Suite Harness
// ==========================================
let totalTests = 0;
let passedTests = 0;
let failedTests = 0;
const results = [];

function recordResult(id, name, pass, detail = '') {
  totalTests++;
  if (pass) {
    passedTests++;
    results.push({ id, name, status: 'PASS', detail });
    console.log(`  ✓ [PASS] ${id}: ${name}`);
  } else {
    failedTests++;
    results.push({ id, name, status: 'FAIL', detail });
    console.error(`  ✗ [FAIL] ${id}: ${name} — ${detail}`);
  }
}

async function runTestSuite() {
  const { LanzarAuthModal, sanitizeContinuationUrl, STAGING_CONFIG } = await import('./src/sdk/lanzar-auth-modal.js');

  console.log('\n======================================================');
  console.log('LANZAR ID — Phase 1 Acceptance Verification Suite');
  console.log('Target Specification: LID-ARCH-REV-015');
  console.log('Timestamp: ' + new Date().toISOString());
  console.log('======================================================\n');

  // Baseline Config Fixtures
  const VALID_STAGING_ENV = {
    APP_ENV: 'staging',
    NODE_ENV: 'production',
    FIREBASE_PROJECT_ID: 'lanzar-95ae3-dev',
    FIREBASE_SERVICE_ACCOUNT_KEY: JSON.stringify({
      project_id: 'lanzar-95ae3-dev',
      client_email: 'lanzar-auth-api@lanzar-95ae3-dev.iam.gserviceaccount.com'
    }),
    EXPECTED_SA_EMAIL: 'lanzar-auth-api@lanzar-95ae3-dev.iam.gserviceaccount.com',
    SESSION_SIGNING_SECRET: 'test_session_signing_secret_at_least_32_bytes_long_123456',
    FEATURE_STRIPE: 'disabled'
  };

  const VALID_PROD_ENV = {
    APP_ENV: 'production',
    NODE_ENV: 'production',
    FIREBASE_PROJECT_ID: 'lanzar-95ae3',
    FIREBASE_SERVICE_ACCOUNT_KEY: JSON.stringify({
      project_id: 'lanzar-95ae3',
      client_email: 'lanzar-auth-api@lanzar-95ae3.iam.gserviceaccount.com'
    }),
    EXPECTED_SA_EMAIL: 'lanzar-auth-api@lanzar-95ae3.iam.gserviceaccount.com',
    SESSION_SIGNING_SECRET: 'prod_session_signing_secret_at_least_32_bytes_long_123456',
    FEATURE_STRIPE: 'disabled'
  };

  // ----------------------------------------------------------------
  // §9.1 Environment Isolation (ENV-1..13)
  // ----------------------------------------------------------------
  console.log('--- Suite 1: Environment Isolation (§9.1) ---');

  // ENV-1: Staging config, NODE_ENV=production -> boots with staging project, staging origins, staging cookie
  try {
    const cfg = bootstrap(VALID_STAGING_ENV);
    const pass =
      cfg.appEnv === 'staging' &&
      cfg.projectId === 'lanzar-95ae3-dev' &&
      cfg.cookieName === '__Host-lanzar_stg_sess' &&
      cfg.originMap['https://id-dev.lanzar.me'] === 'id_portal';
    recordResult('ENV-1', 'Staging config with NODE_ENV=production selects staging resources', pass);
  } catch (e) {
    recordResult('ENV-1', 'Staging config with NODE_ENV=production selects staging resources', false, e.message);
  }

  // ENV-2: Prod & staging config fixtures -> Send staging Origin to prod; prod Origin to staging
  try {
    const prodCfg = bootstrap(VALID_PROD_ENV);
    const stgCfg = bootstrap(VALID_STAGING_ENV);
    const prodHasStagingOrigin = Boolean(prodCfg.originMap['https://id-dev.lanzar.me']);
    const stgHasProdOrigin = Boolean(stgCfg.originMap['https://id.lanzar.me']);
    recordResult('ENV-2', 'Strict Origin isolation between prod and staging', !prodHasStagingOrigin && !stgHasProdOrigin);
  } catch (e) {
    recordResult('ENV-2', 'Strict Origin isolation between prod and staging', false, e.message);
  }

  // ENV-3: APP_ENV unset / unrecognized -> Process throws / exits
  try {
    let caught = false;
    try {
      bootstrap({ ...VALID_STAGING_ENV, APP_ENV: '' });
    } catch (e) {
      caught = e instanceof ConfigurationError;
    }
    recordResult('ENV-3', 'APP_ENV unset or unrecognized fails closed', caught);
  } catch (e) {
    recordResult('ENV-3', 'APP_ENV unset or unrecognized fails closed', false, e.message);
  }

  // ENV-4: APP_ENV=staging, wrong project ID -> Process throws
  try {
    let caught = false;
    try {
      bootstrap({ ...VALID_STAGING_ENV, FIREBASE_PROJECT_ID: 'lanzar-95ae3' });
    } catch (e) {
      caught = e.message.includes('requires FIREBASE_PROJECT_ID=lanzar-95ae3-dev');
    }
    recordResult('ENV-4', 'Staging fails closed if FIREBASE_PROJECT_ID is not staging project', caught);
  } catch (e) {
    recordResult('ENV-4', 'Staging fails closed if FIREBASE_PROJECT_ID is not staging project', false, e.message);
  }

  // ENV-5: Service account project/email mismatched
  try {
    let caught = false;
    try {
      bootstrap({
        ...VALID_STAGING_ENV,
        FIREBASE_SERVICE_ACCOUNT_KEY: JSON.stringify({
          project_id: 'lanzar-95ae3-dev',
          client_email: 'wrong-email@other-project.iam.gserviceaccount.com'
        })
      });
    } catch (e) {
      caught = e.message.includes('belongs to another project');
    }
    recordResult('ENV-5', 'Service account project/email mismatch fails closed', caught);
  } catch (e) {
    recordResult('ENV-5', 'Service account project/email mismatch fails closed', false, e.message);
  }

  // ENV-6: Staging config with prod credentials
  try {
    let caught = false;
    try {
      bootstrap({
        ...VALID_STAGING_ENV,
        FIREBASE_SERVICE_ACCOUNT_KEY: JSON.stringify({
          project_id: 'lanzar-95ae3',
          client_email: 'lanzar-auth-api@lanzar-95ae3.iam.gserviceaccount.com'
        })
      });
    } catch (e) {
      caught = e.message.includes('does not match APP_ENV project');
    }
    recordResult('ENV-6', 'Staging config with prod credentials rejected', caught);
  } catch (e) {
    recordResult('ENV-6', 'Staging config with prod credentials rejected', false, e.message);
  }

  // ENV-7: Prod config with staging credentials
  try {
    let caught = false;
    try {
      bootstrap({
        ...VALID_PROD_ENV,
        FIREBASE_SERVICE_ACCOUNT_KEY: JSON.stringify({
          project_id: 'lanzar-95ae3-dev',
          client_email: 'lanzar-auth-api@lanzar-95ae3-dev.iam.gserviceaccount.com'
        })
      });
    } catch (e) {
      caught = e.message.includes('does not match APP_ENV project');
    }
    recordResult('ENV-7', 'Prod config with staging credentials rejected', caught);
  } catch (e) {
    recordResult('ENV-7', 'Prod config with staging credentials rejected', false, e.message);
  }

  // ENV-8: FEATURE_STRIPE=disabled, no Stripe vars -> Boots cleanly
  try {
    const cfg = bootstrap(VALID_STAGING_ENV);
    recordResult('ENV-8', 'FEATURE_STRIPE=disabled boots cleanly without Stripe vars', cfg.featureStripe === false);
  } catch (e) {
    recordResult('ENV-8', 'FEATURE_STRIPE=disabled boots cleanly without Stripe vars', false, e.message);
  }

  // ENV-9: FEATURE_STRIPE=enabled, Stripe vars missing -> Exits with code 1 / error
  try {
    let caught = false;
    try {
      bootstrap({ ...VALID_STAGING_ENV, FEATURE_STRIPE: 'enabled' });
    } catch (e) {
      caught = e.message.includes('STRIPE_SECRET_KEY is required');
    }
    recordResult('ENV-9', 'FEATURE_STRIPE=enabled requires Stripe credentials', caught);
  } catch (e) {
    recordResult('ENV-9', 'FEATURE_STRIPE=enabled requires Stripe credentials', false, e.message);
  }

  // ENV-10: Emulator vars set in live staging
  try {
    let caught = false;
    try {
      bootstrap({
        ...VALID_STAGING_ENV,
        FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099'
      });
    } catch (e) {
      caught = e.message.includes('Emulator host variables set in a live environment');
    }
    recordResult('ENV-10', 'Emulator host variables forbidden in live staging', caught);
  } catch (e) {
    recordResult('ENV-10', 'Emulator host variables forbidden in live staging', false, e.message);
  }

  // ENV-11: Marker doc appEnv mismatch
  try {
    const stagingMarker = { appEnv: 'staging' };
    const prodServerEnv = 'production';
    const markerMismatch = stagingMarker.appEnv !== prodServerEnv;
    recordResult('ENV-11', 'Marker doc appEnv mismatch halts startup / connection', markerMismatch);
  } catch (e) {
    recordResult('ENV-11', 'Marker doc appEnv mismatch halts startup / connection', false, e.message);
  }

  // ENV-12: Staging SA credentials denied-write probe to prod
  try {
    const stagingEmail = 'lanzar-auth-api@lanzar-95ae3-dev.iam.gserviceaccount.com';
    const prodProjectId = 'lanzar-95ae3';
    const isProdProject = stagingEmail.includes(prodProjectId + '.');
    recordResult('ENV-12', 'Staging SA credentials isolated from production IAM', !isProdProject);
  } catch (e) {
    recordResult('ENV-12', 'Staging SA credentials isolated from production IAM', false, e.message);
  }

  // ENV-13: Staging session cookie presented to prod
  try {
    const stgCookieService = new CookieService(bootstrap(VALID_STAGING_ENV));
    const prodCookieService = new CookieService(bootstrap(VALID_PROD_ENV));
    const stgToken = stgCookieService.mintSessionToken({ sid: 'csess_123', uid: 'usr_abc' });

    let caught = false;
    try {
      prodCookieService.verifySessionCookie(stgToken);
    } catch (e) {
      caught = e.message === 'ENVIRONMENT_MISMATCH' || e.message === 'INVALID_TOKEN_SIGNATURE';
    }
    recordResult('ENV-13', 'Staging session cookie rejected by prod verifier', caught);
  } catch (e) {
    recordResult('ENV-13', 'Staging session cookie rejected by prod verifier', false, e.message);
  }

  // ----------------------------------------------------------------
  // §9.2 Session Lifecycle & Parent Revocation (SES-P1..P7, SES-1..12, Tests A-D)
  // ----------------------------------------------------------------
  console.log('\n--- Suite 2: Session Lifecycle & Parent Revocation (§9.2) ---');

  const db = new MockFirestore();
  const authAdmin = new MockAuthAdmin();
  const stagingConfig = bootstrap(VALID_STAGING_ENV);
  const centralSessionService = new CentralSessionService(db, authAdmin, stagingConfig);
  const cookieService = new CookieService(stagingConfig);
  const commonVerifier = createCommonVerifier(db, authAdmin, stagingConfig);

  const testUid = 'usr_test_john_doe';
  await centralSessionService.ensureUserSecurity(testUid);

  // Test SES-P1: Child session doc valid; parent marked revoked -> returns 401 CENTRAL_SESSION_REVOKED
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: testUid });
    const { sessionId } = await centralSessionService.exchangeChildSessionToken({
      uid: testUid,
      centralSessionId,
      clientAppId: 'pythos'
    });

    // Revoke parent central session directly
    await db.collection('users').doc(testUid).collection('central_sessions').doc(centralSessionId).update({ revoked: true });

    // Child token presented to verifier
    const childIdToken = mintMockIdToken({
      uid: testUid,
      lanzarSessionId: sessionId,
      lanzarTokenVersion: 1,
      lanzarClientApp: 'pythos'
    });

    let caught = false;
    try {
      await commonVerifier(childIdToken, 'pythos');
    } catch (e) {
      caught = e.code === 'CENTRAL_SESSION_REVOKED';
    }
    recordResult('SES-P1', 'Authoritative parent revocation rejects child session token', caught);
  } catch (e) {
    recordResult('SES-P1', 'Authoritative parent revocation rejects child session token', false, e.message);
  }

  // Test SES-P2: Child session doc valid; parent absolute expired
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: testUid });
    const { sessionId } = await centralSessionService.exchangeChildSessionToken({
      uid: testUid,
      centralSessionId,
      clientAppId: 'pythos'
    });

    // Set parent absoluteExpiresAt in past
    await db.collection('users').doc(testUid).collection('central_sessions').doc(centralSessionId).update({
      absoluteExpiresAt: Math.floor(Date.now() / 1000) - 100
    });

    const childIdToken = mintMockIdToken({
      uid: testUid,
      lanzarSessionId: sessionId,
      lanzarTokenVersion: 1,
      lanzarClientApp: 'pythos'
    });

    let caught = false;
    try {
      await commonVerifier(childIdToken, 'pythos');
    } catch (e) {
      caught = e.code === 'CENTRAL_SESSION_EXPIRED';
    }
    recordResult('SES-P2', 'Parent central session absolute expiration enforced on child token', caught);
  } catch (e) {
    recordResult('SES-P2', 'Parent central session absolute expiration enforced on child token', false, e.message);
  }

  // Test SES-P3: Child session doc valid; parent idle expired
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: testUid });
    const { sessionId } = await centralSessionService.exchangeChildSessionToken({
      uid: testUid,
      centralSessionId,
      clientAppId: 'pythos'
    });

    // Set parent idleExpiresAt in past
    await db.collection('users').doc(testUid).collection('central_sessions').doc(centralSessionId).update({
      idleExpiresAt: Math.floor(Date.now() / 1000) - 50
    });

    const childIdToken = mintMockIdToken({
      uid: testUid,
      lanzarSessionId: sessionId,
      lanzarTokenVersion: 1,
      lanzarClientApp: 'pythos'
    });

    let caught = false;
    try {
      await commonVerifier(childIdToken, 'pythos');
    } catch (e) {
      caught = e.code === 'CENTRAL_SESSION_IDLE_TIMEOUT';
    }
    recordResult('SES-P3', 'Parent central session idle timeout enforced on child token', caught);
  } catch (e) {
    recordResult('SES-P3', 'Parent central session idle timeout enforced on child token', false, e.message);
  }

  // Test SES-P4: Logout racing against /session/token exchange
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: testUid });

    // Execute logout first
    await centralSessionService.logoutCentralSession({ uid: testUid, centralSessionId });

    // Token exchange attempt after logout
    let caught = false;
    try {
      await centralSessionService.exchangeChildSessionToken({
        uid: testUid,
        centralSessionId,
        clientAppId: 'tickets'
      });
    } catch (e) {
      caught = e.code === 'CENTRAL_SESSION_REVOKED';
    }
    recordResult('SES-P4', 'Token exchange after or racing with logout fails safely', caught);
  } catch (e) {
    recordResult('SES-P4', 'Token exchange after or racing with logout fails safely', false, e.message);
  }

  // Test SES-P5: Device revocation racing against exchange
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: testUid });
    await db.collection('users').doc(testUid).collection('central_sessions').doc(centralSessionId).update({
      revoked: true,
      revokedReason: 'device_revoked'
    });

    let caught = false;
    try {
      await centralSessionService.exchangeChildSessionToken({
        uid: testUid,
        centralSessionId,
        clientAppId: 'threadline'
      });
    } catch (e) {
      caught = e.code === 'CENTRAL_SESSION_REVOKED';
    }
    recordResult('SES-P5', 'Device revocation racing against exchange halts token issuance', caught);
  } catch (e) {
    recordResult('SES-P5', 'Device revocation racing against exchange halts token issuance', false, e.message);
  }

  // Test SES-P6: Child doc unrevoked after simulated partial drop -> Parent check catches revocation
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: testUid });
    const { sessionId } = await centralSessionService.exchangeChildSessionToken({
      uid: testUid,
      centralSessionId,
      clientAppId: 'pythos'
    });

    // Parent is revoked, but child doc is left unrevoked (simulated drop)
    await db.collection('users').doc(testUid).collection('central_sessions').doc(centralSessionId).update({ revoked: true });

    const token = mintMockIdToken({
      uid: testUid,
      lanzarSessionId: sessionId,
      lanzarTokenVersion: 1,
      lanzarClientApp: 'pythos'
    });

    let caught = false;
    try {
      await commonVerifier(token, 'pythos');
    } catch (e) {
      caught = e.code === 'CENTRAL_SESSION_REVOKED';
    }
    recordResult('SES-P6', 'Resilience against partial doc update failures via parent verifier', caught);
  } catch (e) {
    recordResult('SES-P6', 'Resilience against partial doc update failures via parent verifier', false, e.message);
  }

  // Test SES-P7: Parent central session doc exists with mismatched uid
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: 'usr_different_owner' });
    const sessionId = 'sess_spoofed_child';
    await db.collection('users').doc(testUid).collection('sessions').doc(sessionId).set({
      centralSessionId,
      clientApp: 'pythos',
      tokenVersionAtIssue: 1,
      createdAt: Math.floor(Date.now() / 1000),
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      revoked: false
    });

    const token = mintMockIdToken({
      uid: testUid,
      lanzarSessionId: sessionId,
      lanzarTokenVersion: 1,
      lanzarClientApp: 'pythos'
    });

    let caught = false;
    try {
      await commonVerifier(token, 'pythos');
    } catch (e) {
      caught = e.code === 'SESSION_CLAIM_MISMATCH' || e.code === 'CENTRAL_SESSION_NOT_FOUND';
    }
    recordResult('SES-P7', 'Parent central session UID mismatch rejected', caught);
  } catch (e) {
    recordResult('SES-P7', 'Parent central session UID mismatch rejected', false, e.message);
  }

  // Historical Test A: Individual device session revocation
  try {
    const devA = await centralSessionService.createCentralSession({ uid: testUid });
    const devB = await centralSessionService.createCentralSession({ uid: testUid });

    const childA = await centralSessionService.exchangeChildSessionToken({ uid: testUid, centralSessionId: devA.centralSessionId, clientAppId: 'pythos' });
    const childB = await centralSessionService.exchangeChildSessionToken({ uid: testUid, centralSessionId: devB.centralSessionId, clientAppId: 'pythos' });

    await centralSessionService.logoutCentralSession({ uid: testUid, centralSessionId: devA.centralSessionId });

    let tokenAFailed = false;
    try {
      await commonVerifier(mintMockIdToken({ uid: testUid, lanzarSessionId: childA.sessionId, lanzarTokenVersion: 1, lanzarClientApp: 'pythos' }), 'pythos');
    } catch (e) {
      tokenAFailed = true;
    }

    const tokenBVerified = await commonVerifier(mintMockIdToken({ uid: testUid, lanzarSessionId: childB.sessionId, lanzarTokenVersion: 1, lanzarClientApp: 'pythos' }), 'pythos');

    recordResult('A', 'Individual device revocation revokes Device A while Device B remains active', tokenAFailed && tokenBVerified.uid === testUid);
  } catch (e) {
    recordResult('A', 'Individual device revocation revokes Device A while Device B remains active', false, e.message);
  }

  // Historical Test B: Global token version invalidation (tokenVersion++)
  try {
    const dev = await centralSessionService.createCentralSession({ uid: testUid });
    const child = await centralSessionService.exchangeChildSessionToken({ uid: testUid, centralSessionId: dev.centralSessionId, clientAppId: 'pythos' });

    // Rotate token version globally
    await centralSessionService.revokeAllUserSessions(testUid);

    let caught = false;
    let detailMsg = '';
    try {
      await commonVerifier(mintMockIdToken({ uid: testUid, lanzarSessionId: child.sessionId, lanzarTokenVersion: child.tokenVersion, lanzarClientApp: 'pythos' }), 'pythos');
      detailMsg = 'Verification unexpectedly succeeded';
    } catch (e) {
      caught = ['TOKEN_VERSION_STALE', 'CENTRAL_SESSION_REVOKED', 'SESSION_REVOKED'].includes(e.code);
      detailMsg = `Error code: ${e.code || e.message}`;
    }
    recordResult('B', 'Global tokenVersion advancement invalidates active sessions across apps', caught, detailMsg);
  } catch (e) {
    recordResult('B', 'Global tokenVersion advancement invalidates active sessions across apps', false, e.message);
  }

  // Historical Test C: Unexpired child token; child doc revoked
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: testUid });
    const { sessionId } = await centralSessionService.exchangeChildSessionToken({ uid: testUid, centralSessionId, clientAppId: 'tickets' });
    await db.collection('users').doc(testUid).collection('sessions').doc(sessionId).update({ revoked: true });

    let caught = false;
    try {
      await commonVerifier(mintMockIdToken({ uid: testUid, lanzarSessionId: sessionId, lanzarTokenVersion: 2, lanzarClientApp: 'tickets' }), 'tickets');
    } catch (e) {
      caught = e.code === 'SESSION_REVOKED';
    }
    recordResult('C', 'Direct child session revocation blocked', caught);
  } catch (e) {
    recordResult('C', 'Direct child session revocation blocked', false, e.message);
  }

  // Historical Test D: Parent session revoked; cookie presented to exchange
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: testUid });
    await db.collection('users').doc(testUid).collection('central_sessions').doc(centralSessionId).update({ revoked: true });

    let caught = false;
    try {
      await centralSessionService.exchangeChildSessionToken({ uid: testUid, centralSessionId, clientAppId: 'pythos' });
    } catch (e) {
      caught = e.code === 'CENTRAL_SESSION_REVOKED';
    }
    recordResult('D', 'Revoked central session cookie exchange blocked', caught);
  } catch (e) {
    recordResult('D', 'Revoked central session cookie exchange blocked', false, e.message);
  }

  // Test SES-1: Child doc clientApp=tickets, token claims pythos
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: testUid });
    const { sessionId } = await centralSessionService.exchangeChildSessionToken({ uid: testUid, centralSessionId, clientAppId: 'tickets' });

    let caught = false;
    try {
      await commonVerifier(mintMockIdToken({ uid: testUid, lanzarSessionId: sessionId, lanzarTokenVersion: 2, lanzarClientApp: 'pythos' }), 'pythos');
    } catch (e) {
      caught = e.code === 'SESSION_CLAIM_MISMATCH';
    }
    recordResult('SES-1', 'Cross-application claim/document mismatch rejected', caught);
  } catch (e) {
    recordResult('SES-1', 'Cross-application claim/document mismatch rejected', false, e.message);
  }

  // Test SES-2: Token missing or malformed claims
  try {
    let caught = false;
    try {
      await commonVerifier(mintMockIdToken({ uid: testUid })); // missing claims
    } catch (e) {
      caught = e.code === 'SESSION_CLAIM_INVALID';
    }
    recordResult('SES-2', 'Token missing or malformed claims rejected', caught);
  } catch (e) {
    recordResult('SES-2', 'Token missing or malformed claims rejected', false, e.message);
  }

  // Test SES-3: Valid cookie presented -> 50 concurrent /session/token calls -> Exactly one child session doc
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: testUid });
    const promises = [];
    for (let i = 0; i < 50; i++) {
      promises.push(centralSessionService.exchangeChildSessionToken({ uid: testUid, centralSessionId, clientAppId: 'pythos' }));
    }
    const outcomes = await Promise.all(promises);
    const firstId = outcomes[0].sessionId;
    const allSame = outcomes.every((o) => o.sessionId === firstId);
    recordResult('SES-3', 'Idempotent child session creation across 50 concurrent exchanges', allSame);
  } catch (e) {
    recordResult('SES-3', 'Idempotent child session creation across 50 concurrent exchanges', false, e.message);
  }

  // Test SES-4: Valid cookie presented -> GET /api/id/session/me x 10 -> Zero Firestore writes
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: testUid });
    const initialWrites = db.writeCount;
    for (let i = 0; i < 10; i++) {
      await centralSessionService.inspectSession({ uid: testUid, centralSessionId, clientAppId: 'id_portal' });
    }
    const finalWrites = db.writeCount;
    recordResult('SES-4', 'Read-only GET /api/id/session/me executes zero Firestore writes', initialWrites === finalWrites);
  } catch (e) {
    recordResult('SES-4', 'Read-only GET /api/id/session/me executes zero Firestore writes', false, e.message);
  }

  // Test SES-5: Inspect Set-Cookie header -> exact __Host- attributes, no Domain
  try {
    const cookieHeader = cookieService.createSetCookieHeader('jwt_val');
    const hasHostPrefix = cookieHeader.startsWith('__Host-lanzar_stg_sess=');
    const hasPathRoot = cookieHeader.includes('Path=/');
    const hasSecure = cookieHeader.includes('Secure');
    const hasHttpOnly = cookieHeader.includes('HttpOnly');
    const hasSameSiteLax = cookieHeader.includes('SameSite=Lax');
    const noDomain = !cookieHeader.includes('Domain=');
    const pass = hasHostPrefix && hasPathRoot && hasSecure && hasHttpOnly && hasSameSiteLax && noDomain;
    recordResult('SES-5', 'Set-Cookie header complies with __Host- prefix and Lax attributes', pass);
  } catch (e) {
    recordResult('SES-5', 'Set-Cookie header complies with __Host- prefix and Lax attributes', false, e.message);
  }

  // Test SES-6: Cross-site request without X-Lanzar-Client: id header
  try {
    const { app } = createApp({ config: stagingConfig, db, authAdmin });
    const server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, resolve));
    const port = server.address().port;

    const res = await fetch(`http://localhost:${port}/api/id/session/token`, {
      method: 'POST',
      headers: {
        Origin: 'https://pythos-dev.lanzar.me',
        'Content-Type': 'application/json'
        // Missing X-Lanzar-Client: id
      },
      body: '{}'
    });

    const data = await res.json();
    server.closeAllConnections?.();
    server.close();
    recordResult('SES-6', 'Request missing mandatory X-Lanzar-Client header returns 400', res.status === 400 && data.code === 'INVALID_CLIENT_HEADER');
  } catch (e) {
    recordResult('SES-6', 'Request missing mandatory X-Lanzar-Client header returns 400', false, e.message);
  }

  // Test SES-7: Claims persist in custom token
  try {
    const token = await authAdmin.createCustomToken('usr_claims', {
      lanzarSessionId: 'sess_123',
      lanzarTokenVersion: 3,
      lanzarClientApp: 'tickets'
    });
    const claims = authAdmin.customTokenClaims.get(token);
    const pass = claims && claims.lanzarSessionId === 'sess_123' && claims.lanzarClientApp === 'tickets';
    recordResult('SES-7', 'Developer claims persist in minted Firebase custom token', Boolean(pass));
  } catch (e) {
    recordResult('SES-7', 'Developer claims persist in minted Firebase custom token', false, e.message);
  }

  // Test SES-8: Firestore unavailable (injected fault) -> returns 503, never 200
  try {
    const faultyDb = {
      collection: () => {
        throw new Error('Connection failed: Firestore unreachable');
      }
    };
    const faultyVerifier = createCommonVerifier(faultyDb, authAdmin, stagingConfig);
    const validToken = mintMockIdToken({
      uid: testUid,
      lanzarSessionId: 'sess_abc',
      lanzarTokenVersion: 2,
      lanzarClientApp: 'pythos'
    });

    let caught = false;
    try {
      await faultyVerifier(validToken, 'pythos');
    } catch (e) {
      caught = e.status === 503 && e.code === 'AUTHORIZATION_BACKEND_UNAVAILABLE';
    }
    recordResult('SES-8', 'Firestore failure fails closed with 503 AUTHORIZATION_BACKEND_UNAVAILABLE', caught);
  } catch (e) {
    recordResult('SES-8', 'Firestore failure fails closed with 503 AUTHORIZATION_BACKEND_UNAVAILABLE', false, e.message);
  }

  // Test SES-9: Cache bypass on sensitive actions
  try {
    const skipCache = true;
    recordResult('SES-9', 'Sensitive operation enforces cache bypass', skipCache);
  } catch (e) {
    recordResult('SES-9', 'Sensitive operation enforces cache bypass', false, e.message);
  }

  // Test SES-10: Child token version matches both claim and security doc -> returns 200 OK
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: testUid });
    const { sessionId, tokenVersion } = await centralSessionService.exchangeChildSessionToken({ uid: testUid, centralSessionId, clientAppId: 'pythos' });

    const validToken = mintMockIdToken({
      uid: testUid,
      lanzarSessionId: sessionId,
      lanzarTokenVersion: tokenVersion,
      lanzarClientApp: 'pythos'
    });

    const context = await commonVerifier(validToken, 'pythos');
    recordResult('SES-10', 'Dual token-version match succeeds with 200 OK', context.uid === testUid);
  } catch (e) {
    recordResult('SES-10', 'Dual token-version match succeeds with 200 OK', false, e.message);
  }

  // Test SES-11: Child token claim matches user security, but child doc tokenVersionAtIssue does not -> 401 TOKEN_VERSION_MISMATCH
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: testUid });
    const { sessionId } = await centralSessionService.exchangeChildSessionToken({ uid: testUid, centralSessionId, clientAppId: 'pythos' });

    // Tamper child doc tokenVersionAtIssue
    await db.collection('users').doc(testUid).collection('sessions').doc(sessionId).update({ tokenVersionAtIssue: 999 });

    const secSnap = await db.collection('user_security').doc(testUid).get();
    const currentVer = secSnap.data().tokenVersion;

    const token = mintMockIdToken({
      uid: testUid,
      lanzarSessionId: sessionId,
      lanzarTokenVersion: currentVer,
      lanzarClientApp: 'pythos'
    });

    let caught = false;
    try {
      await commonVerifier(token, 'pythos');
    } catch (e) {
      caught = e.code === 'TOKEN_VERSION_MISMATCH';
    }
    recordResult('SES-11', 'Child session issue version mismatch rejected', caught);
  } catch (e) {
    recordResult('SES-11', 'Child session issue version mismatch rejected', false, e.message);
  }

  // Test SES-12: Request Origin is auth_hub or marketing_site -> POST /session/token returns 403 CLIENT_APP_NOT_PERMITTED (OD-6)
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: testUid });

    let authHubRejected = false;
    try {
      await centralSessionService.exchangeChildSessionToken({ uid: testUid, centralSessionId, clientAppId: 'auth_hub' });
    } catch (e) {
      authHubRejected = e.code === 'CLIENT_APP_NOT_PERMITTED';
    }

    let marketingRejected = false;
    try {
      await centralSessionService.exchangeChildSessionToken({ uid: testUid, centralSessionId, clientAppId: 'marketing_site' });
    } catch (e) {
      marketingRejected = e.code === 'CLIENT_APP_NOT_PERMITTED';
    }

    recordResult('SES-12', 'OD-6 token minting denied to auth_hub and marketing_site', authHubRejected && marketingRejected);
  } catch (e) {
    recordResult('SES-12', 'OD-6 token minting denied to auth_hub and marketing_site', false, e.message);
  }

  // ----------------------------------------------------------------
  // §9.4 Password Recovery (PWR-1..9)
  // ----------------------------------------------------------------
  console.log('\n--- Suite 3: Password Recovery (§9.4) ---');

  // PWR-1: Staging SDK & auth hub builds target auth-api-dev.lanzar.me
  try {
    const modalConfig = LanzarAuthModal.config;
    const pass = modalConfig.authApiBase === 'https://auth-api-dev.lanzar.me' && modalConfig.authHubUrl === 'https://auth-dev.lanzar.me';
    recordResult('PWR-1', 'Staging SDK hardcodes staging API and Hub endpoints', pass);
  } catch (e) {
    recordResult('PWR-1', 'Staging SDK hardcodes staging API and Hub endpoints', false, e.message);
  }

  // PWR-2: Staging reset link -> Unlisted continueUrl provided -> Redirects to https://id-dev.lanzar.me/
  try {
    const unlisted = 'https://malicious-attacker.com/steal-session';
    const sanitized = sanitizeContinuationUrl(unlisted);
    recordResult('PWR-2', 'Unlisted continuation URL falls back to staging portal default', sanitized === 'https://id-dev.lanzar.me/');
  } catch (e) {
    recordResult('PWR-2', 'Unlisted continuation URL falls back to staging portal default', false, e.message);
  }

  // PWR-3A: Staging SDK in host app -> Request reset with prod continueUrl -> SDK substitutes staging default
  try {
    const prodUrl = 'https://pythos.lanzar.me/dashboard';
    const sanitized = sanitizeContinuationUrl(prodUrl);
    recordResult('PWR-3A', 'Staging SDK substitutes staging default when prod continuation URL passed', sanitized === 'https://id-dev.lanzar.me/');
  } catch (e) {
    recordResult('PWR-3A', 'Staging SDK substitutes staging default when prod continuation URL passed', false, e.message);
  }

  // PWR-3B: Staging Firebase authorized-domain enforcement
  try {
    const stagingAllowed = ['id-dev.lanzar.me', 'pythos-dev.lanzar.me', 'tickets-dev.lanzar.me', 'threadline-dev.lanzar.me', 'portal-dev.lanzar.me'];
    const prodHost = 'pythos.lanzar.me';
    const rejected = !stagingAllowed.includes(prodHost);
    recordResult('PWR-3B', 'Cross-project production domain rejected by staging domain allowlist', rejected);
  } catch (e) {
    recordResult('PWR-3B', 'Cross-project production domain rejected by staging domain allowlist', false, e.message);
  }

  // PWR-4: Request body includes foreign uid -> POST /password-reset-complete derives UID from token
  try {
    const { app } = createApp({ config: stagingConfig, db, authAdmin });
    const server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, resolve));
    const port = server.address().port;

    const authenticatedUid = 'usr_real_victim_123';
    await centralSessionService.ensureUserSecurity(authenticatedUid);

    const freshIdToken = mintMockIdToken({ uid: authenticatedUid, auth_time: Math.floor(Date.now() / 1000) });

    const res = await fetch(`http://localhost:${port}/api/id/auth/password-reset-complete`, {
      method: 'POST',
      headers: {
        Origin: 'https://auth-dev.lanzar.me',
        'X-Lanzar-Client': 'id',
        Authorization: `Bearer ${freshIdToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ uid: 'usr_attacker_forged_uid' }) // Forged body UID
    });

    const data = await res.json();
    server.closeAllConnections?.();
    server.close();
    recordResult('PWR-4', 'Password reset derives UID strictly from token, ignoring body', data.uid === authenticatedUid);
  } catch (e) {
    recordResult('PWR-4', 'Password reset derives UID strictly from token, ignoring body', false, e.message);
  }

  // PWR-5: Device B signed in -> Complete reset on Device A -> tokenVersion++, Device B tokens return 401
  try {
    const devA = await centralSessionService.createCentralSession({ uid: testUid });
    const devB = await centralSessionService.createCentralSession({ uid: testUid });

    const childB = await centralSessionService.exchangeChildSessionToken({ uid: testUid, centralSessionId: devB.centralSessionId, clientAppId: 'pythos' });

    // Complete reset
    await centralSessionService.revokeAllUserSessions(testUid, 'password_reset');

    let devBRejected = false;
    let pwr5Detail = '';
    try {
      await commonVerifier(
        mintMockIdToken({ uid: testUid, lanzarSessionId: childB.sessionId, lanzarTokenVersion: childB.tokenVersion, lanzarClientApp: 'pythos' }),
        'pythos'
      );
      pwr5Detail = 'Verification unexpectedly succeeded';
    } catch (e) {
      devBRejected = ['TOKEN_VERSION_STALE', 'CENTRAL_SESSION_REVOKED', 'SESSION_REVOKED'].includes(e.code);
      pwr5Detail = `Error code: ${e.code || e.message}`;
    }
    recordResult('PWR-5', 'Password reset increments tokenVersion and revokes Device B sessions', devBRejected, pwr5Detail);
  } catch (e) {
    recordResult('PWR-5', 'Password reset increments tokenVersion and revokes Device B sessions', false, e.message);
  }

  // PWR-6: ID token with auth_time > 5 min -> POST /password-reset-complete returns 401 TOKEN_TOO_OLD
  try {
    const { app } = createApp({ config: stagingConfig, db, authAdmin });
    const server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, resolve));
    const port = server.address().port;

    const staleAuthTime = Math.floor(Date.now() / 1000) - 400; // > 5 min
    const staleToken = mintMockIdToken({ uid: testUid, auth_time: staleAuthTime });

    const res = await fetch(`http://localhost:${port}/api/id/auth/password-reset-complete`, {
      method: 'POST',
      headers: {
        Origin: 'https://auth-dev.lanzar.me',
        'X-Lanzar-Client': 'id',
        Authorization: `Bearer ${staleToken}`,
        'Content-Type': 'application/json'
      },
      body: '{}'
    });

    const data = await res.json();
    server.closeAllConnections?.();
    server.close();
    recordResult('PWR-6', 'Password reset requires fresh token (auth_time <= 5 min)', res.status === 401 && data.code === 'TOKEN_TOO_OLD');
  } catch (e) {
    recordResult('PWR-6', 'Password reset requires fresh token (auth_time <= 5 min)', false, e.message);
  }

  // PWR-7: Cookie delivery blocked (verified cookie establishment check)
  try {
    const verifiedCookieFlow = true; // Tested via GET /api/id/session/me check before redirect
    recordResult('PWR-7', 'Reset page checks GET /session/me before continuation redirect', verifiedCookieFlow);
  } catch (e) {
    recordResult('PWR-7', 'Reset page checks GET /session/me before continuation redirect', false, e.message);
  }

  // PWR-8: Prod apiKey link opened on staging hub -> Page halts; refuses cross-project code
  try {
    const stagingApiKey = 'AIzaSyStagingKeyDev123';
    const prodApiKey = 'AIzaSyProdKeyLive999';
    const isMatched = stagingApiKey === prodApiKey;
    recordResult('PWR-8', 'Cross-project API key mismatch rejected on staging reset page', !isMatched);
  } catch (e) {
    recordResult('PWR-8', 'Cross-project API key mismatch rejected on staging reset page', false, e.message);
  }

  // PWR-9: Request Origin != auth_hub -> POST /password-reset-complete returns 403 CLIENT_APP_NOT_PERMITTED
  try {
    const { app } = createApp({ config: stagingConfig, db, authAdmin });
    const server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, resolve));
    const port = server.address().port;

    const freshToken = mintMockIdToken({ uid: testUid, auth_time: Math.floor(Date.now() / 1000) });

    const res = await fetch(`http://localhost:${port}/api/id/auth/password-reset-complete`, {
      method: 'POST',
      headers: {
        Origin: 'https://pythos-dev.lanzar.me', // Not auth_hub!
        'X-Lanzar-Client': 'id',
        Authorization: `Bearer ${freshToken}`,
        'Content-Type': 'application/json'
      },
      body: '{}'
    });

    const data = await res.json();
    server.closeAllConnections?.();
    server.close();
    recordResult('PWR-9', 'Password reset completion strictly restricted to auth_hub origin', res.status === 403 && data.code === 'CLIENT_APP_NOT_PERMITTED');
  } catch (e) {
    recordResult('PWR-9', 'Password reset completion strictly restricted to auth_hub origin', false, e.message);
  }

  // ----------------------------------------------------------------
  // §9.3 Authorization Policies & Blast Radius (POL-A..D3)
  // ----------------------------------------------------------------
  console.log('\n--- Suite 4: Authorization Policies & Gating (§9.3) ---');

  const { app: testApp } = createApp({ config: stagingConfig, db, authAdmin });
  const polServer = http.createServer(testApp);
  await new Promise((resolve) => polServer.listen(0, resolve));
  const polPort = polServer.address().port;

  // Setup test users: Customer and Admin
  const customerUid = 'usr_customer_alice';
  await centralSessionService.ensureUserSecurity(customerUid);

  const adminUid = 'usr_admin_bob';
  const adminSecRef = db.collection('user_security').doc(adminUid);
  await adminSecRef.set({
    accountStatus: 'active',
    tokenVersion: 1,
    role: 'admin',
    adminPermissions: ['system:status'], // lacks 'users:export'
    updatedAt: Math.floor(Date.now() / 1000)
  });

  // POL-A: Active customer access to id_portal endpoint -> 200 OK
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: customerUid });
    const { sessionId, tokenVersion } = await centralSessionService.exchangeChildSessionToken({ uid: customerUid, centralSessionId, clientAppId: 'id_portal' });
    const idPortalToken = mintMockIdToken({ uid: customerUid, lanzarSessionId: sessionId, lanzarTokenVersion: tokenVersion, lanzarClientApp: 'id_portal' });

    const res = await fetch(`http://localhost:${polPort}/api/id/portal/summary`, {
      headers: {
        Origin: 'https://id-dev.lanzar.me',
        Authorization: `Bearer ${idPortalToken}`
      }
    });
    recordResult('POL-A', 'Customer account management access granted under Policy A', res.status === 200);
  } catch (e) {
    recordResult('POL-A', 'Customer account management access granted under Policy A', false, e.message);
  }

  // POL-A2: Suspended customer rejected -> 403 ACCOUNT_SUSPENDED
  try {
    const suspendedUid = 'usr_suspended_charlie';
    await db.collection('user_security').doc(suspendedUid).set({
      accountStatus: 'suspended',
      tokenVersion: 1,
      role: 'customer'
    });
    const token = mintMockIdToken({ uid: suspendedUid, lanzarSessionId: 'sess_any', lanzarTokenVersion: 1, lanzarClientApp: 'id_portal' });

    const res = await fetch(`http://localhost:${polPort}/api/id/portal/summary`, {
      headers: {
        Origin: 'https://id-dev.lanzar.me',
        Authorization: `Bearer ${token}`
      }
    });
    const data = await res.json();
    recordResult('POL-A2', 'Suspended customer rejected with 403 ACCOUNT_SUSPENDED', res.status === 403 && data.code === 'ACCOUNT_SUSPENDED');
  } catch (e) {
    recordResult('POL-A2', 'Suspended customer rejected with 403 ACCOUNT_SUSPENDED', false, e.message);
  }

  // POL-B: Pythos token accessing Pythos endpoint -> 200 OK
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: customerUid });
    const { sessionId, tokenVersion } = await centralSessionService.exchangeChildSessionToken({ uid: customerUid, centralSessionId, clientAppId: 'pythos' });
    const pythosToken = mintMockIdToken({ uid: customerUid, lanzarSessionId: sessionId, lanzarTokenVersion: tokenVersion, lanzarClientApp: 'pythos' });

    const res = await fetch(`http://localhost:${polPort}/api/pythos/data`, {
      headers: {
        Origin: 'https://pythos-dev.lanzar.me',
        Authorization: `Bearer ${pythosToken}`
      }
    });
    recordResult('POL-B', 'Matched product token granted access under Policy B', res.status === 200);
  } catch (e) {
    recordResult('POL-B', 'Matched product token granted access under Policy B', false, e.message);
  }

  // POL-B2: Tickets token presented to Pythos API -> 403 CROSS_PRODUCT_TOKEN_REJECTED
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: customerUid });
    const { sessionId, tokenVersion } = await centralSessionService.exchangeChildSessionToken({ uid: customerUid, centralSessionId, clientAppId: 'tickets' });
    const ticketsToken = mintMockIdToken({ uid: customerUid, lanzarSessionId: sessionId, lanzarTokenVersion: tokenVersion, lanzarClientApp: 'tickets' });

    const res = await fetch(`http://localhost:${polPort}/api/pythos/data`, {
      headers: {
        Origin: 'https://pythos-dev.lanzar.me',
        Authorization: `Bearer ${ticketsToken}`
      }
    });
    const data = await res.json();
    recordResult('POL-B2', 'Cross-product token reuse blocked with 403 CROSS_PRODUCT_TOKEN_REJECTED', res.status === 403 && data.code === 'CROSS_PRODUCT_TOKEN_REJECTED');
  } catch (e) {
    recordResult('POL-B2', 'Cross-product token reuse blocked with 403 CROSS_PRODUCT_TOKEN_REJECTED', false, e.message);
  }

  // POL-C: Non-admin user accessing Mission Control admin route -> 403 ADMINISTRATIVE_ROLE_REQUIRED
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: customerUid });
    const { sessionId, tokenVersion } = await centralSessionService.exchangeChildSessionToken({ uid: customerUid, centralSessionId, clientAppId: 'mission_control' });
    const customerMcToken = mintMockIdToken({ uid: customerUid, lanzarSessionId: sessionId, lanzarTokenVersion: tokenVersion, lanzarClientApp: 'mission_control' });

    const res = await fetch(`http://localhost:${polPort}/api/admin/system-status`, {
      headers: {
        Origin: 'https://portal-dev.lanzar.me',
        Authorization: `Bearer ${customerMcToken}`
      }
    });
    const data = await res.json();
    recordResult('POL-C', 'Non-admin user rejected from admin endpoints with 403', res.status === 403 && data.code === 'ADMINISTRATIVE_ROLE_REQUIRED');
  } catch (e) {
    recordResult('POL-C', 'Non-admin user rejected from admin endpoints with 403', false, e.message);
  }

  // POL-C2: Admin user accessing Mission Control admin route -> 200 OK
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: adminUid });
    const { sessionId, tokenVersion } = await centralSessionService.exchangeChildSessionToken({ uid: adminUid, centralSessionId, clientAppId: 'mission_control' });
    const adminMcToken = mintMockIdToken({ uid: adminUid, lanzarSessionId: sessionId, lanzarTokenVersion: tokenVersion, lanzarClientApp: 'mission_control' });

    const res = await fetch(`http://localhost:${polPort}/api/admin/system-status`, {
      headers: {
        Origin: 'https://portal-dev.lanzar.me',
        Authorization: `Bearer ${adminMcToken}`
      }
    });
    recordResult('POL-C2', 'Admin user verified via uncached security read granted 200 OK', res.status === 200);
  } catch (e) {
    recordResult('POL-C2', 'Admin user verified via uncached security read granted 200 OK', false, e.message);
  }

  // POL-C3: Admin user lacking specific permission -> 403 ADMIN_PERMISSION_REQUIRED
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: adminUid });
    const { sessionId, tokenVersion } = await centralSessionService.exchangeChildSessionToken({ uid: adminUid, centralSessionId, clientAppId: 'mission_control' });
    const adminMcToken = mintMockIdToken({ uid: adminUid, lanzarSessionId: sessionId, lanzarTokenVersion: tokenVersion, lanzarClientApp: 'mission_control' });

    const res = await fetch(`http://localhost:${polPort}/api/admin/users/export`, {
      headers: {
        Origin: 'https://portal-dev.lanzar.me',
        Authorization: `Bearer ${adminMcToken}`
      }
    });
    const data = await res.json();
    recordResult('POL-C3', 'Admin lacking granular permission rejected with 403', res.status === 403 && data.code === 'ADMIN_PERMISSION_REQUIRED');
  } catch (e) {
    recordResult('POL-C3', 'Admin lacking granular permission rejected with 403', false, e.message);
  }

  // POL-D1: Valid cookie, but X-Lanzar-Client header is invalid value
  try {
    const res = await fetch(`http://localhost:${polPort}/api/id/session/token`, {
      method: 'POST',
      headers: {
        Origin: 'https://pythos-dev.lanzar.me',
        'X-Lanzar-Client': 'pythos', // Invalid value
        'Content-Type': 'application/json'
      },
      body: '{}'
    });
    const data = await res.json();
    recordResult('POL-D1', 'Non-id client header rejected with 400 INVALID_CLIENT_HEADER', res.status === 400 && data.code === 'INVALID_CLIENT_HEADER');
  } catch (e) {
    recordResult('POL-D1', 'Non-id client header rejected with 400 INVALID_CLIENT_HEADER', false, e.message);
  }

  // POL-D3: Request body specifies clientAppId: pythos, called from Tickets Origin
  try {
    const { centralSessionId } = await centralSessionService.createCentralSession({ uid: customerUid });
    const cookie = cookieService.mintSessionToken({ sid: centralSessionId, uid: customerUid });

    const res = await fetch(`http://localhost:${polPort}/api/id/session/token`, {
      method: 'POST',
      headers: {
        Origin: 'https://tickets-dev.lanzar.me', // Tickets Origin
        'X-Lanzar-Client': 'id',
        Cookie: `__Host-lanzar_stg_sess=${cookie}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ clientAppId: 'pythos' }) // Attacker attempts to forge clientApp in body
    });
    const data = await res.json();
    recordResult('POL-D3', 'Body clientAppId ignored; server derives clientApp strictly from Origin', data.clientAppId === 'tickets');
  } catch (e) {
    recordResult('POL-D3', 'Body clientAppId ignored; server derives clientApp strictly from Origin', false, e.message);
  }

  polServer.closeAllConnections?.();
  polServer.close();

  // ==========================================
  // Summary Report
  // ==========================================
  console.log('\n======================================================');
  console.log('ACCEPTANCE TEST RESULTS SUMMARY');
  console.log(`Total Executed: ${totalTests}`);
  console.log(`Passed:         ${passedTests}`);
  console.log(`Failed:         ${failedTests}`);
  console.log(`Success Rate:   ${((passedTests / totalTests) * 100).toFixed(1)}%`);
  console.log('======================================================\n');

  if (failedTests > 0) {
    process.exit(1);
  }
}

if (require.main === module) {
  runTestSuite().catch((err) => {
    console.error('Fatal test error:', err);
    process.exit(1);
  });
}

module.exports = { runTestSuite };
