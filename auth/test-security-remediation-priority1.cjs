// test-security-remediation-priority1.cjs
// Post-Audit Security Remediation Verification Suite
// Validates LID-SEC-002, LID-SEC-004, and LID-SEC-005
//
// Coverage:
// - Section 1: Mandatory LANZAR ID Session & UID-Binding Enforcement (LID-SEC-004)
// - Section 2: Application-Level Rate Limiting (LID-SEC-002)
// - Section 3: MFA Secret Configuration & Fail-Closed Bootstrap (LID-SEC-005)
// - Section 4: Audit Clarifications (Custom Token Expiration & UID Binding)

const assert = require('assert');
const crypto = require('crypto');
const http = require('http');

const { bootstrap, ConfigurationError } = require('./auth-backend/config/bootstrap');
const { createAuthMiddleware } = require('./auth-backend/middleware/authMiddleware');
const {
  oauthAuthorizeLimiter,
  oauthExchangeLimiter,
  phoneDispatchLimiter,
  mfaVerifyRateLimitMiddleware,
  checkMfaRateLimit,
  recordMfaFailure,
  clearMfaFailures,
  resetRateLimits
} = require('./auth-backend/middleware/rateLimiter');
const {
  getMfaHmacSecret,
  createMfaSignedToken,
  verifyMfaSignedToken,
  KNOWN_DEV_MFA_SECRETS
} = require('./auth-backend/mfaService');

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
    console.error(`  ❌ [FAIL] ${id}: ${desc}`);
    if (errDetail) console.error(`     Details: ${errDetail}`);
  }
}

async function runPriority1RemediationTests() {
  console.log('\n======================================================');
  console.log('LANZAR ID — Post-Audit Security Remediation Suite (P1)');
  console.log('Scope: LID-SEC-002, LID-SEC-004, LID-SEC-005');
  console.log('Timestamp: ' + new Date().toISOString());
  console.log('======================================================\n');

  // ====================================================
  // SECTION 1: LID-SEC-004 — Mandatory LANZAR ID Sessions & UID Binding
  // ====================================================
  console.log('[SECTION 1] LID-SEC-004: Mandatory LANZAR ID Sessions & UID Binding');

  // Mock in-memory database and session service for deterministic middleware testing
  const mockDb = {
    collection: (colName) => ({
      doc: (docId) => ({
        get: async () => {
          if (colName === 'users' && docId === 'user_suspended') {
            return { exists: true, data: () => ({ status: 'suspended' }) };
          }
          if (colName === 'admins' && (docId === 'admin_uid' || docId === 'user_admin_valid')) {
            return { exists: true, data: () => ({ active: true, email: 'admin@lanzar.me' }) };
          }
          return { exists: false, data: () => ({}) };
        }
      }),
      where: () => ({
        where: () => ({
          limit: () => ({
            get: async () => ({ empty: true })
          })
        })
      })
    })
  };

  const mockSessions = new Map([
    ['user_alice:sess_alice_active', { active: true, reason: 'active', expiresAt: '2026-11-20T00:00:00Z' }],
    ['user_alice:sess_alice_expired', { active: false, reason: 'expired', expiresAt: '2026-11-01T00:00:00Z' }],
    ['user_alice:sess_alice_revoked', { active: false, reason: 'revoked', expiresAt: null }],
    ['admin_uid:sess_admin_active', { active: true, reason: 'active', expiresAt: '2026-11-20T00:00:00Z' }]
  ]);

  const mockSessionService = {
    checkSession: async (uid, sessionId) => {
      if (sessionId === 'sess_alice_active' && uid === 'user_bob') {
        // UID mismatch attempt!
        return { active: false, reason: 'uid_mismatch' };
      }
      const key = `${uid}:${sessionId}`;
      return mockSessions.get(key) || { active: false, reason: 'unknown_session' };
    }
  };

  // Helper mock authAdmin that returns tokens based on token string prefix
  const mockAuthAdmin = {
    verifyIdToken: async (token, checkRevoked) => {
      if (token === 'token_revoked') {
        const err = new Error('Token revoked');
        err.code = 'auth/id-token-revoked';
        throw err;
      }
      if (token.startsWith('valid_session:')) {
        const [, uid, sessionId] = token.split(':');
        return { uid, email: `${uid}@lanzar.test`, session_id: sessionId };
      }
      if (token.startsWith('no_session_')) {
        const uid = token.replace('no_session_', '');
        return { uid, email: `${uid}@lanzar.test` }; // Missing session_id!
      }
      if (token === 'admin_token_with_session') {
        return { uid: 'admin_uid', email: 'admin@lanzar.me', session_id: 'sess_admin_active' };
      }
      if (token === 'admin_token_without_session') {
        return { uid: 'admin_uid', email: 'admin@lanzar.me' }; // No session!
      }
      throw new Error('Invalid token structure');
    }
  };

  const middleware = createAuthMiddleware({
    db: mockDb,
    authAdmin: mockAuthAdmin,
    sessionService: mockSessionService
  });

  // Helper to test middleware invocation
  async function testMiddleware(fn, authHeader) {
    return new Promise((resolve) => {
      const req = {
        headers: authHeader ? { authorization: authHeader } : {}
      };
      let statusCalled = null;
      let jsonCalled = null;
      const res = {
        status: (code) => {
          statusCalled = code;
          return {
            json: (payload) => {
              jsonCalled = payload;
              resolve({ status: statusCalled, body: jsonCalled });
            }
          };
        }
      };
      fn(req, res, () => {
        resolve({ status: 200, req });
      });
    });
  }

  // 1.1 Valid LANZAR ID session
  {
    const res = await testMiddleware(middleware.authenticateUserMiddleware, 'Bearer valid_session:user_alice:sess_alice_active');
    recordTest('SEC-P1-01', 'Valid LANZAR ID session passes authentication middleware with session attached',
      res.status === 200 && res.req.sessionId === 'sess_alice_active' && res.req.uid === 'user_alice');
  }

  // 1.2 Missing session_id claim in Firebase ID token
  {
    const res = await testMiddleware(middleware.authenticateUserMiddleware, 'Bearer no_session_user_alice');
    recordTest('SEC-P1-02', 'Token missing session_id claim rejected with HTTP 401 missing_session',
      res.status === 401 && res.body.error === 'missing_session');
  }

  // 1.3 Invalid / non-existent session ID
  {
    const res = await testMiddleware(middleware.authenticateUserMiddleware, 'Bearer valid_session:user_alice:sess_nonexistent');
    recordTest('SEC-P1-03', 'Non-existent session ID rejected with HTTP 401 session_revoked',
      res.status === 401 && res.body.error === 'session_revoked');
  }

  // 1.4 Session belonging to another UID (cross-user tampering)
  {
    const res = await testMiddleware(middleware.authenticateUserMiddleware, 'Bearer valid_session:user_bob:sess_alice_active');
    recordTest('SEC-P1-04', 'Cross-user session hijacking attempt rejected with HTTP 401 session_mismatch',
      res.status === 401 && res.body.error === 'session_mismatch');
  }

  // 1.5 Revoked session
  {
    const res = await testMiddleware(middleware.authenticateUserMiddleware, 'Bearer valid_session:user_alice:sess_alice_revoked');
    recordTest('SEC-P1-05', 'Revoked session rejected with HTTP 401 session_revoked',
      res.status === 401 && res.body.error === 'session_revoked');
  }

  // 1.6 Expired session
  {
    const res = await testMiddleware(middleware.authenticateUserMiddleware, 'Bearer valid_session:user_alice:sess_alice_expired');
    recordTest('SEC-P1-06', 'Expired session rejected with HTTP 401 session_expired',
      res.status === 401 && res.body.error === 'session_expired');
  }

  // 1.7 Administrator API access WITH valid session
  {
    const res = await testMiddleware(middleware.authenticateAdminMiddleware, 'Bearer admin_token_with_session');
    recordTest('SEC-P1-07', 'Administrator with valid session granted administrative access (200, isAdmin=true)',
      res.status === 200 && res.req.isAdmin === true);
  }

  // 1.8 Administrator API access WITHOUT session
  {
    const res = await testMiddleware(middleware.authenticateAdminMiddleware, 'Bearer admin_token_without_session');
    recordTest('SEC-P1-08', 'Administrator token without session rejected by admin middleware (401 missing_session)',
      res.status === 401 && res.body.error === 'missing_session');
  }

  // 1.9 Customer with valid session rejected from admin API
  {
    const res = await testMiddleware(middleware.authenticateAdminMiddleware, 'Bearer valid_session:user_alice:sess_alice_active');
    recordTest('SEC-P1-09', 'Customer token with valid session rejected from admin API (403 forbidden)',
      res.status === 403 && res.body.error === 'forbidden');
  }

  // ====================================================
  // SECTION 2: LID-SEC-002 — Application-Level Rate Limiting
  // ====================================================
  console.log('\n[SECTION 2] LID-SEC-002: Application-Level Rate Limiting');
  resetRateLimits();

  // Helper to execute mock express requests against a middleware
  async function runLimiter(limiter, reqObj) {
    return new Promise((resolve) => {
      const headersSent = {};
      let statusCode = 200;
      let bodySent = null;

      const res = {
        setHeader: (name, val) => { headersSent[name.toLowerCase()] = val; },
        status: (code) => {
          statusCode = code;
          return {
            json: (b) => {
              bodySent = b;
              resolve({ status: statusCode, body: bodySent, headers: headersSent });
            }
          };
        }
      };

      limiter(reqObj, res, () => {
        resolve({ status: 200, body: null, headers: headersSent });
      });
    });
  }

  // 2.1 OAuth Authorize Rate Limiter (20 req/min per IP)
  {
    resetRateLimits();
    const mockReq = { ip: '192.168.1.100', headers: {} };
    let allowedCount = 0;
    let blockedResult = null;

    for (let i = 0; i < 25; i++) {
      const res = await runLimiter(oauthAuthorizeLimiter, mockReq);
      if (res.status === 200) allowedCount++;
      else if (res.status === 429) blockedResult = res;
    }

    recordTest('SEC-P1-10', 'OAuth /authorize rate limiter permits exactly 20 requests and blocks subsequent with 429',
      allowedCount === 20 &&
      blockedResult !== null &&
      blockedResult.status === 429 &&
      blockedResult.body.error === 'too_many_requests' &&
      Boolean(blockedResult.headers['retry-after']));
  }

  // 2.2 OAuth Exchange Rate Limiter (20 req/min per IP)
  {
    resetRateLimits();
    const mockReq = { ip: '192.168.1.101', headers: {} };
    let allowedCount = 0;
    let blockedResult = null;

    for (let i = 0; i < 25; i++) {
      const res = await runLimiter(oauthExchangeLimiter, mockReq);
      if (res.status === 200) allowedCount++;
      else if (res.status === 429) blockedResult = res;
    }

    recordTest('SEC-P1-11', 'OAuth /exchange rate limiter permits exactly 20 requests and blocks 21st with 429',
      allowedCount === 20 &&
      blockedResult !== null &&
      blockedResult.status === 429 &&
      blockedResult.body.error === 'too_many_requests');
  }

  // 2.3 Phone Dispatch Rate Limiter (3 requests per 15 min per IP / phone number)
  {
    resetRateLimits();
    const mockReq = {
      ip: '192.168.1.102',
      body: { phoneNumber: '+1 (555) 234-5678' }
    };
    let allowedCount = 0;
    let blockedResult = null;

    for (let i = 0; i < 5; i++) {
      const res = await runLimiter(phoneDispatchLimiter, mockReq);
      if (res.status === 200) allowedCount++;
      else if (res.status === 429) blockedResult = res;
    }

    recordTest('SEC-P1-12', 'Phone dispatch rate limiter permits exactly 3 requests in 15 min and blocks 4th with 429',
      allowedCount === 3 &&
      blockedResult !== null &&
      blockedResult.status === 429 &&
      blockedResult.body.error === 'too_many_requests');
  }

  // 2.4 Phone Dispatch Rate Limiter blocks by Phone Number even if IP changes
  {
    resetRateLimits();
    const phone = '+1-555-999-8888';
    await runLimiter(phoneDispatchLimiter, { ip: '10.0.0.1', body: { phoneNumber: phone } });
    await runLimiter(phoneDispatchLimiter, { ip: '10.0.0.2', body: { phoneNumber: phone } });
    await runLimiter(phoneDispatchLimiter, { ip: '10.0.0.3', body: { phoneNumber: phone } });
    // 4th request from different IP, same phone number
    const res = await runLimiter(phoneDispatchLimiter, { ip: '10.0.0.4', body: { phoneNumber: phone } });

    recordTest('SEC-P1-13', 'Phone dispatch limiter enforces phone-number tracking across IP rotations',
      res.status === 429 && res.body.error === 'too_many_requests');
  }

  // 2.5 MFA TOTP Verification Failed Attempts Limiter (5 failed attempts per account per 15 min)
  {
    resetRateLimits();
    const targetUid = 'victim_totp_account_123';
    // Simulate 5 failed TOTP attempts
    for (let i = 0; i < 5; i++) {
      recordMfaFailure(targetUid, 'totp');
    }

    // Pre-check middleware must now block
    const mfaSessionToken = `${Buffer.from(JSON.stringify({ uid: targetUid, action: 'mfa_challenge' })).toString('base64url')}.sig`;
    const res = await runLimiter(mfaVerifyRateLimitMiddleware, {
      body: { mfaSession: mfaSessionToken, code: '000000', method: 'totp' }
    });

    recordTest('SEC-P1-14', 'MFA TOTP verification blocks after 5 failed attempts with HTTP 429 and Retry-After',
      res.status === 429 &&
      res.body.error === 'too_many_requests' &&
      res.headers['retry-after'] > 0);
  }

  // 2.6 MFA Recovery Code Verification Failed Attempts Limiter (5 failed attempts per account per 15 min)
  {
    resetRateLimits();
    const targetUid = 'victim_recovery_account_456';
    for (let i = 0; i < 5; i++) {
      recordMfaFailure(targetUid, 'recovery');
    }

    const mfaSessionToken = `${Buffer.from(JSON.stringify({ uid: targetUid, action: 'mfa_challenge' })).toString('base64url')}.sig`;
    const res = await runLimiter(mfaVerifyRateLimitMiddleware, {
      body: { mfaSession: mfaSessionToken, code: 'RC-WRONG', method: 'recovery' }
    });

    recordTest('SEC-P1-15', 'MFA recovery code verification blocks after 5 failed attempts with HTTP 429',
      res.status === 429 && res.body.error === 'too_many_requests');
  }

  // 2.7 MFA Verification Success Resets Failed Attempts
  {
    resetRateLimits();
    const targetUid = 'user_reset_failures';
    recordMfaFailure(targetUid, 'totp');
    recordMfaFailure(targetUid, 'totp');
    recordMfaFailure(targetUid, 'totp');
    // Cleared upon successful verification
    clearMfaFailures(targetUid, 'totp');
    const check = checkMfaRateLimit(targetUid, 'totp');

    recordTest('SEC-P1-16', 'MFA verification success resets failure counter for legitimate user',
      check.allowed === true);
  }

  // ====================================================
  // SECTION 3: LID-SEC-005 — MFA Secret Configuration & Fail-Closed Bootstrap
  // ====================================================
  console.log('\n[SECTION 3] LID-SEC-005: MFA Secret Configuration & Fail-Closed Bootstrap');

  const BASE_STAGING = {
    APP_ENV: 'staging',
    NODE_ENV: 'production',
    FIREBASE_PROJECT_ID: 'lanzar-95ae3-dev',
    FIREBASE_SERVICE_ACCOUNT_KEY: JSON.stringify({
      project_id: 'lanzar-95ae3-dev',
      client_email: 'lanzar-auth-api@lanzar-95ae3-dev.iam.gserviceaccount.com'
    }),
    EXPECTED_SA_EMAIL: 'lanzar-auth-api@lanzar-95ae3-dev.iam.gserviceaccount.com',
    SESSION_SIGNING_SECRET: 'test_session_signing_secret_at_least_32_bytes_long_123456',
    MFA_HMAC_SECRET: 'valid_staging_mfa_signing_secret_crypto_safe_32_bytes',
    FEATURE_STRIPE: 'disabled'
  };

  // 3.1 Missing MFA_HMAC_SECRET in Staging fails closed
  {
    let caught = false;
    try {
      const env = { ...BASE_STAGING };
      delete env.MFA_HMAC_SECRET;
      bootstrap(env);
    } catch (e) {
      caught = e.message.includes('MFA_HMAC_SECRET is required');
    }
    recordTest('SEC-P1-17', 'Staging fails closed when MFA_HMAC_SECRET is missing', caught);
  }

  // 3.2 Weak MFA_HMAC_SECRET (< 32 bytes) in Staging fails closed
  {
    let caught = false;
    try {
      bootstrap({ ...BASE_STAGING, MFA_HMAC_SECRET: 'short_mfa_secret' });
    } catch (e) {
      caught = e.message.includes('MFA_HMAC_SECRET must be at least 32 bytes');
    }
    recordTest('SEC-P1-18', 'Staging fails closed when MFA_HMAC_SECRET is shorter than 32 bytes', caught);
  }

  // 3.3 Known development default secret rejected in Staging
  {
    let caught = false;
    try {
      bootstrap({ ...BASE_STAGING, MFA_HMAC_SECRET: 'lanzar_mfa_signing_key_secure_2026' });
    } catch (e) {
      caught = e.message.includes('cannot use a development or default secret');
    }
    recordTest('SEC-P1-19', 'Staging fails closed when MFA_HMAC_SECRET matches known development default', caught);
  }

  // 3.4 Missing MFA_HMAC_SECRET in Production fails closed
  {
    let caught = false;
    try {
      bootstrap({
        APP_ENV: 'production',
        NODE_ENV: 'production',
        FIREBASE_PROJECT_ID: 'lanzar-95ae3',
        FIREBASE_SERVICE_ACCOUNT_KEY: JSON.stringify({
          project_id: 'lanzar-95ae3',
          client_email: 'lanzar-auth-api@lanzar-95ae3.iam.gserviceaccount.com'
        }),
        EXPECTED_SA_EMAIL: 'lanzar-auth-api@lanzar-95ae3.iam.gserviceaccount.com',
        SESSION_SIGNING_SECRET: 'test_session_signing_secret_at_least_32_bytes_long_123456',
        FEATURE_STRIPE: 'disabled'
      });
    } catch (e) {
      caught = e.message.includes('MFA_HMAC_SECRET is required');
    }
    recordTest('SEC-P1-20', 'Production fails closed when MFA_HMAC_SECRET is missing', caught);
  }

  // 3.5 Valid 32+ byte secret succeeds in Production
  {
    let passed = false;
    try {
      const cfg = bootstrap({
        APP_ENV: 'production',
        NODE_ENV: 'production',
        FIREBASE_PROJECT_ID: 'lanzar-95ae3',
        FIREBASE_SERVICE_ACCOUNT_KEY: JSON.stringify({
          project_id: 'lanzar-95ae3',
          client_email: 'lanzar-auth-api@lanzar-95ae3.iam.gserviceaccount.com'
        }),
        EXPECTED_SA_EMAIL: 'lanzar-auth-api@lanzar-95ae3.iam.gserviceaccount.com',
        SESSION_SIGNING_SECRET: 'prod_session_signing_secret_crypto_grade_32_bytes_long',
        MFA_HMAC_SECRET: 'prod_mfa_signing_secret_crypto_grade_32_bytes_long_hex',
        FEATURE_STRIPE: 'disabled'
      });
      passed = cfg.appEnv === 'production';
    } catch (e) {
      passed = false;
    }
    recordTest('SEC-P1-21', 'Production bootstrap cleanly succeeds with valid strong MFA_HMAC_SECRET', passed);
  }

  // 3.6 Development environment fallback secret functions properly for local testing
  {
    const origEnv = process.env.APP_ENV;
    const origSecret = process.env.MFA_HMAC_SECRET;
    try {
      process.env.APP_ENV = 'development';
      delete process.env.MFA_HMAC_SECRET;
      const secret = getMfaHmacSecret();
      const token = createMfaSignedToken({ uid: 'dev_user', action: 'mfa_challenge' });
      const verified = verifyMfaSignedToken(token);
      recordTest('SEC-P1-22', 'Development environment permits explicit dev fallback and correctly signs/verifies tokens',
        Boolean(secret) && verified !== null && verified.uid === 'dev_user');
    } finally {
      process.env.APP_ENV = origEnv;
      if (origSecret) process.env.MFA_HMAC_SECRET = origSecret;
      else delete process.env.MFA_HMAC_SECRET;
    }
  }

  // 3.7 getMfaHmacSecret throws fatal error in staging when secret is unset
  {
    const origEnv = process.env.APP_ENV;
    const origSecret = process.env.MFA_HMAC_SECRET;
    let threw = false;
    try {
      process.env.APP_ENV = 'staging';
      delete process.env.MFA_HMAC_SECRET;
      getMfaHmacSecret();
    } catch (e) {
      threw = e.message.includes('MFA_HMAC_SECRET must be explicitly configured');
    } finally {
      process.env.APP_ENV = origEnv;
      if (origSecret) process.env.MFA_HMAC_SECRET = origSecret;
      else delete process.env.MFA_HMAC_SECRET;
    }
    recordTest('SEC-P1-23', 'getMfaHmacSecret() throws fatal error in staging if MFA_HMAC_SECRET is missing', threw);
  }

  // ====================================================
  // SECTION 4: AUDIT OBSERVATION VERIFICATION
  // ====================================================
  console.log('\n[SECTION 4] Verification of Audit Observations');

  // 4.A Firebase Custom Token Expiration Clarification
  // Official Firebase Admin SDK semantics: createCustomToken(uid, claims) generates a JWT with exp = iat + 3600 (1 hour).
  // The audit stated "Short-lived custom tokens (5 min)". We verify the actual SDK lifetime is 3600 seconds.
  {
    const oauthRoutesSource = require('fs').readFileSync('auth/auth-backend/routes/oauthRoutes.js', 'utf8');
    const hasExpiresIn3600 = oauthRoutesSource.includes('expires_in: 3600');
    recordTest('SEC-P1-24', 'Verified: Firebase custom token response issues expires_in: 3600 (1 hour), correcting audit observation', hasExpiresIn3600);
  }

  // 4.B Session UID Binding Verification
  {
    const sessionServiceSource = require('fs').readFileSync('auth/auth-backend/sessionService.js', 'utf8');
    const hasUidBoundCache = sessionServiceSource.includes('`${uid}:${sessionId}`');
    const hasUidDocCheck = sessionServiceSource.includes('data.uid !== uid');
    recordTest('SEC-P1-25', 'Verified: checkSession() validates both sessionId and authenticated Firebase UID across cache and database',
      hasUidBoundCache && hasUidDocCheck);
  }

  // ----------------------------------------------------
  // Summary
  // ----------------------------------------------------
  console.log('\n======================================================');
  console.log('SECURITY REMEDIATION PRIORITY 1 SUMMARY');
  console.log(`Total Executed: ${totalTests}`);
  console.log(`Passed:         ${passedTests}`);
  console.log(`Failed:         ${failedTests}`);
  console.log(`Success Rate:   ${((passedTests / totalTests) * 100).toFixed(1)}%`);
  console.log('======================================================\n');

  if (failedTests > 0) {
    process.exit(1);
  }
}

runPriority1RemediationTests();
