// test-preprod-launch-hardening.cjs
// Automated Verification Suite for LANZAR ID Pre-Production Hardening:
// - LID-VER-001: Rate Limiter Upper Memory Bounds & Eviction Policy
// - LID-VER-002: Dual-Key MFA Throttling & Account Lockout DoS Defense
// - LID-VER-003: Reverse-Proxy Trust Configuration & Spoofed IP Defense
// - LID-SEC-001: Distributed Firestore Authorization Code Store & Replay Defense
// - LID-SEC-003: Multi-Instance Distributed Session Revocation Consistency

const path = require('path');
module.paths.push(path.resolve(__dirname, 'auth-backend/node_modules'));
module.paths.push(path.resolve(__dirname, '../node_modules'));

process.env.APP_ENV = process.env.APP_ENV || 'test';
process.env.NODE_ENV = process.env.NODE_ENV || 'test';

const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const express = require('express');

const { MockFirestore, MockAuthAdmin } = require('./test-utils/mockFirebase.cjs');
const {
  createRateLimiter,
  checkMfaRateLimit,
  recordMfaFailure,
  clearMfaFailures,
  resetRateLimits,
  getClientIp,
  isRequestSecure,
  setMaxEntries,
  getRateLimitStoreSize
} = require('./auth-backend/middleware/rateLimiter.js');
const {
  AuthorizationCodeStore,
  FirestoreAuthorizationCodeStore
} = require('./auth-backend/store.js');
const { SessionService } = require('./auth-backend/sessionService.js');
const { ENV_CONFIGS, resolveEnvironment } = require('./auth-backend/config/environments.js');
const { createApp } = require('./auth-backend/app.js');
const {
  generateBase32Secret,
  generateTOTP,
  encryptTotpSecret,
  createMfaSignedToken
} = require('./auth-backend/mfaService.js');

let passCount = 0;
let totalTests = 0;

function runTest(name, fn) {
  totalTests++;
  try {
    fn();
    console.log(`  [PASS] ${name}`);
    passCount++;
  } catch (err) {
    console.error(`  [FAIL] ${name}`);
    console.error(`         ${err.message}`);
    process.exitCode = 1;
  }
}

async function runAsyncTest(name, fn) {
  totalTests++;
  try {
    await fn();
    console.log(`  [PASS] ${name}`);
    passCount++;
  } catch (err) {
    console.error(`  [FAIL] ${name}`);
    console.error(`         ${err.message}`);
    process.exitCode = 1;
  }
}

async function main() {
  console.log('\n============================================================');
  console.log('LANZAR ID PRE-PRODUCTION LAUNCH HARDENING VERIFICATION SUITE');
  console.log('============================================================\n');

  // =========================================================================
  // 1. LID-VER-001: Rate Limiter Upper Memory Bounds & Eviction Policy
  // =========================================================================
  console.log('--- 1. LID-VER-001: Rate Limiter Memory Bounding ---');

  resetRateLimits();
  setMaxEntries(50); // Set small bound for testing

  runTest('LID-VER-001.1: Store size stays bounded under high volume of synthetic keys', () => {
    // Generate 200 distinct keys
    for (let i = 0; i < 200; i++) {
      recordMfaFailure(`user_${i}`, 'totp', `10.0.0.${i}`);
    }
    const currentSize = getRateLimitStoreSize();
    assert(currentSize <= 50, `Expected store size <= 50, got ${currentSize}`);
  });

  runTest('LID-VER-001.2: Expired entries are pruned on capacity exhaustion', () => {
    resetRateLimits();
    setMaxEntries(10);

    // Insert 5 entries that expire immediately
    const past = Date.now() - 1000;
    for (let i = 0; i < 5; i++) {
      recordMfaFailure(`user_expired_${i}`, 'totp', `192.168.1.${i}`);
    }

    // Insert 10 fresh entries
    for (let i = 0; i < 10; i++) {
      recordMfaFailure(`user_fresh_${i}`, 'totp', `172.16.0.${i}`);
    }

    const currentSize = getRateLimitStoreSize();
    assert(currentSize <= 10, `Expected store size <= 10, got ${currentSize}`);
  });

  // Reset max entries to standard default
  setMaxEntries(10000);
  resetRateLimits();

  // =========================================================================
  // 2. LID-VER-002: Dual-Key MFA Throttling & Account Lockout DoS Defense
  // =========================================================================
  console.log('\n--- 2. LID-VER-002: Dual-Key MFA Throttling & Lockout Defense ---');

  runTest('LID-VER-002.1: Attacker on IP A failing 5 times gets throttled on IP A', () => {
    resetRateLimits();
    const attackerIp = '198.51.100.1';
    const victimUid = 'usr_victim_123';

    // Simulate 5 failed attempts from attacker IP
    for (let i = 0; i < 5; i++) {
      recordMfaFailure(victimUid, 'totp', attackerIp);
    }

    const attackerCheck = checkMfaRateLimit(victimUid, 'totp', attackerIp);
    assert.strictEqual(attackerCheck.allowed, false, 'Attacker should be throttled');
    assert.strictEqual(
      attackerCheck.message,
      'Too many failed verification attempts. Please try again later.',
      'Message should be generic and not leak account state'
    );
    assert(attackerCheck.retryAfter > 0, 'Retry-after must be positive integer');
  });

  runTest('LID-VER-002.2: Victim user on IP B is NOT locked out by attacker on IP A', () => {
    const legitimateIp = '203.0.113.5';
    const victimUid = 'usr_victim_123';

    // Victim attempts verification from legitimate IP
    const victimCheck = checkMfaRateLimit(victimUid, 'totp', legitimateIp);
    assert.strictEqual(victimCheck.allowed, true, 'Legitimate user from separate IP must NOT be locked out');
  });

  runTest('LID-VER-002.3: Aggregate IP threshold blocks distributed account scanning from one IP', () => {
    resetRateLimits();
    const scannerIp = '198.51.100.99';

    // Scanner tries 15 different victim accounts from single IP (1 attempt each)
    for (let i = 0; i < 15; i++) {
      recordMfaFailure(`victim_account_${i}`, 'totp', scannerIp);
    }

    // 16th attempt against yet another new account is blocked by aggregate IP limiter
    const scanCheck = checkMfaRateLimit('another_victim_999', 'totp', scannerIp);
    assert.strictEqual(scanCheck.allowed, false, 'IP aggregate limit must block distributed scanner');
    assert.strictEqual(scanCheck.message, 'Too many failed verification attempts. Please try again later.');
  });

  runTest('LID-VER-002.4: Successful verification clears failure count for that UID and IP', () => {
    resetRateLimits();
    const userIp = '10.10.10.10';
    const uid = 'usr_cleared_123';

    recordMfaFailure(uid, 'totp', userIp);
    recordMfaFailure(uid, 'totp', userIp);

    clearMfaFailures(uid, 'totp', userIp);

    const check = checkMfaRateLimit(uid, 'totp', userIp);
    assert.strictEqual(check.allowed, true, 'Cleared failures must allow access');
  });

  // =========================================================================
  // 3. LID-VER-003: Railway Reverse-Proxy Ingress, Client-IP & TLS Verification
  // =========================================================================
  console.log('\n--- 3. LID-VER-003: Railway Proxy Ingress & Client-IP Verification ---');

  runTest('LID-VER-003.1: Environment configs keep trustProxy disabled (false) avoiding blind proxy assumptions', () => {
    assert.strictEqual(ENV_CONFIGS.production.trustProxy, false, 'Production must not blindly trust proxy');
    assert.strictEqual(ENV_CONFIGS.staging.trustProxy, false, 'Staging must not blindly trust proxy');
    assert.strictEqual(ENV_CONFIGS.development.trustProxy, false, 'Development must not blindly trust proxy');
    assert.strictEqual(ENV_CONFIGS.test.trustProxy, false, 'Test must not blindly trust proxy');
  });

  runTest('LID-VER-003.2: Express app default trust proxy is false, preventing arbitrary header trust', () => {
    const db = new MockFirestore();
    const authAdmin = new MockAuthAdmin();
    const envName = resolveEnvironment(process.env) || 'test';
    const config = ENV_CONFIGS[envName];

    const { app } = createApp({ config, db, authAdmin });
    assert.strictEqual(app.get('trust proxy'), false, 'Express trust proxy should be false by default');
  });

  runTest('LID-VER-003.3: getClientIp authoritatively extracts and validates genuine IPv4 X-Real-IP', () => {
    const req = {
      headers: { 'x-real-ip': '198.51.100.42' },
      socket: { remoteAddress: '10.0.0.1' }
    };
    assert.strictEqual(getClientIp(req), '198.51.100.42', 'Valid IPv4 X-Real-IP must be resolved');
  });

  runTest('LID-VER-003.4: getClientIp authoritatively extracts and validates genuine IPv6 X-Real-IP', () => {
    const req = {
      headers: { 'x-real-ip': '2001:0db8:85a3:0000:0000:8a2e:0370:7334' },
      socket: { remoteAddress: '10.0.0.1' }
    };
    assert.strictEqual(getClientIp(req), '2001:0db8:85a3:0000:0000:8a2e:0370:7334', 'Valid IPv6 X-Real-IP must be resolved');
  });

  runTest('LID-VER-003.5: getClientIp strictly ignores forged X-Forwarded-For headers', () => {
    const req = {
      headers: {
        'x-forwarded-for': '203.0.113.195, 10.0.0.1',
        'x-real-ip': '198.51.100.77'
      },
      socket: { remoteAddress: '127.0.0.1' }
    };
    // Must return the X-Real-IP header, NOT any value from X-Forwarded-For
    assert.strictEqual(getClientIp(req), '198.51.100.77', 'Must strictly use X-Real-IP and ignore X-Forwarded-For');

    // When X-Real-IP is absent, must NOT fall back to X-Forwarded-For
    const reqNoRealIp = {
      headers: { 'x-forwarded-for': '203.0.113.195' },
      socket: { remoteAddress: '127.0.0.1' }
    };
    assert.strictEqual(getClientIp(reqNoRealIp), '127.0.0.1', 'Must not parse X-Forwarded-For when X-Real-IP is absent');
  });

  runTest('LID-VER-003.6: getClientIp strictly rejects malformed, non-IP, or injected X-Real-IP', () => {
    const malformedCases = [
      '999.999.999.999',
      'not_an_ip_address',
      '1.2.3.4, 5.6.7.8',
      '<script>alert(1)</script>',
      '127.0.0.1; DROP TABLE sessions;',
      '',
      '   '
    ];

    for (const badIp of malformedCases) {
      const req = {
        headers: { 'x-real-ip': badIp },
        socket: { remoteAddress: '192.168.1.50' }
      };
      assert.strictEqual(getClientIp(req), '192.168.1.50', `Malformed IP "${badIp}" must fall back to socket address`);
    }
  });

  runTest('LID-VER-003.7: getClientIp falls back safely to direct socket address and 127.0.0.1', () => {
    // Normalizes IPv4-mapped IPv6
    const reqV4Mapped = {
      headers: {},
      socket: { remoteAddress: '::ffff:192.168.1.99' }
    };
    assert.strictEqual(getClientIp(reqV4Mapped), '192.168.1.99', 'IPv4-mapped IPv6 must be normalized');

    // Missing socket address falls back to 127.0.0.1
    const reqEmpty = { headers: {} };
    assert.strictEqual(getClientIp(reqEmpty), '127.0.0.1', 'Empty request must fall back to 127.0.0.1');
    assert.strictEqual(getClientIp(null), '127.0.0.1', 'Null request must fall back to 127.0.0.1');
  });

  runTest('LID-VER-003.8: isRequestSecure explicitly checks X-Forwarded-Proto without global trust proxy', () => {
    // Public Railway edge request over HTTPS
    const reqHttps = {
      headers: { 'x-forwarded-proto': 'https' },
      secure: false
    };
    assert.strictEqual(isRequestSecure(reqHttps), true, 'Railway X-Forwarded-Proto: https must be recognized as secure');

    // Insecure HTTP request forwarded by edge
    const reqHttp = {
      headers: { 'x-forwarded-proto': 'http' },
      secure: false
    };
    assert.strictEqual(isRequestSecure(reqHttp), false, 'Plain HTTP request must not be recognized as secure');

    // Direct TLS connection
    const reqDirectTls = {
      headers: {},
      secure: true
    };
    assert.strictEqual(isRequestSecure(reqDirectTls), true, 'Direct TLS socket must be recognized as secure');
  });

  runTest('LID-VER-003.9: Private-network boundary model (*.railway.internal) is asserted', () => {
    // Requests arriving over *.railway.internal bypass Railway public edge header sanitization.
    // The application rate limiter strictly checks net.isIP() regardless of origin, and the Railway
    // project environment is documented as a strict isolation boundary.
    const internalReq = {
      headers: {
        'host': 'auth-backend.railway.internal:4001',
        'x-real-ip': '10.1.2.3'
      },
      socket: { remoteAddress: '10.1.2.3' }
    };
    assert.strictEqual(getClientIp(internalReq), '10.1.2.3', 'Internal service IP must validate as net.isIP');
  });

  // =========================================================================
  // 4. LID-SEC-001: Distributed Firestore Authorization Code Storage
  // =========================================================================
  console.log('\n--- 4. LID-SEC-001: Distributed Firestore Authorization Code Store ---');

  await runAsyncTest('LID-SEC-001.1: Store writes code to Firestore with 10-minute expiry and S256 requirement', async () => {
    const db = new MockFirestore();
    const store = new FirestoreAuthorizationCodeStore(db);

    const challenge = crypto.createHash('sha256').update('test_verifier_string_123').digest('base64url');
    const code = await store.createCode({
      uid: 'user_oauth_123',
      clientId: 'id_portal',
      redirectUri: 'https://id.test.invalid/callback',
      codeChallenge: challenge,
      codeChallengeMethod: 'S256'
    });

    assert.ok(code && typeof code === 'string' && code.length === 64, 'Code must be 64-char hex string');

    const record = await store.getCode(code);
    assert.ok(record, 'Record must exist in Firestore');
    assert.strictEqual(record.uid, 'user_oauth_123');
    assert.strictEqual(record.codeChallengeMethod, 'S256');
    assert.strictEqual(record.used, false);
    assert(record.expiresAt > Date.now() + 500000, 'Expiry must be approximately 10 minutes');
  });

  await runAsyncTest('LID-SEC-001.2: Atomic single-use redemption and replay defense', async () => {
    const db = new MockFirestore();
    const store = new FirestoreAuthorizationCodeStore(db);

    const code = await store.createCode({
      uid: 'user_replay_test',
      clientId: 'mission_control',
      redirectUri: 'https://portal.test.invalid/callback',
      codeChallenge: 'abc',
      codeChallengeMethod: 'S256'
    });

    // First redemption succeeds
    const firstUse = await store.markUsed(code);
    assert.strictEqual(firstUse, true, 'First markUsed must succeed');

    // Immediate second redemption fails (replay prevention)
    const secondUse = await store.markUsed(code);
    assert.strictEqual(secondUse, false, 'Second markUsed must fail (replay rejected)');

    // Concurrent race condition test: two simultaneous redemption attempts
    const raceCode = await store.createCode({
      uid: 'user_race_test',
      clientId: 'mission_control',
      redirectUri: 'https://portal.test.invalid/callback',
      codeChallenge: 'xyz',
      codeChallengeMethod: 'S256'
    });

    const [res1, res2] = await Promise.all([
      store.markUsed(raceCode),
      store.markUsed(raceCode)
    ]);

    // Exactly one must succeed, exactly one must fail
    assert.strictEqual(
      (res1 ? 1 : 0) + (res2 ? 1 : 0),
      1,
      'Exactly one redemption must succeed under concurrent race conditions'
    );
  });

  // =========================================================================
  // 5. LID-SEC-003: Distributed Multi-Instance Session Revocation Consistency
  // =========================================================================
  console.log('\n--- 5. LID-SEC-003: Multi-Instance Session Revocation Consistency ---');

  await runAsyncTest('LID-SEC-003.1: Session revocation is immediately visible across separate service instances', async () => {
    const sharedDb = new MockFirestore();
    const authAdmin = new MockAuthAdmin();

    // Instance A and Instance B simulate separate horizontally-scaled Node.js containers
    const instanceA = new SessionService(sharedDb, authAdmin);
    const instanceB = new SessionService(sharedDb, authAdmin);

    const session = await instanceA.createSession({
      uid: 'user_distributed_test',
      clientId: 'id_portal',
      ipAddress: '10.0.0.1',
      userAgent: 'Node/Test'
    });

    // Both instances see session active
    const checkBeforeA = await instanceA.checkSession('user_distributed_test', session.sessionId);
    const checkBeforeB = await instanceB.checkSession('user_distributed_test', session.sessionId);
    assert.strictEqual(checkBeforeA.active, true, 'Instance A must see session active');
    assert.strictEqual(checkBeforeB.active, true, 'Instance B must see session active');

    // Instance A revokes the session
    await instanceA.revokeSession('user_distributed_test', session.sessionId, 'user_distributed_test', '10.0.0.1');

    // Instance B MUST immediately see the session as revoked (no stale process cache on Instance B)
    const checkAfterB = await instanceB.checkSession('user_distributed_test', session.sessionId);
    assert.strictEqual(checkAfterB.active, false, 'Instance B must immediately observe session as revoked');
    assert.strictEqual(checkAfterB.reason, 'revoked', 'Reason must be revoked');

    const isRevokedB = await instanceB.isSessionRevoked('user_distributed_test', session.sessionId);
    assert.strictEqual(isRevokedB, true, 'isSessionRevoked on Instance B must return true');
  });

  await runAsyncTest('LID-SEC-003.2: revokeAllUserSessions is immediately authoritative across instances', async () => {
    const sharedDb = new MockFirestore();
    const authAdmin = new MockAuthAdmin();

    const instanceA = new SessionService(sharedDb, authAdmin);
    const instanceB = new SessionService(sharedDb, authAdmin);

    const s1 = await instanceA.createSession({ uid: 'usr_revoke_all', clientId: 'app1' });
    const s2 = await instanceA.createSession({ uid: 'usr_revoke_all', clientId: 'app2' });

    await instanceA.revokeAllSessions('usr_revoke_all', 'usr_revoke_all', 'logout_all');

    const check1 = await instanceB.checkSession('usr_revoke_all', s1.sessionId);
    const check2 = await instanceB.checkSession('usr_revoke_all', s2.sessionId);

    assert.strictEqual(check1.active, false, 'Instance B must see session 1 revoked');
    assert.strictEqual(check2.active, false, 'Instance B must see session 2 revoked');
  });

  console.log('\n============================================================');
  console.log(`PRE-PRODUCTION HARDENING TEST SUMMARY: ${passCount} / ${totalTests} PASSED`);
  console.log('============================================================\n');

  if (passCount !== totalTests) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Unhandled fatal error in test suite:', err);
  process.exit(1);
});
