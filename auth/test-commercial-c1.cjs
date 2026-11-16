// test-commercial-c1.cjs
// Verification suite for Milestone C1: Core Auth, Security & Threadline Hardening

const assert = require('assert');
const express = require('./auth-backend/node_modules/express');
const crypto = require('crypto');

const { createOAuthRouter } = require('./auth-backend/routes/oauthRoutes');
const { createAccountRouter } = require('./auth-backend/routes/accountRoutes');
const { ProfileService } = require('./auth-backend/profileService');
const { encryptTotpSecret, decryptTotpSecret } = require('./auth-backend/mfaService');
const { validateAndNormalizeScope } = require('./auth-backend/services/oidcTokenService');

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓ [PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ [FAIL] ${name}: ${err.message}`);
    failed++;
  }
}

async function run() {
  console.log('\n================================================================');
  console.log('LANZAR ID — Milestone C1 Core Auth & Security Verification');
  console.log('================================================================\n');

  // 1. validateAndNormalizeScope
  await test('C1-01: validateAndNormalizeScope enforces SUPPORTED_SCOPES and per-client allowedScopes', async () => {
    const ok1 = validateAndNormalizeScope('openid profile');
    assert.strictEqual(ok1.valid, true);
    assert.strictEqual(ok1.scope, 'openid profile');

    const bad1 = validateAndNormalizeScope('openid admin_all');
    assert.strictEqual(bad1.valid, false);
    assert.strictEqual(bad1.error, 'invalid_scope');

    const ok2 = validateAndNormalizeScope('openid email', ['openid', 'email']);
    assert.strictEqual(ok2.valid, true);
    assert.strictEqual(ok2.scope, 'openid email');

    const bad2 = validateAndNormalizeScope('openid profile', ['openid', 'email']);
    assert.strictEqual(bad2.valid, false);
    assert.strictEqual(bad2.error, 'invalid_scope');
  });

  // 2. GET /oauth/authorize
  await test('C1-02: GET /oauth/authorize validates OAuth/PKCE params and 302 redirects to Auth Hub', async () => {
    const router = createOAuthRouter({
      db: {},
      authAdmin: {},
      codeStore: {},
      isUserAdmin: async () => false,
      authHubUrl: 'https://lanzar-auth-nova.netlify.app',
      getClientOverride: (id) => id === 'threadline' ? {
        clientId: 'threadline',
        enabled: true,
        tenantId: 'lanzar',
        redirectUris: ['https://threadline-nova.netlify.app'],
        allowedScopes: ['openid', 'profile', 'email']
      } : null
    });

    const app = express();
    app.use('/oauth', router);
    const srv = await new Promise((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const base = `http://127.0.0.1:${srv.address().port}`;
    try {
      // Valid GET /oauth/authorize -> 302 redirect
      const resOk = await fetch(
        `${base}/oauth/authorize?client_id=threadline&redirect_uri=${encodeURIComponent('https://threadline-nova.netlify.app')}&response_type=code&code_challenge=abc123&code_challenge_method=S256&state=st1&scope=${encodeURIComponent('openid profile')}&nonce=n1`,
        { redirect: 'manual' }
      );
      assert.strictEqual(resOk.status, 302);
      const loc = new URL(resOk.headers.get('location'));
      assert.strictEqual(loc.origin, 'https://lanzar-auth-nova.netlify.app');
      assert.strictEqual(loc.searchParams.get('client_id'), 'threadline');
      assert.strictEqual(loc.searchParams.get('code_challenge_method'), 'S256');
      assert.strictEqual(loc.searchParams.get('nonce'), 'n1');

      // Invalid response_type
      const resBadType = await fetch(
        `${base}/oauth/authorize?client_id=threadline&redirect_uri=${encodeURIComponent('https://threadline-nova.netlify.app')}&response_type=token&code_challenge=abc&code_challenge_method=S256&state=st1`
      );
      assert.strictEqual(resBadType.status, 400);
      assert.strictEqual((await resBadType.json()).error, 'unsupported_response_type');

      // Invalid scope
      const resBadScope = await fetch(
        `${base}/oauth/authorize?client_id=threadline&redirect_uri=${encodeURIComponent('https://threadline-nova.netlify.app')}&response_type=code&code_challenge=abc&code_challenge_method=S256&state=st1&scope=openid+bogus`
      );
      assert.strictEqual(resBadScope.status, 400);
      assert.strictEqual((await resBadScope.json()).error, 'invalid_scope');
    } finally {
      srv.close();
    }
  });

  // 3. MFA_ENCRYPTION_KEY fail-closed in staging/production
  await test('C1-03: mfaService fails closed in staging/production when MFA_ENCRYPTION_KEY is missing or short', async () => {
    const prevAppEnv = process.env.APP_ENV;
    const prevNodeEnv = process.env.NODE_ENV;
    const prevKey = process.env.MFA_ENCRYPTION_KEY;
    try {
      process.env.APP_ENV = 'staging';
      delete process.env.MFA_ENCRYPTION_KEY;
      assert.throws(() => encryptTotpSecret('JBSWY3DPEHPK3PXP'), /MFA_ENCRYPTION_KEY/);

      process.env.MFA_ENCRYPTION_KEY = 'too_short';
      assert.throws(() => encryptTotpSecret('JBSWY3DPEHPK3PXP'), /MFA_ENCRYPTION_KEY/);

      process.env.MFA_ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef';
      const enc = encryptTotpSecret('JBSWY3DPEHPK3PXP');
      const dec = decryptTotpSecret(enc);
      assert.strictEqual(dec, 'JBSWY3DPEHPK3PXP');
    } finally {
      if (prevAppEnv === undefined) delete process.env.APP_ENV;
      else process.env.APP_ENV = prevAppEnv;
      if (prevNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = prevNodeEnv;
      if (prevKey === undefined) delete process.env.MFA_ENCRYPTION_KEY;
      else process.env.MFA_ENCRYPTION_KEY = prevKey;
    }
  });

  // 4. accountRoutes reconcileCustomerAccount syncs emailVerified
  await test('C1-04: reconcileCustomerAccount syncs emailVerified on creation and update', async () => {
    const docs = new Map();
    const makeDocRef = (col, id) => ({
      path: `${col}/${id}`,
      async get() {
        const val = docs.get(`${col}/${id}`);
        return { exists: !!val, data: () => val };
      },
      async set(data) {
        docs.set(`${col}/${id}`, { ...data });
      },
      async update(data) {
        docs.set(`${col}/${id}`, { ...(docs.get(`${col}/${id}`) || {}), ...data });
      }
    });
    const fakeDb = {
      collection: (col) => ({ doc: (id) => makeDocRef(col, id) })
    };
    const { reconcileCustomerAccount } = createAccountRouter({ db: fakeDb, authAdmin: {} });

    await reconcileCustomerAccount({
      uid: 'u1',
      email: 'u1@example.com',
      displayName: 'User One',
      emailVerified: false
    });
    assert.strictEqual(docs.get('users/u1').emailVerified, false);

    await reconcileCustomerAccount({
      uid: 'u1',
      email: 'u1@example.com',
      displayName: 'User One',
      emailVerified: true
    });
    assert.strictEqual(docs.get('users/u1').emailVerified, true);
  });

  // 5. ProfileService.eraseUserAccount purges central_sessions, session_slots, and customers/{uid}
  await test('C1-05: eraseUserAccount purges sessions, central_sessions, session_slots, founders, customers, users', async () => {
    const deletedPaths = [];
    const makeSubSnap = (paths) => ({
      forEach: (cb) => paths.forEach(p => cb({ ref: { path: p } }))
    });
    const fakeDb = {
      collection: (col) => ({
        doc: (id) => ({
          path: `${col}/${id}`,
          delete: async () => deletedPaths.push(`${col}/${id}`),
          collection: (sub) => ({
            get: async () => makeSubSnap([`${col}/${id}/${sub}/item1`])
          })
        }),
        add: async () => ({ id: 'audit1' })
      }),
      batch: () => ({
        delete: (ref) => deletedPaths.push(ref.path),
        commit: async () => {}
      })
    };
    const svc = new ProfileService(fakeDb, { deleteUser: async () => {} });
    await svc.eraseUserAccount('u-del', 'admin-1');

    assert(deletedPaths.includes('mfa_factors/u-del'));
    assert(deletedPaths.includes('users/u-del/sessions/item1'));
    assert(deletedPaths.includes('users/u-del/central_sessions/item1'));
    assert(deletedPaths.includes('users/u-del/session_slots/item1'));
    assert(deletedPaths.includes('users/u-del/founders/item1'));
    assert(deletedPaths.includes('customers/u-del'));
    assert(deletedPaths.includes('users/u-del'));
  });

  console.log('\n================================================================');
  console.log(`MILESTONE C1 VERIFICATION SUMMARY: ${passed} passed, ${failed} failed`);
  console.log('================================================================\n');
  if (failed > 0) process.exit(1);
}

run().catch((err) => {
  console.error('FATAL:', err);
  process.exit(1);
});
