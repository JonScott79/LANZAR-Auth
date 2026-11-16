// test-commercial-c2.cjs
// Verification suite for Milestone C2: Multi-Tenant SaaS Core, Dynamic CORS, & Self-Service Developer API

const assert = require('assert');
const express = require('./auth-backend/node_modules/express');

const { TenantService, PLAN_ENTITLEMENTS } = require('./auth-backend/services/tenantService');
const {
  ClientRegistryService,
  validateAllowedOrigins,
  validateAllowedScopes
} = require('./auth-backend/services/clientRegistryService');
const { createOriginMiddleware } = require('./auth-backend/middleware/originValidator');
const { createDeveloperRouter } = require('./auth-backend/routes/developerRoutes');
const { createOAuthRouter } = require('./auth-backend/routes/oauthRoutes');

function createInMemoryFirestore() {
  const store = new Map();

  function docRef(path) {
    return {
      path,
      id: path.split('/').pop(),
      async get() {
        const data = store.get(path);
        return { exists: data !== undefined, data: () => (data ? JSON.parse(JSON.stringify(data)) : undefined) };
      },
      async set(data, opts = {}) {
        const prev = opts.merge && store.get(path) ? store.get(path) : {};
        store.set(path, JSON.parse(JSON.stringify({ ...prev, ...data })));
      },
      async update(data) {
        const prev = store.get(path);
        if (!prev) throw new Error(`Doc not found: ${path}`);
        store.set(path, JSON.parse(JSON.stringify({ ...prev, ...data })));
      },
      async delete() {
        store.delete(path);
      },
      collection(sub) {
        return colRef(`${path}/${sub}`);
      }
    };
  }

  function colRef(prefix) {
    return {
      doc(id) {
        return docRef(`${prefix}/${id}`);
      },
      async get() {
        const depth = prefix.split('/').length + 1;
        const docs = [];
        for (const [k, v] of store.entries()) {
          if (k.startsWith(prefix + '/') && k.split('/').length === depth) {
            docs.push({ id: k.split('/').pop(), data: () => JSON.parse(JSON.stringify(v)) });
          }
        }
        return { forEach: (cb) => docs.forEach(cb) };
      }
    };
  }

  return {
    collection: (name) => colRef(name),
    async runTransaction(fn) {
      const tx = {
        get: (ref) => ref.get(),
        set: (ref, data, opts) => ref.set(data, opts),
        update: (ref, data) => ref.update(data),
        delete: (ref) => ref.delete()
      };
      return fn(tx);
    }
  };
}

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
  console.log('LANZAR ID — Milestone C2 Multi-Tenant & Developer API Verification');
  console.log('================================================================\n');

  await test('C2-01: TenantService creates tenant, enforces uniqueness/reserved names, and protects last owner', async () => {
    const db = createInMemoryFirestore();
    const ts = new TenantService(db);

    const t = await ts.createTenant({ ownerUid: 'dev-a', ownerEmail: 'a@acme.dev', name: 'Acme SaaS', tenantId: 'acme-saas' });
    assert.strictEqual(t.tenantId, 'acme-saas');
    assert.strictEqual(t.plan, 'developer');
    assert.strictEqual(t.entitlements.maxApps, PLAN_ENTITLEMENTS.developer.maxApps);

    await assert.rejects(() => ts.createTenant({ ownerUid: 'dev-b', name: 'Dup', tenantId: 'acme-saas' }), /already exists/);
    await assert.rejects(() => ts.createTenant({ ownerUid: 'dev-b', name: 'Lanzar', tenantId: 'lanzar' }), /reserved/);
    await assert.rejects(() => ts.removeMember('acme-saas', 'dev-a'), /last active owner/);

    await ts.upsertMember('acme-saas', { uid: 'dev-b', email: 'b@acme.dev', role: 'developer' });
    const members = await ts.listMembers('acme-saas');
    assert.strictEqual(members.length, 2);
  });

  await test('C2-02: ClientRegistryService validates allowedOrigins/allowedScopes and rotates clientSecret', async () => {
    assert.deepStrictEqual(validateAllowedOrigins(['https://app.acme.com/']), ['https://app.acme.com']);
    assert.throws(() => validateAllowedOrigins(['https://*.acme.com']), /Wildcard/);
    assert.throws(() => validateAllowedOrigins(['https://app.acme.com/path']), /path/);
    assert.deepStrictEqual(validateAllowedScopes(['email']), ['openid', 'email']);
    assert.throws(() => validateAllowedScopes(['admin_root']), /Unsupported scope/);

    const db = createInMemoryFirestore();
    const crs = new ClientRegistryService(db, { isProduction: () => false });
    await crs.registerClient({
      tenantId: 'acme-saas',
      clientId: 'acme-web',
      name: 'Acme Web',
      redirectUris: ['https://app.acme.com/callback'],
      allowedOrigins: ['https://app.acme.com'],
      allowedScopes: ['openid', 'email'],
      tokenEndpointAuthMethod: 'client_secret_post',
      clientSecret: 'initial_secret_16_chars_min'
    });

    assert.strictEqual(await crs.resolveDynamicOriginClient('https://app.acme.com'), 'acme-web');

    const rotated = await crs.rotateClientSecret({ tenantId: 'acme-saas', clientId: 'acme-web' });
    assert(rotated.clientSecret.startsWith('lzd_sec_'));
    const resolved = await crs.resolveClient('acme-web');
    assert.strictEqual(crs.verifyClientCredentials(resolved, 'initial_secret_16_chars_min'), false);
    assert.strictEqual(crs.verifyClientCredentials(resolved, rotated.clientSecret), true);

    await crs.disableClient({ tenantId: 'acme-saas', clientId: 'acme-web' });
    assert.strictEqual(await crs.resolveDynamicOriginClient('https://app.acme.com'), null);
  });

  await test('C2-03: originValidator allows dynamic client origin on /oauth/* and blocks it on /api/admin/* & /api/id/session/establish', async () => {
    const db = createInMemoryFirestore();
    const crs = new ClientRegistryService(db, { isProduction: () => false });
    await crs.registerClient({
      tenantId: 'acme-saas',
      clientId: 'acme-spa',
      name: 'Acme SPA',
      redirectUris: ['https://spa.acme.com/cb'],
      allowedOrigins: ['https://spa.acme.com']
    });

    const app = express();
    app.use(createOriginMiddleware({
      appEnv: 'staging',
      originMap: { 'https://lanzar-auth-nova.netlify.app': 'auth_hub' }
    }, { clientRegistryService: crs }));
    app.post('/oauth/token', (req, res) => res.json({ ok: true, clientAppId: req.clientAppId }));
    app.post('/api/id/session/establish', (req, res) => res.json({ ok: true }));
    app.get('/api/admin/id/users', (req, res) => res.json({ ok: true }));

    const srv = await new Promise((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const base = `http://127.0.0.1:${srv.address().port}`;
    try {
      const rToken = await fetch(`${base}/oauth/token`, {
        method: 'POST',
        headers: { Origin: 'https://spa.acme.com' }
      });
      assert.strictEqual(rToken.status, 200);
      assert.strictEqual(rToken.headers.get('access-control-allow-origin'), 'https://spa.acme.com');

      const rEst = await fetch(`${base}/api/id/session/establish`, {
        method: 'POST',
        headers: { Origin: 'https://spa.acme.com' }
      });
      assert.strictEqual(rEst.status, 403);

      const rAdm = await fetch(`${base}/api/admin/id/users`, {
        headers: { Origin: 'https://spa.acme.com' }
      });
      assert.strictEqual(rAdm.status, 403);
    } finally {
      srv.close();
    }
  });

  await test('C2-04: /api/dev enforces tenant isolation, plan maxApps limits, and suspended tenant blocking', async () => {
    const db = createInMemoryFirestore();
    const ts = new TenantService(db);
    const crs = new ClientRegistryService(db, { isProduction: () => false });

    const app = express();
    app.use(express.json());
    const authUser = (req, res, next) => {
      const uid = req.headers['x-test-uid'];
      if (!uid) return res.status(401).json({ error: 'unauthorized' });
      req.user = { uid, email: `${uid}@example.com` };
      next();
    };
    app.use('/api/dev', createDeveloperRouter({
      tenantService: ts,
      clientRegistryService: crs,
      authenticateUserMiddleware: authUser
    }));
    app.use('/oauth', createOAuthRouter({
      db,
      authAdmin: {},
      codeStore: {},
      isUserAdmin: async () => false,
      clientRegistryService: crs,
      tenantService: ts,
      authHubUrl: 'https://lanzar-auth-nova.netlify.app'
    }));

    const srv = await new Promise((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const base = `http://127.0.0.1:${srv.address().port}`;
    try {
      // Dev A creates tenant
      const rCreate = await fetch(`${base}/api/dev/tenants`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-test-uid': 'dev-a' },
        body: JSON.stringify({ name: 'Beta Corp', tenantId: 'beta-corp' })
      });
      assert.strictEqual(rCreate.status, 201);

      // Dev A creates 3 apps (maxApps = 3 on developer plan)
      for (let i = 1; i <= 3; i++) {
        const rApp = await fetch(`${base}/api/dev/tenants/beta-corp/clients`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-test-uid': 'dev-a' },
          body: JSON.stringify({
            clientId: `beta-app-${i}`,
            name: `Beta App ${i}`,
            redirectUris: [`https://app${i}.beta.com/cb`],
            allowedOrigins: [`https://app${i}.beta.com`]
          })
        });
        assert.strictEqual(rApp.status, 201);
      }

      // 4th app blocked by plan limit
      const r4 = await fetch(`${base}/api/dev/tenants/beta-corp/clients`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-test-uid': 'dev-a' },
        body: JSON.stringify({
          clientId: 'beta-app-4',
          name: 'Beta App 4',
          redirectUris: ['https://app4.beta.com/cb']
        })
      });
      assert.strictEqual(r4.status, 403);
      assert.strictEqual((await r4.json()).error, 'plan_limit_reached');

      // Cross-tenant access by Dev B strictly blocked (403)
      const rCross = await fetch(`${base}/api/dev/tenants/beta-corp/clients`, {
        headers: { 'x-test-uid': 'dev-b' }
      });
      assert.strictEqual(rCross.status, 403);

      // Suspend tenant -> /oauth/authorize blocked with 403 tenant_suspended
      const rSusp = await fetch(`${base}/api/dev/tenants/beta-corp/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-test-uid': 'dev-a' },
        body: JSON.stringify({ status: 'suspended', reason: 'test' })
      });
      assert.strictEqual(rSusp.status, 200);

      const rAuth = await fetch(
        `${base}/oauth/authorize?client_id=beta-app-1&redirect_uri=${encodeURIComponent('https://app1.beta.com/cb')}&response_type=code&code_challenge=xyz&code_challenge_method=S256&state=s1`
      );
      assert.strictEqual(rAuth.status, 403);
      assert.strictEqual((await rAuth.json()).error, 'tenant_suspended');
    } finally {
      srv.close();
    }
  });

  console.log('\n================================================================');
  console.log(`MILESTONE C2 VERIFICATION SUMMARY: ${passed} passed, ${failed} failed`);
  console.log('================================================================\n');
  if (failed > 0) process.exit(1);
}

run().catch((err) => {
  console.error('FATAL:', err);
  process.exit(1);
});
