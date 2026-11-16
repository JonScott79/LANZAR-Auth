// test-commercial-c3.cjs
// Verification suite for Milestone C3: Stripe Test-Mode Billing & Entitlements

const assert = require('assert');
const crypto = require('crypto');
const express = require('./auth-backend/node_modules/express');

const { TenantService, PLAN_ENTITLEMENTS } = require('./auth-backend/services/tenantService');
const { BillingService, verifyStripeWebhookSignature } = require('./auth-backend/services/billingService');
const { createBillingWebhookRouter } = require('./auth-backend/routes/billingRoutes');

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
      async delete() { store.delete(path); },
      collection(sub) { return colRef(`${path}/${sub}`); }
    };
  }
  function colRef(prefix) {
    return {
      doc: (id) => docRef(`${prefix}/${id}`),
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
      return fn({
        get: (ref) => ref.get(),
        set: (ref, data, opts) => ref.set(data, opts),
        update: (ref, data) => ref.update(data),
        delete: (ref) => ref.delete()
      });
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
  console.log('LANZAR ID — Milestone C3 Stripe Test-Mode Billing Verification');
  console.log('================================================================\n');

  await test('C3-01: BillingService strictly rejects sk_live_ keys', async () => {
    const db = createInMemoryFirestore();
    const ts = new TenantService(db);
    assert.throws(() => new BillingService(db, ts, { stripeSecretKey: 'sk_live_12345' }), /sk_live_/);
  });

  await test('C3-02: Stripe webhook HMAC-SHA256 signature verification validates authentic & rejects forged payloads', async () => {
    const secret = 'whsec_test_1234567890';
    const raw = JSON.stringify({ id: 'evt_1', type: 'checkout.session.completed' });
    const ts = Math.floor(Date.now() / 1000);
    const sig = crypto.createHmac('sha256', secret).update(`${ts}.${raw}`, 'utf8').digest('hex');

    assert.strictEqual(verifyStripeWebhookSignature(raw, `t=${ts},v1=${sig}`, secret).valid, true);
    assert.strictEqual(verifyStripeWebhookSignature(raw, `t=${ts},v1=${'0'.repeat(64)}`, secret).valid, false);
  });

  await test('C3-03: Webhook lifecycle upgrades, marks past_due, downgrades, and deduplicates replayed events', async () => {
    const db = createInMemoryFirestore();
    const ts = new TenantService(db);
    await ts.createTenant({ ownerUid: 'dev-1', ownerEmail: 'dev@acme.io', name: 'Acme', tenantId: 'acme' });

    const webhookSecret = 'whsec_test_lifecycle_secret';
    const bs = new BillingService(db, ts, {
      stripeSecretKey: 'sk_test_mock_12345',
      webhookSecret,
      priceMap: { launch: 'price_launch_test', growth: 'price_growth_test', scale: 'price_scale_test' }
    });

    const app = express();
    app.use('/api/billing', createBillingWebhookRouter({ billingService: bs }));
    const srv = await new Promise((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const base = `http://127.0.0.1:${srv.address().port}`;

    const sendSignedEvent = async (eventObj) => {
      const raw = JSON.stringify(eventObj);
      const t = Math.floor(Date.now() / 1000);
      const v1 = crypto.createHmac('sha256', webhookSecret).update(`${t}.${raw}`, 'utf8').digest('hex');
      return fetch(`${base}/api/billing/webhook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'stripe-signature': `t=${t},v1=${v1}` },
        body: raw
      });
    };

    try {
      // 1. Checkout completed -> launch ($29/mo, maxApps=10)
      const r1 = await sendSignedEvent({
        id: 'evt_chk_1',
        type: 'checkout.session.completed',
        data: { object: { customer: 'cus_1', subscription: 'sub_1', metadata: { tenantId: 'acme', planId: 'launch' } } }
      });
      assert.strictEqual(r1.status, 200);
      let tenant = await ts.getTenant('acme');
      assert.strictEqual(tenant.plan, 'launch');
      assert.strictEqual(tenant.entitlements.maxApps, PLAN_ENTITLEMENTS.launch.maxApps);

      // 2. Duplicate event deduplicated
      const rDup = await sendSignedEvent({
        id: 'evt_chk_1',
        type: 'checkout.session.completed',
        data: { object: { customer: 'cus_1', subscription: 'sub_1', metadata: { tenantId: 'acme', planId: 'scale' } } }
      });
      assert.strictEqual((await rDup.json()).deduplicated, true);
      tenant = await ts.getTenant('acme');
      assert.strictEqual(tenant.plan, 'launch');

      // 3. Payment failed -> past_due
      await sendSignedEvent({
        id: 'evt_fail_1',
        type: 'invoice.payment_failed',
        data: { object: { metadata: { tenantId: 'acme' } } }
      });
      tenant = await ts.getTenant('acme');
      assert.strictEqual(tenant.billing.subscriptionStatus, 'past_due');

      // 4. Subscription deleted -> downgraded to developer
      await sendSignedEvent({
        id: 'evt_del_1',
        type: 'customer.subscription.deleted',
        data: { object: { customer: 'cus_1', metadata: { tenantId: 'acme' } } }
      });
      tenant = await ts.getTenant('acme');
      assert.strictEqual(tenant.plan, 'developer');
      assert.strictEqual(tenant.billing.subscriptionStatus, 'canceled');
      assert.strictEqual(tenant.entitlements.maxApps, PLAN_ENTITLEMENTS.developer.maxApps);
    } finally {
      srv.close();
    }
  });

  console.log('\n================================================================');
  console.log(`MILESTONE C3 VERIFICATION SUMMARY: ${passed} passed, ${failed} failed`);
  console.log('================================================================\n');
  if (failed > 0) process.exit(1);
}

run().catch((err) => {
  console.error('FATAL:', err);
  process.exit(1);
});
