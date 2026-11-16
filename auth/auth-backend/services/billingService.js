// billingService.js
// Stripe Test-Mode Subscription Lifecycle, Webhook Verification & Plan Entitlements

const crypto = require('crypto');
const { getEntitlementsForPlan, PLAN_ENTITLEMENTS } = require('./tenantService');

function verifyStripeWebhookSignature(rawBody, sigHeader, webhookSecret, toleranceSec = 300) {
  if (!rawBody || !sigHeader || !webhookSecret) {
    return { valid: false, reason: 'MISSING_SIGNATURE_OR_SECRET' };
  }
  const parts = String(sigHeader).split(',').reduce((acc, item) => {
    const [k, v] = item.split('=');
    if (k && v) acc[k.trim()] = v.trim();
    return acc;
  }, {});

  const timestamp = Number(parts.t);
  const v1 = parts.v1;
  if (!Number.isFinite(timestamp) || !v1) {
    return { valid: false, reason: 'MALFORMED_SIGNATURE_HEADER' };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - timestamp) > toleranceSec) {
    return { valid: false, reason: 'TIMESTAMP_OUT_OF_TOLERANCE' };
  }

  const payload = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : String(rawBody);
  const signedPayload = `${timestamp}.${payload}`;
  const expected = crypto.createHmac('sha256', webhookSecret).update(signedPayload, 'utf8').digest('hex');

  try {
    const a = Buffer.from(v1, 'hex');
    const b = Buffer.from(expected, 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return { valid: false, reason: 'SIGNATURE_MISMATCH' };
    }
  } catch (_) {
    return { valid: false, reason: 'SIGNATURE_COMPARE_ERROR' };
  }

  return { valid: true };
}

class BillingService {
  constructor(db, tenantService, options = {}) {
    if (!db || !tenantService) {
      throw new Error('BillingService requires db and tenantService.');
    }
    this.db = db;
    this.tenantService = tenantService;
    this.stripeSecretKey = options.stripeSecretKey || process.env.STRIPE_SECRET_KEY || '';
    this.webhookSecret = options.webhookSecret || process.env.STRIPE_WEBHOOK_SECRET || '';
    this.priceMap = options.priceMap || {
      launch: process.env.STRIPE_PRICE_LAUNCH || '',
      growth: process.env.STRIPE_PRICE_GROWTH || '',
      scale: process.env.STRIPE_PRICE_SCALE || ''
    };
    this.fetchFn = options.fetchFn || global.fetch;

    if (this.stripeSecretKey && this.stripeSecretKey.startsWith('sk_live_')) {
      throw new Error('[BILLING CONFIG FATAL] Stripe live keys (sk_live_) are strictly forbidden in staging/commercial beta prep.');
    }
  }

  isConfigured() {
    return Boolean(this.stripeSecretKey && this.stripeSecretKey.startsWith('sk_test_'));
  }

  resolvePlanFromPriceId(priceId) {
    if (!priceId) return null;
    for (const [planId, configuredPrice] of Object.entries(this.priceMap)) {
      if (configuredPrice && configuredPrice === priceId) {
        return planId;
      }
    }
    return null;
  }

  async createCheckoutSession({ tenantId, planId, customerEmail, successUrl, cancelUrl }) {
    const cleanPlan = String(planId || '').toLowerCase();
    if (!['launch', 'growth', 'scale'].includes(cleanPlan)) {
      throw new Error('Checkout is supported for paid plans: launch, growth, scale.');
    }
    if (!this.isConfigured()) {
      const err = new Error('Stripe test mode key (STRIPE_SECRET_KEY=sk_test_...) is not configured.');
      err.code = 'STRIPE_NOT_CONFIGURED';
      err.status = 501;
      throw err;
    }
    const priceId = this.priceMap[cleanPlan];
    if (!priceId) {
      const err = new Error(`Stripe price ID for plan "${cleanPlan}" is not configured.`);
      err.code = 'STRIPE_PRICE_MISSING';
      err.status = 501;
      throw err;
    }

    const body = new URLSearchParams({
      mode: 'subscription',
      'line_items[0][price]': priceId,
      'line_items[0][quantity]': '1',
      success_url: successUrl,
      cancel_url: cancelUrl,
      'metadata[tenantId]': tenantId,
      'metadata[planId]': cleanPlan,
      'subscription_data[metadata][tenantId]': tenantId,
      'subscription_data[metadata][planId]': cleanPlan
    });
    if (customerEmail) {
      body.set('customer_email', customerEmail);
    }

    const res = await this.fetchFn('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.stripeSecretKey}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body.toString()
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data?.error?.message || 'Failed to create Stripe Checkout session.');
    }
    return { sessionId: data.id, url: data.url };
  }

  async createCustomerPortalSession({ tenant, returnUrl }) {
    if (!this.isConfigured()) {
      const err = new Error('Stripe test mode key (STRIPE_SECRET_KEY=sk_test_...) is not configured.');
      err.code = 'STRIPE_NOT_CONFIGURED';
      err.status = 501;
      throw err;
    }
    const stripeCustomerId = tenant?.billing?.stripeCustomerId;
    if (!stripeCustomerId) {
      const err = new Error('No Stripe customer associated with this tenant yet.');
      err.code = 'NO_STRIPE_CUSTOMER';
      err.status = 400;
      throw err;
    }

    const body = new URLSearchParams({
      customer: stripeCustomerId,
      return_url: returnUrl
    });

    const res = await this.fetchFn('https://api.stripe.com/v1/billing_portal/sessions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.stripeSecretKey}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body.toString()
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data?.error?.message || 'Failed to create Stripe Billing Portal session.');
    }
    return { url: data.url };
  }

  async handleWebhookEvent(event) {
    if (!event || !event.id || !event.type) {
      throw new Error('Malformed Stripe webhook event.');
    }
    const eventRef = this.db.collection('billing_webhook_events').doc(event.id);
    const alreadyProcessed = await this.db.runTransaction(async (tx) => {
      const snap = await tx.get(eventRef);
      if (snap.exists) return true;
      tx.set(eventRef, {
        eventId: event.id,
        type: event.type,
        receivedAt: new Date().toISOString()
      });
      return false;
    });

    if (alreadyProcessed) {
      return { deduplicated: true, eventId: event.id };
    }

    const obj = event.data && event.data.object ? event.data.object : {};
    const metadata = obj.metadata || {};
    const tenantId = metadata.tenantId || null;

    if (event.type === 'checkout.session.completed' && tenantId) {
      const planId = metadata.planId || 'launch';
      await this.tenantService.updateTenantPlan(tenantId, planId, {
        stripeCustomerId: obj.customer || null,
        stripeSubscriptionId: obj.subscription || null,
        subscriptionStatus: 'active'
      });
      return { processed: true, tenantId, planId, action: 'activated' };
    }

    if (event.type === 'customer.subscription.updated' && tenantId) {
      const priceId = obj.items?.data?.[0]?.price?.id || null;
      const planId = metadata.planId || this.resolvePlanFromPriceId(priceId) || 'launch';
      const status = obj.status || 'active';
      const targetPlan = (status === 'canceled' || status === 'unpaid') ? 'developer' : planId;
      await this.tenantService.updateTenantPlan(tenantId, targetPlan, {
        stripeCustomerId: obj.customer || null,
        stripeSubscriptionId: obj.id || null,
        subscriptionStatus: status,
        currentPeriodEnd: obj.current_period_end ? new Date(obj.current_period_end * 1000).toISOString() : null
      });
      return { processed: true, tenantId, planId: targetPlan, action: 'updated', status };
    }

    if (event.type === 'customer.subscription.deleted' && tenantId) {
      await this.tenantService.updateTenantPlan(tenantId, 'developer', {
        stripeCustomerId: obj.customer || null,
        stripeSubscriptionId: null,
        subscriptionStatus: 'canceled',
        currentPeriodEnd: null
      });
      return { processed: true, tenantId, planId: 'developer', action: 'downgraded' };
    }

    if (event.type === 'invoice.payment_failed' && tenantId) {
      const tenant = await this.tenantService.getTenant(tenantId);
      if (tenant) {
        await this.tenantService.updateTenantPlan(tenantId, tenant.plan || 'developer', {
          subscriptionStatus: 'past_due'
        });
      }
      return { processed: true, tenantId, action: 'marked_past_due' };
    }

    return { processed: false, ignoredType: event.type };
  }
}

module.exports = {
  BillingService,
  verifyStripeWebhookSignature,
  getEntitlementsForPlan,
  PLAN_ENTITLEMENTS
};
