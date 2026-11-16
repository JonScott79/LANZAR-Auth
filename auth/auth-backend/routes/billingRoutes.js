// billingRoutes.js
// Stripe Test-Mode Webhook Receiver & Tenant Billing Portal Endpoints

const express = require('express');
const { verifyStripeWebhookSignature, PLAN_ENTITLEMENTS } = require('../services/billingService');

function createBillingWebhookRouter({ billingService }) {
  const router = express.Router();

  router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    try {
      if (!billingService || !billingService.webhookSecret) {
        return res.status(501).json({ error: 'stripe_webhook_not_configured' });
      }
      const sigHeader = req.headers['stripe-signature'];
      const verification = verifyStripeWebhookSignature(req.body, sigHeader, billingService.webhookSecret);
      if (!verification.valid) {
        return res.status(400).json({ error: 'invalid_signature', reason: verification.reason });
      }
      const event = JSON.parse(Buffer.isBuffer(req.body) ? req.body.toString('utf8') : String(req.body));
      const result = await billingService.handleWebhookEvent(event);
      return res.json({ received: true, ...result });
    } catch (err) {
      return res.status(400).json({ error: 'webhook_error', error_description: err.message });
    }
  });

  return router;
}

function attachTenantBillingRoutes(devRouter, { tenantService, clientRegistryService, billingService }) {
  devRouter.get('/tenants/:tenantId/billing', async (req, res) => {
    try {
      const { tenant } = await tenantService.requireTenantRole(
        req.params.tenantId,
        req.user.uid,
        ['owner', 'admin', 'developer']
      );
      const apps = await clientRegistryService.listTenantClients(req.params.tenantId);
      return res.json({
        plan: tenant.plan || 'developer',
        entitlements: tenant.entitlements,
        billing: tenant.billing || { subscriptionStatus: 'free' },
        usage: {
          appsUsed: apps.length,
          maxApps: tenant.entitlements?.maxApps ?? 3
        },
        stripeConfigured: billingService ? billingService.isConfigured() : false,
        plans: Object.values(PLAN_ENTITLEMENTS)
      });
    } catch (err) {
      return res.status(err.status || 400).json({ error: err.code || 'invalid_request', error_description: err.message });
    }
  });

  devRouter.post('/tenants/:tenantId/billing/checkout', async (req, res) => {
    try {
      await tenantService.requireTenantRole(req.params.tenantId, req.user.uid, ['owner']);
      const { planId, successUrl, cancelUrl } = req.body || {};
      if (!successUrl || !cancelUrl) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'successUrl and cancelUrl are required.' });
      }
      const session = await billingService.createCheckoutSession({
        tenantId: req.params.tenantId,
        planId,
        customerEmail: req.user.email || null,
        successUrl,
        cancelUrl
      });
      return res.json(session);
    } catch (err) {
      return res.status(err.status || 400).json({ error: err.code || 'billing_error', error_description: err.message });
    }
  });

  devRouter.post('/tenants/:tenantId/billing/portal', async (req, res) => {
    try {
      const { tenant } = await tenantService.requireTenantRole(req.params.tenantId, req.user.uid, ['owner']);
      const { returnUrl } = req.body || {};
      if (!returnUrl) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'returnUrl is required.' });
      }
      const session = await billingService.createCustomerPortalSession({ tenant, returnUrl });
      return res.json(session);
    } catch (err) {
      return res.status(err.status || 400).json({ error: err.code || 'billing_error', error_description: err.message });
    }
  });
}

module.exports = {
  createBillingWebhookRouter,
  attachTenantBillingRoutes
};
