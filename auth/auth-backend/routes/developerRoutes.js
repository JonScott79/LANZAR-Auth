// developerRoutes.js
// Self-Service Multi-Tenant Developer Console API (/api/dev) for LANZAR ID

const express = require('express');
const crypto = require('crypto');
const { oauthAuthorizeLimiter } = require('../middleware/rateLimiter');
const { PLAN_ENTITLEMENTS } = require('../services/tenantService');

function createDeveloperRouter({
  tenantService,
  clientRegistryService,
  auditLogService,
  oidcTokenService,
  authenticateUserMiddleware
}) {
  const router = express.Router();

  router.use(authenticateUserMiddleware);

  // Publicly authenticated plan catalog
  router.get('/plans', (req, res) => {
    return res.json({ plans: Object.values(PLAN_ENTITLEMENTS) });
  });

  // List tenants belonging to the authenticated developer
  router.get('/tenants', async (req, res) => {
    try {
      const tenants = await tenantService.listUserTenants(req.user.uid);
      return res.json({ tenants });
    } catch (err) {
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  // Create a new tenant / organization
  router.post('/tenants', oauthAuthorizeLimiter, async (req, res) => {
    try {
      const { name, tenantId } = req.body || {};
      const tenant = await tenantService.createTenant({
        ownerUid: req.user.uid,
        ownerEmail: req.user.email || null,
        name,
        tenantId
      });
      if (auditLogService && typeof auditLogService.recordAdminEvent === 'function') {
        await auditLogService.recordAdminEvent({
          actorUid: req.user.uid,
          actorEmail: req.user.email || null,
          actorTenantId: tenant.tenantId,
          actorRole: 'owner',
          targetTenantId: tenant.tenantId,
          operation: 'tenant.create',
          outcome: 'success',
          metadata: { plan: tenant.plan, name: tenant.name }
        }).catch(() => {});
      }
      return res.status(201).json({ tenant });
    } catch (err) {
      if (err.code === 'TENANT_ALREADY_EXISTS') {
        return res.status(409).json({ error: 'tenant_exists', error_description: err.message });
      }
      return res.status(400).json({ error: 'invalid_request', error_description: err.message });
    }
  });

  // Get tenant details, entitlements, and OIDC integration metadata
  router.get('/tenants/:tenantId', async (req, res) => {
    try {
      const { tenant, member } = await tenantService.requireTenantRole(
        req.params.tenantId,
        req.user.uid,
        ['owner', 'admin', 'developer', 'member']
      );
      const discovery = oidcTokenService ? oidcTokenService.getDiscoveryDocument() : null;
      return res.json({ tenant, role: member.role, discovery });
    } catch (err) {
      return res.status(err.status || 400).json({ error: err.code || 'invalid_request', error_description: err.message });
    }
  });

  // Suspend or reactivate own tenant (owner only)
  router.post('/tenants/:tenantId/status', async (req, res) => {
    try {
      await tenantService.requireTenantRole(req.params.tenantId, req.user.uid, ['owner']);
      const { status, reason } = req.body || {};
      if (!['active', 'suspended'].includes(status)) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'status must be active or suspended' });
      }
      const result = await tenantService.updateTenantStatus(req.params.tenantId, status, req.user.uid, reason);
      return res.json(result);
    } catch (err) {
      return res.status(err.status || 400).json({ error: err.code || 'invalid_request', error_description: err.message });
    }
  });

  // List OAuth clients for this tenant
  router.get('/tenants/:tenantId/clients', async (req, res) => {
    try {
      await tenantService.requireTenantRole(req.params.tenantId, req.user.uid, ['owner', 'admin', 'developer']);
      const clients = await clientRegistryService.listTenantClients(req.params.tenantId);
      return res.json({ clients });
    } catch (err) {
      return res.status(err.status || 400).json({ error: err.code || 'invalid_request', error_description: err.message });
    }
  });

  // Register a new OAuth client for this tenant (enforces plan maxApps entitlement)
  router.post('/tenants/:tenantId/clients', oauthAuthorizeLimiter, async (req, res) => {
    try {
      const { tenant } = await tenantService.requireTenantRole(req.params.tenantId, req.user.uid, ['owner', 'admin', 'developer']);
      if (tenant.status !== 'active') {
        return res.status(403).json({ error: 'tenant_suspended', error_description: 'Cannot create apps while tenant is suspended.' });
      }
      const existing = await clientRegistryService.listTenantClients(req.params.tenantId);
      const maxApps = tenant.entitlements?.maxApps ?? 3;
      if (existing.length >= maxApps) {
        return res.status(403).json({
          error: 'plan_limit_reached',
          error_description: `Your ${tenant.plan} plan allows up to ${maxApps} applications. Upgrade to add more.`
        });
      }

      const {
        clientId,
        name,
        redirectUris,
        allowedOrigins,
        allowedScopes,
        tokenEndpointAuthMethod = 'none'
      } = req.body || {};

      const generatedSecret = tokenEndpointAuthMethod === 'client_secret_post'
        ? `lzd_sec_${crypto.randomBytes(24).toString('hex')}`
        : undefined;

      const resolvedClientId = (typeof clientId === 'string' && clientId.trim())
        ? clientId.trim().toLowerCase()
        : `${req.params.tenantId.slice(0, 16)}-${crypto.randomBytes(4).toString('hex')}`;

      const client = await clientRegistryService.registerClient({
        tenantId: req.params.tenantId,
        clientId: resolvedClientId,
        name,
        redirectUris,
        allowedOrigins: allowedOrigins || [],
        allowedScopes,
        compatibilityMode: 'oidc',
        tokenEndpointAuthMethod,
        clientSecret: generatedSecret,
        enabled: true,
        auditLogService,
        auditContext: {
          actorUid: req.user.uid,
          actorEmail: req.user.email || null,
          ip: req.ip || null
        }
      });

      return res.status(201).json({
        client,
        ...(generatedSecret ? { clientSecret: generatedSecret } : {})
      });
    } catch (err) {
      if (String(err.message).includes('CLIENT_ALREADY_EXISTS')) {
        return res.status(409).json({ error: 'client_exists', error_description: err.message });
      }
      return res.status(err.status || 400).json({ error: err.code || 'invalid_request', error_description: err.message });
    }
  });

  // Update an OAuth client owned by this tenant
  router.patch('/tenants/:tenantId/clients/:clientId', async (req, res) => {
    try {
      await tenantService.requireTenantRole(req.params.tenantId, req.user.uid, ['owner', 'admin', 'developer']);
      const { name, redirectUris, allowedOrigins, allowedScopes, enabled } = req.body || {};
      const client = await clientRegistryService.updateClient({
        tenantId: req.params.tenantId,
        clientId: req.params.clientId,
        patch: { name, redirectUris, allowedOrigins, allowedScopes, enabled },
        auditLogService,
        auditContext: {
          actorUid: req.user.uid,
          actorEmail: req.user.email || null,
          ip: req.ip || null
        }
      });
      return res.json({ client });
    } catch (err) {
      if (String(err.message).includes('TENANT_OWNERSHIP_MISMATCH')) {
        return res.status(403).json({ error: 'forbidden', error_description: 'Client does not belong to this tenant.' });
      }
      if (String(err.message).includes('CLIENT_NOT_FOUND')) {
        return res.status(404).json({ error: 'not_found', error_description: err.message });
      }
      return res.status(err.status || 400).json({ error: err.code || 'invalid_request', error_description: err.message });
    }
  });

  // Rotate client secret for confidential client_secret_post apps
  router.post('/tenants/:tenantId/clients/:clientId/rotate-secret', async (req, res) => {
    try {
      await tenantService.requireTenantRole(req.params.tenantId, req.user.uid, ['owner', 'admin']);
      const result = await clientRegistryService.rotateClientSecret({
        tenantId: req.params.tenantId,
        clientId: req.params.clientId,
        auditLogService,
        auditContext: {
          actorUid: req.user.uid,
          actorEmail: req.user.email || null,
          ip: req.ip || null
        }
      });
      return res.json(result);
    } catch (err) {
      return res.status(err.status || 400).json({ error: err.code || 'invalid_request', error_description: err.message });
    }
  });

  // Tenant-scoped audit logs
  router.get('/tenants/:tenantId/audit-logs', async (req, res) => {
    try {
      await tenantService.requireTenantRole(req.params.tenantId, req.user.uid, ['owner', 'admin', 'developer']);
      if (!auditLogService || typeof auditLogService.listTenantAuditLogs !== 'function') {
        return res.json({ logs: [] });
      }
      const limit = Math.min(Number(req.query.limit) || 50, 100);
      const logs = await auditLogService.listTenantAuditLogs(req.params.tenantId, { limit });
      return res.json({ logs });
    } catch (err) {
      return res.status(err.status || 400).json({ error: err.code || 'invalid_request', error_description: err.message });
    }
  });

  // Tenant members management
  router.get('/tenants/:tenantId/members', async (req, res) => {
    try {
      await tenantService.requireTenantRole(req.params.tenantId, req.user.uid, ['owner', 'admin', 'developer']);
      const members = await tenantService.listMembers(req.params.tenantId);
      return res.json({ members });
    } catch (err) {
      return res.status(err.status || 400).json({ error: err.code || 'invalid_request', error_description: err.message });
    }
  });

  router.post('/tenants/:tenantId/members', async (req, res) => {
    try {
      await tenantService.requireTenantRole(req.params.tenantId, req.user.uid, ['owner', 'admin']);
      const { uid, email, role } = req.body || {};
      const member = await tenantService.upsertMember(req.params.tenantId, { uid, email, role });
      return res.status(201).json({ member });
    } catch (err) {
      return res.status(err.status || 400).json({ error: err.code || 'invalid_request', error_description: err.message });
    }
  });

  router.delete('/tenants/:tenantId/members/:uid', async (req, res) => {
    try {
      await tenantService.requireTenantRole(req.params.tenantId, req.user.uid, ['owner', 'admin']);
      const result = await tenantService.removeMember(req.params.tenantId, req.params.uid);
      return res.json(result);
    } catch (err) {
      return res.status(err.status || 400).json({ error: err.code || 'invalid_request', error_description: err.message });
    }
  });

  return router;
}

module.exports = { createDeveloperRouter };
