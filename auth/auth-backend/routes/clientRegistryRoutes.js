// clientRegistryRoutes.js
// Milestone 1.4: Admin API for Dynamic OAuth Client Registry (`/api/admin/id/clients`)

const express = require('express');
const { sanitizeClientForPublicRead } = require('../services/clientRegistryService');

const TENANT_ID_REGEX = /^[a-z0-9][a-z0-9_-]{1,63}$/;

function resolveAdminTenantScope(req) {
    const adminCtx = req.adminContext;
    const user = req.user || {};
    const isPlatformAdmin = adminCtx
        ? Boolean(adminCtx.isPlatformAdmin === true)
        : Boolean(user.platformAdmin === true || user.role === 'platform_admin' || req.adminRole === 'platform_admin');

    const rawTenantId = adminCtx ? adminCtx.tenantId : user.tenantId;
    if (rawTenantId !== undefined) {
        if (typeof rawTenantId !== 'string' || !TENANT_ID_REGEX.test(rawTenantId.trim())) {
            return { error: 'MALFORMED_TENANT_CLAIM' };
        }
        return { isPlatformAdmin, authorizedTenantId: rawTenantId.trim() };
    }
    return { isPlatformAdmin, authorizedTenantId: 'lanzar' };
}

function createClientRegistryRouter({ clientRegistryService, authenticateAdminMiddleware }) {
    const router = express.Router();

    const requireAdmin = authenticateAdminMiddleware || ((req, res) => {
        return res.status(503).json({ error: 'service_unavailable', error_description: 'Admin authentication unavailable.' });
    });

    router.post('/clients', requireAdmin, async (req, res) => {
        try {
            if (!clientRegistryService) {
                return res.status(503).json({ error: 'service_unavailable', error_description: 'Client registry unavailable.' });
            }
            const scope = resolveAdminTenantScope(req);
            if (scope.error) {
                return res.status(403).json({ error: 'forbidden', error_description: 'TENANT_AUTHORIZATION_DENIED: Malformed tenant claim.' });
            }
            const { isPlatformAdmin, authorizedTenantId } = scope;
            const body = req.body || {};
            if (!isPlatformAdmin && body.tenantId !== undefined && body.tenantId !== authorizedTenantId) {
                return res.status(403).json({
                    error: 'forbidden',
                    error_description: 'TENANT_AUTHORIZATION_DENIED: Cannot register clients for another tenant.'
                });
            }
            const targetTenantId = isPlatformAdmin ? (body.tenantId || authorizedTenantId) : authorizedTenantId;
            const created = await clientRegistryService.registerClient({ ...body, tenantId: targetTenantId });
            return res.status(201).json({ client: created });
        } catch (error) {
            const msg = error.message || 'Failed to register client.';
            const status = msg.startsWith('CLIENT_ALREADY_EXISTS') ? 409 : 400;
            return res.status(status).json({ error: 'invalid_client_metadata', error_description: msg });
        }
    });

    router.post('/clients/seed-internal', requireAdmin, async (req, res) => {
        try {
            if (!clientRegistryService) {
                return res.status(503).json({ error: 'service_unavailable', error_description: 'Client registry unavailable.' });
            }
            const scope = resolveAdminTenantScope(req);
            if (scope.error) {
                return res.status(403).json({ error: 'forbidden', error_description: 'TENANT_AUTHORIZATION_DENIED: Malformed tenant claim.' });
            }
            const { isPlatformAdmin, authorizedTenantId } = scope;
            const requestedTenantId = (req.body && req.body.tenantId) ? req.body.tenantId : authorizedTenantId;
            if (!isPlatformAdmin && (authorizedTenantId !== 'lanzar' || requestedTenantId !== 'lanzar')) {
                return res.status(403).json({
                    error: 'forbidden',
                    error_description: 'TENANT_AUTHORIZATION_DENIED: Internal client bootstrap is restricted to the lanzar tenant or platform administrators.'
                });
            }
            const result = await clientRegistryService.seedApprovedInternalClients({ tenantId: requestedTenantId });
            return res.status(200).json(result);
        } catch (error) {
            return res.status(400).json({ error: 'seed_failed', error_description: error.message });
        }
    });

    router.get('/clients/:clientId', requireAdmin, async (req, res) => {
        try {
            if (!clientRegistryService) {
                return res.status(503).json({ error: 'service_unavailable', error_description: 'Client registry unavailable.' });
            }
            const scope = resolveAdminTenantScope(req);
            if (scope.error) {
                return res.status(403).json({ error: 'forbidden', error_description: 'TENANT_AUTHORIZATION_DENIED: Malformed tenant claim.' });
            }
            const { isPlatformAdmin, authorizedTenantId } = scope;
            const client = await clientRegistryService.resolveClient(req.params.clientId);
            if (!client) {
                return res.status(404).json({ error: 'not_found', error_description: 'Client not found.' });
            }
            if (!isPlatformAdmin && client.tenantId !== authorizedTenantId) {
                return res.status(403).json({
                    error: 'forbidden',
                    error_description: 'TENANT_AUTHORIZATION_DENIED: Client belongs to another tenant.'
                });
            }
            return res.status(200).json({ client: sanitizeClientForPublicRead(client) });
        } catch (error) {
            return res.status(500).json({ error: 'server_error', error_description: error.message });
        }
    });

    router.patch('/clients/:clientId', requireAdmin, async (req, res) => {
        try {
            if (!clientRegistryService) {
                return res.status(503).json({ error: 'service_unavailable', error_description: 'Client registry unavailable.' });
            }
            const scope = resolveAdminTenantScope(req);
            if (scope.error) {
                return res.status(403).json({ error: 'forbidden', error_description: 'TENANT_AUTHORIZATION_DENIED: Malformed tenant claim.' });
            }
            const { isPlatformAdmin, authorizedTenantId } = scope;
            const body = req.body || {};
            if (!isPlatformAdmin && body.tenantId !== undefined && body.tenantId !== authorizedTenantId) {
                return res.status(403).json({
                    error: 'forbidden',
                    error_description: 'TENANT_AUTHORIZATION_DENIED: Cannot update clients for another tenant.'
                });
            }
            const tenantId = isPlatformAdmin ? (body.tenantId || authorizedTenantId) : authorizedTenantId;
            const updated = await clientRegistryService.updateClient({
                tenantId,
                clientId: req.params.clientId,
                patch: body
            });
            return res.status(200).json({ client: updated });
        } catch (error) {
            const msg = error.message || 'Failed to update client.';
            const status = msg.startsWith('CLIENT_NOT_FOUND') ? 404 : (msg.startsWith('TENANT_OWNERSHIP_MISMATCH') ? 403 : 400);
            return res.status(status).json({ error: 'invalid_client_metadata', error_description: msg });
        }
    });

    return router;
}

module.exports = { createClientRegistryRouter };
