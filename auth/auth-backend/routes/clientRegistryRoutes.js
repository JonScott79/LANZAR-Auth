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

function createClientRegistryRouter({ clientRegistryService, authenticateAdminMiddleware, auditLogService }) {
    const router = express.Router();

    const requireAdmin = authenticateAdminMiddleware || ((req, res) => {
        return res.status(503).json({ error: 'service_unavailable', error_description: 'Admin authentication unavailable.' });
    });

    const buildAuditContext = (req) => {
        const user = req.user || {};
        const adminCtx = req.adminContext || {};
        return {
            actorUid: adminCtx.uid || req.uid || user.uid || 'unknown',
            actorEmail: user.email || null,
            actorTenantId: adminCtx.tenantId || user.tenantId || 'lanzar',
            actorRole: (adminCtx.isPlatformAdmin || req.adminRole === 'platform_admin') ? 'platform_admin' : 'tenant_admin',
            correlationId: req.headers['x-correlation-id'] || req.headers['x-request-id'] || null
        };
    };

    const recordAudit = async (req, { targetTenantId, clientId = null, operation, outcome = 'success', reason = null, metadata = {}, strict = false }) => {
        if (!auditLogService || typeof auditLogService.recordAdminEvent !== 'function') return;
        await auditLogService.recordAdminEvent({
            ...buildAuditContext(req),
            targetTenantId,
            clientId,
            operation,
            outcome,
            reason,
            metadata,
            strict
        });
    };

    router.post('/clients', requireAdmin, async (req, res) => {
        const body = req.body || {};
        try {
            if (!clientRegistryService) {
                return res.status(503).json({ error: 'service_unavailable', error_description: 'Client registry unavailable.' });
            }
            const scope = resolveAdminTenantScope(req);
            if (scope.error) {
                await recordAudit(req, { targetTenantId: 'lanzar', clientId: body.clientId, operation: 'client.register', outcome: 'denied', reason: scope.error });
                return res.status(403).json({ error: 'forbidden', error_description: 'TENANT_AUTHORIZATION_DENIED: Malformed tenant claim.' });
            }
            const { isPlatformAdmin, authorizedTenantId } = scope;
            if (!isPlatformAdmin && body.tenantId !== undefined && body.tenantId !== authorizedTenantId) {
                await recordAudit(req, { targetTenantId: body.tenantId, clientId: body.clientId, operation: 'client.register', outcome: 'denied', reason: 'TENANT_AUTHORIZATION_DENIED' });
                return res.status(403).json({
                    error: 'forbidden',
                    error_description: 'TENANT_AUTHORIZATION_DENIED: Cannot register clients for another tenant.'
                });
            }
            const targetTenantId = isPlatformAdmin ? (body.tenantId || authorizedTenantId) : authorizedTenantId;
            const created = await clientRegistryService.registerClient({
                ...body,
                tenantId: targetTenantId,
                auditLogService,
                auditContext: buildAuditContext(req)
            });
            return res.status(201).json({ client: created });
        } catch (error) {
            const msg = error.message || 'Failed to register client.';
            if (msg.startsWith('AUDIT_WRITE_FAILED')) {
                return res.status(503).json({ error: 'service_unavailable', error_description: 'Audit trail unavailable; administrative operation failed closed.' });
            }
            const status = msg.startsWith('CLIENT_ALREADY_EXISTS') ? 409 : 400;
            await recordAudit(req, { targetTenantId: body.tenantId || 'lanzar', clientId: body.clientId, operation: 'client.register', outcome: 'error', reason: msg, strict: false });
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
                await recordAudit(req, { targetTenantId: requestedTenantId, operation: 'client.seed_internal', outcome: 'denied', reason: 'TENANT_AUTHORIZATION_DENIED' });
                return res.status(403).json({
                    error: 'forbidden',
                    error_description: 'TENANT_AUTHORIZATION_DENIED: Internal client bootstrap is restricted to the lanzar tenant or platform administrators.'
                });
            }
            const result = await clientRegistryService.seedApprovedInternalClients({
                tenantId: requestedTenantId,
                auditLogService,
                auditContext: buildAuditContext(req)
            });
            return res.status(200).json(result);
        } catch (error) {
            const msg = error.message || 'Seed failed.';
            if (msg.startsWith('AUDIT_WRITE_FAILED')) {
                return res.status(503).json({ error: 'service_unavailable', error_description: 'Audit trail unavailable; administrative operation failed closed.' });
            }
            return res.status(400).json({ error: 'seed_failed', error_description: msg });
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
                await recordAudit(req, { targetTenantId: client.tenantId, clientId: req.params.clientId, operation: 'client.read', outcome: 'denied', reason: 'TENANT_AUTHORIZATION_DENIED' });
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
        const body = req.body || {};
        try {
            if (!clientRegistryService) {
                return res.status(503).json({ error: 'service_unavailable', error_description: 'Client registry unavailable.' });
            }
            const scope = resolveAdminTenantScope(req);
            if (scope.error) {
                return res.status(403).json({ error: 'forbidden', error_description: 'TENANT_AUTHORIZATION_DENIED: Malformed tenant claim.' });
            }
            const { isPlatformAdmin, authorizedTenantId } = scope;
            if (!isPlatformAdmin && body.tenantId !== undefined && body.tenantId !== authorizedTenantId) {
                await recordAudit(req, { targetTenantId: body.tenantId, clientId: req.params.clientId, operation: 'client.update', outcome: 'denied', reason: 'TENANT_AUTHORIZATION_DENIED' });
                return res.status(403).json({
                    error: 'forbidden',
                    error_description: 'TENANT_AUTHORIZATION_DENIED: Cannot update clients for another tenant.'
                });
            }
            const tenantId = isPlatformAdmin ? (body.tenantId || authorizedTenantId) : authorizedTenantId;
            const updated = await clientRegistryService.updateClient({
                tenantId,
                clientId: req.params.clientId,
                patch: body,
                auditLogService,
                auditContext: buildAuditContext(req)
            });
            return res.status(200).json({ client: updated });
        } catch (error) {
            const msg = error.message || 'Failed to update client.';
            if (msg.startsWith('AUDIT_WRITE_FAILED')) {
                return res.status(503).json({ error: 'service_unavailable', error_description: 'Audit trail unavailable; administrative operation failed closed.' });
            }
            const status = msg.startsWith('CLIENT_NOT_FOUND') ? 404 : (msg.startsWith('TENANT_OWNERSHIP_MISMATCH') ? 403 : 400);
            await recordAudit(req, { targetTenantId: body.tenantId || 'lanzar', clientId: req.params.clientId, operation: 'client.update', outcome: status === 403 ? 'denied' : 'error', reason: msg, strict: false });
            return res.status(status).json({ error: 'invalid_client_metadata', error_description: msg });
        }
    });

    router.post('/clients/:clientId/disable', requireAdmin, async (req, res) => {
        const body = req.body || {};
        try {
            if (!clientRegistryService) {
                return res.status(503).json({ error: 'service_unavailable', error_description: 'Client registry unavailable.' });
            }
            const scope = resolveAdminTenantScope(req);
            if (scope.error) {
                return res.status(403).json({ error: 'forbidden', error_description: 'TENANT_AUTHORIZATION_DENIED: Malformed tenant claim.' });
            }
            const { isPlatformAdmin, authorizedTenantId } = scope;
            if (!isPlatformAdmin && body.tenantId !== undefined && body.tenantId !== authorizedTenantId) {
                await recordAudit(req, { targetTenantId: body.tenantId, clientId: req.params.clientId, operation: 'client.disable', outcome: 'denied', reason: 'TENANT_AUTHORIZATION_DENIED' });
                return res.status(403).json({ error: 'forbidden', error_description: 'TENANT_AUTHORIZATION_DENIED: Cannot disable clients for another tenant.' });
            }
            const tenantId = isPlatformAdmin ? (body.tenantId || authorizedTenantId) : authorizedTenantId;
            const updated = await clientRegistryService.disableClient({
                tenantId,
                clientId: req.params.clientId,
                reason: body.reason || 'admin_disabled',
                auditLogService,
                auditContext: buildAuditContext(req)
            });
            return res.status(200).json({ client: updated });
        } catch (error) {
            const msg = error.message || 'Failed to disable client.';
            if (msg.startsWith('AUDIT_WRITE_FAILED')) {
                return res.status(503).json({ error: 'service_unavailable', error_description: 'Audit trail unavailable; administrative operation failed closed.' });
            }
            const status = msg.startsWith('CLIENT_NOT_FOUND') ? 404 : (msg.startsWith('TENANT_OWNERSHIP_MISMATCH') ? 403 : 400);
            return res.status(status).json({ error: 'invalid_client_metadata', error_description: msg });
        }
    });

    router.post('/clients/:clientId/enable', requireAdmin, async (req, res) => {
        const body = req.body || {};
        try {
            if (!clientRegistryService) {
                return res.status(503).json({ error: 'service_unavailable', error_description: 'Client registry unavailable.' });
            }
            const scope = resolveAdminTenantScope(req);
            if (scope.error) {
                return res.status(403).json({ error: 'forbidden', error_description: 'TENANT_AUTHORIZATION_DENIED: Malformed tenant claim.' });
            }
            const { isPlatformAdmin, authorizedTenantId } = scope;
            if (!isPlatformAdmin && body.tenantId !== undefined && body.tenantId !== authorizedTenantId) {
                await recordAudit(req, { targetTenantId: body.tenantId, clientId: req.params.clientId, operation: 'client.enable', outcome: 'denied', reason: 'TENANT_AUTHORIZATION_DENIED' });
                return res.status(403).json({ error: 'forbidden', error_description: 'TENANT_AUTHORIZATION_DENIED: Cannot enable clients for another tenant.' });
            }
            const tenantId = isPlatformAdmin ? (body.tenantId || authorizedTenantId) : authorizedTenantId;
            const updated = await clientRegistryService.enableClient({
                tenantId,
                clientId: req.params.clientId,
                auditLogService,
                auditContext: buildAuditContext(req)
            });
            return res.status(200).json({ client: updated });
        } catch (error) {
            const msg = error.message || 'Failed to enable client.';
            if (msg.startsWith('AUDIT_WRITE_FAILED')) {
                return res.status(503).json({ error: 'service_unavailable', error_description: 'Audit trail unavailable; administrative operation failed closed.' });
            }
            const status = msg.startsWith('CLIENT_NOT_FOUND') ? 404 : (msg.startsWith('TENANT_OWNERSHIP_MISMATCH') ? 403 : 400);
            return res.status(status).json({ error: 'invalid_client_metadata', error_description: msg });
        }
    });

    router.get('/audit-logs', requireAdmin, async (req, res) => {
        try {
            if (!auditLogService) {
                return res.status(503).json({ error: 'service_unavailable', error_description: 'Audit log service unavailable.' });
            }
            const scope = resolveAdminTenantScope(req);
            if (scope.error) {
                return res.status(403).json({ error: 'forbidden', error_description: 'TENANT_AUTHORIZATION_DENIED: Malformed tenant claim.' });
            }
            const { isPlatformAdmin, authorizedTenantId } = scope;
            const requestedTenant = req.query && req.query.tenantId ? String(req.query.tenantId) : authorizedTenantId;
            if (!isPlatformAdmin && requestedTenant !== authorizedTenantId) {
                return res.status(403).json({ error: 'forbidden', error_description: 'TENANT_AUTHORIZATION_DENIED: Cannot read another tenant audit logs.' });
            }
            const logs = await auditLogService.listTenantAuditLogs(requestedTenant, {
                limit: Math.min(Number(req.query && req.query.limit) || 50, 200)
            });
            return res.status(200).json({ logs });
        } catch (error) {
            return res.status(500).json({ error: 'server_error', error_description: error.message });
        }
    });

    return router;
}

module.exports = { createClientRegistryRouter };
