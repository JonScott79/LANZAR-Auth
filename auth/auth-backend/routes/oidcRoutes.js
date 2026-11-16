// oidcRoutes.js
// Milestone 1.3: OIDC Discovery (`/.well-known/openid-configuration`) & UserInfo (`/oauth/userinfo`)

const express = require('express');
const { hasScope } = require('../services/oidcTokenService');

function createOidcRouter({ oidcTokenService, db, clientRegistryService }) {
    const router = express.Router();

    const handleDiscovery = (req, res) => {
        if (!oidcTokenService || typeof oidcTokenService.getDiscoveryDocument !== 'function') {
            return res.status(503).json({
                error: 'service_unavailable',
                error_description: 'OIDC discovery service is unavailable.'
            });
        }
        res.set('Cache-Control', 'public, max-age=300');
        return res.status(200).json(oidcTokenService.getDiscoveryDocument());
    };

    router.get('/.well-known/openid-configuration', handleDiscovery);
    router.get('/nova/.well-known/openid-configuration', (req, res) => {
        const issuer = oidcTokenService && typeof oidcTokenService.getIssuer === 'function' ? oidcTokenService.getIssuer() : '';
        if (!issuer.endsWith('/nova')) {
            return res.status(404).json({ error: 'not_found', error_description: 'NOVA discovery endpoint is only active in NOVA staging.' });
        }
        return handleDiscovery(req, res);
    });

    router.get('/oauth/userinfo', async (req, res) => {
        try {
            if (!oidcTokenService || typeof oidcTokenService.verifyAccessToken !== 'function') {
                return res.status(503).json({
                    error: 'service_unavailable',
                    error_description: 'OIDC token verification service is unavailable.'
                });
            }

            const authHeader = req.headers.authorization || '';
            if (!authHeader.startsWith('Bearer ')) {
                res.set('WWW-Authenticate', 'Bearer error="invalid_token"');
                return res.status(401).json({
                    error: 'invalid_token',
                    error_description: 'Missing Bearer access token.'
                });
            }

            const token = authHeader.slice(7).trim();
            if (!token) {
                res.set('WWW-Authenticate', 'Bearer error="invalid_token"');
                return res.status(401).json({
                    error: 'invalid_token',
                    error_description: 'Empty Bearer access token.'
                });
            }

            const verified = await oidcTokenService.verifyAccessToken(token, {
                expectedAudience: typeof oidcTokenService.getUserinfoAudience === 'function'
                    ? oidcTokenService.getUserinfoAudience()
                    : undefined
            });
            if (!verified.valid) {
                res.set('WWW-Authenticate', `Bearer error="invalid_token", error_description="${verified.reason}"`);
                return res.status(401).json({
                    error: 'invalid_token',
                    error_description: `Access token rejected: ${verified.reason}`
                });
            }

            const { payload } = verified;
            const uid = payload.sub;
            const sessionId = payload.session_id;
            if (!uid || !sessionId) {
                return res.status(401).json({
                    error: 'invalid_token',
                    error_description: 'Access token missing subject or session binding.'
                });
            }

            // Online session validation: immediate revocation enforcement on UserInfo
            if (!db || typeof db.collection !== 'function') {
                return res.status(503).json({
                    error: 'service_unavailable',
                    error_description: 'Session backend unavailable.'
                });
            }

            const sessionSnap = await db.collection('users').doc(uid).collection('sessions').doc(sessionId).get();
            if (!sessionSnap.exists) {
                return res.status(401).json({
                    error: 'invalid_token',
                    error_description: 'Session not found or revoked.'
                });
            }
            const sessionData = sessionSnap.data() || {};
            if (sessionData.status !== 'active' || sessionData.revoked === true) {
                return res.status(401).json({
                    error: 'invalid_token',
                    error_description: 'Session has been revoked.'
                });
            }
            if (sessionData.uid && sessionData.uid !== uid) {
                return res.status(401).json({
                    error: 'invalid_token',
                    error_description: 'Session subject mismatch.'
                });
            }
            if (!sessionData.tenantId || sessionData.tenantId !== payload.tenant_id) {
                return res.status(401).json({
                    error: 'invalid_token',
                    error_description: 'Session tenant mismatch.'
                });
            }
            if (sessionData.clientId && payload.azp && sessionData.clientId !== payload.azp) {
                return res.status(401).json({
                    error: 'invalid_token',
                    error_description: 'Session client mismatch.'
                });
            }
            const requestedTenant = req.headers['x-lanzar-tenant-id'] || (req.query && req.query.tenant_id);
            if (requestedTenant && String(requestedTenant) !== payload.tenant_id) {
                return res.status(403).json({
                    error: 'forbidden',
                    error_description: 'Token tenant does not match requested tenant.'
                });
            }
            if (clientRegistryService && typeof clientRegistryService.resolveClient === 'function' && payload.azp) {
                const boundClient = await clientRegistryService.resolveClient(payload.azp);
                if (!boundClient || !boundClient.enabled || (boundClient.tenantId && boundClient.tenantId !== payload.tenant_id)) {
                    return res.status(401).json({
                        error: 'invalid_token',
                        error_description: 'Client is disabled or unauthorized for this tenant.'
                    });
                }
            }

            const scope = typeof payload.scope === 'string' ? payload.scope : '';
            const claims = {
                sub: uid,
                tenant_id: payload.tenant_id || sessionData.tenantId || 'lanzar'
            };

            // Optionally enrich from user document if profile/email scope requested
            let userData = null;
            if (hasScope(scope, 'email') || hasScope(scope, 'profile')) {
                const userSnap = await db.collection('users').doc(uid).get();
                if (userSnap.exists) {
                    userData = userSnap.data() || {};
                }
            }

            if (hasScope(scope, 'email') && userData) {
                if (userData.email !== undefined) claims.email = userData.email;
                if (userData.emailVerified !== undefined) claims.email_verified = Boolean(userData.emailVerified);
            }
            if (hasScope(scope, 'profile') && userData) {
                if (userData.displayName !== undefined) claims.name = userData.displayName;
                else if (userData.name !== undefined) claims.name = userData.name;
            }

            return res.status(200).json(claims);
        } catch (error) {
            console.error('[USERINFO ERROR]', error.message);
            return res.status(503).json({
                error: 'service_unavailable',
                error_description: 'Failed to process UserInfo request.'
            });
        }
    });

    return router;
}

module.exports = { createOidcRouter };
