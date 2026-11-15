// jwksRoutes.js
// Milestone 1.2: Public JWKS Discovery Endpoint (`GET /.well-known/jwks.json`)

const express = require('express');

function createJwksRouter({ signingKeystore }) {
    const router = express.Router();

    router.get('/.well-known/jwks.json', async (req, res) => {
        try {
            if (!signingKeystore || typeof signingKeystore.getPublicJwks !== 'function') {
                return res.status(503).json({
                    error: 'service_unavailable',
                    error_description: 'Signing keystore is unavailable.'
                });
            }

            const jwks = await signingKeystore.getPublicJwks();
            res.set('Cache-Control', 'public, max-age=60');
            return res.status(200).json(jwks);
        } catch (error) {
            console.error('[JWKS ERROR]', error.message);
            return res.status(503).json({
                error: 'service_unavailable',
                error_description: 'Failed to load public signing keys.'
            });
        }
    });

    return router;
}

module.exports = { createJwksRouter };
