// deviceSessionRoutes.js
// Device session management & revocation endpoints for LANZAR ID

const express = require('express');

function createDeviceSessionRouter({ db, authAdmin, sessionService, oidcTokenService, authenticateUserMiddleware, isUserAdmin }) {
  const router = express.Router();

  // Accepts either a Firebase ID token (authenticateUserMiddleware) OR a valid LANZAR ID OIDC RS256 access_token
  const authenticateSessionActor = async (req, res, next) => {
    const authHeader = req.headers.authorization || '';
    if (oidcTokenService && authHeader.startsWith('Bearer ')) {
      const token = authHeader.slice(7).trim();
      try {
        const oidcRes = await oidcTokenService.verifyAccessToken(token);
        if (oidcRes && oidcRes.valid && oidcRes.payload && oidcRes.payload.sub) {
          req.uid = oidcRes.payload.sub;
          req.sessionId = oidcRes.payload.session_id || null;
          req.user = oidcRes.payload;
          req.authMethod = 'oidc';
          return next();
        }
      } catch (_) {
        // Fall through to Firebase session middleware
      }
    }
    return authenticateUserMiddleware(req, res, next);
  };

  /**
   * Upgrades a standard Firebase ID token minted on auth_hub standalone sign-in
   * into a session_id-bound Firebase Custom Token so /api/id/* endpoints succeed.
   */
  router.post('/session/standalone', async (req, res) => {
    try {
      if (req.clientAppId && req.clientAppId !== 'auth_hub') {
        return res.status(403).json({
          error: 'client_app_not_permitted',
          error_description: 'Standalone session binding is restricted to auth_hub.'
        });
      }

      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          error: 'unauthorized',
          error_description: 'Missing Authorization Bearer token.'
        });
      }

      const idToken = authHeader.split('Bearer ')[1].trim();
      const decoded = await authAdmin.verifyIdToken(idToken, true);

      const userDoc = await db.collection('users').doc(decoded.uid).get();
      if (userDoc.exists && userDoc.data().status === 'suspended') {
        return res.status(403).json({
          error: 'account_suspended',
          error_description: 'This account has been suspended.'
        });
      }

      const existingSessionId = (typeof decoded.session_id === 'string' && decoded.session_id.trim())
        || (typeof decoded.lanzarSessionId === 'string' && decoded.lanzarSessionId.trim())
        || null;

      if (existingSessionId) {
        const state = await sessionService.checkSession(decoded.uid, existingSessionId);
        if (state.active) {
          return res.json({
            session_id: existingSessionId,
            already_bound: true
          });
        }
        return res.status(401).json({
          error: 'session_revoked',
          error_description: 'This session has been revoked or expired. Please sign in again.'
        });
      }

      const sessionRecord = await sessionService.createSession({
        uid: decoded.uid,
        clientId: 'lanzar-auth-hub',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        deviceName: 'LANZAR ID Account Portal'
      });

      const customToken = await authAdmin.createCustomToken(decoded.uid, {
        session_id: sessionRecord.sessionId,
        tenant_id: 'lanzar',
        client_id: 'lanzar-auth-hub'
      });

      return res.json({
        custom_token: customToken,
        customToken,
        session_id: sessionRecord.sessionId
      });
    } catch (err) {
      if (err.code === 'auth/id-token-revoked') {
        return res.status(401).json({ error: 'token_revoked', error_description: 'Token has been revoked. Please sign in again.' });
      }
      return res.status(401).json({ error: 'invalid_token', error_description: err.message });
    }
  });

  // Session validation & server-side identity resolution for relying clients (e.g. Portal).
  // authenticateUserMiddleware has already: verified the ID token (checkRevoked), rejected
  // suspended accounts, and rejected revoked/expired device sessions.
  // Administrator status is resolved here from the trusted admins collection, never from client claims.
  router.get('/session/validate', authenticateUserMiddleware, async (req, res) => {
    try {
      const email = req.user.email || null;
      const isAdmin = typeof isUserAdmin === 'function' ? await isUserAdmin(req.uid, email) : false;
      return res.json({
        valid: true,
        uid: req.uid,
        email,
        display_name: req.user.name || null,
        session_id: req.sessionId || null,
        expires_at: req.sessionExpiresAt || null,
        is_admin: isAdmin === true
      });
    } catch (err) {
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  router.get('/sessions', authenticateUserMiddleware, async (req, res) => {
    try {
      const sessions = await sessionService.listUserSessions(req.uid);
      return res.json({ sessions });
    } catch (err) {
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  router.delete('/sessions/:sessionId', authenticateSessionActor, async (req, res) => {
    try {
      if (req.authMethod === 'oidc' && req.sessionId && req.sessionId !== req.params.sessionId) {
        return res.status(403).json({ error: 'forbidden', error_description: 'OIDC token may only revoke its own session.' });
      }
      const result = await sessionService.revokeSession(req.uid, req.params.sessionId, req.uid, req.ip);
      return res.json(result);
    } catch (err) {
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  router.post('/sessions/revoke-all', authenticateUserMiddleware, async (req, res) => {
    try {
      const result = await sessionService.revokeAllSessions(req.uid, req.uid, req.ip);
      return res.json(result);
    } catch (err) {
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  return router;
}

module.exports = { createDeviceSessionRouter };
