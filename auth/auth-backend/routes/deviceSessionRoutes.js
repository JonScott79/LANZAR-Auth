// deviceSessionRoutes.js
// Device session management & revocation endpoints for LANZAR ID

const express = require('express');

function createDeviceSessionRouter({ db, sessionService, authenticateUserMiddleware, isUserAdmin }) {
  const router = express.Router();

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

  router.delete('/sessions/:sessionId', authenticateUserMiddleware, async (req, res) => {
    try {
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
