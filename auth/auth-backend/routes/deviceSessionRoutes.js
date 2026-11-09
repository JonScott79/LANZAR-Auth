// deviceSessionRoutes.js
// Device session management & revocation endpoints for LANZAR ID

const express = require('express');

function createDeviceSessionRouter({ sessionService, authenticateUserMiddleware }) {
  const router = express.Router();

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
