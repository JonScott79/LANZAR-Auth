// profileRoutes.js
// Profile management and account erasure endpoints for LANZAR ID

const express = require('express');

function createProfileRouter({ profileService, authenticateUserMiddleware }) {
  const router = express.Router();

  router.get('/profile', authenticateUserMiddleware, async (req, res) => {
    try {
      const profile = await profileService.getUserProfile(req.uid);
      if (!profile) return res.status(404).json({ error: 'user_not_found' });
      return res.json(profile);
    } catch (err) {
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  router.put('/profile', authenticateUserMiddleware, async (req, res) => {
    try {
      const updated = await profileService.updateUserProfile(req.uid, req.body, req.ip);
      return res.json(updated);
    } catch (err) {
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  router.delete('/account', authenticateUserMiddleware, async (req, res) => {
    try {
      const result = await profileService.eraseUserAccount(req.uid, req.uid, req.ip);
      return res.json(result);
    } catch (err) {
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  return router;
}

module.exports = { createProfileRouter };
