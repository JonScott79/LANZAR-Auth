// phoneRoutes.js
// Phone authentication and verification endpoints for LANZAR ID

const express = require('express');
const { phoneDispatchLimiter } = require('../middleware/rateLimiter');

function createPhoneRouter({ smsService, authenticateUserMiddleware }) {
  const router = express.Router();

  router.post('/send-otp', authenticateUserMiddleware, phoneDispatchLimiter, async (req, res) => {
    try {
      const { phoneNumber } = req.body;
      const result = await smsService.sendVerificationOTP(req.uid, phoneNumber, req.ip);
      return res.json(result);
    } catch (err) {
      return res.status(400).json({ error: 'phone_verification_error', error_description: err.message });
    }
  });

  router.post('/verify', authenticateUserMiddleware, async (req, res) => {
    try {
      const { phoneNumber, code } = req.body;
      const result = await smsService.verifyOTP(req.uid, phoneNumber, code);
      return res.json(result);
    } catch (err) {
      return res.status(400).json({ error: 'phone_verification_error', error_description: err.message });
    }
  });

  return router;
}

module.exports = { createPhoneRouter };
