// mfaRoutes.js
// Universal RFC 6238 TOTP and MFA recovery endpoints for LANZAR ID

const express = require('express');
const { FieldValue } = require('firebase-admin/firestore');
const {
  generateBase32Secret,
  verifyTOTP,
  encryptTotpSecret,
  decryptTotpSecret,
  stagePendingEnrollment,
  getPendingEnrollment,
  clearPendingEnrollment,
  generateRecoveryCodes,
  verifyAndConsumeRecoveryCode,
  createMfaSignedToken,
  verifyMfaSignedToken
} = require('../mfaService');
const { recordSecurityEvent } = require('../auditService');
const {
  mfaVerifyRateLimitMiddleware,
  recordMfaFailure,
  clearMfaFailures,
  getClientIp
} = require('../middleware/rateLimiter');

function createMfaRouter({ db, authAdmin, isUserAdmin }) {
  const router = express.Router();

  router.post('/status', async (req, res) => {
    try {
      const { idToken } = req.body;
      if (!idToken) return res.status(400).json({ error: 'missing_token' });
      const decoded = await authAdmin.verifyIdToken(idToken, true);
      const isAdmin = await isUserAdmin(decoded.uid, decoded.email);

      const mfaDoc = await db.collection('mfa_factors').doc(decoded.uid).get();
      const mfaData = mfaDoc.exists ? mfaDoc.data() : null;
      const isEnrolled = Boolean(mfaData && mfaData.enabled);

      return res.json({
        uid: decoded.uid,
        isAdmin,
        mfaRequired: isAdmin,
        mfaEnrolled: isEnrolled,
        factors: {
          totp: Boolean(mfaData && mfaData.totpSecret),
          recoveryCodesRemaining: Array.isArray(mfaData?.recoveryCodes) ? mfaData.recoveryCodes.filter(c => !c.used).length : 0
        }
      });
    } catch (err) {
      return res.status(401).json({ error: 'invalid_token', error_description: err.message });
    }
  });

  router.post('/totp/setup', async (req, res) => {
    try {
      const { idToken } = req.body;
      if (!idToken) return res.status(400).json({ error: 'missing_token' });
      const decoded = await authAdmin.verifyIdToken(idToken, true);

      const secret = generateBase32Secret(20);
      stagePendingEnrollment(decoded.uid, secret);

      const issuer = 'LANZAR ID';
      const otpauthUrl = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(decoded.email)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

      return res.json({
        success: true,
        secret,
        otpauthUrl
      });
    } catch (err) {
      return res.status(401).json({ error: 'invalid_token', error_description: err.message });
    }
  });

  router.post('/totp/enable', async (req, res) => {
    try {
      const { idToken, code } = req.body;
      if (!idToken || !code) return res.status(400).json({ error: 'missing_parameters' });
      const decoded = await authAdmin.verifyIdToken(idToken, true);

      const secret = getPendingEnrollment(decoded.uid);
      if (!secret) {
        return res.status(400).json({ error: 'setup_expired', error_description: 'MFA setup session expired. Please restart setup.' });
      }

      const isValid = verifyTOTP(secret, code, decoded.uid);
      if (!isValid) {
        return res.status(400).json({ error: 'invalid_code', error_description: 'Verification code incorrect. Please try again.' });
      }

      const encryptedSecretData = encryptTotpSecret(secret);
      const { plainCodes, hashedRecords } = generateRecoveryCodes(8);

      await db.collection('mfa_factors').doc(decoded.uid).set({
        uid: decoded.uid,
        email: decoded.email,
        enabled: true,
        totpSecret: encryptedSecretData,
        recoveryCodes: hashedRecords,
        enrolledAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp()
      }, { merge: true });

      clearPendingEnrollment(decoded.uid);

      await recordSecurityEvent(db, {
        actorUid: decoded.uid,
        actorEmail: decoded.email,
        action: 'mfa.totp.enrolled',
        targetUid: decoded.uid,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });

      return res.json({
        success: true,
        recoveryCodes: plainCodes
      });
    } catch (err) {
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  router.post('/verify', mfaVerifyRateLimitMiddleware, async (req, res) => {
    try {
      const { mfaSession, code, method } = req.body;
      if (!mfaSession || !code) return res.status(400).json({ error: 'missing_parameters' });

      const sessionPayload = verifyMfaSignedToken(mfaSession);
      if (!sessionPayload || sessionPayload.action !== 'mfa_challenge') {
        return res.status(401).json({ error: 'session_expired', error_description: 'MFA session has expired. Please sign in again.' });
      }

      const uid = sessionPayload.uid;
      const mfaDoc = await db.collection('mfa_factors').doc(uid).get();
      if (!mfaDoc.exists || !mfaDoc.data().enabled) {
        return res.status(400).json({ error: 'mfa_not_enrolled', error_description: 'MFA is not enrolled.' });
      }

      const mfaData = mfaDoc.data();
      let verified = false;

      if (method === 'recovery') {
        const recoveryResult = verifyAndConsumeRecoveryCode(code, mfaData.recoveryCodes || []);
        if (recoveryResult.valid) {
          verified = true;
          await db.collection('mfa_factors').doc(uid).update({
            recoveryCodes: recoveryResult.updatedRecords,
            updatedAt: FieldValue.serverTimestamp()
          });
          await recordSecurityEvent(db, {
            actorUid: uid,
            action: 'mfa.recovery_code.consumed',
            targetUid: uid,
            ipAddress: req.ip
          });
        }
      } else {
        const plainSecret = decryptTotpSecret(mfaData.totpSecret);
        verified = verifyTOTP(plainSecret, code, uid);
      }

      if (!verified) {
        recordMfaFailure(uid, method === 'recovery' ? 'recovery' : 'totp', getClientIp(req));
        return res.status(401).json({ error: 'invalid_code', error_description: 'The code provided is invalid or expired.' });
      }

      // Verification succeeded: reset failed attempt counter for this method
      clearMfaFailures(uid, method === 'recovery' ? 'recovery' : 'totp', getClientIp(req));

      const mfaProof = createMfaSignedToken({
        uid,
        email: sessionPayload.email,
        action: 'mfa_verified',
        verifiedAt: Date.now()
      }, 300000);

      return res.json({ success: true, mfaProof });
    } catch (err) {
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
  });

  return router;
}

module.exports = { createMfaRouter };
