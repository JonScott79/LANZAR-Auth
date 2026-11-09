// sessionRoutes.js
// Central SSO Session & Token Exchange Endpoints (LID-ARCH-REV-015 §4.2, §4.3)

const express = require('express');
const { requireClientHeader } = require('../middleware/originValidator');

function createSessionRouter({ centralSessionService, cookieService, authAdmin, config }) {
  const router = express.Router();

  /**
   * POST /session/establish
   * Invoked after user credentials or MFA are verified.
   * Creates parent central session and sets host-only cookie.
   */
  router.post('/session/establish', requireClientHeader, async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          error: 'Missing Authorization header with Firebase ID token',
          code: 'UNAUTHORIZED'
        });
      }

      const idToken = authHeader.split('Bearer ')[1].trim();
      let decoded;
      try {
        decoded = await authAdmin.verifyIdToken(idToken, true);
      } catch (err) {
        return res.status(401).json({ error: `Invalid ID token: ${err.message}`, code: 'TOKEN_INVALID' });
      }

      const now = Math.floor(Date.now() / 1000);
      const authTime = decoded.auth_time || now;
      if (now - authTime > 300) {
        return res.status(401).json({ error: 'ID token is too old (auth_time > 5 minutes)', code: 'TOKEN_TOO_OLD' });
      }

      const uid = decoded.uid;
      const { centralSessionId, parentDoc } = await centralSessionService.createCentralSession({
        uid,
        userAgent: req.headers['user-agent'],
        ipAddress: req.ip
      });

      const jwtCookie = cookieService.mintSessionToken({
        sid: centralSessionId,
        uid,
        absoluteExpiresAt: parentDoc.absoluteExpiresAt
      });

      res.setHeader('Set-Cookie', cookieService.createSetCookieHeader(jwtCookie));
      return res.status(200).json({
        established: true,
        uid,
        centralSessionId,
        absoluteExpiresAt: parentDoc.absoluteExpiresAt
      });
    } catch (err) {
      console.error('[SESSION ESTABLISH ERROR]', err);
      return res.status(err.status || 500).json({
        error: err.message,
        code: err.code || 'SESSION_ESTABLISH_FAILED'
      });
    }
  });

  /**
   * GET /session/me
   * Strictly read-only session inspection.
   * ZERO Firestore writes.
   */
  router.get('/session/me', async (req, res) => {
    try {
      const cookieVal = cookieService.parseCookieFromHeaders(req.headers);
      if (!cookieVal) {
        return res.status(401).json({
          authenticated: false,
          error: 'No session cookie present',
          code: 'UNAUTHORIZED'
        });
      }

      let payload;
      try {
        payload = cookieService.verifySessionCookie(cookieVal);
      } catch (err) {
        return res.status(401).json({
          authenticated: false,
          error: `Invalid session cookie: ${err.message}`,
          code: err.code || 'INVALID_COOKIE'
        });
      }

      const info = await centralSessionService.inspectSession({
        uid: payload.uid,
        centralSessionId: payload.sid,
        clientAppId: req.clientAppId || 'unknown'
      });

      return res.status(200).json(info);
    } catch (err) {
      return res.status(err.status || 401).json({
        authenticated: false,
        error: err.message,
        code: err.code || 'SESSION_INSPECTION_FAILED'
      });
    }
  });

  /**
   * POST /session/token
   * Dedicated idempotent endpoint for exchanging central session cookie for Firebase Custom Token.
   * OD-6: Denied to auth_hub and marketing_site.
   */
  router.post('/session/token', requireClientHeader, async (req, res) => {
    try {
      const clientAppId = req.clientAppId;
      if (!clientAppId) {
        return res.status(400).json({
          error: 'Request must originate from an authorized client application',
          code: 'CLIENT_APP_REQUIRED'
        });
      }

      // OD-6 Check: strictly product apps + id_portal
      if (clientAppId === 'auth_hub' || clientAppId === 'marketing_site') {
        return res.status(403).json({
          error: `Token minting is prohibited for application "${clientAppId}"`,
          code: 'CLIENT_APP_NOT_PERMITTED'
        });
      }

      const cookieVal = cookieService.parseCookieFromHeaders(req.headers);
      if (!cookieVal) {
        return res.status(401).json({
          error: 'No session cookie present',
          code: 'UNAUTHORIZED'
        });
      }

      let payload;
      try {
        payload = cookieService.verifySessionCookie(cookieVal);
      } catch (err) {
        return res.status(401).json({
          error: `Invalid session cookie: ${err.message}`,
          code: err.code || 'INVALID_COOKIE'
        });
      }

      const result = await centralSessionService.exchangeChildSessionToken({
        uid: payload.uid,
        centralSessionId: payload.sid,
        clientAppId
      });

      return res.status(200).json(result);
    } catch (err) {
      return res.status(err.status || 500).json({
        error: err.message,
        code: err.code || 'TOKEN_EXCHANGE_FAILED'
      });
    }
  });

  /**
   * POST /session/logout
   * Revokes parent central session and all active child sessions; clears cookie.
   */
  router.post('/session/logout', requireClientHeader, async (req, res) => {
    try {
      const cookieVal = cookieService.parseCookieFromHeaders(req.headers);
      if (cookieVal) {
        try {
          const payload = cookieService.verifySessionCookie(cookieVal);
          await centralSessionService.logoutCentralSession({
            uid: payload.uid,
            centralSessionId: payload.sid
          });
        } catch (e) {
          // Ignore cookie verification errors on logout; still clear cookie
        }
      }

      res.setHeader('Set-Cookie', cookieService.createClearCookieHeader());
      return res.status(200).json({ loggedOut: true });
    } catch (err) {
      return res.status(err.status || 500).json({
        error: err.message,
        code: err.code || 'LOGOUT_FAILED'
      });
    }
  });

  /**
   * POST /auth/password-reset-complete
   * Auth-hub only endpoint called after successful password reset.
   * Increments tokenVersion, revokes all sessions, creates new central session, sets cookie.
   */
  router.post('/auth/password-reset-complete', requireClientHeader, async (req, res) => {
    try {
      if (req.clientAppId !== 'auth_hub') {
        return res.status(403).json({
          error: 'Password reset completion is restricted to auth_hub',
          code: 'CLIENT_APP_NOT_PERMITTED'
        });
      }

      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          error: 'Missing Authorization header with Firebase ID token',
          code: 'UNAUTHORIZED'
        });
      }

      const idToken = authHeader.split('Bearer ')[1].trim();
      let decoded;
      try {
        decoded = await authAdmin.verifyIdToken(idToken, true);
      } catch (err) {
        return res.status(401).json({ error: `Invalid ID token: ${err.message}`, code: 'TOKEN_INVALID' });
      }

      const now = Math.floor(Date.now() / 1000);
      const authTime = decoded.auth_time || now;
      if (now - authTime > 300) {
        return res.status(401).json({ error: 'ID token is too old (auth_time > 5 minutes)', code: 'TOKEN_TOO_OLD' });
      }

      const uid = decoded.uid;

      // 1. Revoke all previous user sessions & advance tokenVersion
      await centralSessionService.revokeAllUserSessions(uid, 'password_reset');

      // 2. Create fresh parent central session
      const { centralSessionId, parentDoc } = await centralSessionService.createCentralSession({
        uid,
        userAgent: req.headers['user-agent'],
        ipAddress: req.ip
      });

      // 3. Mint and set fresh host-only cookie
      const jwtCookie = cookieService.mintSessionToken({
        sid: centralSessionId,
        uid,
        absoluteExpiresAt: parentDoc.absoluteExpiresAt
      });

      res.setHeader('Set-Cookie', cookieService.createSetCookieHeader(jwtCookie));
      return res.status(200).json({
        resetComplete: true,
        uid,
        centralSessionId
      });
    } catch (err) {
      console.error('[PASSWORD RESET COMPLETE ERROR]', err);
      return res.status(err.status || 500).json({
        error: err.message,
        code: err.code || 'PASSWORD_RESET_COMPLETE_FAILED'
      });
    }
  });

  return router;
}

module.exports = {
  createSessionRouter
};
