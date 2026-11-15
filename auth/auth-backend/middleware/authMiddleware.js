// authMiddleware.js
// Shared Authentication & Authorization Middleware for LANZAR ID

function createAuthMiddleware({ db, authAdmin, sessionService }) {
  async function getAdminRecord(uid, email) {
    if (!uid && !email) return null;
    try {
      if (uid) {
        const adminDoc = await db.collection('admins').doc(uid).get();
        if (adminDoc.exists && adminDoc.data().active === true) {
          return adminDoc.data();
        }
      }
      if (email) {
        const emailQuery = await db.collection('admins')
          .where('email', '==', email.toLowerCase())
          .where('active', '==', true)
          .limit(1)
          .get();
        if (!emailQuery.empty) {
          return emailQuery.docs[0].data();
        }
      }
      return null;
    } catch (e) {
      console.error('[AUTH ADMIN CHECK ERROR]', e.message);
      return null;
    }
  }

  async function isUserAdmin(uid, email) {
    const record = await getAdminRecord(uid, email);
    return Boolean(record);
  }

  async function authenticateUserMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'unauthorized', error_description: 'Missing Bearer token.' });
    }

    const token = authHeader.slice(7).trim();

    try {
      // Enforce checkRevoked: true against Google validAfterTime
      const decoded = await authAdmin.verifyIdToken(token, true);
      req.user = decoded;
      req.uid = decoded.uid;

      // Check user account status
      const userDoc = await db.collection('users').doc(decoded.uid).get();
      if (userDoc.exists && userDoc.data().status === 'suspended') {
        return res.status(403).json({ error: 'account_suspended', error_description: 'This account has been suspended.' });
      }

      // Mandatory LANZAR ID Session Enforcement (LID-SEC-004)
      const sessionId = (typeof decoded.session_id === 'string' && decoded.session_id.trim())
        ? decoded.session_id.trim()
        : ((typeof decoded.lanzarSessionId === 'string' && decoded.lanzarSessionId.trim())
          ? decoded.lanzarSessionId.trim()
          : null);

      if (!sessionId) {
        return res.status(401).json({
          error: 'missing_session',
          error_description: 'Authentication token is missing a valid LANZAR ID session identifier.'
        });
      }

      if (!sessionService) {
        console.error('[AUTH ERROR] SessionService unavailable during authentication check');
        return res.status(500).json({
          error: 'server_error',
          error_description: 'Session verification service unavailable.'
        });
      }

      req.sessionId = sessionId;

      // Validate session against authoritative server-side record with UID binding
      const state = typeof sessionService.checkSession === 'function'
        ? await sessionService.checkSession(decoded.uid, sessionId)
        : { active: !(await sessionService.isSessionRevoked(decoded.uid, sessionId)), reason: 'active' };

      if (!state.active) {
        if (state.reason === 'expired') {
          return res.status(401).json({
            error: 'session_expired',
            error_description: 'This device session has expired. Please sign in again.'
          });
        }
        if (state.reason === 'uid_mismatch') {
          return res.status(401).json({
            error: 'session_mismatch',
            error_description: 'Session does not belong to the authenticated user.'
          });
        }
        return res.status(401).json({
          error: 'session_revoked',
          error_description: 'This device session has been revoked or is invalid.'
        });
      }

      req.sessionExpiresAt = state.expiresAt || null;
      next();
    } catch (err) {
      if (err.code === 'auth/id-token-revoked') {
        return res.status(401).json({ error: 'token_revoked', error_description: 'Token has been revoked. Please sign in again.' });
      }
      return res.status(401).json({ error: 'invalid_token', error_description: err.message });
    }
  }

  async function authenticateAdminMiddleware(req, res, next) {
    authenticateUserMiddleware(req, res, async () => {
      const adminRecord = await getAdminRecord(req.uid, req.user.email);
      if (!adminRecord) {
        return res.status(403).json({ error: 'forbidden', error_description: 'Administrative access required.' });
      }
      const isPlatformAdmin = Boolean(
        adminRecord.platformAdmin === true ||
        adminRecord.role === 'platform_admin' ||
        (req.user && (req.user.platformAdmin === true || req.user.role === 'platform_admin'))
      );
      const authoritativeTenantId = adminRecord.tenantId !== undefined
        ? adminRecord.tenantId
        : (req.user ? req.user.tenantId : undefined);
      req.isAdmin = true;
      req.adminRole = isPlatformAdmin ? 'platform_admin' : 'tenant_admin';
      req.adminContext = {
        uid: req.uid,
        isPlatformAdmin,
        tenantId: authoritativeTenantId
      };
      next();
    });
  }

  return {
    isUserAdmin,
    authenticateUserMiddleware,
    authenticateAdminMiddleware
  };
}

module.exports = { createAuthMiddleware };
