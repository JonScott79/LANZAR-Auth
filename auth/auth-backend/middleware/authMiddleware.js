// authMiddleware.js
// Shared Authentication & Authorization Middleware for LANZAR ID

function createAuthMiddleware({ db, authAdmin, sessionService }) {
  async function isUserAdmin(uid, email) {
    if (!uid && !email) return false;
    try {
      if (uid) {
        const adminDoc = await db.collection('admins').doc(uid).get();
        if (adminDoc.exists && adminDoc.data().active === true) {
          return true;
        }
      }
      if (email) {
        const emailQuery = await db.collection('admins')
          .where('email', '==', email.toLowerCase())
          .where('active', '==', true)
          .limit(1)
          .get();
        if (!emailQuery.empty) {
          return true;
        }
      }
      return false;
    } catch (e) {
      console.error('[AUTH ADMIN CHECK ERROR]', e.message);
      return false;
    }
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

      // Server-enforced individual session check if session_id is in claims
      if (decoded.session_id && sessionService) {
        const isRevoked = await sessionService.isSessionRevoked(decoded.uid, decoded.session_id);
        if (isRevoked) {
          return res.status(401).json({ error: 'session_revoked', error_description: 'This device session has been revoked.' });
        }
      }

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
      const isAdmin = await isUserAdmin(req.uid, req.user.email);
      if (!isAdmin) {
        return res.status(403).json({ error: 'forbidden', error_description: 'Administrative access required.' });
      }
      req.isAdmin = true;
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
