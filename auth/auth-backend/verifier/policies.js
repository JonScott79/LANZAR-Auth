// policies.js
// Authorization Policies A, B, and C (LID-ARCH-REV-015 §5.2, §5.3, §5.4)

const { VerifierError } = require('./commonVerifier');

function createPolicyMiddleware(commonVerifier, db) {
  return {
    /**
     * Policy A: Customer Account Services (id_portal)
     */
    async enforcePolicyA(req, res, next) {
      try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return res.status(401).json({ error: 'Missing or malformed Authorization header', code: 'UNAUTHORIZED' });
        }
        const token = authHeader.split('Bearer ')[1].trim();
        const context = await commonVerifier(token, 'id_portal');
        req.authContext = context;
        next();
      } catch (err) {
        return res.status(err.status || 401).json({ error: err.message, code: err.code || 'UNAUTHORIZED' });
      }
    },

    /**
     * Policy B: Commercial Products (pythos, tickets, threadline)
     */
    enforcePolicyB(productName) {
      return async (req, res, next) => {
        try {
          const authHeader = req.headers.authorization;
          if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Missing or malformed Authorization header', code: 'UNAUTHORIZED' });
          }
          const token = authHeader.split('Bearer ')[1].trim();
          const context = await commonVerifier(token, productName);
          req.authContext = context;
          next();
        } catch (err) {
          return res.status(err.status || 401).json({ error: err.message, code: err.code || 'UNAUTHORIZED' });
        }
      };
    },

    /**
     * Policy C: Administrative Services (mission_control)
     */
    enforcePolicyC(requiredPermission = null) {
      return async (req, res, next) => {
        try {
          const authHeader = req.headers.authorization;
          if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Missing or malformed Authorization header', code: 'UNAUTHORIZED' });
          }
          const token = authHeader.split('Bearer ')[1].trim();
          const context = await commonVerifier(token, 'mission_control');

          // Uncached read of /user_security/{uid} to verify admin role
          const secSnap = await db.collection('user_security').doc(context.uid).get();
          if (!secSnap.exists) {
            return res.status(403).json({ error: 'User security profile not found', code: 'FORBIDDEN' });
          }
          const sec = secSnap.data();
          if (sec.role !== 'admin') {
            return res.status(403).json({ error: 'Administrative role required', code: 'ADMINISTRATIVE_ROLE_REQUIRED' });
          }

          if (requiredPermission) {
            const perms = Array.isArray(sec.adminPermissions) ? sec.adminPermissions : [];
            if (!perms.includes(requiredPermission) && !perms.includes('*')) {
              return res.status(403).json({
                error: `Missing required administrative permission: ${requiredPermission}`,
                code: 'ADMIN_PERMISSION_REQUIRED'
              });
            }
          }

          req.authContext = context;
          req.adminProfile = sec;
          next();
        } catch (err) {
          return res.status(err.status || 401).json({ error: err.message, code: err.code || 'UNAUTHORIZED' });
        }
      };
    }
  };
}

module.exports = {
  createPolicyMiddleware
};
