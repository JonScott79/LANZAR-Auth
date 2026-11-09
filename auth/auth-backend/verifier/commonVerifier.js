// commonVerifier.js
// Authoritative 10-Point Session Verifier Pipeline (LID-ARCH-REV-015 §5.1)

class VerifierError extends Error {
  constructor(message, status = 401, code = 'VERIFICATION_FAILED') {
    super(message);
    this.name = 'VerifierError';
    this.status = status;
    this.code = code;
  }
}

/**
 * Creates the common session verifier function bound to the Firestore DB and Firebase Auth Admin.
 */
function createCommonVerifier(db, authAdmin, config) {
  const appEnv = config.appEnv;

  return async function verifyRequestSession(idToken, expectedClientApp = null) {
    const now = Math.floor(Date.now() / 1000);

    // 1 & 2. Verify Firebase ID Token Signature, Project ID, Expiration and Revocation
    let decoded;
    try {
      decoded = await authAdmin.verifyIdToken(idToken, true);
    } catch (err) {
      if (err.code === 'auth/id-token-expired') {
        throw new VerifierError('ID token is expired', 401, 'TOKEN_EXPIRED');
      }
      if (err.code === 'auth/id-token-revoked') {
        throw new VerifierError('ID token has been revoked in Firebase Auth', 401, 'TOKEN_REVOKED');
      }
      throw new VerifierError(`Invalid ID token: ${err.message}`, 401, 'TOKEN_INVALID');
    }

    const uid = decoded.uid;

    // 4. Token Claims Presence & Format
    const { lanzarSessionId, lanzarTokenVersion, lanzarClientApp } = decoded;

    if (
      !lanzarSessionId ||
      typeof lanzarSessionId !== 'string' ||
      lanzarTokenVersion === undefined ||
      typeof lanzarTokenVersion !== 'number' ||
      !lanzarClientApp ||
      typeof lanzarClientApp !== 'string'
    ) {
      throw new VerifierError('Token is missing required LANZAR session claims', 401, 'SESSION_CLAIM_INVALID');
    }

    if (expectedClientApp && lanzarClientApp !== expectedClientApp) {
      throw new VerifierError(
        `Token clientApp (${lanzarClientApp}) does not match expected clientApp (${expectedClientApp})`,
        403,
        'CROSS_PRODUCT_TOKEN_REJECTED'
      );
    }

    // Wrap Firestore reads in fail-closed error handling
    try {
      // 3. User Security Status (/user_security/{uid})
      const secRef = db.collection('user_security').doc(uid);
      const childRef = db.collection('users').doc(uid).collection('sessions').doc(lanzarSessionId);

      const [secSnap, childSnap] = await Promise.all([
        secRef.get(),
        childRef.get()
      ]);

      if (!secSnap.exists) {
        throw new VerifierError('User security profile not found', 403, 'ACCOUNT_NOT_FOUND');
      }
      const userSecurity = secSnap.data();

      if (userSecurity.accountStatus !== 'active') {
        throw new VerifierError('Account is suspended or inactive', 403, 'ACCOUNT_SUSPENDED');
      }

      // 5. Child Session Document Existence (/users/{uid}/sessions/{lanzarSessionId})
      if (!childSnap.exists) {
        throw new VerifierError('Child session document does not exist', 401, 'SESSION_NOT_FOUND');
      }
      const childSession = childSnap.data();

      // 6. Child Session Active Status
      if (childSession.revoked === true) {
        throw new VerifierError('Child session has been revoked', 401, 'SESSION_REVOKED');
      }
      if (childSession.expiresAt <= now) {
        throw new VerifierError('Child session has expired', 401, 'SESSION_EXPIRED');
      }

      // 7. Authoritative Parent Central Session Verification (/users/{uid}/central_sessions/{centralSessionId})
      if (!childSession.centralSessionId) {
        throw new VerifierError('Child session missing parent centralSessionId foreign key', 401, 'SESSION_CLAIM_INVALID');
      }

      const parentRef = db
        .collection('users')
        .doc(uid)
        .collection('central_sessions')
        .doc(childSession.centralSessionId);

      const parentSnap = await parentRef.get();
      if (!parentSnap.exists) {
        throw new VerifierError('Parent central session not found', 401, 'CENTRAL_SESSION_NOT_FOUND');
      }
      const parent = parentSnap.data();

      if (parent.uid !== uid) {
        throw new VerifierError('Parent central session UID does not match token UID', 401, 'SESSION_CLAIM_MISMATCH');
      }
      if (parent.env !== appEnv) {
        throw new VerifierError(`Parent central session environment (${parent.env}) does not match server (${appEnv})`, 401, 'ENVIRONMENT_MISMATCH');
      }
      if (parent.revoked === true) {
        throw new VerifierError('Parent central session has been revoked', 401, 'CENTRAL_SESSION_REVOKED');
      }
      if (now >= parent.absoluteExpiresAt) {
        throw new VerifierError('Parent central session absolute lifetime expired', 401, 'CENTRAL_SESSION_EXPIRED');
      }
      if (now >= parent.idleExpiresAt) {
        throw new VerifierError('Parent central session idle timeout reached', 401, 'CENTRAL_SESSION_IDLE_TIMEOUT');
      }

      // 8. Child-to-Parent & Token Consistency
      if (childSession.clientApp !== lanzarClientApp) {
        throw new VerifierError('Child session clientApp does not match token claim', 401, 'SESSION_CLAIM_MISMATCH');
      }

      // 9. Dual Token Version Consistency Check
      if (lanzarTokenVersion !== userSecurity.tokenVersion) {
        throw new VerifierError(
          `Token version (${lanzarTokenVersion}) is stale compared to security doc (${userSecurity.tokenVersion})`,
          401,
          'TOKEN_VERSION_STALE'
        );
      }
      if (childSession.tokenVersionAtIssue !== lanzarTokenVersion) {
        throw new VerifierError(
          `Child session issue token version (${childSession.tokenVersionAtIssue}) does not match token version (${lanzarTokenVersion})`,
          401,
          'TOKEN_VERSION_MISMATCH'
        );
      }

      // 10. Context Assembly
      return {
        uid,
        email: decoded.email || null,
        role: userSecurity.role || 'customer',
        adminPermissions: userSecurity.adminPermissions || [],
        clientApp: lanzarClientApp,
        sessionId: lanzarSessionId,
        centralSessionId: childSession.centralSessionId,
        authTime: decoded.auth_time || now
      };
    } catch (err) {
      if (err instanceof VerifierError) {
        throw err;
      }
      console.error('[VERIFIER FIRESTORE ERROR]', err);
      throw new VerifierError('Authorization backend unavailable', 503, 'AUTHORIZATION_BACKEND_UNAVAILABLE');
    }
  };
}

module.exports = {
  createCommonVerifier,
  VerifierError
};
