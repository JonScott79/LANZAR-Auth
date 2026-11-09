// centralSessionService.js
// Authoritative Central Session Lifecycle, Slots & Token Exchange (LID-ARCH-REV-015 §4)

const crypto = require('crypto');

class CentralSessionError extends Error {
  constructor(message, status = 400, code = 'SESSION_ERROR') {
    super(message);
    this.name = 'CentralSessionError';
    this.status = status;
    this.code = code;
  }
}

class CentralSessionService {
  constructor(db, authAdmin, config) {
    this.db = db;
    this.authAdmin = authAdmin;
    this.config = config;
    this.appEnv = config.appEnv;
  }

  /**
   * Initializes or fetches /user_security/{uid} metadata doc.
   */
  async ensureUserSecurity(uid, tx = null) {
    const secRef = this.db.collection('user_security').doc(uid);
    const getDoc = tx ? tx.get(secRef) : secRef.get();
    const snap = await getDoc;
    if (snap.exists) {
      return snap.data();
    }
    const now = Math.floor(Date.now() / 1000);
    const initialSec = {
      accountStatus: 'active',
      tokenVersion: 1,
      role: 'customer',
      adminPermissions: [],
      mfaEnrolled: false,
      mfaSecretCiphertext: null,
      updatedAt: now
    };
    if (tx) {
      tx.set(secRef, initialSec);
    } else {
      await secRef.set(initialSec);
    }
    return initialSec;
  }

  /**
   * Creates a new parent central session document in /users/{uid}/central_sessions/{centralSessionId}.
   */
  async createCentralSession({ uid, userAgent, ipAddress }) {
    const now = Math.floor(Date.now() / 1000);
    const centralSessionId = `csess_${Date.now()}_${crypto.randomBytes(12).toString('hex')}`;
    const absoluteExpiresAt = now + 30 * 24 * 60 * 60; // 30 days (OD-5)
    const idleExpiresAt = now + 7 * 24 * 60 * 60;     // 7 days (OD-5)

    const parentDoc = {
      uid, // Strictly populated from authenticated UID
      createdAt: now,
      lastSeenAt: now,
      absoluteExpiresAt,
      idleExpiresAt,
      revoked: false,
      revokedAt: null,
      revokedReason: null,
      env: this.appEnv,
      userAgent: userAgent ? String(userAgent).slice(0, 200) : 'unknown',
      ipAddress: ipAddress ? String(ipAddress).slice(0, 50) : 'unknown'
    };

    await this.ensureUserSecurity(uid);

    await this.db
      .collection('users')
      .doc(uid)
      .collection('central_sessions')
      .doc(centralSessionId)
      .set(parentDoc);

    return {
      centralSessionId,
      parentDoc
    };
  }

  /**
   * Idempotently exchanges a central session for a Firebase Custom Token bound to a child session slot.
   * Strict OD-6 check: denied to auth_hub and marketing_site.
   */
  async exchangeChildSessionToken({ uid, centralSessionId, clientAppId }) {
    const now = Math.floor(Date.now() / 1000);

    // OD-6 Enforcement: Denied to auth_hub and marketing_site
    if (clientAppId === 'auth_hub' || clientAppId === 'marketing_site') {
      throw new CentralSessionError(
        `Token minting is not permitted for client app "${clientAppId}"`,
        403,
        'CLIENT_APP_NOT_PERMITTED'
      );
    }

    const secRef = this.db.collection('user_security').doc(uid);
    const parentRef = this.db
      .collection('users')
      .doc(uid)
      .collection('central_sessions')
      .doc(centralSessionId);

    const slotId = `${centralSessionId}__${clientAppId}`;
    const slotRef = this.db
      .collection('users')
      .doc(uid)
      .collection('session_slots')
      .doc(slotId);

    let assignedSessionId;
    let tokenVersion;

    await this.db.runTransaction(async (tx) => {
      // 1. User Security Check
      const secSnap = await tx.get(secRef);
      if (!secSnap.exists) {
        throw new CentralSessionError('User security profile not found', 403, 'ACCOUNT_NOT_FOUND');
      }
      const secData = secSnap.data();
      if (secData.accountStatus !== 'active') {
        throw new CentralSessionError('Account is suspended or inactive', 403, 'ACCOUNT_SUSPENDED');
      }
      tokenVersion = secData.tokenVersion || 1;

      // 2. Parent Central Session Verification
      const parentSnap = await tx.get(parentRef);
      if (!parentSnap.exists) {
        throw new CentralSessionError('Central session not found', 401, 'SESSION_NOT_FOUND');
      }
      const parent = parentSnap.data();

      if (parent.uid !== uid) {
        throw new CentralSessionError('Parent session UID mismatch', 401, 'SESSION_CLAIM_MISMATCH');
      }
      if (parent.env !== this.appEnv) {
        throw new CentralSessionError('Cross-environment session exchange rejected', 401, 'ENVIRONMENT_MISMATCH');
      }
      if (parent.revoked === true) {
        throw new CentralSessionError('Central session has been revoked', 401, 'CENTRAL_SESSION_REVOKED');
      }
      if (now >= parent.absoluteExpiresAt) {
        throw new CentralSessionError('Central session has expired', 401, 'CENTRAL_SESSION_EXPIRED');
      }
      if (now >= parent.idleExpiresAt) {
        throw new CentralSessionError('Central session timed out due to inactivity', 401, 'CENTRAL_SESSION_IDLE_TIMEOUT');
      }

      // 3. Slot Reuse & Child Session Evaluation
      const slotSnap = await tx.get(slotRef);
      let reuseExisting = false;

      if (slotSnap.exists) {
        const slotData = slotSnap.data();
        if (slotData.activeSessionId) {
          const childRef = this.db
            .collection('users')
            .doc(uid)
            .collection('sessions')
            .doc(slotData.activeSessionId);
          const childSnap = await tx.get(childRef);

          if (childSnap.exists) {
            const child = childSnap.data();
            if (
              child.revoked === false &&
              child.expiresAt > now &&
              child.tokenVersionAtIssue === tokenVersion
            ) {
              assignedSessionId = slotData.activeSessionId;
              reuseExisting = true;
            }
          }
        }
      }

      if (!reuseExisting) {
        assignedSessionId = `sess_${Date.now()}_${crypto.randomBytes(12).toString('hex')}`;
        const childExpiresAt = Math.min(parent.absoluteExpiresAt, now + 24 * 60 * 60); // 24-hour child expiry
        const newChildDoc = {
          centralSessionId,
          clientApp: clientAppId,
          tokenVersionAtIssue: tokenVersion,
          createdAt: now,
          expiresAt: childExpiresAt,
          revoked: false,
          revokedAt: null
        };

        const newChildRef = this.db
          .collection('users')
          .doc(uid)
          .collection('sessions')
          .doc(assignedSessionId);

        tx.set(newChildRef, newChildDoc);

        tx.set(slotRef, {
          activeSessionId: assignedSessionId,
          clientApp: clientAppId,
          createdAt: slotSnap.exists ? slotSnap.data().createdAt : now,
          updatedAt: now
        });
      }

      // 4. Update Parent Idle Expiration and Last Seen
      tx.update(parentRef, {
        lastSeenAt: now,
        idleExpiresAt: now + 7 * 24 * 60 * 60
      });
    });

    // 5. Mint Firebase Custom Token with claims outside transaction
    const customClaims = {
      lanzarSessionId: assignedSessionId,
      lanzarTokenVersion: tokenVersion,
      lanzarClientApp: clientAppId
    };

    const customToken = await this.authAdmin.createCustomToken(uid, customClaims);

    return {
      customToken,
      sessionId: assignedSessionId,
      clientAppId,
      tokenVersion
    };
  }

  /**
   * Strictly read-only inspection of central session status (GET /api/id/session/me).
   * ZERO Firestore writes.
   */
  async inspectSession({ uid, centralSessionId, clientAppId }) {
    const now = Math.floor(Date.now() / 1000);

    const parentRef = this.db
      .collection('users')
      .doc(uid)
      .collection('central_sessions')
      .doc(centralSessionId);
    const secRef = this.db.collection('user_security').doc(uid);

    const [parentSnap, secSnap] = await Promise.all([
      parentRef.get(),
      secRef.get()
    ]);

    if (!parentSnap.exists) {
      throw new CentralSessionError('Session not found', 401, 'SESSION_NOT_FOUND');
    }
    const parent = parentSnap.data();

    if (parent.uid !== uid) {
      throw new CentralSessionError('Parent session UID mismatch', 401, 'SESSION_CLAIM_MISMATCH');
    }
    if (parent.env !== this.appEnv) {
      throw new CentralSessionError('Cross-environment session', 401, 'ENVIRONMENT_MISMATCH');
    }
    if (parent.revoked === true) {
      throw new CentralSessionError('Session has been revoked', 401, 'CENTRAL_SESSION_REVOKED');
    }
    if (now >= parent.absoluteExpiresAt) {
      throw new CentralSessionError('Session expired', 401, 'CENTRAL_SESSION_EXPIRED');
    }
    if (now >= parent.idleExpiresAt) {
      throw new CentralSessionError('Session timed out', 401, 'CENTRAL_SESSION_IDLE_TIMEOUT');
    }

    const sec = secSnap.exists ? secSnap.data() : {};
    if (sec.accountStatus && sec.accountStatus !== 'active') {
      throw new CentralSessionError('Account suspended', 403, 'ACCOUNT_SUSPENDED');
    }

    return {
      authenticated: true,
      uid,
      clientAppId,
      absoluteExpiresAt: parent.absoluteExpiresAt,
      idleExpiresAt: parent.idleExpiresAt,
      role: sec.role || 'customer'
    };
  }

  /**
   * Logs out the parent central session and atomically revokes active child sessions.
   */
  async logoutCentralSession({ uid, centralSessionId }) {
    const now = Math.floor(Date.now() / 1000);
    const parentRef = this.db
      .collection('users')
      .doc(uid)
      .collection('central_sessions')
      .doc(centralSessionId);

    await this.db.runTransaction(async (tx) => {
      const snap = await tx.get(parentRef);
      if (snap.exists) {
        tx.update(parentRef, {
          revoked: true,
          revokedAt: now,
          revokedReason: 'user_logout'
        });
      }
    });

    // Revoke matching child sessions
    const childSnaps = await this.db
      .collection('users')
      .doc(uid)
      .collection('sessions')
      .where('centralSessionId', '==', centralSessionId)
      .where('revoked', '==', false)
      .get();

    if (!childSnaps.empty) {
      const batch = this.db.batch();
      for (const doc of childSnaps.docs) {
        batch.update(doc.ref, {
          revoked: true,
          revokedAt: now
        });
      }
      await batch.commit();
    }

    return { loggedOut: true };
  }

  /**
   * Global revocation: increments tokenVersion and revokes all sessions.
   */
  async revokeAllUserSessions(uid, reason = 'global_revocation') {
    const now = Math.floor(Date.now() / 1000);
    const secRef = this.db.collection('user_security').doc(uid);

    await this.db.runTransaction(async (tx) => {
      const snap = await tx.get(secRef);
      const currentVer = snap.exists ? (snap.data().tokenVersion || 1) : 1;
      tx.set(
        secRef,
        {
          tokenVersion: currentVer + 1,
          updatedAt: now
        },
        { merge: true }
      );
    });

    // Batch revoke central sessions
    const parentSnaps = await this.db
      .collection('users')
      .doc(uid)
      .collection('central_sessions')
      .where('revoked', '==', false)
      .get();

    if (!parentSnaps.empty) {
      const batch = this.db.batch();
      for (const doc of parentSnaps.docs) {
        batch.update(doc.ref, {
          revoked: true,
          revokedAt: now,
          revokedReason: reason
        });
      }
      await batch.commit();
    }

    // Batch revoke child sessions
    const childSnaps = await this.db
      .collection('users')
      .doc(uid)
      .collection('sessions')
      .where('revoked', '==', false)
      .get();

    if (!childSnaps.empty) {
      const batch = this.db.batch();
      for (const doc of childSnaps.docs) {
        batch.update(doc.ref, {
          revoked: true,
          revokedAt: now
        });
      }
      await batch.commit();
    }

    return { revokedAll: true };
  }
}

module.exports = {
  CentralSessionService,
  CentralSessionError
};
