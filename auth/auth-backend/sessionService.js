// sessionService.js
// Server-side session management & revocation registry for LANZAR ID

const crypto = require('crypto');
const { FieldValue } = require('firebase-admin/firestore');
const { recordSecurityEvent } = require('./auditService');

// In-memory LRU-style cache for fast revocation checks to minimize Firestore reads
// Map<sessionId, { revoked: boolean, checkedAt: number }>
const sessionCache = new Map();
const CACHE_TTL_MS = 30000; // 30 seconds

class SessionService {
    constructor(db, authAdmin) {
        this.db = db;
        this.authAdmin = authAdmin;
    }

    /**
     * Creates an active device session document in /users/{uid}/sessions/{sessionId}.
     */
    async createSession({ uid, clientId, ipAddress, userAgent, deviceName = 'Web Client' }) {
        const sessionId = `sess_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
        const now = new Date();
        const expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000); // 7-day TTL

        const sessionDoc = {
            sessionId,
            uid,
            clientId: clientId || 'unknown',
            deviceName: deviceName ? String(deviceName).slice(0, 100) : 'Web Client',
            browser: userAgent ? String(userAgent).slice(0, 150) : 'Unknown Browser',
            ipAddress: ipAddress || 'unknown',
            createdAt: now.toISOString(),
            lastSeenAt: now.toISOString(),
            expiresAt: expiresAt.toISOString(),
            revoked: false,
            revokedAt: null,
            revokedBy: null
        };

        await this.db.collection('users').doc(uid)
            .collection('sessions').doc(sessionId)
            .set(sessionDoc);

        // Pre-warm cache
        sessionCache.set(sessionId, { revoked: false, checkedAt: Date.now() });

        await recordSecurityEvent(this.db, {
            actorUid: uid,
            action: 'session.created',
            targetUid: uid,
            ipAddress,
            userAgent,
            details: { sessionId, clientId, deviceName }
        });

        return sessionDoc;
    }

    /**
     * Resolves the server-side state of an individual session.
     * Returns { active, reason } where reason is one of
     * 'active' | 'revoked' | 'expired' | 'unknown_session' | 'check_failed'.
     * Fails closed on lookup errors.
     */
    async checkSession(uid, sessionId) {
        if (!sessionId) return { active: false, reason: 'unknown_session' };

        const cached = sessionCache.get(sessionId);
        if (cached && Date.now() - cached.checkedAt < CACHE_TTL_MS) {
            return {
                active: !cached.revoked,
                reason: cached.reason || (cached.revoked ? 'revoked' : 'active'),
                expiresAt: cached.expiresAt || null
            };
        }

        try {
            const doc = await this.db.collection('users').doc(uid)
                .collection('sessions').doc(sessionId)
                .get();

            if (!doc.exists) {
                // Unknown session is treated as revoked/invalid
                sessionCache.set(sessionId, { revoked: true, reason: 'unknown_session', checkedAt: Date.now() });
                return { active: false, reason: 'unknown_session' };
            }

            const data = doc.data();
            let reason = 'active';
            if (data.revoked === true) {
                reason = 'revoked';
            } else if (data.expiresAt && new Date(data.expiresAt) < new Date()) {
                reason = 'expired';
            }
            const isRevoked = reason !== 'active';
            const expiresAt = data.expiresAt || null;
            sessionCache.set(sessionId, { revoked: isRevoked, reason, expiresAt, checkedAt: Date.now() });
            return { active: !isRevoked, reason, expiresAt };
        } catch (err) {
            console.error(`[SESSION CHECK ERROR] Failed to check session ${sessionId}:`, err.message);
            // Fail closed on error for security
            return { active: false, reason: 'check_failed' };
        }
    }

    /**
     * Checks whether an individual session has been revoked.
     * Enforced server-side on protected API requests.
     */
    async isSessionRevoked(uid, sessionId) {
        const state = await this.checkSession(uid, sessionId);
        return !state.active;
    }

    /**
     * Revokes an individual device session.
     */
    async revokeSession(uid, sessionId, revokedBy = null, ipAddress = null) {
        const sessionRef = this.db.collection('users').doc(uid)
            .collection('sessions').doc(sessionId);

        const nowIso = new Date().toISOString();
        await sessionRef.update({
            revoked: true,
            revokedAt: nowIso,
            revokedBy: revokedBy || uid
        });

        sessionCache.set(sessionId, { revoked: true, checkedAt: Date.now() });

        await recordSecurityEvent(this.db, {
            actorUid: revokedBy || uid,
            action: 'session.revoked.individual',
            targetUid: uid,
            ipAddress,
            details: { sessionId, revokedBy: revokedBy || uid }
        });

        return { success: true, sessionId };
    }

    /**
     * Global "Sign Out Everywhere" / Account-wide session invalidation.
     * 1. Calls admin.auth().revokeRefreshTokens(uid).
     * 2. Increments tokenVersion on /users/{uid}.
     * 3. Marks all active sessions in /users/{uid}/sessions as revoked.
     */
    async revokeAllSessions(uid, revokedBy = null, ipAddress = null) {
        const nowIso = new Date().toISOString();

        // 1. Google Identity level refresh token revocation (sets validAfterTime)
        try {
            await this.authAdmin.revokeRefreshTokens(uid);
        } catch (err) {
            if (err.code !== 'auth/user-not-found') {
                console.warn(`[SESSION REVOKE REFRESH TOKEN NOTICE] for ${uid}:`, err.message);
            }
        }

        // 2. Increment tokenVersion in Firestore
        const userRef = this.db.collection('users').doc(uid);
        await userRef.set({
            tokenVersion: FieldValue.increment(1),
            updatedAt: FieldValue.serverTimestamp()
        }, { merge: true });

        // 3. Mark all active sessions as revoked in batch
        const sessionsSnapshot = await userRef.collection('sessions')
            .where('revoked', '==', false)
            .get();

        const batch = this.db.batch();
        sessionsSnapshot.forEach(doc => {
            batch.update(doc.ref, {
                revoked: true,
                revokedAt: nowIso,
                revokedBy: revokedBy || uid
            });
            sessionCache.set(doc.id, { revoked: true, checkedAt: Date.now() });
        });

        if (!sessionsSnapshot.empty) {
            await batch.commit();
        }

        await recordSecurityEvent(this.db, {
            actorUid: revokedBy || uid,
            action: 'session.revoked.global',
            targetUid: uid,
            ipAddress,
            details: { revokedSessionsCount: sessionsSnapshot.size, revokedBy: revokedBy || uid }
        });

        return {
            success: true,
            revokedSessionsCount: sessionsSnapshot.size
        };
    }

    /**
     * Lists active device sessions for a user.
     */
    async listUserSessions(uid) {
        const snap = await this.db.collection('users').doc(uid)
            .collection('sessions')
            .orderBy('createdAt', 'desc')
            .limit(20)
            .get();

        return snap.docs.map(doc => {
            const data = doc.data();
            return {
                sessionId: data.sessionId,
                clientId: data.clientId,
                deviceName: data.deviceName,
                browser: data.browser,
                ipAddress: data.ipAddress,
                createdAt: data.createdAt,
                lastSeenAt: data.lastSeenAt,
                revoked: data.revoked === true
            };
        });
    }
}

module.exports = { SessionService };
