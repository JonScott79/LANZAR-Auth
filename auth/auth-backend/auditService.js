// auditService.js
// Tamper-resistant security audit logging for LANZAR ID

const crypto = require('crypto');

/**
 * Strips sensitive fields (passwords, tokens, TOTP secrets) from audit metadata.
 */
function sanitizeAuditDetails(details) {
    if (!details || typeof details !== 'object') return {};
    const sanitized = { ...details };
    const sensitiveKeys = ['password', 'secret', 'totpSecret', 'token', 'idToken', 'customToken', 'recoveryCode', 'code'];
    for (const key of Object.keys(sanitized)) {
        if (sensitiveKeys.some(s => key.toLowerCase().includes(s))) {
            sanitized[key] = '[REDACTED]';
        }
    }
    return sanitized;
}

/**
 * Records an immutable audit log entry in /security_logs.
 * @param {Object} db - Firestore database instance
 * @param {Object} event
 * @param {string} event.actorUid
 * @param {string} event.actorEmail
 * @param {string} event.action - e.g. "auth.login", "admin.founder.granted", "session.revoked"
 * @param {string} [event.targetUid]
 * @param {string} [event.ipAddress]
 * @param {string} [event.userAgent]
 * @param {string} [event.tenantId] - Defaults to "lanzar"
 * @param {string} [event.status] - "success" | "failure" | "blocked"
 * @param {Object} [event.details]
 */
async function recordSecurityEvent(db, {
    actorUid,
    actorEmail,
    action,
    targetUid = null,
    ipAddress = null,
    userAgent = null,
    tenantId = 'lanzar',
    status = 'success',
    details = {}
}) {
    try {
        const eventId = `evt_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`;
        const logDoc = {
            eventId,
            timestamp: new Date().toISOString(),
            actorUid: actorUid || 'anonymous',
            actorEmail: actorEmail || null,
            action,
            targetUid: targetUid || actorUid || null,
            ipAddress: ipAddress || 'unknown',
            userAgent: userAgent ? String(userAgent).slice(0, 255) : 'unknown',
            tenantId: tenantId || 'lanzar',
            status: status || 'success',
            details: sanitizeAuditDetails(details)
        };

        await db.collection('security_logs').doc(eventId).set(logDoc);
        return logDoc;
    } catch (err) {
        console.error('[AUDIT ERROR] Failed to record security event:', err.message);
        // Non-blocking for request, but logged to stderr
        return null;
    }
}

module.exports = { recordSecurityEvent, sanitizeAuditDetails };
