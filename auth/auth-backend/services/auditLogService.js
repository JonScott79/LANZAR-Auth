// auditLogService.js
// Milestone 1.5: Tenant-Aware Immutable Administrative Audit Trail

const crypto = require('crypto');

const SENSITIVE_KEY_PATTERN = /secret|password|token|hash|credential|private|key/i;

function sanitizeAuditMetadata(value, depth = 0) {
    if (depth > 4) return '[TRUNCATED]';
    if (value === null || value === undefined) return value;
    if (Array.isArray(value)) {
        return value.slice(0, 50).map(item => sanitizeAuditMetadata(item, depth + 1));
    }
    if (typeof value === 'object') {
        const sanitized = {};
        for (const [k, v] of Object.entries(value)) {
            if (SENSITIVE_KEY_PATTERN.test(k)) {
                sanitized[k] = '[REDACTED]';
            } else {
                sanitized[k] = sanitizeAuditMetadata(v, depth + 1);
            }
        }
        return sanitized;
    }
    if (typeof value === 'string' && value.length > 512) {
        return `${value.slice(0, 512)}...`;
    }
    return value;
}

class AuditLogService {
    constructor(db, options = {}) {
        if (!db || typeof db.collection !== 'function') {
            throw new Error('AuditLogService requires a valid Firestore instance.');
        }
        this.db = db;
        this.strictAudit = options.strictAudit !== undefined ? Boolean(options.strictAudit) : true;
    }

    buildAdminAuditRecord({
        actorUid = 'unknown',
        actorEmail = null,
        actorTenantId = 'lanzar',
        actorRole = 'tenant_admin',
        targetTenantId = 'lanzar',
        clientId = null,
        operation,
        outcome = 'success',
        reason = null,
        correlationId = null,
        metadata = {},
        auditId: explicitAuditId = null
    }) {
        const safeTargetTenant = (typeof targetTenantId === 'string' && targetTenantId.trim())
            ? targetTenantId.trim()
            : 'lanzar';
        const auditId = (typeof explicitAuditId === 'string' && explicitAuditId.trim())
            ? explicitAuditId.trim()
            : `aud_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
        const record = {
            auditId,
            actorUid: String(actorUid || 'unknown'),
            actorEmail: actorEmail ? String(actorEmail) : null,
            actorTenantId: String(actorTenantId || 'lanzar'),
            actorRole: String(actorRole || 'tenant_admin'),
            targetTenantId: safeTargetTenant,
            clientId: clientId ? String(clientId) : null,
            operation: String(operation || 'unknown'),
            outcome: String(outcome || 'success'),
            reason: reason ? String(reason).slice(0, 256) : null,
            correlationId: correlationId ? String(correlationId).slice(0, 128) : crypto.randomUUID(),
            metadata: sanitizeAuditMetadata(metadata),
            immutable: true,
            timestamp: new Date().toISOString()
        };
        const ref = this.db
            .collection('tenants')
            .doc(safeTargetTenant)
            .collection('admin_audit_logs')
            .doc(auditId);
        return { ref, record };
    }

    writeInTransaction(tx, prepared) {
        const { ref, record } = prepared;
        try {
            if (typeof tx.create === 'function') {
                tx.create(ref, record);
            } else {
                tx.set(ref, record);
            }
            return record;
        } catch (err) {
            throw new Error(`AUDIT_WRITE_FAILED: ${err.message}`);
        }
    }

    async recordAdminEvent(params) {
        const { strict, ...eventParams } = params || {};
        const { ref, record } = this.buildAdminAuditRecord(eventParams);

        try {
            if (typeof ref.create === 'function') {
                await ref.create(record);
            } else {
                await ref.set(record);
            }
            return record;
        } catch (err) {
            console.error('[AUDIT LOG ERROR]', err.message);
            const shouldThrow = strict !== undefined ? Boolean(strict) : this.strictAudit;
            if (shouldThrow) {
                throw new Error(`AUDIT_WRITE_FAILED: ${err.message}`);
            }
            return null;
        }
    }

    async listTenantAuditLogs(tenantId, { limit = 50 } = {}) {
        const safeTenant = (typeof tenantId === 'string' && tenantId.trim()) ? tenantId.trim() : 'lanzar';
        const colRef = this.db.collection('tenants').doc(safeTenant).collection('admin_audit_logs');
        if (typeof colRef.orderBy === 'function') {
            const snap = await colRef.orderBy('timestamp', 'desc').limit(limit).get();
            return (snap.docs || []).map(d => d.data());
        }
        const snap = await colRef.get();
        const docs = (snap.docs || []).map(d => d.data());
        docs.sort((a, b) => String(b.timestamp || '').localeCompare(String(a.timestamp || '')));
        return docs.slice(0, limit);
    }
}

module.exports = { AuditLogService, sanitizeAuditMetadata };
