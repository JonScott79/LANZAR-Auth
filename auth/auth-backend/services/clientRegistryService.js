// clientRegistryService.js
// Milestone 1.4: Dynamic Database-Backed OAuth Client Registry & Exact Whitelists
// Collections:
//   - /tenants/{tenantId}/clients/{clientId}
//   - /clients_index/{clientId}

const crypto = require('crypto');
const net = require('net');
const { clients: staticApprovedClients, getClient: getStaticClient, checkIsProduction } = require('../clients');
const { VALID_COMPATIBILITY_MODES, SUPPORTED_SCOPES } = require('./oidcTokenService');

const CLIENT_ID_REGEX = /^[a-z0-9][a-z0-9_-]{1,63}$/;
const TENANT_ID_REGEX = /^[a-z0-9][a-z0-9_-]{1,63}$/;
const VALID_AUTH_METHODS = new Set(['none', 'client_secret_post']);

function validateAllowedOrigins(origins) {
    if (origins === undefined || origins === null) return [];
    if (!Array.isArray(origins)) {
        throw new Error('allowedOrigins must be an array of exact origin URLs.');
    }
    const normalized = [];
    for (const raw of origins) {
        if (typeof raw !== 'string' || !raw.trim()) {
            throw new Error('Each allowedOrigin must be a non-empty string.');
        }
        if (raw.includes('*')) {
            throw new Error(`Wildcard origins are strictly forbidden: ${raw}`);
        }
        let parsed;
        try {
            parsed = new URL(raw.trim());
        } catch (_) {
            throw new Error(`Invalid origin URL: ${raw}`);
        }
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
            throw new Error(`Unsupported origin protocol: ${raw}`);
        }
        if (parsed.pathname !== '/' || parsed.search || parsed.hash) {
            throw new Error(`Origin must not include a path, query, or fragment: ${raw}`);
        }
        normalized.push(parsed.origin);
    }
    return Array.from(new Set(normalized));
}

function validateAllowedScopes(scopes) {
    if (scopes === undefined || scopes === null) {
        return [...SUPPORTED_SCOPES];
    }
    if (!Array.isArray(scopes) || scopes.length === 0) {
        throw new Error('allowedScopes must be a non-empty array.');
    }
    const normalized = [];
    for (const s of scopes) {
        if (typeof s !== 'string' || !SUPPORTED_SCOPES.includes(s.trim())) {
            throw new Error(`Unsupported scope: ${s}. Supported: ${SUPPORTED_SCOPES.join(', ')}`);
        }
        normalized.push(s.trim());
    }
    if (!normalized.includes('openid')) {
        normalized.unshift('openid');
    }
    return Array.from(new Set(normalized));
}

function hashClientSecret(secret) {
    return crypto.createHash('sha256').update(String(secret), 'utf8').digest('hex');
}

function timingSafeEqualHex(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length || a.length === 0) {
        return false;
    }
    try {
        return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
    } catch (_) {
        return false;
    }
}

function validateRedirectUris(redirectUris) {
    if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
        throw new Error('redirectUris must be a non-empty array of exact URIs.');
    }
    const normalized = [];
    for (const uri of redirectUris) {
        if (typeof uri !== 'string' || !uri) {
            throw new Error('Each redirectUri must be a non-empty string.');
        }
        if (uri.includes('*')) {
            throw new Error(`Wildcard redirect URIs are strictly forbidden: ${uri}`);
        }
        let parsed;
        try {
            parsed = new URL(uri);
        } catch (_) {
            throw new Error(`Invalid redirect URI: ${uri}`);
        }
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
            throw new Error(`Unsupported redirect URI protocol: ${uri}`);
        }
        if (parsed.hash) {
            throw new Error(`Redirect URI must not contain a fragment: ${uri}`);
        }
        normalized.push(uri);
    }
    return Array.from(new Set(normalized));
}

function isLoopbackOrLocalhostUri(uri) {
    if (typeof uri !== 'string' || !uri) return true;
    try {
        const parsed = new URL(uri);
        const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.+$/, '');
        if (host === 'localhost' || host.endsWith('.localhost')) {
            return true;
        }
        if (host === '::1' || host === '0:0:0:0:0:0:0:1') {
            return true;
        }
        if (net.isIPv4(host) && host.startsWith('127.')) {
            return true;
        }
        if (/^(?:::ffff:|0:0:0:0:0:ffff:)(?:127(?:\.\d{1,3}){3}|7f[0-9a-f]{2}:[0-9a-f]{1,4})$/.test(host)) {
            return true;
        }
        return false;
    } catch (_) {
        return true;
    }
}

function filterProductionRedirectUris(redirectUris) {
    if (!Array.isArray(redirectUris)) return [];
    return redirectUris.filter(uri => !isLoopbackOrLocalhostUri(uri));
}

function sanitizeClientForPublicRead(client) {
    if (!client) return null;
    const { clientSecretHash, clientSecret, ...safe } = client;
    return safe;
}

class ClientRegistryService {
    constructor(db, options = {}) {
        if (!db || typeof db.collection !== 'function') {
            throw new Error('ClientRegistryService requires a valid Firestore instance.');
        }
        this.db = db;
        this.isProductionFn = typeof options.isProduction === 'function' ? options.isProduction : checkIsProduction;
        this._originCache = { expiresAt: 0, map: new Map() };
    }

    invalidateOriginCache() {
        this._originCache = { expiresAt: 0, map: new Map() };
    }

    _tenantClientRef(tenantId, clientId) {
        return this.db.collection('tenants').doc(tenantId).collection('clients').doc(clientId);
    }

    _indexRef(clientId) {
        return this.db.collection('clients_index').doc(clientId);
    }

    _prepareAuditEvent(auditLogService, auditContext, details) {
        if (!auditLogService || typeof auditLogService.buildAdminAuditRecord !== 'function' || typeof auditLogService.writeInTransaction !== 'function') {
            return null;
        }
        const ctx = auditContext || {};
        return auditLogService.buildAdminAuditRecord({
            actorUid: ctx.actorUid || 'unknown',
            actorEmail: ctx.actorEmail || null,
            actorTenantId: ctx.actorTenantId || 'lanzar',
            actorRole: ctx.actorRole || 'tenant_admin',
            correlationId: ctx.correlationId || null,
            ...details
        });
    }

    async registerClient({
        tenantId = 'lanzar',
        clientId,
        name,
        redirectUris,
        allowedOrigins,
        allowedScopes,
        compatibilityMode = 'oidc',
        tokenEndpointAuthMethod = 'none',
        clientSecret,
        enabled = true,
        auditLogService,
        auditContext
    }) {
        if (typeof tenantId !== 'string' || !TENANT_ID_REGEX.test(tenantId)) {
            throw new Error('Invalid tenantId format.');
        }
        if (typeof clientId !== 'string' || !CLIENT_ID_REGEX.test(clientId)) {
            throw new Error('Invalid clientId format (must be 2-64 lowercase alphanumeric, underscore, or hyphen).');
        }
        if (typeof name !== 'string' || !name.trim()) {
            throw new Error('Client name is required.');
        }
        if (!VALID_COMPATIBILITY_MODES.has(compatibilityMode)) {
            throw new Error(`Unsupported compatibilityMode: ${compatibilityMode}`);
        }
        if (!VALID_AUTH_METHODS.has(tokenEndpointAuthMethod)) {
            throw new Error(`Unsupported tokenEndpointAuthMethod: ${tokenEndpointAuthMethod}`);
        }
        if (tokenEndpointAuthMethod === 'client_secret_post' && (typeof clientSecret !== 'string' || clientSecret.length < 16)) {
            throw new Error('Confidential clients (client_secret_post) require a clientSecret of at least 16 characters.');
        }

        const validatedUris = validateRedirectUris(redirectUris);
        const validatedOrigins = validateAllowedOrigins(allowedOrigins);
        const validatedScopes = validateAllowedScopes(allowedScopes);
        const nowIso = new Date().toISOString();

        const record = {
            id: clientId,
            clientId,
            tenantId,
            name: name.trim(),
            redirectUris: validatedUris,
            allowedOrigins: validatedOrigins,
            allowedScopes: validatedScopes,
            compatibilityMode,
            tokenEndpointAuthMethod,
            ...(tokenEndpointAuthMethod === 'client_secret_post' ? { clientSecretHash: hashClientSecret(clientSecret) } : {}),
            enabled: Boolean(enabled),
            status: Boolean(enabled) ? 'active' : 'suspended',
            createdAt: nowIso,
            updatedAt: nowIso
        };

        const preparedAudit = this._prepareAuditEvent(auditLogService, auditContext, {
            targetTenantId: tenantId,
            clientId,
            operation: 'client.register',
            outcome: 'success',
            metadata: { compatibilityMode, tokenEndpointAuthMethod }
        });

        await this.db.runTransaction(async (tx) => {
            const indexRef = this._indexRef(clientId);
            const clientRef = this._tenantClientRef(tenantId, clientId);
            const indexSnap = await tx.get(indexRef);
            const clientSnap = await tx.get(clientRef);

            if (indexSnap.exists || clientSnap.exists) {
                throw new Error(`CLIENT_ALREADY_EXISTS: ${clientId}`);
            }

            tx.set(clientRef, record);
            tx.set(indexRef, {
                clientId,
                tenantId,
                allowedOrigins: validatedOrigins,
                enabled: record.enabled,
                updatedAt: nowIso
            });
            if (preparedAudit) {
                auditLogService.writeInTransaction(tx, preparedAudit);
            }
        });
        this.invalidateOriginCache();

        return sanitizeClientForPublicRead(record);
    }

    async updateClient({ tenantId = 'lanzar', clientId, patch = {}, auditLogService, auditContext, auditOperation = 'client.update', auditReason = null }) {
        if (typeof tenantId !== 'string' || !TENANT_ID_REGEX.test(tenantId)) {
            throw new Error('Invalid tenantId format.');
        }
        if (typeof clientId !== 'string' || !CLIENT_ID_REGEX.test(clientId)) {
            throw new Error('Invalid clientId format.');
        }

        const preparedAudit = this._prepareAuditEvent(auditLogService, auditContext, {
            targetTenantId: tenantId,
            clientId,
            operation: auditOperation,
            outcome: 'success',
            reason: auditReason,
            metadata: { patchKeys: Object.keys(patch || {}) }
        });

        const updated = await this.db.runTransaction(async (tx) => {
            const indexRef = this._indexRef(clientId);
            const clientRef = this._tenantClientRef(tenantId, clientId);
            const indexSnap = await tx.get(indexRef);
            const clientSnap = await tx.get(clientRef);

            if (!indexSnap.exists) {
                throw new Error(`CLIENT_NOT_FOUND: ${clientId}`);
            }
            if (indexSnap.data().tenantId !== tenantId) {
                throw new Error(`TENANT_OWNERSHIP_MISMATCH: ${clientId}`);
            }
            if (!clientSnap.exists) {
                throw new Error(`CLIENT_NOT_FOUND: ${clientId}`);
            }

            const current = clientSnap.data();
            const next = { ...current, updatedAt: new Date().toISOString() };

            if (patch.name !== undefined) {
                if (typeof patch.name !== 'string' || !patch.name.trim()) {
                    throw new Error('Client name must be a non-empty string.');
                }
                next.name = patch.name.trim();
            }
            if (patch.redirectUris !== undefined) {
                next.redirectUris = validateRedirectUris(patch.redirectUris);
            }
            if (patch.allowedOrigins !== undefined) {
                next.allowedOrigins = validateAllowedOrigins(patch.allowedOrigins);
            }
            if (patch.allowedScopes !== undefined) {
                next.allowedScopes = validateAllowedScopes(patch.allowedScopes);
            }
            if (patch.compatibilityMode !== undefined) {
                if (!VALID_COMPATIBILITY_MODES.has(patch.compatibilityMode)) {
                    throw new Error(`Unsupported compatibilityMode: ${patch.compatibilityMode}`);
                }
                next.compatibilityMode = patch.compatibilityMode;
            }
            if (patch.enabled !== undefined) {
                next.enabled = Boolean(patch.enabled);
                next.status = next.enabled ? 'active' : 'suspended';
                if (!next.enabled && typeof patch.statusReason === 'string' && patch.statusReason.trim()) {
                    next.statusReason = patch.statusReason.trim().slice(0, 256);
                } else if (next.enabled) {
                    next.statusReason = null;
                }
            }

            tx.set(clientRef, next);
            tx.set(indexRef, {
                clientId,
                tenantId,
                allowedOrigins: Array.isArray(next.allowedOrigins) ? next.allowedOrigins : [],
                enabled: next.enabled,
                status: next.status || (next.enabled ? 'active' : 'suspended'),
                updatedAt: next.updatedAt
            });
            if (preparedAudit) {
                auditLogService.writeInTransaction(tx, preparedAudit);
            }
            return next;
        });
        this.invalidateOriginCache();

        return sanitizeClientForPublicRead(updated);
    }

    async disableClient({ tenantId = 'lanzar', clientId, reason = 'admin_disabled', auditLogService, auditContext }) {
        return this.updateClient({
            tenantId,
            clientId,
            patch: { enabled: false, statusReason: reason },
            auditLogService,
            auditContext,
            auditOperation: 'client.disable',
            auditReason: reason
        });
    }

    async enableClient({ tenantId = 'lanzar', clientId, auditLogService, auditContext }) {
        return this.updateClient({
            tenantId,
            clientId,
            patch: { enabled: true },
            auditLogService,
            auditContext,
            auditOperation: 'client.enable'
        });
    }

    async resolveClient(clientId, { isProduction } = {}) {
        if (typeof clientId !== 'string' || !clientId) {
            return null;
        }
        const prodMode = isProduction !== undefined ? Boolean(isProduction) : Boolean(this.isProductionFn());

        const indexSnap = await this._indexRef(clientId).get();
        if (indexSnap.exists && indexSnap.data() && indexSnap.data().tenantId) {
            const tenantId = indexSnap.data().tenantId;
            const clientSnap = await this._tenantClientRef(tenantId, clientId).get();
            if (!clientSnap.exists) {
                return null;
            }
            const client = clientSnap.data();
            if (prodMode) {
                return {
                    ...client,
                    redirectUris: filterProductionRedirectUris(client.redirectUris)
                };
            }
            return client;
        }

        // Fallback to static approved internal clients (`portal`, `tickets`, `threadline`, `ai` only)
        const staticClient = getStaticClient(clientId);
        if (!staticClient) {
            return null;
        }
        const fallback = {
            ...staticClient,
            clientId: staticClient.id,
            tenantId: 'lanzar',
            tokenEndpointAuthMethod: 'none'
        };
        if (prodMode) {
            fallback.redirectUris = filterProductionRedirectUris(fallback.redirectUris);
        }
        return fallback;
    }

    async listTenantClients(tenantId) {
        if (typeof tenantId !== 'string' || !TENANT_ID_REGEX.test(tenantId)) {
            throw new Error('Invalid tenantId format.');
        }
        const snap = await this.db.collection('tenants').doc(tenantId).collection('clients').get();
        const items = [];
        snap.forEach((d) => items.push(sanitizeClientForPublicRead(d.data())));
        return items;
    }

    async rotateClientSecret({ tenantId, clientId, auditLogService, auditContext }) {
        if (typeof tenantId !== 'string' || !TENANT_ID_REGEX.test(tenantId)) {
            throw new Error('Invalid tenantId format.');
        }
        if (typeof clientId !== 'string' || !CLIENT_ID_REGEX.test(clientId)) {
            throw new Error('Invalid clientId format.');
        }
        const newSecret = `lzd_sec_${crypto.randomBytes(24).toString('hex')}`;
        const preparedAudit = this._prepareAuditEvent(auditLogService, auditContext, {
            targetTenantId: tenantId,
            clientId,
            operation: 'client.rotate_secret',
            outcome: 'success'
        });

        await this.db.runTransaction(async (tx) => {
            const clientRef = this._tenantClientRef(tenantId, clientId);
            const snap = await tx.get(clientRef);
            if (!snap.exists) {
                throw new Error(`CLIENT_NOT_FOUND: ${clientId}`);
            }
            const current = snap.data();
            if (current.tokenEndpointAuthMethod !== 'client_secret_post') {
                throw new Error('Public PKCE clients (tokenEndpointAuthMethod=none) do not have a clientSecret.');
            }
            tx.update(clientRef, {
                clientSecretHash: hashClientSecret(newSecret),
                updatedAt: new Date().toISOString()
            });
            if (preparedAudit) {
                auditLogService.writeInTransaction(tx, preparedAudit);
            }
        });

        return { clientId, tenantId, clientSecret: newSecret };
    }

    async resolveDynamicOriginClient(origin) {
        if (typeof origin !== 'string' || !origin) return null;
        const now = Date.now();
        if (now >= this._originCache.expiresAt) {
            const nextMap = new Map();
            const snap = await this.db.collection('clients_index').get();
            const prodMode = Boolean(this.isProductionFn());
            snap.forEach((doc) => {
                const data = doc.data();
                if (!data || !data.enabled || !Array.isArray(data.allowedOrigins)) return;
                for (const allowed of data.allowedOrigins) {
                    if (prodMode && isLoopbackOrLocalhostUri(allowed)) continue;
                    if (!nextMap.has(allowed)) {
                        nextMap.set(allowed, data.clientId);
                    }
                }
            });
            this._originCache = { expiresAt: now + 30000, map: nextMap };
        }
        return this._originCache.map.get(origin) || null;
    }

    isRedirectUriAuthorized(client, redirectUri) {
        if (!client || typeof redirectUri !== 'string' || !redirectUri) {
            return false;
        }
        if (redirectUri.includes('*')) {
            return false;
        }
        return Array.isArray(client.redirectUris) && client.redirectUris.includes(redirectUri);
    }

    verifyClientCredentials(client, presentedSecret) {
        if (!client) return false;
        const authMethod = client.tokenEndpointAuthMethod || 'none';
        if (authMethod === 'client_secret_post') {
            if (typeof presentedSecret !== 'string' || !presentedSecret || !client.clientSecretHash) {
                return false;
            }
            return timingSafeEqualHex(hashClientSecret(presentedSecret), client.clientSecretHash);
        }
        return true;
    }

    /**
     * Idempotently seeds ONLY the four approved internal LANZAR clients
     * (`portal`, `tickets`, `threadline`, `ai`) into `/tenants/lanzar/clients/{clientId}`
     * and `/clients_index/{clientId}`. Prospective clients remain excluded.
     */
    async seedApprovedInternalClients({ tenantId = 'lanzar', auditLogService, auditContext } = {}) {
        const seeded = [];
        for (const [clientId, cfg] of Object.entries(staticApprovedClients)) {
            const nowIso = new Date().toISOString();
            const preparedAudit = this._prepareAuditEvent(auditLogService, auditContext, {
                targetTenantId: tenantId,
                clientId,
                operation: 'client.seed_internal',
                outcome: 'success',
                metadata: { seededClient: clientId }
            });
            const created = await this.db.runTransaction(async (tx) => {
                const indexRef = this._indexRef(clientId);
                const clientRef = this._tenantClientRef(tenantId, clientId);
                const indexSnap = await tx.get(indexRef);
                if (indexSnap.exists) {
                    return false;
                }
                const record = {
                    id: clientId,
                    clientId,
                    tenantId,
                    name: cfg.name,
                    redirectUris: [...cfg.redirectUris],
                    compatibilityMode: cfg.compatibilityMode || 'legacy_firebase',
                    tokenEndpointAuthMethod: 'none',
                    enabled: Boolean(cfg.enabled),
                    status: Boolean(cfg.enabled) ? 'active' : 'suspended',
                    seeded: true,
                    createdAt: nowIso,
                    updatedAt: nowIso
                };
                tx.set(clientRef, record);
                tx.set(indexRef, {
                    clientId,
                    tenantId,
                    enabled: record.enabled,
                    updatedAt: nowIso
                });
                if (preparedAudit) {
                    auditLogService.writeInTransaction(tx, preparedAudit);
                }
                return true;
            });
            if (created) {
                seeded.push(clientId);
            }
        }
        return { seeded };
    }
}

module.exports = {
    ClientRegistryService,
    validateRedirectUris,
    validateAllowedOrigins,
    validateAllowedScopes,
    hashClientSecret,
    sanitizeClientForPublicRead,
    isLoopbackOrLocalhostUri,
    filterProductionRedirectUris
};
