// oidcTokenService.js
// Milestone 1.3: Standards-Compliant OIDC Token Engine & Scoped Compatibility Adapter

const crypto = require('crypto');
const { getEnvironmentConfig, resolveEnvironment } = require('../config/environments');

const ACCESS_TOKEN_TTL_SECONDS = 900; // 15 minutes (Blueprint §5.2)
const ID_TOKEN_TTL_SECONDS = 3600; // 1 hour
const VALID_COMPATIBILITY_MODES = new Set(['legacy_firebase', 'dual', 'oidc']);
const SUPPORTED_SCOPES = ['openid', 'profile', 'email'];

function resolveDefaultIssuer() {
    if (process.env.OIDC_ISSUER && process.env.OIDC_ISSUER.trim()) {
        return process.env.OIDC_ISSUER.trim().replace(/\/+$/, '');
    }
    try {
        const env = resolveEnvironment(process.env);
        const cfg = getEnvironmentConfig(env);
        if (cfg && (cfg.oidcIssuer || cfg.apiBaseUrl)) {
            return cfg.oidcIssuer || cfg.apiBaseUrl;
        }
    } catch (_) {
        // Fallback for isolated unit/test runs without APP_ENV
    }
    return 'http://localhost:4001';
}

function resolveDefaultApiBaseUrl(fallbackIssuer) {
    try {
        const env = resolveEnvironment(process.env);
        const cfg = getEnvironmentConfig(env);
        if (cfg && cfg.apiBaseUrl) {
            return cfg.apiBaseUrl;
        }
    } catch (_) {
        // Fallback for isolated unit/test runs without APP_ENV
    }
    return fallbackIssuer;
}

function normalizeScope(rawScope) {
    if (typeof rawScope !== 'string' || !rawScope.trim()) {
        return 'openid profile email';
    }
    const parts = rawScope
        .trim()
        .split(/\s+/)
        .filter(Boolean);
    const unique = Array.from(new Set(parts));
    return unique.length > 0 ? unique.join(' ') : 'openid profile email';
}

function validateAndNormalizeScope(rawScope, clientAllowedScopes = null) {
    const allowedSet = new Set(
        Array.isArray(clientAllowedScopes) && clientAllowedScopes.length > 0
            ? clientAllowedScopes.filter(s => SUPPORTED_SCOPES.includes(s))
            : SUPPORTED_SCOPES
    );
    if (typeof rawScope !== 'string' || !rawScope.trim()) {
        const defaults = ['openid', 'profile', 'email'].filter(s => allowedSet.has(s));
        return { valid: true, scope: defaults.length > 0 ? defaults.join(' ') : 'openid' };
    }
    const requested = Array.from(new Set(rawScope.trim().split(/\s+/).filter(Boolean)));
    const unsupported = requested.filter(s => !allowedSet.has(s));
    if (unsupported.length > 0) {
        return {
            valid: false,
            error: 'invalid_scope',
            error_description: `Unsupported or unauthorized scope(s): ${unsupported.join(', ')}`
        };
    }
    return { valid: true, scope: requested.join(' ') };
}

function hasScope(scopeStr, target) {
    if (typeof scopeStr !== 'string') return false;
    return scopeStr.split(/\s+/).includes(target);
}

class OidcTokenService {
    constructor({ signingKeystore, issuer, apiBaseUrl } = {}) {
        if (!signingKeystore || typeof signingKeystore.signJwt !== 'function' || typeof signingKeystore.verifyJwt !== 'function') {
            throw new Error('OidcTokenService requires a valid SigningKeystore instance.');
        }
        this.signingKeystore = signingKeystore;
        this.issuer = (typeof issuer === 'string' && issuer.trim()) ? issuer.trim().replace(/\/+$/, '') : resolveDefaultIssuer();
        this.apiBaseUrl = (typeof apiBaseUrl === 'string' && apiBaseUrl.trim())
            ? apiBaseUrl.trim().replace(/\/+$/, '')
            : resolveDefaultApiBaseUrl(this.issuer);

        let parsedIssuer;
        try {
            parsedIssuer = new URL(this.issuer);
        } catch (_) {
            throw new Error(`Invalid OIDC issuer URL: "${this.issuer}"`);
        }
        if (parsedIssuer.search || parsedIssuer.hash || parsedIssuer.pathname.includes('/NOVA')) {
            throw new Error(`Invalid OIDC issuer format (no query/fragment/uppercase /NOVA allowed): "${this.issuer}"`);
        }
    }

    getIssuer() {
        return this.issuer;
    }

    getApiBaseUrl() {
        return this.apiBaseUrl;
    }

    getUserinfoAudience() {
        return `${this.apiBaseUrl}/oauth/userinfo`;
    }

    getDiscoveryDocument() {
        const api = this.apiBaseUrl;
        return {
            issuer: this.issuer,
            authorization_endpoint: `${api}/oauth/authorize`,
            token_endpoint: `${api}/oauth/token`,
            userinfo_endpoint: `${api}/oauth/userinfo`,
            jwks_uri: `${api}/.well-known/jwks.json`,
            response_types_supported: ['code'],
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: ['RS256'],
            scopes_supported: [...SUPPORTED_SCOPES],
            token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
            code_challenge_methods_supported: ['S256'],
            grant_types_supported: ['authorization_code', 'refresh_token'],
            claims_supported: [
                'sub',
                'iss',
                'aud',
                'azp',
                'exp',
                'iat',
                'auth_time',
                'nonce',
                'email',
                'email_verified',
                'name',
                'tenant_id',
                'session_id',
                'family_id',
                'scope'
            ]
        };
    }

    async mintAccessToken({ uid, clientId, tenantId = 'lanzar', sessionId, familyId, scope, audience, nowSec }) {
        if (!uid || !clientId || !sessionId) {
            throw new Error('uid, clientId, and sessionId are required to mint an access token.');
        }
        const normalizedScope = normalizeScope(scope);
        const defaultAud = clientId === this.getUserinfoAudience()
            ? clientId
            : [clientId, this.getUserinfoAudience()];
        return this.signingKeystore.signJwt(
            {
                iss: this.issuer,
                sub: uid,
                aud: audience !== undefined ? audience : defaultAud,
                azp: clientId,
                tenant_id: tenantId,
                session_id: sessionId,
                ...(familyId ? { family_id: familyId } : {}),
                scope: normalizedScope,
                token_use: 'access',
                jti: crypto.randomBytes(16).toString('hex')
            },
            { expiresInSeconds: ACCESS_TOKEN_TTL_SECONDS, ...(nowSec !== undefined ? { nowSec } : {}) }
        );
    }

    async mintIdToken({
        uid,
        clientId,
        tenantId = 'lanzar',
        sessionId,
        scope,
        email,
        emailVerified,
        name,
        nonce,
        authTime,
        nowSec
    }) {
        if (!uid || !clientId || !sessionId) {
            throw new Error('uid, clientId, and sessionId are required to mint an ID token.');
        }
        const normalizedScope = normalizeScope(scope);
        const includeEmail = hasScope(normalizedScope, 'email');
        const includeProfile = hasScope(normalizedScope, 'profile');

        const payload = {
            iss: this.issuer,
            sub: uid,
            aud: clientId,
            azp: clientId,
            tenant_id: tenantId,
            session_id: sessionId,
            token_use: 'id',
            jti: crypto.randomBytes(16).toString('hex')
        };

        if (typeof nonce === 'string' && nonce) {
            payload.nonce = nonce;
        }
        if (Number.isInteger(authTime) && authTime > 0) {
            payload.auth_time = authTime;
        }
        if (includeEmail && email !== undefined) {
            payload.email = email;
            if (emailVerified !== undefined) {
                payload.email_verified = Boolean(emailVerified);
            }
        }
        if (includeProfile && name !== undefined) {
            payload.name = name;
        }

        return this.signingKeystore.signJwt(
            payload,
            { expiresInSeconds: ID_TOKEN_TTL_SECONDS, ...(nowSec !== undefined ? { nowSec } : {}) }
        );
    }

    /**
     * Scoped Compatibility Adapter:
     * - `legacy_firebase`: mints Firebase `custom_token` only (existing internal apps)
     * - `dual`: mints RS256 `access_token` (+ `id_token` if `openid` scope) AND `custom_token`
     * - `oidc`: mints RS256 `access_token` (+ `id_token` if `openid` scope) only; never mints `custom_token`
     */
    async buildTokenResponse({
        client,
        uid,
        clientId,
        tenantId = 'lanzar',
        sessionId,
        familyId,
        refreshToken,
        scope,
        userClaims = {},
        nonce,
        authTime,
        authAdmin
    }) {
        const mode = (client && client.compatibilityMode) ? client.compatibilityMode : 'legacy_firebase';
        if (!VALID_COMPATIBILITY_MODES.has(mode)) {
            throw new Error(`Unsupported client compatibilityMode: ${mode}`);
        }

        const normalizedScope = normalizeScope(scope);
        const payload = {
            refresh_token: refreshToken,
            family_id: familyId,
            session_id: sessionId
        };

        if (mode === 'legacy_firebase' || mode === 'dual') {
            if (!authAdmin || typeof authAdmin.createCustomToken !== 'function') {
                throw new Error('authAdmin.createCustomToken is required for legacy_firebase/dual compatibility mode.');
            }
            payload.custom_token = await authAdmin.createCustomToken(uid, {
                session_id: sessionId,
                tenant_id: tenantId,
                client_id: clientId
            });
            payload.expires_in = 3600;
        }

        if (mode === 'dual' || mode === 'oidc') {
            payload.access_token = await this.mintAccessToken({
                uid,
                clientId,
                tenantId,
                sessionId,
                familyId,
                scope: normalizedScope
            });
            payload.token_type = 'Bearer';
            payload.expires_in = ACCESS_TOKEN_TTL_SECONDS;
            payload.scope = normalizedScope;

            if (hasScope(normalizedScope, 'openid')) {
                payload.id_token = await this.mintIdToken({
                    uid,
                    clientId,
                    tenantId,
                    sessionId,
                    scope: normalizedScope,
                    email: userClaims.email,
                    emailVerified: userClaims.emailVerified,
                    name: userClaims.name,
                    nonce,
                    authTime
                });
            }
        }

        return payload;
    }

    async verifyAccessToken(token, options = {}) {
        const result = await this.signingKeystore.verifyJwt(token, options);
        if (!result.valid) {
            return result;
        }
        if (!result.header || result.header.alg !== 'RS256') {
            return { valid: false, reason: 'INVALID_ALGORITHM' };
        }
        if (result.payload.token_use !== 'access') {
            return { valid: false, reason: 'INVALID_TOKEN_USE' };
        }
        if (result.payload.iss !== this.issuer) {
            return { valid: false, reason: 'INVALID_ISSUER' };
        }
        const rawAud = result.payload.aud;
        const audList = typeof rawAud === 'string'
            ? (rawAud ? [rawAud] : [])
            : (Array.isArray(rawAud) ? rawAud : []);
        if (audList.length === 0 || !audList.every(a => typeof a === 'string' && a.length > 0)) {
            return { valid: false, reason: 'INVALID_AUDIENCE' };
        }
        const requiredAud = options.expectedAudience || this.getUserinfoAudience();
        if (!audList.includes(requiredAud)) {
            return { valid: false, reason: 'INVALID_AUDIENCE' };
        }
        const azp = result.payload.azp;
        if (audList.length > 1) {
            if (typeof azp !== 'string' || !azp || !audList.includes(azp)) {
                return { valid: false, reason: 'INVALID_AZP' };
            }
        } else if (azp !== undefined && (typeof azp !== 'string' || !azp)) {
            return { valid: false, reason: 'INVALID_AZP' };
        }
        if (options.expectedAzp && azp !== options.expectedAzp) {
            return { valid: false, reason: 'INVALID_AZP' };
        }
        if (typeof result.payload.tenant_id !== 'string' || !result.payload.tenant_id) {
            return { valid: false, reason: 'MISSING_TENANT_ID' };
        }
        if (options.expectedTenantId && result.payload.tenant_id !== options.expectedTenantId) {
            return { valid: false, reason: 'TENANT_MISMATCH' };
        }
        return result;
    }
}

module.exports = {
    OidcTokenService,
    ACCESS_TOKEN_TTL_SECONDS,
    ID_TOKEN_TTL_SECONDS,
    VALID_COMPATIBILITY_MODES,
    SUPPORTED_SCOPES,
    normalizeScope,
    validateAndNormalizeScope,
    hasScope
};
