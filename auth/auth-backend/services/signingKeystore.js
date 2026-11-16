// signingKeystore.js
// Milestone 1.2: Asymmetric Signing Infrastructure (RS256 Keystore & Public JWKS)
//
// Stores RSA-2048+ signing key pairs in Firestore (`system_signing_keys/{keyId}`):
// - Private keys are NEVER stored in plaintext; encrypted at rest with AES-256-GCM
//   (12-byte IV, 16-byte Auth Tag, AAD-bound to `lanzar_signing_key:<kid>:v<kekVersion>`).
// - Supports zero-downtime key rotation (`active` -> `verify_only`) and immediate
//   revocation (`revoked`, excluded from JWKS and signing).
// - Exports standard RFC 7517 public JWKs (`kty`, `use`, `alg`, `kid`, `n`, `e`)
//   for `GET /.well-known/jwks.json` and signs/verifies RS256 JWTs using Node `crypto`.

const crypto = require('crypto');

const GCM_IV_LENGTH = 12;
const GCM_TAG_LENGTH = 16;
const DEFAULT_KEK_VERSION = 1;
const DEFAULT_JWKS_CACHE_TTL_MS = 5 * 1000;
const RSA_MODULUS_LENGTH = 2048;
const ACTIVE_POINTER_DOC_ID = '_active_pointer';
const MAX_SIGNED_TOKEN_TTL_SECONDS = 3600; // Matches ID_TOKEN_TTL_SECONDS (3600s > ACCESS_TOKEN_TTL_SECONDS 900s)
const CLOCK_SKEW_AND_CACHE_MARGIN_SECONDS = 600; // 10 min buffer for clock skew & JWKS cache TTL
const MIN_SAFE_RETIREMENT_GRACE_SECONDS = 3900; // Hard floor: 3600s max token TTL + 300s min skew
const DEFAULT_RETIREMENT_GRACE_SECONDS = MAX_SIGNED_TOKEN_TTL_SECONDS + CLOCK_SKEW_AND_CACHE_MARGIN_SECONDS; // 4200s (70 min)

function validateRetirementGraceSeconds(rawSeconds) {
    const num = Number(rawSeconds);
    if (!Number.isFinite(num) || !Number.isInteger(num) || num < MIN_SAFE_RETIREMENT_GRACE_SECONDS) {
        throw new Error(
            `Signing key retirement grace period must be an integer >= ${MIN_SAFE_RETIREMENT_GRACE_SECONDS}s (max token TTL 3600s + 300s skew), got "${rawSeconds}".`
        );
    }
    return num;
}

function resolveRetirementGraceSeconds(env = process.env) {
    const raw = env && env.SIGNING_KEY_RETIREMENT_GRACE_SECONDS;
    if (raw === undefined || raw === null || String(raw).trim() === '') {
        return DEFAULT_RETIREMENT_GRACE_SECONDS;
    }
    return validateRetirementGraceSeconds(String(raw).trim());
}

const KNOWN_DEV_KEKS = [
    'LANZAR_ID_DEV_SIGNING_KEK_V1_TEST_ONLY_32B',
    'default_dev_secret',
    'dev_secret',
    'lanzar_dev'
];

function isProductionOrStaging(env = process.env) {
    return (
        env.NODE_ENV === 'production' ||
        env.NODE_ENV === 'staging' ||
        env.APP_ENV === 'production' ||
        env.APP_ENV === 'staging'
    );
}

function parseActiveSigningKekVersion(rawValue) {
    if (rawValue === undefined || rawValue === null) {
        return DEFAULT_KEK_VERSION;
    }
    const trimmed = String(rawValue).trim();
    if (trimmed === '') {
        return DEFAULT_KEK_VERSION;
    }
    if (!/^[1-9]\d*$/.test(trimmed)) {
        throw new Error(`ACTIVE_SIGNING_KEK_VERSION must be a positive integer, got "${rawValue}"`);
    }
    const parsed = Number(trimmed);
    if (!Number.isSafeInteger(parsed) || parsed < 1) {
        throw new Error(`ACTIVE_SIGNING_KEK_VERSION must be a positive integer, got "${rawValue}"`);
    }
    return parsed;
}

function parseAndValidateKek(rawKey, version) {
    if (!rawKey) return null;
    let keyBuffer;
    if (Buffer.isBuffer(rawKey)) {
        keyBuffer = rawKey;
    } else if (typeof rawKey === 'string') {
        const trimmed = rawKey.trim();
        if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
            keyBuffer = Buffer.from(trimmed, 'hex');
        } else {
            keyBuffer = Buffer.from(trimmed, 'utf8');
        }
    } else {
        throw new Error(`Signing KEK for version ${version} has invalid type.`);
    }

    if (keyBuffer.length < 32) {
        throw new Error(`Signing KEK for version ${version} must be at least 32 bytes (256 bits), got ${keyBuffer.length} bytes.`);
    }
    return keyBuffer.subarray(0, 32);
}

function resolveRawSigningKekFromEnv(env, numericVersion) {
    if (env.SIGNING_KEY_ENCRYPTION_KEYS) {
        let keyring;
        try {
            keyring = JSON.parse(env.SIGNING_KEY_ENCRYPTION_KEYS);
        } catch (e) {
            throw new Error(`SIGNING_KEY_ENCRYPTION_KEYS must be valid JSON: ${e.message}`);
        }
        if (keyring && typeof keyring === 'object') {
            const candidate = keyring[String(numericVersion)] || keyring[numericVersion];
            if (candidate) return candidate;
        }
    }

    const versionEnvVar = `SIGNING_KEY_ENCRYPTION_KEY_V${numericVersion}`;
    if (env[versionEnvVar]) {
        return env[versionEnvVar];
    }

    if (numericVersion === 1 && env.SIGNING_KEY_ENCRYPTION_KEY) {
        return env.SIGNING_KEY_ENCRYPTION_KEY;
    }

    return null;
}

function resolveSigningKek(version = parseActiveSigningKekVersion(process.env.ACTIVE_SIGNING_KEK_VERSION), env = process.env) {
    const numericVersion = Number(version);
    if (!Number.isInteger(numericVersion) || numericVersion < 1) {
        throw new Error(`Unsupported signing KEK version: ${version}`);
    }

    const rawFromEnv = resolveRawSigningKekFromEnv(env, numericVersion);
    if (rawFromEnv) {
        return parseAndValidateKek(rawFromEnv, numericVersion);
    }

    if (isProductionOrStaging(env)) {
        const envLabel = env.APP_ENV || env.NODE_ENV || 'production';
        throw new Error(`Dedicated SIGNING_KEY_ENCRYPTION_KEY is missing for version ${numericVersion} in ${envLabel} environment.`);
    }

    if (numericVersion === 1) {
        return crypto.createHash('sha256').update('LANZAR_ID_DEV_SIGNING_KEK_V1_TEST_ONLY_32B').digest();
    }

    throw new Error(`Unsupported signing KEK version: ${numericVersion} (unconfigured).`);
}

function validateSigningKeyEncryptionConfiguration(env = process.env) {
    const activeVersion = parseActiveSigningKekVersion(env.ACTIVE_SIGNING_KEK_VERSION);
    const keyRaw = resolveRawSigningKekFromEnv(env, activeVersion);

    if (isProductionOrStaging(env)) {
        const envLabel = env.APP_ENV || env.NODE_ENV || 'production';
        if (!keyRaw) {
            throw new Error(`SIGNING_KEY_ENCRYPTION_KEY is required in ${envLabel} environment for active KEK version ${activeVersion}.`);
        }
        if (typeof keyRaw === 'string') {
            const lower = keyRaw.toLowerCase();
            for (const devStr of KNOWN_DEV_KEKS) {
                if (lower.includes(devStr.toLowerCase())) {
                    throw new Error(`SIGNING_KEY_ENCRYPTION_KEY cannot use a development or default secret in ${envLabel}.`);
                }
            }
        }
        parseAndValidateKek(keyRaw, activeVersion);
    } else if (keyRaw) {
        parseAndValidateKek(keyRaw, activeVersion);
    }
    return true;
}

function encryptPrivateKeyPem(privateKeyPem, keyId, kekVersion = parseActiveSigningKekVersion(process.env.ACTIVE_SIGNING_KEK_VERSION)) {
    if (typeof privateKeyPem !== 'string' || !privateKeyPem) {
        throw new Error('privateKeyPem is required for encryption.');
    }
    if (typeof keyId !== 'string' || !keyId) {
        throw new Error('keyId is required for AAD binding.');
    }
    const key = resolveSigningKek(kekVersion);
    const iv = crypto.randomBytes(GCM_IV_LENGTH);
    const aad = Buffer.from(`lanzar_signing_key:${keyId}:v${kekVersion}`, 'utf8');
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(aad);
    const encrypted = Buffer.concat([cipher.update(privateKeyPem, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return {
        alg: 'aes-256-gcm',
        keyVersion: kekVersion,
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        ciphertext: encrypted.toString('base64')
    };
}

function decryptPrivateKeyPem(encryptedBlob, keyId) {
    if (!encryptedBlob || typeof encryptedBlob !== 'object') {
        throw new Error('Encrypted private key payload is required.');
    }
    const keyVersion = Number(encryptedBlob.keyVersion || DEFAULT_KEK_VERSION);
    const key = resolveSigningKek(keyVersion);
    const iv = Buffer.from(encryptedBlob.iv, 'base64');
    const authTag = Buffer.from(encryptedBlob.authTag, 'base64');
    const ciphertext = Buffer.from(encryptedBlob.ciphertext, 'base64');

    if (iv.length !== GCM_IV_LENGTH || authTag.length !== GCM_TAG_LENGTH) {
        throw new Error('Invalid AES-256-GCM envelope dimensions for signing key.');
    }

    const aad = Buffer.from(`lanzar_signing_key:${keyId}:v${keyVersion}`, 'utf8');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf8');
}

function base64UrlEncode(input) {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
    return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64UrlDecode(str) {
    const normalized = String(str).replace(/-/g, '+').replace(/_/g, '/');
    const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
    return Buffer.from(normalized + pad, 'base64');
}

function sanitizePublicJwk(jwk, kid) {
    if (!jwk || jwk.kty !== 'RSA' || !jwk.n || !jwk.e) {
        throw new Error('Invalid RSA public JWK.');
    }
    return {
        kty: 'RSA',
        use: 'sig',
        alg: 'RS256',
        kid,
        n: jwk.n,
        e: jwk.e
    };
}

function generateRsaSigningKeyRecord(nowMs = Date.now()) {
    const kid = `lanzar_rs256_${nowMs}_${crypto.randomBytes(6).toString('hex')}`;
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: RSA_MODULUS_LENGTH,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    const exportedJwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' });
    const publicJwk = sanitizePublicJwk(exportedJwk, kid);
    const kekVersion = parseActiveSigningKekVersion(process.env.ACTIVE_SIGNING_KEK_VERSION);
    const encryptedPrivateKey = encryptPrivateKeyPem(privateKey, kid, kekVersion);
    const nowIso = new Date(nowMs).toISOString();

    return {
        kid,
        alg: 'RS256',
        kty: 'RSA',
        use: 'sig',
        status: 'active',
        publicJwk,
        encryptedPrivateKey,
        createdAt: nowIso,
        activatedAt: nowIso,
        rotatedAt: null,
        revokedAt: null,
        revocationReason: null
    };
}

class SigningKeystore {
    constructor(db, options = {}) {
        if (!db || typeof db.collection !== 'function') {
            throw new Error('SigningKeystore requires a valid Firestore instance.');
        }
        this.db = db;
        this.collectionName = options.collectionName || 'system_signing_keys';
        this.cacheTtlMs = Number.isFinite(options.cacheTtlMs) ? options.cacheTtlMs : DEFAULT_JWKS_CACHE_TTL_MS;
        this._cachedActive = null;
        this._cachedJwks = null;
        this._cacheExpiresAt = 0;
    }

    invalidateCache() {
        this._cachedActive = null;
        this._cachedJwks = null;
        this._cacheExpiresAt = 0;
    }

    _collectionRef() {
        return this.db.collection(this.collectionName);
    }

    /**
     * Ensures an active RS256 signing key exists in Firestore, creating one
     * atomically if none is active, serialized via the deterministic
     * `_active_pointer` singleton document.
     *
     * Candidate RSA key material is generated outside the transaction callback
     * so Firestore contention retries do not repeatedly generate key pairs.
     */
    async ensureActiveSigningKey({ bypassCache = false } = {}) {
        const nowMs = Date.now();
        if (!bypassCache && this._cachedActive && nowMs < this._cacheExpiresAt) {
            return this._cachedActive;
        }

        const candidateRecord = generateRsaSigningKeyRecord(nowMs);

        const record = await this.db.runTransaction(async (tx) => {
            const pointerRef = this._collectionRef().doc(ACTIVE_POINTER_DOC_ID);
            const pointerSnap = await tx.get(pointerRef);

            if (pointerSnap.exists && pointerSnap.data() && pointerSnap.data().activeKid) {
                const pointedKid = pointerSnap.data().activeKid;
                const pointedSnap = await tx.get(this._collectionRef().doc(pointedKid));
                if (pointedSnap.exists && pointedSnap.data() && pointedSnap.data().status === 'active') {
                    return pointedSnap.data();
                }
            }

            // Reconcile legacy/missing/stale pointer state deterministically without
            // creating duplicate active keys or reactivating revoked keys.
            const activeSnap = await tx.get(this._collectionRef().where('status', '==', 'active'));
            const nowIso = new Date().toISOString();

            if (!activeSnap.empty) {
                const docs = activeSnap.docs.map(d => d.data());
                docs.sort((a, b) => (
                    String(b.activatedAt || b.createdAt || '').localeCompare(String(a.activatedAt || a.createdAt || '')) ||
                    String(a.kid).localeCompare(String(b.kid))
                ));
                const winner = docs[0];
                for (let i = 1; i < docs.length; i++) {
                    tx.update(this._collectionRef().doc(docs[i].kid), {
                        status: 'verify_only',
                        rotatedAt: nowIso
                    });
                }
                tx.set(pointerRef, {
                    activeKid: winner.kid,
                    updatedAt: nowIso
                });
                return winner;
            }

            tx.set(this._collectionRef().doc(candidateRecord.kid), candidateRecord);
            tx.set(pointerRef, {
                activeKid: candidateRecord.kid,
                updatedAt: candidateRecord.createdAt
            });
            return candidateRecord;
        });

        this._cachedActive = record;
        this._cacheExpiresAt = Date.now() + this.cacheTtlMs;
        return record;
    }

    /**
     * Rotates the active RS256 signing key atomically inside a Firestore transaction
     * serialized by `_active_pointer`:
     * - Demotes existing `active` key(s) to `verify_only` so existing tokens remain verifiable.
     * - Activates a fresh RSA-2048 key pair pre-generated outside the transaction callback.
     */
    async rotateSigningKey({ nowMs = Date.now(), graceSeconds } = {}) {
        const effectiveGraceSec = graceSeconds !== undefined
            ? validateRetirementGraceSeconds(graceSeconds)
            : resolveRetirementGraceSeconds(process.env);
        const candidateRecord = generateRsaSigningKeyRecord(nowMs);

        const result = await this.db.runTransaction(async (tx) => {
            const pointerRef = this._collectionRef().doc(ACTIVE_POINTER_DOC_ID);
            const pointerSnap = await tx.get(pointerRef);
            const pointedKid = pointerSnap.exists && pointerSnap.data() ? pointerSnap.data().activeKid : null;
            const pointedSnap = pointedKid
                ? await tx.get(this._collectionRef().doc(pointedKid))
                : null;
            const activeSnap = await tx.get(this._collectionRef().where('status', '==', 'active'));

            const nowIso = new Date(nowMs).toISOString();
            const eligibleForRevocationAt = new Date(nowMs + effectiveGraceSec * 1000).toISOString();
            const demoteIds = new Set();
            for (const docSnap of activeSnap.docs) {
                demoteIds.add(docSnap.id);
            }
            if (pointedSnap && pointedSnap.exists && pointedSnap.data() && pointedSnap.data().status === 'active') {
                demoteIds.add(pointedSnap.id);
            }

            const rotatedIds = Array.from(demoteIds);
            for (const kid of rotatedIds) {
                tx.update(this._collectionRef().doc(kid), {
                    status: 'verify_only',
                    rotatedAt: nowIso,
                    eligibleForRevocationAt,
                    retirementGraceSeconds: effectiveGraceSec
                });
            }

            tx.set(this._collectionRef().doc(candidateRecord.kid), candidateRecord);
            tx.set(pointerRef, {
                activeKid: candidateRecord.kid,
                updatedAt: nowIso
            });
            return { newRecord: candidateRecord, rotatedIds, eligibleForRevocationAt, retirementGraceSeconds: effectiveGraceSec };
        });

        this.invalidateCache();
        this._cachedActive = result.newRecord;
        this._cacheExpiresAt = Date.now() + this.cacheTtlMs;
        return result;
    }

    /**
     * Idempotently retires `verify_only` keys whose grace period has elapsed.
     * Safeguards:
     * - Never retires `_active_pointer.activeKid` or any `active` key.
     * - Respects `MIN_SAFE_RETIREMENT_GRACE_SECONDS` (3900s floor).
     * - Writes an audit log record via `auditLogService` when provided.
     */
    async retireEligibleKeys({ nowMs = Date.now(), graceSeconds, auditLogService = null } = {}) {
        const effectiveGraceSec = graceSeconds !== undefined
            ? validateRetirementGraceSeconds(graceSeconds)
            : resolveRetirementGraceSeconds(process.env);

        const verifyOnlySnap = await this._collectionRef().where('status', '==', 'verify_only').get();
        const retiredKids = [];
        const skippedKids = [];

        for (const docSnap of verifyOnlySnap.docs) {
            const kid = docSnap.id;
            if (kid === ACTIVE_POINTER_DOC_ID) continue;
            const data = docSnap.data() || {};

            let eligibleAtMs = data.eligibleForRevocationAt ? Date.parse(data.eligibleForRevocationAt) : NaN;
            if (!Number.isFinite(eligibleAtMs) && data.rotatedAt) {
                const rotatedMs = Date.parse(data.rotatedAt);
                if (Number.isFinite(rotatedMs)) {
                    eligibleAtMs = rotatedMs + effectiveGraceSec * 1000;
                }
            }
            if (!Number.isFinite(eligibleAtMs) || nowMs < eligibleAtMs) {
                skippedKids.push({ kid, reason: 'GRACE_PERIOD_ACTIVE' });
                continue;
            }

            const outcome = await this.db.runTransaction(async (tx) => {
                const pointerRef = this._collectionRef().doc(ACTIVE_POINTER_DOC_ID);
                const keyRef = this._collectionRef().doc(kid);
                const [pointerSnap, freshSnap] = await Promise.all([tx.get(pointerRef), tx.get(keyRef)]);

                if (!freshSnap.exists) {
                    return { retired: false, reason: 'NOT_FOUND' };
                }
                const fresh = freshSnap.data() || {};
                const activeKid = pointerSnap.exists && pointerSnap.data() ? pointerSnap.data().activeKid : null;
                if (activeKid === kid || fresh.status === 'active') {
                    return { retired: false, reason: 'ACTIVE_KEY_PROTECTED' };
                }
                if (fresh.status !== 'verify_only') {
                    return { retired: false, reason: `ALREADY_${String(fresh.status || 'UNKNOWN').toUpperCase()}` };
                }

                const nowIso = new Date(nowMs).toISOString();
                tx.update(keyRef, {
                    status: 'revoked',
                    revokedAt: nowIso,
                    revocationReason: 'grace_period_elapsed',
                    retiredBy: 'system:worker'
                });

                if (auditLogService && typeof auditLogService.buildAdminAuditRecord === 'function') {
                    const prepared = auditLogService.buildAdminAuditRecord({
                        auditId: `aud_key_retire_${kid}`,
                        actorUid: 'system:worker',
                        actorEmail: null,
                        actorTenantId: 'lanzar',
                        actorRole: 'system',
                        targetTenantId: 'lanzar',
                        clientId: kid,
                        operation: 'platform.signing_key.auto_retired',
                        outcome: 'success',
                        metadata: {
                            kid,
                            rotatedAt: fresh.rotatedAt || null,
                            eligibleForRevocationAt: new Date(eligibleAtMs).toISOString(),
                            graceSeconds: effectiveGraceSec
                        }
                    });
                    auditLogService.writeInTransaction(tx, prepared);
                }

                return { retired: true };
            });

            if (outcome.retired) {
                retiredKids.push(kid);
            } else {
                skippedKids.push({ kid, reason: outcome.reason });
            }
        }

        if (retiredKids.length > 0) {
            this.invalidateCache();
        }
        return { retiredKids, skippedKids };
    }

    /**
     * Immediately revokes a signing key (`status: 'revoked'`), excluding it from
     * both future signing and the public JWKS endpoint, and clears `_active_pointer`
     * if it referenced the revoked key.
     */
    async revokeSigningKey(kid, reason = 'manual_revocation') {
        if (typeof kid !== 'string' || !kid || kid === ACTIVE_POINTER_DOC_ID) {
            throw new Error('kid is required to revoke a signing key.');
        }

        const revoked = await this.db.runTransaction(async (tx) => {
            const pointerRef = this._collectionRef().doc(ACTIVE_POINTER_DOC_ID);
            const ref = this._collectionRef().doc(kid);
            const pointerSnap = await tx.get(pointerRef);
            const snap = await tx.get(ref);
            if (!snap.exists) {
                return false;
            }
            const nowIso = new Date().toISOString();
            tx.update(ref, {
                status: 'revoked',
                revokedAt: nowIso,
                revocationReason: reason
            });
            if (pointerSnap.exists && pointerSnap.data() && pointerSnap.data().activeKid === kid) {
                tx.set(pointerRef, {
                    activeKid: null,
                    revokedAt: nowIso,
                    updatedAt: nowIso
                });
            }
            return true;
        });

        this.invalidateCache();
        return revoked;
    }

    /**
     * Returns RFC 7517 public JWKS (`{ keys: [...] }`) for all `active` and `verify_only`
     * keys. Revoked keys and all private/encrypted key material are strictly excluded.
     */
    async getPublicJwks({ bypassCache = false } = {}) {
        const nowMs = Date.now();
        if (!bypassCache && this._cachedJwks && nowMs < this._cacheExpiresAt) {
            return this._cachedJwks;
        }

        await this.ensureActiveSigningKey({ bypassCache });
        const snap = await this._collectionRef().get();
        const keys = [];
        for (const docSnap of snap.docs) {
            if (docSnap.id === ACTIVE_POINTER_DOC_ID) {
                continue;
            }
            const data = docSnap.data();
            if (data && (data.status === 'active' || data.status === 'verify_only') && data.publicJwk) {
                keys.push(sanitizePublicJwk(data.publicJwk, data.kid));
            }
        }

        const jwks = { keys };
        this._cachedJwks = jwks;
        this._cacheExpiresAt = Date.now() + this.cacheTtlMs;
        return jwks;
    }

    /**
     * Signs a JWT payload with the current active RS256 private key.
     */
    async signJwt(payload, { expiresInSeconds = 900, nowSec = Math.floor(Date.now() / 1000) } = {}) {
        if (!payload || typeof payload !== 'object') {
            throw new Error('JWT payload must be an object.');
        }
        const activeRecord = await this.ensureActiveSigningKey();
        const privateKeyPem = decryptPrivateKeyPem(activeRecord.encryptedPrivateKey, activeRecord.kid);
        const privateKey = crypto.createPrivateKey(privateKeyPem);

        const header = {
            alg: 'RS256',
            typ: 'JWT',
            kid: activeRecord.kid
        };
        const fullPayload = {
            ...payload,
            iat: payload.iat !== undefined ? payload.iat : nowSec,
            exp: payload.exp !== undefined ? payload.exp : nowSec + expiresInSeconds
        };

        const encodedHeader = base64UrlEncode(JSON.stringify(header));
        const encodedPayload = base64UrlEncode(JSON.stringify(fullPayload));
        const signingInput = `${encodedHeader}.${encodedPayload}`;
        const signature = crypto.sign('RSA-SHA256', Buffer.from(signingInput, 'utf8'), privateKey);

        return `${signingInput}.${base64UrlEncode(signature)}`;
    }

    /**
     * Verifies an RS256 compact JWT against the currently published public JWKS.
     */
    async verifyJwt(token, { bypassCache = false, nowSec = Math.floor(Date.now() / 1000) } = {}) {
        if (typeof token !== 'string') {
            return { valid: false, reason: 'TOKEN_NOT_STRING' };
        }
        const parts = token.split('.');
        if (parts.length !== 3) {
            return { valid: false, reason: 'MALFORMED_JWT' };
        }
        let header;
        let payload;
        try {
            header = JSON.parse(base64UrlDecode(parts[0]).toString('utf8'));
            payload = JSON.parse(base64UrlDecode(parts[1]).toString('utf8'));
        } catch {
            return { valid: false, reason: 'INVALID_JWT_ENCODING' };
        }

        if (!header || header.alg !== 'RS256' || typeof header.kid !== 'string' || !header.kid) {
            return { valid: false, reason: 'UNSUPPORTED_HEADER' };
        }

        const jwks = await this.getPublicJwks({ bypassCache });
        const matchingJwk = jwks.keys.find(k => k.kid === header.kid);
        if (!matchingJwk) {
            return { valid: false, reason: 'UNKNOWN_OR_REVOKED_KID' };
        }

        const publicKey = crypto.createPublicKey({ key: matchingJwk, format: 'jwk' });
        const signingInput = `${parts[0]}.${parts[1]}`;
        const sigBuf = base64UrlDecode(parts[2]);
        const sigValid = crypto.verify('RSA-SHA256', Buffer.from(signingInput, 'utf8'), publicKey, sigBuf);
        if (!sigValid) {
            return { valid: false, reason: 'INVALID_SIGNATURE' };
        }

        if (!Number.isFinite(payload.exp) || nowSec >= payload.exp) {
            return { valid: false, reason: 'TOKEN_EXPIRED' };
        }
        if (payload.nbf !== undefined && (!Number.isFinite(payload.nbf) || nowSec < payload.nbf)) {
            return { valid: false, reason: 'TOKEN_NOT_YET_VALID' };
        }

        return { valid: true, header, payload, kid: header.kid };
    }
}

module.exports = {
    SigningKeystore,
    validateSigningKeyEncryptionConfiguration,
    parseActiveSigningKekVersion,
    resolveSigningKek,
    encryptPrivateKeyPem,
    decryptPrivateKeyPem,
    generateRsaSigningKeyRecord,
    sanitizePublicJwk,
    resolveRetirementGraceSeconds,
    validateRetirementGraceSeconds,
    MIN_SAFE_RETIREMENT_GRACE_SECONDS,
    DEFAULT_RETIREMENT_GRACE_SECONDS
};
