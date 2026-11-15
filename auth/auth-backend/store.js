// store.js
// OAuth 2.0 Authorization Code Storage for LANZAR ID
// Specification: LID-SPEC-M1.1-STORE-REV7-AUTHORITATIVE & LID-ARCH-REV-022-FINAL-AUTHORITATIVE
//
// ============================================================================
// ARCHITECTURAL DESIGN & INVARIANTS:
// ============================================================================
// 1. Two-Phase Distributed State Machine:
//    Transitions through: ISSUED -> REDEEMING -> COMPLETED | COMPROMISED
// 2. Strict Read-Before-Write Firestore Transactions:
//    All document reads strictly precede all document mutations.
// 3. Stale-Worker Revocation Safety:
//    A stale worker is fenced out and MUST NEVER revoke resources belonging
//    to a newer worker or already active resources.
// 4. Explicit Expired-Lock Takeover Policy:
//    - Same idempotency key: safe recovery/takeover with cleanup of old pending state.
//    - Different idempotency key: triggers conflict/replay compromise defense.
// 5. Complete Three-Document Relationship Validation:
//    Validates session familyId, family sessionId, session/family tenantId,
//    stored document IDs, and authorization code's expected session/family IDs.
// 6. Failure-Handler Fencing:
//    Late exceptions from old workers are fenced and cannot revoke newer records.
// 7. NIST SP 800-38D AES-256-GCM Receipt Encryption:
//    12-byte CSPRNG IV, 16-byte Auth Tag, Cryptographic AAD Context Binding.
// ============================================================================

const crypto = require('crypto');

const GCM_IV_LENGTH = 12; // 96 bits (NIST SP 800-38D)
const GCM_TAG_LENGTH = 16; // 128 bits
const DEFAULT_RECEIPT_KEY_VERSION = 1;

/**
 * Checks whether the current process is running in production or staging.
 */
function isProductionOrStaging(env = process.env) {
    return (
        env.NODE_ENV === 'production' ||
        env.NODE_ENV === 'staging' ||
        env.APP_ENV === 'production' ||
        env.APP_ENV === 'staging'
    );
}

/**
 * Known development-only key signatures that are strictly prohibited in production or staging.
 */
const KNOWN_DEV_RECEIPT_KEYS = [
    'LANZAR_ID_DEV_RECEIPT_SECRET_V1',
    'LANZAR_ID_DEV_RECEIPT_KEY_VERSION_1_TEST_ONLY_32B',
    'default_dev_secret',
    'dev_receipt_key',
    'lanzar_dev',
    'dev_secret'
];

/**
 * Validates a key buffer or hex/utf8 string for receipt encryption.
 * Must provide at least 32 bytes (256 bits) of cryptographic key material.
 */
function parseAndValidateReceiptKey(rawKey, version) {
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
        throw new Error(`Receipt encryption key for version ${version} has invalid type.`);
    }

    if (keyBuffer.length < 32) {
        throw new Error(`Receipt encryption key for version ${version} is invalid: must be at least 32 bytes (256 bits), got ${keyBuffer.length} bytes.`);
    }

    return keyBuffer.subarray(0, 32);
}

/**
 * In-memory test keyring override for isolated multi-version rotation tests.
 */
let receiptKeyringOverride = null;

function setReceiptKeyringForTesting(keyring) {
    receiptKeyringOverride = keyring;
}

function resetReceiptKeyringForTesting() {
    receiptKeyringOverride = null;
}

function parseActiveReceiptKeyVersion(rawValue) {
    if (rawValue === undefined || rawValue === null) {
        return DEFAULT_RECEIPT_KEY_VERSION;
    }
    const trimmed = String(rawValue).trim();
    if (trimmed === '') {
        return DEFAULT_RECEIPT_KEY_VERSION;
    }
    if (!/^[1-9]\d*$/.test(trimmed)) {
        throw new Error(`ACTIVE_RECEIPT_KEY_VERSION must be a positive integer, got "${rawValue}"`);
    }
    const parsed = Number(trimmed);
    if (!Number.isSafeInteger(parsed) || parsed < 1) {
        throw new Error(`ACTIVE_RECEIPT_KEY_VERSION must be a positive integer, got "${rawValue}"`);
    }
    return parsed;
}

function getActiveReceiptKeyVersion() {
    return parseActiveReceiptKeyVersion(process.env.ACTIVE_RECEIPT_KEY_VERSION);
}

/**
 * Resolves the raw receipt key entry from environment variables using the canonical
 * deterministic fallback order shared by startup validation and runtime resolution:
 * 1. RECEIPT_ENCRYPTION_KEYS[version] (JSON keyring)
 * 2. RECEIPT_ENCRYPTION_KEY_V{version}
 * 3. RECEIPT_ENCRYPTION_KEY (version 1 only)
 * 4. TOKEN_RECEIPT_KEY (version 1 development/non-production fallback only)
 */
function resolveRawReceiptKeyFromEnv(env, numericVersion) {
    if (env.RECEIPT_ENCRYPTION_KEYS) {
        let keyring;
        try {
            keyring = JSON.parse(env.RECEIPT_ENCRYPTION_KEYS);
        } catch (e) {
            throw new Error(`RECEIPT_ENCRYPTION_KEYS must be valid JSON: ${e.message}`);
        }
        if (keyring && typeof keyring === 'object') {
            const candidate = keyring[String(numericVersion)] || keyring[numericVersion];
            if (candidate) {
                return candidate;
            }
        }
    }

    const versionEnvVar = `RECEIPT_ENCRYPTION_KEY_V${numericVersion}`;
    if (env[versionEnvVar]) {
        return env[versionEnvVar];
    }

    if (numericVersion === 1) {
        if (env.RECEIPT_ENCRYPTION_KEY) {
            return env.RECEIPT_ENCRYPTION_KEY;
        }
        if (!isProductionOrStaging(env) && env.TOKEN_RECEIPT_KEY) {
            return env.TOKEN_RECEIPT_KEY;
        }
    }

    return null;
}

/**
 * Resolves the 256-bit symmetric encryption key for token receipts by key version.
 * Supports key rotation across multiple key versions.
 *
 * In production/staging:
 * - Requires a dedicated receipt encryption key.
 * - Missing or invalid keys throw immediately.
 * - Never falls back to SESSION_SECRET, default strings, or hardcoded dev keys.
 */
function resolveReceiptKey(version = getActiveReceiptKeyVersion()) {
    const numericVersion = Number(version);
    if (!Number.isInteger(numericVersion) || numericVersion < 1) {
        throw new Error(`Unsupported receipt key version: ${version} (version must be a positive integer).`);
    }

    // 1. Check test keyring override
    if (receiptKeyringOverride) {
        if (receiptKeyringOverride[numericVersion]) {
            return parseAndValidateReceiptKey(receiptKeyringOverride[numericVersion], numericVersion);
        }
        throw new Error(`Unsupported receipt key version: ${numericVersion} (not found in active keyring).`);
    }

    // 2. Canonical deterministic environment lookup (JSON keyring -> V{n} -> V1 primary)
    const rawFromEnv = resolveRawReceiptKeyFromEnv(process.env, numericVersion);
    if (rawFromEnv) {
        return parseAndValidateReceiptKey(rawFromEnv, numericVersion);
    }

    // 3. In production or staging: FAIL CLOSED IMMEDIATELY. ZERO UNSAFE FALLBACKS!
    if (isProductionOrStaging()) {
        const envLabel = process.env.APP_ENV || process.env.NODE_ENV || 'production';
        throw new Error(`Dedicated receipt encryption key is missing for version ${numericVersion} in ${envLabel} environment. Dedicated key is required in production.`);
    }

    // 4. Explicitly isolated development/test fallback ONLY for version 1
    if (numericVersion === 1) {
        const devFallbackKey = `LANZAR_ID_DEV_RECEIPT_KEY_V1_TEST_ONLY_32B`;
        return crypto.createHash('sha256').update(devFallbackKey).digest();
    }

    // Unknown version > 1 requested without key in keyring
    throw new Error(`Unsupported receipt key version: ${numericVersion} (unconfigured key version).`);
}

/**
 * Validates receipt encryption key configuration during server bootstrap.
 * Throws immediately if dedicated key is missing, weak, or using dev values in production/staging.
 */
function validateReceiptKeyConfiguration(env = process.env) {
    const envLabel = env.APP_ENV || env.NODE_ENV;
    const isProd = isProductionOrStaging(env);

    const activeVersion = parseActiveReceiptKeyVersion(env.ACTIVE_RECEIPT_KEY_VERSION);
    const keyRaw = resolveRawReceiptKeyFromEnv(env, activeVersion);

    if (isProd) {
        if (!keyRaw) {
            throw new Error(`RECEIPT_ENCRYPTION_KEY is required in ${envLabel} environment for active key version ${activeVersion}.`);
        }
        if (typeof keyRaw === 'string') {
            const lower = keyRaw.toLowerCase();
            for (const devStr of KNOWN_DEV_RECEIPT_KEYS) {
                if (lower.includes(devStr.toLowerCase())) {
                    throw new Error(`RECEIPT_ENCRYPTION_KEY cannot use a development or default secret in ${envLabel}.`);
                }
            }
        }
        parseAndValidateReceiptKey(keyRaw, activeVersion);
    } else if (keyRaw) {
        parseAndValidateReceiptKey(keyRaw, activeVersion);
    }
    return true;
}

/**
 * Encrypts an issued token payload using AES-256-GCM with AAD context binding.
 * @param {Object} payload - Raw tokens payload ({ custom_token, session_id, expires_in, ... })
 * @param {string} aadContext - Context string (codeHash:clientId:tenantId:uid:ceremonyId)
 * @param {Object} options - Optional parameters ({ keyVersion })
 * @returns {Object} Encrypted receipt object
 */
function encryptTokenReceipt(payload, aadContext, options = {}) {
    if (!payload) throw new Error('Token payload is required for receipt encryption.');
    if (!aadContext || typeof aadContext !== 'string') {
        throw new Error('AAD context string is required for receipt encryption.');
    }

    const keyVersion = options.keyVersion || getActiveReceiptKeyVersion();
    const iv = crypto.randomBytes(GCM_IV_LENGTH);
    const key = resolveReceiptKey(keyVersion);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: GCM_TAG_LENGTH });
    cipher.setAAD(Buffer.from(aadContext, 'utf8'));

    const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
        keyVersion,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        ciphertext: ciphertext.toString('base64')
    };
}

/**
 * Decrypts a cached token receipt with AES-256-GCM authentication and AAD verification.
 * Supports key rotation: resolves the exact key version recorded in the receipt envelope.
 * @param {Object} receipt - Encrypted receipt object
 * @param {string} expectedAadContext - Context string (codeHash:clientId:tenantId:uid:ceremonyId)
 * @returns {Object} Decrypted tokens payload
 */
function decryptTokenReceipt(receipt, expectedAadContext) {
    if (!receipt || !receipt.iv || !receipt.authTag || !receipt.ciphertext) {
        throw new Error('Invalid receipt structure.');
    }
    const iv = Buffer.from(receipt.iv, 'hex');
    const authTag = Buffer.from(receipt.authTag, 'hex');
    const ciphertext = Buffer.from(receipt.ciphertext, 'base64');

    if (iv.length !== GCM_IV_LENGTH) throw new Error('Invalid IV dimension.');
    if (authTag.length !== GCM_TAG_LENGTH) throw new Error('Invalid Auth Tag dimension.');

    const version = receipt.keyVersion || DEFAULT_RECEIPT_KEY_VERSION;
    const key = resolveReceiptKey(version);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: GCM_TAG_LENGTH });
    decipher.setAAD(Buffer.from(expectedAadContext, 'utf8'));
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(decrypted.toString('utf8'));
}

/**
 * Cryptographic SHA-256 hash helper for authorization codes.
 * Ensures authorization code document IDs in Firestore never store raw credentials.
 */
function hashAuthorizationCode(code) {
    return crypto.createHash('sha256').update(String(code)).digest('hex');
}

/**
 * Generates a structured refresh token bound to its family ID and rotation sequence number.
 * Format: lanzar_rt_<familyId>.<sequenceNumber>.<64-hex-random>
 */
function generateRefreshToken(familyId, sequenceNumber = 1) {
    return `lanzar_rt_${familyId}.${sequenceNumber}.${crypto.randomBytes(32).toString('hex')}`;
}

/**
 * Parses a structured refresh token and extracts its bound familyId and sequenceNumber.
 * Returns null if the token does not match the expected format.
 */
function parseRefreshToken(refreshToken) {
    if (typeof refreshToken !== 'string') return null;
    const match = /^lanzar_rt_([^.]+)\.([1-9]\d*)\.([0-9a-fA-F]{64})$/.exec(refreshToken);
    if (!match) return null;
    const sequenceNumber = Number(match[2]);
    if (!Number.isSafeInteger(sequenceNumber) || sequenceNumber < 1) return null;
    return { familyId: match[1], sequenceNumber };
}

/**
 * Constant-time SHA-256 hex digest comparison.
 */
function timingSafeEqualHex(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== 64 || b.length !== 64) {
        return false;
    }
    try {
        return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
    } catch {
        return false;
    }
}

/**
 * Helper to convert Firestore Timestamps, Date objects, or numbers to epoch milliseconds.
 */
function toEpochMs(val) {
    if (val === null || val === undefined) return 0;
    if (typeof val === 'number') return val;
    if (typeof val.toMillis === 'function') return val.toMillis();
    if (typeof val.getTime === 'function') return val.getTime();
    const parsed = new Date(val).getTime();
    return Number.isFinite(parsed) ? parsed : 0;
}

/**
 * Strengthened Stale-Worker Safety Predicate: Verifies if a worker is authorized to revoke a session document.
 * Validates all applicable ownership relationships, including UID, tenant, client, ceremony,
 * document identity, session/family cross-references, and fencing generation.
 */
function canWorkerRevokeSession(sessionDoc, codeDoc, redemptionLockId, fenceToken, options = {}) {
    if (!sessionDoc || !sessionDoc.exists) return false;
    if (!redemptionLockId || !Number.isFinite(fenceToken)) return false;
    const sessionData = sessionDoc.data();
    // Must be in pending_activation status (NEVER revoke active session!)
    if (sessionData.status !== 'pending_activation') return false;
    // Fencing protection: Must strictly match THIS worker's lock ID and fence token
    if (sessionData.redemptionLockId !== redemptionLockId || sessionData.fenceToken !== fenceToken) {
        return false;
    }
    // Ceremony match if codeDoc exists
    if (codeDoc && codeDoc.exists) {
        const codeData = codeDoc.data();
        if (sessionData.ceremonyId !== codeData.ceremonyId) return false;
        if (sessionData.tenantId !== codeData.tenantId) return false;
        if (sessionData.uid !== codeData.uid) return false;
        if (sessionData.clientId !== codeData.clientId) return false;
    }
    // Document identity validation
    if (options.targetSessionId && sessionData.sessionId !== options.targetSessionId) {
        return false;
    }
    // Cross-reference validation to companion family
    if (options.targetFamilyId && sessionData.familyId !== options.targetFamilyId) {
        return false;
    }
    return true;
}

/**
 * Strengthened Stale-Worker Safety Predicate: Verifies if a worker is authorized to revoke a token family.
 * Validates all applicable ownership relationships, including UID, tenant, client, ceremony,
 * document identity, session/family cross-references, and fencing generation.
 */
function canWorkerRevokeFamily(familyDoc, codeDoc, redemptionLockId, fenceToken, options = {}) {
    if (!familyDoc || !familyDoc.exists) return false;
    if (!redemptionLockId || !Number.isFinite(fenceToken)) return false;
    const familyData = familyDoc.data();
    // Must be in pending_activation status (NEVER revoke active family!)
    if (familyData.status !== 'pending_activation') return false;
    // Fencing protection: Must strictly match THIS worker's lock ID and fence token
    if (familyData.redemptionLockId !== redemptionLockId || familyData.fenceToken !== fenceToken) {
        return false;
    }
    // Ceremony match if codeDoc exists
    if (codeDoc && codeDoc.exists) {
        const codeData = codeDoc.data();
        if (familyData.ceremonyId !== codeData.ceremonyId) return false;
        if (familyData.tenantId !== codeData.tenantId) return false;
        if (familyData.uid !== codeData.uid) return false;
        if (familyData.clientId !== codeData.clientId) return false;
    }
    // Document identity validation
    if (options.targetFamilyId && familyData.familyId !== options.targetFamilyId) {
        return false;
    }
    // Cross-reference validation to companion session
    if (options.targetSessionId && familyData.sessionId !== options.targetSessionId) {
        return false;
    }
    return true;
}

/**
 * Replay-Defense Predicate: Verifies whether a session document belongs to the completed
 * authorization ceremony before revoking it during a post-completion replay attack.
 * Permits revoking `active` (and `pending_activation`) records while strictly enforcing
 * document identity, UID, tenant, client, ceremony, cross-references, and code pointers.
 */
function canReplayRevokeSession(sessionDoc, codeDoc) {
    if (!sessionDoc || !sessionDoc.exists || !codeDoc || !codeDoc.exists) return false;
    const sessionData = sessionDoc.data();
    const codeData = codeDoc.data();
    if (!codeData.issuedSessionId || !codeData.issuedFamilyId) return false;
    if (sessionData.status !== 'active' && sessionData.status !== 'pending_activation') return false;
    if (sessionData.sessionId !== codeData.issuedSessionId) return false;
    if (sessionData.familyId !== codeData.issuedFamilyId) return false;
    if (sessionData.uid !== codeData.uid) return false;
    if (sessionData.tenantId !== codeData.tenantId) return false;
    if (sessionData.clientId !== codeData.clientId) return false;
    if (sessionData.ceremonyId !== codeData.ceremonyId) return false;
    if (!Number.isInteger(codeData.fenceToken) || codeData.fenceToken <= 0 || sessionData.fenceToken !== codeData.fenceToken) {
        return false;
    }
    const expectedLockId = codeData.completedLockId || codeData.redemptionLockId;
    if (!expectedLockId || typeof expectedLockId !== 'string' || sessionData.redemptionLockId !== expectedLockId) {
        return false;
    }
    return true;
}

/**
 * Replay-Defense Predicate: Verifies whether a token-family document belongs to the completed
 * authorization ceremony before revoking it during a post-completion replay attack.
 */
function canReplayRevokeFamily(familyDoc, codeDoc) {
    if (!familyDoc || !familyDoc.exists || !codeDoc || !codeDoc.exists) return false;
    const familyData = familyDoc.data();
    const codeData = codeDoc.data();
    if (!codeData.issuedSessionId || !codeData.issuedFamilyId) return false;
    if (familyData.status !== 'active' && familyData.status !== 'pending_activation') return false;
    if (familyData.familyId !== codeData.issuedFamilyId) return false;
    if (familyData.sessionId !== codeData.issuedSessionId) return false;
    if (familyData.uid !== codeData.uid) return false;
    if (familyData.tenantId !== codeData.tenantId) return false;
    if (familyData.clientId !== codeData.clientId) return false;
    if (familyData.ceremonyId !== codeData.ceremonyId) return false;
    if (!Number.isInteger(codeData.fenceToken) || codeData.fenceToken <= 0 || familyData.fenceToken !== codeData.fenceToken) {
        return false;
    }
    const expectedLockId = codeData.completedLockId || codeData.redemptionLockId;
    if (!expectedLockId || typeof expectedLockId !== 'string' || familyData.redemptionLockId !== expectedLockId) {
        return false;
    }
    return true;
}

/**
 * Paired Replay-Defense Predicate: Validates the complete session + token-family + authorization-code
 * triad before executing post-completion replay revocation. Prevents partial revocation or revocation
 * of inconsistent/mismatched companion records.
 */
function canReplayRevokePair(sessionDoc, familyDoc, codeDoc) {
    if (!canReplayRevokeSession(sessionDoc, codeDoc)) return false;
    if (!canReplayRevokeFamily(familyDoc, codeDoc)) return false;

    const sessionData = sessionDoc.data();
    const familyData = familyDoc.data();

    // Paired cross-reference agreement
    if (sessionData.familyId !== familyData.familyId) return false;
    if (familyData.sessionId !== sessionData.sessionId) return false;

    // Paired ownership, ceremony, and fencing agreement
    if (sessionData.uid !== familyData.uid) return false;
    if (sessionData.tenantId !== familyData.tenantId) return false;
    if (sessionData.clientId !== familyData.clientId) return false;
    if (sessionData.ceremonyId !== familyData.ceremonyId) return false;
    if (sessionData.fenceToken !== familyData.fenceToken) return false;
    if (!sessionData.redemptionLockId || !familyData.redemptionLockId || sessionData.redemptionLockId !== familyData.redemptionLockId) {
        return false;
    }

    return true;
}

/**
 * Independent Ceremony & Lock Ownership Proof: Used for replay containment when the
 * authorization code's fenceToken is invalid/corrupted, authenticating ownership via
 * immutable ceremonyId, completedLockId, uid, tenantId, clientId, and session/family IDs.
 */
function canContainByCeremonyAndLock(recordDoc, codeDoc) {
    if (!recordDoc || !recordDoc.exists || !codeDoc || !codeDoc.exists) return false;
    const recordData = recordDoc.data();
    const codeData = codeDoc.data();
    if (!codeData.issuedSessionId || !codeData.issuedFamilyId) return false;
    if (typeof codeData.ceremonyId !== 'string' || !codeData.ceremonyId) return false;
    const expectedLockId = codeData.completedLockId || codeData.redemptionLockId;
    if (typeof expectedLockId !== 'string' || !expectedLockId) return false;
    if (recordData.status !== 'active' && recordData.status !== 'pending_activation') return false;
    if (recordData.sessionId !== codeData.issuedSessionId) return false;
    if (recordData.familyId !== codeData.issuedFamilyId) return false;
    if (recordData.uid !== codeData.uid) return false;
    if (recordData.tenantId !== codeData.tenantId) return false;
    if (recordData.clientId !== codeData.clientId) return false;
    if (recordData.ceremonyId !== codeData.ceremonyId) return false;
    if (recordData.redemptionLockId !== expectedLockId) return false;
    if (!Number.isInteger(recordData.fenceToken) || recordData.fenceToken <= 0) return false;
    return true;
}

class AuthorizationCodeStore {
    constructor() {
        this.codes = new Map();
    }

    async createCode(data) {
        if (!data || !data.codeChallengeMethod) {
            throw new Error('Explicit codeChallengeMethod is required (no fallback allowed)');
        }
        const code = crypto.randomBytes(32).toString('hex');
        const expiresAt = Date.now() + 60000;

        this.codes.set(code, {
            ...data,
            codeChallengeMethod: data.codeChallengeMethod,
            expiresAt,
            used: false
        });

        return code;
    }

    async getCode(code) {
        return this.codes.get(code);
    }

    async markUsed(code) {
        const record = this.codes.get(code);
        if (!record || record.used) {
            return false;
        }
        record.used = true;
        this.codes.set(code, record);
        return true;
    }

    async registerStagedRecords(params) {
        return { success: true };
    }
}

/**
 * Distributed Firestore-backed OAuth 2.0 Authorization Code Store (LID-SPEC-M1.1-STORE-REV7-AUTHORITATIVE)
 * Executes atomic two-phase authorization ceremony state machine with durable replay defense.
 */
class FirestoreAuthorizationCodeStore {
    constructor(db) {
        if (!db) {
            throw new Error('Firestore database instance is required for FirestoreAuthorizationCodeStore');
        }
        this.db = db;
        this.collectionName = 'authorization_codes';

        // Fail-closed startup validation for receipt encryption keys
        validateReceiptKeyConfiguration(process.env);
    }

    get collection() {
        return this.db.collection(this.collectionName);
    }

    /**
     * Creates a new authorization code ceremony record in Firestore.
     */
    async createCode(data) {
        if (!data || !data.codeChallengeMethod) {
            throw new Error('Explicit codeChallengeMethod is required (no fallback allowed)');
        }
        if (data.codeChallengeMethod !== 'S256') {
            throw new Error('Only S256 codeChallengeMethod is supported');
        }
        if (!data.codeChallenge) {
            throw new Error('codeChallenge is required');
        }

        const code = crypto.randomBytes(32).toString('hex');
        const codeHash = hashAuthorizationCode(code);
        const opTime = Date.now();
        const ceremonyId = `auth_ceremony_${crypto.randomBytes(16).toString('hex')}`;
        const expiresAt = new Date(opTime + 600000); // 10 minutes

        const record = {
            codeHash,
            ceremonyId,
            uid: data.uid,
            tenantId: data.tenantId || 'lanzar',
            clientId: data.clientId,
            redirectUri: data.redirectUri,
            codeChallenge: data.codeChallenge,
            codeChallengeMethod: 'S256',
            status: 'ISSUED',
            fenceToken: 0,
            redemptionLockId: null,
            redemptionLockExpiresAt: null,
            issuedSessionId: null,
            issuedFamilyId: null,
            issuedTokenReceipt: null,
            replayAttemptCount: 0,
            takeoverCount: 0,
            authSessionId: data.authSessionId || null,
            scope: data.scope || 'openid profile email',
            nonce: data.nonce || null,
            mfaVerified: !!data.mfaVerified,
            createdAt: new Date(opTime),
            expiresAt: expiresAt,
            used: false // Backward compatibility
        };

        await this.collection.doc(codeHash).set(record);
        return code;
    }

    /**
     * Phase 1: Initiates redemption via atomic Firestore transaction.
     * Enforces verification-first security and explicit expired-lock takeover policy.
     */
    async initiateRedemption({ code, clientId, redirectUri, codeVerifier, idempotencyKey }) {
        if (!idempotencyKey || typeof idempotencyKey !== 'string' || !/^[a-zA-Z0-9_-]{16,128}$/.test(idempotencyKey)) {
            return {
                status: 'INVALID_REQUEST',
                errorDescription: 'Missing or malformed Idempotency-Key (must be 16-128 characters).'
            };
        }

        if (!code || !clientId || !redirectUri || !codeVerifier) {
            return {
                status: 'INVALID_REQUEST',
                errorDescription: 'Missing required authorization parameters.'
            };
        }

        const codeHash = hashAuthorizationCode(code);
        const codeRef = this.collection.doc(codeHash);

        return await this.db.runTransaction(async (transaction) => {
            const opTime = Date.now();
            // --- ALL READS MUST PRECEDE ALL WRITES ---
            const codeDoc = await transaction.get(codeRef);
            if (!codeDoc.exists) {
                return { status: 'NOT_FOUND', errorDescription: 'Authorization code not found.' };
            }

            const data = codeDoc.data();

            // 1. EXACT CLIENT ID MATCH
            if (data.clientId !== clientId) {
                return { status: 'CLIENT_MISMATCH', errorDescription: 'Client ID mismatch.' };
            }

            // 2. EXACT REDIRECT URI MATCH
            if (data.redirectUri !== redirectUri) {
                return { status: 'REDIRECT_MISMATCH', errorDescription: 'Redirect URI mismatch.' };
            }

            // 3. CRYPTOGRAPHIC PKCE S256 VERIFIER VALIDATION
            const calculatedChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
            if (calculatedChallenge !== data.codeChallenge) {
                return { status: 'PKCE_MISMATCH', errorDescription: 'PKCE challenge verification failed.' };
            }

            // 4. PRE-READ DOCUMENTS FOR REPLAY, CONFLICT, OR EXPIRED TAKEOVER BRANCHES
            let sessionDoc = null;
            let familyDoc = null;
            let sessionRef = null;
            let familyRef = null;

            const lockExpiresMs = toEpochMs(data.redemptionLockExpiresAt);
            const lockExpired = !Number.isFinite(lockExpiresMs) || lockExpiresMs <= 0 || opTime > lockExpiresMs;

            const needsPreRead =
                (data.status === 'COMPLETED' && data.idempotencyKey !== idempotencyKey) ||
                (data.status === 'REDEEMING' && (!lockExpired && data.idempotencyKey !== idempotencyKey)) ||
                (data.status === 'REDEEMING' && lockExpired);

            if (needsPreRead) {
                if (data.issuedSessionId) {
                    sessionRef = this.db.collection('users').doc(data.uid).collection('sessions').doc(data.issuedSessionId);
                    sessionDoc = await transaction.get(sessionRef);
                }
                if (data.issuedFamilyId) {
                    familyRef = this.db.collection('tenants').doc(data.tenantId).collection('token_families').doc(data.issuedFamilyId);
                    familyDoc = await transaction.get(familyRef);
                }
            }

            // --- ALL WRITES COMMENCE BELOW THIS LINE ---

            // --- BRANCH A: CEREMONY ALREADY COMPLETED ---
            if (data.status === 'COMPLETED') {
                if (data.idempotencyKey === idempotencyKey) {
                    const aadContext = `${codeHash}:${data.clientId}:${data.tenantId}:${data.uid}:${data.ceremonyId}`;
                    const decryptedReceipt = decryptTokenReceipt(data.issuedTokenReceipt, aadContext);
                    return {
                        status: 'IDEMPOTENT_RECOVERY',
                        tokenReceipt: decryptedReceipt,
                        sessionId: data.issuedSessionId,
                        familyId: data.issuedFamilyId
                    };
                }

                // Confirmed Replay Attack: Validate Expected Records and Execute Immediate Revocation
                const attemptSeq = (data.replayAttemptCount || 0) + 1;
                const eventId = `sec_replay_${codeHash.slice(0, 16)}_${attemptSeq}_${opTime}`;

                transaction.update(codeRef, {
                    status: 'COMPROMISED',
                    replayAttemptCount: attemptSeq,
                    lastReplayAt: new Date(opTime)
                });

                const sessionMissing = !data.issuedSessionId || !sessionDoc || !sessionDoc.exists;
                const familyMissing = !data.issuedFamilyId || !familyDoc || !familyDoc.exists;
                const codeFenceValid = Number.isInteger(data.fenceToken) && data.fenceToken > 0;
                const sessionIndependentlyVerified = Boolean(
                    sessionRef && (codeFenceValid ? canReplayRevokeSession(sessionDoc, codeDoc) : canContainByCeremonyAndLock(sessionDoc, codeDoc))
                );
                const familyIndependentlyVerified = Boolean(
                    familyRef && (codeFenceValid ? canReplayRevokeFamily(familyDoc, codeDoc) : canContainByCeremonyAndLock(familyDoc, codeDoc))
                );
                const pairEligible = Boolean(
                    codeFenceValid &&
                    sessionIndependentlyVerified &&
                    familyIndependentlyVerified &&
                    canReplayRevokePair(sessionDoc, familyDoc, codeDoc)
                );

                // Independently revoke each verified record synchronously so a surviving
                // active family or session cannot remain usable even if its companion is missing
                // or corrupt, or if codeData.fenceToken is invalid while ceremony+lock ownership is proven.
                if (sessionIndependentlyVerified) {
                    transaction.update(sessionRef, {
                        status: 'revoked',
                        revocationReason: 'authorization_code_replay_compromise',
                        revokedAt: new Date(opTime)
                    });
                }
                if (familyIndependentlyVerified) {
                    transaction.update(familyRef, {
                        status: 'revoked',
                        revocationReason: 'authorization_code_replay_compromise',
                        revokedAt: new Date(opTime)
                    });
                }

                // Enforceable ceremony-level containment tombstone whenever pair integrity fails
                // or code fenceToken is invalid so unproven/unrevoked credentials still cannot refresh.
                if (!pairEligible && typeof data.ceremonyId === 'string' && data.ceremonyId) {
                    transaction.set(this.db.collection('compromised_ceremonies').doc(data.ceremonyId), {
                        ceremonyId: data.ceremonyId,
                        codeHash,
                        uid: data.uid,
                        tenantId: data.tenantId,
                        clientId: data.clientId,
                        reason: !codeFenceValid ? 'invalid_code_fence_token_replay_compromise' : 'authorization_code_replay_compromise',
                        compromisedAt: new Date(opTime)
                    });
                }

                if (!pairEligible) {
                    const integrityEventType = (sessionMissing || familyMissing)
                        ? 'CRITICAL_SECURITY_RECORD_MISSING'
                        : 'CRITICAL_REPLAY_PAIR_INTEGRITY_FAILURE';
                    const integrityPrefix = (sessionMissing || familyMissing) ? 'sec_integrity' : 'sec_pair_integrity';
                    const integrityEventId = `${integrityPrefix}_${codeHash.slice(0, 16)}_${attemptSeq}_${opTime}`;

                    transaction.set(this.db.collection('security_outbox').doc(integrityEventId), {
                        eventId: integrityEventId,
                        tenantId: data.tenantId,
                        uid: data.uid,
                        eventType: integrityEventType,
                        severity: 'CRITICAL',
                        details: {
                            ceremonyId: data.ceremonyId,
                            expectedSessionId: data.issuedSessionId,
                            expectedFamilyId: data.issuedFamilyId,
                            codeFenceToken: data.fenceToken ?? null,
                            codeFenceValid,
                            sessionMissing,
                            familyMissing,
                            sessionInconsistent: !sessionMissing && !sessionIndependentlyVerified,
                            familyInconsistent: !familyMissing && !familyIndependentlyVerified,
                            pairInconsistent: !sessionMissing && !familyMissing && sessionIndependentlyVerified && familyIndependentlyVerified && !pairEligible,
                            sessionIndependentlyVerified,
                            familyIndependentlyVerified,
                            sessionRevoked: sessionIndependentlyVerified,
                            familyRevoked: familyIndependentlyVerified
                        },
                        status: 'pending',
                        retryCount: 0,
                        nextRetryAt: new Date(opTime),
                        createdAt: new Date(opTime)
                    });
                }

                transaction.set(this.db.collection('security_outbox').doc(eventId), {
                    eventId,
                    tenantId: data.tenantId,
                    uid: data.uid,
                    eventType: 'AUTHORIZATION_CODE_REPLAY_ATTACK',
                    severity: 'CRITICAL',
                    details: {
                        ceremonyId: data.ceremonyId,
                        clientId: data.clientId,
                        codeHashPrefix: codeHash.slice(0, 16) + '...',
                        compromisedSessionId: data.issuedSessionId,
                        compromisedFamilyId: data.issuedFamilyId,
                        authSessionId: data.authSessionId
                    },
                    status: 'pending',
                    retryCount: 0,
                    nextRetryAt: new Date(opTime),
                    createdAt: new Date(opTime)
                });

                return {
                    status: 'REPLAY_DETECTED',
                    errorDescription: 'Authorization code replay detected.',
                    compromisedSessionId: data.issuedSessionId,
                    compromisedFamilyId: data.issuedFamilyId
                };
            }

            // --- BRANCH B: CEREMONY ALREADY COMPROMISED ---
            if (data.status === 'COMPROMISED') {
                return { status: 'REPLAY_DETECTED', errorDescription: 'Authorization ceremony compromised.' };
            }

            // --- BRANCH C: CEREMONY IN-PROGRESS (REDEEMING) ---
            if (data.status === 'REDEEMING') {
                const isLeaseValid = Number.isFinite(lockExpiresMs) && lockExpiresMs > 0;
                if (!isLeaseValid) {
                    // Fail closed immediately on missing, zero, negative, malformed, or non-finite lease expiration
                    const attemptSeq = (data.replayAttemptCount || 0) + 1;
                    const eventId = `sec_invalid_lease_${codeHash.slice(0, 16)}_${attemptSeq}_${opTime}`;

                    transaction.update(codeRef, {
                        status: 'COMPROMISED',
                        failureReason: 'invalid_lock_expiration',
                        replayAttemptCount: attemptSeq,
                        lastReplayAt: new Date(opTime)
                    });

                    const workerOpts = {
                        targetSessionId: data.issuedSessionId,
                        targetFamilyId: data.issuedFamilyId
                    };
                    if (sessionRef && canWorkerRevokeSession(sessionDoc, codeDoc, data.redemptionLockId, data.fenceToken, workerOpts)) {
                        transaction.update(sessionRef, {
                            status: 'revoked',
                            revocationReason: 'invalid_lock_expiration',
                            revokedAt: new Date(opTime)
                        });
                    }

                    if (familyRef && canWorkerRevokeFamily(familyDoc, codeDoc, data.redemptionLockId, data.fenceToken, workerOpts)) {
                        transaction.update(familyRef, {
                            status: 'revoked',
                            revocationReason: 'invalid_lock_expiration',
                            revokedAt: new Date(opTime)
                        });
                    }

                    transaction.set(this.db.collection('security_outbox').doc(eventId), {
                        eventId,
                        tenantId: data.tenantId,
                        uid: data.uid,
                        eventType: 'CORRUPT_LEASE_METADATA_DEFENSE',
                        severity: 'CRITICAL',
                        details: {
                            ceremonyId: data.ceremonyId,
                            clientId: data.clientId,
                            codeHashPrefix: codeHash.slice(0, 16) + '...',
                            rawLeaseValue: String(data.redemptionLockExpiresAt),
                            parsedLeaseMs: lockExpiresMs
                        },
                        status: 'pending',
                        retryCount: 0,
                        nextRetryAt: new Date(opTime),
                        createdAt: new Date(opTime)
                    });

                    return { status: 'REPLAY_DETECTED', errorDescription: 'Invalid redemption lock expiration metadata.' };
                }

                if (!lockExpired) {
                    // Lock active (within 15s)
                    if (data.idempotencyKey === idempotencyKey) {
                        return { status: 'IN_PROGRESS', errorDescription: 'Redemption in progress; wait.' };
                    }

                    // Concurrent Conflict: active lock targeted by different key
                    const attemptSeq = (data.replayAttemptCount || 0) + 1;
                    const eventId = `sec_conflict_${codeHash.slice(0, 16)}_${attemptSeq}_${opTime}`;

                    transaction.update(codeRef, {
                        status: 'COMPROMISED',
                        replayAttemptCount: attemptSeq,
                        lastReplayAt: new Date(opTime)
                    });

                    const conflictWorkerOpts = {
                        targetSessionId: data.issuedSessionId,
                        targetFamilyId: data.issuedFamilyId
                    };
                    if (sessionRef && canWorkerRevokeSession(sessionDoc, codeDoc, data.redemptionLockId, data.fenceToken, conflictWorkerOpts)) {
                        transaction.update(sessionRef, {
                            status: 'revoked',
                            revocationReason: 'concurrent_redemption_conflict',
                            revokedAt: new Date(opTime)
                        });
                    }
                    if (familyRef && canWorkerRevokeFamily(familyDoc, codeDoc, data.redemptionLockId, data.fenceToken, conflictWorkerOpts)) {
                        transaction.update(familyRef, {
                            status: 'revoked',
                            revocationReason: 'concurrent_redemption_conflict',
                            revokedAt: new Date(opTime)
                        });
                    }

                    const sessionMissing = data.issuedSessionId && (!sessionDoc || !sessionDoc.exists);
                    const familyMissing = data.issuedFamilyId && (!familyDoc || !familyDoc.exists);
                    if (sessionMissing || familyMissing) {
                        const integrityEventId = `sec_integrity_${codeHash.slice(0, 16)}_${attemptSeq}_${opTime}`;
                        transaction.set(this.db.collection('security_outbox').doc(integrityEventId), {
                            eventId: integrityEventId,
                            tenantId: data.tenantId,
                            uid: data.uid,
                            eventType: 'CRITICAL_SECURITY_RECORD_MISSING',
                            severity: 'CRITICAL',
                            details: {
                                ceremonyId: data.ceremonyId,
                                sessionMissing,
                                familyMissing,
                                expectedSessionId: data.issuedSessionId,
                                expectedFamilyId: data.issuedFamilyId
                            },
                            status: 'pending',
                            retryCount: 0,
                            nextRetryAt: new Date(opTime),
                            createdAt: new Date(opTime)
                        });
                    }

                    transaction.set(this.db.collection('security_outbox').doc(eventId), {
                        eventId,
                        tenantId: data.tenantId,
                        uid: data.uid,
                        eventType: 'CONCURRENT_REDEMPTION_CONFLICT',
                        severity: 'CRITICAL',
                        details: {
                            ceremonyId: data.ceremonyId,
                            clientId: data.clientId,
                            codeHashPrefix: codeHash.slice(0, 16) + '...',
                            compromisedSessionId: data.issuedSessionId,
                            compromisedFamilyId: data.issuedFamilyId
                        },
                        status: 'pending',
                        retryCount: 0,
                        nextRetryAt: new Date(opTime),
                        createdAt: new Date(opTime)
                    });

                    return { status: 'REPLAY_DETECTED', errorDescription: 'Concurrent redemption conflict.' };
                } else {
                    // Lock has EXPIRED! Explicit policy:
                    // 1. Different idempotency key -> Conflict/Replay Defense!
                    if (data.idempotencyKey !== idempotencyKey) {
                        const attemptSeq = (data.replayAttemptCount || 0) + 1;
                        const eventId = `sec_expired_conflict_${codeHash.slice(0, 16)}_${attemptSeq}_${opTime}`;

                        transaction.update(codeRef, {
                            status: 'COMPROMISED',
                            replayAttemptCount: attemptSeq,
                            lastReplayAt: new Date(opTime)
                        });

                        // Clean up old pending records belonging to the expired worker
                        const oldWorkerOptions = {
                            targetSessionId: data.issuedSessionId,
                            targetFamilyId: data.issuedFamilyId
                        };
                        const canRevokeOldSession = canWorkerRevokeSession(
                            sessionDoc,
                            codeDoc,
                            data.redemptionLockId,
                            data.fenceToken,
                            oldWorkerOptions
                        );
                        const canRevokeOldFamily = canWorkerRevokeFamily(
                            familyDoc,
                            codeDoc,
                            data.redemptionLockId,
                            data.fenceToken,
                            oldWorkerOptions
                        );

                        if (canRevokeOldSession) {
                            transaction.update(sessionRef, {
                                status: 'revoked',
                                revocationReason: 'expired_lock_conflict_compromise',
                                revokedAt: new Date(opTime)
                            });
                        }
                        if (canRevokeOldFamily) {
                            transaction.update(familyRef, {
                                status: 'revoked',
                                revocationReason: 'expired_lock_conflict_compromise',
                                revokedAt: new Date(opTime)
                            });
                        }

                        transaction.set(this.db.collection('security_outbox').doc(eventId), {
                            eventId,
                            tenantId: data.tenantId,
                            uid: data.uid,
                            eventType: 'CONCURRENT_REDEMPTION_CONFLICT',
                            severity: 'CRITICAL',
                            details: {
                                reason: 'expired_lock_different_idempotency_key',
                                ceremonyId: data.ceremonyId,
                                clientId: data.clientId,
                                codeHashPrefix: codeHash.slice(0, 16) + '...'
                            },
                            status: 'pending',
                            retryCount: 0,
                            nextRetryAt: new Date(opTime),
                            createdAt: new Date(opTime)
                        });

                        return { status: 'REPLAY_DETECTED', errorDescription: 'Concurrent redemption conflict on expired lock.' };
                    }

                    // 2. Same idempotency key -> Safe Takeover / Recovery!
                    // Clean up old pending session & family from crashed/stalled worker
                    // Validates record ownership and fencing generation before revocation!
                    const oldWorkerOptions = {
                        targetSessionId: data.issuedSessionId,
                        targetFamilyId: data.issuedFamilyId
                    };
                    const canRevokeOldSession = canWorkerRevokeSession(
                        sessionDoc,
                        codeDoc,
                        data.redemptionLockId,
                        data.fenceToken,
                        oldWorkerOptions
                    );
                    const canRevokeOldFamily = canWorkerRevokeFamily(
                        familyDoc,
                        codeDoc,
                        data.redemptionLockId,
                        data.fenceToken,
                        oldWorkerOptions
                    );

                    if (canRevokeOldSession) {
                        transaction.update(sessionRef, {
                            status: 'revoked',
                            revocationReason: 'expired_lease_takeover_cleanup',
                            revokedAt: new Date(opTime)
                        });
                    }
                    if (canRevokeOldFamily) {
                        transaction.update(familyRef, {
                            status: 'revoked',
                            revocationReason: 'expired_lease_takeover_cleanup',
                            revokedAt: new Date(opTime)
                        });
                    }

                    // Advance fence token and issue new lease lock
                    const nextFence = (data.fenceToken || 0) + 1;
                    const newLockId = crypto.randomBytes(16).toString('hex');
                    const takeoverSeq = (data.takeoverCount || 0) + 1;

                    transaction.update(codeRef, {
                        status: 'REDEEMING',
                        redemptionLockId: newLockId,
                        redemptionLockExpiresAt: new Date(opTime + 15000), // 15s lease
                        fenceToken: nextFence,
                        takeoverCount: takeoverSeq,
                        lastTakeoverAt: new Date(opTime),
                        issuedSessionId: null,
                        issuedFamilyId: null,
                        redeemedAt: new Date(opTime)
                    });

                    const takeoverEventId = `sec_takeover_${codeHash.slice(0, 16)}_${takeoverSeq}_${opTime}`;
                    transaction.set(this.db.collection('security_outbox').doc(takeoverEventId), {
                        eventId: takeoverEventId,
                        tenantId: data.tenantId,
                        uid: data.uid,
                        eventType: 'REDEMPTION_LOCK_TAKEOVER_RECOVERY',
                        severity: 'INFO',
                        details: {
                            ceremonyId: data.ceremonyId,
                            codeHashPrefix: codeHash.slice(0, 16) + '...',
                            newFenceToken: nextFence,
                            newLockId
                        },
                        status: 'pending',
                        retryCount: 0,
                        nextRetryAt: new Date(opTime),
                        createdAt: new Date(opTime)
                    });

                    return {
                        status: 'SUCCESS',
                        codeHash,
                        redemptionLockId: newLockId,
                        fenceToken: nextFence,
                        record: {
                            ceremonyId: data.ceremonyId,
                            uid: data.uid,
                            clientId: data.clientId,
                            tenantId: data.tenantId,
                            redirectUri: data.redirectUri,
                            authSessionId: data.authSessionId,
                            scope: data.scope,
                            nonce: data.nonce,
                            mfaVerified: data.mfaVerified
                        }
                    };
                }
            }

            // --- BRANCH D: EXPIRATION CHECK (STRICT FAIL-CLOSED) ---
            if (data.status === 'EXPIRED') {
                return { status: 'EXPIRED', errorDescription: 'Authorization code has expired.' };
            }
            if (data.status !== 'ISSUED') {
                return { status: 'INVALID_REQUEST', errorDescription: `Invalid authorization code status: ${data.status}` };
            }

            const expiresMs = toEpochMs(data.expiresAt);
            if (!Number.isFinite(expiresMs) || expiresMs <= 0) {
                transaction.update(codeRef, {
                    status: 'EXPIRED',
                    failureReason: 'invalid_code_expiration',
                    expiredAt: new Date(opTime)
                });
                return { status: 'EXPIRED', errorDescription: 'Authorization code has invalid or missing expiration.' };
            }
            if (opTime > expiresMs) {
                transaction.update(codeRef, {
                    status: 'EXPIRED',
                    failureReason: 'code_expired',
                    expiredAt: new Date(opTime)
                });
                return { status: 'EXPIRED', errorDescription: 'Authorization code has expired.' };
            }

            // --- BRANCH E: INITIAL CLAIM (ISSUED -> REDEEMING) ---
            const lockId = crypto.randomBytes(16).toString('hex');
            const nextFence = (data.fenceToken || 0) + 1;

            transaction.update(codeRef, {
                status: 'REDEEMING',
                redemptionLockId: lockId,
                redemptionLockExpiresAt: new Date(opTime + 15000), // 15-second lease
                fenceToken: nextFence,
                idempotencyKey,
                redeemedAt: new Date(opTime)
            });

            return {
                status: 'SUCCESS',
                codeHash,
                redemptionLockId: lockId,
                fenceToken: nextFence,
                record: {
                    ceremonyId: data.ceremonyId,
                    uid: data.uid,
                    clientId: data.clientId,
                    tenantId: data.tenantId,
                    redirectUri: data.redirectUri,
                    authSessionId: data.authSessionId,
                    scope: data.scope,
                    nonce: data.nonce,
                    mfaVerified: data.mfaVerified
                }
            };
        });
    }

    /**
     * Atomically registers staged session and token-family document IDs onto the authorization code.
     * Enforces three-document transactional validation, strict fail-closed lease checks,
     * and fencing invariants to prevent stale workers from overwriting newer records.
     *
     * Invariants enforced:
     * 1. Authorization code must exist and be in REDEEMING status.
     * 2. Redemption lease lock must be positive, finite, and unexpired.
     * 3. Worker's redemptionLockId and fenceToken must match authorization code exactly.
     * 4. Ceremony ID, UID, tenantId, and clientId must match authorization code.
     * 5. Staged session document must exist, be 'pending_activation', and match fencing + ownership.
     * 6. Staged token-family document must exist, be 'pending_activation', and match fencing + ownership.
     * 7. Cross-document circular pointers must match (session.familyId and family.sessionId).
     * 8. Cannot overwrite an existing differing registration (pointer conflict defense).
     */
    async registerStagedRecords({
        codeHash,
        redemptionLockId,
        fenceToken,
        uid,
        tenantId,
        clientId,
        ceremonyId,
        issuedSessionId,
        issuedFamilyId
    }) {
        if (!codeHash || !redemptionLockId || !fenceToken || !issuedSessionId || !issuedFamilyId) {
            return { success: false, reason: 'INVALID_PARAMETERS' };
        }

        const codeRef = this.collection.doc(codeHash);
        const sessionRef = this.db.collection('users').doc(uid).collection('sessions').doc(issuedSessionId);
        const familyRef = this.db.collection('tenants').doc(tenantId || 'lanzar').collection('token_families').doc(issuedFamilyId);

        return await this.db.runTransaction(async (transaction) => {
            const opTime = Date.now();
            // --- 1. ALL TRANSACTION READS PRECEDING ALL WRITES ---
            const [codeDoc, sessionDoc, familyDoc] = await Promise.all([
                transaction.get(codeRef),
                transaction.get(sessionRef),
                transaction.get(familyRef)
            ]);

            if (!codeDoc.exists) return { success: false, reason: 'CODE_NOT_FOUND' };
            if (!sessionDoc.exists) return { success: false, reason: 'STAGED_SESSION_NOT_FOUND' };
            if (!familyDoc.exists) return { success: false, reason: 'STAGED_FAMILY_NOT_FOUND' };

            const codeData = codeDoc.data();
            const sessionData = sessionDoc.data();
            const familyData = familyDoc.data();

            // 2. Status must be REDEEMING (reject COMPROMISED, COMPLETED, or ISSUED)
            if (codeData.status !== 'REDEEMING') {
                return { success: false, reason: `INVALID_CODE_STATUS_${codeData.status}` };
            }

            // 3. Lease lock validation (FAIL-CLOSED: must be positive, finite, and unexpired)
            const lockExpiresMs = toEpochMs(codeData.redemptionLockExpiresAt);
            if (!Number.isFinite(lockExpiresMs) || lockExpiresMs <= 0) {
                transaction.update(codeRef, {
                    status: 'COMPROMISED',
                    failureReason: 'invalid_lock_expiration',
                    lastReplayAt: new Date(opTime)
                });
                if (sessionDoc.exists && sessionData.redemptionLockId === redemptionLockId && sessionData.fenceToken === fenceToken && sessionData.status === 'pending_activation') {
                    transaction.update(sessionRef, { status: 'revoked', revocationReason: 'invalid_lock_expiration', revokedAt: new Date(opTime) });
                }
                if (familyDoc.exists && familyData.redemptionLockId === redemptionLockId && familyData.fenceToken === fenceToken && familyData.status === 'pending_activation') {
                    transaction.update(familyRef, { status: 'revoked', revocationReason: 'invalid_lock_expiration', revokedAt: new Date(opTime) });
                }
                return { success: false, reason: 'INVALID_LOCK_EXPIRATION' };
            }
            if (opTime > lockExpiresMs) {
                transaction.update(codeRef, {
                    status: 'COMPROMISED',
                    failureReason: 'lock_expired',
                    lastReplayAt: new Date(opTime)
                });
                if (sessionDoc.exists && sessionData.redemptionLockId === redemptionLockId && sessionData.fenceToken === fenceToken && sessionData.status === 'pending_activation') {
                    transaction.update(sessionRef, { status: 'revoked', revocationReason: 'redemption_lock_expired', revokedAt: new Date(opTime) });
                }
                if (familyDoc.exists && familyData.redemptionLockId === redemptionLockId && familyData.fenceToken === fenceToken && familyData.status === 'pending_activation') {
                    transaction.update(familyRef, { status: 'revoked', revocationReason: 'redemption_lock_expired', revokedAt: new Date(opTime) });
                }
                return { success: false, reason: 'LOCK_EXPIRED' };
            }

            // 4. Fencing validation: Lock ID and Fence Token must strictly match THIS worker
            if (codeData.redemptionLockId !== redemptionLockId || codeData.fenceToken !== fenceToken) {
                return { success: false, reason: 'STALE_WORKER_FENCED' };
            }

            // 5. Code metadata ownership validation
            const expectedTenant = tenantId || 'lanzar';
            if (codeData.ceremonyId !== ceremonyId ||
                codeData.uid !== uid ||
                (codeData.tenantId || 'lanzar') !== expectedTenant ||
                codeData.clientId !== clientId) {
                return { success: false, reason: 'METADATA_MISMATCH' };
            }

            // 6. Staged records status: Both must be 'pending_activation'
            if (sessionData.status !== 'pending_activation' || familyData.status !== 'pending_activation') {
                return { success: false, reason: 'STAGED_RECORD_NOT_PENDING' };
            }

            // 7. Staged records fencing tokens: Both must carry current worker's lock ID and fenceToken
            if (sessionData.redemptionLockId !== redemptionLockId || sessionData.fenceToken !== fenceToken ||
                familyData.redemptionLockId !== redemptionLockId || familyData.fenceToken !== fenceToken) {
                return { success: false, reason: 'STAGED_RECORD_FENCING_MISMATCH' };
            }

            // 8. Staged records ownership validation (UID, tenantId, clientId, ceremonyId)
            if (sessionData.uid !== uid || familyData.uid !== uid ||
                sessionData.clientId !== clientId || familyData.clientId !== clientId ||
                sessionData.ceremonyId !== ceremonyId || familyData.ceremonyId !== ceremonyId ||
                sessionData.tenantId !== expectedTenant || familyData.tenantId !== expectedTenant) {
                return { success: false, reason: 'STAGED_RECORD_OWNERSHIP_MISMATCH' };
            }

            // 9. Document identity & circular pointer integrity
            if (sessionData.sessionId !== issuedSessionId || familyData.familyId !== issuedFamilyId ||
                sessionData.familyId !== issuedFamilyId || familyData.sessionId !== issuedSessionId) {
                return { success: false, reason: 'STAGED_RECORD_POINTER_MISMATCH' };
            }

            // 10. Pointer conflict protection: Cannot overwrite if already assigned to differing IDs
            if (codeData.issuedSessionId && codeData.issuedSessionId !== issuedSessionId) {
                return { success: false, reason: 'SESSION_POINTER_CONFLICT' };
            }
            if (codeData.issuedFamilyId && codeData.issuedFamilyId !== issuedFamilyId) {
                return { success: false, reason: 'FAMILY_POINTER_CONFLICT' };
            }

            // --- ALL WRITES COMMENCE ---
            transaction.update(codeRef, {
                issuedSessionId,
                issuedFamilyId,
                stagedAt: new Date(opTime)
            });

            return { success: true };
        });
    }

    /**
     * Phase 2: Finalizes redemption via atomic three-document transaction.
     * Enforces complete relationship validation across all three documents and
     * guarantees stale-worker revocation safety.
     */
    async finalizeRedemption({
        codeHash,
        redemptionLockId,
        fenceToken,
        uid,
        tenantId,
        issuedSessionId,
        issuedFamilyId,
        rawTokensPayload
    }) {
        const codeRef = this.collection.doc(codeHash);
        const sessionRef = this.db.collection('users').doc(uid).collection('sessions').doc(issuedSessionId);
        const familyRef = this.db.collection('tenants').doc(tenantId).collection('token_families').doc(issuedFamilyId);

        return await this.db.runTransaction(async (transaction) => {
            const opTime = Date.now();
            // --- ALL READS MUST PRECEDE ALL WRITES ---
            const [codeDoc, sessionDoc, familyDoc] = await Promise.all([
                transaction.get(codeRef),
                transaction.get(sessionRef),
                transaction.get(familyRef)
            ]);

            // Handle missing records
            if (!codeDoc.exists || !sessionDoc.exists || !familyDoc.exists) {
                if (canWorkerRevokeSession(sessionDoc, codeDoc, redemptionLockId, fenceToken)) {
                    transaction.update(sessionRef, { status: 'revoked', revocationReason: 'missing_security_record', revokedAt: new Date(opTime) });
                }
                if (canWorkerRevokeFamily(familyDoc, codeDoc, redemptionLockId, fenceToken)) {
                    transaction.update(familyRef, { status: 'revoked', revocationReason: 'missing_security_record', revokedAt: new Date(opTime) });
                }
                if (codeDoc.exists && codeDoc.data().status === 'REDEEMING' && codeDoc.data().redemptionLockId === redemptionLockId) {
                    transaction.update(codeRef, { status: 'COMPROMISED', lastReplayAt: new Date(opTime) });
                }

                const missingEventId = `sec_missing_${codeHash.slice(0, 16)}_${opTime}`;
                transaction.set(this.db.collection('security_outbox').doc(missingEventId), {
                    eventId: missingEventId,
                    tenantId: tenantId || 'unknown',
                    uid: uid || 'unknown',
                    eventType: 'CRITICAL_SECURITY_RECORD_MISSING',
                    severity: 'CRITICAL',
                    details: {
                        codeMissing: !codeDoc.exists,
                        sessionMissing: !sessionDoc.exists,
                        familyMissing: !familyDoc.exists,
                        issuedSessionId,
                        issuedFamilyId
                    },
                    status: 'pending',
                    retryCount: 0,
                    nextRetryAt: new Date(opTime),
                    createdAt: new Date(opTime)
                });

                if (!codeDoc.exists) return { success: false, reason: 'CODE_NOT_FOUND' };
                if (!sessionDoc.exists) return { success: false, reason: 'SESSION_NOT_FOUND' };
                return { success: false, reason: 'FAMILY_NOT_FOUND' };
            }

            const codeData = codeDoc.data();
            const sessionData = sessionDoc.data();
            const familyData = familyDoc.data();

            const workerOptions = { targetSessionId: issuedSessionId, targetFamilyId: issuedFamilyId };

            // 1. REPLAY DETECTION DURING MINTING
            if (codeData.status === 'COMPROMISED') {
                if (canWorkerRevokeSession(sessionDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
                    transaction.update(sessionRef, {
                        status: 'revoked',
                        revocationReason: 'compromised_during_minting',
                        revokedAt: new Date(opTime)
                    });
                }
                if (canWorkerRevokeFamily(familyDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
                    transaction.update(familyRef, {
                        status: 'revoked',
                        revocationReason: 'compromised_during_minting',
                        revokedAt: new Date(opTime)
                    });
                }
                return { success: false, reason: 'COMPROMISED_DURING_ISSUANCE' };
            }

            // 2. STALE WORKER FENCING SAFETY (Requirement 1 & 2)
            // A stale worker MUST NEVER revoke resources belonging to a newer worker or active resources.
            if (codeData.status !== 'REDEEMING' || codeData.redemptionLockId !== redemptionLockId || codeData.fenceToken !== fenceToken) {
                // Only clean up if this session strictly belongs to THIS stale worker's attempt and is still pending
                if (canWorkerRevokeSession(sessionDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
                    transaction.update(sessionRef, { status: 'revoked', revocationReason: 'stale_worker_fenced', revokedAt: new Date(opTime) });
                }
                if (canWorkerRevokeFamily(familyDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
                    transaction.update(familyRef, { status: 'revoked', revocationReason: 'stale_worker_fenced', revokedAt: new Date(opTime) });
                }

                const fenceEventId = `sec_fence_${codeHash.slice(0, 16)}_${opTime}`;
                transaction.set(this.db.collection('security_outbox').doc(fenceEventId), {
                    eventId: fenceEventId,
                    tenantId,
                    uid,
                    eventType: 'STALE_WORKER_FENCED',
                    severity: 'HIGH',
                    details: { codeHashPrefix: codeHash.slice(0, 16), expectedLock: redemptionLockId, actualLock: codeData.redemptionLockId },
                    status: 'pending',
                    retryCount: 0,
                    nextRetryAt: new Date(opTime),
                    createdAt: new Date(opTime)
                });
                return { success: false, reason: 'STALE_WORKER_FENCED' };
            }

            // 3. EXPIRED LOCK CLEANUP (Strict fail-closed: must be positive, finite, and unexpired)
            const lockExpiresMs = toEpochMs(codeData.redemptionLockExpiresAt);
            if (!Number.isFinite(lockExpiresMs) || lockExpiresMs <= 0 || opTime > lockExpiresMs) {
                transaction.update(codeRef, {
                    status: 'COMPROMISED',
                    failureReason: !Number.isFinite(lockExpiresMs) || lockExpiresMs <= 0 ? 'invalid_lock_expiration' : 'lock_expired',
                    lastReplayAt: new Date(opTime)
                });
                if (canWorkerRevokeSession(sessionDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
                    transaction.update(sessionRef, { status: 'revoked', revocationReason: 'redemption_lock_expired', revokedAt: new Date(opTime) });
                }
                if (canWorkerRevokeFamily(familyDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
                    transaction.update(familyRef, { status: 'revoked', revocationReason: 'redemption_lock_expired', revokedAt: new Date(opTime) });
                }

                const lockEventId = `sec_lock_exp_${codeHash.slice(0, 16)}_${opTime}`;
                transaction.set(this.db.collection('security_outbox').doc(lockEventId), {
                    eventId: lockEventId,
                    tenantId,
                    uid,
                    eventType: 'REDEMPTION_LOCK_EXPIRED',
                    severity: 'HIGH',
                    details: { codeHashPrefix: codeHash.slice(0, 16), issuedSessionId, issuedFamilyId },
                    status: 'pending',
                    retryCount: 0,
                    nextRetryAt: new Date(opTime),
                    createdAt: new Date(opTime)
                });
                return { success: false, reason: !Number.isFinite(lockExpiresMs) || lockExpiresMs <= 0 ? 'INVALID_LOCK_EXPIRATION' : 'LOCK_EXPIRED' };
            }

            // 4. COMPLETE THREE-DOCUMENT RELATIONSHIP VALIDATION (Requirement 3)
            const relationshipValid =
                // Status must be pending_activation
                sessionData.status === 'pending_activation' &&
                familyData.status === 'pending_activation' &&
                // Stored document IDs must match
                sessionData.sessionId === issuedSessionId &&
                familyData.familyId === issuedFamilyId &&
                // Cross-document pointers: session.familyId and family.sessionId
                sessionData.familyId === issuedFamilyId &&
                familyData.sessionId === issuedSessionId &&
                // Tenant ID must match across all 3 records (Mandatory session & family check)
                sessionData.tenantId === tenantId &&
                familyData.tenantId === tenantId &&
                codeData.tenantId === tenantId &&
                sessionData.tenantId === codeData.tenantId &&
                familyData.tenantId === codeData.tenantId &&
                // UID must match across all 3 records
                sessionData.uid === uid &&
                familyData.uid === uid &&
                codeData.uid === uid &&
                // Client ID must match across all 3 records
                sessionData.clientId === codeData.clientId &&
                familyData.clientId === codeData.clientId &&
                // Ceremony ID must match across all 3 records
                sessionData.ceremonyId === codeData.ceremonyId &&
                familyData.ceremonyId === codeData.ceremonyId &&
                // Fencing credentials stored on session and family must match lockId and fenceToken
                sessionData.redemptionLockId === redemptionLockId &&
                sessionData.fenceToken === fenceToken &&
                familyData.redemptionLockId === redemptionLockId &&
                familyData.fenceToken === fenceToken &&
                // Mandatory authorization code registered session and family pointers
                codeData.issuedSessionId === issuedSessionId &&
                codeData.issuedFamilyId === issuedFamilyId;

            if (!relationshipValid) {
                if (codeData.status === 'REDEEMING' && codeData.redemptionLockId === redemptionLockId) {
                    transaction.update(codeRef, { status: 'COMPROMISED', failureReason: 'relationship_mismatch', lastReplayAt: new Date(opTime) });
                }
                if (canWorkerRevokeSession(sessionDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
                    transaction.update(sessionRef, { status: 'revoked', revocationReason: 'relationship_mismatch', revokedAt: new Date(opTime) });
                }
                if (canWorkerRevokeFamily(familyDoc, codeDoc, redemptionLockId, fenceToken, workerOptions)) {
                    transaction.update(familyRef, { status: 'revoked', revocationReason: 'relationship_mismatch', revokedAt: new Date(opTime) });
                }

                const mismatchEventId = `sec_mismatch_${codeHash.slice(0, 16)}_${opTime}`;
                transaction.set(this.db.collection('security_outbox').doc(mismatchEventId), {
                    eventId: mismatchEventId,
                    tenantId,
                    uid,
                    eventType: 'RECORD_RELATIONSHIP_MISMATCH',
                    severity: 'CRITICAL',
                    details: {
                        expectedUid: codeData.uid,
                        sessionUid: sessionData.uid,
                        familyUid: familyData.uid,
                        expectedTenant: codeData.tenantId,
                        sessionTenant: sessionData.tenantId,
                        familyTenant: familyData.tenantId,
                        expectedClient: codeData.clientId,
                        sessionClient: sessionData.clientId,
                        familyClient: familyData.clientId,
                        sessionFamilyId: sessionData.familyId,
                        familySessionId: familyData.sessionId
                    },
                    status: 'pending',
                    retryCount: 0,
                    nextRetryAt: new Date(opTime),
                    createdAt: new Date(opTime)
                });
                return { success: false, reason: 'RECORD_RELATIONSHIP_MISMATCH' };
            }

            // --- ALL WRITES COMMENCE (ATOMIC THREE-DOCUMENT COMPLETION & ACTIVATION) ---
            const aadContext = `${codeHash}:${codeData.clientId}:${codeData.tenantId}:${codeData.uid}:${codeData.ceremonyId}`;
            const encryptedReceipt = encryptTokenReceipt(rawTokensPayload, aadContext);

            transaction.update(codeRef, {
                status: 'COMPLETED',
                issuedSessionId,
                issuedFamilyId,
                issuedTokenReceipt: encryptedReceipt,
                completedLockId: redemptionLockId,
                redemptionLockId: null,
                redemptionLockExpiresAt: null,
                completedAt: new Date(opTime),
                used: true // Backward compatibility
            });

            transaction.update(sessionRef, {
                status: 'active',
                activatedAt: new Date(opTime)
            });

            transaction.update(familyRef, {
                status: 'active',
                activatedAt: new Date(opTime)
            });

            return { success: true };
        });
    }

    /**
     * Failure cleanup handler with strict ownership and fencing protections (Requirement 4).
     * A late exception from an old worker MUST NOT revoke resources belonging to a newer worker.
     */
    async handleRedemptionFailure({
        codeHash,
        redemptionLockId,
        fenceToken,
        uid,
        tenantId,
        sessionId,
        familyId,
        errorReason
    }) {
        const codeRef = this.collection.doc(codeHash);
        const sessionRef = sessionId ? this.db.collection('users').doc(uid).collection('sessions').doc(sessionId) : null;
        const familyRef = familyId ? this.db.collection('tenants').doc(tenantId).collection('token_families').doc(familyId) : null;

        return await this.db.runTransaction(async (transaction) => {
            const opTime = Date.now();
            // --- 1. ALL READS PRECEDE ALL WRITES ---
            const codeDoc = await transaction.get(codeRef);
            const sessionDoc = sessionRef ? await transaction.get(sessionRef) : null;
            const familyDoc = familyRef ? await transaction.get(familyRef) : null;

            // Check if this worker still holds the valid code lock
            const isCurrentCodeWorker = codeDoc.exists &&
                codeDoc.data().status === 'REDEEMING' &&
                codeDoc.data().redemptionLockId === redemptionLockId &&
                codeDoc.data().fenceToken === fenceToken;

            // Fencing check for session & family: ONLY revoke if it belongs to THIS worker's attempt and is still pending
            const workerOptions = { targetSessionId: sessionId, targetFamilyId: familyId };
            const canRevokeSession = canWorkerRevokeSession(sessionDoc, codeDoc, redemptionLockId, fenceToken, workerOptions);
            const canRevokeFamily = canWorkerRevokeFamily(familyDoc, codeDoc, redemptionLockId, fenceToken, workerOptions);

            // If worker is completely stale and holds none of the current records
            if (!isCurrentCodeWorker && !canRevokeSession && !canRevokeFamily) {
                const staleEventId = `sec_stale_fail_${codeHash.slice(0, 16)}_${opTime}`;
                transaction.set(this.db.collection('security_outbox').doc(staleEventId), {
                    eventId: staleEventId,
                    tenantId: tenantId || 'unknown',
                    uid: uid || 'unknown',
                    eventType: 'STALE_WORKER_FAILURE_FENCED',
                    severity: 'WARN',
                    details: {
                        codeHashPrefix: codeHash.slice(0, 16),
                        staleLockId: redemptionLockId,
                        staleFenceToken: fenceToken,
                        attemptedSessionId: sessionId,
                        attemptedFamilyId: familyId
                    },
                    status: 'pending',
                    retryCount: 0,
                    nextRetryAt: new Date(opTime),
                    createdAt: new Date(opTime)
                });
                return { success: false, reason: 'STALE_WORKER_FENCED' };
            }

            // --- 2. WRITES COMMENCE ---
            if (canRevokeSession) {
                transaction.update(sessionRef, {
                    status: 'revoked',
                    revocationReason: errorReason || 'redemption_minting_failure',
                    revokedAt: new Date(opTime)
                });
            }

            if (canRevokeFamily) {
                transaction.update(familyRef, {
                    status: 'revoked',
                    revocationReason: errorReason || 'redemption_minting_failure',
                    revokedAt: new Date(opTime)
                });
            }

            if (isCurrentCodeWorker) {
                transaction.update(codeRef, {
                    status: 'COMPROMISED',
                    failureReason: errorReason || 'minting_or_encryption_failure',
                    lastReplayAt: new Date(opTime)
                });
            }

            const failureEventId = `sec_fail_${codeHash.slice(0, 16)}_${opTime}`;
            transaction.set(this.db.collection('security_outbox').doc(failureEventId), {
                eventId: failureEventId,
                tenantId: tenantId || 'unknown',
                uid: uid || 'unknown',
                eventType: 'REDEMPTION_PROCESSING_FAILURE',
                severity: 'HIGH',
                details: {
                    codeHashPrefix: codeHash.slice(0, 16),
                    errorReason,
                    sessionId,
                    familyId
                },
                status: 'pending',
                retryCount: 0,
                nextRetryAt: new Date(opTime),
                createdAt: new Date(opTime)
            });

            return { success: true };
        });
    }

    /**
     * Retrieves the authorization code record by hashing the incoming code.
     * Maintained for backward compatibility.
     */
    async getCode(code) {
        if (!code || typeof code !== 'string') return null;
        const codeHash = hashAuthorizationCode(code);
        try {
            const snap = await this.collection.doc(codeHash).get();
            if (!snap.exists) return null;
            const data = snap.data();
            const expMs = toEpochMs(data.expiresAt);
            return {
                ...data,
                used: data.status === 'COMPLETED' || data.status === 'COMPROMISED' || data.status === 'EXPIRED',
                expiresAt: expMs
            };
        } catch (_) {
            return null;
        }
    }

    /**
     * Atomically marks an authorization code as used via Firestore transaction.
     * Maintained for backward compatibility.
     */
    async markUsed(code) {
        if (!code || typeof code !== 'string') return false;
        const codeHash = hashAuthorizationCode(code);
        const docRef = this.collection.doc(codeHash);
        try {
            return await this.db.runTransaction(async (transaction) => {
                const snap = await transaction.get(docRef);
                if (!snap.exists) return false;
                const data = snap.data();
                if (data.status === 'COMPLETED' || data.status === 'COMPROMISED' || data.status === 'EXPIRED') return false;
                const expMs = toEpochMs(data.expiresAt);
                if (expMs > 0 && Date.now() > expMs) return false;

                transaction.update(docRef, {
                    status: 'COMPLETED',
                    used: true,
                    consumedAt: Date.now()
                });
                return true;
            });
        } catch (err) {
            return false;
        }
    }

    /**
     * Atomically authenticates and rotates a refresh token inside a Firestore transaction:
     * 1. Parses the presented refresh token and verifies its bound familyId matches the request.
     * 2. Reads token_families/{familyId}, users/{uid}/sessions/{sessionId}, and compromised_ceremonies/{ceremonyId}.
     * 3. Validates active status, ownership/cross-references, ceremony metadata, and finite future expiration.
     * 4. Compares SHA-256(refreshToken) in constant time against currentActiveTokenHash and sequenceNumber.
     * 5. On replay of a previously rotated token, atomically revokes both family and session, writes the
     *    compromised_ceremonies tombstone, and stages a CRITICAL outbox alert.
     * 6. On valid active token, atomically rotates currentActiveTokenHash, sequenceNumber, and rotatedTokenHashes
     *    in the same transaction before returning the new access token and rotated refresh token.
     */
    async authorizeRefreshGrant({ tenantId, familyId, uid, sessionId, refreshToken }) {
        if (
            typeof tenantId !== 'string' || !tenantId ||
            typeof familyId !== 'string' || !familyId ||
            typeof uid !== 'string' || !uid ||
            typeof sessionId !== 'string' || !sessionId ||
            typeof refreshToken !== 'string' || !refreshToken
        ) {
            return { allowed: false, reason: 'INVALID_REQUEST' };
        }

        const parsedToken = parseRefreshToken(refreshToken);
        if (!parsedToken) {
            return { allowed: false, reason: 'INVALID_REFRESH_TOKEN' };
        }
        if (parsedToken.familyId !== familyId) {
            return { allowed: false, reason: 'TOKEN_FAMILY_MISMATCH' };
        }

        const presentedHash = hashAuthorizationCode(refreshToken);
        const familyRef = this.db.collection('tenants').doc(tenantId).collection('token_families').doc(familyId);
        const sessionRef = this.db.collection('users').doc(uid).collection('sessions').doc(sessionId);

        return await this.db.runTransaction(async (tx) => {
            const familyDoc = await tx.get(familyRef);
            const sessionDoc = await tx.get(sessionRef);

            if (!familyDoc.exists || !sessionDoc.exists) {
                return { allowed: false, reason: 'RECORD_NOT_FOUND' };
            }

            const familyData = familyDoc.data();
            const sessionData = sessionDoc.data();

            if (familyData.status !== 'active') {
                return { allowed: false, reason: 'FAMILY_REVOKED' };
            }
            if (sessionData.status !== 'active' || sessionData.revoked === true) {
                return { allowed: false, reason: 'SESSION_REVOKED' };
            }
            if (
                familyData.uid !== uid ||
                sessionData.uid !== uid ||
                familyData.tenantId !== tenantId ||
                sessionData.tenantId !== tenantId ||
                familyData.sessionId !== sessionId ||
                sessionData.familyId !== familyId
            ) {
                return { allowed: false, reason: 'RELATIONSHIP_MISMATCH' };
            }
            if (
                typeof familyData.ceremonyId !== 'string' ||
                !familyData.ceremonyId ||
                familyData.ceremonyId !== sessionData.ceremonyId
            ) {
                return { allowed: false, reason: 'CEREMONY_METADATA_INVALID' };
            }

            const compromisedRef = this.db.collection('compromised_ceremonies').doc(familyData.ceremonyId);
            const compromisedSnap = await tx.get(compromisedRef);
            if (compromisedSnap.exists) {
                return { allowed: false, reason: 'CEREMONY_COMPROMISED' };
            }

            const nowMs = Date.now();
            const familyExpiresMs = toEpochMs(familyData.expiresAt);
            if (!Number.isFinite(familyExpiresMs) || familyExpiresMs <= 0 || nowMs > familyExpiresMs) {
                return { allowed: false, reason: 'REFRESH_TOKEN_EXPIRED' };
            }
            if (sessionData.expiresAt !== undefined && sessionData.expiresAt !== null) {
                const sessionExpiresMs = toEpochMs(sessionData.expiresAt);
                if (!Number.isFinite(sessionExpiresMs) || sessionExpiresMs <= 0 || nowMs > sessionExpiresMs) {
                    return { allowed: false, reason: 'SESSION_EXPIRED' };
                }
            }

            const currentHash = familyData.currentActiveTokenHash;
            const currentSeq = familyData.sequenceNumber;
            if (typeof currentHash !== 'string' || !Number.isInteger(currentSeq) || currentSeq < 1) {
                return { allowed: false, reason: 'FAMILY_TOKEN_STATE_INVALID' };
            }

            const isActiveMatch =
                timingSafeEqualHex(presentedHash, currentHash) &&
                parsedToken.sequenceNumber === currentSeq;

            if (!isActiveMatch) {
                const rotatedHashes = Array.isArray(familyData.rotatedTokenHashes) ? familyData.rotatedTokenHashes : [];
                const isRotatedReplay = rotatedHashes.some((h) => timingSafeEqualHex(presentedHash, h));
                if (isRotatedReplay) {
                    const nowIso = new Date(nowMs).toISOString();
                    tx.update(familyRef, {
                        status: 'revoked',
                        revoked: true,
                        revocationReason: 'refresh_token_reuse_detected',
                        revokedAt: nowIso,
                        updatedAt: nowIso
                    });
                    tx.update(sessionRef, {
                        status: 'revoked',
                        revoked: true,
                        revocationReason: 'refresh_token_reuse_detected',
                        revokedAt: nowIso,
                        updatedAt: nowIso
                    });
                    tx.set(compromisedRef, {
                        ceremonyId: familyData.ceremonyId,
                        tenantId,
                        uid,
                        clientId: familyData.clientId || null,
                        familyId,
                        sessionId,
                        reason: 'refresh_token_reuse_detected',
                        detectedAt: nowIso
                    }, { merge: true });
                    const outboxId = `sec_rt_replay_${familyId}_${nowMs}_${crypto.randomBytes(4).toString('hex')}`;
                    tx.set(this.db.collection('security_outbox').doc(outboxId), {
                        eventId: outboxId,
                        tenantId,
                        uid,
                        eventType: 'REFRESH_TOKEN_REPLAY_DETECTED',
                        severity: 'CRITICAL',
                        status: 'pending',
                        retryCount: 0,
                        nextRetryAt: nowIso,
                        createdAt: nowIso,
                        details: {
                            ceremonyId: familyData.ceremonyId,
                            familyId,
                            sessionId,
                            presentedSequence: parsedToken.sequenceNumber,
                            currentSequence: currentSeq
                        }
                    });
                    return { allowed: false, reason: 'REFRESH_TOKEN_REPLAY', replayDetected: true };
                }
                return { allowed: false, reason: 'INVALID_REFRESH_TOKEN' };
            }

            // Atomic rotation: advance sequenceNumber and currentActiveTokenHash in the same transaction
            const nextSequence = currentSeq + 1;
            const nextRefreshToken = generateRefreshToken(familyId, nextSequence);
            const nextRefreshTokenHash = hashAuthorizationCode(nextRefreshToken);
            const nowIso = new Date(nowMs).toISOString();
            const prevRotated = Array.isArray(familyData.rotatedTokenHashes) ? familyData.rotatedTokenHashes : [];
            const updatedRotated = [...prevRotated, presentedHash].slice(-50);

            tx.update(familyRef, {
                currentActiveTokenHash: nextRefreshTokenHash,
                sequenceNumber: nextSequence,
                rotatedTokenHashes: updatedRotated,
                lastRotatedAt: nowIso,
                updatedAt: nowIso
            });
            tx.update(sessionRef, {
                lastSeenAt: nowIso
            });

            return {
                allowed: true,
                accessToken: 'lanzar_at_' + crypto.randomBytes(16).toString('hex'),
                refreshToken: nextRefreshToken,
                familyId,
                sessionId,
                ceremonyId: familyData.ceremonyId,
                sequenceNumber: nextSequence
            };
        });
    }
}

module.exports = {
    AuthorizationCodeStore,
    FirestoreAuthorizationCodeStore,
    hashAuthorizationCode,
    generateRefreshToken,
    parseRefreshToken,
    encryptTokenReceipt,
    decryptTokenReceipt,
    resolveReceiptKey,
    validateReceiptKeyConfiguration,
    parseAndValidateReceiptKey,
    parseActiveReceiptKeyVersion,
    getActiveReceiptKeyVersion,
    setReceiptKeyringForTesting,
    resetReceiptKeyringForTesting,
    canWorkerRevokeSession,
    canWorkerRevokeFamily,
    canReplayRevokeSession,
    canReplayRevokeFamily,
    canReplayRevokePair,
    canContainByCeremonyAndLock
};
