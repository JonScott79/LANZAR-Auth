// mfaService.js
// Standard RFC 6238 / RFC 4226 TOTP Engine, AES-256-GCM Encryption at Rest & Recovery Codes
// Universal compatibility with Google Authenticator, Microsoft Authenticator, 1Password, Bitwarden

const crypto = require('crypto');
const { resolveEnvironment } = require('./config/environments');

// Known development secrets that MUST NOT be used in live/staging environments (LID-SEC-005)
const KNOWN_DEV_MFA_SECRETS = [
    'lanzar_mfa_signing_key_secure_2026',
    'default_dev_secret',
    'dev_mfa_signing_key_secure_2026',
    'dev_only_local_mfa_signing_secret_for_offline_testing_32b'
];

// Explicit local development fallback secret (offline emulator testing only)
const DEV_ONLY_FALLBACK_MFA_SECRET = 'dev_only_local_mfa_signing_secret_for_offline_testing_32b';

function getMfaHmacSecret(env = process.env) {
    const effectiveEnv = resolveEnvironment(env);
    const secret = env.MFA_HMAC_SECRET;

    if (!effectiveEnv) {
        throw new Error(`[MFA CONFIG FATAL] Environment configuration missing or unrecognized: APP_ENV="${env.APP_ENV || ''}", NODE_ENV="${env.NODE_ENV || ''}". Development fallback secret is forbidden in unverified environments.`);
    }

    if (effectiveEnv === 'staging' || effectiveEnv === 'production') {
        if (!secret) {
            throw new Error(`[MFA CONFIG FATAL] MFA_HMAC_SECRET must be explicitly configured in APP_ENV=${effectiveEnv}`);
        }
        if (Buffer.byteLength(secret, 'utf8') < 32) {
            throw new Error(`[MFA CONFIG FATAL] MFA_HMAC_SECRET must be at least 32 bytes in APP_ENV=${effectiveEnv}`);
        }
        if (
            KNOWN_DEV_MFA_SECRETS.includes(secret) ||
            secret.toLowerCase().includes('dev') ||
            secret.toLowerCase().includes('default')
        ) {
            throw new Error(`[MFA CONFIG FATAL] Known development secret cannot be used for MFA_HMAC_SECRET in APP_ENV=${effectiveEnv}`);
        }
        return secret;
    }

    // development or test environment:
    if (secret) {
        if (Buffer.byteLength(secret, 'utf8') < 16) {
            throw new Error(`[MFA CONFIG FATAL] MFA_HMAC_SECRET must be at least 16 bytes in APP_ENV=${effectiveEnv}`);
        }
        return secret;
    }
    return DEV_ONLY_FALLBACK_MFA_SECRET;
}

const MFA_ENCRYPTION_KEY = process.env.MFA_ENCRYPTION_KEY || crypto.createHash('sha256').update('lanzar_totp_aes_pepper_2026').digest(); // 32 bytes

// Cache of consumed (uid + timeStep) to prevent replay of the same 6-digit code within its 30-second validity window
// Map<string, number> where key = `${uid}_${timeStep}`, value = expiry timestamp
const consumedStepCache = new Map();

// Pending unconfirmed enrollment cache: Map<uid, { secret: string, expiresAt: number }>
// Unconfirmed secrets expire in 10 minutes and are permanently discarded if not verified
const pendingEnrollmentCache = new Map();

function cleanExpiredCacheEntries() {
    const now = Date.now();
    for (const [key, exp] of consumedStepCache.entries()) {
        if (now > exp) consumedStepCache.delete(key);
    }
    for (const [uid, item] of pendingEnrollmentCache.entries()) {
        if (now > item.expiresAt) pendingEnrollmentCache.delete(uid);
    }
}
setInterval(cleanExpiredCacheEntries, 60000).unref(); // Clean every minute without holding event loop open

// ==========================================
// AES-256-GCM Encryption at Rest
// ==========================================
function encryptTotpSecret(plainBase32) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', MFA_ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(plainBase32, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const tag = cipher.getAuthTag();
    return {
        encryptedSecret: encrypted,
        iv: iv.toString('hex'),
        tag: tag.toString('hex'),
        kv: 1 // Key version
    };
}

function decryptTotpSecret(encryptedObj) {
    if (!encryptedObj) return null;
    // Backwards compatibility for unencrypted base32 secrets in legacy/dev
    if (typeof encryptedObj === 'string') {
        return encryptedObj;
    }
    const { encryptedSecret, iv, tag } = encryptedObj;
    if (!encryptedSecret || !iv || !tag) return null;

    const decipher = crypto.createDecipheriv('aes-256-gcm', MFA_ENCRYPTION_KEY, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    let decrypted = decipher.update(encryptedSecret, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// ==========================================
// Base32 RFC 3548 / RFC 4648 Encoding
// ==========================================
function base32Decode(base32) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    const clean = base32.replace(/[\s=-]/g, '').toUpperCase();
    for (let i = 0; i < clean.length; i++) {
        const val = alphabet.indexOf(clean.charAt(i));
        if (val === -1) continue;
        bits += val.toString(2).padStart(5, '0');
    }
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(parseInt(bits.substr(i, 8), 2));
    }
    return Buffer.from(bytes);
}

function base32Encode(buffer) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    for (let i = 0; i < buffer.length; i++) {
        bits += buffer[i].toString(2).padStart(8, '0');
    }
    let encoded = '';
    for (let i = 0; i + 5 <= bits.length; i += 5) {
        encoded += alphabet[parseInt(bits.substr(i, 5), 2)];
    }
    return encoded;
}

function generateBase32Secret(byteLength = 20) {
    return base32Encode(crypto.randomBytes(byteLength));
}

/**
 * Builds a standard Key URI (RFC / Google Authenticator / Authy compatible)
 * for an already-generated TOTP secret without mutating or regenerating it.
 */
function buildTotpProvisioningUri({
    secret,
    accountName,
    issuer = 'LANZAR ID',
    algorithm = 'SHA1',
    digits = 6,
    period = 30
}) {
    if (!secret || typeof secret !== 'string') {
        throw new Error('TOTP secret is required to build provisioning URI.');
    }
    if (!accountName || typeof accountName !== 'string') {
        throw new Error('Account identifier is required to build provisioning URI.');
    }
    const cleanSecret = secret.replace(/[\s=-]/g, '').toUpperCase();
    const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}`;
    const params = new URLSearchParams({
        secret: cleanSecret,
        issuer,
        algorithm,
        digits: String(digits),
        period: String(period)
    });
    // %20 is required instead of '+' for spaces in issuer across mobile authenticators
    return `otpauth://totp/${label}?${params.toString().replace(/\+/g, '%20')}`;
}

// ==========================================
// RFC 6238 TOTP Engine (Compatible with MS & Google Authenticator)
// ==========================================
function generateTOTP(secret, counter = Math.floor(Date.now() / 30000)) {
    const key = base32Decode(secret);
    const buf = Buffer.alloc(8);
    buf.writeBigInt64BE(BigInt(counter));
    const hmac = crypto.createHmac('sha1', key).update(buf).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % 1000000;
    return code.toString().padStart(6, '0');
}

/**
 * Verifies standard RFC 6238 TOTP with:
 * - Constant-time comparison
 * - Single-step clock drift window (+/- 1 step = +/- 30s)
 * - Step replay protection
 */
function verifyTOTP(secret, token, uid = null, window = 1) {
    if (!token || typeof token !== 'string') return false;
    const cleanToken = token.trim().replace(/\s+/g, '');
    if (cleanToken.length !== 6 || !/^\d{6}$/.test(cleanToken)) return false;

    const currentCounter = Math.floor(Date.now() / 30000);
    for (let w = -window; w <= window; w++) {
        const step = currentCounter + w;
        const candidate = generateTOTP(secret, step);
        if (crypto.timingSafeEqual(Buffer.from(candidate), Buffer.from(cleanToken))) {
            // Replay check
            if (uid) {
                const replayKey = `${uid}_${step}`;
                if (consumedStepCache.has(replayKey)) {
                    console.warn(`[MFA REPLAY BLOCKED] User ${uid} attempted to replay TOTP step ${step}`);
                    return false;
                }
                // Mark step consumed for next 90 seconds
                consumedStepCache.set(replayKey, Date.now() + 90000);
            }
            return true;
        }
    }
    return false;
}

// ==========================================
// Pending Unconfirmed Enrollment Cache
// ==========================================
function stagePendingEnrollment(uid, secret) {
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes TTL
    pendingEnrollmentCache.set(uid, { secret, expiresAt });
    return { secret, expiresAt };
}

function getPendingEnrollment(uid) {
    const item = pendingEnrollmentCache.get(uid);
    if (!item) return null;
    if (Date.now() > item.expiresAt) {
        pendingEnrollmentCache.delete(uid);
        return null;
    }
    return item.secret;
}

function clearPendingEnrollment(uid) {
    pendingEnrollmentCache.delete(uid);
}

// ==========================================
// Recovery Codes
// ==========================================
function generateRecoveryCodes(count = 8) {
    const plainCodes = [];
    const hashedRecords = [];
    for (let i = 0; i < count; i++) {
        const raw = crypto.randomBytes(4).toString('hex').toUpperCase();
        const formatted = `${raw.slice(0, 4)}-${raw.slice(4, 8)}`;
        const hash = crypto.createHash('sha256').update(formatted).digest('hex');
        plainCodes.push(formatted);
        hashedRecords.push({
            hash,
            used: false,
            usedAt: null
        });
    }
    return { plainCodes, hashedRecords };
}

function verifyAndConsumeRecoveryCode(providedCode, hashedRecords = []) {
    if (!providedCode || typeof providedCode !== 'string') return { valid: false };
    const clean = providedCode.trim().toUpperCase().replace(/\s+/g, '');
    const candidateHash = crypto.createHash('sha256').update(clean).digest('hex');

    for (let i = 0; i < hashedRecords.length; i++) {
        const rec = hashedRecords[i];
        if (!rec.used && rec.hash === candidateHash) {
            rec.used = true;
            rec.usedAt = new Date().toISOString();
            return { valid: true, updatedRecords: hashedRecords, consumedCode: clean };
        }
    }
    return { valid: false };
}

// ==========================================
// Signed MFA Challenge Proof Tokens
// ==========================================
function createMfaSignedToken(payload, expiresInMs = 300000) {
    const data = {
        ...payload,
        iat: Date.now(),
        exp: Date.now() + expiresInMs
    };
    const body = Buffer.from(JSON.stringify(data)).toString('base64url');
    const secret = getMfaHmacSecret();
    const sig = crypto.createHmac('sha256', secret).update(body).digest('base64url');
    return `${body}.${sig}`;
}

function verifyMfaSignedToken(token) {
    if (!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [body, sig] = parts;
    const secret = getMfaHmacSecret();
    const expectedSig = crypto.createHmac('sha256', secret).update(body).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) {
        return null;
    }
    try {
        const data = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
        if (Date.now() > data.exp) return null;
        return data;
    } catch {
        return null;
    }
}

module.exports = {
    getMfaHmacSecret,
    KNOWN_DEV_MFA_SECRETS,
    generateBase32Secret,
    buildTotpProvisioningUri,
    generateTOTP,
    verifyTOTP,
    encryptTotpSecret,
    decryptTotpSecret,
    stagePendingEnrollment,
    getPendingEnrollment,
    clearPendingEnrollment,
    generateRecoveryCodes,
    verifyAndConsumeRecoveryCode,
    createMfaSignedToken,
    verifyMfaSignedToken
};
