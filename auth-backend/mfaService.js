// mfaService.js
// Standard RFC 6238 / RFC 4226 TOTP, WebAuthn Challenge, and Single-Use Recovery Codes
const crypto = require('crypto');

const MFA_SECRET_KEY = process.env.MFA_HMAC_SECRET || 'lanzar_mfa_signing_key_secure_2026';

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

function generateTOTP(secret, counter = Math.floor(Date.now() / 30000)) {
    const key = base32Decode(secret);
    const buf = Buffer.alloc(8);
    buf.writeBigInt64BE(BigInt(counter));
    const hmac = crypto.createHmac('sha1', key).update(buf).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % 1000000;
    return code.toString().padStart(6, '0');
}

function verifyTOTP(secret, token, window = 1) {
    if (!token || typeof token !== 'string') return false;
    const cleanToken = token.trim().replace(/\s+/g, '');
    if (cleanToken.length !== 6 || !/^\d{6}$/.test(cleanToken)) return false;

    const currentCounter = Math.floor(Date.now() / 30000);
    for (let w = -window; w <= window; w++) {
        const candidate = generateTOTP(secret, currentCounter + w);
        if (crypto.timingSafeEqual(Buffer.from(candidate), Buffer.from(cleanToken))) {
            return true;
        }
    }
    return false;
}

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

function createMfaSignedToken(payload, expiresInMs = 300000) {
    const data = {
        ...payload,
        exp: Date.now() + expiresInMs
    };
    const jsonStr = JSON.stringify(data);
    const b64Data = Buffer.from(jsonStr).toString('base64url');
    const signature = crypto.createHmac('sha256', MFA_SECRET_KEY).update(b64Data).digest('base64url');
    return `${b64Data}.${signature}`;
}

function verifyMfaSignedToken(signedToken) {
    if (!signedToken || typeof signedToken !== 'string') return null;
    const parts = signedToken.split('.');
    if (parts.length !== 2) return null;
    const [b64Data, signature] = parts;
    const expectedSig = crypto.createHmac('sha256', MFA_SECRET_KEY).update(b64Data).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
        return null;
    }
    try {
        const payload = JSON.parse(Buffer.from(b64Data, 'base64url').toString('utf8'));
        if (Date.now() > payload.exp) {
            return null; // Expired
        }
        return payload;
    } catch (e) {
        return null;
    }
}

function generateWebAuthnChallenge() {
    return crypto.randomBytes(32).toString('base64url');
}

module.exports = {
    generateBase32Secret,
    generateTOTP,
    verifyTOTP,
    generateRecoveryCodes,
    verifyAndConsumeRecoveryCode,
    createMfaSignedToken,
    verifyMfaSignedToken,
    generateWebAuthnChallenge
};
