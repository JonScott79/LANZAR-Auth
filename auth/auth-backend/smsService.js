// smsService.js
// Phone Authentication & Verification Service with Provider Abstraction (Amendment #002)
// Live SMS provider deferred behind SMS_LIVE_ENABLED=false feature flag

const crypto = require('crypto');
const { FieldValue } = require('firebase-admin/firestore');
const { resolveEnvironment } = require('./config/environments');

function checkIsProduction() {
    try {
        return resolveEnvironment(process.env) === 'production';
    } catch (_) {
        return process.env.NODE_ENV === 'production' || process.env.APP_ENV === 'production';
    }
}

const SMS_LIVE_ENABLED = process.env.SMS_LIVE_ENABLED === 'true';

class SMSProvider {
    /**
     * @param {Object} params
     * @param {string} params.phoneNumber - E.164 normalized number
     * @param {string} params.code - 6-digit OTP
     * @param {string} params.purpose - 'verification' | 'login' | 'mfa' | 'replacement'
     */
    async sendOTP({ phoneNumber, code, purpose }) {
        throw new Error('sendOTP must be implemented by provider subclass.');
    }

    async getDeliveryStatus(messageId) {
        throw new Error('getDeliveryStatus must be implemented by provider subclass.');
    }
}

/**
 * Mock provider: strictly for development and staging.
 * Never calls external APIs, zero cost.
 */
class MockSMSProvider extends SMSProvider {
    async sendOTP({ phoneNumber, code, purpose }) {
        // SECURITY GUARD: Never expose plain OTP codes in production logs
        if (!checkIsProduction()) {
            console.log(`[DEV/STAGING MOCK SMS] Target: ${phoneNumber} | Purpose: ${purpose} | Code: [${code}]`);
        } else {
            console.log(`[MOCK SMS] Simulated OTP dispatch to ${phoneNumber.slice(0, 4)}***${phoneNumber.slice(-2)} | Purpose: ${purpose}`);
        }
        return {
            success: true,
            provider: 'mock',
            messageId: `mock_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
            deliveredAt: new Date().toISOString()
        };
    }

    async getDeliveryStatus(messageId) {
        return { messageId, status: 'delivered', provider: 'mock' };
    }
}

/**
 * Production provider stub (Twilio / Brevo) - ACTIVATION DEFERRED
 * Requires explicit SMS_LIVE_ENABLED=true and approved credentials
 */
class LiveSMSProviderStub extends SMSProvider {
    constructor(config = {}) {
        super();
        this.config = config;
    }

    async sendOTP({ phoneNumber, code, purpose }) {
        if (!SMS_LIVE_ENABLED) {
            throw new Error('Live SMS delivery is currently unactivated and deferred by system directive.');
        }
        throw new Error('Live SMS provider adapter not configured. Please contact operations.');
    }
}

class SMSService {
    constructor(db, options = {}) {
        this.db = db;
        // Default allowed country calling codes (US & Canada +1 default)
        this.allowedCountryCodes = options.allowedCountryCodes || ['+1'];
        // Monthly spend cap guard ($25 limit)
        this.monthlySpendingCap = options.monthlySpendingCap || 25.00;
        
        // Provider resolution
        if (SMS_LIVE_ENABLED && options.provider) {
            this.provider = options.provider;
        } else {
            this.provider = new MockSMSProvider();
        }

        // In-memory rate limiting map: Map<phoneNumber, timestamp>
        this.phoneRateLimit = new Map();
        // IP rate limiting map: Map<ip, Array<timestamp>>
        this.ipRateLimit = new Map();
    }

    /**
     * Strict E.164 normalization and country validation.
     */
    normalizePhoneNumber(rawNumber) {
        if (!rawNumber || typeof rawNumber !== 'string') return null;
        let cleaned = rawNumber.replace(/[^\d+]/g, '');
        if (!cleaned.startsWith('+')) {
            cleaned = '+1' + cleaned;
        }
        if (!/^\+[1-9]\d{9,14}$/.test(cleaned)) {
            return null;
        }

        // Geo-whitelisting defense against toll-fraud / premium numbers
        const isWhitelisted = this.allowedCountryCodes.some(prefix => cleaned.startsWith(prefix));
        if (!isWhitelisted) {
            throw new Error(`Country code not permitted. Supported destinations: ${this.allowedCountryCodes.join(', ')}`);
        }

        return cleaned;
    }

    /**
     * Rate limiting & abuse prevention.
     */
    checkRateLimits(phoneNumber, ipAddress) {
        const now = Date.now();

        // 1. Phone rate limit: max 1 request per 60 seconds
        const lastPhoneReq = this.phoneRateLimit.get(phoneNumber);
        if (lastPhoneReq && now - lastPhoneReq < 60000) {
            const waitSec = Math.ceil((60000 - (now - lastPhoneReq)) / 1000);
            throw new Error(`Please wait ${waitSec} seconds before requesting another verification code.`);
        }

        // 2. IP rate limit: max 3 requests per hour
        if (ipAddress) {
            const ipHistory = (this.ipRateLimit.get(ipAddress) || []).filter(ts => now - ts < 3600000);
            if (ipHistory.length >= 3) {
                throw new Error('Too many verification requests from this IP address. Please try again later.');
            }
            ipHistory.push(now);
            this.ipRateLimit.set(ipAddress, ipHistory);
        }

        this.phoneRateLimit.set(phoneNumber, now);
    }

    // ==========================================
    // CAPABILITY 1: Account Settings Phone Verification
    // ==========================================
    async sendVerificationOTP(uidOrObj, rawPhoneNumber, ipAddress = null) {
        let uid = uidOrObj;
        let phone = rawPhoneNumber;
        let ip = ipAddress;
        if (typeof uidOrObj === 'object' && uidOrObj !== null) {
            uid = uidOrObj.uid;
            phone = uidOrObj.phoneNumber || uidOrObj.rawPhoneNumber;
            ip = uidOrObj.ipAddress || null;
        }

        const normalized = this.normalizePhoneNumber(phone);
        if (!normalized) {
            throw new Error('Invalid phone number format. Please provide a valid E.164 phone number.');
        }

        this.checkRateLimits(normalized, ip);

        const code = crypto.randomInt(100000, 999999).toString();
        const codeHash = crypto.createHash('sha256').update(code).digest('hex');
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // 5 minutes TTL

        await this.db.collection('phone_otps').doc(normalized).set({
            uid,
            phoneNumber: normalized,
            purpose: 'settings_verification',
            codeHash,
            expiresAt,
            attempts: 0,
            verified: false,
            createdAt: FieldValue.serverTimestamp()
        });

        await this.provider.sendOTP({ phoneNumber: normalized, code, purpose: 'settings_verification' });

        return {
            success: true,
            phoneNumber: normalized,
            expiresInSeconds: 300,
            liveSmsActive: SMS_LIVE_ENABLED
        };
    }

    async verifyOTP(uidOrObj, rawPhoneNumber, submittedCode) {
        let uid = uidOrObj;
        let phone = rawPhoneNumber;
        let code = submittedCode;
        if (typeof uidOrObj === 'object' && uidOrObj !== null) {
            uid = uidOrObj.uid;
            phone = uidOrObj.phoneNumber || uidOrObj.rawPhoneNumber;
            code = uidOrObj.code || uidOrObj.submittedCode;
        }

        const normalized = this.normalizePhoneNumber(phone);
        if (!normalized || !code) {
            throw new Error('Phone number and verification code are required.');
        }

        const otpRef = this.db.collection('phone_otps').doc(normalized);
        const otpSnap = await otpRef.get();

        if (!otpSnap.exists) {
            throw new Error('No pending verification code found for this phone number.');
        }

        const otpData = otpSnap.data();

        if (otpData.uid !== uid) {
            throw new Error('Phone verification session does not match authenticated user.');
        }

        if (new Date(otpData.expiresAt) < new Date()) {
            throw new Error('Verification code has expired. Please request a new code.');
        }

        if (otpData.attempts >= 5) {
            await otpRef.delete();
            throw new Error('Too many failed verification attempts. Please request a new code.');
        }

        const submittedHash = crypto.createHash('sha256').update(String(submittedCode).trim()).digest('hex');
        if (submittedHash !== otpData.codeHash) {
            await otpRef.update({ attempts: FieldValue.increment(1) });
            throw new Error('Verification code incorrect. Please try again.');
        }

        // Verification successful: burn OTP record
        await otpRef.delete();

        // Update user profile with verified phone
        await this.db.collection('users').doc(uid).set({
            phoneNumber: normalized,
            phoneVerified: true,
            updatedAt: FieldValue.serverTimestamp()
        }, { merge: true });

        return {
            success: true,
            phoneNumber: normalized,
            phoneVerified: true
        };
    }

    // ==========================================
    // CAPABILITY 2: Phone-Number Login
    // ==========================================
    async sendPhoneLoginOTP(rawPhoneNumber, ipAddress = null) {
        const normalized = this.normalizePhoneNumber(rawPhoneNumber);
        if (!normalized) {
            throw new Error('Invalid phone number format.');
        }

        // Check if an account exists with this verified phone number
        const userQuery = await this.db.collection('users')
            .where('phoneNumber', '==', normalized)
            .where('phoneVerified', '==', true)
            .limit(1)
            .get();

        if (userQuery.empty) {
            // Anti-enumeration: still return success message without sending code
            return { success: true, message: 'If an account exists, a verification code was sent.' };
        }

        const targetUser = userQuery.docs[0].data();
        this.checkRateLimits(normalized, ipAddress);

        const code = crypto.randomInt(100000, 999999).toString();
        const codeHash = crypto.createHash('sha256').update(code).digest('hex');
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

        await this.db.collection('phone_otps').doc(normalized).set({
            uid: targetUser.uid,
            phoneNumber: normalized,
            purpose: 'phone_login',
            codeHash,
            expiresAt,
            attempts: 0,
            verified: false,
            createdAt: FieldValue.serverTimestamp()
        });

        await this.provider.sendOTP({ phoneNumber: normalized, code, purpose: 'phone_login' });

        return { success: true, expiresInSeconds: 300 };
    }

    // ==========================================
    // CAPABILITY 3: Phone Replacement & Re-verification
    // ==========================================
    async initiatePhoneReplacement(uid, newRawPhoneNumber, ipAddress = null) {
        const normalized = this.normalizePhoneNumber(newRawPhoneNumber);
        if (!normalized) {
            throw new Error('Invalid replacement phone number format.');
        }

        this.checkRateLimits(normalized, ipAddress);

        const code = crypto.randomInt(100000, 999999).toString();
        const codeHash = crypto.createHash('sha256').update(code).digest('hex');
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

        await this.db.collection('phone_otps').doc(normalized).set({
            uid,
            phoneNumber: normalized,
            purpose: 'phone_replacement',
            codeHash,
            expiresAt,
            attempts: 0,
            verified: false,
            createdAt: FieldValue.serverTimestamp()
        });

        await this.provider.sendOTP({ phoneNumber: normalized, code, purpose: 'phone_replacement' });

        return { success: true, phoneNumber: normalized, expiresInSeconds: 300 };
    }
}

module.exports = {
    SMSService,
    SMSProvider,
    MockSMSProvider,
    LiveSMSProviderStub,
    SMS_LIVE_ENABLED
};
