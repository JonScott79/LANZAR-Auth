// store.js
const crypto = require('crypto');

class AuthorizationCodeStore {
    constructor() {
        this.codes = new Map();
    }

    /**
     * @param {Object} data 
     * @param {string} data.uid
     * @param {string} data.clientId
     * @param {string} data.redirectUri
     * @param {string} data.codeChallenge
     * @param {string} data.codeChallengeMethod
     * @returns {string} The generated code
     */
    async createCode(data) {
        if (!data || !data.codeChallengeMethod) {
            throw new Error('Explicit codeChallengeMethod is required (no fallback allowed)');
        }
        const code = crypto.randomBytes(32).toString('hex');
        const expiresAt = Date.now() + 60000; // 60 seconds

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

    /**
     * Atomically marks an authorization code as used.
     * Returns true if successfully transitioned from used: false to used: true (single-use).
     * Returns false if the code does not exist or has already been consumed.
     */
    async markUsed(code) {
        const record = this.codes.get(code);
        if (!record || record.used) {
            return false;
        }
        record.used = true;
        this.codes.set(code, record);
        return true;
    }
}

module.exports = { AuthorizationCodeStore };
