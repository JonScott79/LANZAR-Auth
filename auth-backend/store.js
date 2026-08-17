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
     * @returns {string} The generated code
     */
    async createCode(data) {
        const code = crypto.randomBytes(32).toString('hex');
        const expiresAt = Date.now() + 60000; // 60 seconds

        this.codes.set(code, {
            ...data,
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
        if (record) {
            record.used = true;
            this.codes.set(code, record);
        }
    }
}

module.exports = { AuthorizationCodeStore };
