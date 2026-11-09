// store.js
// OAuth 2.0 Authorization Code Storage for LANZAR ID
//
// ============================================================================
// DEPLOYMENT ARCHITECTURE REQUIREMENT & CONCURRENCY BOUNDARY NOTE:
// ============================================================================
// 1. Single-Process Protection Scope:
//    The current AuthorizationCodeStore uses an in-memory JavaScript Map.
//    Atomic single-use consumption and compare-and-swap semantics (markUsed)
//    guarantee protection strictly within a single Node.js runtime process.
//
// 2. Multi-Instance Deployment Requirement:
//    In a horizontally-scaled multi-instance or clustered production deployment,
//    in-memory Maps across independent processes do NOT share state. Therefore:
//    - Multi-instance deployment requires shared, high-availability persistent storage
//      (e.g., Firestore distributed documents, Redis, or Memcached).
//    - Authorization code consumption across multiple instances MUST use an atomic,
//      transactional operation (such as a Firestore transaction with precondition checks,
//      or a Redis Lua script / SETNX with atomic expiration) to guarantee global single-use
//      and prevent cross-instance replay or race conditions.
//
// 3. Task Scope Boundary:
//    In accordance with architectural authorization for Step 5, this in-memory
//    implementation is retained for offline, zero-cloud test isolation and local runtime.
//    Do not introduce live databases, external network caches, or paid infrastructure.
// ============================================================================

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
