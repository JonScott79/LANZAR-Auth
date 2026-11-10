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

/**
 * Cryptographic SHA-256 hash helper for authorization codes.
 * Ensures authorization code document IDs in Firestore never store raw credentials.
 */
function hashAuthorizationCode(code) {
    return crypto.createHash('sha256').update(String(code)).digest('hex');
}

/**
 * Distributed Firestore-backed OAuth 2.0 Authorization Code Store (LID-SEC-001)
 * Guarantees cross-instance durability, single-use atomic consumption,
 * client binding, PKCE S256 validation, and replay defense across multi-instance deployments.
 * Stores authorization-code documents keyed by cryptographic hash (SHA-256) of the raw code.
 */
class FirestoreAuthorizationCodeStore {
    constructor(db) {
        if (!db) {
            throw new Error('Firestore database instance is required for FirestoreAuthorizationCodeStore');
        }
        this.db = db;
    }

    /**
     * @param {Object} data
     * @param {string} data.uid
     * @param {string} data.clientId
     * @param {string} data.redirectUri
     * @param {string} data.codeChallenge
     * @param {string} data.codeChallengeMethod
     * @returns {Promise<string>} The generated raw authorization code (returned to client)
     */
    async createCode(data) {
        if (!data || !data.codeChallengeMethod) {
            throw new Error('Explicit codeChallengeMethod is required (no fallback allowed)');
        }
        if (data.codeChallengeMethod !== 'S256') {
            throw new Error('Only S256 codeChallengeMethod is supported');
        }

        const code = crypto.randomBytes(32).toString('hex');
        const codeHash = hashAuthorizationCode(code);
        const expiresAt = Date.now() + 600000; // 10 minutes (600 seconds)

        const record = {
            codeHash,
            uid: data.uid,
            clientId: data.clientId,
            redirectUri: data.redirectUri,
            codeChallenge: data.codeChallenge,
            codeChallengeMethod: data.codeChallengeMethod,
            expiresAt,
            used: false,
            createdAt: Date.now()
        };

        // Key document by cryptographic hash, never by the raw authorization code
        await this.db.collection('oauth_codes').doc(codeHash).set(record);
        return code;
    }

    /**
     * Retrieves the authorization code record by hashing the incoming code.
     * @param {string} code - Raw authorization code
     * @returns {Promise<Object|null>}
     */
    async getCode(code) {
        if (!code || typeof code !== 'string') return null;
        const codeHash = hashAuthorizationCode(code);
        try {
            const snap = await this.db.collection('oauth_codes').doc(codeHash).get();
            if (!snap.exists) return null;
            return snap.data();
        } catch (_) {
            return null;
        }
    }

    /**
     * Atomically marks an authorization code as used via Firestore transaction.
     * Guarantees atomic CAS semantics across distributed multi-instance nodes.
     * Resolves document using cryptographic hash of the incoming code.
     * @param {string} code - Raw authorization code
     * @returns {Promise<boolean>} True if transitioned from used: false to used: true; false if already used or missing
     */
    async markUsed(code) {
        if (!code || typeof code !== 'string') return false;
        const codeHash = hashAuthorizationCode(code);
        const docRef = this.db.collection('oauth_codes').doc(codeHash);
        try {
            return await this.db.runTransaction(async (transaction) => {
                const snap = await transaction.get(docRef);
                if (!snap.exists) return false;
                const data = snap.data();
                if (data.used) return false;
                if (data.expiresAt && Date.now() > data.expiresAt) return false;

                transaction.update(docRef, {
                    used: true,
                    consumedAt: Date.now()
                });
                return true;
            });
        } catch (err) {
            return false;
        }
    }
}

module.exports = { AuthorizationCodeStore, FirestoreAuthorizationCodeStore, hashAuthorizationCode };
