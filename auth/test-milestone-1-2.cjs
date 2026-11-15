// test-milestone-1-2.cjs
// Milestone 1.2 Verification Suite: Asymmetric Signing Infrastructure (RS256 Keystore & Public JWKS)

const assert = require('assert');
const crypto = require('crypto');
const express = require('./auth-backend/node_modules/express');
const {
    SigningKeystore,
    validateSigningKeyEncryptionConfiguration,
    encryptPrivateKeyPem,
    decryptPrivateKeyPem
} = require('./auth-backend/services/signingKeystore');
const { createJwksRouter } = require('./auth-backend/routes/jwksRoutes');

// Minimal in-memory Firestore mock supporting where('status', '==', ...), get(), set(), update(), runTransaction()
class MockKeystoreFirestore {
    constructor() {
        this.docs = new Map();
        this.txQueue = Promise.resolve();
    }

    collection(name) {
        const self = this;
        return {
            doc(id) {
                const key = `${name}/${id}`;
                return {
                    id,
                    _key: key,
                    async get() {
                        const val = self.docs.get(key);
                        return { id, exists: val !== undefined, data: () => (val ? structuredClone(val) : undefined) };
                    }
                };
            },
            where(field, op, value) {
                return {
                    async get() {
                        const matched = [];
                        for (const [k, v] of self.docs.entries()) {
                            if (k.startsWith(`${name}/`) && op === '==' && v[field] === value) {
                                const id = k.slice(name.length + 1);
                                matched.push({ id, exists: true, data: () => structuredClone(v) });
                            }
                        }
                        return { empty: matched.length === 0, docs: matched };
                    }
                };
            },
            async get() {
                const all = [];
                for (const [k, v] of self.docs.entries()) {
                    if (k.startsWith(`${name}/`)) {
                        const id = k.slice(name.length + 1);
                        all.push({ id, exists: true, data: () => structuredClone(v) });
                    }
                }
                return { empty: all.length === 0, docs: all };
            }
        };
    }

    async runTransaction(fn) {
        return new Promise((resolve, reject) => {
            this.txQueue = this.txQueue.then(async () => {
                try {
                    let writeStarted = false;
                    const tx = {
                        async get(target) {
                            if (writeStarted) throw new Error('Firestore Read-Before-Write violation');
                            return await target.get();
                        },
                        set(docRef, data) {
                            writeStarted = true;
                            selfSet(docRef._key, data);
                        },
                        update(docRef, patch) {
                            writeStarted = true;
                            const cur = self.docs.get(docRef._key);
                            if (!cur) throw new Error(`Document not found: ${docRef._key}`);
                            selfSet(docRef._key, { ...cur, ...patch });
                        }
                    };
                    const self = this;
                    function selfSet(k, v) {
                        self.docs.set(k, structuredClone(v));
                    }
                    const res = await fn(tx);
                    resolve(res);
                } catch (e) {
                    reject(e);
                }
            });
        });
    }
}

let passed = 0;
let failed = 0;

async function test(name, fn) {
    try {
        await fn();
        console.log(`  ✓ [PASS] ${name}`);
        passed++;
    } catch (err) {
        console.error(`  ✗ [FAIL] ${name}`);
        console.error(`    ${err.stack || err.message}`);
        failed++;
    }
}

async function main() {
    console.log('================================================================');
    console.log('LANZAR ID — Milestone 1.2 Verification Suite (RS256 & JWKS)');
    console.log('================================================================\n');

    await test('M1.2-01: Production KEK validation fails closed on missing, weak, dev, or invalid version', async () => {
        assert.throws(() => validateSigningKeyEncryptionConfiguration({ NODE_ENV: 'production' }), /SIGNING_KEY_ENCRYPTION_KEY is required/);
        assert.throws(() => validateSigningKeyEncryptionConfiguration({ APP_ENV: 'staging', SIGNING_KEY_ENCRYPTION_KEY: 'short' }), /at least 32 bytes/);
        assert.throws(() => validateSigningKeyEncryptionConfiguration({ NODE_ENV: 'production', SIGNING_KEY_ENCRYPTION_KEY: 'LANZAR_ID_DEV_SIGNING_KEK_V1_TEST_ONLY_32B' }), /development or default secret/);
        assert.throws(() => validateSigningKeyEncryptionConfiguration({ NODE_ENV: 'production', ACTIVE_SIGNING_KEK_VERSION: '1.5', SIGNING_KEY_ENCRYPTION_KEY: 'a'.repeat(64) }), /positive integer/);
        assert.strictEqual(validateSigningKeyEncryptionConfiguration({ NODE_ENV: 'production', SIGNING_KEY_ENCRYPTION_KEY: 'a'.repeat(64) }), true);
    });

    await test('M1.2-02: Private keys are encrypted at rest with AES-256-GCM (12B IV, 16B tag, AAD bound)', async () => {
        const blob = encryptPrivateKeyPem('-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----', 'kid_test_1', 1);
        assert.strictEqual(Buffer.from(blob.iv, 'base64').length, 12);
        assert.strictEqual(Buffer.from(blob.authTag, 'base64').length, 16);
        assert.strictEqual(decryptPrivateKeyPem(blob, 'kid_test_1').includes('TEST'), true);
        assert.throws(() => decryptPrivateKeyPem(blob, 'kid_wrong_aad'));
    });

    await test('M1.2-03: Concurrent ensureActiveSigningKey() initializes exactly one active RS256 key', async () => {
        const db = new MockKeystoreFirestore();
        const keystore = new SigningKeystore(db);
        const results = await Promise.all([
            keystore.ensureActiveSigningKey({ bypassCache: true }),
            keystore.ensureActiveSigningKey({ bypassCache: true }),
            keystore.ensureActiveSigningKey({ bypassCache: true })
        ]);
        const kids = new Set(results.map(r => r.kid));
        assert.strictEqual(kids.size, 1);
        const keyDocs = Array.from(db.docs.entries()).filter(([id]) => id !== 'system_signing_keys/_active_pointer');
        assert.strictEqual(keyDocs.length, 1);
        const pointer = db.docs.get('system_signing_keys/_active_pointer');
        assert.ok(pointer && pointer.activeKid === results[0].kid);
        const stored = keyDocs[0][1];
        assert.ok(stored.encryptedPrivateKey && stored.encryptedPrivateKey.ciphertext);
        assert.strictEqual(stored.privateKey, undefined);
    });

    await test('M1.2-04: signJwt() and verifyJwt() sign RS256 JWTs and reject tampered signatures or expired tokens', async () => {
        const db = new MockKeystoreFirestore();
        const keystore = new SigningKeystore(db);
        const token = await keystore.signJwt({ sub: 'usr_123', tenant_id: 'lanzar', scope: 'openid' }, { expiresInSeconds: 900 });
        const verified = await keystore.verifyJwt(token);
        assert.strictEqual(verified.valid, true);
        assert.strictEqual(verified.header.alg, 'RS256');
        assert.strictEqual(verified.payload.sub, 'usr_123');

        const parts = token.split('.');
        const tamperedPayload = Buffer.from(JSON.stringify({ sub: 'usr_attacker', exp: verified.payload.exp })).toString('base64url');
        const badSigResult = await keystore.verifyJwt(`${parts[0]}.${tamperedPayload}.${parts[2]}`);
        assert.strictEqual(badSigResult.valid, false);
        assert.strictEqual(badSigResult.reason, 'INVALID_SIGNATURE');

        const expiredResult = await keystore.verifyJwt(token, { nowSec: verified.payload.exp + 1 });
        assert.strictEqual(expiredResult.valid, false);
        assert.strictEqual(expiredResult.reason, 'TOKEN_EXPIRED');
    });

    await test('M1.2-05: Zero-downtime rotateSigningKey() keeps old key verify_only in JWKS while signing with new key', async () => {
        const db = new MockKeystoreFirestore();
        const keystore = new SigningKeystore(db);
        const oldJwt = await keystore.signJwt({ sub: 'usr_old' });
        const oldKid = JSON.parse(Buffer.from(oldJwt.split('.')[0], 'base64url').toString('utf8')).kid;

        const { newRecord, rotatedIds } = await keystore.rotateSigningKey();
        assert.ok(rotatedIds.includes(oldKid));
        assert.notStrictEqual(newRecord.kid, oldKid);

        const newJwt = await keystore.signJwt({ sub: 'usr_new' });
        const newKid = JSON.parse(Buffer.from(newJwt.split('.')[0], 'base64url').toString('utf8')).kid;
        assert.strictEqual(newKid, newRecord.kid);

        const jwks = await keystore.getPublicJwks({ bypassCache: true });
        assert.strictEqual(jwks.keys.length, 2);
        assert.strictEqual((await keystore.verifyJwt(oldJwt)).valid, true);
        assert.strictEqual((await keystore.verifyJwt(newJwt)).valid, true);
    });

    await test('M1.2-06: revokeSigningKey() removes key from JWKS immediately and blocks verification', async () => {
        const db = new MockKeystoreFirestore();
        const keystore = new SigningKeystore(db);
        const jwt = await keystore.signJwt({ sub: 'usr_rev' });
        const kid = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString('utf8')).kid;

        await keystore.revokeSigningKey(kid, 'key_compromise');
        const jwks = await keystore.getPublicJwks({ bypassCache: true });
        assert.strictEqual(jwks.keys.some(k => k.kid === kid), false);

        const res = await keystore.verifyJwt(jwt, { bypassCache: true });
        assert.strictEqual(res.valid, false);
        assert.strictEqual(res.reason, 'UNKNOWN_OR_REVOKED_KID');
    });

    await test('M1.2-07: HTTP GET /.well-known/jwks.json serves public RFC 7517 JWKs with zero private fields and 503 when unavailable', async () => {
        const db = new MockKeystoreFirestore();
        const keystore = new SigningKeystore(db);
        await keystore.ensureActiveSigningKey();

        const app = express();
        app.use('/', createJwksRouter({ signingKeystore: keystore }));
        const server = await new Promise(resolve => {
            const s = app.listen(0, '127.0.0.1', () => resolve(s));
        });
        try {
            const resp = await fetch(`http://127.0.0.1:${server.address().port}/.well-known/jwks.json`);
            assert.strictEqual(resp.status, 200);
            assert.ok(resp.headers.get('cache-control').includes('max-age=60'));
            const body = await resp.json();
            assert.strictEqual(Array.isArray(body.keys), true);
            assert.strictEqual(body.keys.length, 1);
            const jwk = body.keys[0];
            assert.strictEqual(jwk.kty, 'RSA');
            assert.strictEqual(jwk.use, 'sig');
            assert.strictEqual(jwk.alg, 'RS256');
            assert.ok(jwk.kid && jwk.n && jwk.e);
            assert.strictEqual(jwk.d, undefined);
            assert.strictEqual(jwk.encryptedPrivateKey, undefined);

            // Verify Node crypto can import the served JWK and verify a signed token directly
            const token = await keystore.signJwt({ sub: 'usr_http_jwks' });
            const [h, p, s] = token.split('.');
            const pubKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
            assert.strictEqual(crypto.verify('RSA-SHA256', Buffer.from(`${h}.${p}`), pubKey, Buffer.from(s, 'base64url')), true);
        } finally {
            await new Promise(resolve => server.close(resolve));
        }

        const appDown = express();
        appDown.use('/', createJwksRouter({ signingKeystore: null }));
        const srvDown = await new Promise(resolve => {
            const s = appDown.listen(0, '127.0.0.1', () => resolve(s));
        });
        try {
            const resp = await fetch(`http://127.0.0.1:${srvDown.address().port}/.well-known/jwks.json`);
            assert.strictEqual(resp.status, 503);
        } finally {
            await new Promise(resolve => srvDown.close(resolve));
        }
    });

    await test('M1.2-08: Staging and production KEK validation rejects dev fallback across all NODE_ENV/APP_ENV combinations', async () => {
        for (const env of [
            { NODE_ENV: 'staging' },
            { APP_ENV: 'staging' },
            { NODE_ENV: 'production' },
            { APP_ENV: 'production' }
        ]) {
            assert.throws(() => validateSigningKeyEncryptionConfiguration(env), /SIGNING_KEY_ENCRYPTION_KEY is required/);
            assert.throws(
                () => validateSigningKeyEncryptionConfiguration({ ...env, SIGNING_KEY_ENCRYPTION_KEY: 'LANZAR_ID_DEV_SIGNING_KEK_V1_TEST_ONLY_32B' }),
                /development or default secret/
            );
            assert.strictEqual(
                validateSigningKeyEncryptionConfiguration({ ...env, SIGNING_KEY_ENCRYPTION_KEY: 'b'.repeat(64) }),
                true
            );
        }

        // Explicitly non-production, non-staging environments continue to allow dev fallback
        assert.strictEqual(validateSigningKeyEncryptionConfiguration({ NODE_ENV: 'development' }), true);
        assert.strictEqual(validateSigningKeyEncryptionConfiguration({ NODE_ENV: 'test' }), true);
    });

    await test('M1.2-09: Reconciles existing active keys without _active_pointer deterministically without creating duplicates', async () => {
        const db = new MockKeystoreFirestore();
        const { generateRsaSigningKeyRecord } = require('./auth-backend/services/signingKeystore.js');
        const legacy1 = generateRsaSigningKeyRecord(Date.now() - 20000);
        const legacy2 = generateRsaSigningKeyRecord(Date.now() - 10000);
        db.docs.set(`system_signing_keys/${legacy1.kid}`, legacy1);
        db.docs.set(`system_signing_keys/${legacy2.kid}`, legacy2);

        const keystore = new SigningKeystore(db);
        const active = await keystore.ensureActiveSigningKey({ bypassCache: true });

        assert.strictEqual(active.kid, legacy2.kid);
        assert.strictEqual(db.docs.get('system_signing_keys/_active_pointer').activeKid, legacy2.kid);
        assert.strictEqual(db.docs.get(`system_signing_keys/${legacy1.kid}`).status, 'verify_only');
        assert.strictEqual(db.docs.get(`system_signing_keys/${legacy2.kid}`).status, 'active');

        const keyDocs = Array.from(db.docs.entries()).filter(([id]) => id !== 'system_signing_keys/_active_pointer');
        assert.strictEqual(keyDocs.length, 2, 'Reconciliation must not create a third key');
    });

    await test('M1.2-10: Revoked keys cannot be reactivated even if _active_pointer points to a revoked key', async () => {
        const db = new MockKeystoreFirestore();
        const keystore = new SigningKeystore(db);
        const first = await keystore.ensureActiveSigningKey({ bypassCache: true });
        await keystore.revokeSigningKey(first.kid, 'key_compromise');

        // Simulate stale pointer still pointing at the revoked key
        db.docs.set('system_signing_keys/_active_pointer', { activeKid: first.kid, updatedAt: new Date().toISOString() });

        const replacement = await keystore.ensureActiveSigningKey({ bypassCache: true });
        assert.notStrictEqual(replacement.kid, first.kid);
        assert.strictEqual(replacement.status, 'active');
        assert.strictEqual(db.docs.get(`system_signing_keys/${first.kid}`).status, 'revoked');
        assert.strictEqual(db.docs.get('system_signing_keys/_active_pointer').activeKid, replacement.kid);
    });

    await test('M1.2-11: Default internal cache TTL is 5s and transaction retries do not regenerate RSA keys', async () => {
        const db = new MockKeystoreFirestore();
        let txAttempts = 0;
        const origRunTx = db.runTransaction.bind(db);
        db.runTransaction = async (fn) => {
            return origRunTx(async (tx) => {
                txAttempts++;
                if (txAttempts < 3) {
                    throw new Error('ABORTED: simulated contention');
                }
                return fn(tx);
            });
        };

        const cryptoMod = require('crypto');
        let keyGenCalls = 0;
        const origGen = cryptoMod.generateKeyPairSync;
        cryptoMod.generateKeyPairSync = (...args) => {
            keyGenCalls++;
            return origGen(...args);
        };

        try {
            const keystore = new SigningKeystore(db);
            assert.strictEqual(keystore.cacheTtlMs, 5000);
            try {
                await keystore.ensureActiveSigningKey({ bypassCache: true });
            } catch (e) {
                // MockKeystoreFirestore doesn't auto-retry; simulate 3 caller retries via wrapper:
            }
            // Reset and test single runTransaction call that internally retries callback 3 times
            txAttempts = 0;
            keyGenCalls = 0;
            db.runTransaction = async (fn) => {
                let lastErr;
                for (let i = 0; i < 3; i++) {
                    try {
                        txAttempts++;
                        return await origRunTx(async (tx) => {
                            if (txAttempts < 3) {
                                throw new Error('ABORTED: simulated contention');
                            }
                            return fn(tx);
                        });
                    } catch (err) {
                        lastErr = err;
                    }
                }
                throw lastErr;
            };

            const active = await keystore.ensureActiveSigningKey({ bypassCache: true });
            assert.ok(active && active.kid);
            assert.strictEqual(txAttempts, 3);
            assert.strictEqual(keyGenCalls, 1, 'RSA key generation must happen once outside transaction retry loop');
        } finally {
            cryptoMod.generateKeyPairSync = origGen;
        }
    });

    console.log('\n================================================================');
    console.log('MILESTONE 1.2 VERIFICATION SUMMARY');
    console.log(`Total Executed: ${passed + failed}`);
    console.log(`Passed:         ${passed}`);
    console.log(`Failed:         ${failed}`);
    console.log(`Success Rate:   ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
    console.log('================================================================\n');

    if (failed > 0) process.exit(1);
}

main().catch(err => {
    console.error('Fatal Milestone 1.2 test error:', err);
    process.exit(1);
});
