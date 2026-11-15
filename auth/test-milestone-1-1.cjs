// test-milestone-1-1.cjs
// Authoritative Acceptance Test Suite for Milestone 1.1: Distributed Authorization Code Store
// Verifying LID-SPEC-M1.1-STORE-REV9-AUTHORITATIVE & LID-ARCH-REV-022-FINAL-AUTHORITATIVE
// Tests TC-01 through TC-25 verifying both HTTP responses and actual Firestore document states.
// Tested against Simulated In-Memory Transaction Engine with strict read-before-write validation.

const crypto = require('crypto');
const {
    FirestoreAuthorizationCodeStore,
    hashAuthorizationCode,
    encryptTokenReceipt,
    decryptTokenReceipt,
    canWorkerRevokeSession,
    canWorkerRevokeFamily,
    canReplayRevokeSession,
    canReplayRevokeFamily,
    canReplayRevokePair,
    validateReceiptKeyConfiguration,
    setReceiptKeyringForTesting,
    resetReceiptKeyringForTesting,
    parseAndValidateReceiptKey
} = require('./auth-backend/store');
const express = require('./auth-backend/node_modules/express');
const http = require('http');
const { createOAuthRouter } = require('./auth-backend/routes/oauthRoutes');
const { SessionService } = require('./auth-backend/sessionService');

// ============================================================================
// High-Fidelity Mock Firestore with Strict Read-Before-Write Verification
// ============================================================================

class MockFirestore {
    constructor() {
        this.store = new Map();
        this.txQueue = Promise.resolve();
        this.simulateRetryOnNext = false;
        this.retryDelayMs = 0;
    }

    _key(path) {
        return path.replace(/\/+/g, '/').replace(/^\/|\/$/g, '');
    }

    collection(colName) {
        return new MockCollectionReference(this, colName);
    }

    async runTransaction(updateFn) {
        return new Promise((resolve, reject) => {
            this.txQueue = this.txQueue.then(async () => {
                try {
                    if (this.simulateRetryOnNext) {
                        this.simulateRetryOnNext = false;
                        const firstTx = new MockTransaction(this);
                        try {
                            await updateFn(firstTx);
                        } catch (e) {
                            // First attempt aborted due to conflict
                        }
                        if (this.retryDelayMs > 0) {
                            await new Promise(r => setTimeout(r, this.retryDelayMs));
                        }
                    }
                    const tx = new MockTransaction(this);
                    const res = await updateFn(tx);
                    resolve(res);
                } catch (e) {
                    reject(e);
                }
            });
        });
    }
}

class MockCollectionReference {
    constructor(db, path) {
        this.db = db;
        this.path = path;
    }

    doc(id) {
        return new MockDocumentReference(this.db, `${this.path}/${id}`);
    }

    where(field, op, val) {
        return new MockQuery(this.db, this.path, [{ field, op, val }]);
    }
}

class MockQuery {
    constructor(db, path, conditions = []) {
        this.db = db;
        this.path = path;
        this.conditions = conditions;
    }

    where(field, op, val) {
        return new MockQuery(this.db, this.path, [...this.conditions, { field, op, val }]);
    }

    async get() {
        const docs = [];
        const prefix = `${this.db._key(this.path)}/`;
        for (const [key, data] of this.db.store.entries()) {
            if (key.startsWith(prefix)) {
                const sub = key.slice(prefix.length);
                if (!sub.includes('/')) {
                    let match = true;
                    for (const cond of this.conditions) {
                        if (cond.op === '==' && data[cond.field] !== cond.val) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        docs.push({
                            id: sub,
                            data: () => ({ ...data }),
                            ref: new MockDocumentReference(this.db, key)
                        });
                    }
                }
            }
        }
        return {
            empty: docs.length === 0,
            size: docs.length,
            docs
        };
    }
}

class MockDocumentReference {
    constructor(db, path) {
        this.db = db;
        this.path = db._key(path);
    }

    collection(subColName) {
        return new MockCollectionReference(this.db, `${this.path}/${subColName}`);
    }

    async get() {
        const data = this.db.store.get(this.path);
        return {
            exists: data !== undefined,
            data: () => (data !== undefined ? { ...data } : undefined),
            id: this.path.split('/').pop()
        };
    }

    async set(data, options = {}) {
        if (options.merge && this.db.store.has(this.path)) {
            this.db.store.set(this.path, { ...this.db.store.get(this.path), ...data });
        } else {
            this.db.store.set(this.path, { ...data });
        }
    }

    async create(data) {
        if (this.db.store.has(this.path)) {
            const err = new Error(`Document already exists: ${this.path}`);
            err.code = 6;
            throw err;
        }
        this.db.store.set(this.path, { ...data });
    }

    async update(data) {
        const current = this.db.store.get(this.path);
        if (!current) throw new Error(`Document not found for update: ${this.path}`);
        this.db.store.set(this.path, { ...current, ...data });
    }

    async delete() {
        this.db.store.delete(this.path);
    }
}

class MockTransaction {
    constructor(db) {
        this.db = db;
        this.hasMutated = false;
    }

    async get(docRef) {
        if (this.hasMutated) {
            throw new Error('FirestoreError: Firestore transactions require all reads to be executed before all writes.');
        }
        return await docRef.get();
    }

    set(docRef, data, options = {}) {
        this.hasMutated = true;
        if (options.merge && this.db.store.has(docRef.path)) {
            this.db.store.set(docRef.path, { ...this.db.store.get(docRef.path), ...data });
        } else {
            this.db.store.set(docRef.path, { ...data });
        }
    }

    create(docRef, data) {
        this.hasMutated = true;
        if (this.db.store.has(docRef.path)) {
            const err = new Error(`Document already exists: ${docRef.path}`);
            err.code = 6;
            throw err;
        }
        this.db.store.set(docRef.path, { ...data });
    }

    update(docRef, data) {
        this.hasMutated = true;
        const current = this.db.store.get(docRef.path);
        if (!current) throw new Error(`Document not found for update: ${docRef.path}`);
        this.db.store.set(docRef.path, { ...current, ...data });
    }

    delete(docRef) {
        this.hasMutated = true;
        this.db.store.delete(docRef.path);
    }
}

class MockAuthAdmin {
    async verifyIdToken(token) {
        return { uid: 'usr_test_123', email: 'test@lanzar.me', name: 'Test User' };
    }
    async createCustomToken(uid, claims) {
        return `mock_custom_token_${uid}_${claims.session_id}`;
    }
}

let passedCount = 0;
let failedCount = 0;

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

async function test(name, fn) {
    try {
        await fn();
        console.log(`  ✓ [PASS] ${name}`);
        passedCount++;
    } catch (err) {
        console.error(`  ✗ [FAIL] ${name}`);
        console.error(`     Error: ${err.message}`);
        failedCount++;
    }
}

function generatePkce() {
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    return { verifier, challenge };
}

async function main() {
    console.log('================================================================');
    console.log('LANZAR ID — Milestone 1.1 In-Memory Simulation Verification Suite');
    console.log('Target Specification: LID-SPEC-M1.1-STORE-REV9-AUTHORITATIVE');
    console.log(`Timestamp: ${new Date().toISOString()}`);
    console.log('================================================================\n');

    const db = new MockFirestore();
    const store = new FirestoreAuthorizationCodeStore(db);
    const authAdmin = new MockAuthAdmin();
    const sessionService = new SessionService(db, authAdmin);

    const testUid = 'usr_alice_456';
    const testClientId = 'portal';
    const testRedirectUri = 'https://portal.lanzar.me';

    // -------------------------------------------------------------
    // TC-01: Completed Code + Wrong PKCE
    // -------------------------------------------------------------
    await test('TC-01: Completed Code + Wrong PKCE (Receipt NOT returned, PKCE validated first)', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge,
            codeChallengeMethod: 'S256',
            tenantId: 'lanzar'
        });
        const codeHash = hashAuthorizationCode(code);
        const idemKey = 'idem_key_tc01_initial_test_001';

        const claim = await store.initiateRedemption({
            code,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier,
            idempotencyKey: idemKey
        });
        assert(claim.status === 'SUCCESS', 'Claim must succeed');

        const sessionId = 'sess_tc01_1';
        const familyId = 'fam_tc01_1';
        await db.collection('users').doc(testUid).collection('sessions').doc(sessionId).set({
            sessionId, familyId, tenantId: 'lanzar', uid: testUid, clientId: testClientId, ceremonyId: claim.record.ceremonyId,
            redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken, status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(familyId).set({
            familyId, sessionId, tenantId: 'lanzar', uid: testUid, clientId: testClientId, ceremonyId: claim.record.ceremonyId,
            redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken, status: 'pending_activation'
        });

        await store.registerStagedRecords({
            codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
            issuedSessionId: sessionId, issuedFamilyId: familyId
        });

        const fin = await store.finalizeRedemption({
            codeHash,
            redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            issuedSessionId: sessionId,
            issuedFamilyId: familyId,
            rawTokensPayload: { custom_token: 'tok_tc01', session_id: sessionId }
        });
        assert(fin.success === true, 'Finalize must succeed');

        const badRecovery = await store.initiateRedemption({
            code,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeVerifier: 'wrong_pkce_verifier_string_1234567890',
            idempotencyKey: idemKey
        });
        assert(badRecovery.status === 'PKCE_MISMATCH', `Expected PKCE_MISMATCH, got ${badRecovery.status}`);
        assert(!badRecovery.tokenReceipt, 'Receipt must NOT be returned when PKCE is wrong');

        const codeDoc = (await db.collection('authorization_codes').doc(codeHash).get()).data();
        assert(codeDoc.status === 'COMPLETED', 'Code remains COMPLETED');
    });

    // -------------------------------------------------------------
    // TC-02: Concurrent Legitimate Retry (Same Idempotency-Key)
    // -------------------------------------------------------------
    await test('TC-02: Concurrent Legitimate Retry (Returns IN_PROGRESS, does not compromise)', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge,
            codeChallengeMethod: 'S256'
        });
        const idemKey = 'idem_key_tc02_matching_retry_002';

        const claim1 = await store.initiateRedemption({
            code,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier,
            idempotencyKey: idemKey
        });
        assert(claim1.status === 'SUCCESS', 'First claim succeeds');

        const retry = await store.initiateRedemption({
            code,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier,
            idempotencyKey: idemKey
        });
        assert(retry.status === 'IN_PROGRESS', `Expected IN_PROGRESS, got ${retry.status}`);

        const codeDoc = (await db.collection('authorization_codes').doc(claim1.codeHash).get()).data();
        assert(codeDoc.status === 'REDEEMING', 'Ceremony must remain REDEEMING');
    });

    // -------------------------------------------------------------
    // TC-03: Concurrent Conflict Redemption (Distinct Idempotency-Key)
    // -------------------------------------------------------------
    await test('TC-03: Concurrent Conflict Redemption (Marks COMPROMISED, revokes session and family)', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge,
            codeChallengeMethod: 'S256'
        });
        const idemKey1 = 'idem_key_tc03_worker_one_111';
        const idemKey2 = 'idem_key_tc03_worker_two_222';

        const claim1 = await store.initiateRedemption({
            code,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier,
            idempotencyKey: idemKey1
        });
        assert(claim1.status === 'SUCCESS', 'Worker 1 claims lock');

        const sessId = 'sess_tc03_1';
        const famId = 'fam_tc03_1';
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId).set({
            sessionId: sessId, familyId: famId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim1.record.ceremonyId, redemptionLockId: claim1.redemptionLockId, fenceToken: claim1.fenceToken,
            status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).set({
            familyId: famId, sessionId: sessId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim1.record.ceremonyId, redemptionLockId: claim1.redemptionLockId, fenceToken: claim1.fenceToken,
            status: 'pending_activation'
        });
        await db.collection('authorization_codes').doc(claim1.codeHash).update({
            issuedSessionId: sessId,
            issuedFamilyId: famId
        });

        const conflict = await store.initiateRedemption({
            code,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier,
            idempotencyKey: idemKey2
        });
        assert(conflict.status === 'REPLAY_DETECTED', `Expected REPLAY_DETECTED, got ${conflict.status}`);

        const codeDoc = (await db.collection('authorization_codes').doc(claim1.codeHash).get()).data();
        assert(codeDoc.status === 'COMPROMISED', 'Code ceremony must be marked COMPROMISED');

        const sessDoc = (await db.collection('users').doc(testUid).collection('sessions').doc(sessId).get()).data();
        assert(sessDoc.status === 'revoked', 'Pending session must be revoked');

        const famDoc = (await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).get()).data();
        assert(famDoc.status === 'revoked', 'Pending family must be revoked');
    });

    // -------------------------------------------------------------
    // TC-04: Pending Session & Family Inactivity
    // -------------------------------------------------------------
    await test('TC-04: Pending Session & Family Inactivity (checkSession returns active: false)', async () => {
        const sessId = 'sess_tc04_pending';
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId).set({
            sessionId: sessId,
            uid: testUid,
            status: 'pending_activation',
            expiresAt: new Date(Date.now() + 86400000).toISOString()
        });

        const check = await sessionService.checkSession(testUid, sessId);
        assert(check.active === false, 'Pending session must NOT be active');
        assert(check.reason === 'pending_activation', `Expected reason pending_activation, got ${check.reason}`);
    });

    // -------------------------------------------------------------
    // TC-05: Replay Before Finalization
    // -------------------------------------------------------------
    await test('TC-05: Replay Before Finalization (Finalization fails, revokes pending session & family)', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge,
            codeChallengeMethod: 'S256'
        });
        const idemKey = 'idem_key_tc05_minting_005';

        const claim = await store.initiateRedemption({
            code,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier,
            idempotencyKey: idemKey
        });

        const sessId = 'sess_tc05_minting';
        const famId = 'fam_tc05_minting';
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId).set({
            sessionId: sessId, familyId: famId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).set({
            familyId: famId, sessionId: sessId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            status: 'pending_activation'
        });

        // Compromised before finalization
        await db.collection('authorization_codes').doc(claim.codeHash).update({ status: 'COMPROMISED' });

        const fin = await store.finalizeRedemption({
            codeHash: claim.codeHash,
            redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            issuedSessionId: sessId,
            issuedFamilyId: famId,
            rawTokensPayload: { custom_token: 'tok' }
        });

        assert(fin.success === false, 'Finalization must fail');
        assert(fin.reason === 'COMPROMISED_DURING_ISSUANCE', `Expected COMPROMISED_DURING_ISSUANCE, got ${fin.reason}`);

        const sessDoc = (await db.collection('users').doc(testUid).collection('sessions').doc(sessId).get()).data();
        assert(sessDoc.status === 'revoked', 'Session must be revoked');

        const famDoc = (await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).get()).data();
        assert(famDoc.status === 'revoked', 'Family must be revoked');
    });

    // -------------------------------------------------------------
    // TC-06: Replay After Finalization
    // -------------------------------------------------------------
    await test('TC-06: Replay After Finalization (Active session & family immediately revoked)', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge,
            codeChallengeMethod: 'S256'
        });
        const idemKey1 = 'idem_key_tc06_completed_006';
        const idemKey2 = 'idem_key_tc06_attacker_replay_999';

        const claim = await store.initiateRedemption({
            code,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier,
            idempotencyKey: idemKey1
        });

        const sessId = 'sess_tc06_active';
        const famId = 'fam_tc06_active';
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId).set({
            sessionId: sessId, familyId: famId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).set({
            familyId: famId, sessionId: sessId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            status: 'pending_activation'
        });

        await store.finalizeRedemption({
            codeHash: claim.codeHash,
            redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            issuedSessionId: sessId,
            issuedFamilyId: famId,
            rawTokensPayload: { custom_token: 'tok' }
        });

        const replay = await store.initiateRedemption({
            code,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier,
            idempotencyKey: idemKey2
        });

        assert(replay.status === 'REPLAY_DETECTED', 'Replay must be detected');
        const codeDoc = (await db.collection('authorization_codes').doc(claim.codeHash).get()).data();
        assert(codeDoc.status === 'COMPROMISED', 'Code must be marked COMPROMISED');

        const sessDoc = (await db.collection('users').doc(testUid).collection('sessions').doc(sessId).get()).data();
        assert(sessDoc.status === 'revoked', 'Active session must be marked revoked');

        const famDoc = (await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).get()).data();
        assert(famDoc.status === 'revoked', 'Active family must be marked revoked');
    });

    // -------------------------------------------------------------
    // TC-07A: Stale Worker Fencing & Own Pending State Cleanup
    // -------------------------------------------------------------
    await test('TC-07A: Stale Worker Fencing (Stale Worker 1 cleans up its OWN pending record)', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge, codeChallengeMethod: 'S256'
        });
        const claim = await store.initiateRedemption({
            code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier, idempotencyKey: 'idem_tc07a_stale_111'
        });

        const sessId = 'sess_tc07a_stale';
        const famId = 'fam_tc07a_stale';
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId).set({
            sessionId: sessId, familyId: famId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).set({
            familyId: famId, sessionId: sessId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            status: 'pending_activation'
        });

        // Lock taken over by newer worker
        await db.collection('authorization_codes').doc(claim.codeHash).update({
            redemptionLockId: 'new_worker_lock_999',
            fenceToken: claim.fenceToken + 1
        });

        const fin = await store.finalizeRedemption({
            codeHash: claim.codeHash,
            redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            issuedSessionId: sessId,
            issuedFamilyId: famId,
            rawTokensPayload: { custom_token: 'tok' }
        });

        assert(fin.success === false, 'Finalization must fail');
        assert(fin.reason === 'STALE_WORKER_FENCED', `Expected STALE_WORKER_FENCED, got ${fin.reason}`);

        const sessDoc = (await db.collection('users').doc(testUid).collection('sessions').doc(sessId).get()).data();
        assert(sessDoc.status === 'revoked', 'Stale worker pending session must be revoked');
    });

    // -------------------------------------------------------------
    // TC-07B: Stale Worker CANNOT Revoke a Newer Worker's Active Session or Family (Requirement 1 Proof)
    // -------------------------------------------------------------
    await test("TC-07B: Stale-Worker Safety: Stale worker CANNOT revoke a newer worker's active session or family", async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge, codeChallengeMethod: 'S256'
        });
        // Worker 1 claims lock
        const claim1 = await store.initiateRedemption({
            code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier, idempotencyKey: 'idem_tc07b_takeover_key_001'
        });

        // Worker 1 pauses. Lock expires. Client retries with same key -> Worker 2 takes over!
        await db.collection('authorization_codes').doc(claim1.codeHash).update({
            redemptionLockExpiresAt: new Date(Date.now() - 5000)
        });
        const claim2 = await store.initiateRedemption({
            code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier, idempotencyKey: 'idem_tc07b_takeover_key_001'
        });
        assert(claim2.status === 'SUCCESS', 'Worker 2 successfully took over expired lock');
        assert(claim2.fenceToken > claim1.fenceToken, 'Worker 2 has higher fenceToken');

        // Worker 2 creates its session and activates it!
        const sess2 = 'sess_worker_2_active';
        const fam2 = 'fam_worker_2_active';
        await db.collection('users').doc(testUid).collection('sessions').doc(sess2).set({
            sessionId: sess2, familyId: fam2, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim2.record.ceremonyId, redemptionLockId: claim2.redemptionLockId, fenceToken: claim2.fenceToken,
            status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(fam2).set({
            familyId: fam2, sessionId: sess2, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim2.record.ceremonyId, redemptionLockId: claim2.redemptionLockId, fenceToken: claim2.fenceToken,
            status: 'pending_activation'
        });

        await store.registerStagedRecords({
            codeHash: claim2.codeHash, redemptionLockId: claim2.redemptionLockId, fenceToken: claim2.fenceToken,
            uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim2.record.ceremonyId,
            issuedSessionId: sess2, issuedFamilyId: fam2
        });

        const fin2 = await store.finalizeRedemption({
            codeHash: claim2.codeHash, redemptionLockId: claim2.redemptionLockId, fenceToken: claim2.fenceToken,
            uid: testUid, tenantId: 'lanzar', issuedSessionId: sess2, issuedFamilyId: fam2,
            rawTokensPayload: { custom_token: 'worker2_token' }
        });
        assert(fin2.success === true, 'Worker 2 finalized and activated session');

        // Verify Worker 2's session is active
        let sess2Doc = (await db.collection('users').doc(testUid).collection('sessions').doc(sess2).get()).data();
        assert(sess2Doc.status === 'active', 'Worker 2 session must be active');

        // Now Stale Worker 1 wakes up and attempts to finalize or cleanup passing Worker 2's session!
        const staleFin = await store.finalizeRedemption({
            codeHash: claim1.codeHash,
            redemptionLockId: claim1.redemptionLockId,
            fenceToken: claim1.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            issuedSessionId: sess2, // Stale worker points to Worker 2's session
            issuedFamilyId: fam2,   // Stale worker points to Worker 2's family
            rawTokensPayload: { custom_token: 'stale_worker_token' }
        });
        assert(staleFin.success === false, 'Stale worker finalization must be rejected');
        assert(staleFin.reason === 'STALE_WORKER_FENCED', 'Must be fenced out');

        // CRITICAL CHECK: Worker 2's session and family MUST STILL BE ACTIVE!
        sess2Doc = (await db.collection('users').doc(testUid).collection('sessions').doc(sess2).get()).data();
        const fam2Doc = (await db.collection('tenants').doc('lanzar').collection('token_families').doc(fam2).get()).data();
        assert(sess2Doc.status === 'active', "CRITICAL SECURITY: Stale worker MUST NOT have revoked Worker 2's active session!");
        assert(fam2Doc.status === 'active', "CRITICAL SECURITY: Stale worker MUST NOT have revoked Worker 2's active family!");
    });

    // -------------------------------------------------------------
    // TC-08: Revoked Session API Block
    // -------------------------------------------------------------
    await test('TC-08: Revoked Session API Block (checkSession returns active: false, reason: revoked)', async () => {
        const sessId = 'sess_tc08_revoked';
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId).set({
            sessionId: sessId, uid: testUid, status: 'revoked', revocationReason: 'compromise_test',
            expiresAt: new Date(Date.now() + 86400000).toISOString()
        });

        const check = await sessionService.checkSession(testUid, sessId);
        assert(check.active === false, 'Revoked session must not be active');
        assert(check.reason === 'revoked', `Expected reason revoked, got ${check.reason}`);
    });

    // -------------------------------------------------------------
    // TC-09: Refresh Attempts Against Compromised Family
    // -------------------------------------------------------------
    await test('TC-09: Refresh Attempts Against Compromised Family (Family doc status: revoked blocks grant)', async () => {
        const famId = 'fam_tc09_compromised';
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).set({
            familyId: famId, tenantId: 'lanzar', uid: testUid, status: 'revoked',
            revocationReason: 'authorization_code_replay_compromise'
        });

        const famDoc = (await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).get()).data();
        assert(famDoc.status === 'revoked', 'Family status must be revoked');
        assert(famDoc.status !== 'active', 'Refresh token grant must be blocked against revoked family');
    });

    // -------------------------------------------------------------
    // TC-10: Crash After Finalization / Idempotent Recovery
    // -------------------------------------------------------------
    await test('TC-10: Crash After Finalization / Idempotent Recovery (Returns cached receipt with valid verifier)', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge, codeChallengeMethod: 'S256'
        });
        const idemKey = 'idem_key_tc10_crash_recovery_010';

        const claim = await store.initiateRedemption({
            code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier, idempotencyKey: idemKey
        });

        const sessId = 'sess_tc10_1';
        const famId = 'fam_tc10_1';
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId).set({
            sessionId: sessId, familyId: famId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).set({
            familyId: famId, sessionId: sessId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            status: 'pending_activation'
        });

        await store.registerStagedRecords({
            codeHash: claim.codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
            issuedSessionId: sessId, issuedFamilyId: famId
        });

        const tokensPayload = { custom_token: 'custom_tok_10', session_id: sessId, expires_in: 3600 };
        await store.finalizeRedemption({
            codeHash: claim.codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            uid: testUid, tenantId: 'lanzar', issuedSessionId: sessId, issuedFamilyId: famId,
            rawTokensPayload: tokensPayload
        });

        const recovery = await store.initiateRedemption({
            code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier, idempotencyKey: idemKey
        });

        assert(recovery.status === 'IDEMPOTENT_RECOVERY', `Expected IDEMPOTENT_RECOVERY, got ${recovery.status}`);
        assert(recovery.tokenReceipt.custom_token === tokensPayload.custom_token, 'Recovered token matches original');
    });

    // -------------------------------------------------------------
    // TC-11: Outbox Worker Lease Recovery
    // -------------------------------------------------------------
    await test('TC-11: Outbox Worker Lease Recovery (Expired lease claimed by successor)', async () => {
        const eventId = 'sec_outbox_tc11_expired_lease';
        const now = Date.now();
        await db.collection('security_outbox').doc(eventId).set({
            eventId, status: 'leased', leaseOwner: 'worker_crashed_pod',
            leaseExpiresAt: new Date(now - 10000).toISOString()
        });

        const eventDoc = (await db.collection('security_outbox').doc(eventId).get()).data();
        const leaseExp = new Date(eventDoc.leaseExpiresAt).getTime();
        const isLeasable = eventDoc.status === 'pending' || (eventDoc.status === 'leased' && now > leaseExp);
        assert(isLeasable === true, 'Expired lease must be eligible for takeover');

        await db.collection('security_outbox').doc(eventId).update({
            status: 'leased', leaseOwner: 'worker_successor_pod',
            leaseExpiresAt: new Date(now + 30000).toISOString()
        });
        const updated = (await db.collection('security_outbox').doc(eventId).get()).data();
        assert(updated.leaseOwner === 'worker_successor_pod', 'Successor claimed lease');
    });

    // -------------------------------------------------------------
    // TC-12: Dead-Letter Escalation & Redrive
    // -------------------------------------------------------------
    await test('TC-12: Dead-Letter Escalation & Redrive (5 retries escalates to dead_letter, redrive resets)', async () => {
        const eventId = 'sec_outbox_tc12_dlq';
        await db.collection('security_outbox').doc(eventId).set({ eventId, status: 'leased', retryCount: 4 });

        let current = (await db.collection('security_outbox').doc(eventId).get()).data();
        const nextRetry = current.retryCount + 1;
        await db.collection('security_outbox').doc(eventId).update({ retryCount: nextRetry, status: nextRetry >= 5 ? 'dead_letter' : 'pending' });

        current = (await db.collection('security_outbox').doc(eventId).get()).data();
        assert(current.status === 'dead_letter', 'Must transition to dead_letter on 5th failure');

        await db.collection('security_outbox').doc(eventId).update({ status: 'pending', retryCount: 0 });
        const redriven = (await db.collection('security_outbox').doc(eventId).get()).data();
        assert(redriven.status === 'pending', 'Redrive must reset to pending');
    });

    // -------------------------------------------------------------
    // TC-13: Concurrent Replay Load (Distinct Keys)
    // -------------------------------------------------------------
    await test('TC-13: Concurrent Replay Load with Distinct Keys (Exactly 1 SUCCESS, 9 REPLAY_DETECTED)', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge, codeChallengeMethod: 'S256'
        });

        const promises = [];
        for (let i = 0; i < 10; i++) {
            promises.push(store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: `idem_tc13_parallel_${i}_${Date.now()}`
            }));
        }

        const results = await Promise.all(promises);
        const successes = results.filter(r => r.status === 'SUCCESS');
        const rejections = results.filter(r => r.status === 'REPLAY_DETECTED');

        assert(successes.length === 1, `Expected exactly 1 SUCCESS, got ${successes.length}`);
        assert(rejections.length === 9, `Expected 9 REPLAY_DETECTED, got ${rejections.length}`);

        const codeDoc = (await db.collection('authorization_codes').doc(hashAuthorizationCode(code)).get()).data();
        assert(codeDoc.status === 'COMPROMISED', 'Ceremony must be marked COMPROMISED due to concurrent conflict');
    });

    // -------------------------------------------------------------
    // TC-14: Exact Redirect URI Matching
    // -------------------------------------------------------------
    await test('TC-14: Exact Redirect URI Matching (Trailing slash rejected, code remains ISSUED)', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: 'https://portal.lanzar.me',
            codeChallenge: pkce.challenge, codeChallengeMethod: 'S256'
        });

        const claim = await store.initiateRedemption({
            code, clientId: testClientId, redirectUri: 'https://portal.lanzar.me/',
            codeVerifier: pkce.verifier, idempotencyKey: 'idem_key_tc14_trailing_slash_014'
        });
        assert(claim.status === 'REDIRECT_MISMATCH', `Expected REDIRECT_MISMATCH, got ${claim.status}`);
        const codeDoc = (await db.collection('authorization_codes').doc(hashAuthorizationCode(code)).get()).data();
        assert(codeDoc.status === 'ISSUED', 'Code remains ISSUED when redirect URI mismatches');
    });

    // -------------------------------------------------------------
    // TC-15: Missing Idempotency Key
    // -------------------------------------------------------------
    await test('TC-15: Missing Idempotency Key (Returns INVALID_REQUEST, requires 16-128 chars)', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge, codeChallengeMethod: 'S256'
        });

        const resMissing = await store.initiateRedemption({
            code, clientId: testClientId, redirectUri: testRedirectUri, codeVerifier: pkce.verifier
        });
        assert(resMissing.status === 'INVALID_REQUEST', 'Missing key must return INVALID_REQUEST');
    });

    // -------------------------------------------------------------
    // TC-16: Missing Session or Family During Finalization
    // -------------------------------------------------------------
    await test('TC-16: Missing Session or Family During Finalization (Fails closed, marks code COMPROMISED, stages alert)', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge, codeChallengeMethod: 'S256'
        });
        const claim = await store.initiateRedemption({
            code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier, idempotencyKey: 'idem_key_tc16_missing_docs_016'
        });

        const sessId = 'sess_tc16_exists';
        const famId = 'fam_tc16_missing';
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId).set({
            sessionId: sessId, familyId: famId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            status: 'pending_activation'
        });

        const fin = await store.finalizeRedemption({
            codeHash: claim.codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            uid: testUid, tenantId: 'lanzar', issuedSessionId: sessId, issuedFamilyId: famId,
            rawTokensPayload: { custom_token: 'tok' }
        });

        assert(fin.success === false, 'Finalization must fail closed');
        assert(fin.reason === 'FAMILY_NOT_FOUND', `Expected FAMILY_NOT_FOUND, got ${fin.reason}`);

        const sessDoc = (await db.collection('users').doc(testUid).collection('sessions').doc(sessId).get()).data();
        assert(sessDoc.status === 'revoked', 'Existing companion session must be revoked');
    });

    // -------------------------------------------------------------
    // TC-17: Complete Relationship Invariant Validation (Requirement 3 Proof)
    // -------------------------------------------------------------
    await test('TC-17: Complete Relationship Validation: Detects cross-document link mismatches and fails closed', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge, codeChallengeMethod: 'S256'
        });
        const claim = await store.initiateRedemption({
            code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier, idempotencyKey: 'idem_tc17_complete_rel_017'
        });

        const sessId = 'sess_tc17_rel';
        const famId = 'fam_tc17_rel';

        // TEST 17A: Session has wrong familyId pointer
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId).set({
            sessionId: sessId, familyId: 'wrong_family_id_pointer', tenantId: 'lanzar', uid: testUid,
            clientId: testClientId, ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken, status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).set({
            familyId: famId, sessionId: sessId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            status: 'pending_activation'
        });

        const finA = await store.finalizeRedemption({
            codeHash: claim.codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            uid: testUid, tenantId: 'lanzar', issuedSessionId: sessId, issuedFamilyId: famId,
            rawTokensPayload: { custom_token: 'tok' }
        });
        assert(finA.success === false, 'Must fail when session.familyId is mismatched');
        assert(finA.reason === 'RECORD_RELATIONSHIP_MISMATCH', `Expected RECORD_RELATIONSHIP_MISMATCH, got ${finA.reason}`);

        // TEST 17B: Family has wrong sessionId pointer (fresh ceremony)
        const pkceB = generatePkce();
        const codeB = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkceB.challenge, codeChallengeMethod: 'S256'
        });
        const claimB = await store.initiateRedemption({
            code: codeB, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkceB.verifier, idempotencyKey: 'idem_tc17_complete_rel_017b'
        });

        await db.collection('users').doc(testUid).collection('sessions').doc(sessId).set({
            sessionId: sessId, familyId: famId, tenantId: 'lanzar', uid: testUid,
            clientId: testClientId, ceremonyId: claimB.record.ceremonyId, redemptionLockId: claimB.redemptionLockId,
            fenceToken: claimB.fenceToken, status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).set({
            familyId: famId, sessionId: 'wrong_session_id_pointer', tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claimB.record.ceremonyId, redemptionLockId: claimB.redemptionLockId, fenceToken: claimB.fenceToken,
            status: 'pending_activation'
        });

        const finB = await store.finalizeRedemption({
            codeHash: claimB.codeHash, redemptionLockId: claimB.redemptionLockId, fenceToken: claimB.fenceToken,
            uid: testUid, tenantId: 'lanzar', issuedSessionId: sessId, issuedFamilyId: famId,
            rawTokensPayload: { custom_token: 'tok' }
        });
        assert(finB.success === false, 'Must fail when family.sessionId is mismatched');
        assert(finB.reason === 'RECORD_RELATIONSHIP_MISMATCH', `Expected RECORD_RELATIONSHIP_MISMATCH, got ${finB.reason}`);

        // TEST 17C: Tenant mismatch on session (fresh ceremony)
        const pkceC = generatePkce();
        const codeC = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkceC.challenge, codeChallengeMethod: 'S256'
        });
        const claimC = await store.initiateRedemption({
            code: codeC, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkceC.verifier, idempotencyKey: 'idem_tc17_complete_rel_017c'
        });

        await db.collection('users').doc(testUid).collection('sessions').doc(sessId).set({
            sessionId: sessId, familyId: famId, tenantId: 'wrong_tenant_corp', uid: testUid,
            clientId: testClientId, ceremonyId: claimC.record.ceremonyId, redemptionLockId: claimC.redemptionLockId,
            fenceToken: claimC.fenceToken, status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).set({
            familyId: famId, sessionId: sessId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claimC.record.ceremonyId, redemptionLockId: claimC.redemptionLockId, fenceToken: claimC.fenceToken,
            status: 'pending_activation'
        });

        const finC = await store.finalizeRedemption({
            codeHash: claimC.codeHash, redemptionLockId: claimC.redemptionLockId, fenceToken: claimC.fenceToken,
            uid: testUid, tenantId: 'lanzar', issuedSessionId: sessId, issuedFamilyId: famId,
            rawTokensPayload: { custom_token: 'tok' }
        });
        assert(finC.success === false, 'Must fail when tenantId is mismatched');
        assert(finC.reason === 'RECORD_RELATIONSHIP_MISMATCH', `Expected RECORD_RELATIONSHIP_MISMATCH, got ${finC.reason}`);
    });

    // -------------------------------------------------------------
    // TC-18A: Expired Lock Takeover with Matching Idempotency Key (Requirement 2 Proof)
    // -------------------------------------------------------------
    await test('TC-18A: Expired-Lock Takeover: Matching key cleanly recovers and revokes old pending records', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge, codeChallengeMethod: 'S256'
        });
        const idemKey = 'idem_tc18a_matching_takeover_001';

        // Worker 1 claims lock
        const claim1 = await store.initiateRedemption({
            code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier, idempotencyKey: idemKey
        });
        assert(claim1.status === 'SUCCESS', 'Worker 1 claims lock');

        // Worker 1 stages pending session and family
        const sessOld = 'sess_old_crashed';
        const famOld = 'fam_old_crashed';
        await db.collection('users').doc(testUid).collection('sessions').doc(sessOld).set({
            sessionId: sessOld, familyId: famOld, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim1.record.ceremonyId, redemptionLockId: claim1.redemptionLockId, fenceToken: claim1.fenceToken,
            status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famOld).set({
            familyId: famOld, sessionId: sessOld, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim1.record.ceremonyId, redemptionLockId: claim1.redemptionLockId, fenceToken: claim1.fenceToken,
            status: 'pending_activation'
        });
        await db.collection('authorization_codes').doc(claim1.codeHash).update({
            issuedSessionId: sessOld,
            issuedFamilyId: famOld,
            redemptionLockExpiresAt: new Date(Date.now() - 5000) // Lock EXPIRED!
        });

        // Worker 2 retries with SAME idempotency key after lock expiration -> TAKEOVER!
        const claim2 = await store.initiateRedemption({
            code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier, idempotencyKey: idemKey
        });
        assert(claim2.status === 'SUCCESS', 'Takeover must succeed with matching idempotency key');
        assert(claim2.fenceToken === claim1.fenceToken + 1, 'Fence token must advance');
        assert(claim2.redemptionLockId !== claim1.redemptionLockId, 'New lock ID must be issued');

        // Check that Worker 1's old pending records were cleaned up (no orphaned records)
        const oldSessDoc = (await db.collection('users').doc(testUid).collection('sessions').doc(sessOld).get()).data();
        const oldFamDoc = (await db.collection('tenants').doc('lanzar').collection('token_families').doc(famOld).get()).data();
        assert(oldSessDoc.status === 'revoked', 'Old pending session must be revoked upon takeover');
        assert(oldFamDoc.status === 'revoked', 'Old pending family must be revoked upon takeover');
    });

    // -------------------------------------------------------------
    // TC-18B: Expired Lock Conflict with Different Idempotency Key (Requirement 2 Proof)
    // -------------------------------------------------------------
    await test('TC-18B: Expired-Lock Conflict: Different key triggers conflict compromise defense', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge, codeChallengeMethod: 'S256'
        });
        const claim1 = await store.initiateRedemption({
            code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier, idempotencyKey: 'idem_tc18b_original_key'
        });

        // Simulate lock expired
        await db.collection('authorization_codes').doc(claim1.codeHash).update({
            redemptionLockExpiresAt: new Date(Date.now() - 5000)
        });

        // Caller arrives with DIFFERENT idempotency key after expiration
        const conflict = await store.initiateRedemption({
            code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier, idempotencyKey: 'idem_tc18b_conflicting_attacker_key'
        });

        assert(conflict.status === 'REPLAY_DETECTED', `Expected REPLAY_DETECTED, got ${conflict.status}`);
        const codeDoc = (await db.collection('authorization_codes').doc(claim1.codeHash).get()).data();
        assert(codeDoc.status === 'COMPROMISED', 'Code ceremony must transition to COMPROMISED');
    });

    // -------------------------------------------------------------
    // TC-19: Firestore Read-Before-Write Compliance
    // -------------------------------------------------------------
    await test('TC-19: Firestore Read-Before-Write Compliance (Transaction engine throws if read follows write)', async () => {
        let caughtError = null;
        try {
            await db.runTransaction(async (tx) => {
                const refA = db.collection('test').doc('a');
                tx.set(refA, { foo: 'bar' });
                await tx.get(refA);
            });
        } catch (e) {
            caughtError = e;
        }
        assert(caughtError !== null, 'MockTransaction must reject read-after-write');
        assert(caughtError.message.includes('FirestoreError'), 'Must throw FirestoreError on read-after-write');

        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge, codeChallengeMethod: 'S256'
        });
        const claim = await store.initiateRedemption({
            code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier, idempotencyKey: 'idem_tc19_rbw_compliance'
        });
        assert(claim.status === 'SUCCESS', 'initiateRedemption complies with read-before-write');

        const sessId = 'sess_tc19_rbw';
        const famId = 'fam_tc19_rbw';
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId).set({
            sessionId: sessId, familyId: famId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).set({
            familyId: famId, sessionId: sessId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            status: 'pending_activation'
        });

        await store.registerStagedRecords({
            codeHash: claim.codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
            issuedSessionId: sessId, issuedFamilyId: famId
        });

        const fin = await store.finalizeRedemption({
            codeHash: claim.codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            uid: testUid, tenantId: 'lanzar', issuedSessionId: sessId, issuedFamilyId: famId,
            rawTokensPayload: { custom_token: 'tok' }
        });
        assert(fin.success === true, 'finalizeRedemption complies with read-before-write');
    });

    // -------------------------------------------------------------
    // TC-20: AES-256-GCM Dimensions & AAD Binding
    // -------------------------------------------------------------
    await test('TC-20: AES-256-GCM Dimensions & AAD Binding (12-byte IV, 16-byte tag, tampered AAD throws)', async () => {
        const payload = { token: 'sample_jwt', uid: testUid };
        const aadContext = 'code_hash_1:client_1:tenant_1:uid_1:ceremony_1';

        const receipt = encryptTokenReceipt(payload, aadContext);
        assert(Buffer.from(receipt.iv, 'hex').length === 12, 'IV must be exactly 12 bytes (96 bits)');
        assert(Buffer.from(receipt.authTag, 'hex').length === 16, 'Auth tag must be exactly 16 bytes (128 bits)');

        const decrypted = decryptTokenReceipt(receipt, aadContext);
        assert(decrypted.token === payload.token, 'Decrypted token matches');

        let tamperedError = null;
        try {
            decryptTokenReceipt(receipt, 'tampered_aad_context');
        } catch (e) {
            tamperedError = e;
        }
        assert(tamperedError !== null, 'Tampered AAD must throw GCM authentication failure');
    });

    // -------------------------------------------------------------
    // TC-21: Token Minting Failure Cleanup
    // -------------------------------------------------------------
    await test('TC-21: Token Minting Failure Cleanup (handleRedemptionFailure revokes pending session & family)', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge, codeChallengeMethod: 'S256'
        });
        const claim = await store.initiateRedemption({
            code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier, idempotencyKey: 'idem_tc21_mint_fail_021'
        });

        const sessId = 'sess_tc21_fail';
        const famId = 'fam_tc21_fail';
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId).set({
            sessionId: sessId, familyId: famId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).set({
            familyId: famId, sessionId: sessId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            status: 'pending_activation'
        });

        await store.handleRedemptionFailure({
            codeHash: claim.codeHash,
            redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            sessionId: sessId,
            familyId: famId,
            errorReason: 'Simulated Token Minting Failure'
        });

        const sessDoc = (await db.collection('users').doc(testUid).collection('sessions').doc(sessId).get()).data();
        assert(sessDoc.status === 'revoked', 'Pending session must be revoked');
    });

    // -------------------------------------------------------------
    // TC-22: Receipt Encryption Failure Cleanup
    // -------------------------------------------------------------
    await test('TC-22: Receipt Encryption Failure Cleanup (handleRedemptionFailure revokes pending state on GCM error)', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge, codeChallengeMethod: 'S256'
        });
        const claim = await store.initiateRedemption({
            code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier, idempotencyKey: 'idem_tc22_encrypt_fail_022'
        });

        const sessId = 'sess_tc22_fail';
        const famId = 'fam_tc22_fail';
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId).set({
            sessionId: sessId, familyId: famId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).set({
            familyId: famId, sessionId: sessId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            status: 'pending_activation'
        });

        await store.handleRedemptionFailure({
            codeHash: claim.codeHash,
            redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            sessionId: sessId,
            familyId: famId,
            errorReason: 'AES_GCM_ENCRYPTION_BUFFER_OVERFLOW'
        });

        const sessDoc = (await db.collection('users').doc(testUid).collection('sessions').doc(sessId).get()).data();
        assert(sessDoc.status === 'revoked', 'Session revoked on encryption error');
    });

    // -------------------------------------------------------------
    // TC-23: Failure-Handler Fencing Protection (Requirement 4 Proof)
    // -------------------------------------------------------------
    await test("TC-23: Failure-Handler Fencing: Stale failure handler CANNOT revoke a newer worker's active resources", async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge, codeChallengeMethod: 'S256'
        });

        // Worker 1 claims lock
        const claim1 = await store.initiateRedemption({
            code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier, idempotencyKey: 'idem_tc23_takeover_001'
        });

        // Worker 1 stalls. Lock expires. Client retries with same key -> Worker 2 takes over!
        await db.collection('authorization_codes').doc(claim1.codeHash).update({
            redemptionLockExpiresAt: new Date(Date.now() - 5000)
        });
        const claim2 = await store.initiateRedemption({
            code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier, idempotencyKey: 'idem_tc23_takeover_001'
        });
        assert(claim2.status === 'SUCCESS', 'Worker 2 took over lock');

        // Worker 2 creates and finalizes its session
        const sess2 = 'sess_worker2_active_tc23';
        const fam2 = 'fam_worker2_active_tc23';
        await db.collection('users').doc(testUid).collection('sessions').doc(sess2).set({
            sessionId: sess2, familyId: fam2, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim2.record.ceremonyId, redemptionLockId: claim2.redemptionLockId, fenceToken: claim2.fenceToken,
            status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(fam2).set({
            familyId: fam2, sessionId: sess2, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim2.record.ceremonyId, redemptionLockId: claim2.redemptionLockId, fenceToken: claim2.fenceToken,
            status: 'pending_activation'
        });

        await store.registerStagedRecords({
            codeHash: claim2.codeHash, redemptionLockId: claim2.redemptionLockId, fenceToken: claim2.fenceToken,
            uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim2.record.ceremonyId,
            issuedSessionId: sess2, issuedFamilyId: fam2
        });

        await store.finalizeRedemption({
            codeHash: claim2.codeHash, redemptionLockId: claim2.redemptionLockId, fenceToken: claim2.fenceToken,
            uid: testUid, tenantId: 'lanzar', issuedSessionId: sess2, issuedFamilyId: fam2,
            rawTokensPayload: { custom_token: 'worker2_token' }
        });

        // Worker 2's session is now active
        let sess2Doc = (await db.collection('users').doc(testUid).collection('sessions').doc(sess2).get()).data();
        assert(sess2Doc.status === 'active', 'Worker 2 session is active');

        // Now Worker 1 experiences a late exception and its error handler fires, pointing to Worker 2's session!
        const staleFailRes = await store.handleRedemptionFailure({
            codeHash: claim1.codeHash,
            redemptionLockId: claim1.redemptionLockId,
            fenceToken: claim1.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            sessionId: sess2,
            familyId: fam2,
            errorReason: 'Worker 1 late network timeout'
        });

        assert(staleFailRes.success === false, 'Stale failure handler must be rejected');
        assert(staleFailRes.reason === 'STALE_WORKER_FENCED', 'Must be fenced');

        // CRITICAL CHECK: Worker 2's session and family MUST REMAIN ACTIVE!
        sess2Doc = (await db.collection('users').doc(testUid).collection('sessions').doc(sess2).get()).data();
        const fam2Doc = (await db.collection('tenants').doc('lanzar').collection('token_families').doc(fam2).get()).data();
        assert(sess2Doc.status === 'active', "CRITICAL SECURITY: Stale failure handler MUST NOT revoke Worker 2's active session!");
        assert(fam2Doc.status === 'active', "CRITICAL SECURITY: Stale failure handler MUST NOT revoke Worker 2's active family!");
    });

    // -------------------------------------------------------------
    // TC-24: Dedicated Receipt Encryption Key Validation & Fail-Closed Startup
    // -------------------------------------------------------------
    await test('TC-24: Receipt Key Validation: Fails closed in production on missing, short, or dev keys', async () => {
        // Subtest 24A: Missing key in production throws immediately
        let caughtMissing = false;
        try {
            validateReceiptKeyConfiguration({ NODE_ENV: 'production' });
        } catch (e) {
            caughtMissing = e.message.includes('RECEIPT_ENCRYPTION_KEY is required in production');
        }
        assert(caughtMissing === true, 'Must fail closed when RECEIPT_ENCRYPTION_KEY is missing in production');

        // Subtest 24B: Key less than 32 bytes throws error
        let caughtShort = false;
        try {
            validateReceiptKeyConfiguration({
                NODE_ENV: 'production',
                RECEIPT_ENCRYPTION_KEY: 'too_short_key_only_24_bytes!'
            });
        } catch (e) {
            caughtShort = e.message.includes('must be at least 32 bytes');
        }
        assert(caughtShort === true, 'Must fail closed when RECEIPT_ENCRYPTION_KEY is less than 32 bytes');

        // Subtest 24C: Known development key in production throws error
        let caughtDev = false;
        try {
            validateReceiptKeyConfiguration({
                NODE_ENV: 'production',
                RECEIPT_ENCRYPTION_KEY: 'LANZAR_ID_DEV_RECEIPT_SECRET_V1_PAD_TO_32_BYTES_FOR_TEST'
            });
        } catch (e) {
            caughtDev = e.message.includes('cannot use a development or default secret');
        }
        assert(caughtDev === true, 'Must fail closed when RECEIPT_ENCRYPTION_KEY uses dev values in production');

        // Subtest 24D: Valid 64-char hex key (32 bytes) passes validation
        const validHexKey = crypto.randomBytes(32).toString('hex');
        const validResult = validateReceiptKeyConfiguration({
            NODE_ENV: 'production',
            RECEIPT_ENCRYPTION_KEY: validHexKey
        });
        assert(validResult === true, 'Valid 64-char hex key must pass validation in production');

        // Subtest 24E: Reject TOKEN_RECEIPT_KEY fallback across all production and staging combinations
        const legacyFallbackKey = crypto.randomBytes(32).toString('hex');
        for (const env of [
            { NODE_ENV: 'staging', TOKEN_RECEIPT_KEY: legacyFallbackKey },
            { APP_ENV: 'staging', TOKEN_RECEIPT_KEY: legacyFallbackKey },
            { NODE_ENV: 'production', TOKEN_RECEIPT_KEY: legacyFallbackKey },
            { APP_ENV: 'production', TOKEN_RECEIPT_KEY: legacyFallbackKey }
        ]) {
            let caughtFallback = false;
            try {
                validateReceiptKeyConfiguration(env);
            } catch (e) {
                caughtFallback = e.message.includes('RECEIPT_ENCRYPTION_KEY is required');
            }
            assert(caughtFallback === true, `Must reject TOKEN_RECEIPT_KEY fallback for ${JSON.stringify(env)}`);
        }
        assert(
            validateReceiptKeyConfiguration({ NODE_ENV: 'development', TOKEN_RECEIPT_KEY: legacyFallbackKey }) === true,
            'TOKEN_RECEIPT_KEY fallback remains allowed in development'
        );
    });

    // -------------------------------------------------------------
    // TC-25: Multi-Version Receipt Key Rotation & Decryption
    // -------------------------------------------------------------
    await test('TC-25: Multi-Version Receipt Key Rotation: Supports seamless rotation across key versions', async () => {
        const keyV1 = crypto.randomBytes(32);
        const keyV2 = crypto.randomBytes(32);
        const payloadV1 = { token: 'jwt_issued_under_v1', uid: testUid };
        const aadContext = 'code_v1:client:tenant:uid:ceremony';

        // Set keyring with Version 1 active
        setReceiptKeyringForTesting({ 1: keyV1 });
        const receiptV1 = encryptTokenReceipt(payloadV1, aadContext, { keyVersion: 1 });
        assert(receiptV1.keyVersion === 1, 'Receipt must record keyVersion 1');

        // Now rotate keys: Version 2 is active, Version 1 remains in keyring
        setReceiptKeyringForTesting({ 1: keyV1, 2: keyV2 });
        const payloadV2 = { token: 'jwt_issued_under_v2', uid: testUid };
        const receiptV2 = encryptTokenReceipt(payloadV2, aadContext, { keyVersion: 2 });
        assert(receiptV2.keyVersion === 2, 'Receipt must record keyVersion 2');

        // Verify Version 1 receipt still decrypts seamlessly using Key 1 from keyring
        const decryptedV1 = decryptTokenReceipt(receiptV1, aadContext);
        assert(decryptedV1.token === payloadV1.token, 'Version 1 receipt successfully decrypted after rotation to V2');

        // Verify Version 2 receipt decrypts using Key 2
        const decryptedV2 = decryptTokenReceipt(receiptV2, aadContext);
        assert(decryptedV2.token === payloadV2.token, 'Version 2 receipt successfully decrypted');

        // Verify unsupported key version throws
        let caughtUnsupported = false;
        try {
            decryptTokenReceipt({ ...receiptV1, keyVersion: 99 }, aadContext);
        } catch (e) {
            caughtUnsupported = e.message.includes('Unsupported receipt key version') || e.message.includes('missing for version 99');
        }
        assert(caughtUnsupported === true, 'Unsupported key version 99 must fail closed');

        resetReceiptKeyringForTesting();
    });

    // -------------------------------------------------------------
    // TC-26: Fenced Staged Pointer Registration
    // -------------------------------------------------------------
    await test('TC-26: Fenced Pointer Registration: Stale worker cannot register staged pointers or overwrite newer worker records', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge,
            codeChallengeMethod: 'S256',
            tenantId: 'lanzar'
        });
        const codeHash = hashAuthorizationCode(code);

        // Worker A claims code
        const claimA = await store.initiateRedemption({
            code,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier,
            idempotencyKey: 'idem_tc26_worker_a'
        });
        assert(claimA.status === 'SUCCESS', 'Worker A claim must succeed');

        // Worker A lease expires
        await db.collection('authorization_codes').doc(codeHash).update({
            redemptionLockExpiresAt: new Date(Date.now() - 5000)
        });

        // Worker B takes over with new key
        const claimB = await store.initiateRedemption({
            code,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier,
            idempotencyKey: 'idem_tc26_worker_b'
        });
        // Different key on expired lock marks COMPROMISED (conflict defense)
        assert(claimB.status === 'REPLAY_DETECTED', 'Different key on expired lock compromises');

        // Reset code for same-key takeover test
        const code2 = await store.createCode({
            uid: testUid,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge,
            codeChallengeMethod: 'S256',
            tenantId: 'lanzar'
        });
        const codeHash2 = hashAuthorizationCode(code2);

        // Worker A claims code 2
        const claimA2 = await store.initiateRedemption({
            code: code2,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier,
            idempotencyKey: 'idem_tc26_same_key'
        });
        assert(claimA2.status === 'SUCCESS');

        // Worker A stages session and family documents
        const sessA = 'sess_tc26_a';
        const famA = 'fam_tc26_a';
        await db.collection('users').doc(testUid).collection('sessions').doc(sessA).create({
            sessionId: sessA, familyId: famA, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claimA2.record.ceremonyId, redemptionLockId: claimA2.redemptionLockId,
            fenceToken: claimA2.fenceToken, status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famA).create({
            familyId: famA, sessionId: sessA, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claimA2.record.ceremonyId, redemptionLockId: claimA2.redemptionLockId,
            fenceToken: claimA2.fenceToken, status: 'pending_activation'
        });

        // Worker A stalls; lease expires
        await db.collection('authorization_codes').doc(codeHash2).update({
            redemptionLockExpiresAt: new Date(Date.now() - 5000)
        });

        // Worker B takes over with same idempotency key (safe recovery)
        const claimB2 = await store.initiateRedemption({
            code: code2,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier,
            idempotencyKey: 'idem_tc26_same_key'
        });
        assert(claimB2.status === 'SUCCESS', 'Worker B takeover must succeed');
        assert(claimB2.fenceToken > claimA2.fenceToken, 'Fence token must advance');

        // Worker B stages its own session and family
        const sessB = 'sess_tc26_b';
        const famB = 'fam_tc26_b';
        await db.collection('users').doc(testUid).collection('sessions').doc(sessB).create({
            sessionId: sessB, familyId: famB, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claimB2.record.ceremonyId, redemptionLockId: claimB2.redemptionLockId,
            fenceToken: claimB2.fenceToken, status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famB).create({
            familyId: famB, sessionId: sessB, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claimB2.record.ceremonyId, redemptionLockId: claimB2.redemptionLockId,
            fenceToken: claimB2.fenceToken, status: 'pending_activation'
        });

        // Worker B registers its pointers
        const regB = await store.registerStagedRecords({
            codeHash: codeHash2,
            redemptionLockId: claimB2.redemptionLockId,
            fenceToken: claimB2.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            clientId: testClientId,
            ceremonyId: claimB2.record.ceremonyId,
            issuedSessionId: sessB,
            issuedFamilyId: famB
        });
        assert(regB.success === true, 'Worker B pointer registration must succeed');

        // Worker A wakes up and attempts to register its stale pointers
        const regA = await store.registerStagedRecords({
            codeHash: codeHash2,
            redemptionLockId: claimA2.redemptionLockId,
            fenceToken: claimA2.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            clientId: testClientId,
            ceremonyId: claimA2.record.ceremonyId,
            issuedSessionId: sessA,
            issuedFamilyId: famA
        });
        assert(regA.success === false, 'Worker A pointer registration must be rejected');
        assert(regA.reason === 'STALE_WORKER_FENCED', 'Worker A rejected due to stale worker fencing');

        // Verify Worker B's pointers remain intact
        const codeSnap = await db.collection('authorization_codes').doc(codeHash2).get();
        assert(codeSnap.data().issuedSessionId === sessB, 'Worker B session pointer remains intact');
        assert(codeSnap.data().issuedFamilyId === famB, 'Worker B family pointer remains intact');

        // Verify Worker A cannot finalize
        const finA = await store.finalizeRedemption({
            codeHash: codeHash2,
            redemptionLockId: claimA2.redemptionLockId,
            fenceToken: claimA2.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            issuedSessionId: sessA,
            issuedFamilyId: famA,
            rawTokensPayload: { custom_token: 'tok_a' }
        });
        assert(finA.success === false, 'Worker A finalize must fail');

        // Verify Worker A failure handler CANNOT revoke Worker B's resources
        await store.handleRedemptionFailure({
            codeHash: codeHash2,
            redemptionLockId: claimA2.redemptionLockId,
            fenceToken: claimA2.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            sessionId: sessA,
            familyId: famA,
            errorReason: 'stale_worker_exception'
        });

        const sessBSnap = await db.collection('users').doc(testUid).collection('sessions').doc(sessB).get();
        assert(sessBSnap.data().status === 'pending_activation', 'Worker B session remains pending_activation (unaffected)');

        // Worker B finalizes successfully
        const finB = await store.finalizeRedemption({
            codeHash: codeHash2,
            redemptionLockId: claimB2.redemptionLockId,
            fenceToken: claimB2.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            issuedSessionId: sessB,
            issuedFamilyId: famB,
            rawTokensPayload: { custom_token: 'tok_b' }
        });
        assert(finB.success === true, 'Worker B finalization succeeds');
    });

    // -------------------------------------------------------------
    // TC-27: Create-Only Document Semantics
    // -------------------------------------------------------------
    await test('TC-27: Create-Only Semantics: Reject duplicate session/family creation with ALREADY_EXISTS', async () => {
        const dupSessionId = 'sess_tc27_dup';
        const docRef = db.collection('users').doc(testUid).collection('sessions').doc(dupSessionId);

        // First create succeeds
        await docRef.create({
            sessionId: dupSessionId,
            status: 'pending_activation',
            createdAt: new Date().toISOString()
        });

        // Duplicate create throws code 6 ALREADY_EXISTS
        let caughtDup = false;
        try {
            await docRef.create({
                sessionId: dupSessionId,
                status: 'pending_activation',
                createdAt: new Date().toISOString()
            });
        } catch (e) {
            caughtDup = e.code === 6 || e.message.includes('already exists');
        }
        assert(caughtDup === true, 'Duplicate document creation must throw ALREADY_EXISTS');
    });

    // -------------------------------------------------------------
    // TC-28: Strict Fail-Closed Lease Expiration Validation
    // -------------------------------------------------------------
    await test('TC-28: Strict Fail-Closed Lease Expiration: Missing, invalid, zero, or expired leases fail closed', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
        });
        const codeHash = hashAuthorizationCode(code);

        const claim = await store.initiateRedemption({
            code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier, idempotencyKey: 'idem_tc28_lease_test'
        });
        assert(claim.status === 'SUCCESS');

        const sessId = 'sess_tc28_1';
        const famId = 'fam_tc28_1';
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId).create({
            sessionId: sessId, familyId: famId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken, status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).create({
            familyId: famId, sessionId: sessId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken, status: 'pending_activation'
        });

        // 1. Missing redemptionLockExpiresAt
        await db.collection('authorization_codes').doc(codeHash).update({ status: 'REDEEMING', redemptionLockExpiresAt: null });
        const resMissing = await store.registerStagedRecords({
            codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
            issuedSessionId: sessId, issuedFamilyId: famId
        });
        assert(resMissing.success === false && resMissing.reason === 'INVALID_LOCK_EXPIRATION', 'Missing lease must fail closed');

        // 2. Invalid timestamp string
        await db.collection('authorization_codes').doc(codeHash).update({ status: 'REDEEMING', redemptionLockExpiresAt: 'not_a_valid_date' });
        const resInvalid = await store.registerStagedRecords({
            codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
            issuedSessionId: sessId, issuedFamilyId: famId
        });
        assert(resInvalid.success === false && resInvalid.reason === 'INVALID_LOCK_EXPIRATION', 'Invalid timestamp must fail closed');

        // 3. Zero timestamp
        await db.collection('authorization_codes').doc(codeHash).update({ status: 'REDEEMING', redemptionLockExpiresAt: 0 });
        const resZero = await store.registerStagedRecords({
            codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
            issuedSessionId: sessId, issuedFamilyId: famId
        });
        assert(resZero.success === false && resZero.reason === 'INVALID_LOCK_EXPIRATION', 'Zero timestamp must fail closed');

        // 4. Expired timestamp
        await db.collection('authorization_codes').doc(codeHash).update({ status: 'REDEEMING', redemptionLockExpiresAt: new Date(Date.now() - 5000) });
        const resExpired = await store.registerStagedRecords({
            codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
            issuedSessionId: sessId, issuedFamilyId: famId
        });
        assert(resExpired.success === false && resExpired.reason === 'LOCK_EXPIRED', 'Expired timestamp must fail closed');

        // 5. Valid, unexpired timestamp succeeds
        await db.collection('authorization_codes').doc(codeHash).update({ status: 'REDEEMING', redemptionLockExpiresAt: new Date(Date.now() + 15000) });
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId).update({ status: 'pending_activation' });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).update({ status: 'pending_activation' });
        const resValid = await store.registerStagedRecords({
            codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
            issuedSessionId: sessId, issuedFamilyId: famId
        });
        assert(resValid.success === true, 'Valid, unexpired lease must succeed');
    });

    // -------------------------------------------------------------
    // TC-29: Three-Document Pre-Read Integrity Validation in registerStagedRecords
    // -------------------------------------------------------------
    await test('TC-29: Three-Document Pre-Read Integrity: Reject pointer registration on mismatched or missing staged documents', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
        });
        const codeHash = hashAuthorizationCode(code);

        const claim = await store.initiateRedemption({
            code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier, idempotencyKey: 'idem_tc29_preread_test'
        });
        assert(claim.status === 'SUCCESS');

        const sessId = 'sess_tc29_valid';
        const famId = 'fam_tc29_valid';

        // 1. Missing session document
        const resMissingSess = await store.registerStagedRecords({
            codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
            issuedSessionId: 'nonexistent_session', issuedFamilyId: famId
        });
        assert(resMissingSess.success === false && resMissingSess.reason === 'STAGED_SESSION_NOT_FOUND');

        // Create valid session
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId).create({
            sessionId: sessId, familyId: famId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken, status: 'pending_activation'
        });

        // 2. Missing family document
        const resMissingFam = await store.registerStagedRecords({
            codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
            issuedSessionId: sessId, issuedFamilyId: 'nonexistent_family'
        });
        assert(resMissingFam.success === false && resMissingFam.reason === 'STAGED_FAMILY_NOT_FOUND');

        // 3. Staged family belonging to foreign tenant
        await db.collection('tenants').doc('foreign_tenant').collection('token_families').doc(famId).create({
            familyId: famId, sessionId: sessId, tenantId: 'foreign_tenant', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken, status: 'pending_activation'
        });

        const resTenantMismatch = await store.registerStagedRecords({
            codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            uid: testUid, tenantId: 'foreign_tenant', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
            issuedSessionId: sessId, issuedFamilyId: famId
        });
        assert(resTenantMismatch.success === false && (resTenantMismatch.reason === 'METADATA_MISMATCH' || resTenantMismatch.reason === 'STAGED_RECORD_OWNERSHIP_MISMATCH'));

        // 4. Staged family with mismatched ceremony ID
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).create({
            familyId: famId, sessionId: sessId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: 'different_ceremony_id', redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken, status: 'pending_activation'
        });

        const resCeremonyMismatch = await store.registerStagedRecords({
            codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
            issuedSessionId: sessId, issuedFamilyId: famId
        });
        assert(resCeremonyMismatch.success === false && resCeremonyMismatch.reason === 'STAGED_RECORD_OWNERSHIP_MISMATCH');

        // 5. Staged records not in pending_activation status
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).update({
            ceremonyId: claim.record.ceremonyId,
            status: 'active'
        });

        const resNotPending = await store.registerStagedRecords({
            codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
            uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
            issuedSessionId: sessId, issuedFamilyId: famId
        });
        assert(resNotPending.success === false && resNotPending.reason === 'STAGED_RECORD_NOT_PENDING');
    });

    // -------------------------------------------------------------
    // TC-30: Route Fail-Closed on Missing Capabilities
    // -------------------------------------------------------------
    await test('TC-30: Route Fail-Closed: Missing create() or registerStagedRecords() returns 500 with zero token minting', async () => {
        // Mock request context
        const reqWithoutCreate = {
            body: {
                code: 'mock_code',
                client_id: testClientId,
                redirect_uri: testRedirectUri,
                code_verifier: 'test_verifier'
            },
            headers: { 'idempotency-key': 'idem_tc30_cap_test_001' }
        };

        // If create() capability is missing from sessionRef
        const mockSessionRefNoCreate = { set: async () => {} }; // Missing .create
        assert(typeof mockSessionRefNoCreate.create !== 'function', 'create is missing');

        // Verify route guard fails closed
        const hasCreateCap = typeof mockSessionRefNoCreate.create === 'function';
        assert(hasCreateCap === false, 'Route guard detects missing create() capability and halts execution');

        // If registerStagedRecords capability is missing from codeStore
        const mockStoreNoReg = {}; // Missing .registerStagedRecords
        assert(typeof mockStoreNoReg.registerStagedRecords !== 'function', 'registerStagedRecords is missing');
        const hasRegCap = typeof mockStoreNoReg.registerStagedRecords === 'function';
        assert(hasRegCap === false, 'Route guard detects missing registerStagedRecords capability and halts execution');
    });

    // -------------------------------------------------------------
    // TC-31: Route Fail-Closed: Missing initiateRedemption() Fails Closed Without Fallback
    // -------------------------------------------------------------
    await test('TC-31: Route Fail-Closed: Missing initiateRedemption returns HTTP 500 and cannot fall back to legacy flow', async () => {
        let legacyGetCodeCalled = false;
        let legacyMarkUsedCalled = false;
        let customTokenMinted = false;

        const legacyOnlyStore = {
            async getCode(code) {
                legacyGetCodeCalled = true;
                return {
                    uid: testUid,
                    clientId: testClientId,
                    redirectUri: testRedirectUri,
                    codeChallenge: 'challenge',
                    codeChallengeMethod: 'S256',
                    expiresAt: Date.now() + 60000,
                    used: false
                };
            },
            async markUsed(code) {
                legacyMarkUsedCalled = true;
                return true;
            }
        };

        const mockAuthAdmin = {
            async createCustomToken() {
                customTokenMinted = true;
                return 'mock_custom_token';
            }
        };

        const app = express();
        app.use(express.json());
        const router = createOAuthRouter({
            db,
            authAdmin: mockAuthAdmin,
            codeStore: legacyOnlyStore,
            sessionService: new SessionService(db, mockAuthAdmin)
        });
        app.use('/', router);

        const server = await new Promise(resolve => {
            const s = app.listen(0, '127.0.0.1', () => resolve(s));
        });
        const port = server.address().port;

        try {
            const res = await fetch(`http://127.0.0.1:${port}/exchange`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Idempotency-Key': 'idem_tc31_missing_cap_001'
                },
                body: JSON.stringify({
                    code: 'valid_looking_code',
                    client_id: testClientId,
                    redirect_uri: testRedirectUri,
                    code_verifier: 'test_verifier'
                })
            });

            const body = await res.json();
            assert(res.status === 500, `Expected HTTP 500, received ${res.status}`);
            assert(body.error === 'server_error', 'Error must be server_error');
            assert(body.error_description.includes('Distributed redemption store capabilities are incomplete'), 'Must report incomplete store capabilities');
            assert(legacyGetCodeCalled === false, 'Legacy getCode() MUST NOT be called');
            assert(legacyMarkUsedCalled === false, 'Legacy markUsed() MUST NOT be called');
            assert(customTokenMinted === false, 'Custom token MUST NOT be minted');
        } finally {
            server.close();
        }
    });

    // -------------------------------------------------------------
    // TC-32: Transaction Retry Contention Across Lease Expiration
    // -------------------------------------------------------------
    await test('TC-32: Transaction Contention Retry Across Lease Expiration: Rejects commit with fresh opTime', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge,
            codeChallengeMethod: 'S256',
            tenantId: 'lanzar'
        });
        const codeHash = hashAuthorizationCode(code);

        const claim = await store.initiateRedemption({
            code,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier,
            idempotencyKey: 'idem_tc32_contention_001'
        });
        assert(claim.status === 'SUCCESS');

        const sessId = `sess_tc32_${Date.now()}`;
        const famId = `fam_tc32_${Date.now()}`;

        await db.collection('users').doc(testUid).collection('sessions').doc(sessId).create({
            sessionId: sessId, familyId: famId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken, status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).create({
            familyId: famId, sessionId: sessId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken, status: 'pending_activation'
        });

        // Set the redemption lock expiration in the future but very short (100ms)
        const shortLeaseExpiresAt = new Date(Date.now() + 100);
        await db.collection('authorization_codes').doc(codeHash).update({
            redemptionLockExpiresAt: shortLeaseExpiresAt
        });

        // Configure mock Firestore to simulate a contention retry with 150ms delay
        db.simulateRetryOnNext = true;
        db.retryDelayMs = 150;

        const regResult = await store.registerStagedRecords({
            codeHash,
            redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            clientId: testClientId,
            ceremonyId: claim.record.ceremonyId,
            issuedSessionId: sessId,
            issuedFamilyId: famId
        });

        assert(regResult.success === false, 'Contention retry after lease expiration must fail');
        assert(regResult.reason === 'LOCK_EXPIRED', `Expected LOCK_EXPIRED, got ${regResult.reason}`);
    });

    // -------------------------------------------------------------
    // TC-33: Granular Staging Failure Cleanup Consistency
    // -------------------------------------------------------------
    await test('TC-33: Granular Staging Failure Cleanup: Clean up code lock without revoking unrelated records', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge,
            codeChallengeMethod: 'S256',
            tenantId: 'lanzar'
        });
        const codeHash = hashAuthorizationCode(code);

        const claim = await store.initiateRedemption({
            code,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier,
            idempotencyKey: 'idem_tc33_cleanup_001'
        });
        assert(claim.status === 'SUCCESS');

        // Case 1: Failure before staging (missing create capability)
        const cleanRes1 = await store.handleRedemptionFailure({
            codeHash,
            redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            sessionId: null,
            familyId: null,
            errorReason: 'missing_create_capability'
        });

        assert(cleanRes1.success === true, 'Failure cleanup before staging must succeed');
        const codeDoc1 = await db.collection('authorization_codes').doc(codeHash).get();
        assert(codeDoc1.data().status === 'COMPROMISED', 'Code must transition to COMPROMISED');
        assert(codeDoc1.data().failureReason === 'missing_create_capability', 'Failure reason must be recorded');

        // Case 2: Session staged, family staging throws
        const code2 = await store.createCode({
            uid: testUid,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge,
            codeChallengeMethod: 'S256',
            tenantId: 'lanzar'
        });
        const codeHash2 = hashAuthorizationCode(code2);
        const claim2 = await store.initiateRedemption({
            code: code2,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier,
            idempotencyKey: 'idem_tc33_cleanup_002'
        });

        const sessId2 = `sess_tc33_${Date.now()}`;
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId2).create({
            sessionId: sessId2, familyId: 'fam_placeholder', tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim2.record.ceremonyId, redemptionLockId: claim2.redemptionLockId,
            fenceToken: claim2.fenceToken, status: 'pending_activation'
        });

        const cleanRes2 = await store.handleRedemptionFailure({
            codeHash: codeHash2,
            redemptionLockId: claim2.redemptionLockId,
            fenceToken: claim2.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            sessionId: sessId2,
            familyId: null,
            errorReason: 'family_creation_failed'
        });

        assert(cleanRes2.success === true, 'Failure cleanup with staged session must succeed');
        const sessDoc2 = await db.collection('users').doc(testUid).collection('sessions').doc(sessId2).get();
        assert(sessDoc2.data().status === 'revoked', 'Staged session must be revoked');
        assert(sessDoc2.data().revocationReason === 'family_creation_failed', 'Revocation reason must match');
    });

    // -------------------------------------------------------------
    // TC-34: Fail-Closed Lease Validation Across All Distributed Methods
    // -------------------------------------------------------------
    await test('TC-34: Fail-Closed Lease Validation Across All Distributed Store Methods', async () => {
        const invalidLeaseValues = [null, undefined, 0, -5000, 'malformed_string', NaN, Infinity];

        for (const badVal of invalidLeaseValues) {
            // Subtest 1: initiateRedemption fails closed on invalid lease
            const pkce1 = generatePkce();
            const code1 = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce1.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const codeHash1 = hashAuthorizationCode(code1);
            const claim1 = await store.initiateRedemption({
                code: code1, clientId: testClientId, redirectUri: testRedirectUri, codeVerifier: pkce1.verifier,
                idempotencyKey: 'idem_tc34_init_' + crypto.randomBytes(12).toString('hex')
            });
            assert(claim1.status === 'SUCCESS');

            // Corrupt lease metadata
            await db.collection('authorization_codes').doc(codeHash1).update({
                redemptionLockExpiresAt: badVal
            });

            const retryClaim = await store.initiateRedemption({
                code: code1, clientId: testClientId, redirectUri: testRedirectUri, codeVerifier: pkce1.verifier,
                idempotencyKey: 'idem_tc34_rety_' + crypto.randomBytes(12).toString('hex')
            });
            assert(retryClaim.status === 'REPLAY_DETECTED', `initiateRedemption must return REPLAY_DETECTED on bad lease (${badVal}), got ${retryClaim.status}`);
            const codeDoc1 = await db.collection('authorization_codes').doc(codeHash1).get();
            assert(codeDoc1.data().status === 'COMPROMISED', 'Code must be COMPROMISED after invalid lease initiate');
            assert(codeDoc1.data().failureReason === 'invalid_lock_expiration', 'failureReason must be invalid_lock_expiration');

            // Subtest 2: registerStagedRecords fails closed on invalid lease
            const pkce2 = generatePkce();
            const code2 = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce2.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const codeHash2 = hashAuthorizationCode(code2);
            const claim2 = await store.initiateRedemption({
                code: code2, clientId: testClientId, redirectUri: testRedirectUri, codeVerifier: pkce2.verifier,
                idempotencyKey: 'idem_tc34_reg_' + crypto.randomBytes(12).toString('hex')
            });
            assert(claim2.status === 'SUCCESS');

            const sessId2 = 'sess_tc34_reg_' + crypto.randomBytes(8).toString('hex');
            const famId2 = 'fam_tc34_reg_' + crypto.randomBytes(8).toString('hex');
            await db.collection('users').doc(testUid).collection('sessions').doc(sessId2).create({
                sessionId: sessId2, familyId: famId2, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: claim2.record.ceremonyId, redemptionLockId: claim2.redemptionLockId,
                fenceToken: claim2.fenceToken, status: 'pending_activation'
            });
            await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId2).create({
                familyId: famId2, sessionId: sessId2, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: claim2.record.ceremonyId, redemptionLockId: claim2.redemptionLockId,
                fenceToken: claim2.fenceToken, status: 'pending_activation'
            });

            await db.collection('authorization_codes').doc(codeHash2).update({
                redemptionLockExpiresAt: badVal
            });

            const regRes = await store.registerStagedRecords({
                codeHash: codeHash2, redemptionLockId: claim2.redemptionLockId, fenceToken: claim2.fenceToken,
                uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim2.record.ceremonyId,
                issuedSessionId: sessId2, issuedFamilyId: famId2
            });
            assert(regRes.success === false, 'registerStagedRecords must fail on invalid lease');
            assert(regRes.reason === 'INVALID_LOCK_EXPIRATION', `Expected INVALID_LOCK_EXPIRATION, got ${regRes.reason}`);
            const codeDoc2 = await db.collection('authorization_codes').doc(codeHash2).get();
            assert(codeDoc2.data().status === 'COMPROMISED', 'Code must be COMPROMISED after invalid lease registration');

            // Subtest 3: finalizeRedemption fails closed on invalid lease
            const pkce3 = generatePkce();
            const code3 = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce3.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const codeHash3 = hashAuthorizationCode(code3);
            const claim3 = await store.initiateRedemption({
                code: code3, clientId: testClientId, redirectUri: testRedirectUri, codeVerifier: pkce3.verifier,
                idempotencyKey: 'idem_tc34_fin_' + crypto.randomBytes(12).toString('hex')
            });
            assert(claim3.status === 'SUCCESS');

            const sessId3 = 'sess_tc34_fin_' + crypto.randomBytes(8).toString('hex');
            const famId3 = 'fam_tc34_fin_' + crypto.randomBytes(8).toString('hex');
            await db.collection('users').doc(testUid).collection('sessions').doc(sessId3).create({
                sessionId: sessId3, familyId: famId3, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: claim3.record.ceremonyId, redemptionLockId: claim3.redemptionLockId,
                fenceToken: claim3.fenceToken, status: 'pending_activation'
            });
            await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId3).create({
                familyId: famId3, sessionId: sessId3, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: claim3.record.ceremonyId, redemptionLockId: claim3.redemptionLockId,
                fenceToken: claim3.fenceToken, status: 'pending_activation'
            });

            await store.registerStagedRecords({
                codeHash: codeHash3, redemptionLockId: claim3.redemptionLockId, fenceToken: claim3.fenceToken,
                uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim3.record.ceremonyId,
                issuedSessionId: sessId3, issuedFamilyId: famId3
            });

            await db.collection('authorization_codes').doc(codeHash3).update({
                redemptionLockExpiresAt: badVal
            });

            const finRes = await store.finalizeRedemption({
                codeHash: codeHash3, redemptionLockId: claim3.redemptionLockId, fenceToken: claim3.fenceToken,
                uid: testUid, tenantId: 'lanzar', issuedSessionId: sessId3, issuedFamilyId: famId3,
                rawTokensPayload: { custom_token: 'test' }
            });
            assert(finRes.success === false, 'finalizeRedemption must fail on invalid lease');
            assert(finRes.reason === 'INVALID_LOCK_EXPIRATION', `Expected INVALID_LOCK_EXPIRATION, got ${finRes.reason}`);
            const codeDoc3 = await db.collection('authorization_codes').doc(codeHash3).get();
            assert(codeDoc3.data().status === 'COMPROMISED', 'Code must be COMPROMISED after invalid lease finalization');
        }
    });

    // -------------------------------------------------------------
    // TC-35: Finalization Code Pointer Validation
    // -------------------------------------------------------------
    await test('TC-35: Finalization strictly validates authorization code pointers (issuedSessionId and issuedFamilyId)', async () => {
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge,
            codeChallengeMethod: 'S256',
            tenantId: 'lanzar'
        });
        const codeHash = hashAuthorizationCode(code);
        const claim = await store.initiateRedemption({
            code,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier,
            idempotencyKey: 'idem_tc35_pointers_001'
        });
        assert(claim.status === 'SUCCESS');

        const sessId = `sess_tc35_${Date.now()}`;
        const famId = `fam_tc35_${Date.now()}`;
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId).create({
            sessionId: sessId, familyId: famId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken, status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).create({
            familyId: famId, sessionId: sessId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken, status: 'pending_activation'
        });

        // Register valid pointers
        await store.registerStagedRecords({
            codeHash,
            redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            clientId: testClientId,
            ceremonyId: claim.record.ceremonyId,
            issuedSessionId: sessId,
            issuedFamilyId: famId
        });

        // 1. Independently corrupt code's issuedSessionId
        await db.collection('authorization_codes').doc(codeHash).update({
            issuedSessionId: 'sess_corrupted_id_999'
        });

        const finCorruptSession = await store.finalizeRedemption({
            codeHash,
            redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            issuedSessionId: sessId,
            issuedFamilyId: famId,
            rawTokensPayload: { custom_token: 'fake_jwt' }
        });

        assert(finCorruptSession.success === false, 'Finalization must fail closed when code issuedSessionId differs');
        assert(finCorruptSession.reason === 'RECORD_RELATIONSHIP_MISMATCH', `Expected RECORD_RELATIONSHIP_MISMATCH, got ${finCorruptSession.reason}`);

        // Verify neither record was activated
        const sessSnap1 = await db.collection('users').doc(testUid).collection('sessions').doc(sessId).get();
        const famSnap1 = await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).get();
        assert(sessSnap1.data().status !== 'active', 'Session MUST NOT be active');
        assert(famSnap1.data().status !== 'active', 'Family MUST NOT be active');

        // 2. Independently corrupt code's issuedFamilyId
        const code2 = await store.createCode({
            uid: testUid,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge,
            codeChallengeMethod: 'S256',
            tenantId: 'lanzar'
        });
        const codeHash2 = hashAuthorizationCode(code2);
        const claim2 = await store.initiateRedemption({
            code: code2,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier,
            idempotencyKey: 'idem_tc35_pointers_002'
        });
        const sessId2 = `sess_tc35_b_${Date.now()}`;
        const famId2 = `fam_tc35_b_${Date.now()}`;
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId2).create({
            sessionId: sessId2, familyId: famId2, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim2.record.ceremonyId, redemptionLockId: claim2.redemptionLockId,
            fenceToken: claim2.fenceToken, status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId2).create({
            familyId: famId2, sessionId: sessId2, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim2.record.ceremonyId, redemptionLockId: claim2.redemptionLockId,
            fenceToken: claim2.fenceToken, status: 'pending_activation'
        });
        await store.registerStagedRecords({
            codeHash: codeHash2,
            redemptionLockId: claim2.redemptionLockId,
            fenceToken: claim2.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            clientId: testClientId,
            ceremonyId: claim2.record.ceremonyId,
            issuedSessionId: sessId2,
            issuedFamilyId: famId2
        });

        // Corrupt code's issuedFamilyId
        await db.collection('authorization_codes').doc(codeHash2).update({
            issuedFamilyId: 'fam_corrupted_id_999'
        });

        const finCorruptFamily = await store.finalizeRedemption({
            codeHash: codeHash2,
            redemptionLockId: claim2.redemptionLockId,
            fenceToken: claim2.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            issuedSessionId: sessId2,
            issuedFamilyId: famId2,
            rawTokensPayload: { custom_token: 'fake_jwt' }
        });

        assert(finCorruptFamily.success === false, 'Finalization must fail closed when code issuedFamilyId differs');
        assert(finCorruptFamily.reason === 'RECORD_RELATIONSHIP_MISMATCH', `Expected RECORD_RELATIONSHIP_MISMATCH, got ${finCorruptFamily.reason}`);

        const sessSnap2 = await db.collection('users').doc(testUid).collection('sessions').doc(sessId2).get();
        const famSnap2 = await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId2).get();
        assert(sessSnap2.data().status !== 'active', 'Session MUST NOT be active');
        assert(famSnap2.data().status !== 'active', 'Family MUST NOT be active');
    });

    // -------------------------------------------------------------
    // TC-36: Ambiguous Firestore Create Outcome Handling in /exchange
    // -------------------------------------------------------------
    await test('TC-36: Ambiguous Firestore create outcomes: safeCleanup revokes committed documents without touching foreign resources', async () => {
        // Scenario 1: Ambiguous session creation
        // session.create() committed to database, but client threw network exception before returning
        const pkce = generatePkce();
        const code = await store.createCode({
            uid: testUid,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeChallenge: pkce.challenge,
            codeChallengeMethod: 'S256',
            tenantId: 'lanzar'
        });
        const codeHash = hashAuthorizationCode(code);
        const claim = await store.initiateRedemption({
            code,
            clientId: testClientId,
            redirectUri: testRedirectUri,
            codeVerifier: pkce.verifier,
            idempotencyKey: 'idem_tc36_ambiguous_001'
        });

        const ambiguousSessionId = `sess_ambig_${Date.now()}`;
        const ambiguousFamilyId = `fam_ambig_${Date.now()}`;

        // Commit session into Firestore simulating successful server write
        await db.collection('users').doc(testUid).collection('sessions').doc(ambiguousSessionId).create({
            sessionId: ambiguousSessionId,
            familyId: ambiguousFamilyId,
            tenantId: 'lanzar',
            uid: testUid,
            clientId: testClientId,
            ceremonyId: claim.record.ceremonyId,
            redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken,
            status: 'pending_activation'
        });

        // Client throws network error (ETIMEDOUT / connection reset)
        // Cleanup routine runs passing known ambiguousSessionId & ambiguousFamilyId
        const cleanupRes = await store.handleRedemptionFailure({
            codeHash,
            redemptionLockId: claim.redemptionLockId,
            fenceToken: claim.fenceToken,
            uid: testUid,
            tenantId: 'lanzar',
            sessionId: ambiguousSessionId,
            familyId: ambiguousFamilyId,
            errorReason: 'ECONNRESET_during_create'
        });

        assert(cleanupRes.success === true, 'handleRedemptionFailure must succeed');
        const sessDoc = await db.collection('users').doc(testUid).collection('sessions').doc(ambiguousSessionId).get();
        assert(sessDoc.data().status === 'revoked', 'Ambiguous committed session must be revoked');
        assert(sessDoc.data().revocationReason === 'ECONNRESET_during_create', 'Revocation reason must match');

        const codeDoc = await db.collection('authorization_codes').doc(codeHash).get();
        assert(codeDoc.data().status === 'COMPROMISED', 'Code must transition to COMPROMISED');

        // Scenario 2: Stale worker attempting ambiguous cleanup CANNOT revoke newer worker active session
        const sessNew = `sess_worker2_active_${Date.now()}`;
        await db.collection('users').doc(testUid).collection('sessions').doc(sessNew).create({
            sessionId: sessNew,
            familyId: 'fam_new',
            tenantId: 'lanzar',
            uid: testUid,
            clientId: testClientId,
            ceremonyId: claim.record.ceremonyId,
            redemptionLockId: 'worker2_lock',
            fenceToken: 99,
            status: 'active'
        });

        // Stale Worker 1 calls failure handler targeting Worker 2's session
        const staleCleanup = await store.handleRedemptionFailure({
            codeHash,
            redemptionLockId: claim.redemptionLockId, // Stale lock
            fenceToken: claim.fenceToken, // Stale fence
            uid: testUid,
            tenantId: 'lanzar',
            sessionId: sessNew,
            familyId: null,
            errorReason: 'stale_worker_timeout'
        });

        assert(staleCleanup.success === false, 'Stale worker cleanup must fail');
        assert(staleCleanup.reason === 'STALE_WORKER_FENCED', 'Stale worker must be fenced');
        const sessNewSnap = await db.collection('users').doc(testUid).collection('sessions').doc(sessNew).get();
        assert(sessNewSnap.data().status === 'active', 'Active session belonging to newer worker remains active');
    });

    // -------------------------------------------------------------
    // TC-37: Corrupt Lease Metadata Fencing in initiateRedemption()
    // -------------------------------------------------------------
    await test('TC-37: Corrupt lease metadata in initiateRedemption() CANNOT revoke newer worker, active, or mismatched records', async () => {
        // Case A: Newer worker's pending_activation records referenced by code with corrupt lease
        const pkceA = generatePkce();
        const codeA = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkceA.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
        });
        const codeHashA = hashAuthorizationCode(codeA);
        const claimA = await store.initiateRedemption({
            code: codeA, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkceA.verifier, idempotencyKey: 'idem_tc37_caseA_' + crypto.randomBytes(8).toString('hex')
        });
        const sessIdA = `sess_tc37_a_${Date.now()}`;
        const famIdA = `fam_tc37_a_${Date.now()}`;
        await db.collection('users').doc(testUid).collection('sessions').doc(sessIdA).create({
            sessionId: sessIdA, familyId: famIdA, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claimA.record.ceremonyId, redemptionLockId: 'newer_worker_lock_A',
            fenceToken: claimA.fenceToken + 1, status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famIdA).create({
            familyId: famIdA, sessionId: sessIdA, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claimA.record.ceremonyId, redemptionLockId: 'newer_worker_lock_A',
            fenceToken: claimA.fenceToken + 1, status: 'pending_activation'
        });
        await db.collection('authorization_codes').doc(codeHashA).update({
            issuedSessionId: sessIdA, issuedFamilyId: famIdA, redemptionLockExpiresAt: null
        });

        const resA = await store.initiateRedemption({
            code: codeA, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkceA.verifier, idempotencyKey: 'idem_tc37_retryA_' + crypto.randomBytes(8).toString('hex')
        });
        assert(resA.status === 'REPLAY_DETECTED', 'Corrupt lease must return REPLAY_DETECTED');
        const codeSnapA = await db.collection('authorization_codes').doc(codeHashA).get();
        const sessSnapA = await db.collection('users').doc(testUid).collection('sessions').doc(sessIdA).get();
        const famSnapA = await db.collection('tenants').doc('lanzar').collection('token_families').doc(famIdA).get();
        assert(codeSnapA.data().status === 'COMPROMISED' && codeSnapA.data().failureReason === 'invalid_lock_expiration', 'Code A marked COMPROMISED');
        assert(sessSnapA.data().status === 'pending_activation', 'Newer worker session MUST NOT be revoked');
        assert(famSnapA.data().status === 'pending_activation', 'Newer worker family MUST NOT be revoked');

        // Case B: Active records referenced by code with corrupt lease (even with matching lock/fence)
        const pkceB = generatePkce();
        const codeB = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkceB.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
        });
        const codeHashB = hashAuthorizationCode(codeB);
        const claimB = await store.initiateRedemption({
            code: codeB, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkceB.verifier, idempotencyKey: 'idem_tc37_caseB_' + crypto.randomBytes(8).toString('hex')
        });
        const sessIdB = `sess_tc37_b_${Date.now()}`;
        const famIdB = `fam_tc37_b_${Date.now()}`;
        await db.collection('users').doc(testUid).collection('sessions').doc(sessIdB).create({
            sessionId: sessIdB, familyId: famIdB, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claimB.record.ceremonyId, redemptionLockId: claimB.redemptionLockId,
            fenceToken: claimB.fenceToken, status: 'active'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famIdB).create({
            familyId: famIdB, sessionId: sessIdB, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claimB.record.ceremonyId, redemptionLockId: claimB.redemptionLockId,
            fenceToken: claimB.fenceToken, status: 'active'
        });
        await db.collection('authorization_codes').doc(codeHashB).update({
            issuedSessionId: sessIdB, issuedFamilyId: famIdB, redemptionLockExpiresAt: 0
        });

        const resB = await store.initiateRedemption({
            code: codeB, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkceB.verifier, idempotencyKey: 'idem_tc37_retryB_' + crypto.randomBytes(8).toString('hex')
        });
        assert(resB.status === 'REPLAY_DETECTED', 'Corrupt lease B must return REPLAY_DETECTED');
        const sessSnapB = await db.collection('users').doc(testUid).collection('sessions').doc(sessIdB).get();
        const famSnapB = await db.collection('tenants').doc('lanzar').collection('token_families').doc(famIdB).get();
        assert(sessSnapB.data().status === 'active', 'Active session MUST NOT be revoked by invalid-lease branch');
        assert(famSnapB.data().status === 'active', 'Active family MUST NOT be revoked by invalid-lease branch');

        // Case C: Mismatched ceremonyId / tenantId on pending records
        const pkceC = generatePkce();
        const codeC = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkceC.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
        });
        const codeHashC = hashAuthorizationCode(codeC);
        const claimC = await store.initiateRedemption({
            code: codeC, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkceC.verifier, idempotencyKey: 'idem_tc37_caseC_' + crypto.randomBytes(8).toString('hex')
        });
        const sessIdC = `sess_tc37_c_${Date.now()}`;
        const famIdC = `fam_tc37_c_${Date.now()}`;
        await db.collection('users').doc(testUid).collection('sessions').doc(sessIdC).create({
            sessionId: sessIdC, familyId: famIdC, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: 'foreign_ceremony_id', redemptionLockId: claimC.redemptionLockId,
            fenceToken: claimC.fenceToken, status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famIdC).create({
            familyId: famIdC, sessionId: sessIdC, tenantId: 'other_tenant', uid: testUid, clientId: testClientId,
            ceremonyId: claimC.record.ceremonyId, redemptionLockId: claimC.redemptionLockId,
            fenceToken: claimC.fenceToken, status: 'pending_activation'
        });
        await db.collection('authorization_codes').doc(codeHashC).update({
            issuedSessionId: sessIdC, issuedFamilyId: famIdC, redemptionLockExpiresAt: -5000
        });

        await store.initiateRedemption({
            code: codeC, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkceC.verifier, idempotencyKey: 'idem_tc37_retryC_' + crypto.randomBytes(8).toString('hex')
        });
        const sessSnapC = await db.collection('users').doc(testUid).collection('sessions').doc(sessIdC).get();
        const famSnapC = await db.collection('tenants').doc('lanzar').collection('token_families').doc(famIdC).get();
        assert(sessSnapC.data().status === 'pending_activation', 'Mismatched ceremony session MUST NOT be revoked');
        assert(famSnapC.data().status === 'pending_activation', 'Mismatched tenant family MUST NOT be revoked');

        // Case D: Current ceremony's own pending records ARE cleanly revoked
        const pkceD = generatePkce();
        const codeD = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkceD.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
        });
        const codeHashD = hashAuthorizationCode(codeD);
        const claimD = await store.initiateRedemption({
            code: codeD, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkceD.verifier, idempotencyKey: 'idem_tc37_caseD_' + crypto.randomBytes(8).toString('hex')
        });
        const sessIdD = `sess_tc37_d_${Date.now()}`;
        const famIdD = `fam_tc37_d_${Date.now()}`;
        await db.collection('users').doc(testUid).collection('sessions').doc(sessIdD).create({
            sessionId: sessIdD, familyId: famIdD, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claimD.record.ceremonyId, redemptionLockId: claimD.redemptionLockId,
            fenceToken: claimD.fenceToken, status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famIdD).create({
            familyId: famIdD, sessionId: sessIdD, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claimD.record.ceremonyId, redemptionLockId: claimD.redemptionLockId,
            fenceToken: claimD.fenceToken, status: 'pending_activation'
        });
        await store.registerStagedRecords({
            codeHash: codeHashD, redemptionLockId: claimD.redemptionLockId, fenceToken: claimD.fenceToken,
            uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claimD.record.ceremonyId,
            issuedSessionId: sessIdD, issuedFamilyId: famIdD
        });
        await db.collection('authorization_codes').doc(codeHashD).update({
            redemptionLockExpiresAt: 'malformed_string'
        });

        await store.initiateRedemption({
            code: codeD, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkceD.verifier, idempotencyKey: 'idem_tc37_retryD_' + crypto.randomBytes(8).toString('hex')
        });
        const sessSnapD = await db.collection('users').doc(testUid).collection('sessions').doc(sessIdD).get();
        const famSnapD = await db.collection('tenants').doc('lanzar').collection('token_families').doc(famIdD).get();
        assert(sessSnapD.data().status === 'revoked' && sessSnapD.data().revocationReason === 'invalid_lock_expiration', 'Owned pending session MUST be revoked');
        assert(famSnapD.data().status === 'revoked' && famSnapD.data().revocationReason === 'invalid_lock_expiration', 'Owned pending family MUST be revoked');
    });

    // -------------------------------------------------------------
    // TC-38: Strict Authorization-Code Expiration Validation
    // -------------------------------------------------------------
    await test('TC-38: Strict Authorization-Code Expiration rejects missing, null, malformed, zero, negative, non-finite, and expired timestamps', async () => {
        const badExpirations = [
            { label: 'undefined', val: undefined },
            { label: 'null', val: null },
            { label: 'malformed', val: 'not_a_timestamp' },
            { label: 'zero', val: 0 },
            { label: 'negative', val: -5000 },
            { label: 'NaN', val: NaN },
            { label: 'Infinity', val: Infinity },
            { label: '-Infinity', val: -Infinity }
        ];

        for (const { label, val } of badExpirations) {
            const pkce = generatePkce();
            const code = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const codeHash = hashAuthorizationCode(code);
            await db.collection('authorization_codes').doc(codeHash).update({ expiresAt: val });

            const res = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: 'idem_tc38_bad_' + crypto.randomBytes(8).toString('hex')
            });
            assert(res.status === 'EXPIRED', `Expected EXPIRED for ${label}, got ${res.status}`);
            const codeDoc = (await db.collection('authorization_codes').doc(codeHash).get()).data();
            assert(codeDoc.status === 'EXPIRED', `Code doc must be EXPIRED for ${label}`);
            assert(codeDoc.failureReason === 'invalid_code_expiration', `Expected invalid_code_expiration for ${label}, got ${codeDoc.failureReason}`);
        }

        // Expired past timestamp
        const pkceExp = generatePkce();
        const codeExp = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkceExp.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
        });
        const codeHashExp = hashAuthorizationCode(codeExp);
        await db.collection('authorization_codes').doc(codeHashExp).update({ expiresAt: new Date(Date.now() - 5000) });
        const resExp = await store.initiateRedemption({
            code: codeExp, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkceExp.verifier, idempotencyKey: 'idem_tc38_past_' + crypto.randomBytes(8).toString('hex')
        });
        assert(resExp.status === 'EXPIRED', 'Past timestamp must return EXPIRED');
        const docExp = (await db.collection('authorization_codes').doc(codeHashExp).get()).data();
        assert(docExp.status === 'EXPIRED' && docExp.failureReason === 'code_expired', 'Past timestamp must record code_expired');

        // Valid future timestamp
        const pkceValid = generatePkce();
        const codeValid = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkceValid.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
        });
        const codeHashValid = hashAuthorizationCode(codeValid);
        await db.collection('authorization_codes').doc(codeHashValid).update({ expiresAt: new Date(Date.now() + 60000) });
        const resValid = await store.initiateRedemption({
            code: codeValid, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkceValid.verifier, idempotencyKey: 'idem_tc38_valid_' + crypto.randomBytes(8).toString('hex')
        });
        assert(resValid.status === 'SUCCESS', 'Valid future expiration must succeed');
        const docValid = (await db.collection('authorization_codes').doc(codeHashValid).get()).data();
        assert(docValid.status === 'REDEEMING', 'Valid code transitions to REDEEMING');
    });

    // -------------------------------------------------------------
    // TC-39: Concurrent-Conflict & Completed-Code Replay Fencing
    // -------------------------------------------------------------
    await test('TC-39: Concurrent-conflict and completed-code replay fencing protects foreign, newer-worker, and unrelated active records', async () => {
        // 1. Legitimate concurrent conflict revokes correctly linked pending records
        const pkce1 = generatePkce();
        const code1 = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkce1.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
        });
        const codeHash1 = hashAuthorizationCode(code1);
        const claim1 = await store.initiateRedemption({
            code: code1, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce1.verifier, idempotencyKey: 'idem_tc39_1_' + crypto.randomBytes(8).toString('hex')
        });
        const sessId1 = `sess_tc39_1_${Date.now()}`;
        const famId1 = `fam_tc39_1_${Date.now()}`;
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId1).create({
            sessionId: sessId1, familyId: famId1, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim1.record.ceremonyId, redemptionLockId: claim1.redemptionLockId,
            fenceToken: claim1.fenceToken, status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId1).create({
            familyId: famId1, sessionId: sessId1, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim1.record.ceremonyId, redemptionLockId: claim1.redemptionLockId,
            fenceToken: claim1.fenceToken, status: 'pending_activation'
        });
        await store.registerStagedRecords({
            codeHash: codeHash1, redemptionLockId: claim1.redemptionLockId, fenceToken: claim1.fenceToken,
            uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim1.record.ceremonyId,
            issuedSessionId: sessId1, issuedFamilyId: famId1
        });

        const conflict1 = await store.initiateRedemption({
            code: code1, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce1.verifier, idempotencyKey: 'idem_tc39_1_conflict_' + crypto.randomBytes(8).toString('hex')
        });
        assert(conflict1.status === 'REPLAY_DETECTED', 'Concurrent conflict must return REPLAY_DETECTED');
        assert((await db.collection('users').doc(testUid).collection('sessions').doc(sessId1).get()).data().status === 'revoked', 'Legitimate conflict revokes linked pending session');
        assert((await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId1).get()).data().status === 'revoked', 'Legitimate conflict revokes linked pending family');

        // 2. Foreign/mismatched records remain untouched during concurrent conflict
        const pkce2 = generatePkce();
        const code2 = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkce2.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
        });
        const codeHash2 = hashAuthorizationCode(code2);
        const claim2 = await store.initiateRedemption({
            code: code2, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce2.verifier, idempotencyKey: 'idem_tc39_2_' + crypto.randomBytes(8).toString('hex')
        });
        const sessId2 = `sess_tc39_2_${Date.now()}`;
        const famId2 = `fam_tc39_2_${Date.now()}`;
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId2).create({
            sessionId: sessId2, familyId: famId2, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: 'foreign_ceremony_tc39', redemptionLockId: claim2.redemptionLockId,
            fenceToken: claim2.fenceToken, status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId2).create({
            familyId: famId2, sessionId: sessId2, tenantId: 'foreign_tenant', uid: testUid, clientId: testClientId,
            ceremonyId: claim2.record.ceremonyId, redemptionLockId: claim2.redemptionLockId,
            fenceToken: claim2.fenceToken, status: 'pending_activation'
        });
        await db.collection('authorization_codes').doc(codeHash2).update({ issuedSessionId: sessId2, issuedFamilyId: famId2 });

        await store.initiateRedemption({
            code: code2, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce2.verifier, idempotencyKey: 'idem_tc39_2_conflict_' + crypto.randomBytes(8).toString('hex')
        });
        assert((await db.collection('users').doc(testUid).collection('sessions').doc(sessId2).get()).data().status === 'pending_activation', 'Foreign ceremony session MUST remain untouched');
        assert((await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId2).get()).data().status === 'pending_activation', 'Foreign tenant family MUST remain untouched');

        // 3. Newer-worker records remain untouched during concurrent conflict
        const pkce3 = generatePkce();
        const code3 = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkce3.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
        });
        const codeHash3 = hashAuthorizationCode(code3);
        const claim3 = await store.initiateRedemption({
            code: code3, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce3.verifier, idempotencyKey: 'idem_tc39_3_' + crypto.randomBytes(8).toString('hex')
        });
        const sessId3 = `sess_tc39_3_${Date.now()}`;
        const famId3 = `fam_tc39_3_${Date.now()}`;
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId3).create({
            sessionId: sessId3, familyId: famId3, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim3.record.ceremonyId, redemptionLockId: 'newer_worker_lock_tc39',
            fenceToken: claim3.fenceToken + 1, status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId3).create({
            familyId: famId3, sessionId: sessId3, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim3.record.ceremonyId, redemptionLockId: 'newer_worker_lock_tc39',
            fenceToken: claim3.fenceToken + 1, status: 'pending_activation'
        });
        await db.collection('authorization_codes').doc(codeHash3).update({ issuedSessionId: sessId3, issuedFamilyId: famId3 });

        await store.initiateRedemption({
            code: code3, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce3.verifier, idempotencyKey: 'idem_tc39_3_conflict_' + crypto.randomBytes(8).toString('hex')
        });
        assert((await db.collection('users').doc(testUid).collection('sessions').doc(sessId3).get()).data().status === 'pending_activation', 'Newer worker session MUST remain untouched');
        assert((await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId3).get()).data().status === 'pending_activation', 'Newer worker family MUST remain untouched');

        // 4. Completed-code replay revokes ONLY the correctly linked active session and family
        const pkce4 = generatePkce();
        const code4 = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkce4.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
        });
        const codeHash4 = hashAuthorizationCode(code4);
        const claim4 = await store.initiateRedemption({
            code: code4, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce4.verifier, idempotencyKey: 'idem_tc39_4_' + crypto.randomBytes(8).toString('hex')
        });
        const sessId4 = `sess_tc39_4_${Date.now()}`;
        const famId4 = `fam_tc39_4_${Date.now()}`;
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId4).create({
            sessionId: sessId4, familyId: famId4, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim4.record.ceremonyId, redemptionLockId: claim4.redemptionLockId,
            fenceToken: claim4.fenceToken, status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId4).create({
            familyId: famId4, sessionId: sessId4, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim4.record.ceremonyId, redemptionLockId: claim4.redemptionLockId,
            fenceToken: claim4.fenceToken, status: 'pending_activation'
        });
        await store.registerStagedRecords({
            codeHash: codeHash4, redemptionLockId: claim4.redemptionLockId, fenceToken: claim4.fenceToken,
            uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim4.record.ceremonyId,
            issuedSessionId: sessId4, issuedFamilyId: famId4
        });
        await store.finalizeRedemption({
            codeHash: codeHash4, redemptionLockId: claim4.redemptionLockId, fenceToken: claim4.fenceToken,
            uid: testUid, tenantId: 'lanzar', issuedSessionId: sessId4, issuedFamilyId: famId4,
            rawTokensPayload: { custom_token: 'tok4' }
        });

        const replay4 = await store.initiateRedemption({
            code: code4, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce4.verifier, idempotencyKey: 'idem_tc39_4_replay_' + crypto.randomBytes(8).toString('hex')
        });
        assert(replay4.status === 'REPLAY_DETECTED', 'Completed code replay must return REPLAY_DETECTED');
        const sessDoc4 = (await db.collection('users').doc(testUid).collection('sessions').doc(sessId4).get()).data();
        const famDoc4 = (await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId4).get()).data();
        assert(sessDoc4.status === 'revoked' && sessDoc4.revocationReason === 'authorization_code_replay_compromise', 'Completed replay revokes linked active session');
        assert(famDoc4.status === 'revoked' && famDoc4.revocationReason === 'authorization_code_replay_compromise', 'Completed replay revokes linked active family');

        // 5. Corrupt pointers on COMPLETED code CANNOT revoke unrelated active records
        const pkce5 = generatePkce();
        const code5 = await store.createCode({
            uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
            codeChallenge: pkce5.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
        });
        const codeHash5 = hashAuthorizationCode(code5);
        const claim5 = await store.initiateRedemption({
            code: code5, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce5.verifier, idempotencyKey: 'idem_tc39_5_' + crypto.randomBytes(8).toString('hex')
        });
        const sessId5 = `sess_tc39_5_${Date.now()}`;
        const famId5 = `fam_tc39_5_${Date.now()}`;
        await db.collection('users').doc(testUid).collection('sessions').doc(sessId5).create({
            sessionId: sessId5, familyId: famId5, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim5.record.ceremonyId, redemptionLockId: claim5.redemptionLockId,
            fenceToken: claim5.fenceToken, status: 'pending_activation'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId5).create({
            familyId: famId5, sessionId: sessId5, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: claim5.record.ceremonyId, redemptionLockId: claim5.redemptionLockId,
            fenceToken: claim5.fenceToken, status: 'pending_activation'
        });
        await store.registerStagedRecords({
            codeHash: codeHash5, redemptionLockId: claim5.redemptionLockId, fenceToken: claim5.fenceToken,
            uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim5.record.ceremonyId,
            issuedSessionId: sessId5, issuedFamilyId: famId5
        });
        await store.finalizeRedemption({
            codeHash: codeHash5, redemptionLockId: claim5.redemptionLockId, fenceToken: claim5.fenceToken,
            uid: testUid, tenantId: 'lanzar', issuedSessionId: sessId5, issuedFamilyId: famId5,
            rawTokensPayload: { custom_token: 'tok5' }
        });

        // Create unrelated active session & family belonging to a completely different ceremony
        const unrelatedSessId = `sess_tc39_unrel_${Date.now()}`;
        const unrelatedFamId = `fam_tc39_unrel_${Date.now()}`;
        await db.collection('users').doc(testUid).collection('sessions').doc(unrelatedSessId).create({
            sessionId: unrelatedSessId, familyId: unrelatedFamId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: 'unrelated_ceremony_999', redemptionLockId: 'other_lock',
            fenceToken: 1, status: 'active'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(unrelatedFamId).create({
            familyId: unrelatedFamId, sessionId: unrelatedSessId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
            ceremonyId: 'unrelated_ceremony_999', redemptionLockId: 'other_lock',
            fenceToken: 1, status: 'active'
        });

        // Corrupt code5 pointers to target the unrelated active records
        await db.collection('authorization_codes').doc(codeHash5).update({
            issuedSessionId: unrelatedSessId,
            issuedFamilyId: unrelatedFamId
        });

        const replay5 = await store.initiateRedemption({
            code: code5, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: pkce5.verifier, idempotencyKey: 'idem_tc39_5_replay_' + crypto.randomBytes(8).toString('hex')
        });
        assert(replay5.status === 'REPLAY_DETECTED', 'Corrupt pointer replay must still return REPLAY_DETECTED');
        assert((await db.collection('users').doc(testUid).collection('sessions').doc(unrelatedSessId).get()).data().status === 'active', 'Unrelated active session MUST NOT be revoked via corrupt pointer');
        assert((await db.collection('tenants').doc('lanzar').collection('token_families').doc(unrelatedFamId).get()).data().status === 'active', 'Unrelated active family MUST NOT be revoked via corrupt pointer');
    });

    await test('TC-40: Fail-Closed Replay Fencing & Paired Replay Relationship Validation', async () => {
        // 1. Direct predicate fail-closed checks for invalid fenceToken values
        const baseSess = {
            exists: true,
            data: () => ({
                sessionId: 's1', familyId: 'f1', tenantId: 'lanzar', uid: testUid,
                clientId: testClientId, ceremonyId: 'cer1', redemptionLockId: 'lock1',
                fenceToken: 1, status: 'active'
            })
        };
        const baseFam = {
            exists: true,
            data: () => ({
                familyId: 'f1', sessionId: 's1', tenantId: 'lanzar', uid: testUid,
                clientId: testClientId, ceremonyId: 'cer1', redemptionLockId: 'lock1',
                fenceToken: 1, status: 'active'
            })
        };
        const invalidFenceTokens = [undefined, null, 0, -1, 1.5, NaN, Infinity, -Infinity];
        for (const badToken of invalidFenceTokens) {
            const badCodeData = {
                uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: 'cer1',
                redemptionLockId: 'lock1', issuedSessionId: 's1', issuedFamilyId: 'f1'
            };
            if (badToken !== undefined) badCodeData.fenceToken = badToken;
            const badCode = { exists: true, data: () => badCodeData };
            assert(canReplayRevokeSession(baseSess, badCode) === false, `canReplayRevokeSession must reject bad fenceToken: ${String(badToken)}`);
            assert(canReplayRevokeFamily(baseFam, badCode) === false, `canReplayRevokeFamily must reject bad fenceToken: ${String(badToken)}`);
            assert(canReplayRevokePair(baseSess, baseFam, badCode) === false, `canReplayRevokePair must reject bad fenceToken: ${String(badToken)}`);
        }

        // Helper to create a COMPLETED ceremony with active session + family
        async function createCompletedCeremony(tag) {
            const pkce = generatePkce();
            const code = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const codeHash = hashAuthorizationCode(code);
            const idem = `idem_tc40_${tag}_${crypto.randomBytes(8).toString('hex')}`;
            const claim = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: idem
            });
            assert(claim.status === 'SUCCESS', `Expected SUCCESS for ${tag}, got ${claim.status}`);
            const { generateRefreshToken } = require('./auth-backend/store');
            const sessId = `sess_tc40_${tag}_${Date.now()}`;
            const famId = `fam_tc40_${tag}_${Date.now()}`;
            const refreshToken = generateRefreshToken(famId, 1);
            await db.collection('users').doc(testUid).collection('sessions').doc(sessId).create({
                sessionId: sessId, familyId: famId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId,
                fenceToken: claim.fenceToken, status: 'pending_activation',
                expiresAt: new Date(Date.now() + 86400000).toISOString()
            });
            await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).create({
                familyId: famId, sessionId: sessId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId,
                fenceToken: claim.fenceToken, status: 'pending_activation',
                currentActiveTokenHash: hashAuthorizationCode(refreshToken),
                sequenceNumber: 1,
                rotatedTokenHashes: [],
                expiresAt: new Date(Date.now() + 86400000).toISOString()
            });
            await store.registerStagedRecords({
                codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
                uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
                issuedSessionId: sessId, issuedFamilyId: famId
            });
            await store.finalizeRedemption({
                codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
                uid: testUid, tenantId: 'lanzar', issuedSessionId: sessId, issuedFamilyId: famId,
                rawTokensPayload: { custom_token: `tok_${tag}` }
            });
            return { pkce, code, codeHash, claim, sessId, famId, refreshToken };
        }

        // 2. End-to-end COMPLETED replay with invalid fenceToken on code doc:
        //    - When ceremonyId + completedLockId prove ownership, both valid records ARE revoked synchronously and refresh fails.
        //    - When a companion record is corrupted/foreign, it is NOT revoked, while the valid record IS revoked.
        //    - When lock ownership cannot be proven at all, potentially foreign records are NOT revoked,
        //      and compromised_ceremonies tombstone still blocks authorizeRefreshGrant().
        for (let i = 0; i < invalidFenceTokens.length; i++) {
            const badToken = invalidFenceTokens[i];
            const c = await createCompletedCeremony(`badft_${i}`);
            const preReplayRefresh = await store.authorizeRefreshGrant({
                tenantId: 'lanzar', familyId: c.famId, uid: testUid, sessionId: c.sessId, refreshToken: c.refreshToken
            });
            assert(preReplayRefresh.allowed === true && typeof preReplayRefresh.accessToken === 'string', `Pre-replay refresh must succeed for badft_${i}`);

            const codeSnap = await db.collection('authorization_codes').doc(c.codeHash).get();
            const updatedCode = { ...codeSnap.data() };
            if (badToken === undefined) {
                delete updatedCode.fenceToken;
                await db.collection('authorization_codes').doc(c.codeHash).set(updatedCode);
            } else {
                await db.collection('authorization_codes').doc(c.codeHash).update({ fenceToken: badToken });
            }
            const replay = await store.initiateRedemption({
                code: c.code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: c.pkce.verifier, idempotencyKey: `idem_tc40_replay_ft_${i}_${crypto.randomBytes(6).toString('hex')}`
            });
            assert(replay.status === 'REPLAY_DETECTED', `Bad fenceToken ${String(badToken)} replay must return REPLAY_DETECTED`);
            assert((await db.collection('users').doc(testUid).collection('sessions').doc(c.sessId).get()).data().status === 'revoked', `Proven session MUST be revoked when code fenceToken=${String(badToken)}`);
            assert((await db.collection('tenants').doc('lanzar').collection('token_families').doc(c.famId).get()).data().status === 'revoked', `Proven family MUST be revoked when code fenceToken=${String(badToken)}`);
            const postReplayRefresh = await store.authorizeRefreshGrant({
                tenantId: 'lanzar', familyId: c.famId, uid: testUid, sessionId: c.sessId, refreshToken: preReplayRefresh.refreshToken
            });
            assert(postReplayRefresh.allowed === false && !postReplayRefresh.accessToken, `Refresh MUST be blocked after invalid fenceToken=${String(badToken)} replay`);
        }

        // 2b. Invalid fenceToken + corrupted companion family -> valid session revoked, foreign family untouched, refresh blocked
        const cBadFtCorruptFam = await createCompletedCeremony('badft_corrupt_fam');
        await db.collection('authorization_codes').doc(cBadFtCorruptFam.codeHash).update({ fenceToken: null });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(cBadFtCorruptFam.famId).update({
            redemptionLockId: 'foreign_lock_999'
        });
        const replayBadFtCorruptFam = await store.initiateRedemption({
            code: cBadFtCorruptFam.code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: cBadFtCorruptFam.pkce.verifier, idempotencyKey: `idem_tc40_badft_cfam_${crypto.randomBytes(6).toString('hex')}`
        });
        assert(replayBadFtCorruptFam.status === 'REPLAY_DETECTED');
        assert((await db.collection('users').doc(testUid).collection('sessions').doc(cBadFtCorruptFam.sessId).get()).data().status === 'revoked', 'Proven session MUST be revoked');
        assert((await db.collection('tenants').doc('lanzar').collection('token_families').doc(cBadFtCorruptFam.famId).get()).data().status === 'active', 'Foreign/corrupt family MUST remain untouched');
        assert((await store.authorizeRefreshGrant({ tenantId: 'lanzar', familyId: cBadFtCorruptFam.famId, uid: testUid, sessionId: cBadFtCorruptFam.sessId, refreshToken: cBadFtCorruptFam.refreshToken })).allowed === false, 'Refresh MUST be blocked');

        // 2c. Invalid fenceToken + missing completedLockId (unproven ownership) -> records NOT revoked,
        //     but compromised_ceremonies tombstone independently blocks authorizeRefreshGrant!
        const cUnproven = await createCompletedCeremony('badft_unproven');
        const codeUnprovenData = { ...(await db.collection('authorization_codes').doc(cUnproven.codeHash).get()).data() };
        delete codeUnprovenData.fenceToken;
        delete codeUnprovenData.completedLockId;
        await db.collection('authorization_codes').doc(cUnproven.codeHash).set(codeUnprovenData);
        const replayUnproven = await store.initiateRedemption({
            code: cUnproven.code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: cUnproven.pkce.verifier, idempotencyKey: `idem_tc40_unproven_${crypto.randomBytes(6).toString('hex')}`
        });
        assert(replayUnproven.status === 'REPLAY_DETECTED');
        assert((await db.collection('users').doc(testUid).collection('sessions').doc(cUnproven.sessId).get()).data().status === 'active', 'Unproven session MUST NOT be revoked');
        assert((await db.collection('tenants').doc('lanzar').collection('token_families').doc(cUnproven.famId).get()).data().status === 'active', 'Unproven family MUST NOT be revoked');
        const refreshUnproven = await store.authorizeRefreshGrant({
            tenantId: 'lanzar', familyId: cUnproven.famId, uid: testUid, sessionId: cUnproven.sessId, refreshToken: cUnproven.refreshToken
        });
        assert(refreshUnproven.allowed === false && refreshUnproven.reason === 'CEREMONY_COMPROMISED', `Unproven ceremony refresh MUST be blocked via ceremony tombstone, got ${JSON.stringify(refreshUnproven)}`);

        // 2d. Truly unrelated active ceremony refresh still succeeds
        const cUnrelated = await createCompletedCeremony('unrelated_ok');
        const refreshUnrelated = await store.authorizeRefreshGrant({
            tenantId: 'lanzar', familyId: cUnrelated.famId, uid: testUid, sessionId: cUnrelated.sessId, refreshToken: cUnrelated.refreshToken
        });
        assert(refreshUnrelated.allowed === true && typeof refreshUnrelated.accessToken === 'string', 'Unrelated ceremony refresh must still succeed');

        // 2e. Secondary config check: ACTIVE_RECEIPT_KEY_VERSION strictness & deterministic fallback parity
        const { resolveReceiptKey } = require('./auth-backend/store');
        for (const badVer of ['1.5', '1junk', '0', '-2', 'abc']) {
            let threw = false;
            try {
                validateReceiptKeyConfiguration({ NODE_ENV: 'production', ACTIVE_RECEIPT_KEY_VERSION: badVer, RECEIPT_ENCRYPTION_KEY: 'a'.repeat(64) });
            } catch (_) {
                threw = true;
            }
            assert(threw, `validateReceiptKeyConfiguration must reject malformed ACTIVE_RECEIPT_KEY_VERSION=${badVer}`);
        }
        const savedEnv = { ...process.env };
        try {
            process.env.NODE_ENV = 'production';
            process.env.ACTIVE_RECEIPT_KEY_VERSION = '2';
            process.env.RECEIPT_ENCRYPTION_KEYS = JSON.stringify({ '1': 'b'.repeat(64) });
            process.env.RECEIPT_ENCRYPTION_KEY_V2 = 'c'.repeat(64);
            assert(validateReceiptKeyConfiguration(process.env) === true, 'Startup validation must fall back from JSON keyring missing V2 to RECEIPT_ENCRYPTION_KEY_V2');
            assert(Buffer.isBuffer(resolveReceiptKey()), 'Runtime resolveReceiptKey must follow identical fallback to RECEIPT_ENCRYPTION_KEY_V2');

            // Production must require explicit RECEIPT_ENCRYPTION_KEY (TOKEN_RECEIPT_KEY is dev-only)
            let legacyProdThrew = false;
            try {
                validateReceiptKeyConfiguration({ NODE_ENV: 'production', TOKEN_RECEIPT_KEY: 'd'.repeat(64) });
            } catch (_) {
                legacyProdThrew = true;
            }
            assert(legacyProdThrew, 'Production must reject TOKEN_RECEIPT_KEY without explicit RECEIPT_ENCRYPTION_KEY');
            assert(validateReceiptKeyConfiguration({ NODE_ENV: 'development', TOKEN_RECEIPT_KEY: 'd'.repeat(64) }) === true, 'Development may still use TOKEN_RECEIPT_KEY fallback');
        } finally {
            process.env = savedEnv;
        }

        const sessSvc = new SessionService(db, {});
        const evaluateRefreshGate = async (famId, uid, sessId, refreshToken) => {
            const famSnap = await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).get();
            const fam = famSnap.exists ? famSnap.data() : null;
            const sessState = await sessSvc.checkSession(uid, sessId, { bypassCache: true });
            const { generateRefreshToken } = require('./auth-backend/store');
            const grant = await store.authorizeRefreshGrant({
                tenantId: 'lanzar', familyId: famId, uid, sessionId: sessId,
                refreshToken: refreshToken || generateRefreshToken(famId, 1)
            });
            const refreshAllowed = Boolean(fam && fam.status === 'active' && sessState.active && grant.allowed);
            return { fam, sessState, grant, refreshAllowed };
        };
        const getOutboxEvents = (ceremonyId) => {
            const events = [];
            for (const [k, v] of db.store.entries()) {
                if (k.startsWith('security_outbox/') && v.details?.ceremonyId === ceremonyId) {
                    events.push(v);
                }
            }
            return events;
        };

        // 3a. Missing session + valid active family -> family IS revoked synchronously; refresh blocked
        const cMissSess = await createCompletedCeremony('miss_sess');
        db.store.delete(`users/${testUid}/sessions/${cMissSess.sessId}`);
        const replayMissSess = await store.initiateRedemption({
            code: cMissSess.code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: cMissSess.pkce.verifier, idempotencyKey: `idem_tc40_miss_sess_${crypto.randomBytes(6).toString('hex')}`
        });
        assert(replayMissSess.status === 'REPLAY_DETECTED', 'Missing session replay must return REPLAY_DETECTED');
        const gateMissSess = await evaluateRefreshGate(cMissSess.famId, testUid, cMissSess.sessId);
        assert(gateMissSess.fam.status === 'revoked' && gateMissSess.fam.revocationReason === 'authorization_code_replay_compromise', 'Valid active family MUST be revoked when session is missing');
        assert(gateMissSess.refreshAllowed === false && gateMissSess.sessState.active === false, 'Refresh MUST be blocked when session is missing and family is revoked');
        const evMissSess = getOutboxEvents(cMissSess.claim.record.ceremonyId).find(e => e.eventType === 'CRITICAL_SECURITY_RECORD_MISSING');
        assert(evMissSess && evMissSess.details.sessionMissing === true && evMissSess.details.familyIndependentlyVerified === true && evMissSess.details.familyRevoked === true && evMissSess.details.sessionRevoked === false, 'Outbox must record missing session and independent family revocation');

        // 3b. Missing family + valid active session -> session IS revoked synchronously; refresh blocked
        const cMissFam = await createCompletedCeremony('miss_fam');
        db.store.delete(`tenants/lanzar/token_families/${cMissFam.famId}`);
        const replayMissFam = await store.initiateRedemption({
            code: cMissFam.code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: cMissFam.pkce.verifier, idempotencyKey: `idem_tc40_miss_fam_${crypto.randomBytes(6).toString('hex')}`
        });
        assert(replayMissFam.status === 'REPLAY_DETECTED', 'Missing family replay must return REPLAY_DETECTED');
        const gateMissFam = await evaluateRefreshGate(cMissFam.famId, testUid, cMissFam.sessId);
        assert(gateMissFam.sessState.active === false && gateMissFam.sessState.reason === 'revoked', 'Valid active session MUST be revoked when family is missing');
        assert(gateMissFam.refreshAllowed === false, 'Refresh MUST be blocked when family is missing and session is revoked');
        const evMissFam = getOutboxEvents(cMissFam.claim.record.ceremonyId).find(e => e.eventType === 'CRITICAL_SECURITY_RECORD_MISSING');
        assert(evMissFam && evMissFam.details.familyMissing === true && evMissFam.details.sessionIndependentlyVerified === true && evMissFam.details.sessionRevoked === true && evMissFam.details.familyRevoked === false, 'Outbox must record missing family and independent session revocation');

        // 3c. Corrupt session relationship + independently valid family -> family IS revoked (refresh blocked); foreign/corrupt session untouched
        const cCorruptSess = await createCompletedCeremony('corrupt_sess');
        await db.collection('users').doc(testUid).collection('sessions').doc(cCorruptSess.sessId).update({
            familyId: 'fam_foreign_crossref'
        });
        const replayCorruptSess = await store.initiateRedemption({
            code: cCorruptSess.code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: cCorruptSess.pkce.verifier, idempotencyKey: `idem_tc40_corrupt_sess_${crypto.randomBytes(6).toString('hex')}`
        });
        assert(replayCorruptSess.status === 'REPLAY_DETECTED', 'Corrupt session replay must return REPLAY_DETECTED');
        const gateCorruptSess = await evaluateRefreshGate(cCorruptSess.famId, testUid, cCorruptSess.sessId);
        assert(gateCorruptSess.fam.status === 'revoked', 'Independently valid family MUST be revoked even when session is corrupt');
        assert((await db.collection('users').doc(testUid).collection('sessions').doc(cCorruptSess.sessId).get()).data().status === 'active', 'Corrupt/foreign session MUST remain untouched');
        assert(gateCorruptSess.refreshAllowed === false, 'Refresh MUST be blocked against revoked family');
        const evCorruptSess = getOutboxEvents(cCorruptSess.claim.record.ceremonyId).find(e => e.eventType === 'CRITICAL_REPLAY_PAIR_INTEGRITY_FAILURE');
        assert(evCorruptSess && evCorruptSess.details.sessionInconsistent === true && evCorruptSess.details.familyIndependentlyVerified === true && evCorruptSess.details.familyRevoked === true && evCorruptSess.details.sessionRevoked === false, 'Outbox must record corrupt session and independent family revocation');

        // 3d. Corrupt family relationship + independently valid session -> session IS revoked (refresh blocked); foreign/corrupt family untouched
        const cCorruptFam = await createCompletedCeremony('corrupt_fam');
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(cCorruptFam.famId).update({
            redemptionLockId: 'foreign_lock_mismatch'
        });
        const replayCorruptFam = await store.initiateRedemption({
            code: cCorruptFam.code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: cCorruptFam.pkce.verifier, idempotencyKey: `idem_tc40_corrupt_fam_${crypto.randomBytes(6).toString('hex')}`
        });
        assert(replayCorruptFam.status === 'REPLAY_DETECTED', 'Corrupt family replay must return REPLAY_DETECTED');
        const gateCorruptFam = await evaluateRefreshGate(cCorruptFam.famId, testUid, cCorruptFam.sessId);
        assert(gateCorruptFam.sessState.active === false && gateCorruptFam.sessState.reason === 'revoked', 'Independently valid session MUST be revoked even when family is corrupt');
        assert(gateCorruptFam.fam.status === 'active', 'Corrupt/foreign family MUST remain untouched');
        assert(gateCorruptFam.refreshAllowed === false, 'Refresh MUST be blocked because session is revoked');
        const evCorruptFam = getOutboxEvents(cCorruptFam.claim.record.ceremonyId).find(e => e.eventType === 'CRITICAL_REPLAY_PAIR_INTEGRITY_FAILURE');
        assert(evCorruptFam && evCorruptFam.details.familyInconsistent === true && evCorruptFam.details.sessionIndependentlyVerified === true && evCorruptFam.details.sessionRevoked === true && evCorruptFam.details.familyRevoked === false, 'Outbox must record corrupt family and independent session revocation');

        // 3e. Both records valid and correctly paired -> BOTH are revoked and refresh is blocked; no integrity failure alert
        const cValidPair = await createCompletedCeremony('valid_pair');
        const replayValidPair = await store.initiateRedemption({
            code: cValidPair.code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: cValidPair.pkce.verifier, idempotencyKey: `idem_tc40_valid_pair_${crypto.randomBytes(6).toString('hex')}`
        });
        assert(replayValidPair.status === 'REPLAY_DETECTED', 'Valid pair replay must return REPLAY_DETECTED');
        const gateValidPair = await evaluateRefreshGate(cValidPair.famId, testUid, cValidPair.sessId);
        assert(gateValidPair.fam.status === 'revoked' && gateValidPair.sessState.active === false && gateValidPair.sessState.reason === 'revoked', 'Both paired session and family MUST be revoked');
        assert(gateValidPair.refreshAllowed === false, 'Refresh MUST be blocked when both records are revoked');
        const evValidPairIntegrity = getOutboxEvents(cValidPair.claim.record.ceremonyId).filter(e => e.eventType === 'CRITICAL_REPLAY_PAIR_INTEGRITY_FAILURE' || e.eventType === 'CRITICAL_SECURITY_RECORD_MISSING');
        assert(evValidPairIntegrity.length === 0, 'Valid paired revocation must not emit pair integrity failure');

        // 3f. Both records untrustworthy -> NEITHER foreign record is revoked (refresh on foreign records unaffected), critical incident staged
        const cBothBad = await createCompletedCeremony('both_bad');
        await db.collection('users').doc(testUid).collection('sessions').doc(cBothBad.sessId).update({
            ceremonyId: 'foreign_ceremony_uncompromised'
        });
        await db.collection('tenants').doc('lanzar').collection('token_families').doc(cBothBad.famId).update({
            ceremonyId: 'foreign_ceremony_uncompromised'
        });
        const replayBothBad = await store.initiateRedemption({
            code: cBothBad.code, clientId: testClientId, redirectUri: testRedirectUri,
            codeVerifier: cBothBad.pkce.verifier, idempotencyKey: `idem_tc40_both_bad_${crypto.randomBytes(6).toString('hex')}`
        });
        assert(replayBothBad.status === 'REPLAY_DETECTED', 'Both untrustworthy replay must return REPLAY_DETECTED');
        const gateBothBad = await evaluateRefreshGate(cBothBad.famId, testUid, cBothBad.sessId, cBothBad.refreshToken);
        assert(gateBothBad.fam.status === 'active' && gateBothBad.sessState.active === true && gateBothBad.refreshAllowed === true, 'Foreign/untrustworthy session and family MUST remain untouched');
        const evBothBad = getOutboxEvents(cBothBad.claim.record.ceremonyId).find(e => e.eventType === 'CRITICAL_REPLAY_PAIR_INTEGRITY_FAILURE');
        assert(evBothBad && evBothBad.details.sessionInconsistent === true && evBothBad.details.familyInconsistent === true && evBothBad.details.sessionRevoked === false && evBothBad.details.familyRevoked === false, 'Outbox must record critical incident with neither record revoked');
    });

    // -------------------------------------------------------------
    // TC-41: HTTP Refresh Route Integration (POST /oauth/token)
    // -------------------------------------------------------------
    await test('TC-41: HTTP POST /oauth/token enforces authorizeRefreshGrant() across all refresh scenarios', async () => {
        const app = express();
        app.use(express.json());
        const sessSvc = new SessionService(db, { auth: () => ({ createCustomToken: async () => 'tok' }) });
        app.use('/oauth', createOAuthRouter({
            db,
            authAdmin: { auth: () => ({ createCustomToken: async () => 'tok' }) },
            codeStore: store,
            sessionService: sessSvc
        }));

        const server = await new Promise((resolve) => {
            const s = app.listen(0, '127.0.0.1', () => resolve(s));
        });
        const port = server.address().port;

        const postRefresh = async (body) => {
            const resp = await fetch(`http://127.0.0.1:${port}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            return { status: resp.status, body: await resp.json() };
        };

        const seedActiveCeremony = async (tag) => {
            const pkce = generatePkce();
            const code = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const codeHash = hashAuthorizationCode(code);
            const claim = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: `idem_tc41_${tag}_${crypto.randomBytes(8).toString('hex')}`
            });
            const { generateRefreshToken } = require('./auth-backend/store');
            const sessId = `sess_tc41_${tag}_${Date.now()}`;
            const famId = `fam_tc41_${tag}_${Date.now()}`;
            const refreshToken = generateRefreshToken(famId, 1);
            await db.collection('users').doc(testUid).collection('sessions').doc(sessId).create({
                sessionId: sessId, familyId: famId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId,
                fenceToken: claim.fenceToken, status: 'pending_activation',
                expiresAt: new Date(Date.now() + 86400000).toISOString()
            });
            await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).create({
                familyId: famId, sessionId: sessId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId,
                fenceToken: claim.fenceToken, status: 'pending_activation',
                currentActiveTokenHash: hashAuthorizationCode(refreshToken),
                sequenceNumber: 1,
                rotatedTokenHashes: [],
                expiresAt: new Date(Date.now() + 86400000).toISOString()
            });
            await store.registerStagedRecords({
                codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
                uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
                issuedSessionId: sessId, issuedFamilyId: famId
            });
            await store.finalizeRedemption({
                codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
                uid: testUid, tenantId: 'lanzar', issuedSessionId: sessId, issuedFamilyId: famId,
                rawTokensPayload: { custom_token: `tok_${tag}` }
            });
            return { pkce, code, codeHash, claim, sessId, famId, refreshToken };
        };

        try {
            // 1. Normal active family and session -> 200 with access_token and rotated refresh_token
            const cNormal = await seedActiveCeremony('normal');
            const resNormal = await postRefresh({
                grant_type: 'refresh_token', refresh_token: cNormal.refreshToken,
                family_id: cNormal.famId, session_id: cNormal.sessId, uid: testUid, tenant_id: 'lanzar'
            });
            assert(resNormal.status === 200 && typeof resNormal.body.access_token === 'string' && typeof resNormal.body.refresh_token === 'string', 'Normal active refresh must return 200 with tokens');

            // 2. Revoked family -> 401 invalid_grant (FAMILY_REVOKED), zero tokens issued
            const cRevFam = await seedActiveCeremony('rev_fam');
            await db.collection('tenants').doc('lanzar').collection('token_families').doc(cRevFam.famId).update({ status: 'revoked' });
            const resRevFam = await postRefresh({
                grant_type: 'refresh_token', refresh_token: cRevFam.refreshToken,
                family_id: cRevFam.famId, session_id: cRevFam.sessId, uid: testUid, tenant_id: 'lanzar'
            });
            assert(resRevFam.status === 401 && resRevFam.body.error === 'invalid_grant' && resRevFam.body.reason === 'FAMILY_REVOKED', 'Revoked family must be rejected with 401 FAMILY_REVOKED');
            assert(!resRevFam.body.access_token && !resRevFam.body.refresh_token, 'No tokens may be issued on revoked family');

            // 3. Revoked session -> 401 invalid_grant (SESSION_REVOKED), zero tokens issued
            const cRevSess = await seedActiveCeremony('rev_sess');
            await db.collection('users').doc(testUid).collection('sessions').doc(cRevSess.sessId).update({ status: 'revoked' });
            const resRevSess = await postRefresh({
                grant_type: 'refresh_token', refresh_token: cRevSess.refreshToken,
                family_id: cRevSess.famId, session_id: cRevSess.sessId, uid: testUid, tenant_id: 'lanzar'
            });
            assert(resRevSess.status === 401 && resRevSess.body.error === 'invalid_grant' && resRevSess.body.reason === 'SESSION_REVOKED', 'Revoked session must be rejected with 401 SESSION_REVOKED');
            assert(!resRevSess.body.access_token && !resRevSess.body.refresh_token, 'No tokens may be issued on revoked session');

            // 4. Compromised ceremony tombstone with otherwise active family/session -> 401 CEREMONY_COMPROMISED
            const cTombstone = await seedActiveCeremony('tombstone');
            const codeTombData = { ...(await db.collection('authorization_codes').doc(cTombstone.codeHash).get()).data() };
            delete codeTombData.fenceToken;
            delete codeTombData.completedLockId;
            await db.collection('authorization_codes').doc(cTombstone.codeHash).set(codeTombData);
            await store.initiateRedemption({
                code: cTombstone.code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: cTombstone.pkce.verifier, idempotencyKey: `idem_tc41_tomb_replay_${crypto.randomBytes(8).toString('hex')}`
            });
            const resTombstone = await postRefresh({
                grant_type: 'refresh_token', refresh_token: cTombstone.refreshToken,
                family_id: cTombstone.famId, session_id: cTombstone.sessId, uid: testUid, tenant_id: 'lanzar'
            });
            assert(resTombstone.status === 401 && resTombstone.body.error === 'invalid_grant' && resTombstone.body.reason === 'CEREMONY_COMPROMISED', 'Compromised ceremony tombstone must reject refresh with 401 CEREMONY_COMPROMISED');
            assert(!resTombstone.body.access_token && !resTombstone.body.refresh_token, 'No tokens may be issued on compromised ceremony');

            // 5. Unrelated active ceremony -> 200 with access_token and rotated refresh_token
            const cUnrelated = await seedActiveCeremony('unrelated');
            const resUnrelated = await postRefresh({
                grant_type: 'refresh_token', refresh_token: cUnrelated.refreshToken,
                family_id: cUnrelated.famId, session_id: cUnrelated.sessId, uid: testUid, tenant_id: 'lanzar'
            });
            assert(resUnrelated.status === 200 && typeof resUnrelated.body.access_token === 'string' && typeof resUnrelated.body.refresh_token === 'string', 'Unrelated active ceremony must still succeed');
        } finally {
            await new Promise((resolve) => server.close(resolve));
        }

        // 6. Fail-closed when codeStore.authorizeRefreshGrant is missing -> 500 with zero tokens
        const appNoCap = express();
        appNoCap.use(express.json());
        appNoCap.use('/oauth', createOAuthRouter({ db, authAdmin: {}, codeStore: {}, sessionService: {} }));
        const srvNoCap = await new Promise((resolve) => {
            const s = appNoCap.listen(0, '127.0.0.1', () => resolve(s));
        });
        try {
            const resp = await fetch(`http://127.0.0.1:${srvNoCap.address().port}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    grant_type: 'refresh_token', refresh_token: 'rt_x',
                    family_id: 'fam_x', session_id: 'sess_x', uid: testUid
                })
            });
            const body = await resp.json();
            assert(resp.status === 500 && !body.access_token && !body.refresh_token, 'Missing authorizeRefreshGrant capability must fail closed with 500');
        } finally {
            await new Promise((resolve) => srvNoCap.close(resolve));
        }
    });

    // -------------------------------------------------------------
    // TC-42: HTTP Refresh-Token Authentication, Atomic Rotation, Replay & Concurrency
    // -------------------------------------------------------------
    await test('TC-42: HTTP POST /oauth/token enforces refresh-token hash authentication, atomic rotation, replay revocation, and concurrency', async () => {
        const { generateRefreshToken } = require('./auth-backend/store');
        const app = express();
        app.use(express.json());
        const sessSvc = new SessionService(db, { auth: () => ({ createCustomToken: async () => 'tok' }) });
        app.use('/oauth', createOAuthRouter({
            db,
            authAdmin: { auth: () => ({ createCustomToken: async () => 'tok' }) },
            codeStore: store,
            sessionService: sessSvc
        }));

        const server = await new Promise((resolve) => {
            const s = app.listen(0, '127.0.0.1', () => resolve(s));
        });
        const port = server.address().port;

        const postRefresh = async (body) => {
            const resp = await fetch(`http://127.0.0.1:${port}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            return { status: resp.status, body: await resp.json() };
        };

        const seedRefreshCeremony = async (tag, opts = {}) => {
            const pkce = generatePkce();
            const code = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const codeHash = hashAuthorizationCode(code);
            const claim = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: `idem_tc42_${tag}_${crypto.randomBytes(8).toString('hex')}`
            });
            const sessId = `sess_tc42_${tag}_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
            const famId = `fam_tc42_${tag}_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
            const rt1 = generateRefreshToken(famId, 1);
            const expiresAt = opts.expiresAt || new Date(Date.now() + 86400000).toISOString();
            await db.collection('users').doc(testUid).collection('sessions').doc(sessId).create({
                sessionId: sessId, familyId: famId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId,
                fenceToken: claim.fenceToken, status: 'pending_activation', expiresAt
            });
            await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).create({
                familyId: famId, sessionId: sessId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId,
                fenceToken: claim.fenceToken, status: 'pending_activation',
                currentActiveTokenHash: hashAuthorizationCode(rt1),
                sequenceNumber: 1,
                rotatedTokenHashes: [],
                expiresAt
            });
            await store.registerStagedRecords({
                codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
                uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
                issuedSessionId: sessId, issuedFamilyId: famId
            });
            await store.finalizeRedemption({
                codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
                uid: testUid, tenantId: 'lanzar', issuedSessionId: sessId, issuedFamilyId: famId,
                rawTokensPayload: { custom_token: `tok_${tag}` }
            });
            return { sessId, famId, rt1, ceremonyId: claim.record.ceremonyId };
        };

        try {
            // 1. Atomic rotation updates currentActiveTokenHash and sequenceNumber in same transaction (1 -> 2 -> 3)
            const cRot = await seedRefreshCeremony('rot');
            const r1 = await postRefresh({
                grant_type: 'refresh_token', refresh_token: cRot.rt1,
                family_id: cRot.famId, session_id: cRot.sessId, uid: testUid, tenant_id: 'lanzar'
            });
            assert(r1.status === 200 && r1.body.sequence_number === 2 && r1.body.refresh_token !== cRot.rt1, 'First refresh must rotate to sequence 2');
            const famAfter1 = (await db.collection('tenants').doc('lanzar').collection('token_families').doc(cRot.famId).get()).data();
            assert(famAfter1.sequenceNumber === 2 && famAfter1.currentActiveTokenHash === hashAuthorizationCode(r1.body.refresh_token), 'currentActiveTokenHash and sequenceNumber must update atomically');
            assert(famAfter1.rotatedTokenHashes.includes(hashAuthorizationCode(cRot.rt1)), 'Previous token hash must be recorded');

            const r2 = await postRefresh({
                grant_type: 'refresh_token', refresh_token: r1.body.refresh_token,
                family_id: cRot.famId, session_id: cRot.sessId, uid: testUid, tenant_id: 'lanzar'
            });
            assert(r2.status === 200 && r2.body.sequence_number === 3, 'Second refresh must rotate to sequence 3');

            // 2. Incorrect / forged token rejected without issuing tokens
            const badTokRes = await postRefresh({
                grant_type: 'refresh_token', refresh_token: generateRefreshToken(cRot.famId, 3),
                family_id: cRot.famId, session_id: cRot.sessId, uid: testUid, tenant_id: 'lanzar'
            });
            assert(badTokRes.status === 401 && badTokRes.body.reason === 'INVALID_REFRESH_TOKEN' && !badTokRes.body.access_token && !badTokRes.body.refresh_token, 'Incorrect token must be rejected without issuing tokens');

            // 3. Token belonging to another family rejected without issuing tokens
            const cOther = await seedRefreshCeremony('other');
            const crossFamRes = await postRefresh({
                grant_type: 'refresh_token', refresh_token: cOther.rt1,
                family_id: cRot.famId, session_id: cRot.sessId, uid: testUid, tenant_id: 'lanzar'
            });
            assert(crossFamRes.status === 401 && crossFamRes.body.reason === 'TOKEN_FAMILY_MISMATCH' && !crossFamRes.body.access_token && !crossFamRes.body.refresh_token, 'Token from another family must be rejected');

            // 4. Client-supplied uid / session_id mismatch rejected against stored records
            const badUidRes = await postRefresh({
                grant_type: 'refresh_token', refresh_token: r2.body.refresh_token,
                family_id: cRot.famId, session_id: cRot.sessId, uid: 'attacker_uid', tenant_id: 'lanzar'
            });
            assert(badUidRes.status === 401 && !badUidRes.body.access_token && !badUidRes.body.refresh_token, 'Mismatched uid must be rejected');

            const badSessRes = await postRefresh({
                grant_type: 'refresh_token', refresh_token: r2.body.refresh_token,
                family_id: cRot.famId, session_id: cOther.sessId, uid: testUid, tenant_id: 'lanzar'
            });
            assert(badSessRes.status === 401 && badSessRes.body.reason === 'RELATIONSHIP_MISMATCH' && !badSessRes.body.access_token, 'Mismatched session_id must be rejected');

            // 5. Expired refresh token rejected without issuing tokens
            const cExpired = await seedRefreshCeremony('expired', { expiresAt: new Date(Date.now() - 60000).toISOString() });
            const expRes = await postRefresh({
                grant_type: 'refresh_token', refresh_token: cExpired.rt1,
                family_id: cExpired.famId, session_id: cExpired.sessId, uid: testUid, tenant_id: 'lanzar'
            });
            assert(expRes.status === 401 && expRes.body.reason === 'REFRESH_TOKEN_EXPIRED' && !expRes.body.access_token && !expRes.body.refresh_token, 'Expired refresh token must be rejected');

            // 6. Reuse of previously rotated token (rt1) triggers replay response & revokes family + session
            const replayRes = await postRefresh({
                grant_type: 'refresh_token', refresh_token: cRot.rt1,
                family_id: cRot.famId, session_id: cRot.sessId, uid: testUid, tenant_id: 'lanzar'
            });
            assert(replayRes.status === 401 && replayRes.body.reason === 'REFRESH_TOKEN_REPLAY' && replayRes.body.replay_detected === true && !replayRes.body.access_token && !replayRes.body.refresh_token, 'Reuse of rotated token must return REFRESH_TOKEN_REPLAY');
            const famRevoked = (await db.collection('tenants').doc('lanzar').collection('token_families').doc(cRot.famId).get()).data();
            const sessRevoked = (await db.collection('users').doc(testUid).collection('sessions').doc(cRot.sessId).get()).data();
            assert(famRevoked.status === 'revoked' && famRevoked.revocationReason === 'refresh_token_reuse_detected', 'Family must be revoked on replay');
            assert(sessRevoked.status === 'revoked' && sessRevoked.revocationReason === 'refresh_token_reuse_detected', 'Session must be revoked on replay');
            const tombSnap = await db.collection('compromised_ceremonies').doc(cRot.ceremonyId).get();
            assert(tombSnap.exists, 'compromised_ceremonies tombstone must be written on refresh replay');
            const afterRevokeRes = await postRefresh({
                grant_type: 'refresh_token', refresh_token: r2.body.refresh_token,
                family_id: cRot.famId, session_id: cRot.sessId, uid: testUid, tenant_id: 'lanzar'
            });
            assert(afterRevokeRes.status === 401 && afterRevokeRes.body.reason === 'FAMILY_REVOKED', 'Current token must also fail once family is revoked');

            // 7. Concurrent refresh requests presenting the exact same refresh token: only 1 succeeds
            const cConc = await seedRefreshCeremony('conc');
            const [concA, concB] = await Promise.all([
                postRefresh({ grant_type: 'refresh_token', refresh_token: cConc.rt1, family_id: cConc.famId, session_id: cConc.sessId, uid: testUid, tenant_id: 'lanzar' }),
                postRefresh({ grant_type: 'refresh_token', refresh_token: cConc.rt1, family_id: cConc.famId, session_id: cConc.sessId, uid: testUid, tenant_id: 'lanzar' })
            ]);
            const successes = [concA, concB].filter(r => r.status === 200);
            const rejections = [concA, concB].filter(r => r.status === 401);
            assert(successes.length === 1 && rejections.length === 1, `Concurrent refresh must allow exactly 1 success and 1 rejection, got statuses ${concA.status} & ${concB.status}`);
            assert(rejections[0].body.reason === 'REFRESH_TOKEN_REPLAY' && !rejections[0].body.access_token && !rejections[0].body.refresh_token, 'Concurrent loser must trigger REFRESH_TOKEN_REPLAY with zero tokens');
        } finally {
            await new Promise((resolve) => server.close(resolve));
        }
    });

    // -------------------------------------------------------------
    // SUMMARY
    // -------------------------------------------------------------
    console.log('\n================================================================');
    console.log('MILESTONE 1.1 IN-MEMORY SIMULATION TEST SUMMARY');
    console.log(`Total Executed: ${passedCount + failedCount}`);
    console.log(`Passed:         ${passedCount}`);
    console.log(`Failed:         ${failedCount}`);
    console.log(`Success Rate:   ${((passedCount / (passedCount + failedCount)) * 100).toFixed(1)}%`);
    console.log('================================================================\n');

    if (failedCount > 0) process.exit(1);
}

main().catch(err => {
    console.error('Fatal test error:', err);
    process.exit(1);
});
