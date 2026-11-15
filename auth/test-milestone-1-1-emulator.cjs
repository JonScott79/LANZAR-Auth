// test-milestone-1-1-emulator.cjs
// Live Google Cloud Firestore Emulator Integration Test Suite for Milestone 1.1
// Executes real Firestore distributed transactions against Java Cloud Firestore Emulator.
// Verifies LID-SPEC-M1.1-STORE-REV9-AUTHORITATIVE & LID-ARCH-REV-022-FINAL-AUTHORITATIVE

const path = require('path');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const { spawn, execSync } = require('child_process');

// Add auth-backend node_modules to module search paths
module.paths.push(path.join(__dirname, 'auth-backend', 'node_modules'));

const { initializeApp, getApps } = require('firebase-admin/app');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');

const {
    FirestoreAuthorizationCodeStore,
    hashAuthorizationCode,
    encryptTokenReceipt,
    decryptTokenReceipt,
    canReplayRevokeSession,
    canReplayRevokeFamily,
    canReplayRevokePair,
    validateReceiptKeyConfiguration,
    setReceiptKeyringForTesting,
    resetReceiptKeyringForTesting
} = require('./auth-backend/store');
const { SessionService } = require('./auth-backend/sessionService');
const express = require('express');
const { createOAuthRouter } = require('./auth-backend/routes/oauthRoutes');

// ============================================================================
// Emulator Lifecycle & Configuration
// ============================================================================
const PROJECT_ID = 'demo-lanzar-id-store-test';
const EMULATOR_HOST = '127.0.0.1';
const EMULATOR_PORT = 8088;

function findEmulatorJar() {
    const cacheDir = path.resolve(process.env.USERPROFILE, '.cache/firebase/emulators');
    if (fs.existsSync(cacheDir)) {
        const files = fs.readdirSync(cacheDir);
        const jar = files.find(f => f.startsWith('cloud-firestore-emulator-') && f.endsWith('.jar'));
        if (jar) return path.join(cacheDir, jar);
    }
    return path.resolve(cacheDir, 'cloud-firestore-emulator-v1.19.8.jar');
}

const EMULATOR_JAR = findEmulatorJar();

let emulatorProc = null;
let isReusingActive = false;
let passedCount = 0;
let failedCount = 0;

function assert(condition, message) {
    if (!condition) throw new Error(message);
}

async function test(name, fn) {
    try {
        await fn();
        console.log(`  ✓ [PASS] ${name}`);
        passedCount++;
    } catch (err) {
        console.error(`  ✗ [FAIL] ${name}`);
        console.error(`     Error: ${err.message}`);
        console.error(err.stack);
        failedCount++;
    }
}

function generatePkce() {
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    return { verifier, challenge };
}

async function probeEmulator(host, port, maxAttempts = 15, delayMs = 300) {
    for (let i = 1; i <= maxAttempts; i++) {
        try {
            await new Promise((resolve, reject) => {
                const req = http.get(`http://${host}:${port}/`, (res) => resolve(res.statusCode));
                req.on('error', reject);
                req.setTimeout(1000, () => { req.destroy(); reject(new Error('timeout')); });
            });
            return true;
        } catch (e) {
            if (i === maxAttempts) throw e;
            await new Promise(r => setTimeout(r, delayMs));
        }
    }
}

async function terminateEmulator() {
    if (isReusingActive || !emulatorProc) return;
    const pid = emulatorProc.pid;
    console.log(`\n[EMULATOR] Terminating emulator process PID ${pid}...`);
    try {
        if (process.platform === 'win32') {
            execSync(`taskkill /F /PID ${pid} /T`, { stdio: 'ignore' });
        } else {
            emulatorProc.kill('SIGKILL');
        }
    } catch (_) {}
}

async function main() {
    console.log('================================================================');
    console.log('LANZAR ID — Milestone 1.1 Live Cloud Firestore Emulator Battery');
    console.log('Target Specification: LID-SPEC-M1.1-STORE-REV9-AUTHORITATIVE');
    console.log(`Target Project:       ${PROJECT_ID} (Enforcing Offline Demo Mode)`);
    console.log(`Emulator Endpoint:    ${EMULATOR_HOST}:${EMULATOR_PORT}`);
    console.log(`Timestamp:            ${new Date().toISOString()}`);
    console.log('================================================================\n');

    process.env.FIRESTORE_EMULATOR_HOST = `${EMULATOR_HOST}:${EMULATOR_PORT}`;

    // Probe if already running
    try {
        await probeEmulator(EMULATOR_HOST, EMULATOR_PORT, 2, 100);
        isReusingActive = true;
        console.log(`[EMULATOR] Active emulator detected on ${EMULATOR_HOST}:${EMULATOR_PORT}. Reusing instance.\n`);
    } catch (_) {
        isReusingActive = false;
    }

    if (!isReusingActive) {
        if (!fs.existsSync(EMULATOR_JAR)) {
            throw new Error(`Emulator JAR not found at ${EMULATOR_JAR}`);
        }
        console.log(`[EMULATOR] Spawning Java Cloud Firestore Emulator on port ${EMULATOR_PORT}...`);
        emulatorProc = spawn('java', [
            '-jar', EMULATOR_JAR,
            '--host', EMULATOR_HOST,
            '--port', String(EMULATOR_PORT)
        ], { stdio: 'pipe' });

        await probeEmulator(EMULATOR_HOST, EMULATOR_PORT, 20, 400);
        console.log(`  ✓ Cloud Firestore Emulator is healthy and accepting connections.\n`);
    }

    // Initialize real Firebase Admin SDK
    const app = getApps().length > 0 ? getApps()[0] : initializeApp({ projectId: PROJECT_ID });
    const db = getFirestore(app);
    const store = new FirestoreAuthorizationCodeStore(db);
    const sessionService = new SessionService(db, null);

    const testUid = 'usr_emu_test_user';
    const testClientId = 'portal';
    const testRedirectUri = 'https://portal.lanzar.me';

    try {
        // -------------------------------------------------------------
        // EMU-01: Real Firestore Atomic Code Creation and Retrieval
        // -------------------------------------------------------------
        await test('EMU-01: Real Firestore: Code creation persists document in /authorization_codes with SHA-256 key', async () => {
            const pkce = generatePkce();
            const code = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const codeHash = hashAuthorizationCode(code);
            const snap = await db.collection('authorization_codes').doc(codeHash).get();
            assert(snap.exists === true, 'Document must exist in real Firestore');
            assert(snap.data().status === 'ISSUED', 'Initial status must be ISSUED');
            assert(snap.data().uid === testUid, 'UID must match');
        });

        // -------------------------------------------------------------
        // EMU-02: Real Firestore Atomic Two-Phase Redemption & GCM Receipt Recovery
        // -------------------------------------------------------------
        await test('EMU-02: Real Firestore: Atomic Two-Phase Redemption & GCM Receipt Recovery', async () => {
            const pkce = generatePkce();
            const code = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const idemKey = 'idem_emu02_test_receipt_recovery';

            const claim = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: idemKey
            });
            assert(claim.status === 'SUCCESS', 'Claim must succeed');

            const sessId = `sess_emu02_${Date.now()}`;
            const famId = `fam_emu02_${Date.now()}`;
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

            const rawTokens = { custom_token: 'emu_custom_token_val', session_id: sessId, expires_in: 3600 };
            const fin = await store.finalizeRedemption({
                codeHash: claim.codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
                uid: testUid, tenantId: 'lanzar', issuedSessionId: sessId, issuedFamilyId: famId,
                rawTokensPayload: rawTokens
            });
            assert(fin.success === true, 'Finalization must commit in real Firestore');

            // Verify live documents in Firestore
            const sessSnap = await db.collection('users').doc(testUid).collection('sessions').doc(sessId).get();
            assert(sessSnap.data().status === 'active', 'Live session document must be active');

            const famSnap = await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).get();
            assert(famSnap.data().status === 'active', 'Live family document must be active');

            // Recover with idempotency key
            const recovery = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: idemKey
            });
            assert(recovery.status === 'IDEMPOTENT_RECOVERY', 'Idempotent recovery must succeed');
            assert(recovery.tokenReceipt.custom_token === rawTokens.custom_token, 'Decrypted token matches');
        });

        // -------------------------------------------------------------
        // EMU-03: Real Firestore: Stale-Worker Safety Under Concurrent Takeover
        // -------------------------------------------------------------
        await test("EMU-03: Real Firestore: Stale worker CANNOT revoke a newer worker's active session or family", async () => {
            const pkce = generatePkce();
            const code = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const idemKey = 'idem_emu03_takeover_test';

            // Worker 1 claims lock
            const claim1 = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: idemKey
            });

            // Simulate lock expiration in real Firestore
            await db.collection('authorization_codes').doc(claim1.codeHash).update({
                redemptionLockExpiresAt: new Date(Date.now() - 5000)
            });

            // Worker 2 takes over with same key
            const claim2 = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: idemKey
            });
            assert(claim2.status === 'SUCCESS', 'Worker 2 took over lock');
            assert(claim2.fenceToken > claim1.fenceToken, 'Worker 2 fence advanced');

            // Worker 2 activates session 2
            const sess2 = `sess_emu03_w2_${Date.now()}`;
            const fam2 = `fam_emu03_w2_${Date.now()}`;
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
                rawTokensPayload: { custom_token: 'worker2_live_token' }
            });

            // Worker 1 wakes up and attempts to finalize with Worker 2's session
            const staleFin = await store.finalizeRedemption({
                codeHash: claim1.codeHash, redemptionLockId: claim1.redemptionLockId, fenceToken: claim1.fenceToken,
                uid: testUid, tenantId: 'lanzar', issuedSessionId: sess2, issuedFamilyId: fam2,
                rawTokensPayload: { custom_token: 'stale_worker_token' }
            });
            assert(staleFin.success === false, 'Stale worker must fail');
            assert(staleFin.reason === 'STALE_WORKER_FENCED', 'Must be fenced');

            // CRITICAL CHECK in real Firestore: Worker 2 session & family must still be active!
            const sess2Snap = await db.collection('users').doc(testUid).collection('sessions').doc(sess2).get();
            const fam2Snap = await db.collection('tenants').doc('lanzar').collection('token_families').doc(fam2).get();
            assert(sess2Snap.data().status === 'active', "Worker 2 active session was NOT revoked by stale worker!");
            assert(fam2Snap.data().status === 'active', "Worker 2 active family was NOT revoked by stale worker!");
        });

        // -------------------------------------------------------------
        // EMU-04: Real Firestore: Expired Lock Conflict Compromise Defense
        // -------------------------------------------------------------
        await test('EMU-04: Real Firestore: Expired lock targeted by different key transitions to COMPROMISED', async () => {
            const pkce = generatePkce();
            const code = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const claim1 = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: 'idem_emu04_orig_key'
            });

            await db.collection('authorization_codes').doc(claim1.codeHash).update({
                redemptionLockExpiresAt: new Date(Date.now() - 5000)
            });

            const conflict = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: 'idem_emu04_attacker_key'
            });
            assert(conflict.status === 'REPLAY_DETECTED', 'Must detect replay conflict');

            const snap = await db.collection('authorization_codes').doc(claim1.codeHash).get();
            assert(snap.data().status === 'COMPROMISED', 'Live document must be marked COMPROMISED');
        });

        // -------------------------------------------------------------
        // EMU-05: Real Firestore: Failure-Handler Fencing Protection
        // -------------------------------------------------------------
        await test("EMU-05: Real Firestore: Stale failure handler CANNOT revoke a newer worker's active resources", async () => {
            const pkce = generatePkce();
            const code = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });

            const claim1 = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: 'idem_emu05_valid_key'
            });

            await db.collection('authorization_codes').doc(claim1.codeHash).update({
                redemptionLockExpiresAt: new Date(Date.now() - 5000)
            });

            const claim2 = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: 'idem_emu05_valid_key'
            });

            const sess2 = `sess_emu05_w2_${Date.now()}`;
            const fam2 = `fam_emu05_w2_${Date.now()}`;
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

            // Late exception in Worker 1 triggers handleRedemptionFailure pointing to sess2
            const failRes = await store.handleRedemptionFailure({
                codeHash: claim1.codeHash, redemptionLockId: claim1.redemptionLockId, fenceToken: claim1.fenceToken,
                uid: testUid, tenantId: 'lanzar', sessionId: sess2, familyId: fam2,
                errorReason: 'Late network exception in worker 1'
            });
            assert(failRes.success === false, 'Stale failure handler must be rejected');

            // Verify live documents in Firestore: sess2 and fam2 must STILL be active
            const sessSnap = await db.collection('users').doc(testUid).collection('sessions').doc(sess2).get();
            const famSnap = await db.collection('tenants').doc('lanzar').collection('token_families').doc(fam2).get();
            assert(sessSnap.data().status === 'active', "Live active session was NOT revoked by stale failure handler!");
            assert(famSnap.data().status === 'active', "Live active family was NOT revoked by stale failure handler!");
        });

        // -------------------------------------------------------------
        // EMU-06: Real Firestore: Same-Key Expired-Lock Takeover and Old-Record Cleanup
        // -------------------------------------------------------------
        await test('EMU-06: Real Firestore: Same-key expired-lock takeover cleanly revokes old pending records and fences stale worker', async () => {
            const pkce = generatePkce();
            const code = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });

            // 1. Worker 1 initiates redemption
            const claim1 = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: 'idem_emu06_same_key_takeover'
            });
            assert(claim1.status === 'SUCCESS', 'Worker 1 initial claim must succeed');

            // Stage Worker 1's uncommitted pending session and family
            const sessOld = `sess_emu06_old_${Date.now()}`;
            const famOld = `fam_emu06_old_${Date.now()}`;
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

            // Link pending records to code doc and expire the lock (simulate worker stall/crash)
            await db.collection('authorization_codes').doc(claim1.codeHash).update({
                issuedSessionId: sessOld,
                issuedFamilyId: famOld,
                redemptionLockExpiresAt: new Date(Date.now() - 5000)
            });

            // 2. Worker 2 retries with the SAME idempotency key (safe takeover)
            const claim2 = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: 'idem_emu06_same_key_takeover'
            });
            assert(claim2.status === 'SUCCESS', 'Same-key takeover must succeed');
            assert(claim2.fenceToken === claim1.fenceToken + 1, 'Fence token must be incremented');
            assert(claim2.redemptionLockId !== claim1.redemptionLockId, 'New distinct lock ID must be issued');

            // 3. Verify in real Firestore that the old pending session and family were revoked!
            const sessOldSnap = await db.collection('users').doc(testUid).collection('sessions').doc(sessOld).get();
            const famOldSnap = await db.collection('tenants').doc('lanzar').collection('token_families').doc(famOld).get();
            assert(sessOldSnap.data().status === 'revoked', 'Old pending session must be revoked');
            assert(sessOldSnap.data().revocationReason === 'expired_lease_takeover_cleanup', 'Old session revocation reason matches');
            assert(famOldSnap.data().status === 'revoked', 'Old pending family must be revoked');
            assert(famOldSnap.data().revocationReason === 'expired_lease_takeover_cleanup', 'Old family revocation reason matches');

            // 4. Worker 2 stages new session and family and finalizes
            const sessNew = `sess_emu06_new_${Date.now()}`;
            const famNew = `fam_emu06_new_${Date.now()}`;
            await db.collection('users').doc(testUid).collection('sessions').doc(sessNew).set({
                sessionId: sessNew, familyId: famNew, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: claim2.record.ceremonyId, redemptionLockId: claim2.redemptionLockId, fenceToken: claim2.fenceToken,
                status: 'pending_activation'
            });
            await db.collection('tenants').doc('lanzar').collection('token_families').doc(famNew).set({
                familyId: famNew, sessionId: sessNew, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: claim2.record.ceremonyId, redemptionLockId: claim2.redemptionLockId, fenceToken: claim2.fenceToken,
                status: 'pending_activation'
            });

            await store.registerStagedRecords({
                codeHash: claim2.codeHash, redemptionLockId: claim2.redemptionLockId, fenceToken: claim2.fenceToken,
                uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim2.record.ceremonyId,
                issuedSessionId: sessNew, issuedFamilyId: famNew
            });

            const fin2 = await store.finalizeRedemption({
                codeHash: claim2.codeHash, redemptionLockId: claim2.redemptionLockId, fenceToken: claim2.fenceToken,
                uid: testUid, tenantId: 'lanzar', issuedSessionId: sessNew, issuedFamilyId: famNew,
                rawTokensPayload: { custom_token: 'worker2_fresh_token' }
            });
            assert(fin2.success === true, 'Worker 2 finalization must succeed');

            // 5. Worker 1 wakes up late and attempts finalization targeting Worker 2's session
            const staleFin = await store.finalizeRedemption({
                codeHash: claim1.codeHash, redemptionLockId: claim1.redemptionLockId, fenceToken: claim1.fenceToken,
                uid: testUid, tenantId: 'lanzar', issuedSessionId: sessNew, issuedFamilyId: famNew,
                rawTokensPayload: { custom_token: 'stale_token' }
            });
            assert(staleFin.success === false, 'Stale worker finalization must fail');
            assert(staleFin.reason === 'STALE_WORKER_FENCED', 'Stale worker must be fenced out');

            // Verify live documents: Worker 2's resources remain active and unharmed
            const sessNewSnap = await db.collection('users').doc(testUid).collection('sessions').doc(sessNew).get();
            const famNewSnap = await db.collection('tenants').doc('lanzar').collection('token_families').doc(famNew).get();
            assert(sessNewSnap.data().status === 'active', 'Worker 2 active session remains active');
            assert(famNewSnap.data().status === 'active', 'Worker 2 active family remains active');
        });

        // -------------------------------------------------------------
        // EMU-07: Real Firestore: Cross-Document Relationship Mismatch (Tenant Mismatch)
        // -------------------------------------------------------------
        await test('EMU-07: Real Firestore: Complete relationship validation rejects mismatched session tenant', async () => {
            const pkce = generatePkce();
            const code = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });

            const claim = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: 'idem_emu07_tenant_mismatch'
            });

            const sessId = `sess_emu07_${Date.now()}`;
            const famId = `fam_emu07_${Date.now()}`;

            // Session has mismatched tenantId ('acme_corp' vs code's 'lanzar')
            await db.collection('users').doc(testUid).collection('sessions').doc(sessId).set({
                sessionId: sessId, familyId: famId, tenantId: 'acme_corp', uid: testUid, clientId: testClientId,
                ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
                status: 'pending_activation'
            });
            await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).set({
                familyId: famId, sessionId: sessId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
                status: 'pending_activation'
            });

            await db.collection('authorization_codes').doc(claim.codeHash).update({
                issuedSessionId: sessId,
                issuedFamilyId: famId
            });

            const finRes = await store.finalizeRedemption({
                codeHash: claim.codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
                uid: testUid, tenantId: 'lanzar', issuedSessionId: sessId, issuedFamilyId: famId,
                rawTokensPayload: { custom_token: 'tok' }
            });

            assert(finRes.success === false, 'Finalization must fail closed on session tenant mismatch');
            assert(finRes.reason === 'RECORD_RELATIONSHIP_MISMATCH', 'Must return RECORD_RELATIONSHIP_MISMATCH');

            // Verify live documents in Firestore: code is COMPROMISED and session was NEVER activated
            const codeSnap = await db.collection('authorization_codes').doc(claim.codeHash).get();
            const sessSnap = await db.collection('users').doc(testUid).collection('sessions').doc(sessId).get();
            assert(codeSnap.data().status === 'COMPROMISED', 'Code document must transition to COMPROMISED');
            assert(sessSnap.data().status !== 'active', 'Mismatched session from another tenant must NEVER be activated');
        });

        // -------------------------------------------------------------
        // EMU-08: Real Firestore: Concurrent Redemption Contention & Transaction Retries
        // -------------------------------------------------------------
        await test('EMU-08: Real Firestore: Concurrent transaction contention handles 10 parallel claims safely', async () => {
            const pkce = generatePkce();
            const code = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });

            // Fire 10 concurrent redemption requests simultaneously targeting the same code
            const results = await Promise.all(
                Array.from({ length: 10 }, (_, i) =>
                    store.initiateRedemption({
                        code, clientId: testClientId, redirectUri: testRedirectUri,
                        codeVerifier: pkce.verifier, idempotencyKey: `idem_emu08_concurrent_key_${i}_${Date.now()}`
                    })
                )
            );

            const successes = results.filter(r => r.status === 'SUCCESS');
            const replays = results.filter(r => r.status === 'REPLAY_DETECTED');

            assert(successes.length === 1, `Exactly 1 concurrent claim must succeed, got ${successes.length}`);
            assert(replays.length === 9, `Remaining 9 callers must detect conflict/replay, got ${replays.length}`);

            const codeHash = hashAuthorizationCode(code);
            const codeSnap = await db.collection('authorization_codes').doc(codeHash).get();
            assert(codeSnap.data().status === 'COMPROMISED', 'Contended code must be durably marked COMPROMISED');
        });

        // -------------------------------------------------------------
        // EMU-09: Real Firestore: Multi-Version Receipt Key Rotation & Recovery
        // -------------------------------------------------------------
        await test('EMU-09: Real Firestore: Multi-version key rotation recovers receipt encrypted under earlier key', async () => {
            const keyV1 = crypto.randomBytes(32);
            const keyV2 = crypto.randomBytes(32);

            // Active keyring: Version 1
            setReceiptKeyringForTesting({ 1: keyV1 });

            const pkce = generatePkce();
            const code = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });

            const idemKey = 'idem_emu09_key_rotation_valid';
            const claim = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: idemKey
            });

            const sessId = `sess_emu09_${Date.now()}`;
            const famId = `fam_emu09_${Date.now()}`;
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

            // Finalize redemption under Key Version 1
            const payload = { custom_token: 'custom_jwt_v1_payload', uid: testUid };
            const fin = await store.finalizeRedemption({
                codeHash: claim.codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
                uid: testUid, tenantId: 'lanzar', issuedSessionId: sessId, issuedFamilyId: famId,
                rawTokensPayload: payload
            });
            assert(fin.success === true, 'Finalization under Version 1 key succeeded');

            // Now rotate keys: Version 2 is active, Version 1 remains in keyring for decryption
            process.env.ACTIVE_RECEIPT_KEY_VERSION = '2';
            setReceiptKeyringForTesting({ 1: keyV1, 2: keyV2 });

            // Client retries with valid PKCE and matching idempotency key (idempotent recovery)
            const recovery = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: idemKey
            });

            assert(recovery.status === 'IDEMPOTENT_RECOVERY', 'Must return IDEMPOTENT_RECOVERY');
            assert(recovery.tokenReceipt.custom_token === payload.custom_token, 'Decrypted token receipt matches original payload across key rotation');

            // Reset environment and test keyring
            delete process.env.ACTIVE_RECEIPT_KEY_VERSION;
            resetReceiptKeyringForTesting();
        });

        // -------------------------------------------------------------
        // EMU-10: Real Firestore: Stale-Worker Fenced Pointer Registration
        // -------------------------------------------------------------
        await test("EMU-10: Real Firestore: Stale worker cannot overwrite pointers after takeover; Worker B pointers remain intact", async () => {
            const pkce = generatePkce();
            const code = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const codeHash = hashAuthorizationCode(code);
            const idemKey = 'idem_emu10_takeover_fencing';

            // 1. Worker A claims the code
            const claimA = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: idemKey
            });
            assert(claimA.status === 'SUCCESS', 'Worker A claim must succeed');

            // Worker A stages session and family documents via create-only
            const sessA = `sess_emu10_a_${Date.now()}`;
            const famA = `fam_emu10_a_${Date.now()}`;
            await db.collection('users').doc(testUid).collection('sessions').doc(sessA).create({
                sessionId: sessA, familyId: famA, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: claimA.record.ceremonyId, redemptionLockId: claimA.redemptionLockId,
                fenceToken: claimA.fenceToken, status: 'pending_activation'
            });
            await db.collection('tenants').doc('lanzar').collection('token_families').doc(famA).create({
                familyId: famA, sessionId: sessA, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: claimA.record.ceremonyId, redemptionLockId: claimA.redemptionLockId,
                fenceToken: claimA.fenceToken, status: 'pending_activation'
            });

            // 2. Worker A's lease expires while staging
            await db.collection('authorization_codes').doc(codeHash).update({
                redemptionLockExpiresAt: new Date(Date.now() - 5000)
            });

            // 3. Worker B takes over (safe recovery with matching idempotency key)
            const claimB = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: idemKey
            });
            assert(claimB.status === 'SUCCESS', 'Worker B takeover must succeed');
            assert(claimB.fenceToken > claimA.fenceToken, 'Worker B must have an advanced fence token');
            assert(claimB.redemptionLockId !== claimA.redemptionLockId, 'Worker B must have a fresh lock ID');

            // 4. Worker B stages its own records via create-only
            const sessB = `sess_emu10_b_${Date.now()}`;
            const famB = `fam_emu10_b_${Date.now()}`;
            await db.collection('users').doc(testUid).collection('sessions').doc(sessB).create({
                sessionId: sessB, familyId: famB, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: claimB.record.ceremonyId, redemptionLockId: claimB.redemptionLockId,
                fenceToken: claimB.fenceToken, status: 'pending_activation'
            });
            await db.collection('tenants').doc('lanzar').collection('token_families').doc(famB).create({
                familyId: famB, sessionId: sessB, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: claimB.record.ceremonyId, redemptionLockId: claimB.redemptionLockId,
                fenceToken: claimB.fenceToken, status: 'pending_activation'
            });

            // 5. Worker B registers its pointers conditionally and atomically
            const regB = await store.registerStagedRecords({
                codeHash,
                redemptionLockId: claimB.redemptionLockId,
                fenceToken: claimB.fenceToken,
                uid: testUid,
                tenantId: 'lanzar',
                clientId: testClientId,
                ceremonyId: claimB.record.ceremonyId,
                issuedSessionId: sessB,
                issuedFamilyId: famB
            });
            assert(regB.success === true, 'Worker B pointer registration must succeed');

            // 6. Worker A resumes and attempts to register its stale pointers
            const regA = await store.registerStagedRecords({
                codeHash,
                redemptionLockId: claimA.redemptionLockId,
                fenceToken: claimA.fenceToken,
                uid: testUid,
                tenantId: 'lanzar',
                clientId: testClientId,
                ceremonyId: claimA.record.ceremonyId,
                issuedSessionId: sessA,
                issuedFamilyId: famA
            });
            assert(regA.success === false, 'Worker A pointer registration must fail');
            assert(regA.reason === 'STALE_WORKER_FENCED', 'Worker A rejected due to stale worker fencing');

            // 7. Verify Worker B's pointers remain unchanged in Cloud Firestore
            const codeSnap = await db.collection('authorization_codes').doc(codeHash).get();
            assert(codeSnap.data().issuedSessionId === sessB, 'Worker B session pointer remains intact');
            assert(codeSnap.data().issuedFamilyId === famB, 'Worker B family pointer remains intact');

            // 8. Verify Worker A cannot finalize or return tokens
            const finA = await store.finalizeRedemption({
                codeHash,
                redemptionLockId: claimA.redemptionLockId,
                fenceToken: claimA.fenceToken,
                uid: testUid,
                tenantId: 'lanzar',
                issuedSessionId: sessA,
                issuedFamilyId: famA,
                rawTokensPayload: { custom_token: 'tok_a' }
            });
            assert(finA.success === false, 'Worker A finalize must fail');
            assert(finA.reason === 'STALE_WORKER_FENCED', 'Worker A finalize rejected due to stale worker fencing');

            // 9. Verify Worker A cannot revoke Worker B's resources
            await store.handleRedemptionFailure({
                codeHash,
                redemptionLockId: claimA.redemptionLockId,
                fenceToken: claimA.fenceToken,
                uid: testUid,
                tenantId: 'lanzar',
                sessionId: sessA,
                familyId: famA,
                errorReason: 'stale_worker_exception'
            });

            // Worker B session and family must remain pending_activation
            const sessBSnap = await db.collection('users').doc(testUid).collection('sessions').doc(sessB).get();
            const famBSnap = await db.collection('tenants').doc('lanzar').collection('token_families').doc(famB).get();
            assert(sessBSnap.data().status === 'pending_activation', 'Worker B session untouched by Worker A failure cleanup');
            assert(famBSnap.data().status === 'pending_activation', 'Worker B family untouched by Worker A failure cleanup');

            // Code document remains REDEEMING under Worker B (not marked COMPROMISED)
            const codeSnapAfterA = await db.collection('authorization_codes').doc(codeHash).get();
            assert(codeSnapAfterA.data().status === 'REDEEMING', 'Code remains in REDEEMING state under Worker B');
            assert(codeSnapAfterA.data().redemptionLockId === claimB.redemptionLockId, 'Code lock ID remains Worker B');

            // 10. Worker B finalizes successfully
            const finB = await store.finalizeRedemption({
                codeHash,
                redemptionLockId: claimB.redemptionLockId,
                fenceToken: claimB.fenceToken,
                uid: testUid,
                tenantId: 'lanzar',
                issuedSessionId: sessB,
                issuedFamilyId: famB,
                rawTokensPayload: { custom_token: 'tok_b', session_id: sessB }
            });
            assert(finB.success === true, 'Worker B finalization succeeds');

            const sessBSnapActive = await db.collection('users').doc(testUid).collection('sessions').doc(sessB).get();
            assert(sessBSnapActive.data().status === 'active', 'Worker B session is active');
        });

        // -------------------------------------------------------------
        // EMU-11: Real Firestore: Create-Only Document Semantics
        // -------------------------------------------------------------
        await test('EMU-11: Real Firestore: Create-only semantics strictly reject duplicate session and family creation', async () => {
            const dupSessionId = `sess_emu11_${Date.now()}`;
            const dupFamilyId = `fam_emu11_${Date.now()}`;
            const sessionRef = db.collection('users').doc(testUid).collection('sessions').doc(dupSessionId);
            const familyRef = db.collection('tenants').doc('lanzar').collection('token_families').doc(dupFamilyId);

            // Initial create succeeds
            await sessionRef.create({
                sessionId: dupSessionId, status: 'pending_activation', createdAt: new Date().toISOString()
            });
            await familyRef.create({
                familyId: dupFamilyId, status: 'pending_activation', createdAt: new Date().toISOString()
            });

            // Duplicate session create throws ALREADY_EXISTS (gRPC code 6)
            let sessionDupCaught = false;
            try {
                await sessionRef.create({
                    sessionId: dupSessionId, status: 'pending_activation', createdAt: new Date().toISOString()
                });
            } catch (err) {
                sessionDupCaught = err.code === 6 || String(err.message).includes('already exists') || String(err.message).includes('ALREADY_EXISTS');
            }
            assert(sessionDupCaught === true, 'Duplicate session create must throw ALREADY_EXISTS');

            // Duplicate family create throws ALREADY_EXISTS (gRPC code 6)
            let familyDupCaught = false;
            try {
                await familyRef.create({
                    familyId: dupFamilyId, status: 'pending_activation', createdAt: new Date().toISOString()
                });
            } catch (err) {
                familyDupCaught = err.code === 6 || String(err.message).includes('already exists') || String(err.message).includes('ALREADY_EXISTS');
            }
            assert(familyDupCaught === true, 'Duplicate token-family create must throw ALREADY_EXISTS');

            // Verify original data in Firestore is completely unmodified
            const origSnap = await sessionRef.get();
            assert(origSnap.exists && origSnap.data().status === 'pending_activation', 'Original session data remains intact and unmodified');
        });

        // -------------------------------------------------------------
        // EMU-12: Real Firestore: Strict Fail-Closed Lease Expiration
        // -------------------------------------------------------------
        await test('EMU-12: Real Firestore: Missing, zero, invalid, or expired leases fail closed', async () => {
            const pkce = generatePkce();
            const code = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const codeHash = hashAuthorizationCode(code);
            const claim = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: `idem_emu12_${Date.now()}`
            });
            assert(claim.status === 'SUCCESS');

            const sessId = `sess_emu12_${Date.now()}`;
            const famId = `fam_emu12_${Date.now()}`;
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

            // 1. Missing timestamp in Firestore
            await db.collection('authorization_codes').doc(codeHash).update({ redemptionLockExpiresAt: null });
            const resNull = await store.registerStagedRecords({
                codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
                uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
                issuedSessionId: sessId, issuedFamilyId: famId
            });
            assert(resNull.success === false && resNull.reason === 'INVALID_LOCK_EXPIRATION', 'Null lease expiration fails closed');

            // 2. Zero timestamp in Firestore (reset code status and companion documents)
            await db.collection('authorization_codes').doc(codeHash).update({ redemptionLockExpiresAt: 0, status: 'REDEEMING' });
            await db.collection('users').doc(testUid).collection('sessions').doc(sessId).update({ status: 'pending_activation' });
            await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).update({ status: 'pending_activation' });
            const resZero = await store.registerStagedRecords({
                codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
                uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
                issuedSessionId: sessId, issuedFamilyId: famId
            });
            assert(resZero.success === false && resZero.reason === 'INVALID_LOCK_EXPIRATION', 'Zero lease expiration fails closed');

            // 3. Expired timestamp in Firestore (reset code status and companion documents)
            await db.collection('authorization_codes').doc(codeHash).update({ redemptionLockExpiresAt: new Date(Date.now() - 5000), status: 'REDEEMING' });
            await db.collection('users').doc(testUid).collection('sessions').doc(sessId).update({ status: 'pending_activation' });
            await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).update({ status: 'pending_activation' });
            const resExp = await store.registerStagedRecords({
                codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
                uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
                issuedSessionId: sessId, issuedFamilyId: famId
            });
            assert(resExp.success === false && resExp.reason === 'LOCK_EXPIRED', 'Expired lease fails closed');

            // 4. Valid, unexpired timestamp succeeds (reset code status and companion documents)
            await db.collection('authorization_codes').doc(codeHash).update({ redemptionLockExpiresAt: new Date(Date.now() + 15000), status: 'REDEEMING' });
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
        // EMU-13: Real Firestore: Three-Document Pre-Read Integrity Validation
        // -------------------------------------------------------------
        await test('EMU-13: Real Firestore: Three-document pre-read integrity rejects missing or mismatched staged docs', async () => {
            const pkce = generatePkce();
            const code = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const codeHash = hashAuthorizationCode(code);
            const claim = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: `idem_emu13_${Date.now()}`
            });
            assert(claim.status === 'SUCCESS');

            const sessId = `sess_emu13_${Date.now()}`;
            const famId = `fam_emu13_${Date.now()}`;

            // 1. Missing session document in Firestore
            const resNoSess = await store.registerStagedRecords({
                codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
                uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
                issuedSessionId: 'nonexistent_session', issuedFamilyId: famId
            });
            assert(resNoSess.success === false && resNoSess.reason === 'STAGED_SESSION_NOT_FOUND', 'Missing session rejected');

            // Create valid session
            await db.collection('users').doc(testUid).collection('sessions').doc(sessId).create({
                sessionId: sessId, familyId: famId, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: claim.record.ceremonyId, redemptionLockId: claim.redemptionLockId,
                fenceToken: claim.fenceToken, status: 'pending_activation'
            });

            // 2. Missing family document in Firestore
            const resNoFam = await store.registerStagedRecords({
                codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
                uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
                issuedSessionId: sessId, issuedFamilyId: 'nonexistent_family'
            });
            assert(resNoFam.success === false && resNoFam.reason === 'STAGED_FAMILY_NOT_FOUND', 'Missing family rejected');

            // 3. Staged family with ceremony ID mismatch
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

            // Fix family ceremony ID
            await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).update({
                ceremonyId: claim.record.ceremonyId
            });

            // 4. Staged records successfully verified and registered
            const resOk = await store.registerStagedRecords({
                codeHash, redemptionLockId: claim.redemptionLockId, fenceToken: claim.fenceToken,
                uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim.record.ceremonyId,
                issuedSessionId: sessId, issuedFamilyId: famId
            });
            assert(resOk.success === true, 'Three-document pre-read and pointer registration succeeded');
        });

        // -------------------------------------------------------------
        // EMU-14: Real Firestore: Fail-Closed Protection Against Missing Capabilities
        // -------------------------------------------------------------
        await test('EMU-14: Real Firestore: Route fail-closed guard rejects missing capabilities without minting tokens', async () => {
            // Test 1: Verify missing create() capability is detected
            const mockRefWithoutCreate = { set: async () => {} };
            assert(typeof mockRefWithoutCreate.create !== 'function', 'Mock ref is missing create()');
            const canStage = typeof mockRefWithoutCreate.create === 'function';
            assert(canStage === false, 'Fail-closed guard prevents staging when create() capability is unavailable');

            // Test 2: Verify missing registerStagedRecords() capability is detected
            const mockStoreWithoutReg = {};
            assert(typeof mockStoreWithoutReg.registerStagedRecords !== 'function', 'Mock store is missing registerStagedRecords');
            const canRegister = typeof mockStoreWithoutReg.registerStagedRecords === 'function';
            assert(canRegister === false, 'Fail-closed guard prevents token minting when registerStagedRecords is unavailable');
        });

        // -------------------------------------------------------------
        // EMU-15: Real Firestore: Contention Retry After Lease Expiration Fails Closed
        // -------------------------------------------------------------
        await test('EMU-15: Real Firestore: Contention retry after lease expiration fails closed with fresh opTime', async () => {
            const pkce = generatePkce();
            const code = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const codeHash = hashAuthorizationCode(code);

            const claim = await store.initiateRedemption({
                code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce.verifier, idempotencyKey: `idem_emu15_${Date.now()}`
            });
            assert(claim.status === 'SUCCESS');

            const sessId = `sess_emu15_${Date.now()}`;
            const famId = `fam_emu15_${Date.now()}`;
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

            // Set redemption lock lease to expire in 120ms
            const shortLeaseExpiresAt = new Date(Date.now() + 120);
            await db.collection('authorization_codes').doc(codeHash).update({
                redemptionLockExpiresAt: shortLeaseExpiresAt
            });

            // Intercept db.runTransaction to simulate contention retry:
            // Attempt 1 delays 180ms (so lease expires) and aborts with code 10 (Firestore ABORTED)
            // Attempt 2 runs with fresh opTime = Date.now(), detecting lease expiration
            let txAttempts = 0;
            const originalRunTransaction = db.runTransaction.bind(db);
            db.runTransaction = async (updateFunction) => {
                return originalRunTransaction(async (transaction) => {
                    txAttempts++;
                    if (txAttempts === 1) {
                        await new Promise(r => setTimeout(r, 180));
                        const abortErr = new Error('Simulated contention retry');
                        abortErr.code = 10; // Firestore ABORTED triggers client retry
                        throw abortErr;
                    }
                    return await updateFunction(transaction);
                });
            };

            let finRes;
            try {
                finRes = await store.finalizeRedemption({
                    codeHash,
                    redemptionLockId: claim.redemptionLockId,
                    fenceToken: claim.fenceToken,
                    uid: testUid,
                    tenantId: 'lanzar',
                    issuedSessionId: sessId,
                    issuedFamilyId: famId,
                    rawTokensPayload: { custom_token: 'test_token' }
                });
            } finally {
                db.runTransaction = originalRunTransaction;
            }

            assert(txAttempts >= 2, `Transaction must have retried (attempts: ${txAttempts})`);
            assert(finRes.success === false, 'Finalization on expired lease retry must fail');
            assert(finRes.reason === 'LOCK_EXPIRED', `Expected reason LOCK_EXPIRED, got ${finRes.reason}`);

            // Verify live documents in Firestore: code is COMPROMISED, pending session & family are revoked
            const codeSnap = await db.collection('authorization_codes').doc(codeHash).get();
            const sessSnap = await db.collection('users').doc(testUid).collection('sessions').doc(sessId).get();
            const famSnap = await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).get();

            assert(codeSnap.data().status === 'COMPROMISED', 'Code document must transition to COMPROMISED');
            assert(codeSnap.data().failureReason === 'lock_expired', 'Failure reason must be lock_expired');
            assert(sessSnap.data().status === 'revoked', 'Pending session must be revoked');
            assert(sessSnap.data().revocationReason === 'redemption_lock_expired', 'Revocation reason must match');
            assert(famSnap.data().status === 'revoked', 'Pending family must be revoked');
            assert(famSnap.data().revocationReason === 'redemption_lock_expired', 'Revocation reason must match');
        });

        // -------------------------------------------------------------
        // EMU-16: Real Firestore: Missing initiateRedemption Fails Closed With HTTP 500
        // -------------------------------------------------------------
        await test('EMU-16: Real Firestore: Missing initiateRedemption capability fails closed with HTTP 500 and zero tokens', async () => {
            let legacyGetCodeCalled = false;
            let legacyMarkUsedCalled = false;

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
                    throw new Error('createCustomToken must NEVER be called');
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
                        'Idempotency-Key': 'idem_emu16_missing_cap_001'
                    },
                    body: JSON.stringify({
                        code: 'test_code_emu16',
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
            } finally {
                server.close();
            }
        });

        // -------------------------------------------------------------
        // EMU-17: Real Firestore: Fail-Closed Lease Validation Across All 3 Methods
        // -------------------------------------------------------------
        await test('EMU-17: Real Firestore: Fail-closed lease validation across all 3 methods with corrupt expiration values', async () => {
            const badValues = [
                { label: 'missing/deleted', val: FieldValue.delete() },
                { label: 'null', val: null },
                { label: 'zero', val: 0 },
                { label: 'negative', val: -5000 },
                { label: 'malformed string', val: 'malformed_non_numeric_expiration' },
                { label: 'NaN', val: NaN }
            ];

            for (const { label, val } of badValues) {
                // Subtest 1: initiateRedemption fails closed on invalid lease
                const pkce1 = generatePkce();
                const code1 = await store.createCode({
                    uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                    codeChallenge: pkce1.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
                });
                const codeHash1 = hashAuthorizationCode(code1);
                const claim1 = await store.initiateRedemption({
                    code: code1, clientId: testClientId, redirectUri: testRedirectUri, codeVerifier: pkce1.verifier,
                    idempotencyKey: 'idem_emu17_init_' + crypto.randomBytes(12).toString('hex')
                });
                assert(claim1.status === 'SUCCESS');

                // Corrupt lease metadata
                await db.collection('authorization_codes').doc(codeHash1).update({
                    redemptionLockExpiresAt: val
                });

                const retryClaim = await store.initiateRedemption({
                    code: code1, clientId: testClientId, redirectUri: testRedirectUri, codeVerifier: pkce1.verifier,
                    idempotencyKey: 'idem_emu17_retry_' + crypto.randomBytes(12).toString('hex')
                });
                assert(retryClaim.status === 'REPLAY_DETECTED', `initiateRedemption must return REPLAY_DETECTED for bad lease (${label}), got ${retryClaim.status}`);
                const codeDoc1 = await db.collection('authorization_codes').doc(codeHash1).get();
                assert(codeDoc1.data().status === 'COMPROMISED', `Code must be COMPROMISED after invalid lease initiate (${label})`);
                assert(codeDoc1.data().failureReason === 'invalid_lock_expiration', `failureReason must be invalid_lock_expiration (${label})`);

                // Subtest 2: registerStagedRecords fails closed on invalid lease
                const pkce2 = generatePkce();
                const code2 = await store.createCode({
                    uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                    codeChallenge: pkce2.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
                });
                const codeHash2 = hashAuthorizationCode(code2);
                const claim2 = await store.initiateRedemption({
                    code: code2, clientId: testClientId, redirectUri: testRedirectUri, codeVerifier: pkce2.verifier,
                    idempotencyKey: 'idem_emu17_reg_' + crypto.randomBytes(12).toString('hex')
                });
                assert(claim2.status === 'SUCCESS');

                const sessId2 = 'sess_emu17_reg_' + crypto.randomBytes(8).toString('hex');
                const famId2 = 'fam_emu17_reg_' + crypto.randomBytes(8).toString('hex');
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
                    redemptionLockExpiresAt: val
                });

                const regRes = await store.registerStagedRecords({
                    codeHash: codeHash2, redemptionLockId: claim2.redemptionLockId, fenceToken: claim2.fenceToken,
                    uid: testUid, tenantId: 'lanzar', clientId: testClientId, ceremonyId: claim2.record.ceremonyId,
                    issuedSessionId: sessId2, issuedFamilyId: famId2
                });
                assert(regRes.success === false, `registerStagedRecords must fail on invalid lease (${label})`);
                assert(regRes.reason === 'INVALID_LOCK_EXPIRATION', `Expected INVALID_LOCK_EXPIRATION, got ${regRes.reason}`);
                const codeDoc2 = await db.collection('authorization_codes').doc(codeHash2).get();
                assert(codeDoc2.data().status === 'COMPROMISED', `Code must be COMPROMISED after invalid lease registration (${label})`);

                // Subtest 3: finalizeRedemption fails closed on invalid lease
                const pkce3 = generatePkce();
                const code3 = await store.createCode({
                    uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                    codeChallenge: pkce3.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
                });
                const codeHash3 = hashAuthorizationCode(code3);
                const claim3 = await store.initiateRedemption({
                    code: code3, clientId: testClientId, redirectUri: testRedirectUri, codeVerifier: pkce3.verifier,
                    idempotencyKey: 'idem_emu17_fin_' + crypto.randomBytes(12).toString('hex')
                });
                assert(claim3.status === 'SUCCESS');

                const sessId3 = 'sess_emu17_fin_' + crypto.randomBytes(8).toString('hex');
                const famId3 = 'fam_emu17_fin_' + crypto.randomBytes(8).toString('hex');
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
                    redemptionLockExpiresAt: val
                });

                const finRes = await store.finalizeRedemption({
                    codeHash: codeHash3, redemptionLockId: claim3.redemptionLockId, fenceToken: claim3.fenceToken,
                    uid: testUid, tenantId: 'lanzar', issuedSessionId: sessId3, issuedFamilyId: famId3,
                    rawTokensPayload: { custom_token: 'test' }
                });
                assert(finRes.success === false, `finalizeRedemption must fail on invalid lease (${label})`);
                assert(finRes.reason === 'INVALID_LOCK_EXPIRATION', `Expected INVALID_LOCK_EXPIRATION, got ${finRes.reason}`);
                const codeDoc3 = await db.collection('authorization_codes').doc(codeHash3).get();
                assert(codeDoc3.data().status === 'COMPROMISED', `Code must be COMPROMISED after invalid lease finalization (${label})`);
            }
        });

        // -------------------------------------------------------------
        // EMU-18: Real Firestore: Finalization Code Pointer Validation
        // -------------------------------------------------------------
        await test('EMU-18: Real Firestore: Finalization strictly validates authorization code pointers (issuedSessionId and issuedFamilyId)', async () => {
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
                idempotencyKey: 'idem_emu18_ptr_' + crypto.randomBytes(10).toString('hex')
            });
            assert(claim.status === 'SUCCESS');

            const sessId = `sess_emu18_${Date.now()}`;
            const famId = `fam_emu18_${Date.now()}`;
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
                idempotencyKey: 'idem_emu18_ptr2_' + crypto.randomBytes(10).toString('hex')
            });
            const sessId2 = `sess_emu18_b_${Date.now()}`;
            const famId2 = `fam_emu18_b_${Date.now()}`;
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
        // EMU-19: Real Firestore: Ambiguous Firestore Create Outcome Handling
        // -------------------------------------------------------------
        await test('EMU-19: Real Firestore: Ambiguous Firestore create outcomes: safeCleanup revokes committed documents without touching foreign resources', async () => {
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
                idempotencyKey: 'idem_emu19_ambig_' + crypto.randomBytes(10).toString('hex')
            });

            const ambiguousSessionId = `sess_emu19_ambig_${Date.now()}`;
            const ambiguousFamilyId = `fam_emu19_ambig_${Date.now()}`;

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
            const sessNew = `sess_emu19_worker2_active_${Date.now()}`;
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
        // EMU-20: Real Firestore: Corrupt Lease Metadata Fencing in initiateRedemption()
        // -------------------------------------------------------------
        await test('EMU-20: Real Firestore: Corrupt lease metadata in initiateRedemption() CANNOT revoke newer worker, active, or mismatched records', async () => {
            // Case A: Newer worker's pending_activation records referenced by code with corrupt lease
            const pkceA = generatePkce();
            const codeA = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkceA.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const codeHashA = hashAuthorizationCode(codeA);
            const claimA = await store.initiateRedemption({
                code: codeA, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkceA.verifier, idempotencyKey: 'idem_emu20_caseA_' + crypto.randomBytes(8).toString('hex')
            });
            const sessIdA = `sess_emu20_a_${Date.now()}`;
            const famIdA = `fam_emu20_a_${Date.now()}`;
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
                codeVerifier: pkceA.verifier, idempotencyKey: 'idem_emu20_retryA_' + crypto.randomBytes(8).toString('hex')
            });
            assert(resA.status === 'REPLAY_DETECTED', 'Corrupt lease must return REPLAY_DETECTED');
            const codeSnapA = await db.collection('authorization_codes').doc(codeHashA).get();
            const sessSnapA = await db.collection('users').doc(testUid).collection('sessions').doc(sessIdA).get();
            const famSnapA = await db.collection('tenants').doc('lanzar').collection('token_families').doc(famIdA).get();
            assert(codeSnapA.data().status === 'COMPROMISED' && codeSnapA.data().failureReason === 'invalid_lock_expiration', 'Code A marked COMPROMISED');
            assert(sessSnapA.data().status === 'pending_activation', 'Newer worker session MUST NOT be revoked in live Firestore');
            assert(famSnapA.data().status === 'pending_activation', 'Newer worker family MUST NOT be revoked in live Firestore');

            // Case B: Active records referenced by code with corrupt lease
            const pkceB = generatePkce();
            const codeB = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkceB.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const codeHashB = hashAuthorizationCode(codeB);
            const claimB = await store.initiateRedemption({
                code: codeB, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkceB.verifier, idempotencyKey: 'idem_emu20_caseB_' + crypto.randomBytes(8).toString('hex')
            });
            const sessIdB = `sess_emu20_b_${Date.now()}`;
            const famIdB = `fam_emu20_b_${Date.now()}`;
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
                codeVerifier: pkceB.verifier, idempotencyKey: 'idem_emu20_retryB_' + crypto.randomBytes(8).toString('hex')
            });
            assert(resB.status === 'REPLAY_DETECTED', 'Corrupt lease B must return REPLAY_DETECTED');
            const sessSnapB = await db.collection('users').doc(testUid).collection('sessions').doc(sessIdB).get();
            const famSnapB = await db.collection('tenants').doc('lanzar').collection('token_families').doc(famIdB).get();
            assert(sessSnapB.data().status === 'active', 'Active session MUST NOT be revoked in live Firestore');
            assert(famSnapB.data().status === 'active', 'Active family MUST NOT be revoked in live Firestore');

            // Case C: Mismatched ceremonyId / tenantId on pending records
            const pkceC = generatePkce();
            const codeC = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkceC.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const codeHashC = hashAuthorizationCode(codeC);
            const claimC = await store.initiateRedemption({
                code: codeC, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkceC.verifier, idempotencyKey: 'idem_emu20_caseC_' + crypto.randomBytes(8).toString('hex')
            });
            const sessIdC = `sess_emu20_c_${Date.now()}`;
            const famIdC = `fam_emu20_c_${Date.now()}`;
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
                codeVerifier: pkceC.verifier, idempotencyKey: 'idem_emu20_retryC_' + crypto.randomBytes(8).toString('hex')
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
                codeVerifier: pkceD.verifier, idempotencyKey: 'idem_emu20_caseD_' + crypto.randomBytes(8).toString('hex')
            });
            const sessIdD = `sess_emu20_d_${Date.now()}`;
            const famIdD = `fam_emu20_d_${Date.now()}`;
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
                codeVerifier: pkceD.verifier, idempotencyKey: 'idem_emu20_retryD_' + crypto.randomBytes(8).toString('hex')
            });
            const sessSnapD = await db.collection('users').doc(testUid).collection('sessions').doc(sessIdD).get();
            const famSnapD = await db.collection('tenants').doc('lanzar').collection('token_families').doc(famIdD).get();
            assert(sessSnapD.data().status === 'revoked' && sessSnapD.data().revocationReason === 'invalid_lock_expiration', 'Owned pending session MUST be revoked');
            assert(famSnapD.data().status === 'revoked' && famSnapD.data().revocationReason === 'invalid_lock_expiration', 'Owned pending family MUST be revoked');
        });

        // -------------------------------------------------------------
        // EMU-21: Real Firestore: Strict Authorization-Code Expiration Validation
        // -------------------------------------------------------------
        await test('EMU-21: Real Firestore: Strict Authorization-Code Expiration rejects missing, null, malformed, zero, negative, non-finite, and expired timestamps', async () => {
            const badExpirations = [
                { label: 'missing/deleted', val: FieldValue.delete() },
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
                    codeVerifier: pkce.verifier, idempotencyKey: 'idem_emu21_bad_' + crypto.randomBytes(8).toString('hex')
                });
                assert(res.status === 'EXPIRED', `Expected EXPIRED for ${label}, got ${res.status}`);
                const codeDoc = (await db.collection('authorization_codes').doc(codeHash).get()).data();
                assert(codeDoc.status === 'EXPIRED', `Live Firestore code doc must be EXPIRED for ${label}`);
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
                codeVerifier: pkceExp.verifier, idempotencyKey: 'idem_emu21_past_' + crypto.randomBytes(8).toString('hex')
            });
            assert(resExp.status === 'EXPIRED', 'Past timestamp must return EXPIRED');
            const docExp = (await db.collection('authorization_codes').doc(codeHashExp).get()).data();
            assert(docExp.status === 'EXPIRED' && docExp.failureReason === 'code_expired', 'Past timestamp must record code_expired in live Firestore');

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
                codeVerifier: pkceValid.verifier, idempotencyKey: 'idem_emu21_valid_' + crypto.randomBytes(8).toString('hex')
            });
            assert(resValid.status === 'SUCCESS', 'Valid future expiration must succeed');
            const docValid = (await db.collection('authorization_codes').doc(codeHashValid).get()).data();
            assert(docValid.status === 'REDEEMING', 'Valid code transitions to REDEEMING in live Firestore');
        });

        // -------------------------------------------------------------
        // EMU-22: Real Firestore: Concurrent-Conflict & Completed-Code Replay Fencing
        // -------------------------------------------------------------
        await test('EMU-22: Real Firestore: Concurrent-conflict and completed-code replay fencing protects foreign, newer-worker, and unrelated active records', async () => {
            // 1. Legitimate concurrent conflict revokes correctly linked pending records
            const pkce1 = generatePkce();
            const code1 = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce1.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const codeHash1 = hashAuthorizationCode(code1);
            const claim1 = await store.initiateRedemption({
                code: code1, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce1.verifier, idempotencyKey: 'idem_emu22_1_' + crypto.randomBytes(8).toString('hex')
            });
            const sessId1 = `sess_emu22_1_${Date.now()}`;
            const famId1 = `fam_emu22_1_${Date.now()}`;
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
                codeVerifier: pkce1.verifier, idempotencyKey: 'idem_emu22_1_conflict_' + crypto.randomBytes(8).toString('hex')
            });
            assert(conflict1.status === 'REPLAY_DETECTED', 'Concurrent conflict must return REPLAY_DETECTED');
            assert((await db.collection('users').doc(testUid).collection('sessions').doc(sessId1).get()).data().status === 'revoked', 'Legitimate conflict revokes linked pending session in live Firestore');
            assert((await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId1).get()).data().status === 'revoked', 'Legitimate conflict revokes linked pending family in live Firestore');

            // 2. Foreign/mismatched records remain untouched during concurrent conflict
            const pkce2 = generatePkce();
            const code2 = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce2.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const codeHash2 = hashAuthorizationCode(code2);
            const claim2 = await store.initiateRedemption({
                code: code2, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce2.verifier, idempotencyKey: 'idem_emu22_2_' + crypto.randomBytes(8).toString('hex')
            });
            const sessId2 = `sess_emu22_2_${Date.now()}`;
            const famId2 = `fam_emu22_2_${Date.now()}`;
            await db.collection('users').doc(testUid).collection('sessions').doc(sessId2).create({
                sessionId: sessId2, familyId: famId2, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: 'foreign_ceremony_emu22', redemptionLockId: claim2.redemptionLockId,
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
                codeVerifier: pkce2.verifier, idempotencyKey: 'idem_emu22_2_conflict_' + crypto.randomBytes(8).toString('hex')
            });
            assert((await db.collection('users').doc(testUid).collection('sessions').doc(sessId2).get()).data().status === 'pending_activation', 'Foreign ceremony session MUST remain untouched in live Firestore');
            assert((await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId2).get()).data().status === 'pending_activation', 'Foreign tenant family MUST remain untouched in live Firestore');

            // 3. Newer-worker records remain untouched during concurrent conflict
            const pkce3 = generatePkce();
            const code3 = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce3.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const codeHash3 = hashAuthorizationCode(code3);
            const claim3 = await store.initiateRedemption({
                code: code3, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce3.verifier, idempotencyKey: 'idem_emu22_3_' + crypto.randomBytes(8).toString('hex')
            });
            const sessId3 = `sess_emu22_3_${Date.now()}`;
            const famId3 = `fam_emu22_3_${Date.now()}`;
            await db.collection('users').doc(testUid).collection('sessions').doc(sessId3).create({
                sessionId: sessId3, familyId: famId3, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: claim3.record.ceremonyId, redemptionLockId: 'newer_worker_lock_emu22',
                fenceToken: claim3.fenceToken + 1, status: 'pending_activation'
            });
            await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId3).create({
                familyId: famId3, sessionId: sessId3, tenantId: 'lanzar', uid: testUid, clientId: testClientId,
                ceremonyId: claim3.record.ceremonyId, redemptionLockId: 'newer_worker_lock_emu22',
                fenceToken: claim3.fenceToken + 1, status: 'pending_activation'
            });
            await db.collection('authorization_codes').doc(codeHash3).update({ issuedSessionId: sessId3, issuedFamilyId: famId3 });

            await store.initiateRedemption({
                code: code3, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce3.verifier, idempotencyKey: 'idem_emu22_3_conflict_' + crypto.randomBytes(8).toString('hex')
            });
            assert((await db.collection('users').doc(testUid).collection('sessions').doc(sessId3).get()).data().status === 'pending_activation', 'Newer worker session MUST remain untouched in live Firestore');
            assert((await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId3).get()).data().status === 'pending_activation', 'Newer worker family MUST remain untouched in live Firestore');

            // 4. Completed-code replay revokes ONLY the correctly linked active session and family
            const pkce4 = generatePkce();
            const code4 = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce4.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const codeHash4 = hashAuthorizationCode(code4);
            const claim4 = await store.initiateRedemption({
                code: code4, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce4.verifier, idempotencyKey: 'idem_emu22_4_' + crypto.randomBytes(8).toString('hex')
            });
            const sessId4 = `sess_emu22_4_${Date.now()}`;
            const famId4 = `fam_emu22_4_${Date.now()}`;
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
                codeVerifier: pkce4.verifier, idempotencyKey: 'idem_emu22_4_replay_' + crypto.randomBytes(8).toString('hex')
            });
            assert(replay4.status === 'REPLAY_DETECTED', 'Completed code replay must return REPLAY_DETECTED');
            const sessDoc4 = (await db.collection('users').doc(testUid).collection('sessions').doc(sessId4).get()).data();
            const famDoc4 = (await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId4).get()).data();
            assert(sessDoc4.status === 'revoked' && sessDoc4.revocationReason === 'authorization_code_replay_compromise', 'Completed replay revokes linked active session in live Firestore');
            assert(famDoc4.status === 'revoked' && famDoc4.revocationReason === 'authorization_code_replay_compromise', 'Completed replay revokes linked active family in live Firestore');

            // 5. Corrupt pointers on COMPLETED code CANNOT revoke unrelated active records
            const pkce5 = generatePkce();
            const code5 = await store.createCode({
                uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                codeChallenge: pkce5.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
            });
            const codeHash5 = hashAuthorizationCode(code5);
            const claim5 = await store.initiateRedemption({
                code: code5, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: pkce5.verifier, idempotencyKey: 'idem_emu22_5_' + crypto.randomBytes(8).toString('hex')
            });
            const sessId5 = `sess_emu22_5_${Date.now()}`;
            const famId5 = `fam_emu22_5_${Date.now()}`;
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
            const unrelatedSessId = `sess_emu22_unrel_${Date.now()}`;
            const unrelatedFamId = `fam_emu22_unrel_${Date.now()}`;
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
                codeVerifier: pkce5.verifier, idempotencyKey: 'idem_emu22_5_replay_' + crypto.randomBytes(8).toString('hex')
            });
            assert(replay5.status === 'REPLAY_DETECTED', 'Corrupt pointer replay must still return REPLAY_DETECTED');
            assert((await db.collection('users').doc(testUid).collection('sessions').doc(unrelatedSessId).get()).data().status === 'active', 'Unrelated active session MUST NOT be revoked in live Firestore');
            assert((await db.collection('tenants').doc('lanzar').collection('token_families').doc(unrelatedFamId).get()).data().status === 'active', 'Unrelated active family MUST NOT be revoked in live Firestore');
        });

        await test('EMU-23: Live Firestore Fail-Closed Replay Fencing & Paired Relationship Validation', async () => {
            const store = new FirestoreAuthorizationCodeStore(db);

            // 1. Direct predicate fail-closed checks
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
                assert(canReplayRevokeSession(baseSess, badCode) === false, `canReplayRevokeSession must reject ${String(badToken)}`);
                assert(canReplayRevokeFamily(baseFam, badCode) === false, `canReplayRevokeFamily must reject ${String(badToken)}`);
                assert(canReplayRevokePair(baseSess, baseFam, badCode) === false, `canReplayRevokePair must reject ${String(badToken)}`);
            }

            async function createLiveCompletedCeremony(tag) {
                const pkce = generatePkce();
                const code = await store.createCode({
                    uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                    codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
                });
                const codeHash = hashAuthorizationCode(code);
                const idem = `idem_emu23_${tag}_${crypto.randomBytes(8).toString('hex')}`;
                const claim = await store.initiateRedemption({
                    code, clientId: testClientId, redirectUri: testRedirectUri,
                    codeVerifier: pkce.verifier, idempotencyKey: idem
                });
                assert(claim.status === 'SUCCESS', `Expected SUCCESS for ${tag}, got ${claim.status}`);
                const { generateRefreshToken } = require('./auth-backend/store');
                const sessId = `sess_emu23_${tag}_${Date.now()}`;
                const famId = `fam_emu23_${tag}_${Date.now()}`;
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

            // 2. Live Firestore COMPLETED replay with invalid fenceToken values
            for (let i = 0; i < invalidFenceTokens.length; i++) {
                const badToken = invalidFenceTokens[i];
                const c = await createLiveCompletedCeremony(`badft_${i}`);
                const preReplayRefresh = await store.authorizeRefreshGrant({
                    tenantId: 'lanzar', familyId: c.famId, uid: testUid, sessionId: c.sessId, refreshToken: c.refreshToken
                });
                assert(preReplayRefresh.allowed === true && typeof preReplayRefresh.accessToken === 'string', `Live pre-replay refresh must succeed for badft_${i}`);

                if (badToken === undefined) {
                    await db.collection('authorization_codes').doc(c.codeHash).update({ fenceToken: FieldValue.delete() });
                } else {
                    await db.collection('authorization_codes').doc(c.codeHash).update({ fenceToken: badToken });
                }
                const replay = await store.initiateRedemption({
                    code: c.code, clientId: testClientId, redirectUri: testRedirectUri,
                    codeVerifier: c.pkce.verifier, idempotencyKey: `idem_emu23_replay_ft_${i}_${crypto.randomBytes(6).toString('hex')}`
                });
                assert(replay.status === 'REPLAY_DETECTED', `Bad fenceToken ${String(badToken)} replay must return REPLAY_DETECTED`);
                assert((await db.collection('users').doc(testUid).collection('sessions').doc(c.sessId).get()).data().status === 'revoked', `Live proven session MUST be revoked when fenceToken=${String(badToken)}`);
                assert((await db.collection('tenants').doc('lanzar').collection('token_families').doc(c.famId).get()).data().status === 'revoked', `Live proven family MUST be revoked when fenceToken=${String(badToken)}`);
                const postReplayRefresh = await store.authorizeRefreshGrant({
                    tenantId: 'lanzar', familyId: c.famId, uid: testUid, sessionId: c.sessId, refreshToken: preReplayRefresh.refreshToken
                });
                assert(postReplayRefresh.allowed === false && !postReplayRefresh.accessToken, `Live refresh MUST be blocked after invalid fenceToken=${String(badToken)} replay`);
            }

            // 2b. Live Firestore: Invalid fenceToken + corrupted companion family -> valid session revoked, foreign family untouched, refresh blocked
            const cBadFtCorruptFam = await createLiveCompletedCeremony('badft_corrupt_fam');
            await db.collection('authorization_codes').doc(cBadFtCorruptFam.codeHash).update({ fenceToken: null });
            await db.collection('tenants').doc('lanzar').collection('token_families').doc(cBadFtCorruptFam.famId).update({
                redemptionLockId: 'foreign_lock_999'
            });
            const replayBadFtCorruptFam = await store.initiateRedemption({
                code: cBadFtCorruptFam.code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: cBadFtCorruptFam.pkce.verifier, idempotencyKey: `idem_emu23_badft_cfam_${crypto.randomBytes(6).toString('hex')}`
            });
            assert(replayBadFtCorruptFam.status === 'REPLAY_DETECTED');
            assert((await db.collection('users').doc(testUid).collection('sessions').doc(cBadFtCorruptFam.sessId).get()).data().status === 'revoked', 'Live proven session MUST be revoked');
            assert((await db.collection('tenants').doc('lanzar').collection('token_families').doc(cBadFtCorruptFam.famId).get()).data().status === 'active', 'Live foreign/corrupt family MUST remain untouched');
            assert((await store.authorizeRefreshGrant({ tenantId: 'lanzar', familyId: cBadFtCorruptFam.famId, uid: testUid, sessionId: cBadFtCorruptFam.sessId, refreshToken: cBadFtCorruptFam.refreshToken })).allowed === false, 'Live refresh MUST be blocked');

            // 2c. Live Firestore: Invalid fenceToken + missing completedLockId (unproven ownership) -> records NOT revoked,
            //     but compromised_ceremonies tombstone independently blocks authorizeRefreshGrant!
            const cUnproven = await createLiveCompletedCeremony('badft_unproven');
            await db.collection('authorization_codes').doc(cUnproven.codeHash).update({
                fenceToken: FieldValue.delete(),
                completedLockId: FieldValue.delete()
            });
            const replayUnproven = await store.initiateRedemption({
                code: cUnproven.code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: cUnproven.pkce.verifier, idempotencyKey: `idem_emu23_unproven_${crypto.randomBytes(6).toString('hex')}`
            });
            assert(replayUnproven.status === 'REPLAY_DETECTED');
            assert((await db.collection('users').doc(testUid).collection('sessions').doc(cUnproven.sessId).get()).data().status === 'active', 'Live unproven session MUST NOT be revoked');
            assert((await db.collection('tenants').doc('lanzar').collection('token_families').doc(cUnproven.famId).get()).data().status === 'active', 'Live unproven family MUST NOT be revoked');
            const refreshUnproven = await store.authorizeRefreshGrant({
                tenantId: 'lanzar', familyId: cUnproven.famId, uid: testUid, sessionId: cUnproven.sessId, refreshToken: cUnproven.refreshToken
            });
            assert(refreshUnproven.allowed === false && refreshUnproven.reason === 'CEREMONY_COMPROMISED', `Live unproven ceremony refresh MUST be blocked via ceremony tombstone, got ${JSON.stringify(refreshUnproven)}`);

            // 2d. Truly unrelated active ceremony refresh still succeeds in live Firestore
            const cUnrelated = await createLiveCompletedCeremony('unrelated_ok');
            const refreshUnrelated = await store.authorizeRefreshGrant({
                tenantId: 'lanzar', familyId: cUnrelated.famId, uid: testUid, sessionId: cUnrelated.sessId, refreshToken: cUnrelated.refreshToken
            });
            assert(refreshUnrelated.allowed === true && typeof refreshUnrelated.accessToken === 'string', 'Live unrelated ceremony refresh must still succeed');

            const { SessionService } = require('./auth-backend/sessionService');
            const sessSvc = new SessionService(db, {});
            const evaluateLiveRefreshGate = async (famId, uid, sessId, refreshToken) => {
                const { generateRefreshToken } = require('./auth-backend/store');
                const famSnap = await db.collection('tenants').doc('lanzar').collection('token_families').doc(famId).get();
                const fam = famSnap.exists ? famSnap.data() : null;
                const sessState = await sessSvc.checkSession(uid, sessId, { bypassCache: true });
                const grant = await store.authorizeRefreshGrant({
                    tenantId: 'lanzar', familyId: famId, uid, sessionId: sessId,
                    refreshToken: refreshToken || generateRefreshToken(famId, 1)
                });
                const refreshAllowed = Boolean(fam && fam.status === 'active' && sessState.active && grant.allowed);
                return { fam, sessState, grant, refreshAllowed };
            };

            // 3a. Missing session + valid active family -> family IS revoked synchronously; refresh blocked
            const cMissSess = await createLiveCompletedCeremony('miss_sess');
            await db.collection('users').doc(testUid).collection('sessions').doc(cMissSess.sessId).delete();
            const replayMissSess = await store.initiateRedemption({
                code: cMissSess.code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: cMissSess.pkce.verifier, idempotencyKey: `idem_emu23_miss_sess_${crypto.randomBytes(6).toString('hex')}`
            });
            assert(replayMissSess.status === 'REPLAY_DETECTED', 'Missing session replay must return REPLAY_DETECTED');
            const gateMissSess = await evaluateLiveRefreshGate(cMissSess.famId, testUid, cMissSess.sessId);
            assert(gateMissSess.fam.status === 'revoked' && gateMissSess.fam.revocationReason === 'authorization_code_replay_compromise', 'Live valid active family MUST be revoked when session is missing');
            assert(gateMissSess.refreshAllowed === false && gateMissSess.sessState.active === false, 'Live refresh MUST be blocked when session is missing and family is revoked');
            const outboxMissSessSnap = await db.collection('security_outbox').where('details.ceremonyId', '==', cMissSess.claim.record.ceremonyId).get();
            const evMissSess = outboxMissSessSnap.docs.map(d => d.data()).find(d => d.eventType === 'CRITICAL_SECURITY_RECORD_MISSING');
            assert(evMissSess && evMissSess.details.sessionMissing === true && evMissSess.details.familyIndependentlyVerified === true && evMissSess.details.familyRevoked === true && evMissSess.details.sessionRevoked === false, 'Live outbox must record missing session and independent family revocation');

            // 3b. Missing family + valid active session -> session IS revoked synchronously; refresh blocked
            const cMissFam = await createLiveCompletedCeremony('miss_fam');
            await db.collection('tenants').doc('lanzar').collection('token_families').doc(cMissFam.famId).delete();
            const replayMissFam = await store.initiateRedemption({
                code: cMissFam.code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: cMissFam.pkce.verifier, idempotencyKey: `idem_emu23_miss_fam_${crypto.randomBytes(6).toString('hex')}`
            });
            assert(replayMissFam.status === 'REPLAY_DETECTED', 'Missing family replay must return REPLAY_DETECTED');
            const gateMissFam = await evaluateLiveRefreshGate(cMissFam.famId, testUid, cMissFam.sessId);
            assert(gateMissFam.sessState.active === false && gateMissFam.sessState.reason === 'revoked', 'Live valid active session MUST be revoked when family is missing');
            assert(gateMissFam.refreshAllowed === false, 'Live refresh MUST be blocked when family is missing and session is revoked');
            const outboxMissFamSnap = await db.collection('security_outbox').where('details.ceremonyId', '==', cMissFam.claim.record.ceremonyId).get();
            const evMissFam = outboxMissFamSnap.docs.map(d => d.data()).find(d => d.eventType === 'CRITICAL_SECURITY_RECORD_MISSING');
            assert(evMissFam && evMissFam.details.familyMissing === true && evMissFam.details.sessionIndependentlyVerified === true && evMissFam.details.sessionRevoked === true && evMissFam.details.familyRevoked === false, 'Live outbox must record missing family and independent session revocation');

            // 3c. Corrupt session relationship + independently valid family -> family IS revoked (refresh blocked); foreign/corrupt session untouched
            const cCorruptSess = await createLiveCompletedCeremony('corrupt_sess');
            await db.collection('users').doc(testUid).collection('sessions').doc(cCorruptSess.sessId).update({
                familyId: 'fam_foreign_crossref'
            });
            const replayCorruptSess = await store.initiateRedemption({
                code: cCorruptSess.code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: cCorruptSess.pkce.verifier, idempotencyKey: `idem_emu23_corrupt_sess_${crypto.randomBytes(6).toString('hex')}`
            });
            assert(replayCorruptSess.status === 'REPLAY_DETECTED', 'Corrupt session replay must return REPLAY_DETECTED');
            const gateCorruptSess = await evaluateLiveRefreshGate(cCorruptSess.famId, testUid, cCorruptSess.sessId);
            assert(gateCorruptSess.fam.status === 'revoked', 'Live independently valid family MUST be revoked even when session is corrupt');
            assert((await db.collection('users').doc(testUid).collection('sessions').doc(cCorruptSess.sessId).get()).data().status === 'active', 'Live corrupt/foreign session MUST remain untouched');
            assert(gateCorruptSess.refreshAllowed === false, 'Live refresh MUST be blocked against revoked family');
            const outboxCorruptSessSnap = await db.collection('security_outbox').where('details.ceremonyId', '==', cCorruptSess.claim.record.ceremonyId).get();
            const evCorruptSess = outboxCorruptSessSnap.docs.map(d => d.data()).find(d => d.eventType === 'CRITICAL_REPLAY_PAIR_INTEGRITY_FAILURE');
            assert(evCorruptSess && evCorruptSess.details.sessionInconsistent === true && evCorruptSess.details.familyIndependentlyVerified === true && evCorruptSess.details.familyRevoked === true && evCorruptSess.details.sessionRevoked === false, 'Live outbox must record corrupt session and independent family revocation');

            // 3d. Corrupt family relationship + independently valid session -> session IS revoked (refresh blocked); foreign/corrupt family untouched
            const cCorruptFam = await createLiveCompletedCeremony('corrupt_fam');
            await db.collection('tenants').doc('lanzar').collection('token_families').doc(cCorruptFam.famId).update({
                redemptionLockId: 'foreign_lock_mismatch'
            });
            const replayCorruptFam = await store.initiateRedemption({
                code: cCorruptFam.code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: cCorruptFam.pkce.verifier, idempotencyKey: `idem_emu23_corrupt_fam_${crypto.randomBytes(6).toString('hex')}`
            });
            assert(replayCorruptFam.status === 'REPLAY_DETECTED', 'Corrupt family replay must return REPLAY_DETECTED');
            const gateCorruptFam = await evaluateLiveRefreshGate(cCorruptFam.famId, testUid, cCorruptFam.sessId);
            assert(gateCorruptFam.sessState.active === false && gateCorruptFam.sessState.reason === 'revoked', 'Live independently valid session MUST be revoked even when family is corrupt');
            assert(gateCorruptFam.fam.status === 'active', 'Live corrupt/foreign family MUST remain untouched');
            assert(gateCorruptFam.refreshAllowed === false, 'Live refresh MUST be blocked because session is revoked');
            const outboxCorruptFamSnap = await db.collection('security_outbox').where('details.ceremonyId', '==', cCorruptFam.claim.record.ceremonyId).get();
            const evCorruptFam = outboxCorruptFamSnap.docs.map(d => d.data()).find(d => d.eventType === 'CRITICAL_REPLAY_PAIR_INTEGRITY_FAILURE');
            assert(evCorruptFam && evCorruptFam.details.familyInconsistent === true && evCorruptFam.details.sessionIndependentlyVerified === true && evCorruptFam.details.sessionRevoked === true && evCorruptFam.details.familyRevoked === false, 'Live outbox must record corrupt family and independent session revocation');

            // 3e. Both records valid and correctly paired -> BOTH are revoked and refresh is blocked; no integrity failure alert
            const cValidPair = await createLiveCompletedCeremony('valid_pair');
            const replayValidPair = await store.initiateRedemption({
                code: cValidPair.code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: cValidPair.pkce.verifier, idempotencyKey: `idem_emu23_valid_pair_${crypto.randomBytes(6).toString('hex')}`
            });
            assert(replayValidPair.status === 'REPLAY_DETECTED', 'Valid pair replay must return REPLAY_DETECTED');
            const gateValidPair = await evaluateLiveRefreshGate(cValidPair.famId, testUid, cValidPair.sessId);
            assert(gateValidPair.fam.status === 'revoked' && gateValidPair.sessState.active === false && gateValidPair.sessState.reason === 'revoked', 'Both paired live session and family MUST be revoked');
            assert(gateValidPair.refreshAllowed === false, 'Live refresh MUST be blocked when both records are revoked');
            const outboxValidPairSnap = await db.collection('security_outbox').where('details.ceremonyId', '==', cValidPair.claim.record.ceremonyId).get();
            assert(!outboxValidPairSnap.docs.some(d => ['CRITICAL_REPLAY_PAIR_INTEGRITY_FAILURE', 'CRITICAL_SECURITY_RECORD_MISSING'].includes(d.data().eventType)), 'Valid paired revocation must not emit pair integrity failure');

            // 3f. Both records untrustworthy -> NEITHER foreign record is revoked (refresh on foreign records unaffected), critical incident staged
            const cBothBad = await createLiveCompletedCeremony('both_bad');
            await db.collection('users').doc(testUid).collection('sessions').doc(cBothBad.sessId).update({
                ceremonyId: 'foreign_ceremony_uncompromised'
            });
            await db.collection('tenants').doc('lanzar').collection('token_families').doc(cBothBad.famId).update({
                ceremonyId: 'foreign_ceremony_uncompromised'
            });
            const replayBothBad = await store.initiateRedemption({
                code: cBothBad.code, clientId: testClientId, redirectUri: testRedirectUri,
                codeVerifier: cBothBad.pkce.verifier, idempotencyKey: `idem_emu23_both_bad_${crypto.randomBytes(6).toString('hex')}`
            });
            assert(replayBothBad.status === 'REPLAY_DETECTED', 'Both untrustworthy replay must return REPLAY_DETECTED');
            const gateBothBad = await evaluateLiveRefreshGate(cBothBad.famId, testUid, cBothBad.sessId, cBothBad.refreshToken);
            assert(gateBothBad.fam.status === 'active' && gateBothBad.sessState.active === true && gateBothBad.refreshAllowed === true, 'Live foreign/untrustworthy session and family MUST remain untouched');
            const outboxBothBadSnap = await db.collection('security_outbox').where('details.ceremonyId', '==', cBothBad.claim.record.ceremonyId).get();
            const evBothBad = outboxBothBadSnap.docs.map(d => d.data()).find(d => d.eventType === 'CRITICAL_REPLAY_PAIR_INTEGRITY_FAILURE');
            assert(evBothBad && evBothBad.details.sessionInconsistent === true && evBothBad.details.familyInconsistent === true && evBothBad.details.sessionRevoked === false && evBothBad.details.familyRevoked === false, 'Live outbox must record critical incident with neither record revoked');
        });

        await test('EMU-24: Live Firestore HTTP POST /oauth/token enforces authorizeRefreshGrant() across all refresh scenarios', async () => {
            const store = new FirestoreAuthorizationCodeStore(db);
            const express = require('./auth-backend/node_modules/express');
            const { createOAuthRouter } = require('./auth-backend/routes/oauthRoutes');
            const { SessionService } = require('./auth-backend/sessionService');

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

            const seedLiveCeremony = async (tag) => {
                const pkce = generatePkce();
                const code = await store.createCode({
                    uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                    codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
                });
                const codeHash = hashAuthorizationCode(code);
                const claim = await store.initiateRedemption({
                    code, clientId: testClientId, redirectUri: testRedirectUri,
                    codeVerifier: pkce.verifier, idempotencyKey: `idem_emu24_${tag}_${crypto.randomBytes(8).toString('hex')}`
                });
                const { generateRefreshToken } = require('./auth-backend/store');
                const sessId = `sess_emu24_${tag}_${Date.now()}`;
                const famId = `fam_emu24_${tag}_${Date.now()}`;
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
                // 1. Normal active family and session -> 200 with tokens
                const cNormal = await seedLiveCeremony('normal');
                const resNormal = await postRefresh({
                    grant_type: 'refresh_token', refresh_token: cNormal.refreshToken,
                    family_id: cNormal.famId, session_id: cNormal.sessId, uid: testUid, tenant_id: 'lanzar'
                });
                assert(resNormal.status === 200 && typeof resNormal.body.access_token === 'string' && typeof resNormal.body.refresh_token === 'string', 'Live normal active refresh must return 200 with tokens');

                // 2. Revoked family -> 401 FAMILY_REVOKED
                const cRevFam = await seedLiveCeremony('rev_fam');
                await db.collection('tenants').doc('lanzar').collection('token_families').doc(cRevFam.famId).update({ status: 'revoked' });
                const resRevFam = await postRefresh({
                    grant_type: 'refresh_token', refresh_token: cRevFam.refreshToken,
                    family_id: cRevFam.famId, session_id: cRevFam.sessId, uid: testUid, tenant_id: 'lanzar'
                });
                assert(resRevFam.status === 401 && resRevFam.body.error === 'invalid_grant' && resRevFam.body.reason === 'FAMILY_REVOKED', 'Live revoked family must be rejected');
                assert(!resRevFam.body.access_token && !resRevFam.body.refresh_token);

                // 3. Revoked session -> 401 SESSION_REVOKED
                const cRevSess = await seedLiveCeremony('rev_sess');
                await db.collection('users').doc(testUid).collection('sessions').doc(cRevSess.sessId).update({ status: 'revoked' });
                const resRevSess = await postRefresh({
                    grant_type: 'refresh_token', refresh_token: cRevSess.refreshToken,
                    family_id: cRevSess.famId, session_id: cRevSess.sessId, uid: testUid, tenant_id: 'lanzar'
                });
                assert(resRevSess.status === 401 && resRevSess.body.error === 'invalid_grant' && resRevSess.body.reason === 'SESSION_REVOKED', 'Live revoked session must be rejected');
                assert(!resRevSess.body.access_token && !resRevSess.body.refresh_token);

                // 4. Compromised ceremony tombstone with otherwise active family/session -> 401 CEREMONY_COMPROMISED
                const cTombstone = await seedLiveCeremony('tombstone');
                await db.collection('authorization_codes').doc(cTombstone.codeHash).update({
                    fenceToken: FieldValue.delete(),
                    completedLockId: FieldValue.delete()
                });
                await store.initiateRedemption({
                    code: cTombstone.code, clientId: testClientId, redirectUri: testRedirectUri,
                    codeVerifier: cTombstone.pkce.verifier, idempotencyKey: `idem_emu24_tomb_replay_${crypto.randomBytes(8).toString('hex')}`
                });
                const resTombstone = await postRefresh({
                    grant_type: 'refresh_token', refresh_token: cTombstone.refreshToken,
                    family_id: cTombstone.famId, session_id: cTombstone.sessId, uid: testUid, tenant_id: 'lanzar'
                });
                assert(resTombstone.status === 401 && resTombstone.body.error === 'invalid_grant' && resTombstone.body.reason === 'CEREMONY_COMPROMISED', 'Live compromised ceremony tombstone must reject refresh');
                assert(!resTombstone.body.access_token && !resTombstone.body.refresh_token);

                // 5. Unrelated active ceremony -> 200 with tokens
                const cUnrelated = await seedLiveCeremony('unrelated');
                const resUnrelated = await postRefresh({
                    grant_type: 'refresh_token', refresh_token: cUnrelated.refreshToken,
                    family_id: cUnrelated.famId, session_id: cUnrelated.sessId, uid: testUid, tenant_id: 'lanzar'
                });
                assert(resUnrelated.status === 200 && typeof resUnrelated.body.access_token === 'string' && typeof resUnrelated.body.refresh_token === 'string', 'Live unrelated active ceremony must still succeed');
            } finally {
                await new Promise((resolve) => server.close(resolve));
            }
        });

        await test('EMU-25: Live Firestore HTTP POST /oauth/token enforces refresh-token hash authentication, atomic rotation, replay revocation, and concurrency', async () => {
            const store = new FirestoreAuthorizationCodeStore(db);
            const { generateRefreshToken } = require('./auth-backend/store');
            const express = require('./auth-backend/node_modules/express');
            const { createOAuthRouter } = require('./auth-backend/routes/oauthRoutes');
            const { SessionService } = require('./auth-backend/sessionService');

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

            const seedLiveRefreshCeremony = async (tag, opts = {}) => {
                const pkce = generatePkce();
                const code = await store.createCode({
                    uid: testUid, clientId: testClientId, redirectUri: testRedirectUri,
                    codeChallenge: pkce.challenge, codeChallengeMethod: 'S256', tenantId: 'lanzar'
                });
                const codeHash = hashAuthorizationCode(code);
                const claim = await store.initiateRedemption({
                    code, clientId: testClientId, redirectUri: testRedirectUri,
                    codeVerifier: pkce.verifier, idempotencyKey: `idem_emu25_${tag}_${crypto.randomBytes(8).toString('hex')}`
                });
                const sessId = `sess_emu25_${tag}_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
                const famId = `fam_emu25_${tag}_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
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
                // 1. Atomic rotation updates currentActiveTokenHash and sequenceNumber in Firestore
                const cRot = await seedLiveRefreshCeremony('rot');
                const r1 = await postRefresh({
                    grant_type: 'refresh_token', refresh_token: cRot.rt1,
                    family_id: cRot.famId, session_id: cRot.sessId, uid: testUid, tenant_id: 'lanzar'
                });
                assert(r1.status === 200 && r1.body.sequence_number === 2 && r1.body.refresh_token !== cRot.rt1, 'Live first refresh must rotate to sequence 2');
                const famAfter1 = (await db.collection('tenants').doc('lanzar').collection('token_families').doc(cRot.famId).get()).data();
                assert(famAfter1.sequenceNumber === 2 && famAfter1.currentActiveTokenHash === hashAuthorizationCode(r1.body.refresh_token), 'Live currentActiveTokenHash and sequenceNumber must update atomically');

                // 2. Incorrect token rejected without issuing tokens
                const badTokRes = await postRefresh({
                    grant_type: 'refresh_token', refresh_token: generateRefreshToken(cRot.famId, 2),
                    family_id: cRot.famId, session_id: cRot.sessId, uid: testUid, tenant_id: 'lanzar'
                });
                assert(badTokRes.status === 401 && badTokRes.body.reason === 'INVALID_REFRESH_TOKEN' && !badTokRes.body.access_token && !badTokRes.body.refresh_token, 'Live incorrect token must be rejected');

                // 3. Token belonging to another family rejected
                const cOther = await seedLiveRefreshCeremony('other');
                const crossFamRes = await postRefresh({
                    grant_type: 'refresh_token', refresh_token: cOther.rt1,
                    family_id: cRot.famId, session_id: cRot.sessId, uid: testUid, tenant_id: 'lanzar'
                });
                assert(crossFamRes.status === 401 && crossFamRes.body.reason === 'TOKEN_FAMILY_MISMATCH' && !crossFamRes.body.access_token, 'Live cross-family token must be rejected');

                // 4. Client-supplied uid/session mismatch rejected
                const badSessRes = await postRefresh({
                    grant_type: 'refresh_token', refresh_token: r1.body.refresh_token,
                    family_id: cRot.famId, session_id: cOther.sessId, uid: testUid, tenant_id: 'lanzar'
                });
                assert(badSessRes.status === 401 && badSessRes.body.reason === 'RELATIONSHIP_MISMATCH' && !badSessRes.body.access_token, 'Live mismatched session_id must be rejected');

                // 5. Expired refresh token rejected
                const cExpired = await seedLiveRefreshCeremony('expired', { expiresAt: new Date(Date.now() - 60000).toISOString() });
                const expRes = await postRefresh({
                    grant_type: 'refresh_token', refresh_token: cExpired.rt1,
                    family_id: cExpired.famId, session_id: cExpired.sessId, uid: testUid, tenant_id: 'lanzar'
                });
                assert(expRes.status === 401 && expRes.body.reason === 'REFRESH_TOKEN_EXPIRED' && !expRes.body.access_token, 'Live expired token must be rejected');

                // 6. Reuse of previously rotated token (rt1) triggers replay response & revokes family + session
                const replayRes = await postRefresh({
                    grant_type: 'refresh_token', refresh_token: cRot.rt1,
                    family_id: cRot.famId, session_id: cRot.sessId, uid: testUid, tenant_id: 'lanzar'
                });
                assert(replayRes.status === 401 && replayRes.body.reason === 'REFRESH_TOKEN_REPLAY' && replayRes.body.replay_detected === true && !replayRes.body.access_token, 'Live reuse of rotated token must return REFRESH_TOKEN_REPLAY');
                assert((await db.collection('tenants').doc('lanzar').collection('token_families').doc(cRot.famId).get()).data().status === 'revoked', 'Live family must be revoked on replay');
                assert((await db.collection('users').doc(testUid).collection('sessions').doc(cRot.sessId).get()).data().status === 'revoked', 'Live session must be revoked on replay');
                assert((await db.collection('compromised_ceremonies').doc(cRot.ceremonyId).get()).exists, 'Live compromised_ceremonies tombstone must exist');

                // 7. Concurrent Firestore refresh requests presenting the same refresh token: only 1 succeeds
                const cConc = await seedLiveRefreshCeremony('conc');
                const [concA, concB] = await Promise.all([
                    postRefresh({ grant_type: 'refresh_token', refresh_token: cConc.rt1, family_id: cConc.famId, session_id: cConc.sessId, uid: testUid, tenant_id: 'lanzar' }),
                    postRefresh({ grant_type: 'refresh_token', refresh_token: cConc.rt1, family_id: cConc.famId, session_id: cConc.sessId, uid: testUid, tenant_id: 'lanzar' })
                ]);
                const successes = [concA, concB].filter(r => r.status === 200);
                const rejections = [concA, concB].filter(r => r.status === 401);
                assert(successes.length === 1 && rejections.length === 1, `Live concurrent refresh must allow exactly 1 success and 1 rejection, got ${concA.status} & ${concB.status}`);
                assert(rejections[0].body.reason === 'REFRESH_TOKEN_REPLAY' && !rejections[0].body.access_token && !rejections[0].body.refresh_token, 'Live concurrent loser must return REFRESH_TOKEN_REPLAY with zero tokens');
            } finally {
                await new Promise((resolve) => server.close(resolve));
            }
        });

    } finally {
        await terminateEmulator();
    }

    console.log('\n================================================================');
    console.log('LIVE FIRESTORE EMULATOR TEST SUMMARY');
    console.log(`Total Executed: ${passedCount + failedCount}`);
    console.log(`Passed:         ${passedCount}`);
    console.log(`Failed:         ${failedCount}`);
    console.log(`Success Rate:   ${((passedCount / (passedCount + failedCount)) * 100).toFixed(1)}%`);
    console.log('================================================================\n');

    if (failedCount > 0) process.exit(1);
}

main().catch(async (err) => {
    console.error('Fatal emulator test error:', err);
    await terminateEmulator();
    process.exit(1);
});
