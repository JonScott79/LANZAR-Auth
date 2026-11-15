// test-milestone-1-2-emulator.cjs
// Milestone 1.2 Live Cloud Firestore Emulator Verification Suite

const assert = require('assert');
const crypto = require('crypto');
const path = require('path');
const { spawn } = require('child_process');
module.paths.push(path.join(__dirname, 'auth-backend', 'node_modules'));
const { initializeApp } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const { SigningKeystore } = require('./auth-backend/services/signingKeystore');

const EMULATOR_HOST = '127.0.0.1';
const EMULATOR_PORT = 8089;
const PROJECT_ID = 'demo-lanzar-id-m1-2-test';

let emulatorProc = null;

async function waitForEmulator(timeoutMs = 20000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
        try {
            const resp = await fetch(`http://${EMULATOR_HOST}:${EMULATOR_PORT}/`);
            if (resp.ok || resp.status === 404 || resp.status === 200) return;
        } catch {
            // retry
        }
        await new Promise(r => setTimeout(r, 300));
    }
    throw new Error('Timed out waiting for Firestore Emulator');
}

async function startEmulator() {
    const jarPath = path.join(
        process.env.USERPROFILE || process.env.HOME,
        '.cache', 'firebase', 'emulators', 'cloud-firestore-emulator-v1.19.8.jar'
    );
    emulatorProc = spawn('java', [
        '-jar', jarPath,
        '--host', EMULATOR_HOST,
        '--port', String(EMULATOR_PORT),
        '--project_id', PROJECT_ID
    ], { stdio: 'ignore' });
    await waitForEmulator();
}

async function stopEmulator() {
    if (emulatorProc && !emulatorProc.killed) {
        emulatorProc.kill();
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
    process.env.FIRESTORE_EMULATOR_HOST = `${EMULATOR_HOST}:${EMULATOR_PORT}`;
    process.env.GCLOUD_PROJECT = PROJECT_ID;

    console.log('================================================================');
    console.log('LANZAR ID — Milestone 1.2 Live Cloud Firestore Emulator Suite');
    console.log(`Project: ${PROJECT_ID} | Endpoint: ${EMULATOR_HOST}:${EMULATOR_PORT}`);
    console.log('================================================================\n');

    await startEmulator();
    const app = initializeApp({ projectId: PROJECT_ID }, 'm12-emu-app');
    const db = getFirestore(app);

    try {
        await test('EMU-M1.2-01: Key creation persists encrypted private key and public JWK in Firestore', async () => {
            const ks = new SigningKeystore(db, { collectionName: 'system_signing_keys_01' });
            const rec = await ks.ensureActiveSigningKey({ bypassCache: true });
            const snap = await db.collection('system_signing_keys_01').doc(rec.kid).get();
            assert.strictEqual(snap.exists, true);
            const data = snap.data();
            assert.strictEqual(data.status, 'active');
            assert.ok(data.encryptedPrivateKey && data.encryptedPrivateKey.ciphertext);
            assert.strictEqual(data.privateKey, undefined);
        });

        await test('EMU-M1.2-02: Concurrent initialization in live Firestore creates only ONE active key', async () => {
            const ks1 = new SigningKeystore(db, { collectionName: 'system_signing_keys_02' });
            const ks2 = new SigningKeystore(db, { collectionName: 'system_signing_keys_02' });
            const ks3 = new SigningKeystore(db, { collectionName: 'system_signing_keys_02' });

            const results = await Promise.all([
                ks1.ensureActiveSigningKey({ bypassCache: true }),
                ks2.ensureActiveSigningKey({ bypassCache: true }),
                ks3.ensureActiveSigningKey({ bypassCache: true })
            ]);
            const snap = await db.collection('system_signing_keys_02').where('status', '==', 'active').get();
            assert.strictEqual(snap.size, 1, `Expected 1 active key in Firestore, got ${snap.size}`);
            const kids = new Set(results.map(r => r.kid));
            assert.strictEqual(kids.size, 1, `Expected all callers to receive same kid, got ${Array.from(kids).join(', ')}`);
        });

        await test('EMU-M1.2-03: Rotation in live Firestore demotes prior key to verify_only and preserves verification', async () => {
            const ks = new SigningKeystore(db, { collectionName: 'system_signing_keys_03' });
            const tok1 = await ks.signJwt({ sub: 'emu_u1' });
            const kid1 = JSON.parse(Buffer.from(tok1.split('.')[0], 'base64url').toString('utf8')).kid;

            const { newRecord } = await ks.rotateSigningKey();
            const tok2 = await ks.signJwt({ sub: 'emu_u2' });

            const doc1 = (await db.collection('system_signing_keys_03').doc(kid1).get()).data();
            const doc2 = (await db.collection('system_signing_keys_03').doc(newRecord.kid).get()).data();
            assert.strictEqual(doc1.status, 'verify_only');
            assert.strictEqual(doc2.status, 'active');
            assert.strictEqual((await ks.verifyJwt(tok1, { bypassCache: true })).valid, true);
            assert.strictEqual((await ks.verifyJwt(tok2, { bypassCache: true })).valid, true);
        });

        await test('EMU-M1.2-04: Revocation in live Firestore excludes key from JWKS and rejects verification', async () => {
            const ks = new SigningKeystore(db, { collectionName: 'system_signing_keys_04' });
            const tok = await ks.signJwt({ sub: 'emu_rev' });
            const kid = JSON.parse(Buffer.from(tok.split('.')[0], 'base64url').toString('utf8')).kid;

            await ks.revokeSigningKey(kid, 'compromised');
            const doc = (await db.collection('system_signing_keys_04').doc(kid).get()).data();
            assert.strictEqual(doc.status, 'revoked');
            const jwks = await ks.getPublicJwks({ bypassCache: true });
            assert.strictEqual(jwks.keys.some(k => k.kid === kid), false);
            const res = await ks.verifyJwt(tok, { bypassCache: true });
            assert.strictEqual(res.valid, false);
            assert.strictEqual(res.reason, 'UNKNOWN_OR_REVOKED_KID');
        });

        await test('EMU-M1.2-05: Concurrent rotation and retry handles contention safely', async () => {
            const ks = new SigningKeystore(db, { collectionName: 'system_signing_keys_05' });
            await ks.ensureActiveSigningKey({ bypassCache: true });
            const [r1, r2] = await Promise.all([
                ks.rotateSigningKey(),
                ks.rotateSigningKey()
            ]);
            assert.notStrictEqual(r1.newRecord.kid, r2.newRecord.kid);
            const activeSnap = await db.collection('system_signing_keys_05').where('status', '==', 'active').get();
            assert.strictEqual(activeSnap.size, 1, `Expected 1 active key after concurrent rotation, got ${activeSnap.size}`);
            const pointerDoc = (await db.collection('system_signing_keys_05').doc('_active_pointer').get()).data();
            assert.strictEqual(pointerDoc.activeKid, activeSnap.docs[0].id);
        });

        await test('EMU-M1.2-06: Legacy active keys without _active_pointer reconcile deterministically in live Firestore', async () => {
            const col = db.collection('system_signing_keys_06');
            const { generateRsaSigningKeyRecord } = require('./auth-backend/services/signingKeystore.js');
            const legacy1 = generateRsaSigningKeyRecord(Date.now() - 20000);
            const legacy2 = generateRsaSigningKeyRecord(Date.now() - 10000);
            await col.doc(legacy1.kid).set(legacy1);
            await col.doc(legacy2.kid).set(legacy2);

            const ks = new SigningKeystore(db, { collectionName: 'system_signing_keys_06' });
            const active = await ks.ensureActiveSigningKey({ bypassCache: true });
            assert.strictEqual(active.kid, legacy2.kid);

            const pointerDoc = (await col.doc('_active_pointer').get()).data();
            assert.strictEqual(pointerDoc.activeKid, legacy2.kid);
            assert.strictEqual((await col.doc(legacy1.kid).get()).data().status, 'verify_only');
            assert.strictEqual((await col.doc(legacy2.kid).get()).data().status, 'active');

            const jwks = await ks.getPublicJwks({ bypassCache: true });
            assert.strictEqual(jwks.keys.length, 2);
            assert.strictEqual(jwks.keys.some(k => k.kid === '_active_pointer'), false);
        });

        await test('EMU-M1.2-07: Revoked key cannot be reactivated in live Firestore even with stale _active_pointer', async () => {
            const col = db.collection('system_signing_keys_07');
            const ks = new SigningKeystore(db, { collectionName: 'system_signing_keys_07' });
            const first = await ks.ensureActiveSigningKey({ bypassCache: true });
            await ks.revokeSigningKey(first.kid, 'compromised');
            await col.doc('_active_pointer').set({ activeKid: first.kid, updatedAt: new Date().toISOString() });

            const replacement = await ks.ensureActiveSigningKey({ bypassCache: true });
            assert.notStrictEqual(replacement.kid, first.kid);
            assert.strictEqual(replacement.status, 'active');
            assert.strictEqual((await col.doc(first.kid).get()).data().status, 'revoked');
            assert.strictEqual((await col.doc('_active_pointer').get()).data().activeKid, replacement.kid);
        });
    } finally {
        await stopEmulator();
    }

    console.log('\n================================================================');
    console.log('MILESTONE 1.2 EMULATOR VERIFICATION SUMMARY');
    console.log(`Total Executed: ${passed + failed}`);
    console.log(`Passed:         ${passed}`);
    console.log(`Failed:         ${failed}`);
    console.log(`Success Rate:   ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
    console.log('================================================================\n');

    if (failed > 0) process.exit(1);
}

main().catch(async err => {
    console.error('Fatal M1.2 emulator error:', err);
    await stopEmulator();
    process.exit(1);
});
