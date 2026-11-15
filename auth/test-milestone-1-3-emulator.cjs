// test-milestone-1-3-emulator.cjs
// Milestone 1.3 Live Cloud Firestore Emulator Verification Suite

const assert = require('assert');
const crypto = require('crypto');
const path = require('path');
const { spawn } = require('child_process');
module.paths.push(path.join(__dirname, 'auth-backend', 'node_modules'));
const { initializeApp } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const { SigningKeystore } = require('./auth-backend/services/signingKeystore');
const { OidcTokenService } = require('./auth-backend/services/oidcTokenService');
const { FirestoreAuthorizationCodeStore, hashAuthorizationCode, generateRefreshToken } = require('./auth-backend/store');
const { getClient } = require('./auth-backend/clients');

const EMULATOR_HOST = '127.0.0.1';
const EMULATOR_PORT = 8090;
const PROJECT_ID = 'demo-lanzar-id-m1-3-test';

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
    console.log('LANZAR ID — Milestone 1.3 Live Cloud Firestore Emulator Suite');
    console.log(`Project: ${PROJECT_ID} | Endpoint: ${EMULATOR_HOST}:${EMULATOR_PORT}`);
    console.log('================================================================\n');

    await startEmulator();
    const app = initializeApp({ projectId: PROJECT_ID });
    const db = getFirestore(app);

    try {
        await test('EMU-M1.3-01: Complete authorization-code data path preserves userClaims, scope, and nonce into OIDC ID-token issuance', async () => {
            const codeStore = new FirestoreAuthorizationCodeStore(db);
            const keystore = new SigningKeystore(db, { collectionName: 'system_signing_keys_m1_3' });
            const oidc = new OidcTokenService({ signingKeystore: keystore, issuer: 'https://auth-api-dev.lanzar.me' });

            const verifier = 'emu_pkce_verifier_' + crypto.randomBytes(20).toString('hex');
            const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
            const expectedUserClaims = {
                email: 'emu_oidc@lanzar.me',
                emailVerified: true,
                name: 'Emulator OIDC User',
                authTime: 1700000999
            };
            const expectedScope = 'openid profile email';
            const expectedNonce = 'emu_nonce_' + crypto.randomBytes(8).toString('hex');

            // 1. Persist ceremony through real FirestoreAuthorizationCodeStore
            const code = await codeStore.createCode({
                uid: 'uid_emu_oidc_1',
                clientId: 'threadline',
                redirectUri: 'https://threadline.lanzar.me',
                codeChallenge: challenge,
                codeChallengeMethod: 'S256',
                tenantId: 'lanzar',
                scope: expectedScope,
                nonce: expectedNonce,
                userClaims: expectedUserClaims,
                mfaVerified: false
            });
            assert.ok(code && typeof code === 'string');

            // 2. Redeem via normal two-phase redemption flow
            const claim = await codeStore.initiateRedemption({
                code,
                clientId: 'threadline',
                redirectUri: 'https://threadline.lanzar.me',
                codeVerifier: verifier,
                idempotencyKey: 'emu_idem_key_1234567890'
            });
            assert.strictEqual(claim.status, 'SUCCESS');

            // 3. Verify returned record preserves userClaims, scope, and nonce exactly
            assert.strictEqual(claim.record.scope, expectedScope);
            assert.strictEqual(claim.record.nonce, expectedNonce);
            assert.deepStrictEqual(claim.record.userClaims, expectedUserClaims);

            // 4. Stage session & family, register pointers, and issue OIDC tokens
            const sessionId = 'sess_emu_' + crypto.randomBytes(6).toString('hex');
            const familyId = 'fam_emu_' + crypto.randomBytes(6).toString('hex');
            const expiresAt = new Date(Date.now() + 86400000).toISOString();
            const refreshToken = generateRefreshToken(familyId, 1);

            await db.collection('users').doc('uid_emu_oidc_1').collection('sessions').doc(sessionId).create({
                sessionId,
                familyId,
                uid: 'uid_emu_oidc_1',
                tenantId: 'lanzar',
                clientId: 'threadline',
                ceremonyId: claim.record.ceremonyId,
                status: 'pending_activation',
                redemptionLockId: claim.redemptionLockId,
                fenceToken: claim.fenceToken,
                expiresAt,
                revoked: false
            });
            await db.collection('tenants').doc('lanzar').collection('token_families').doc(familyId).create({
                familyId,
                sessionId,
                uid: 'uid_emu_oidc_1',
                tenantId: 'lanzar',
                clientId: 'threadline',
                ceremonyId: claim.record.ceremonyId,
                status: 'pending_activation',
                redemptionLockId: claim.redemptionLockId,
                fenceToken: claim.fenceToken,
                currentActiveTokenHash: hashAuthorizationCode(refreshToken),
                sequenceNumber: 1,
                rotatedTokenHashes: [],
                scope: claim.record.scope,
                authTime: claim.record.userClaims.authTime,
                expiresAt,
                revoked: false
            });

            const regResult = await codeStore.registerStagedRecords({
                codeHash: claim.codeHash,
                redemptionLockId: claim.redemptionLockId,
                fenceToken: claim.fenceToken,
                uid: 'uid_emu_oidc_1',
                tenantId: 'lanzar',
                clientId: 'threadline',
                ceremonyId: claim.record.ceremonyId,
                issuedSessionId: sessionId,
                issuedFamilyId: familyId
            });
            assert.strictEqual(regResult.success, true);

            const tokensPayload = await oidc.buildTokenResponse({
                client: getClient('threadline'),
                uid: 'uid_emu_oidc_1',
                clientId: 'threadline',
                tenantId: 'lanzar',
                sessionId,
                familyId,
                refreshToken,
                scope: claim.record.scope,
                userClaims: claim.record.userClaims,
                nonce: claim.record.nonce,
                authTime: claim.record.userClaims.authTime,
                authAdmin: { async createCustomToken(u) { return `fb_emu_${u}`; } }
            });

            const finalResult = await codeStore.finalizeRedemption({
                codeHash: claim.codeHash,
                redemptionLockId: claim.redemptionLockId,
                fenceToken: claim.fenceToken,
                uid: 'uid_emu_oidc_1',
                tenantId: 'lanzar',
                issuedSessionId: sessionId,
                issuedFamilyId: familyId,
                rawTokensPayload: tokensPayload
            });
            assert.strictEqual(finalResult.success, true);

            // 5. Verify claims reached the OIDC ID-token issuance layer and verify signature via JWKS
            assert.ok(tokensPayload.id_token);
            const idVerified = await keystore.verifyJwt(tokensPayload.id_token, { bypassCache: true });
            assert.strictEqual(idVerified.valid, true);
            assert.strictEqual(idVerified.payload.sub, 'uid_emu_oidc_1');
            assert.strictEqual(idVerified.payload.nonce, expectedNonce);
            assert.strictEqual(idVerified.payload.auth_time, expectedUserClaims.authTime);
            assert.strictEqual(idVerified.payload.email, expectedUserClaims.email);
            assert.strictEqual(idVerified.payload.email_verified, true);
            assert.strictEqual(idVerified.payload.name, expectedUserClaims.name);
        });
    } finally {
        await stopEmulator();
    }

    console.log('\n================================================================');
    console.log('MILESTONE 1.3 EMULATOR VERIFICATION SUMMARY');
    console.log(`Total Executed: ${passed + failed}`);
    console.log(`Passed:         ${passed}`);
    console.log(`Failed:         ${failed}`);
    console.log(`Success Rate:   ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
    console.log('================================================================\n');

    if (failed > 0) process.exit(1);
}

main().catch(async err => {
    console.error('Fatal M1.3 emulator error:', err);
    await stopEmulator();
    process.exit(1);
});
