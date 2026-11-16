// test-firestore-rules-emulator.cjs
// Live Cloud Firestore Emulator Security Rules Verification Suite

const assert = require('assert');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');
module.paths.push(path.join(__dirname, 'auth-backend', 'node_modules'));
const { initializeApp, deleteApp } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');

const EMULATOR_HOST = '127.0.0.1';
const EMULATOR_PORT = 8093;
const PROJECT_ID = 'demo-lanzar-id-rules-test';
const RULES_PATH = path.join(__dirname, '..', 'firestore.rules');
const EMULATOR_JAR = path.join(process.env.USERPROFILE || process.env.HOME || '', '.cache', 'firebase', 'emulators', 'cloud-firestore-emulator-v1.19.8.jar');

function makeEmulatorUserJwt(uid) {
    const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    return `${b64({ alg: 'none', typ: 'JWT' })}.${b64({
        iss: `https://securetoken.google.com/${PROJECT_ID}`,
        aud: PROJECT_ID,
        sub: uid,
        user_id: uid,
        iat: now,
        exp: now + 3600
    })}.`;
}

function waitForPort(host, port, timeoutMs = 20000) {
    const start = Date.now();
    return new Promise((resolve, reject) => {
        const tryConnect = () => {
            const socket = net.connect({ host, port });
            socket.once('connect', () => { socket.destroy(); resolve(); });
            socket.once('error', () => {
                socket.destroy();
                if (Date.now() - start > timeoutMs) reject(new Error(`Timeout waiting for emulator on ${host}:${port}`));
                else setTimeout(tryConnect, 250);
            });
        };
        tryConnect();
    });
}

async function startEmulator() {
    const child = spawn('java', [
        '-jar', EMULATOR_JAR,
        '--host', EMULATOR_HOST,
        '--port', String(EMULATOR_PORT),
        '--rules', RULES_PATH
    ], { stdio: 'ignore' });
    await waitForPort(EMULATOR_HOST, EMULATOR_PORT, 25000);
    return child;
}

async function restGet(docPath, bearerJwt) {
    const url = `http://${EMULATOR_HOST}:${EMULATOR_PORT}/v1/projects/${PROJECT_ID}/databases/(default)/documents/${docPath}`;
    return fetch(url, { headers: bearerJwt ? { Authorization: `Bearer ${bearerJwt}` } : {} });
}

async function restPatch(docPath, fields, bearerJwt) {
    const url = `http://${EMULATOR_HOST}:${EMULATOR_PORT}/v1/projects/${PROJECT_ID}/databases/(default)/documents/${docPath}`;
    return fetch(url, {
        method: 'PATCH',
        headers: {
            'Content-Type': 'application/json',
            ...(bearerJwt ? { Authorization: `Bearer ${bearerJwt}` } : {})
        },
        body: JSON.stringify({ fields })
    });
}

async function restDelete(docPath, bearerJwt) {
    const url = `http://${EMULATOR_HOST}:${EMULATOR_PORT}/v1/projects/${PROJECT_ID}/databases/(default)/documents/${docPath}`;
    return fetch(url, {
        method: 'DELETE',
        headers: bearerJwt ? { Authorization: `Bearer ${bearerJwt}` } : {}
    });
}

async function main() {
    let emulatorProc;
    let passed = 0;
    let failed = 0;

    async function test(name, fn) {
        try {
            await fn();
            console.log(`  ✓ [PASS] ${name}`);
            passed++;
        } catch (err) {
            console.error(`  ✗ [FAIL] ${name}`);
            console.error(err);
            failed++;
        }
    }

    try {
        emulatorProc = await startEmulator();
        process.env.FIRESTORE_EMULATOR_HOST = `${EMULATOR_HOST}:${EMULATOR_PORT}`;
        process.env.GCLOUD_PROJECT = PROJECT_ID;

        const app = initializeApp({ projectId: PROJECT_ID }, 'rules-emulator-test');
        const adminDb = getFirestore(app);

        // Seed records via Admin SDK (server-side)
        await adminDb.collection('users').doc('user_a').set({ uid: 'user_a', displayName: 'Alice', status: 'active' });
        await adminDb.collection('users').doc('user_b').set({ uid: 'user_b', displayName: 'Bob', status: 'active' });
        await adminDb.collection('users').doc('user_a').collection('sessions').doc('s_a').set({ sessionId: 's_a', tenantId: 'tenant_a', status: 'active' });
        await adminDb.collection('users').doc('user_a').collection('central_sessions').doc('cs_a').set({ sessionId: 'cs_a', revoked: false });
        await adminDb.collection('users').doc('user_a').collection('session_slots').doc('slot_a').set({ slotId: 'slot_a' });
        await adminDb.collection('users').doc('user_a').collection('founders').doc('portal').set({ programId: 'portal', active: true });
        await adminDb.collection('user_security').doc('user_a').set({ tokenVersion: 1 });
        await adminDb.collection('security_logs').doc('log_1').set({ action: 'login' });
        await adminDb.collection('mfa_factors').doc('user_a').set({ enabled: true });
        await adminDb.collection('phone_otps').doc('otp_1').set({ codeHash: 'abc' });
        await adminDb.collection('admins').doc('admin_1').set({ role: 'platform_admin', active: true });
        await adminDb.collection('pythos').doc('app').collection('lanzar_id_accounts').doc('acc_1').set({ uid: 'user_a' });
        await adminDb.collection('tenants').doc('tenant_a').collection('clients').doc('c_a').set({ clientId: 'c_a', tenantId: 'tenant_a', enabled: true });
        await adminDb.collection('tenants').doc('tenant_b').collection('clients').doc('c_b').set({ clientId: 'c_b', tenantId: 'tenant_b', enabled: true });
        await adminDb.collection('tenants').doc('tenant_b').collection('token_families').doc('f_b').set({ familyId: 'f_b', tenantId: 'tenant_b', status: 'active' });
        await adminDb.collection('tenants').doc('tenant_b').collection('admin_audit_logs').doc('aud_b').set({ auditId: 'aud_b', operation: 'client.register' });
        await adminDb.collection('tenants').doc('tenant_a').collection('token_families').doc('f_a').set({ familyId: 'f_a', tenantId: 'tenant_a', status: 'active' });
        await adminDb.collection('tenants').doc('tenant_a').collection('admin_audit_logs').doc('aud_1').set({ auditId: 'aud_1', operation: 'client.register' });
        await adminDb.collection('clients_index').doc('c_a').set({ clientId: 'c_a', tenantId: 'tenant_a' });
        await adminDb.collection('system_signing_keys').doc('k_1').set({ kid: 'k_1', status: 'active' });
        await adminDb.collection('oauth_authorization_codes').doc('code_1').set({ status: 'ISSUED' });
        await adminDb.collection('authorization_codes').doc('code_2').set({ status: 'ISSUED' });
        await adminDb.collection('compromised_ceremonies').doc('cer_1').set({ ceremonyId: 'cer_1' });
        await adminDb.collection('security_outbox').doc('evt_1').set({ status: 'pending' });
        await adminDb.collection('admin_idempotency').doc('idem_1').set({ status: 'COMPLETED' });
        await adminDb.collection('auth_reconciliation').doc('rec_1').set({ status: 'CONVERGED' });

        const jwtA = makeEmulatorUserJwt('user_a');

        console.log('\n================================================================');
        console.log('LANZAR ID — Firestore Security Rules Emulator Suite');
        console.log(`Project: ${PROJECT_ID} | Endpoint: ${EMULATOR_HOST}:${EMULATOR_PORT}`);
        console.log('================================================================\n');

        await test('RULES-01: Authenticated user_a can read and update allowlisted displayName on own /users/user_a', async () => {
            const getRes = await restGet('users/user_a', jwtA);
            assert.strictEqual(getRes.status, 200);
            const patchRes = await restPatch('users/user_a?updateMask.fieldPaths=displayName', {
                displayName: { stringValue: 'Alice Updated' }
            }, jwtA);
            assert.strictEqual(patchRes.status, 200);
        });

        await test('RULES-02: user_a is DENIED read/write to /users/user_b and /users/*/sessions/*', async () => {
            assert.strictEqual((await restGet('users/user_b', jwtA)).status, 403);
            assert.strictEqual((await restGet('users/user_a/sessions/s_a', jwtA)).status, 403);
            assert.strictEqual((await restPatch('users/user_a/sessions/s_a', { status: { stringValue: 'hacked' } }, jwtA)).status, 403);
        });

        await test('RULES-03: Client access DENIED for all M1.1-M1.5 server-only collections and audit logs (read/create/update/delete)', async () => {
            const paths = [
                'tenants/tenant_a/clients/c_a',
                'tenants/tenant_a/token_families/f_a',
                'tenants/tenant_a/admin_audit_logs/aud_1',
                'clients_index/c_a',
                'system_signing_keys/k_1',
                'oauth_authorization_codes/code_1',
                'authorization_codes/code_2',
                'compromised_ceremonies/cer_1',
                'security_outbox/evt_1',
                'admin_idempotency/idem_1',
                'auth_reconciliation/rec_1'
            ];
            for (const p of paths) {
                assert.strictEqual((await restGet(p, jwtA)).status, 403, `Expected 403 GET ${p}`);
                assert.strictEqual((await restPatch(p, { tampered: { booleanValue: true } }, jwtA)).status, 403, `Expected 403 PATCH ${p}`);
                assert.strictEqual((await restDelete(p, jwtA)).status, 403, `Expected 403 DELETE ${p}`);
            }
            // Explicit create attempt on admin_audit_logs denied
            assert.strictEqual((await restPatch('tenants/tenant_a/admin_audit_logs/aud_new', { auditId: { stringValue: 'aud_new' } }, jwtA)).status, 403);
        });

        await test('RULES-04: Unauthenticated requests are DENIED on /users/user_a and server-only collections', async () => {
            assert.strictEqual((await restGet('users/user_a', null)).status, 403);
            assert.strictEqual((await restPatch('users/user_a?updateMask.fieldPaths=displayName', { displayName: { stringValue: 'Anon' } }, null)).status, 403);
            assert.strictEqual((await restGet('system_signing_keys/k_1', null)).status, 403);
            assert.strictEqual((await restGet('tenants/tenant_a/clients/c_a', null)).status, 403);
        });

        await test('RULES-05: /users/user_a denies create, delete, disallowed fields, and invalid avatarUrl', async () => {
            // Create new user doc denied
            assert.strictEqual((await restPatch('users/user_new', { displayName: { stringValue: 'New' } }, makeEmulatorUserJwt('user_new'))).status, 403);
            // Delete own user doc denied
            assert.strictEqual((await restDelete('users/user_a', jwtA)).status, 403);
            // Disallowed fields denied
            assert.strictEqual((await restPatch('users/user_a?updateMask.fieldPaths=status', { status: { stringValue: 'admin' } }, jwtA)).status, 403);
            assert.strictEqual((await restPatch('users/user_a?updateMask.fieldPaths=tokenVersion', { tokenVersion: { integerValue: '99' } }, jwtA)).status, 403);
            assert.strictEqual((await restPatch('users/user_a?updateMask.fieldPaths=updatedAt', { updatedAt: { stringValue: '2026-01-01' } }, jwtA)).status, 403);
            // Non-https avatarUrl denied
            assert.strictEqual((await restPatch('users/user_a?updateMask.fieldPaths=avatarUrl', { avatarUrl: { stringValue: 'http://insecure.example/a.png' } }, jwtA)).status, 403);
        });

        await test('RULES-06: Legacy, nested, and /pythos/app/lanzar_id_accounts server-only paths are DENIED (read/write/delete)', async () => {
            const legacyAndNestedPaths = [
                'users/user_a/central_sessions/cs_a',
                'users/user_a/session_slots/slot_a',
                'users/user_a/founders/portal',
                'user_security/user_a',
                'security_logs/log_1',
                'mfa_factors/user_a',
                'phone_otps/otp_1',
                'admins/admin_1',
                'pythos/app/lanzar_id_accounts/acc_1'
            ];
            for (const p of legacyAndNestedPaths) {
                assert.strictEqual((await restGet(p, jwtA)).status, 403, `Expected 403 GET ${p}`);
                assert.strictEqual((await restPatch(p, { tampered: { booleanValue: true } }, jwtA)).status, 403, `Expected 403 PATCH ${p}`);
                assert.strictEqual((await restDelete(p, jwtA)).status, 403, `Expected 403 DELETE ${p}`);
            }
        });

        await test('RULES-07: Cross-tenant client access to /tenants/tenant_b/* is DENIED', async () => {
            const crossTenantPaths = [
                'tenants/tenant_b',
                'tenants/tenant_b/clients/c_b',
                'tenants/tenant_b/token_families/f_b',
                'tenants/tenant_b/admin_audit_logs/aud_b'
            ];
            for (const p of crossTenantPaths) {
                assert.strictEqual((await restGet(p, jwtA)).status, 403, `Expected 403 GET ${p}`);
                assert.strictEqual((await restPatch(p, { tampered: { booleanValue: true } }, jwtA)).status, 403, `Expected 403 PATCH ${p}`);
                assert.strictEqual((await restDelete(p, jwtA)).status, 403, `Expected 403 DELETE ${p}`);
            }
        });

        console.log('\n================================================================');
        console.log('FIRESTORE SECURITY RULES EMULATOR SUMMARY');
        console.log(`Total Executed: ${passed + failed}`);
        console.log(`Passed:         ${passed}`);
        console.log(`Failed:         ${failed}`);
        console.log(`Success Rate:   ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
        console.log('================================================================\n');

        await deleteApp(app);
    } finally {
        if (emulatorProc) emulatorProc.kill();
    }
    process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => {
    console.error('Fatal Firestore Rules Emulator error:', err);
    process.exit(1);
});
