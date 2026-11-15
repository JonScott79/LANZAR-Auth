// test-milestone-1-5-emulator.cjs
// Milestone 1.5 Live Cloud Firestore Emulator Verification Suite

const assert = require('assert');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');
module.paths.push(path.join(__dirname, 'auth-backend', 'node_modules'));
const { initializeApp, deleteApp } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const { ClientRegistryService } = require('./auth-backend/services/clientRegistryService');
const { AuditLogService } = require('./auth-backend/services/auditLogService');
const { FirestoreAuthorizationCodeStore, generateRefreshToken, hashAuthorizationCode } = require('./auth-backend/store');

const EMULATOR_HOST = '127.0.0.1';
const EMULATOR_PORT = 8092;
const PROJECT_ID = 'demo-lanzar-id-m1-5-test';
const EMULATOR_JAR = path.join(process.env.USERPROFILE || process.env.HOME || '', '.cache', 'firebase', 'emulators', 'cloud-firestore-emulator-v1.19.8.jar');

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
    const child = spawn('java', ['-jar', EMULATOR_JAR, '--host', EMULATOR_HOST, '--port', String(EMULATOR_PORT)], { stdio: ['ignore', 'pipe', 'pipe'] });
    await waitForPort(EMULATOR_HOST, EMULATOR_PORT, 25000);
    return child;
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

        const app = initializeApp({ projectId: PROJECT_ID }, 'm1-5-emulator-test');
        const db = getFirestore(app);
        const registry = new ClientRegistryService(db);
        const auditService = new AuditLogService(db);
        const codeStore = new FirestoreAuthorizationCodeStore(db);

        console.log('\n================================================================');
        console.log('LANZAR ID — Milestone 1.5 Live Cloud Firestore Emulator Suite');
        console.log(`Project: ${PROJECT_ID} | Endpoint: ${EMULATOR_HOST}:${EMULATOR_PORT}`);
        console.log('================================================================\n');

        await test('EMU-M1.5-01: Client lifecycle disableClient/enableClient updates dual collections in live Firestore', async () => {
            await registry.registerClient({
                tenantId: 'tenant_alpha',
                clientId: 'emu_life',
                name: 'Emu Lifecycle',
                redirectUris: ['https://alpha.example.com/cb'],
                compatibilityMode: 'oidc'
            });
            const disabled = await registry.disableClient({ tenantId: 'tenant_alpha', clientId: 'emu_life', reason: 'policy_hold' });
            assert.strictEqual(disabled.enabled, false);
            assert.strictEqual(disabled.status, 'suspended');

            const idxSnap = await db.collection('clients_index').doc('emu_life').get();
            assert.strictEqual(idxSnap.data().enabled, false);
            assert.strictEqual(idxSnap.data().status, 'suspended');

            const enabled = await registry.enableClient({ tenantId: 'tenant_alpha', clientId: 'emu_life' });
            assert.strictEqual(enabled.enabled, true);
            assert.strictEqual(enabled.status, 'active');
        });

        await test('EMU-M1.5-02: AuditLogService persists immutable redacted audit logs in live Firestore', async () => {
            const rec = await auditService.recordAdminEvent({
                actorUid: 'adm_alpha',
                actorTenantId: 'tenant_alpha',
                actorRole: 'tenant_admin',
                targetTenantId: 'tenant_alpha',
                clientId: 'emu_life',
                operation: 'client.disable',
                outcome: 'success',
                metadata: { clientSecret: 'should_not_leak', reason: 'policy_hold' }
            });
            assert.ok(rec.auditId);
            const logs = await auditService.listTenantAuditLogs('tenant_alpha');
            assert.strictEqual(logs.length, 1);
            assert.strictEqual(logs[0].metadata.clientSecret, '[REDACTED]');
            assert.strictEqual(logs[0].immutable, true);
        });

        await test('EMU-M1.5-03: authorizeRefreshGrant rejects cross-tenant family/session access in live Firestore', async () => {
            const famId = 'fam_emu_m15_1';
            const sessId = 'sess_emu_m15_1';
            const rt = generateRefreshToken(famId, 1);
            const futureIso = new Date(Date.now() + 600000).toISOString();

            await db.collection('users').doc('u_emu').collection('sessions').doc(sessId).create({
                sessionId: sessId, familyId: famId, uid: 'u_emu', tenantId: 'tenant_alpha', clientId: 'emu_life',
                ceremonyId: 'cer_1', status: 'active', revoked: false, expiresAt: futureIso
            });
            await db.collection('tenants').doc('tenant_alpha').collection('token_families').doc(famId).create({
                familyId: famId, sessionId: sessId, uid: 'u_emu', tenantId: 'tenant_alpha', clientId: 'emu_life',
                ceremonyId: 'cer_1', status: 'active', currentActiveTokenHash: hashAuthorizationCode(rt),
                sequenceNumber: 1, rotatedTokenHashes: [], expiresAt: futureIso
            });

            const cross = await codeStore.authorizeRefreshGrant({
                tenantId: 'tenant_beta',
                familyId: famId,
                uid: 'u_emu',
                sessionId: sessId,
                refreshToken: rt,
                clientId: 'emu_life'
            });
            assert.strictEqual(cross.allowed, false);
        });

        console.log('\n================================================================');
        console.log('MILESTONE 1.5 EMULATOR VERIFICATION SUMMARY');
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
    console.error('Fatal Milestone 1.5 emulator error:', err);
    process.exit(1);
});
