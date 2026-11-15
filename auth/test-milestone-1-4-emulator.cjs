// test-milestone-1-4-emulator.cjs
// Milestone 1.4 Live Cloud Firestore Emulator Verification Suite

const assert = require('assert');
const crypto = require('crypto');
const path = require('path');
const { spawn } = require('child_process');
module.paths.push(path.join(__dirname, 'auth-backend', 'node_modules'));
const { initializeApp } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const { ClientRegistryService } = require('./auth-backend/services/clientRegistryService');

const EMULATOR_HOST = '127.0.0.1';
const EMULATOR_PORT = 8091;
const PROJECT_ID = 'demo-lanzar-id-m1-4-test';

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
    console.log('LANZAR ID — Milestone 1.4 Live Cloud Firestore Emulator Suite');
    console.log(`Project: ${PROJECT_ID} | Endpoint: ${EMULATOR_HOST}:${EMULATOR_PORT}`);
    console.log('================================================================\n');

    await startEmulator();
    const app = initializeApp({ projectId: PROJECT_ID });
    const db = getFirestore(app);

    try {
        await test('EMU-M1.4-01: registerClient() persists dual-collection records and blocks cross-tenant duplicate clientId in live Firestore', async () => {
            const registry = new ClientRegistryService(db);
            const created = await registry.registerClient({
                tenantId: 'tenant_alpha',
                clientId: 'alpha_oidc',
                name: 'Alpha OIDC App',
                redirectUris: ['https://alpha.example.com/callback'],
                compatibilityMode: 'oidc',
                tokenEndpointAuthMethod: 'client_secret_post',
                clientSecret: 'alpha_secret_1234567890'
            });
            assert.strictEqual(created.clientId, 'alpha_oidc');

            const indexSnap = await db.collection('clients_index').doc('alpha_oidc').get();
            const tenantSnap = await db.collection('tenants').doc('tenant_alpha').collection('clients').doc('alpha_oidc').get();
            assert.strictEqual(indexSnap.exists, true);
            assert.strictEqual(tenantSnap.exists, true);
            assert.strictEqual(indexSnap.data().tenantId, 'tenant_alpha');

            await assert.rejects(
                () => registry.registerClient({
                    tenantId: 'tenant_beta',
                    clientId: 'alpha_oidc',
                    name: 'Hijack',
                    redirectUris: ['https://beta.example.com/cb']
                }),
                /CLIENT_ALREADY_EXISTS/
            );
        });

        await test('EMU-M1.4-02: seedApprovedInternalClients() seeds strictly portal, tickets, threadline, ai in live Firestore', async () => {
            const registry = new ClientRegistryService(db);
            const res = await registry.seedApprovedInternalClients({ tenantId: 'lanzar' });
            assert.deepStrictEqual(res.seeded.sort(), ['ai', 'portal', 'threadline', 'tickets']);

            const threadline = await registry.resolveClient('threadline');
            assert.strictEqual(threadline.compatibilityMode, 'dual');
            assert.strictEqual(await registry.resolveClient('pythos'), null);
            assert.strictEqual(await registry.resolveClient('mothership'), null);
        });

        await test('EMU-M1.4-03: updateClient() enforces tenant ownership and exact redirect URI updates in live Firestore', async () => {
            const registry = new ClientRegistryService(db);
            await assert.rejects(
                () => registry.updateClient({ tenantId: 'tenant_beta', clientId: 'alpha_oidc', patch: { enabled: false } }),
                /TENANT_OWNERSHIP_MISMATCH/
            );

            const updated = await registry.updateClient({
                tenantId: 'tenant_alpha',
                clientId: 'alpha_oidc',
                patch: { redirectUris: ['https://alpha.example.com/v2/cb'], enabled: false }
            });
            assert.deepStrictEqual(updated.redirectUris, ['https://alpha.example.com/v2/cb']);
            assert.strictEqual(updated.enabled, false);
        });
    } finally {
        await stopEmulator();
    }

    console.log('\n================================================================');
    console.log('MILESTONE 1.4 EMULATOR VERIFICATION SUMMARY');
    console.log(`Total Executed: ${passed + failed}`);
    console.log(`Passed:         ${passed}`);
    console.log(`Failed:         ${failed}`);
    console.log(`Success Rate:   ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
    console.log('================================================================\n');

    if (failed > 0) process.exit(1);
}

main().catch(async err => {
    console.error('Fatal M1.4 emulator error:', err);
    await stopEmulator();
    process.exit(1);
});
