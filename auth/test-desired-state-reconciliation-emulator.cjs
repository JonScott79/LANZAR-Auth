// test-desired-state-reconciliation-emulator.cjs
// Live Cloud Firestore Emulator Suite for Strict Freshness Invariant,
// Async-Barrier External Side-Effect Races (Race A & Race B), and
// Durable Desired-State Reconciliation against a Deterministic Firebase Auth Double.

const assert = require('assert');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');
module.paths.push(path.join(__dirname, 'auth-backend', 'node_modules'));
const { initializeApp, deleteApp } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');

const EMULATOR_HOST = '127.0.0.1';
const EMULATOR_PORT = 8095;
const PROJECT_ID = 'demo-lanzar-id-reconcile-test';
const EMULATOR_JAR = path.join(process.env.USERPROFILE || process.env.HOME || '', '.cache', 'firebase', 'emulators', 'cloud-firestore-emulator-v1.19.8.jar');

const { AuditLogService } = require('./auth-backend/services/auditLogService');
const { PlatformOutboxService } = require('./auth-backend/services/platformOutboxService');
const { DesiredStateReconciler } = require('./auth-backend/services/desiredStateReconciler');

function waitForPort(host, port, timeoutMs = 25000) {
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
        '--port', String(EMULATOR_PORT)
    ], { stdio: 'ignore' });
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

        const app = initializeApp({ projectId: PROJECT_ID }, 'reconcile-emulator-test');
        const db = getFirestore(app);
        const auditLogService = new AuditLogService(db);

        console.log('\n================================================================');
        console.log('LANZAR ID — Desired-State Reconciliation Emulator Suite');
        console.log(`Project: ${PROJECT_ID} | Endpoint: ${EMULATOR_HOST}:${EMULATOR_PORT}`);
        console.log('================================================================\n');

        await test('EMU-REC-01 (Race A): Delayed v4 suspension RPC completes AFTER v5 activation COMPLETED -> reconciler detects & repairs drift', async () => {
            const uid = 'u_race_a';
            const authState = { disabled: false };
            await db.collection('users').doc(uid).set({
                uid, status: 'suspended', desiredAuthVersion: 4, desiredAuthDisabled: true
            });
            await db.collection('security_outbox').doc('outbox_ra_v4').set({
                outboxId: 'outbox_ra_v4',
                type: 'platform_admin_cross_service',
                operation: 'platform.user.status_update',
                targetUid: uid,
                actorUid: 'uid_plat',
                operationVersion: 4,
                status: 'PENDING_EXTERNAL_AUTH',
                payload: { disabled: true, status: 'suspended', revokeRefreshTokens: false },
                progress: { updateUserDone: false, revokeRefreshTokensDone: true },
                attempts: 0, fencingToken: 0, leaseOwner: null, leaseExpiresAt: 0, nextRetryAt: 0
            });

            // Async barrier inside authAdmin.updateUser for Worker A's v4 call
            let releaseWorkerA;
            let workerAAtBarrier;
            const barrierPromise = new Promise(r => { releaseWorkerA = r; });
            const atBarrierPromise = new Promise(r => { workerAAtBarrier = r; });

            const authDouble = {
                getUser: async () => ({ uid, disabled: authState.disabled }),
                updateUser: async (u, { disabled }) => {
                    if (disabled === true) {
                        workerAAtBarrier();
                        await barrierPromise;
                    }
                    authState.disabled = disabled;
                },
                revokeRefreshTokens: async () => ({})
            };

            const workerA = new PlatformOutboxService(db, authDouble, { workerId: 'workerA', auditLogService });
            const workerB = new PlatformOutboxService(db, authDouble, { workerId: 'workerB', auditLogService });
            const reconciler = new DesiredStateReconciler(db, authDouble, { auditLogService, reconcileIntervalMs: 1000 });

            // 1. Worker A passes _assertLeaseAndFreshness for v4 and enters authAdmin.updateUser barrier
            const workerAPromise = workerA.processEventById('outbox_ra_v4', { nowMs: 1000 });
            await atBarrierPromise;

            // 2. Admin accepts activation v5 & Worker B completes v5 (disabled=false, COMPLETED)
            await db.collection('users').doc(uid).update({ status: 'active', desiredAuthVersion: 5, desiredAuthDisabled: false });
            await db.collection('security_outbox').doc('outbox_ra_v5').set({
                outboxId: 'outbox_ra_v5',
                type: 'platform_admin_cross_service',
                operation: 'platform.user.status_update',
                targetUid: uid,
                actorUid: 'uid_plat',
                operationVersion: 5,
                status: 'PENDING_EXTERNAL_AUTH',
                payload: { disabled: false, status: 'active', revokeRefreshTokens: false },
                progress: { updateUserDone: false, revokeRefreshTokensDone: true },
                attempts: 0, fencingToken: 0, leaseOwner: null, leaseExpiresAt: 0, nextRetryAt: 0
            });
            const resB = await workerB.processEventById('outbox_ra_v5', { nowMs: 1100 });
            assert.strictEqual(resB.status, 'COMPLETED');
            assert.strictEqual(authState.disabled, false);

            // 3. Worker A's delayed suspension RPC finishes late -> Firebase Auth transiently corrupted to disabled=true!
            releaseWorkerA();
            const resA = await workerAPromise;
            assert.strictEqual(resA.status, 'SUPERSEDED');
            assert.strictEqual(authState.disabled, true); // Drift present while v5 is COMPLETED!

            // 4. Desired-State Reconciler detects drift and repairs Firebase Auth back to disabled=false
            const recRes = await reconciler.reconcileUser(uid, { nowMs: 2000, ignoreSchedule: true });
            assert.strictEqual(recRes.status, 'REPAIRED');
            assert.strictEqual(recRes.driftDetected, true);
            assert.strictEqual(authState.disabled, false);

            const logs = await auditLogService.listTenantAuditLogs('lanzar');
            assert.ok(logs.some(l => l.operation === 'platform.reconciliation.drift_repaired' && l.clientId === uid));
        });

        await test('EMU-REC-02 (Race B): Worker A loses lease mid-RPC, Worker B takes over, Worker A completes late -> converges to latest desired version', async () => {
            const uid = 'u_race_b';
            const authState = { disabled: false };
            await db.collection('users').doc(uid).set({
                uid, status: 'suspended', desiredAuthVersion: 1, desiredAuthDisabled: true
            });
            await db.collection('security_outbox').doc('outbox_rb_1').set({
                outboxId: 'outbox_rb_1',
                type: 'platform_admin_cross_service',
                operation: 'platform.user.status_update',
                targetUid: uid,
                actorUid: 'uid_plat',
                operationVersion: 1,
                status: 'PENDING_EXTERNAL_AUTH',
                payload: { disabled: true, status: 'suspended', revokeRefreshTokens: false },
                progress: { updateUserDone: false, revokeRefreshTokensDone: true },
                attempts: 0, fencingToken: 0, leaseOwner: null, leaseExpiresAt: 0, nextRetryAt: 0
            });

            let releaseWorkerA;
            let workerAAtBarrier;
            const barrierPromise = new Promise(r => { releaseWorkerA = r; });
            const atBarrierPromise = new Promise(r => { workerAAtBarrier = r; });
            let firstCall = true;

            const authDouble = {
                getUser: async () => ({ uid, disabled: authState.disabled }),
                updateUser: async (u, { disabled }) => {
                    if (firstCall) {
                        firstCall = false;
                        workerAAtBarrier();
                        await barrierPromise;
                    }
                    authState.disabled = disabled;
                },
                revokeRefreshTokens: async () => ({})
            };

            const workerA = new PlatformOutboxService(db, authDouble, { workerId: 'wA', leaseDurationMs: 1000, auditLogService });
            const workerB = new PlatformOutboxService(db, authDouble, { workerId: 'wB', leaseDurationMs: 1000, auditLogService });
            const reconciler = new DesiredStateReconciler(db, authDouble, { auditLogService });

            const pA = workerA.processEventById('outbox_rb_1', { nowMs: 1000 });
            await atBarrierPromise;

            // Lease expires at 2000; Worker B takes over at 3000 and completes v1
            const resB = await workerB.processEventById('outbox_rb_1', { nowMs: 3000 });
            assert.strictEqual(resB.status, 'COMPLETED');

            // Meanwhile admin activates v2 (disabled=false) and completes it
            await db.collection('users').doc(uid).update({ status: 'active', desiredAuthVersion: 2, desiredAuthDisabled: false });
            authState.disabled = false;

            // Stale Worker A finishes late (setting disabled=true), but is FENCED in Firestore
            releaseWorkerA();
            const resA = await pA;
            assert.strictEqual(resA.status, 'FENCED');
            assert.strictEqual(authState.disabled, true);

            // Reconciler repairs Firebase Auth to latest desired version v2 (disabled=false)
            const recRes = await reconciler.reconcileUser(uid, { nowMs: 4000, ignoreSchedule: true });
            assert.strictEqual(recRes.status, 'REPAIRED');
            assert.strictEqual(authState.disabled, false);
        });

        await test('EMU-REC-03: Strict freshness invariant fails closed on missing desiredAuthVersion and version mismatch', async () => {
            await db.collection('users').doc('u_missing_ver').set({ uid: 'u_missing_ver', status: 'active' });
            await db.collection('security_outbox').doc('outbox_missing_ver').set({
                outboxId: 'outbox_missing_ver',
                type: 'platform_admin_cross_service',
                operation: 'platform.user.sessions_revoke_all',
                targetUid: 'u_missing_ver',
                actorUid: 'uid_plat',
                revocationVersion: 1,
                status: 'PENDING_EXTERNAL_AUTH',
                payload: { revokeRefreshTokens: true },
                attempts: 0, fencingToken: 0, leaseOwner: null, leaseExpiresAt: 0, nextRetryAt: 0
            });

            await db.collection('users').doc('u_lower_ver').set({ uid: 'u_lower_ver', status: 'active', desiredAuthVersion: 2, desiredAuthDisabled: false, desiredRevocationVersion: 2 });
            await db.collection('security_outbox').doc('outbox_lower_ver').set({
                outboxId: 'outbox_lower_ver',
                type: 'platform_admin_cross_service',
                operation: 'platform.user.sessions_revoke_all',
                targetUid: 'u_lower_ver',
                actorUid: 'uid_plat',
                revocationVersion: 5,
                status: 'PENDING_EXTERNAL_AUTH',
                payload: { revokeRefreshTokens: true },
                attempts: 0, fencingToken: 0, leaseOwner: null, leaseExpiresAt: 0, nextRetryAt: 0
            });

            let authCalled = false;
            const authDouble = { revokeRefreshTokens: async () => { authCalled = true; } };
            const worker = new PlatformOutboxService(db, authDouble, { auditLogService });

            const r1 = await worker.processEventById('outbox_missing_ver');
            assert.strictEqual(r1.status, 'DEAD_LETTER');
            assert.strictEqual(r1.reason, 'MISSING_DESIRED_VERSION');

            const r2 = await worker.processEventById('outbox_lower_ver');
            assert.strictEqual(r2.status, 'DEAD_LETTER');
            assert.strictEqual(r2.reason, 'VERSION_MISMATCH');
            assert.strictEqual(authCalled, false);
        });

        await test('EMU-REC-04: Repeated reconciliation is idempotent with zero duplicate drift audits, and concurrent workers serialize safely', async () => {
            const uid = 'u_rec_idem';
            const authState = { disabled: false };
            let updateCalls = 0;
            await db.collection('users').doc(uid).set({
                uid, status: 'suspended', desiredAuthVersion: 1, desiredAuthDisabled: true
            });

            const authDouble = {
                getUser: async () => ({ uid, disabled: authState.disabled }),
                updateUser: async (u, { disabled }) => { updateCalls++; authState.disabled = disabled; },
                revokeRefreshTokens: async () => ({})
            };

            const r1 = new DesiredStateReconciler(db, authDouble, { workerId: 'rec_1', auditLogService, reconcileIntervalMs: 1000 });
            const r2 = new DesiredStateReconciler(db, authDouble, { workerId: 'rec_2', auditLogService, reconcileIntervalMs: 1000 });

            // Concurrent workers -> only 1 claims lease and repairs drift
            const [res1, res2] = await Promise.all([
                r1.reconcileUser(uid, { nowMs: 1000 }),
                r2.reconcileUser(uid, { nowMs: 1000 })
            ]);
            const statuses = [res1.status, res2.status].sort();
            assert.deepStrictEqual(statuses, ['REPAIRED', 'SKIPPED']);
            assert.strictEqual(updateCalls, 1);
            assert.strictEqual(authState.disabled, true);

            // Repeated reconciliation when already converged -> CONVERGED without calling updateUser or writing drift audit
            const res3 = await r1.reconcileUser(uid, { nowMs: 5000 });
            assert.strictEqual(res3.status, 'CONVERGED');
            assert.strictEqual(res3.driftDetected, false);
            assert.strictEqual(updateCalls, 1);

            const logs = (await auditLogService.listTenantAuditLogs('lanzar')).filter(l => l.clientId === uid && l.operation === 'platform.reconciliation.drift_repaired');
            assert.strictEqual(logs.length, 1);
        });

        await test('EMU-REC-05: Reconciliation outage, retry exhaustion -> DEAD_LETTER, and audited operator redrive recovery', async () => {
            const uid = 'u_rec_outage';
            const authState = { disabled: false };
            let authOutage = true;
            await db.collection('users').doc(uid).set({
                uid, status: 'suspended', desiredAuthVersion: 1, desiredAuthDisabled: true
            });

            const authDouble = {
                getUser: async () => {
                    if (authOutage) throw Object.assign(new Error('auth_down'), { code: 'auth/unavailable' });
                    return { uid, disabled: authState.disabled };
                },
                updateUser: async (u, { disabled }) => { authState.disabled = disabled; },
                revokeRefreshTokens: async () => ({})
            };

            const reconciler = new DesiredStateReconciler(db, authDouble, {
                auditLogService, maxAttempts: 2, baseBackoffMs: 0, reconcileIntervalMs: 1000
            });

            const attempt1 = await reconciler.reconcileUser(uid, { nowMs: 1000 });
            assert.strictEqual(attempt1.status, 'DRIFT_RETRYABLE');
            const attempt2 = await reconciler.reconcileUser(uid, { nowMs: 2000 });
            assert.strictEqual(attempt2.status, 'DEAD_LETTER');

            // Automatic sweep skips DEAD_LETTER
            const skipped = await reconciler.reconcileUser(uid, { nowMs: 99999 });
            assert.strictEqual(skipped.status, 'SKIPPED');
            assert.strictEqual(skipped.reason, 'DEAD_LETTER');

            // Operator redrives after Firebase Auth recovers
            authOutage = false;
            const redriveRes = await reconciler.redriveUser({ uid, actorUid: 'uid_plat', correlationId: 'corr_rec_redrive' });
            assert.strictEqual(redriveRes.redriven, true);
            assert.strictEqual(redriveRes.reconcileResult.status, 'REPAIRED');
            assert.strictEqual(authState.disabled, true);

            const logs = await auditLogService.listTenantAuditLogs('lanzar');
            assert.ok(logs.some(l => l.operation === 'platform.reconciliation.dead_lettered' && l.clientId === uid));
            assert.ok(logs.some(l => l.operation === 'platform.reconciliation.redrive' && l.clientId === uid && l.correlationId === 'corr_rec_redrive'));
        });

        console.log('\n================================================================');
        console.log('DESIRED-STATE RECONCILIATION EMULATOR SUMMARY');
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
    console.error('Fatal Desired-State Reconciliation Emulator error:', err);
    process.exit(1);
});
