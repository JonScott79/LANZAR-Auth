// test-revocation-consistency-emulator.cjs
// Live Cloud Firestore Emulator Suite for Independent Refresh-Token Revocation Dimension,
// Outbox/Reconciliation Verification against `tokensValidAfterTime`, and Async-Barrier Races.
// Note: External Firebase Auth calls use a deterministic in-process test double (not live Firebase Auth).

const assert = require('assert');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');
module.paths.push(path.join(__dirname, 'auth-backend', 'node_modules'));
const { initializeApp, deleteApp } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');

const EMULATOR_HOST = '127.0.0.1';
const EMULATOR_PORT = 8096;
const PROJECT_ID = 'demo-lanzar-id-revocation-test';
const EMULATOR_JAR = path.join(process.env.USERPROFILE || process.env.HOME || '', '.cache', 'firebase', 'emulators', 'cloud-firestore-emulator-v1.19.8.jar');

const { createApp } = require('./auth-backend/app');
const { createAuthMiddleware } = require('./auth-backend/middleware/authMiddleware');
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

async function withServer(app, fn) {
    const server = await new Promise((resolve) => {
        const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const { port } = server.address();
    try {
        return await fn(`http://127.0.0.1:${port}`);
    } finally {
        await new Promise((resolve) => server.close(resolve));
    }
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

        const app = initializeApp({ projectId: PROJECT_ID }, 'revocation-emulator-test');
        const db = getFirestore(app);
        await db.collection('admins').doc('uid_plat').set({ email: 'plat@lanzar.me', active: true, role: 'platform_admin' });
        const auditLogService = new AuditLogService(db);

        console.log('\n================================================================');
        console.log('LANZAR ID — Revocation Consistency Emulator Suite');
        console.log(`Project: ${PROJECT_ID} | Endpoint: ${EMULATOR_HOST}:${EMULATOR_PORT}`);
        console.log('================================================================\n');

        await test('EMU-REV-01: Revoke-all pending followed by activation preserves revocation requirement and completes', async () => {
            const uid = 'u_rev_act_1';
            await db.collection('users').doc(uid).set({ uid, status: 'suspended', desiredAuthVersion: 0, desiredAuthDisabled: true });
            let failRevoke = true;
            let revokeCount = 0;
            const authState = { disabled: true, tokensValidAfterTime: null };

            const authDouble = {
                getUser: async () => ({ uid, disabled: authState.disabled, tokensValidAfterTime: authState.tokensValidAfterTime }),
                updateUser: async (u, { disabled }) => { authState.disabled = disabled; },
                revokeRefreshTokens: async () => {
                    if (failRevoke) throw Object.assign(new Error('revoke_down'), { code: 'auth/unavailable' });
                    revokeCount++;
                    authState.tokensValidAfterTime = new Date(Date.now() + 1000).toISOString();
                },
                verifyIdToken: async () => ({ uid: 'uid_plat', email: 'plat@lanzar.me', session_id: 'sp' })
            };
            const sessionService = { checkSession: async () => ({ active: true }) };
            const authMiddleware = createAuthMiddleware({ db, authAdmin: authDouble, sessionService });
            const outboxSvc = new PlatformOutboxService(db, authDouble, { auditLogService, baseBackoffMs: 0 });
            const { app: expressApp } = createApp({ db, authAdmin: authDouble, services: { authMiddleware, sessionService, auditLogService, platformOutboxService: outboxSvc } });

            await withServer(expressApp, async (baseUrl) => {
                // 1. Revoke-all fails externally -> pending
                const revRes = await fetch(`${baseUrl}/api/admin/id/users/${uid}/sessions/revoke-all`, {
                    method: 'POST',
                    headers: { Authorization: 'Bearer tok', 'Idempotency-Key': 'idem-rev-act-revoke-001' }
                });
                assert.strictEqual(revRes.status, 503);
                const revBody = await revRes.json();

                // 2. Activation is accepted and completes (increments desiredAuthVersion only, NOT desiredRevocationVersion)
                const actRes = await fetch(`${baseUrl}/api/admin/id/users/${uid}/suspend`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok', 'Idempotency-Key': 'idem-rev-act-active-001' },
                    body: JSON.stringify({ status: 'active', reason: 'unlocked' })
                });
                assert.strictEqual(actRes.status, 200);
                assert.strictEqual(authState.disabled, false);

                // 3. Revoke-all outbox event is NOT superseded by activation -> executes and verifies!
                failRevoke = false;
                const retryRes = await outboxSvc.processEventById(revBody.outboxId, { nowMs: Date.now() + 5000 });
                assert.strictEqual(retryRes.status, 'COMPLETED');
                assert.strictEqual(revokeCount, 1);
                const uDoc = (await db.collection('users').doc(uid).get()).data();
                assert.strictEqual(uDoc.appliedRevocationVersion, uDoc.desiredRevocationVersion);
            });
        });

        await test('EMU-REV-02: Delayed revokeRefreshTokens (async barrier) followed by activation still completes and verifies', async () => {
            const uid = 'u_rev_delay';
            await db.collection('users').doc(uid).set({ uid, status: 'suspended', desiredAuthVersion: 0, desiredAuthDisabled: true });
            const authState = { disabled: true, tokensValidAfterTime: null };

            let releaseRevoke;
            let atRevokeBarrier;
            const barrierPromise = new Promise(r => { releaseRevoke = r; });
            const atBarrierPromise = new Promise(r => { atRevokeBarrier = r; });

            const authDouble = {
                getUser: async () => ({ uid, disabled: authState.disabled, tokensValidAfterTime: authState.tokensValidAfterTime }),
                updateUser: async (u, { disabled }) => { authState.disabled = disabled; },
                revokeRefreshTokens: async () => {
                    atRevokeBarrier();
                    await barrierPromise;
                    authState.tokensValidAfterTime = new Date(Date.now() + 1000).toISOString();
                },
                verifyIdToken: async () => ({ uid: 'uid_plat', email: 'plat@lanzar.me', session_id: 'sp' })
            };
            const sessionService = { checkSession: async () => ({ active: true }) };
            const authMiddleware = createAuthMiddleware({ db, authAdmin: authDouble, sessionService });
            const outboxSvc = new PlatformOutboxService(db, authDouble, { auditLogService, baseBackoffMs: 0 });
            const { app: expressApp } = createApp({ db, authAdmin: authDouble, services: { authMiddleware, sessionService, auditLogService, platformOutboxService: outboxSvc } });

            await withServer(expressApp, async (baseUrl) => {
                const revPromise = fetch(`${baseUrl}/api/admin/id/users/${uid}/sessions/revoke-all`, {
                    method: 'POST',
                    headers: { Authorization: 'Bearer tok', 'Idempotency-Key': 'idem-rev-delay-revoke-01' }
                });
                await atBarrierPromise;

                const actRes = await fetch(`${baseUrl}/api/admin/id/users/${uid}/suspend`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok', 'Idempotency-Key': 'idem-rev-delay-active-01' },
                    body: JSON.stringify({ status: 'active', reason: 'ok' })
                });
                assert.strictEqual(actRes.status, 200);
                assert.strictEqual(authState.disabled, false);

                releaseRevoke();
                const revRes = await revPromise;
                assert.strictEqual(revRes.status, 200);
                assert.ok(authState.tokensValidAfterTime);
            });
        });

        await test('EMU-REV-03: Failed revocation followed by worker restart converges via DesiredStateReconciler', async () => {
            const uid = 'u_rev_restart';
            const nowIso = new Date().toISOString();
            await db.collection('users').doc(uid).set({
                uid, status: 'active', desiredAuthVersion: 1, desiredAuthDisabled: false,
                desiredRevocationVersion: 1, desiredRevokedAt: nowIso, appliedRevocationVersion: 0
            });
            const authState = { disabled: false, tokensValidAfterTime: null };
            let outage = true;
            const authDouble = {
                getUser: async () => ({ uid, disabled: authState.disabled, tokensValidAfterTime: authState.tokensValidAfterTime }),
                revokeRefreshTokens: async () => {
                    if (outage) throw Object.assign(new Error('auth_down'), { code: 'auth/unavailable' });
                    authState.tokensValidAfterTime = new Date(Date.now() + 1000).toISOString();
                }
            };

            const r1 = new DesiredStateReconciler(db, authDouble, { workerId: 'rec_w1', auditLogService, baseBackoffMs: 0 });
            const res1 = await r1.reconcileUser(uid, { nowMs: 1000 });
            assert.strictEqual(res1.status, 'DRIFT_RETRYABLE');

            // Simulated worker restart with new worker instance after outage resolves
            outage = false;
            const r2 = new DesiredStateReconciler(db, authDouble, { workerId: 'rec_w2', auditLogService, baseBackoffMs: 0 });
            const res2 = await r2.reconcileUser(uid, { nowMs: 5000 });
            assert.strictEqual(res2.status, 'REPAIRED');
            assert.strictEqual(res2.revocationRepaired, true);
            assert.strictEqual((await db.collection('users').doc(uid).get()).data().appliedRevocationVersion, 1);
        });

        await test('EMU-REV-04: Repeated revocation reconciliation is idempotent with zero duplicate audits', async () => {
            const uid = 'u_rev_repeat';
            const authDouble = {
                getUser: async () => ({ uid, disabled: false, tokensValidAfterTime: new Date(Date.now() + 1000).toISOString() }),
                revokeRefreshTokens: async () => { throw new Error('Should not revoke again when already verified'); }
            };
            await db.collection('users').doc(uid).set({
                uid, status: 'active', desiredAuthVersion: 1, desiredAuthDisabled: false,
                desiredRevocationVersion: 1, desiredRevokedAt: new Date().toISOString(), appliedRevocationVersion: 1
            });

            const rec = new DesiredStateReconciler(db, authDouble, { auditLogService, reconcileIntervalMs: 1000 });
            const r1 = await rec.reconcileUser(uid, { nowMs: 1000 });
            const r2 = await rec.reconcileUser(uid, { nowMs: 5000 });
            assert.strictEqual(r1.status, 'CONVERGED');
            assert.strictEqual(r2.status, 'CONVERGED');
            const logs = (await auditLogService.listTenantAuditLogs('lanzar')).filter(l => l.clientId === uid);
            assert.strictEqual(logs.length, 0);
        });

        await test('EMU-REV-05 & 06: Two successive revoke-all operations & older revocation event superseded by newer revocation', async () => {
            const uid = 'u_rev_two';
            const t1 = new Date(Date.now() - 5000).toISOString();
            const t2 = new Date().toISOString();
            await db.collection('users').doc(uid).set({
                uid, desiredRevocationVersion: 2, desiredRevokedAt: t2, appliedRevocationVersion: 0
            });
            await db.collection('security_outbox').doc('outbox_rev_v1').set({
                outboxId: 'outbox_rev_v1', type: 'platform_admin_cross_service', operation: 'platform.user.sessions_revoke_all',
                targetUid: uid, actorUid: 'uid_plat', revocationVersion: 1, desiredRevokedAt: t1,
                status: 'PENDING_EXTERNAL_AUTH', payload: { revokeRefreshTokens: true }, progress: { revokeRefreshTokensDone: false },
                attempts: 0, fencingToken: 0, leaseOwner: null, leaseExpiresAt: 0, nextRetryAt: 0
            });
            await db.collection('security_outbox').doc('outbox_rev_v2').set({
                outboxId: 'outbox_rev_v2', type: 'platform_admin_cross_service', operation: 'platform.user.sessions_revoke_all',
                targetUid: uid, actorUid: 'uid_plat', revocationVersion: 2, desiredRevokedAt: t2,
                status: 'PENDING_EXTERNAL_AUTH', payload: { revokeRefreshTokens: true }, progress: { revokeRefreshTokensDone: false },
                attempts: 0, fencingToken: 0, leaseOwner: null, leaseExpiresAt: 0, nextRetryAt: 0
            });

            let revokeCalls = 0;
            const authDouble = {
                getUser: async () => ({ uid, disabled: false, tokensValidAfterTime: new Date(Date.now() + 1000).toISOString() }),
                revokeRefreshTokens: async () => { revokeCalls++; }
            };
            const worker = new PlatformOutboxService(db, authDouble, { auditLogService });

            // Older v1 processed after v2 was accepted -> SUPERSEDED without calling revokeRefreshTokens
            const res1 = await worker.processEventById('outbox_rev_v1');
            assert.strictEqual(res1.status, 'SUPERSEDED');
            assert.strictEqual(revokeCalls, 0);

            // Newer v2 completes and advances appliedRevocationVersion to 2
            const res2 = await worker.processEventById('outbox_rev_v2');
            assert.strictEqual(res2.status, 'COMPLETED');
            assert.strictEqual(revokeCalls, 1);
            assert.strictEqual((await db.collection('users').doc(uid).get()).data().appliedRevocationVersion, 2);
        });

        await test('EMU-REV-07: Concurrent account-state and revocation reconciliation serialize safely', async () => {
            const uid = 'u_rev_conc_rec';
            const authState = { disabled: false, tokensValidAfterTime: null };
            await db.collection('users').doc(uid).set({
                uid, desiredAuthVersion: 1, desiredAuthDisabled: true,
                desiredRevocationVersion: 1, desiredRevokedAt: new Date().toISOString(), appliedRevocationVersion: 0
            });
            const authDouble = {
                getUser: async () => ({ uid, disabled: authState.disabled, tokensValidAfterTime: authState.tokensValidAfterTime }),
                updateUser: async (u, { disabled }) => { authState.disabled = disabled; },
                revokeRefreshTokens: async () => { authState.tokensValidAfterTime = new Date(Date.now() + 1000).toISOString(); }
            };

            const w1 = new DesiredStateReconciler(db, authDouble, { workerId: 'cw1', auditLogService });
            const w2 = new DesiredStateReconciler(db, authDouble, { workerId: 'cw2', auditLogService });
            const [res1, res2] = await Promise.all([
                w1.reconcileUser(uid, { nowMs: 1000 }),
                w2.reconcileUser(uid, { nowMs: 1000 })
            ]);
            assert.deepStrictEqual([res1.status, res2.status].sort(), ['REPAIRED', 'SKIPPED']);
            assert.strictEqual(authState.disabled, true);
            assert.strictEqual((await db.collection('users').doc(uid).get()).data().appliedRevocationVersion, 1);
        });

        await test('EMU-REV-08, 09 & 10: Outage, stale tokensValidAfterTime, and verification failure after revoke RPC do not mark complete', async () => {
            const uid = 'u_rev_verify_fail';
            const desiredIso = new Date(Date.now() + 60000).toISOString();
            await db.collection('users').doc(uid).set({
                uid, desiredAuthVersion: 1, desiredAuthDisabled: false,
                desiredRevocationVersion: 1, desiredRevokedAt: desiredIso, appliedRevocationVersion: 0
            });

            // Stale tokensValidAfterTime (older than desiredRevokedAt) even after revokeRefreshTokens RPC succeeds!
            let allowFreshAfterRpc = false;
            let returnFreshTimestamp = false;
            const authDouble = {
                getUser: async () => ({
                    uid,
                    disabled: false,
                    tokensValidAfterTime: returnFreshTimestamp
                        ? new Date(Date.parse(desiredIso) + 2000).toISOString()
                        : new Date(Date.parse(desiredIso) - 10000).toISOString()
                }),
                revokeRefreshTokens: async () => {
                    if (allowFreshAfterRpc) returnFreshTimestamp = true;
                }
            };

            const reconciler = new DesiredStateReconciler(db, authDouble, { auditLogService, maxAttempts: 3, baseBackoffMs: 0 });
            const failRes = await reconciler.reconcileUser(uid, { nowMs: 1000 });
            assert.strictEqual(failRes.status, 'DRIFT_RETRYABLE');
            assert.strictEqual(failRes.errorCode, 'auth/revocation-not-verified');
            // appliedRevocationVersion MUST remain 0!
            assert.strictEqual((await db.collection('users').doc(uid).get()).data().appliedRevocationVersion, 0);

            // Once Firebase Auth returns fresh tokensValidAfterTime after revoke RPC, reconciliation verifies and completes
            allowFreshAfterRpc = true;
            const okRes = await reconciler.reconcileUser(uid, { nowMs: 5000 });
            assert.strictEqual(okRes.status, 'REPAIRED');
            assert.strictEqual((await db.collection('users').doc(uid).get()).data().appliedRevocationVersion, 1);
        });

        console.log('\n================================================================');
        console.log('REVOCATION CONSISTENCY EMULATOR SUMMARY');
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
    console.error('Fatal Revocation Consistency Emulator error:', err);
    process.exit(1);
});
