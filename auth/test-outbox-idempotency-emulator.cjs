// test-outbox-idempotency-emulator.cjs
// Live Cloud Firestore Emulator Suite for Platform Outbox, Leases/Fencing,
// Bounded Retries, Dead-Lettering, Audited Redrive, Partial Auth Recovery, and Durable Idempotency.

const assert = require('assert');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');
module.paths.push(path.join(__dirname, 'auth-backend', 'node_modules'));
const { initializeApp, deleteApp } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');

const EMULATOR_HOST = '127.0.0.1';
const EMULATOR_PORT = 8094;
const PROJECT_ID = 'demo-lanzar-id-outbox-test';
const EMULATOR_JAR = path.join(process.env.USERPROFILE || process.env.HOME || '', '.cache', 'firebase', 'emulators', 'cloud-firestore-emulator-v1.19.8.jar');

const { createApp } = require('./auth-backend/app');
const { createAuthMiddleware } = require('./auth-backend/middleware/authMiddleware');
const { AuditLogService } = require('./auth-backend/services/auditLogService');
const { FounderService } = require('./auth-backend/founderService');
const { PlatformOutboxService } = require('./auth-backend/services/platformOutboxService');

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

        const app = initializeApp({ projectId: PROJECT_ID }, 'outbox-emulator-test');
        const db = getFirestore(app);

        await db.collection('admins').doc('uid_plat').set({ email: 'plat@lanzar.me', active: true, role: 'platform_admin' });

        console.log('\n================================================================');
        console.log('LANZAR ID — Outbox & Idempotency Live Firestore Emulator Suite');
        console.log(`Project: ${PROJECT_ID} | Endpoint: ${EMULATOR_HOST}:${EMULATOR_PORT}`);
        console.log('================================================================\n');

        await test('EMU-OI-01: Founder grant and founder revoke audit-failure rollbacks in live Firestore transactions', async () => {
            await db.collection('users').doc('u_f1').set({ uid: 'u_f1', email: 'f1@lanzar.me', status: 'active', derivedBadges: [] });
            const authAdmin = { verifyIdToken: async () => ({ uid: 'uid_plat', email: 'plat@lanzar.me', session_id: 'sp' }) };
            const sessionService = { checkSession: async () => ({ active: true }) };
            const authMiddleware = createAuthMiddleware({ db, authAdmin, sessionService });
            const auditLogService = new AuditLogService(db);
            const founderService = new FounderService(db);
            const { app: expressApp } = createApp({ db, authAdmin, services: { authMiddleware, sessionService, auditLogService, founderService } });

            await withServer(expressApp, async (baseUrl) => {
                // Grant succeeds
                assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/users/u_f1/founders`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok' },
                    body: JSON.stringify({ programId: 'portal_founder', grantReason: 'Founding member' })
                })).status, 200);
                assert.deepStrictEqual((await db.collection('users').doc('u_f1').get()).data().derivedBadges, ['portal_founder']);

                // Simulate audit failure on revoke -> must roll back founder active=true and derivedBadges
                const origWrite = auditLogService.writeInTransaction.bind(auditLogService);
                auditLogService.writeInTransaction = () => { throw new Error('EMU_AUDIT_FAIL_REVOKE'); };
                const revFail = await fetch(`${baseUrl}/api/admin/id/users/u_f1/founders/portal_founder`, {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok' },
                    body: JSON.stringify({ revocationReason: 'Audit fail test' })
                });
                assert.strictEqual(revFail.status, 503);
                assert.strictEqual((await db.collection('users').doc('u_f1').collection('founders').doc('portal_founder').get()).data().active, true);
                assert.deepStrictEqual((await db.collection('users').doc('u_f1').get()).data().derivedBadges, ['portal_founder']);
                auditLogService.writeInTransaction = origWrite;
            });
        });

        await test('EMU-OI-02: Mandatory Idempotency-Key validation, same-key replay, payload conflict (409), and concurrent duplicates', async () => {
            await db.collection('users').doc('u_idem').set({ uid: 'u_idem', email: 'idem@lanzar.me', status: 'active', tokenVersion: 1 });
            await db.collection('users').doc('u_idem').collection('sessions').doc('s1').set({ sessionId: 's1', revoked: false });
            await db.collection('users').doc('u_idem').collection('sessions').doc('s2').set({ sessionId: 's2', revoked: true });

            let revokeAuthCalls = 0;
            const authAdmin = {
                updateUser: async () => ({}),
                revokeRefreshTokens: async () => { revokeAuthCalls++; },
                verifyIdToken: async () => ({ uid: 'uid_plat', email: 'plat@lanzar.me', session_id: 'sp' })
            };
            const sessionService = { checkSession: async () => ({ active: true }) };
            const authMiddleware = createAuthMiddleware({ db, authAdmin, sessionService });
            const auditLogService = new AuditLogService(db);
            const { app: expressApp } = createApp({ db, authAdmin, services: { authMiddleware, sessionService, auditLogService } });

            await withServer(expressApp, async (baseUrl) => {
                // Missing or invalid (<16 chars) Idempotency-Key -> 400
                assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/users/u_idem/sessions/revoke-all`, {
                    method: 'POST', headers: { Authorization: 'Bearer tok' }
                })).status, 400);
                assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/users/u_idem/sessions/revoke-all`, {
                    method: 'POST', headers: { Authorization: 'Bearer tok', 'Idempotency-Key': 'too_short_15ch!' }
                })).status, 400);

                // Concurrent duplicate HTTP requests with identical Idempotency-Key
                const [r1, r2, r3] = await Promise.all([1, 2, 3].map(() =>
                    fetch(`${baseUrl}/api/admin/id/users/u_idem/sessions/revoke-all`, {
                        method: 'POST',
                        headers: { Authorization: 'Bearer tok', 'Idempotency-Key': 'idem-emu-concurrent-001' }
                    })
                ));
                const statuses = [r1.status, r2.status, r3.status];
                const bodies = await Promise.all([r1.json(), r2.json(), r3.json()]);
                assert.ok(statuses.every((s, idx) => s === 200 || (s === 503 && bodies[idx].externalAuthStatus === 'pending' && bodies[idx].idempotentReplay === true)));
                assert.strictEqual(new Set(bodies.map(b => b.outboxId)).size, 1);
                assert.strictEqual(bodies.filter(b => !b.idempotentReplay).length, 1);
                assert.strictEqual(bodies.filter(b => b.idempotentReplay === true).length, 2);
                assert.strictEqual(revokeAuthCalls, 1);
                // tokenVersion incremented ONLY once (1 -> 2)
                assert.strictEqual((await db.collection('users').doc('u_idem').get()).data().tokenVersion, 2);

                // Post-completion replay deterministically returns 200 completed
                const postReplay = await fetch(`${baseUrl}/api/admin/id/users/u_idem/sessions/revoke-all`, {
                    method: 'POST',
                    headers: { Authorization: 'Bearer tok', 'Idempotency-Key': 'idem-emu-concurrent-001' }
                });
                assert.strictEqual(postReplay.status, 200);
                const postBody = await postReplay.json();
                assert.strictEqual(postBody.idempotentReplay, true);
                assert.strictEqual(postBody.externalAuthStatus, 'completed');

                // Suspend with same key, different payload -> 409 conflict
                assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/users/u_idem/suspend`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok', 'Idempotency-Key': 'idem-emu-suspend-conflict' },
                    body: JSON.stringify({ status: 'suspended', reason: 'reason_a' })
                })).status, 200);
                assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/users/u_idem/suspend`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok', 'Idempotency-Key': 'idem-emu-suspend-conflict' },
                    body: JSON.stringify({ status: 'suspended', reason: 'reason_b' })
                })).status, 409);
            });
        });

        await test('EMU-OI-03: Pending operation replay returns 503 pending, then 200 completed after worker finishes', async () => {
            await db.collection('users').doc('u_pend').set({ uid: 'u_pend', email: 'pend@lanzar.me', status: 'active', tokenVersion: 1 });
            let failAuth = true;
            const authAdmin = {
                updateUser: async () => { if (failAuth) throw Object.assign(new Error('auth_down'), { code: 'auth/unavailable' }); },
                revokeRefreshTokens: async () => ({}),
                verifyIdToken: async () => ({ uid: 'uid_plat', email: 'plat@lanzar.me', session_id: 'sp' })
            };
            const sessionService = { checkSession: async () => ({ active: true }) };
            const authMiddleware = createAuthMiddleware({ db, authAdmin, sessionService });
            const auditLogService = new AuditLogService(db);
            const outboxSvc = new PlatformOutboxService(db, authAdmin, { auditLogService, baseBackoffMs: 0, maxAttempts: 5 });
            const { app: expressApp } = createApp({ db, authAdmin, services: { authMiddleware, sessionService, auditLogService, platformOutboxService: outboxSvc } });

            await withServer(expressApp, async (baseUrl) => {
                const res1 = await fetch(`${baseUrl}/api/admin/id/users/u_pend/suspend`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok', 'Idempotency-Key': 'idem-emu-pending-001' },
                    body: JSON.stringify({ status: 'suspended', reason: 'abuse' })
                });
                assert.strictEqual(res1.status, 503);
                const b1 = await res1.json();
                assert.strictEqual(b1.externalAuthStatus, 'pending');

                // Replay while still pending -> 503 pending + idempotentReplay: true, no tokenVersion bump
                const res2 = await fetch(`${baseUrl}/api/admin/id/users/u_pend/suspend`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok', 'Idempotency-Key': 'idem-emu-pending-001' },
                    body: JSON.stringify({ status: 'suspended', reason: 'abuse' })
                });
                assert.strictEqual(res2.status, 503);
                const b2 = await res2.json();
                assert.strictEqual(b2.idempotentReplay, true);
                assert.strictEqual(b2.externalAuthStatus, 'pending');
                assert.strictEqual(b2.outboxId, b1.outboxId);
                assert.strictEqual((await db.collection('users').doc('u_pend').get()).data().tokenVersion, 2);

                // Worker recovers -> replay returns 200 completed
                failAuth = false;
                await outboxSvc.runOnce({ nowMs: Date.now() + 10000 });
                const res3 = await fetch(`${baseUrl}/api/admin/id/users/u_pend/suspend`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok', 'Idempotency-Key': 'idem-emu-pending-001' },
                    body: JSON.stringify({ status: 'suspended', reason: 'abuse' })
                });
                assert.strictEqual(res3.status, 200);
                const b3 = await res3.json();
                assert.strictEqual(b3.idempotentReplay, true);
                assert.strictEqual(b3.externalAuthStatus, 'completed');
            });
        });

        await test('EMU-OI-04: Concurrent worker claims, expired lease recovery, stale worker fencing, and duplicate reconcile guard', async () => {
            const outboxId = 'outbox_lease_test_1';
            await db.collection('users').doc('u_lease').set({ uid: 'u_lease', desiredAuthVersion: 1, desiredAuthDisabled: false, desiredRevocationVersion: 1 });
            await db.collection('security_outbox').doc(outboxId).set({
                outboxId,
                type: 'platform_admin_cross_service',
                operation: 'platform.user.sessions_revoke_all',
                targetUid: 'u_lease',
                actorUid: 'uid_plat',
                revocationVersion: 1,
                status: 'PENDING_EXTERNAL_AUTH',
                payload: { revokeRefreshTokens: true },
                progress: { revokeRefreshTokensDone: false },
                attempts: 0,
                fencingToken: 0,
                leaseOwner: null,
                leaseExpiresAt: 0,
                nextRetryAt: 0
            });

            const auditLogService = new AuditLogService(db);
            const authAdmin = { revokeRefreshTokens: async () => ({}) };
            const workerA = new PlatformOutboxService(db, authAdmin, { workerId: 'worker_A', leaseDurationMs: 5000, auditLogService });
            const workerB = new PlatformOutboxService(db, authAdmin, { workerId: 'worker_B', leaseDurationMs: 5000, auditLogService });

            const t0 = 1000000;
            const [cA, cB] = await Promise.all([
                workerA.claimLease(outboxId, { nowMs: t0 }),
                workerB.claimLease(outboxId, { nowMs: t0 })
            ]);
            assert.strictEqual([cA.claimed, cB.claimed].filter(Boolean).length, 1);
            const winner = cA.claimed ? workerA : workerB;
            const winnerToken = cA.claimed ? cA.fencingToken : cB.fencingToken;
            const loser = cA.claimed ? workerB : workerA;

            // Loser cannot claim while lease is active
            const retryLoser = await loser.claimLease(outboxId, { nowMs: t0 + 1000 });
            assert.strictEqual(retryLoser.claimed, false);
            assert.strictEqual(retryLoser.reason, 'LEASE_HELD');

            // After lease expires, loser recovers the event with higher fencing token
            const takeover = await loser.claimLease(outboxId, { nowMs: t0 + 6000 });
            assert.strictEqual(takeover.claimed, true);
            assert.strictEqual(takeover.fencingToken, winnerToken + 1);

            // Stale winner cannot overwrite state with old fencing token
            const staleWrite = await winner._fencedPersist(outboxId, {
                workerId: winner.workerId,
                fencingToken: winnerToken,
                nextStatus: 'COMPLETED'
            });
            assert.strictEqual(staleWrite.persisted, false);
            assert.strictEqual(staleWrite.fenced, true);

            // Current owner completes cleanly
            const validWrite = await loser._fencedPersist(outboxId, {
                workerId: loser.workerId,
                fencingToken: takeover.fencingToken,
                nextStatus: 'COMPLETED',
                auditOperation: 'platform.outbox.completed'
            });
            assert.strictEqual(validWrite.persisted, true);

            // Duplicate reconciliation returns alreadyCompleted: true
            const dup = await loser.processEventById(outboxId);
            assert.strictEqual(dup.status, 'COMPLETED');
            assert.strictEqual(dup.alreadyCompleted, true);
        });

        await test('EMU-OI-05: Bounded retries, DEAD_LETTER transition, and audited HTTP administrative redrive', async () => {
            const outboxId = 'outbox_dlq_1';
            await db.collection('users').doc('u_dlq').set({ uid: 'u_dlq', desiredAuthVersion: 1, desiredAuthDisabled: false, desiredRevocationVersion: 1 });
            await db.collection('security_outbox').doc(outboxId).set({
                outboxId,
                type: 'platform_admin_cross_service',
                operation: 'platform.user.sessions_revoke_all',
                targetUid: 'u_dlq',
                actorUid: 'uid_plat',
                revocationVersion: 1,
                status: 'PENDING_EXTERNAL_AUTH',
                payload: { revokeRefreshTokens: true },
                progress: { revokeRefreshTokensDone: false },
                attempts: 0,
                fencingToken: 0,
                leaseOwner: null,
                leaseExpiresAt: 0,
                nextRetryAt: 0
            });

            let authFail = true;
            const authAdmin = {
                revokeRefreshTokens: async () => { if (authFail) throw Object.assign(new Error('perm_fail'), { code: 'auth/internal-error' }); },
                verifyIdToken: async () => ({ uid: 'uid_plat', email: 'plat@lanzar.me', session_id: 'sp' })
            };
            const sessionService = { checkSession: async () => ({ active: true }) };
            const authMiddleware = createAuthMiddleware({ db, authAdmin, sessionService });
            const auditLogService = new AuditLogService(db);
            const outboxSvc = new PlatformOutboxService(db, authAdmin, { auditLogService, maxAttempts: 2, baseBackoffMs: 0 });
            const { app: expressApp } = createApp({ db, authAdmin, services: { authMiddleware, sessionService, auditLogService, platformOutboxService: outboxSvc } });

            const r1 = await outboxSvc.processEventById(outboxId, { nowMs: 1000 });
            assert.strictEqual(r1.status, 'FAILED_RETRYABLE');
            const r2 = await outboxSvc.processEventById(outboxId, { nowMs: 5000 });
            assert.strictEqual(r2.status, 'DEAD_LETTER');

            // Automatic sweep does NOT pick up DEAD_LETTER
            const sweep = await outboxSvc.runOnce({ nowMs: 999999 });
            assert.strictEqual(sweep.some(s => s.outboxId === outboxId), false);

            // Audited HTTP redrive recovers DEAD_LETTER once Auth is healthy
            authFail = false;
            await withServer(expressApp, async (baseUrl) => {
                const redriveRes = await fetch(`${baseUrl}/api/admin/id/outbox/${outboxId}/redrive`, {
                    method: 'POST',
                    headers: { Authorization: 'Bearer tok', 'x-correlation-id': 'corr_redrive_1' }
                });
                assert.strictEqual(redriveRes.status, 200);
                const redriveBody = await redriveRes.json();
                assert.strictEqual(redriveBody.redriven, true);
                assert.strictEqual(redriveBody.processResult.status, 'COMPLETED');
                assert.strictEqual((await db.collection('security_outbox').doc(outboxId).get()).data().status, 'COMPLETED');

                const logs = await auditLogService.listTenantAuditLogs('lanzar');
                assert.ok(logs.some(l => l.operation === 'platform.outbox.dead_lettered' && l.metadata.outboxId === outboxId));
                assert.ok(logs.some(l => l.operation === 'platform.outbox.redrive' && l.metadata.outboxId === outboxId && l.correlationId === 'corr_redrive_1'));
                assert.ok(logs.some(l => l.operation === 'platform.outbox.completed' && l.metadata.outboxId === outboxId));
            });
        });

        await test('EMU-OI-06: Partial Firebase Auth failure (updateUser succeeds, revokeRefreshTokens fails) converges on worker restart', async () => {
            const outboxId = 'outbox_partial_1';
            await db.collection('users').doc('u_partial').set({ uid: 'u_partial', desiredAuthVersion: 1, desiredAuthDisabled: true });
            await db.collection('security_outbox').doc(outboxId).set({
                outboxId,
                type: 'platform_admin_cross_service',
                operation: 'platform.user.status_update',
                targetUid: 'u_partial',
                actorUid: 'uid_plat',
                operationVersion: 1,
                status: 'PENDING_EXTERNAL_AUTH',
                payload: { disabled: true, status: 'suspended', revokeRefreshTokens: true },
                progress: { updateUserDone: false, revokeRefreshTokensDone: false },
                attempts: 0,
                fencingToken: 0,
                leaseOwner: null,
                leaseExpiresAt: 0,
                nextRetryAt: 0
            });

            let updateCalls = 0;
            let revokeCalls = 0;
            let failRevoke = true;
            const authAdmin = {
                updateUser: async () => { updateCalls++; return {}; },
                revokeRefreshTokens: async () => {
                    revokeCalls++;
                    if (failRevoke) throw Object.assign(new Error('revoke_timeout'), { code: 'auth/timeout' });
                }
            };
            const auditLogService = new AuditLogService(db);
            const worker1 = new PlatformOutboxService(db, authAdmin, { workerId: 'w1', auditLogService, baseBackoffMs: 0 });
            const r1 = await worker1.processEventById(outboxId, { nowMs: 1000 });
            assert.strictEqual(r1.status, 'FAILED_RETRYABLE');
            assert.strictEqual(updateCalls, 1);
            assert.strictEqual(revokeCalls, 1);
            assert.strictEqual((await db.collection('security_outbox').doc(outboxId).get()).data().progress.updateUserDone, true);

            // Simulated new worker after restart skips updateUser and completes revokeRefreshTokens
            failRevoke = false;
            const worker2 = new PlatformOutboxService(db, authAdmin, { workerId: 'w2', auditLogService, baseBackoffMs: 0 });
            const r2 = await worker2.runOnce({ nowMs: 5000 });
            assert.ok(r2.some(r => r.outboxId === outboxId && r.status === 'COMPLETED'));
            assert.strictEqual(updateCalls, 1);
            assert.strictEqual(revokeCalls, 2);
        });

        await test('EMU-OI-07: Suspend pending -> Activate completes -> stale Suspend retry is SUPERSEDED and never overwrites Auth', async () => {
            await db.collection('users').doc('u_order1').set({ uid: 'u_order1', email: 'o1@lanzar.me', status: 'active', desiredAuthVersion: 0 });
            let authState = { disabled: false };
            let failSuspend = true;
            const authAdmin = {
                updateUser: async (uid, { disabled }) => {
                    if (disabled && failSuspend) throw Object.assign(new Error('temp_down'), { code: 'auth/unavailable' });
                    authState.disabled = disabled;
                },
                revokeRefreshTokens: async () => ({}),
                verifyIdToken: async () => ({ uid: 'uid_plat', email: 'plat@lanzar.me', session_id: 'sp' })
            };
            const sessionService = { checkSession: async () => ({ active: true }) };
            const authMiddleware = createAuthMiddleware({ db, authAdmin, sessionService });
            const auditLogService = new AuditLogService(db);
            const outboxSvc = new PlatformOutboxService(db, authAdmin, { auditLogService, baseBackoffMs: 0 });
            const { app: expressApp } = createApp({ db, authAdmin, services: { authMiddleware, sessionService, auditLogService, platformOutboxService: outboxSvc } });

            await withServer(expressApp, async (baseUrl) => {
                // 1. Suspend accepted, external Auth fails -> pending (v1)
                const suspRes = await fetch(`${baseUrl}/api/admin/id/users/u_order1/suspend`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok', 'Idempotency-Key': 'idem-order1-suspend-0001' },
                    body: JSON.stringify({ status: 'suspended', reason: 'abuse' })
                });
                assert.strictEqual(suspRes.status, 503);
                const suspBody = await suspRes.json();

                // 2. Activate accepted and completes (v2)
                const actRes = await fetch(`${baseUrl}/api/admin/id/users/u_order1/suspend`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok', 'Idempotency-Key': 'idem-order1-activate-001' },
                    body: JSON.stringify({ status: 'active', reason: 'resolved' })
                });
                assert.strictEqual(actRes.status, 200);
                const actBody = await actRes.json();
                assert.strictEqual(actBody.operationVersion, 2);
                assert.strictEqual(authState.disabled, false);

                // 3. Older suspend event retries after Auth recovers -> marked SUPERSEDED, Auth stays disabled=false!
                failSuspend = false;
                const retryRes = await outboxSvc.processEventById(suspBody.outboxId, { nowMs: Date.now() + 10000 });
                assert.strictEqual(retryRes.status, 'SUPERSEDED');
                assert.strictEqual(authState.disabled, false);
                assert.strictEqual((await db.collection('security_outbox').doc(suspBody.outboxId).get()).data().status, 'SUPERSEDED');

                // 4. Replaying original suspend Idempotency-Key reports superseded
                const replaySusp = await fetch(`${baseUrl}/api/admin/id/users/u_order1/suspend`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok', 'Idempotency-Key': 'idem-order1-suspend-0001' },
                    body: JSON.stringify({ status: 'suspended', reason: 'abuse' })
                });
                assert.strictEqual(replaySusp.status, 200);
                const replayBody = await replaySusp.json();
                assert.strictEqual(replayBody.externalAuthStatus, 'superseded');
                assert.strictEqual(replayBody.superseded, true);

                // 5. Redrive on SUPERSEDED is rejected (409)
                assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/outbox/${suspBody.outboxId}/redrive`, {
                    method: 'POST', headers: { Authorization: 'Bearer tok' }
                })).status, 409);
            });
        });

        await test('EMU-OI-08: Activate pending -> Suspend accepted -> final Auth state is disabled=true and Activate is SUPERSEDED', async () => {
            await db.collection('users').doc('u_order2').set({ uid: 'u_order2', email: 'o2@lanzar.me', status: 'suspended', desiredAuthVersion: 0 });
            let authState = { disabled: true };
            let failActivate = true;
            const authAdmin = {
                updateUser: async (uid, { disabled }) => {
                    if (!disabled && failActivate) throw Object.assign(new Error('temp_down'), { code: 'auth/unavailable' });
                    authState.disabled = disabled;
                },
                revokeRefreshTokens: async () => ({}),
                verifyIdToken: async () => ({ uid: 'uid_plat', email: 'plat@lanzar.me', session_id: 'sp' })
            };
            const sessionService = { checkSession: async () => ({ active: true }) };
            const authMiddleware = createAuthMiddleware({ db, authAdmin, sessionService });
            const auditLogService = new AuditLogService(db);
            const outboxSvc = new PlatformOutboxService(db, authAdmin, { auditLogService, baseBackoffMs: 0 });
            const { app: expressApp } = createApp({ db, authAdmin, services: { authMiddleware, sessionService, auditLogService, platformOutboxService: outboxSvc } });

            await withServer(expressApp, async (baseUrl) => {
                const actRes = await fetch(`${baseUrl}/api/admin/id/users/u_order2/suspend`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok', 'Idempotency-Key': 'idem-order2-activate-001' },
                    body: JSON.stringify({ status: 'active', reason: 'appeal' })
                });
                assert.strictEqual(actRes.status, 503);
                const actBody = await actRes.json();

                const suspRes = await fetch(`${baseUrl}/api/admin/id/users/u_order2/suspend`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok', 'Idempotency-Key': 'idem-order2-suspend-0001' },
                    body: JSON.stringify({ status: 'suspended', reason: 'reoffend' })
                });
                assert.strictEqual(suspRes.status, 200);
                assert.strictEqual(authState.disabled, true);

                failActivate = false;
                const retryAct = await outboxSvc.processEventById(actBody.outboxId, { nowMs: Date.now() + 10000 });
                assert.strictEqual(retryAct.status, 'SUPERSEDED');
                assert.strictEqual(authState.disabled, true);
            });
        });

        await test('EMU-OI-09: Concurrent version assignment assigns strictly monotonic operationVersions', async () => {
            await db.collection('users').doc('u_conc_v').set({ uid: 'u_conc_v', email: 'cv@lanzar.me', status: 'active', desiredAuthVersion: 0 });
            const authAdmin = {
                updateUser: async () => ({}),
                revokeRefreshTokens: async () => ({}),
                verifyIdToken: async () => ({ uid: 'uid_plat', email: 'plat@lanzar.me', session_id: 'sp' })
            };
            const sessionService = { checkSession: async () => ({ active: true }) };
            const authMiddleware = createAuthMiddleware({ db, authAdmin, sessionService });
            const auditLogService = new AuditLogService(db);
            const { app: expressApp } = createApp({ db, authAdmin, services: { authMiddleware, sessionService, auditLogService } });

            await withServer(expressApp, async (baseUrl) => {
                const responses = await Promise.all([
                    fetch(`${baseUrl}/api/admin/id/users/u_conc_v/suspend`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok', 'Idempotency-Key': 'idem-conc-version-0001' },
                        body: JSON.stringify({ status: 'suspended', reason: 'r1' })
                    }),
                    fetch(`${baseUrl}/api/admin/id/users/u_conc_v/suspend`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok', 'Idempotency-Key': 'idem-conc-version-0002' },
                        body: JSON.stringify({ status: 'active', reason: 'r2' })
                    }),
                    fetch(`${baseUrl}/api/admin/id/users/u_conc_v/sessions/revoke-all`, {
                        method: 'POST',
                        headers: { Authorization: 'Bearer tok', 'Idempotency-Key': 'idem-conc-version-0003' }
                    })
                ]);
                assert.ok(responses.every(r => r.status === 200));
                const bodies = await Promise.all(responses.map(r => r.json()));
                const accountVersions = bodies.filter(b => b.operationVersion).map(b => b.operationVersion).sort((a, b) => a - b);
                assert.deepStrictEqual(accountVersions, [1, 2]);
                assert.strictEqual(bodies.filter(b => b.revocationVersion).length, 1);
                assert.strictEqual((await db.collection('users').doc('u_conc_v').get()).data().desiredAuthVersion, 2);
                assert.strictEqual((await db.collection('users').doc('u_conc_v').get()).data().desiredRevocationVersion >= 1, true);
            });
        });

        await test('EMU-OI-10: Out-of-order worker execution & lease expiration during processing prevents stale Auth write', async () => {
            await db.collection('users').doc('u_ooo').set({ uid: 'u_ooo', email: 'ooo@lanzar.me', status: 'active', desiredAuthVersion: 2, desiredAuthDisabled: false });
            await db.collection('security_outbox').doc('outbox_ooo_v1').set({
                outboxId: 'outbox_ooo_v1',
                type: 'platform_admin_cross_service',
                operation: 'platform.user.status_update',
                targetUid: 'u_ooo',
                actorUid: 'uid_plat',
                operationVersion: 1,
                status: 'PENDING_EXTERNAL_AUTH',
                payload: { disabled: true, status: 'suspended', revokeRefreshTokens: true },
                progress: { updateUserDone: false, revokeRefreshTokensDone: false },
                attempts: 0, fencingToken: 0, leaseOwner: null, leaseExpiresAt: 0, nextRetryAt: 0
            });
            await db.collection('security_outbox').doc('outbox_ooo_v2').set({
                outboxId: 'outbox_ooo_v2',
                type: 'platform_admin_cross_service',
                operation: 'platform.user.status_update',
                targetUid: 'u_ooo',
                actorUid: 'uid_plat',
                operationVersion: 2,
                status: 'PENDING_EXTERNAL_AUTH',
                payload: { disabled: false, status: 'active', revokeRefreshTokens: false },
                progress: { updateUserDone: false, revokeRefreshTokensDone: true },
                attempts: 0, fencingToken: 0, leaseOwner: null, leaseExpiresAt: 0, nextRetryAt: 0
            });

            const authLog = [];
            const authAdmin = {
                updateUser: async (uid, { disabled }) => { authLog.push(disabled); },
                revokeRefreshTokens: async () => ({})
            };
            const auditLogService = new AuditLogService(db);
            const worker1 = new PlatformOutboxService(db, authAdmin, { workerId: 'w_ooo_1', leaseDurationMs: 1000, auditLogService });
            const worker2 = new PlatformOutboxService(db, authAdmin, { workerId: 'w_ooo_2', leaseDurationMs: 1000, auditLogService });

            // v2 runs first (out of order) -> sets disabled=false
            const resV2 = await worker2.processEventById('outbox_ooo_v2', { nowMs: 1000 });
            assert.strictEqual(resV2.status, 'COMPLETED');

            // v1 runs after -> rejected as SUPERSEDED without touching authAdmin
            const resV1 = await worker1.processEventById('outbox_ooo_v1', { nowMs: 1000 });
            assert.strictEqual(resV1.status, 'SUPERSEDED');
            assert.deepStrictEqual(authLog, [false]);

            // Lease expiration during processing: worker1 claims v3, lease expires, worker2 takes over and completes; worker1 is fenced before Auth call
            await db.collection('users').doc('u_ooo').update({ desiredAuthVersion: 3, desiredRevocationVersion: 1 });
            await db.collection('security_outbox').doc('outbox_ooo_v3').set({
                outboxId: 'outbox_ooo_v3',
                type: 'platform_admin_cross_service',
                operation: 'platform.user.sessions_revoke_all',
                targetUid: 'u_ooo',
                actorUid: 'uid_plat',
                revocationVersion: 1,
                status: 'PENDING_EXTERNAL_AUTH',
                payload: { revokeRefreshTokens: true },
                progress: { revokeRefreshTokensDone: false },
                attempts: 0, fencingToken: 0, leaseOwner: null, leaseExpiresAt: 0, nextRetryAt: 0
            });
            const claim1 = await worker1.claimLease('outbox_ooo_v3', { nowMs: 1000 });
            assert.strictEqual(claim1.claimed, true);
            // Lease expires at 2000; worker2 claims at 3000 and completes
            const resW2 = await worker2.processEventById('outbox_ooo_v3', { nowMs: 3000 });
            assert.strictEqual(resW2.status, 'COMPLETED');
            // Stale worker1 attempts _executeExternalAuth -> fenced before calling authAdmin!
            let staleAuthCalled = false;
            await assert.rejects(
                () => worker1._executeExternalAuth(claim1.event, {
                    authAdmin: { revokeRefreshTokens: async () => { staleAuthCalled = true; } },
                    workerId: worker1.workerId,
                    fencingToken: claim1.fencingToken
                }),
                /STALE_FENCING_TOKEN/
            );
            assert.strictEqual(staleAuthCalled, false);
        });

        console.log('\n================================================================');
        console.log('OUTBOX & IDEMPOTENCY EMULATOR VERIFICATION SUMMARY');
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
    console.error('Fatal Outbox & Idempotency Emulator error:', err);
    process.exit(1);
});
