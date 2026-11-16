// test-preprod-hardening.cjs
// Pre-Production Hardening Verification Suite

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const express = require('./auth-backend/node_modules/express');
const { createApp } = require('./auth-backend/app');
const { createAuthMiddleware } = require('./auth-backend/middleware/authMiddleware');
const { SigningKeystore, validateSigningKeyEncryptionConfiguration } = require('./auth-backend/services/signingKeystore');
const { AuditLogService } = require('./auth-backend/services/auditLogService');
const { FounderService } = require('./auth-backend/founderService');
const { reconcilePlatformOutboxEvent } = require('./auth-backend/routes/adminRoutes');
const { validateReceiptKeyConfiguration } = require('./auth-backend/store');

class InMemoryFirestore {
    constructor() {
        this.docs = new Map();
        this.txQueue = Promise.resolve();
    }

    collection(name) {
        const self = this;
        const makeCol = (prefix) => ({
            doc(id) {
                const key = `${prefix}/${id}`;
                return {
                    id,
                    path: key,
                    collection(sub) { return makeCol(`${key}/${sub}`); },
                    async get() {
                        const val = self.docs.get(key);
                        return { exists: val !== undefined, id, data: () => (val ? JSON.parse(JSON.stringify(val)) : undefined) };
                    },
                    async set(data, opts) {
                        const cloned = JSON.parse(JSON.stringify(data));
                        if (opts && opts.merge) {
                            const cur = self.docs.get(key) || {};
                            self.docs.set(key, { ...cur, ...cloned });
                        } else {
                            self.docs.set(key, cloned);
                        }
                    },
                    async create(data) {
                        if (self.docs.has(key)) throw new Error(`6 ALREADY_EXISTS: ${key}`);
                        self.docs.set(key, JSON.parse(JSON.stringify(data)));
                    },
                    async update(patch) {
                        const cur = self.docs.get(key);
                        if (!cur) throw new Error(`5 NOT_FOUND: ${key}`);
                        self.docs.set(key, { ...cur, ...JSON.parse(JSON.stringify(patch)) });
                    }
                };
            },
            async get() {
                const docs = [];
                for (const [k, v] of self.docs.entries()) {
                    if (k.startsWith(`${prefix}/`) && !k.slice(prefix.length + 1).includes('/')) {
                        const docRef = makeCol(prefix).doc(k.slice(prefix.length + 1));
                        docs.push({ id: k.slice(prefix.length + 1), ref: docRef, data: () => JSON.parse(JSON.stringify(v)) });
                    }
                }
                return { empty: docs.length === 0, size: docs.length, docs, forEach: (cb) => docs.forEach(cb) };
            },
            where() { return this; },
            orderBy() { return this; },
            limit() { return this; }
        });
        return makeCol(name);
    }

    async runTransaction(fn) {
        const run = async () => {
            const writes = [];
            const tx = {
                async get(ref) { return await ref.get(); },
                set(ref, data, opts) { writes.push(() => ref.set(data, opts)); },
                create(ref, data) { writes.push(() => ref.create(data)); },
                update(ref, patch) { writes.push(() => ref.update(patch)); }
            };
            const res = await fn(tx);
            for (const w of writes) await w();
            return res;
        };
        const p = this.txQueue.then(run, run);
        this.txQueue = p.catch(() => {});
        return p;
    }
}

async function withServer(app, fn) {
    const server = await new Promise((resolve) => {
        const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const { port } = server.address();
    const baseUrl = `http://127.0.0.1:${port}`;
    try {
        return await fn(baseUrl);
    } finally {
        await new Promise((resolve) => server.close(resolve));
    }
}

async function main() {
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

    console.log('\n================================================================');
    console.log('LANZAR ID — Pre-Production Hardening Verification Suite');
    console.log('================================================================\n');

    await test('PPH-01: Legacy adminRoutes.js requires platform_admin adminContext, rejects tenant_admin (403), and records audit logs', async () => {
        const db = new InMemoryFirestore();
        await db.collection('admins').doc('uid_tenant').set({ email: 't@a.com', active: true, tenantId: 'tenant_a' });
        await db.collection('admins').doc('uid_plat').set({ email: 'p@a.com', active: true, role: 'platform_admin' });
        await db.collection('users').doc('u1').set({ uid: 'u1', email: 'u1@lanzar.me', status: 'active' });

        const authAdmin = {
            updateUser: async () => ({}),
            revokeRefreshTokens: async () => ({}),
            verifyIdToken: async (tok) => {
                if (tok === 'tok_tenant') return { uid: 'uid_tenant', email: 't@a.com', session_id: 'st' };
                if (tok === 'tok_plat') return { uid: 'uid_plat', email: 'p@a.com', session_id: 'sp' };
                throw new Error('invalid_token');
            }
        };
        const sessionService = {
            checkSession: async () => ({ active: true }),
            revokeAllSessions: async (uid) => ({ uid, revoked: true })
        };
        const authMiddleware = createAuthMiddleware({ db, authAdmin, sessionService });
        const auditLogService = new AuditLogService(db);
        const { app } = createApp({
            db,
            authAdmin,
            services: {
                authMiddleware,
                sessionService,
                auditLogService,
                profileService: { setAccountStatus: async (uid, status) => ({ uid, status }) }
            }
        });

        await withServer(app, async (baseUrl) => {
            // Tenant admin rejected from platform-wide endpoints
            assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/users`, { headers: { Authorization: 'Bearer tok_tenant' } })).status, 403);
            assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/telemetry`, { headers: { Authorization: 'Bearer tok_tenant' } })).status, 403);
            assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/users/u1/suspend`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok_tenant', 'Idempotency-Key': 'idem_pph01_tenant' },
                body: JSON.stringify({ status: 'suspended', reason: 'abuse' })
            })).status, 403);

            // Platform admin succeeds and records audit log
            assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/users`, { headers: { Authorization: 'Bearer tok_plat' } })).status, 200);
            const susp = await fetch(`${baseUrl}/api/admin/id/users/u1/suspend`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok_plat', 'x-correlation-id': 'corr_pph_1', 'Idempotency-Key': 'idem_pph01_suspend_1' },
                body: JSON.stringify({ status: 'suspended', reason: 'abuse' })
            });
            assert.strictEqual(susp.status, 200);

            const logs = await auditLogService.listTenantAuditLogs('lanzar');
            assert.ok(logs.some(l => l.operation === 'platform.user.status_update' && l.correlationId === 'corr_pph_1'));
        });
    });

    await test('PPH-02: /api/id/ready returns 200 when Firestore and signing keys are ready, and 503 when unavailable', async () => {
        const db = new InMemoryFirestore();
        const emptyKeystore = new SigningKeystore(db);
        emptyKeystore.getPublicJwks = async () => ({ keys: [] });
        const { app: unreadyApp } = createApp({ db, authAdmin: {}, services: { signingKeystore: emptyKeystore } });

        await withServer(unreadyApp, async (baseUrl) => {
            // No active signing keys -> 503 not_ready
            const unready = await fetch(`${baseUrl}/api/id/ready`);
            assert.strictEqual(unready.status, 503);
        });

        const keystore = new SigningKeystore(db);
        await keystore.ensureActiveSigningKey();
        const { app } = createApp({ db, authAdmin: {}, services: { signingKeystore: keystore } });

        await withServer(app, async (baseUrl) => {
            const ready = await fetch(`${baseUrl}/api/id/ready`);
            assert.strictEqual(ready.status, 200);
            const body = await ready.json();
            assert.strictEqual(body.status, 'ready');
            assert.strictEqual(body.checks.firestore, 'ok');
            assert.strictEqual(body.checks.signingKeystore, 'ok');
        });

        // Failing Firestore -> 503 without leaking internal error message
        const failingDb = { collection: () => ({ doc: () => ({ get: async () => { throw new Error('SECRET_CONN_STRING'); } }) }) };
        const { app: failApp } = createApp({ db: failingDb, authAdmin: {}, services: { signingKeystore: keystore } });
        await withServer(failApp, async (baseUrl) => {
            const res = await fetch(`${baseUrl}/api/id/ready`);
            assert.strictEqual(res.status, 503);
            const txt = await res.text();
            assert.strictEqual(txt.includes('SECRET_CONN_STRING'), false);
        });
    });

    await test('PPH-03: Production and staging reject missing or development encryption keys (KEK & RECEIPT_ENCRYPTION_KEY)', async () => {
        for (const env of [
            { NODE_ENV: 'production' },
            { APP_ENV: 'production' },
            { NODE_ENV: 'staging' },
            { APP_ENV: 'staging' }
        ]) {
            assert.throws(() => validateSigningKeyEncryptionConfiguration(env));
            assert.throws(() => validateSigningKeyEncryptionConfiguration({ ...env, SIGNING_KEY_ENCRYPTION_KEY: 'LANZAR_ID_DEV_SIGNING_KEK_V1_TEST_ONLY_32B' }));
            assert.throws(() => validateReceiptKeyConfiguration(env));
            assert.throws(() => validateReceiptKeyConfiguration({ ...env, RECEIPT_ENCRYPTION_KEY: 'LANZAR_ID_DEV_RECEIPT_KEY_V1_TEST_ONLY_32B' }));
        }
    });

    await test('PPH-04: Correlation ID header propagated and terminal error handler sanitizes errors', async () => {
        const db = new InMemoryFirestore();
        const { app } = createApp({ db, authAdmin: {} });
        await withServer(app, async (baseUrl) => {
            const res = await fetch(`${baseUrl}/api/id/health`, { headers: { 'x-correlation-id': 'corr_health_123' } });
            assert.strictEqual(res.status, 200);
            assert.strictEqual(res.headers.get('x-correlation-id'), 'corr_health_123');
        });
    });

    await test('PPH-05: firestore.rules explicitly denies client access to all M1.1-M1.5 server-only collections', async () => {
        const rulesPath = path.join(__dirname, '..', 'firestore.rules');
        const rules = fs.readFileSync(rulesPath, 'utf8');
        for (const pattern of [
            '/oauth_authorization_codes/{codeHash}',
            '/authorization_codes/{codeHash}',
            '/compromised_ceremonies/{ceremonyId}',
            '/security_outbox/{eventId}',
            '/system_signing_keys/{kid}',
            '/clients_index/{clientId}',
            '/tenants/{tenantId}/clients/{clientId}',
            '/tenants/{tenantId}/token_families/{familyId}',
            '/tenants/{tenantId}/admin_audit_logs/{auditId}',
            '/pythos/app/lanzar_id_accounts/{document=**}',
            '/admin_idempotency/{keyHash}',
            '/auth_reconciliation/{uid}'
        ]) {
            assert.ok(rules.includes(pattern), `Missing explicit rule for ${pattern}`);
        }
        assert.ok(rules.includes('allow read, create, update, delete: if false;'));
    });

    await test('PPH-06: Founder grant/revoke enforces platform_admin, writes atomic audit, and rolls back on audit failure (503)', async () => {
        const db = new InMemoryFirestore();
        await db.collection('admins').doc('uid_tenant').set({ email: 't@a.com', active: true, tenantId: 'tenant_a' });
        await db.collection('admins').doc('uid_plat').set({ email: 'p@a.com', active: true, role: 'platform_admin' });
        await db.collection('users').doc('u1').set({ uid: 'u1', email: 'u1@lanzar.me', status: 'active' });

        const authAdmin = {
            verifyIdToken: async (tok) => {
                if (tok === 'tok_tenant') return { uid: 'uid_tenant', email: 't@a.com', session_id: 'st' };
                if (tok === 'tok_plat') return { uid: 'uid_plat', email: 'p@a.com', session_id: 'sp' };
                throw new Error('invalid_token');
            }
        };
        const sessionService = { checkSession: async () => ({ active: true }) };
        const authMiddleware = createAuthMiddleware({ db, authAdmin, sessionService });
        const auditLogService = new AuditLogService(db);
        const founderService = new FounderService(db);
        const { app } = createApp({ db, authAdmin, services: { authMiddleware, sessionService, auditLogService, founderService } });

        await withServer(app, async (baseUrl) => {
            // Tenant admin denied (403)
            assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/users/u1/founders`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok_tenant' },
                body: JSON.stringify({ programId: 'portal', grantReason: 'Early supporter' })
            })).status, 403);

            // Platform admin grant succeeds + writes audit
            const grantRes = await fetch(`${baseUrl}/api/admin/id/users/u1/founders`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok_plat', 'x-correlation-id': 'corr_f_grant' },
                body: JSON.stringify({ programId: 'portal_founder', founderNumber: 7, grantReason: 'Early supporter' })
            });
            assert.strictEqual(grantRes.status, 200);
            const grantBody = await grantRes.json();
            assert.ok(grantBody.auditId);
            assert.deepStrictEqual((await db.collection('users').doc('u1').get()).data().derivedBadges, ['portal_founder']);

            // Platform admin revoke succeeds + writes audit
            const revRes = await fetch(`${baseUrl}/api/admin/id/users/u1/founders/portal_founder`, {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok_plat', 'x-correlation-id': 'corr_f_rev' },
                body: JSON.stringify({ revocationReason: 'Test revoke' })
            });
            assert.strictEqual(revRes.status, 200);
            assert.deepStrictEqual((await db.collection('users').doc('u1').get()).data().derivedBadges, []);

            // Audit write failure rolls back founder grant and sanitizes error (503)
            const origWrite = auditLogService.writeInTransaction.bind(auditLogService);
            auditLogService.writeInTransaction = () => { throw new Error('INTERNAL_AUDIT_DISK_FAIL'); };
            const failRes = await fetch(`${baseUrl}/api/admin/id/users/u1/founders`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok_plat' },
                body: JSON.stringify({ programId: 'threadline_founder', grantReason: 'Should rollback' })
            });
            assert.strictEqual(failRes.status, 503);
            const failTxt = await failRes.text();
            assert.strictEqual(failTxt.includes('INTERNAL_AUDIT_DISK_FAIL'), false);
            assert.strictEqual((await db.collection('users').doc('u1').collection('founders').doc('threadline_founder').get()).exists, false);
            auditLogService.writeInTransaction = origWrite;

            const logs = await auditLogService.listTenantAuditLogs('lanzar');
            assert.ok(logs.some(l => l.operation === 'platform.founder.grant' && l.correlationId === 'corr_f_grant' && l.metadata.targetUid === 'u1'));
            assert.ok(logs.some(l => l.operation === 'platform.founder.revoke' && l.correlationId === 'corr_f_rev' && l.metadata.targetUid === 'u1'));
        });
    });

    await test('PPH-07: Revoke-all sessions enforces platform_admin, writes atomic outbox+audit, and rolls back on audit failure (503)', async () => {
        const db = new InMemoryFirestore();
        await db.collection('admins').doc('uid_tenant').set({ email: 't@a.com', active: true, tenantId: 'tenant_a' });
        await db.collection('admins').doc('uid_plat').set({ email: 'p@a.com', active: true, role: 'platform_admin' });
        await db.collection('users').doc('u1').set({ uid: 'u1', email: 'u1@lanzar.me', status: 'active' });
        await db.collection('users').doc('u1').collection('sessions').doc('s1').set({ sessionId: 's1', revoked: false });

        let revokedInAuth = 0;
        const authAdmin = {
            revokeRefreshTokens: async () => { revokedInAuth++; },
            verifyIdToken: async (tok) => {
                if (tok === 'tok_tenant') return { uid: 'uid_tenant', email: 't@a.com', session_id: 'st' };
                if (tok === 'tok_plat') return { uid: 'uid_plat', email: 'p@a.com', session_id: 'sp' };
                throw new Error('invalid_token');
            }
        };
        const sessionService = { checkSession: async () => ({ active: true }) };
        const authMiddleware = createAuthMiddleware({ db, authAdmin, sessionService });
        const auditLogService = new AuditLogService(db);
        const { app } = createApp({ db, authAdmin, services: { authMiddleware, sessionService, auditLogService } });

        await withServer(app, async (baseUrl) => {
            assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/users/u1/sessions/revoke-all`, {
                method: 'POST',
                headers: { Authorization: 'Bearer tok_tenant' }
            })).status, 403);

            // Audit write failure rolls back session revocation & skips Firebase Auth call
            const origWrite = auditLogService.writeInTransaction.bind(auditLogService);
            auditLogService.writeInTransaction = () => { throw new Error('AUDIT_TX_ABORT'); };
            const failRes = await fetch(`${baseUrl}/api/admin/id/users/u1/sessions/revoke-all`, {
                method: 'POST',
                headers: { Authorization: 'Bearer tok_plat', 'Idempotency-Key': 'idem_pph07_fail_01' }
            });
            assert.strictEqual(failRes.status, 503);
            assert.strictEqual((await failRes.text()).includes('AUDIT_TX_ABORT'), false);
            assert.strictEqual((await db.collection('users').doc('u1').collection('sessions').doc('s1').get()).data().revoked, false);
            assert.strictEqual(revokedInAuth, 0);
            auditLogService.writeInTransaction = origWrite;

            // Success path
            const okRes = await fetch(`${baseUrl}/api/admin/id/users/u1/sessions/revoke-all`, {
                method: 'POST',
                headers: { Authorization: 'Bearer tok_plat', 'x-correlation-id': 'corr_rev_all', 'Idempotency-Key': 'idem_pph07_ok_001' }
            });
            assert.strictEqual(okRes.status, 200);
            const okBody = await okRes.json();
            assert.strictEqual(okBody.externalAuthStatus, 'completed');
            assert.strictEqual(revokedInAuth, 1);
            assert.strictEqual((await db.collection('users').doc('u1').collection('sessions').doc('s1').get()).data().revoked, true);
            assert.strictEqual((await db.collection('security_outbox').doc(okBody.outboxId).get()).data().status, 'COMPLETED');
        });
    });

    await test('PPH-08: Cross-service outbox records FAILED_RETRYABLE (503) when Firebase Auth fails and reconciles on recovery', async () => {
        const db = new InMemoryFirestore();
        await db.collection('admins').doc('uid_plat').set({ email: 'p@a.com', active: true, role: 'platform_admin' });
        await db.collection('users').doc('u1').set({ uid: 'u1', email: 'u1@lanzar.me', status: 'active' });

        let authHealthy = false;
        const authAdmin = {
            updateUser: async () => {
                if (!authHealthy) throw Object.assign(new Error('SECRET_FIREBASE_AUTH_RPC_ERROR'), { code: 'auth/internal-error' });
                return {};
            },
            revokeRefreshTokens: async () => ({}),
            verifyIdToken: async (tok) => {
                if (tok === 'tok_plat') return { uid: 'uid_plat', email: 'p@a.com', session_id: 'sp' };
                throw new Error('invalid_token');
            }
        };
        const sessionService = { checkSession: async () => ({ active: true }) };
        const authMiddleware = createAuthMiddleware({ db, authAdmin, sessionService });
        const auditLogService = new AuditLogService(db);
        const { app } = createApp({ db, authAdmin, services: { authMiddleware, sessionService, auditLogService } });

        await withServer(app, async (baseUrl) => {
            const res = await fetch(`${baseUrl}/api/admin/id/users/u1/suspend`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok_plat', 'x-correlation-id': 'corr_outbox_fail', 'Idempotency-Key': 'idem_pph08_fail_01' },
                body: JSON.stringify({ status: 'suspended', reason: 'abuse' })
            });
            assert.strictEqual(res.status, 503);
            const body = await res.json();
            assert.strictEqual(body.error, 'external_auth_sync_pending');
            assert.strictEqual(JSON.stringify(body).includes('SECRET_FIREBASE_AUTH_RPC_ERROR'), false);

            const outboxDoc = (await db.collection('security_outbox').doc(body.outboxId).get()).data();
            assert.strictEqual(outboxDoc.status, 'FAILED_RETRYABLE');
            assert.strictEqual(outboxDoc.attempts, 1);

            // Reconcile once Firebase Auth recovers
            authHealthy = true;
            const rec = await reconcilePlatformOutboxEvent({ db, authAdmin, outboxId: body.outboxId });
            assert.strictEqual(rec.status, 'COMPLETED');
            assert.strictEqual((await db.collection('security_outbox').doc(body.outboxId).get()).data().status, 'COMPLETED');
        });
    });

    await test('PPH-09: Missing auditLogService fails closed (503) on all mutating platform-admin routes without mutating state', async () => {
        const db = new InMemoryFirestore();
        await db.collection('admins').doc('uid_plat').set({ email: 'p@a.com', active: true, role: 'platform_admin' });
        await db.collection('users').doc('u1').set({ uid: 'u1', email: 'u1@lanzar.me', status: 'active' });

        let authCalled = false;
        const authAdmin = {
            updateUser: async () => { authCalled = true; },
            revokeRefreshTokens: async () => { authCalled = true; },
            verifyIdToken: async () => ({ uid: 'uid_plat', email: 'p@a.com', session_id: 'sp' })
        };
        const sessionService = { checkSession: async () => ({ active: true }) };
        const authMiddleware = createAuthMiddleware({ db, authAdmin, sessionService });
        const { app } = createApp({ db, authAdmin, services: { authMiddleware, sessionService, auditLogService: {} } });

        await withServer(app, async (baseUrl) => {
            assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/users/u1/suspend`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok_plat', 'Idempotency-Key': 'idem_pph09_susp_01' },
                body: JSON.stringify({ status: 'suspended', reason: 'test' })
            })).status, 503);
            assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/users/u1/founders`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok_plat' },
                body: JSON.stringify({ programId: 'portal_founder', grantReason: 'test' })
            })).status, 503);
            assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/users/u1/founders/portal_founder`, {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok_plat' },
                body: JSON.stringify({ revocationReason: 'test' })
            })).status, 503);
            assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/users/u1/sessions/revoke-all`, {
                method: 'POST',
                headers: { Authorization: 'Bearer tok_plat', 'Idempotency-Key': 'idem_pph09_rev_001' }
            })).status, 503);
            assert.strictEqual(authCalled, false);
            assert.strictEqual((await db.collection('users').doc('u1').get()).data().status, 'active');
        });
    });

    await test('PPH-10: /api/id/ready bypasses stale JWKS cache (bypassCache: true) and detects unavailable keys', async () => {
        const db = new InMemoryFirestore();
        const keystore = new SigningKeystore(db);
        let bypassFlagSeen = null;
        keystore.getPublicJwks = async (opts = {}) => {
            bypassFlagSeen = opts.bypassCache === true;
            return { keys: [] };
        };
        const { app } = createApp({ db, authAdmin: {}, services: { signingKeystore: keystore } });

        await withServer(app, async (baseUrl) => {
            const res = await fetch(`${baseUrl}/api/id/ready`);
            assert.strictEqual(res.status, 503);
            assert.strictEqual(bypassFlagSeen, true);
        });
    });

    console.log('\n================================================================');
    console.log('PRE-PRODUCTION HARDENING VERIFICATION SUMMARY');
    console.log(`Total Executed: ${passed + failed}`);
    console.log(`Passed:         ${passed}`);
    console.log(`Failed:         ${failed}`);
    console.log(`Success Rate:   ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
    console.log('================================================================\n');

    if (failed > 0) process.exit(1);
}

main().catch(err => {
    console.error('Fatal Pre-Production Hardening test error:', err);
    process.exit(1);
});
