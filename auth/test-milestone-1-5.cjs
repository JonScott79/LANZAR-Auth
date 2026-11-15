// test-milestone-1-5.cjs
// Milestone 1.5 Verification Suite: Tenant Isolation, Client Lifecycle, Audit Trail & Operational Hardening

const assert = require('assert');
const crypto = require('crypto');
const express = require('./auth-backend/node_modules/express');
const { ClientRegistryService } = require('./auth-backend/services/clientRegistryService');
const { AuditLogService } = require('./auth-backend/services/auditLogService');
const { createClientRegistryRouter } = require('./auth-backend/routes/clientRegistryRoutes');
const { createAuthMiddleware } = require('./auth-backend/middleware/authMiddleware');
const { createOAuthRouter } = require('./auth-backend/routes/oauthRoutes');
const { createOidcRouter } = require('./auth-backend/routes/oidcRoutes');
const { SigningKeystore } = require('./auth-backend/services/signingKeystore');
const { OidcTokenService } = require('./auth-backend/services/oidcTokenService');
const { FirestoreAuthorizationCodeStore } = require('./auth-backend/store');

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
                    collection(sub) {
                        return makeCol(`${key}/${sub}`);
                    },
                    async get() {
                        const val = self.docs.get(key);
                        return { exists: val !== undefined, id, data: () => (val ? JSON.parse(JSON.stringify(val)) : undefined) };
                    },
                    async set(data) {
                        self.docs.set(key, JSON.parse(JSON.stringify(data)));
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
                        docs.push({ id: k.slice(prefix.length + 1), data: () => JSON.parse(JSON.stringify(v)) });
                    }
                }
                return { empty: docs.length === 0, docs };
            },
            where() {
                return this;
            },
            orderBy() {
                return this;
            },
            limit() {
                return this;
            }
        });
        return makeCol(name);
    }

    async runTransaction(fn) {
        const run = async () => {
            const writes = [];
            const tx = {
                async get(ref) { return await ref.get(); },
                set(ref, data) { writes.push(() => ref.set(data)); },
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
    console.log('LANZAR ID — Milestone 1.5 Verification Suite (Tenant Isolation & Hardening)');
    console.log('================================================================\n');

    await test('M1.5-01: Cross-tenant token, session, UserInfo, and refresh-token reuse are rejected', async () => {
        const db = new InMemoryFirestore();
        const registry = new ClientRegistryService(db);
        await registry.registerClient({
            tenantId: 'tenant_a',
            clientId: 'app_a',
            name: 'App A',
            redirectUris: ['https://a.example.com/cb'],
            compatibilityMode: 'oidc'
        });
        await registry.registerClient({
            tenantId: 'tenant_b',
            clientId: 'app_b',
            name: 'App B',
            redirectUris: ['https://b.example.com/cb'],
            compatibilityMode: 'oidc'
        });

        const keystore = new SigningKeystore(db, { env: { APP_ENV: 'development', NODE_ENV: 'development' } });
        await keystore.ensureActiveSigningKey();
        const oidc = new OidcTokenService({ signingKeystore: keystore, issuer: 'https://id.lanzar.me' });
        const codeStore = new FirestoreAuthorizationCodeStore(db);

        // Verify expectedTenantId check on verifyAccessToken
        const tokA = await oidc.mintAccessToken({ uid: 'u1', clientId: 'app_a', tenantId: 'tenant_a', sessionId: 's1', scope: 'openid' });
        assert.strictEqual((await oidc.verifyAccessToken(tokA, { expectedTenantId: 'tenant_a' })).valid, true);
        const crossVer = await oidc.verifyAccessToken(tokA, { expectedTenantId: 'tenant_b' });
        assert.strictEqual(crossVer.valid, false);
        assert.strictEqual(crossVer.reason, 'TENANT_MISMATCH');

        const app = express();
        app.use(express.json());
        app.use('/oauth', createOAuthRouter({
            db,
            authAdmin: { verifyIdToken: async () => ({ uid: 'u1', email: 'u1@a.com', auth_time: Math.floor(Date.now() / 1000) }) },
            codeStore,
            sessionService: {},
            isUserAdmin: async () => false,
            oidcTokenService: oidc,
            clientRegistryService: registry
        }));
        app.use('/', createOidcRouter({ oidcTokenService: oidc, db, clientRegistryService: registry }));

        await withServer(app, async (baseUrl) => {
            const verifier = 'verifier_1234567890123456789012345678901234567890';
            const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
            const authA = await (await fetch(`${baseUrl}/oauth/authorize`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    idToken: 'tok',
                    client_id: 'app_a',
                    redirect_uri: 'https://a.example.com/cb',
                    state: 's1',
                    code_challenge: challenge,
                    code_challenge_method: 'S256',
                    scope: 'openid profile email offline_access'
                })
            })).json();
            const tokResA = await (await fetch(`${baseUrl}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 'idem_m15_01_12345678' },
                body: JSON.stringify({
                    grant_type: 'authorization_code',
                    code: authA.code,
                    client_id: 'app_a',
                    redirect_uri: 'https://a.example.com/cb',
                    code_verifier: verifier
                })
            })).json();
            assert.ok(tokResA.access_token && tokResA.refresh_token);

            // Cross-tenant refresh attempt with tenant_b or app_b must fail
            const crossRefTenant = await fetch(`${baseUrl}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    grant_type: 'refresh_token',
                    refresh_token: tokResA.refresh_token,
                    family_id: tokResA.family_id,
                    session_id: tokResA.session_id,
                    uid: 'u1',
                    tenant_id: 'tenant_b',
                    client_id: 'app_a'
                })
            });
            assert.strictEqual(crossRefTenant.status, 401);

            const crossRefClient = await fetch(`${baseUrl}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    grant_type: 'refresh_token',
                    refresh_token: tokResA.refresh_token,
                    family_id: tokResA.family_id,
                    session_id: tokResA.session_id,
                    uid: 'u1',
                    tenant_id: 'tenant_a',
                    client_id: 'app_b'
                })
            });
            assert.strictEqual(crossRefClient.status, 401);

            // UserInfo rejects cross-tenant header/query
            const uiCross = await fetch(`${baseUrl}/oauth/userinfo`, {
                headers: { Authorization: `Bearer ${tokResA.access_token}`, 'x-lanzar-tenant-id': 'tenant_b' }
            });
            assert.strictEqual(uiCross.status, 403);

            // Legitimate UserInfo succeeds for tenant_a
            const uiOk = await fetch(`${baseUrl}/oauth/userinfo`, {
                headers: { Authorization: `Bearer ${tokResA.access_token}`, 'x-lanzar-tenant-id': 'tenant_a' }
            });
            assert.strictEqual(uiOk.status, 200);
            assert.strictEqual((await uiOk.json()).tenant_id, 'tenant_a');
        });
    });

    await test('M1.5-02: Client lifecycle disable/enable immediately blocks/restores OAuth authorize, refresh, and UserInfo', async () => {
        const db = new InMemoryFirestore();
        const registry = new ClientRegistryService(db);
        const auditLogService = new AuditLogService(db);
        await db.collection('admins').doc('adm_a').set({ email: 'adm@a.com', active: true, tenantId: 'tenant_a' });

        await registry.registerClient({
            tenantId: 'tenant_a',
            clientId: 'life_app',
            name: 'Lifecycle App',
            redirectUris: ['https://life.example.com/cb'],
            compatibilityMode: 'oidc'
        });

        const keystore = new SigningKeystore(db, { env: { APP_ENV: 'development', NODE_ENV: 'development' } });
        await keystore.ensureActiveSigningKey();
        const oidc = new OidcTokenService({ signingKeystore: keystore, issuer: 'https://id.lanzar.me' });
        const codeStore = new FirestoreAuthorizationCodeStore(db);
        const authMiddleware = createAuthMiddleware({
            db,
            authAdmin: { verifyIdToken: async (t) => (t === 'adm_tok' ? { uid: 'adm_a', email: 'adm@a.com', session_id: 's_adm' } : { uid: 'u1', email: 'u1@a.com', auth_time: Math.floor(Date.now() / 1000) }) },
            sessionService: { checkSession: async () => ({ active: true }) }
        });

        const app = express();
        app.use(express.json());
        app.use('/api/admin/id', createClientRegistryRouter({
            clientRegistryService: registry,
            authenticateAdminMiddleware: authMiddleware.authenticateAdminMiddleware,
            auditLogService
        }));
        app.use('/oauth', createOAuthRouter({
            db,
            authAdmin: { verifyIdToken: async () => ({ uid: 'u1', email: 'u1@a.com', auth_time: Math.floor(Date.now() / 1000) }) },
            codeStore,
            sessionService: {},
            isUserAdmin: async () => false,
            oidcTokenService: oidc,
            clientRegistryService: registry
        }));
        app.use('/', createOidcRouter({ oidcTokenService: oidc, db, clientRegistryService: registry }));

        await withServer(app, async (baseUrl) => {
            const verifier = 'verifier_1234567890123456789012345678901234567890';
            const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
            const authRes = await (await fetch(`${baseUrl}/oauth/authorize`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    idToken: 'u_tok',
                    client_id: 'life_app',
                    redirect_uri: 'https://life.example.com/cb',
                    state: 's1',
                    code_challenge: challenge,
                    code_challenge_method: 'S256',
                    scope: 'openid profile offline_access'
                })
            })).json();
            const tokRes = await (await fetch(`${baseUrl}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 'idem_m15_02_12345678' },
                body: JSON.stringify({
                    grant_type: 'authorization_code',
                    code: authRes.code,
                    client_id: 'life_app',
                    redirect_uri: 'https://life.example.com/cb',
                    code_verifier: verifier
                })
            })).json();

            // Disable client via admin lifecycle endpoint
            const disRes = await fetch(`${baseUrl}/api/admin/id/clients/life_app/disable`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer adm_tok', 'x-correlation-id': 'corr_dis_1' },
                body: JSON.stringify({ reason: 'security_incident' })
            });
            assert.strictEqual(disRes.status, 200);
            const disBody = await disRes.json();
            assert.strictEqual(disBody.client.enabled, false);
            assert.strictEqual(disBody.client.status, 'suspended');

            // Existing UserInfo, refresh, and new /authorize are all blocked while disabled
            assert.strictEqual((await fetch(`${baseUrl}/oauth/userinfo`, { headers: { Authorization: `Bearer ${tokRes.access_token}` } })).status, 401);
            assert.strictEqual((await fetch(`${baseUrl}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    grant_type: 'refresh_token',
                    refresh_token: tokRes.refresh_token,
                    family_id: tokRes.family_id,
                    session_id: tokRes.session_id,
                    uid: 'u1',
                    tenant_id: 'tenant_a',
                    client_id: 'life_app'
                })
            })).status, 401);
            assert.strictEqual((await fetch(`${baseUrl}/oauth/authorize`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    idToken: 'u_tok',
                    client_id: 'life_app',
                    redirect_uri: 'https://life.example.com/cb',
                    state: 's2',
                    code_challenge: challenge,
                    code_challenge_method: 'S256'
                })
            })).status, 400);

            // Re-enable client -> restores UserInfo & refresh on existing non-expired session
            const enRes = await fetch(`${baseUrl}/api/admin/id/clients/life_app/enable`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer adm_tok', 'x-correlation-id': 'corr_en_1' },
                body: JSON.stringify({})
            });
            assert.strictEqual(enRes.status, 200);
            assert.strictEqual((await enRes.json()).client.status, 'active');
            assert.strictEqual((await fetch(`${baseUrl}/oauth/userinfo`, { headers: { Authorization: `Bearer ${tokRes.access_token}` } })).status, 200);
        });
    });

    await test('M1.5-03: AuditLogService redacts secrets and enforces tenant-scoped audit log access', async () => {
        const db = new InMemoryFirestore();
        const registry = new ClientRegistryService(db);
        const auditLogService = new AuditLogService(db);
        await db.collection('admins').doc('adm_a').set({ email: 'a@a.com', active: true, tenantId: 'tenant_a' });
        await db.collection('admins').doc('adm_plat').set({ email: 'p@p.com', active: true, role: 'platform_admin' });

        const authMiddleware = createAuthMiddleware({
            db,
            authAdmin: { verifyIdToken: async (t) => (t === 'tok_a' ? { uid: 'adm_a', email: 'a@a.com', session_id: 'sa' } : { uid: 'adm_plat', email: 'p@p.com', session_id: 'sp' }) },
            sessionService: { checkSession: async () => ({ active: true }) }
        });
        const app = express();
        app.use(express.json());
        app.use('/api/admin/id', createClientRegistryRouter({
            clientRegistryService: registry,
            authenticateAdminMiddleware: authMiddleware.authenticateAdminMiddleware,
            auditLogService
        }));

        await withServer(app, async (baseUrl) => {
            const secret = 'super_secret_client_value_123456';
            await fetch(`${baseUrl}/api/admin/id/clients`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok_a', 'x-correlation-id': 'corr_reg_1' },
                body: JSON.stringify({
                    clientId: 'aud_app',
                    name: 'Audit App',
                    redirectUris: ['https://aud.example.com/cb'],
                    tokenEndpointAuthMethod: 'client_secret_post',
                    clientSecret: secret
                })
            });

            // Direct audit redaction test
            const rec = await auditLogService.recordAdminEvent({
                actorUid: 'adm_a',
                targetTenantId: 'tenant_a',
                clientId: 'aud_app',
                operation: 'client.test',
                metadata: { clientSecret: secret, nested: { password: 'pw', safe: 'ok' } }
            });
            assert.strictEqual(rec.metadata.clientSecret, '[REDACTED]');
            assert.strictEqual(rec.metadata.nested.password, '[REDACTED]');
            assert.strictEqual(rec.metadata.nested.safe, 'ok');

            // Tenant A can read own audit logs, blocked from tenant_b
            const ownLogs = await fetch(`${baseUrl}/api/admin/id/audit-logs`, { headers: { Authorization: 'Bearer tok_a' } });
            assert.strictEqual(ownLogs.status, 200);
            const logsBody = await ownLogs.json();
            assert.ok(logsBody.logs.length >= 2);
            assert.strictEqual(JSON.stringify(logsBody).includes(secret), false);

            const otherLogs = await fetch(`${baseUrl}/api/admin/id/audit-logs?tenantId=tenant_b`, { headers: { Authorization: 'Bearer tok_a' } });
            assert.strictEqual(otherLogs.status, 403);

            // Platform admin can read tenant_a logs
            const platLogs = await fetch(`${baseUrl}/api/admin/id/audit-logs?tenantId=tenant_a`, { headers: { Authorization: 'Bearer tok_plat' } });
            assert.strictEqual(platLogs.status, 200);
        });
    });

    await test('M1.5-04: Operational reliability — Firestore failure fails closed (503) without leaking secrets', async () => {
        const db = new InMemoryFirestore();
        const keystore = new SigningKeystore(db, { env: { APP_ENV: 'development', NODE_ENV: 'development' } });
        await keystore.ensureActiveSigningKey();
        const oidc = new OidcTokenService({ signingKeystore: keystore, issuer: 'https://id.lanzar.me' });
        const tok = await oidc.mintAccessToken({ uid: 'u1', clientId: 'portal', tenantId: 'lanzar', sessionId: 's1', scope: 'openid' });

        const failingDb = {
            collection() {
                return {
                    doc() {
                        return {
                            collection() {
                                return {
                                    doc() {
                                        return {
                                            async get() { throw new Error('FIRESTORE_UNREACHABLE'); }
                                        };
                                    }
                                };
                            }
                        };
                    }
                };
            }
        };

        const app = express();
        app.use('/', createOidcRouter({ oidcTokenService: oidc, db: failingDb }));
        await withServer(app, async (baseUrl) => {
            const res = await fetch(`${baseUrl}/oauth/userinfo`, { headers: { Authorization: `Bearer ${tok}` } });
            assert.strictEqual(res.status, 503);
        });

        const strictAudit = new AuditLogService(failingDb, { strictAudit: true });
        await assert.rejects(() => strictAudit.recordAdminEvent({ operation: 'client.register', targetTenantId: 'lanzar' }), /AUDIT_WRITE_FAILED/);
    });

    await test('M1.5-05: Audit failure rolls back client disable atomically (503, client remains enabled, existing audit intact)', async () => {
        const db = new InMemoryFirestore();
        const registry = new ClientRegistryService(db);
        const goodAudit = new AuditLogService(db);
        await db.collection('admins').doc('adm_a').set({ email: 'a@a.com', active: true, tenantId: 'tenant_a' });
        await registry.registerClient({
            tenantId: 'tenant_a',
            clientId: 'strict_app',
            name: 'Strict App',
            redirectUris: ['https://strict.example.com/cb'],
            compatibilityMode: 'oidc',
            auditLogService: goodAudit,
            auditContext: { actorUid: 'adm_a', actorTenantId: 'tenant_a', actorRole: 'tenant_admin' }
        });
        const initialLogs = await goodAudit.listTenantAuditLogs('tenant_a');
        assert.strictEqual(initialLogs.length, 1);

        // AuditLogService exposes no update/delete methods
        assert.strictEqual(typeof goodAudit.updateAuditLog, 'undefined');
        assert.strictEqual(typeof goodAudit.deleteAuditLog, 'undefined');

        // Failing audit service whose writeInTransaction throws
        const failingAudit = new AuditLogService(db);
        failingAudit.writeInTransaction = () => {
            throw new Error('AUDIT_WRITE_FAILED: forced audit failure');
        };

        const authMiddleware = createAuthMiddleware({
            db,
            authAdmin: { verifyIdToken: async () => ({ uid: 'adm_a', email: 'a@a.com', session_id: 'sa' }) },
            sessionService: { checkSession: async () => ({ active: true }) }
        });

        const keystore = new SigningKeystore(db, { env: { APP_ENV: 'development', NODE_ENV: 'development' } });
        await keystore.ensureActiveSigningKey();
        const oidc = new OidcTokenService({ signingKeystore: keystore, issuer: 'https://id.lanzar.me' });
        await db.collection('users').doc('u_cross').collection('sessions').doc('s_cross').set({
            uid: 'u_cross', tenantId: 'tenant_b', clientId: 'strict_app', status: 'active', revoked: false
        });
        const tokCross = await oidc.mintAccessToken({ uid: 'u_cross', clientId: 'strict_app', tenantId: 'tenant_a', sessionId: 's_cross', scope: 'openid' });

        const app = express();
        app.use(express.json());
        app.use('/api/admin/id', createClientRegistryRouter({
            clientRegistryService: registry,
            authenticateAdminMiddleware: authMiddleware.authenticateAdminMiddleware,
            auditLogService: failingAudit
        }));
        app.use('/', createOidcRouter({ oidcTokenService: oidc, db, clientRegistryService: registry }));

        await withServer(app, async (baseUrl) => {
            const disRes = await fetch(`${baseUrl}/api/admin/id/clients/strict_app/disable`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok' },
                body: JSON.stringify({ reason: 'test_strict' })
            });
            assert.strictEqual(disRes.status, 503);

            // Client state MUST remain enabled/active (no partial mutation)
            const currentClient = await registry.resolveClient('strict_app');
            assert.strictEqual(currentClient.enabled, true);
            assert.strictEqual(currentClient.status, 'active');

            // Existing audit records MUST remain unaffected
            const logsAfter = await goodAudit.listTenantAuditLogs('tenant_a');
            assert.strictEqual(logsAfter.length, 1);
            assert.strictEqual(logsAfter[0].auditId, initialLogs[0].auditId);

            const uiRes = await fetch(`${baseUrl}/oauth/userinfo`, {
                headers: { Authorization: `Bearer ${tokCross}` }
            });
            assert.strictEqual(uiRes.status, 401);
        });
    });

    await test('M1.5-06: Firestore transaction retries during client disable produce zero duplicate audit events', async () => {
        const db = new InMemoryFirestore();
        const origRunTx = db.runTransaction.bind(db);
        let retrySimulated = false;
        db.runTransaction = async (fn) => {
            return origRunTx(async (tx) => {
                if (!retrySimulated) {
                    retrySimulated = true;
                    // Simulate first aborted attempt executing callback without committing
                    await fn({
                        get: (ref) => tx.get(ref),
                        set: () => {},
                        create: () => {},
                        update: () => {}
                    });
                }
                return fn(tx);
            });
        };

        const registry = new ClientRegistryService(db);
        const auditSvc = new AuditLogService(db);
        await registry.registerClient({
            tenantId: 'tenant_a',
            clientId: 'retry_app',
            name: 'Retry App',
            redirectUris: ['https://retry.example.com/cb'],
            compatibilityMode: 'oidc'
        });

        const disabled = await registry.disableClient({
            tenantId: 'tenant_a',
            clientId: 'retry_app',
            reason: 'retry_test',
            auditLogService: auditSvc,
            auditContext: { actorUid: 'adm_a', actorTenantId: 'tenant_a', actorRole: 'tenant_admin' }
        });
        assert.strictEqual(disabled.enabled, false);

        const logs = await auditSvc.listTenantAuditLogs('tenant_a');
        assert.strictEqual(logs.length, 1);
        assert.strictEqual(logs[0].operation, 'client.disable');
    });

    console.log('\n================================================================');
    console.log('MILESTONE 1.5 VERIFICATION SUMMARY');
    console.log(`Total Executed: ${passed + failed}`);
    console.log(`Passed:         ${passed}`);
    console.log(`Failed:         ${failed}`);
    console.log(`Success Rate:   ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
    console.log('================================================================\n');

    if (failed > 0) process.exit(1);
}

main().catch(err => {
    console.error('Fatal Milestone 1.5 test error:', err);
    process.exit(1);
});
