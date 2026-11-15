// test-milestone-1-4.cjs
// Milestone 1.4 Verification Suite: Dynamic Database-Backed OAuth Client Registry & Exact Whitelists

const assert = require('assert');
const crypto = require('crypto');
const express = require('./auth-backend/node_modules/express');
const { ClientRegistryService } = require('./auth-backend/services/clientRegistryService');
const { createClientRegistryRouter } = require('./auth-backend/routes/clientRegistryRoutes');
const { createAuthMiddleware } = require('./auth-backend/middleware/authMiddleware');
const { createOAuthRouter } = require('./auth-backend/routes/oauthRoutes');
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
                    _key: key,
                    async get() {
                        const val = self.docs.get(key);
                        return { id, exists: val !== undefined, data: () => (val ? structuredClone(val) : undefined) };
                    },
                    async set(data, opts) {
                        if (opts && opts.merge && self.docs.has(key)) {
                            self.docs.set(key, structuredClone({ ...self.docs.get(key), ...data }));
                        } else {
                            self.docs.set(key, structuredClone(data));
                        }
                    },
                    async create(data) {
                        if (self.docs.has(key)) {
                            const err = new Error(`ALREADY_EXISTS: ${key}`);
                            err.code = 6;
                            throw err;
                        }
                        self.docs.set(key, structuredClone(data));
                    },
                    async update(patch) {
                        const cur = self.docs.get(key);
                        if (!cur) throw new Error(`Document not found: ${key}`);
                        self.docs.set(key, structuredClone({ ...cur, ...patch }));
                    },
                    collection(sub) {
                        return makeCol(`${key}/${sub}`);
                    }
                };
            },
            where(field, op, value) {
                return {
                    async get() {
                        const matched = [];
                        for (const [k, v] of self.docs.entries()) {
                            if (k.startsWith(`${prefix}/`) && !k.slice(prefix.length + 1).includes('/') && op === '==' && v[field] === value) {
                                matched.push({ id: k.slice(prefix.length + 1), exists: true, data: () => structuredClone(v) });
                            }
                        }
                        return { empty: matched.length === 0, docs: matched };
                    }
                };
            },
            async get() {
                const all = [];
                for (const [k, v] of self.docs.entries()) {
                    if (k.startsWith(`${prefix}/`) && !k.slice(prefix.length + 1).includes('/')) {
                        all.push({ id: k.slice(prefix.length + 1), exists: true, data: () => structuredClone(v) });
                    }
                }
                return { empty: all.length === 0, docs: all };
            }
        });
        return makeCol(name);
    }

    async runTransaction(fn) {
        return new Promise((resolve, reject) => {
            this.txQueue = this.txQueue.then(async () => {
                try {
                    let writeStarted = false;
                    const self = this;
                    const tx = {
                        async get(target) {
                            if (writeStarted) throw new Error('Firestore Read-Before-Write violation');
                            return await target.get();
                        },
                        set(docRef, data, opts) {
                            writeStarted = true;
                            if (opts && opts.merge && self.docs.has(docRef._key)) {
                                self.docs.set(docRef._key, structuredClone({ ...self.docs.get(docRef._key), ...data }));
                            } else {
                                self.docs.set(docRef._key, structuredClone(data));
                            }
                        },
                        update(docRef, patch) {
                            writeStarted = true;
                            const cur = self.docs.get(docRef._key);
                            if (!cur) throw new Error(`Document not found: ${docRef._key}`);
                            self.docs.set(docRef._key, structuredClone({ ...cur, ...patch }));
                        }
                    };
                    resolve(await fn(tx));
                } catch (e) {
                    reject(e);
                }
            });
        });
    }
}

async function withServer(app, fn) {
    const server = await new Promise(resolve => {
        const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    try {
        return await fn(`http://127.0.0.1:${server.address().port}`);
    } finally {
        await new Promise(resolve => server.close(resolve));
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
    console.log('================================================================');
    console.log('LANZAR ID — Milestone 1.4 Verification Suite (Dynamic Registry)');
    console.log('================================================================\n');

    await test('M1.4-01: Rejects wildcard, fragment, invalid protocol, and malformed redirect URIs', async () => {
        const db = new InMemoryFirestore();
        const registry = new ClientRegistryService(db);

        await assert.rejects(
            () => registry.registerClient({ clientId: 'bad_wc', name: 'Bad', redirectUris: ['https://*.example.com/cb'] }),
            /Wildcard redirect URIs are strictly forbidden/
        );
        await assert.rejects(
            () => registry.registerClient({ clientId: 'bad_frag', name: 'Bad', redirectUris: ['https://app.example.com/cb#frag'] }),
            /must not contain a fragment/
        );
        await assert.rejects(
            () => registry.registerClient({ clientId: 'bad_proto', name: 'Bad', redirectUris: ['javascript:alert(1)'] }),
            /Unsupported redirect URI protocol/
        );
        await assert.rejects(
            () => registry.registerClient({ clientId: 'bad_mode', name: 'Bad', redirectUris: ['https://app.example.com/cb'], compatibilityMode: 'unknown' }),
            /Unsupported compatibilityMode/
        );
    });

    await test('M1.4-02: Dual-collection persistence (/tenants/{t}/clients/{c} + /clients_index/{c}) & cross-tenant collision protection', async () => {
        const db = new InMemoryFirestore();
        const registry = new ClientRegistryService(db);

        const created = await registry.registerClient({
            tenantId: 'tenant_acme',
            clientId: 'acme_web',
            name: 'ACME Web',
            redirectUris: ['https://acme.example.com/callback', 'http://localhost:3000/callback'],
            compatibilityMode: 'oidc'
        });
        assert.strictEqual(created.clientId, 'acme_web');
        assert.strictEqual(created.tenantId, 'tenant_acme');

        // Duplicate clientId across another tenant must fail closed
        await assert.rejects(
            () => registry.registerClient({
                tenantId: 'tenant_evil',
                clientId: 'acme_web',
                name: 'Hijack',
                redirectUris: ['https://evil.example.com/cb']
            }),
            /CLIENT_ALREADY_EXISTS/
        );

        // Tenant ownership mismatch on update must fail closed
        await assert.rejects(
            () => registry.updateClient({ tenantId: 'tenant_evil', clientId: 'acme_web', patch: { enabled: false } }),
            /TENANT_OWNERSHIP_MISMATCH/
        );

        // Production resolution strips localhost URIs
        const prodView = await registry.resolveClient('acme_web', { isProduction: true });
        assert.deepStrictEqual(prodView.redirectUris, ['https://acme.example.com/callback']);
    });

    await test('M1.4-03: Strict character-for-character redirect URI matching (no trailing-slash or prefix tolerance)', async () => {
        const db = new InMemoryFirestore();
        const registry = new ClientRegistryService(db);
        await registry.registerClient({
            tenantId: 'lanzar',
            clientId: 'exact_app',
            name: 'Exact App',
            redirectUris: ['https://exact.example.com/cb'],
            compatibilityMode: 'oidc'
        });
        const client = await registry.resolveClient('exact_app', { isProduction: false });
        assert.strictEqual(registry.isRedirectUriAuthorized(client, 'https://exact.example.com/cb'), true);
        assert.strictEqual(registry.isRedirectUriAuthorized(client, 'https://exact.example.com/cb/'), false);
        assert.strictEqual(registry.isRedirectUriAuthorized(client, 'https://exact.example.com/cb/extra'), false);
    });

    await test('M1.4-04: seedApprovedInternalClients() seeds strictly portal, tickets, threadline, ai (never pythos/mothership)', async () => {
        const db = new InMemoryFirestore();
        const registry = new ClientRegistryService(db);
        const res1 = await registry.seedApprovedInternalClients();
        assert.deepStrictEqual(res1.seeded.sort(), ['ai', 'portal', 'threadline', 'tickets']);

        // Idempotent second call seeds 0
        const res2 = await registry.seedApprovedInternalClients();
        assert.deepStrictEqual(res2.seeded, []);

        assert.strictEqual(await registry.resolveClient('pythos'), null);
        assert.strictEqual(await registry.resolveClient('mothership'), null);
        assert.strictEqual((await registry.resolveClient('threadline')).compatibilityMode, 'dual');
    });

    await test('M1.4-05: Confidential client (client_secret_post) enforces hashed secret on /oauth/token', async () => {
        const db = new InMemoryFirestore();
        const registry = new ClientRegistryService(db);
        const keystore = new SigningKeystore(db);
        const oidc = new OidcTokenService({ signingKeystore: keystore, issuer: 'https://auth-api-dev.lanzar.me' });
        const codeStore = new FirestoreAuthorizationCodeStore(db);

        const secret = 'super_secret_client_credential_12345';
        const registered = await registry.registerClient({
            tenantId: 'tenant_partner',
            clientId: 'conf_partner',
            name: 'Confidential Partner',
            redirectUris: ['https://partner.example.com/oauth/cb'],
            compatibilityMode: 'oidc',
            tokenEndpointAuthMethod: 'client_secret_post',
            clientSecret: secret
        });
        assert.strictEqual(registered.clientSecretHash, undefined, 'Public view must not leak clientSecretHash');

        const app = express();
        app.use(express.json());
        app.use('/oauth', createOAuthRouter({
            db,
            authAdmin: { async verifyIdToken() { return { uid: 'u_conf', email: 'c@partner.example.com', auth_time: 1700000777 }; } },
            codeStore,
            sessionService: {},
            isUserAdmin: async () => false,
            oidcTokenService: oidc,
            clientRegistryService: registry
        }));

        await withServer(app, async (baseUrl) => {
            const verifier = 'ver_conf_' + crypto.randomBytes(16).toString('hex');
            const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
            const authRes = await (await fetch(`${baseUrl}/oauth/authorize`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    idToken: 'fb_tok',
                    client_id: 'conf_partner',
                    redirect_uri: 'https://partner.example.com/oauth/cb',
                    state: 'st_c',
                    code_challenge: challenge,
                    code_challenge_method: 'S256'
                })
            })).json();
            assert.ok(authRes.code);

            // Missing or wrong client_secret rejected (401) without redeeming code
            const noSecret = await fetch(`${baseUrl}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 'idem_conf_1234567890' },
                body: JSON.stringify({
                    grant_type: 'authorization_code',
                    code: authRes.code,
                    client_id: 'conf_partner',
                    redirect_uri: 'https://partner.example.com/oauth/cb',
                    code_verifier: verifier
                })
            });
            assert.strictEqual(noSecret.status, 401);

            // Correct client_secret succeeds
            const okTok = await fetch(`${baseUrl}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 'idem_conf_1234567890' },
                body: JSON.stringify({
                    grant_type: 'authorization_code',
                    code: authRes.code,
                    client_id: 'conf_partner',
                    client_secret: secret,
                    redirect_uri: 'https://partner.example.com/oauth/cb',
                    code_verifier: verifier
                })
            });
            assert.strictEqual(okTok.status, 200);
            const body = await okTok.json();
            assert.ok(body.access_token && body.id_token && body.refresh_token);
            assert.strictEqual(body.custom_token, undefined);
        });
    });

    await test('M1.4-06: Admin client registry API enforces admin auth and supports CRUD', async () => {
        const db = new InMemoryFirestore();
        const registry = new ClientRegistryService(db);
        const app = express();
        app.use(express.json());
        app.use('/api/admin/id', createClientRegistryRouter({
            clientRegistryService: registry,
            authenticateAdminMiddleware: (req, res, next) => {
                if (req.headers['x-test-admin'] !== 'true') {
                    return res.status(403).json({ error: 'forbidden' });
                }
                return next();
            }
        }));

        await withServer(app, async (baseUrl) => {
            const unauth = await fetch(`${baseUrl}/api/admin/id/clients`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ clientId: 'adm_app', name: 'A', redirectUris: ['https://a.example.com/cb'] })
            });
            assert.strictEqual(unauth.status, 403);

            const created = await fetch(`${baseUrl}/api/admin/id/clients`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'x-test-admin': 'true' },
                body: JSON.stringify({ clientId: 'adm_app', name: 'Admin App', redirectUris: ['https://a.example.com/cb'], compatibilityMode: 'oidc' })
            });
            assert.strictEqual(created.status, 201);

            const patched = await fetch(`${baseUrl}/api/admin/id/clients/adm_app`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json', 'x-test-admin': 'true' },
                body: JSON.stringify({ enabled: false })
            });
            assert.strictEqual(patched.status, 200);
            assert.strictEqual((await patched.json()).client.enabled, false);
        });
    });

    await test('M1.4-07: Tenant admin isolation enforced from auth claims with explicit platform_admin exception', async () => {
        const db = new InMemoryFirestore();
        const registry = new ClientRegistryService(db);
        const app = express();
        app.use(express.json());
        app.use('/api/admin/id', createClientRegistryRouter({
            clientRegistryService: registry,
            authenticateAdminMiddleware: (req, res, next) => {
                const role = req.headers['x-role'];
                if (role === 'tenant_acme') {
                    req.isAdmin = true;
                    req.user = { uid: 'adm_acme', tenantId: 'acme' };
                    return next();
                }
                if (role === 'platform_admin') {
                    req.isAdmin = true;
                    req.user = { uid: 'adm_plat', platformAdmin: true };
                    return next();
                }
                return res.status(403).json({ error: 'forbidden' });
            }
        }));

        await withServer(app, async (baseUrl) => {
            // Tenant admin creates in own tenant (without passing tenantId -> derived from req.user.tenantId)
            const acmeCreate = await fetch(`${baseUrl}/api/admin/id/clients`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'x-role': 'tenant_acme' },
                body: JSON.stringify({ clientId: 'acme_portal', name: 'Acme Portal', redirectUris: ['https://acme.example.com/cb'] })
            });
            assert.strictEqual(acmeCreate.status, 201);
            const acmeBody = await acmeCreate.json();
            assert.strictEqual(acmeBody.client.tenantId, 'acme');

            // Tenant admin blocked from creating in another tenant
            const crossCreate = await fetch(`${baseUrl}/api/admin/id/clients`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'x-role': 'tenant_acme' },
                body: JSON.stringify({ tenantId: 'beta', clientId: 'beta_app', name: 'Beta', redirectUris: ['https://beta.example.com/cb'] })
            });
            assert.strictEqual(crossCreate.status, 403);

            // Tenant admin blocked from seeding internal lanzar clients
            const crossSeed = await fetch(`${baseUrl}/api/admin/id/clients/seed-internal`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'x-role': 'tenant_acme' },
                body: JSON.stringify({ tenantId: 'lanzar' })
            });
            assert.strictEqual(crossSeed.status, 403);

            // Platform admin creates client in beta tenant
            const platCreate = await fetch(`${baseUrl}/api/admin/id/clients`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'x-role': 'platform_admin' },
                body: JSON.stringify({ tenantId: 'beta', clientId: 'beta_app', name: 'Beta', redirectUris: ['https://beta.example.com/cb'] })
            });
            assert.strictEqual(platCreate.status, 201);

            // Tenant admin blocked from reading or updating beta_app
            const crossGet = await fetch(`${baseUrl}/api/admin/id/clients/beta_app`, {
                headers: { 'x-role': 'tenant_acme' }
            });
            assert.strictEqual(crossGet.status, 403);

            const crossPatch = await fetch(`${baseUrl}/api/admin/id/clients/beta_app`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json', 'x-role': 'tenant_acme' },
                body: JSON.stringify({ tenantId: 'beta', enabled: false })
            });
            assert.strictEqual(crossPatch.status, 403);

            // Platform admin CAN read and update across tenants
            const platGet = await fetch(`${baseUrl}/api/admin/id/clients/acme_portal`, {
                headers: { 'x-role': 'platform_admin' }
            });
            assert.strictEqual(platGet.status, 200);
        });
    });

    await test('M1.4-08: Production redirect URI filtering uses parsed host/IP (HTTP/HTTPS localhost, 127.0.0.0/8, ::1, *.localhost)', async () => {
        const db = new InMemoryFirestore();
        const registry = new ClientRegistryService(db);
        await registry.registerClient({
            tenantId: 'lanzar',
            clientId: 'loopback_test',
            name: 'Loopback Test',
            redirectUris: [
                'http://localhost:3000/cb',
                'https://localhost:3000/cb',
                'http://127.0.0.1:5173/cb',
                'https://127.0.0.1/cb',
                'http://127.0.0.2:8080/cb',
                'http://[::1]:3000/cb',
                'https://[::1]/cb',
                'http://app.localhost:5173/cb',
                'https://sub.localhost/cb',
                'https://localhost./cb',
                'http://[0000:0000:0000:0000:0000:0000:0000:0001]:3000/cb',
                'https://[::ffff:127.0.0.1]/cb',
                'http://2130706433/cb',
                'https://portal.lanzar.me/cb'
            ]
        });

        const devResolved = await registry.resolveClient('loopback_test', { isProduction: false });
        assert.strictEqual(devResolved.redirectUris.length, 14);

        const prodResolved = await registry.resolveClient('loopback_test', { isProduction: true });
        assert.deepStrictEqual(prodResolved.redirectUris, ['https://portal.lanzar.me/cb']);
        assert.strictEqual(registry.isRedirectUriAuthorized(prodResolved, 'https://portal.lanzar.me/cb'), true);
        assert.strictEqual(registry.isRedirectUriAuthorized(prodResolved, 'https://portal.lanzar.me/cb/'), false);
        assert.strictEqual(registry.isRedirectUriAuthorized(prodResolved, 'https://localhost:3000/cb'), false);
        assert.strictEqual(registry.isRedirectUriAuthorized(prodResolved, 'http://[::1]:3000/cb'), false);
        assert.strictEqual(registry.isRedirectUriAuthorized(prodResolved, 'https://[::ffff:127.0.0.1]/cb'), false);
    });

    await test('M1.4-09: OAuth token endpoint enforces confidential secret on refresh_token before rotation, allows public PKCE with/without secret, and sanitizes hashes', async () => {
        const db = new InMemoryFirestore();
        const registry = new ClientRegistryService(db);
        const secret = 'conf_secret_value_at_least_32_chars_long';
        const regConf = await registry.registerClient({
            tenantId: 'lanzar',
            clientId: 'conf_refresh_app',
            name: 'Conf Refresh App',
            redirectUris: ['https://conf.example.com/cb'],
            compatibilityMode: 'oidc',
            tokenEndpointAuthMethod: 'client_secret_post',
            clientSecret: secret
        });
        assert.strictEqual(regConf.clientSecretHash, undefined);
        assert.strictEqual(regConf.clientSecret, undefined);

        await registry.registerClient({
            tenantId: 'lanzar',
            clientId: 'pub_app',
            name: 'Public App',
            redirectUris: ['https://pub.example.com/cb'],
            compatibilityMode: 'oidc',
            tokenEndpointAuthMethod: 'none'
        });

        await registry.registerClient({
            tenantId: 'lanzar',
            clientId: 'disabled_app',
            name: 'Disabled App',
            redirectUris: ['https://dis.example.com/cb'],
            compatibilityMode: 'oidc',
            enabled: false
        });

        const keystore = new SigningKeystore(db, { env: { APP_ENV: 'development', NODE_ENV: 'development' } });
        await keystore.ensureActiveSigningKey();
        const oidcTokenService = new OidcTokenService({ signingKeystore: keystore, issuer: 'https://id.lanzar.me' });
        const codeStore = new FirestoreAuthorizationCodeStore(db);
        const app = express();
        app.use(express.json());
        app.use('/oauth', createOAuthRouter({
            db,
            authAdmin: { verifyIdToken: async () => ({ uid: 'u1', email: 'u1@lanzar.me', auth_time: Math.floor(Date.now() / 1000) }) },
            codeStore,
            sessionService: {},
            isUserAdmin: async () => false,
            oidcTokenService,
            clientRegistryService: registry
        }));

        await withServer(app, async (baseUrl) => {
            // Disabled client rejected on /oauth/authorize
            const disAuth = await fetch(`${baseUrl}/oauth/authorize`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    idToken: 'tok',
                    client_id: 'disabled_app',
                    redirect_uri: 'https://dis.example.com/cb',
                    state: 's1',
                    code_challenge: 'abc',
                    code_challenge_method: 'S256'
                })
            });
            assert.strictEqual(disAuth.status, 400);

            // Confidential client: authorize -> exchange -> refresh
            const verifier = 'verifier_1234567890123456789012345678901234567890';
            const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
            const authRes = await (await fetch(`${baseUrl}/oauth/authorize`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    idToken: 'tok',
                    client_id: 'conf_refresh_app',
                    redirect_uri: 'https://conf.example.com/cb',
                    state: 's2',
                    code_challenge: challenge,
                    code_challenge_method: 'S256',
                    scope: 'openid profile email offline_access'
                })
            })).json();

            const tokRes = await (await fetch(`${baseUrl}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 'idem_m14_09_conf_12345' },
                body: JSON.stringify({
                    grant_type: 'authorization_code',
                    code: authRes.code,
                    client_id: 'conf_refresh_app',
                    redirect_uri: 'https://conf.example.com/cb',
                    code_verifier: verifier,
                    client_secret: secret
                })
            })).json();
            assert.ok(tokRes.refresh_token);

            // Refresh with WRONG secret must return 401 and MUST NOT rotate the refresh token family
            const badRefresh = await fetch(`${baseUrl}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    grant_type: 'refresh_token',
                    refresh_token: tokRes.refresh_token,
                    family_id: tokRes.family_id,
                    session_id: tokRes.session_id,
                    uid: 'u1',
                    client_id: 'conf_refresh_app',
                    client_secret: 'wrong_secret'
                })
            });
            assert.strictEqual(badRefresh.status, 401);

            // Subsequent refresh with VALID secret and original refresh_token still succeeds (proving no premature rotation)
            const goodRefresh = await fetch(`${baseUrl}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    grant_type: 'refresh_token',
                    refresh_token: tokRes.refresh_token,
                    family_id: tokRes.family_id,
                    session_id: tokRes.session_id,
                    uid: 'u1',
                    client_id: 'conf_refresh_app',
                    client_secret: secret
                })
            });
            assert.strictEqual(goodRefresh.status, 200);

            // Public client works both without and with an ignored client_secret
            for (const extraSecret of [undefined, 'ignored_public_secret']) {
                const pubAuth = await (await fetch(`${baseUrl}/oauth/authorize`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        idToken: 'tok',
                        client_id: 'pub_app',
                        redirect_uri: 'https://pub.example.com/cb',
                        state: 's_pub',
                        code_challenge: challenge,
                        code_challenge_method: 'S256'
                    })
                })).json();
                const pubTok = await fetch(`${baseUrl}/oauth/token`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Idempotency-Key': `idem_pub_${extraSecret || 'none'}_123456` },
                    body: JSON.stringify({
                        grant_type: 'authorization_code',
                        code: pubAuth.code,
                        client_id: 'pub_app',
                        redirect_uri: 'https://pub.example.com/cb',
                        code_verifier: verifier,
                        ...(extraSecret ? { client_secret: extraSecret } : {})
                    })
                });
                assert.strictEqual(pubTok.status, 200);
            }
        });
    });

    await test('M1.4-10: End-to-end authMiddleware -> clientRegistryRoutes enforces platformAdmin trust boundary and rejects impersonation/malformed tenant claims', async () => {
        const db = new InMemoryFirestore();
        const registry = new ClientRegistryService(db);
        await db.collection('admins').doc('uid_tenant_a').set({ email: 'a@t.com', active: true, tenantId: 'tenant_a' });
        await db.collection('admins').doc('uid_malformed').set({ email: 'm@t.com', active: true, tenantId: '../evil' });
        await db.collection('admins').doc('uid_missing_tenant').set({ email: 'l@t.com', active: true });
        await db.collection('admins').doc('uid_plat').set({ email: 'p@t.com', active: true, role: 'platform_admin' });

        const authMiddleware = createAuthMiddleware({
            db,
            authAdmin: {
                verifyIdToken: async (tok) => {
                    const map = {
                        tok_a: { uid: 'uid_tenant_a', email: 'a@t.com', session_id: 's_a' },
                        tok_mal: { uid: 'uid_malformed', email: 'm@t.com', session_id: 's_m' },
                        tok_miss: { uid: 'uid_missing_tenant', email: 'l@t.com', session_id: 's_l' },
                        tok_plat: { uid: 'uid_plat', email: 'p@t.com', session_id: 's_p' }
                    };
                    return map[tok];
                }
            },
            sessionService: { checkSession: async () => ({ active: true }) }
        });

        const app = express();
        app.use(express.json());
        app.use('/api/admin/id', createClientRegistryRouter({
            clientRegistryService: registry,
            authenticateAdminMiddleware: authMiddleware.authenticateAdminMiddleware
        }));

        await withServer(app, async (baseUrl) => {
            // Platform admin registers client in tenant_b
            const platReg = await fetch(`${baseUrl}/api/admin/id/clients`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok_plat' },
                body: JSON.stringify({ tenantId: 'tenant_b', clientId: 'tb_app', name: 'TB', redirectUris: ['https://tb.example.com/cb'] })
            });
            assert.strictEqual(platReg.status, 201);

            // Tenant A cannot impersonate platform admin via headers or body
            const impPost = await fetch(`${baseUrl}/api/admin/id/clients`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok_a', 'x-admin-role': 'platform_admin' },
                body: JSON.stringify({ tenantId: 'tenant_b', platformAdmin: true, clientId: 'tb_hijack', name: 'H', redirectUris: ['https://tb.example.com/cb'] })
            });
            assert.strictEqual(impPost.status, 403);

            // Tenant A cannot read or update Tenant B's client
            assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/clients/tb_app`, { headers: { Authorization: 'Bearer tok_a' } })).status, 403);
            assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/clients/tb_app`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok_a' },
                body: JSON.stringify({ tenantId: 'tenant_b', enabled: false })
            })).status, 403);

            // Tenant A cannot seed Tenant B or lanzar
            assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/clients/seed-internal`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok_a' },
                body: JSON.stringify({ tenantId: 'tenant_b' })
            })).status, 403);

            // Malformed tenant claim fails closed with 403 even for own request
            assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/clients`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok_mal' },
                body: JSON.stringify({ clientId: 'evil_app', name: 'E', redirectUris: ['https://e.example.com/cb'] })
            })).status, 403);

            // Missing tenant claim (non-platform admin) is scoped to lanzar and cannot access tenant_b
            assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/clients/tb_app`, {
                headers: { Authorization: 'Bearer tok_miss' }
            })).status, 403);

            // Platform admin CAN read and update Tenant B's client
            assert.strictEqual((await fetch(`${baseUrl}/api/admin/id/clients/tb_app`, {
                headers: { Authorization: 'Bearer tok_plat' }
            })).status, 200);
        });
    });

    console.log('\n================================================================');
    console.log('MILESTONE 1.4 VERIFICATION SUMMARY');
    console.log(`Total Executed: ${passed + failed}`);
    console.log(`Passed:         ${passed}`);
    console.log(`Failed:         ${failed}`);
    console.log(`Success Rate:   ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
    console.log('================================================================\n');

    if (failed > 0) process.exit(1);
}

main().catch(err => {
    console.error('Fatal Milestone 1.4 test error:', err);
    process.exit(1);
});
