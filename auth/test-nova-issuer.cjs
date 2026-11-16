// test-nova-issuer.cjs
// NOVA Issuer Architecture, Discovery, Decoupled API Endpoints, and Cross-Environment Isolation Suite.

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { bootstrap } = require('./auth-backend/config/bootstrap');
const { createApp } = require('./auth-backend/app');
const { SigningKeystore } = require('./auth-backend/services/signingKeystore');
const { OidcTokenService } = require('./auth-backend/services/oidcTokenService');

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
                            self.docs.set(key, { ...(self.docs.get(key) || {}), ...cloned });
                        } else {
                            self.docs.set(key, cloned);
                        }
                    },
                    async create(data) {
                        if (self.docs.has(key)) throw new Error(`ALREADY_EXISTS: ${key}`);
                        self.docs.set(key, JSON.parse(JSON.stringify(data)));
                    },
                    async update(patch) {
                        const cur = self.docs.get(key);
                        if (!cur) throw new Error(`NOT_FOUND: ${key}`);
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
    try {
        return await fn(`http://127.0.0.1:${port}`);
    } finally {
        await new Promise((resolve) => server.close(resolve));
    }
}

function makeEnv(appEnv, overrides = {}) {
    const isProd = appEnv === 'production';
    const projectId = isProd ? 'lanzar-95ae3' : 'lanzar-95ae3-dev';
    return {
        APP_ENV: appEnv,
        NODE_ENV: appEnv,
        FIREBASE_PROJECT_ID: projectId,
        FIREBASE_SERVICE_ACCOUNT_KEY: JSON.stringify({
            type: 'service_account',
            project_id: projectId,
            client_email: `sa@${projectId}.iam.gserviceaccount.com`,
            private_key: 'test'
        }),
        SESSION_SIGNING_SECRET: 'a'.repeat(32),
        MFA_HMAC_SECRET: 'b'.repeat(32),
        FEATURE_STRIPE: 'disabled',
        ...overrides
    };
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
    console.log('LANZAR ID — NOVA Issuer Architecture Verification Suite');
    console.log('================================================================\n');

    await test('NOVA-01: Production issuer and discovery endpoints remain unchanged', async () => {
        const prodCfg = bootstrap(makeEnv('production'));
        assert.strictEqual(prodCfg.oidcIssuer, 'https://auth.lanzar.me');
        assert.strictEqual(prodCfg.apiBaseUrl, 'https://auth-api.lanzar.me');

        const db = new InMemoryFirestore();
        const keystore = new SigningKeystore(db);
        const { app } = createApp({ config: prodCfg, db, authAdmin: {}, services: { signingKeystore: keystore } });
        await withServer(app, async (baseUrl) => {
            const disc = await (await fetch(`${baseUrl}/.well-known/openid-configuration`)).json();
            assert.strictEqual(disc.issuer, 'https://auth.lanzar.me');
            assert.strictEqual(disc.jwks_uri, 'https://auth-api.lanzar.me/.well-known/jwks.json');
            assert.strictEqual(disc.token_endpoint, 'https://auth-api.lanzar.me/oauth/token');
            assert.strictEqual(disc.userinfo_endpoint, 'https://auth-api.lanzar.me/oauth/userinfo');
            assert.strictEqual((await fetch(`${baseUrl}/nova/.well-known/openid-configuration`)).status, 404);
        });
    });

    await test('NOVA-02: NOVA staging advertises decoupled issuer (auth.lanzar.me/nova) and API endpoints (auth-api-nova.lanzar.me)', async () => {
        const novaCfg = bootstrap(makeEnv('staging', { OIDC_ISSUER: 'https://auth.lanzar.me/nova' }));
        assert.strictEqual(novaCfg.oidcIssuer, 'https://auth.lanzar.me/nova');
        assert.strictEqual(novaCfg.apiBaseUrl, 'https://auth-api-nova.lanzar.me');

        const db = new InMemoryFirestore();
        const keystore = new SigningKeystore(db);
        const { app } = createApp({ config: novaCfg, db, authAdmin: {}, services: { signingKeystore: keystore } });
        await withServer(app, async (baseUrl) => {
            for (const p of ['/.well-known/openid-configuration', '/nova/.well-known/openid-configuration']) {
                const res = await fetch(`${baseUrl}${p}`);
                assert.strictEqual(res.status, 200);
                const disc = await res.json();
                assert.strictEqual(disc.issuer, 'https://auth.lanzar.me/nova');
                assert.strictEqual(disc.jwks_uri, 'https://auth-api-nova.lanzar.me/.well-known/jwks.json');
                assert.strictEqual(disc.token_endpoint, 'https://auth-api-nova.lanzar.me/oauth/token');
                assert.strictEqual(disc.userinfo_endpoint, 'https://auth-api-nova.lanzar.me/oauth/userinfo');
                assert.strictEqual(disc.authorization_endpoint, 'https://auth-api-nova.lanzar.me/oauth/authorize');
            }
            const jwksRes = await fetch(`${baseUrl}/.well-known/jwks.json`);
            assert.strictEqual(jwksRes.status, 200);
            const jwks = await jwksRes.json();
            assert.ok(Array.isArray(jwks.keys) && jwks.keys.length >= 1);
        });
    });

    await test('NOVA-03: Minted JWT iss matches configured issuer and cross-environment tokens are rejected', async () => {
        const prodDb = new InMemoryFirestore();
        const novaDb = new InMemoryFirestore();
        const prodKs = new SigningKeystore(prodDb);
        const novaKs = new SigningKeystore(novaDb);

        const prodOidc = new OidcTokenService({ signingKeystore: prodKs, issuer: 'https://auth.lanzar.me', apiBaseUrl: 'https://auth-api.lanzar.me' });
        const novaOidc = new OidcTokenService({ signingKeystore: novaKs, issuer: 'https://auth.lanzar.me/nova', apiBaseUrl: 'https://auth-api-nova.lanzar.me' });

        const prodTok = await prodOidc.mintAccessToken({ uid: 'u1', clientId: 'portal', tenantId: 'lanzar', sessionId: 's1', familyId: 'f1' });
        const novaTok = await novaOidc.mintAccessToken({ uid: 'u1', clientId: 'portal', tenantId: 'lanzar', sessionId: 's1', familyId: 'f1' });

        const prodVer = await prodOidc.verifyAccessToken(prodTok, { expectedAudience: prodOidc.getUserinfoAudience() });
        assert.strictEqual(prodVer.valid, true);
        assert.strictEqual(prodVer.payload.iss, 'https://auth.lanzar.me');

        const novaVer = await novaOidc.verifyAccessToken(novaTok, { expectedAudience: novaOidc.getUserinfoAudience() });
        assert.strictEqual(novaVer.valid, true);
        assert.strictEqual(novaVer.payload.iss, 'https://auth.lanzar.me/nova');

        // Cross-environment rejection (different signing keys AND different issuer/audience)
        assert.strictEqual((await novaOidc.verifyAccessToken(prodTok)).valid, false);
        assert.strictEqual((await prodOidc.verifyAccessToken(novaTok)).valid, false);

        // Even with shared keystore, issuer mismatch rejects cross-environment tokens
        const sharedNova = new OidcTokenService({ signingKeystore: prodKs, issuer: 'https://auth.lanzar.me/nova', apiBaseUrl: 'https://auth-api-nova.lanzar.me' });
        const crossIss = await sharedNova.verifyAccessToken(prodTok);
        assert.strictEqual(crossIss.valid, false);
        assert.strictEqual(crossIss.reason, 'INVALID_ISSUER');
    });

    await test('NOVA-04: Invalid, uppercase /NOVA, non-HTTPS, or cross-env OIDC_ISSUER fails closed at bootstrap', async () => {
        assert.throws(() => bootstrap(makeEnv('staging', { OIDC_ISSUER: 'http://auth.lanzar.me/nova' })));
        assert.throws(() => bootstrap(makeEnv('staging', { OIDC_ISSUER: 'https://auth.lanzar.me/NOVA' })));
        assert.throws(() => bootstrap(makeEnv('staging', { OIDC_ISSUER: 'https://auth.lanzar.me/nova?x=1' })));
        assert.throws(() => bootstrap(makeEnv('staging', { OIDC_ISSUER: 'https://auth.lanzar.me' })));
        assert.throws(() => bootstrap(makeEnv('production', { OIDC_ISSUER: 'https://auth.lanzar.me/nova' })));
    });

    await test('NOVA-05: Frontend hosting configs (netlify.toml & vercel.json) proxy /nova/.well-known/* above SPA catch-all', async () => {
        const netlifyToml = fs.readFileSync(path.join(__dirname, 'netlify.toml'), 'utf8');
        const vercelJson = JSON.parse(fs.readFileSync(path.join(__dirname, 'vercel.json'), 'utf8'));
        assert.ok(netlifyToml.indexOf('/nova/.well-known/openid-configuration') < netlifyToml.indexOf('from = "/*"'));
        assert.ok(netlifyToml.includes('https://auth-api-nova.lanzar.me/nova/.well-known/openid-configuration'));
        assert.strictEqual(vercelJson.rewrites[0].source, '/nova/.well-known/openid-configuration');
        assert.strictEqual(vercelJson.rewrites[vercelJson.rewrites.length - 1].source, '/(.*)');
    });

    console.log('\n================================================================');
    console.log('NOVA ISSUER VERIFICATION SUMMARY');
    console.log(`Total Executed: ${passed + failed}`);
    console.log(`Passed:         ${passed}`);
    console.log(`Failed:         ${failed}`);
    console.log(`Success Rate:   ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
    console.log('================================================================\n');
    if (failed > 0) process.exit(1);
}

main().catch(err => {
    console.error('Fatal NOVA Issuer test error:', err);
    process.exit(1);
});
