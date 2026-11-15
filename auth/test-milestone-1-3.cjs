// test-milestone-1-3.cjs
// Milestone 1.3 Verification Suite: Standards-Compliant OIDC Token Engine & Scoped Compatibility Adapter

const assert = require('assert');
const crypto = require('crypto');
const express = require('./auth-backend/node_modules/express');
const { SigningKeystore } = require('./auth-backend/services/signingKeystore');
const { OidcTokenService, ACCESS_TOKEN_TTL_SECONDS } = require('./auth-backend/services/oidcTokenService');
const { createJwksRouter } = require('./auth-backend/routes/jwksRoutes');
const { createOidcRouter } = require('./auth-backend/routes/oidcRoutes');
const { createOAuthRouter } = require('./auth-backend/routes/oauthRoutes');
const { FirestoreAuthorizationCodeStore } = require('./auth-backend/store');
const { getClient } = require('./auth-backend/clients');

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

function sha256Base64Url(input) {
    return crypto.createHash('sha256').update(input).digest('base64url');
}

function decodeJwtPart(jwt, index) {
    return JSON.parse(Buffer.from(jwt.split('.')[index], 'base64url').toString('utf8'));
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

async function withServer(app, fn) {
    const server = await new Promise(resolve => {
        const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    try {
        const baseUrl = `http://127.0.0.1:${server.address().port}`;
        return await fn(baseUrl);
    } finally {
        await new Promise(resolve => server.close(resolve));
    }
}

async function main() {
    console.log('================================================================');
    console.log('LANZAR ID — Milestone 1.3 Verification Suite (OIDC & Adapter)');
    console.log('================================================================\n');

    await test('M1.3-01: OIDC Discovery (/.well-known/openid-configuration) returns metadata and fails closed 503 when unavailable', async () => {
        const db = new InMemoryFirestore();
        const keystore = new SigningKeystore(db);
        const oidc = new OidcTokenService({ signingKeystore: keystore, issuer: 'https://auth-api-dev.lanzar.me' });

        const app = express();
        app.use('/', createOidcRouter({ oidcTokenService: oidc, db }));
        await withServer(app, async (baseUrl) => {
            const resp = await fetch(`${baseUrl}/.well-known/openid-configuration`);
            assert.strictEqual(resp.status, 200);
            const doc = await resp.json();
            assert.strictEqual(doc.issuer, 'https://auth-api-dev.lanzar.me');
            assert.strictEqual(doc.token_endpoint, 'https://auth-api-dev.lanzar.me/oauth/token');
            assert.strictEqual(doc.userinfo_endpoint, 'https://auth-api-dev.lanzar.me/oauth/userinfo');
            assert.strictEqual(doc.jwks_uri, 'https://auth-api-dev.lanzar.me/.well-known/jwks.json');
            assert.deepStrictEqual(doc.id_token_signing_alg_values_supported, ['RS256']);
            assert.deepStrictEqual(doc.code_challenge_methods_supported, ['S256']);
            assert.deepStrictEqual(doc.grant_types_supported, ['authorization_code', 'refresh_token']);
            assert.deepStrictEqual(doc.scopes_supported, ['openid', 'profile', 'email']);
        });

        const appDown = express();
        appDown.use('/', createOidcRouter({ oidcTokenService: null, db }));
        await withServer(appDown, async (baseUrl) => {
            const resp = await fetch(`${baseUrl}/.well-known/openid-configuration`);
            assert.strictEqual(resp.status, 503);
        });
    });

    await test('M1.3-02: Minted RS256 access_token (900s) and id_token verify against public JWKS with nonce & auth_time', async () => {
        const db = new InMemoryFirestore();
        const keystore = new SigningKeystore(db);
        const oidc = new OidcTokenService({ signingKeystore: keystore, issuer: 'https://auth-api.lanzar.me' });

        const app = express();
        app.use('/', createJwksRouter({ signingKeystore: keystore }));

        await withServer(app, async (baseUrl) => {
            const at = await oidc.mintAccessToken({
                uid: 'usr_oidc_1',
                clientId: 'threadline',
                tenantId: 'lanzar',
                sessionId: 'sess_1',
                familyId: 'fam_1',
                scope: 'openid profile email'
            });
            const idt = await oidc.mintIdToken({
                uid: 'usr_oidc_1',
                clientId: 'threadline',
                tenantId: 'lanzar',
                sessionId: 'sess_1',
                scope: 'openid profile email',
                email: 'user@lanzar.me',
                emailVerified: true,
                name: 'Jon Scott',
                nonce: 'nonce_abc_123',
                authTime: 1700000000
            });

            const jwksResp = await fetch(`${baseUrl}/.well-known/jwks.json`);
            const jwks = await jwksResp.json();
            assert.strictEqual(jwks.keys.length, 1);

            const atHeader = decodeJwtPart(at, 0);
            const atPayload = decodeJwtPart(at, 1);
            assert.strictEqual(atHeader.alg, 'RS256');
            assert.strictEqual(atHeader.kid, jwks.keys[0].kid);
            assert.strictEqual(atPayload.exp - atPayload.iat, ACCESS_TOKEN_TTL_SECONDS);
            assert.strictEqual(atPayload.token_use, 'access');
            assert.strictEqual(atPayload.sub, 'usr_oidc_1');

            const idPayload = decodeJwtPart(idt, 1);
            assert.strictEqual(idPayload.token_use, 'id');
            assert.strictEqual(idPayload.nonce, 'nonce_abc_123');
            assert.strictEqual(idPayload.auth_time, 1700000000);
            assert.strictEqual(idPayload.email, 'user@lanzar.me');
            assert.strictEqual(idPayload.name, 'Jon Scott');

            const pubKey = crypto.createPublicKey({ key: jwks.keys[0], format: 'jwk' });
            const [h, p, s] = idt.split('.');
            assert.strictEqual(crypto.verify('RSA-SHA256', Buffer.from(`${h}.${p}`), pubKey, Buffer.from(s, 'base64url')), true);
        });
    });

    await test('M1.3-03: Scoped Compatibility Adapter enforces legacy_firebase, dual, and oidc modes accurately', async () => {
        const db = new InMemoryFirestore();
        const keystore = new SigningKeystore(db);
        const oidc = new OidcTokenService({ signingKeystore: keystore, issuer: 'https://auth-api-dev.lanzar.me' });

        let customTokenCalls = 0;
        const mockAuthAdmin = {
            async createCustomToken(uid, claims) {
                customTokenCalls++;
                return `fb_custom_${uid}_${claims.client_id}`;
            }
        };

        // 1. legacy_firebase (portal)
        const legacyRes = await oidc.buildTokenResponse({
            client: getClient('portal'),
            uid: 'u1',
            clientId: 'portal',
            tenantId: 'lanzar',
            sessionId: 's1',
            familyId: 'f1',
            refreshToken: 'rt1',
            authAdmin: mockAuthAdmin
        });
        assert.strictEqual(legacyRes.custom_token, 'fb_custom_u1_portal');
        assert.strictEqual(legacyRes.access_token, undefined);
        assert.strictEqual(legacyRes.id_token, undefined);

        // 2. dual (threadline)
        const dualRes = await oidc.buildTokenResponse({
            client: getClient('threadline'),
            uid: 'u1',
            clientId: 'threadline',
            tenantId: 'lanzar',
            sessionId: 's2',
            familyId: 'f2',
            refreshToken: 'rt2',
            scope: 'openid profile email',
            userClaims: { email: 'a@lanzar.me', emailVerified: true, name: 'Alice' },
            authAdmin: mockAuthAdmin
        });
        assert.strictEqual(dualRes.custom_token, 'fb_custom_u1_threadline');
        assert.ok(dualRes.access_token && dualRes.id_token);
        assert.strictEqual(dualRes.token_type, 'Bearer');
        assert.strictEqual(dualRes.expires_in, 900);

        // 3. oidc (pure third-party OIDC client — must NOT call createCustomToken)
        const callsBeforeOidc = customTokenCalls;
        const oidcRes = await oidc.buildTokenResponse({
            client: { id: 'third_party_oidc', compatibilityMode: 'oidc', enabled: true },
            uid: 'u1',
            clientId: 'third_party_oidc',
            tenantId: 'lanzar',
            sessionId: 's3',
            familyId: 'f3',
            refreshToken: 'rt3',
            scope: 'openid email',
            userClaims: { email: 'a@lanzar.me', emailVerified: true, name: 'Alice' },
            authAdmin: mockAuthAdmin
        });
        assert.strictEqual(customTokenCalls, callsBeforeOidc);
        assert.strictEqual(oidcRes.custom_token, undefined);
        assert.ok(oidcRes.access_token && oidcRes.id_token);
        assert.strictEqual(decodeJwtPart(oidcRes.id_token, 1).name, undefined, 'profile scope was not requested');
        assert.strictEqual(decodeJwtPart(oidcRes.id_token, 1).email, 'a@lanzar.me');
    });

    await test('M1.3-04: End-to-end HTTP OIDC flow (/authorize -> /token authorization_code -> /userinfo -> /token refresh_token)', async () => {
        const db = new InMemoryFirestore();
        const keystore = new SigningKeystore(db);
        const oidc = new OidcTokenService({ signingKeystore: keystore, issuer: 'https://auth-api-dev.lanzar.me' });
        const codeStore = new FirestoreAuthorizationCodeStore(db);

        await db.collection('users').doc('uid_e2e').set({
            email: 'e2e@lanzar.me',
            emailVerified: true,
            displayName: 'E2E User',
            status: 'active'
        });

        const mockAuthAdmin = {
            async verifyIdToken() {
                return { uid: 'uid_e2e', email: 'e2e@lanzar.me', email_verified: true, name: 'E2E User', auth_time: 1700000100 };
            },
            async createCustomToken() {
                throw new Error('Should not be called for oidc client');
            }
        };

        const customClients = {
            oidc_partner: {
                id: 'oidc_partner',
                redirectUris: ['https://partner.example.com/callback'],
                compatibilityMode: 'oidc',
                enabled: true
            }
        };

        const app = express();
        app.use(express.json());
        app.use('/oauth', createOAuthRouter({
            db,
            authAdmin: mockAuthAdmin,
            codeStore,
            sessionService: {},
            isUserAdmin: async () => false,
            oidcTokenService: oidc,
            getClientOverride: (id) => customClients[id]
        }));
        app.use('/', createOidcRouter({ oidcTokenService: oidc, db }));
        app.use('/', createJwksRouter({ signingKeystore: keystore }));

        await withServer(app, async (baseUrl) => {
            const verifier = 'verifier_' + crypto.randomBytes(24).toString('hex');
            const challenge = sha256Base64Url(verifier);

            // 1. Authorize
            const authResp = await fetch(`${baseUrl}/oauth/authorize`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    idToken: 'firebase_id_tok',
                    client_id: 'oidc_partner',
                    redirect_uri: 'https://partner.example.com/callback',
                    state: 'st_1',
                    code_challenge: challenge,
                    code_challenge_method: 'S256',
                    scope: 'openid profile email',
                    nonce: 'n_e2e_1'
                })
            });
            assert.strictEqual(authResp.status, 200);
            const { code } = await authResp.json();
            assert.ok(code);

            // 2. Standard OIDC /oauth/token (grant_type=authorization_code)
            const tokResp = await fetch(`${baseUrl}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 'idem_e2e_key_12345678' },
                body: JSON.stringify({
                    grant_type: 'authorization_code',
                    code,
                    client_id: 'oidc_partner',
                    redirect_uri: 'https://partner.example.com/callback',
                    code_verifier: verifier
                })
            });
            assert.strictEqual(tokResp.status, 200);
            const tokBody = await tokResp.json();
            assert.strictEqual(tokBody.token_type, 'Bearer');
            assert.strictEqual(tokBody.expires_in, 900);
            assert.strictEqual(tokBody.custom_token, undefined);
            assert.ok(tokBody.access_token && tokBody.id_token && tokBody.refresh_token);
            assert.strictEqual(decodeJwtPart(tokBody.id_token, 1).nonce, 'n_e2e_1');

            // 3. /oauth/userinfo with Bearer access_token
            const uiResp = await fetch(`${baseUrl}/oauth/userinfo`, {
                headers: { Authorization: `Bearer ${tokBody.access_token}` }
            });
            assert.strictEqual(uiResp.status, 200);
            const uiBody = await uiResp.json();
            assert.strictEqual(uiBody.sub, 'uid_e2e');
            assert.strictEqual(uiBody.email, 'e2e@lanzar.me');
            assert.strictEqual(uiBody.name, 'E2E User');

            // 4. Refresh grant on /oauth/token returns fresh RS256 access_token + id_token
            const refResp = await fetch(`${baseUrl}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    grant_type: 'refresh_token',
                    refresh_token: tokBody.refresh_token,
                    family_id: tokBody.family_id,
                    session_id: tokBody.session_id,
                    uid: 'uid_e2e',
                    tenant_id: 'lanzar'
                })
            });
            assert.strictEqual(refResp.status, 200);
            const refBody = await refResp.json();
            assert.strictEqual(refBody.expires_in, 900);
            assert.notStrictEqual(refBody.refresh_token, tokBody.refresh_token);
            assert.strictEqual((await oidc.verifyAccessToken(refBody.access_token)).valid, true);
            assert.ok(refBody.id_token);

            // 5. Idempotent recovery on /oauth/token (authorization_code) returns same tokens
            const idemResp = await fetch(`${baseUrl}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 'idem_e2e_key_12345678' },
                body: JSON.stringify({
                    grant_type: 'authorization_code',
                    code,
                    client_id: 'oidc_partner',
                    redirect_uri: 'https://partner.example.com/callback',
                    code_verifier: verifier
                })
            });
            assert.strictEqual(idemResp.status, 200);
            const idemBody = await idemResp.json();
            assert.strictEqual(idemBody.access_token, tokBody.access_token);
        });
    });

    await test('M1.3-05: /oauth/userinfo rejects missing token, tampered token, id_token as Bearer, and revoked session', async () => {
        const db = new InMemoryFirestore();
        const keystore = new SigningKeystore(db);
        const oidc = new OidcTokenService({ signingKeystore: keystore, issuer: 'https://auth-api-dev.lanzar.me' });

        await db.collection('users').doc('u_ui').collection('sessions').doc('s_ui').set({
            uid: 'u_ui',
            tenantId: 'lanzar',
            status: 'active',
            revoked: false
        });

        const at = await oidc.mintAccessToken({ uid: 'u_ui', clientId: 'portal', tenantId: 'lanzar', sessionId: 's_ui', scope: 'openid' });
        const idt = await oidc.mintIdToken({ uid: 'u_ui', clientId: 'portal', tenantId: 'lanzar', sessionId: 's_ui', scope: 'openid' });

        const app = express();
        app.use('/', createOidcRouter({ oidcTokenService: oidc, db }));

        await withServer(app, async (baseUrl) => {
            assert.strictEqual((await fetch(`${baseUrl}/oauth/userinfo`)).status, 401);
            assert.strictEqual((await fetch(`${baseUrl}/oauth/userinfo`, { headers: { Authorization: `Bearer ${idt}` } })).status, 401);
            assert.strictEqual((await fetch(`${baseUrl}/oauth/userinfo`, { headers: { Authorization: `Bearer ${at}tamper` } })).status, 401);
            assert.strictEqual((await fetch(`${baseUrl}/oauth/userinfo`, { headers: { Authorization: `Bearer ${at}` } })).status, 200);

            // Revoke session -> immediate 401 on UserInfo
            await db.collection('users').doc('u_ui').collection('sessions').doc('s_ui').update({ status: 'revoked', revoked: true });
            assert.strictEqual((await fetch(`${baseUrl}/oauth/userinfo`, { headers: { Authorization: `Bearer ${at}` } })).status, 401);
        });
    });

    await test('M1.3-06: Client registry scope & exact redirect URI matching reject prospective/prefix URIs', async () => {
        assert.ok(getClient('portal') && getClient('portal').compatibilityMode === 'legacy_firebase');
        assert.ok(getClient('tickets') && getClient('tickets').compatibilityMode === 'legacy_firebase');
        assert.ok(getClient('threadline') && getClient('threadline').compatibilityMode === 'dual');
        assert.ok(getClient('ai') && getClient('ai').compatibilityMode === 'legacy_firebase');
        assert.strictEqual(getClient('pythos'), null, 'pythos is prospective only and must not be active');
        assert.strictEqual(getClient('mothership'), null, 'mothership is prospective only and must not be active');

        const db = new InMemoryFirestore();
        const codeStore = new FirestoreAuthorizationCodeStore(db);
        const app = express();
        app.use(express.json());
        app.use('/oauth', createOAuthRouter({
            db,
            authAdmin: { async verifyIdToken() { return { uid: 'u1' }; } },
            codeStore,
            sessionService: {},
            isUserAdmin: async () => false
        }));

        await withServer(app, async (baseUrl) => {
            const challenge = sha256Base64Url('v123');
            // Unapproved client rejected
            const rUnapproved = await fetch(`${baseUrl}/oauth/authorize`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    idToken: 'tok',
                    client_id: 'pythos',
                    redirect_uri: 'https://pythos.lanzar.me',
                    state: 's1',
                    code_challenge: challenge,
                    code_challenge_method: 'S256'
                })
            });
            assert.strictEqual(rUnapproved.status, 400);
            assert.strictEqual((await rUnapproved.json()).error, 'invalid_client');

            // Prefix/path redirect URI mismatch rejected (exact character-for-character match required)
            const rPrefix = await fetch(`${baseUrl}/oauth/authorize`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    idToken: 'tok',
                    client_id: 'portal',
                    redirect_uri: 'https://portal.lanzar.me/evil_prefix',
                    state: 's1',
                    code_challenge: challenge,
                    code_challenge_method: 'S256'
                })
            });
            assert.strictEqual(rPrefix.status, 400);
            assert.strictEqual((await rPrefix.json()).error, 'invalid_request');
        });
    });

    await test('M1.3-07: Fail-closed UserInfo/verifyAccessToken boundaries, refresh auth_time/nonce, and mode lock', async () => {
        const db = new InMemoryFirestore();
        const keystore = new SigningKeystore(db);
        const oidc = new OidcTokenService({ signingKeystore: keystore, issuer: 'https://auth-api-dev.lanzar.me' });
        const codeStore = new FirestoreAuthorizationCodeStore(db);

        // 1. Missing iss / aud / wrong aud / invalid azp / tenant_id must fail closed in verifyAccessToken
        const noIssJwt = await keystore.signJwt({ sub: 'u1', aud: ['portal', oidc.getUserinfoAudience()], azp: 'portal', tenant_id: 'lanzar', token_use: 'access' });
        assert.strictEqual((await oidc.verifyAccessToken(noIssJwt)).reason, 'INVALID_ISSUER');
        const noAudJwt = await keystore.signJwt({ iss: 'https://auth-api-dev.lanzar.me', sub: 'u1', tenant_id: 'lanzar', token_use: 'access' });
        assert.strictEqual((await oidc.verifyAccessToken(noAudJwt)).reason, 'INVALID_AUDIENCE');
        const wrongAudJwt = await keystore.signJwt({ iss: 'https://auth-api-dev.lanzar.me', sub: 'u1', aud: 'https://other.example.com', azp: 'portal', tenant_id: 'lanzar', token_use: 'access' });
        assert.strictEqual((await oidc.verifyAccessToken(wrongAudJwt)).reason, 'INVALID_AUDIENCE');
        const multiAudMissingAzp = await keystore.signJwt({ iss: 'https://auth-api-dev.lanzar.me', sub: 'u1', aud: ['portal', oidc.getUserinfoAudience()], tenant_id: 'lanzar', token_use: 'access' });
        assert.strictEqual((await oidc.verifyAccessToken(multiAudMissingAzp)).reason, 'INVALID_AZP');
        const multiAudBadAzp = await keystore.signJwt({ iss: 'https://auth-api-dev.lanzar.me', sub: 'u1', aud: ['portal', oidc.getUserinfoAudience()], azp: 'rogue_client', tenant_id: 'lanzar', token_use: 'access' });
        assert.strictEqual((await oidc.verifyAccessToken(multiAudBadAzp)).reason, 'INVALID_AZP');
        const noTenantJwt = await keystore.signJwt({ iss: 'https://auth-api-dev.lanzar.me', sub: 'u1', aud: ['portal', oidc.getUserinfoAudience()], azp: 'portal', token_use: 'access' });
        assert.strictEqual((await oidc.verifyAccessToken(noTenantJwt)).reason, 'MISSING_TENANT_ID');

        // Positive multi-audience & single UserInfo-audience checks
        const validSingleAud = await keystore.signJwt({ iss: 'https://auth-api-dev.lanzar.me', sub: 'u1', aud: oidc.getUserinfoAudience(), tenant_id: 'lanzar', token_use: 'access' });
        assert.strictEqual((await oidc.verifyAccessToken(validSingleAud)).valid, true);
        const validMultiAud = await keystore.signJwt({ iss: 'https://auth-api-dev.lanzar.me', sub: 'u1', aud: ['portal', oidc.getUserinfoAudience()], azp: 'portal', tenant_id: 'lanzar', token_use: 'access' });
        assert.strictEqual((await oidc.verifyAccessToken(validMultiAud)).valid, true);

        // 2. Tenant mismatch and wrong-audience rejection in /oauth/userinfo (401)
        await db.collection('users').doc('u_tm').collection('sessions').doc('s_tm').set({
            uid: 'u_tm',
            tenantId: 'other_tenant',
            status: 'active',
            revoked: false
        });
        const crossTenantAt = await oidc.mintAccessToken({ uid: 'u_tm', clientId: 'portal', tenantId: 'lanzar', sessionId: 's_tm', scope: 'openid' });
        const uiApp = express();
        uiApp.use('/', createOidcRouter({ oidcTokenService: oidc, db }));
        await withServer(uiApp, async (baseUrl) => {
            assert.strictEqual((await fetch(`${baseUrl}/oauth/userinfo`, { headers: { Authorization: `Bearer ${crossTenantAt}` } })).status, 401);
            assert.strictEqual((await fetch(`${baseUrl}/oauth/userinfo`, { headers: { Authorization: `Bearer ${wrongAudJwt}` } })).status, 401);
            assert.strictEqual((await fetch(`${baseUrl}/oauth/userinfo`, { headers: { Authorization: `Bearer ${multiAudBadAzp}` } })).status, 401);
        });

        // 3. Refresh preserves auth_time, omits nonce, blocks client_id spoofing, and locks legacy_firebase mode
        await db.collection('users').doc('u_ref').set({ email: 'r@lanzar.me', status: 'active' });
        const oauthApp = express();
        oauthApp.use(express.json());
        oauthApp.use('/oauth', createOAuthRouter({
            db,
            authAdmin: {
                async verifyIdToken() { return { uid: 'u_ref', email: 'r@lanzar.me', auth_time: 1700000555 }; },
                async createCustomToken(u) { return `fb_${u}`; }
            },
            codeStore,
            sessionService: {},
            isUserAdmin: async () => false,
            oidcTokenService: oidc
        }));

        await withServer(oauthApp, async (baseUrl) => {
            // 3a. dual client (threadline): refresh returns RS256 id_token with auth_time and NO nonce
            const v1 = 'ver_dual_' + crypto.randomBytes(16).toString('hex');
            const a1 = await (await fetch(`${baseUrl}/oauth/authorize`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    idToken: 't',
                    client_id: 'threadline',
                    redirect_uri: 'https://threadline.lanzar.me',
                    state: 's',
                    code_challenge: sha256Base64Url(v1),
                    code_challenge_method: 'S256',
                    scope: 'openid profile',
                    nonce: 'orig_nonce_123'
                })
            })).json();
            const t1 = await (await fetch(`${baseUrl}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 'idem_dual_1234567890' },
                body: JSON.stringify({
                    grant_type: 'authorization_code',
                    code: a1.code,
                    client_id: 'threadline',
                    redirect_uri: 'https://threadline.lanzar.me',
                    code_verifier: v1
                })
            })).json();
            assert.strictEqual(decodeJwtPart(t1.id_token, 1).nonce, 'orig_nonce_123');
            assert.strictEqual(decodeJwtPart(t1.id_token, 1).auth_time, 1700000555);

            // Client spoofing on refresh rejected
            const spoofResp = await fetch(`${baseUrl}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    grant_type: 'refresh_token',
                    refresh_token: t1.refresh_token,
                    family_id: t1.family_id,
                    session_id: t1.session_id,
                    uid: 'u_ref',
                    client_id: 'portal'
                })
            });
            assert.strictEqual(spoofResp.status, 401);

            // Legitimate refresh preserves auth_time and omits nonce
            const r1 = await (await fetch(`${baseUrl}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    grant_type: 'refresh_token',
                    refresh_token: t1.refresh_token,
                    family_id: t1.family_id,
                    session_id: t1.session_id,
                    uid: 'u_ref'
                })
            })).json();
            assert.strictEqual(decodeJwtPart(r1.id_token, 1).auth_time, 1700000555);
            assert.strictEqual(decodeJwtPart(r1.id_token, 1).nonce, undefined);

            // 3b. legacy_firebase client (portal) does NOT get OIDC id_token on refresh
            const v2 = 'ver_leg_' + crypto.randomBytes(16).toString('hex');
            const a2 = await (await fetch(`${baseUrl}/oauth/authorize`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    idToken: 't',
                    client_id: 'portal',
                    redirect_uri: 'https://portal.lanzar.me',
                    state: 's',
                    code_challenge: sha256Base64Url(v2),
                    code_challenge_method: 'S256'
                })
            })).json();
            const t2 = await (await fetch(`${baseUrl}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 'idem_leg_1234567890' },
                body: JSON.stringify({
                    grant_type: 'authorization_code',
                    code: a2.code,
                    client_id: 'portal',
                    redirect_uri: 'https://portal.lanzar.me',
                    code_verifier: v2
                })
            })).json();
            assert.strictEqual(t2.id_token, undefined);
            const r2 = await (await fetch(`${baseUrl}/oauth/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    grant_type: 'refresh_token',
                    refresh_token: t2.refresh_token,
                    family_id: t2.family_id,
                    session_id: t2.session_id,
                    uid: 'u_ref'
                })
            })).json();
            assert.strictEqual(r2.id_token, undefined);
        });
    });

    console.log('\n================================================================');
    console.log('MILESTONE 1.3 VERIFICATION SUMMARY');
    console.log(`Total Executed: ${passed + failed}`);
    console.log(`Passed:         ${passed}`);
    console.log(`Failed:         ${failed}`);
    console.log(`Success Rate:   ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
    console.log('================================================================\n');

    if (failed > 0) process.exit(1);
}

main().catch(err => {
    console.error('Fatal Milestone 1.3 test error:', err);
    process.exit(1);
});
