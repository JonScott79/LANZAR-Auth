// test_ai_hardening.js
// Verification suite for LANZAR AI AuthVerifier & OIDC RS256 JWKS hardening

const assert = require('assert');
const crypto = require('crypto');
const { AuthVerifier, verifyOidcAccessToken, clearJwksCache } = require('../server/auth-verifier');

function b64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(JSON.stringify(input), 'utf8');
  return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function signRs256(header, payload, privateKey) {
  const signingInput = `${b64url(header)}.${b64url(payload)}`;
  const sig = crypto.sign('RSA-SHA256', Buffer.from(signingInput, 'utf8'), privateKey);
  return `${signingInput}.${b64url(sig)}`;
}

async function run() {
  console.log('=== LANZAR AI Security & OIDC Hardening Tests ===');
  const prevTestFlag = process.env.AI_ALLOW_TEST_TOKENS;
  delete process.env.AI_ALLOW_TEST_TOKENS;

  try {
    // 1. Unauthenticated request returns guest (authenticated: false)
    const guest = await AuthVerifier.verify(null, 'user_spoof');
    assert.strictEqual(guest.authenticated, false);
    assert.strictEqual(guest.isGuest, true);
    console.log('  ✓ X-User-Id spoof ignored when AI_ALLOW_TEST_TOKENS is unset');

    // 2. test_* / user_* / arbitrary bearer tokens fail closed (401)
    await assert.rejects(() => AuthVerifier.verify('Bearer test_user_alpha'), (err) => err.status === 401);
    await assert.rejects(() => AuthVerifier.verify('Bearer arbitrary_fake_token'), (err) => err.status === 401);
    console.log('  ✓ Fake test_* and unverified bearer tokens fail closed with 401');

    // 3. Valid RS256 OIDC access token for aud=ai succeeds; wrong aud/iss rejected
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' });
    jwk.kid = 'ai_test_kid_1';
    jwk.use = 'sig';
    jwk.alg = 'RS256';
    const mockFetch = async () => ({ ok: true, status: 200, json: async () => ({ keys: [jwk] }) });

    const nowSec = Math.floor(Date.now() / 1000);
    const validTok = signRs256(
      { alg: 'RS256', typ: 'JWT', kid: 'ai_test_kid_1' },
      { sub: 'ai-user-1', iss: 'https://auth.lanzar.me/nova', aud: 'ai', azp: 'ai', iat: nowSec, exp: nowSec + 900 },
      privateKey
    );
    clearJwksCache();
    const ok = await verifyOidcAccessToken(validTok, {
      authApiUrl: 'https://auth-api-nova.lanzar.me',
      expectedIssuer: 'https://auth.lanzar.me/nova',
      fetchFn: mockFetch
    });
    assert.strictEqual(ok.valid, true);
    assert.strictEqual(ok.uid, 'ai-user-1');

    const wrongAudTok = signRs256(
      { alg: 'RS256', typ: 'JWT', kid: 'ai_test_kid_1' },
      { sub: 'ai-user-1', iss: 'https://auth.lanzar.me/nova', aud: 'threadline', iat: nowSec, exp: nowSec + 900 },
      privateKey
    );
    const badAud = await verifyOidcAccessToken(wrongAudTok, {
      authApiUrl: 'https://auth-api-nova.lanzar.me',
      expectedIssuer: 'https://auth.lanzar.me/nova',
      fetchFn: mockFetch
    });
    assert.strictEqual(badAud.valid, false);
    assert.strictEqual(badAud.reason, 'INVALID_AUDIENCE');
    console.log('  ✓ Valid RS256 OIDC token for aud=ai accepted; wrong audience rejected');

    console.log('ALL LANZAR AI HARDENING TESTS PASSED.');
  } finally {
    if (prevTestFlag !== undefined) process.env.AI_ALLOW_TEST_TOKENS = prevTestFlag;
  }
}

run().catch((err) => {
  console.error('TEST FAILED:', err);
  process.exit(1);
});
