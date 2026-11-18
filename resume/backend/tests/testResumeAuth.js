const assert = require("assert");
const crypto = require("crypto");
const { verifyOidcAccessToken, clearJwksCache } = require("../server");

function b64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(JSON.stringify(input), "utf8");
  return buf.toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function signRs256(header, payload, privateKey) {
  const signingInput = `${b64url(header)}.${b64url(payload)}`;
  const sig = crypto.sign("RSA-SHA256", Buffer.from(signingInput, "utf8"), privateKey);
  return `${signingInput}.${b64url(sig)}`;
}

async function run() {
  console.log("=== LANZAR Resume OIDC Auth Tests ===");
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  jwk.kid = "resume_test_kid_1";
  jwk.use = "sig";
  jwk.alg = "RS256";
  const mockFetch = async () => ({ ok: true, status: 200, json: async () => ({ keys: [jwk] }) });

  const nowSec = Math.floor(Date.now() / 1000);
  const validTok = signRs256(
    { alg: "RS256", typ: "JWT", kid: "resume_test_kid_1" },
    { sub: "res-user-1", iss: "https://auth.lanzar.me/nova", aud: "resume", iat: nowSec, exp: nowSec + 900 },
    privateKey
  );
  clearJwksCache();
  const ok = await verifyOidcAccessToken(validTok, { fetchFn: mockFetch });
  assert.strictEqual(ok.valid, true);
  assert.strictEqual(ok.uid, "res-user-1");

  const badAud = await verifyOidcAccessToken(
    signRs256({ alg: "RS256", typ: "JWT", kid: "resume_test_kid_1" }, { sub: "res-user-1", iss: "https://auth.lanzar.me/nova", aud: "portal", iat: nowSec, exp: nowSec + 900 }, privateKey),
    { fetchFn: mockFetch }
  );
  assert.strictEqual(badAud.valid, false);
  assert.strictEqual(badAud.reason, "INVALID_AUDIENCE");

  console.log("ALL 2 LANZAR RESUME AUTH TESTS PASSED.");
}

run().catch((err) => { console.error(err); process.exit(1); });
