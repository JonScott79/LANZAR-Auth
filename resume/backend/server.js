const crypto = require("crypto");
const express = require("express");
const cors = require("cors");

const app = express();
const jwksCache = new Map();

const allowedOrigins = (process.env.RESUME_ALLOWED_ORIGINS || "http://localhost:5173,https://resume.lanzar.me,https://lanzar-resume-nova.netlify.app")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("CORS origin not allowed"));
  },
  credentials: true
}));
app.use(express.json());

function base64UrlDecode(str) {
  const padded = String(str).replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (String(str).length % 4)) % 4);
  return Buffer.from(padded, "base64");
}

async function verifyOidcAccessToken(token, options = {}) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return { valid: false, reason: "MALFORMED_JWT" };
  let header, payload;
  try {
    header = JSON.parse(base64UrlDecode(parts[0]).toString("utf8"));
    payload = JSON.parse(base64UrlDecode(parts[1]).toString("utf8"));
  } catch (_) {
    return { valid: false, reason: "INVALID_ENCODING" };
  }
  if (!header || header.alg !== "RS256" || typeof header.kid !== "string" || !header.kid) {
    return { valid: false, reason: "UNSUPPORTED_HEADER" };
  }

  const authApiUrl = (options.authApiUrl || process.env.LANZAR_AUTH_API_URL || "https://auth-api-nova.lanzar.me").replace(/\/+$/, "");
  const expectedIssuer = (options.expectedIssuer || process.env.LANZAR_OIDC_ISSUER || "https://auth.lanzar.me/nova").replace(/\/+$/, "");
  const fetchFn = options.fetchFn || global.fetch;

  const nowMs = Date.now();
  let cached = jwksCache.get(authApiUrl);
  if (!cached || nowMs >= cached.expiresAt) {
    const res = await fetchFn(`${authApiUrl}/.well-known/jwks.json`);
    if (!res || !res.ok) return { valid: false, reason: "JWKS_FETCH_FAILED" };
    const body = await res.json();
    cached = { keys: Array.isArray(body?.keys) ? body.keys : [], expiresAt: nowMs + 60000 };
    jwksCache.set(authApiUrl, cached);
  }

  const jwk = cached.keys.find((k) => k.kid === header.kid);
  if (!jwk) return { valid: false, reason: "UNKNOWN_KID" };

  const publicKey = crypto.createPublicKey({ key: jwk, format: "jwk" });
  const sigOk = crypto.verify("RSA-SHA256", Buffer.from(`${parts[0]}.${parts[1]}`, "utf8"), publicKey, base64UrlDecode(parts[2]));
  if (!sigOk) return { valid: false, reason: "INVALID_SIGNATURE" };

  const nowSec = Math.floor(nowMs / 1000);
  if (!Number.isFinite(payload.exp) || nowSec >= payload.exp) return { valid: false, reason: "TOKEN_EXPIRED" };
  if (payload.nbf !== undefined && (!Number.isFinite(payload.nbf) || nowSec < payload.nbf)) return { valid: false, reason: "TOKEN_NOT_YET_VALID" };
  if (String(payload.iss || "").replace(/\/+$/, "") !== expectedIssuer) return { valid: false, reason: "INVALID_ISSUER" };
  const audMatches = payload.aud === "resume" || (Array.isArray(payload.aud) && payload.aud.includes("resume")) || payload.azp === "resume";
  if (!audMatches) return { valid: false, reason: "INVALID_AUDIENCE" };
  if (typeof payload.sub !== "string" || !payload.sub) return { valid: false, reason: "MISSING_SUB" };

  return { valid: true, uid: payload.sub, payload };
}

async function requireLanzarAuth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "unauthorized" });
  }
  const token = authHeader.slice(7).trim();
  const result = await verifyOidcAccessToken(token).catch(() => ({ valid: false }));
  if (!result || !result.valid) {
    return res.status(401).json({ error: "unauthorized", reason: result?.reason || "INVALID_TOKEN" });
  }
  req.uid = result.uid;
  req.user = result.payload;
  return next();
}

app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "LANZAR Resume" });
});

app.get("/api/me", requireLanzarAuth, (req, res) => {
  res.json({ uid: req.uid, email: req.user?.email || null });
});

const PORT = process.env.PORT || 3001;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on ${PORT}`);
  });
}

module.exports = { app, verifyOidcAccessToken, clearJwksCache: () => jwksCache.clear() };
