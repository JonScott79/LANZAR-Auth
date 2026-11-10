// rateLimiter.js
// Application-Level Rate Limiting Middleware for LANZAR ID (LID-SEC-002, LID-VER-001, LID-VER-002, LID-VER-003)
//
// Single-Instance In-Memory Protection:
// NOTE FOR DEPLOYMENT: This implementation uses in-memory bounded sliding counters.
// In a distributed, multi-instance production environment, these limiters can be
// augmented by a shared distributed atomic store (e.g. Redis sliding window or Cloud Armor)
// to prevent attackers from distributing brute-force attempts across sibling nodes.

const net = require('net');
const { verifyMfaSignedToken } = require('../mfaService');

// Map<key, { count?: number, resetAt: number, failedCount?: number } >
const rateLimitStore = new Map();

// Upper bound for in-memory entries (LID-VER-001)
let MAX_ENTRIES = 10000;

function setMaxEntries(n) {
  MAX_ENTRIES = n;
}

function getRateLimitStoreSize() {
  return rateLimitStore.size;
}

function pruneExpiredEntries(now = Date.now()) {
  for (const [key, record] of rateLimitStore.entries()) {
    if (now >= record.resetAt) {
      rateLimitStore.delete(key);
    }
  }
}

/**
 * Safe bounded insert into rateLimitStore.
 * Prunes expired entries when capacity is reached; evicts oldest entries if still at capacity.
 */
function safeSet(key, record) {
  if (rateLimitStore.has(key)) {
    rateLimitStore.set(key, record);
    return;
  }
  if (rateLimitStore.size >= MAX_ENTRIES) {
    pruneExpiredEntries();
    while (rateLimitStore.size >= MAX_ENTRIES) {
      const oldestKey = rateLimitStore.keys().next().value;
      if (oldestKey === undefined) break;
      rateLimitStore.delete(oldestKey);
    }
  }
  rateLimitStore.set(key, record);
}

// Periodic cleanup of expired rate limit buckets (every 60s, unreferenced)
const cleanupTimer = setInterval(() => {
  pruneExpiredEntries();
}, 60000);
if (cleanupTimer.unref) cleanupTimer.unref();

/**
 * Resolves and strictly validates the genuine client IP address for rate limiting.
 *
 * Railway Ingress Contract:
 * Railway terminates TLS at its public edge router and authoritatively sets
 * the connecting client's genuine public IP in the `X-Real-IP` header.
 *
 * Security Requirements:
 * 1. Read X-Real-IP and strictly validate with Node's net.isIP().
 * 2. Do NOT use req.ip or parse arbitrary/spoofed X-Forwarded-For values.
 * 3. Fallback to direct socket remoteAddress (validated with net.isIP()),
 *    normalizing IPv4-mapped IPv6 strings (::ffff:127.0.0.1 -> 127.0.0.1).
 * 4. Fallback to '127.0.0.1' if missing, empty, or malformed.
 */
function getClientIp(req) {
  if (!req) return '127.0.0.1';

  // 1. Authoritative Railway public ingress header
  const rawRealIp = req.headers && req.headers['x-real-ip'];
  if (typeof rawRealIp === 'string') {
    const trimmed = rawRealIp.trim();
    if (net.isIP(trimmed)) {
      return trimmed;
    }
  }

  // 2. Fallback to direct socket connection remoteAddress
  const socketAddr = req.socket?.remoteAddress;
  if (typeof socketAddr === 'string') {
    const trimmed = socketAddr.trim();
    const normalized = trimmed.startsWith('::ffff:') ? trimmed.slice(7) : trimmed;
    if (net.isIP(normalized)) {
      return normalized;
    }
  }

  return '127.0.0.1';
}

/**
 * Explicit HTTPS connection evaluation.
 * Railway public edge terminates TLS and supplies X-Forwarded-Proto: https.
 * Handled explicitly without globally trusting arbitrary forwarding headers.
 */
function isRequestSecure(req) {
  if (!req) return false;
  if (req.secure || req.socket?.encrypted) return true;
  return Boolean(req.headers && req.headers['x-forwarded-proto'] === 'https');
}

/**
 * Generic sliding window rate limiter
 */
function createRateLimiter({
  windowMs = 60000,
  maxRequests = 20,
  keyPrefix = 'rl',
  keyGenerator = (req) => getClientIp(req),
  errorMessage = 'Rate limit exceeded. Please try again later.'
}) {
  return function rateLimiterMiddleware(req, res, next) {
    const key = `${keyPrefix}:${keyGenerator(req)}`;
    const now = Date.now();
    let record = rateLimitStore.get(key);

    if (!record || now >= record.resetAt) {
      record = { count: 0, resetAt: now + windowMs };
      safeSet(key, record);
    }

    record.count++;

    const remaining = Math.max(0, maxRequests - record.count);
    const retryAfterSec = Math.ceil((record.resetAt - now) / 1000);

    res.setHeader('X-RateLimit-Limit', maxRequests);
    res.setHeader('X-RateLimit-Remaining', remaining);
    res.setHeader('X-RateLimit-Reset', Math.ceil(record.resetAt / 1000));

    if (record.count > maxRequests) {
      res.setHeader('Retry-After', retryAfterSec);
      return res.status(429).json({
        error: 'too_many_requests',
        error_description: errorMessage,
        retry_after: retryAfterSec
      });
    }

    next();
  };
}

// 1. OAuth Authorize Rate Limiter (20 req / 1 min per IP)
const oauthAuthorizeLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 20,
  keyPrefix: 'oauth_auth',
  errorMessage: 'Rate limit exceeded for OAuth authorization requests. Please try again in 1 minute.'
});

// 2. OAuth Exchange Rate Limiter (20 req / 1 min per IP)
const oauthExchangeLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 20,
  keyPrefix: 'oauth_exch',
  errorMessage: 'Rate limit exceeded for OAuth token exchange requests. Please try again in 1 minute.'
});

// 3. Phone Verification Dispatch Rate Limiter (3 requests per 15 min per IP and per phone number)
function phoneDispatchLimiter(req, res, next) {
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const maxAttempts = 3;
  const now = Date.now();
  const ip = getClientIp(req);
  const rawPhone = req.body?.phoneNumber ? String(req.body.phoneNumber).replace(/\D/g, '') : 'unknown';

  const ipKey = `phone_dispatch_ip:${ip}`;
  const phoneKey = `phone_dispatch_num:${rawPhone}`;

  let ipRecord = rateLimitStore.get(ipKey);
  if (!ipRecord || now >= ipRecord.resetAt) {
    ipRecord = { count: 0, resetAt: now + windowMs };
    safeSet(ipKey, ipRecord);
  }

  let phoneRecord = rateLimitStore.get(phoneKey);
  if (!phoneRecord || now >= phoneRecord.resetAt) {
    phoneRecord = { count: 0, resetAt: now + windowMs };
    safeSet(phoneKey, phoneRecord);
  }

  ipRecord.count++;
  phoneRecord.count++;

  const retryAfterSec = Math.max(
    Math.ceil((ipRecord.resetAt - now) / 1000),
    Math.ceil((phoneRecord.resetAt - now) / 1000)
  );

  if (ipRecord.count > maxAttempts || phoneRecord.count > maxAttempts) {
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({
      error: 'too_many_requests',
      error_description: 'Too many verification attempts for this phone number or network. Please try again later.',
      retry_after: retryAfterSec
    });
  }

  next();
}

// 4. MFA Dual-Key Failed Attempt Tracker (LID-VER-002)
// Per-account-and-IP limit: 5 failures / 15 min (prevents account lockout DoS against victims from other IPs)
// Per-IP limit: 15 failures / 15 min (prevents brute-forcing / credential scanning across multiple accounts from single IP)
const MFA_FAIL_ACC_IP_LIMIT = 5;
const MFA_FAIL_IP_LIMIT = 15;
const MFA_FAIL_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

function checkMfaRateLimit(uid, method = 'totp', ip = 'unknown') {
  const now = Date.now();
  const safeIp = ip || 'unknown';

  // 1. Check IP aggregate throttle (protects against distributed credential stuffing / enumeration)
  if (safeIp !== 'unknown') {
    const ipKey = `mfa_fail:ip:${safeIp}`;
    const ipRecord = rateLimitStore.get(ipKey);
    if (ipRecord && now < ipRecord.resetAt && ipRecord.failedCount >= MFA_FAIL_IP_LIMIT) {
      const retryAfter = Math.ceil((ipRecord.resetAt - now) / 1000);
      return {
        allowed: false,
        retryAfter,
        message: 'Too many failed verification attempts. Please try again later.'
      };
    }
  }

  // 2. Check UID + IP specific throttle (prevents attacker on IP A from locking out legitimate user on IP B)
  if (uid) {
    const accIpKey = `mfa_fail:acc_ip:${uid}:${safeIp}`;
    const accRecord = rateLimitStore.get(accIpKey);
    if (accRecord && now < accRecord.resetAt && accRecord.failedCount >= MFA_FAIL_ACC_IP_LIMIT) {
      const retryAfter = Math.ceil((accRecord.resetAt - now) / 1000);
      return {
        allowed: false,
        retryAfter,
        message: 'Too many failed verification attempts. Please try again later.'
      };
    }

    // Check unknown-IP record for callers that record failures without an explicit client IP
    if (safeIp !== 'unknown') {
      const unkKey = `mfa_fail:acc_ip:${uid}:unknown`;
      const unkRecord = rateLimitStore.get(unkKey);
      if (unkRecord && now < unkRecord.resetAt && unkRecord.failedCount >= MFA_FAIL_ACC_IP_LIMIT) {
        const retryAfter = Math.ceil((unkRecord.resetAt - now) / 1000);
        return {
          allowed: false,
          retryAfter,
          message: 'Too many failed verification attempts. Please try again later.'
        };
      }
    }

    // Backwards-compatible check for legacy UID key if present
    const legacyKey = `mfa_fail:${method}:${uid}`;
    const legacyRecord = rateLimitStore.get(legacyKey);
    if (legacyRecord && now < legacyRecord.resetAt && legacyRecord.failedCount >= MFA_FAIL_ACC_IP_LIMIT) {
      const retryAfter = Math.ceil((legacyRecord.resetAt - now) / 1000);
      return {
        allowed: false,
        retryAfter,
        message: 'Too many failed verification attempts. Please try again later.'
      };
    }
  }

  return { allowed: true };
}

function recordMfaFailure(uid, method = 'totp', ip = 'unknown') {
  const now = Date.now();
  const safeIp = ip || 'unknown';

  if (safeIp !== 'unknown') {
    const ipKey = `mfa_fail:ip:${safeIp}`;
    let ipRecord = rateLimitStore.get(ipKey);
    if (!ipRecord || now >= ipRecord.resetAt) {
      ipRecord = { failedCount: 0, resetAt: now + MFA_FAIL_WINDOW_MS };
    }
    ipRecord.failedCount++;
    safeSet(ipKey, ipRecord);
  }

  if (uid) {
    const accIpKey = `mfa_fail:acc_ip:${uid}:${safeIp}`;
    let accRecord = rateLimitStore.get(accIpKey);
    if (!accRecord || now >= accRecord.resetAt) {
      accRecord = { failedCount: 0, resetAt: now + MFA_FAIL_WINDOW_MS };
    }
    accRecord.failedCount++;
    safeSet(accIpKey, accRecord);
  }
}

function clearMfaFailures(uid, method = 'totp', ip = 'unknown') {
  const safeIp = ip || 'unknown';
  if (uid) {
    rateLimitStore.delete(`mfa_fail:acc_ip:${uid}:${safeIp}`);
    rateLimitStore.delete(`mfa_fail:acc_ip:${uid}:unknown`);
    rateLimitStore.delete(`mfa_fail:${method}:${uid}`);
  }
}

/**
 * Pre-validation middleware for /mfa/verify
 */
function mfaVerifyRateLimitMiddleware(req, res, next) {
  const { mfaSession, method } = req.body || {};
  const ip = getClientIp(req);

  if (!mfaSession) {
    // Check IP-level throttle even before session is validated
    const ipCheck = checkMfaRateLimit(null, method, ip);
    if (!ipCheck.allowed) {
      res.setHeader('Retry-After', ipCheck.retryAfter);
      return res.status(429).json({
        error: 'too_many_requests',
        error_description: ipCheck.message,
        retry_after: ipCheck.retryAfter
      });
    }
    return next(); // Missing parameter caught by route handler
  }

  // Safely extract UID without verifying signature yet (verify will happen in handler)
  let uid = null;
  try {
    const parts = mfaSession.split('.');
    if (parts.length === 2) {
      const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      uid = payload.uid;
    }
  } catch (_) {
    // Malformed session will be rejected in route handler
  }

  const check = checkMfaRateLimit(uid, method === 'recovery' ? 'recovery' : 'totp', ip);
  if (!check.allowed) {
    res.setHeader('Retry-After', check.retryAfter);
    return res.status(429).json({
      error: 'too_many_requests',
      error_description: check.message,
      retry_after: check.retryAfter
    });
  }

  next();
}

/**
 * Test utility to clear rate limits
 */
function resetRateLimits() {
  rateLimitStore.clear();
}

module.exports = {
  createRateLimiter,
  oauthAuthorizeLimiter,
  oauthExchangeLimiter,
  phoneDispatchLimiter,
  mfaVerifyRateLimitMiddleware,
  checkMfaRateLimit,
  recordMfaFailure,
  clearMfaFailures,
  resetRateLimits,
  getClientIp,
  isRequestSecure,
  setMaxEntries,
  getRateLimitStoreSize
};
