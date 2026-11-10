// rateLimiter.js
// Application-Level Rate Limiting Middleware for LANZAR ID (LID-SEC-002)
//
// Single-Instance In-Memory Protection:
// NOTE FOR DEPLOYMENT: This implementation uses in-memory sliding counters.
// In a distributed, multi-instance production environment, these limiters must be
// backed by a shared distributed atomic store (e.g. Redis sliding window or Cloud Armor)
// to prevent attackers from distributing brute-force attempts across sibling nodes.

const { verifyMfaSignedToken } = require('../mfaService');

// Map<key, { count: number, resetAt: number, failedCount: number } >
const rateLimitStore = new Map();

// Periodic cleanup of expired rate limit buckets (every 60s, unreferenced)
const cleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, record] of rateLimitStore.entries()) {
    if (now >= record.resetAt) {
      rateLimitStore.delete(key);
    }
  }
}, 60000);
if (cleanupTimer.unref) cleanupTimer.unref();

function getClientIp(req) {
  return (
    req.ip ||
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.socket?.remoteAddress ||
    '127.0.0.1'
  );
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
      rateLimitStore.set(key, record);
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
    rateLimitStore.set(ipKey, ipRecord);
  }

  let phoneRecord = rateLimitStore.get(phoneKey);
  if (!phoneRecord || now >= phoneRecord.resetAt) {
    phoneRecord = { count: 0, resetAt: now + windowMs };
    rateLimitStore.set(phoneKey, phoneRecord);
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

// 4. MFA Failed Attempt Tracker (5 failed attempts per account per 15 minutes)
const MFA_FAIL_LIMIT = 5;
const MFA_FAIL_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

function checkMfaRateLimit(uid, method = 'totp') {
  if (!uid) return { allowed: true };
  const key = `mfa_fail:${method}:${uid}`;
  const now = Date.now();
  const record = rateLimitStore.get(key);

  if (record && now < record.resetAt && record.failedCount >= MFA_FAIL_LIMIT) {
    const retryAfter = Math.ceil((record.resetAt - now) / 1000);
    return {
      allowed: false,
      retryAfter,
      message: `Too many failed ${method === 'recovery' ? 'recovery code' : 'TOTP'} attempts. Please try again in ${Math.ceil(retryAfter / 60)} minutes.`
    };
  }

  return { allowed: true };
}

function recordMfaFailure(uid, method = 'totp') {
  if (!uid) return;
  const key = `mfa_fail:${method}:${uid}`;
  const now = Date.now();
  let record = rateLimitStore.get(key);

  if (!record || now >= record.resetAt) {
    record = { failedCount: 0, resetAt: now + MFA_FAIL_WINDOW_MS };
    rateLimitStore.set(key, record);
  }

  record.failedCount++;
}

function clearMfaFailures(uid, method = 'totp') {
  if (!uid) return;
  rateLimitStore.delete(`mfa_fail:${method}:${uid}`);
}

/**
 * Pre-validation middleware for /mfa/verify
 */
function mfaVerifyRateLimitMiddleware(req, res, next) {
  const { mfaSession, method } = req.body || {};
  if (!mfaSession) {
    return next(); // Missing parameter will be caught by route handler
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

  if (uid) {
    const check = checkMfaRateLimit(uid, method === 'recovery' ? 'recovery' : 'totp');
    if (!check.allowed) {
      res.setHeader('Retry-After', check.retryAfter);
      return res.status(429).json({
        error: 'too_many_requests',
        error_description: check.message,
        retry_after: check.retryAfter
      });
    }
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
  resetRateLimits
};
