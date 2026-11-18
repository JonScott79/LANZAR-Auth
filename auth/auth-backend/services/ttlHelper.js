// ttlHelper.js
// Dual-field Firestore Native TTL Timestamp Helpers (NOVA Staging Migration)
// Preserves all existing ISO-string and numeric-epoch expiration fields while
// writing native Firestore Timestamp values (`Date` -> Firestore Timestamp) to `ttlExpiresAt`.

const SESSION_TTL_GRACE_MS = 24 * 60 * 60 * 1000;        // +24 hours
const CENTRAL_SESSION_TTL_GRACE_MS = 0;                   // Absolute expiration, no grace
const TOKEN_FAMILY_TTL_GRACE_MS = 7 * 24 * 60 * 60 * 1000; // +7 days
const PHONE_OTP_TTL_GRACE_MS = 60 * 60 * 1000;            // +1 hour
const ADMIN_IDEMPOTENCY_TTL_GRACE_MS = 0;                 // Matches IDEMPOTENCY_TTL_MS (24h)

/**
 * Converts an existing expiration value into epoch milliseconds.
 * @param {Date|string|number|{toMillis?: Function, _seconds?: number, seconds?: number}} value
 * @param {'auto'|'seconds'|'ms'|'iso'} unitHint
 * @returns {number|null}
 */
function parseExpiryToMs(value, unitHint = 'auto') {
  if (value === null || value === undefined) return null;

  if (value instanceof Date) {
    const ms = value.getTime();
    return Number.isFinite(ms) ? ms : null;
  }

  if (typeof value === 'object') {
    if (typeof value.toMillis === 'function') {
      const ms = value.toMillis();
      return Number.isFinite(ms) ? ms : null;
    }
    const sec = value._seconds !== undefined ? value._seconds : value.seconds;
    if (typeof sec === 'number' && Number.isFinite(sec)) {
      return sec * 1000;
    }
    return null;
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    if (unitHint === 'seconds') return value * 1000;
    if (unitHint === 'ms') return value;
    // 'auto': Unix seconds through year 2100 are < 1e11; ms are >= 1e11
    return value < 1e11 ? value * 1000 : value;
  }

  if (typeof value === 'string' && value.trim()) {
    const trimmed = value.trim();
    if (/^\d+(\.\d+)?$/.test(trimmed)) {
      return parseExpiryToMs(Number(trimmed), unitHint);
    }
    const parsed = Date.parse(trimmed);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
}

/**
 * Computes a native JavaScript Date (serialized by Firestore Admin SDK as a Timestamp)
 * for `ttlExpiresAt`, adding the configured retention grace window.
 */
function computeTtlDate(rawExpiry, graceMs = 0, unitHint = 'auto') {
  const baseMs = parseExpiryToMs(rawExpiry, unitHint);
  if (baseMs === null) {
    throw new Error(`Invalid expiration value for ttlExpiresAt: ${String(rawExpiry)}`);
  }
  const targetMs = baseMs + Number(graceMs || 0);
  if (!Number.isFinite(targetMs)) {
    throw new Error(`Computed ttlExpiresAt is not finite: ${targetMs}`);
  }
  return new Date(targetMs);
}

module.exports = {
  SESSION_TTL_GRACE_MS,
  CENTRAL_SESSION_TTL_GRACE_MS,
  TOKEN_FAMILY_TTL_GRACE_MS,
  PHONE_OTP_TTL_GRACE_MS,
  ADMIN_IDEMPOTENCY_TTL_GRACE_MS,
  parseExpiryToMs,
  computeTtlDate
};
