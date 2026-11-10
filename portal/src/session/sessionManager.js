/*
    sessionManager.js

    LANZAR Portal central session management (LANZAR ID).

    Responsibilities:
    - Validate the server-issued LANZAR ID session (session_id) against the trusted backend
    - Resolve administrator status from the backend (never from client-side claims)
    - Authenticated fetch helper for LANZAR ID APIs (no unauthenticated fallback)
    - Surface session revocation / expiry to the application
    - Best-effort server-side revocation of the current session on logout
*/

import { auth } from '../firebase/auth.js'

export const SESSION_STORAGE_KEY = 'lanzar_session_id'

export const AUTH_API_BASE =
  window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:4001'
    : 'https://auth-api.lanzar.me'

// Backend error codes that mean the credential is no longer valid for this session
const INVALID_SESSION_ERRORS = {
  session_revoked: 'revoked',
  token_revoked: 'revoked',
  session_expired: 'expired',
  invalid_token: 'invalid',
  unauthorized: 'invalid',
}

export const SESSION_MESSAGES = {
  revoked: 'Your session was ended from another device or by an administrator. Please sign in again.',
  expired: 'Your session has expired. Please sign in again.',
  invalid: 'Your session is no longer valid. Please sign in again.',
  suspended: 'This account has been suspended. Contact LANZAR support for assistance.',
  no_session: 'A LANZAR ID session is required. Please sign in with LANZAR ID.',
  unavailable: 'Unable to verify your session right now. Please try again.',
}

export class SessionInvalidError extends Error {
  constructor(reason, message) {
    super(message || SESSION_MESSAGES[reason] || SESSION_MESSAGES.invalid)
    this.name = 'SessionInvalidError'
    this.reason = reason
  }
}

// ==========================
// Invalidation event bus
// ==========================

const invalidationListeners = new Set()

export function onSessionInvalidated(handler) {
  invalidationListeners.add(handler)
  return () => invalidationListeners.delete(handler)
}

function notifyInvalidated(reason) {
  invalidationListeners.forEach((handler) => {
    try { handler(reason) } catch (_) { /* listener errors must not break the request path */ }
  })
}

export function clearStoredSession() {
  try {
    sessionStorage.removeItem(SESSION_STORAGE_KEY)
    sessionStorage.removeItem('pkce_state')
    sessionStorage.removeItem('pkce_code_verifier')
  } catch (_) { /* storage unavailable */ }
}

// ==========================
// Authenticated requests
// ==========================

async function getBearerToken() {
  const user = auth.currentUser
  if (!user) {
    throw new SessionInvalidError('invalid', 'Not signed in.')
  }
  try {
    return await user.getIdToken()
  } catch (err) {
    // Refresh token revoked / user disabled / user removed
    throw new SessionInvalidError('revoked')
  }
}

function reasonFromBody(body) {
  return INVALID_SESSION_ERRORS[body?.error] || null
}

/**
 * fetch() against a LANZAR ID API with a Firebase ID token.
 * There is intentionally no fallback credential: with no signed-in user this throws.
 * A 401 carrying a session/token invalidation code notifies the app and throws SessionInvalidError.
 */
export async function authFetch(url, options = {}) {
  let token
  try {
    token = await getBearerToken()
  } catch (err) {
    if (err instanceof SessionInvalidError) notifyInvalidated(err.reason)
    throw err
  }

  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
      Authorization: `Bearer ${token}`,
    },
  })

  if (res.status === 401) {
    const body = await res.clone().json().catch(() => ({}))
    const reason = reasonFromBody(body) || 'invalid'
    notifyInvalidated(reason)
    throw new SessionInvalidError(reason, body?.error_description)
  }

  return res
}

// ==========================
// Session validation / restoration
// ==========================

/**
 * Validates the current Firebase user's LANZAR ID session with the trusted backend.
 * Returns { status, ... } where status is one of:
 *   'valid' | 'revoked' | 'expired' | 'invalid' | 'suspended' | 'no_session' | 'unavailable'
 * On 'valid' the payload includes uid, email, session_id, expires_at and is_admin (server-resolved).
 */
export async function validateSession() {
  const user = auth.currentUser
  if (!user) return { status: 'invalid' }

  let token
  try {
    token = await user.getIdToken()
  } catch (err) {
    return { status: 'revoked' }
  }

  let res
  try {
    res = await fetch(`${AUTH_API_BASE}/api/id/session/validate`, {
      headers: { Authorization: `Bearer ${token}` },
    })
  } catch (err) {
    return { status: 'unavailable' }
  }

  const body = await res.json().catch(() => ({}))

  if (res.ok && body.valid === true) {
    if (!body.session_id) {
      // Signed in to Firebase without a LANZAR ID session claim: not an authorized Portal session
      return { status: 'no_session' }
    }
    return { status: 'valid', ...body }
  }

  if (res.status === 403 && body.error === 'account_suspended') {
    return { status: 'suspended' }
  }

  if (res.status === 401) {
    return { status: reasonFromBody(body) || 'invalid' }
  }

  return { status: 'unavailable' }
}

// ==========================
// Logout
// ==========================

/**
 * Best-effort revocation of the current device session on the LANZAR ID backend.
 * Must run before Firebase sign-out (needs the ID token). Never throws.
 */
export async function revokeCurrentSession() {
  try {
    const user = auth.currentUser
    const sessionId = sessionStorage.getItem(SESSION_STORAGE_KEY)
    if (!user || !sessionId) return false
    const token = await user.getIdToken()
    const res = await fetch(`${AUTH_API_BASE}/api/id/sessions/${encodeURIComponent(sessionId)}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    })
    return res.ok
  } catch (_) {
    return false
  }
}
