/**
 * LANZAR MISSION CONTROL — Admin API Client
 * File: portal/src/admin/decks/adminApi.js
 *
 * All requests carry the signed-in user's Firebase ID token (which embeds the LANZAR ID session_id).
 * There is no fallback credential: unauthenticated callers fail. Administrator authorization is
 * enforced by the backend (authenticateAdminMiddleware), never by this client.
 */

import { authFetch, AUTH_API_BASE } from '../../session/sessionManager.js';

export async function fetchTelemetry() {
  const res = await authFetch(`${AUTH_API_BASE}/api/admin/id/telemetry`);
  if (!res.ok) throw new Error(`Telemetry fetch failed: ${res.statusText}`);
  return await res.json();
}

export async function fetchClients() {
  const res = await authFetch(`${AUTH_API_BASE}/api/admin/id/clients`);
  if (!res.ok) throw new Error(`Clients fetch failed: ${res.statusText}`);
  return await res.json();
}

export async function fetchUsers(searchQuery = '', status = '', limit = 50) {
  const params = new URLSearchParams();
  if (searchQuery) params.set('query', searchQuery);
  if (status && status !== 'all') params.set('status', status);
  params.set('limit', limit);

  const res = await authFetch(`${AUTH_API_BASE}/api/admin/id/users?${params.toString()}`);
  if (!res.ok) throw new Error(`Users fetch failed: ${res.statusText}`);
  return await res.json();
}

export async function fetchUserDetail(uid) {
  const res = await authFetch(`${AUTH_API_BASE}/api/admin/id/users/${uid}`);
  if (!res.ok) throw new Error(`User detail fetch failed: ${res.statusText}`);
  return await res.json();
}

export async function setAccountStatus(uid, status, reason) {
  const res = await authFetch(`${AUTH_API_BASE}/api/admin/id/users/${uid}/suspend`, {
    method: 'POST',
    body: JSON.stringify({ status, reason })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error_description || `Failed to update status: ${res.statusText}`);
  }
  return await res.json();
}

export async function revokeAllSessions(uid) {
  const res = await authFetch(`${AUTH_API_BASE}/api/admin/id/users/${uid}/sessions/revoke-all`, {
    method: 'POST'
  });
  if (!res.ok) throw new Error(`Session revocation failed: ${res.statusText}`);
  return await res.json();
}

export async function grantFounderDesignation(uid, programId, founderNumber, title, grantReason) {
  const res = await authFetch(`${AUTH_API_BASE}/api/admin/id/users/${uid}/founders`, {
    method: 'POST',
    body: JSON.stringify({ programId, founderNumber, title, grantReason })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error_description || `Failed to grant founder: ${res.statusText}`);
  }
  return await res.json();
}

export async function revokeFounderDesignation(uid, programId, revocationReason) {
  const res = await authFetch(`${AUTH_API_BASE}/api/admin/id/users/${uid}/founders/${programId}`, {
    method: 'DELETE',
    body: JSON.stringify({ revocationReason })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error_description || `Failed to revoke founder: ${res.statusText}`);
  }
  return await res.json();
}

export async function fetchAuditLogs(limit = 50) {
  const res = await authFetch(`${AUTH_API_BASE}/api/admin/id/audit-log?limit=${limit}`);
  if (!res.ok) throw new Error(`Audit log fetch failed: ${res.statusText}`);
  return await res.json();
}
