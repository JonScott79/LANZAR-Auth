/**
 * LANZAR MISSION CONTROL — Admin API Client
 * File: portal/src/admin/decks/adminApi.js
 */

import { auth } from '../../firebase/auth.js';

const AUTH_API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
  ? 'http://localhost:4001'
  : 'https://auth-api.lanzar.me';

async function getAuthHeader() {
  const user = auth.currentUser;
  if (!user) {
    return {
      'Authorization': 'Bearer mock_admin_dev_token',
      'Content-Type': 'application/json'
    };
  }
  const token = await user.getIdToken(true);
  return {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  };
}

export async function fetchTelemetry() {
  const headers = await getAuthHeader();
  const res = await fetch(`${AUTH_API_BASE}/api/admin/id/telemetry`, { headers });
  if (!res.ok) throw new Error(`Telemetry fetch failed: ${res.statusText}`);
  return await res.json();
}

export async function fetchClients() {
  const headers = await getAuthHeader();
  const res = await fetch(`${AUTH_API_BASE}/api/admin/id/clients`, { headers });
  if (!res.ok) throw new Error(`Clients fetch failed: ${res.statusText}`);
  return await res.json();
}

export async function fetchUsers(searchQuery = '', status = '', limit = 50) {
  const headers = await getAuthHeader();
  const params = new URLSearchParams();
  if (searchQuery) params.set('query', searchQuery);
  if (status && status !== 'all') params.set('status', status);
  params.set('limit', limit);

  const res = await fetch(`${AUTH_API_BASE}/api/admin/id/users?${params.toString()}`, { headers });
  if (!res.ok) throw new Error(`Users fetch failed: ${res.statusText}`);
  return await res.json();
}

export async function fetchUserDetail(uid) {
  const headers = await getAuthHeader();
  const res = await fetch(`${AUTH_API_BASE}/api/admin/id/users/${uid}`, { headers });
  if (!res.ok) throw new Error(`User detail fetch failed: ${res.statusText}`);
  return await res.json();
}

export async function setAccountStatus(uid, status, reason) {
  const headers = await getAuthHeader();
  const res = await fetch(`${AUTH_API_BASE}/api/admin/id/users/${uid}/suspend`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ status, reason })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error_description || `Failed to update status: ${res.statusText}`);
  }
  return await res.json();
}

export async function revokeAllSessions(uid) {
  const headers = await getAuthHeader();
  const res = await fetch(`${AUTH_API_BASE}/api/admin/id/users/${uid}/sessions/revoke-all`, {
    method: 'POST',
    headers
  });
  if (!res.ok) throw new Error(`Session revocation failed: ${res.statusText}`);
  return await res.json();
}

export async function grantFounderDesignation(uid, programId, founderNumber, title, grantReason) {
  const headers = await getAuthHeader();
  const res = await fetch(`${AUTH_API_BASE}/api/admin/id/users/${uid}/founders`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ programId, founderNumber, title, grantReason })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error_description || `Failed to grant founder: ${res.statusText}`);
  }
  return await res.json();
}

export async function revokeFounderDesignation(uid, programId, revocationReason) {
  const headers = await getAuthHeader();
  const res = await fetch(`${AUTH_API_BASE}/api/admin/id/users/${uid}/founders/${programId}`, {
    method: 'DELETE',
    headers,
    body: JSON.stringify({ revocationReason })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error_description || `Failed to revoke founder: ${res.statusText}`);
  }
  return await res.json();
}

export async function fetchAuditLogs(limit = 50) {
  const headers = await getAuthHeader();
  const res = await fetch(`${AUTH_API_BASE}/api/admin/id/audit-log?limit=${limit}`, { headers });
  if (!res.ok) throw new Error(`Audit log fetch failed: ${res.statusText}`);
  return await res.json();
}
