const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

/**
 * APIShield API client.
 * Never logs Authorization headers, passwords, or tokens.
 */

function authHeaders(token) {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function apiFetch(path, options = {}, token = null) {
  const url = `${API_BASE}${path}`;
  const headers = {
    'Content-Type': 'application/json',
    ...authHeaders(token),
    ...(options.headers || {}),
  };
  const res = await fetch(url, { ...options, headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw Object.assign(new Error(err.detail || 'Request failed'), { status: res.status, data: err });
  }
  return res.json();
}

export async function getHealth() {
  return apiFetch('/health');
}

export async function login(username, password) {
  // password is only used in-memory; never stored beyond this call
  return apiFetch('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
}

export async function getLabMode(token) {
  return apiFetch('/admin/lab-mode', {}, token);
}

export async function getDefenses(token) {
  return apiFetch('/admin/defenses', {}, token);
}

export async function patchDefenses(token, updates) {
  return apiFetch('/admin/defenses', {
    method: 'PATCH',
    body: JSON.stringify(updates),
  }, token);
}

export async function getEvents(token, { limit = 50, offset = 0, action } = {}) {
  const params = new URLSearchParams({ limit, offset });
  if (action) params.set('action', action);
  return apiFetch(`/admin/events?${params}`, {}, token);
}
