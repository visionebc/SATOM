/* ============================================================
   OFortMAut — api.js
   Centralized fetch wrapper + per-feature API helpers
   ============================================================ */

'use strict';

// ============================================================
// CSRF Token
// ============================================================
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';

// ============================================================
// Core Fetch Wrapper
// ============================================================
async function apiFetch(url, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    'X-CSRFToken': csrfToken,
    ...options.headers,
  };

  const resp = await fetch(url, { ...options, headers });

  if (!resp.ok) {
    let errText;
    try { errText = await resp.text(); } catch (_) { errText = `HTTP ${resp.status}`; }
    throw new Error(errText || `HTTP ${resp.status}`);
  }

  const ct = resp.headers.get('Content-Type') || '';
  if (ct.includes('application/json')) {
    return resp.json();
  }
  return resp.text();
}

// ============================================================
// Appliance API
// ============================================================
async function testConnection(applianceId) {
  const btn = document.querySelector(`[data-test-id="${applianceId}"]`);
  const badge = document.querySelector(`[data-status-id="${applianceId}"]`);

  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="fw-loading-spinner"></span>';
  }

  try {
    const result = await apiFetch(`/api/appliances/${applianceId}/test`, { method: 'POST' });

    const online = result.status === 'online';
    if (badge) {
      badge.className = online ? 'fw-status fw-status-online' : 'fw-status fw-status-offline';
      badge.innerHTML = `<span class="fw-status-dot"></span>${online ? 'Online' : 'Offline'}`;
    }

    window.FW?.toast(online ? 'Connection successful' : 'Connection failed', online ? 'success' : 'danger');
    return result;
  } catch (err) {
    if (badge) {
      badge.className = 'fw-status fw-status-offline';
      badge.innerHTML = '<span class="fw-status-dot"></span>Offline';
    }
    window.FW?.toast('Test failed: ' + err.message, 'danger');
    throw err;
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-lightning"></i>';
    }
  }
}

async function getAppliances() {
  return apiFetch('/api/appliances');
}

async function deleteAppliance(applianceId) {
  return apiFetch(`/api/appliances/${applianceId}`, { method: 'DELETE' });
}

// ============================================================
// Server Policy API
// ============================================================
async function getPolicies(applianceId) {
  return apiFetch(`/api/appliances/${applianceId}/policies`);
}

async function getPolicyDetail(applianceId, policyName) {
  return apiFetch(`/api/appliances/${applianceId}/policies/${encodeURIComponent(policyName)}`);
}

// ============================================================
// Backup API
// ============================================================
async function createBackup(applianceId) {
  const btn = document.getElementById('btn-create-backup');
  if (btn) { btn.disabled = true; btn.textContent = 'Creating…'; }

  try {
    const result = await apiFetch(`/api/appliances/${applianceId}/backups`, { method: 'POST' });
    window.FW?.toast('Backup created successfully', 'success');
    setTimeout(() => window.location.reload(), 1500);
    return result;
  } catch (err) {
    window.FW?.toast('Backup failed: ' + err.message, 'danger');
    throw err;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Create Backup'; }
  }
}

async function deleteBackup(applianceId, backupName) {
  await apiFetch(`/api/appliances/${applianceId}/backups/${encodeURIComponent(backupName)}`, { method: 'DELETE' });
  window.FW?.toast('Backup deleted', 'info');
  setTimeout(() => window.location.reload(), 1000);
}

// ============================================================
// User Management API
// ============================================================
async function createUser(userData) {
  return apiFetch('/api/users', { method: 'POST', body: JSON.stringify(userData) });
}

async function deleteUser(userId) {
  return apiFetch(`/api/users/${userId}`, { method: 'DELETE' });
}

async function updateUserRole(userId, role) {
  return apiFetch(`/api/users/${userId}`, {
    method: 'PATCH',
    body: JSON.stringify({ role }),
  });
}

// ============================================================
// Analysis API
// ============================================================
async function getAnalysisSummary(applianceId, params = {}) {
  const qs = new URLSearchParams(params).toString();
  return apiFetch(`/api/appliances/${applianceId}/analysis?${qs}`);
}

async function getTopSources(applianceId, limit = 10) {
  return apiFetch(`/api/appliances/${applianceId}/analysis/top-sources?limit=${limit}`);
}

async function getAttackTypes(applianceId) {
  return apiFetch(`/api/appliances/${applianceId}/analysis/attack-types`);
}

// ============================================================
// Log Collection API
// ============================================================
async function getLogs(applianceId, params = {}) {
  const qs = new URLSearchParams(params).toString();
  return apiFetch(`/api/appliances/${applianceId}/logs?${qs}`);
}

// ============================================================
// Registry API
// ============================================================
async function getRegistryEntries(type) {
  return apiFetch(`/api/registry?type=${encodeURIComponent(type || '')}`);
}

async function createRegistryEntry(data) {
  return apiFetch('/api/registry', { method: 'POST', body: JSON.stringify(data) });
}

async function deleteRegistryEntry(id) {
  return apiFetch(`/api/registry/${id}`, { method: 'DELETE' });
}

// ============================================================
// Settings API
// ============================================================
async function getSettings() {
  return apiFetch('/api/settings');
}

async function saveSettings(data) {
  return apiFetch('/api/settings', { method: 'PUT', body: JSON.stringify(data) });
}

// ============================================================
// Search API
// ============================================================
async function globalSearch(query, applianceId) {
  const params = new URLSearchParams({ q: query });
  if (applianceId) params.set('appliance_id', applianceId);
  return apiFetch(`/api/search?${params}`);
}

// ============================================================
// Modal Helper
// ============================================================
function openModal(modalId) {
  const el = document.getElementById(modalId);
  if (el && window.bootstrap) {
    const m = bootstrap.Modal.getOrCreateInstance(el);
    m.show();
  }
}

function closeModal(modalId) {
  const el = document.getElementById(modalId);
  if (el && window.bootstrap) {
    const m = bootstrap.Modal.getInstance(el);
    if (m) m.hide();
  }
}

// ============================================================
// Form Serializer
// ============================================================
function serializeForm(formEl) {
  const fd  = new FormData(formEl);
  const obj = {};
  fd.forEach(function (v, k) {
    if (obj[k] !== undefined) {
      if (!Array.isArray(obj[k])) obj[k] = [obj[k]];
      obj[k].push(v);
    } else {
      obj[k] = v;
    }
  });
  return obj;
}

// ============================================================
// Export
// ============================================================
window.API = {
  fetch: apiFetch,
  testConnection,
  getAppliances,
  deleteAppliance,
  getPolicies,
  getPolicyDetail,
  createBackup,
  deleteBackup,
  createUser,
  deleteUser,
  updateUserRole,
  getAnalysisSummary,
  getTopSources,
  getAttackTypes,
  getLogs,
  getRegistryEntries,
  createRegistryEntry,
  deleteRegistryEntry,
  getSettings,
  saveSettings,
  globalSearch,
  openModal,
  closeModal,
  serializeForm,
};
