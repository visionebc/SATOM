/* Administrator > Access > Directory connections (directory_connections/index.html):
 * create, edit, test and delete. Server side: app/views/directory_connections.py.
 * The secret is write-only: the page never receives it. */
(function () {
  'use strict';
  var cfgEl = document.getElementById('dc-config');
  if (!cfgEl) return;
  var CFG = JSON.parse(cfgEl.textContent);
  var meta = document.querySelector('meta[name="csrf-token"]');
  var CSRF = meta ? meta.getAttribute('content') : '';
  function $(id) { return document.getElementById(id); }
  function post(url, body) {
    return fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF, 'Accept': 'application/json' },
      body: JSON.stringify(body || {})
    }).then(function (r) {
      return r.json().catch(function () { return { ok: false, error: 'HTTP ' + r.status }; }).then(function (d) {
        if (!r.ok || (d.ok === false && !('detail' in d))) throw new Error(d.error || ('HTTP ' + r.status));
        return d;
      });
    });
  }
  function byId(id) {
    for (var i = 0; i < CFG.data.length; i++) if (CFG.data[i].id === id) return CFG.data[i];
    return null;
  }
  var TEXT = ['host', 'base_dn', 'user_attr', 'ad_domain', 'bind_dn', 'user_filter', 'nas_id'];
  var NUM = ['port', 'timeout'];
  var BOOL = ['use_ssl', 'start_tls', 'tls_verify'];
  var modal = window.bootstrap ? new window.bootstrap.Modal($('dc-modal')) : null;
  var tmodal = window.bootstrap ? new window.bootstrap.Modal($('dc-test-modal')) : null;
  var editing = null, testing = null;

  function showKind() {
    var k = $('dc-kind').value;
    function vis(sel, on) { document.querySelectorAll(sel).forEach(function (e) { e.classList.toggle('d-none', !on); }); }
    vis('.dc-ldap', k !== 'radius');
    vis('.dc-ad', k === 'ad');
    vis('.dc-ldaponly', k === 'ldap');
    vis('.dc-radius', k === 'radius');
    vis('.dc-secret', k !== 'ad');
    $('dc-secret-label').textContent = k === 'radius' ? 'Shared secret' : 'Bind password';
  }
  function open(id) {
    editing = id;
    var c = id ? byId(id) : { name: '', slug: '', kind: 'ad', enabled: true, cfg: { tls_verify: true, timeout: 8 }, has_secret: false };
    $('dc-title').textContent = id ? 'Edit connection' : 'New connection';
    $('dc-name').value = c.name; $('dc-slug').value = c.slug; $('dc-slug').disabled = !!id;
    $('dc-kind').value = c.kind; $('dc-kind').disabled = !!id;
    TEXT.forEach(function (k) { $('dc-' + k).value = c.cfg[k] || ''; });
    NUM.forEach(function (k) { $('dc-' + k).value = c.cfg[k] == null ? '' : c.cfg[k]; });
    BOOL.forEach(function (k) { $('dc-' + k).checked = !!c.cfg[k]; });
    $('dc-enabled').checked = !!c.enabled;
    $('dc-secret').value = '';
    $('dc-secret-help').textContent = c.has_secret ? 'A secret is stored. Blank keeps it.' : 'No secret stored yet.';
    $('dc-err').textContent = '';
    showKind();
    if (modal) modal.show();
  }
  $('dc-kind').addEventListener('change', showKind);
  $('dc-new').addEventListener('click', function () { open(null); });
  document.querySelectorAll('.dc-edit').forEach(function (b) {
    b.addEventListener('click', function () { open(+b.getAttribute('data-id')); });
  });
  $('dc-save').addEventListener('click', function () {
    var cfg = {};
    TEXT.forEach(function (k) { cfg[k] = $('dc-' + k).value; });
    NUM.forEach(function (k) { cfg[k] = $('dc-' + k).value; });
    BOOL.forEach(function (k) { cfg[k] = $('dc-' + k).checked; });
    post(CFG.save, { id: editing, name: $('dc-name').value, slug: $('dc-slug').value, kind: $('dc-kind').value,
                     cfg: cfg, secret: $('dc-secret').value, enabled: $('dc-enabled').checked })
      .then(function () { window.location.reload(); })
      .catch(function (e) { $('dc-err').textContent = e.message; });
  });
  document.querySelectorAll('.dc-test').forEach(function (b) {
    b.addEventListener('click', function () {
      testing = +b.getAttribute('data-id');
      $('dct-user').value = ''; $('dct-pass').value = ''; $('dct-out').textContent = '';
      if (tmodal) tmodal.show();
    });
  });
  $('dct-run').addEventListener('click', function () {
    $('dct-out').textContent = 'Testing…';
    post(CFG.base + testing + '/test', { username: $('dct-user').value, password: $('dct-pass').value })
      .then(function (d) {
        $('dct-out').innerHTML = '<span class="fw-badge"></span> <span></span>';
        var badge = $('dct-out').firstChild;
        badge.className = 'fw-badge ' + (d.ok ? 'fw-badge-success' : 'fw-badge-danger');
        badge.textContent = d.ok ? 'OK' : 'FAILED';
        $('dct-out').lastChild.textContent = d.detail || '';
        $('dct-pass').value = '';
      })
      .catch(function (e) { $('dct-out').textContent = e.message; });
  });
  document.querySelectorAll('.dc-del').forEach(function (b) {
    b.addEventListener('click', function () {
      if (!window.confirm('Delete the connection ' + b.getAttribute('data-name') + '?')) return;
      post(CFG.base + b.getAttribute('data-id') + '/delete').then(function () { window.location.reload(); })
        .catch(function (e) { $('dc-msg').innerHTML = '<span style="color:#8B1C2A;"></span>'; $('dc-msg').firstChild.textContent = e.message; });
    });
  });
})();
