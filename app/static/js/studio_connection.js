/* Python Studio > Connection page (studio/connection.html): save the settings,
 * replace or clear the write-only secret, try a call. Server side:
 * app/views/studio.py (connection_*), app/services/studio_connections.py.
 */
(function () {
  'use strict';
  var cfgEl = document.getElementById('cn-config');
  if (!cfgEl) return;
  var CFG = JSON.parse(cfgEl.textContent);
  var U = CFG.urls;
  var meta = document.querySelector('meta[name="csrf-token"]');
  var CSRF = meta ? meta.getAttribute('content') : '';
  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function post(url, body) {
    return fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF, 'Accept': 'application/json' },
      body: JSON.stringify(body || {})
    }).then(function (r) {
      return r.json().catch(function () { return { error: 'HTTP ' + r.status }; }).then(function (d) {
        if (!r.ok || (d.ok === false && d.error && !('status' in d))) {
          var err = new Error(d.error || ('HTTP ' + r.status));
          err.data = d;
          throw err;
        }
        return d;
      });
    });
  }
  function msg(text, bad) {
    $('cn-msg').innerHTML = text ? '<span style="color:' + (bad ? '#8B1C2A' : '#15692A') + ';">' + esc(text) + '</span>' : '';
  }
  function val(id) { var e = $('cn-' + id); return e ? (e.type === 'checkbox' ? e.checked : e.value) : undefined; }

  function authUI() {
    var a = val('auth');
    if (a === undefined) return;
    function vis(cls, on) { document.querySelectorAll('.' + cls).forEach(function (e) { e.style.display = on ? '' : 'none'; }); }
    vis('cn-auth-user', a === 'basic' || a === 'oauth2' || a === 'session');
    vis('cn-auth-header', a === 'api_key');
    vis('cn-auth-oauth', a === 'oauth2');
    vis('cn-auth-session', a === 'session');
  }
  if ($('cn-auth')) { $('cn-auth').addEventListener('change', authUI); authUI(); }

  $('cn-save').addEventListener('click', function () {
    var body = {};
    ['name', 'description', 'base_url', 'auth', 'username', 'header_name', 'token_url', 'login_path', 'scope',
     'verify_tls', 'host', 'port', 'database', 'timeout', 'allow_writes'].forEach(function (k) {
      var v = val(k); if (v !== undefined) body[k] = v;
    });
    if (body.verify_tls === undefined) body.verify_tls = true;
    if ($('cn-api_version_id')) body.api_version_id = $('cn-api_version_id').value;
    function send(b) {
      return post(U.save, b).then(function (d) {
        if (d && d.secret_dropped && CFG.kind === 'server') {
          $('cn-hostkey-state').innerHTML = '<span class="fw-badge fw-badge-warning">not trusted</span>';
          $('cn-fingerprint').textContent = '—';
          msg('Saved. The host or port changed, so the trusted host key was forgotten: fetch and trust the new one.', true);
        } else if (d && d.secret_dropped) {
          $('cn-secret-state').innerHTML = '<span class="fw-badge fw-badge-secondary">not set</span>';
          msg('Saved. The destination changed, so the stored secret was cleared: enter it again.', true);
        } else { msg('Saved.' + (d.impact && d.impact.length ? ' ' + d.impact.length + ' app step(s) now need a fix before their app can be published again.' : '')); }
      });
    }
    send(body).catch(function (e) {
      // Another API version: the server names the app steps whose endpoint
      // the new version lacks, and saves only when that is confirmed.
      if (e.data && e.data.needs_confirm) {
        if (window.confirm(e.message + ':\n\n' + e.data.impact.join('\n') +
                           '\n\nThose steps fail when they run. Pin the connection anyway?')) {
          body.confirm = true;
          return send(body).catch(function (e2) { msg(e2.message, true); });
        }
        msg('Not saved.', true);
        return;
      }
      msg(e.message, true);
    });
  });
  function setSecret(v) {
    post(U.secret, { value: v }).then(function (d) {
      $('cn-secret').value = '';
      $('cn-secret-state').innerHTML = d.has_secret ? '<span class="fw-badge fw-badge-success">stored</span>'
        : '<span class="fw-badge fw-badge-secondary">not set</span>';
      msg(v ? 'Secret replaced.' : 'Secret cleared.');
    }).catch(function (e) { msg(e.message, true); });
  }
  // Absent for a server connection: its secret is a generated SSH key.
  if ($('cn-secret-set')) $('cn-secret-set').addEventListener('click', function () {
    if (!$('cn-secret').value) { msg('Type the new value first.', true); return; }
    setSecret($('cn-secret').value);
  });
  if ($('cn-secret-clear')) $('cn-secret-clear').addEventListener('click', function () {
    if (window.confirm('Clear the stored secret?')) setSecret('');
  });
  if ($('cn-keygen')) $('cn-keygen').addEventListener('click', function () {
    if ($('cn-pubkey').value && !window.confirm('Generate a NEW key? Servers that trust the current key will refuse SATOM until the installer runs again with the new one.')) return;
    post(U.keygen).then(function (d) {
      $('cn-pubkey').value = d.public_key || '';
      $('cn-install').value = d.install_command || '';
      $('cn-secret-state').innerHTML = '<span class="fw-badge fw-badge-success">stored</span>';
      msg('New key generated. Run the installer on the server with this public key.');
    }).catch(function (e) { msg(e.message, true); });
  });
  function hostkey(action) {
    return post(U.hostkey, { action: action }).then(function (d) {
      $('cn-fingerprint').textContent = d.fingerprint || '—';
      $('cn-hostkey-state').innerHTML = d.host_key ? '<span class="fw-badge fw-badge-success">trusted</span>'
        : '<span class="fw-badge fw-badge-warning">not trusted</span>';
      msg(d.host_key ? 'Host key trusted: ' + d.fingerprint : 'Host key forgotten: every call is refused until a key is trusted.');
    }).catch(function (e) { msg(e.message, true); });
  }
  if ($('cn-hostkey-trust')) $('cn-hostkey-trust').addEventListener('click', function () {
    if (window.confirm('Fetch the key the server presents now and trust it? Compare its fingerprint with the server first.')) hostkey('trust');
  });
  if ($('cn-hostkey-forget')) $('cn-hostkey-forget').addEventListener('click', function () {
    if (window.confirm('Forget the trusted host key?')) hostkey('forget');
  });
  // Absent for a template (Examples): templates are never deleted.
  if ($('cn-delete')) $('cn-delete').addEventListener('click', function () {
    if (!window.confirm('Delete the connection ' + CFG.slug + ' and its secret?')) return;
    post(U['delete']).then(function () { window.location = U.back; }).catch(function (e) { msg(e.message, true); });
  });
  $('cn-test').addEventListener('click', function () {
    var btn = this; btn.disabled = true;
    $('cn-t-status').innerHTML = '<span class="text-muted">Testing…</span>';
    post(U.test, { path: val('t-path') || '', extract: val('t-extract') || '', sql: val('t-sql') || '' })
      .then(function (d) {
        btn.disabled = false;
        if (d.error) {
          $('cn-t-status').innerHTML = '<span class="fw-badge fw-badge-danger">error</span>';
          $('cn-t-out').textContent = d.error; return;
        }
        $('cn-t-status').innerHTML = '<span class="fw-badge fw-badge-' + (d.ok ? 'success' : 'warning') + '">' + esc(d.status) +
          '</span> <span class="text-muted">' + esc(d.ms) + ' ms' + (d.url ? ' · ' + esc(d.url) : '') + '</span>';
        $('cn-t-out').textContent = typeof d.body === 'string' ? d.body : JSON.stringify(d.body, null, 2);
        var has = 'extract' in d;
        $('cn-t-extract-label').style.display = has ? '' : 'none';
        $('cn-t-extract-out').style.display = has ? '' : 'none';
        if (has) $('cn-t-extract-out').textContent = JSON.stringify(d.extract, null, 2);
      }).catch(function (e) { btn.disabled = false; $('cn-t-out').textContent = e.message; });
  });
})();
