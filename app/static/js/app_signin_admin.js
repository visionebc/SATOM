/* Administrator > Access > App sign-in > <app> (directory_connections/signin_edit.html):
 * the app's sign-in rules, its access list and its grants.
 * Server side: app/views/directory_connections.py, services/app_signin.py. */
(function () {
  'use strict';
  var cfgEl = document.getElementById('si-config');
  if (!cfgEl) return;
  var CFG = JSON.parse(cfgEl.textContent);
  var meta = document.querySelector('meta[name="csrf-token"]');
  var CSRF = meta ? meta.getAttribute('content') : '';
  function $(id) { return document.getElementById(id); }
  function el(tag, attrs, text) {
    var e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    if (text != null) e.textContent = text;
    return e;
  }
  function post(url, body) {
    return fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF, 'Accept': 'application/json' },
      body: JSON.stringify(body || {})
    }).then(function (r) {
      return r.json().catch(function () { return { ok: false, error: 'HTTP ' + r.status }; }).then(function (d) {
        if (!r.ok || d.ok === false) throw new Error(d.error || ('HTTP ' + r.status));
        return d;
      });
    });
  }
  var CONNS = {};
  CFG.conns.forEach(function (c) { CONNS[String(c.id)] = c; });
  var rules = (CFG.policy.rules || []).map(function (r) { return JSON.parse(JSON.stringify(r)); });

  function lines(v) { return (v || []).join('\n'); }
  function unlines(s) { return String(s || '').split(/\r?\n/).map(function (x) { return x.trim(); }).filter(Boolean); }

  function render() {
    var box = $('si-rules');
    box.textContent = '';
    if (!rules.length) { box.appendChild(el('div', { 'class': 'text-muted small' }, 'No rules: nobody can sign in on the app page.')); return; }
    rules.forEach(function (r, i) {
      var card = el('div', { 'class': 'fw-card mb-2' });
      var body = el('div', { 'class': 'fw-card-body', style: 'padding:10px 12px;' });
      var head = el('div', { 'class': 'd-flex align-items-center gap-2 mb-1' });
      var c = r.connection_id === 'local' ? null : CONNS[String(r.connection_id)];
      var title = r.connection_id === 'local' ? 'Local SATOM accounts'
        : (c ? c.name + ' — ' + c.kind_label + (c.enabled ? '' : ' (disabled)') : 'missing connection #' + r.connection_id);
      head.appendChild(el('span', { 'class': 'fw-badge fw-badge-info' }, String(i + 1)));
      head.appendChild(el('strong', {}, title));
      var tools = el('span', { 'class': 'ms-auto d-flex gap-1' });
      [['bi-arrow-up', -1], ['bi-arrow-down', 1]].forEach(function (t) {
        var b = el('button', { type: 'button', 'class': 'btn btn-sm btn-outline-secondary btn-sm-icon', title: t[1] < 0 ? 'Up' : 'Down' });
        b.appendChild(el('i', { 'class': 'bi ' + t[0] }));
        b.addEventListener('click', function () {
          var j = i + t[1]; if (j < 0 || j >= rules.length) return;
          var x = rules[i]; rules[i] = rules[j]; rules[j] = x; render();
        });
        tools.appendChild(b);
      });
      var del = el('button', { type: 'button', 'class': 'btn btn-sm btn-outline-danger btn-sm-icon', title: 'Remove' });
      del.appendChild(el('i', { 'class': 'bi bi-trash' }));
      del.addEventListener('click', function () { rules.splice(i, 1); render(); });
      tools.appendChild(del);
      head.appendChild(tools);
      body.appendChild(head);
      var row = el('div', { 'class': 'row g-2', style: 'font-size:12px;' });
      if (c && (c.kind === 'ad' || c.kind === 'ldap')) {
        var c1 = el('div', { 'class': 'col-md-6' });
        c1.appendChild(el('label', { 'class': 'form-label small mb-0' }, 'Member of any of these groups (one DN per line)'));
        var ta = el('textarea', { 'class': 'form-control form-control-sm font-monospace', rows: '3', placeholder: 'CN=noc,OU=Groups,DC=corp,DC=local' });
        ta.value = lines(r.group_dns);
        ta.addEventListener('input', function () { r.group_dns = unlines(ta.value); });
        c1.appendChild(ta);
        if (c.kind === 'ad') c1.appendChild(el('div', { 'class': 'form-text' }, 'Nested groups count (AD matching rule in chain).'));
        var c2 = el('div', { 'class': 'col-md-6' });
        c2.appendChild(el('label', { 'class': 'form-label small mb-0' }, 'And match this LDAP filter (optional)'));
        var inp = el('input', { 'class': 'form-control form-control-sm font-monospace', placeholder: '(department=NOC)' });
        inp.value = r.ldap_filter || '';
        inp.addEventListener('input', function () { r.ldap_filter = inp.value; });
        c2.appendChild(inp);
        c2.appendChild(el('div', { 'class': 'form-text' }, 'Needs the connection\'s base DN. Empty both = anyone the directory accepts.'));
        row.appendChild(c1); row.appendChild(c2);
      } else if (c && c.kind === 'radius') {
        var c3 = el('div', { 'class': 'col-md-8' });
        c3.appendChild(el('label', { 'class': 'form-label small mb-0' }, 'The reply names any of these groups (one per line)'));
        var ta2 = el('textarea', { 'class': 'form-control form-control-sm', rows: '2', placeholder: 'satom-app-users' });
        ta2.value = lines(r.radius_groups);
        ta2.addEventListener('input', function () { r.radius_groups = unlines(ta2.value); });
        c3.appendChild(ta2);
        c3.appendChild(el('div', { 'class': 'form-text' }, 'Fortinet-Group-Name in the Access-Accept: the FortiAuthenticator sends it when its RADIUS client for SATOM sends group attributes. A reply with none fails the rule. Empty = anyone the server accepts.'));
        row.appendChild(c3);
      } else if (r.connection_id === 'local') {
        row.appendChild(el('div', { 'class': 'col-12 text-muted' }, 'A local account\'s password. It may open the app only when the app is shared with it (right).'));
      }
      var c4 = el('div', { 'class': 'col-12' });
      var fc = el('div', { 'class': 'form-check' });
      var cb = el('input', { 'class': 'form-check-input', type: 'checkbox', id: 'si-2fa-' + i });
      cb.checked = !!r.require_2fa;
      cb.addEventListener('change', function () { r.require_2fa = cb.checked; });
      fc.appendChild(cb);
      fc.appendChild(el('label', { 'class': 'form-check-label', 'for': 'si-2fa-' + i }, 'Require a SATOM authenticator code (set up at the first sign-in)'));
      c4.appendChild(fc);
      row.appendChild(c4);
      body.appendChild(row);
      card.appendChild(body);
      box.appendChild(card);
    });
  }
  render();

  $('si-add').addEventListener('click', function () {
    var v = $('si-add-conn').value;
    rules.push({ connection_id: v === 'local' ? 'local' : +v, group_dns: [], ldap_filter: '', radius_groups: [], require_2fa: false });
    render();
  });
  function checked(sel) {
    return Array.prototype.filter.call(document.querySelectorAll(sel), function (c) { return c.checked; })
      .map(function (c) { return +c.value; });
  }
  $('si-save').addEventListener('click', function () {
    $('si-err').textContent = '';
    var pid = $('si-profile').value;
    post(CFG.save, {
      policy: { enabled: $('si-enabled').checked, rules: rules, profile_id: pid ? +pid : null,
                require_approval: $('si-approval').checked },
      access: { groups: checked('.si-group'), users: checked('.si-user') }
    }).then(function () { window.location.reload(); })
      .catch(function (e) { $('si-err').textContent = e.message; });
  });
  document.querySelectorAll('.si-revoke').forEach(function (b) {
    b.addEventListener('click', function () {
      if (!window.confirm('Revoke ' + b.getAttribute('data-name') + '\'s access to this app?')) return;
      post(CFG.revoke + b.getAttribute('data-uid') + '/revoke').then(function () { window.location.reload(); })
        .catch(function (e) { $('si-msg').textContent = e.message; });
    });
  });
})();
