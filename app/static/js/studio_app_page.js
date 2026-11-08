/* Plugin Studio > Apps > a page plugin (studio/app_page.html): save where
 * the entry is drawn, delete. Server side: views.studio.app_settings /
 * app_delete, services.studio_apps (which re-checks everything sent here).
 */
(function () {
  'use strict';
  var cfgEl = document.getElementById('ap-page-config');
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
      return r.json().catch(function () { return { ok: false, error: 'HTTP ' + r.status }; }).then(function (d) {
        if (!r.ok || d.ok === false) throw new Error(d.error || ('HTTP ' + r.status));
        return d;
      });
    });
  }
  function state(text, bad) {
    $('ap-state').innerHTML = text ? '<span style="font-size:12px;color:' + (bad ? '#8B1C2A' : '#15692A') + ';">' + esc(text) + '</span>' : '';
  }
  function checked(sel) {
    return Array.prototype.filter.call(document.querySelectorAll(sel), function (c) { return c.checked; })
      .map(function (c) { return c.value; });
  }
  $('ap-save-settings').addEventListener('click', function () {
    // a page plugin has no access list: the page's permission decides who
    post(U.settings, {
      name: $('ap-name').value, icon: $('ap-icon').value, description: $('ap-desc').value,
      group: $('ap-menu-group').value, adoms: checked('.ap-adom'), access: { groups: [], users: [] }
    }).then(function () { $('ap-title').textContent = $('ap-name').value; state('Settings saved.'); })
      .catch(function (e) { state(e.message, true); });
  });
  // Source code (read-only): one file of the page's closed list at a time,
  // fetched as text and drawn escaped, a line per span (the gutter is CSS).
  var files = document.querySelectorAll('.ap-src-file');
  Array.prototype.forEach.call(files, function (btn) {
    btn.addEventListener('click', function () {
      var path = btn.getAttribute('data-path');
      var view = $('ap-src-view');
      var role = $('ap-src-role');
      Array.prototype.forEach.call(files, function (b) { b.classList.toggle('active', b === btn); });
      role.textContent = 'Loading ' + path + '…';
      fetch(U.source + '?path=' + encodeURIComponent(path), { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
        .then(function (r) { return r.json().then(function (d) { if (!r.ok || !d.ok) throw new Error(d.error || ('HTTP ' + r.status)); return d; }); })
        .then(function (d) {
          var i = (CFG.paths || []).indexOf(path);
          role.textContent = path + (i >= 0 && CFG.roles[i] ? ' — ' + CFG.roles[i] : '');
          view.innerHTML = d.text.replace(/\n$/, '').split('\n').map(function (l) {
            return '<span class="ap-ln">' + esc(l) + '</span>';
          }).join('');
          view.classList.remove('d-none');
          view.scrollTop = 0;
        })
        .catch(function (e) { role.textContent = e.message; view.classList.add('d-none'); });
    });
  });
  if ($('ap-delete')) $('ap-delete').addEventListener('click', function () {
    if (!window.confirm('Delete the app ' + CFG.slug + '? The page stays in SATOM and keeps answering by its address.')) return;
    post(U['delete']).then(function () { window.location = U.back; }).catch(function (e) { state(e.message, true); });
  });
})();
