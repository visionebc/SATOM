/* Administrator > Access > Groups (user_groups/index.html): create, edit and
 * delete groups. Server side: app/views/user_groups.py. */
(function () {
  'use strict';
  var cfgEl = document.getElementById('ug-config');
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
        if (!r.ok || d.ok === false) throw new Error(d.error || ('HTTP ' + r.status));
        return d;
      });
    });
  }
  var modal = window.bootstrap ? new window.bootstrap.Modal($('ug-modal')) : null;
  var editing = null;
  function open(id) {
    editing = id;
    var g = id ? CFG.data[String(id)] : { name: '', description: '', members: [] };
    $('ug-title').textContent = id ? 'Edit group' : 'New group';
    $('ug-name').value = g.name; $('ug-desc').value = g.description || ''; $('ug-err').textContent = '';
    Array.prototype.forEach.call($('ug-members').querySelectorAll('input'), function (c) {
      c.checked = g.members.indexOf(+c.value) >= 0;
    });
    if (modal) modal.show();
  }
  $('ug-new').addEventListener('click', function () { open(null); });
  document.querySelectorAll('.ug-edit').forEach(function (b) {
    b.addEventListener('click', function () { open(+b.getAttribute('data-id')); });
  });
  document.querySelectorAll('.ug-del').forEach(function (b) {
    b.addEventListener('click', function () {
      var nw = parseInt(b.getAttribute('data-wiki') || '0', 10);
      var msg = 'Delete the group ' + b.getAttribute('data-name') + '?';
      if (nw) msg += '\n\n' + nw + ' Wiki article(s) are shared with it. They stay closed: only their authors and the Wiki moderators will read them until someone picks a new audience.';
      if (!window.confirm(msg)) return;
      post(CFG.del + b.getAttribute('data-id') + '/delete').then(function () { window.location.reload(); })
        .catch(function (e) { $('ug-msg').innerHTML = '<span style="color:#8B1C2A;"></span>'; $('ug-msg').firstChild.textContent = e.message; });
    });
  });
  $('ug-save').addEventListener('click', function () {
    var members = Array.prototype.filter.call($('ug-members').querySelectorAll('input'), function (c) { return c.checked; })
      .map(function (c) { return +c.value; });
    post(CFG.save, { id: editing, name: $('ug-name').value, description: $('ug-desc').value, members: members })
      .then(function () { window.location.reload(); })
      .catch(function (e) { $('ug-err').textContent = e.message; });
  });
})();
