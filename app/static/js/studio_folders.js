/* Plugin Studio > Folders (studio/index.html): Edit (name, description, the
 * ADOMs and user groups the folder hands its apps) and Delete. Server side:
 * app/views/studio.py (folder_save, folder_delete) and
 * app/services/studio_apps.py (save_folder, delete_folder). Deleting asks
 * for the folder's name typed back; its apps stay, with no folder.
 */
(function () {
  'use strict';
  var cfgEl = document.getElementById('fo-config');
  if (!cfgEl) return;
  var CFG = JSON.parse(cfgEl.textContent);
  var meta = document.querySelector('meta[name="csrf-token"]');
  var CSRF = meta ? meta.getAttribute('content') : '';
  var box = document.getElementById('foMsg');
  var modal = document.getElementById('foModal');
  var current = null;
  function msg(text, bad) {
    if (!box) return;
    box.textContent = text;
    box.className = 'small mb-2 ' + (bad ? 'text-danger' : 'text-success');
  }
  function url(tpl, id) { return tpl.replace(/\/0\//, '/' + encodeURIComponent(id) + '/'); }
  function post(u, body) {
    return fetch(u, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'X-CSRFToken': CSRF, 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {})
    }).then(function (r) {
      return r.json().catch(function () { return { error: 'HTTP ' + r.status }; }).then(function (d) {
        if (!r.ok || d.ok === false) throw new Error(d.error || ('HTTP ' + r.status));
        return d;
      });
    });
  }
  function checked(sel) {
    return Array.prototype.map.call(modal.querySelectorAll(sel + ':checked'), function (x) { return x.value; });
  }
  function tick(sel, values) {
    modal.querySelectorAll(sel).forEach(function (x) { x.checked = values.indexOf(x.value) >= 0; });
  }
  document.addEventListener('click', function (ev) {
    var b = ev.target.closest('[data-folder-act]');
    if (!b) return;
    var tr = b.closest('tr[data-folder]');
    var f = JSON.parse(tr.getAttribute('data-folder'));
    if (b.getAttribute('data-folder-act') === 'edit') {
      if (!modal || !window.bootstrap) return;
      current = f;
      document.getElementById('foTitle').textContent = f.name;
      document.getElementById('foName').value = f.name;
      document.getElementById('foDesc').value = f.description || '';
      tick('.fo-adom', f.adoms.map(String));
      tick('.fo-group', f.groups.map(String));
      window.bootstrap.Modal.getOrCreateInstance(modal).show();
      return;
    }
    var got = window.prompt('Delete folder ' + f.name + '? Its apps stay, with no folder, and ' +
                            'lose the ADOMs and user groups it gave them.\n\nType the folder name to confirm:');
    if (got === null || got.trim() !== f.name) return;
    b.disabled = true;
    post(url(CFG['delete'], f.id), {})
      .then(function (d) {
        msg('Deleted folder ' + f.name + (d.apps.length ? '; out of it now: ' + d.apps.join(', ') : '') + '.');
        window.setTimeout(function () { window.location = CFG.back; }, 1000);
      })
      .catch(function (e) { b.disabled = false; msg(e.message, true); });
  });
  var save = document.getElementById('foSave');
  if (save) save.addEventListener('click', function () {
    if (!current) return;
    save.disabled = true;
    post(url(CFG.save, current.id), {
      name: document.getElementById('foName').value,
      description: document.getElementById('foDesc').value,
      adoms: checked('.fo-adom'), groups: checked('.fo-group')
    }).then(function (d) {
      window.bootstrap.Modal.getOrCreateInstance(modal).hide();
      msg('Saved folder ' + d.name + '.');
      window.setTimeout(function () { window.location = CFG.back; }, 800);
    }).catch(function (e) { save.disabled = false; msg(e.message, true); });
  });
})();
