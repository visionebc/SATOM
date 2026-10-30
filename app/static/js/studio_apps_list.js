/* Plugin Studio > Apps (studio/index.html): the Actions column -- enable /
 * disable, menu group, reset, delete -- the search box and the menu-group
 * filter. Server side: app/views/studio.py (app_enable, app_group,
 * app_reset, app_delete) and app/services/studio_apps.py (set_enabled,
 * set_group, reset, remove). Reset and Delete
 * cannot be undone, so they ask for the app's id typed back. A template
 * (from Examples) has no Delete button and the server refuses it anyway.
 */
(function () {
  'use strict';
  var cfgEl = document.getElementById('ap-config');
  if (!cfgEl) return;
  var CFG = JSON.parse(cfgEl.textContent);
  var meta = document.querySelector('meta[name="csrf-token"]');
  var CSRF = meta ? meta.getAttribute('content') : '';
  var box = document.getElementById('apMsg');
  function msg(text, bad) {
    if (!box) return;
    box.textContent = text;
    box.className = 'small mb-2 ' + (bad ? 'text-danger' : 'text-success');
  }
  function post(url, body) {
    return fetch(url, {
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
  function typed(slug, what) {
    var got = window.prompt(what + '\n\nType the app id (' + slug + ') to confirm:');
    return got !== null && got.trim() === slug;
  }
  function list(xs) { return xs && xs.length ? xs.join(', ') : 'none'; }
  document.addEventListener('click', function (ev) {
    var b = ev.target.closest('[data-app-act]');
    if (!b) return;
    var tr = b.closest('tr[data-app]');
    var slug = tr.getAttribute('data-app');
    var act = b.getAttribute('data-app-act');
    var url, body = {}, done;
    if (act === 'group') { askGroup(slug, b.getAttribute('data-group') || ''); return; }
    if (act === 'enable' || act === 'disable') {
      url = CFG.enable; body = { enabled: act === 'enable' };
      done = function () { return (act === 'enable' ? 'Enabled ' : 'Disabled ') + slug + '.'; };
    } else if (act === 'reset') {
      if (!typed(slug, 'Reset deletes this app\'s data from the database: its run history and ' +
                 'every row of the data stores only it uses. Stores other apps use are kept. ' +
                 'Download the data first if you need it. This cannot be undone.')) return;
      url = CFG.reset;
      done = function (d) {
        return 'Reset ' + slug + ': ' + d.runs + ' run(s) and ' + d.rows + ' row(s) deleted' +
          ' (stores emptied: ' + list(d.stores) + '; shared, kept: ' + list(d.shared) + ').';
      };
    } else if (act === 'delete') {
      if (!typed(slug, 'Delete this app for good, with its runs and the data stores only it ' +
                 'uses (a script app: its code, versions, saved runs and credentials). ' +
                 'Connections and APIs are kept. This cannot be undone.')) return;
      url = CFG['delete'];
      done = function () { return 'Deleted ' + slug + '.'; };
    } else {
      return;
    }
    b.disabled = true;
    post(url.replace('SLUG', encodeURIComponent(slug)), body)
      .then(function (d) {
        msg(done(d));
        window.setTimeout(function () { window.location = CFG.back; }, 1200);
      })
      .catch(function (e) { b.disabled = false; msg(e.message, true); });
  });
  // Menu group: a modal with the groups that exist as suggestions; "" takes
  // the app out of its group.
  var gModal = document.getElementById('apGroupModal');
  var gSlug = null;
  function askGroup(slug, current) {
    if (!gModal || !window.bootstrap) return;
    gSlug = slug;
    document.getElementById('apGroupSlug').textContent = slug;
    var inp = document.getElementById('apGroupInput');
    inp.value = current;
    window.bootstrap.Modal.getOrCreateInstance(gModal).show();
    window.setTimeout(function () { inp.focus(); inp.select(); }, 200);
  }
  var gSave = document.getElementById('apGroupSave');
  if (gSave) gSave.addEventListener('click', function () {
    if (!gSlug) return;
    gSave.disabled = true;
    post(CFG.group.replace('SLUG', encodeURIComponent(gSlug)),
         { group: document.getElementById('apGroupInput').value })
      .then(function (d) {
        window.bootstrap.Modal.getOrCreateInstance(gModal).hide();
        msg(d.group ? gSlug + ' is in menu group ' + d.group + '.' : gSlug + ' has no menu group now.');
        window.setTimeout(function () { window.location = CFG.back; }, 900);
      })
      .catch(function (e) { gSave.disabled = false; msg(e.message, true); });
  });
  // Search and menu-group filter: a row shows when it matches both.
  var search = document.getElementById('apSearch');
  var gFilter = document.getElementById('apGroupFilter');
  function filterRows() {
    var q = search ? search.value.trim().toLowerCase() : '';
    var g = gFilter ? gFilter.value : '*';
    document.querySelectorAll('#apTable tbody tr[data-app]').forEach(function (tr) {
      var okText = !q || tr.textContent.toLowerCase().indexOf(q) >= 0;
      var okGroup = g === '*' || (tr.getAttribute('data-group') || '') === g;
      tr.style.display = okText && okGroup ? '' : 'none';
    });
  }
  if (search) search.addEventListener('input', filterRows);
  if (gFilter) gFilter.addEventListener('change', filterRows);
  // Import app package: the button is the label of a hidden file input;
  // choosing a file submits the form (layout sweep 2026-10-24).
  var imp = document.querySelector('input[data-ap-import]');
  if (imp) imp.addEventListener('change', function () {
    if (!imp.files || !imp.files.length || !imp.form) return;
    if (imp.form.requestSubmit) imp.form.requestSubmit(); else imp.form.submit();
  });
})();
