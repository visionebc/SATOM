/* Plugin Studio > Apps (studio/index.html): the Actions column -- enable /
 * disable, menu group, clone, reset, delete -- the search box and the menu-group
 * filter. Server side: app/views/studio.py (app_enable, app_group,
 * app_clone, app_reset, app_delete) and app/services/studio_apps.py
 * (set_enabled, set_group, clone, reset, remove). Reset and Delete
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
    if (act === 'clone') { askClone(slug); return; }
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
  // Clone: a dialog that asks for the new id and name and, for a flow app,
  // whether the copy takes everything (the rows of its data stores), only
  // the structure (the same stores, empty) or the same data (no copy: both
  // apps use the original's stores). No mode is preselected: the
  // operator chooses. The copy writes to its own stores
  // (studio_apps.clone); stores other apps use too stay shared unless ticked.
  var cModal = document.getElementById('apCloneModal');
  var cSrc = null, cKind = 'flow';
  var cGo = document.getElementById('apCloneGo');
  function stores(xs) {
    return xs.map(function (s) { return s.slug + ' (' + s.rows + ' row' + (s.rows === 1 ? '' : 's') + ')'; }).join(', ');
  }
  function cloneReady() {
    if (!cGo) return;
    var slugOk = /^[a-z0-9][a-z0-9_-]{1,47}$/.test(document.getElementById('apCloneSlug').value.trim());
    var mode = document.querySelector('input[name="apCloneMode"]:checked');
    // Same data: nothing is copied, so "copy the shared stores too" has no say
    var cs = document.getElementById('apCloneCopyShared');
    cs.disabled = !!(mode && mode.value === 'shared');
    if (cs.disabled) cs.checked = false;
    cGo.disabled = !(slugOk && (cKind === 'script' || mode));
  }
  function askClone(slug) {
    if (!cModal || !window.bootstrap) return;
    fetch(CFG.clone_plan.replace('SLUG', encodeURIComponent(slug)),
          { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (p) {
        if (!p.ok) throw new Error(p.error || 'cannot read the app');
        cSrc = slug; cKind = p.kind;
        document.getElementById('apCloneSrc').textContent = slug;
        var base = (slug.slice(0, 43) + '-copy');
        document.getElementById('apCloneSlug').value = base;
        document.getElementById('apCloneName').value = (p.name + ' (copy)').slice(0, 120);
        document.querySelectorAll('input[name="apCloneMode"]').forEach(function (r) { r.checked = false; });
        document.getElementById('apCloneCopyShared').checked = false;
        document.getElementById('apCloneFlow').classList.toggle('d-none', p.kind === 'script');
        document.getElementById('apCloneScript').classList.toggle('d-none', p.kind !== 'script');
        document.getElementById('apCloneOwn').textContent = p.own.length
          ? 'Data stores only this app uses: ' + stores(p.own) + '.'
          : 'This app uses no data store of its own.';
        document.getElementById('apCloneSharedBox').classList.toggle('d-none', !p.shared.length);
        document.getElementById('apCloneShared').textContent = p.shared.length
          ? 'Shared with other apps: ' + stores(p.shared) + '.' : '';
        cloneReady();
        window.bootstrap.Modal.getOrCreateInstance(cModal).show();
      })
      .catch(function (e) { msg(e.message, true); });
  }
  if (cModal) {
    cModal.addEventListener('input', cloneReady);
    cModal.addEventListener('change', cloneReady);
  }
  if (cGo) cGo.addEventListener('click', function () {
    if (!cSrc) return;
    var mode = document.querySelector('input[name="apCloneMode"]:checked');
    cGo.disabled = true;
    post(CFG.clone.replace('SLUG', encodeURIComponent(cSrc)), {
      slug: document.getElementById('apCloneSlug').value.trim(),
      name: document.getElementById('apCloneName').value.trim(),
      mode: cKind === 'script' ? 'structure' : (mode ? mode.value : ''),
      copy_shared: document.getElementById('apCloneCopyShared').checked
    }).then(function (d) {
      window.bootstrap.Modal.getOrCreateInstance(cModal).hide();
      var copied = (d.stores || []).map(function (s) { return s.from + ' → ' + s.to + ' (' + s.rows + ' rows)'; });
      msg('Cloned ' + cSrc + ' as ' + d.slug + (copied.length ? ': ' + copied.join(', ') : '') +
          (d.shared && d.shared.length ? '; same data as the original: ' + d.shared.join(', ') : '') +
          '. Opening the copy…');
      window.setTimeout(function () { window.location = d.edit; }, 1200);
    }).catch(function (e) { cGo.disabled = false; msg(e.message, true); });
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
