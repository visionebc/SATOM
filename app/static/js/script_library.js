/* Studio → Script Library. Two pages share this file:
 *  - the library index (only the run-log buttons),
 *  - the editor: file tree + code editor, form designer with live preview,
 *    settings, test runs of the saved draft, versions and publishing, and
 *    the draft history (every save/upload/restore is a revision; the editor
 *    autosaves a few seconds after the last change).
 * The editor is a plain textarea with a line-number gutter (no third-party
 * editor: the product ships offline and vendors nothing it does not need).
 * Server side: app/views/script_library.py, app/services/script_library.py.
 */
(function () {
  'use strict';

  var cfgEl = document.getElementById('sl-config');
  if (!cfgEl) return;
  var CFG = {};
  try { CFG = JSON.parse(cfgEl.textContent) || {}; } catch (e) { return; }
  var URLS = CFG.urls || {};
  var metaTok = document.querySelector('meta[name="csrf-token"]');
  var CSRF = metaTok ? metaTok.getAttribute('content') : '';

  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function postJSON(url, body) {
    return fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF, 'Accept': 'application/json' },
      body: JSON.stringify(body || {})
    }).then(function (r) {
      return r.json().catch(function () { return { error: 'HTTP ' + r.status }; })
        .then(function (d) { if (!r.ok) { throw new Error(d.error || ('HTTP ' + r.status)); } return d; });
    });
  }
  function runUrl(rid) { return URLS.run.replace('RID', encodeURIComponent(rid)); }

  // ---------------------------------------------------------------- run log
  function renderRun(st) {
    var lines = ['status: ' + st.status + (st.exit_code != null ? '  (exit ' + st.exit_code + ')' : '')
      + (st.duration_ms ? '  ' + (st.duration_ms / 1000).toFixed(1) + ' s' : '')];
    if (st.error) lines.push('error: ' + st.error);
    if (st.inputs && Object.keys(st.inputs).length) lines.push('inputs: ' + JSON.stringify(st.inputs));
    if (st.output) { lines.push('', st.output); }
    if (st.result != null) { lines.push('', 'result():', JSON.stringify(st.result, null, 2)); }
    if (st.egress && st.egress.length) { lines.push('', 'connections:'); st.egress.forEach(function (e) { lines.push('  ' + e); }); }
    return lines.join('\n');
  }
  document.querySelectorAll('.sl-run-open').forEach(function (b) {
    b.addEventListener('click', function () {
      var box = b.closest('.sl-runs-wrap').querySelector('.sl-run-log');
      box.style.display = '';
      box.textContent = 'loading…';
      fetch(runUrl(b.getAttribute('data-rid')), { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
        .then(function (r) { return r.json(); })
        .then(function (st) { box.textContent = renderRun(st); })
        .catch(function (e) { box.textContent = 'Error: ' + e.message; });
    });
  });

  // index page: filter the script table as you type
  var search = $('slSearch');
  if (search) search.addEventListener('input', function () {
    var q = search.value.trim().toLowerCase();
    document.querySelectorAll('#slTable tbody tr').forEach(function (tr) {
      tr.style.display = !q || tr.textContent.toLowerCase().indexOf(q) >= 0 ? '' : 'none';
    });
  });

  var code = $('sl-code');
  if (!code) return;                       // index page: done

  // ================================================================ editor
  var files = CFG.files || {};
  var fields = (CFG.fields || []).map(function (f) { return Object.assign({}, f); });
  var settings = Object.assign({}, CFG.settings || {});
  var creds = (CFG.credentials || []).map(function (c) { return Object.assign({}, c); });
  var credStatus = CFG.credStatus || {};
  var current = files['main.py'] != null ? 'main.py' : Object.keys(files).sort()[0];
  var dirty = false;
  var problems = CFG.problems || [];
  var shown = null;     // the file whose text is in the textarea right now

  var AUTOSAVE_MS = 4000;
  var autoTimer = null, saving = null, changes = 0;
  function setDirty(v) {
    dirty = v;
    if (v) changes++;
    $('sl-dirty').style.display = v ? '' : 'none';
    if (autoTimer) { clearTimeout(autoTimer); autoTimer = null; }
    if (v) autoTimer = setTimeout(autosave, AUTOSAVE_MS);
  }
  function autosave() {
    autoTimer = null;
    if (!dirty) return;
    if (saving) { autoTimer = setTimeout(autosave, AUTOSAVE_MS); return; }
    save('save', '', true).catch(function () {});
  }
  function state(msg, kind) {
    var el = $('sl-state');
    el.className = 'ms-2 small ' + (kind === 'err' ? 'text-danger' : kind === 'ok' ? 'text-success' : 'text-muted');
    el.textContent = msg || '';
  }
  window.addEventListener('beforeunload', function (e) {
    if (dirty) { e.preventDefault(); e.returnValue = ''; }
  });

  // ---- file tree
  function renderTree() {
    var ul = $('sl-tree');
    var names = Object.keys(files).sort(function (a, b) {
      if (a === 'main.py') return -1; if (b === 'main.py') return 1; return a.localeCompare(b);
    });
    var bad = {};
    problems.forEach(function (p) { bad[p.file] = true; });
    ul.innerHTML = names.map(function (n) {
      var icon = /\.py$/.test(n) ? 'bi-filetype-py' : 'bi-file-earmark-text';
      return '<li><a href="#" class="d-flex align-items-center px-2 py-1 text-decoration-none sl-file'
        + (n === current ? ' fw-bold' : '') + '" data-file="' + esc(n) + '" style="'
        + (n === current ? 'background:var(--fw-surface-alt);' : '') + 'color:inherit;">'
        + '<i class="bi ' + icon + ' me-1"></i><span class="text-truncate">' + esc(n) + '</span>'
        + (bad[n] ? '<i class="bi bi-exclamation-triangle-fill text-danger ms-auto" title="syntax error"></i>' : '')
        + '</a></li>';
    }).join('');
    ul.querySelectorAll('.sl-file').forEach(function (a) {
      a.addEventListener('click', function (e) { e.preventDefault(); openFile(a.getAttribute('data-file')); });
    });
    $('sl-del-file').disabled = current === 'main.py';
    $('sl-rename').disabled = current === 'main.py';
  }
  function openFile(name) {
    // Keep the edits of the file being left -- only if one is really loaded:
    // at boot the textarea is empty and must not overwrite main.py.
    if (shown != null && files[shown] != null) files[shown] = code.value;
    current = name;
    shown = name;
    code.value = files[name] || '';
    $('sl-cur-file').textContent = name;
    code.scrollTop = 0;
    renderGutter(); renderTree(); renderPos(); renderProblems();
  }
  function validName(n) {
    return /^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,63}(\/[A-Za-z0-9_][A-Za-z0-9_.\-]{0,63}){0,3}$/.test(n)
      && n.split('/').indexOf('..') < 0
      && (CFG.limits.suffixes || []).some(function (s) { return n.toLowerCase().slice(-s.length) === s; });
  }
  $('sl-new-file').addEventListener('click', function () {
    var n = window.prompt('New file name (e.g. helpers.py, lib/devices.py, data/hosts.csv):', '');
    if (!n) return;
    n = n.trim();
    if (!validName(n)) { window.alert('Invalid name. Allowed suffixes: ' + CFG.limits.suffixes.join(' ')); return; }
    if (files[n] != null) { window.alert(n + ' already exists.'); return; }
    files[current] = code.value;
    files[n] = /\.py$/.test(n) ? '' : '';
    setDirty(true);
    openFile(n);
  });
  $('sl-rename').addEventListener('click', function () {
    if (current === 'main.py') return;
    var n = window.prompt('Rename ' + current + ' to:', current);
    if (!n || n === current) return;
    n = n.trim();
    if (!validName(n)) { window.alert('Invalid name.'); return; }
    if (files[n] != null) { window.alert(n + ' already exists.'); return; }
    files[n] = code.value; delete files[current]; current = n; shown = n;
    setDirty(true); openFile(n);
  });
  $('sl-del-file').addEventListener('click', function () {
    if (current === 'main.py') return;
    if (!window.confirm('Delete ' + current + ' from the draft?')) return;
    delete files[current];
    setDirty(true);
    current = null; shown = null;
    openFile('main.py');
  });
  $('sl-upload').addEventListener('change', function () {
    var f = this.files[0];
    this.value = '';
    if (!f) return;
    var fd = new FormData();
    fd.append('file', f);
    state('uploading ' + f.name + '…');
    fetch(URLS.upload, { method: 'POST', credentials: 'same-origin', headers: { 'X-CSRFToken': CSRF }, body: fd })
      .then(function (r) { return r.json().then(function (d) { if (!r.ok) throw new Error(d.error || r.status); return d; }); })
      .then(function (d) {
        var names = Object.keys(d.files);
        var clash = names.filter(function (n) { return files[n] != null; });
        var replaceAll = false;
        if (/\.zip$/i.test(f.name)) {
          replaceAll = window.confirm('The zip holds ' + names.length + ' file(s).\n\nOK = REPLACE the whole draft with the zip\nCancel = merge into the current files');
        }
        if (!replaceAll && clash.length && !window.confirm('Overwrite ' + clash.join(', ') + '?')) return;
        files[current] = code.value;
        if (replaceAll) {
          if (d.files['main.py'] == null) { window.alert('The zip has no main.py; merging instead.'); }
          else { files = {}; shown = null; }
        }
        names.forEach(function (n) { files[n] = d.files[n]; });
        problems = d.problems || [];
        openFile(names.indexOf('main.py') >= 0 ? 'main.py' : names[0]);
        // An upload is saved at once, as its own revision in the history.
        setDirty(true);
        return save('upload', f.name);
      })
      .catch(function (e) { state('Upload refused: ' + e.message, 'err'); });
  });

  // ---- editor behaviour
  function renderGutter() {
    var n = code.value.split('\n').length;
    var bad = {};
    problems.forEach(function (p) { if (p.file === current) bad[p.line] = true; });
    var out = [];
    for (var i = 1; i <= n; i++) out.push(bad[i] ? '<span style="color:#8B1C2A;font-weight:700;">' + i + '</span>' : i);
    $('sl-gutter').innerHTML = out.join('\n');
    $('sl-gutter').scrollTop = code.scrollTop;
  }
  function renderPos() {
    var before = code.value.slice(0, code.selectionStart).split('\n');
    $('sl-pos').textContent = 'Ln ' + before.length + ', Col ' + (before[before.length - 1].length + 1);
  }
  function renderProblems() {
    var box = $('sl-problems');
    if (!problems.length) { box.innerHTML = '<span class="text-success"><i class="bi bi-check-circle me-1"></i>No syntax errors</span>'; return; }
    box.innerHTML = problems.map(function (p, i) {
      return '<div><a href="#" class="text-danger sl-prob" data-i="' + i + '"><i class="bi bi-x-circle me-1"></i>'
        + esc(p.file) + ':' + p.line + ' — ' + esc(p.message) + '</a></div>';
    }).join('');
    box.querySelectorAll('.sl-prob').forEach(function (a) {
      a.addEventListener('click', function (e) {
        e.preventDefault();
        var p = problems[+a.getAttribute('data-i')];
        if (p.file !== current) openFile(p.file);
        goLine(p.line);
      });
    });
  }
  function goLine(line) {
    var lines = code.value.split('\n');
    var pos = 0;
    for (var i = 0; i < Math.min(line - 1, lines.length); i++) pos += lines[i].length + 1;
    code.focus();
    code.setSelectionRange(pos, pos + (lines[line - 1] || '').length);
    code.scrollTop = Math.max(0, (line - 5) * 18);
    renderPos();
  }
  code.addEventListener('input', function () { files[current] = code.value; setDirty(true); renderGutter(); renderPos(); });
  code.addEventListener('scroll', function () { $('sl-gutter').scrollTop = code.scrollTop; });
  code.addEventListener('click', renderPos);
  code.addEventListener('keyup', renderPos);
  code.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 's') { e.preventDefault(); save(); return; }
    if (e.key === 'Tab') {
      e.preventDefault();
      var s = code.selectionStart, en = code.selectionEnd, v = code.value;
      var ls = v.lastIndexOf('\n', s - 1) + 1;
      if (s === en && !e.shiftKey) {
        code.setRangeText('    ', s, en, 'end');
      } else {
        var block = v.slice(ls, en);
        var nb = e.shiftKey ? block.replace(/^ {1,4}/gm, '') : block.replace(/^/gm, '    ');
        code.setRangeText(nb, ls, en, 'select');
      }
      code.dispatchEvent(new Event('input'));
      return;
    }
    if (e.key === 'Enter') {
      // keep the indentation of the current line; one level more after ':'
      var p = code.selectionStart, val = code.value;
      var lineStart = val.lastIndexOf('\n', p - 1) + 1;
      var line = val.slice(lineStart, p);
      var ind = (line.match(/^\s*/) || [''])[0];
      if (/:\s*$/.test(line)) ind += '    ';
      e.preventDefault();
      code.setRangeText('\n' + ind, p, code.selectionEnd, 'end');
      code.dispatchEvent(new Event('input'));
    }
  });
  $('sl-check').addEventListener('click', function () {
    files[current] = code.value;
    postJSON(URLS.check, { files: files }).then(function (d) {
      problems = d.problems || [];
      renderProblems(); renderGutter(); renderTree();
      state(problems.length ? problems.length + ' syntax error(s)' : 'syntax OK', problems.length ? 'err' : 'ok');
    }).catch(function (e) { state(e.message, 'err'); });
  });

  // ================================================================ form
  var TYPES = CFG.fieldTypes || ['text'];
  function fieldRow(f, i) {
    var opts = TYPES.map(function (t) { return '<option' + (t === f.type ? ' selected' : '') + '>' + t + '</option>'; }).join('');
    var isSel = f.type === 'select', isPw = f.type === 'password', isCb = f.type === 'checkbox';
    var isDb = DB_TYPES.indexOf(f.type) >= 0;
    var def = isDb ? '<div class="small text-muted mt-1">' + (f.type === 'dataset' ? 'The whole result goes to the script.' : 'Choices come from the query below.') + '</div>'
      : isCb ? '<div class="form-check mt-1"><input class="form-check-input sl-f" data-k="default" type="checkbox"' + (f.default ? ' checked' : '') + '><label class="form-check-label small">checked by default</label></div>'
      : '<input class="form-control form-control-sm sl-f" data-k="default" placeholder="' + (isPw ? 'no default for passwords' : 'default') + '" value="' + esc(f.default == null ? '' : f.default) + '"' + (isPw ? ' disabled' : '') + '>';
    return '<div class="border rounded p-2 mb-2 sl-field" data-i="' + i + '" style="border-color:var(--fw-border)!important;">'
      + '<div class="row g-2 align-items-end">'
      + '<div class="col-md-3"><label class="form-label small mb-0">Variable</label><input class="form-control form-control-sm sl-f" data-k="name" value="' + esc(f.name) + '" placeholder="host"></div>'
      + '<div class="col-md-4"><label class="form-label small mb-0">Label</label><input class="form-control form-control-sm sl-f" data-k="label" value="' + esc(f.label) + '" placeholder="Host"></div>'
      + '<div class="col-md-2"><label class="form-label small mb-0">Type</label><select class="form-select form-select-sm sl-f" data-k="type">' + opts + '</select></div>'
      + '<div class="col-md-3 d-flex gap-1 justify-content-end">'
      + '<div class="form-check me-auto mt-1"><input class="form-check-input sl-f" data-k="required" type="checkbox"' + (f.required ? ' checked' : '') + '><label class="form-check-label small">required</label></div>'
      + '<button type="button" class="btn btn-outline-secondary btn-sm py-0 sl-up" title="up">↑</button>'
      + '<button type="button" class="btn btn-outline-secondary btn-sm py-0 sl-down" title="down">↓</button>'
      + '<button type="button" class="btn btn-outline-danger btn-sm py-0 sl-rm" title="remove">✕</button></div>'
      + '<div class="col-md-5">' + def + '</div>'
      + '<div class="col-md-7"><input class="form-control form-control-sm sl-f" data-k="help" value="' + esc(f.help || '') + '" placeholder="help text (optional)"></div>'
      + (isSel ? '<div class="col-12"><label class="form-label small mb-0">Options (one per line)</label><textarea class="form-control form-control-sm sl-f" data-k="options" rows="3">' + esc((f.options || []).join('\n')) + '</textarea></div>' : '')
      + (isDb ? '<div class="col-12 sl-qb" data-i="' + i + '"></div>' : '')
      + '</div></div>';
  }
  function renderFields() {
    var box = $('sl-fields');
    box.innerHTML = fields.length ? fields.map(fieldRow).join('')
      : '<div class="text-muted small">No fields: the script runs without input.</div>';
    $('sl-field-count').textContent = fields.length || '';
    box.querySelectorAll('.sl-field').forEach(function (row) {
      var i = +row.getAttribute('data-i');
      row.querySelectorAll('.sl-f').forEach(function (inp) {
        var ev = inp.tagName === 'SELECT' || inp.type === 'checkbox' ? 'change' : 'input';
        inp.addEventListener(ev, function () {
          var k = inp.getAttribute('data-k');
          var v = inp.type === 'checkbox' ? inp.checked : inp.value;
          if (k === 'options') v = inp.value.split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
          fields[i][k] = v;
          setDirty(true);
          if (k === 'type') {
            if (v === 'password' || DB_TYPES.indexOf(v) >= 0) fields[i].default = null;
            if (DB_TYPES.indexOf(v) >= 0 && !fields[i].query) {
              fields[i].query = { base: 'appliances', joins: [], columns: [{ table: 'appliances', col: 'id' }, { table: 'appliances', col: 'name' }], filters: [], limit: 100 };
              fields[i].value_col = 'appliances.id'; fields[i].label_col = 'appliances.name';
            }
            renderFields();
          }
          renderPreview();
        });
      });
      row.querySelector('.sl-rm').addEventListener('click', function () { fields.splice(i, 1); setDirty(true); renderFields(); renderPreview(); });
      row.querySelector('.sl-up').addEventListener('click', function () { if (i > 0) { fields.splice(i - 1, 0, fields.splice(i, 1)[0]); setDirty(true); renderFields(); renderPreview(); } });
      row.querySelector('.sl-down').addEventListener('click', function () { if (i < fields.length - 1) { fields.splice(i + 1, 0, fields.splice(i, 1)[0]); setDirty(true); renderFields(); renderPreview(); } });
    });
    box.querySelectorAll('.sl-qb').forEach(function (qb) { renderQB(+qb.getAttribute('data-i'), qb); });
  }

  // ================================================================ database fields
  // A database field's query is a Report Builder spec: base table, joins
  // (picked from the tables related to it, so the admin never types a key),
  // columns, filters, order and limit. The SERVER adds the ADOM scope and
  // runs it (services/db_lookup.py); this only edits the spec.
  var DB_TYPES = ['lookup', 'lookup_multi', 'dataset'];
  var QB_OPS = ['=', '!=', '>', '<', '>=', '<=', 'like', 'not-like', 'is-null', 'is-not-null', 'in'];
  var CAT = null, RELATED = {};
  function getJSON(url) {
    return fetch(url, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json().then(function (d) { if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status)); return d; }); });
  }
  function catalog() {
    if (CAT) return Promise.resolve(CAT);
    return getJSON(URLS.lookupCatalog).then(function (d) {
      CAT = { tables: d.tables || [], by: {} };
      CAT.tables.forEach(function (t) { CAT.by[t.name] = t; });
      return CAT;
    });
  }
  function related(base) {
    if (RELATED[base]) return Promise.resolve(RELATED[base]);
    return getJSON(URLS.lookupRelated + '?base=' + encodeURIComponent(base)).then(function (d) { RELATED[base] = d.related || []; return RELATED[base]; });
  }
  function qTables(q) { return [q.base].concat((q.joins || []).map(function (j) { return j.table; })); }
  function qColNames(q) {
    return (q.columns || []).map(function (c) { return (c.table || q.base) + '.' + c.col; });
  }
  function qbChanged(i) { setDirty(true); renderPreview(); }
  function renderQB(i, box) {
    var f = fields[i], q = f.query || (f.query = { base: 'appliances', joins: [], columns: [], filters: [], limit: 100 });
    box.innerHTML = '<div class="text-muted small">loading the database catalogue…</div>';
    catalog().then(function (cat) { return related(q.base).then(function (rel) { drawQB(i, box, cat, rel); }); })
      .catch(function (e) { box.innerHTML = '<div class="text-danger small">' + esc(e.message) + '</div>'; });
  }
  function drawQB(i, box, cat, rel) {
    var f = fields[i], q = f.query;
    // A saved query carries only the keys it uses: no "joins" when it joins
    // nothing. Normalise before anything pushes into them.
    q.joins = q.joins || []; q.columns = q.columns || []; q.filters = q.filters || [];
    var used = qTables(q);
    var colSet = {}; qColNames(q).forEach(function (n) { colSet[n] = true; });
    var allCols = [];
    used.forEach(function (t) { ((cat.by[t] || {}).columns || []).forEach(function (c) { allCols.push(t + '.' + c.name); }); });
    var chosen = qColNames(q);
    function opt(v, cur, label) { return '<option value="' + esc(v) + '"' + (v === cur ? ' selected' : '') + '>' + esc(label || v) + '</option>'; }
    var h = '<div class="border rounded p-2" style="border-color:var(--fw-border)!important;background:var(--fw-content-bg,#F3F6FC);">';
    h += '<div class="d-flex align-items-center gap-2 mb-2"><i class="bi bi-database text-accent"></i><strong class="small">Database query</strong>'
      + '<span class="text-muted small">Read-only. Each user sees only the rows of their ADOMs.</span></div>';
    h += '<div class="row g-2 align-items-end mb-2"><div class="col-md-5"><label class="form-label small mb-0">Table</label><select class="form-select form-select-sm" data-qb="base">'
      + cat.tables.map(function (t) { return opt(t.name, q.base, t.label + (t.label !== t.name ? ' (' + t.name + ')' : '')); }).join('') + '</select></div>';
    var free = rel.filter(function (r) { return used.indexOf(r.table) < 0; });
    h += '<div class="col-md-7"><label class="form-label small mb-0">Combine with a related table</label><select class="form-select form-select-sm" data-qb="join"><option value="">— add a table —</option>'
      + free.map(function (r, k) { return '<option value="' + k + '">' + esc(r.label) + ' — ' + esc(r.phrase) + (r.hops > 1 ? ' (via ' + r.hops + ' joins)' : '') + '</option>'; }).join('') + '</select></div></div>';
    used.forEach(function (t, ti) {
      var cols = (cat.by[t] || {}).columns || [];
      h += '<div class="mb-1"><span class="small fw-semibold">' + esc((cat.by[t] || {}).label || t) + '</span>'
        + (ti > 0 ? ' <button type="button" class="btn btn-link btn-sm p-0 text-danger" data-qb="unjoin" data-t="' + esc(t) + '">remove</button>' : '')
        // A wide table (baselines, appliances…) is dozens of columns: a
        // checkbox dropdown whose button says what is ticked, not a wall of
        // loose checkboxes. Same pattern as the API token pickers.
        + '<div class="dropdown sl-colpick" data-t="' + esc(t) + '">'
        + '<button class="form-select form-select-sm text-start text-truncate" type="button" data-bs-toggle="dropdown" data-bs-auto-close="outside" aria-expanded="false"><span class="sl-colpick-sum"></span></button>'
        + '<div class="dropdown-menu w-100 p-2" style="max-height:320px;overflow-y:auto;">'
        + (cols.length > 8 ? '<input type="search" class="form-control form-control-sm mb-2 sl-colpick-search" placeholder="Filter columns…" aria-label="Filter columns">' : '')
        + '<div class="d-flex gap-3 mb-1 small"><button type="button" class="btn btn-link btn-sm p-0" data-qb="colall">All</button><button type="button" class="btn btn-link btn-sm p-0" data-qb="colnone">None</button></div>'
        + cols.map(function (c, ci) {
          var n = t + '.' + c.name, id = 'slqb' + i + '-' + ti + '-' + ci;
          return '<div class="form-check sl-colpick-item" data-text="' + esc(c.name.toLowerCase()) + '"><input type="checkbox" class="form-check-input" id="' + id + '" data-qb="col" data-n="' + esc(n) + '"' + (colSet[n] ? ' checked' : '') + '><label class="form-check-label small w-100" for="' + id + '">' + esc(c.name) + '</label></div>';
        }).join('') + '</div></div></div>';
    });
    h += '<div class="mt-2"><span class="small fw-semibold">Filters</span>';
    (q.filters || []).forEach(function (fl, k) {
      var n = (fl.table || q.base) + '.' + fl.col, nul = fl.op === 'is-null' || fl.op === 'is-not-null';
      h += '<div class="d-flex gap-1 mt-1"><select class="form-select form-select-sm" data-qb="fcol" data-k="' + k + '">' + allCols.map(function (c) { return opt(c, n); }).join('') + '</select>'
        + '<select class="form-select form-select-sm" style="max-width:130px" data-qb="fop" data-k="' + k + '">' + QB_OPS.map(function (o) { return opt(o, fl.op || '='); }).join('') + '</select>'
        + '<input class="form-control form-control-sm" data-qb="fval" data-k="' + k + '" value="' + esc(fl.value == null ? '' : fl.value) + '"' + (nul ? ' disabled' : '') + ' placeholder="' + (fl.op === 'in' ? 'a, b, c' : 'value') + '">'
        + '<button type="button" class="btn btn-outline-danger btn-sm py-0" data-qb="frm" data-k="' + k + '">✕</button></div>';
    });
    h += ' <button type="button" class="btn btn-link btn-sm p-0" data-qb="fadd">+ add a filter</button></div>';
    var ob = q.order_by || {};
    h += '<div class="row g-2 mt-1 align-items-end"><div class="col-md-5"><label class="form-label small mb-0">Order by</label><select class="form-select form-select-sm" data-qb="ocol"><option value="">—</option>'
      + allCols.map(function (c) { return opt(c, ob.col ? (ob.table || q.base) + '.' + ob.col : ''); }).join('') + '</select></div>'
      + '<div class="col-md-3"><label class="form-label small mb-0">&nbsp;</label><select class="form-select form-select-sm" data-qb="odir">' + opt('asc', ob.dir || 'asc', 'ascending') + opt('desc', ob.dir || 'asc', 'descending') + '</select></div>'
      + '<div class="col-md-4"><label class="form-label small mb-0">Max rows (≤500)</label><input type="number" min="1" max="500" class="form-control form-control-sm" data-qb="limit" value="' + esc(q.limit || 100) + '"></div></div>';
    if (f.type !== 'dataset') {
      h += '<div class="row g-2 mt-1"><div class="col-md-6"><label class="form-label small mb-0">Value (what the script gets)</label><select class="form-select form-select-sm" data-qb="vcol">' + chosen.map(function (c) { return opt(c, f.value_col); }).join('') + '</select></div>'
        + '<div class="col-md-6"><label class="form-label small mb-0">Label (what the user sees)</label><select class="form-select form-select-sm" data-qb="lcol">' + chosen.map(function (c) { return opt(c, f.label_col || f.value_col); }).join('') + '</select></div></div>';
    }
    h += '<div class="mt-2 d-flex gap-2 align-items-center"><button type="button" class="btn btn-sm btn-fw-outline" data-qb="preview"><i class="bi bi-eye me-1"></i>Preview rows</button><span class="small text-muted" data-qb="pmsg"></span></div>'
      + '<div class="sl-qb-out mt-2" style="max-height:260px;overflow:auto;"></div></div>';
    box.innerHTML = h;
    function redraw() { drawQB(i, box, cat, rel); qbChanged(i); }
    function syncPick() {
      var names = qColNames(q);
      if (names.indexOf(f.value_col) < 0) f.value_col = names[0] || '';
      if (names.indexOf(f.label_col) < 0) f.label_col = f.value_col;
    }
    box.querySelector('[data-qb="base"]').addEventListener('change', function () {
      q.base = this.value; q.joins = []; q.filters = []; q.order_by = null;
      var cols = (cat.by[q.base] || {}).columns || [];
      q.columns = cols.slice(0, 2).map(function (c) { return { table: q.base, col: c.name }; });
      syncPick(); related(q.base).then(function (r) { rel = r; redraw(); });
    });
    box.querySelector('[data-qb="join"]').addEventListener('change', function () {
      var r = free[+this.value]; if (!r) return;
      (r.path || []).forEach(function (st) {
        if (qTables(q).indexOf(st.to_table) >= 0) return;
        q.joins.push({ table: st.to_table, from_table: st.from_table, from_col: st.from_col, to_col: st.to_col });
      });
      redraw();
    });
    box.querySelectorAll('[data-qb="unjoin"]').forEach(function (b) {
      b.addEventListener('click', function () {
        var gone = [b.getAttribute('data-t')], again = true;
        while (again) {   // drop the table and every join hanging from it
          again = false;
          q.joins.forEach(function (j) { if (gone.indexOf(j.from_table) >= 0 && gone.indexOf(j.table) < 0) { gone.push(j.table); again = true; } });
        }
        q.joins = q.joins.filter(function (j) { return gone.indexOf(j.table) < 0; });
        q.columns = q.columns.filter(function (c) { return gone.indexOf(c.table || q.base) < 0; });
        q.filters = (q.filters || []).filter(function (x) { return gone.indexOf(x.table || q.base) < 0; });
        if (q.order_by && gone.indexOf(q.order_by.table || q.base) >= 0) q.order_by = null;
        syncPick(); redraw();
      });
    });
    // Ticking a column must NOT redraw: that would close the open dropdown on
    // every click. Update the spec, the summaries and the value/label lists in place.
    function setCol(cb) {
      var n = cb.getAttribute('data-n'), dot = n.indexOf('.'), t = n.slice(0, dot), c = n.slice(dot + 1);
      q.columns = q.columns.filter(function (x) { return !((x.table || q.base) === t && x.col === c); });
      if (cb.checked) q.columns.push({ table: t, col: c });
    }
    function refreshCols(changed) {
      box.querySelectorAll('.sl-colpick').forEach(function (p) {
        var all = p.querySelectorAll('[data-qb="col"]'), on = p.querySelectorAll('[data-qb="col"]:checked');
        var sum = p.querySelector('.sl-colpick-sum'), names = Array.prototype.map.call(on, function (x) { return x.parentNode.textContent; });
        sum.textContent = on.length ? on.length + ' of ' + all.length + ': ' + names.join(', ') : 'No columns (' + all.length + ' available)';
        sum.classList.toggle('text-muted', !on.length);
      });
      syncPick();
      var names = qColNames(q);
      [[box.querySelector('[data-qb="vcol"]'), f.value_col], [box.querySelector('[data-qb="lcol"]'), f.label_col || f.value_col]].forEach(function (pair) {
        if (pair[0]) pair[0].innerHTML = names.map(function (c) { return opt(c, pair[1]); }).join('');
      });
      if (changed !== false) qbChanged(i);
    }
    box.querySelectorAll('[data-qb="col"]').forEach(function (cb) {
      cb.addEventListener('change', function () { setCol(cb); refreshCols(); });
    });
    box.querySelectorAll('.sl-colpick').forEach(function (p) {
      function bulk(on) {
        p.querySelectorAll('.sl-colpick-item:not(.d-none) [data-qb="col"]').forEach(function (cb) { if (cb.checked !== on) { cb.checked = on; setCol(cb); } });
        refreshCols();
      }
      p.querySelector('[data-qb="colall"]').addEventListener('click', function () { bulk(true); });
      p.querySelector('[data-qb="colnone"]').addEventListener('click', function () { bulk(false); });
      var s = p.querySelector('.sl-colpick-search');
      if (s) s.addEventListener('input', function () {
        var v = s.value.trim().toLowerCase();
        p.querySelectorAll('.sl-colpick-item').forEach(function (it) { it.classList.toggle('d-none', !!v && it.getAttribute('data-text').indexOf(v) < 0); });
      });
    });
    refreshCols(false);
    function split(n) { var d = n.indexOf('.'); return { table: n.slice(0, d), col: n.slice(d + 1) }; }
    box.querySelector('[data-qb="fadd"]').addEventListener('click', function () {
      var c = split(allCols[0] || (q.base + '.id'));
      (q.filters = q.filters || []).push({ table: c.table, col: c.col, op: '=', value: '' }); redraw();
    });
    box.querySelectorAll('[data-qb="frm"]').forEach(function (b) { b.addEventListener('click', function () { q.filters.splice(+b.getAttribute('data-k'), 1); redraw(); }); });
    box.querySelectorAll('[data-qb="fcol"]').forEach(function (el) { el.addEventListener('change', function () { var c = split(el.value), fl = q.filters[+el.getAttribute('data-k')]; fl.table = c.table; fl.col = c.col; qbChanged(i); }); });
    box.querySelectorAll('[data-qb="fop"]').forEach(function (el) { el.addEventListener('change', function () { q.filters[+el.getAttribute('data-k')].op = el.value; redraw(); }); });
    box.querySelectorAll('[data-qb="fval"]').forEach(function (el) {
      el.addEventListener('input', function () {
        var fl = q.filters[+el.getAttribute('data-k')];
        fl.value = fl.op === 'in' ? el.value.split(',').map(function (s) { return s.trim(); }).filter(Boolean) : el.value;
        qbChanged(i);
      });
    });
    box.querySelector('[data-qb="ocol"]').addEventListener('change', function () {
      if (!this.value) { q.order_by = null; } else { var c = split(this.value); q.order_by = { table: c.table, col: c.col, dir: (q.order_by || {}).dir || 'asc' }; }
      qbChanged(i);
    });
    box.querySelector('[data-qb="odir"]').addEventListener('change', function () { if (q.order_by) { q.order_by.dir = this.value; qbChanged(i); } });
    box.querySelector('[data-qb="limit"]').addEventListener('input', function () { q.limit = Math.max(1, Math.min(500, +this.value || 100)); qbChanged(i); });
    var vc = box.querySelector('[data-qb="vcol"]'), lc = box.querySelector('[data-qb="lcol"]');
    if (vc) vc.addEventListener('change', function () { f.value_col = vc.value; qbChanged(i); });
    if (lc) lc.addEventListener('change', function () { f.label_col = lc.value; qbChanged(i); });
    box.querySelector('[data-qb="preview"]').addEventListener('click', function () {
      var out = box.querySelector('.sl-qb-out'), msg = box.querySelector('[data-qb="pmsg"]');
      msg.textContent = 'running…'; out.innerHTML = '';
      postJSON(URLS.lookupPreview, { field: f }).then(function (d) {
        msg.textContent = d.row_count + ' row(s) for your ADOMs' + (d.truncated ? ' (more than the limit)' : '') + (d.row_count > d.rows.length ? ', first ' + d.rows.length + ' shown' : '');
        out.innerHTML = '<table class="fw-table table table-sm mb-0" style="font-size:12px;"><thead><tr>' + d.columns.map(function (c) { return '<th>' + esc(c) + (c === d.value_col ? ' <span class="fw-badge fw-badge-info">value</span>' : '') + (c === d.label_col ? ' <span class="fw-badge fw-badge-secondary">label</span>' : '') + '</th>'; }).join('') + '</tr></thead><tbody>'
          + d.rows.map(function (r) { return '<tr>' + d.columns.map(function (c) { return '<td>' + esc(r[c]) + '</td>'; }).join('') + '</tr>'; }).join('') + '</tbody></table>';
      }).catch(function (e) { msg.textContent = ''; out.innerHTML = '<div class="text-danger small">' + esc(e.message) + '</div>'; });
    });
  }
  $('sl-add-field').addEventListener('click', function () {
    if (fields.length >= CFG.limits.fields) { window.alert('At most ' + CFG.limits.fields + ' fields.'); return; }
    var n = 1; while (fields.some(function (f) { return f.name === 'field_' + n; })) n++;
    fields.push({ name: 'field_' + n, label: 'Field ' + n, type: 'text', required: false, help: '', default: null });
    setDirty(true); renderFields(); renderPreview();
  });

  // The operator's form, drawn from the field list (same function for the
  // preview and the Test tab, so what you test is what they get).
  function renderForm(form, prefix, values) {
    values = values || {};
    form.innerHTML = fields.length ? fields.map(function (f) {
      var id = prefix + '-' + esc(f.name);
      var req = f.required ? ' <span class="text-danger">*</span>' : '';
      var help = f.help ? '<div class="form-text">' + esc(f.help) + '</div>' : '';
      var v = values[f.name] != null ? values[f.name] : (f.default == null ? '' : f.default);
      var ctl;
      if (f.type === 'textarea') ctl = '<textarea class="form-control form-control-sm" rows="3" id="' + id + '" name="' + esc(f.name) + '">' + esc(v) + '</textarea>';
      else if (f.type === 'select') ctl = '<select class="form-select form-select-sm" id="' + id + '" name="' + esc(f.name) + '">' + (f.required ? '' : '<option value=""></option>') + (f.options || []).map(function (o) { return '<option' + (o === v ? ' selected' : '') + '>' + esc(o) + '</option>'; }).join('') + '</select>';
      else if (f.type === 'lookup' || f.type === 'lookup_multi') ctl = '<select class="form-select form-select-sm" id="' + id + '" name="' + esc(f.name) + '" data-lookup-i="' + fields.indexOf(f) + '"' + (f.type === 'lookup_multi' ? ' multiple size="5"' : '') + '><option value="" disabled>loading…</option></select>';
      else if (f.type === 'dataset') ctl = '<div class="form-text mt-0"><i class="bi bi-database me-1"></i>Rows from the SATOM database are read when the run starts and passed to the script.</div>';
      else if (f.type === 'checkbox') return '<div class="form-check mb-2"><input class="form-check-input" type="checkbox" id="' + id + '" name="' + esc(f.name) + '"' + (v === true ? ' checked' : '') + '><label class="form-check-label small" for="' + id + '">' + esc(f.label || f.name) + '</label>' + help + '</div>';
      else ctl = '<input class="form-control form-control-sm" type="' + (f.type === 'number' ? 'number' : f.type === 'password' ? 'password' : 'text') + '" id="' + id + '" name="' + esc(f.name) + '" value="' + (f.type === 'password' ? '' : esc(v)) + '"' + (f.type === 'password' ? ' autocomplete="new-password"' : '') + (f.type === 'number' ? ' step="any"' : '') + '>';
      return '<div class="mb-2"><label class="form-label small mb-0" for="' + id + '">' + esc(f.label || f.name) + req + '</label>' + ctl + help + '</div>';
    }).join('') : '<div class="text-muted small">This script takes no input.</div>';
  }
  function formValues(form) {
    var out = {};
    fields.forEach(function (f) {
      var el = form.querySelector('[name="' + f.name + '"]');
      if (!el) return;
      if (f.type === 'checkbox') out[f.name] = el.checked;
      else if (f.type === 'lookup_multi') out[f.name] = Array.prototype.filter.call(el.options, function (o) { return o.selected && o.value; }).map(function (o) { return o.value; });
      else out[f.name] = el.value;
    });
    return out;
  }
  // Pick lists of the preview and Test forms: read through the designer
  // preview, so an unsaved query already shows its choices.
  var lookupTimer = null;
  function fillLookups(form, keep) {
    form.querySelectorAll('select[data-lookup-i]').forEach(function (sel) {
      var f = fields[+sel.getAttribute('data-lookup-i')];
      if (!f) return;
      postJSON(URLS.lookupPreview, { field: f, options: true }).then(function (d) {
        var was = keep && keep[f.name], opts = d.options || [];
        sel.innerHTML = (f.type === 'lookup' && !f.required ? '<option value=""></option>' : '')
          + opts.map(function (o) {
            var on = Array.isArray(was) ? was.indexOf(o.value) >= 0 : was === o.value;
            return '<option value="' + esc(o.value) + '"' + (on ? ' selected' : '') + '>' + esc(o.label) + '</option>';
          }).join('') + (opts.length ? '' : '<option value="" disabled>no rows</option>');
      }).catch(function (e) { sel.innerHTML = '<option value="" disabled>' + esc(e.message) + '</option>'; });
    });
  }
  function renderPreview() {
    renderForm($('sl-preview'), 'pv');
    var keep = formValues($('sl-test-form'));
    renderForm($('sl-test-form'), 'tf', keep);
    clearTimeout(lookupTimer);
    lookupTimer = setTimeout(function () { fillLookups($('sl-preview')); fillLookups($('sl-test-form'), keep); }, 400);
  }
  [$('sl-preview'), $('sl-test-form')].forEach(function (f) { f.addEventListener('submit', function (e) { e.preventDefault(); }); });

  // ================================================================ settings
  function loadSettings() {
    $('sl-set-name').value = settings.name || '';
    $('sl-set-desc').value = settings.description || '';
    $('sl-set-timeout').value = settings.timeout || 60;
    $('sl-set-audience').value = settings.audience || 'admins';
    ($('sl-net-' + (settings.network || 'none')) || $('sl-net-none')).checked = true;
  }
  ['sl-set-name', 'sl-set-desc', 'sl-set-timeout', 'sl-set-audience', 'sl-net-none', 'sl-net-egress'].forEach(function (id) {
    $(id).addEventListener('input', function () { setDirty(true); });
    $(id).addEventListener('change', function () { setDirty(true); });
  });
  function readSettings() {
    return {
      name: $('sl-set-name').value, description: $('sl-set-desc').value,
      timeout: parseInt($('sl-set-timeout').value, 10) || 60,
      audience: $('sl-set-audience').value,
      network: $('sl-net-egress').checked ? 'egress' : 'none',
      fields: fields,
      credentials: creds,
      connections: conns
    };
  }

  // ================================================================ connections
  // Studio connections the script declares: services/studio_broker.py answers
  // satom_script.connection() for these and refuses every other.
  var conns = (CFG.connections || []).slice();
  function renderConns() {
    var box = $('sl-conns');
    if (!box) return;
    var all = CFG.studioConnections || [];
    box.innerHTML = all.length ? all.map(function (c) {
      return '<label class="small"><input type="checkbox" class="sl-conn" value="' + esc(c.slug) + '"' +
        (conns.indexOf(c.slug) >= 0 ? ' checked' : '') + '> ' + esc(c.name) + ' <code>' + esc(c.slug) + '</code>' +
        (c.kind === 'postgres' ? ' (PostgreSQL)' : '') + (c.secret && !CFG.vaultOk ? ' <span class="fw-badge fw-badge-warning">needs the vault</span>' : '') + '</label>';
    }).join('') : '<div class="text-muted small">No connections exist yet (Python Studio &gt; Connections).</div>';
    conns.filter(function (k) { return !all.some(function (c) { return c.slug === k; }); }).forEach(function (k) {
      box.insertAdjacentHTML('beforeend', '<label class="small text-danger"><input type="checkbox" class="sl-conn" value="' + esc(k) + '" checked> ' + esc(k) + ' — does not exist</label>');
    });
    box.querySelectorAll('.sl-conn').forEach(function (cb) {
      cb.addEventListener('change', function () {
        conns = Array.prototype.filter.call(box.querySelectorAll('.sl-conn'), function (x) { return x.checked; }).map(function (x) { return x.value; });
        setDirty(true);
      });
    });
  }
  renderConns();

  // ================================================================ credentials
  function credRow(c, i) {
    var st = credStatus[c.name];
    var badge = !CFG.vaultOk ? '<span class="fw-badge fw-badge-secondary">no vault</span>'
      : st === 'stored' ? '<span class="fw-badge fw-badge-success">stored</span>'
      : st === 'not set' ? '<span class="fw-badge fw-badge-warning">not set</span>'
      : st ? '<span class="fw-badge fw-badge-danger" title="' + esc(st) + '">error</span>'
      : '<span class="fw-badge fw-badge-secondary">save first</span>';
    var isUp = c.kind !== 'secret';
    return '<div class="border rounded p-2 mb-2 sl-cred" data-i="' + i + '" style="border-color:var(--fw-border)!important;">'
      + '<div class="row g-2 align-items-end">'
      + '<div class="col-md-3"><label class="form-label small mb-0">Name</label><input class="form-control form-control-sm sl-c" data-k="name" value="' + esc(c.name) + '" placeholder="FGT_ADMIN"></div>'
      + '<div class="col-md-4"><label class="form-label small mb-0">Label</label><input class="form-control form-control-sm sl-c" data-k="label" value="' + esc(c.label || '') + '"></div>'
      + '<div class="col-md-3"><label class="form-label small mb-0">Kind</label><select class="form-select form-select-sm sl-c" data-k="kind">'
      + '<option value="userpass"' + (isUp ? ' selected' : '') + '>user + password</option>'
      + '<option value="secret"' + (!isUp ? ' selected' : '') + '>single value (token, key)</option></select></div>'
      + '<div class="col-md-2 d-flex gap-1 justify-content-end align-items-center">' + badge
      + '<button type="button" class="btn btn-outline-danger btn-sm py-0 sl-crm" title="remove">✕</button></div>'
      + '<div class="col-12 d-flex gap-2 align-items-end">'
      + (isUp ? '<input class="form-control form-control-sm sl-cv" data-k="username" placeholder="username" autocomplete="off" style="max-width:220px;">' : '')
      + '<input class="form-control form-control-sm sl-cv" data-k="' + (isUp ? 'password' : 'value') + '" type="password" autocomplete="new-password" placeholder="' + (isUp ? 'password' : 'value') + '" style="max-width:260px;">'
      + '<button type="button" class="btn btn-outline-primary btn-sm sl-cset"' + (CFG.vaultOk ? '' : ' disabled') + '>Set value</button>'
      + '<span class="small text-muted sl-cmsg"></span></div>'
      + '</div></div>';
  }
  function renderCreds() {
    var box = $('sl-creds');
    box.innerHTML = creds.length ? creds.map(credRow).join('') : '<div class="text-muted small">No credentials declared.</div>';
    box.querySelectorAll('.sl-cred').forEach(function (row) {
      var i = +row.getAttribute('data-i');
      row.querySelectorAll('.sl-c').forEach(function (inp) {
        inp.addEventListener(inp.tagName === 'SELECT' ? 'change' : 'input', function () {
          var k = inp.getAttribute('data-k');
          creds[i][k] = k === 'name' ? inp.value.toUpperCase().replace(/[^A-Z0-9_]/g, '_') : inp.value;
          if (k === 'name') inp.value = creds[i].name;
          delete credStatus[creds[i].name];
          setDirty(true);
          if (k === 'kind') renderCreds();
        });
      });
      row.querySelector('.sl-crm').addEventListener('click', function () {
        if (!window.confirm('Remove ' + creds[i].name + ' from the script? Its stored value is kept until the script is deleted.')) return;
        creds.splice(i, 1); setDirty(true); renderCreds();
      });
      row.querySelector('.sl-cset').addEventListener('click', function () {
        var body = {};
        row.querySelectorAll('.sl-cv').forEach(function (v) { body[v.getAttribute('data-k')] = v.value; });
        var msg = row.querySelector('.sl-cmsg');
        var name = creds[i].name;
        var go = dirty ? save() : Promise.resolve();
        msg.textContent = 'storing…';
        go.then(function () { return postJSON(URLS.credential.replace('NAME', encodeURIComponent(name)), body); })
          .then(function (d) {
            credStatus[name] = d.status || 'stored';
            row.querySelectorAll('.sl-cv').forEach(function (v) { v.value = ''; });
            renderCreds();
          })
          .catch(function (e) { msg.className = 'small text-danger sl-cmsg'; msg.textContent = e.message; });
      });
    });
  }
  var addCred = $('sl-add-cred');
  if (addCred) addCred.addEventListener('click', function () {
    var n = 1; while (creds.some(function (c) { return c.name === 'CREDENTIAL_' + n; })) n++;
    creds.push({ name: 'CREDENTIAL_' + n, label: '', kind: 'userpass' });
    setDirty(true); renderCreds();
  });

  // ================================================================ save / publish
  function save(kind, note, auto) {
    files[current] = code.value;
    state(auto ? 'autosaving…' : 'saving…');
    var sent = changes;
    var p = postJSON(URLS.save, { files: files, settings: readSettings(), kind: kind || 'save', note: note || '' }).then(function (d) {
      problems = d.problems || [];
      if (d.cred_status) { credStatus = d.cred_status; renderCreds(); }
      if (d.revisions) { CFG.revisions = d.revisions; renderRevisions(); }
      // Typing while the request was in flight is NOT saved: stay dirty.
      if (changes === sent) setDirty(false); else setDirty(true);
      $('sl-title').textContent = $('sl-set-name').value;
      renderProblems(); renderGutter(); renderTree();
      var last = (CFG.revisions || [])[(CFG.revisions || []).length - 1];
      var when = new Date().toTimeString().slice(0, 5);
      state((kind === 'upload' ? 'uploaded and saved' : auto ? 'saved automatically' : 'saved') + ' ' + when
        + (last ? ' · v' + last.n : '')
        + (problems.length ? ' — ' + problems.length + ' syntax error(s); publishing is blocked until fixed' : ''), problems.length ? 'err' : 'ok');
      return d;
    }).catch(function (e) { state('Not saved: ' + e.message, 'err'); throw e; });
    saving = p;
    p.then(function () { saving = null; }, function () { saving = null; });
    return p;
  }
  $('sl-save').addEventListener('click', function () { save().catch(function () {}); });
  $('sl-publish').addEventListener('click', function () {
    var latest = (CFG.revisions || [])[(CFG.revisions || []).length - 1];
    var note = window.prompt('Publish ' + (latest ? 'v' + latest.n + ' (the latest version)' : 'the latest version') + '.\nOperators will run it from now on.\n\nRelease note (optional):', '');
    if (note === null) return;
    var go = dirty ? save() : Promise.resolve();
    go.then(function () { return postJSON(URLS.publish, { note: note }); })
      .then(function (d) {
        CFG.versions = d.versions; CFG.published = d.published;
        $('sl-pub').className = 'fw-badge fw-badge-success';
        $('sl-pub').textContent = 'v' + d.published + ' published';
        if (d.revisions) CFG.revisions = d.revisions;
        renderRevisions();
        state('published v' + d.published, 'ok');
      })
      .catch(function (e) { state(e.message, 'err'); });
  });

  // ================================================================ test
  function poll(rid, n) {
    fetch(runUrl(rid), { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); })
      .then(function (st) {
        var badge = { ok: 'success', failed: 'danger', timeout: 'warning', running: 'info', queued: 'secondary' }[st.status] || 'secondary';
        $('sl-test-status').innerHTML = '<span class="fw-badge fw-badge-' + badge + '">' + esc(st.status) + '</span>'
          + (st.duration_ms ? ' <span class="text-muted small">' + (st.duration_ms / 1000).toFixed(1) + ' s</span>' : '');
        $('sl-test-out').textContent = (st.error ? 'error: ' + st.error + '\n\n' : '') + (st.output || '');
        $('sl-test-result').textContent = st.result != null ? JSON.stringify(st.result, null, 2) : '';
        $('sl-test-egress').textContent = (st.egress || []).join('\n');
        if (st.status === 'queued' || st.status === 'running') {
          if (n > 600) { $('sl-test-out').textContent += '\n(still ' + st.status + ' — is satom-scripts.path enabled on this node?)'; return; }
          setTimeout(function () { poll(rid, n + 1); }, n < 10 ? 500 : 1500);
        }
      })
      .catch(function () { setTimeout(function () { poll(rid, n + 1); }, 2000); });
  }
  $('sl-run-test').addEventListener('click', function () {
    var inputs = formValues($('sl-test-form'));
    $('sl-test-out').textContent = ''; $('sl-test-result').textContent = ''; $('sl-test-egress').textContent = '';
    $('sl-test-status').innerHTML = '<span class="fw-badge fw-badge-secondary">saving…</span>';
    save().then(function () { return postJSON(URLS.test, { inputs: inputs }); })
      .then(function (st) { poll(st.request_id, 0); })
      .catch(function (e) { $('sl-test-status').innerHTML = ''; $('sl-test-out').textContent = 'Not started: ' + e.message; });
  });

  // ================================================================ versions
  // One list: every save is version N (a revision on disk, ref "r<N>");
  // publishing approves one of them, and operators run that one.
  var KIND_LABEL = { created: 'Created', save: 'Edited', upload: 'Uploaded', restore: 'Restored' };
  function liveN() { return CFG.published || null; }
  function wasPublished(n) { return (CFG.versions || []).some(function (v) { return v.n === n; }); }
  function vlabel(ref) { return ref === 'draft' ? 'the current draft' : 'v' + ref.slice(1); }
  function iconBtn(cls, ref, icon, title, extra) {
    return '<button type="button" class="btn btn-sm btn-outline-secondary btn-sm-icon me-1 ' + cls + '" data-ref="' + ref + '"'
      + (extra || '') + ' title="' + title + '"><i class="bi ' + icon + '"></i></button>';
  }
  function renderRevisions() {
    var revs = CFG.revisions || [];
    var rows = revs.slice().reverse();
    var newest = rows.length ? rows[0].n : null;
    $('sl-revisions').innerHTML = rows.length ? rows.map(function (r, i) {
      var prev = rows[i + 1];
      var what = esc(KIND_LABEL[r.kind] || r.kind) + (r.note ? ' <span class="text-muted">' + esc(r.note) + '</span>' : '')
        + (r.edits > 1 ? ' <span class="text-muted">(' + r.edits + ' saves)</span>' : '');
      var status = r.n === liveN() ? '<span class="fw-badge fw-badge-success">published</span>'
        : wasPublished(r.n) ? '<span class="fw-badge fw-badge-secondary">published before</span>'
        : r.n === newest ? '<span class="fw-badge fw-badge-warning">latest · not published</span>' : '';
      return '<tr><td><strong>v' + r.n + '</strong></td><td>' + status + '</td>'
        + '<td style="font-size:13px;white-space:nowrap;">' + esc((r.at || '').slice(0, 16).replace('T', ' ')) + '</td><td>' + esc(r.by) + '</td>'
        + '<td>' + what + '</td><td>' + r.files + '</td>'
        + '<td class="actions-col">'
        + iconBtn('sl-view', 'r' + r.n, 'bi-eye', 'View')
        + (prev ? iconBtn('sl-cmp-prev', 'r' + r.n, 'bi-arrow-left-right', 'Compare with v' + prev.n, ' data-prev="r' + prev.n + '"') : '')
        + '<a class="btn btn-sm btn-outline-secondary btn-sm-icon me-1" href="' + URLS.download + '?revision=' + r.n + '" title="Download"><i class="bi bi-download"></i></a>'
        + (r.n === newest ? '' : iconBtn('sl-rrestore', 'r' + r.n, 'bi-arrow-counterclockwise', 'Restore (saves it as a new version)'))
        + '</td></tr>';
    }).join('') : '<tr><td colspan="7" class="text-muted p-3">No versions yet: the first save creates one.</td></tr>';
    $('sl-revisions').querySelectorAll('.sl-rrestore').forEach(function (b) {
      b.addEventListener('click', function () { restoreRef(b.getAttribute('data-ref')); });
    });
    $('sl-revisions').querySelectorAll('.sl-cmp-prev').forEach(function (b) {
      b.addEventListener('click', function () { openCompare(b.getAttribute('data-prev'), b.getAttribute('data-ref')); });
    });
    bindViews($('sl-revisions'));
    renderCompareBar();
  }
  // ---- compare any two versions
  var cmpTouched = false;    // keep the operator's pick across saves; else previous -> latest
  function renderCompareBar() {
    var revs = (CFG.revisions || []).slice().reverse();
    var a = $('sl-cmp-a'), b = $('sl-cmp-b');
    if (!a) return;
    var keepA = a.value, keepB = b.value;
    var opts = revs.map(function (r) {
      return '<option value="r' + r.n + '">v' + r.n + (r.n === liveN() ? ' (published)' : '') + '</option>';
    }).join('');
    a.innerHTML = opts; b.innerHTML = opts;
    var defA = revs[1] ? 'r' + revs[1].n : (revs[0] ? 'r' + revs[0].n : '');
    var defB = revs[0] ? 'r' + revs[0].n : '';
    var has = function (v) { return v && a.querySelector('option[value="' + v + '"]'); };
    a.value = cmpTouched && has(keepA) ? keepA : defA;
    b.value = cmpTouched && has(keepB) ? keepB : defB;
    $('sl-cmp-go').disabled = revs.length < 2;
  }
  ['sl-cmp-a', 'sl-cmp-b'].forEach(function (id) {
    if ($(id)) $(id).addEventListener('change', function () { cmpTouched = true; });
  });
  $('sl-cmp-go').addEventListener('click', function () {
    if ($('sl-cmp-a').value === $('sl-cmp-b').value) { state('Pick two different versions to compare', 'err'); return; }
    openCompare($('sl-cmp-a').value, $('sl-cmp-b').value);
  });
  function restoreRef(ref) {
    var n = ref.slice(1);
    if (!window.confirm('Restore v' + n + '? Its code, form and settings are saved as a new version; nothing is deleted.'
      + (dirty ? '\nUnsaved changes of the last seconds are lost.' : ''))) return;
    var url = ref.charAt(0) === 'r' ? URLS.restoreRevision + n + '/restore' : URLS.restore + n;
    if (autoTimer) { clearTimeout(autoTimer); autoTimer = null; }
    postJSON(url, {}).then(function () { dirty = false; window.location.hash = 'history'; window.location.reload(); })
      .catch(function (e) { state(e.message, 'err'); });
  }

  // ---- read-only viewer + diff (a version against the draft, or two versions)
  var view = { ref: null, against: 'draft', files: {}, diff: null, mode: 'code' };
  function viewModal() {
    var el = $('sl-view-modal');
    return window.bootstrap && el ? window.bootstrap.Modal.getOrCreateInstance(el) : null;
  }
  function renderView() {
    var sel = $('sl-view-file');
    var body = $('sl-view-body');
    var names;
    if (view.mode === 'diff') {
      if (!view.diff) { body.textContent = 'loading…'; return; }
      names = view.diff.files.map(function (f) { return f.file; });
      var extra = view.diff.settings_changed.length ? 'Also changed: ' + view.diff.settings_changed.join(', ') + '\n\n' : '';
      if (!names.length) { sel.innerHTML = ''; body.textContent = extra + 'No code differences between ' + vlabel(view.ref) + ' and ' + vlabel(view.against) + '.'; return; }
      if (names.indexOf(sel.value) < 0) sel.innerHTML = names.map(function (n) { return '<option>' + esc(n) + '</option>'; }).join('');
      var f = view.diff.files.filter(function (x) { return x.file === sel.value; })[0] || view.diff.files[0];
      body.innerHTML = esc(extra) + f.diff.split('\n').map(function (ln) {
        var c = /^\+(?!\+\+)/.test(ln) ? '#15692A' : /^-(?!--)/.test(ln) ? '#8B1C2A' : /^@@/.test(ln) ? '#4C2A85' : '';
        return c ? '<span style="color:' + c + ';">' + esc(ln) + '</span>' : esc(ln);
      }).join('\n');
      return;
    }
    names = Object.keys(view.files).sort(function (a, b) {
      if (a === 'main.py') return -1; if (b === 'main.py') return 1; return a.localeCompare(b);
    });
    var keep = sel.value;
    sel.innerHTML = names.map(function (n) { return '<option' + (n === keep ? ' selected' : '') + '>' + esc(n) + '</option>'; }).join('');
    body.textContent = view.files[sel.value] != null ? view.files[sel.value] : '';
  }
  function setViewMode(m) {
    view.mode = m;
    $('sl-view-mode-code').classList.toggle('active', m === 'code');
    $('sl-view-mode-diff').classList.toggle('active', m === 'diff');
    $('sl-view-mode-diff').textContent = 'Changes against ' + vlabel(view.against);
    $('sl-view-file').innerHTML = '';
    if (m === 'diff' && !view.diff) {
      var go = dirty && view.against === 'draft' ? save('save', '', true) : Promise.resolve();
      go.then(function () {
        return fetch(URLS.diff + '?a=' + encodeURIComponent(view.ref) + '&b=' + encodeURIComponent(view.against),
          { credentials: 'same-origin', headers: { 'Accept': 'application/json' } });
      }).then(function (r) { return r.json(); })
        .then(function (d) { view.diff = d.files ? d : { files: [], settings_changed: [] }; renderView(); })
        .catch(function (e) { $('sl-view-body').textContent = 'Error: ' + e.message; });
    }
    renderView();
  }
  function openView(ref, against, mode) {
    var isRev = ref.charAt(0) === 'r';
    var url = (isRev ? URLS.revision : URLS.version) + ref.slice(1);
    view = { ref: ref, against: against || 'draft', files: {}, diff: null, mode: 'code' };
    var tag = function (r) { return r !== 'draft' && +r.slice(1) === liveN() ? ' (published)' : ''; };
    $('sl-view-title').textContent = CFG.slug + ' — v' + ref.slice(1) + tag(ref)
      + (view.against !== 'draft' ? ' → ' + vlabel(view.against) + tag(view.against) : '');
    $('sl-view-zip').href = URLS.download + (isRev ? '?revision=' : '?version=') + ref.slice(1);
    $('sl-view-restore').style.display = (CFG.revisions || []).length && ('r' + CFG.revisions[CFG.revisions.length - 1].n) === ref ? 'none' : '';
    $('sl-view-body').textContent = 'loading…';
    $('sl-view-meta').textContent = '';
    setViewMode(mode || 'code');
    var m = viewModal(); if (m) m.show();
    fetch(url, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (d) {
        view.files = d.files || {};
        $('sl-view-meta').textContent = (d.at || d.published_at || '').slice(0, 16).replace('T', ' ') + ' · ' + (d.by || d.published_by || '')
          + ' · ' + (d.fields || []).length + ' form field(s) · network ' + (d.network || 'none');
        if (view.mode === 'code') renderView();
      })
      .catch(function (e) { $('sl-view-body').textContent = 'Error: ' + e.message; });
  }
  function openCompare(a, b) { openView(a, b, 'diff'); }
  function bindViews(root) {
    root.querySelectorAll('.sl-view').forEach(function (b) {
      b.addEventListener('click', function () { openView(b.getAttribute('data-ref')); });
    });
  }
  $('sl-view-file').addEventListener('change', renderView);
  $('sl-view-mode-code').addEventListener('click', function () { setViewMode('code'); });
  $('sl-view-mode-diff').addEventListener('click', function () { setViewMode('diff'); });
  $('sl-view-restore').addEventListener('click', function () {
    var m = viewModal(); if (m) m.hide();
    restoreRef(view.ref);
  });

  $('sl-delete').addEventListener('click', function () {
    var typed = window.prompt('Delete this script, its versions and its draft? Run records stay.\nType the id (' + CFG.slug + ') to confirm:', '');
    if (typed !== CFG.slug) return;
    postJSON(URLS.delete, {}).then(function () { dirty = false; window.location.href = URLS.index; })
      .catch(function (e) { state(e.message, 'err'); });
  });

  // ---- boot
  loadSettings();
  renderCreds();
  renderFields();
  renderPreview();
  renderRevisions();
  openFile(current);
  setDirty(false);
  // #history / #compare (the library's row actions) open the Versions tab.
  if (window.location.hash === '#history' || window.location.hash === '#compare') {
    var tabBtn = document.querySelector('[data-bs-target="#sl-tab-versions"]');
    if (tabBtn && window.bootstrap) window.bootstrap.Tab.getOrCreateInstance(tabBtn).show();
    if (window.location.hash === '#compare' && $('sl-cmp-a')) $('sl-cmp-a').focus();
  }
})();
