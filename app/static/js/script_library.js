/* Studio → Script Library. Two pages share this file:
 *  - the library index (only the run-log buttons),
 *  - the editor: file tree + code editor, form designer with live preview,
 *    settings, test runs of the saved draft, versions and publishing.
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
      var box = b.closest('.fw-card-body').querySelector('.sl-run-log');
      box.style.display = '';
      box.textContent = 'loading…';
      fetch(runUrl(b.getAttribute('data-rid')), { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
        .then(function (r) { return r.json(); })
        .then(function (st) { box.textContent = renderRun(st); })
        .catch(function (e) { box.textContent = 'Error: ' + e.message; });
    });
  });

  var code = $('sl-code');
  if (!code) return;                       // index page: done

  // ================================================================ editor
  var files = CFG.files || {};
  var fields = (CFG.fields || []).map(function (f) { return Object.assign({}, f); });
  var settings = Object.assign({}, CFG.settings || {});
  var current = files['main.py'] != null ? 'main.py' : Object.keys(files).sort()[0];
  var dirty = false;
  var problems = CFG.problems || [];

  function setDirty(v) {
    dirty = v;
    $('sl-dirty').style.display = v ? '' : 'none';
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
    if (current != null && files[current] != null) files[current] = code.value;
    current = name;
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
    files[n] = code.value; delete files[current]; current = n;
    setDirty(true); openFile(n);
  });
  $('sl-del-file').addEventListener('click', function () {
    if (current === 'main.py') return;
    if (!window.confirm('Delete ' + current + ' from the draft?')) return;
    delete files[current];
    setDirty(true);
    current = null;
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
          else { files = {}; }
        }
        names.forEach(function (n) { files[n] = d.files[n]; });
        setDirty(true);
        problems = d.problems || [];
        state(names.length + ' file(s) loaded — not saved yet', 'ok');
        openFile(names.indexOf('main.py') >= 0 ? 'main.py' : names[0]);
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
    var def = isCb ? '<div class="form-check mt-1"><input class="form-check-input sl-f" data-k="default" type="checkbox"' + (f.default ? ' checked' : '') + '><label class="form-check-label small">checked by default</label></div>'
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
          if (k === 'type') { if (v === 'password') fields[i].default = null; renderFields(); }
          renderPreview();
        });
      });
      row.querySelector('.sl-rm').addEventListener('click', function () { fields.splice(i, 1); setDirty(true); renderFields(); renderPreview(); });
      row.querySelector('.sl-up').addEventListener('click', function () { if (i > 0) { fields.splice(i - 1, 0, fields.splice(i, 1)[0]); setDirty(true); renderFields(); renderPreview(); } });
      row.querySelector('.sl-down').addEventListener('click', function () { if (i < fields.length - 1) { fields.splice(i + 1, 0, fields.splice(i, 1)[0]); setDirty(true); renderFields(); renderPreview(); } });
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
      out[f.name] = f.type === 'checkbox' ? el.checked : el.value;
    });
    return out;
  }
  function renderPreview() {
    renderForm($('sl-preview'), 'pv');
    var keep = formValues($('sl-test-form'));
    renderForm($('sl-test-form'), 'tf', keep);
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
      fields: fields
    };
  }

  // ================================================================ save / publish
  function save() {
    files[current] = code.value;
    state('saving…');
    return postJSON(URLS.save, { files: files, settings: readSettings() }).then(function (d) {
      problems = d.problems || [];
      setDirty(false);
      $('sl-title').textContent = $('sl-set-name').value;
      renderProblems(); renderGutter(); renderTree();
      state('saved' + (problems.length ? ' — ' + problems.length + ' syntax error(s); publishing is blocked until fixed' : ''), problems.length ? 'err' : 'ok');
      return d;
    }).catch(function (e) { state('Not saved: ' + e.message, 'err'); throw e; });
  }
  $('sl-save').addEventListener('click', function () { save().catch(function () {}); });
  $('sl-publish').addEventListener('click', function () {
    var note = window.prompt('Publish the saved draft as a new version.\nOperators will run this version from now on.\n\nRelease note (optional):', '');
    if (note === null) return;
    var go = dirty ? save() : Promise.resolve();
    go.then(function () { return postJSON(URLS.publish, { note: note }); })
      .then(function (d) {
        CFG.versions = d.versions; CFG.published = d.published;
        $('sl-pub').className = 'fw-badge fw-badge-success';
        $('sl-pub').textContent = 'v' + d.published + ' published';
        renderVersions();
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
  function renderVersions() {
    var rows = (CFG.versions || []).slice().reverse();
    $('sl-versions').innerHTML = rows.length ? rows.map(function (v) {
      return '<tr><td><strong>v' + v.n + '</strong>' + (v.n === CFG.published ? ' <span class="fw-badge fw-badge-success">live</span>' : '') + '</td>'
        + '<td class="text-muted">' + esc((v.at || '').slice(0, 16).replace('T', ' ')) + '</td><td>' + esc(v.by) + '</td>'
        + '<td>' + esc(v.note || '') + '</td><td>' + v.files + '</td>'
        + '<td class="text-end"><a class="btn btn-link btn-sm p-0 me-2" href="' + URLS.download + '?version=' + v.n + '">zip</a>'
        + '<button type="button" class="btn btn-link btn-sm p-0 sl-restore" data-n="' + v.n + '">restore to draft</button></td></tr>';
    }).join('') : '<tr><td colspan="6" class="text-muted p-3">Nothing published yet.</td></tr>';
    $('sl-versions').querySelectorAll('.sl-restore').forEach(function (b) {
      b.addEventListener('click', function () {
        var n = b.getAttribute('data-n');
        if (!window.confirm('Replace the draft (code, form and settings) with v' + n + '?' + (dirty ? '\nYour unsaved changes are lost.' : ''))) return;
        postJSON(URLS.restore + n, {}).then(function () { dirty = false; window.location.reload(); })
          .catch(function (e) { state(e.message, 'err'); });
      });
    });
  }
  $('sl-delete').addEventListener('click', function () {
    var typed = window.prompt('Delete this script, its versions and its draft? Run records stay.\nType the id (' + CFG.slug + ') to confirm:', '');
    if (typed !== CFG.slug) return;
    postJSON(URLS.delete, {}).then(function () { dirty = false; window.location.href = URLS.index; })
      .catch(function (e) { state(e.message, 'err'); });
  });

  // ---- boot
  loadSettings();
  renderFields();
  renderPreview();
  renderVersions();
  openFile(current);
  setDirty(false);
})();
