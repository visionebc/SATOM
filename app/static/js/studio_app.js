/* Python Studio > Apps > editor (studio/app.html): settings, the form
 * designer, the actions designer, test runs and publishing. The diagram tab
 * is process_editor.js; test runs are drawn by apps_run.js. Server side:
 * app/views/studio.py (app_*), app/services/studio_apps.py, which re-checks
 * everything this page sends.
 */
(function () {
  'use strict';
  var cfgEl = document.getElementById('ap-config');
  if (!cfgEl) return;
  var CFG = JSON.parse(cfgEl.textContent);
  var U = CFG.urls, CH = CFG.choices || {};
  var fields = (CFG.fields || []).map(function (f) { return Object.assign({}, f); });
  var actions = (CFG.actions || []).map(function (a) { return JSON.parse(JSON.stringify(a)); });
  var SCHEMA = {};
  CFG.actionSchema.forEach(function (s) { SCHEMA[s.key] = s; });
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
  function problems(list) {
    var box = $('ap-problems');
    if (!box || !list) return;
    box.innerHTML = list.length
      ? '<div class="alert alert-warning py-2" style="font-size:12px;"><strong>Fix before publishing:</strong><ul class="mb-0">' +
        list.map(function (p) { return '<li>' + esc(p) + '</li>'; }).join('') + '</ul></div>'
      : '<div class="text-success small mb-2"><i class="bi bi-check-circle me-1"></i>The draft is ready to publish.</div>';
  }
  function opts(list, cur) {
    return '<option value="">—</option>' + (list || []).map(function (x) {
      return '<option' + (x === cur ? ' selected' : '') + '>' + esc(x) + '</option>';
    }).join('');
  }
  function checked(sel) {
    return Array.prototype.filter.call(document.querySelectorAll(sel), function (c) { return c.checked; })
      .map(function (c) { return c.value; });
  }

  /* ── settings ─────────────────────────────────────────────────────── */
  $('ap-save-settings').addEventListener('click', function () {
    post(U.settings, {
      name: $('ap-name').value, icon: $('ap-icon').value, description: $('ap-desc').value,
      adoms: checked('.ap-adom'), access: { groups: checked('.ap-group'), users: checked('.ap-user') }
    }).then(function () { $('ap-title').textContent = $('ap-name').value; state('Settings saved.'); })
      .catch(function (e) { state(e.message, true); });
  });

  /* ── form designer ────────────────────────────────────────────────── */
  var LIST_TYPES = ['select', 'store_select', 'api_select', 'satom_select'];
  function inp(i, k, v, ph, w) {
    return '<input class="form-control form-control-sm" data-i="' + i + '" data-k="' + k + '" value="' + esc(v || '') +
      '" placeholder="' + esc(ph || '') + '"' + (w ? ' style="max-width:' + w + 'px;"' : '') + '>';
  }
  function drawFields() {
    $('ap-fields').innerHTML = fields.map(function (f, i) {
      var t = f.type;
      var extra = '';
      if (t === 'select') {
        extra = '<textarea class="form-control form-control-sm" rows="2" data-i="' + i + '" data-k="options" placeholder="One choice per line">' + esc(f.options || '') + '</textarea>';
      } else if (t === 'store_select') {
        extra = '<div class="d-flex gap-2"><select class="form-select form-select-sm" data-i="' + i + '" data-k="store">' + opts(CH.stores, f.store) + '</select>' +
          inp(i, 'value_col', f.value_col, 'value column') + inp(i, 'label_col', f.label_col, 'label column (optional)') + '</div>';
      } else if (t === 'satom_select') {
        extra = '<select class="form-select form-select-sm" style="max-width:420px;" data-i="' + i + '" data-k="source">' +
          '<option value="">What the list shows…</option>' +
          (CH.satom_sources || []).map(function (s) {
            return '<option value="' + esc(s.key) + '"' + (s.key === f.source ? ' selected' : '') + '>' + esc(s.label) + '</option>';
          }).join('') + '</select>';
      } else if (t === 'api_select') {
        extra = '<div class="d-flex gap-2"><select class="form-select form-select-sm" data-i="' + i + '" data-k="connection">' + opts(CH.http, f.connection) + '</select>' +
          inp(i, 'path', f.path, '/path') + inp(i, 'list_path', f.list_path, 'list JSON path, e.g. items') +
          inp(i, 'value_key', f.value_key, 'value key') + inp(i, 'label_key', f.label_key, 'label key') + '</div>';
      }
      return '<div class="border rounded p-2 mb-2" data-row="' + i + '"><div class="d-flex gap-2 align-items-center flex-wrap">' +
        inp(i, 'name', f.name, 'name', 160) + inp(i, 'label', f.label, 'Label', 220) +
        '<select class="form-select form-select-sm" style="max-width:150px;" data-i="' + i + '" data-k="type">' +
        CFG.fieldTypes.map(function (x) { return '<option' + (x === t ? ' selected' : '') + '>' + x + '</option>'; }).join('') + '</select>' +
        '<div class="form-check"><input class="form-check-input" type="checkbox" data-i="' + i + '" data-k="required"' + (f.required ? ' checked' : '') + '><label class="form-check-label small">required</label></div>' +
        (LIST_TYPES.indexOf(t) >= 0
          ? '<div class="form-check" title="A search box over the choices"><input class="form-check-input" type="checkbox" data-i="' + i + '" data-k="search"' + (f.search ? ' checked' : '') + '><label class="form-check-label small">searchable</label></div>'
          : '') +
        (t === 'password' ? '' : inp(i, 'default', f['default'], 'default', 160)) +
        '<span class="ms-auto"><button type="button" class="btn btn-sm btn-outline-secondary" data-mv="-1" data-i="' + i + '">↑</button> ' +
        '<button type="button" class="btn btn-sm btn-outline-secondary" data-mv="1" data-i="' + i + '">↓</button> ' +
        '<button type="button" class="btn btn-sm btn-outline-danger" data-rm="1" data-i="' + i + '">✕</button></span></div>' +
        (extra ? '<div class="mt-2">' + extra + '</div>' : '') +
        '<div class="mt-2">' + inp(i, 'help', f.help, 'help text (optional)') + '</div></div>';
    }).join('') || '<div class="text-muted small">No fields: the app runs without a form.</div>';
  }
  function fieldChange(e) {
    var el = e.target, i = el.getAttribute('data-i'), k = el.getAttribute('data-k');
    if (i === null || !k) return;
    fields[+i][k] = el.type === 'checkbox' ? el.checked : el.value;
    if (k === 'type' && e.type === 'change') drawFields();
  }
  $('ap-fields').addEventListener('input', fieldChange);
  $('ap-fields').addEventListener('change', fieldChange);
  $('ap-fields').addEventListener('click', function (e) {
    var b = e.target.closest('button'); if (!b) return;
    var i = +b.getAttribute('data-i');
    if (b.getAttribute('data-rm')) { fields.splice(i, 1); drawFields(); return; }
    var mv = +b.getAttribute('data-mv');
    if (mv && fields[i + mv]) { var t = fields[i]; fields[i] = fields[i + mv]; fields[i + mv] = t; drawFields(); }
  });
  $('ap-field-add').addEventListener('click', function () {
    fields.push({ name: 'field_' + (fields.length + 1), label: 'Field ' + (fields.length + 1), type: 'text', required: false });
    drawFields();
  });
  $('ap-save-form').addEventListener('click', function () {
    post(U.draft, { fields: fields }).then(function (d) { state('Form saved.'); problems(d.problems); loadTestForm(); })
      .catch(function (e) { state(e.message, true); });
  });

  /* ── actions designer ─────────────────────────────────────────────── */
  function drawActions() {
    $('ap-actions').innerHTML = actions.map(function (a, i) {
      var s = SCHEMA[a.kind] || { params: [], label: a.kind };
      a.params = a.params || {};
      return '<div class="border rounded p-2 mb-2"><div class="d-flex gap-2 align-items-center flex-wrap">' +
        '<span class="fw-badge fw-badge-info">' + esc(s.label) + '</span>' +
        '<input class="form-control form-control-sm" style="max-width:150px;" data-a="' + i + '" data-k="key" value="' + esc(a.key) + '" placeholder="key">' +
        '<input class="form-control form-control-sm" style="max-width:240px;" data-a="' + i + '" data-k="label" value="' + esc(a.label) + '" placeholder="Button label">' +
        '<div class="form-check"><input class="form-check-input" type="checkbox" data-a="' + i + '" data-k="confirm"' + (a.confirm ? ' checked' : '') + '><label class="form-check-label small">ask to confirm</label></div>' +
        '<button type="button" class="btn btn-sm btn-outline-danger ms-auto" data-arm="' + i + '">✕</button></div>' +
        '<div class="row g-2 mt-1">' + s.params.map(function (p) {
          var v = a.params[p.name] !== undefined ? a.params[p.name] : p['default'];
          a.params[p.name] = v;
          var ctl;
          if (p.kind === 'select') {
            ctl = '<select class="form-select form-select-sm" data-a="' + i + '" data-p="' + p.name + '">' + opts(p.choices, v) + '</select>';
          } else if (p.kind === 'textarea' || p.kind === 'json') {
            ctl = '<textarea class="form-control form-control-sm" rows="2" data-a="' + i + '" data-p="' + p.name + '" style="font-family:ui-monospace,Menlo,monospace;">' + esc(v) + '</textarea>';
          } else {
            ctl = '<input class="form-control form-control-sm" data-a="' + i + '" data-p="' + p.name + '" value="' + esc(v) + '">';
          }
          return '<div class="col-md-6"><label class="form-label small mb-0">' + esc(p.label) + '</label>' + ctl +
            (p.help ? '<div class="form-text">' + esc(p.help) + '</div>' : '') + '</div>';
        }).join('') + '</div></div>';
    }).join('') || '<div class="text-muted small">No actions: the output is only shown.</div>';
  }
  function actionChange(e) {
    var el = e.target, i = el.getAttribute('data-a');
    if (i === null) return;
    var a = actions[+i];
    if (el.getAttribute('data-p')) { a.params[el.getAttribute('data-p')] = el.value; return; }
    var k = el.getAttribute('data-k');
    if (k) a[k] = el.type === 'checkbox' ? el.checked : el.value;
  }
  $('ap-actions').addEventListener('input', actionChange);
  $('ap-actions').addEventListener('change', actionChange);
  $('ap-actions').addEventListener('click', function (e) {
    var b = e.target.closest('[data-arm]'); if (!b) return;
    actions.splice(+b.getAttribute('data-arm'), 1); drawActions();
  });
  $('ap-action-add').addEventListener('click', function () {
    var kind = $('ap-action-kind').value;
    actions.push({ key: kind.replace(/_/g, '-') + '-' + (actions.length + 1), label: SCHEMA[kind].label, kind: kind, confirm: kind === 'change_request', params: {} });
    drawActions();
  });
  $('ap-save-actions').addEventListener('click', function () {
    post(U.draft, { actions: actions }).then(function (d) { state('Actions saved.'); problems(d.problems); })
      .catch(function (e) { state(e.message, true); });
  });

  /* ── test ─────────────────────────────────────────────────────────── */
  function loadTestForm() {
    fetch(U.form, { credentials: 'same-origin' }).then(function (r) { return r.text(); })
      .then(function (h) { $('ap-test-form').innerHTML = h; });
  }
  $('ap-test-reload').addEventListener('click', loadTestForm);
  if (window.AppRun) {
    window.AppRun.mount({ form: $('ap-test-form'), runBtn: $('ap-test-run'), out: $('ap-test-out'), runUrl: U.test,
                          extra: function () { return { rehearsal: $('ap-rehearsal').checked }; } });
  }

  /* ── publish ──────────────────────────────────────────────────────── */
  $('ap-publish').addEventListener('click', function () {
    post(U.publish, { note: $('ap-note').value }).then(function (d) {
      state('Published as v' + d.version + '. Reloading…');
      window.setTimeout(function () { window.location.reload(); }, 700);
    }).catch(function (e) { state(e.message, true); });
  });
  if ($('ap-unpublish')) $('ap-unpublish').addEventListener('click', function () {
    if (!window.confirm('Remove the app from the menu? Its versions are kept.')) return;
    post(U.unpublish).then(function () { window.location.reload(); }).catch(function (e) { state(e.message, true); });
  });
  // Absent for a template (Examples): templates are never deleted.
  if ($('ap-delete')) $('ap-delete').addEventListener('click', function () {
    if (!window.confirm('Delete the app ' + CFG.slug + ' for good, with its versions, its runs and the data stores only it uses?')) return;
    post(U['delete']).then(function () { window.location = U.back; }).catch(function (e) { state(e.message, true); });
  });

  /* ── diagram: analysis and the last run ──────────────────────────── */
  function li(items, colour) {
    return items.length ? '<ul class="mb-1" style="color:' + colour + ';">' + items.map(function (x) {
      return '<li>' + esc(x) + '</li>'; }).join('') + '</ul>' : '';
  }
  if ($('ap-analyze')) $('ap-analyze').addEventListener('click', function () {
    var g = window.SatomProcEditor ? window.SatomProcEditor.graph() : null;
    post(U.analyze, g ? { graph: g } : {}).then(function (d) {
      var sm = d.summary || {};
      var h = '<div class="fw-card"><div class="fw-card-header"><span class="fw-card-title" style="font-size:13px;">' +
        '<i class="bi bi-search me-2 text-accent"></i>Analysis</span><span class="text-muted ms-2" style="font-size:12px;">' +
        sm.steps + ' steps · ' + sm.writes + ' write · ' + sm.device_writes + ' on a device · ' + sm.error_arrows + ' error arrows</span></div>' +
        '<div class="fw-card-body">';
      if (d.problems.length) h += '<strong style="color:#8B1C2A;">Blocks publishing</strong>' + li(d.problems, '#8B1C2A');
      if (d.warnings.length) h += '<strong style="color:#7A5700;">Worth a look</strong>' + li(d.warnings, '#7A5700');
      if (!d.problems.length && !d.warnings.length) h += '<div style="color:#15692A;" class="mb-2">No problems and nothing suspicious.</div>';
      h += '<table class="table table-sm mb-0" style="font-size:12px;"><thead><tr><th>Step</th><th>Kind</th><th>Saves</th><th>Reads</th><th>On error</th></tr></thead><tbody>' +
        d.steps.map(function (st) {
          return '<tr data-step="' + esc(st.key) + '" style="cursor:pointer;' + (st.reachable ? '' : 'opacity:.55;') + '"><td><strong>' + esc(st.label) + '</strong><div class="text-muted"><code>' + esc(st.key) + '</code></div></td>' +
            '<td>' + esc(st.kind_label) + (st.device ? ' <span class="fw-badge fw-badge-danger">device</span>' : (st.writes ? ' <span class="fw-badge fw-badge-warning">writes</span>' : '')) + '</td>' +
            '<td>' + (st.saves ? '<code>' + esc(st.saves) + '</code>' : '') + '</td>' +
            '<td>' + st.reads.concat(st.reads_form.map(function (x) { return 'form.' + x; })).map(function (x) { return '<code>' + esc(x) + '</code>'; }).join(' ') + '</td>' +
            '<td>' + esc(st.on_error || '') + (st.undo && st.undo.length ? '<div class="text-muted">undo: ' + esc(st.undo.join(', ')) + '</div>' : '') + '</td></tr>';
        }).join('') + '</tbody></table></div></div>';
      $('ap-analysis').innerHTML = h;
    }).catch(function (e) { $('ap-analysis').innerHTML = '<span style="color:#8B1C2A;">' + esc(e.message) + '</span>'; });
  });
  if ($('ap-analysis')) $('ap-analysis').addEventListener('click', function (e) {
    var tr = e.target.closest('[data-step]');
    if (tr && window.SatomProcEditor) window.SatomProcEditor.select(tr.getAttribute('data-step'));
  });
  if ($('ap-lastrun')) $('ap-lastrun').addEventListener('click', function () {
    fetch(U.lastRun, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json(); }).then(function (d) {
        if (!d.run) { state('This app has not run yet.'); return; }
        if (window.SatomProcEditor) window.SatomProcEditor.overlay(d.run.steps || []);
        state('Run #' + d.run.id + ' (' + d.run.status + ') laid over the diagram: click a step for its detail.');
      }).catch(function (e) { state(e.message, true); });
  });

  drawFields(); drawActions(); loadTestForm();
})();
