/* Python Studio > API Catalog: the API page (studio/api.html: settings,
 * versions, compare) and the version page (studio/api_version.html: import,
 * endpoint editor, publish, deprecate). Server side: app/views/studio.py
 * (api_*), app/services/studio_apis.py and studio_api_spec.py, which re-check
 * everything this page sends.
 */
(function () {
  'use strict';
  var cfgEl = document.getElementById('api-config');
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
  function post(url, body, multipart) {
    var headers = { 'X-CSRFToken': CSRF, 'Accept': 'application/json' };
    if (!multipart) headers['Content-Type'] = 'application/json';
    return fetch(url, {
      method: 'POST', credentials: 'same-origin', headers: headers,
      body: multipart ? body : JSON.stringify(body || {})
    }).then(function (r) {
      return r.json().catch(function () { return { ok: false, error: 'HTTP ' + r.status }; }).then(function (d) {
        if (!r.ok || d.ok === false) throw new Error(d.error || ('HTTP ' + r.status));
        return d;
      });
    });
  }
  function msg(text, bad) {
    var box = $(CFG.page === 'api' ? 'api-msg' : 'av-msg');
    box.innerHTML = text ? '<span style="color:' + (bad ? '#8B1C2A' : '#15692A') + ';">' + esc(text) + '</span>' : '';
  }
  function reload(text) {
    msg(text + ' Reloading…');
    window.setTimeout(function () { window.location.reload(); }, 600);
  }

  /* ── API page ─────────────────────────────────────────────────────── */
  if (CFG.page === 'api') {
    $('api-save').addEventListener('click', function () {
      post(U.save, { name: $('api-name').value, owner: $('api-owner').value,
                     docs_url: $('api-docs_url').value, description: $('api-description').value })
        .then(function () { msg('Saved.'); }).catch(function (e) { msg(e.message, true); });
    });
    $('api-delete').addEventListener('click', function () {
      if (!window.confirm('Delete the API ' + CFG.slug + ' and all its versions?')) return;
      post(U['delete']).then(function () { window.location = U.back; }).catch(function (e) { msg(e.message, true); });
    });
    $('api-version-create').addEventListener('click', function () {
      post(U.create, { version: $('api-new-version').value.trim(), copy_from: $('api-copy-from').value })
        .then(function (d) { window.location = d.url; }).catch(function (e) { msg(e.message, true); });
    });
    if ($('api-cmp-go')) $('api-cmp-go').addEventListener('click', function () {
      var q = '?a=' + encodeURIComponent($('api-cmp-a').value) + '&b=' + encodeURIComponent($('api-cmp-b').value);
      fetch(U.compare + q, { credentials: 'same-origin' }).then(function (r) { return r.json(); }).then(function (d) {
        if (d.ok === false) throw new Error(d.error);
        function list(title, cls, rows, fmt) {
          if (!rows.length) return '';
          return '<div class="mt-2"><span class="fw-badge ' + cls + '">' + title + ' (' + rows.length + ')</span><ul class="mb-0 mt-1">' +
            rows.map(function (r) { return '<li>' + fmt(r) + '</li>'; }).join('') + '</ul></div>';
        }
        function op(o) { return '<code>' + esc(o.id) + '</code> ' + esc(o.method + ' ' + o.path); }
        var html = '<div class="text-muted">' + esc(d.a) + ' → ' + esc(d.b) + ': ' + d.same + ' unchanged.</div>' +
          list('Removed — calls to these break', 'fw-badge-danger', d.removed, op) +
          list('Changed', 'fw-badge-warning', d.changed, function (c) {
            return '<code>' + esc(c.id) + '</code> ' + esc(c.fields.join(', ')) + ': ' +
              esc(c.old.method + ' ' + c.old.path) + ' → ' + esc(c['new'].method + ' ' + c['new'].path);
          }) +
          list('Added', 'fw-badge-success', d.added, op);
        $('api-cmp-out').innerHTML = html;
      }).catch(function (e) { $('api-cmp-out').innerHTML = '<span style="color:#8B1C2A;">' + esc(e.message) + '</span>'; });
    });
    return;
  }

  /* ── version page ─────────────────────────────────────────────────── */
  var ops = (CFG.ops || []).map(function (o) { return JSON.parse(JSON.stringify(o)); });
  var filter = '';
  function queryNames(o) {
    return (o.params || []).filter(function (p) { return p['in'] === 'query'; }).map(function (p) { return p.name; }).join(', ');
  }
  function methodSelect(i, cur) {
    return '<select class="form-select form-select-sm" data-i="' + i + '" data-k="method" style="width:100px;">' +
      CFG.methods.map(function (m) { return '<option' + (m === cur ? ' selected' : '') + '>' + m + '</option>'; }).join('') + '</select>';
  }
  function draw() {
    var f = filter.toLowerCase();
    $('av-rows').innerHTML = ops.map(function (o, i) {
      var hay = (o.id + ' ' + o.method + ' ' + o.path + ' ' + (o.summary || '')).toLowerCase();
      if (f && hay.indexOf(f) < 0) return '';
      if (!CFG.draft) {
        return '<tr><td><code>' + esc(o.id) + '</code>' + (o.deprecated ? ' <span class="fw-badge fw-badge-warning">deprecated</span>' : '') + '</td>' +
          '<td><span class="fw-badge fw-badge-secondary">' + esc(o.method) + '</span></td><td><code>' + esc(o.path) + '</code></td>' +
          '<td>' + esc(o.summary || '') + '</td><td style="font-size:12px;">' + esc(queryNames(o)) + '</td><td>' + (o.body ? 'yes' : '') + '</td></tr>';
      }
      return '<tr>' +
        '<td><input class="form-control form-control-sm" data-i="' + i + '" data-k="id" value="' + esc(o.id) + '" placeholder="auto" style="min-width:140px;"></td>' +
        '<td>' + methodSelect(i, o.method) + '</td>' +
        '<td><input class="form-control form-control-sm" data-i="' + i + '" data-k="path" value="' + esc(o.path) + '" placeholder="/hosts/{id}" style="min-width:180px;font-family:ui-monospace,Menlo,monospace;"></td>' +
        '<td><input class="form-control form-control-sm" data-i="' + i + '" data-k="summary" value="' + esc(o.summary || '') + '"></td>' +
        '<td><input class="form-control form-control-sm" data-i="' + i + '" data-k="query" value="' + esc(queryNames(o)) + '" placeholder="limit, offset"></td>' +
        '<td><input class="form-check-input" type="checkbox" data-i="' + i + '" data-k="body"' + (o.body ? ' checked' : '') + '></td>' +
        '<td><button type="button" class="btn btn-sm btn-outline-danger" data-del="' + i + '">✕</button></td></tr>';
    }).join('') || '<tr><td colspan="7" class="text-muted p-3">' +
      (CFG.draft ? 'No endpoints yet: import a document or add them.' : 'No endpoints.') + '</td></tr>';
  }
  $('av-filter').addEventListener('input', function () { filter = this.value; draw(); });
  draw();
  if (!CFG.draft) {
    $('av-deprecate').addEventListener('click', function () {
      var on = this.getAttribute('data-on') === '1';
      post(U.deprecate, { on: on }).then(function () { reload(on ? 'Deprecated.' : 'Marked as current.'); })
        .catch(function (e) { msg(e.message, true); });
    });
    return;
  }

  function change(e) {
    var el = e.target, i = el.getAttribute('data-i');
    if (i === null) return;
    var o = ops[+i], k = el.getAttribute('data-k');
    if (k === 'body') { o.body = el.checked; return; }
    if (k === 'query') {
      var keep = (o.params || []).filter(function (p) { return p['in'] !== 'query'; });
      var old = {};
      (o.params || []).forEach(function (p) { if (p['in'] === 'query') old[p.name] = p; });
      el.value.split(',').map(function (s) { return s.trim(); }).filter(Boolean).forEach(function (n) {
        keep.push(old[n] || { name: n, 'in': 'query', required: false, type: 'string' });
      });
      o.params = keep;
      return;
    }
    o[k] = el.value;
  }
  $('av-rows').addEventListener('input', change);
  $('av-rows').addEventListener('change', change);
  $('av-rows').addEventListener('click', function (e) {
    var b = e.target.closest('[data-del]'); if (!b) return;
    ops.splice(+b.getAttribute('data-del'), 1); draw();
  });
  $('av-add').addEventListener('click', function () {
    if (ops.length >= CFG.maxOps) { msg('At most ' + CFG.maxOps + ' endpoints in one version.', true); return; }
    ops.unshift({ id: '', method: 'GET', path: '/', summary: '', params: [], body: false });
    filter = ''; $('av-filter').value = ''; draw();
  });
  function save() {
    return post(U.save, { operations: ops, notes: $('av-notes').value, base_path: $('av-base_path').value });
  }
  $('av-save').addEventListener('click', function () {
    save().then(function (d) { reload('Saved: ' + d.operations + ' endpoints.'); }).catch(function (e) { msg(e.message, true); });
  });
  $('av-import').addEventListener('click', function () {
    var f = $('av-file').files[0], p;
    if (f) { var fd = new FormData(); fd.append('file', f); p = post(U['import'], fd, true); }
    else { p = post(U['import'], { text: $('av-text').value }); }
    p.then(function (d) {
      $('av-import-out').innerHTML = '<div style="color:#15692A;">' + d.operations + ' endpoints imported' +
        (d.title ? ' from ' + esc(d.title) + (d.document_version ? ' ' + esc(d.document_version) : '') : '') + '.</div>' +
        (d.warnings && d.warnings.length ? '<ul class="mb-0 text-muted">' + d.warnings.map(function (w) { return '<li>' + esc(w) + '</li>'; }).join('') + '</ul>' : '');
      window.setTimeout(function () { window.location.reload(); }, d.warnings && d.warnings.length ? 2500 : 700);
    }).catch(function (e) { msg(e.message, true); });
  });
  $('av-publish').addEventListener('click', function () {
    if (!window.confirm('Publish ' + CFG.slug + ' ' + CFG.version + '? Its endpoints are frozen for good; later changes go into a new version.')) return;
    save().then(function () { return post(U.publish); })
      .then(function () { reload('Published.'); }).catch(function (e) { msg(e.message, true); });
  });
  $('av-delete').addEventListener('click', function () {
    if (!window.confirm('Delete the draft ' + CFG.version + '?')) return;
    post(U['delete']).then(function () { window.location = U.back; }).catch(function (e) { msg(e.message, true); });
  });
})();
