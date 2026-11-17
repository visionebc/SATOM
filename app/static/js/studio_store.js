/* Python Studio > Data store page (studio/store.html): the rows grid with an
 * add/edit modal, the column editor and CSV import. Server side:
 * app/views/studio.py (store_*), app/services/studio_store.py, which
 * re-checks every value against the column types.
 */
(function () {
  'use strict';
  var cfgEl = document.getElementById('st-config');
  if (!cfgEl) return;
  var CFG = JSON.parse(cfgEl.textContent);
  var U = CFG.urls;
  var cols = CFG.columns.slice();
  var rows = CFG.rows.slice();
  var meta = document.querySelector('meta[name="csrf-token"]');
  var CSRF = meta ? meta.getAttribute('content') : '';
  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function post(url, body, isForm) {
    var opt = { method: 'POST', credentials: 'same-origin', headers: { 'X-CSRFToken': CSRF, 'Accept': 'application/json' } };
    if (isForm) { opt.body = body; } else { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body || {}); }
    return fetch(url, opt).then(function (r) {
      return r.json().catch(function () { return { error: 'HTTP ' + r.status }; }).then(function (d) {
        if (!r.ok || d.ok === false) throw new Error(d.error || ('HTTP ' + r.status));
        return d;
      });
    });
  }
  function msg(text, bad) {
    $('st-msg').innerHTML = text ? '<span style="color:' + (bad ? '#8B1C2A' : '#15692A') + ';">' + esc(text) + '</span>' : '';
  }
  function show(v) {
    if (v === null || v === undefined) return '';
    if (typeof v === 'object') return JSON.stringify(v);
    if (v === true) return '✓';
    if (v === false) return '—';
    return String(v);
  }

  /* ── rows ─────────────────────────────────────────────────────────── */
  function drawRows() {
    var q = ($('st-search').value || '').toLowerCase();
    var head = '<tr><th>#</th>' + cols.map(function (c) { return '<th>' + esc(c.label) + '</th>'; }).join('') +
      '<th>' + 'Updated' + '</th></tr>';
    $('st-rows').querySelector('thead').innerHTML = head;
    var body = rows.filter(function (r) {
      if (!q) return true;
      return cols.some(function (c) { return show(r[c.name]).toLowerCase().indexOf(q) >= 0; });
    }).map(function (r) {
      return '<tr data-id="' + r._id + '" style="cursor:pointer;"><td>' + r._id + '</td>' +
        cols.map(function (c) { return '<td>' + esc(show(r[c.name])).slice(0, 300) + '</td>'; }).join('') +
        '<td style="font-size:12px;white-space:nowrap;">' + esc((r._updated_at || '').replace('T', ' ')) + ' · ' + esc(r._by) + '</td></tr>';
    }).join('');
    $('st-rows').querySelector('tbody').innerHTML = body ||
      '<tr><td colspan="' + (cols.length + 2) + '" class="text-muted p-3">No rows.</td></tr>';
    $('st-count').textContent = rows.length;
  }
  $('st-search').addEventListener('input', drawRows);

  var editing = null;
  var modal = window.bootstrap ? new window.bootstrap.Modal($('st-row-modal')) : null;
  function openRow(row) {
    editing = row;
    $('st-row-title').textContent = row ? 'Row ' + row._id : 'New row';
    $('st-row-del').style.display = row ? '' : 'none';
    $('st-row-err').textContent = '';
    $('st-row-form').innerHTML = cols.map(function (c, i) {
      var v = row ? row[c.name] : null;
      var id = 'st-f-' + i, lab = '<label class="form-label small" for="' + id + '">' + esc(c.label) +
        (c.required ? ' *' : '') + ' <code class="text-muted">' + esc(c.name) + ' · ' + c.type + '</code></label>';
      if (c.type === 'boolean') {
        return '<div class="form-check mb-2"><input class="form-check-input" type="checkbox" id="' + id + '"' + (v ? ' checked' : '') +
          '><label class="form-check-label small" for="' + id + '">' + esc(c.label) + '</label></div>';
      }
      if (c.type === 'json') {
        return '<div class="mb-2">' + lab + '<textarea class="form-control form-control-sm" rows="3" id="' + id + '" style="font-family:ui-monospace,Menlo,monospace;">' +
          esc(v === null || v === undefined ? '' : JSON.stringify(v, null, 2)) + '</textarea></div>';
      }
      var t = c.type === 'number' ? 'number" step="any' : (c.type === 'date' ? 'date' : 'text');
      return '<div class="mb-2">' + lab + '<input class="form-control form-control-sm" type="' + t + '" id="' + id + '" value="' + esc(v === null || v === undefined ? '' : v) + '"></div>';
    }).join('');
    if (modal) modal.show();
  }
  function formValues() {
    var out = {};
    cols.forEach(function (c, i) {
      var el = $('st-f-' + i);
      if (!el) return;
      out[c.name] = c.type === 'boolean' ? el.checked : el.value;
    });
    return out;
  }
  $('st-add').addEventListener('click', function () { openRow(null); });
  $('st-rows').addEventListener('click', function (e) {
    var tr = e.target.closest('tr[data-id]');
    if (!tr) return;
    var id = +tr.getAttribute('data-id');
    openRow(rows.filter(function (r) { return r._id === id; })[0]);
  });
  $('st-row-save').addEventListener('click', function () {
    var url = editing ? U.row + editing._id : U.rows;
    post(url, { values: formValues() }).then(function (d) {
      if (editing) { rows = rows.map(function (r) { return r._id === d.row._id ? d.row : r; }); }
      else { rows.push(d.row); }
      if (modal) modal.hide();
      drawRows(); msg('Saved.');
    }).catch(function (err) { $('st-row-err').textContent = err.message; });
  });
  $('st-row-del').addEventListener('click', function () {
    if (!editing || !window.confirm('Delete row ' + editing._id + '?')) return;
    var id = editing._id;
    post(U.row + id + '/delete').then(function () {
      rows = rows.filter(function (r) { return r._id !== id; });
      if (modal) modal.hide();
      drawRows(); msg('Row ' + id + ' deleted.');
    }).catch(function (err) { $('st-row-err').textContent = err.message; });
  });

  /* ── columns ──────────────────────────────────────────────────────── */
  $('st-name').value = CFG.name;
  $('st-desc').value = CFG.description || '';
  function drawCols() {
    $('st-cols').innerHTML = cols.map(function (c, i) {
      return '<tr data-i="' + i + '">' +
        '<td><input class="form-control form-control-sm" data-k="name" value="' + esc(c.name) + '" maxlength="64"></td>' +
        '<td><input class="form-control form-control-sm" data-k="label" value="' + esc(c.label) + '" maxlength="120"></td>' +
        '<td><select class="form-select form-select-sm" data-k="type">' + CFG.types.map(function (t) {
          return '<option' + (t === c.type ? ' selected' : '') + '>' + t + '</option>';
        }).join('') + '</select></td>' +
        '<td><input class="form-check-input" type="checkbox" data-k="required"' + (c.required ? ' checked' : '') + '></td>' +
        '<td class="text-end"><button type="button" class="btn btn-sm btn-outline-secondary" data-mv="-1" title="Up">↑</button> ' +
        '<button type="button" class="btn btn-sm btn-outline-secondary" data-mv="1" title="Down">↓</button> ' +
        '<button type="button" class="btn btn-sm btn-outline-danger" data-rm="1" title="Remove">✕</button></td></tr>';
    }).join('');
  }
  $('st-cols').addEventListener('input', function (e) {
    var tr = e.target.closest('tr'); if (!tr) return;
    var c = cols[+tr.getAttribute('data-i')], k = e.target.getAttribute('data-k');
    c[k] = k === 'required' ? e.target.checked : e.target.value;
  });
  $('st-cols').addEventListener('change', function (e) {
    var tr = e.target.closest('tr'); if (!tr) return;
    var c = cols[+tr.getAttribute('data-i')], k = e.target.getAttribute('data-k');
    if (k) c[k] = k === 'required' ? e.target.checked : e.target.value;
  });
  $('st-cols').addEventListener('click', function (e) {
    var tr = e.target.closest('tr'); if (!tr) return;
    var i = +tr.getAttribute('data-i');
    if (e.target.getAttribute('data-rm')) { cols.splice(i, 1); drawCols(); }
    var mv = +e.target.getAttribute('data-mv');
    if (mv && cols[i + mv]) { var t = cols[i]; cols[i] = cols[i + mv]; cols[i + mv] = t; drawCols(); }
  });
  $('st-col-add').addEventListener('click', function () {
    if (cols.length >= CFG.maxColumns) return;
    cols.push({ name: 'column_' + (cols.length + 1), label: 'Column ' + (cols.length + 1), type: 'text', required: false });
    drawCols();
  });
  $('st-save-schema').addEventListener('click', function () {
    post(U.schema, { name: $('st-name').value, description: $('st-desc').value, columns: cols }).then(function (d) {
      cols = d.columns; drawCols(); drawRows();
      $('st-title').textContent = $('st-name').value;
      msg('Columns saved.' + (d.warnings && d.warnings.length ? ' ' + d.warnings.join(' · ') : ''));
    }).catch(function (err) { msg(err.message, true); });
  });
  // Absent for a template (Examples): templates are never deleted.
  if ($('st-delete')) $('st-delete').addEventListener('click', function () {
    if (!window.confirm('Delete the data store ' + CFG.slug + ' and all its rows? This cannot be undone.')) return;
    post(U['delete']).then(function () { window.location = U.back; })
      .catch(function (err) { msg(err.message, true); });
  });

  /* ── CSV import ───────────────────────────────────────────────────── */
  $('st-import').addEventListener('change', function () {
    var f = this.files[0]; if (!f) return;
    var fd = new FormData(); fd.append('file', f);
    post(U['import'], fd, true).then(function (d) {
      msg(d.imported + ' rows imported. Reloading…');
      window.setTimeout(function () { window.location.reload(); }, 600);
    }).catch(function (err) { msg(err.message, true); });
    this.value = '';
  });

  drawRows(); drawCols();
})();
