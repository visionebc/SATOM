/* Python Studio apps -- run a form, follow the run, draw its output and its
 * steps, offer its actions. Shared by the operator page (apps/page.html), the
 * run page (apps/run.html) and the editor's Test tab (studio/app.html).
 * Server side: app/views/apps.py, app/services/studio_apps.py.
 *
 * window.AppRun.mount({form, runBtn, out, runUrl, extra(), runId, statusUrl})
 */
(function () {
  'use strict';
  var meta = document.querySelector('meta[name="csrf-token"]');
  var CSRF = meta ? meta.getAttribute('content') : '';

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
  function getJSON(url) {
    return fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); });
  }
  function formValues(form) {
    var out = {};
    if (!form) return out;
    Array.prototype.forEach.call(form.querySelectorAll('[name]'), function (el) {
      out[el.name] = el.type === 'checkbox' ? el.checked : el.value;
    });
    return out;
  }
  function cell(v) {
    if (v === null || v === undefined) return '';
    if (typeof v === 'object') return '<code style="font-size:11px;">' + esc(JSON.stringify(v)) + '</code>';
    if (v === true) return '✓';
    if (v === false) return '—';
    return esc(v);
  }
  function view(o) {
    var v = o.value, kind = o.view || 'auto';
    if (kind === 'auto') {
      if (Array.isArray(v) && v.length && v.every(function (x) { return x && typeof x === 'object' && !Array.isArray(x); })) kind = 'table';
      else if (Array.isArray(v)) kind = 'list';
      else if (v && typeof v === 'object') kind = 'keyvalue';
      else kind = 'text';
    }
    if (kind === 'table') {
      var rows = Array.isArray(v) ? v : [v], cols = [];
      rows.forEach(function (r) { if (r && typeof r === 'object') Object.keys(r).forEach(function (k) { if (cols.indexOf(k) < 0) cols.push(k); }); });
      return '<div class="fw-table-wrapper mb-0"><table class="fw-table"><thead><tr>' +
        cols.map(function (c) { return '<th>' + esc(c) + '</th>'; }).join('') + '</tr></thead><tbody>' +
        (rows.map(function (r) { return '<tr>' + cols.map(function (c) { return '<td>' + cell(r ? r[c] : '') + '</td>'; }).join('') + '</tr>'; }).join('') ||
          '<tr><td class="text-muted p-2">No rows.</td></tr>') + '</tbody></table></div>' +
        '<div class="text-muted small mt-1">' + rows.length + ' row(s)</div>';
    }
    if (kind === 'list') {
      return '<ul class="mb-0">' + (Array.isArray(v) ? v : [v]).map(function (x) { return '<li>' + cell(x) + '</li>'; }).join('') + '</ul>';
    }
    if (kind === 'keyvalue' && v && typeof v === 'object') {
      return '<table class="table table-sm mb-0" style="font-size:13px;">' + Object.keys(v).map(function (k) {
        return '<tr><th style="width:30%;">' + esc(k) + '</th><td>' + cell(v[k]) + '</td></tr>';
      }).join('') + '</table>';
    }
    if (kind === 'json') {
      return '<pre class="p-2 mb-0" style="max-height:50vh;overflow:auto;font-size:12px;background:var(--fw-surface-alt);border:1px solid var(--fw-border);border-radius:8px;white-space:pre-wrap;">' +
        esc(JSON.stringify(v, null, 2)) + '</pre>';
    }
    return '<div style="white-space:pre-wrap;">' + esc(typeof v === 'string' ? v : JSON.stringify(v)) + '</div>';
  }
  var BADGE = { done: 'success', failed: 'danger', running: 'info' };
  var OUT = { ok: 'success', yes: 'success', no: 'warning', error: 'danger' };

  function draw(box, d) {
    var h = '<div class="d-flex align-items-center gap-2 mb-2" style="font-size:13px;">' +
      '<span class="fw-badge fw-badge-' + (BADGE[d.status] || 'secondary') + '">' + esc(d.status) + '</span>' +
      '<span class="text-muted">run #' + d.id + (d.version ? ' · v' + d.version : ' · draft') +
      (d.armed ? '' : ' · rehearsal: nothing was written') + ' · ' + esc(d.user) + '</span>' +
      (d.status === 'running' ? '<span class="spinner-border spinner-border-sm text-secondary"></span>' : '') + '</div>';
    if (d.error) h += '<div class="alert alert-danger py-2" style="font-size:13px;">' + esc(d.error) + '</div>';
    (d.outputs || []).forEach(function (o) {
      h += '<div class="fw-card mb-2"><div class="fw-card-body">' +
        (o.title ? '<div class="fw-card-title mb-2" style="font-size:14px;">' + esc(o.title) + '</div>' : '') + view(o) + '</div></div>';
    });
    if (d.actions && d.actions.length) {
      h += '<div class="d-flex flex-wrap gap-2 my-2" data-actions>' + d.actions.map(function (a) {
        return '<button type="button" class="btn btn-sm btn-outline-primary" data-act="' + esc(a.key) + '" data-kind="' + esc(a.kind) +
          '" data-confirm="' + (a.confirm ? '1' : '') + '" data-label="' + esc(a.label) + '">' + esc(a.label) + '</button>';
      }).join('') + '</div><div data-act-msg style="font-size:12px;"></div>';
    }
    h += '<details class="mt-2"><summary class="text-muted" style="font-size:12px;cursor:pointer;">Steps (' + (d.steps || []).length + ')</summary>' +
      '<table class="table table-sm mt-1" style="font-size:12px;"><tbody>' + (d.steps || []).map(function (s) {
        return '<tr><td><code>' + esc(s.key) + '</code></td><td>' + esc(s.label) + '</td><td><span class="fw-badge fw-badge-' + (OUT[s.outcome] || 'secondary') +
          '">' + esc(s.outcome) + '</span></td><td>' + esc(s.detail) + '</td><td class="text-muted">' + (s.ms || 0) + ' ms</td></tr>';
      }).join('') + '</tbody></table>' +
      (d.vars ? '<div class="text-muted small">Variables (authors only)</div><pre class="p-2" style="max-height:30vh;overflow:auto;font-size:11px;background:var(--fw-surface-alt);border:1px solid var(--fw-border);border-radius:8px;white-space:pre-wrap;">' +
        esc(JSON.stringify(d.vars, null, 2)) + '</pre>' : '') + '</details>';
    box.innerHTML = h;
    /* In the app editor, the same run is laid over the diagram: each step
       coloured by how it ended, its detail in the inspector. */
    if (window.SatomProcEditor && d.steps) window.SatomProcEditor.overlay(d.steps);
    var actBox = box.querySelector('[data-actions]');
    if (actBox) actBox.addEventListener('click', function (e) {
      var b = e.target.closest('[data-act]'); if (!b) return;
      var key = b.getAttribute('data-act'), msg = box.querySelector('[data-act-msg]');
      if (b.getAttribute('data-confirm') && !window.confirm(b.getAttribute('data-label') + '?')) return;
      if (b.getAttribute('data-kind') === 'download') {
        window.location = '/apps/runs/' + d.id + '/download/' + encodeURIComponent(key);
        return;
      }
      b.disabled = true;
      post('/apps/runs/' + d.id + '/action/' + encodeURIComponent(key), {}).then(function (r) {
        b.disabled = false;
        msg.innerHTML = '<span style="color:#15692A;">' + esc(r.message) + '</span>' +
          (r.url ? ' <a href="' + esc(r.url) + '">Open</a>' : '');
      }).catch(function (err) { b.disabled = false; msg.innerHTML = '<span style="color:#8B1C2A;">' + esc(err.message) + '</span>'; });
    });
  }

  function follow(box, url) {
    var n = 0;
    (function tick() {
      getJSON(url).then(function (d) {
        draw(box, d);
        if (d.status === 'running' && n++ < 900) window.setTimeout(tick, n < 10 ? 700 : 2000);
      }).catch(function (err) { box.innerHTML = '<span style="color:#8B1C2A;">' + esc(err.message) + '</span>'; });
    })();
  }

  function mount(o) {
    if (o.statusUrl && !o.runBtn) { follow(o.out, o.statusUrl); return; }
    if (!o.runBtn) return;
    /* Enter in a one-field form would submit it as a page load. */
    document.addEventListener('submit', function (e) {
      var form = typeof o.form === 'function' ? o.form() : o.form;
      if (form && e.target === form) { e.preventDefault(); o.runBtn.click(); }
    });
    o.runBtn.addEventListener('click', function () {
      var form = typeof o.form === 'function' ? o.form() : o.form;
      if (form && form.reportValidity && !form.reportValidity()) return;
      var body = { inputs: formValues(form) };
      if (o.extra) { var x = o.extra(); for (var k in x) body[k] = x[k]; }
      o.runBtn.disabled = true;
      o.out.innerHTML = '<span class="text-muted"><span class="spinner-border spinner-border-sm"></span> Starting…</span>';
      post(o.runUrl, body).then(function (d) {
        o.runBtn.disabled = false;
        follow(o.out, d.status_url);
      }).catch(function (err) {
        o.runBtn.disabled = false;
        o.out.innerHTML = '<div class="alert alert-danger py-2" style="font-size:13px;">' + esc(err.message) + '</div>';
      });
    });
  }
  window.AppRun = { mount: mount, draw: draw, follow: follow };

  var cfgEl = document.getElementById('app-run-config');
  if (cfgEl) {
    var C = JSON.parse(cfgEl.textContent);
    mount({ form: document.getElementById(C.form), runBtn: document.getElementById(C.runBtn),
            out: document.getElementById(C.out), runUrl: C.runUrl, statusUrl: C.statusUrl });
  }
})();
