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

  function statusHtml(d) {
    var h = '<div class="d-flex align-items-center gap-2 mb-2" style="font-size:13px;">' +
      '<span class="fw-badge fw-badge-' + (BADGE[d.status] || 'secondary') + '">' + esc(d.status) + '</span>' +
      '<span class="text-muted">run #' + d.id + (d.version ? ' · v' + d.version : ' · draft') +
      (d.armed ? '' : ' · rehearsal: nothing was written') + ' · ' + esc(d.user) + '</span>' +
      (d.status === 'running' ? '<span class="spinner-border spinner-border-sm text-secondary"></span>' : '') + '</div>';
    if (d.error) h += '<div class="alert alert-danger py-2" style="font-size:13px;">' + esc(d.error) + '</div>';
    return h;
  }
  function outputCard(o, title, kind, bare) {
    var t = title || o.title, body = view({ value: o.value, view: kind || o.view });
    var head = t ? '<div class="fw-card-title mb-2" style="font-size:14px;">' + esc(t) + '</div>' : '';
    return bare ? head + body : '<div class="fw-card-body">' + head + body + '</div>';
  }
  function actionsHtml(d) {
    if (!d.actions || !d.actions.length) return '';
    return '<div class="d-flex flex-wrap gap-2 my-2" data-actions>' + d.actions.map(function (a) {
      return '<button type="button" class="btn btn-sm btn-outline-primary" data-act="' + esc(a.key) + '" data-kind="' + esc(a.kind) +
        '" data-confirm="' + (a.confirm ? '1' : '') + '" data-label="' + esc(a.label) + '">' + esc(a.label) + '</button>';
    }).join('') + '</div><div data-act-msg style="font-size:12px;"></div>';
  }
  function stepsHtml(d, open) {
    return '<details class="mt-2"' + (open ? ' open' : '') + '><summary class="text-muted" style="font-size:12px;cursor:pointer;">Steps (' + (d.steps || []).length + ')</summary>' +
      '<table class="table table-sm mt-1" style="font-size:12px;"><tbody>' + (d.steps || []).map(function (s) {
        return '<tr><td><code>' + esc(s.key) + '</code></td><td>' + esc(s.label) + '</td><td><span class="fw-badge fw-badge-' + (OUT[s.outcome] || 'secondary') +
          '">' + esc(s.outcome) + '</span></td><td>' + esc(s.detail) + '</td><td class="text-muted">' + (s.ms || 0) + ' ms</td></tr>';
      }).join('') + '</tbody></table>' +
      (d.vars ? '<div class="text-muted small">Variables (authors only)</div><pre class="p-2" style="max-height:30vh;overflow:auto;font-size:11px;background:var(--fw-surface-alt);border:1px solid var(--fw-border);border-radius:8px;white-space:pre-wrap;">' +
        esc(JSON.stringify(d.vars, null, 2)) + '</pre>' : '') + '</details>';
  }
  /* A number tile: the value at a dotted path inside an output; a list or an
     object shows how many items it holds. */
  function statValue(v, path) {
    (path ? String(path).split('.') : []).forEach(function (k) {
      if (v === null || v === undefined || k === '') return;
      v = Array.isArray(v) && /^\d+$/.test(k) ? v[+k] : (typeof v === 'object' ? v[k] : undefined);
    });
    if (Array.isArray(v)) return v.length.toLocaleString();
    if (v && typeof v === 'object') return Object.keys(v).length.toLocaleString();
    if (typeof v === 'number') return v.toLocaleString();
    if (v === null || v === undefined || v === '') return '—';
    return String(v);
  }
  function byKey(d) {
    var m = {};
    (d.outputs || []).forEach(function (o) { if (o.key && !m[o.key]) m[o.key] = o; });
    return m;
  }
  /* Fill the slots of a designed result (templates/apps/_design.html). */
  function fill(root, d) {
    var outs = byKey(d), placed = {};
    Array.prototype.forEach.call(root.querySelectorAll('[data-sapp-output]'), function (el) {
      var k = el.getAttribute('data-sapp-output'), o = outs[k];
      placed[k] = true;
      el.hidden = !o;
      el.innerHTML = o ? outputCard(o, el.getAttribute('data-title'), el.getAttribute('data-view'), el.getAttribute('data-bare') === '1') : '';
    });
    Array.prototype.forEach.call(root.querySelectorAll('[data-sapp-stat]'), function (el) {
      var o = outs[el.getAttribute('data-sapp-stat')], v = el.querySelector('[data-v]');
      if (v) v.textContent = o ? statValue(o.value, el.getAttribute('data-path')) : (d.status === 'running' ? '…' : '—');
    });
    Array.prototype.forEach.call(root.querySelectorAll('[data-sapp-slot]'), function (el) {
      var slot = el.getAttribute('data-sapp-slot');
      if (slot === 'status') el.innerHTML = statusHtml(d);
      else if (slot === 'outputs') {
        el.innerHTML = (d.outputs || []).filter(function (o) { return !(o.key && placed[o.key]); }).map(function (o) {
          return '<div class="fw-card mb-2">' + outputCard(o) + '</div>';
        }).join('');
      } else if (slot === 'actions') el.innerHTML = actionsHtml(d);
      else if (slot === 'steps') el.innerHTML = stepsHtml(d, el.getAttribute('data-open') === '1');
    });
  }

  function draw(box, d) {
    if (d.layout) {
      var tmp = document.createElement('div');
      tmp.innerHTML = d.layout;
      var fresh = tmp.querySelector('[data-sapp-layout]'), cur = box.querySelector('[data-sapp-layout]');
      /* keep the layout already drawn (an open tab, a scrolled table) while
         the run is followed; only its slots are refilled */
      if (fresh && (!cur || cur.getAttribute('data-sapp-layout') !== fresh.getAttribute('data-sapp-layout'))) {
        box.innerHTML = '';
        box.appendChild(fresh);
      }
      fill(box, d);
    } else {
      var h = statusHtml(d);
      (d.outputs || []).forEach(function (o) { h += '<div class="fw-card mb-2">' + outputCard(o) + '</div>'; });
      h += actionsHtml(d) + stepsHtml(d, false);
      box.innerHTML = h;
    }
    box._sappRun = d;
    /* In the app editor, the same run is laid over the diagram: each step
       coloured by how it ended, its detail in the inspector. */
    if (window.SatomProcEditor && d.steps) window.SatomProcEditor.overlay(d.steps);
    if (box._sappWired) return;
    box._sappWired = true;
    box.addEventListener('click', function (e) {
      var b = e.target.closest('[data-act]'); if (!b || !box.contains(b)) return;
      var run = box._sappRun, key = b.getAttribute('data-act'), msg = box.querySelector('[data-act-msg]');
      if (b.getAttribute('data-confirm') && !window.confirm(b.getAttribute('data-label') + '?')) return;
      if (b.getAttribute('data-kind') === 'download') {
        window.location = '/apps/runs/' + run.id + '/download/' + encodeURIComponent(key);
        return;
      }
      b.disabled = true;
      post('/apps/runs/' + run.id + '/action/' + encodeURIComponent(key), {}).then(function (r) {
        b.disabled = false;
        if (msg) msg.innerHTML = '<span style="color:#15692A;">' + esc(r.message) + '</span>' +
          (r.url ? ' <a href="' + esc(r.url) + '">Open</a>' : '');
      }).catch(function (err) { b.disabled = false; if (msg) msg.innerHTML = '<span style="color:#8B1C2A;">' + esc(err.message) + '</span>'; });
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
  /* A list field with "search" (_field.html): the box narrows the choices of
   * its <select>. Every word must appear in the label or the value. The
   * options are rebuilt, not hidden (Safari ignores hidden options). A
   * choice the user MADE stays listed, so filtering never changes it
   * behind their back; otherwise the first match is selected (a required
   * list has no "—" to fall back on). Delegated: the Test tab injects its
   * form later. */
  function searchSelect(box) {
    var id = box.getAttribute('data-sapp-search');
    var sel = document.getElementById(id);
    if (!sel) return;
    if (!sel._sappAll) {
      sel._sappAll = Array.prototype.map.call(sel.options, function (o) {
        return { value: o.value, label: o.text };
      });
    }
    var words = box.value.toLowerCase().split(/\s+/).filter(Boolean);
    var cur = sel.value, keep = !!sel._sappChosen && cur !== '';
    var total = 0, hits = [], curOpt = null;
    sel.innerHTML = '';
    sel._sappAll.forEach(function (o) {
      var opt = new Option(o.label, o.value);
      if (o.value === '') { sel.appendChild(opt); if (cur === '') curOpt = opt; return; }
      total++;
      var hay = (o.label + ' ' + o.value).toLowerCase();
      var hit = words.every(function (w) { return hay.indexOf(w) >= 0; });
      if (!hit && !(keep && o.value === cur)) return;
      if (hit) hits.push(opt);
      if (o.value === cur) curOpt = opt;
      sel.appendChild(opt);
    });
    if (keep || !words.length) {
      if (curOpt) curOpt.selected = true;          /* the user's choice, or nothing typed */
    } else if (hits.length) {
      hits[0].selected = true;                     /* typing, nothing chosen: first match */
    } else if (sel.options.length) {
      sel.options[0].selected = true;              /* no match: "—" (a required list ends empty) */
    }
    var count = document.querySelector('[data-sapp-search-count="' + id + '"]');
    if (count) count.textContent = words.length ? hits.length + ' / ' + total : String(total);
  }
  document.addEventListener('input', function (e) {
    var t = e.target;
    if (t && t.hasAttribute && t.hasAttribute('data-sapp-search')) searchSelect(t);
  });
  /* A choice made by hand (not by the search box) is kept while filtering. */
  document.addEventListener('change', function (e) {
    var t = e.target;
    if (t && t.tagName === 'SELECT') t._sappChosen = t.value !== '';
  });
  document.addEventListener('keydown', function (e) {
    var t = e.target;
    /* Enter in the search box would submit the form, i.e. RUN the app. */
    if (e.key === 'Enter' && t && t.hasAttribute && t.hasAttribute('data-sapp-search')) e.preventDefault();
  });

  window.AppRun = { mount: mount, draw: draw, follow: follow, fill: fill, searchSelect: searchSelect };

  var cfgEl = document.getElementById('app-run-config');
  if (cfgEl) {
    var C = JSON.parse(cfgEl.textContent);
    mount({ form: document.getElementById(C.form), runBtn: document.getElementById(C.runBtn),
            out: document.getElementById(C.out), runUrl: C.runUrl, statusUrl: C.statusUrl });
  }
})();
