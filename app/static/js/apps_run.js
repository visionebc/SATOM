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
  /* Row buttons: an app opens its form over this page (openApp), a url is a
     SATOM path the server already checked. */
  function rowButtons(acts) {
    return (acts || []).map(function (a) {
      if (a.url) {
        return '<a class="btn btn-sm btn-outline-primary py-0 px-2 me-1" style="font-size:11px;" target="_blank" rel="noopener" href="' +
          esc(a.url) + '">' + esc(a.label) + ' <i class="bi bi-box-arrow-up-right"></i></a>';
      }
      return '<button type="button" class="btn btn-sm btn-outline-primary py-0 px-2 me-1" style="font-size:11px;" data-open-app="' +
        esc(a.app) + '" data-inputs="' + esc(JSON.stringify(a.inputs || {})) + '">' + esc(a.label) + '</button>';
    }).join('');
  }
  /* A decommission plan (Output "Show as: plan"): what goes, what stays and
     why, and the warnings -- the DNS & LB Lookup page's confirmation view. */
  var ACTION_BADGE = { 'delete': 'danger', unbind: 'warning', keep: 'secondary' };
  function planHtml(p) {
    if (!p || typeof p !== 'object' || !Array.isArray(p.items)) return view({ value: p, view: 'json' });
    var t = p.target || {}, c = p.counts || {}, titles = {};
    (p.stages || []).forEach(function (s) { titles[s.key] = s.title; });
    var h = '<div class="mb-2" style="font-size:13px;"><strong>' + esc(t.product || '') + ' ' + esc(t.appliance || '') + '</strong> › ' +
      esc(t.policy || '') + (t.hostname ? ' <span class="text-muted">(' + esc(t.hostname) + ')</span>' : '') + '</div>' +
      '<div class="d-flex flex-wrap gap-2 mb-2">' +
      '<span class="fw-badge fw-badge-danger">' + (c['delete'] || 0) + ' delete</span>' +
      '<span class="fw-badge fw-badge-warning">' + (c.unbind || 0) + ' unbind</span>' +
      '<span class="fw-badge fw-badge-secondary">' + (c.keep || 0) + ' keep</span>' +
      (p.blocked ? '<span class="fw-badge fw-badge-danger">BLOCKED</span>' : '') + '</div>';
    (p.warnings || []).forEach(function (w) {
      h += '<div class="alert ' + (w.blocking ? 'alert-danger' : 'alert-warning') + ' py-1 px-2 mb-1" style="font-size:12px;"><strong>' +
        (w.blocking ? 'Blocker' : 'Warning') + ':</strong> ' + esc(w.text) + '</div>';
    });
    var last = null;
    h += '<div class="fw-table-wrapper mb-0"><table class="fw-table"><thead><tr><th>Object</th><th>Kind</th><th>Action</th><th>Why</th><th>Still used by</th></tr></thead><tbody>';
    p.items.forEach(function (i) {
      if (i.stage !== last) {
        last = i.stage;
        h += '<tr><td colspan="5" style="background:var(--fw-surface-alt,#F3F6FC);font-weight:600;font-size:12px;">' + esc(titles[i.stage] || i.stage) + '</td></tr>';
      }
      h += '<tr><td>' + esc(i.label) + '</td><td>' + esc(i.kind) + '</td><td><span class="fw-badge fw-badge-' + (ACTION_BADGE[i.action] || 'secondary') + '">' +
        esc(i.action) + '</span></td><td>' + esc(i.reason || '') + '</td><td>' + esc((i.holders || []).join(', ')) + '</td></tr>';
    });
    if (!p.items.length) h += '<tr><td colspan="5" class="text-muted p-2">Nothing to remove.</td></tr>';
    return h + '</tbody></table></div>';
  }
  function view(o) {
    var v = o.value, kind = o.view || 'auto';
    if (kind === 'auto') {
      if (Array.isArray(v) && v.length && v.every(function (x) { return x && typeof x === 'object' && !Array.isArray(x); })) kind = 'table';
      else if (Array.isArray(v)) kind = 'list';
      else if (v && typeof v === 'object') kind = 'keyvalue';
      else kind = 'text';
    }
    if (kind === 'plan') return planHtml(v);
    if (kind === 'table') {
      /* Columns starting with _ are the app's (ids, row buttons), not shown;
         a row's _actions are its buttons (an Output's row_actions). */
      var rows = Array.isArray(v) ? v : [v], cols = [], btns = false;
      rows.forEach(function (r) {
        if (!r || typeof r !== 'object') return;
        Object.keys(r).forEach(function (k) { if (k.charAt(0) !== '_' && cols.indexOf(k) < 0) cols.push(k); });
        if (Array.isArray(r._actions) && r._actions.length) btns = true;
      });
      return '<div class="fw-table-wrapper mb-0"><table class="fw-table"><thead><tr>' +
        cols.map(function (c) { return '<th>' + esc(c) + '</th>'; }).join('') + (btns ? '<th></th>' : '') + '</tr></thead><tbody>' +
        (rows.map(function (r) {
          return '<tr>' + cols.map(function (c) { return '<td>' + cell(r ? r[c] : '') + '</td>'; }).join('') +
            (btns ? '<td style="white-space:nowrap;">' + rowButtons(r && r._actions) + '</td>' : '') + '</tr>';
        }).join('') ||
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
  var BADGE = { done: 'success', failed: 'danger', running: 'info', waiting: 'warning' };
  var OUT = { ok: 'success', yes: 'success', no: 'warning', error: 'danger', waiting: 'info' };

  function statusHtml(d) {
    var h = '<div class="d-flex align-items-center gap-2 mb-2" style="font-size:13px;">' +
      '<span class="fw-badge fw-badge-' + (BADGE[d.status] || 'secondary') + '">' + esc(d.status) + '</span>' +
      '<span class="text-muted">run #' + d.id + (d.version ? ' · v' + d.version : ' · draft') +
      (d.armed ? '' : ' · rehearsal: nothing was written') + ' · ' + esc(d.user) + '</span>' +
      (d.status === 'running' ? '<span class="spinner-border spinner-border-sm text-secondary"></span>' : '') + '</div>';
    if (d.error) h += '<div class="alert alert-danger py-2" style="font-size:13px;">' + esc(d.error) + '</div>';
    if (d.waiting) h += waitingHtml(d);
    return h;
  }
  /* An "Ask a person" step: the run is parked until somebody answers here. */
  function waitingHtml(d) {
    var w = d.waiting, h = '<div class="fw-card mb-2" style="border-left:4px solid #7A5700;"><div class="fw-card-body" style="font-size:13px;">' +
      '<div class="fw-card-title mb-1" style="font-size:14px;"><i class="bi bi-hand-index me-1"></i>' + esc(w.label) + '</div>' +
      '<div style="white-space:pre-line;">' + esc(w.prompt) + '</div>';
    if (w.role || w.time) {
      h += '<div class="my-2">' + (w.role ? '<span class="fw-badge fw-badge-secondary me-1"><i class="bi bi-person me-1"></i>' + esc(w.role) + '</span>' : '') +
        (w.time ? '<span class="fw-badge fw-badge-secondary"><i class="bi bi-clock me-1"></i>' + esc(w.time) + '</span>' : '') + '</div>';
    }
    if (w.doc) h += '<div class="p-2 my-2" style="white-space:pre-line;font-size:12.5px;background:var(--fw-surface-alt,#F3F6FC);border:1px solid var(--fw-border,#DFE1E6);border-radius:6px;">' + esc(w.doc) + '</div>';
    /* The Ask step's gate: blockers refuse Yes; every warning must be ticked
       (the server checks both again, studio_apps.answer). */
    var blocked = (w.blockers || []).length > 0, acks = w.acknowledge || [];
    (w.blockers || []).forEach(function (b) {
      h += '<div class="alert alert-danger py-1 px-2 my-1" style="font-size:12px;"><strong>Blocker:</strong> ' + esc(b) + '</div>';
    });
    acks.forEach(function (a, i) {
      h += '<div class="form-check my-1" style="font-size:12.5px;"><input class="form-check-input" type="checkbox" data-ack="' + i + '" id="sapp-ack-' + i + '">' +
        '<label class="form-check-label" for="sapp-ack-' + i + '"><strong>Warning:</strong> ' + esc(a) + ' — I have read this</label></div>';
    });
    if (w.can_answer) {
      h += '<div class="d-flex flex-wrap gap-2 align-items-center mt-2"><input class="form-control form-control-sm" data-answer-note maxlength="400" placeholder="Note (optional)" style="max-width:320px;">' +
        '<button type="button" class="btn btn-sm btn-success" data-answer="yes"' + (blocked || acks.length ? ' disabled' : '') +
        (blocked ? ' title="Blocked: see above"' : '') + '>' + esc(w.pass_label || 'Yes') + '</button>' +
        (w.buttons === 'one' ? '' : '<button type="button" class="btn btn-sm btn-danger" data-answer="no">' + esc(w.fail_label || 'No') + '</button>') +
        '<span data-answer-msg class="small"></span></div>';
    } else {
      h += '<div class="text-muted small mt-2">Waiting for the person who started the run, or a Plugin Studio author.</div>';
    }
    return h + '</div></div>';
  }
  function outputCard(o, title, kind, bare) {
    var t = title || o.title, body = view({ value: o.value, view: kind || o.view });
    var head = t ? '<div class="fw-card-title mb-2" style="font-size:14px;">' + esc(t) + '</div>' : '';
    return bare ? head + body : '<div class="fw-card-body">' + head + body + '</div>';
  }
  function actionsHtml(d) {
    if (!d.actions || !d.actions.length) return '';
    return '<div class="d-flex flex-wrap gap-2 my-2" data-actions>' + d.actions.map(function (a) {
      var off = a.error ? ' disabled title="' + esc(a.error) + '"' : '';
      if (a.kind === 'copy') {
        return '<button type="button" class="btn btn-sm btn-outline-secondary" data-copy="' + esc(a.key) + '"' + off + '><i class="bi bi-clipboard me-1"></i>' + esc(a.label) + '</button>';
      }
      if (a.kind === 'open_app') {
        return '<button type="button" class="btn btn-sm btn-outline-primary" data-open-app="' + esc(a.app || '') + '" data-inputs="' +
          esc(JSON.stringify(a.inputs || {})) + '"' + off + '>' + esc(a.label) + '</button>';
      }
      return '<button type="button" class="btn btn-sm btn-outline-primary" data-act="' + esc(a.key) + '" data-kind="' + esc(a.kind) +
        '" data-confirm="' + (a.confirm ? '1' : '') + '" data-label="' + esc(a.label) + '">' + esc(a.label) + '</button>';
    }).join('') + '</div><div data-act-msg style="font-size:12px;"></div>';
  }
  function stepsHtml(d, open) {
    return '<details class="mt-2"' + (open ? ' open' : '') + '><summary class="text-muted" style="font-size:12px;cursor:pointer;">Steps (' + (d.steps || []).length + ')</summary>' +
      '<table class="table table-sm mt-1" style="font-size:12px;"><tbody>' + (d.steps || []).map(function (s) {
        var doc = (d.docs || {})[s.key], extra = '';
        if (doc) {
          extra = '<details><summary class="text-muted">Instructions' + (doc.role ? ' · ' + esc(doc.role) : '') + (doc.time ? ' · ' + esc(doc.time) : '') +
            '</summary>' + (doc.doc ? '<div style="white-space:pre-line;">' + esc(doc.doc) + '</div>' : '') + '</details>';
        }
        return '<tr><td><code>' + esc(s.key) + '</code></td><td>' + esc(s.label) + extra + '</td><td><span class="fw-badge fw-badge-' + (OUT[s.outcome] || 'secondary') +
          '">' + esc(s.outcome) + '</span></td><td style="white-space:pre-line;">' + esc(s.detail) + '</td><td class="text-muted">' + (s.ms || 0) + ' ms</td></tr>';
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
    gateYes(box);
    if (box._sappWired) return;
    box._sappWired = true;
    box.addEventListener('change', function (e) {
      if (e.target && e.target.hasAttribute && e.target.hasAttribute('data-ack')) gateYes(box);
    });
    box.addEventListener('click', function (e) {
      var ans = e.target.closest('[data-answer]');
      if (ans && box.contains(ans)) {
        var note = box.querySelector('[data-answer-note]'), am = box.querySelector('[data-answer-msg]');
        var acks = Array.prototype.filter.call(box.querySelectorAll('[data-ack]'), function (x) { return x.checked; })
          .map(function (x) { return +x.getAttribute('data-ack'); });
        Array.prototype.forEach.call(box.querySelectorAll('[data-answer]'), function (x) { x.disabled = true; });
        answer(box, ans.getAttribute('data-answer'), note ? note.value : '', acks).catch(function (err) {
          Array.prototype.forEach.call(box.querySelectorAll('[data-answer]'), function (x) { x.disabled = false; });
          gateYes(box);
          if (am) am.innerHTML = '<span style="color:#8B1C2A;">' + esc(err.message) + '</span>';
        });
        return;
      }
      var cp = e.target.closest('[data-copy]');
      if (cp && box.contains(cp)) { copyAction(box, cp); return; }
      var op = e.target.closest('[data-open-app]');
      if (op && box.contains(op)) {
        var vals = {};
        try { vals = JSON.parse(op.getAttribute('data-inputs') || '{}'); } catch (x) { vals = {}; }
        openApp(op.getAttribute('data-open-app'), vals);
        return;
      }
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

  function answer(box, value, note, acks) {
    var run = box._sappRun;
    return post('/apps/runs/' + run.id + '/answer', { answer: value, note: note || '', acks: acks || [] }).then(function () {
      follow(box, box._sappUrl, box._sappAuto);
    });
  }
  /* Yes stays off while a blocker stands or a warning is not ticked. */
  function gateYes(box) {
    var d = box._sappRun, w = d && d.waiting, yes = box.querySelector('[data-answer="yes"]');
    if (!w || !yes) return;
    var all = Array.prototype.every.call(box.querySelectorAll('[data-ack]'), function (x) { return x.checked; });
    yes.disabled = (w.blockers || []).length > 0 || !all;
  }

  /* Copy: the text was rendered by the server (run_json) from this run. */
  function copyAction(box, b) {
    var act = ((box._sappRun || {}).actions || []).filter(function (a) { return a.key === b.getAttribute('data-copy'); })[0];
    var msg = box.querySelector('[data-act-msg]');
    if (!act || act.error) { if (msg) msg.innerHTML = '<span style="color:#8B1C2A;">' + esc(act ? act.error : 'nothing to copy') + '</span>'; return; }
    var done = function () {
      var old = b.textContent;
      b.textContent = act.label + ' — copied';
      window.setTimeout(function () { b.textContent = old; }, 1600);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(act.text || '').then(done, function () { legacyCopy(act.text || '') && done(); });
    } else if (legacyCopy(act.text || '')) done();
  }
  function legacyCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (x) { ok = false; }
    document.body.removeChild(ta);
    return ok;
  }

  /* Another app's form over this page, filled in (a row button or an Open
     app action); Run follows that run in the same window. A button inside
     it opens the next app in the same window. */
  var modalEl = null;
  function modal() {
    if (modalEl) return modalEl;
    modalEl = document.createElement('div');
    modalEl.className = 'modal fade';
    modalEl.tabIndex = -1;
    modalEl.innerHTML = '<div class="modal-dialog modal-xl modal-dialog-scrollable"><div class="modal-content">' +
      '<div class="modal-header py-2"><h5 class="modal-title" style="font-size:15px;" data-m-title></h5>' +
      '<a class="ms-3 small" data-m-page target="_blank" rel="noopener">Open the app page</a>' +
      '<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>' +
      '<div class="modal-body" style="font-size:13px;"><div class="row g-3"><div class="col-lg-4"><form data-m-form></form>' +
      '<button type="button" class="btn btn-fw-primary btn-sm mt-1" data-m-run><i class="bi bi-play-fill me-1"></i>Run</button></div>' +
      '<div class="col-lg-8"><div data-m-out class="text-muted">Check the values and press Run.</div></div></div></div></div></div>';
    document.body.appendChild(modalEl);
    modalEl.querySelector('[data-m-run]').addEventListener('click', function () {
      var form = modalEl.querySelector('[data-m-form]'), out = modalEl.querySelector('[data-m-out]'), btn = this;
      if (form.reportValidity && !form.reportValidity()) return;
      btn.disabled = true;
      out.innerHTML = '<span class="text-muted"><span class="spinner-border spinner-border-sm"></span> Starting…</span>';
      post(modalEl._runUrl, { inputs: formValues(form) }).then(function (d) {
        btn.disabled = false;
        follow(out, d.status_url);
      }).catch(function (err) {
        btn.disabled = false;
        out.innerHTML = '<div class="alert alert-danger py-2" style="font-size:13px;">' + esc(err.message) + '</div>';
      });
    });
    return modalEl;
  }
  function fillForm(form, vals) {
    Object.keys(vals || {}).forEach(function (k) {
      Array.prototype.forEach.call(form.querySelectorAll('[name]'), function (el) {
        if (el.name !== k) return;
        var v = vals[k];
        if (el.type === 'checkbox') el.checked = v === true || v === 'true' || v === 'yes' || v === 'on' || v === 1 || v === '1';
        else el.value = v === null || v === undefined ? '' : String(v);
      });
    });
  }
  function openApp(slug, vals) {
    var m = modal(), out = m.querySelector('[data-m-out]');
    m.querySelector('[data-m-title]').textContent = 'Loading…';
    m.querySelector('[data-m-form]').innerHTML = '';
    out.innerHTML = '<span class="text-muted">Check the values and press Run.</span>';
    out._sappRun = null; out._sappGen = (out._sappGen || 0) + 1;
    var shown = window.bootstrap && window.bootstrap.Modal ? window.bootstrap.Modal.getOrCreateInstance(m) : null;
    if (shown) shown.show(); else m.style.display = 'block';
    getJSON('/apps/' + encodeURIComponent(slug) + '/form.json').then(function (d) {
      if (!d.ok) throw new Error(d.error || 'the app cannot be opened');
      m.querySelector('[data-m-title]').innerHTML = '<i class="bi ' + esc(d.icon || 'bi-app') + ' me-2"></i>' + esc(d.name);
      m.querySelector('[data-m-page]').href = d.page_url;
      var form = m.querySelector('[data-m-form]');
      form.innerHTML = d.html;
      fillForm(form, vals);
      m._runUrl = d.run_url;
    }).catch(function (err) {
      m.querySelector('[data-m-title]').textContent = 'Cannot open the app';
      out.innerHTML = '<div class="alert alert-danger py-2" style="font-size:13px;">' +
        esc(/404/.test(err.message) ? 'You may not use this app here.' : err.message) + '</div>';
    });
  }

  /* autoYes(): the Simulate panel's "answer Yes to every question" -- each
     question is answered yes as soon as the walk reaches it. */
  function follow(box, url, autoYes) {
    var n = 0, gen = box._sappGen = (box._sappGen || 0) + 1;
    box._sappUrl = url; box._sappAuto = autoYes;
    (function tick() {
      getJSON(url).then(function (d) {
        if (box._sappGen !== gen) return;   /* another run took this box over */
        draw(box, d);
        if (d.status === 'running' && n++ < 900) window.setTimeout(tick, n < 10 ? 700 : 2000);
        else if (d.status === 'waiting' && d.waiting && d.waiting.can_answer && autoYes && autoYes()) {
          window.setTimeout(function () { answer(box, 'yes', 'simulation: Yes to every question'); }, 400);
        }
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
        follow(o.out, d.status_url, o.autoYes);
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
