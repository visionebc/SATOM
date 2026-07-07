/* FortiWeb-style slide-over object panels (2026-07-06).
 *
 * In the FortiWeb GUI, opening a referenced object (a WPP sub-policy, a rule
 * named by a rule-list row, a pool from a policy…) never navigates away — a
 * panel slides in from the RIGHT over the current page, and deeper references
 * stack more panels (each one slightly narrower, so the parents stay visible
 * at the left edge). This module reproduces that for the generic object editor:
 *
 *   ✎ / ↗  on a reference field  → FWDrawer.openEdit(coll, name)   (edit panel)
 *   ＋      on a reference field  → FWDrawer.openCreate(coll)       (create panel)
 *
 * Each panel loads /objedit/<aid>/edit?partial=1 — the SAME editor fragment the
 * full page uses, so sub-tables (rows, exceptions, members…) are editable in
 * the panel itself, any depth. Creating an object inside a panel promotes that
 * panel to the new object's edit view AND selects the name back into the
 * dropdown that opened it. CSP: injected <script>/<style> are re-stamped with
 * the live document nonce (same pattern as section_config's inline editor).
 *
 * Scope guard: the delegated listeners only act on buttons inside a
 * [data-fw-objedit] container (the generic editor fragment). The Server Policy
 * workspace keeps its own bespoke modal handlers untouched.
 */
(function () {
  'use strict';

  var STACK = [];            // bottom → top panel elements
  var BASE_W = 880;          // px, top-most panel; deeper panels shave STEP each
  var STEP = 34;
  var MIN_W = 420;

  function nonce() {
    var m = document.querySelector('meta[name=csp-nonce]');
    return (m && m.content) || '';
  }

  function aid() { return window.OBJEDIT_AID; }

  function editUrl(coll, mkey, title, create) {
    var u = '/objedit/' + aid() + '/edit?partial=1'
      + '&collection=' + encodeURIComponent(coll)
      + '&mkey=' + encodeURIComponent(mkey || '')
      + '&title=' + encodeURIComponent(title || '');
    if (create) u += '&create=1';
    return u;
  }

  // Re-stamp + re-create injected <script>/<style> so they execute under the
  // enforced CSP nonce (innerHTML-injected scripts never run on their own).
  function execFragment(root) {
    root.querySelectorAll('script').forEach(function (old) {
      var sc = document.createElement('script');
      sc.nonce = nonce();
      if (old.src) sc.src = old.src; else sc.textContent = old.textContent;
      old.parentNode.replaceChild(sc, old);
    });
    root.querySelectorAll('style').forEach(function (old) {
      var st = document.createElement('style');
      st.nonce = nonce();
      st.textContent = old.textContent;
      old.parentNode.replaceChild(st, old);
    });
  }

  function backdrop() {
    var b = document.querySelector('.fw-drawer-backdrop');
    if (!b) {
      b = document.createElement('div');
      b.className = 'fw-drawer-backdrop';
      b.addEventListener('click', function () { pop(); });
      document.body.appendChild(b);
    }
    return b;
  }

  function syncChrome() {
    var b = backdrop();
    if (STACK.length) b.classList.add('show'); else b.classList.remove('show');
    STACK.forEach(function (p, i) {
      var depth = STACK.length - 1 - i;                    // 0 = top panel
      var w = Math.max(MIN_W, BASE_W - depth * STEP);
      p.style.width = 'min(' + w + 'px, 94vw)';
      p.style.zIndex = String(1051 + i);
      p.classList.toggle('fw-drawer-under', depth > 0);
    });
  }

  function esc(v) {
    var d = document.createElement('div');
    d.textContent = (v == null ? '' : String(v));
    return d.innerHTML;
  }

  function build(title, coll) {
    var p = document.createElement('aside');
    p.className = 'fw-drawer';
    p.innerHTML =
      '<div class="fw-drawer-head">' +
        '<div class="fw-drawer-titles">' +
          '<i class="bi bi-layers me-2"></i>' +
          '<span class="fw-drawer-title">' + esc(title || 'Object') + '</span>' +
          '<code class="fw-drawer-coll">' + esc(coll || '') + '</code>' +
        '</div>' +
        '<div class="fw-drawer-actions">' +
          '<button type="button" class="btn btn-sm btn-fw-outline fw-drawer-reload" title="Reload this panel"><i class="bi bi-arrow-clockwise"></i></button>' +
          '<button type="button" class="btn btn-sm btn-fw-outline fw-drawer-close" title="Close (Esc)"><i class="bi bi-x-lg"></i></button>' +
        '</div>' +
      '</div>' +
      '<div class="fw-drawer-body"><div class="text-muted p-4"><span class="spinner-border spinner-border-sm me-2"></span>Loading…</div></div>';
    document.body.appendChild(p);
    // next frame → CSS slide-in transition
    requestAnimationFrame(function () { p.classList.add('show'); });
    return p;
  }

  function load(panel) {
    var body = panel.querySelector('.fw-drawer-body');
    fetch(panel.dataset.url)
      .then(function (r) { return r.text(); })
      .then(function (html) {
        body.innerHTML = html;
        execFragment(body);
        if (window.objeditPopulateRefs) window.objeditPopulateRefs(body);
        if (window.fwRefreshVis) window.fwRefreshVis(body);
        body.scrollTop = 0;
      })
      .catch(function (e) {
        body.innerHTML = '<div class="alert alert-danger m-3">Failed to load: ' + esc(e.message) + '</div>';
      });
  }

  function open(opts) {
    if (aid() == null) return;
    var p = build(opts.title, opts.coll);
    p.dataset.url = opts.url;
    p._opener = opts.opener || null;       // the <select> that spawned the panel
    STACK.push(p);
    syncChrome();
    load(p);
    return p;
  }

  function pop(panel) {
    var p = panel || STACK[STACK.length - 1];
    if (!p) return;
    var i = STACK.indexOf(p);
    if (i >= 0) STACK.splice(i, 1);
    p.classList.remove('show');
    setTimeout(function () { p.remove(); }, 250);
    syncChrome();
  }

  function fieldLabel(btn) {
    var f = btn.closest('.fw-fld');
    var lab = f && f.querySelector('.fw-fld-label');
    if (!lab) return '';
    var c = lab.cloneNode(true);
    var k = c.querySelector('.fw-key');
    if (k) k.remove();
    return c.textContent.trim();
  }

  var FWDrawer = {
    openEdit: function (coll, mkey, opts) {
      opts = opts || {};
      var t = opts.title || (coll || '').split('/').pop();
      return open({url: editUrl(coll, mkey, t), title: t + ' — ' + mkey,
                   coll: coll, opener: opts.opener});
    },
    openCreate: function (coll, opts) {
      opts = opts || {};
      var t = opts.title || (coll || '').split('/').pop();
      return open({url: editUrl(coll, '', t, true), title: 'New ' + t,
                   coll: coll, opener: opts.opener});
    },
    reload: function (panel) { if (panel && panel.dataset.url) load(panel); },
    // A create inside the panel succeeded: select the new name back into the
    // dropdown that opened the panel, then promote the panel to the object's
    // edit view so its sub-tables can be filled — the FortiWeb flow.
    createdObject: function (panel, coll, name, title) {
      var sel = panel._opener;
      if (sel && sel.tagName === 'SELECT') {
        var have = Array.prototype.some.call(sel.options, function (o) { return o.value === name; });
        if (!have) {
          var o = document.createElement('option');
          o.value = name; o.textContent = name;
          sel.appendChild(o);
        }
        sel.value = name;
        sel.dispatchEvent(new Event('change', {bubbles: true}));
        if (window.FW) FW.toast('"' + name + '" selected in ' + (sel.dataset.key || 'the field'), 'info');
      }
      panel.dataset.url = editUrl(coll, name, title);
      var t = panel.querySelector('.fw-drawer-title');
      if (t) t.textContent = (title || (coll || '').split('/').pop()) + ' — ' + name;
      load(panel);
    },
    closeAll: function () { while (STACK.length) pop(); }
  };
  window.FWDrawer = FWDrawer;

  // ── delegated wiring (bound once; document survives Turbo body swaps) ──────
  if (window.__fwDrawerBound) return;
  window.__fwDrawerBound = true;

  document.addEventListener('click', function (ev) {
    var t = ev.target;
    if (!t.closest) return;
    var x = t.closest('.fw-drawer-close');
    if (x) { pop(x.closest('.fw-drawer')); return; }
    var r = t.closest('.fw-drawer-reload');
    if (r) { load(r.closest('.fw-drawer')); return; }

    // ✎ / ＋ on reference fields — ONLY inside the generic editor fragment
    // (the Server Policy workspace has its own modal handlers).
    var btn = t.closest('.fw-edit-ref, .fw-create');
    if (!btn || !btn.closest('[data-fw-objedit]')) return;
    var coll = (btn.dataset.ref || '').split('|')[0];
    if (!coll) return;
    ev.preventDefault();
    ev.stopPropagation();          // keep workspace-style document handlers out
    var sel = btn.closest('.fw-ref') ? btn.closest('.fw-ref').querySelector('select.fw-ref-select') : null;
    var label = fieldLabel(btn) || coll.split('/').pop();
    if (btn.classList.contains('fw-create')) {
      FWDrawer.openCreate(coll, {title: label, opener: sel});
      return;
    }
    var val = sel ? (sel.value || '').trim() : '';
    if (!val) { if (window.FW) FW.toast('Pick an object first, then edit it', 'info'); return; }
    FWDrawer.openEdit(coll, val, {title: label, opener: sel});
  }, true);

  document.addEventListener('keydown', function (ev) {
    if (ev.key === 'Escape' && STACK.length) { ev.stopPropagation(); pop(); }
  }, true);

  // Turbo Drive swaps the <body>: the panel/backdrop NODES die with it — drop
  // the stale stack so the next page starts clean.
  document.addEventListener('turbo:load', function () { STACK.length = 0; });
})();
