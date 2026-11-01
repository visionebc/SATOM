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
 *   ✎ in a device-layout dialog   → FWDrawer.openFrame(url, …)       (the device's
 *                                    own dialog for that object, in a frame)
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
  var BASE_W = 1012;         // px, top-most panel; deeper panels shave STEP each
  var STEP = 39;
  var MIN_W = 483;
  var WIDE_W = 1725;         // px, a page FortiWeb slides in full width (Signature Details)

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
      p.style.width = p.classList.contains('is-wide') ? 'min(' + (WIDE_W - depth * STEP) + 'px, 97vw)'
                                                       : 'min(' + w + 'px, 94vw)';
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
    // the generic editor builds its URL from the appliance id; a framed page
    // comes with its whole URL
    if (!opts.frame && aid() == null) return;
    var p = build(opts.title, opts.coll);
    p.dataset.url = opts.url;
    p._opener = opts.opener || null;       // the <select> that spawned the panel
    p._onClose = opts.onClose || null;     // told how the framed page closed
    p._onCreated = opts.onCreated || null; // a framed "+ Create" names what it saved
    if (opts.wide) p.classList.add('is-wide');
    STACK.push(p);
    syncChrome();
    if (opts.frame) frame(p); else load(p);
    return p;
  }

  // A device-layout dialog (workspace.fwgui_object) in the panel: its own
  // document in a same-origin frame, so its scripts (Save, live show/hide,
  // its own pencils) never meet the dialog underneath. The framed page draws
  // the dialog alone (html.fw-framed) and asks to close through postMessage.
  function frame(panel) {
    var body = panel.querySelector('.fw-drawer-body');
    body.classList.add('is-frame');
    body.innerHTML = '';
    var f = document.createElement('iframe');
    f.className = 'fw-drawer-frame';
    f.src = panel.dataset.url;
    f.title = panel.querySelector('.fw-drawer-title').textContent;
    body.appendChild(f);
  }

  function pop(panel, info) {
    var p = panel || STACK[STACK.length - 1];
    if (!p) return;
    var i = STACK.indexOf(p);
    if (i >= 0) STACK.splice(i, 1);
    // a framed page that wrote to the device says so (changed): its opener
    // refreshes, as FortiWeb's slide does on close (onSlideDone)
    var changed = !!(p._changed || (info && info.changed));
    if (p._onClose) { try { p._onClose({changed: changed}); } catch (e) { /* opener gone */ } }
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
    // ✎ on a reference whose collection has a device-layout page: that
    // dialog, as the device draws it (url from the fwg_ref_page global).
    openFrame: function (url, coll, mkey, opts) {
      opts = opts || {};
      var t = opts.title || (coll || '').split('/').pop();
      return open({url: url, title: t + ' — ' + mkey, coll: coll,
                   opener: opts.opener, frame: true, wide: !!opts.wide,
                   onClose: opts.onClose, onCreated: opts.onCreated});
    },
    reload: function (panel) {
      if (!panel || !panel.dataset.url) return;
      var f = panel.querySelector('.fw-drawer-frame');
      if (f) { f.src = panel.dataset.url; return; }
      load(panel);
    },
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
    if (r) { FWDrawer.reload(r.closest('.fw-drawer')); return; }

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
    if (ev.key !== 'Escape') return;
    if (STACK.length) { ev.stopPropagation(); pop(); return; }
    if (window.self !== window.top) window.parent.postMessage({fwDrawer: 'close', changed: !!window.__fwFrameChanged}, location.origin);
  }, true);

  // A framed dialog asks to close (Cancel, Esc): pop the panel holding it.
  window.addEventListener('message', function (ev) {
    if (ev.origin !== location.origin || !ev.data) return;
    var kind = ev.data.fwDrawer;
    if (kind !== 'close' && kind !== 'changed' && kind !== 'created') return;
    for (var i = STACK.length - 1; i >= 0; i--) {
      var f = STACK[i].querySelector('.fw-drawer-frame');
      if (f && f.contentWindow === ev.source) {
        // a write inside the frame (it may reload itself afterwards): remembered
        if (kind === 'changed') { STACK[i]._changed = true; return; }
        // created from a selector's "+ Create": selected in the opener, panel closed
        if (kind === 'created') {
          if (STACK[i]._onCreated) { try { STACK[i]._onCreated(String(ev.data.name || '')); } catch (e) { /* opener gone */ } }
          pop(STACK[i]); return;
        }
        pop(STACK[i], ev.data); return;
      }
    }
  });

  // Turbo Drive swaps the <body>: the panel/backdrop NODES die with it — drop
  // the stale stack so the next page starts clean.
  document.addEventListener('turbo:load', function () { STACK.length = 0; });
})();
