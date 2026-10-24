// ── CSRF guard: inject X-CSRFToken into every same-origin state-changing
//    fetch() so JSON POST/PUT/DELETE calls aren't rejected (302→login) by
//    Flask-WTF CSRFProtect. Pages used to hand-roll this header and some
//    omitted it, silently breaking saves; doing it here once covers every
//    page and any future call. (2026-06-28)
(function () {
  // Turbo Drive re-executes body scripts on every visit; wrap fetch ONCE so the
  // CSRF shim doesn't nest itself on each navigation.
  if (window.__fwFetchGuard) return;
  window.__fwFetchGuard = true;
  var _fetch = window.fetch;
  window.fetch = function (input, init) {
    init = init || {};
    var method = (init.method || (input && input.method) || 'GET').toUpperCase();
    var url = (typeof input === 'string') ? input : (input && input.url) || '';
    var sameOrigin = url.indexOf('/') === 0 || url.indexOf(location.origin) === 0;
    if (sameOrigin) {
      var h = new Headers(init.headers || (typeof input === 'object' && input && input.headers) || {});
      if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
        if (!h.has('X-CSRFToken')) {
          var meta = document.querySelector('meta[name="csrf-token"]');
          if (meta && meta.content) h.set('X-CSRFToken', meta.content);
        }
      }
      // Per-tab ADOM: every same-origin call carries this tab's ADOM so
      // product-scoped JSON feeds (jobs, notifications, metrics…) answer for
      // THIS tab, not whatever ADOM another tab switched the session to.
      try {
        var adom = sessionStorage.getItem('fmAdom');
        if (adom && !h.has('X-ADOM')) h.set('X-ADOM', adom);
      } catch (e2) {}
      init.headers = h;
    }
    return _fetch.call(this, input, init);
  };
})();

/* ============================================================
   SATOM — main.js
   ============================================================ */

'use strict';

// ============================================================
// Sidebar Toggle — delegated 2026-10-11
// Turbo Drive re-executes this file on every visit and swaps the whole
// <body>, so handlers bound to the toggle button die with the old body and a
// document listener bound per visit closes over a sidebar that is no longer
// in the page. The listeners below are bound ONCE on document and look the
// elements up when the event fires.
//
// Desktop collapse is persisted; the phone overlay is NOT. Closing the
// overlay on a phone used to write the desktop "collapsed" flag, so the next
// desktop visit from the same browser opened with the sidebar hidden.
// ============================================================
(function () {
  var COLLAPSED_KEY = 'fw_sidebar_collapsed';
  var PHONE_MAX = 768;   // fortiweb.css: @media (max-width: 768px)

  function isPhone() { return window.innerWidth <= PHONE_MAX; }
  function parts(root) {
    root = root || document;
    return {
      btn:    root.querySelector('#fw-sidebar-toggle'),
      sb:     root.querySelector('#fw-sidebar'),
      main:   root.querySelector('#fw-main'),
      footer: root.querySelector('#fw-footer'),
    };
  }
  function storedCollapsed() {
    try { return localStorage.getItem(COLLAPSED_KEY) === '1'; } catch (x) { return false; }
  }
  function setCollapsed(p, collapsed, persist) {
    if (!p.sb) return;
    p.sb.classList.toggle('collapsed', collapsed);
    if (p.main)   p.main.style.marginLeft = collapsed ? '0' : '';
    if (p.footer) p.footer.style.marginLeft = collapsed ? '0' : '';
    if (persist) {
      try {
        if (collapsed) localStorage.setItem(COLLAPSED_KEY, '1');
        else localStorage.removeItem(COLLAPSED_KEY);
      } catch (x) {}
    }
  }
  function setPhoneOpen(p, open) {
    if (!p.sb) return;
    p.sb.classList.remove('collapsed');
    p.sb.classList.toggle('mobile-open', open);
    if (p.main)   p.main.style.marginLeft = '';
    if (p.footer) p.footer.style.marginLeft = '';
    if (p.btn) p.btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    document.body.classList.toggle('fw-sidebar-open', open);
  }

  if (!window.__fwSidebarToggleBound) {
    window.__fwSidebarToggleBound = true;

    document.addEventListener('click', function (e) {
      var p = parts();
      if (!p.btn || !p.sb) return;
      if (p.btn.contains(e.target)) {
        if (isPhone()) setPhoneOpen(p, !p.sb.classList.contains('mobile-open'));
        else setCollapsed(p, !p.sb.classList.contains('collapsed'), true);
        return;
      }
      // Phone: a tap outside the open overlay closes it.
      if (isPhone() && p.sb.classList.contains('mobile-open') && !p.sb.contains(e.target)) {
        setPhoneOpen(p, false);
      }
    });

    document.addEventListener('keydown', function (e) {
      if (e.key !== 'Escape' || !isPhone()) return;
      var p = parts();
      if (p.sb && p.sb.classList.contains('mobile-open')) setPhoneOpen(p, false);
    });

    // Apply the desktop collapse to the incoming body BEFORE it is painted,
    // so a collapsed sidebar does not flash open on every navigation.
    document.addEventListener('turbo:before-render', function (e) {
      var nb = e.detail && e.detail.newBody;
      document.body.classList.remove('fw-sidebar-open');
      if (nb && !isPhone() && storedCollapsed()) setCollapsed(parts(nb), true, false);
    });
  }

  // First load (and any render the hook above did not see).
  if (!isPhone() && storedCollapsed()) setCollapsed(parts(), true, false);
})();

// ============================================================
// Active Nav Highlighting
// ============================================================
(function () {
  const path    = window.location.pathname;
  const navItems = document.querySelectorAll('.fw-nav-item');

  navItems.forEach(function (item) {
    const href = item.getAttribute('href');
    if (!href) return;

    // Exact match or prefix match (longer paths win)
    if (href !== '/' && path.startsWith(href)) {
      item.classList.add('active');
    } else if (href === '/' && path === '/') {
      item.classList.add('active');
    }
  });

  // If multiple items matched (prefix), keep the longest match only
  const active = Array.from(navItems).filter(i => i.classList.contains('active'));
  if (active.length > 1) {
    let longest = active.reduce((a, b) =>
      (a.getAttribute('href') || '').length >= (b.getAttribute('href') || '').length ? a : b
    );
    active.forEach(i => {
      if (i !== longest) i.classList.remove('active');
    });
  }
})();

// ============================================================
// Status Badge Poller
// ------------------------------------------------------------
// `var` + reuse, not `const`: Turbo re-executes this file on every visit, and a
// second `const` of the same global is a SyntaxError that stops the WHOLE file
// before its first line runs — sidebar toggle, confirm dialogs, row links and
// all. One poller for the life of the tab, so its interval never doubles.
// ============================================================
var StatusPoller = (window.FW && window.FW.StatusPoller) || (function () {
  let intervalId = null;

  function updateBadge(applianceId, status) {
    const badges = document.querySelectorAll('[data-status-id="' + applianceId + '"]');
    badges.forEach(function (badge) {
      badge.innerHTML = '';

      const dot  = document.createElement('span');
      dot.className = 'fw-status-dot';

      const txt  = document.createElement('span');

      if (status === 'online') {
        badge.className = 'fw-status fw-status-online';
        txt.textContent = 'Online';
      } else if (status === 'offline') {
        badge.className = 'fw-status fw-status-offline';
        txt.textContent = 'Offline';
      } else {
        badge.className = 'fw-status fw-status-unknown';
        txt.textContent = 'Unknown';
      }

      badge.appendChild(dot);
      badge.appendChild(txt);
    });
  }

  function poll() {
    const badges = document.querySelectorAll('[data-status-id]');
    if (!badges.length) return;

    fetch('/api/appliances', { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (appliances) {
        appliances.forEach(function (a) {
          updateBadge(a.id, a.status);
        });
      })
      .catch(function () {
        // Silently ignore network errors for status polling
      });
  }

  function start(intervalMs) {
    intervalMs = intervalMs || 30000;
    stop();
    poll();
    intervalId = setInterval(poll, intervalMs);
  }

  function stop() {
    if (intervalId) { clearInterval(intervalId); intervalId = null; }
  }

  return { start, stop, poll };
})();

// Auto-start poller if status badges exist on page
document.addEventListener('DOMContentLoaded', function () {
  if (document.querySelector('[data-status-id]')) {
    StatusPoller.start(30000);
  } else {
    StatusPoller.stop();
  }
});

// ============================================================
// Auto-Refresh for Analysis / Logs Pages
// ============================================================
var AutoRefresh = (window.FW && window.FW.AutoRefresh) || (function () {
  let intervalId = null;

  function init() {
    // A countdown started on the previous page must not reload this one.
    if (intervalId) { clearInterval(intervalId); intervalId = null; }
    const meta = document.querySelector('meta[name="fw-auto-refresh"]');
    if (!meta) return;

    const seconds = parseInt(meta.getAttribute('content'), 10) || 60;
    let remaining = seconds;

    const counterEl = document.getElementById('fw-refresh-counter');

    intervalId = setInterval(function () {
      remaining--;
      if (counterEl) counterEl.textContent = remaining;

      if (remaining <= 0) {
        clearInterval(intervalId);
        window.location.reload();
      }
    }, 1000);

    // Manual refresh button
    const btn = document.getElementById('fw-refresh-btn');
    if (btn) {
      btn.addEventListener('click', function () {
        window.location.reload();
      });
    }
  }

  return { init };
})();

document.addEventListener('DOMContentLoaded', function () { AutoRefresh.init(); });

// ============================================================
// Confirm Dialogs for Destructive Actions
// ============================================================
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('[data-fw-confirm]').forEach(function (el) {
    el.addEventListener('click', function (e) {
      const msg = el.getAttribute('data-fw-confirm') || 'Are you sure?';
      if (!confirm(msg)) {
        e.preventDefault();
        e.stopPropagation();
      }
    });
  });

  // Forms with data-fw-confirm-form
  document.querySelectorAll('form[data-fw-confirm-form]').forEach(function (form) {
    form.addEventListener('submit', function (e) {
      const msg = form.getAttribute('data-fw-confirm-form') || 'Are you sure?';
      if (!confirm(msg)) {
        e.preventDefault();
      }
    });
  });
});

// ============================================================
// Flash Message Auto-dismiss
// ============================================================
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('.fw-auto-dismiss').forEach(function (alert) {
    setTimeout(function () {
      alert.style.transition = 'opacity 0.5s ease';
      alert.style.opacity = '0';
      setTimeout(function () { alert.remove(); }, 500);
    }, 4000);
  });
});

// ============================================================
// Table rows: no shared click handler
// ============================================================
// Lists with a toolbar (Clone, Save as template, Delete...) select a row on
// a single click and open it on double-click or Enter; each list template
// binds that itself. A shared single-click handler here navigated away
// before the selection could be used (tests/test_row_select_click.py).

// ============================================================
// Tag Input Helper
// ============================================================
function initTagInput(inputId, containerClass) {
  const input = document.getElementById(inputId);
  const container = document.querySelector('.' + containerClass);
  if (!input || !container) return;

  let tags = [];

  function renderTags() {
    container.querySelectorAll('.fw-tag-item').forEach(function (t) { t.remove(); });
    tags.forEach(function (tag, i) {
      const el = document.createElement('span');
      el.className = 'fw-tag fw-tag-item';
      el.innerHTML = tag + ' <span style="cursor:pointer;margin-left:3px;" data-idx="' + i + '">×</span>';
      el.querySelector('span').addEventListener('click', function () {
        tags.splice(i, 1);
        renderTags();
        updateHidden();
      });
      container.insertBefore(el, input);
    });
  }

  function updateHidden() {
    const hidden = document.getElementById(inputId + '_hidden');
    if (hidden) hidden.value = tags.join(',');
  }

  input.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      const val = input.value.trim().replace(/,/g, '');
      if (val && !tags.includes(val)) {
        tags.push(val);
        renderTags();
        updateHidden();
      }
      input.value = '';
    } else if (e.key === 'Backspace' && !input.value && tags.length) {
      tags.pop();
      renderTags();
      updateHidden();
    }
  });
}

// ============================================================
// General Utility Exports
// ============================================================
window.FW = {
  StatusPoller,
  AutoRefresh,
  initTagInput,
  toast: function (msg, type) {
    type = type || 'info';
    const el = document.createElement('div');
    el.className = 'fw-alert fw-alert-' + type + ' fw-auto-dismiss';
    el.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:9999;min-width:260px;box-shadow:0 4px 12px rgba(0,0,0,0.15)';
    el.textContent = msg;
    document.body.appendChild(el);
    setTimeout(function () {
      el.style.transition = 'opacity 0.5s';
      el.style.opacity = '0';
      setTimeout(function () { el.remove(); }, 500);
    }, 3500);
  }
};

// ============================================================
// On/off toggle switches (.fw-toggle-sw, rendered by the `switch` macro)
// ------------------------------------------------------------
// Keep the underlying checkbox's .value canonical ('enable'/'disable') so the
// existing save / dirty-tracking / live-visibility code (which reads
// input.value) works unchanged, and reflect the state in the adjacent label.
// Called inline (oninput/onchange) by the macro, so a switch behaves correctly
// on EVERY page that renders it — no per-page wiring needed. Global on purpose.
// ============================================================
function fwSync(el) {
  if (!el) return;
  el.value = el.checked ? 'enable' : 'disable';
  var t = el.parentElement && el.parentElement.querySelector('.fw-toggle-sw-text');
  if (t) t.textContent = el.checked ? (el.dataset.on || 'Enabled') : (el.dataset.off || 'Disabled');
}
window.fwSync = fwSync;

// ============================================================
// Collapsible sidebar nav groups (accordion) — delegated 2026-07-05
// The ACTIVE section is rendered .open SERVER-SIDE (base.html) so a page
// load paints the right state with NO flash. The click toggle is bound ONCE
// and DELEGATED on document, because Turbo Drive swaps the <body> (and the
// whole sidebar) on every link navigation — per-element handlers bound to
// the old sidebar are thrown away with it, so after the first Turbo visit
// the toggles "stopped working". document is never replaced, so a single
// delegated listener survives every navigation. Idempotent: guarded so a
// Turbo re-exec of main.js never stacks duplicate listeners.
// ============================================================
(function () {
  var OPEN_KEY = 'fw_nav_open_group';
  var SCROLL_KEY = 'fw_nav_scroll';
  function nameOf(g) { return g.getAttribute('data-nav-group') || ''; }
  function sidebarEl() { return document.getElementById('fw-sidebar'); }

  // --- Bind ONCE on document (survives Turbo body swaps) ---------------------
  if (!window.__fwNavAccordionBound) {
    window.__fwNavAccordionBound = true;

    // Nested Studio subgroup: toggle ONLY itself; do not touch .fw-nav-group
    // (its own class keeps it out of the flat accordion above). 2026-07-11
    document.addEventListener('click', function (e) {
      var sh = e.target.closest ? e.target.closest('.fw-nav-subtoggle') : null;
      if (!sh) return;
      var sg = sh.closest('.fw-nav-subgroup');
      if (sg) { e.preventDefault(); sg.classList.toggle('open'); }
    });

    document.addEventListener('click', function (e) {
      var head = e.target.closest ? e.target.closest('.fw-nav-toggle') : null;
      if (!head) return;
      var g = head.closest('.fw-nav-group');
      var sb = sidebarEl();
      if (!g || !sb || !sb.contains(g)) return;
      var willOpen = !g.classList.contains('open');
      // The device's own menu (.fw-nav-device: FortiWeb, FortiGate, ...) is
      // outside the accordion: open by default, it toggles only itself and
      // the server reads the closed names back from this cookie (2026-10-14).
      if (g.classList.contains('fw-nav-device')) {
        g.classList.toggle('open', willOpen);
        var closed = [];
        try {
          var m = document.cookie.match(/(?:^|;\s*)fw_nav_dev_closed=([^;]*)/);
          closed = m && m[1] ? decodeURIComponent(m[1]).split('|') : [];
        } catch (x) {}
        closed = closed.filter(function (n) { return n && n !== nameOf(g); });
        if (!willOpen) closed.push(nameOf(g));
        document.cookie = 'fw_nav_dev_closed=' + encodeURIComponent(closed.join('|')) +
          '; path=/; max-age=31536000; SameSite=Lax' + (location.protocol === 'https:' ? '; Secure' : '');
        return;
      }
      var groups = sb.querySelectorAll('.fw-nav-group:not(.fw-nav-device)');
      for (var i = 0; i < groups.length; i++) groups[i].classList.remove('open');
      if (willOpen) {
        g.classList.add('open');
        try { localStorage.setItem(OPEN_KEY, nameOf(g)); } catch (x) {}
      } else {
        try { localStorage.removeItem(OPEN_KEY); } catch (x) {}
      }
    });

    // Persist the sidebar's own scroll (capture phase: scroll doesn't bubble).
    document.addEventListener('scroll', function (e) {
      var sb = sidebarEl();
      if (sb && e.target === sb) {
        try { sessionStorage.setItem(SCROLL_KEY, sb.scrollTop); } catch (x) {}
      }
    }, true);
  }

  // --- Per-execution: restore open section + scroll (best-effort) ------------
  var sb = sidebarEl();
  if (!sb) return;

  // If the server didn't open a section (page outside the accordion), reopen
  // the last one the user had open.
  if (!sb.querySelector('.fw-nav-group.open:not(.fw-nav-device)')) {
    var saved = null;
    try { saved = localStorage.getItem(OPEN_KEY); } catch (x) {}
    if (saved) {
      var gs = sb.querySelectorAll('.fw-nav-group:not(.fw-nav-device)');
      for (var j = 0; j < gs.length; j++) {
        if (nameOf(gs[j]) === saved) { gs[j].classList.add('open'); break; }
      }
    }
  }

  var openNow = sb.querySelector('.fw-nav-group.open:not(.fw-nav-device)');
  if (openNow) { try { localStorage.setItem(OPEN_KEY, nameOf(openNow)); } catch (x) {} }

  var sc = null;
  try { sc = sessionStorage.getItem(SCROLL_KEY); } catch (x) {}
  if (sc !== null) sb.scrollTop = parseInt(sc, 10) || 0;

  var activeItem = sb.querySelector('.fw-nav-item.active');
  if (activeItem) {
    var ir = activeItem.getBoundingClientRect(), sr = sb.getBoundingClientRect();
    if (ir.top < sr.top || ir.bottom > sr.bottom) activeItem.scrollIntoView({ block: 'center' });
  }
})();


// ============================================================
// Nested sub-menu accordion (native <details>) — click-driven, 2026-07-06
// The nested sidebar sub-menus (.fw-so-parent, .fw-so-nav-group, .fw-cfg-section)
// are native <details>. Without coordination they open INDEPENDENTLY. This makes
// them an accordion at EVERY depth: opening one collapses every OTHER open
// <details> in the sidebar that is not an ANCESTOR of it, so other branches
// collapse (at any depth) while the opened element's own path stays expanded.
//
// Bound on a SUMMARY CLICK — a genuine user action — NOT on the  event.
// Turbo Drive swaps the whole sidebar on navigation and re-connecting a
// server-rendered <details open> can SYNTHESIZE  events; a toggle-based
// listener then fired on navigation and, when the server rendered two branches
// open, made them fight and collapsed the one the user was in. A click never
// fires on a Turbo render, so navigation can no longer collapse anything.
//
// Delegated on document (survives Turbo body swaps) + guarded (idempotent).
// ============================================================
(function () {
  if (window.__fwNavDetailsAccordionBound) return;
  window.__fwNavDetailsAccordionBound = true;

  document.addEventListener('click', function (e) {
    var sm = e.target && e.target.closest ? e.target.closest('summary') : null;
    if (!sm) return;
    var d = sm.parentElement;
    if (!d || d.tagName !== 'DETAILS') return;
    var sb = document.getElementById('fw-sidebar');
    if (!sb || !sb.contains(d)) return;
    // The native default action toggles d.open AFTER this handler. We only
    // collapse other branches when d is about to OPEN (it is currently closed);
    // a click that is about to CLOSE d must leave the rest untouched.
    if (d.open) return;
    var opens = sb.querySelectorAll('details[open]');
    for (var i = 0; i < opens.length; i++) {
      var o = opens[i];
      // Close every open <details> that is NOT an ancestor of d (o.contains(d)
      // is true for an ancestor of d or d itself), collapsing sibling/other
      // branches at any depth while keeping d's own path expanded.
      if (o !== d && !o.contains(d)) o.open = false;
    }
  });
})();

// ============================================================
// Data-attribute behaviours (the CSP sets script-src-attr 'none', so inline
// on*= handlers never run; templates declare the behaviour instead)
// ============================================================
document.addEventListener('DOMContentLoaded', function () {
  // <select data-fw-autosubmit>: submit the owning form on change
  document.querySelectorAll('[data-fw-autosubmit]').forEach(function (el) {
    el.addEventListener('change', function () { if (el.form) { el.form.submit(); } });
  });
  // <span data-fw-copy="text">: copy the value, flash a check mark
  document.querySelectorAll('[data-fw-copy]').forEach(function (el) {
    el.addEventListener('click', function () {
      var label = el.textContent;
      if (navigator.clipboard) { navigator.clipboard.writeText(el.getAttribute('data-fw-copy')); }
      el.textContent = '✓';
      setTimeout(function () { el.textContent = label; }, 1200);
    });
  });
});

// ============================================================
// Phone: a table wider than the screen scrolls in its own box — 2026-10-11
// Lists rendered in .fw-table-wrapper already scroll sideways. A bare
// Bootstrap .table in a card body does not, and ONE such table widened the
// whole page (Monitoring → Collection: 759px on a 390px phone), so the
// browser zoomed every card on it out to fit. Only a table that really
// overflows and has no scrolling ancestor is wrapped; tables that fit are
// left alone. Watched with one observer because many tables arrive by
// fetch() after the page has rendered.
// ============================================================
(function () {
  if (window.__fwPhoneTablesBound) return;
  window.__fwPhoneTablesBound = true;
  var PHONE_MAX = 768;   // fortiweb.css: @media (max-width: 768px)

  function scrollsX(el) {
    var o = getComputedStyle(el).overflowX;
    return o === 'auto' || o === 'scroll' || o === 'hidden' || o === 'clip';
  }
  function fit() {
    if (window.innerWidth > PHONE_MAX) return;
    var main = document.getElementById('fw-main');
    if (!main) return;
    var limit = document.documentElement.clientWidth + 1;
    var tables = main.querySelectorAll('table');
    for (var i = 0; i < tables.length; i++) {
      var t = tables[i];
      if (t.closest('.modal, .fw-phone-scroll')) continue;
      if (t.getBoundingClientRect().right <= limit) continue;
      var clipped = false;
      for (var p = t.parentElement; p && p !== main; p = p.parentElement) {
        if (scrollsX(p)) { clipped = true; break; }
      }
      if (clipped) continue;
      var box = document.createElement('div');
      box.className = 'fw-phone-scroll';
      t.parentNode.insertBefore(box, t);
      box.appendChild(t);
    }
  }

  var timer = null;
  function soon() { clearTimeout(timer); timer = setTimeout(fit, 200); }
  document.addEventListener('turbo:load', soon);
  window.addEventListener('resize', soon);
  if (window.MutationObserver) {
    new MutationObserver(function () {
      if (window.innerWidth <= PHONE_MAX) soon();
    }).observe(document.documentElement, { childList: true, subtree: true });
  }
  soon();
})();

// ============================================================
// Tables fit their container (>= 769 px wide) — 2026-10-24
// ------------------------------------------------------------
// One opt-out pass for every visible <table> in #fw-main (not in a .modal,
// not under [data-fit="off"], not nested in another table). A table that
// is wider than its scroll/clip box gets, in this order, only as far as it
// still overflows:
//   1. headers and ordinary text cells may wrap at word boundaries
//      (action cells, checkboxes, numbers and dates stay on one line);
//      a pathological value (PEM, base64, a replacement-message body: one
//      token longer than 40 characters or more than 300 characters) shows
//      on one line, max 320 px, with an ellipsis and the full value in
//      `title`;
//   2. the lowest-priority columns are hidden from the right, never the
//      checkbox column, the first identifying column (and the narrow ones
//      left of it), a Status column, an Actions column or a th[data-keep].
//      th[data-priority="1..5"]: 1 = hidden last, 5 = hidden first,
//      unmarked = 3; at most half of the columns. A
//      "N columns hidden · Show all" link above the table
//      toggles show-all (then the table scrolls inside its own box) and back;
//   3. last resort: long words in text cells may break anywhere.
// Cells are hidden with a class, never removed, so scripts that read
// td[i] keep working. A bare table with no scroll box of its own is moved
// into a .fw-fit-scrollbox the first time it overflows, so it can never
// widen the page. Re-runs on Turbo visits/renders/frame loads, Bootstrap
// tab/collapse, container resize (ResizeObserver) and DOM changes in
// #fw-main (MutationObserver), all debounced; a signature (box width,
// rows, text length) makes a re-run on an unchanged table a no-op.
// ============================================================
(function () {
  var api = window.__fwTableFit || (window.__fwTableFit = (function () {
    var MIN_VW = 769;          // phones keep the .fw-phone-scroll behaviour above
    var CLIP_TOKEN = 40, CLIP_LEN = 300, TITLE_MAX = 1000;
    var timer = null, muting = false;
    var observed = new WeakSet();
    var ro = window.ResizeObserver ? new ResizeObserver(function () { schedule(120); }) : null;

    function mainEl() { return document.getElementById('fw-main'); }
    function px(v) { return parseFloat(v) || 0; }
    function txt(el) { return (el.textContent || '').replace(/\s+/g, ' ').trim(); }

    function eligible(t) {
      if (t.closest('.modal, .dropdown-menu, [data-fit="off"]')) return false;
      if (t.parentElement && t.parentElement.closest('table')) return false;
      return t.offsetWidth > 0 && t.offsetHeight > 0;
    }
    function clipOf(t, main) {
      for (var p = t.parentElement; p && p !== main; p = p.parentElement) {
        if (getComputedStyle(p).overflowX !== 'visible') return p;
      }
      return main;
    }
    // What does not fit: the table against the content box of its clip box,
    // and (when nothing between them scrolls) against #fw-main itself, since
    // a box that grows with its table pushes the page sideways instead.
    function excess(t, box, main) {
      var tr = t.getBoundingClientRect();
      var br = box.getBoundingClientRect(), bs = getComputedStyle(box);
      var left = tr.left - br.left - box.clientLeft + box.scrollLeft;
      var right = px(bs.paddingRight) + px(getComputedStyle(t).marginRight);
      for (var p = t.parentElement; p && p !== box; p = p.parentElement) {
        var cs = getComputedStyle(p);
        right += px(cs.paddingRight) + px(cs.borderRightWidth) + px(cs.marginRight);
      }
      var ex = tr.width - (box.clientWidth - left - right);
      if (box !== main) {
        var outer = true;
        for (var q = box; q && q !== main; q = q.parentElement) {
          var qs = getComputedStyle(q);
          // a drawer / popover placed by position is not in the page flow
          if ((q !== box && qs.overflowX !== 'visible') || qs.position === 'fixed' || qs.position === 'absolute') { outer = false; break; }
        }
        if (outer) {
          var mr = main.getBoundingClientRect();
          var limit = mr.left + main.clientLeft + main.clientWidth - px(getComputedStyle(main).paddingRight);
          ex = Math.max(ex, br.right - limit);
        }
      }
      return ex;
    }
    function sigOf(t, box) {
      var b = t.tBodies[0];
      return [Math.round(box.clientWidth), t.rows.length, t.rows[0] ? t.rows[0].cells.length : 0,
              b ? b.textContent.length : 0, t.getAttribute('data-fit-all') || ''].join('|');
    }
    function fitId(t) {
      if (!t.getAttribute('data-fit-id')) t.setAttribute('data-fit-id', 'f' + Math.random().toString(36).slice(2, 9));
      return t.getAttribute('data-fit-id');
    }
    function barOf(t) {
      var id = t.getAttribute('data-fit-id');
      return id ? document.querySelector('.fw-fit-bar[data-fit-for="' + id + '"]') : null;
    }
    function removeBar(t) { var b = barOf(t); if (b) b.remove(); }

    function reset(t) {
      t.classList.remove('fw-fit-wrap', 'fw-fit-break');
      t.style.removeProperty('--fw-fit-clip');
      for (var i = 0; i < t.rows.length; i++) {
        var cells = t.rows[i].cells;
        for (var j = 0; j < cells.length; j++) {
          var c = cells[j];
          c.classList.remove('fw-fit-nw', 'fw-fit-1tok', 'fw-fit-clip', 'fw-fit-hide');
          if (c.__fitTok) { c.__fitTok.el.textContent = c.__fitTok.text; c.__fitTok = null; }
          if (c.hasAttribute('data-fit-colspan')) {
            c.colSpan = +c.getAttribute('data-fit-colspan');
            c.removeAttribute('data-fit-colspan');
          }
          if (c.hasAttribute('data-fit-title')) { c.removeAttribute('title'); c.removeAttribute('data-fit-title'); }
        }
      }
      var bs = t.querySelectorAll('.fw-fit-wrapbadge');
      for (var k = 0; k < bs.length; k++) bs[k].classList.remove('fw-fit-wrapbadge');
    }

    var NUMDATE = /^(?:[-+~<>≈]?[\d][\d\s.,:\/\-+%()x×]*\s*(?:[kmgtp]?i?b|ms|s|sec|min|h|d|days?|%|px|°c)?|\d{4}-\d{2}-\d{2}(?:[ T]\d{1,2}:\d{2}(?::\d{2})?(?:\.\d+)?)?\s*(?:z|utc|[+-]\d{2}:?\d{2})?|.{1,14}\bago|—|-|n\/a|never|none|yes|no|on|off)$/i;
    // Step 1: what each cell may do once the table wraps.
    function markCells(t) {
      t.classList.add('fw-fit-wrap');
      // the identifying column (first titled header that is not '#'): a short
      // name stays on one line ("- fortiadc10" broke under its marker)
      var hr0 = t.tHead && t.tHead.rows.length === 1 ? t.tHead.rows[0] : null, keyIdx = -1;
      if (hr0) for (var h = 0; h < hr0.cells.length; h++) {
        var hs = txt(hr0.cells[h]);
        if (hs && hs !== '#' && !hr0.cells[h].querySelector('input')) { keyIdx = h; break; }
      }
      for (var i = 0; i < t.rows.length; i++) {
        var row = t.rows[i], head = row.parentElement && row.parentElement.tagName === 'THEAD';
        for (var j = 0; j < row.cells.length; j++) {
          var c = row.cells[j];
          if (head) continue;
          if (c.querySelector('.btn, button, input, select, textarea, .dropdown, .form-check, .form-switch')) {
            c.classList.add('fw-fit-nw'); continue;
          }
          var s = txt(c);
          if (!s) continue;
          if (j === keyIdx && row.cells.length === hr0.cells.length && s.length <= 40) { c.classList.add('fw-fit-nw'); continue; }
          if (s.length <= 32 && NUMDATE.test(s)) { c.classList.add('fw-fit-nw'); continue; }
          var longTok = 0, toks = s.split(' ');
          for (var k = 0; k < toks.length; k++) if (toks[k].length > longTok) longTok = toks[k].length;
          if ((longTok > CLIP_TOKEN || s.length > CLIP_LEN) && !c.querySelector('table, ul, ol, .badge, .fw-badge, img, svg')) {
            c.classList.add('fw-fit-clip');
            if (!c.hasAttribute('title')) {
              c.setAttribute('title', s.length > TITLE_MAX ? s.slice(0, TITLE_MAX) + '…' : s);
              c.setAttribute('data-fit-title', '1');
            }
          }
          // wrap between words only: object names are full of hyphens
          // ("net-lab-front") and a break after one reads as two names
          if (s.indexOf(' ') < 0) c.classList.add('fw-fit-1tok');
          else if (/[-\/]/.test(s)) tokenize(c);
          var badges = c.querySelectorAll('.badge, .fw-badge');
          for (var m = 0; m < badges.length; m++) if (txt(badges[m]).length > 40) badges[m].classList.add('fw-fit-wrapbadge');
        }
      }
    }

    // The words of a plain-text cell (or of its single inline child) each in
    // a nowrap span; the separators stay text nodes, so textContent is
    // unchanged. reset() puts the original text back.
    function tokenize(c) {
      var el = c;
      while (el.childNodes.length === 1 && el.firstChild.nodeType === 1 &&
             !el.firstChild.matches('code, pre, .badge, .fw-badge')) el = el.firstChild;
      for (var i = 0; i < el.childNodes.length; i++) if (el.childNodes[i].nodeType !== 3) return;
      var orig = el.textContent, parts = orig.split(/(\s+)/), frag = document.createDocumentFragment();
      for (var j = 0; j < parts.length; j++) {
        if (!parts[j]) continue;
        if (/^\s+$/.test(parts[j]) || !/[-\/]/.test(parts[j])) { frag.appendChild(document.createTextNode(parts[j])); continue; }
        var sp = document.createElement('span');
        sp.className = 'fw-fit-tok';
        sp.textContent = parts[j];
        frag.appendChild(sp);
      }
      el.textContent = '';
      el.appendChild(frag);
      c.__fitTok = { el: el, text: orig };
    }

    // Step 2 helpers: the header row and the columns that may go.
    function headerRow(t) {
      var hr = null;
      if (t.tHead) { if (t.tHead.rows.length !== 1) return null; hr = t.tHead.rows[0]; }
      else if (t.rows[0]) {
        hr = t.rows[0];
        for (var i = 0; i < hr.cells.length; i++) if (hr.cells[i].tagName !== 'TH') return null;
      }
      if (!hr || hr.cells.length < 3) return null;
      for (var j = 0; j < hr.cells.length; j++) if (hr.cells[j].colSpan > 1) return null;
      var rs = t.querySelectorAll('td[rowspan], th[rowspan]');
      for (var k = 0; k < rs.length; k++) if (rs[k].closest('table') === t && rs[k].rowSpan > 1) return null;
      return hr;
    }
    function forCol(t, idx, fn) {
      for (var i = 0; i < t.rows.length; i++) {
        var cells = t.rows[i].cells, at = 0;
        for (var j = 0; j < cells.length; j++) {
          var c = cells[j];
          var span = c.hasAttribute('data-fit-colspan') ? +c.getAttribute('data-fit-colspan') : c.colSpan;
          if (idx >= at && idx < at + span) { fn(c, span); break; }
          at += span;
        }
      }
    }
    function hideCol(t, idx) {
      forCol(t, idx, function (c, span) {
        if (span === 1) { c.classList.add('fw-fit-hide'); return; }
        if (!c.hasAttribute('data-fit-colspan')) c.setAttribute('data-fit-colspan', span);
        c.colSpan = Math.max(1, c.colSpan - 1);
      });
    }
    function unhideCol(t, idx) {
      forCol(t, idx, function (c, span) {
        if (span === 1) c.classList.remove('fw-fit-hide');
        else c.colSpan = c.colSpan + 1;
      });
    }
    function candidates(t, hr) {
      var n = hr.cells.length, firstId = -1, keep = [], out = [];
      var body = t.tBodies[0], sample = body ? Array.prototype.slice.call(body.rows, 0, 20) : [];
      for (var i = 0; i < n; i++) {
        var th = hr.cells[i], s = txt(th);
        if (firstId < 0 && s && s !== '#' && !th.querySelector('input')) firstId = i;
        var k = th.hasAttribute('data-keep') || th.classList.contains('actions-col') ||
                !!th.querySelector('input[type="checkbox"]') ||
                /^(actions?|operations?)$/i.test(s) || /\bstatus\b/i.test(s) || /^state$/i.test(s);
        if (!k && sample.length) {
          var act = 0;
          for (var r = 0; r < sample.length; r++) {
            var cell = sample[r].cells[i];
            if (cell && cell.querySelector('.btn, button, input[type="checkbox"], .dropdown')) act++;
          }
          if (act * 2 >= sample.length && act > 0) k = true;
        }
        keep.push(k);
      }
      for (var j = 0; j < n; j++) {
        if (keep[j] || j <= firstId) continue;
        var pr = parseInt(hr.cells[j].getAttribute('data-priority'), 10);
        out.push({ i: j, p: isNaN(pr) ? 3 : pr, name: txt(hr.cells[j]) });
      }
      out.sort(function (a, b) { return (b.p - a.p) || (b.i - a.i); });
      return out;
    }

    function ensureScrollBox(t, box, main) {
      var dedicated = box !== main && getComputedStyle(box).overflowX !== 'hidden' &&
                      getComputedStyle(box).overflowX !== 'clip';
      if (dedicated) {
        for (var i = 0; i < box.children.length; i++) {
          var k = box.children[i];
          if (k !== t && !k.classList.contains('fw-fit-bar')) { dedicated = false; break; }
        }
      }
      if (dedicated) return box;
      if (t.parentElement.classList.contains('fw-fit-scrollbox')) return t.parentElement;
      var w = document.createElement('div');
      w.className = 'fw-fit-scrollbox';
      t.parentNode.insertBefore(w, t);
      w.appendChild(t);
      return w;
    }
    function setBar(t, box, hidden, all) {
      var bar = barOf(t);
      if (!hidden.length && !all) { if (bar) bar.remove(); return; }
      if (!bar) {
        bar = document.createElement('div');
        bar.className = 'fw-fit-bar';
        bar.setAttribute('data-fit-for', fitId(t));
        var b = document.createElement('button');
        b.type = 'button';
        b.className = 'btn btn-link btn-sm fw-fit-toggle';
        bar.appendChild(b);
        var anchor = (box.children.length === 1 || box.classList.contains('fw-fit-scrollbox')) && box !== mainEl() ? box : t;
        anchor.parentNode.insertBefore(bar, anchor);
      }
      var btn = bar.firstChild;
      if (all) {
        btn.innerHTML = '<i class="bi bi-arrows-angle-contract me-1"></i>All columns shown · Fit to width';
        btn.title = 'Hide the lowest-priority columns so the table fits without scrolling';
      } else {
        btn.innerHTML = '<i class="bi bi-layout-three-columns me-1"></i>' + hidden.length +
          (hidden.length === 1 ? ' column hidden' : ' columns hidden') + ' · Show all';
        btn.title = 'Hidden to fit the width: ' + hidden.join(', ');
      }
    }

    var runs = new WeakMap();
    function fit(t, main) {
      if (!eligible(t)) return;
      var box = clipOf(t, main);
      var sig = sigOf(t, box);
      if (t.__fitSig === sig && t.getAttribute('data-fit-id')) return;
      // a table whose box resizes because of what this pass did (a page
      // scrollbar that comes and goes) must not flip for ever
      var now = Date.now(), r = runs.get(t) || { n: 0, t0: now };
      if (now - r.t0 > 3000) { r.n = 0; r.t0 = now; }
      if (++r.n > 8) return;
      runs.set(t, r);
      fitId(t);
      reset(t);
      var all = t.getAttribute('data-fit-all') === '1';
      var hidden = [];
      if (excess(t, box, main) > 1) {
        box = ensureScrollBox(t, box, main);
        if (ro && !observed.has(box)) { ro.observe(box); observed.add(box); }
        markCells(t);
        var ex = excess(t, box, main);
        if (ex > 1 && t.querySelector('.fw-fit-clip')) {
          // a narrow box (a 2-column table in a side panel): the clipped
          // values give up width first, down to 120 px
          var cw = t.querySelector('.fw-fit-clip').getBoundingClientRect().width;
          t.style.setProperty('--fw-fit-clip', Math.max(120, Math.floor(Math.min(cw, 340) - ex - 16)) + 'px');
          ex = excess(t, box, main);
        }
        var hr = ex > 1 ? headerRow(t) : null;
        var cand = hr ? candidates(t, hr) : [];
        if (hr && cand.length) {
          if (all) { hidden = []; }
          else {
            // never more than half the columns: a narrow panel that would be
            // left with its name column alone breaks long words instead
            cand = cand.slice(0, Math.floor(hr.cells.length / 2));
            while (ex > 1 && cand.length) {
              // one column at a time (exact); a long list in batches sized
              // by the header widths, to keep the number of layouts low
              var freed = 0, batch = [], big = t.rows.length > 300;
              while (cand.length && (batch.length === 0 || (big && freed < ex))) {
                var c = cand.shift();
                freed += hr.cells[c.i].getBoundingClientRect().width;
                hideCol(t, c.i);
                batch.push(c);
              }
              var ex2 = excess(t, box, main);
              if (ex2 >= ex - 1) {
                // hiding did not help: the overflow is not this table's
                // columns (something else widens the box) - undo and stop
                batch.forEach(function (b) { unhideCol(t, b.i); });
                break;
              }
              batch.forEach(function (b) { hidden.push(b.name || ('column ' + (b.i + 1))); });
              ex = ex2;
            }
          }
          setBar(t, box, hidden, all);
        } else {
          removeBar(t);
        }
        // last resort (nothing left to hide, or no header to hide by): long
        // tokens in text cells may break anywhere rather than scroll
        if (!all && excess(t, box, main) > 1) t.classList.add('fw-fit-break');
      } else {
        removeBar(t);
      }
      t.__fitSig = sigOf(t, clipOf(t, main));
    }

    function run() {
      timer = null;
      var main = mainEl();
      if (!main || window.innerWidth < MIN_VW) return;
      muting = true;
      try {
        var ts = main.querySelectorAll('table');
        for (var i = 0; i < ts.length; i++) {
          var t = ts[i];
          if (ro && !observed.has(t)) { ro.observe(t); observed.add(t); }
          try { fit(t, main); } catch (e) { /* one odd table must not stop the rest */ }
        }
      } finally {
        if (mo) mo.takeRecords();
        muting = false;
      }
    }
    function schedule(ms) {
      clearTimeout(timer);
      timer = setTimeout(run, ms == null ? 120 : ms);
    }
    function resetAll() {
      var main = mainEl();
      if (!main) return;
      var ts = main.querySelectorAll('table[data-fit-id]');
      for (var i = 0; i < ts.length; i++) { reset(ts[i]); removeBar(ts[i]); ts[i].__fitSig = null; }
    }

    var mo = window.MutationObserver ? new MutationObserver(function (recs) {
      if (muting) return;
      var main = mainEl();
      if (!main) return;
      for (var i = 0; i < recs.length; i++) {
        var tg = recs[i].target;
        if (tg === main || main.contains(tg)) { schedule(150); return; }
      }
    }) : null;
    if (mo) mo.observe(document.documentElement, { childList: true, subtree: true });

    ['turbo:load', 'turbo:render', 'turbo:frame-load', 'shown.bs.tab', 'shown.bs.collapse', 'shown.bs.modal']
      .forEach(function (ev) { document.addEventListener(ev, function () { schedule(30); }); });
    window.addEventListener('resize', function () { schedule(150); });
    document.addEventListener('turbo:before-cache', resetAll);
    document.addEventListener('turbo:before-render', function () {
      if (ro) { ro.disconnect(); observed = new WeakSet(); }
    });
    document.addEventListener('click', function (e) {
      var b = e.target.closest ? e.target.closest('.fw-fit-toggle') : null;
      if (!b) return;
      var bar = b.closest('.fw-fit-bar');
      var t = bar && document.querySelector('table[data-fit-id="' + bar.getAttribute('data-fit-for') + '"]');
      if (!t) return;
      if (t.getAttribute('data-fit-all') === '1') t.removeAttribute('data-fit-all');
      else t.setAttribute('data-fit-all', '1');
      t.__fitSig = null;
      runs.delete(t);
      var main = mainEl();
      muting = true;
      try { fit(t, main); } finally { if (mo) mo.takeRecords(); muting = false; }
    });

    return { run: run, schedule: schedule, reset: resetAll };
  })());
  if (window.FW) window.FW.fitTables = api.run;
  api.schedule(0);
})();
