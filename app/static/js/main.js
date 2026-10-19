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
