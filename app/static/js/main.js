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
   Fortinet Manager Web — main.js
   ============================================================ */

'use strict';

// ============================================================
// Sidebar Toggle
// ============================================================
(function () {
  const toggleBtn = document.getElementById('fw-sidebar-toggle');
  const sidebar   = document.getElementById('fw-sidebar');
  const main      = document.getElementById('fw-main');
  const footer    = document.getElementById('fw-footer');

  if (!toggleBtn || !sidebar) return;

  const COLLAPSED_KEY = 'fw_sidebar_collapsed';

  function setSidebarState(collapsed) {
    if (collapsed) {
      sidebar.classList.add('collapsed');
      if (main)   main.style.marginLeft = '0';
      if (footer) footer.style.marginLeft = '0';
      localStorage.setItem(COLLAPSED_KEY, '1');
    } else {
      sidebar.classList.remove('collapsed');
      if (main)   main.style.marginLeft = '';
      if (footer) footer.style.marginLeft = '';
      localStorage.removeItem(COLLAPSED_KEY);
    }

    // Mobile: use separate class
    if (window.innerWidth <= 768) {
      sidebar.classList.toggle('mobile-open', !collapsed);
      sidebar.classList.remove('collapsed');
      if (main)   main.style.marginLeft = '';
      if (footer) footer.style.marginLeft = '';
    }
  }

  // Restore persisted state on load
  if (window.innerWidth > 768 && localStorage.getItem(COLLAPSED_KEY) === '1') {
    setSidebarState(true);
  }

  toggleBtn.addEventListener('click', function () {
    if (window.innerWidth <= 768) {
      setSidebarState(sidebar.classList.contains('mobile-open'));
    } else {
      setSidebarState(!sidebar.classList.contains('collapsed'));
    }
  });

  // Close sidebar overlay on outside click (mobile)
  document.addEventListener('click', function (e) {
    if (window.innerWidth <= 768 &&
        sidebar.classList.contains('mobile-open') &&
        !sidebar.contains(e.target) &&
        !toggleBtn.contains(e.target)) {
      setSidebarState(true);
    }
  });
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
// ============================================================
const StatusPoller = (function () {
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
  }
});

// ============================================================
// Auto-Refresh for Analysis / Logs Pages
// ============================================================
const AutoRefresh = (function () {
  let intervalId = null;

  function init() {
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
// Table Row Click Navigation
// ============================================================
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('tr[data-href]').forEach(function (row) {
    row.style.cursor = 'pointer';
    row.addEventListener('click', function (e) {
      if (e.target.closest('button, a, input, select')) return;
      window.location.href = row.getAttribute('data-href');
    });
  });
});

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
      var groups = sb.querySelectorAll('.fw-nav-group');
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
  if (!sb.querySelector('.fw-nav-group.open')) {
    var saved = null;
    try { saved = localStorage.getItem(OPEN_KEY); } catch (x) {}
    if (saved) {
      var gs = sb.querySelectorAll('.fw-nav-group');
      for (var j = 0; j < gs.length; j++) {
        if (nameOf(gs[j]) === saved) { gs[j].classList.add('open'); break; }
      }
    }
  }

  var openNow = sb.querySelector('.fw-nav-group.open');
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
