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
