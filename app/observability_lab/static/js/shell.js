/* SATOM Observability — application shell: menu, scope + time range, global
   search, live/health indicators, notifications, shortcuts. No inline handlers
   (CSP). Pages listen for the 'obs:context' event to reload their data. */
(function () {
  'use strict';
  var root = document.documentElement;
  var me = document.currentScript;
  var SHELL_URL = me && me.getAttribute('data-shell-url');
  var store = {
    get: function (k, d) { try { var v = localStorage.getItem(k); return v === null ? d : v; } catch (e) { return d; } },
    set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) { /* private mode */ } }
  };
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }

  // ---------- menu: collapse (desktop) / off-canvas (narrow) ----------
  var sbBtn = document.getElementById('obs-sb-toggle');
  var narrow = window.matchMedia('(max-width: 991px)');
  function syncSbBtn() {
    var open = narrow.matches ? root.classList.contains('obs-sb-open') : !root.classList.contains('obs-sb-collapsed');
    if (sbBtn) { sbBtn.setAttribute('aria-expanded', open ? 'true' : 'false'); sbBtn.title = (open ? 'Collapse' : 'Expand') + ' menu ( [ )'; }
  }
  function toggleSb() {
    if (narrow.matches) { root.classList.toggle('obs-sb-open'); }
    else { var c = root.classList.toggle('obs-sb-collapsed'); store.set('obs.sb', c ? '1' : '0'); }
    syncSbBtn();
  }
  if (sbBtn) sbBtn.addEventListener('click', toggleSb);
  document.addEventListener('click', function (ev) {
    if (narrow.matches && root.classList.contains('obs-sb-open') && !ev.target.closest('#obs-sidebar, #obs-sb-toggle')) { root.classList.remove('obs-sb-open'); syncSbBtn(); }
  });
  syncSbBtn();

  // ---------- context: scope (source) + time range ----------
  // URL wins (deep links), then the stored choice, then the default.
  var params = new URLSearchParams(location.search);
  var RANGES = ['5m', '15m', '1h', '6h', '12h', '24h', '7d', '30d'];
  var ctx = {
    range: RANGES.indexOf(params.get('range')) >= 0 ? params.get('range') : store.get('obs.range', '1h'),
    source: params.has('source') ? params.get('source') : store.get('obs.source', '')
  };
  if (RANGES.indexOf(ctx.range) < 0) ctx.range = '1h';
  window.OBS = window.OBS || {};
  window.OBS.context = function () { return { range: ctx.range, source: ctx.source }; };
  window.OBS.esc = esc;
  var rangeSel = document.getElementById('obs-range'), scopeSel = document.getElementById('obs-scope');
  if (rangeSel) rangeSel.value = ctx.range;
  function announce() {
    var u = new URL(location.href);
    u.searchParams.set('range', ctx.range);
    if (ctx.source) u.searchParams.set('source', ctx.source); else u.searchParams.delete('source');
    if (document.body.hasAttribute('data-context-url')) history.replaceState(null, '', u);
    document.dispatchEvent(new CustomEvent('obs:context', { detail: window.OBS.context() }));
  }
  if (rangeSel) rangeSel.addEventListener('change', function () { ctx.range = rangeSel.value; store.set('obs.range', ctx.range); announce(); });
  if (scopeSel) scopeSel.addEventListener('change', function () { ctx.source = scopeSel.value; store.set('obs.source', ctx.source); announce(); refreshShell(); });

  // ---------- live / health / notifications ----------
  var livePill = document.getElementById('obs-live-pill'), healthPill = document.getElementById('obs-health-pill');
  var bellCount = document.getElementById('obs-bell-count'), notifList = document.getElementById('obs-notif-list'), notifTotal = document.getElementById('obs-notif-total');
  function ago(iso) {
    var s = Math.round((Date.now() - Date.parse(iso)) / 1000);
    if (isNaN(s)) return '';
    if (s < 45) return 'just now';
    if (s < 3600) return Math.round(s / 60) + ' min ago';
    if (s < 86400) return Math.round(s / 3600) + ' h ago';
    return Math.round(s / 86400) + ' d ago';
  }
  window.OBS.ago = ago;
  function setPill(el, st, html, title) { if (!el) return; el.className = el.className.replace(/\bst-\S+/g, '').trim() + ' st-' + st; el.innerHTML = html; if (title) el.title = title; }
  var lastShell = null;
  function renderShell(d) {
    lastShell = d;
    if (scopeSel && scopeSel.options.length <= 1) {
      d.sources.forEach(function (s) { var o = document.createElement('option'); o.value = s.name; o.textContent = s.name; scopeSel.appendChild(o); });
      var known = d.sources.some(function (s) { return s.name === ctx.source; });
      if (!known) { ctx.source = ''; }
      scopeSel.value = ctx.source;
    }
    var liveTxt = { ok: 'Live', stale: 'Stale', error: 'Collection failing', none: 'No data yet' }[d.live] || d.live;
    var when = d.last_read ? ' · ' + ago(d.last_read) : '';
    setPill(livePill, d.live, '<span class="dot" aria-hidden="true"></span><span>' + esc(liveTxt + when) + '</span>',
      d.last_read ? 'Last successful collection: ' + d.last_read.replace('T', ' ').slice(0, 19) + ' UTC' : 'Nothing collected yet');
    var crit = d.problems.filter(function (p) { return p.severity === 'critical'; }).length;
    var hTxt = d.health === 'ok' ? 'Healthy' : d.health === 'none' ? 'No sources' :
      (d.health === 'critical' ? crit + ' critical' : d.problem_count + ' warning' + (d.problem_count === 1 ? '' : 's'));
    var hIcon = { ok: 'check-circle-fill', warning: 'exclamation-triangle-fill', critical: 'x-octagon-fill', none: 'dash-circle' }[d.health];
    setPill(healthPill, d.health, '<i class="bi bi-' + hIcon + '" aria-hidden="true"></i><span>' + esc(hTxt) + '</span>');
    if (bellCount) {
      bellCount.hidden = !d.problem_count;
      bellCount.textContent = d.problem_count > 99 ? '99+' : d.problem_count;
      bellCount.classList.toggle('warn', d.health !== 'critical');
      document.getElementById('obs-bell').setAttribute('aria-label', 'Notifications: ' + d.problem_count + ' need attention');
    }
    if (notifTotal) notifTotal.textContent = d.problem_count ? d.problem_count + ' open' : '';
    if (notifList) {
      notifList.innerHTML = d.problems.length ? d.problems.map(function (p) {
        var ic = p.severity === 'critical' ? 'x-octagon-fill' : 'exclamation-triangle-fill';
        return '<a class="obs-notif-item" href="' + esc(p.url) + '"><i class="bi bi-' + ic + ' ' + p.severity + '" aria-hidden="true"></i>' +
          '<span><span class="visually-hidden">' + p.severity + ': </span><span class="t d-block">' + esc(p.title) + '</span><span class="d d-block">' + esc(p.detail) + '</span></span></a>';
      }).join('') + (d.problem_count > d.problems.length ? '<div class="obs-notif-empty">…and ' + (d.problem_count - d.problems.length) + ' more</div>' : '')
        : '<div class="obs-notif-empty"><i class="bi bi-check-circle text-success" aria-hidden="true"></i> Nothing needs attention.</div>';
    }
    document.dispatchEvent(new CustomEvent('obs:shell', { detail: d }));
  }
  function refreshShell() {
    if (!SHELL_URL || document.hidden) return;
    var u = SHELL_URL + (ctx.source ? '?source=' + encodeURIComponent(ctx.source) : '');
    fetch(u, { credentials: 'same-origin', headers: { Accept: 'application/json' } })
      .then(function (r) { if (r.status === 401 || r.redirected) { location.reload(); throw new Error('signed out'); } if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(renderShell)
      .catch(function () { setPill(livePill, 'error', '<span class="dot" aria-hidden="true"></span><span>Status unavailable</span>', 'The status request failed'); });
  }
  refreshShell();
  setInterval(refreshShell, 60000);
  setInterval(function () { if (lastShell) renderShell(lastShell); }, 30000); // keep "x min ago" honest
  document.addEventListener('visibilitychange', function () { if (!document.hidden) refreshShell(); });

  // ---------- global search (combobox) ----------
  var q = document.getElementById('obs-q'), box = document.getElementById('obs-q-results');
  var ICON = { source: 'hdd-network', diagram: 'diagram-3', if: 'ethernet', policy: 'shield-check', pool: 'collection',
    vip: 'geo-alt', vzone: 'bezier2', backend: 'server', fwpolicy: 'bricks', address: 'geo', endpoint: 'pc-display' };
  var TYPE = { if: 'interface', vzone: 'v-zone', fwpolicy: 'firewall policy', endpoint: 'detected device' };
  var timer = null, seq = 0, active = -1;
  function items() { return box ? box.querySelectorAll('.obs-sr-item') : []; }
  function close() { if (!box) return; box.hidden = true; q.setAttribute('aria-expanded', 'false'); active = -1; q.removeAttribute('aria-activedescendant'); }
  function mark(i) {
    var it = items(); if (!it.length) return;
    active = (i + it.length) % it.length;
    it.forEach(function (el, n) { el.setAttribute('aria-selected', n === active ? 'true' : 'false'); });
    q.setAttribute('aria-activedescendant', it[active].id); it[active].scrollIntoView({ block: 'nearest' });
  }
  function run() {
    var v = q.value.trim(), mine = ++seq;
    if (v.length < 2) { close(); return; }
    fetch(q.getAttribute('data-url') + '?q=' + encodeURIComponent(v), { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (d) {
        if (mine !== seq) return;
        box.innerHTML = d.results.length ? d.results.map(function (r, i) {
          return '<a class="obs-sr-item" role="option" id="obs-sr-' + i + '" aria-selected="false" href="' + esc(r.url) + '">' +
            '<i class="bi bi-' + (ICON[r.type] || 'dot') + '" aria-hidden="true"></i><span class="obs-sr-label">' + esc(r.label) + '</span>' +
            '<span class="obs-sr-sub">' + esc((TYPE[r.type] || r.type) + ' · ' + r.sub) + '</span></a>';
        }).join('') : '<div class="obs-sr-empty">Nothing matches “' + esc(v) + '”.</div>';
        box.hidden = false; q.setAttribute('aria-expanded', 'true'); active = -1;
      })
      .catch(function () { if (mine === seq) { box.innerHTML = '<div class="obs-sr-empty">Search failed. Try again.</div>'; box.hidden = false; } });
  }
  if (q && box) {
    q.addEventListener('input', function () { clearTimeout(timer); timer = setTimeout(run, 180); });
    q.addEventListener('keydown', function (ev) {
      if (ev.key === 'ArrowDown') { ev.preventDefault(); if (box.hidden) run(); else mark(active + 1); }
      else if (ev.key === 'ArrowUp') { ev.preventDefault(); mark(active - 1); }
      else if (ev.key === 'Enter') { var it = items(); if (it.length) { ev.preventDefault(); (it[active >= 0 ? active : 0]).click(); } }
      else if (ev.key === 'Escape') { if (!box.hidden) close(); else q.blur(); }
    });
    q.addEventListener('blur', function () { setTimeout(close, 150); });
    q.addEventListener('focus', function () { if (q.value.trim().length >= 2) run(); });
  }

  // ---------- shortcuts ----------
  document.addEventListener('keydown', function (ev) {
    var t = ev.target, typing = t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
    if (typing || ev.ctrlKey || ev.metaKey || ev.altKey) return;
    if (document.body.classList.contains('obs-wide')) return; // the editor owns the keyboard
    if (ev.key === '/' && q) { ev.preventDefault(); q.focus(); q.select(); }
    else if (ev.key === '[') { ev.preventDefault(); toggleSb(); }
  });

  // ---------- deep links into tabs (#L7 opens that layer's tab) ----------
  if (location.hash && window.bootstrap) {
    var tab = document.getElementById('tab-' + decodeURIComponent(location.hash.slice(1)));
    if (tab) { bootstrap.Tab.getOrCreateInstance(tab).show(); }
  }
})();
