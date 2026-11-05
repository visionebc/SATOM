/* Monitor / Visualize / Analyze pages: the shell's scope and range drive a
   reload (the server filters, the URL is the state); [data-series] hosts draw a
   named series, [data-top] hosts a ranking; rows open with [data-toggle-next]. */
(function () {
  'use strict';
  var page = document.querySelector('.obs-page[data-scope]');
  var ROOT = document.body.getAttribute('data-root') || '';
  var C = window.OBSCharts, esc = (window.OBS && window.OBS.esc) || function (s) { return String(s); };

  function ctx() { return window.OBS && window.OBS.context ? window.OBS.context() : { range: '1h', source: '' }; }
  function go(c) {
    var u = new URL(location.href);
    u.searchParams.set('range', c.range);
    if (c.source) u.searchParams.set('source', c.source); else u.searchParams.delete('source');
    if (u.href !== location.href) location.assign(u.href);
  }
  if (page) {
    // A stored scope that the URL does not carry yet: apply it once.
    var c0 = ctx(), params = new URLSearchParams(location.search);
    if (!params.has('source') && c0.source && c0.source !== page.getAttribute('data-scope')) { go(c0); return; }
    document.addEventListener('obs:context', function (ev) { go(ev.detail || ctx()); });
  }

  function qs() {
    var c = ctx(), p = new URLSearchParams({ range: c.range });
    if (c.source) p.set('source', c.source);
    return p;
  }
  function getJSON(url) {
    return fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (b) { if (!r.ok) throw new Error(b.error || ('HTTP ' + r.status)); return b; });
    });
  }

  // ---------- named series ----------
  var cache = {};
  function stats(id, d) {
    var t = document.getElementById(id);
    if (!t) return;
    var body = t.querySelector('tbody');
    body.innerHTML = d.series.map(function (s) {
      var st = s.stats || {};
      function c(v) { return '<td class="text-end">' + (v === null || v === undefined ? '<span class="text-muted">—</span>' : esc(C.fmt(v, d.unit))) + '</td>'; }
      return '<tr><td>' + esc(s.legend) + (st.n ? ' <span class="text-muted small">' + st.n + ' pts</span>' : '') + '</td>' + c(st.min) + c(st.avg) + c(st.p95) + c(st.max) + c(st.last) + '</tr>';
    }).join('') || '<tr><td colspan="6" class="text-muted small">No data in the range.</td></tr>';
  }
  function loadSeries(host) {
    var name = host.getAttribute('data-series'), p = qs();
    var src = host.getAttribute('data-series-source');
    if (src) p.set('source', src);
    var opts = { height: +host.getAttribute('data-height') || 190 };
    if (host.getAttribute('data-area') === '0') opts.area = false;
    C.skeleton(host);
    getJSON(ROOT + '/api/v1/analytics/' + encodeURIComponent(name) + '?' + p.toString()).then(function (d) {
      cache[name + '|' + (src || '')] = { host: host, d: d, opts: opts };
      C.line(host, d, opts);
      if (host.getAttribute('data-stats')) stats(host.getAttribute('data-stats'), d);
    }).catch(function (e) {
      C.message(host, 'error', 'Could not load ' + name + ': ' + e.message);
      var t = host.getAttribute('data-stats') && document.getElementById(host.getAttribute('data-stats'));
      if (t) t.querySelector('tbody').innerHTML = '<tr><td colspan="6" class="text-danger small"><i class="bi bi-x-octagon-fill" aria-hidden="true"></i> ERROR — ' + esc(e.message) + '</td></tr>';
    });
  }

  // ---------- rankings ----------
  function loadTop(host) {
    var what = host.getAttribute('data-top'), unit = host.getAttribute('data-unit');
    C.skeleton(host);
    getJSON(ROOT + '/api/v1/top/' + what + '?' + qs().toString()).then(function (d) {
      C.bars(host, d.rows.filter(function (r) { return r.value; }).map(function (r) {
        return { label: what === 'interfaces' ? r.source + ' ' + r.interface : r.source + ' #' + r.policy, value: r.value };
      }), { unit: unit, empty: what === 'interfaces' ? 'No interface traffic in the window.' : 'No firewall policy moved bytes in the range.' });
    }).catch(function (e) { C.message(host, 'error', 'Metrics store: ' + e.message); });
  }

  if (C) {
    document.querySelectorAll('[data-series]').forEach(loadSeries);
    document.querySelectorAll('[data-top]').forEach(loadTop);
    var rt = null;
    window.addEventListener('resize', function () {
      clearTimeout(rt);
      rt = setTimeout(function () { Object.keys(cache).forEach(function (k) { var x = cache[k]; C.line(x.host, x.d, x.opts); }); }, 200);
    });
  }

  // ---------- expandable rows ----------
  document.querySelectorAll('[data-toggle-next]').forEach(function (b) {
    b.addEventListener('click', function () {
      var row = b.closest('tr'), next = row && row.nextElementSibling;
      if (!next) return;
      var open = next.hasAttribute('hidden');
      if (open) next.removeAttribute('hidden'); else next.setAttribute('hidden', '');
      b.setAttribute('aria-expanded', open ? 'true' : 'false');
      b.classList.toggle('open', open);
    });
  });

  // ---------- analytics layout ----------
  document.querySelectorAll('[data-cols]').forEach(function (b) {
    b.addEventListener('click', function () {
      var one = b.getAttribute('data-cols') === '1', grid = document.getElementById('an-grid');
      b.parentNode.querySelectorAll('button').forEach(function (x) { x.classList.toggle('active', x === b); x.setAttribute('aria-pressed', x === b ? 'true' : 'false'); });
      if (grid) grid.classList.toggle('obs-an-one', one);
      window.dispatchEvent(new Event('resize'));
    });
  });

  // ---------- print ----------
  document.querySelectorAll('[data-print]').forEach(function (b) { b.addEventListener('click', function () { window.print(); }); });
})();
