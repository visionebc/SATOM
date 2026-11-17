/* SATOM Observability — small SVG charts (no library: offline installs, strict CSP).
   Rules (dataviz skill): one y-axis; series told apart by line style AND colour;
   legend for >= 2 series; crosshair + tooltip on hover and keyboard; a table view
   for every chart; missing points are gaps, never zero. */
(function () {
  'use strict';
  var NS = 'http://www.w3.org/2000/svg';
  var DASH = ['', '6 4', '2 3'];
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function el(tag, attrs, parent) {
    var e = document.createElementNS(NS, tag);
    for (var k in attrs) if (attrs[k] !== undefined && attrs[k] !== null) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }

  // ---------- number formatting by unit ----------
  function si(v, base) {
    var units = ['', 'k', 'M', 'G', 'T'], i = 0, a = Math.abs(v);
    while (a >= base && i < units.length - 1) { a /= base; v /= base; i++; }
    return (Math.abs(v) >= 100 ? v.toFixed(0) : Math.abs(v) >= 10 ? v.toFixed(1) : v.toFixed(2)).replace(/\.0+$|(\.\d*[1-9])0+$/, '$1') + ' ' + units[i];
  }
  function fmt(v, unit) {
    if (v === null || v === undefined || isNaN(v)) return '—';
    switch (unit) {
      case 'bps': return si(v, 1000) + 'bit/s';
      case 'pps': return si(v, 1000) + 'pkt/s';
      case 'bytes': return si(v, 1000) + 'B';
      case 'cps': return si(v, 1000).trim() + '/s';
      case 'ms': return (v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v >= 1 ? v.toFixed(2) : v === 0 ? '0' : v.toFixed(3)).replace(/(\.\d*?)0+$/, '$1').replace(/\.$/, '') + ' ms';
      case 'ratio': return (v * 100).toFixed(v >= 0.9995 ? 0 : 1) + ' %';
      case 'pct': return v.toFixed(1).replace(/\.0$/, '') + ' %';
      default: return si(v, 1000).trim();
    }
  }
  function niceMax(m) {
    if (m <= 0) return 1;
    var p = Math.pow(10, Math.floor(Math.log10(m))), f = m / p;
    // Maxima whose quarter is a round number, so the 4 grid steps read cleanly.
    return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 4 ? 4 : f <= 6 ? 6 : f <= 8 ? 8 : 10) * p;
  }
  function timeLabel(t, span) {
    var d = new Date(t * 1000);
    var hm = String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
    if (span <= 86400) return hm;
    return (d.getMonth() + 1) + '/' + d.getDate() + (span <= 7 * 86400 ? ' ' + hm : '');
  }
  function stamp(t) { var d = new Date(t * 1000); return d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }); }

  // ---------- states ----------
  function message(host, kind, text) {
    host.innerHTML = '<div class="obs-chart-msg ' + kind + '" role="' + (kind === 'error' ? 'alert' : 'status') + '">' +
      '<i class="bi bi-' + (kind === 'error' ? 'x-octagon-fill' : kind === 'loading' ? 'hourglass-split' : 'dash-circle') + '" aria-hidden="true"></i> ' + esc(text) + '</div>';
  }
  function skeleton(host) { host.innerHTML = '<div class="obs-skel obs-skel-chart" aria-hidden="true"></div><span class="visually-hidden" role="status">Loading chart</span>'; }

  // ---------- time-series line chart ----------
  function line(host, data, opts) {
    opts = opts || {};
    var unit = data.unit, series = data.series || [];
    var pts = 0; series.forEach(function (s) { s.points.forEach(function (p) { if (p[1] !== null) pts++; }); });
    if (!pts) { message(host, 'empty', 'No samples in this range yet. Collection runs every few minutes; pick a longer range or wait for the next read.'); return; }
    host.innerHTML = '';
    var W = Math.max(280, host.clientWidth || 600), H = opts.height || 190;
    var m = { t: 10, r: 14, b: 24, l: 64 };
    var iw = W - m.l - m.r, ih = H - m.t - m.b;
    var t0 = data.start, t1 = data.end, span = t1 - t0;
    var ymax = 0; series.forEach(function (s) { s.points.forEach(function (p) { if (p[1] !== null && p[1] > ymax) ymax = p[1]; }); });
    ymax = unit === 'ratio' ? Math.max(1, ymax) : niceMax(ymax * 1.08);
    var X = function (t) { return m.l + (t - t0) / (span || 1) * iw; };
    var Y = function (v) { return m.t + ih - v / ymax * ih; };
    var svg = el('svg', { viewBox: '0 0 ' + W + ' ' + H, width: '100%', height: H, class: 'obs-chart', role: 'img', tabindex: 0,
      'aria-label': (data.title || 'Chart') + '. Use left and right arrow keys to read values.' }, host);
    var grid = el('g', { class: 'obs-chart-grid' }, svg);
    for (var i = 0; i <= 4; i++) {
      var v = ymax * i / 4, y = Y(v);
      el('line', { x1: m.l, x2: W - m.r, y1: y, y2: y }, grid);
      el('text', { x: m.l - 8, y: y + 4, 'text-anchor': 'end', class: 'obs-chart-tick' }, grid).textContent = fmt(v, unit);
    }
    var nx = Math.max(2, Math.min(6, Math.floor(iw / 110)));
    for (i = 0; i <= nx; i++) {
      var t = t0 + span * i / nx;
      el('text', { x: X(t), y: H - 6, 'text-anchor': i === 0 ? 'start' : i === nx ? 'end' : 'middle', class: 'obs-chart-tick' }, grid).textContent = timeLabel(t, span);
    }
    series.forEach(function (s, si_) {
      var color = 'var(--viz-' + (si_ + 1) + ')', d = '', area = '', run = [];
      function flush() {
        if (!run.length) return;
        d += 'M' + run.map(function (p) { return X(p[0]).toFixed(1) + ',' + Y(p[1]).toFixed(1); }).join('L');
        if (si_ === 0 && opts.area !== false) area += 'M' + X(run[0][0]).toFixed(1) + ',' + Y(0) + 'L' + run.map(function (p) { return X(p[0]).toFixed(1) + ',' + Y(p[1]).toFixed(1); }).join('L') + 'L' + X(run[run.length - 1][0]).toFixed(1) + ',' + Y(0) + 'Z';
        if (run.length === 1) el('circle', { cx: X(run[0][0]), cy: Y(run[0][1]), r: 3, fill: color }, svg);
        run = [];
      }
      s.points.forEach(function (p) { if (p[1] === null) flush(); else run.push(p); }); flush();
      if (area) el('path', { d: area, fill: color, 'fill-opacity': .12, stroke: 'none' }, svg);
      if (d) el('path', { d: d, fill: 'none', stroke: color, 'stroke-width': 2, 'stroke-dasharray': DASH[si_ % 3], 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }, svg);
    });
    // Legend with the latest value (identity never by colour alone: line style swatch).
    if (series.length > 1 || opts.legend) {
      var lg = document.createElement('div'); lg.className = 'obs-legend-row';
      lg.innerHTML = series.map(function (s, k) {
        var last = null; for (var j = s.points.length - 1; j >= 0; j--) if (s.points[j][1] !== null) { last = s.points[j][1]; break; }
        return '<span class="obs-lg"><svg width="22" height="8" aria-hidden="true"><line x1="1" y1="4" x2="21" y2="4" stroke="var(--viz-' + (k + 1) + ')" stroke-width="2.5" stroke-dasharray="' + DASH[k % 3] + '"/></svg>' +
          esc(s.legend) + ' <b>' + esc(fmt(last, unit)) + '</b></span>';
      }).join('');
      host.appendChild(lg);
    }
    // Crosshair + tooltip (mouse and keyboard).
    var times = []; series.forEach(function (s) { s.points.forEach(function (p) { if (times.indexOf(p[0]) < 0) times.push(p[0]); }); });
    times.sort(function (a, b) { return a - b; });
    var cross = el('line', { class: 'obs-chart-cross', y1: m.t, y2: m.t + ih, visibility: 'hidden' }, svg);
    var tip = document.createElement('div'); tip.className = 'obs-tip'; tip.hidden = true; host.style.position = 'relative'; host.appendChild(tip);
    var live = document.createElement('span'); live.className = 'visually-hidden'; live.setAttribute('aria-live', 'polite'); host.appendChild(live);
    var cur = -1;
    function show(idx, announce) {
      if (idx < 0 || !times.length) return; cur = Math.max(0, Math.min(times.length - 1, idx));
      var t = times[cur], x = X(t);
      cross.setAttribute('x1', x); cross.setAttribute('x2', x); cross.setAttribute('visibility', 'visible');
      var rows = series.map(function (s, k) {
        var p = s.points.find(function (q) { return q[0] === t; });
        return { k: k, legend: s.legend, v: p ? p[1] : null };
      });
      tip.innerHTML = '<div class="obs-tip-t">' + esc(stamp(t)) + '</div>' + rows.map(function (r) {
        return '<div class="obs-tip-r"><svg width="16" height="6" aria-hidden="true"><line x1="0" y1="3" x2="16" y2="3" stroke="var(--viz-' + (r.k + 1) + ')" stroke-width="2.5" stroke-dasharray="' + DASH[r.k % 3] + '"/></svg>' + esc(r.legend) + '<b>' + esc(fmt(r.v, unit)) + '</b></div>';
      }).join('');
      tip.hidden = false;
      var px = x / W * host.clientWidth;
      tip.style.left = Math.min(Math.max(4, px + 12), host.clientWidth - tip.offsetWidth - 4) + 'px';
      tip.style.top = '8px';
      if (announce) live.textContent = stamp(t) + ': ' + rows.map(function (r) { return r.legend + ' ' + fmt(r.v, unit); }).join(', ');
    }
    function hide() { cross.setAttribute('visibility', 'hidden'); tip.hidden = true; }
    function nearest(clientX) {
      var r = svg.getBoundingClientRect(), x = (clientX - r.left) / r.width * W, best = 0, bd = Infinity;
      times.forEach(function (t, k) { var dd = Math.abs(X(t) - x); if (dd < bd) { bd = dd; best = k; } });
      return best;
    }
    svg.addEventListener('mousemove', function (ev) { show(nearest(ev.clientX)); });
    svg.addEventListener('mouseleave', hide);
    svg.addEventListener('blur', hide);
    svg.addEventListener('keydown', function (ev) {
      if (ev.key === 'ArrowRight') { ev.preventDefault(); show(cur < 0 ? times.length - 1 : cur + 1, true); }
      else if (ev.key === 'ArrowLeft') { ev.preventDefault(); show(cur < 0 ? times.length - 1 : cur - 1, true); }
      else if (ev.key === 'Home') { ev.preventDefault(); show(0, true); }
      else if (ev.key === 'End') { ev.preventDefault(); show(times.length - 1, true); }
      else if (ev.key === 'Escape') hide();
    });
    // Table view.
    if (opts.table !== false) {
      var det = document.createElement('details'); det.className = 'obs-chart-table';
      det.innerHTML = '<summary>Table view</summary><div class="table-responsive"><table class="table table-sm mb-0"><thead><tr><th scope="col">Time</th>' +
        series.map(function (s) { return '<th scope="col" class="text-end">' + esc(s.legend) + '</th>'; }).join('') + '</tr></thead><tbody>' +
        times.slice().reverse().map(function (t) {
          return '<tr><td>' + esc(stamp(t)) + '</td>' + series.map(function (s) { var p = s.points.find(function (q) { return q[0] === t; }); return '<td class="text-end">' + esc(fmt(p ? p[1] : null, unit)) + '</td>'; }).join('') + '</tr>';
        }).join('') + '</tbody></table></div>';
      host.appendChild(det);
    }
    var reads = times.filter(function (t) { return series.some(function (s) { return s.points.some(function (p) { return p[0] === t && p[1] !== null; }); }); }).length;
    if (reads < 4) {
      var n = document.createElement('div'); n.className = 'obs-chart-note';
      n.textContent = 'Only ' + reads + ' point' + (reads === 1 ? '' : 's') + ' in time in this range — collection runs every few minutes.';
      host.appendChild(n);
    }
  }

  // ---------- horizontal bars (one series = one colour) ----------
  function bars(host, rows, opts) {
    opts = opts || {};
    if (!rows.length) { message(host, 'empty', opts.empty || 'Nothing to rank.'); return; }
    var max = Math.max.apply(null, rows.map(function (r) { return r.value || 0; })) || 1;
    host.innerHTML = '<ol class="obs-bars">' + rows.map(function (r) {
      var w = Math.max(r.value ? 1.5 : 0, (r.value || 0) / max * 100);
      var label = r.href ? '<a href="' + esc(r.href) + '">' + esc(r.label) + '</a>' : esc(r.label);
      return '<li title="' + esc(r.label + ': ' + fmt(r.value, opts.unit)) + '"><span class="obs-bar-l">' + label + '</span>' +
        '<span class="obs-bar-track" aria-hidden="true"><span class="obs-bar-fill" style="width:' + w.toFixed(1) + '%"></span></span>' +
        '<span class="obs-bar-v">' + esc(fmt(r.value, opts.unit)) + '</span></li>';
    }).join('') + '</ol>';
  }

  // ---------- 100 % stacked status bar + legend (icon + label + count) ----------
  function stack(host, parts, opts) {
    opts = opts || {};
    var total = parts.reduce(function (a, p) { return a + p.value; }, 0);
    if (!total) { message(host, 'empty', opts.empty || 'No data.'); return; }
    host.innerHTML = '<div class="obs-stack" role="img" aria-label="' + esc(parts.filter(function (p) { return p.value; }).map(function (p) { return p.value + ' ' + p.label; }).join(', ')) + '">' +
      parts.filter(function (p) { return p.value; }).map(function (p) {
        return '<span class="obs-stack-seg st-' + p.status + '" style="flex:' + p.value + '" title="' + esc(p.label + ': ' + p.value) + '"></span>';
      }).join('') + '</div><ul class="obs-stack-legend">' + parts.map(function (p) {
        return '<li class="' + (p.value ? '' : 'zero') + '"><i class="bi bi-' + p.icon + ' st-' + p.status + '" aria-hidden="true"></i>' + esc(p.label) +
          '<b>' + p.value + '</b><span class="text-muted">' + (100 * p.value / total).toFixed(0) + ' %</span></li>';
      }).join('') + '</ul>';
  }

  window.OBSCharts = { line: line, bars: bars, stack: stack, fmt: fmt, message: message, skeleton: skeleton };
})();
