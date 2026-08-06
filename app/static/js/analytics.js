/* Analytics boards — renderer, editor and refresh loop.
 *
 * Chart.js is already loaded globally by base.html from
 * /static/vendor/chart/chart.umd.min.js. It must stay vendored: this product
 * installs into isolated management networks, and a chart that only draws with
 * public internet does not draw where it matters.
 *
 * No inline on* handlers anywhere — the CSP forbids them. Everything is
 * delegated from document, which also survives the innerHTML rewrites the
 * refresh loop performs.
 *
 * Two rules the renderer must not break:
 *   1. A missing bucket is null and stays a gap (spanGaps:false). Joining
 *      across an outage draws a confident straight line through the exact
 *      interval the chart was opened to inspect.
 *   2. "Nothing measured" never renders as a number. It renders as "no data".
 */
(function () {
  'use strict';

  var root = document.getElementById('an-root');
  if (!root) { return; }

  var BASE = root.dataset.base || '/monitoring/analytics/';
  var CAN_EDIT = root.dataset.canEdit === '1';
  var CSRF = (document.querySelector('meta[name=csrf-token]') || {}).content || '';
  var CATALOG = JSON.parse(root.dataset.catalog || '{}');

  var state = {
    board: root.dataset.board || '',
    range: root.dataset.range || '24h',
    from: '',
    to: '',
    charts: {},          // panelId -> Chart instance
    hidden: {},          // panelId -> {seriesIdx: true}
    timer: null,
    busy: false,
    vars: {}           // variable name -> selected value
  };

  // ---------------------------------------------------------------- utils --
  function el(tag, cls, txt) {
    var n = document.createElement(tag);
    if (cls) { n.className = cls; }
    if (txt !== undefined && txt !== null) { n.textContent = String(txt); }
    return n;
  }

  function fmt(v, unit, digits) {
    if (v === null || v === undefined || isNaN(v)) { return '—'; }
    var d = digits === undefined ? 2 : digits;
    var abs = Math.abs(v);
    // Big numbers do not need two decimals; small ones become 0.00 without them.
    if (abs >= 1000) { d = 0; } else if (abs >= 100) { d = Math.min(d, 1); }
    var txt = Number(v).toFixed(d).replace(/\.?0+$/, '');
    if (txt === '' || txt === '-') { txt = '0'; }
    return unit ? (txt + ' ' + unit) : txt;
  }

  function qs(extra) {
    var p = new URLSearchParams();
    if (state.range === 'custom' && state.from && state.to) {
      p.set('from', state.from); p.set('to', state.to);
    } else {
      p.set('range', state.range);
    }
    // Selections ride on EVERY request, the per-panel refresh included: a
    // panel that resolves $device on load but not on refresh draws once and
    // then errors, which reads as a store fault rather than a missing arg.
    Object.keys(state.vars || {}).forEach(function (k) {
      p.set('var_' + k, state.vars[k]);
    });
    Object.keys(extra || {}).forEach(function (k) { p.set(k, extra[k]); });
    return p.toString();
  }

  function vesc(v) {
    return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;',
               '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function renderVars(list) {
    var host = document.getElementById('an-vars');
    if (!host) { return; }
    if (!list || !list.length) { host.innerHTML = ''; return; }
    var html = '';
    list.forEach(function (v) {
      var id = 'an-var-' + v.name;
      html += '<label class="text-muted small mb-0" for="' + id + '">' +
              vesc(v.label) + '</label>';
      if (v.error) {
        // A picker whose options could not be fetched must SAY so. Rendering
        // it empty would look like a fleet with nothing in it.
        html += '<span class="fw-badge fw-badge-danger" title="' +
                vesc(v.error) + '">unavailable</span>';
        return;
      }
      html += '<select class="form-select form-select-sm" id="' + id +
              '" data-act="var" data-var="' + vesc(v.name) +
              '" style="width:auto" data-an-scope>';
      if (v.allow_all !== false) {
        html += '<option value="$__all"' +
                (v.value === '$__all' ? ' selected' : '') + '>All</option>';
      }
      (v.options || []).forEach(function (o) {
        html += '<option value="' + vesc(o) + '"' +
                (o === v.value ? ' selected' : '') + '>' + vesc(o) + '</option>';
      });
      html += '</select>';
      if (v.truncated) {
        html += '<span class="text-muted small" title="more values exist than ' +
                'can be listed">(truncated)</span>';
      }
    });
    host.innerHTML = html;
    // Mirror the SERVER's resolved values back into state. The server is the
    // authority on what a selection resolved to, so a value it refused must
    // not survive in the client and be re-sent on the next request.
    (list || []).forEach(function (v) {
      if (!v.error) { state.vars[v.name] = v.value; }
    });
  }

  function post(url, data) {
    var body = new URLSearchParams();
    Object.keys(data || {}).forEach(function (k) { body.set(k, data[k]); });
    return fetch(url, {
      method: 'POST',
      headers: {
        'X-CSRFToken': CSRF,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body.toString()
    }).then(function (r) { return r.json().catch(function () { return {ok: false, error: 'bad response'}; }); });
  }

  function toast(msg, bad) {
    var box = document.getElementById('an-toast');
    if (!box) { return; }
    box.textContent = msg;
    box.className = 'alert ' + (bad ? 'alert-danger' : 'alert-success') + ' py-2 px-3 mb-2';
    box.style.display = 'block';
    window.setTimeout(function () { box.style.display = 'none'; }, bad ? 8000 : 3500);
  }

  // Short axis label. Full ISO is unreadable at 60 ticks; the date only matters
  // when the window actually spans days.
  function tickLabel(iso, bucketSeconds) {
    var t = iso.replace('T', ' ');
    if (bucketSeconds >= 86400) { return t.slice(5, 10); }
    if (bucketSeconds >= 3600) { return t.slice(5, 16); }
    return t.slice(11, 16);
  }

  var SOURCE_NOTE = {
    raw: 'raw samples',
    hour: 'hourly average',
    day: 'daily average'
  };

  // ------------------------------------------------------------- rendering --
  function render(payload) {
    var grid = document.getElementById('an-grid');
    if (!grid) { return; }
    destroyCharts();
    grid.innerHTML = '';

    if (!payload.panels || !payload.panels.length) {
      var empty = el('div', 'an-empty');
      empty.appendChild(el('i', 'bi bi-graph-up'));
      empty.appendChild(el('div', null,
        CAN_EDIT ? 'This board has no panels yet. Use “Add panel” to build one.'
                 : 'This board has no panels yet.'));
      grid.appendChild(empty);
      return;
    }
    payload.panels.forEach(function (p) { grid.appendChild(panelNode(p)); });
  }

  function destroyCharts() {
    Object.keys(state.charts).forEach(function (k) {
      try { state.charts[k].destroy(); } catch (e) { /* already gone */ }
    });
    state.charts = {};
  }

  function panelNode(data) {
    var p = data.panel;
    var wrap = el('div', 'an-panel');
    wrap.dataset.w = String(p.width || 6);
    wrap.dataset.panel = String(p.id);
    if (CAN_EDIT) { wrap.draggable = true; }

    var card = el('div', 'an-card');
    var head = el('div', 'an-card-head');
    var titles = el('div', null);
    titles.style.minWidth = '0';
    titles.appendChild(el('div', 'an-card-title', p.title || 'Panel'));
    if (p.subtitle) { titles.appendChild(el('div', 'an-card-sub', p.subtitle)); }
    head.appendChild(titles);

    var tools = el('div', 'an-card-tools');
    if (CAN_EDIT) {
      tools.appendChild(iconBtn('bi-pencil', 'Edit panel', 'edit', p.id));
      tools.appendChild(iconBtn('bi-trash', 'Delete panel', 'delete', p.id));
    }
    head.appendChild(tools);
    card.appendChild(head);

    var body = el('div', 'an-card-body');
    card.appendChild(body);

    if (data.error) {
      // A failed query is NOT an empty chart. The two look identical on a
      // canvas and mean opposite things: "nothing is happening" versus "we
      // cannot see whether anything is happening".
      var er = el('div', 'an-empty');
      er.appendChild(el('i', 'bi bi-exclamation-triangle text-danger'));
      er.appendChild(el('div', null, 'Query failed: ' + data.error));
      if (data.expr) { er.appendChild(el('code', null, data.expr)); }
      body.appendChild(er);
    } else if (data.empty) {
      var e = el('div', 'an-empty');
      e.appendChild(el('i', 'bi bi-slash-circle'));
      e.appendChild(el('div', null,
        data.expr ? 'The store has no series matching this expression yet.'
                  : 'No probe matches this panel’s selection.'));
      if (data.expr) { e.appendChild(el('code', null, data.expr)); }
      body.appendChild(e);
    } else {
      drawPanel(body, data);
    }

    card.appendChild(footNode(data));
    wrap.appendChild(card);
    return wrap;
  }

  function iconBtn(icon, title, act, pid) {
    var b = el('button', null);
    b.type = 'button';
    b.title = title;
    b.dataset.act = act;
    b.dataset.panel = String(pid);
    b.appendChild(el('i', 'bi ' + icon));
    return b;
  }

  function footNode(data) {
    var foot = el('div', 'an-card-foot');
    var src = el('span', 'an-src',
      (SOURCE_NOTE[data.source] || data.source) +
      (data.axis && data.axis.length ? ' · ' + data.axis.length + ' pts' : ''));
    foot.appendChild(src);
    if (data.mixed_units) {
      foot.appendChild(el('span', 'an-mixed',
        '⚠ mixed units — series use a second axis'));
    }
    // "no data" must key off POINTS, not off healthy_pct. Store-backed panels
    // have no health concept at all, so a healthy_pct test printed "no data in
    // this window" underneath seventeen plotted points — the footer
    // contradicting the chart above it.
    var plotted = (data.series || []).reduce(function (n, s) {
      return n + ((s.summary && s.summary.points) || 0);
    }, 0);
    if ((data.series || []).length && !plotted) {
      foot.appendChild(el('span', 'an-nodata', 'no data in this window'));
    }
    return foot;
  }

  function drawPanel(body, data) {
    var viz = data.panel.viz;
    if (viz === 'stat') { return drawStat(body, data); }
    if (viz === 'gauge') { return drawGauge(body, data); }
    if (viz === 'table') { return drawTable(body, data); }
    if (viz === 'heatmap') { return drawHeat(body, data); }
    if (viz === 'status') { return drawStrip(body, data); }
    return drawChart(body, data);
  }

  // --- line / area / bar ---------------------------------------------------
  function drawChart(body, data) {
    var wrap = el('div', 'an-chart-wrap');
    wrap.style.height = (data.panel.height || 260) + 'px';
    var canvas = el('canvas');
    wrap.appendChild(canvas);
    body.appendChild(wrap);

    var viz = data.panel.viz;
    var labels = data.axis.map(function (t) {
      return tickLabel(t, data.bucket_seconds);
    });
    var sets = [];
    var hidden = state.hidden[data.panel.id] || {};
    var units = data.units || [];

    data.series.forEach(function (s, i) {
      // The min/max band goes in FIRST so the mean line draws on top of it.
      if (data.panel.show_band && s.min && s.max && viz !== 'bar') {
        sets.push(bandSet(s.max, s.color, i, 'max', hidden[i]));
        sets.push(bandSet(s.min, s.color, i, 'min', hidden[i], '-1'));
      }
      sets.push({
        label: s.label,
        data: s.avg,
        borderColor: s.color,
        backgroundColor: viz === 'area' ? rgba(s.color, 0.18) : s.color,
        borderWidth: 2,
        pointRadius: 0,
        pointHoverRadius: 4,
        tension: 0.25,
        fill: viz === 'area' ? 'origin' : false,
        // A gap is a gap. Joining it invents a reading for the interval the
        // operator opened the chart to look at.
        spanGaps: false,
        hidden: !!hidden[i],
        yAxisID: axisFor(s, units),
        _unit: s.unit,
        _serie: i
      });
      if (s.v2) {
        sets.push({
          label: s.label + ' · ' + (s.v2_label || 'secondary'),
          data: s.v2,
          borderColor: rgba(s.color, 0.55),
          borderDash: [4, 3],
          borderWidth: 1.5,
          pointRadius: 0,
          tension: 0.25,
          fill: false,
          spanGaps: false,
          hidden: !!hidden[i],
          yAxisID: 'y2',
          _unit: s.v2_unit || '',
          _serie: i
        });
      }
    });

    // Threshold lines, once per distinct level — drawing one per series would
    // stack five identical rules at 80 %.
    if (data.panel.show_thresholds) {
      thresholdSets(data).forEach(function (t) { sets.push(t); });
    }

    var scales = {
      x: {
        ticks: { maxTicksLimit: 10, autoSkip: true, font: { size: 10 },
                 color: '#5A6572' },
        grid: { color: 'rgba(31,41,51,.08)' }
      },
      y: {
        beginAtZero: false,
        ticks: { font: { size: 10 }, color: '#5A6572' },
        grid: { color: 'rgba(31,41,51,.08)' },
        title: units.length === 1
          ? { display: true, text: units[0], font: { size: 10 }, color: '#5A6572' }
          : { display: false }
      }
    };
    if (sets.some(function (s) { return s.yAxisID === 'y2'; })) {
      scales.y2 = {
        position: 'right', beginAtZero: false,
        ticks: { font: { size: 10 }, color: '#5A6572' },
        grid: { drawOnChartArea: false }
      };
    }

    var chart = new Chart(canvas.getContext('2d'), {
      type: viz === 'bar' ? 'bar' : 'line',
      data: { labels: labels, datasets: sets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              title: function (items) {
                var i = items.length ? items[0].dataIndex : 0;
                return (data.axis[i] || '').replace('T', ' ') + ' UTC';
              },
              label: function (ctx) {
                if (ctx.dataset._band) { return null; }
                var v = ctx.parsed.y;
                if (v === null || v === undefined) { return ctx.dataset.label + ': no data'; }
                return ctx.dataset.label + ': ' + fmt(v, ctx.dataset._unit);
              }
            }
          }
        },
        scales: scales
      }
    });
    state.charts[data.panel.id] = chart;
    body.appendChild(legendNode(data));
  }

  function axisFor(s, units) {
    // Two different units on one axis is not a comparison. The first unit keeps
    // the left axis, everything else moves right.
    if (units.length > 1 && s.unit && s.unit !== units[0]) { return 'y2'; }
    return 'y';
  }

  function bandSet(vals, color, idx, which, hidden, fillTo) {
    return {
      label: which,
      data: vals,
      borderColor: 'transparent',
      backgroundColor: rgba(color, 0.10),
      pointRadius: 0,
      fill: fillTo || false,
      spanGaps: false,
      tension: 0.25,
      hidden: !!hidden,
      yAxisID: 'y',
      _band: true,
      _serie: idx
    };
  }

  function thresholdSets(data) {
    var out = [];
    var seen = {};
    var n = data.axis.length;
    data.series.forEach(function (s) {
      ['warn', 'crit'].forEach(function (lvl) {
        var v = (s.thresholds || {})[lvl];
        if (!v) { return; }
        var key = lvl + ':' + v;
        if (seen[key]) { return; }
        seen[key] = true;
        out.push({
          label: lvl + ' ' + fmt(v, s.unit),
          data: new Array(n).fill(v),
          borderColor: lvl === 'crit' ? 'rgba(139,28,42,.55)' : 'rgba(122,87,0,.55)',
          borderWidth: 1,
          borderDash: [5, 4],
          pointRadius: 0,
          fill: false,
          yAxisID: 'y',
          _threshold: true
        });
      });
    });
    return out;
  }

  function rgba(hex, a) {
    var h = (hex || '#000').replace('#', '');
    if (h.length === 3) { h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2]; }
    var n = parseInt(h, 16);
    return 'rgba(' + ((n >> 16) & 255) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',' + a + ')';
  }

  function legendNode(data) {
    var box = el('div', 'an-legend');
    data.series.forEach(function (s, i) {
      var item = el('div', 'an-legend-item' +
        ((state.hidden[data.panel.id] || {})[i] ? ' off' : ''));
      item.dataset.act = 'toggle-series';
      item.dataset.panel = String(data.panel.id);
      item.dataset.idx = String(i);
      var dot = el('span', 'an-dot');
      dot.style.background = s.color;
      item.appendChild(dot);
      item.appendChild(el('span', null, s.label));
      box.appendChild(item);
    });
    return box;
  }

  // --- stat ----------------------------------------------------------------
  function drawStat(body, data) {
    var box = el('div', 'an-stat');
    var prev = (data.previous || {}).series || {};
    var isPct = data.panel.stat_func === 'healthy_pct';

    // Headline: the single series if there is one, otherwise the aggregate.
    var vals = data.series.map(function (s) { return s.stat; })
                          .filter(function (v) { return v !== null && v !== undefined; });
    var head = null;
    if (data.series.length === 1) {
      head = data.series[0].stat;
    } else if (vals.length) {
      head = data.panel.stat_func === 'max' ? Math.max.apply(null, vals)
           : data.panel.stat_func === 'min' ? Math.min.apply(null, vals)
           : data.panel.stat_func === 'sum' ? vals.reduce(function (a, b) { return a + b; }, 0)
           : vals.reduce(function (a, b) { return a + b; }, 0) / vals.length;
    }

    var row = el('div', 'an-stat-row');
    if (head === null || head === undefined) {
      // Not "0". A panel that prints zero for "we never measured" tells the
      // operator the service is dead.
      row.appendChild(el('div', 'an-stat-value an-nodata', 'no data'));
    } else {
      row.appendChild(el('div', 'an-stat-value', fmt(head, '', isPct ? 1 : 2)));
      var unit = isPct ? '%' : ((data.units || [])[0] || '');
      if (unit) { row.appendChild(el('div', 'an-stat-unit', unit)); }
      var d = deltaOf(data, prev, head);
      if (d !== null) {
        row.appendChild(el('div', 'an-delta',
          (d > 0 ? '▲ +' : d < 0 ? '▼ ' : '· ') + fmt(d, '%', 1)));
      }
    }
    box.appendChild(row);
    box.appendChild(el('div', 'an-stat-label',
      (CATALOG.stat_meta || {})[data.panel.stat_func] || data.panel.stat_func));

    if (data.series.length > 1) {
      var list = el('div', 'an-stat-list');
      data.series.slice(0, 8).forEach(function (s, i) {
        var it = el('div', 'an-stat-item');
        var dot = el('span', 'an-dot');
        dot.style.background = s.color;
        it.appendChild(dot);
        it.appendChild(el('span', 'an-name', s.label));
        var num = el('span', 'an-num');
        if (s.stat === null || s.stat === undefined) {
          num.className = 'an-num an-nodata';
          num.textContent = 'no data';
        } else {
          num.textContent = fmt(s.stat, isPct ? '%' : s.unit);
        }
        it.appendChild(num);
        list.appendChild(it);
      });
      box.appendChild(list);
    }
    body.appendChild(box);
  }

  function deltaOf(data, prev, head) {
    if (!data.panel.compare_prev || !data.series.length) { return null; }
    var prevVals = data.series.map(function (s) {
      var row = prev[String(s.probe_id)];
      return row ? row.stat : null;
    }).filter(function (v) { return v !== null && v !== undefined; });
    if (!prevVals.length) { return null; }
    var base = prevVals.reduce(function (a, b) { return a + b; }, 0) / prevVals.length;
    // Change from zero is not infinite growth; report nothing rather than ∞.
    if (!base) { return null; }
    return Math.round(1000 * (head - base) / Math.abs(base)) / 10;
  }

  // --- gauge ---------------------------------------------------------------
  function drawGauge(body, data) {
    var box = el('div', 'an-gauge');
    data.series.slice(0, 12).forEach(function (s) {
      var row = el('div', 'an-gauge-row');
      row.appendChild(el('div', 'an-gauge-name', s.label));
      var track = el('div', 'an-gauge-track');
      var th = s.thresholds || {};
      // Scale: thresholds define the meaningful ceiling. Percent metrics use
      // 100 so two gauges of the same kind are visually comparable.
      var top = th.crit || th.warn || (s.unit === '%' ? 100 : (s.summary || {}).max || 1);
      if (s.unit === '%') { top = 100; }
      var val = s.stat;
      if (val !== null && val !== undefined) {
        var pct = Math.max(0, Math.min(100, (val / (top || 1)) * 100));
        var fill = el('div', 'an-gauge-fill');
        fill.style.width = pct + '%';
        fill.style.background = th.crit && val >= th.crit ? '#8B1C2A'
                              : th.warn && val >= th.warn ? '#7A5700'
                              : s.color;
        track.appendChild(fill);
      }
      [['warn', th.warn], ['crit', th.crit]].forEach(function (pair) {
        if (!pair[1] || !top) { return; }
        var m = el('div', 'an-gauge-mark');
        m.style.left = Math.min(100, (pair[1] / top) * 100) + '%';
        m.title = pair[0] + ' ' + pair[1];
        track.appendChild(m);
      });
      row.appendChild(track);
      var v = el('div', 'an-gauge-val');
      if (val === null || val === undefined) {
        v.className = 'an-gauge-val an-nodata';
        v.textContent = 'no data';
      } else {
        v.textContent = fmt(val, s.unit);
      }
      row.appendChild(v);
      box.appendChild(row);
    });
    body.appendChild(box);
  }

  // --- table ---------------------------------------------------------------
  function drawTable(body, data) {
    var wrap = el('div', 'an-table-wrap');
    wrap.style.maxHeight = (data.panel.height || 260) + 'px';
    var t = el('table', 'an-table');
    var thead = el('thead');
    var hr = el('tr');
    ['Series', 'Min', 'Avg', 'Max', 'Last', 'Healthy', 'Drift'].forEach(function (h, i) {
      var th = el('th', i ? 'an-num' : null, h);
      hr.appendChild(th);
    });
    thead.appendChild(hr);
    t.appendChild(thead);
    var tb = el('tbody');
    data.series.forEach(function (s) {
      var tr = el('tr');
      var name = el('td');
      var dot = el('span', 'an-dot');
      dot.style.cssText = 'display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:.35rem;background:' + s.color;
      name.appendChild(dot);
      name.appendChild(document.createTextNode(s.label));
      tr.appendChild(name);
      var sm = s.summary || {};
      [sm.min, sm.avg, sm.max, sm.last].forEach(function (v) {
        tr.appendChild(el('td', 'an-num', fmt(v, s.unit)));
      });
      var hp = el('td', 'an-num');
      if (s.healthy_pct === null || s.healthy_pct === undefined) {
        hp.className = 'an-num an-nodata';
        hp.textContent = 'no data';
      } else {
        hp.textContent = fmt(s.healthy_pct, '%', 1);
      }
      tr.appendChild(hp);
      tr.appendChild(el('td', 'an-num', String(sm.changes || 0)));
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    wrap.appendChild(t);
    body.appendChild(wrap);
  }

  // --- heatmap -------------------------------------------------------------
  function drawHeat(body, data) {
    var box = el('div', 'an-heat');
    box.style.maxHeight = (data.panel.height || 260) + 'px';
    box.style.overflowY = 'auto';
    data.series.forEach(function (s) {
      var row = el('div', 'an-heat-row');
      row.appendChild(el('div', 'an-heat-name', s.label));
      var cells = el('div', 'an-heat-cells');
      // Cap the cell count: 90 days of hourly is 2160 sub-pixel divs, which is
      // slow to lay out and unreadable anyway. Fold into buckets of equal size.
      var vals = foldStatus(s.status, 180);
      vals.forEach(function (st, i) {
        var c = el('div', 'an-heat-cell st-' + (st || 'unknown'));
        c.title = (data.axis[Math.floor(i * data.axis.length / vals.length)] || '') +
                  ' · ' + (st || 'no data');
        cells.appendChild(c);
      });
      row.appendChild(cells);
      box.appendChild(row);
    });
    body.appendChild(box);
  }

  // Worst status wins in a folded cell — an outage inside an otherwise healthy
  // hour must not be averaged away into green.
  var RANK = { crit: 0, error: 1, warn: 2, unknown: 3, ok: 4 };
  function foldStatus(list, max) {
    if (!list || !list.length) { return []; }
    if (list.length <= max) { return list; }
    var out = [];
    var size = Math.ceil(list.length / max);
    for (var i = 0; i < list.length; i += size) {
      var chunk = list.slice(i, i + size).filter(Boolean);
      if (!chunk.length) { out.push(null); continue; }
      chunk.sort(function (a, b) { return (RANK[a] || 3) - (RANK[b] || 3); });
      out.push(chunk[0]);
    }
    return out;
  }

  // --- status strip --------------------------------------------------------
  function drawStrip(body, data) {
    var box = el('div', 'an-strip');
    box.style.maxHeight = (data.panel.height || 260) + 'px';
    box.style.overflowY = 'auto';
    data.series.forEach(function (s) {
      var row = el('div', 'an-strip-row');
      var name = el('div', 'an-strip-name');
      name.appendChild(el('span', null, s.label));
      var hp = el('span', s.healthy_pct === null || s.healthy_pct === undefined
        ? 'an-nodata' : null,
        s.healthy_pct === null || s.healthy_pct === undefined
          ? 'no data' : fmt(s.healthy_pct, '% healthy', 1));
      name.appendChild(hp);
      row.appendChild(name);
      var bar = el('div', 'an-strip-bar');
      foldStatus(s.status, 240).forEach(function (st, i) {
        var seg = el('div', 'an-strip-seg st-' + (st || 'unknown'));
        seg.title = st || 'no data';
        bar.appendChild(seg);
      });
      row.appendChild(bar);
      box.appendChild(row);
    });
    body.appendChild(box);
  }

  // ---------------------------------------------------------------- loading --
  function load() {
    if (state.busy) { return; }
    state.busy = true;
    var grid = document.getElementById('an-grid');
    if (grid) { grid.style.opacity = '.55'; }
    fetch(BASE + 'data?' + qs({ board: state.board }))
      .then(function (r) { return r.json(); })
      .then(function (payload) {
        if (!payload.ok) { throw new Error(payload.error || 'load failed'); }
        renderVars(payload.variables);
        render(payload);
        var stamp = document.getElementById('an-window');
        if (stamp) {
          stamp.textContent = payload.from.replace('T', ' ') + ' → ' +
                              payload.to.replace('T', ' ') + ' UTC';
        }
      })
      .catch(function (e) { toast('Could not load board: ' + e.message, true); })
      .then(function () {
        state.busy = false;
        if (grid) { grid.style.opacity = '1'; }
      });
  }

  function scheduleRefresh(seconds) {
    if (state.timer) { window.clearInterval(state.timer); state.timer = null; }
    if (seconds > 0) {
      state.timer = window.setInterval(load, seconds * 1000);
    }
  }

  // ---------------------------------------------------------------- editing --
  function openEditor(panelId) {
    var modalEl = document.getElementById('an-panel-modal');
    if (!modalEl) { return; }
    var form = modalEl.querySelector('form');
    form.reset();
    form.dataset.panel = panelId ? String(panelId) : '';
    modalEl.querySelector('.modal-title').textContent =
      panelId ? 'Edit panel' : 'Add panel';

    if (panelId) {
      fetch(BASE + 'panel/' + panelId + '/data?' + qs())
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (d.ok) { fillForm(form, d.panel); syncFormVisibility(form); }
        });
    } else {
      syncFormVisibility(form);
    }
    bsModal(modalEl).show();
  }

  function fillForm(form, p) {
    setVal(form, 'title', p.title);
    setVal(form, 'subtitle', p.subtitle);
    setVal(form, 'viz', p.viz);
    setVal(form, 'select_mode', p.select_mode);
    setVal(form, 'rule_kind', p.rule_kind);
    setVal(form, 'vm_expr', p.vm_expr);
    setVal(form, 'vm_legend', p.vm_legend);
    setVal(form, 'vm_unit', p.vm_unit);
    setVal(form, 'rule_match', p.rule_match);
    setVal(form, 'stat_func', p.stat_func);
    setVal(form, 'range_key', p.range_key);
    setVal(form, 'width', String(p.width));
    setVal(form, 'height', String(p.height));
    ['show_band', 'show_v2', 'show_thresholds', 'compare_prev'].forEach(function (k) {
      var box = form.querySelector('[name=' + k + ']');
      if (box) { box.checked = !!p[k]; }
    });
    multiSelect(form, 'rule_devices', p.rule_devices || []);
    multiSelect(form, 'probe_ids', p.probe_ids || []);
  }

  function setVal(form, name, val) {
    var f = form.querySelector('[name=' + name + ']');
    if (f) { f.value = val === undefined || val === null ? '' : String(val); }
  }

  function multiSelect(form, name, values) {
    var sel = form.querySelector('[name=' + name + ']');
    if (!sel) { return; }
    var want = (values || []).map(String);
    Array.prototype.forEach.call(sel.options, function (o) {
      o.selected = want.indexOf(o.value) !== -1;
    });
  }

  function syncFormVisibility(form) {
    var mode = (form.querySelector('[name=select_mode]') || {}).value || 'rule';
    var viz = (form.querySelector('[name=viz]') || {}).value || 'line';
    form.querySelectorAll('[data-when-mode]').forEach(function (n) {
      n.style.display = n.dataset.whenMode === mode ? '' : 'none';
    });
    form.querySelectorAll('[data-when-viz]').forEach(function (n) {
      var list = n.dataset.whenViz.split(',');
      n.style.display = list.indexOf(viz) !== -1 ? '' : 'none';
    });
  }

  function collect(form) {
    var out = {};
    ['title', 'subtitle', 'viz', 'select_mode', 'rule_kind', 'rule_match',
     'vm_expr', 'vm_legend', 'vm_unit',
     'stat_func', 'range_key', 'width', 'height'].forEach(function (k) {
      var f = form.querySelector('[name=' + k + ']');
      if (f) { out[k] = f.value; }
    });
    ['rule_devices', 'probe_ids'].forEach(function (k) {
      var sel = form.querySelector('[name=' + k + ']');
      if (!sel) { return; }
      out[k] = Array.prototype.filter.call(sel.options, function (o) {
        return o.selected;
      }).map(function (o) { return o.value; }).join(',');
    });
    // Checkboxes: send the companion __present marker so the server can tell
    // "unticked" from "this form never rendered the field".
    ['show_band', 'show_v2', 'show_thresholds', 'compare_prev'].forEach(function (k) {
      var box = form.querySelector('[name=' + k + ']');
      if (!box) { return; }
      out[k] = box.checked ? '1' : '0';
      out[k + '__present'] = '1';
    });
    return out;
  }

  function bsModal(node) {
    return (window.bootstrap && window.bootstrap.Modal)
      ? window.bootstrap.Modal.getOrCreateInstance(node)
      : { show: function () { node.style.display = 'block'; },
          hide: function () { node.style.display = 'none'; } };
  }

  // --------------------------------------------------------------- cadence --
  function loadCadence() {
    var host = document.getElementById('an-cadence-body');
    if (!host) { return; }
    host.innerHTML = '<tr><td colspan="6" class="text-muted">Loading…</td></tr>';
    fetch(BASE + 'cadence').then(function (r) { return r.json(); })
      .then(function (d) {
        var note = document.getElementById('an-cadence-note');
        if (note) {
          note.textContent = d.sweep_configured
            ? ('Sweep tick: every ' + d.tick_min + ' min · ' + d.drifted +
               ' of ' + d.total + ' probe(s) do not divide evenly into it.')
            : 'No enabled deep_monitor sweep is scheduled, so nothing is being '
              + 'collected and no effective cadence can be computed. '
              + 'Create it in Automation, or run: satom execute seed actions';
          note.className = d.sweep_configured ? 'text-muted small'
                                              : 'an-nodata small';
        }
        host.innerHTML = '';
        (d.probes || []).forEach(function (p) {
          var tr = el('tr');
          tr.appendChild(el('td', null, p.appliance || '—'));
          tr.appendChild(el('td', null, p.name));
          tr.appendChild(el('td', null, p.kind));
          tr.appendChild(el('td', null, p.enabled ? 'enabled' : 'paused'));
          tr.appendChild(el('td', 'an-num', p.interval_min + ' min'));
          var eff = el('td', 'an-num' + (p.drift ? ' an-drift' : ''));
          eff.textContent = p.effective_min ? (p.effective_min + ' min') : '—';
          if (p.drift) { eff.title = 'Declared ' + p.interval_min +
            ' min, but the sweep only fires every ' + d.tick_min + ' min.'; }
          tr.appendChild(eff);
          host.appendChild(tr);
        });
      })
      .catch(function () {
        host.innerHTML = '<tr><td colspan="6" class="an-nodata">Could not load cadence.</td></tr>';
      });
  }

  // ------------------------------------------------------------ delegation --
  // Delegation is scoped so this page cannot hijack a `data-act` click
  // elsewhere in the console. #an-root is not enough on its own: the page
  // header and the cadence modal are siblings of it, not descendants, so their
  // controls opt in with `data-an-scope`. Without that they render, look
  // enabled, and silently do nothing — which is worse than not offering them.
  function inScope(node) {
    return root.contains(node) || !!node.closest('[data-an-scope]');
  }

  document.addEventListener('click', function (ev) {
    var t = ev.target.closest('[data-act]');
    if (!t || !inScope(t)) { return; }
    var act = t.dataset.act;

    if (act === 'range') {
      ev.preventDefault();
      state.range = t.dataset.range;
      state.from = ''; state.to = '';
      root.querySelectorAll('[data-act=range]').forEach(function (b) {
        b.classList.toggle('active', b === t);
      });
      load();
      return;
    }
    if (act === 'custom-range') {
      ev.preventDefault();
      var f = document.getElementById('an-from');
      var to = document.getElementById('an-to');
      if (!f || !to || !f.value || !to.value) {
        toast('Pick both a start and an end date.', true); return;
      }
      // The picker is local-time; the store is UTC.
      state.from = new Date(f.value).toISOString().slice(0, 19);
      state.to = new Date(to.value).toISOString().slice(0, 19);
      state.range = 'custom';
      root.querySelectorAll('[data-act=range]').forEach(function (b) {
        b.classList.remove('active');
      });
      load();
      return;
    }
    if (act === 'refresh') { ev.preventDefault(); load(); return; }
    if (act === 'add-panel') { ev.preventDefault(); openEditor(0); return; }
    if (act === 'edit') { ev.preventDefault(); openEditor(t.dataset.panel); return; }
    if (act === 'cadence') { ev.preventDefault(); loadCadence(); return; }

    if (act === 'delete') {
      ev.preventDefault();
      if (!window.confirm('Delete this panel?')) { return; }
      post(BASE + 'panel/' + t.dataset.panel + '/delete', {}).then(function (d) {
        if (d.ok) { load(); } else { toast(d.error || 'Delete failed', true); }
      });
      return;
    }
    if (act === 'toggle-series') {
      var pid = t.dataset.panel, idx = parseInt(t.dataset.idx, 10);
      state.hidden[pid] = state.hidden[pid] || {};
      state.hidden[pid][idx] = !state.hidden[pid][idx];
      t.classList.toggle('off', !!state.hidden[pid][idx]);
      var chart = state.charts[pid];
      if (chart) {
        chart.data.datasets.forEach(function (ds) {
          if (ds._serie === idx) { ds.hidden = !!state.hidden[pid][idx]; }
        });
        chart.update();
      }
      return;
    }
    if (act === 'del-board') {
      ev.preventDefault();
      if (!window.confirm('Delete this board and all its panels?')) { return; }
      post(BASE + 'board/' + t.dataset.board + '/delete', {}).then(function (d) {
        if (d.ok) { window.location.search = ''; }
        else { toast(d.error || 'Delete failed', true); }
      });
      return;
    }
    if (act === 'dup-board') {
      ev.preventDefault();
      post(BASE + 'board/' + t.dataset.board + '/duplicate', {}).then(function (d) {
        if (d.ok) { window.location.search = '?board=' + d.board.slug; }
        else { toast(d.error || 'Copy failed', true); }
      });
      return;
    }
  });

  document.addEventListener('change', function (ev) {
    var t = ev.target;
    if (!inScope(t)) { return; }
    if (t.name === 'select_mode' || t.name === 'viz') {
      var form = t.closest('form');
      if (form) { syncFormVisibility(form); }
    }
    if (t.id === 'an-refresh') {
      scheduleRefresh(parseInt(t.value, 10) || 0);
    }
    if (t.dataset && t.dataset.act === 'var') {
      state.vars[t.dataset.var] = t.value;
      load();
    }
  });

  document.addEventListener('submit', function (ev) {
    var form = ev.target;
    if (form.id !== 'an-panel-form') { return; }
    ev.preventDefault();
    var pid = form.dataset.panel;
    var url = pid ? (BASE + 'panel/' + pid)
                  : (BASE + 'board/' + root.dataset.boardId + '/panel');
    post(url, collect(form)).then(function (d) {
      if (!d.ok) { toast(d.error || 'Save failed', true); return; }
      bsModal(document.getElementById('an-panel-modal')).hide();
      load();
    });
  });

  // --- drag to reorder -----------------------------------------------------
  var dragging = null;
  document.addEventListener('dragstart', function (ev) {
    var p = ev.target.closest('.an-panel');
    if (!p || !root.contains(p) || !CAN_EDIT) { return; }
    dragging = p;
    p.classList.add('an-dragging');
    ev.dataTransfer.effectAllowed = 'move';
    // Firefox refuses to start a drag without payload.
    ev.dataTransfer.setData('text/plain', p.dataset.panel);
  });
  document.addEventListener('dragover', function (ev) {
    var p = ev.target.closest('.an-panel');
    if (!p || !dragging || p === dragging) { return; }
    ev.preventDefault();
    p.classList.add('an-drag-over');
  });
  document.addEventListener('dragleave', function (ev) {
    var p = ev.target.closest('.an-panel');
    if (p) { p.classList.remove('an-drag-over'); }
  });
  document.addEventListener('drop', function (ev) {
    var p = ev.target.closest('.an-panel');
    if (!p || !dragging || p === dragging) { return; }
    ev.preventDefault();
    p.classList.remove('an-drag-over');
    var grid = document.getElementById('an-grid');
    var nodes = Array.prototype.slice.call(grid.children);
    var from = nodes.indexOf(dragging), to = nodes.indexOf(p);
    if (from < to) { p.after(dragging); } else { p.before(dragging); }
    var order = Array.prototype.map.call(grid.children, function (n) {
      return n.dataset.panel;
    });
    post(BASE + 'board/' + root.dataset.boardId + '/reorder',
         { order: JSON.stringify(order) }).then(function (d) {
      if (!d.ok) { toast(d.error || 'Could not save order', true); load(); }
    });
  });
  document.addEventListener('dragend', function () {
    if (dragging) { dragging.classList.remove('an-dragging'); }
    dragging = null;
    var g = document.getElementById('an-grid');
    if (g) {
      Array.prototype.forEach.call(g.children, function (n) {
        n.classList.remove('an-drag-over');
      });
    }
  });

  // ------------------------------------------------------------------ boot --
  var initialRefresh = parseInt(root.dataset.refresh || '0', 10);
  var sel = document.getElementById('an-refresh');
  if (sel) { sel.value = String(initialRefresh); }
  scheduleRefresh(initialRefresh);
  load();
})();
