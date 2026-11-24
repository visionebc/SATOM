/* Overview: KPIs, distributions and time series for the current scope + range. */
(function () {
  'use strict';
  var host = document.getElementById('obs-overview');
  if (!host || !window.OBSCharts) return;
  document.body.setAttribute('data-context-url', ''); // the shell keeps ?range=&source= in the URL
  var C = window.OBSCharts, esc = window.OBS.esc, fmt = C.fmt;
  var OV = host.getAttribute('data-overview-url'), SER = host.getAttribute('data-series-url');
  var ROOT = document.body.getAttribute('data-root') || '';
  var tpName = 'throughput', sesName = 'sessions', fwName = 'fw_traffic', paused = false, seq = 0, cache = {};

  function qs(extra) {
    var c = window.OBS.context(), p = new URLSearchParams({ range: c.range });
    if (c.source) p.set('source', c.source);
    return '?' + p.toString() + (extra || '');
  }
  function getJSON(url) {
    return fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (b) {
        if (!r.ok) throw new Error(b.error || ('HTTP ' + r.status));
        return b;
      });
    });
  }

  // ---------- KPIs ----------
  var ST_ICON = { ok: 'check-circle-fill', warning: 'exclamation-triangle-fill', critical: 'x-octagon-fill', none: 'dash-circle', error: 'x-octagon-fill', stale: 'exclamation-triangle-fill' };
  function kpi(name, label, value, foot, state, icon) {
    var el = host.querySelector('[data-kpi="' + name + '"]');
    if (!el) return;
    el.className = 'obs-kpi' + (state ? ' st-' + state : '');
    el.innerHTML = '<div class="obs-kpi-k"><i class="bi bi-' + icon + '" aria-hidden="true"></i>' + esc(label) + '</div>' +
      '<div class="obs-kpi-v">' + value + '</div><div class="obs-kpi-s">' + foot + '</div>';
  }
  function stateChip(st, text) { return '<span class="obs-chip st-' + ({ warning: 'stale', critical: 'error' }[st] || st) + '"><i class="bi bi-' + ST_ICON[st] + '" aria-hidden="true"></i> ' + esc(text) + '</span>'; }
  function nowVal(n) {
    if (!n) return '—';
    if (n.error) return '<span class="obs-kpi-err" title="' + esc(n.error) + '"><i class="bi bi-x-octagon-fill" aria-hidden="true"></i> ERROR</span>';
    return esc(fmt(n.value, n.unit)).replace(/ ([^ ]+)$/, ' <small>$1</small>');
  }

  function renderOverview(d) {
    var crit = d.critical, warn = d.problem_count - crit;
    var h = !d.sources.total ? 'none' : crit ? 'critical' : warn ? 'warning' : 'ok';
    kpi('health', 'Health', { ok: 'Healthy', warning: 'Warning', critical: 'Critical', none: 'No sources' }[h],
      stateChip(h, d.problem_count ? d.problem_count + ' open' : 'nothing open'), h, 'heart-pulse');
    var st = d.sources.states;
    kpi('systems', 'Systems', d.sources.total,
      esc(d.interfaces.up + ' of ' + d.interfaces.total + ' interfaces up') + (st.stale || st.error ? ' · ' + stateChip(st.error ? 'critical' : 'warning', (st.error + st.stale) + ' not current') : ''), '', 'hdd-rack');
    kpi('services', 'Services', d.services.enabled,
      esc('of ' + d.services.total + ' server policies'), '', 'window-stack');
    kpi('critical', 'Critical', crit, crit ? stateChip('critical', 'see Needs attention') : stateChip('ok', 'none'), crit ? 'critical' : '', 'exclamation-octagon');
    var av = d.services.availability;
    var hb = d.services.health;
    kpi('availability', 'Availability', av === null ? '—' : esc(av.toFixed(1).replace(/\.0$/, '') + ' %'),
      esc(av === null ? 'no health-checked services' : 'policies with a back-end up · ' + (hb.unchecked || 0) + ' without health check'),
      av === null ? '' : av < 100 ? (av < 90 ? 'critical' : 'warning') : 'ok', 'shield-check');
    kpi('throughput', 'Throughput', '<span title="In">↓ ' + nowVal(d.now.throughput_in) + '</span>',
      '<span title="Out">↑ ' + nowVal(d.now.throughput_out) + '</span>', '', 'arrow-left-right');
    kpi('sessions', 'Sessions', nowVal(d.now.sessions), nowVal(d.now.connections) + ' new', '', 'people');
    kpi('latency', 'App response', nowVal(d.now.app_response),
      'client RTT ' + nowVal(d.now.client_rtt) + ' · server ' + nowVal(d.now.server_rtt), '', 'stopwatch');
    var ra = d.now.read_availability;
    kpi('reads', 'Collection', nowVal(ra), esc(d.reads.ok + ' of ' + d.reads.total + ' reads OK now'),
      ra && !ra.error && ra.value !== null ? (ra.value < 0.95 ? 'warning' : 'ok') : '', 'cloud-check');

    // Distributions (status colours + icon + label + count).
    C.stack(document.getElementById('ch-services'), [
      { label: 'Healthy', value: hb.ok || 0, status: 'ok', icon: 'check-circle-fill' },
      { label: 'Back-ends down', value: hb.degraded || 0, status: 'stale', icon: 'exclamation-triangle-fill' },
      { label: 'All back-ends down', value: hb.all_down || 0, status: 'error', icon: 'x-octagon-fill' },
      { label: 'No health check', value: hb.unchecked || 0, status: 'none', icon: 'question-circle' },
      { label: 'Not read', value: hb.no_data || 0, status: 'none', icon: 'dash-circle' },
      { label: 'Disabled', value: hb.disabled || 0, status: 'off', icon: 'pause-circle' }
    ], { empty: 'No server policies collected.' });
    C.stack(document.getElementById('ch-backends'), [
      { label: 'Up', value: d.backends.up, status: 'ok', icon: 'check-circle-fill' },
      { label: 'Down', value: d.backends.down, status: 'error', icon: 'x-octagon-fill' },
      { label: 'No health check', value: d.backends.unchecked, status: 'none', icon: 'question-circle' }
    ], { empty: 'No back-ends collected.' });
    C.stack(document.getElementById('ch-interfaces'), [
      { label: 'Link up', value: d.interfaces.up, status: 'ok', icon: 'check-circle-fill' },
      { label: 'Link down', value: d.interfaces.down, status: 'error', icon: 'x-octagon-fill' },
      { label: 'Other', value: d.interfaces.total - d.interfaces.up - d.interfaces.down, status: 'none', icon: 'dash-circle' }
    ], { empty: 'No interfaces collected.' });

    // Rankings.
    function ranks(id, rows, unit, empty) {
      var elx = document.getElementById(id);
      if (d.top_error) { C.message(elx, 'error', 'Metrics store: ' + d.top_error); return; }
      var srcIds = {}; d.sources.rows.forEach(function (s) { srcIds[s.name] = s.id; });
      C.bars(elx, rows.filter(function (r) { return r.value; }).map(function (r) {
        return { label: r.policy, value: r.value, href: srcIds[r.source] ? ROOT + '/sources/' + srcIds[r.source] + '#L7' : '' };
      }), { unit: unit, empty: empty });
    }
    ranks('ch-top-sessions', d.top.sessions, 'count', 'No server policy has active sessions right now.');
    ranks('ch-top-slow', d.top.app_response, 'ms', 'Every server policy reports 0 ms app response right now (no traffic).');
    ranks('ch-top-fw', d.top.fw_sessions || [], 'count', 'No firewall policy has active sessions right now.');

    // Devices: only what each connector collects; the rest is "—" with the reason in the title.
    var dv = document.getElementById('ov-devices');
    function cell(v, unit, why) { return v === undefined || v === null ? '<span class="text-muted" title="' + esc(why) + '">—</span>' : esc(fmt(v, unit)); }
    dv.innerHTML = d.devices.length ? '<div class="table-responsive"><table class="table table-sm obs-table mb-0"><thead><tr>' +
      '<th scope="col">Device</th><th scope="col" class="text-end">CPU</th><th scope="col" class="text-end">Memory</th>' +
      '<th scope="col" class="text-end">Sessions</th><th scope="col">Licence</th></tr></thead><tbody>' + d.devices.map(function (r) {
        var lic = r.licence_valid === false || String(r.vm_licence || '').toLowerCase() === 'invalid' ? stateChip('critical', 'invalid') :
          (r.licence_valid === true || String(r.vm_licence || '').toLowerCase() === 'valid' ? '<span title="' + esc(r.licence_status || r.vm_licence || '') + '">' + stateChip('ok', 'valid') + '</span>' : '<span class="text-muted">—</span>');
        var nr = 'not collected for ' + r.kind;
        return '<tr><td><a href="' + ROOT + '/sources/' + r.source_id + '"><b>' + esc(r.source) + '</b></a> ' + stateChip({ ok: 'ok', stale: 'warning', error: 'critical', none: 'none' }[r.state], r.state) + '<div class="text-muted small obs-clip" title="' + esc(r.firmware || '') + '">' + esc(r.firmware || r.kind) + '</div></td>' +
          '<td class="text-end">' + cell(r.cpu_pct, 'pct', nr) + '</td><td class="text-end">' + cell(r.mem_pct, 'pct', nr) + '</td>' +
          '<td class="text-end">' + cell(r.sessions, 'count', nr) + '</td><td>' + lic + '</td></tr>';
      }).join('') + '</tbody></table></div>' : '<div class="obs-empty"><div class="obs-empty-title">No sources yet</div></div>';

    // Needs attention.
    document.getElementById('att-count').textContent = d.problem_count ? d.problem_count + ' open' + (d.problem_count > d.problems.length ? ' · first ' + d.problems.length + ' shown' : '') : '';
    var pl = document.getElementById('ov-problems');
    pl.innerHTML = d.problems.length ? '<ul class="obs-att">' + d.problems.map(function (p) {
      return '<li class="sev-' + p.severity + '"><i class="bi bi-' + (p.severity === 'critical' ? 'x-octagon-fill' : 'exclamation-triangle-fill') + '" aria-hidden="true"></i>' +
        '<span class="obs-att-sev">' + (p.severity === 'critical' ? 'Critical' : 'Warning') + '</span>' +
        '<a href="' + esc(p.url) + '" class="obs-att-t">' + esc(p.title) + '</a><span class="obs-att-k">' + esc(p.kind) + '</span>' +
        '<span class="obs-att-d">' + esc(p.detail) + '</span></li>';
    }).join('') + '</ul>' : '<div class="obs-empty"><i class="bi bi-check2-circle" aria-hidden="true"></i><div class="obs-empty-title">Nothing needs attention</div><p>All reads succeed, no back-end or link is down.</p></div>';

    // Activity timeline.
    var names = {}; d.sources.rows.forEach(function (s) { names[s.id] = s.name; });
    document.getElementById('ov-activity').innerHTML = d.activity.length ? d.activity.map(function (j) {
      var st = j.status === 'done' ? 'ok' : j.status === 'failed' ? 'error' : 'none';
      return '<li class="st-' + st + '"><span class="obs-tl-dot" aria-hidden="true"></span>' +
        '<a href="' + ROOT + '/jobs/' + j.id + '"><b>' + esc(j.kind === 'collect' ? 'Collection' : 'Connection test') + '</b> · ' + esc(names[j.source_id] || '') + '</a>' +
        '<time datetime="' + esc(j.at) + '" title="' + esc(j.at) + '">' + esc(window.OBS.ago(j.at)) + '</time>' +
        '<span class="obs-tl-s">' + stateChip(st === 'ok' ? 'ok' : st === 'error' ? 'critical' : 'none', j.status) + ' ' + esc(j.summary) + (j.failed_steps ? ' · ' + j.failed_steps + ' failed steps' : '') + '</span></li>';
    }).join('') : '<li class="obs-empty">No collections yet.</li>';
  }

  function series(name, id, opts) {
    var target = document.getElementById(id);
    if (!cache[id]) C.skeleton(target);
    return getJSON(SER.replace('__N__', name) + qs()).then(function (d) { cache[id] = { d: d, opts: opts }; C.line(target, d, opts); })
      .catch(function (e) { C.message(target, 'error', 'Could not load ' + name + ': ' + e.message); });
  }

  function load() {
    var mine = ++seq;
    var jobs = [
      getJSON(OV + qs()).then(function (d) { if (mine === seq) renderOverview(d); })
        .catch(function (e) { host.querySelectorAll('.obs-kpi').forEach(function (k) { k.innerHTML = '<div class="obs-chart-msg error" role="alert"><i class="bi bi-x-octagon-fill" aria-hidden="true"></i> ' + esc(e.message) + '</div>'; }); }),
      series(tpName, 'ch-throughput', { height: 220 }),
      series('latency', 'ch-latency', { area: false }),
      series(sesName, 'ch-sessions', {}),
      series('reads', 'ch-reads', { height: 150 }),
      series('resources', 'ch-resources', { area: false }),
      series(fwName, 'ch-fw', { height: 200 })
    ];
    Promise.all(jobs).then(function () {
      if (mine !== seq) return;
      var t = new Date();
      document.getElementById('ov-updated').textContent = 'Updated ' + t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    });
  }

  // Segmented switches inside cards.
  function seg(attr, set) {
    host.querySelectorAll('[' + attr + ']').forEach(function (b) {
      b.addEventListener('click', function () {
        b.parentNode.querySelectorAll('button').forEach(function (x) { x.classList.toggle('active', x === b); x.setAttribute('aria-pressed', x === b ? 'true' : 'false'); });
        set(b.getAttribute(attr));
      });
    });
  }
  seg('data-tp', function (v) { tpName = v; series(tpName, 'ch-throughput', { height: 220 }); });
  seg('data-ses', function (v) { sesName = v; series(sesName, 'ch-sessions', {}); });
  seg('data-fw', function (v) { fwName = v; series(fwName, 'ch-fw', { height: 200 }); });

  var pauseBtn = document.getElementById('ov-pause');
  pauseBtn.addEventListener('click', function () {
    paused = !paused;
    pauseBtn.setAttribute('aria-pressed', paused ? 'true' : 'false');
    pauseBtn.innerHTML = paused ? '<i class="bi bi-play-fill" aria-hidden="true"></i> <span>Resume</span>' : '<i class="bi bi-pause-fill" aria-hidden="true"></i> <span>Pause</span>';
  });
  document.getElementById('ov-refresh').addEventListener('click', load);
  document.addEventListener('obs:context', function () { cache = {}; load(); });
  setInterval(function () { if (!paused && !document.hidden) load(); }, 60000);
  var resizeT = null;
  window.addEventListener('resize', function () {
    clearTimeout(resizeT);
    resizeT = setTimeout(function () { Object.keys(cache).forEach(function (id) { C.line(document.getElementById(id), cache[id].d, cache[id].opts); }); }, 200);
  });
  load();
})();
