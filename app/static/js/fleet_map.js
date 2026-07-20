/* Fleet Map — network-design style topology renderer.
 * Internet ☁ → published services (VIP:port) → FortiWeb appliances →
 * server pools → backend server stacks, grouped in zone regions.
 * Data: /architecture/map-data (device cache only — never live REST).
 */
(function () {
  'use strict';

  var viewport = document.getElementById('mapViewport');
  var svg = document.getElementById('mapSvg');
  var listEl = document.getElementById('mapList');
  if (!viewport || !svg) return;

  var NS = 'http://www.w3.org/2000/svg';
  var cfgEl = document.getElementById('fmConfig');
  var CFG = {};
  try { CFG = JSON.parse(cfgEl ? cfgEl.textContent : '{}') || {}; } catch (e) { CFG = {}; }
  var metaTok = document.querySelector('meta[name="csrf-token"]');
  var CSRF = metaTok ? metaTok.getAttribute('content') : '';

  // ---- palette (canonical desktop theme.py MAP_PALETTE) --------------------
  var MAP_PALETTE = [
    '#4f8cff', '#8b5cf6', '#06b6d4', '#10b981',
    '#f59e0b', '#ef4444', '#ec4899', '#14b8a6',
    '#a855f7', '#84cc16', '#f97316', '#6366f1',
    '#0ea5e9', '#22c55e', '#eab308', '#fb7185'
  ];
  function paletteColor(name) {
    if (!name || name.indexOf('(no ') === 0) return '#475569';
    var h = 2166136261;
    for (var i = 0; i < name.length; i++) {
      h = (Math.imul(h ^ name.charCodeAt(i), 16777619)) >>> 0;
    }
    return MAP_PALETTE[h % MAP_PALETTE.length];
  }

  // ---- layout constants -----------------------------------------------------
  var TIER = { net: 96, vip: 318, dev: 492, pool: 688, back: 806 };
  var COLW = 176;          // per-service column width (expanded device)
  var DEVW = 244;          // collapsed device width
  var DEVH = 104;
  var GAP = 58;            // gap between devices
  var ZPAD = 30;           // zone box inner padding
  var ZGAP = 72;           // gap between zones
  var XSTART = 60;
  var VIPW = 156, VIPH = 50;
  var POOLW = 152, POOLH = 44;
  var BEW = 160, BEROW = 26;

  // ---- state ----------------------------------------------------------------
  var model = { devices: [] };
  // Everything starts COLLAPSED on every page load (user rule) — expansion is
  // in-page state only, never restored from a previous visit.
  var expanded = {};                       // devId -> true
  // Multi-select filters: each facet holds an ARRAY of accepted values.
  // Empty array = facet inactive. Within a facet values OR; facets AND.
  var filters = {
    zone: [], line: [], dept: [],          // device facets
    kind: [], firmware: [], data: [],      // device facets
    proto: [], waf: [], status: []         // service facets (filter policies)
  };
  var query = '';
  var viewMode = (CFG.savedView === 'list') ? 'list' : 'map';
  var tx = 0, ty = 0, scale = 1;
  var world = null;

  function rememberExpanded() { /* expansion is intentionally not persisted */ }

  // ---- svg helpers ----------------------------------------------------------
  function el(tag, attrs, parent) {
    var n = document.createElementNS(NS, tag);
    if (attrs) for (var k in attrs) n.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(n);
    return n;
  }
  function txt(parent, x, y, str, cls, anchor) {
    var t = el('text', { x: x, y: y, 'class': cls || '' }, parent);
    if (anchor) t.setAttribute('text-anchor', anchor);
    t.textContent = str;
    return t;
  }
  function trunc(s, n) {
    s = s || '';
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
  }
  function subnet24(ip) {
    var m = /^(\d+\.\d+\.\d+)\.\d+$/.exec(ip || '');
    return m ? m[1] + '.0/24' : '';
  }

  function buildDefs() {
    var defs = el('defs', null, svg);
    var g1 = el('linearGradient', { id: 'fmAccent', x1: '0', y1: '0', x2: '1', y2: '1' }, defs);
    el('stop', { offset: '0%', 'stop-color': '#3b82f6' }, g1);
    el('stop', { offset: '100%', 'stop-color': '#8b5cf6' }, g1);
    var g2 = el('linearGradient', { id: 'fmDevBody', x1: '0', y1: '0', x2: '0', y2: '1' }, defs);
    el('stop', { offset: '0%', 'stop-color': '#182643' }, g2);
    el('stop', { offset: '100%', 'stop-color': '#0e1730' }, g2);
    var g3 = el('linearGradient', { id: 'fmCloud', x1: '0', y1: '0', x2: '0', y2: '1' }, defs);
    el('stop', { offset: '0%', 'stop-color': '#1c2f55' }, g3);
    el('stop', { offset: '100%', 'stop-color': '#101a34' }, g3);
    var f = el('filter', { id: 'fmGlow', x: '-60%', y: '-60%', width: '220%', height: '220%' }, defs);
    el('feGaussianBlur', { stdDeviation: '5', result: 'b' }, f);
    var m = el('feMerge', null, f);
    el('feMergeNode', { 'in': 'b' }, m);
    el('feMergeNode', { 'in': 'SourceGraphic' }, m);
    var sh = el('filter', { id: 'fmShadow', x: '-30%', y: '-30%', width: '160%', height: '180%' }, defs);
    el('feDropShadow', { dx: '0', dy: '4', stdDeviation: '6', 'flood-color': '#000000', 'flood-opacity': '0.45' }, sh);
  }

  // ---- data → layout --------------------------------------------------------
  function policyPasses(p) {
    if (filters.proto.length) {
      var proto = (p.https_service || p.ssl) ? 'HTTPS' : 'HTTP';
      if (filters.proto.indexOf(proto) === -1) return false;
    }
    if (filters.waf.length) {
      var waf = p.wpp ? 'protected' : 'no WAF';
      if (filters.waf.indexOf(waf) === -1) return false;
    }
    if (filters.status.length) {
      var st = p.status === 'enable' ? 'enabled' : 'disabled';
      if (filters.status.indexOf(st) === -1) return false;
    }
    return true;
  }
  function serviceFilterOn() {
    return !!(filters.proto.length || filters.waf.length || filters.status.length);
  }
  function policiesOf(d) {
    return serviceFilterOn() ? d.policies.filter(policyPasses) : d.policies;
  }

  function facetPasses(key, value) {
    return !filters[key].length || filters[key].indexOf(value) !== -1;
  }
  function visibleDevices() {
    return model.devices.filter(function (d) {
      if (!facetPasses('zone', d.zone || '(no zone)')) return false;
      if (!facetPasses('line', d.line || '(no line)')) return false;
      if (!facetPasses('dept', d.department || '(no department)')) return false;
      if (!facetPasses('kind', (d.kind || '?').toUpperCase())) return false;
      if (!facetPasses('firmware', d.firmware || '(unknown)')) return false;
      if (!facetPasses('data', d.cached ? 'cached' : 'no data')) return false;
      if (serviceFilterOn() && !policiesOf(d).length) return false;
      return true;
    });
  }

  function computeLayout() {
    var devs = visibleDevices().slice().sort(function (a, b) {
      var ka = [(a.zone || '~'), (a.line || '~'), (a.department || '~'), a.name];
      var kb = [(b.zone || '~'), (b.line || '~'), (b.department || '~'), b.name];
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    });

    var zones = [];
    var byZone = {};
    devs.forEach(function (d) {
      var z = d.zone || '(no zone)';
      if (!byZone[z]) { byZone[z] = []; zones.push(z); }
      byZone[z].push(d);
    });

    var x = XSTART;
    var maxBottom = TIER.dev + DEVH;
    var L = { zones: [], devices: [], width: 0, height: 0 };

    zones.forEach(function (z) {
      var zx0 = x;
      var zoneBottom = TIER.dev + DEVH;
      byZone[z].forEach(function (d) {
        var pols = policiesOf(d);
        var isOpen = !!expanded[d.id] && pols.length > 0;
        var cols = isOpen ? pols.length : 0;
        var w = isOpen ? Math.max(DEVW, cols * COLW) : DEVW;
        var maxBe = 0;
        if (isOpen) {
          pols.forEach(function (p) {
            if (p.backends.length > maxBe) maxBe = p.backends.length;
          });
        }
        var bottom = isOpen
          ? (maxBe > 0 ? TIER.back + 20 + maxBe * BEROW + 34 : TIER.pool + POOLH + 30)
          : TIER.dev + DEVH;
        if (bottom > zoneBottom) zoneBottom = bottom;
        if (bottom > maxBottom) maxBottom = bottom;
        L.devices.push({ d: d, x: x, w: w, open: isOpen, cols: cols, pols: pols });
        x += w + GAP;
      });
      var zx1 = x - GAP;
      L.zones.push({ name: z, x0: zx0 - ZPAD, x1: zx1 + ZPAD, bottom: zoneBottom + 26 });
      x += ZGAP;
    });

    L.width = Math.max(x - ZGAP + XSTART, 900);
    L.height = maxBottom + 80;
    L.cloudX = L.width / 2;
    return L;
  }

  // ---- glyphs ---------------------------------------------------------------
  function drawCloud(parent, cx) {
    var g = el('g', { 'class': 'fm-cloud', transform: 'translate(' + cx + ',' + TIER.net + ')' }, parent);
    el('path', {
      d: 'M -78,26 C -108,26 -114,-4 -88,-12 C -92,-36 -58,-48 -40,-34 ' +
         'C -30,-58 12,-60 26,-40 C 54,-52 84,-30 72,-8 C 96,-2 90,26 62,26 Z',
      fill: 'url(#fmCloud)', stroke: '#4f8cff', 'stroke-opacity': '0.55',
      'stroke-width': '1.6', filter: 'url(#fmShadow)'
    }, g);
    txt(g, 0, -4, 'INTERNET', 'fm-t-cloud', 'middle');
    txt(g, 0, 14, 'public clients', 'fm-t-dim', 'middle');
  }

  function drawZone(parent, z) {
    var c = paletteColor(z.name);
    var y0 = TIER.vip - 92;
    var g = el('g', { 'class': 'fm-zone' }, parent);
    el('rect', {
      x: z.x0, y: y0, width: z.x1 - z.x0, height: z.bottom - y0,
      rx: 22, fill: c, 'fill-opacity': '0.05',
      stroke: c, 'stroke-opacity': '0.28', 'stroke-width': '1.4',
      'stroke-dasharray': '7 5'
    }, g);
    var lw = Math.max(z.name.length * 8 + 34, 74);
    el('rect', { x: z.x0 + 16, y: y0 - 13, width: lw, height: 26, rx: 13, fill: c }, g);
    txt(g, z.x0 + 16 + lw / 2, y0 + 4, 'ZONE · ' + z.name.toUpperCase(), 'fm-t-zone', 'middle');
  }

  function edgePath(x1, y1, x2, y2) {
    var my = (y1 + y2) / 2;
    return 'M ' + x1 + ',' + y1 + ' C ' + x1 + ',' + my + ' ' + x2 + ',' + my + ' ' + x2 + ',' + y2;
  }

  function drawEdge(parent, d, cls, pk, dev) {
    var p = el('path', { d: d, 'class': 'fm-edge ' + (cls || '') }, parent);
    if (pk) p.setAttribute('data-pk', pk);
    if (dev) p.setAttribute('data-dev', dev);
    return p;
  }

  function lockIcon(parent, x, y, color) {
    var g = el('g', { transform: 'translate(' + x + ',' + y + ')' }, parent);
    el('rect', { x: -4.5, y: -2, width: 9, height: 7.5, rx: 1.6, fill: color }, g);
    el('path', { d: 'M -2.6,-2 V -4.2 A 2.6,2.8 0 0 1 2.6,-4.2 V -2', fill: 'none', stroke: color, 'stroke-width': '1.5' }, g);
    return g;
  }

  function shieldIcon(parent, x, y, color) {
    var g = el('g', { transform: 'translate(' + x + ',' + y + ')' }, parent);
    el('path', {
      d: 'M 0,-7 L 6,-4.5 C 6,0.5 3.5,5 0,7 C -3.5,5 -6,0.5 -6,-4.5 Z',
      fill: color, 'fill-opacity': '0.22', stroke: color, 'stroke-width': '1.3'
    }, g);
    el('path', { d: 'M -2.4,0 L -0.7,1.9 L 2.8,-2.2', fill: 'none', stroke: color, 'stroke-width': '1.4', 'stroke-linecap': 'round' }, g);
    return g;
  }

  function globeIcon(parent, x, y, color) {
    var g = el('g', { transform: 'translate(' + x + ',' + y + ')' }, parent);
    el('circle', { r: 7, fill: 'none', stroke: color, 'stroke-width': '1.3' }, g);
    el('ellipse', { rx: 3, ry: 7, fill: 'none', stroke: color, 'stroke-width': '1' }, g);
    el('line', { x1: -7, y1: 0, x2: 7, y2: 0, stroke: color, 'stroke-width': '1' }, g);
    return g;
  }

  function lbIcon(parent, x, y, color) {
    var g = el('g', { transform: 'translate(' + x + ',' + y + ')' }, parent);
    el('circle', { cy: -4, r: 2.4, fill: color }, g);
    el('circle', { cx: -5, cy: 4, r: 2.4, fill: color, 'fill-opacity': '0.65' }, g);
    el('circle', { cx: 5, cy: 4, r: 2.4, fill: color, 'fill-opacity': '0.65' }, g);
    el('path', { d: 'M 0,-2 L -5,2 M 0,-2 L 5,2', stroke: color, 'stroke-width': '1.2', fill: 'none' }, g);
    return g;
  }

  function vipLabel(p) {
    var v = (p.vips && p.vips[0]) || null;
    if (v && v.ip) return String(v.ip).split('/')[0];
    if (v && v.source) {
      var m = /interface \((.+)\)/.exec(v.source);
      if (m) return 'via ' + m[1];
    }
    return p.vserver || '—';
  }

  function portLabel(p) {
    var parts = [];
    if (p.http_service) parts.push(':' + (p.port != null ? p.port : p.http_service));
    if (p.https_service) parts.push(':' + (p.https_port != null ? p.https_port : p.https_service) + ' TLS');
    if (!parts.length && p.ssl) parts.push('TLS');
    return parts.join('  ');
  }

  function drawVip(parent, x, p, pk, dev) {
    var isTls = !!p.https_service || p.ssl;
    var off = p.status !== 'enable';
    var c = off ? '#64748b' : (isTls ? '#22c55e' : '#4f8cff');
    var g = el('g', {
      'class': 'fm-node fm-vip' + (off ? ' off' : ''),
      'data-pk': pk, 'data-dev': dev,
      transform: 'translate(' + (x - VIPW / 2) + ',' + (TIER.vip - VIPH / 2) + ')'
    }, parent);
    el('rect', {
      width: VIPW, height: VIPH, rx: VIPH / 2, fill: '#0f1a33',
      stroke: c, 'stroke-opacity': '0.75', 'stroke-width': '1.5', filter: 'url(#fmShadow)'
    }, g);
    globeIcon(g, 22, VIPH / 2, c);
    txt(g, 40, 21, trunc(vipLabel(p), 15), 'fm-t-vip');
    txt(g, 40, 37, trunc(portLabel(p) || p.mode, 16), 'fm-t-port');
    if (isTls) lockIcon(g, VIPW - 16, VIPH / 2 - 1, '#22c55e');
    g.__tip = tipPolicy(p, 'Published service');
    return g;
  }

  function drawPool(parent, x, p, pk, dev) {
    var off = p.status !== 'enable';
    var c = off ? '#64748b' : '#8b5cf6';
    var g = el('g', {
      'class': 'fm-node fm-pool' + (off ? ' off' : ''),
      'data-pk': pk, 'data-dev': dev,
      transform: 'translate(' + (x - POOLW / 2) + ',' + (TIER.pool - POOLH / 2) + ')'
    }, parent);
    el('rect', {
      width: POOLW, height: POOLH, rx: 10, fill: '#131c38',
      stroke: c, 'stroke-opacity': '0.65', 'stroke-width': '1.4', filter: 'url(#fmShadow)'
    }, g);
    lbIcon(g, 20, POOLH / 2, c);
    txt(g, 38, 19, trunc(p.pool.name || 'pool', 15), 'fm-t-pool');
    txt(g, 38, 34, p.pool.health ? '♥ ' + trunc(p.pool.health, 13) : 'no health check', 'fm-t-dim2');
    g.__tip = '<b>Server pool</b><br>' + esc(p.pool.name) +
      (p.pool.health ? '<br>health: ' + esc(p.pool.health) : '') +
      (p.pool.balance === 'enable' ? '<br>server balance: on' : '') +
      '<br><span style="color:#64748b">click = full details + config links</span>';
    return g;
  }

  function drawBackends(parent, x, p, pk, dev, yTop, beHits) {
    var list = p.backends || [];
    if (!list.length) return null;
    var y0 = (yTop == null) ? TIER.back : yTop;
    var h = 20 + list.length * BEROW + 8;
    var g = el('g', {
      'class': 'fm-node fm-bes', 'data-pk': pk, 'data-dev': dev,
      transform: 'translate(' + (x - BEW / 2) + ',' + y0 + ')'
    }, parent);
    el('rect', {
      width: BEW, height: h, rx: 10, fill: '#0d1526',
      stroke: '#14b8a6', 'stroke-opacity': '0.5', 'stroke-width': '1.3', filter: 'url(#fmShadow)'
    }, g);
    txt(g, BEW / 2, 15, 'SERVERS', 'fm-t-beh', 'middle');
    list.forEach(function (b, i) {
      var y = 20 + i * BEROW;
      var ok = b.status === 'enable';
      var isHit = beHits && beHits.indexOf(i) >= 0;
      el('rect', {
        x: 7, y: y, width: BEW - 14, height: BEROW - 4, rx: 5,
        fill: isHit ? '#2b2410' : (ok ? '#132038' : '#1c1626'),
        stroke: isHit ? '#f59e0b' : 'none',
        'stroke-width': isHit ? '1.3' : '0',
        'class': isHit ? 'fm-behit' : ''
      }, g);
      // little server front: 3 slots
      var sg = el('g', { transform: 'translate(' + 16 + ',' + (y + (BEROW - 4) / 2) + ')' }, g);
      el('rect', { x: -5, y: -5, width: 10, height: 10, rx: 2, fill: 'none', stroke: ok ? '#14b8a6' : '#ef4444', 'stroke-width': '1.2' }, sg);
      el('line', { x1: -5, y1: -1.4, x2: 5, y2: -1.4, stroke: ok ? '#14b8a6' : '#ef4444', 'stroke-width': '0.9' }, sg);
      el('line', { x1: -5, y1: 2, x2: 5, y2: 2, stroke: ok ? '#14b8a6' : '#ef4444', 'stroke-width': '0.9' }, sg);
      var bt = txt(g, 28, y + 15, (b.ip || '?') + (b.port ? ':' + b.port : ''), ok ? 'fm-t-be' : 'fm-t-be down');
      bt.setAttribute('data-ip', b.ip || '');
      el('circle', { cx: BEW - 14, cy: y + (BEROW - 4) / 2, r: 3, fill: ok ? '#22c55e' : '#ef4444' }, g);
    });
    var sn = subnet24(list[0].ip);
    if (sn) txt(g, BEW / 2, h + 15, sn, 'fm-t-subnet', 'middle');
    g.__tip = '<b>Back-end servers</b><br>' + list.map(function (b) {
      return esc((b.ip || '?') + (b.port ? ':' + b.port : '')) +
        (b.status === 'enable' ? '' : ' <span style="color:#ef4444">(disabled)</span>');
    }).join('<br>') +
      '<br><span style="color:#64748b">click = full details + config links</span>';
    return g;
  }

  function ledColor(d) { return d.cached ? '#22c55e' : '#64748b'; }

  function drawDevice(parent, ld) {
    var d = ld.d;
    var w = ld.w;
    var pols = ld.pols || d.policies;
    var lineC = paletteColor(d.line || '(no line)');
    var g = el('g', {
      'class': 'fm-node fm-dev', 'data-dev': d.id,
      transform: 'translate(' + ld.x + ',' + TIER.dev + ')'
    }, parent);
    el('rect', {
      width: w, height: DEVH, rx: 14, fill: 'url(#fmDevBody)',
      stroke: 'rgba(148,163,184,0.28)', 'stroke-width': '1.3', filter: 'url(#fmShadow)'
    }, g);
    // brand stripe
    el('rect', { x: 0, y: 0, width: w, height: 5, rx: 2.5, fill: 'url(#fmAccent)' }, g);
    // line accent stripe (left)
    el('rect', { x: 0, y: 12, width: 4, height: DEVH - 24, rx: 2, fill: lineC }, g);
    // status LEDs
    el('circle', { cx: w - 18, cy: 20, r: 4.5, fill: ledColor(d), 'class': d.cached ? 'fm-led' : '' }, g);
    el('circle', { cx: w - 32, cy: 20, r: 4.5, fill: '#f59e0b', 'fill-opacity': pols.length ? '0.9' : '0.25' }, g);
    // expander chevron
    var chev = el('g', { 'class': 'fm-chev', transform: 'translate(18,' + 22 + ')' }, g);
    el('circle', { r: 9, fill: 'rgba(79,140,255,0.16)', stroke: 'rgba(79,140,255,0.5)', 'stroke-width': '1' }, chev);
    el('path', {
      d: ld.open ? 'M -3.6,1.6 L 0,-2.2 L 3.6,1.6' : 'M -1.8,-3.6 L 2.2,0 L -1.8,3.6',
      fill: 'none', stroke: '#9ec1ff', 'stroke-width': '1.7', 'stroke-linecap': 'round'
    }, chev);
    txt(g, 36, 27, d.name, 'fm-t-dev');
    txt(g, 36, 44, d.host + (d.port && String(d.port) !== '443' ? ':' + d.port : ''), 'fm-t-host');
    // shield: WAF protected services
    var wppN = pols.filter(function (p) { return p.wpp; }).length;
    if (wppN) {
      shieldIcon(g, w - 24, 44, '#22c55e');
      txt(g, w - 38, 48, String(wppN), 'fm-t-shield', 'end');
    }
    // chips
    var chips = [];
    chips.push({ t: d.kind ? d.kind.toUpperCase() : 'FORTIWEB', c: '#4f8cff' });
    if (d.firmware) chips.push({ t: trunc(d.firmware, 12), c: '#8b5cf6' });
    if (d.line) chips.push({ t: 'LINE ' + d.line, c: lineC });
    if (d.department) chips.push({ t: trunc(d.department, 12), c: '#64748b' });
    if (d.hw && (d.hw.cpu_count || d.hw.mem_total_mb || d.hw.disk_total_gb)) {
      var hwParts = [];
      if (d.hw.cpu_count) hwParts.push(d.hw.cpu_count + ' vCPU');
      if (d.hw.mem_total_mb) hwParts.push(Math.round(d.hw.mem_total_mb / 1024) + ' GB RAM');
      if (d.hw.disk_total_gb) hwParts.push(d.hw.disk_total_gb + ' GB disk');
      chips.push({ t: hwParts.join(' \u00b7 '), c: '#f59e0b' });
    }
    var cx = 36;
    var CHIP_R = w - 12;                       // right edge the chips must never cross
    for (var ci = 0; ci < chips.length; ci++) {
      var ch = chips[ci];
      if (cx > CHIP_R - 20) break;             // no usable room left on this card
      var clabel = ch.t;
      var cw = clabel.length * 6.4 + 16;
      if (cx + cw > CHIP_R) {                   // chip would spill past the card edge -> truncate to fit
        clabel = trunc(clabel, Math.max(2, Math.floor((CHIP_R - cx - 16) / 6.4)));
        cw = clabel.length * 6.4 + 16;
        if (cx + cw > CHIP_R) break;            // still doesn't fit -> stop here
      }
      el('rect', { x: cx, y: 56, width: cw, height: 18, rx: 9, fill: ch.c, 'fill-opacity': '0.16', stroke: ch.c, 'stroke-opacity': '0.45', 'stroke-width': '1' }, g);
      txt(g, cx + cw / 2, 68.5, clabel, 'fm-t-chip', 'middle').setAttribute('fill', ch.c);
      cx += cw + 7;
    }
    // freshness + summary line
    var beN = 0;
    pols.forEach(function (p) { beN += p.backends.length; });
    var summary = pols.length
      ? pols.length + ' service' + (pols.length > 1 ? 's' : '') + ' · ' + beN + ' server' + (beN !== 1 ? 's' : '') + ' · ' + d.freshness
      : (d.policies.length ? 'no service matches the filters' : 'no cached topology — run a sync');
    txt(g, 36, 92, trunc(summary, Math.floor((w - 120) / 6.2)), 'fm-t-fresh');

    // action buttons (bottom-right): info + enter
    var bi = el('g', { 'class': 'fm-btn fm-btn-info', transform: 'translate(' + (w - 92) + ',80)' }, g);
    el('rect', { width: 26, height: 18, rx: 9, fill: 'rgba(148,163,184,0.14)', stroke: 'rgba(148,163,184,0.4)', 'stroke-width': '1' }, bi);
    txt(bi, 13, 13, 'ⓘ', 'fm-t-btn', 'middle');
    bi.setAttribute('data-action', 'info');
    bi.setAttribute('data-id', d.id);
    var be = el('g', { 'class': 'fm-btn fm-btn-enter', transform: 'translate(' + (w - 62) + ',80)' }, g);
    el('rect', { width: 50, height: 18, rx: 9, fill: 'rgba(79,140,255,0.2)', stroke: 'rgba(79,140,255,0.6)', 'stroke-width': '1' }, be);
    txt(be, 25, 13, 'Enter ▶', 'fm-t-btn', 'middle');
    be.setAttribute('data-action', 'enter');
    be.setAttribute('data-id', d.id);

    // port squares where columns attach
    if (ld.open) {
      pols.forEach(function (p, i) {
        var px = ld.x0col(i) - ld.x;
        el('rect', { x: px - 4, y: -4, width: 8, height: 8, rx: 2, fill: '#0b1222', stroke: '#4f8cff', 'stroke-opacity': '0.7', 'stroke-width': '1' }, g);
        el('rect', { x: px - 4, y: DEVH - 4, width: 8, height: 8, rx: 2, fill: '#0b1222', stroke: '#8b5cf6', 'stroke-opacity': '0.7', 'stroke-width': '1' }, g);
      });
    } else if (pols.length) {
      el('rect', { x: w / 2 - 4, y: -4, width: 8, height: 8, rx: 2, fill: '#0b1222', stroke: '#4f8cff', 'stroke-opacity': '0.7', 'stroke-width': '1' }, g);
    }
    g.__tip = '<b>' + esc(d.name) + '</b><br>' + esc(d.host) +
      (d.model ? '<br>' + esc(d.model) : '') +
      (d.firmware ? '<br>firmware ' + esc(d.firmware) : '') +
      (d.hw ? '<br><span style="color:#fcd34d">' + (d.hw.cpu_count || '?') + ' vCPU \u00b7 ' + (d.hw.mem_total_mb ? Math.round(d.hw.mem_total_mb / 1024) + ' GB RAM' : '? RAM') + (d.hw.disk_total_gb ? ' \u00b7 ' + d.hw.disk_total_gb + ' GB disk' : '') + '</span>' : '') +
      '<br><span style="color:#93a1bd">' + esc(d.zone || 'no zone') + ' · ' +
      esc(d.line || 'no line') + ' · ' + esc(d.department || 'no dept') + '</span>' +
      '<br><span style="color:#93a1bd">data: ' + esc(d.freshness) + '</span>' +
      '<br><span style="color:#64748b">click card = expand · ⓘ = inventory · Enter ▶ = work on it</span>';
    return g;
  }

  function tipPolicy(p, title) {
    var rows = ['<b>' + esc(title || 'Service') + '</b> — ' + esc(p.name)];
    rows.push('mode: ' + esc(p.mode || '?') + (p.status === 'enable' ? '' : ' · <span style="color:#ef4444">disabled</span>'));
    if (p.monitor) rows.push('<span style="color:#f59e0b">monitor mode (detection only)</span>');
    var pl = portLabel(p);
    if (pl) rows.push('ports: ' + esc(pl));
    if (p.wpp) rows.push('WAF profile: ' + esc(p.wpp));
    rows.push('<span style="color:#64748b">click = full details + config links</span>');
    return rows.join('<br>');
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }

  // ---- render ----------------------------------------------------------------
  function render() {
    if (viewMode === 'list') { renderList(); return; }
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    buildDefs();
    world = el('g', { id: 'fmWorld' }, svg);
    if (query.trim()) {
      renderSearch();
      applyTransform();
      return;
    }
    renderFull();
    applyTransform();
    applyHighlights();
    updateStats();
  }

  function renderFull() {
    var L = computeLayout();
    svg.setAttribute('data-w', L.width);
    svg.setAttribute('data-h', L.height);

    var gZones = el('g', null, world);
    var gEdges = el('g', null, world);
    var gNodes = el('g', null, world);

    L.zones.forEach(function (z) { drawZone(gZones, z); });
    drawCloud(gNodes, L.cloudX);

    L.devices.forEach(function (ld) {
      var d = ld.d;
      ld.x0col = function (i) { return ld.x + i * COLW + COLW / 2; };
      if (ld.open) {
        ld.pols.forEach(function (p, i) {
          var x = ld.x0col(i);
          var pk = d.id + '/' + p.name;
          var eCls = (p.https_service || p.ssl ? 'https ' : '') +
                     (p.status !== 'enable' ? 'off ' : 'flow ') +
                     (p.monitor ? 'mon' : '');
          drawEdge(gEdges, edgePath(L.cloudX, TIER.net + 30, x, TIER.vip - VIPH / 2 - 2), eCls, pk, d.id);
          drawEdge(gEdges, 'M ' + x + ',' + (TIER.vip + VIPH / 2) + ' L ' + x + ',' + TIER.dev, eCls, pk, d.id);
          drawEdge(gEdges, 'M ' + x + ',' + (TIER.dev + DEVH) + ' L ' + x + ',' + (TIER.pool - POOLH / 2), eCls, pk, d.id);
          if (p.backends.length) {
            drawEdge(gEdges, 'M ' + x + ',' + (TIER.pool + POOLH / 2) + ' L ' + x + ',' + TIER.back, eCls, pk, d.id);
          }
          drawVip(gNodes, x, p, pk, d.id);
          drawPool(gNodes, x, p, pk, d.id);
          drawBackends(gNodes, x, p, pk, d.id);
        });
      } else if (ld.pols.length) {
        var cx = ld.x + ld.w / 2;
        var agg = drawEdge(gEdges, edgePath(L.cloudX, TIER.net + 30, cx, TIER.dev - 2), 'agg flow', null, d.id);
        agg.setAttribute('data-dev', d.id);
      }
      drawDevice(gNodes, ld);
    });
  }

  // ---- search mode: a focused, uncluttered result view -----------------------
  // Shows ONLY: zone → device + department header → matching server policy →
  // its backend servers (matched rows highlighted). No cloud / VIP / pool tiers.
  function polSearchText(p) {
    return [p.name, vipLabel(p), p.wpp, p.pool.name, p.vserver, p.mode]
      .concat((p.backends || []).map(function (b) {
        return (b.ip || '') + ' ' + (b.ip || '') + ':' + (b.port || '');
      }))
      .join(' ').toLowerCase();
  }

  function searchMatches() {
    var q = query.trim().toLowerCase();
    var out = [];
    if (!q) return out;
    visibleDevices().forEach(function (d) {
      var devHit = (d.name || '').toLowerCase().indexOf(q) >= 0 ||
                   (d.host || '').toLowerCase().indexOf(q) >= 0;
      var hits = [];
      policiesOf(d).forEach(function (p) {
        var beHits = [];
        (p.backends || []).forEach(function (b, i) {
          var s = ((b.ip || '') + ':' + (b.port || '')).toLowerCase();
          if (s.indexOf(q) >= 0) beHits.push(i);
        });
        if (beHits.length || polSearchText(p).indexOf(q) >= 0) {
          hits.push({ p: p, beHits: beHits });
        }
      });
      if (devHit && !hits.length) {
        hits = policiesOf(d).map(function (p) { return { p: p, beHits: [] }; });
      }
      if (devHit || hits.length) out.push({ d: d, devHit: devHit, hits: hits });
    });
    return out;
  }

  var SPOLW = 164, SPOLH = 52;
  var S_HEAD = 96, S_POL = 168, S_BACK = 252;

  function drawSearchPolicy(parent, x, p, pk, dev, isMatch) {
    var off = p.status !== 'enable';
    var isTls = !!p.https_service || p.ssl;
    var c = off ? '#64748b' : (isTls ? '#22c55e' : '#4f8cff');
    var g = el('g', {
      'class': 'fm-node fm-vip' + (off ? ' off' : '') + (isMatch ? ' fm-match' : ''),
      'data-pk': pk, 'data-dev': dev,
      transform: 'translate(' + (x - SPOLW / 2) + ',' + (S_POL - SPOLH / 2) + ')'
    }, parent);
    el('rect', {
      width: SPOLW, height: SPOLH, rx: 12, fill: '#0f1a33',
      stroke: c, 'stroke-opacity': '0.8', 'stroke-width': '1.5', filter: 'url(#fmShadow)'
    }, g);
    txt(g, 12, 21, trunc(p.name, 21), 'fm-t-vip');
    var sub = vipLabel(p) + '  ' + (portLabel(p) || p.mode || '');
    txt(g, 12, 38, trunc(sub, 23), 'fm-t-port');
    if (isTls) lockIcon(g, SPOLW - 14, 13, '#22c55e');
    if (p.wpp) shieldIcon(g, SPOLW - 14, 38, '#22c55e');
    g.__tip = tipPolicy(p, 'Server policy');
    return g;
  }

  function renderSearch() {
    var ms = searchMatches();
    var gZones = el('g', null, world);
    var gEdges = el('g', null, world);
    var gNodes = el('g', null, world);
    var statsEl2 = document.getElementById('mapStats');

    if (!ms.length) {
      svg.setAttribute('data-w', 900);
      svg.setAttribute('data-h', 300);
      txt(gNodes, 450, 150, 'No match for "' + query.trim() + '"', 'fm-t-dev', 'middle');
      txt(gNodes, 450, 176, 'search covers device / host / policy / VIP / WAF profile / pool / backend ip:port', 'fm-t-dim', 'middle');
      if (statsEl2) statsEl2.textContent = '0 matches — clear the search to go back to the full map';
      return;
    }

    // group matches by zone
    var zones = [], byZone = {};
    ms.forEach(function (m) {
      var z = m.d.zone || '(no zone)';
      if (!byZone[z]) { byZone[z] = []; zones.push(z); }
      byZone[z].push(m);
    });

    var x = XSTART;
    var maxBottom = S_POL + SPOLH;
    var totPol = 0, totBe = 0;

    zones.forEach(function (z) {
      var zx0 = x;
      var zBottom = S_POL + SPOLH;
      byZone[z].forEach(function (m) {
        var d = m.d;
        var cols = Math.max(m.hits.length, 1);
        var w = cols * COLW;
        // device + department header (compact)
        var hg = el('g', {
          'class': 'fm-node fm-dev', 'data-dev': d.id,
          transform: 'translate(' + (x + w / 2) + ',' + S_HEAD + ')'
        }, gNodes);
        var label = d.name + (d.department ? '  ·  ' + d.department : '');
        var lw2 = Math.min(label.length * 7.4 + 30, w - 8);
        el('rect', {
          x: -lw2 / 2, y: -16, width: lw2, height: 32, rx: 16,
          fill: 'url(#fmDevBody)', stroke: 'rgba(148,163,184,0.3)', 'stroke-width': '1.2',
          filter: 'url(#fmShadow)'
        }, hg);
        txt(hg, 0, -1, trunc(d.name, 24), 'fm-t-sdev', 'middle');
        txt(hg, 0, 12, trunc(d.department || d.line || '', 26), 'fm-t-sdept', 'middle');
        hg.__tip = '<b>' + esc(d.name) + '</b><br>' + esc(d.host) +
          '<br><span style="color:#93a1bd">' + esc(d.zone || 'no zone') + ' · ' +
          esc(d.department || 'no dept') + '</span>';

        m.hits.forEach(function (h, i) {
          var cx2 = x + i * COLW + COLW / 2;
          var pk = d.id + '/' + h.p.name;
          var eCls = (h.p.https_service || h.p.ssl ? 'https ' : '') +
                     (h.p.status !== 'enable' ? 'off' : 'flow');
          drawEdge(gEdges, edgePath(x + w / 2, S_HEAD + 16, cx2, S_POL - SPOLH / 2 - 2), eCls, pk, d.id);
          drawSearchPolicy(gNodes, cx2, h.p, pk, d.id, true);
          if (h.p.backends.length) {
            drawEdge(gEdges, 'M ' + cx2 + ',' + (S_POL + SPOLH / 2) + ' L ' + cx2 + ',' + S_BACK, eCls, pk, d.id);
            drawBackends(gNodes, cx2, h.p, pk, d.id, S_BACK, h.beHits);
            var bh = S_BACK + 20 + h.p.backends.length * BEROW + 34;
            if (bh > zBottom) zBottom = bh;
            if (bh > maxBottom) maxBottom = bh;
            totBe += h.p.backends.length;
          }
          totPol++;
        });
        x += w + GAP;
      });
      var zx1 = x - GAP;
      // zone region (compact top)
      var c = paletteColor(z);
      var y0 = S_HEAD - 44;
      var zg = el('g', { 'class': 'fm-zone' }, gZones);
      el('rect', {
        x: zx0 - ZPAD, y: y0, width: (zx1 + ZPAD) - (zx0 - ZPAD), height: zBottom + 26 - y0,
        rx: 22, fill: c, 'fill-opacity': '0.05',
        stroke: c, 'stroke-opacity': '0.28', 'stroke-width': '1.4', 'stroke-dasharray': '7 5'
      }, zg);
      var lw = Math.max(z.length * 8 + 34, 74);
      el('rect', { x: zx0 - ZPAD + 16, y: y0 - 13, width: lw, height: 26, rx: 13, fill: c }, zg);
      txt(zg, zx0 - ZPAD + 16 + lw / 2, y0 + 4, 'ZONE · ' + z.toUpperCase(), 'fm-t-zone', 'middle');
      x += ZGAP;
    });

    svg.setAttribute('data-w', Math.max(x - ZGAP + XSTART, 900));
    svg.setAttribute('data-h', maxBottom + 80);
    if (statsEl2) {
      statsEl2.textContent = ms.length + ' device(s) · ' + totPol + ' matching server polic' +
        (totPol === 1 ? 'y' : 'ies') + ' · ' + totBe + ' backend server(s) — focused search view; clear the search to see the full map';
    }
  }

  function updateStats() {
    var devs = visibleDevices();
    var svcs = 0, bes = 0, cachedN = 0;
    devs.forEach(function (d) {
      var pols = policiesOf(d);
      svcs += pols.length;
      if (pols.length) cachedN++;
      pols.forEach(function (p) { bes += p.backends.length; });
    });
    var elS = document.getElementById('mapStats');
    if (elS) {
      elS.textContent = devs.length + ' device(s) · ' + svcs + ' published service(s) · ' +
        bes + ' backend server(s) · source: device cache (DB) · ' +
        'drag = pan · wheel = zoom · click a device = expand its topology';
    }
  }

  // ---- highlight / search -----------------------------------------------------
  function applyHighlights() {
    var q = query.trim().toLowerCase();
    svg.classList.toggle('searching', !!q);
    if (!q) {
      svg.querySelectorAll('.fm-match, .fm-dimdev').forEach(function (n) {
        n.classList.remove('fm-match', 'fm-dimdev');
      });
      return;
    }
    var matchDevs = {};
    model.devices.forEach(function (d) {
      var hit = (d.name || '').toLowerCase().indexOf(q) >= 0 ||
                (d.host || '').toLowerCase().indexOf(q) >= 0;
      var pkHits = [];
      d.policies.forEach(function (p) {
        var s = [p.name, vipLabel(p), p.wpp, p.pool.name]
          .concat(p.backends.map(function (b) { return b.ip; }))
          .join(' ').toLowerCase();
        if (s.indexOf(q) >= 0) pkHits.push(d.id + '/' + p.name);
      });
      if (hit || pkHits.length) matchDevs[d.id] = pkHits;
    });
    svg.querySelectorAll('[data-dev]').forEach(function (n) {
      var devId = n.getAttribute('data-dev');
      var pk = n.getAttribute('data-pk');
      var m = matchDevs[devId];
      var isMatch = m !== undefined && (!pk || m.indexOf(pk) >= 0 || m.length === 0);
      n.classList.toggle('fm-match', !!(isMatch && (pk || n.classList.contains('fm-dev'))));
      n.classList.toggle('fm-dimdev', m === undefined);
    });
  }

  function focusPk(pk, devId) {
    svg.classList.add('focus');
    svg.querySelectorAll('[data-dev]').forEach(function (n) {
      var hot = pk
        ? (n.getAttribute('data-pk') === pk ||
           (n.classList.contains('fm-dev') && n.getAttribute('data-dev') === String(devId)))
        : n.getAttribute('data-dev') === String(devId);
      n.classList.toggle('hot', hot);
    });
  }
  function clearFocus() {
    svg.classList.remove('focus');
    svg.querySelectorAll('.hot').forEach(function (n) { n.classList.remove('hot'); });
  }

  // ---- tooltip ------------------------------------------------------------------
  var tip = document.getElementById('fmTooltip');
  function showTip(html, evt) {
    if (!tip) return;
    tip.innerHTML = html;
    tip.style.display = 'block';
    moveTip(evt);
  }
  function moveTip(evt) {
    if (!tip || tip.style.display === 'none') return;
    var r = viewport.getBoundingClientRect();
    var x = evt.clientX - r.left + 16;
    var y = evt.clientY - r.top + 14;
    if (x + tip.offsetWidth > r.width - 8) x = evt.clientX - r.left - tip.offsetWidth - 12;
    if (y + tip.offsetHeight > r.height - 8) y = evt.clientY - r.top - tip.offsetHeight - 10;
    tip.style.left = x + 'px';
    tip.style.top = y + 'px';
  }
  function hideTip() { if (tip) tip.style.display = 'none'; }

  // ---- pan / zoom -----------------------------------------------------------------
  function applyTransform() {
    if (world) world.setAttribute('transform', 'translate(' + tx + ',' + ty + ') scale(' + scale + ')');
  }
  function fit() {
    if (viewMode === 'list') return;
    var w = parseFloat(svg.getAttribute('data-w')) || 1200;
    var h = parseFloat(svg.getAttribute('data-h')) || 800;
    var vw = viewport.clientWidth, vh = viewport.clientHeight;
    scale = Math.min(vw / w, vh / h, 1);
    if (scale < 0.18) scale = 0.18;
    tx = (vw - w * scale) / 2;
    ty = Math.max((vh - h * scale) / 2, 8);
    applyTransform();
  }
  function zoomAt(mx, my, factor) {
    var ns = Math.min(2.5, Math.max(0.15, scale * factor));
    tx = mx - (mx - tx) * (ns / scale);
    ty = my - (my - ty) * (ns / scale);
    scale = ns;
    applyTransform();
  }

  var dragging = false, sx = 0, sy = 0, stx = 0, sty = 0, moved = false;
  viewport.addEventListener('pointerdown', function (e) {
    if (e.target.closest('.fm-btn')) return;
    dragging = true; moved = false;
    sx = e.clientX; sy = e.clientY; stx = tx; sty = ty;
    viewport.setPointerCapture(e.pointerId);
    viewport.classList.add('grabbing');
  });
  viewport.addEventListener('pointermove', function (e) {
    if (!dragging) { moveTip(e); return; }
    var dx = e.clientX - sx, dy = e.clientY - sy;
    if (Math.abs(dx) + Math.abs(dy) > 3) moved = true;
    tx = stx + dx; ty = sty + dy;
    applyTransform();
  });
  viewport.addEventListener('pointerup', function (e) {
    dragging = false;
    viewport.classList.remove('grabbing');
  });
  viewport.addEventListener('wheel', function (e) {
    e.preventDefault();
    var r = viewport.getBoundingClientRect();
    zoomAt(e.clientX - r.left, e.clientY - r.top, e.deltaY > 0 ? 0.88 : 1.14);
  }, { passive: false });

  // ---- interactions (delegated) ------------------------------------------------------
  svg.addEventListener('click', function (e) {
    if (moved) return;                       // it was a drag
    var btn = e.target.closest('.fm-btn');
    if (btn) {
      var id = btn.getAttribute('data-id');
      if (btn.getAttribute('data-action') === 'info') openModal(id);
      else enterDevice(id);
      return;
    }
    // any service node (VIP pill / pool / backend stack / policy card in the
    // search view) opens the full policy-detail modal with config deep-links
    var svcNode = e.target.closest('.fm-node[data-pk]');
    if (svcNode && !svcNode.classList.contains('fm-dev')) {
      var spk = svcNode.getAttribute('data-pk');
      var si = spk.indexOf('/');
      if (si > 0) { openPolicyModal(spk.slice(0, si), spk.slice(si + 1)); return; }
    }
    var dev = e.target.closest('.fm-dev');
    if (dev) {
      var did = dev.getAttribute('data-dev');
      expanded[did] = !expanded[did];
      rememberExpanded();
      render();
    }
  });
  svg.addEventListener('pointerover', function (e) {
    var n = e.target.closest('[data-pk], .fm-dev, .fm-cloud');
    if (!n) return;
    var pk = n.getAttribute && n.getAttribute('data-pk');
    var devId = n.getAttribute && n.getAttribute('data-dev');
    if (pk || (n.classList && n.classList.contains('fm-dev'))) focusPk(pk, devId);
    var tg = n.closest('.fm-node, .fm-cloud');
    if (tg && tg.__tip) showTip(tg.__tip, e);
  });
  svg.addEventListener('pointerout', function (e) {
    var n = e.target.closest('[data-pk], .fm-dev, .fm-cloud');
    if (!n) return;
    clearFocus();
    hideTip();
  });

  function enterDevice(id) {
    var f = document.createElement('form');
    f.method = 'post';
    f.action = (CFG.selectBase || '/architecture/select/') + id;
    var i = document.createElement('input');
    i.type = 'hidden'; i.name = 'csrf_token'; i.value = CSRF;
    f.appendChild(i);
    document.body.appendChild(f);
    f.submit();
  }

  // ---- inventory card -------------------------------------------------------------
  // Everything rendered here is DB-only (device cache + operator documentation +
  // cached MACs) so the card opens instantly even against a powered-off box.
  // The single live action is the explicit "Fetch MAC addresses" button.
  var DM_HW = { hardware: 'Hardware appliance', vm: 'Virtual machine', unknown: 'Unknown' };

  function dmEl(tag, cls, parent, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    if (parent) parent.appendChild(n);
    return n;
  }

  function dmDash(td, cls) {
    dmEl('span', 'dm-dash', td, '—');
    if (cls) td.className = cls;
  }

  function dmSpecs(d) {
    var box = document.getElementById('dmSpecs');
    box.innerHTML = '';
    [['Platform', DM_HW[d.hw_type] || 'Unknown'],
     ['Model', d.model],
     ['Firmware', d.firmware],
     ['Management', (d.host || '') + (d.port ? ':' + d.port : '')],
     ['VDOM', d.vdom],
     ['Zone', d.zone],
     ['Line', d.line],
     ['Department', d.department]].forEach(function (kv) {
      var c = dmEl('div', 'dm-spec', box);
      dmEl('div', 'k', c, kv[0]);
      dmEl('div', 'v', c, (kv[1] === null || kv[1] === undefined || kv[1] === '') ? '—' : kv[1]);
    });
  }

  function dmStatePill(state) {
    var s = (state || '').toLowerCase().trim();
    if (s === 'up' || s === 'online' || s === 'enable') return ['dm-pill dm-pill-up', s || 'up'];
    if (s === 'down' || s === 'offline' || s === 'disable') return ['dm-pill dm-pill-down', s];
    return ['dm-pill dm-pill-mut', s || 'unknown'];
  }

  function dmRenderIfaces(ifaces) {
    var tb = document.getElementById('dmIfaces');
    var empty = document.getElementById('dmNoIfaces');
    var wrap = document.querySelector('.dm-iftable-wrap');
    tb.innerHTML = '';
    document.getElementById('dmIfCount').textContent =
      ifaces.length ? ifaces.length + (ifaces.length === 1 ? ' port' : ' ports') : '';
    if (!ifaces.length) {
      empty.classList.remove('d-none');
      if (wrap) wrap.classList.add('d-none');
      return;
    }
    empty.classList.add('d-none');
    if (wrap) wrap.classList.remove('d-none');

    ifaces.forEach(function (i2) {
      var tr = dmEl('tr', i2.ip_address ? '' : 'dm-idle', tb);

      // port + provenance icons + secondary chips (type / mtu / vlan / speed)
      var tdP = dmEl('td', '', tr);
      var head = dmEl('div', 'dm-port', tdP);
      dmEl('span', '', head, i2.name);
      if (i2.cached) { var ic = dmEl('i', 'bi bi-database', head); ic.title = 'From the device cache'; }
      if (i2.documented) { var id2 = dmEl('i', 'bi bi-pencil-square', head); id2.title = 'Operator-documented'; }
      var meta = dmEl('div', 'dm-meta', tdP);
      [i2.if_type, i2.mode, i2.speed && i2.speed !== 'auto' ? i2.speed : '',
       i2.mtu ? 'MTU ' + i2.mtu : '',
       (i2.vlan && i2.vlan !== '0') ? 'VLAN ' + i2.vlan : '']
        .filter(Boolean).forEach(function (t) { dmEl('span', '', meta, t); });
      if (i2.description) dmEl('span', '', meta, i2.description);

      // state
      var tdS = dmEl('td', '', tr);
      var pill = dmStatePill(i2.status);
      dmEl('span', pill[0], tdS, pill[1]);

      // address (+ allowed management access underneath)
      var tdA = dmEl('td', '', tr);
      if (i2.ip_address) {
        dmEl('div', 'dm-addr', tdA, i2.ip_address);
        if (i2.allowaccess) dmEl('div', 'dm-meta', tdA).appendChild(
          dmEl('span', '', null, i2.allowaccess.trim()));
      } else dmDash(tdA);

      // MAC (click to copy)
      var tdM = dmEl('td', '', tr);
      if (i2.mac) {
        var m = dmEl('span', 'dm-mac', tdM, i2.mac);
        m.title = 'Click to copy';
        m.addEventListener('click', function () {
          if (navigator.clipboard) navigator.clipboard.writeText(i2.mac);
          var was = m.textContent; m.textContent = 'copied';
          setTimeout(function () { m.textContent = was; }, 900);
        });
      } else dmDash(tdM);

      var tdC = dmEl('td', '', tr);
      if (i2.connected_to) dmEl('span', '', tdC, i2.connected_to); else dmDash(tdC);

      var tdN = dmEl('td', '', tr);
      if (i2.notes) dmEl('span', '', tdN, i2.notes); else dmDash(tdN);
    });
  }

  function dmFreshness(d) {
    var el = document.getElementById('dmIfFresh');
    var bits = [];
    var g = (d.iface_cache || {}).generated_at;
    if (g) bits.push('cache ' + String(g).replace('T', ' ').slice(0, 16));
    if (d.mac_fetched_at) bits.push('MACs ' + String(d.mac_fetched_at).replace('T', ' ').slice(0, 16));
    el.textContent = bits.join(' · ');
  }

  function openModal(id) {
    var modalEl = document.getElementById('deviceModal');
    if (!modalEl || !window.bootstrap) return;
    var modal = bootstrap.Modal.getOrCreateInstance(modalEl);
    var $ = function (i) { return document.getElementById(i); };
    $('dmLoading').classList.remove('d-none');
    $('dmContent').classList.add('d-none');
    $('dmError').classList.add('d-none');
    $('dmMacErr').classList.add('d-none');
    $('dmName').textContent = 'Device';
    var ef = $('dmEnterForm');
    if (ef) ef.action = (CFG.selectBase || '/architecture/select/') + id;
    modal.show();
    fetch((CFG.deviceBase || '/architecture/device/') + id, { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (d) {
        $('dmName').textContent = d.name || 'Device';
        var sp = dmStatePill(d.status);
        var pill = $('dmStatusPill');
        pill.className = sp[0]; pill.textContent = sp[1];
        $('dmKindChip').textContent = d.kind || '';
        $('dmHostChip').textContent = (d.host || '') + (d.port ? ':' + d.port : '');
        var fw = $('dmFwChip');
        if (d.firmware) { fw.textContent = d.firmware; fw.classList.remove('d-none'); }
        else fw.classList.add('d-none');

        dmSpecs(d);
        dmFreshness(d);
        dmRenderIfaces(d.interfaces || []);

        var dsWrap = $('dmDatasheetWrap');
        if (d.datasheet_url) { $('dmDatasheet').href = d.datasheet_url; dsWrap.classList.remove('d-none'); }
        else dsWrap.classList.add('d-none');
        $('dmDetailLink').href = d.detail_url || '#';

        var btn = $('dmMacBtn');
        btn.disabled = false;
        $('dmMacBtnTxt').textContent = d.mac_fetched_at ? 'Refresh MAC addresses' : 'Fetch MAC addresses';
        btn.onclick = function () { dmFetchMacs(d); };

        $('dmLoading').classList.add('d-none');
        $('dmContent').classList.remove('d-none');
      })
      .catch(function (err) {
        $('dmLoading').classList.add('d-none');
        $('dmError').textContent = 'Could not load device details: ' + err.message;
        $('dmError').classList.remove('d-none');
      });
  }

  function dmFetchMacs(d) {
    var btn = document.getElementById('dmMacBtn');
    var txt = document.getElementById('dmMacBtnTxt');
    var err = document.getElementById('dmMacErr');
    err.classList.add('d-none');
    btn.disabled = true;
    txt.textContent = 'Probing device…';
    fetch(d.macs_url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'X-CSRFToken': CSRF, 'Content-Type': 'application/json' }
    })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) {
        btn.disabled = false;
        if (!res.ok || !res.j.ok) {
          txt.textContent = 'Retry MAC addresses';
          err.textContent = 'MAC probe failed: ' + (res.j.error || 'unknown error');
          err.classList.remove('d-none');
          return;
        }
        txt.textContent = 'Refresh MAC addresses';
        dmRenderIfaces(res.j.interfaces || []);
      })
      .catch(function (e) {
        btn.disabled = false;
        txt.textContent = 'Retry MAC addresses';
        err.textContent = 'MAC probe failed: ' + e.message;
        err.classList.remove('d-none');
      });
  }

  // ---- policy detail modal (all cached data + config deep-links) -----------------
  var PM_SKIP = /^(q_|_|can_|sz_)/;

  function pmEl(tag, cls, parent, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    if (parent) parent.appendChild(n);
    return n;
  }

  function pmCfgLink(parent, url, label) {
    if (!url) return null;
    var a = pmEl('a', 'pm-cfg-link', parent, '⚙ ' + (label || 'Configure'));
    a.href = url;
    a.target = '_blank';
    a.rel = 'noopener';
    return a;
  }

  function pmSection(parent, title, cfgUrl, cfgLabel) {
    var s = pmEl('div', 'pm-section', parent);
    var h = pmEl('div', 'pm-sec-head', s);
    pmEl('div', 'pm-sec-title', h, title);
    if (cfgUrl) pmCfgLink(h, cfgUrl, cfgLabel || 'Configure');
    return s;
  }

  function pmValStr(v) {
    if (v === null || v === undefined) return '';
    if (typeof v === 'object') { try { return JSON.stringify(v); } catch (e) { return String(v); } }
    return String(v);
  }

  function pmKv(parent, obj) {
    var grid = pmEl('div', 'pm-kv', parent);
    var hidden = 0, shown = 0;
    Object.keys(obj || {}).forEach(function (k) {
      if (PM_SKIP.test(k)) return;
      var v = pmValStr(obj[k]);
      if (v === '') { hidden++; return; }
      var row = pmEl('div', 'row2', grid);
      pmEl('span', 'k', row, k);
      pmEl('span', 'v', row, v);
      shown++;
    });
    if (!shown) pmEl('div', 'pm-empty-note', parent, 'No data cached for this object.');
    else if (hidden) pmEl('div', 'pm-empty-note', parent, hidden + ' empty field' + (hidden > 1 ? 's' : '') + ' hidden.');
    return grid;
  }

  function pmStatusChip(parent, on, labelOn, labelOff) {
    pmEl('span', 'pm-chip ' + (on ? 'on' : 'off'), parent, on ? (labelOn || 'enabled') : (labelOff || 'disabled'));
  }

  function renderPolicyModal(res) {
    var C = document.getElementById('pmContent');
    C.innerHTML = '';
    var data = res.data || {};
    var pol = data.policy || {};
    var links = res.links || {};

    document.getElementById('pmName').textContent = res.name || '';
    document.getElementById('pmAppl').textContent =
      (res.appliance ? res.appliance.name + ' (' + res.appliance.host + ')' : '');
    document.getElementById('pmFresh').textContent = res.freshness || '';
    var pl = document.getElementById('pmPolicyLink');
    if (links.policy) { pl.href = links.policy; pl.classList.remove('d-none'); }

    // --- Server Policy (all fields) ---
    var s1 = pmSection(C, 'Server policy — ' + (res.name || ''), links.policy, 'Configure policy');
    var head1 = s1.querySelector('.pm-sec-title');
    pmStatusChip(head1, pol.status === 'enable');
    if (pol['monitor-mode'] === 'enable') pmEl('span', 'pm-chip off', head1, 'monitor mode');
    pmKv(s1, pol);

    // --- Virtual server + VIPs ---
    if (data.vserver || (data.vips || []).length) {
      var s2 = pmSection(C, 'Virtual server' + (pol.vserver ? ' — ' + pol.vserver : ''),
                         links.vserver, 'Configure virtual server');
      if (data.vserver) pmKv(s2, data.vserver);
      var vips = data.vips || [];
      if (vips.length) {
        var vt = pmEl('table', 'table table-sm pm-table mt-2', s2);
        var vh = pmEl('tr', null, pmEl('thead', null, vt));
        ['VIP', 'Effective IP', 'Source', ''].forEach(function (h) { pmEl('th', null, vh, h); });
        var vb = pmEl('tbody', null, vt);
        vips.forEach(function (v) {
          var tr = pmEl('tr', null, vb);
          var nm = v.vip || v.name || '';
          pmEl('td', null, tr, nm || '—');
          pmEl('td', null, tr, v.effective_ip || v.ip || '—');
          pmEl('td', null, tr, v.ip_source || v.source || '');
          var tdl = pmEl('td', null, tr);
          if (nm && links.vips && links.vips[nm]) pmCfgLink(tdl, links.vips[nm], 'Configure VIP');
        });
      }
    }

    // --- Server pool ---
    var pool = data.pool || {};
    if (Object.keys(pool).length) {
      var s3 = pmSection(C, 'Server pool' + (pool.name ? ' — ' + pool.name : ''),
                         links.pool, 'Configure pool');
      pmKv(s3, pool);
      if (pool.health && links.health) {
        var hd = pmEl('div', 'pm-empty-note', s3, 'Health check “' + pool.health + '” — ');
        pmCfgLink(hd, links.health, 'configure health check');
      }
    }

    // --- Backend servers ---
    var backends = data.backends || [];
    if (backends.length) {
      var s4 = pmSection(C, 'Back-end servers (' + backends.length + ')',
                         links.pool, 'Edit members in the pool');
      // dynamic columns: ip/port/status first, then the other non-empty keys
      var cols = ['ip', 'port', 'status'];
      var extra = {};
      backends.forEach(function (b) {
        Object.keys(b || {}).forEach(function (k) {
          if (PM_SKIP.test(k) || cols.indexOf(k) >= 0) return;
          if (pmValStr(b[k]) !== '') extra[k] = 1;
        });
      });
      cols = cols.concat(Object.keys(extra).slice(0, 6));
      var bt = pmEl('table', 'table table-sm pm-table', s4);
      var bh = pmEl('tr', null, pmEl('thead', null, bt));
      cols.forEach(function (c) { pmEl('th', null, bh, c); });
      pmEl('th', null, bh, '');
      var bb = pmEl('tbody', null, bt);
      backends.forEach(function (b) {
        var tr = pmEl('tr', null, bb);
        cols.forEach(function (c) {
          var td = pmEl('td', null, tr, pmValStr(b[c]) || '—');
          if (c === 'status') {
            td.textContent = '';
            pmStatusChip(td, b.status === 'enable');
          }
        });
        var tdl = pmEl('td', null, tr);
        if (links.pool) pmCfgLink(tdl, links.pool, 'Edit');
      });
    }

    // --- Services (custom services are editable objects) ---
    if (links.http_service || links.https_service) {
      var s5 = pmSection(C, 'Custom services', null, null);
      if (links.http_service) {
        var d1 = pmEl('div', 'pm-empty-note', s5, 'HTTP service “' + (pol.service || '') + '” — ');
        pmCfgLink(d1, links.http_service, 'configure service');
      }
      if (links.https_service) {
        var d2 = pmEl('div', 'pm-empty-note', s5, 'HTTPS service “' + (pol['https-service'] || '') + '” — ');
        pmCfgLink(d2, links.https_service, 'configure service');
      }
    }

    // --- Web Protection Profile ---
    var wpp = data.wpp || {};
    var wppName = pol['web-protection-profile'] || wpp.name || '';
    if (wppName || Object.keys(wpp).length) {
      var s6 = pmSection(C, 'Web Protection Profile' + (wppName ? ' — ' + wppName : ''),
                         links.wpp, 'Configure WAF profile');
      if (Object.keys(wpp).length) pmKv(s6, wpp);
      else pmEl('div', 'pm-empty-note', s6,
                'Profile contents not in the deep cache — open the configuration to see it live.');
    }

    // --- Content routing ---
    var crs = res.content_routing || [];
    if (crs.length) {
      var s7 = pmSection(C, 'HTTP content routing (' + crs.length + ')', null, null);
      var ct = pmEl('table', 'table table-sm pm-table', s7);
      var ch = pmEl('tr', null, pmEl('thead', null, ct));
      ['#', 'Content routing policy', 'Profile inherit', 'WAF profile', ''].forEach(function (h) {
        pmEl('th', null, ch, h);
      });
      var cb = pmEl('tbody', null, ct);
      crs.forEach(function (e2, i) {
        var tr = pmEl('tr', null, cb);
        var nm = e2['content-routing-policy-name'] || '';
        pmEl('td', null, tr, e2.id !== undefined ? e2.id : i + 1);
        pmEl('td', null, tr, nm || '—');
        pmEl('td', null, tr, e2['profile-inherit'] || '');
        pmEl('td', null, tr, e2['web-protection-profile'] || '');
        var tdl = pmEl('td', null, tr);
        var lk = (res.links.content_routing || {})[nm];
        if (lk) pmCfgLink(tdl, lk, 'Configure');
      });
    }
  }

  function openPolicyModal(devId, polName) {
    var modalEl = document.getElementById('policyModal');
    if (!modalEl || !window.bootstrap) return;
    var modal = bootstrap.Modal.getOrCreateInstance(modalEl);
    var $ = function (i) { return document.getElementById(i); };
    $('pmLoading').classList.remove('d-none');
    $('pmContent').classList.add('d-none');
    $('pmError').classList.add('d-none');
    $('pmName').textContent = polName;
    $('pmAppl').textContent = '';
    $('pmFresh').textContent = '';
    $('pmPolicyLink').classList.add('d-none');
    hideTip();
    modal.show();
    fetch((CFG.policyBase || '/architecture/policy/') + devId + '/' + encodeURIComponent(polName),
          { credentials: 'same-origin' })
      .then(function (r) {
        return r.json().catch(function () { throw new Error('HTTP ' + r.status); })
          .then(function (j) {
            if (!r.ok || j.ok === false) throw new Error(j.error || ('HTTP ' + r.status));
            return j;
          });
      })
      .then(function (res) {
        renderPolicyModal(res);
        $('pmLoading').classList.add('d-none');
        $('pmContent').classList.remove('d-none');
      })
      .catch(function (err) {
        $('pmLoading').classList.add('d-none');
        $('pmError').textContent = 'Could not load policy details: ' + err.message;
        $('pmError').classList.remove('d-none');
      });
  }

  // ---- filter pills -------------------------------------------------------------------------
  // All filters (device facets + service facets + the search text) are saved
  // per-user on the server (/architecture/filters) and restored on next visit.
  var saveTimer = null;
  function persistFilters() {
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(function () {
      // The server stores one string per facet; a multi-selection is encoded
      // as a JSON array string ('["A","B"]'). A legacy single-value string
      // restores as a 1-element selection (see _decodeFacet).
      var enc = function (k) { return filters[k].length ? JSON.stringify(filters[k]) : ''; };
      fetch(CFG.filtersUrl || '/architecture/filters', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF },
        body: JSON.stringify({
          zone: enc('zone'), line: enc('line'), department: enc('dept'),
          kind: enc('kind'), firmware: enc('firmware'), data: enc('data'),
          proto: enc('proto'), waf: enc('waf'), status: enc('status'),
          text: query, view: viewMode
        })
      }).catch(function () {});
    }, 600);
  }

  function anyFilterActive() {
    for (var k in filters) if (filters[k].length) return true;
    return false;
  }
  function updateClearBtn() {
    var btn = document.getElementById('fmClearFilters');
    if (!btn) return;
    btn.classList.toggle('show', anyFilterActive() || !!query.trim());
  }
  function closeAllPanels(except) {
    document.querySelectorAll('.fm-msel-panel').forEach(function (p) {
      if (p !== except) p.remove();
    });
  }

  // One dropdown button per facet; its panel is a checkbox list (multi-select).
  function buildFacetSelect(f, names, colorOf) {
    var wrap = document.createElement('div');
    wrap.className = 'fm-msel';
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'fm-msel-btn';
    wrap.appendChild(btn);

    function syncBtn() {
      var sel = filters[f.key];
      btn.innerHTML = '';
      btn.appendChild(document.createTextNode(f.label));
      if (sel.length) {
        var cnt = document.createElement('span');
        cnt.className = 'fm-msel-count';
        cnt.textContent = sel.length;
        btn.appendChild(cnt);
      }
      var caret = document.createElement('i');
      caret.className = 'bi bi-chevron-down';
      caret.style.fontSize = '10px';
      btn.appendChild(caret);
      btn.classList.toggle('active', !!sel.length);
      btn.title = sel.length ? f.label + ': ' + sel.join(', ') : f.label + ' — all';
    }

    function applyChange() {
      syncBtn();
      updateClearBtn();
      render();
      fit();
      persistFilters();
    }

    function openPanel() {
      closeAllPanels();
      var panel = document.createElement('div');
      panel.className = 'fm-msel-panel';
      names.forEach(function (name) {
        var item = document.createElement('label');
        item.className = 'fm-msel-item';
        var cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.checked = filters[f.key].indexOf(name) !== -1;
        item.appendChild(cb);
        var dot = document.createElement('span');
        dot.className = 'fm-msel-dot';
        dot.style.background = colorOf(name);
        item.appendChild(dot);
        item.appendChild(document.createTextNode(name));
        cb.addEventListener('change', function () {
          var idx = filters[f.key].indexOf(name);
          if (cb.checked && idx === -1) filters[f.key].push(name);
          if (!cb.checked && idx !== -1) filters[f.key].splice(idx, 1);
          applyChange();
        });
        panel.appendChild(item);
      });
      var actions = document.createElement('div');
      actions.className = 'fm-msel-actions';
      var allA = document.createElement('a');
      allA.textContent = 'Select all';
      allA.addEventListener('click', function () {
        filters[f.key] = names.slice();
        panel.querySelectorAll('input').forEach(function (i) { i.checked = true; });
        applyChange();
      });
      var noneA = document.createElement('a');
      noneA.textContent = 'Clear';
      noneA.addEventListener('click', function () {
        filters[f.key] = [];
        panel.querySelectorAll('input').forEach(function (i) { i.checked = false; });
        applyChange();
      });
      actions.appendChild(allA);
      actions.appendChild(noneA);
      panel.appendChild(actions);
      wrap.appendChild(panel);
    }

    btn.addEventListener('click', function (e) {
      e.stopPropagation();
      var open = wrap.querySelector('.fm-msel-panel');
      if (open) { open.remove(); } else { openPanel(); }
    });
    wrap.addEventListener('click', function (e) { e.stopPropagation(); });

    syncBtn();
    return wrap;
  }

  var FIXED_COLORS = {
    'cached': '#22c55e', 'no data': '#64748b',
    'HTTPS': '#22c55e', 'HTTP': '#4f8cff',
    'protected': '#22c55e', 'no WAF': '#ef4444',
    'enabled': '#22c55e', 'disabled': '#64748b'
  };

  function buildFilterPills() {
    var container = document.getElementById('mapFilters');
    if (!container) return;
    container.innerHTML = '';
    var lbl = document.createElement('span');
    lbl.textContent = 'Filters';
    lbl.className = 'fm-filter-label';
    container.appendChild(lbl);

    // device facets discovered from the data
    var facets = [
      { label: 'Zone', key: 'zone', vals: {} },
      { label: 'Line', key: 'line', vals: {} },
      { label: 'Dept', key: 'dept', vals: {} },
      { label: 'Kind', key: 'kind', vals: {} },
      { label: 'Firmware', key: 'firmware', vals: {} }
    ];
    model.devices.forEach(function (d) {
      facets[0].vals[d.zone || '(no zone)'] = 1;
      facets[1].vals[d.line || '(no line)'] = 1;
      facets[2].vals[d.department || '(no department)'] = 1;
      facets[3].vals[(d.kind || '?').toUpperCase()] = 1;
      if (d.firmware) facets[4].vals[d.firmware] = 1;
    });
    // fixed-value facets (device data state + service properties)
    facets.push({ label: 'Data', key: 'data', vals: { 'cached': 1, 'no data': 1 }, fixed: true });
    facets.push({ label: 'Proto', key: 'proto', vals: { 'HTTPS': 1, 'HTTP': 1 }, fixed: true });
    facets.push({ label: 'WAF', key: 'waf', vals: { 'protected': 1, 'no WAF': 1 }, fixed: true });
    facets.push({ label: 'Policy', key: 'status', vals: { 'enabled': 1, 'disabled': 1 }, fixed: true });

    facets.forEach(function (f) {
      var names = Object.keys(f.vals);
      if (!f.fixed) names.sort();
      // hide single-value discovered facets (nothing to filter) except zone
      if (!f.fixed && names.length < 2 && f.key !== 'zone') return;
      var colorOf = function (name) {
        return f.fixed ? (FIXED_COLORS[name] || '#4f8cff') : paletteColor(name);
      };
      container.appendChild(buildFacetSelect(f, names, colorOf));
    });

    // clear-all button (visible only while something is active)
    var clr = document.createElement('button');
    clr.type = 'button';
    clr.id = 'fmClearFilters';
    clr.className = 'fm-filter-clearbtn';
    clr.innerHTML = '<i class="bi bi-x-lg"></i> Clear filters';
    clr.addEventListener('click', function () {
      for (var k in filters) filters[k] = [];
      query = '';
      var ms2 = document.getElementById('mapSearch');
      if (ms2) ms2.value = '';
      buildFilterPills();
      render();
      fit();
      persistFilters();
    });
    container.appendChild(clr);
    updateClearBtn();

    // close any open panel when clicking elsewhere (bound once)
    if (!window.__fmMselCloseBound) {
      window.__fmMselCloseBound = true;
      document.addEventListener('click', function () { closeAllPanels(); });
    }
  }

  // ---- list view -----------------------------------------------------------------------------
  // A grouped, scannable alternative to the network map: devices arranged by
  // Zone -> Line -> Department. Respects every active filter + the search box.
  function applyViewMode() {
    var isList = viewMode === 'list';
    if (viewport) viewport.style.display = isList ? 'none' : '';
    if (listEl) listEl.classList.toggle('show', isList);
    var mapTools = document.querySelector('.fm-toolbtns');
    if (mapTools) mapTools.style.display = isList ? 'none' : '';
    var mb = document.getElementById('fmViewMap');
    var lb = document.getElementById('fmViewList');
    if (mb) mb.classList.toggle('active', !isList);
    if (lb) lb.classList.toggle('active', isList);
  }

  function listTextPasses(d) {
    var q = query.trim().toLowerCase();
    if (!q) return true;
    var hay = [d.name, d.host, d.zone, d.line, d.department, d.firmware, d.kind]
      .join(' ').toLowerCase();
    if (hay.indexOf(q) !== -1) return true;
    return policiesOf(d).some(function (p) { return polSearchText(p).indexOf(q) !== -1; });
  }

  function listCell(row, cls) {
    var td = document.createElement('td');
    if (cls) td.className = cls;
    row.appendChild(td);
    return td;
  }

  function listDeviceRow(d) {
    var tr = document.createElement('tr');
    tr.className = 'fm-list-row';
    tr.addEventListener('click', function () { openModal(d.id); });

    var tdName = listCell(tr);
    var nm = document.createElement('div');
    nm.className = 'fm-list-name';
    nm.textContent = d.name || '(unnamed)';
    var hs = document.createElement('div');
    hs.className = 'fm-list-host';
    hs.textContent = (d.host || '') + (d.port ? ':' + d.port : '');
    tdName.appendChild(nm); tdName.appendChild(hs);

    var tdKind = listCell(tr);
    var kb = document.createElement('span');
    var kind = (d.kind || 'fortiweb').toLowerCase();
    kb.className = 'fm-list-badge k-' + kind;
    kb.textContent = kind.toUpperCase();
    tdKind.appendChild(kb);

    listCell(tr).textContent = d.firmware || '—';

    var tdPol = listCell(tr);
    var pols = policiesOf(d);
    var wc = pols.filter(function (p) { return p.wpp; }).length;
    var ps = document.createElement('span');
    ps.textContent = pols.length + (pols.length === 1 ? ' policy' : ' policies');
    tdPol.appendChild(ps);
    if (wc) {
      var waf = document.createElement('span');
      waf.style.marginLeft = '8px';
      waf.style.color = '#22c55e';
      waf.style.fontWeight = '700';
      waf.textContent = '🛡 ' + wc;
      tdPol.appendChild(waf);
    }

    var tdFresh = listCell(tr, 'fm-list-host');
    tdFresh.textContent = d.freshness || (d.cached ? '' : 'no local data');

    var tdStat = listCell(tr);
    var dot = document.createElement('span');
    dot.className = 'fm-list-dotstat';
    dot.style.background = d.cached ? '#22c55e' : '#64748b';
    dot.title = d.cached ? 'Topology cached' : 'No local data';
    tdStat.appendChild(dot);

    return tr;
  }

  function renderList() {
    if (!listEl) return;
    listEl.innerHTML = '';
    var devs = visibleDevices().filter(listTextPasses).slice().sort(function (a, b) {
      var ka = [(a.zone || '~'), (a.line || '~'), (a.department || '~'), a.name].join(' ');
      var kb = [(b.zone || '~'), (b.line || '~'), (b.department || '~'), b.name].join(' ');
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    });
    if (!devs.length) {
      var empty = document.createElement('div');
      empty.className = 'fm-list-empty';
      empty.textContent = query.trim() || anyFilterActive()
        ? 'No devices match the current filters.'
        : 'No appliances to show.';
      listEl.appendChild(empty);
      updateStats();
      return;
    }

    var zones = [], tree = {};
    devs.forEach(function (d) {
      var z = d.zone || '(no zone)', l = d.line || '(no line)', dp = d.department || '(no department)';
      if (!tree[z]) { tree[z] = { lines: {}, order: [], count: 0 }; zones.push(z); }
      tree[z].count++;
      if (!tree[z].lines[l]) { tree[z].lines[l] = { depts: {}, order: [] }; tree[z].order.push(l); }
      if (!tree[z].lines[l].depts[dp]) { tree[z].lines[l].depts[dp] = []; tree[z].lines[l].order.push(dp); }
      tree[z].lines[l].depts[dp].push(d);
    });

    zones.forEach(function (z) {
      var zc = tree[z];
      var zwrap = document.createElement('div');
      zwrap.className = 'fm-list-zone';
      var zh = document.createElement('div');
      zh.className = 'fm-list-zone-head';
      zh.style.borderLeftColor = paletteColor(z);
      var zt = document.createElement('span');
      zt.textContent = z;
      zh.appendChild(zt);
      var zcnt = document.createElement('span');
      zcnt.className = 'fm-zcount';
      zcnt.textContent = zc.count + (zc.count === 1 ? ' device' : ' devices');
      zh.appendChild(zcnt);
      zwrap.appendChild(zh);

      zc.order.forEach(function (l) {
        var lwrap = document.createElement('div');
        lwrap.className = 'fm-list-line';
        var lh = document.createElement('div');
        lh.className = 'fm-list-line-head';
        var ldot = document.createElement('span');
        ldot.className = 'fm-dot';
        ldot.style.background = paletteColor(l);
        lh.appendChild(ldot);
        lh.appendChild(document.createTextNode(l));
        lwrap.appendChild(lh);

        tree[z].lines[l].order.forEach(function (dp) {
          var dwrap = document.createElement('div');
          dwrap.className = 'fm-list-dept';
          var dh = document.createElement('div');
          dh.className = 'fm-list-dept-head';
          dh.textContent = dp;
          dwrap.appendChild(dh);
          var table = document.createElement('table');
          table.className = 'fm-list-table';
          var tb = document.createElement('tbody');
          tree[z].lines[l].depts[dp].forEach(function (d) { tb.appendChild(listDeviceRow(d)); });
          table.appendChild(tb);
          dwrap.appendChild(table);
          lwrap.appendChild(dwrap);
        });
        zwrap.appendChild(lwrap);
      });
      listEl.appendChild(zwrap);
    });
    updateStats();
  }

  // ---- toolbar -------------------------------------------------------------------------------
  function bindToolbar() {
    var b;
    if ((b = document.getElementById('fmZoomIn'))) b.addEventListener('click', function () {
      zoomAt(viewport.clientWidth / 2, viewport.clientHeight / 2, 1.25);
    });
    if ((b = document.getElementById('fmZoomOut'))) b.addEventListener('click', function () {
      zoomAt(viewport.clientWidth / 2, viewport.clientHeight / 2, 0.8);
    });
    if ((b = document.getElementById('fmFit'))) b.addEventListener('click', fit);
    if ((b = document.getElementById('fmExpand'))) b.addEventListener('click', function () {
      model.devices.forEach(function (d) { expanded[d.id] = true; });
      rememberExpanded(); render(); fit();
    });
    if ((b = document.getElementById('fmCollapse'))) b.addEventListener('click', function () {
      expanded = {};
      rememberExpanded(); render(); fit();
    });
    if ((b = document.getElementById('fmViewMap'))) b.addEventListener('click', function () {
      if (viewMode === 'map') return;
      viewMode = 'map'; applyViewMode(); render(); fit(); persistFilters();
    });
    if ((b = document.getElementById('fmViewList'))) b.addEventListener('click', function () {
      if (viewMode === 'list') return;
      viewMode = 'list'; applyViewMode(); render(); persistFilters();
    });
    var ms = document.getElementById('mapSearch');
    if (ms) {
      var lastMode = false;
      ms.addEventListener('input', function () {
        query = ms.value || '';
        var nowMode = !!query.trim();
        render();
        // re-fit when entering/leaving search mode or while results reshape
        if (nowMode || lastMode !== nowMode) fit();
        lastMode = nowMode;
        updateClearBtn();            // keep the "clear filters" button in sync
        persistFilters();
      });
    }
  }

  // ---- boot ------------------------------------------------------------------------------------
  var saved = CFG.savedFilters || {};
  // A saved facet is either a JSON array string (multi-select, new format) or
  // a bare legacy single value — both restore into the array-based filters.
  function _decodeFacet(v) {
    if (!v) return [];
    if (typeof v === 'string' && v.charAt(0) === '[') {
      try {
        var a = JSON.parse(v);
        return Array.isArray(a) ? a.filter(Boolean).map(String) : [];
      } catch (e) { return []; }
    }
    return [String(v)];
  }
  filters.zone = _decodeFacet(saved.zone);
  filters.line = _decodeFacet(saved.line);
  filters.dept = _decodeFacet(saved.dept || saved.department);
  filters.kind = _decodeFacet(saved.kind);
  filters.firmware = _decodeFacet(saved.firmware);
  filters.data = _decodeFacet(saved.data);
  filters.proto = _decodeFacet(saved.proto);
  filters.waf = _decodeFacet(saved.waf);
  filters.status = _decodeFacet(saved.status);

  var statsEl = document.getElementById('mapStats');
  if (statsEl) statsEl.textContent = 'Loading topology from the device cache…';

  fetch(CFG.dataUrl || '/architecture/map-data', { credentials: 'same-origin' })
    .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
    .then(function (data) {
      model.devices = data.devices || [];
      var ms = document.getElementById('mapSearch');
      if (saved.text && ms) { ms.value = saved.text; query = saved.text; }
      buildFilterPills();
      bindToolbar();
      applyViewMode();
      render();
      fit();
    })
    .catch(function (err) {
      if (statsEl) statsEl.textContent = 'Could not load topology: ' + err.message;
    });
})();
