/* Fleet → Architecture — operator-drawn diagram + live device overlay.
 * Drawing: #naConfig.layout (stored). Overlay: GET liveUrl (read on request).
 * See app/services/netarch.py for what the overlay reads and why.
 */
(function () {
  'use strict';

  var pick = document.getElementById('naPick');
  if (pick) pick.addEventListener('change', function () { window.location.href = pick.value; });
  var svg = document.getElementById('naCanvas');
  var cfgEl = document.getElementById('naConfig');
  if (!svg || !cfgEl) return;
  var CFG = {};
  try { CFG = JSON.parse(cfgEl.textContent) || {}; } catch (e) { return; }
  var NS = 'http://www.w3.org/2000/svg';
  var metaTok = document.querySelector('meta[name="csrf-token"]');
  var CSRF = metaTok ? metaTok.getAttribute('content') : '';
  var layout = CFG.layout || { nodes: [], edges: [] };
  var TYPES = CFG.types || {};
  var APPL = CFG.appliances || [];
  var EDIT = !!CFG.mayEdit;
  var insp = document.getElementById('naInspector');
  var statusEl = document.getElementById('naStatus');

  var COLORS = { internet: '#3D4550', lan: '#4C2A85', segment: '#4C2A85',
    fortigate: '#EF5424', fortiweb: '#1D5FBF', fortiadc: '#0F7B8A',
    fortiauthenticator: '#7A5700', fortianalyzer: '#5B6B7F',
    backend: '#15692A', management: '#3D4550', host: '#5B6B7F' };
  var NET = { internet: 1, lan: 1, segment: 1 };

  var live = null, selId = null, linkFrom = null, linking = false, hlPolicy = null;
  var dirty = false;
  var view = { x: 0, y: 0, k: 1 };

  function el(tag, attrs, parent) {
    var n = document.createElementNS(NS, tag);
    for (var k in attrs) if (attrs[k] !== undefined && attrs[k] !== null) n.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(n);
    return n;
  }
  function esc(s) {
    return String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function byId(id) { for (var i = 0; i < layout.nodes.length; i++) if (layout.nodes[i].id === id) return layout.nodes[i]; return null; }
  function size(n) { return NET[n.type] ? { w: 230, h: 50 } : { w: 170, h: 50 }; }
  function fitText(t, max) { t = String(t || ''); return t.length > max ? t.slice(0, max - 1) + '…' : t; }
  function center(n) { var s = size(n); return { x: n.x + s.w / 2, y: n.y + s.h / 2 }; }
  function setStatus(t, err) { if (statusEl) { statusEl.textContent = t || ''; statusEl.className = 'na-status ms-auto' + (err ? ' na-err' : ''); } }
  function human(b) {
    if (b === null || b === undefined) return '—';
    var u = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0; b = Number(b);
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return (i ? b.toFixed(1) : b) + ' ' + u[i];
  }
  function ago(ts) {
    if (!ts) return 'never';
    var s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    if (s < 90) return s + ' s ago';
    if (s < 5400) return Math.round(s / 60) + ' min ago';
    if (s < 172800) return Math.round(s / 3600) + ' h ago';
    return Math.round(s / 86400) + ' d ago';
  }
  function markDirty() { dirty = true; setStatus('Unsaved changes'); }

  // ---------------------------------------------------------------- render
  var root = el('g', {}, svg);
  function applyView() { root.setAttribute('transform', 'translate(' + view.x + ',' + view.y + ') scale(' + view.k + ')'); }

  function deviceState(n) {
    if (!live) return null;
    if (live.hidden && live.hidden.indexOf(n.id) >= 0) return 'hidden';
    var p = live.probes && live.probes[n.id];
    if (p) return p.ok ? 'ok' : 'bad';
    var d = live.devices && live.devices[n.id];
    if (d && d.fortigate) return (d.fortigate.errors && d.fortigate.errors.length) ? (d.fortigate.policies.length ? 'warn' : 'bad') : 'ok';
    return null;
  }

  function flowList() {
    var out = [];
    if (!live || !live.flows) return out;
    Object.keys(live.flows).forEach(function (fgt) {
      (live.flows[fgt] || []).forEach(function (f) { out.push({ fgt: fgt, f: f }); });
    });
    return out;
  }

  function render() {
    while (root.firstChild) root.removeChild(root.firstChild);
    var gEdges = el('g', {}, root), gFlows = el('g', {}, root), gNodes = el('g', {}, root);

    layout.nodes.forEach(function (n) {
      if (!n.gateway) return;
      var g = byId(n.gateway); if (!g) return;
      var a = center(n), b = center(g);
      el('line', { x1: a.x, y1: a.y, x2: b.x, y2: b.y, 'class': 'na-gw' }, gEdges);
    });
    layout.edges.forEach(function (e) {
      var a = byId(e.from), b = byId(e.to); if (!a || !b) return;
      var p = center(a), q = center(b);
      el('line', { x1: p.x, y1: p.y, x2: q.x, y2: q.y, 'class': 'na-edge' }, gEdges);
      if (e.label) {
        var t = el('text', { x: (p.x + q.x) / 2, y: (p.y + q.y) / 2 - 4, 'text-anchor': 'middle', 'class': 'na-edge-label' }, gEdges);
        t.textContent = e.label;
      }
    });

    var showFlows = document.getElementById('naFlows');
    showFlows = !showFlows || showFlows.checked;
    var pairIdx = {};
    flowList().forEach(function (item) {
      var f = item.f, cls = f.action === 'accept' ? 'accept' : 'deny';
      var key = item.fgt + ':' + f.policy;
      f.from.forEach(function (s) {
        f.to.forEach(function (d) {
          var a = byId(s), b = byId(d); if (!a || !b || s === d) return;
          var pk = s + '>' + d; pairIdx[pk] = (pairIdx[pk] || 0) + 1;
          var p = center(a), q = center(b);
          var mx = (p.x + q.x) / 2, my = (p.y + q.y) / 2;
          var dx = q.x - p.x, dy = q.y - p.y, L = Math.sqrt(dx * dx + dy * dy) || 1;
          var off = 40 * pairIdx[pk];
          var cx = mx - dy / L * off, cy = my + dx / L * off;
          var hl = hlPolicy === key;
          var vis = showFlows || hl;
          el('path', { d: 'M' + p.x + ',' + p.y + ' Q' + cx + ',' + cy + ' ' + q.x + ',' + q.y,
            'class': 'na-flow ' + cls + (hl ? ' hl' : '') + (vis ? '' : ' off'),
            'marker-end': 'url(#naArrow' + cls + ')' }, gFlows);
          if (vis) {
            var t = el('text', { x: (p.x + 2 * cx + q.x) / 4, y: (p.y + 2 * cy + q.y) / 4, 'text-anchor': 'middle',
              'class': 'na-flow-label ' + cls }, gFlows);
            t.textContent = '#' + f.policy + ' ' + (f.name || '') + ' · ' + (f.hit_count === null || f.hit_count === undefined ? '?' : f.hit_count) + ' hits';
          }
        });
      });
    });

    var hlNodes = null;
    if (hlPolicy) {
      hlNodes = {};
      flowList().forEach(function (item) {
        if (item.fgt + ':' + item.f.policy !== hlPolicy) return;
        hlNodes[item.fgt] = 1;
        item.f.from.concat(item.f.to).forEach(function (x) { hlNodes[x] = 1; });
      });
    }

    layout.nodes.forEach(function (n) {
      var s = size(n), col = COLORS[n.type] || '#5B6B7F';
      var g = el('g', { 'class': 'na-node' + (n.id === selId ? ' sel' : '') + (hlNodes && !hlNodes[n.id] ? ' dim' : ''),
        transform: 'translate(' + n.x + ',' + n.y + ')', 'data-id': n.id }, gNodes);
      el('rect', { 'class': 'box', width: s.w, height: s.h, rx: NET[n.type] ? 18 : 6,
        'stroke-dasharray': NET[n.type] ? '5 3' : null }, g);
      el('rect', { x: 0, y: 0, width: 5, height: s.h, rx: 2, fill: col }, g);
      var tt = el('text', { x: 12, y: 13, 'class': 'tt' }, g);
      tt.textContent = (TYPES[n.type] || {}).label || n.type;
      var chars = Math.floor((s.w - 26) / 6.6);
      var t1 = el('text', { x: 12, y: 28, 'class': 't1' }, g);
      t1.textContent = fitText(n.label || n.id, chars);
      var tip = el('title', {}, g); tip.textContent = (n.label || n.id) + (n.note ? '\n' + n.note : '');
      var sub = n.cidr || n.ip || '';
      if (n.vlan) sub = (sub ? sub + ' · ' : '') + 'VLAN ' + n.vlan;
      if (n.interface && NET[n.type]) sub = (sub ? sub + ' · ' : '') + n.interface;
      if (sub) { var t2 = el('text', { x: 12, y: 42, 'class': 't2' }, g); t2.textContent = fitText(sub, chars + 4); }
      var st = deviceState(n);
      if (st) {
        var c = { ok: '#15692A', warn: '#7A5700', bad: '#8B1C2A', hidden: '#9AA6B8' }[st];
        el('circle', { cx: s.w - 9, cy: 9, r: 5, fill: c }, g);
      }
    });
  }

  function defs() {
    var d = el('defs', {}, svg);
    [['accept', '#15692A'], ['deny', '#8B1C2A']].forEach(function (p) {
      var m = el('marker', { id: 'naArrow' + p[0], viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: 'auto-start-reverse' }, d);
      el('path', { d: 'M0,0 L10,5 L0,10 z', fill: p[1] }, m);
    });
  }

  function fit() {
    if (!layout.nodes.length) { view = { x: 20, y: 20, k: 1 }; applyView(); return; }
    var x0 = 1e9, y0 = 1e9, x1 = -1e9, y1 = -1e9;
    layout.nodes.forEach(function (n) { var s = size(n); x0 = Math.min(x0, n.x); y0 = Math.min(y0, n.y); x1 = Math.max(x1, n.x + s.w); y1 = Math.max(y1, n.y + s.h); });
    var W = svg.clientWidth || 900, H = svg.clientHeight || 600, pad = 40;
    var k = Math.min((W - 2 * pad) / (x1 - x0 || 1), (H - 2 * pad) / (y1 - y0 || 1), 1.4);
    view = { k: k, x: pad - x0 * k + ((W - 2 * pad) - (x1 - x0) * k) / 2, y: pad - y0 * k + ((H - 2 * pad) - (y1 - y0) * k) / 2 };
    applyView();
  }

  // ------------------------------------------------------------ inspector
  function field(label, key, n, opts) {
    opts = opts || {};
    var v = n[key] === undefined ? '' : n[key];
    if (!EDIT) return v === '' ? '' : '<div class="mb-1"><label>' + esc(label) + '</label><div>' + esc(v) + '</div></div>';
    return '<div class="mb-2"><label>' + esc(label) + '</label><input class="form-control" data-k="' + key + '" value="' + esc(v) + '" placeholder="' + esc(opts.ph || '') + '"></div>';
  }
  function select(label, key, n, options) {
    var v = n[key] === undefined ? '' : String(n[key]);
    if (!EDIT) { var o = options.filter(function (x) { return String(x[0]) === v; })[0]; return o ? '<div class="mb-1"><label>' + esc(label) + '</label><div>' + esc(o[1]) + '</div></div>' : ''; }
    return '<div class="mb-2"><label>' + esc(label) + '</label><select class="form-select" data-k="' + key + '">' +
      options.map(function (x) { return '<option value="' + esc(x[0]) + '"' + (String(x[0]) === v ? ' selected' : '') + '>' + esc(x[1]) + '</option>'; }).join('') + '</select></div>';
  }

  function inspect() {
    var n = selId && byId(selId);
    if (!n) { insp.innerHTML = '<div class="text-muted small">Select an element' + (EDIT ? ', or add one from the toolbar.' : '.') + '</div>'; return; }
    var t = TYPES[n.type] || {}, h = '<h5 class="mb-2">' + esc(n.label || n.id) + '</h5><div class="small text-muted mb-2">' + esc(t.label || n.type) + '</div>';
    h += field('Label', 'label', n);
    if (NET[n.type]) {
      h += field('Network (CIDR)', 'cidr', n, { ph: '192.0.2.0/24' });
      h += field('VLAN tag', 'vlan', n);
      var fgts = [['', '— none —']].concat(layout.nodes.filter(function (m) { return m.type === 'fortigate'; }).map(function (m) { return [m.id, m.label || m.id]; }));
      h += select('Behind FortiGate', 'gateway', n, fgts);
      h += field('FortiGate interface', 'interface', n, { ph: 'port2' });
    } else {
      h += field('IP address', 'ip', n);
    }
    if (t.device) {
      var opts = [['', '— not bound —']].concat(APPL.filter(function (a) { return a.kind === t.device; }).map(function (a) { return [a.id, a.name + ' (' + a.host + ')']; }));
      h += select('SATOM appliance', 'appliance_id', n, opts);
    }
    if (n.type === 'backend' || n.type === 'host' || n.type === 'management') {
      h += field('Probe URL', 'url', n, { ph: 'http://192.0.2.10/' });
      h += field('Show response header', 'header', n, { ph: 'Server' });
    }
    h += field('Note', 'note', n);
    h += liveSection(n);
    insp.innerHTML = h;
  }

  function liveSection(n) {
    if (!live) return '<h6>Live</h6><div class="small text-muted">Press <b>Read devices</b> to read the bound devices now.</div>';
    var h = '';
    if (live.hidden && live.hidden.indexOf(n.id) >= 0) return '<h6>Live</h6><div class="small text-muted">Bound to a device this ADOM cannot see.</div>';
    var d = live.devices && live.devices[n.id];
    if (d) {
      h += '<h6>Device</h6><div class="small mb-1">' + esc(d.name) + ' · ' + esc(d.host) + '</div><div class="d-flex flex-wrap gap-1 mb-1">';
      if (d.links.detail) h += '<a class="btn btn-sm btn-outline-secondary" href="' + esc(d.links.detail) + '">Device</a>';
      if (d.links.scout) h += '<a class="btn btn-sm btn-outline-secondary" href="' + esc(d.links.scout) + '"><i class="bi bi-search"></i> Scout</a>';
      if (d.links.sentinel) h += '<a class="btn btn-sm btn-outline-secondary" href="' + esc(d.links.sentinel) + '"><i class="bi bi-shield-check"></i> Sentinel</a>';
      h += '</div>';
      var f = d.fortigate;
      if (f) {
        (f.errors || []).forEach(function (e) { h += '<div class="na-err">' + esc(e) + '</div>'; });
        h += '<h6>Interfaces</h6><table class="na-tbl"><tr><th>Port</th><th>Address</th><th>Link</th><th>RX / TX</th></tr>';
        f.interfaces.filter(function (i) { return i.ip || i.alias; }).forEach(function (i) {
          h += '<tr><td>' + esc(i.name) + (i.alias ? '<div class="text-muted">' + esc(i.alias) + '</div>' : '') + '</td><td>' + esc(i.ip || '—') + (i.vlanid ? ' · VLAN ' + esc(i.vlanid) : '') + '</td><td>' +
            (i.link === true ? '<span class="fw-badge fw-badge-success">up</span>' : i.link === false ? '<span class="fw-badge fw-badge-danger">down</span>' : '—') + '</td><td>' + human(i.rx_bytes) + ' / ' + human(i.tx_bytes) + '</td></tr>';
        });
        h += '</table><h6>Policies</h6><table class="na-tbl"><tr><th>#</th><th>From → To</th><th>Service</th><th>Hits</th><th>Bytes</th><th>Last</th></tr>';
        var flows = {}; (live.flows[n.id] || []).forEach(function (x) { flows[x.policy] = x; });
        f.policies.forEach(function (p) {
          var key = n.id + ':' + p.id, fl = flows[p.id] || {};
          var un = (fl.unmapped || []).length ? '<div class="na-err">not drawn: ' + esc(fl.unmapped.join(', ')) + '</div>' : '';
          h += '<tr class="pol' + (hlPolicy === key ? ' hl' : '') + '" data-pol="' + esc(key) + '"><td>' + esc(p.id) + '</td><td><b>' + esc(p.name) + '</b>' +
            (p.status === 'disable' ? ' <span class="fw-badge fw-badge-secondary">disabled</span>' : '') +
            '<div>' + esc(p.srcintf.join(',')) + ' → ' + esc(p.dstintf.join(',')) + '</div><div class="text-muted">' + esc(p.srcaddr.join(', ')) + ' → ' + esc(p.dstaddr.join(', ')) +
            '</div><div>' + (p.action === 'accept' ? '<span class="fw-badge fw-badge-success">accept</span>' : '<span class="fw-badge fw-badge-danger">' + esc(p.action) + '</span>') + (p.nat ? ' <span class="fw-badge fw-badge-info">NAT</span>' : '') + '</div>' + un + '</td><td>' +
            esc(p.service.join(', ')) + '</td><td>' + (p.hit_count === null || p.hit_count === undefined ? '—' : esc(p.hit_count)) + '</td><td>' + human(p.bytes) + '</td><td>' + ago(p.last_used) + '</td></tr>';
        });
        h += '</table>';
        if (f.implicit_deny) h += '<div class="small mt-1">Implicit deny: <b>' + esc(f.implicit_deny.hit_count) + '</b> hits, ' + human(f.implicit_deny.bytes) + ', last ' + ago(f.implicit_deny.last_used) + '.</div>';
        h += '<div class="small text-muted mt-1">Read ' + ago(f.read_at) + '. Click a policy to draw its path.</div>';
      }
    }
    var p = live.probes && live.probes[n.id];
    if (p) {
      h += '<h6>Probe</h6><div class="small">' + (p.ok ? '<span class="fw-badge fw-badge-success">' : '<span class="fw-badge fw-badge-danger">') + esc(p.status === null ? 'no answer' : 'HTTP ' + p.status) + '</span> ' + esc(p.ms) + ' ms</div>';
      if (p.error) h += '<div class="na-err">' + esc(p.error) + '</div>';
      if (p.header) Object.keys(p.header).forEach(function (k) { h += '<div class="small">' + esc(k) + ': <code>' + esc(p.header[k] || '(absent)') + '</code></div>'; });
    }
    return h || '<h6>Live</h6><div class="small text-muted">Nothing to read for this element (no device binding, no probe URL).</div>';
  }

  insp.addEventListener('input', function (ev) {
    var k = ev.target.getAttribute('data-k'); if (!k) return;
    var n = byId(selId); if (!n) return;
    var v = ev.target.value;
    if (v === '') delete n[k]; else n[k] = (k === 'appliance_id') ? Number(v) : v;
    markDirty(); render();
  });
  insp.addEventListener('change', function (ev) {
    // Only a select rebuilds the panel (it changes which fields apply); an
    // input's change fires on blur, and rebuilding then would eat the click
    // that moved focus to the next field.
    if (ev.target.tagName === 'SELECT' && ev.target.getAttribute('data-k')) inspect();
  });
  var delForm = document.getElementById('naDelForm');
  if (delForm) delForm.addEventListener('submit', function (ev) {
    if (!window.confirm(delForm.getAttribute('data-confirm') || 'Delete?')) ev.preventDefault();
  });
  insp.addEventListener('click', function (ev) {
    var tr = ev.target.closest && ev.target.closest('tr.pol'); if (!tr) return;
    var key = tr.getAttribute('data-pol');
    hlPolicy = hlPolicy === key ? null : key;
    render(); inspect();
  });

  // ---------------------------------------------------------- interaction
  function toWorld(ev) {
    var r = svg.getBoundingClientRect();
    return { x: (ev.clientX - r.left - view.x) / view.k, y: (ev.clientY - r.top - view.y) / view.k };
  }
  var drag = null;
  svg.addEventListener('mousedown', function (ev) {
    var g = ev.target.closest && ev.target.closest('.na-node');
    if (g) {
      var id = g.getAttribute('data-id');
      if (linking) {
        if (!linkFrom) { linkFrom = id; selId = id; setStatus('Link from ' + (byId(id).label || id) + ': click the other element'); }
        else if (linkFrom !== id) {
          var dup = layout.edges.some(function (e) { return (e.from === linkFrom && e.to === id) || (e.from === id && e.to === linkFrom); });
          if (!dup) { layout.edges.push({ from: linkFrom, to: id }); markDirty(); }
          linkFrom = null; selId = id;
        }
        render(); inspect(); return;
      }
      selId = id; inspect(); render();
      if (EDIT) { var w = toWorld(ev), n = byId(id); drag = { node: n, dx: w.x - n.x, dy: w.y - n.y }; }
      return;
    }
    drag = { pan: true, sx: ev.clientX - view.x, sy: ev.clientY - view.y, moved: false };
  });
  window.addEventListener('mousemove', function (ev) {
    if (!drag) return;
    if (drag.pan) { view.x = ev.clientX - drag.sx; view.y = ev.clientY - drag.sy; drag.moved = true; applyView(); return; }
    var w = toWorld(ev);
    drag.node.x = Math.round((w.x - drag.dx) / 10) * 10; drag.node.y = Math.round((w.y - drag.dy) / 10) * 10;
    drag.moved = true; render();
  });
  window.addEventListener('mouseup', function () {
    if (drag && !drag.pan && drag.moved) markDirty();
    if (drag && drag.pan && !drag.moved) { selId = null; hlPolicy = null; inspect(); render(); }
    drag = null;
  });
  svg.addEventListener('wheel', function (ev) {
    ev.preventDefault();
    var r = svg.getBoundingClientRect(), mx = ev.clientX - r.left, my = ev.clientY - r.top;
    var k2 = Math.max(0.2, Math.min(3, view.k * (ev.deltaY < 0 ? 1.12 : 1 / 1.12)));
    view.x = mx - (mx - view.x) * k2 / view.k; view.y = my - (my - view.y) * k2 / view.k; view.k = k2; applyView();
  }, { passive: false });

  function on(id, fn) { var b = document.getElementById(id); if (b) b.addEventListener('click', fn); }
  on('naAdd', function () {
    var type = document.getElementById('naAddType').value, i = 1;
    while (byId(type + i)) i++;
    var W = svg.clientWidth || 900, H = svg.clientHeight || 600;
    var n = { id: type + i, type: type, label: (TYPES[type] || {}).label + ' ' + i,
      x: Math.round(((W / 2 - view.x) / view.k) / 10) * 10, y: Math.round(((H / 2 - view.y) / view.k) / 10) * 10 };
    layout.nodes.push(n); selId = n.id; markDirty(); render(); inspect();
  });
  on('naLink', function () {
    linking = !linking; linkFrom = null;
    this.classList.toggle('on', linking); svg.classList.toggle('linking', linking);
    setStatus(linking ? 'Link mode: click two elements' : (dirty ? 'Unsaved changes' : ''));
  });
  on('naDel', function () {
    if (!selId) return;
    layout.nodes = layout.nodes.filter(function (n) { return n.id !== selId; });
    layout.edges = layout.edges.filter(function (e) { return e.from !== selId && e.to !== selId; });
    layout.nodes.forEach(function (n) { if (n.gateway === selId) delete n.gateway; });
    selId = null; markDirty(); render(); inspect();
  });
  on('naFit', fit);
  var flowsBox = document.getElementById('naFlows');
  if (flowsBox) flowsBox.addEventListener('change', render);
  on('naSave', function () {
    setStatus('Saving…');
    fetch(CFG.saveUrl, { method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF },
      body: JSON.stringify({ layout: layout }) })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) {
        if (res.ok && res.j.ok) { layout = res.j.layout; dirty = false; setStatus('Saved'); render(); inspect(); }
        else setStatus('Not saved: ' + ((res.j.errors || []).join('; ') || res.j.error || 'error'), true);
      })
      .catch(function (e) { setStatus('Not saved: ' + e.message, true); });
  });
  on('naLive', function () {
    if (dirty) { setStatus('Save first: live data is read for the stored drawing', true); return; }
    setStatus('Reading devices…');
    fetch(CFG.liveUrl, { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (j) {
        live = j;
        var nd = Object.keys(j.devices || {}).length, np = Object.keys(j.probes || {}).length, nf = flowList().length;
        setStatus('Read ' + nd + ' device(s), ' + np + ' probe(s), ' + nf + ' policy flow(s) at ' + new Date().toLocaleTimeString());
        render(); inspect();
      })
      .catch(function (e) { setStatus('Live read failed: ' + e.message, true); });
  });
  window.addEventListener('beforeunload', function (ev) { if (dirty) { ev.preventDefault(); ev.returnValue = ''; } });

  defs(); render(); fit(); inspect();
})();
