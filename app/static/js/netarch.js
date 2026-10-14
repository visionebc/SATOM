/* Fleet → Architecture — operator-drawn diagram, read by layer.
 * Drawing: #naConfig.layout (stored, autosaved with a version so two people
 * editing one drawing never overwrite each other). Overlay: liveUrl (read on
 * request). Trace: traceUrl (every FortiGate on the way answers for itself).
 * See app/services/netarch.py for what is read and why.
 */
(function () {
  'use strict';

  var svg = document.getElementById('naCanvas');
  var vp = document.getElementById('naViewport');
  var cfgEl = document.getElementById('naConfig');
  var pick = document.getElementById('naPick');
  if (pick) pick.addEventListener('change', function () { window.location.href = pick.value; });
  if (!svg || !vp || !cfgEl) return;
  var CFG = {};
  try { CFG = JSON.parse(cfgEl.textContent) || {}; } catch (e) { return; }
  var NS = 'http://www.w3.org/2000/svg';
  var metaTok = document.querySelector('meta[name="csrf-token"]');
  var CSRF = metaTok ? metaTok.getAttribute('content') : '';
  var layout = CFG.layout || { nodes: [], edges: [] };
  var version = CFG.version || '';
  var TYPES = CFG.types || {};
  var APPL = CFG.appliances || [];
  var EDIT = !!CFG.mayEdit;
  var insp = document.getElementById('naInspector');
  var statusEl = document.getElementById('naStatus');
  var saveEl = document.getElementById('naSave');
  var legend = document.getElementById('naLegend');

  // Same palette family as the Service Diagram (fleet_map.js).
  var COLORS = { internet: '#cfe0ff', lan: '#a78bfa', segment: '#a78bfa',
    fortigate: '#f97316', fortiweb: '#4f8cff', fortiadc: '#06b6d4',
    fortiauthenticator: '#eab308', fortianalyzer: '#8b5cf6',
    backend: '#14b8a6', management: '#94a3b8', host: '#94a3b8' };
  var NET = { internet: 1, lan: 1, segment: 1 };
  var KIND_TYPE = { fortigate: 'fortigate', fortiweb: 'fortiweb', fortiadc: 'fortiadc',
    fortiauthenticator: 'fortiauthenticator', fortianalyzer: 'fortianalyzer' };

  var live = null, traceRes = null, selId = null, linkFrom = null, linking = false, hlPolicy = null;
  var layer = 'l3', hoverId = null;
  var view = { x: 0, y: 0, k: 1 };
  var undo = [], redo = [];
  var dirty = false, saving = false, saveTimer = null, autoTimer = null;

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
  function size(n) { return NET[n.type] ? { w: 240, h: 54 } : { w: 180, h: 62 }; }
  function center(n) { var s = size(n); return { x: n.x + s.w / 2, y: n.y + s.h / 2 }; }
  function fitText(t, max) { t = String(t || ''); return t.length > max ? t.slice(0, max - 1) + '…' : t; }
  function setStatus(t, err) { if (statusEl) { statusEl.textContent = t || ''; statusEl.className = 'na-status' + (err ? ' na-err' : ''); } }
  function setSave(t, cls) { if (saveEl) { saveEl.textContent = t; saveEl.className = 'na-save ms-auto ' + (cls || ''); } }
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

  // ------------------------------------------------------- history + save
  function snapshot() {
    if (!EDIT) return;
    undo.push(JSON.stringify(layout)); if (undo.length > 100) undo.shift();
    redo = []; syncHist();
  }
  function syncHist() {
    var u = document.getElementById('naUndo'), r = document.getElementById('naRedo');
    if (u) u.disabled = !undo.length; if (r) r.disabled = !redo.length;
  }
  function restore(from, to) {
    if (!from.length) return;
    to.push(JSON.stringify(layout));
    layout = JSON.parse(from.pop());
    if (selId && !byId(selId)) selId = null;
    syncHist(); changed();
  }
  function changed() { dirty = true; render(); inspect(); scheduleSave(); }
  function scheduleSave() {
    if (!EDIT) return;
    setSave('Unsaved…', 'busy');
    clearTimeout(saveTimer); saveTimer = setTimeout(save, 900);
  }
  function save() {
    if (saving) { scheduleSave(); return; }
    saving = true; setSave('Saving…', 'busy');
    var sent = JSON.stringify(layout);
    fetch(CFG.saveUrl, { method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': CSRF },
      body: JSON.stringify({ layout: layout, base: version }) })
      .then(function (r) { return r.json().then(function (j) { return { status: r.status, j: j }; }); })
      .then(function (res) {
        saving = false;
        if (res.status === 200 && res.j.ok) {
          version = res.j.version;
          if (JSON.stringify(layout) === sent) { dirty = false; setSave('Saved ' + new Date().toLocaleTimeString(), 'ok'); }
          else scheduleSave();
        } else if (res.status === 409) {
          // Theirs wins on screen; ours stays one Undo away — nothing lost.
          undo.push(JSON.stringify(layout)); redo = []; syncHist();
          layout = res.j.layout; version = res.j.version; dirty = false;
          setSave('Updated by ' + (res.j.updated_by || 'someone') + ' — your change is in Undo', 'bad');
          render(); inspect();
        } else {
          setSave('Not saved: ' + ((res.j.errors || []).join('; ') || res.j.error || 'error'), 'bad');
        }
      })
      .catch(function (e) { saving = false; setSave('Not saved: ' + e.message, 'bad'); });
  }
  function poll() {
    if (dirty || saving || document.hidden) return;
    fetch(CFG.layoutUrl, { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) {
        if (!j || dirty || saving || j.version === version) return;
        layout = j.layout; version = j.version;
        if (selId && !byId(selId)) selId = null;
        setSave('Updated by ' + (j.updated_by || 'someone') + ' ' + new Date().toLocaleTimeString(), 'ok');
        render(); inspect();
      }).catch(function () {});
  }
  setInterval(poll, 15000);

  // ---------------------------------------------------------------- render
  var defs = el('defs', {}, svg);
  var glow = el('filter', { id: 'naGlow', x: '-50%', y: '-50%', width: '200%', height: '200%' }, defs);
  el('feGaussianBlur', { stdDeviation: 2.5, result: 'b' }, glow);
  var mg = el('feMerge', {}, glow); el('feMergeNode', { 'in': 'b' }, mg); el('feMergeNode', { 'in': 'SourceGraphic' }, mg);
  [['accept', '#22c55e'], ['deny', '#ef4444'], ['l7', '#14b8a6']].forEach(function (p) {
    var m = el('marker', { id: 'naArrow' + p[0], viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: 'auto-start-reverse' }, defs);
    el('path', { d: 'M0,0 L10,5 L0,10 z', fill: p[1] }, m);
  });
  var root = el('g', {}, svg);
  function applyView() { root.setAttribute('transform', 'translate(' + view.x + ',' + view.y + ') scale(' + view.k + ')'); }

  function fgtData(id) { var d = live && live.devices && live.devices[id]; return d && d.fortigate; }
  function ifaceFor(fgtId, net) {
    var f = fgtData(fgtId); if (!f) return null;
    for (var i = 0; i < f.interfaces.length; i++) {
      var itf = f.interfaces[i];
      if (net.interface && net.interface === itf.name) return itf;
    }
    for (var j = 0; j < f.interfaces.length; j++) {
      var it = f.interfaces[j];
      if (it.ip && net.cidr && inCidr(it.ip.split('/')[0], net.cidr)) return it;
    }
    return null;
  }
  function ip2n(ip) { var p = String(ip).split('.'); if (p.length !== 4) return null; return ((+p[0] << 24) >>> 0) + (+p[1] << 16) + (+p[2] << 8) + (+p[3]); }
  function inCidr(ip, cidr) {
    var parts = String(cidr).split('/'), a = ip2n(ip), b = ip2n(parts[0]), m = +parts[1];
    if (a === null || b === null || isNaN(m)) return false;
    var mask = m === 0 ? 0 : ((0xffffffff << (32 - m)) >>> 0);
    return ((a & mask) >>> 0) === ((b & mask) >>> 0);
  }
  function arpFor(ip) {
    if (!live || !ip) return null;
    for (var k in live.devices) {
      var f = live.devices[k].fortigate; if (!f || !f.arp) continue;
      for (var i = 0; i < f.arp.length; i++) if (f.arp[i].ip === ip) return { fgt: k, a: f.arp[i] };
    }
    return null;
  }
  function deviceState(n) {
    if (!live) return null;
    if (live.hidden && live.hidden.indexOf(n.id) >= 0) return 'hidden';
    var p = live.probes && live.probes[n.id];
    if (p) return p.ok ? 'ok' : 'bad';
    var d = live.devices && live.devices[n.id];
    if (d && d.fortigate) return (d.fortigate.errors && d.fortigate.errors.length) ? (d.fortigate.policies.length ? 'warn' : 'bad') : 'ok';
    if (d) return 'ok';
    return null;
  }
  function flowList() {
    var out = [];
    if (!live || !live.flows) return out;
    Object.keys(live.flows).forEach(function (fgt) { (live.flows[fgt] || []).forEach(function (f) { out.push({ fgt: fgt, f: f }); }); });
    return out;
  }
  function polByKey(fgt, id) {
    var f = fgtData(fgt); if (!f) return null;
    for (var i = 0; i < f.policies.length; i++) if (f.policies[i].id === id) return f.policies[i];
    return null;
  }
  function curve(p, q, off) {
    var mx = (p.x + q.x) / 2, my = (p.y + q.y) / 2, dx = q.x - p.x, dy = q.y - p.y, L = Math.sqrt(dx * dx + dy * dy) || 1;
    var cx = mx - dy / L * off, cy = my + dx / L * off;
    var u = 0.33, a1 = (1 - u) * (1 - u), b1 = 2 * u * (1 - u), c1 = u * u;
    return { d: 'M' + p.x + ',' + p.y + ' Q' + cx + ',' + cy + ' ' + q.x + ',' + q.y,
      lx: a1 * p.x + b1 * cx + c1 * q.x, ly: a1 * p.y + b1 * cy + c1 * q.y };
  }
  function l7Edges() {
    var out = [];
    if (!live || !live.devices) return out;
    Object.keys(live.devices).forEach(function (nid) {
      var fw = live.devices[nid].fortiweb; if (!fw) return;
      fw.policies.forEach(function (p) {
        (p.backends || []).forEach(function (b) {
          layout.nodes.forEach(function (m) {
            if (m.ip && m.ip === b.ip && m.id !== nid) out.push({ from: nid, to: m.id, p: p, b: b });
          });
        });
      });
    });
    return out;
  }

  function render() {
    while (root.firstChild) root.removeChild(root.firstChild);
    var gE = el('g', {}, root), gF = el('g', {}, root), gT = el('g', {}, root), gN = el('g', {}, root);
    var hot = {};  // ids of things touching the hovered/trace element
    var focus = null;
    if (traceRes && traceRes.path && traceRes.path.length) { focus = {}; traceRes.path.forEach(function (x) { focus[x] = 1; }); }
    else if (hoverId) { focus = {}; focus[hoverId] = 1; }
    else if (hlPolicy) {
      focus = {};
      flowList().forEach(function (it) { if (it.fgt + ':' + it.f.policy === hlPolicy) { focus[it.fgt] = 1; it.f.from.concat(it.f.to).forEach(function (x) { focus[x] = 1; }); } });
    }
    function touches(a, b) { return focus && (hoverId ? (a === hoverId || b === hoverId) : (focus[a] && focus[b])); }

    layout.nodes.forEach(function (n) {
      if (!n.gateway) return;
      var g = byId(n.gateway); if (!g) return;
      var a = center(n), b = center(g);
      el('line', { x1: a.x, y1: a.y, x2: b.x, y2: b.y, 'class': 'na-gw' + (touches(n.id, g.id) ? ' hot' : '') }, gE);
    });
    layout.edges.forEach(function (e) {
      var a = byId(e.from), b = byId(e.to); if (!a || !b) return;
      var p = center(a), q = center(b), cls = 'na-edge', lbl = e.label || '';
      var fg = a.type === 'fortigate' ? a : (b.type === 'fortigate' ? b : null), net = NET[a.type] ? a : (NET[b.type] ? b : null);
      if (fg && net) {
        var itf = ifaceFor(fg.id, net);
        if (itf) {
          if (layer === 'l2') { cls += itf.link === false ? ' down' : ' up'; lbl = itf.name + (itf.mac ? ' · ' + itf.mac : '') + (itf.speed ? ' · ' + (itf.speed >= 1000 ? itf.speed / 1000 + 'G' : itf.speed + 'M') : '') + (net.vlan ? ' · VLAN ' + net.vlan : ''); }
          else if (layer === 'l3') lbl = itf.name + ' ' + (itf.ip || '');
          else if (layer === 'l4') lbl = itf.name + ' · RX ' + human(itf.rx_bytes) + ' / TX ' + human(itf.tx_bytes);
        }
      }
      if (touches(e.from, e.to)) cls += ' hot';
      el('line', { x1: p.x, y1: p.y, x2: q.x, y2: q.y, 'class': cls }, gE);
      if (lbl && layer !== 'l7') {
        var t = el('text', { x: (p.x + q.x) / 2, y: (p.y + q.y) / 2 - 5, 'text-anchor': 'middle', 'class': 'na-elabel' + (touches(e.from, e.to) ? ' hot' : '') }, gE);
        t.textContent = lbl;
      }
    });

    if (layer === 'l3' || layer === 'l4') {
      var pairIdx = {};
      flowList().forEach(function (item) {
        var f = item.f, cls = f.action === 'accept' ? 'accept' : 'deny', key = item.fgt + ':' + f.policy;
        var pol = polByKey(item.fgt, f.policy) || {};
        f.from.forEach(function (s) {
          f.to.forEach(function (d) {
            var a = byId(s), b = byId(d); if (!a || !b || s === d) return;
            var pk = s + '>' + d; pairIdx[pk] = (pairIdx[pk] || 0) + 1;
            var c = curve(center(a), center(b), 46 * pairIdx[pk]);
            var isHot = hlPolicy === key || (hoverId && (s === hoverId || d === hoverId || item.fgt === hoverId));
            el('path', { d: c.d, 'class': 'na-flow ' + cls + (hlPolicy === key ? ' hl' : '') + (isHot ? ' hot' : ''), 'marker-end': 'url(#naArrow' + cls + ')' }, gF);
            var t = el('text', { x: c.lx, y: c.ly, 'text-anchor': 'middle', 'class': 'na-flabel ' + cls + (isHot ? ' hot' : '') }, gF);
            if (layer === 'l3') t.textContent = '#' + f.policy + ' ' + (f.name || '');
            else t.textContent = '#' + f.policy + ' ' + fitText((pol.service || []).join(','), 22) + ' · ' + (pol.active_sessions == null ? '?' : pol.active_sessions) + ' sess · ' + (f.hit_count == null ? '?' : f.hit_count) + ' hits';
          });
        });
      });
    }
    if (layer === 'l7') {
      var seen = {};
      l7Edges().forEach(function (e) {
        var k = e.from + '>' + e.to; seen[k] = (seen[k] || 0) + 1; if (seen[k] > 3) return;
        var a = byId(e.from), b = byId(e.to);
        var c = curve(center(a), center(b), 30 * seen[k]);
        var isHot = hoverId && (e.from === hoverId || e.to === hoverId);
        el('path', { d: c.d, 'class': 'na-edge l7' + (isHot ? ' hot' : ''), 'marker-end': 'url(#naArrowl7)' }, gF);
        var t = el('text', { x: c.lx, y: c.ly, 'text-anchor': 'middle', 'class': 'na-elabel' + (isHot ? ' hot' : '') }, gF);
        t.textContent = fitText(e.p.name, 18) + ' → :' + (e.b.port || '?');
      });
    }

    if (traceRes && traceRes.path && traceRes.path.length > 1) {
      var pts = traceRes.path.map(function (id) { var n = byId(id); return n ? center(n) : null; }).filter(Boolean);
      var d = 'M' + pts.map(function (p) { return p.x + ',' + p.y; }).join(' L');
      el('path', { d: d, 'class': 'na-trace-path ' + traceRes.verdict }, gT);
    }

    layout.nodes.forEach(function (n) {
      var s = size(n), col = COLORS[n.type] || '#94a3b8', isNet = !!NET[n.type];
      var cls = 'na-node' + (isNet ? ' net' : '') + (n.id === selId ? ' sel' : '') + (focus && focus[n.id] ? ' hot' : '');
      if (hoverId && !focus[n.id]) {
        layout.edges.forEach(function (e) { if ((e.from === hoverId && e.to === n.id) || (e.to === hoverId && e.from === n.id)) cls += ' hot'; });
        if (n.gateway === hoverId || (byId(hoverId) || {}).gateway === n.id) cls += ' hot';
      }
      var g = el('g', { 'class': cls, transform: 'translate(' + n.x + ',' + n.y + ')', 'data-id': n.id }, gN);
      el('rect', { 'class': 'box', width: s.w, height: s.h, rx: isNet ? 26 : 10 }, g);
      if (!isNet) el('rect', { x: 0, y: 0, width: s.w, height: 3, rx: 1.5, fill: col }, g);
      var tt = el('text', { x: 14, y: isNet ? 17 : 19, 'class': 'tt', fill: col }, g);
      tt.textContent = String(((TYPES[n.type] || {}).label || n.type)).toUpperCase();
      var chars = Math.floor((s.w - 30) / 7.4);
      var t1 = el('text', { x: 14, y: isNet ? 33 : 36, 'class': 't1' }, g);
      t1.textContent = fitText(n.label || n.id, chars);
      var tip = el('title', {}, g); tip.textContent = (n.label || n.id) + (n.note ? '\n' + n.note : '');
      var sub = '', sub2 = '';
      if (layer === 'l2') {
        if (isNet) sub = (n.vlan ? 'VLAN ' + n.vlan : 'untagged') + (n.interface ? ' · ' + n.interface : '');
        else { var ar = arpFor(n.ip); sub = ar ? ar.a.mac : (n.ip || ''); sub2 = ar ? 'seen on ' + ar.a.interface : ''; }
      } else if (layer === 'l7') {
        var pr = live && live.probes && live.probes[n.id];
        var fw = live && live.devices && live.devices[n.id] && live.devices[n.id].fortiweb;
        sub = n.cidr || n.ip || '';
        if (pr) sub2 = (pr.status == null ? 'no answer' : 'HTTP ' + pr.status) + ' · ' + pr.ms + ' ms';
        else if (fw) sub2 = fw.count + ' server policies';
      } else {
        sub = n.cidr || n.ip || '';
        if (isNet && n.vlan) sub += ' · VLAN ' + n.vlan;
        if (layer === 'l4') { var pr4 = live && live.probes && live.probes[n.id]; if (pr4) sub2 = (pr4.status == null ? 'no answer' : 'answered') + ' · ' + pr4.ms + ' ms'; }
      }
      if (sub) { var t2 = el('text', { x: 14, y: isNet ? 46 : 50, 'class': 't2' }, g); t2.textContent = fitText(sub, chars + 6); }
      if (sub2 && !isNet) { var t3 = el('text', { x: s.w - 10, y: 19, 'class': 't3', 'text-anchor': 'end' }, g); t3.textContent = fitText(sub2, 22); }
      var st = deviceState(n);
      if (st) el('circle', { cx: s.w - 10, cy: isNet ? 27 : 34, r: 4.5, 'class': st === 'ok' ? 'na-led' : '', fill: { ok: '#22c55e', warn: '#f59e0b', bad: '#ef4444', hidden: '#64748b' }[st] }, g);
    });
    svg.classList.toggle('focus', !!focus);
    if (legend) legend.innerHTML = {
      l2: '<b>L2</b> port · MAC · speed · VLAN — green link up, red down. Hosts show the MAC the FortiGate learned.',
      l3: '<b>L3</b> addresses and routes — arrows are firewall policies, source segment to destination segment.',
      l4: '<b>L4</b> services per policy, active sessions and hit counters; port byte counters on the links.',
      l7: '<b>L7</b> FortiWeb server policies to the back-ends they publish; HTTP probe answers on back-ends.'
    }[layer] + (live ? '' : ' Press <b>Read devices</b>.');
  }

  function fit() {
    if (!layout.nodes.length) { view = { x: 20, y: 20, k: 1 }; applyView(); return; }
    var x0 = 1e9, y0 = 1e9, x1 = -1e9, y1 = -1e9;
    layout.nodes.forEach(function (n) { var s = size(n); x0 = Math.min(x0, n.x); y0 = Math.min(y0, n.y); x1 = Math.max(x1, n.x + s.w); y1 = Math.max(y1, n.y + s.h); });
    var W = vp.clientWidth || 900, H = vp.clientHeight || 600, pad = 50;
    var k = Math.min((W - 2 * pad) / (x1 - x0 || 1), (H - 2 * pad) / (y1 - y0 || 1), 1.3);
    view = { k: k, x: pad - x0 * k + ((W - 2 * pad) - (x1 - x0) * k) / 2, y: pad - y0 * k + ((H - 2 * pad) - (y1 - y0) * k) / 2 };
    applyView();
  }
  function zoom(f) {
    var W = vp.clientWidth / 2, H = vp.clientHeight / 2, k2 = Math.max(0.2, Math.min(3, view.k * f));
    view.x = W - (W - view.x) * k2 / view.k; view.y = H - (H - view.y) * k2 / view.k; view.k = k2; applyView();
  }

  // -------------------------------------------------------------- palette
  var pal = document.getElementById('naPalette');
  function drawnAppl(id) { return layout.nodes.some(function (n) { return n.appliance_id === id; }); }
  function renderPalette(q) {
    if (!pal) return;
    q = (q || '').toLowerCase();
    var h = '<input id="naPalQ" placeholder="Search the fleet…" value="' + esc(q) + '">';
    var groups = {};
    APPL.forEach(function (a) {
      if (q && (a.name + ' ' + a.host + ' ' + a.kind).toLowerCase().indexOf(q) < 0) return;
      (groups[a.kind] = groups[a.kind] || []).push(a);
    });
    Object.keys(groups).sort().forEach(function (k) {
      h += '<h6>' + esc((TYPES[KIND_TYPE[k]] || {}).label || k) + '</h6>';
      groups[k].forEach(function (a) {
        h += '<div class="na-pal-item" data-appl="' + a.id + '"><span>' + esc(a.name) + ' <span class="h">' + esc(a.host) + '</span></span>' + (drawnAppl(a.id) ? '<span class="done">✓ drawn</span>' : '') + '</div>';
      });
    });
    if (!Object.keys(groups).length) h += '<div class="h mt-2">No device of the fleet matches (this ADOM sees only its own).</div>';
    h += '<h6>Generic</h6>';
    Object.keys(TYPES).forEach(function (t) { h += '<div class="na-pal-item" data-type="' + esc(t) + '"><span>' + esc(TYPES[t].label) + '</span></div>'; });
    pal.innerHTML = h;
    var qi = document.getElementById('naPalQ');
    if (qi) { qi.addEventListener('input', function () { var v = qi.value, pos = qi.selectionStart; renderPalette(v); var n = document.getElementById('naPalQ'); n.focus(); n.setSelectionRange(pos, pos); }); }
  }
  function freeSpot() {
    var W = vp.clientWidth || 900, H = vp.clientHeight || 600;
    var x = Math.round(((W / 2 - view.x) / view.k) / 10) * 10, y = Math.round(((H / 2 - view.y) / view.k) / 10) * 10;
    for (var i = 0; i < 40 && layout.nodes.some(function (n) { return Math.abs(n.x - x) < 60 && Math.abs(n.y - y) < 40; }); i++) { x += 30; y += 30; }
    return { x: x, y: y };
  }
  function newId(base) { base = String(base).toLowerCase().replace(/[^a-z0-9_.:-]/g, '_').slice(0, 40) || 'n'; var id = base, i = 2; while (byId(id)) id = base + '_' + i++; return id; }
  if (pal) pal.addEventListener('click', function (ev) {
    var it = ev.target.closest && ev.target.closest('.na-pal-item'); if (!it) return;
    var aid = it.getAttribute('data-appl'), type = it.getAttribute('data-type'), spot = freeSpot(), n;
    if (aid) {
      var a = APPL.filter(function (x) { return String(x.id) === aid; })[0]; if (!a) return;
      var exist = layout.nodes.filter(function (m) { return m.appliance_id === a.id; })[0];
      if (exist) { selId = exist.id; render(); inspect(); return; }
      n = { id: newId(a.name), type: KIND_TYPE[a.kind] || 'host', label: a.name, ip: a.host, appliance_id: a.id, x: spot.x, y: spot.y };
      if (!/^\d+\.\d+\.\d+\.\d+$/.test(a.host || '')) delete n.ip;
    } else {
      n = { id: newId(type), type: type, label: (TYPES[type] || {}).label, x: spot.x, y: spot.y };
    }
    snapshot(); layout.nodes.push(n); selId = n.id; changed(); renderPalette(document.getElementById('naPalQ') ? document.getElementById('naPalQ').value : '');
  });

  // ------------------------------------------------------------ inspector
  function field(label, key, n, ph) {
    var v = n[key] === undefined ? '' : n[key];
    if (!EDIT) return v === '' ? '' : '<div class="mb-1"><label>' + esc(label) + '</label><div>' + esc(v) + '</div></div>';
    return '<div class="mb-2"><label>' + esc(label) + '</label><input class="form-control" data-k="' + key + '" value="' + esc(v) + '" placeholder="' + esc(ph || '') + '"></div>';
  }
  function select(label, key, n, options) {
    var v = n[key] === undefined ? '' : String(n[key]);
    if (!EDIT) { var o = options.filter(function (x) { return String(x[0]) === v; })[0]; return o && o[0] !== '' ? '<div class="mb-1"><label>' + esc(label) + '</label><div>' + esc(o[1]) + '</div></div>' : ''; }
    return '<div class="mb-2"><label>' + esc(label) + '</label><select class="form-select" data-k="' + key + '">' +
      options.map(function (x) { return '<option value="' + esc(x[0]) + '"' + (String(x[0]) === v ? ' selected' : '') + '>' + esc(x[1]) + '</option>'; }).join('') + '</select></div>';
  }

  function inspect() {
    if (traceRes) { insp.innerHTML = traceCard(); return; }
    var n = selId && byId(selId);
    if (!n) { insp.innerHTML = '<div class="text-muted small">Select an element' + (EDIT ? ', or open <b>Elements</b> to add one from the fleet.' : '.') + ' Hover an element to light up everything connected to it.</div>' + liveSummary(); return; }
    var t = TYPES[n.type] || {}, h = '<h5 class="mb-1">' + esc(n.label || n.id) + '</h5><div class="small text-muted mb-2">' + esc(t.label || n.type) + '</div>';
    h += field('Label', 'label', n);
    if (NET[n.type]) {
      h += field('Network (CIDR)', 'cidr', n, '192.0.2.0/24') + field('VLAN tag', 'vlan', n);
      var fgts = [['', '— none —']].concat(layout.nodes.filter(function (m) { return m.type === 'fortigate'; }).map(function (m) { return [m.id, m.label || m.id]; }));
      h += select('Behind FortiGate', 'gateway', n, fgts) + field('FortiGate interface', 'interface', n, 'port2');
    } else {
      h += field('IP address', 'ip', n);
    }
    if (t.device) {
      var opts = [['', '— not bound —']].concat(APPL.filter(function (a) { return a.kind === t.device; }).map(function (a) { return [a.id, a.name + ' (' + a.host + ')']; }));
      h += select('SATOM appliance', 'appliance_id', n, opts);
    }
    if (n.type === 'backend' || n.type === 'host' || n.type === 'management') h += field('Probe URL', 'url', n, 'http://192.0.2.10/') + field('Show response header', 'header', n, 'Server');
    h += field('Note', 'note', n);
    if (n.ip) h += '<div class="d-flex gap-1 mb-2"><button type="button" class="btn btn-sm btn-outline-secondary" data-trace="src">Trace from here</button><button type="button" class="btn btn-sm btn-outline-secondary" data-trace="dst">Trace to here</button></div>';
    insp.innerHTML = h + liveSection(n);
  }
  function liveSummary() {
    if (!live) return '';
    var nd = Object.keys(live.devices || {}).length, np = Object.keys(live.probes || {}).length;
    return '<div class="small mt-2">Read ' + nd + ' device(s) and ' + np + ' probe(s). Pick an element for its detail.</div>';
  }

  function liveSection(n) {
    if (!live) return '<h6>Live</h6><div class="small text-muted">Press <b>Read devices</b> to read the bound devices now.</div>';
    if (live.hidden && live.hidden.indexOf(n.id) >= 0) return '<h6>Live</h6><div class="small text-muted">Bound to a device this ADOM cannot see.</div>';
    var h = '', d = live.devices && live.devices[n.id];
    if (d) {
      h += '<h6>Device</h6><div class="small mb-1">' + esc(d.name) + ' · ' + esc(d.host) + '</div><div class="d-flex flex-wrap gap-1 mb-1">';
      if (d.links.detail) h += '<a class="btn btn-sm btn-outline-secondary" href="' + esc(d.links.detail) + '">Device</a>';
      if (d.links.scout) h += '<a class="btn btn-sm btn-outline-secondary" href="' + esc(d.links.scout) + '"><i class="bi bi-search"></i> Path Diagnostics</a>';
      if (d.links.sentinel) h += '<a class="btn btn-sm btn-outline-secondary" href="' + esc(d.links.sentinel) + '"><i class="bi bi-shield-check"></i> Sentinel</a>';
      h += '</div>';
      if (d.fortigate) h += fgtSection(n, d.fortigate);
      if (d.fortiweb) h += fwbSection(d.fortiweb);
    }
    var ar = arpFor(n.ip);
    if (ar) h += '<h6>L2</h6><div class="small">MAC <code>' + esc(ar.a.mac) + '</code> learned by ' + esc((byId(ar.fgt) || {}).label || ar.fgt) + ' on ' + esc(ar.a.interface) + ' (' + esc(ar.a.age) + ' s ago).</div>';
    var p = live.probes && live.probes[n.id];
    if (p) {
      h += '<h6>Probe (L4/L7)</h6><div class="small">' + (p.ok ? '<span class="fw-badge fw-badge-success">' : '<span class="fw-badge fw-badge-danger">') + esc(p.status === null ? 'no answer' : 'HTTP ' + p.status) + '</span> ' + esc(p.ms) + ' ms</div>';
      if (p.error) h += '<div class="na-err">' + esc(p.error) + '</div>';
      if (p.header) Object.keys(p.header).forEach(function (k) { h += '<div class="small">' + esc(k) + ': <code>' + esc(p.header[k] || '(absent)') + '</code></div>'; });
    }
    return h || '<h6>Live</h6><div class="small text-muted">Nothing to read for this element (no device binding, no probe URL).</div>';
  }
  function fgtSection(n, f) {
    var h = '';
    (f.errors || []).forEach(function (e) { h += '<div class="na-err">' + esc(e) + '</div>'; });
    if (layer === 'l2') {
      h += '<h6>Ports (L2)</h6><table class="na-tbl"><tr><th>Port</th><th>MAC</th><th>Link</th><th>Errors</th></tr>';
      f.interfaces.filter(function (i) { return i.mac || i.ip; }).forEach(function (i) {
        h += '<tr><td>' + esc(i.name) + (i.vlanid ? ' · VLAN ' + esc(i.vlanid) : '') + '</td><td><code>' + esc(i.mac || '—') + '</code></td><td>' + (i.link === true ? '<span class="fw-badge fw-badge-success">up</span>' : i.link === false ? '<span class="fw-badge fw-badge-danger">down</span>' : '—') + (i.speed ? ' ' + esc(i.speed >= 1000 ? i.speed / 1000 + 'G' : i.speed + 'M') : '') + '</td><td>' + esc((i.rx_errors || 0) + (i.tx_errors || 0)) + '</td></tr>';
      });
      h += '</table><h6>ARP (' + (f.arp || []).length + ')</h6><table class="na-tbl"><tr><th>IP</th><th>MAC</th><th>Port</th></tr>';
      (f.arp || []).forEach(function (a) { h += '<tr><td>' + esc(a.ip) + '</td><td><code>' + esc(a.mac) + '</code></td><td>' + esc(a.interface) + '</td></tr>'; });
      return h + '</table>';
    }
    if (layer === 'l3') {
      h += '<h6>Routes</h6><table class="na-tbl"><tr><th>Destination</th><th>Gateway</th><th>Port</th></tr>';
      (f.routes || []).forEach(function (r) { h += '<tr><td>' + esc(r.dst) + '</td><td>' + esc(r.gateway === '0.0.0.0' ? 'connected' : r.gateway) + '</td><td>' + esc(r.interface) + '</td></tr>'; });
      h += '</table>';
    }
    h += '<h6>Policies</h6><table class="na-tbl"><tr><th>#</th><th>From → To</th><th>' + (layer === 'l4' ? 'Service' : 'Addresses') + '</th><th>Hits</th><th>' + (layer === 'l4' ? 'Sess' : 'Last') + '</th></tr>';
    var flows = {}; (live.flows[n.id] || []).forEach(function (x) { flows[x.policy] = x; });
    f.policies.forEach(function (p) {
      var key = n.id + ':' + p.id, fl = flows[p.id] || {};
      var un = (fl.unmapped || []).length ? '<div class="na-err">not drawn: ' + esc(fl.unmapped.join(', ')) + '</div>' : '';
      h += '<tr class="pol' + (hlPolicy === key ? ' hl' : '') + '" data-pol="' + esc(key) + '"><td>' + esc(p.id) + '</td><td><b>' + esc(p.name) + '</b>' +
        (p.status === 'disable' ? ' <span class="fw-badge fw-badge-secondary">disabled</span>' : '') +
        '<div>' + esc(p.srcintf.join(',')) + ' → ' + esc(p.dstintf.join(',')) + '</div><div>' + (p.action === 'accept' ? '<span class="fw-badge fw-badge-success">accept</span>' : '<span class="fw-badge fw-badge-danger">' + esc(p.action) + '</span>') + (p.nat ? ' <span class="fw-badge fw-badge-info">NAT</span>' : '') + '</div>' + un + '</td><td>' +
        (layer === 'l4' ? esc(p.service.join(', ')) : esc(p.srcaddr.join(', ')) + ' → ' + esc(p.dstaddr.join(', '))) + '</td><td>' + (p.hit_count == null ? '—' : esc(p.hit_count)) + '<div class="text-muted">' + human(p.bytes) + '</div></td><td>' + (layer === 'l4' ? (p.active_sessions == null ? '—' : esc(p.active_sessions)) : ago(p.last_used)) + '</td></tr>';
    });
    h += '</table>';
    if (f.implicit_deny) h += '<div class="small mt-1">Implicit deny: <b>' + esc(f.implicit_deny.hit_count) + '</b> hits, last ' + ago(f.implicit_deny.last_used) + '.</div>';
    return h + '<div class="small text-muted mt-1">Read ' + ago(f.read_at) + '. Click a policy to draw its path.</div>';
  }
  function fwbSection(fw) {
    var h = '<h6>Server policies (L7, device cache) — ' + esc(fw.count) + '</h6>';
    if (!fw.policies.length) return h + '<div class="small text-muted">None in the cache yet.</div>';
    h += '<table class="na-tbl"><tr><th>Policy</th><th>Published</th><th>Pool → back-ends</th></tr>';
    fw.policies.slice(0, 60).forEach(function (p) {
      var drawn = (p.backends || []).map(function (b) { var m = layout.nodes.filter(function (x) { return x.ip === b.ip; })[0]; return esc(b.ip + ':' + (b.port || '')) + (m ? ' ✓' : ''); });
      h += '<tr><td><b>' + esc(p.name) + '</b>' + (p.status === 'disable' ? ' <span class="fw-badge fw-badge-secondary">off</span>' : '') + '</td><td>' + esc(p.vips.join(', ')) + (p.port ? ':' + esc(p.port) : '') + (p.https_port ? ' / ' + esc(p.https_port) : '') + '</td><td>' + esc(p.pool) + '<div class="text-muted">' + drawn.join(', ') + '</div></td></tr>';
    });
    return h + '</table><div class="small text-muted mt-1">✓ = back-end drawn on this diagram (shown as an L7 arrow).</div>';
  }
  function traceCard() {
    var r = traceRes, h = '<h5 class="mb-1">Trace</h5><div class="small mb-2"><code>' + esc(r.src) + '</code> → <code>' + esc(r.dst) + '</code> ' + esc(r.proto.toUpperCase()) + (r.port ? ':' + esc(r.port) : '') + '</div>';
    var badge = { allowed: 'fw-badge-success', denied: 'fw-badge-danger', unknown: 'fw-badge-warning' }[r.verdict];
    h += '<div class="mb-2"><span class="fw-badge ' + badge + '">' + esc(r.verdict.toUpperCase()) + '</span> ' + esc(r.reason || '') + '</div>';
    if (!r.src_net && !r.src_node) h += '<div class="small na-err">The source is not on the drawing.</div>';
    if (!r.dst_net && !r.dst_node) h += '<div class="small na-err">The destination is not on the drawing.</div>';
    r.hops.forEach(function (hp) {
      var fg = byId(hp.fgt) || {}, pol = hp.policy_id != null ? polByKey(hp.fgt, hp.policy_id) : null;
      if (hp.error) { h += '<div class="na-hop err"><b>' + esc(fg.label || hp.fgt) + '</b><div class="na-err">' + esc(hp.error) + '</div></div>'; return; }
      h += '<div class="na-hop ' + (hp.action === 'accept' ? 'accept' : 'deny') + '"><b>' + esc(fg.label || hp.fgt) + '</b> ' + esc(hp.srcintf) + ' → ' + esc(hp.dstintf) +
        (hp.gateway && hp.gateway !== '0.0.0.0' ? ' via ' + esc(hp.gateway) : '') + '<div>' + (hp.match ? 'policy <b>#' + esc(hp.policy_id) + '</b>' + (pol ? ' ' + esc(pol.name) : '') : 'no policy matches') + ' · <b>' + esc(hp.action) + '</b></div>' +
        (hp.route ? '<div class="text-muted">route ' + esc(hp.route) + '</div>' : '') + '</div>';
    });
    if (r.scout) h += '<a class="btn btn-sm btn-outline-primary mt-2" href="' + esc(r.scout) + '"><i class="bi bi-search"></i> Validate with Path Diagnostics</a>';
    h += '<div class="small text-muted mt-2">Each FortiGate answers with its own routing and policy lookup; SATOM does not evaluate rules itself.</div>';
    return h;
  }

  var focusSnap = false;
  insp.addEventListener('focusin', function (ev) { if (ev.target.getAttribute('data-k') && !focusSnap) { snapshot(); focusSnap = true; } });
  insp.addEventListener('focusout', function () { focusSnap = false; });
  insp.addEventListener('input', function (ev) {
    var k = ev.target.getAttribute('data-k'); if (!k) return;
    var n = byId(selId); if (!n) return;
    var v = ev.target.value;
    if (v === '') delete n[k]; else n[k] = (k === 'appliance_id') ? Number(v) : v;
    dirty = true; render(); scheduleSave();
  });
  insp.addEventListener('change', function (ev) {
    // Only a select rebuilds the panel (it changes which fields apply); an
    // input's change fires on blur, and rebuilding then would eat the click
    // that moved focus to the next field.
    if (ev.target.tagName === 'SELECT' && ev.target.getAttribute('data-k')) { focusSnap = false; inspect(); }
  });
  insp.addEventListener('click', function (ev) {
    var tb = ev.target.closest && ev.target.closest('[data-trace]');
    if (tb) { var n = byId(selId); openTrace(); traceForm.elements[tb.getAttribute('data-trace')].value = n.ip; return; }
    var tr = ev.target.closest && ev.target.closest('tr.pol'); if (!tr) return;
    var key = tr.getAttribute('data-pol');
    hlPolicy = hlPolicy === key ? null : key;
    if (layer !== 'l3' && layer !== 'l4') setLayer('l3');
    render(); inspect();
  });

  // ---------------------------------------------------------- interaction
  function toWorld(ev) { var r = svg.getBoundingClientRect(); return { x: (ev.clientX - r.left - view.x) / view.k, y: (ev.clientY - r.top - view.y) / view.k }; }
  var drag = null;
  svg.addEventListener('mousedown', function (ev) {
    var g = ev.target.closest && ev.target.closest('.na-node');
    if (g) {
      var id = g.getAttribute('data-id');
      if (linking) {
        if (!linkFrom) { linkFrom = id; selId = id; setStatus('Link from ' + (byId(id).label || id) + ': click the other element'); }
        else if (linkFrom !== id) {
          var dup = layout.edges.some(function (e) { return (e.from === linkFrom && e.to === id) || (e.from === id && e.to === linkFrom); });
          if (!dup) { snapshot(); layout.edges.push({ from: linkFrom, to: id }); linkFrom = null; selId = id; changed(); return; }
          linkFrom = null; selId = id;
        }
        render(); inspect(); return;
      }
      if (traceRes) traceRes = null;
      selId = id; inspect(); render();
      if (EDIT) { var w = toWorld(ev), n = byId(id); drag = { node: n, dx: w.x - n.x, dy: w.y - n.y, moved: false, before: JSON.stringify(layout) }; }
      return;
    }
    drag = { pan: true, sx: ev.clientX - view.x, sy: ev.clientY - view.y, moved: false };
  });
  svg.addEventListener('mousemove', function (ev) {
    if (drag) return;
    var g = ev.target.closest && ev.target.closest('.na-node'), id = g ? g.getAttribute('data-id') : null;
    if (id !== hoverId) { hoverId = id; render(); }
  });
  svg.addEventListener('mouseleave', function () { if (hoverId) { hoverId = null; render(); } });
  window.addEventListener('mousemove', function (ev) {
    if (!drag) return;
    if (drag.pan) { view.x = ev.clientX - drag.sx; view.y = ev.clientY - drag.sy; drag.moved = true; applyView(); return; }
    var w = toWorld(ev);
    drag.node.x = Math.round((w.x - drag.dx) / 10) * 10; drag.node.y = Math.round((w.y - drag.dy) / 10) * 10;
    drag.moved = true; render();
  });
  window.addEventListener('mouseup', function () {
    if (drag && !drag.pan && drag.moved) { undo.push(drag.before); redo = []; syncHist(); changed(); }
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
  function delSelected() {
    if (!selId) return;
    snapshot();
    layout.nodes = layout.nodes.filter(function (n) { return n.id !== selId; });
    layout.edges = layout.edges.filter(function (e) { return e.from !== selId && e.to !== selId; });
    layout.nodes.forEach(function (n) { if (n.gateway === selId) delete n.gateway; });
    selId = null; changed();
  }
  on('naUndo', function () { restore(undo, redo); });
  on('naRedo', function () { restore(redo, undo); });
  on('naDel', delSelected);
  on('naPal', function () { pal.classList.toggle('show'); this.classList.toggle('on'); if (pal.classList.contains('show')) renderPalette(''); });
  on('naLink', function () {
    linking = !linking; linkFrom = null;
    this.classList.toggle('on', linking); vp.classList.toggle('linking', linking);
    setStatus(linking ? 'Link mode: click two elements' : '');
  });
  on('naFit', fit); on('naZoomIn', function () { zoom(1.2); }); on('naZoomOut', function () { zoom(1 / 1.2); });
  function setLayer(l) {
    layer = l;
    Array.prototype.forEach.call(document.querySelectorAll('[data-layer]'), function (b) { b.classList.toggle('on', b.getAttribute('data-layer') === l); });
    render(); inspect();
  }
  Array.prototype.forEach.call(document.querySelectorAll('[data-layer]'), function (b) {
    b.addEventListener('click', function () { setLayer(b.getAttribute('data-layer')); });
  });
  document.addEventListener('keydown', function (ev) {
    var tag = (ev.target.tagName || '').toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select') return;
    if (!document.getElementById('naCanvas')) return;
    var mod = ev.ctrlKey || ev.metaKey;
    if (EDIT && mod && ev.key.toLowerCase() === 'z' && !ev.shiftKey) { ev.preventDefault(); restore(undo, redo); }
    else if (EDIT && mod && (ev.key.toLowerCase() === 'y' || (ev.key.toLowerCase() === 'z' && ev.shiftKey))) { ev.preventDefault(); restore(redo, undo); }
    else if (EDIT && (ev.key === 'Delete' || ev.key === 'Backspace') && selId) { ev.preventDefault(); delSelected(); }
    else if (ev.key === 'Escape') { traceRes = null; hlPolicy = null; selId = null; render(); inspect(); }
  });

  function readLive() {
    if (dirty || saving) { setStatus('Saving first…'); setTimeout(readLive, 1200); return; }
    setStatus('Reading devices…');
    fetch(CFG.liveUrl, { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (j) {
        live = j;
        setStatus('Read ' + Object.keys(j.devices || {}).length + ' device(s), ' + Object.keys(j.probes || {}).length + ' probe(s), ' + flowList().length + ' policy flow(s) at ' + new Date().toLocaleTimeString());
        render(); inspect();
      })
      .catch(function (e) { setStatus('Live read failed: ' + e.message, true); });
  }
  on('naLive', readLive);
  var auto = document.getElementById('naAuto');
  if (auto) auto.addEventListener('change', function () {
    clearInterval(autoTimer); autoTimer = null;
    if (auto.checked) { readLive(); autoTimer = setInterval(function () { if (!document.hidden) readLive(); }, 30000); }
  });

  // ---------------------------------------------------------------- trace
  var traceForm = document.getElementById('naTrace');
  var traceStatus = document.getElementById('naTraceStatus');
  function openTrace() { if (traceForm) traceForm.classList.add('show'); var b = document.getElementById('naTraceBtn'); if (b) b.classList.add('on'); }
  on('naTraceBtn', function () { traceForm.classList.toggle('show'); this.classList.toggle('on'); });
  on('naTraceClear', function () { traceRes = null; if (traceStatus) traceStatus.textContent = ''; render(); inspect(); });
  if (traceForm) {
    traceForm.elements.proto.addEventListener('change', function () { traceForm.elements.port.disabled = traceForm.elements.proto.value === 'icmp'; });
    traceForm.addEventListener('submit', function (ev) {
      ev.preventDefault();
      if (dirty || saving) { traceStatus.textContent = 'Saving first…'; setTimeout(function () { traceForm.requestSubmit(); }, 1200); return; }
      var f = traceForm.elements, q = '?src=' + encodeURIComponent(f.src.value.trim()) + '&dst=' + encodeURIComponent(f.dst.value.trim()) + '&proto=' + f.proto.value + (f.proto.value === 'icmp' ? '' : '&port=' + encodeURIComponent(f.port.value));
      traceStatus.textContent = 'Asking the firewalls…'; traceStatus.className = 'na-status';
      fetch(CFG.traceUrl + q, { credentials: 'same-origin' })
        .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
        .then(function (res) {
          if (!res.ok || !res.j.ok) { traceStatus.textContent = res.j.error || 'Trace failed'; traceStatus.className = 'na-status na-err'; return; }
          traceRes = res.j; selId = null; hlPolicy = null;
          traceStatus.textContent = res.j.verdict.toUpperCase() + ' — ' + res.j.hops.length + ' firewall(s) asked';
          if (!live) readLive();
          render(); inspect();
        })
        .catch(function (e) { traceStatus.textContent = 'Trace failed: ' + e.message; traceStatus.className = 'na-status na-err'; });
    });
  }

  var delForm = document.getElementById('naDelForm');
  if (delForm) delForm.addEventListener('submit', function (ev) {
    if (!window.confirm(delForm.getAttribute('data-confirm') || 'Delete?')) ev.preventDefault();
  });
  window.addEventListener('beforeunload', function (ev) { if (dirty) { save(); ev.preventDefault(); ev.returnValue = ''; } });

  syncHist(); render(); fit(); inspect();
})();
