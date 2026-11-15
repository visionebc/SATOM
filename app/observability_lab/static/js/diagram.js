/* SATOM Observability — diagram editor with the live L1–L7 overlay.
 *
 * Large diagrams: the canvas is a zoomable/pannable viewport (wheel, drag on the
 * background, +/-/1/F keys, minimap), the side panels collapse, and the app menu
 * is hidden on this page. "Expand" on a bound element draws its live children —
 * server policies and their back-ends — from the stored facts; those children are
 * derived on every render and never saved (only the element's `expand` flag is).
 * State is never colour-only: every element carries an icon and a text label for
 * its state, error links are dashed, and the List view is the accessible table of
 * the same data. The overlay reads stored facts (GET /overlay); nothing here
 * talks to a device.
 */
(function () {
  'use strict';
  var root = document.querySelector('.obs-editor');
  if (!root) return;
  var SVGNS = 'http://www.w3.org/2000/svg';
  var svg = document.getElementById('obs-canvas');
  var mini = document.getElementById('obs-minimap');
  var props = document.getElementById('obs-props');
  var statusEl = document.getElementById('obs-status');
  var liveEl = document.getElementById('obs-live');
  var listEl = document.getElementById('obs-list');
  var TYPES = JSON.parse(document.getElementById('obs-node-types').textContent);
  var SOURCES = JSON.parse(document.getElementById('obs-sources').textContent);
  var LAYERS = ['L1', 'L2', 'L3', 'L4', 'L7'];
  var NODE_W = 196, NODE_H = 58, CHILD_W = 156, CHILD_H = 44;
  var STATE_ICON = { ok: 'check-circle-fill', error: 'x-octagon-fill', stale: 'clock-fill', none: 'dash-circle' };
  var STATE_TEXT = { ok: 'OK', error: 'Error', stale: 'Stale', none: 'No data' };
  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  var state = { layout: { nodes: [], edges: [] }, version: 0, overlay: { nodes: {}, edges: {} },
                sel: null, linkMode: false, linkFrom: null, layer: 'all', dirty: false,
                view: { k: 1, x: 0, y: 0 }, auto: true, lastRead: null, mode: 'graph', virtual: [] };
  var objCache = {};

  // ---------------------------------------------------------------- helpers
  function el(tag, attrs, parent) {
    var e = document.createElementNS(SVGNS, tag);
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    if (parent) parent.appendChild(e);
    return e;
  }
  function h(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }
  function say(msg, bad) { statusEl.textContent = msg || ''; statusEl.classList.toggle('bad', !!bad); }
  function markDirty() { state.dirty = true; say('Unsaved changes — Ctrl+S to save'); }
  function nodeById(id) { return state.layout.nodes.find(function (n) { return n.id === id; }); }
  function edgeKey(e) { return e.from + '|' + e.to; }
  function newId(type) {
    var i = 1, id;
    do { id = type.replace(/[^a-z0-9]/gi, '') + '-' + i++; } while (nodeById(id));
    return id;
  }
  var glyphs = {};
  function glyph(name) {  // Bootstrap Icons code point, so the SVG draws the same icon
    if (glyphs[name] !== undefined) return glyphs[name];
    var i = document.createElement('i');
    i.className = 'bi bi-' + name; i.style.position = 'absolute'; i.style.visibility = 'hidden';
    document.body.appendChild(i);
    var c = getComputedStyle(i, '::before').content || '';
    document.body.removeChild(i);
    return (glyphs[name] = c.replace(/^["']|["']$/g, ''));
  }
  function clip(s, n) { s = String(s || ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; }

  // ------------------------------------------------------- overlay → state
  var RANK = { error: 4, stale: 3, ok: 2, none: 1 };
  function ovState(ov) {
    if (!ov) return null;
    var layers = state.layer === 'all' ? LAYERS : [state.layer];
    var best = null;
    layers.forEach(function (l) {
      var s = ov.layers[l] ? ov.layers[l].state : 'none';
      if (!best || RANK[s] > RANK[best]) best = s;
    });
    return best;
  }

  // Live children of an expanded element: its server policies and back-ends.
  function policiesOf(ov) {
    if (!ov) return [];
    var l7 = (ov.layers.L7 || {}).objects || {}, l4 = (ov.layers.L4 || {}).objects || {};
    return Object.keys(l7).filter(function (r) { return r.indexOf('policy:') === 0; }).map(function (r) {
      var o = l7[r], p4 = l4[r] || {};
      return { ref: r, name: r.slice(7), status: o.status, listen: p4.listen, backends: o.backends || [],
               sessions: o.sessions, pool: o.server_pool };
    });
  }
  // Children are laid out as a grid of columns UNDER their element (a long
  // single column made 50 policies unreadable), most severe first, joined to the
  // element by a tree connector (one bus, one line per column).
  var CELL_W = CHILD_W + 34, ROW_H = CHILD_H + 10, SEV = { error: 0, stale: 1, none: 2, ok: 3 };
  function policyState(p) {
    if (!p.backends.length) return 'none';
    var down = p.backends.filter(function (b) { return b.health === 'down'; }).length;
    return down === p.backends.length ? 'error' : (down ? 'stale' : 'ok');
  }
  function buildVirtual() {
    var out = [], groups = [];
    state.layout.nodes.forEach(function (n) {
      if (!n.expand) return;
      var pols = policiesOf(state.overlay.nodes[n.id]);
      var single = n.object_ref && n.object_ref.indexOf('policy:') === 0;
      var rows = [], summary;
      if (single) {  // bound to one policy: its back-ends directly
        (pols[0] ? pols[0].backends : []).forEach(function (b, i) { rows.push({ b: b, pol: pols[0], i: i }); });
        var dn = rows.filter(function (r) { return r.b.health === 'down'; }).length;
        summary = rows.length + ' back-ends · ' + dn + ' down';
      } else {
        var enabled = pols.filter(function (p) { return p.status === 'enable'; });
        enabled.forEach(function (p) { p.st = policyState(p); });
        enabled.sort(function (a, b) { return SEV[a.st] - SEV[b.st] || a.name.localeCompare(b.name); });
        var cnt = { error: 0, stale: 0, ok: 0, none: 0 };
        enabled.forEach(function (p) { cnt[p.st]++; });
        var shown = n.filter === 'problems' ? enabled.filter(function (p) { return p.st === 'error' || p.st === 'stale'; }) : enabled;
        shown.forEach(function (p) {
          rows.push({ pol: p });
          if (n.expandPolicies && n.expandPolicies[p.ref]) p.backends.forEach(function (b, i) { rows.push({ b: b, pol: p, i: i, nested: true }); });
        });
        summary = enabled.length + ' enabled policies · ' + cnt.error + ' all down · ' + cnt.stale + ' some down · ' +
                  cnt.ok + ' OK' + (pols.length > enabled.length ? ' · ' + (pols.length - enabled.length) + ' disabled hidden' : '') +
                  (n.filter === 'problems' ? '  —  showing problems only' : '');
      }
      if (!rows.length) { groups.push({ parent: n, cols: [], summary: summary + (rows.length ? '' : '  —  nothing to show'), y0: n.y + NODE_H / 2 + 70 }); return; }
      var cols = Math.max(1, Math.min(8, Math.ceil(Math.sqrt(rows.length / 1.6))));
      var per = Math.ceil(rows.length / cols), colItems = [], cur = [];
      rows.forEach(function (r) {  // never split a policy from its own back-ends at a column top
        if (cur.length >= per && !r.nested) { colItems.push(cur); cur = []; }
        cur.push(r);
      });
      if (cur.length) colItems.push(cur);
      var x0 = n.x - (colItems.length * CELL_W) / 2 + CELL_W / 2, y0 = n.y + NODE_H / 2 + 70;
      var g = { parent: n, cols: [], summary: summary, y0: y0 };
      colItems.forEach(function (items, ci) {
        var cx = x0 + ci * CELL_W, col = { x: cx, items: [] };
        items.forEach(function (r, ri) {
          var y = y0 + ri * ROW_H, v;
          if (r.b) {
            v = backendNode(r.pol, r.b, r.i, single ? n.id : 'v:' + n.id + ':' + r.pol.ref);
            v.x = cx + (r.nested ? 14 : 0); v.y = y; v.grand = n.id;
          } else {
            var p = r.pol;
            v = { id: 'v:' + n.id + ':' + p.ref, parent: n.id, kind: 'policy', x: cx, y: y,
                  label: p.name, sub: (p.listen || '') + (p.pool ? ' · ' + p.pool : ''), st: p.st,
                  stText: { ok: 'all back-ends up', error: 'all back-ends down', stale: 'some back-ends down', none: 'no back-ends read' }[p.st],
                  data: p, src: n.source_id };
          }
          out.push(v); col.items.push(v);
        });
        g.cols.push(col);
      });
      groups.push(g);
    });
    state.virtual = out; state.groups = groups;
  }
  function backendNode(pol, b, i, parentId) {
    var down = b.health === 'down', nohc = b.health === 'no health check';
    return { id: parentId + ':b:' + (b.address || '?') + ':' + b.port + ':' + i, parent: parentId, kind: 'backend',
             label: (b.address || '?') + ':' + (b.port || ''), sub: (b.pool || pol.pool || '') + (b.backup ? ' · backup' : ''),
             st: down ? 'error' : (nohc ? 'none' : 'ok'), stText: down ? 'DOWN' : (nohc ? 'no health check' : 'UP'),
             data: b, policy: pol };
  }
  function drawGroups() {
    (state.groups || []).forEach(function (g) {
      var n = g.parent, busY = g.y0 - 30;
      var t = el('text', { x: n.x, y: busY - 10, 'class': 'obs-group-summary' }, gEdges);
      t.textContent = g.summary;
      if (!g.cols.length) return;
      el('path', { d: 'M' + n.x + ',' + (n.y + NODE_H / 2) + ' V' + busY, 'class': 'obs-tree' }, gEdges);
      var lx = g.cols[0].x - CHILD_W / 2 - 10, rx = g.cols[g.cols.length - 1].x - CHILD_W / 2 - 10;
      el('path', { d: 'M' + Math.min(lx, n.x) + ',' + busY + ' H' + Math.max(rx, n.x), 'class': 'obs-tree' }, gEdges);
      g.cols.forEach(function (c) {
        var vx = c.x - CHILD_W / 2 - 10, last = c.items[c.items.length - 1];
        el('path', { d: 'M' + vx + ',' + busY + ' V' + last.y, 'class': 'obs-tree' }, gEdges);
        c.items.forEach(function (v) {
          el('path', { d: 'M' + vx + ',' + v.y + ' H' + (v.x - CHILD_W / 2), 'class': 'obs-tree' + (v.st === 'error' ? ' st-error' : '') }, gEdges);
        });
      });
    });
  }
  function tidy() {  // left-to-right layering by the links, generous spacing
    var nodes = state.layout.nodes, lvl = {};
    nodes.forEach(function (n) { lvl[n.id] = 0; });
    for (var i = 0; i < nodes.length; i++) {
      var changed = false;
      state.layout.edges.forEach(function (e) {
        if (lvl[e.to] < lvl[e.from] + 1 && lvl[e.from] + 1 < nodes.length) { lvl[e.to] = lvl[e.from] + 1; changed = true; }
      });
      if (!changed) break;
    }
    var per = {};
    nodes.forEach(function (n) { (per[lvl[n.id]] = per[lvl[n.id]] || []).push(n); });
    Object.keys(per).forEach(function (l) {
      per[l].forEach(function (n, j) { n.x = 160 + l * (NODE_W + 120); n.y = 160 + (j - (per[l].length - 1) / 2) * (NODE_H + 90); });
    });
    markDirty(); render(); fit();
  }

  // ------------------------------------------------------------ viewport
  var vp, gEdges, gNodes;
  function applyView() {
    if (vp) vp.setAttribute('transform', 'translate(' + state.view.x + ',' + state.view.y + ') scale(' + state.view.k + ')');
    document.getElementById('obs-zoom-100').textContent = Math.round(state.view.k * 100) + '%';
    drawMinimap();
  }
  function toWorld(ev) {
    var r = svg.getBoundingClientRect();
    return { x: (ev.clientX - r.left - state.view.x) / state.view.k, y: (ev.clientY - r.top - state.view.y) / state.view.k };
  }
  function zoomAt(factor, cx, cy) {
    var r = svg.getBoundingClientRect();
    if (cx === undefined) { cx = r.width / 2; cy = r.height / 2; }
    var k = Math.max(0.15, Math.min(3, state.view.k * factor));
    state.view.x = cx - (cx - state.view.x) * k / state.view.k;
    state.view.y = cy - (cy - state.view.y) * k / state.view.k;
    state.view.k = k; applyView();
  }
  function bounds() {
    var all = state.layout.nodes.concat(state.virtual);
    if (!all.length) return { x: 0, y: 0, w: 800, h: 500 };
    var x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    all.forEach(function (n) {
      x0 = Math.min(x0, n.x - NODE_W / 2); y0 = Math.min(y0, n.y - NODE_H / 2);
      x1 = Math.max(x1, n.x + NODE_W / 2); y1 = Math.max(y1, n.y + NODE_H / 2 + 14);
    });
    return { x: x0, y: y0, w: x1 - x0, h: y1 - y0 };
  }
  function fit() {
    var r = svg.getBoundingClientRect(), b = bounds(), pad = 48;
    var k = Math.max(0.15, Math.min(1.25, Math.min((r.width - pad * 2) / b.w, (r.height - pad * 2) / b.h)));
    state.view = { k: k, x: (r.width - b.w * k) / 2 - b.x * k, y: (r.height - b.h * k) / 2 - b.y * k };
    applyView();
  }
  function drawMinimap() {
    if (!mini) return;
    while (mini.firstChild) mini.removeChild(mini.firstChild);
    var b = bounds(), r = svg.getBoundingClientRect();
    var vx = -state.view.x / state.view.k, vy = -state.view.y / state.view.k;
    var vw = r.width / state.view.k, vh = r.height / state.view.k;
    var x0 = Math.min(b.x, vx), y0 = Math.min(b.y, vy);
    var x1 = Math.max(b.x + b.w, vx + vw), y1 = Math.max(b.y + b.h, vy + vh);
    mini.setAttribute('viewBox', [x0 - 20, y0 - 20, (x1 - x0) + 40, (y1 - y0) + 40].join(' '));
    state.layout.nodes.concat(state.virtual).forEach(function (n) {
      var st = n.st || ovState(state.overlay.nodes[n.id]) || 'plain';
      el('rect', { x: n.x - NODE_W / 2, y: n.y - NODE_H / 2, width: NODE_W, height: NODE_H, rx: 8, 'class': 'mm-node st-' + st }, mini);
    });
    el('rect', { x: vx, y: vy, width: vw, height: vh, 'class': 'mm-view' }, mini);
  }
  mini.addEventListener('click', function (ev) {
    var pt = mini.createSVGPoint(); pt.x = ev.clientX; pt.y = ev.clientY;
    var w = pt.matrixTransform(mini.getScreenCTM().inverse()), r = svg.getBoundingClientRect();
    state.view.x = r.width / 2 - w.x * state.view.k; state.view.y = r.height / 2 - w.y * state.view.k; applyView();
  });

  // ----------------------------------------------------------------- render
  function render() {
    buildVirtual();
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    var defs = el('defs', {}, svg);
    var pat = el('pattern', { id: 'obs-grid', width: 24, height: 24, patternUnits: 'userSpaceOnUse' }, defs);
    el('circle', { cx: 1, cy: 1, r: 1, 'class': 'obs-grid-dot' }, pat);
    var bg = el('rect', { x: -50000, y: -50000, width: 100000, height: 100000, fill: 'url(#obs-grid)', 'class': 'obs-bg' });
    vp = el('g', {}, svg); vp.appendChild(bg);
    gEdges = el('g', {}, vp); gNodes = el('g', {}, vp);
    state.layout.edges.forEach(drawEdge);
    drawGroups();
    state.layout.nodes.forEach(drawNode);
    state.virtual.forEach(drawChild);
    applyView();
    if (state.mode === 'list') renderList();
  }
  function drawLine(a, b, cls) {
    // orthogonal-ish connector: out of the right side of a, into the left side of b
    var x1 = a.x + (b.x >= a.x ? NODE_W / 2 : -NODE_W / 2), x2 = b.x - (b.x >= a.x ? (b.kind ? CHILD_W : NODE_W) / 2 : -NODE_W / 2);
    var mx = (x1 + x2) / 2;
    return el('path', { d: 'M' + x1 + ',' + a.y + ' C' + mx + ',' + a.y + ' ' + mx + ',' + b.y + ' ' + x2 + ',' + b.y, 'class': cls }, gEdges);
  }
  function drawEdge(e) {
    var a = nodeById(e.from), b = nodeById(e.to);
    if (!a || !b) return;
    var st = ovState(state.overlay.edges[edgeKey(e)]);
    var cls = 'obs-edge' + (st ? ' st-' + st : '') + (state.sel === 'e:' + edgeKey(e) ? ' sel' : '');
    drawLine(a, b, cls);
    var hit = drawLine(a, b, 'obs-edge-hit');
    hit.addEventListener('click', function (ev) { ev.stopPropagation(); select('e:' + edgeKey(e)); });
    if (e.label || e.object_ref || st) {
      var t = el('text', { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 - 8, 'class': 'obs-edge-label' }, gEdges);
      t.textContent = (st && st !== 'ok' ? '[' + STATE_TEXT[st] + '] ' : '') + (e.label || e.object_ref || '');
    }
  }
  function drawNode(n) {
    var st = ovState(state.overlay.nodes[n.id]);
    var t = TYPES[n.type] || { label: n.type, icon: 'square' };
    var full = n.label || t.label;
    var g = el('g', { transform: 'translate(' + n.x + ',' + n.y + ')', tabindex: 0, role: 'button', 'data-id': n.id,
      'aria-label': full + ', ' + t.label + (st ? ', state ' + STATE_TEXT[st] : ', not bound'),
      'class': 'obs-node' + (st ? ' st-' + st : '') + (state.sel === 'n:' + n.id ? ' sel' : '') +
               (state.linkFrom === n.id ? ' linking' : '') }, gNodes);
    el('title', {}, g).textContent = full + (st ? ' — ' + STATE_TEXT[st] : '');
    el('rect', { x: -NODE_W / 2, y: -NODE_H / 2, width: NODE_W, height: NODE_H, rx: 10, 'class': 'obs-node-box' }, g);
    el('rect', { x: -NODE_W / 2, y: -NODE_H / 2, width: 5, height: NODE_H, rx: 2, 'class': 'obs-node-bar' }, g);
    el('text', { x: -NODE_W / 2 + 22, y: 1, 'class': 'obs-node-icon' }, g).textContent = glyph(t.icon);
    el('text', { x: -NODE_W / 2 + 42, y: -6, 'class': 'obs-node-label' }, g).textContent = clip(full, 21);
    el('text', { x: -NODE_W / 2 + 42, y: 12, 'class': 'obs-node-sub' }, g).textContent =
      clip(n.ip || (n.object_ref || '') || t.label, 26);
    if (st) {
      el('text', { x: NODE_W / 2 - 14, y: -NODE_H / 2 + 15, 'class': 'obs-state-ico st-' + st }, g).textContent = glyph(STATE_ICON[st]);
    }
    var pols = policiesOf(state.overlay.nodes[n.id]);
    if (pols.length) {  // expand / collapse handle
      var hb = el('g', { transform: 'translate(' + (NODE_W / 2) + ',0)', 'class': 'obs-expand', tabindex: 0, role: 'button',
        'aria-label': (n.expand ? 'Collapse ' : 'Expand ') + full }, g);
      el('circle', { r: 11 }, hb);
      el('text', { y: 1 }, hb).textContent = glyph(n.expand ? 'dash' : 'plus');
      var tg = function (ev) { ev.stopPropagation(); toggleExpand(n); };
      hb.addEventListener('click', tg);
      hb.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') tg(ev); });
      hb.addEventListener('mousedown', function (ev) { ev.stopPropagation(); });
    }
    g.addEventListener('mousedown', function (ev) { startDrag(ev, n); });
    g.addEventListener('click', function (ev) { ev.stopPropagation(); if (state.linkMode) return linkClick(n); select('n:' + n.id); });
    g.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') { if (state.linkMode) linkClick(n); else select('n:' + n.id); } });
    g.addEventListener('dblclick', function (ev) { ev.stopPropagation(); if (pols.length) toggleExpand(n); });
  }
  function drawChild(v) {
    var g = el('g', { transform: 'translate(' + v.x + ',' + v.y + ')', tabindex: 0, role: 'button',
      'aria-label': v.label + ', ' + v.kind + ', ' + v.stText,
      'class': 'obs-child obs-child-' + v.kind + ' st-' + v.st + (state.sel === 'v:' + v.id ? ' sel' : '') }, gNodes);
    el('title', {}, g).textContent = v.label + ' — ' + v.stText + (v.sub ? ' (' + v.sub + ')' : '');
    el('rect', { x: -CHILD_W / 2, y: -CHILD_H / 2, width: CHILD_W, height: CHILD_H, rx: 8, 'class': 'obs-node-box' }, g);
    if (v.kind !== 'note') {
      el('text', { x: -CHILD_W / 2 + 14, y: 1, 'class': 'obs-state-ico st-' + v.st }, g).textContent = glyph(STATE_ICON[v.st] || 'dash-circle');
    }
    el('text', { x: -CHILD_W / 2 + (v.kind === 'note' ? 10 : 28), y: v.sub ? -4 : 4, 'class': 'obs-child-label' }, g).textContent = clip(v.label, 20);
    if (v.sub) el('text', { x: -CHILD_W / 2 + 28, y: 12, 'class': 'obs-node-sub' }, g).textContent =
      clip((v.kind === 'backend' ? v.stText + ' · ' : '') + v.sub, 24);
    if (v.kind === 'policy' && v.data.backends.length) {
      var root_ = nodeById(v.parent), open = root_ && root_.expandPolicies && root_.expandPolicies[v.data.ref];
      var hb = el('g', { transform: 'translate(' + (CHILD_W / 2) + ',0)', 'class': 'obs-expand', tabindex: 0, role: 'button',
        'aria-label': (open ? 'Hide' : 'Show') + ' back-ends of ' + v.label }, g);
      el('circle', { r: 10 }, hb);
      el('text', { y: 1 }, hb).textContent = glyph(open ? 'dash' : 'plus');
      var tg = function (ev) {
        ev.stopPropagation();
        root_.expandPolicies = root_.expandPolicies || {};
        root_.expandPolicies[v.data.ref] = !open; render();
      };
      hb.addEventListener('click', tg);
      hb.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') tg(ev); });
    }
    g.addEventListener('click', function (ev) { ev.stopPropagation(); select('v:' + v.id); });
    g.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') select('v:' + v.id); });
  }
  function toggleExpand(n) {
    if (n.expand) { delete n.expand; delete n.expandPolicies; } else { n.expand = true; }
    markDirty(); render(); fit();
    say(n.expand ? 'Expanded ' + (n.label || n.id) + ' — live children are not saved, only the expanded flag' : 'Collapsed');
  }

  // ------------------------------------------------------------ list view
  function renderList() {
    listEl.innerHTML = '';
    var tbl = h('table', 'table table-sm obs-list-table');
    var head = h('thead'); var hr = h('tr');
    ['Element', 'Type', 'Bound to'].concat(LAYERS).forEach(function (c) { hr.appendChild(h('th', null, c)); });
    head.appendChild(hr); tbl.appendChild(head);
    var body = h('tbody');
    state.layout.nodes.forEach(function (n) {
      var ov = state.overlay.nodes[n.id], tr = h('tr');
      var a = h('button', 'btn btn-link btn-sm p-0', n.label || n.id); a.type = 'button';
      a.addEventListener('click', function () { setMode('graph'); select('n:' + n.id); centerOn(n); });
      var td = h('td'); td.appendChild(a); tr.appendChild(td);
      tr.appendChild(h('td', null, (TYPES[n.type] || {}).label || n.type));
      tr.appendChild(h('td', 'small', ov ? ov.source.name + (n.object_ref ? ' · ' + n.object_ref : '') : '—'));
      LAYERS.forEach(function (l) {
        var s = ov && ov.layers[l] ? ov.layers[l].state : null, c = h('td');
        if (s) c.appendChild(stateChip(s)); else c.textContent = '—';
        tr.appendChild(c);
      });
      body.appendChild(tr);
      if (n.expand) state.virtual.filter(function (v) { return v.parent === n.id || v.grand === n.id; }).forEach(function (v) {
        var r2 = h('tr', 'obs-list-child');
        r2.appendChild(h('td', null, (v.kind === 'backend' ? '↳↳ ' : '↳ ') + v.label));
        r2.appendChild(h('td', null, v.kind));
        r2.appendChild(h('td', 'small', v.sub || ''));
        var c = h('td'); c.colSpan = LAYERS.length; c.appendChild(stateChip(v.st, v.stText)); r2.appendChild(c);
        body.appendChild(r2);
      });
    });
    tbl.appendChild(body); listEl.appendChild(tbl);
    if (!state.layout.nodes.length) listEl.appendChild(h('p', 'text-muted p-3', 'No elements yet.'));
  }
  function stateChip(s, text) {
    var c = h('span', 'obs-chip st-' + s);
    var i = h('i', 'bi bi-' + STATE_ICON[s]); i.setAttribute('aria-hidden', 'true');
    c.appendChild(i); c.appendChild(document.createTextNode(' ' + (text || STATE_TEXT[s])));
    return c;
  }
  function setMode(m) {
    state.mode = m;
    listEl.hidden = m !== 'list'; svg.style.visibility = m === 'list' ? 'hidden' : 'visible';
    document.getElementById('obs-view-graph').classList.toggle('active', m === 'graph');
    document.getElementById('obs-view-list').classList.toggle('active', m === 'list');
    document.getElementById('obs-view-graph').setAttribute('aria-pressed', m === 'graph');
    document.getElementById('obs-view-list').setAttribute('aria-pressed', m === 'list');
    if (m === 'list') renderList();
  }
  document.getElementById('obs-view-graph').addEventListener('click', function () { setMode('graph'); });
  document.getElementById('obs-view-list').addEventListener('click', function () { setMode('list'); });
  function centerOn(n) {
    var r = svg.getBoundingClientRect();
    state.view.x = r.width / 2 - n.x * state.view.k; state.view.y = r.height / 2 - n.y * state.view.k; applyView();
  }

  // --------------------------------------------------------- interactions
  var drag = null, pan = null;
  function startDrag(ev, n) {
    if (state.linkMode || ev.button !== 0) return;
    ev.stopPropagation();
    var w = toWorld(ev); drag = { n: n, dx: w.x - n.x, dy: w.y - n.y, moved: false };
  }
  svg.addEventListener('mousedown', function (ev) {
    if (ev.button !== 0) return;
    pan = { sx: ev.clientX, sy: ev.clientY, x: state.view.x, y: state.view.y, moved: false };
    svg.classList.add('panning');
  });
  window.addEventListener('mousemove', function (ev) {
    if (drag) {
      var w = toWorld(ev);
      drag.n.x = Math.round((w.x - drag.dx) / 4) * 4; drag.n.y = Math.round((w.y - drag.dy) / 4) * 4;
      drag.moved = true; render();
    } else if (pan) {
      state.view.x = pan.x + ev.clientX - pan.sx; state.view.y = pan.y + ev.clientY - pan.sy;
      if (Math.abs(ev.clientX - pan.sx) + Math.abs(ev.clientY - pan.sy) > 3) pan.moved = true;
      applyView();
    }
  });
  window.addEventListener('mouseup', function () {
    if (drag && drag.moved) markDirty();
    if (pan && !pan.moved) select(null);
    drag = null; pan = null; svg.classList.remove('panning');
  });
  svg.addEventListener('wheel', function (ev) {
    ev.preventDefault();
    var r = svg.getBoundingClientRect();
    zoomAt(ev.deltaY < 0 ? 1.12 : 1 / 1.12, ev.clientX - r.left, ev.clientY - r.top);
  }, { passive: false });
  function linkClick(n) {
    if (!state.linkFrom) { state.linkFrom = n.id; render(); say('Now choose the second element'); return; }
    if (state.linkFrom !== n.id) {
      var a = state.linkFrom, b = n.id;
      var dup = state.layout.edges.some(function (e) { return (e.from === a && e.to === b) || (e.from === b && e.to === a); });
      if (!dup) { state.layout.edges.push({ from: a, to: b }); markDirty(); }
    }
    state.linkFrom = null; render();
  }
  function toggleLink() {
    state.linkMode = !state.linkMode; state.linkFrom = null;
    var b = document.getElementById('obs-linkmode');
    b.classList.toggle('active', state.linkMode); b.setAttribute('aria-pressed', state.linkMode);
    say(state.linkMode ? 'Link mode: choose two elements (Esc to stop)' : '');
    render();
  }
  document.getElementById('obs-linkmode').addEventListener('click', toggleLink);
  document.querySelectorAll('.obs-pal-btn').forEach(function (b) {
    b.addEventListener('click', function () {
      var type = b.getAttribute('data-type'), r = svg.getBoundingClientRect();
      var cx = (r.width / 2 - state.view.x) / state.view.k, cy = (r.height / 2 - state.view.y) / state.view.k;
      var n = { id: newId(type), type: type, x: Math.round(cx + (Math.random() - 0.5) * 80), y: Math.round(cy + (Math.random() - 0.5) * 60) };
      state.layout.nodes.push(n); markDirty(); select('n:' + n.id);
    });
  });
  document.querySelectorAll('#obs-layers button').forEach(function (b) {
    b.addEventListener('click', function () {
      document.querySelectorAll('#obs-layers button').forEach(function (x) { x.classList.remove('active'); x.setAttribute('aria-pressed', 'false'); });
      b.classList.add('active'); b.setAttribute('aria-pressed', 'true');
      state.layer = b.getAttribute('data-layer'); render(); showProps();
    });
  });
  document.getElementById('obs-zoom-in').addEventListener('click', function () { zoomAt(1.2); });
  document.getElementById('obs-zoom-out').addEventListener('click', function () { zoomAt(1 / 1.2); });
  document.getElementById('obs-zoom-100').addEventListener('click', function () { zoomAt(1 / state.view.k); });
  document.getElementById('obs-fit').addEventListener('click', fit);
  document.getElementById('obs-tidy').addEventListener('click', tidy);
  document.getElementById('obs-full').addEventListener('click', function () {
    if (document.fullscreenElement) document.exitFullscreen(); else root.requestFullscreen && root.requestFullscreen();
  });
  document.addEventListener('fullscreenchange', function () { setTimeout(fit, 50); });
  function panelToggle(btnId, panelId, cls) {
    var b = document.getElementById(btnId), body = document.getElementById('obs-body');
    b.addEventListener('click', function () {
      var collapsed = body.classList.toggle(cls);
      b.setAttribute('aria-expanded', !collapsed);
      try { localStorage.setItem('obs.' + cls, collapsed ? '1' : ''); } catch (e) { /* private mode */ }
      setTimeout(applyView, 10);
    });
    try { if (localStorage.getItem('obs.' + cls)) { body.classList.add(cls); b.setAttribute('aria-expanded', 'false'); } } catch (e) { /* ignore */ }
  }
  panelToggle('obs-pal-toggle', 'obs-palette', 'pal-collapsed');
  panelToggle('obs-side-toggle', 'obs-side', 'side-collapsed');

  document.addEventListener('keydown', function (ev) {
    var tag = document.activeElement && document.activeElement.tagName;
    if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 's') { ev.preventDefault(); save(); return; }
    if (/INPUT|TEXTAREA|SELECT/.test(tag)) return;
    if (ev.key === 'Escape') { if (state.linkMode) toggleLink(); else select(null); return; }
    if (ev.key === '+' || ev.key === '=') { zoomAt(1.2); return; }
    if (ev.key === '-') { zoomAt(1 / 1.2); return; }
    if (ev.key === '1') { zoomAt(1 / state.view.k); return; }
    if (ev.key.toLowerCase() === 'f') { fit(); return; }
    if (ev.key.toLowerCase() === 'r') { refreshOverlay(); return; }
    if (ev.key.toLowerCase() === 'l') { toggleLink(); return; }
    if (ev.key.toLowerCase() === 't') { tidy(); return; }
    if (ev.key === 'Delete' || ev.key === 'Backspace') { if (state.sel && state.sel.indexOf('v:') !== 0) { ev.preventDefault(); removeSelected(); } return; }
    if (/^Arrow/.test(ev.key) && state.sel && state.sel.indexOf('n:') === 0) {  // keyboard alternative to dragging
      var n = nodeById(state.sel.slice(2)), step = ev.shiftKey ? 48 : 8;
      if (!n) return;
      ev.preventDefault();
      if (ev.key === 'ArrowLeft') n.x -= step; if (ev.key === 'ArrowRight') n.x += step;
      if (ev.key === 'ArrowUp') n.y -= step; if (ev.key === 'ArrowDown') n.y += step;
      markDirty(); render();
      var f = svg.querySelector('[data-id="' + n.id + '"]'); if (f) f.focus();
    }
  });
  function removeSelected() {
    if (!state.sel) return;
    if (state.sel.indexOf('n:') === 0) {
      var id = state.sel.slice(2);
      state.layout.nodes = state.layout.nodes.filter(function (n) { return n.id !== id; });
      state.layout.edges = state.layout.edges.filter(function (e) { return e.from !== id && e.to !== id; });
    } else if (state.sel.indexOf('e:') === 0) {
      var k = state.sel.slice(2);
      state.layout.edges = state.layout.edges.filter(function (e) { return edgeKey(e) !== k; });
    }
    state.sel = null; markDirty(); render(); showProps();
  }
  function select(s) { state.sel = s; render(); showProps(); }

  // -------------------------------------------- properties + live panel
  function field(label, input) {
    var w = h('div', 'mb-2'), id = 'f-' + Math.random().toString(36).slice(2);
    var l = h('label', 'form-label small mb-0', label); l.htmlFor = id; input.id = id;
    w.appendChild(l); w.appendChild(input); return w;
  }
  function textInput(obj, key, ph) {
    var i = h('input', 'form-control form-control-sm'); i.value = obj[key] || ''; i.placeholder = ph || '';
    i.addEventListener('change', function () { if (i.value) obj[key] = i.value; else delete obj[key]; markDirty(); render(); });
    return i;
  }
  function sourceSelect(obj) {
    var s = h('select', 'form-select form-select-sm');
    s.appendChild(new Option('— not bound —', ''));
    SOURCES.forEach(function (src) { s.appendChild(new Option(src.name + ' (' + src.kind + ')', src.id)); });
    s.value = obj.source_id || '';
    s.addEventListener('change', function () {
      if (s.value) obj.source_id = parseInt(s.value, 10); else { delete obj.source_id; delete obj.object_ref; }
      markDirty(); render(); showProps();
    });
    return s;
  }
  function objectSelect(obj) {
    var s = h('select', 'form-select form-select-sm');
    s.appendChild(new Option('— whole source —', ''));
    if (!obj.source_id) { s.disabled = true; return s; }
    var fill = function (refs) { refs.forEach(function (r) { s.appendChild(new Option(r, r)); }); s.value = obj.object_ref || ''; };
    if (objCache[obj.source_id]) fill(objCache[obj.source_id]);
    else fetch(root.dataset.objectsUrl.replace(/\/0$/, '/' + obj.source_id), { credentials: 'same-origin' })
      .then(function (r) { return r.json(); }).then(function (refs) { objCache[obj.source_id] = refs; fill(refs); });
    s.addEventListener('change', function () { if (s.value) obj.object_ref = s.value; else delete obj.object_ref; markDirty(); render(); });
    return s;
  }
  function summarize(v) {
    if (Array.isArray(v)) {
      if (!v.length) return '(none)';
      if (typeof v[0] === 'object') return v.length + ' rows';
      return v.join(', ');
    }
    return typeof v === 'object' ? JSON.stringify(v) : String(v);
  }
  function backendTable(list) {
    var t = h('table', 'table table-sm obs-mini-table mb-1'), hr = h('tr');
    ['', 'Back-end', 'Pool', 'Sess.'].forEach(function (c) { hr.appendChild(h('th', null, c)); });
    var th = h('thead'); th.appendChild(hr); t.appendChild(th);
    var tb = h('tbody');
    list.forEach(function (b) {
      var down = b.health === 'down', nohc = b.health === 'no health check', tr = h('tr');
      var c = h('td'); c.appendChild(stateChip(down ? 'error' : (nohc ? 'none' : 'ok'), down ? 'DOWN' : (nohc ? 'no HC' : 'UP'))); tr.appendChild(c);
      tr.appendChild(h('td', 'font-monospace', (b.address || '?') + ':' + (b.port || '')));
      tr.appendChild(h('td', null, (b.pool || '') + (b.backup ? ' (backup)' : '')));
      tr.appendChild(h('td', null, b.sessions == null ? '' : b.sessions));
      tb.appendChild(tr);
    });
    t.appendChild(tb); return t;
  }
  function overlayBlock(ov) {
    var box = h('div', 'obs-ov mt-2');
    if (!ov) { box.appendChild(h('p', 'small text-muted mb-0', 'Bind it to a source to see live data.')); return box; }
    var head = h('div', 'obs-ov-head');
    head.appendChild(h('strong', null, ov.source.name));
    head.appendChild(h('span', 'small text-muted', ' ' + (ov.source.build || ov.source.kind)));
    box.appendChild(head);
    if (!ov.source.tls_verify) box.appendChild(h('div', 'obs-warn small mb-1', 'TLS verification is OFF for this source (operator choice).'));
    var layers = state.layer === 'all' ? ['device'].concat(LAYERS) : [state.layer];
    layers.forEach(function (l) {
      var L = ov.layers[l]; if (!L) return;
      var objs = Object.keys(L.objects);
      var sec = h('details', 'obs-ov-layer'); sec.open = l !== 'device' && (state.layer !== 'all' || objs.length <= 6);
      var sum = h('summary', 'obs-ov-title');
      sum.appendChild(h('span', 'obs-ov-name', l === 'device' ? 'Device' : l));
      sum.appendChild(stateChip(L.state));
      sum.appendChild(h('span', 'text-muted small ms-auto', objs.length + ' obj' + (L.read_at ? ' · ' + L.read_at.slice(11, 16) + ' UTC' : '')));
      sec.appendChild(sum);
      if (L.why) sec.appendChild(h('div', 'small ' + (L.state === 'error' ? 'text-danger' : 'text-muted'), L.why));
      objs.slice(0, 60).forEach(function (o) {
        var row = h('div', 'obs-ov-obj');
        row.appendChild(h('div', 'obs-ov-ref', o));
        Object.keys(L.objects[o]).forEach(function (k) {
          var v = L.objects[o][k];
          if (k === 'backends' && Array.isArray(v)) { row.appendChild(backendTable(v)); return; }
          var line = h('div', 'obs-ov-kv');
          line.appendChild(h('span', 'k', k)); line.appendChild(h('span', 'v', summarize(v)));
          row.appendChild(line);
        });
        sec.appendChild(row);
      });
      if (objs.length > 60) sec.appendChild(h('div', 'small text-muted', '…' + (objs.length - 60) + ' more — see the source page or the List view'));
      box.appendChild(sec);
    });
    return box;
  }
  function showProps() {
    props.innerHTML = '';
    if (!state.sel) {
      props.appendChild(h('p', 'text-muted small mb-2', 'Select an element or a link.'));
      var ul = h('ul', 'small text-muted obs-help');
      ['Wheel or +/- to zoom, drag the background to pan, F to fit, 1 for 100 %.',
       'Expand (the + on an element) lists its server policies under it, worst first; + on a policy shows its back-ends.',
       'Arrow keys move the selected element (Shift = bigger steps).',
       'L starts a link, Delete removes, Ctrl+S saves, R re-reads the overlay.'].forEach(function (t) { ul.appendChild(h('li', null, t)); });
      props.appendChild(ul);
      return;
    }
    var del = h('button', 'btn btn-sm btn-outline-danger mt-1', 'Remove'); del.type = 'button';
    del.addEventListener('click', removeSelected);
    if (state.sel.indexOf('v:') === 0) {
      var v = state.virtual.find(function (x) { return 'v:' + x.id === state.sel; }); if (!v) return;
      props.appendChild(h('div', 'obs-props-title', (v.kind === 'backend' ? 'Back-end ' : 'Server policy ') + v.label));
      props.appendChild(stateChip(v.st, v.stText));
      if (v.kind === 'policy') {
        props.appendChild(h('div', 'small mt-2', 'Listens on ' + (v.data.listen || '?') + ' · pool ' + (v.data.pool || '?')));
        props.appendChild(backendTable(v.data.backends));
      } else if (v.kind === 'backend') {
        props.appendChild(backendTable([v.data]));
      }
      var pin = h('button', 'btn btn-sm btn-outline-primary mt-2', 'Add to the diagram'); pin.type = 'button';
      pin.addEventListener('click', function () { pinVirtual(v); });
      props.appendChild(pin);
      props.appendChild(h('p', 'small text-muted mt-2', 'Derived from the stored facts; it is redrawn on every refresh and not saved unless added.'));
      return;
    }
    if (state.sel.indexOf('n:') === 0) {
      var n = nodeById(state.sel.slice(2)); if (!n) return;
      props.appendChild(h('div', 'obs-props-title', ((TYPES[n.type] || {}).label || n.type) + ' · ' + n.id));
      var ts = h('select', 'form-select form-select-sm');
      Object.keys(TYPES).forEach(function (k) { ts.appendChild(new Option(TYPES[k].label, k)); });
      ts.value = n.type; ts.addEventListener('change', function () { n.type = ts.value; markDirty(); render(); showProps(); });
      props.appendChild(field('Type', ts));
      props.appendChild(field('Label', textInput(n, 'label')));
      var row = h('div', 'row g-2');
      var c1 = h('div', 'col-6'), c2 = h('div', 'col-6');
      c1.appendChild(field('IP address', textInput(n, 'ip', 'e.g. 192.0.2.82')));
      c2.appendChild(field('Network (CIDR)', textInput(n, 'cidr', 'e.g. 192.0.2.0/24')));
      row.appendChild(c1); row.appendChild(c2); props.appendChild(row);
      props.appendChild(field('Source', sourceSelect(n)));
      props.appendChild(field('Object (optional)', objectSelect(n)));
      props.appendChild(field('Note', textInput(n, 'note')));
      var acts = h('div', 'd-flex gap-2 flex-wrap');
      if (policiesOf(state.overlay.nodes[n.id]).length) {
        var ex = h('button', 'btn btn-sm btn-outline-primary mt-1', n.expand ? 'Collapse children' : 'Expand policies / back-ends'); ex.type = 'button';
        ex.addEventListener('click', function () { toggleExpand(n); showProps(); });
        acts.appendChild(ex);
        if (n.expand && !(n.object_ref || '').startsWith('policy:')) {
          var fl = h('button', 'btn btn-sm btn-outline-secondary mt-1', n.filter === 'problems' ? 'Show all policies' : 'Show problems only'); fl.type = 'button';
          fl.setAttribute('aria-pressed', n.filter === 'problems');
          fl.addEventListener('click', function () { if (n.filter === 'problems') delete n.filter; else n.filter = 'problems'; render(); fit(); showProps(); });
          acts.appendChild(fl);
        }
      }
      acts.appendChild(del); props.appendChild(acts);
      props.appendChild(overlayBlock(state.overlay.nodes[n.id]));
    } else {
      var k = state.sel.slice(2);
      var e = state.layout.edges.find(function (x) { return edgeKey(x) === k; }); if (!e) return;
      props.appendChild(h('div', 'obs-props-title', 'Link ' + e.from + ' — ' + e.to));
      props.appendChild(field('Label', textInput(e, 'label', 'e.g. port2 / VLAN 66 / HTTPS')));
      props.appendChild(field('Source', sourceSelect(e)));
      props.appendChild(field('Object (e.g. if:port1)', objectSelect(e)));
      props.appendChild(del);
      props.appendChild(overlayBlock(state.overlay.edges[k]));
    }
  }
  function pinVirtual(v) {
    var src = v.kind === 'policy' ? v.src : (nodeById(v.grand || v.parent) || {}).source_id;
    var n = { id: newId(v.kind === 'policy' ? 'policy' : 'server'), type: v.kind === 'policy' ? 'load-balancer' : 'server',
              x: Math.round(v.x), y: Math.round(v.y + 90), label: v.label };
    if (src) { n.source_id = src; n.object_ref = v.kind === 'policy' ? v.data.ref : v.policy.ref; }
    if (v.kind === 'backend' && /^\d+\.\d+\.\d+\.\d+$/.test(v.data.address || '')) n.ip = v.data.address;
    state.layout.nodes.push(n);
    var from = v.kind === 'policy' ? v.parent : (v.grand || v.parent);
    if (nodeById(from)) state.layout.edges.push({ from: from, to: n.id });
    markDirty(); select('n:' + n.id); refreshOverlay();
  }

  // ------------------------------------------------------------------ I/O
  function updateLive() {
    var newest = null, stale = false, err = false;
    function scan(ov) {
      if (!ov) return;
      Object.keys(ov.layers).forEach(function (l) {
        var L = ov.layers[l];
        if (L.read_at && (!newest || L.read_at > newest)) newest = L.read_at;
        if (L.state === 'stale') stale = true; if (L.state === 'error') err = true;
      });
    }
    Object.keys(state.overlay.nodes).forEach(function (k) { scan(state.overlay.nodes[k]); });
    Object.keys(state.overlay.edges).forEach(function (k) { scan(state.overlay.edges[k]); });
    liveEl.className = 'obs-live';
    if (!newest) { liveEl.textContent = 'No live data — bind elements to a source'; liveEl.classList.add('none'); return; }
    var mins = Math.max(0, Math.round((Date.now() - Date.parse(newest.replace(' ', 'T') + 'Z')) / 60000));
    liveEl.innerHTML = '';
    var i = h('i', 'bi bi-' + (err ? 'x-octagon-fill' : (stale ? 'clock-fill' : 'broadcast'))); i.setAttribute('aria-hidden', 'true');
    liveEl.appendChild(i);
    liveEl.appendChild(document.createTextNode(' ' + (err ? 'Read errors' : (stale ? 'Stale' : 'Live')) +
      ' · data read ' + newest.slice(11, 16) + ' UTC (' + (mins < 1 ? 'just now' : mins + ' min ago') + ')'));
    liveEl.classList.add(err ? 'error' : (stale ? 'stale' : 'ok'));
  }
  function load() {
    return fetch(root.dataset.layoutUrl, { credentials: 'same-origin' }).then(function (r) { return r.json(); })
      .then(function (j) {
        state.layout = j.layout || { nodes: [], edges: [] };
        state.layout.nodes = state.layout.nodes || []; state.layout.edges = state.layout.edges || [];
        state.version = j.version; render(); fit(); showProps(); return refreshOverlay(true);
      });
  }
  function refreshOverlay(first) {
    return fetch(root.dataset.overlayUrl, { credentials: 'same-origin' }).then(function (r) { return r.json(); })
      .then(function (ov) {
        state.overlay = ov; render(); if (first) fit(); showProps(); updateLive();
        if (!state.dirty) say('');
      })
      .catch(function () { say('The overlay could not be read', true); });
  }
  function save() {
    var body = { layout: state.layout, version: state.version, name: document.getElementById('obs-name').value };
    say('Saving…');
    return fetch(root.dataset.saveUrl, { method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': root.dataset.csrf }, body: JSON.stringify(body) })
      .then(function (r) { return r.json().then(function (j) { return { st: r.status, j: j }; }); })
      .then(function (res) {
        if (res.j.ok) { state.version = res.j.version; state.dirty = false; say('Saved (version ' + state.version + ')'); refreshOverlay(); }
        else say('Not saved: ' + (res.j.errors || ['error']).join('; '), true);
      }).catch(function () { say('Not saved: the server did not answer', true); });
  }
  document.getElementById('obs-save').addEventListener('click', save);
  document.getElementById('obs-refresh').addEventListener('click', function () { refreshOverlay(); });
  document.getElementById('obs-name').addEventListener('change', markDirty);
  var autoBtn = document.getElementById('obs-auto');
  autoBtn.addEventListener('click', function () {
    state.auto = !state.auto;
    autoBtn.setAttribute('aria-pressed', state.auto);
    autoBtn.innerHTML = state.auto ? '<i class="bi bi-pause-fill" aria-hidden="true"></i> Auto' : '<i class="bi bi-play-fill" aria-hidden="true"></i> Auto';
    say(state.auto ? 'Auto refresh on (every 60 s)' : 'Auto refresh paused');
  });
  setInterval(function () {  // stop work while the tab is hidden or the user is editing
    if (state.auto && document.visibilityState === 'visible' && !drag && !pan) refreshOverlay(); else updateLive();
  }, 60000);
  window.addEventListener('resize', function () { applyView(); });
  window.addEventListener('beforeunload', function (ev) { if (state.dirty) { ev.preventDefault(); ev.returnValue = ''; } });
  if (reduceMotion) document.documentElement.classList.add('obs-reduce-motion');
  load();
})();
