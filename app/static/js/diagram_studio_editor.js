/* diagram_studio_editor.js — Diagram Studio editor: canvas interaction.
 *
 * Selection, move (snap to grid + smart guides), resize (8 handles, Shift
 * keeps the aspect), rotate (Shift snaps to 15°), connectors (drag from a
 * port, re-attach ends, waypoints, labels), in-place text editing through a
 * textarea laid over the canvas, clipboard, group, z-order, align, auto
 * layout, keyboard shortcuts, save with an optimistic lock + autosave.
 * Panels (inspector, layers, pages, library, search, history) live in
 * diagram_studio_panels.js and talk to the Editor object built here.
 *
 * The satom.diagram/1 document in DS.Store is the only state that is saved.
 */
(function () {
  'use strict';
  var DS = window.DS;
  var root = document.getElementById('dsEditor');
  if (!root || root.dataset.dsBooted) return;
  root.dataset.dsBooted = '1';
  var G = DS.geom, R = DS.routing, M = DS.model, s = DS.s;

  var cfg = DS.config();
  var api = DS.Api(cfg);
  var canEdit = !!cfg.mayEdit;
  var svg = document.getElementById('dsCanvas');
  var wrap = document.getElementById('dsCanvasWrap');
  var textEdit = document.getElementById('dsTextEdit');
  var statusEl = document.getElementById('dsSaveStatus');

  var diagram = cfg.diagram || { id: 0, name: (cfg.doc && cfg.doc.name) || 'Untitled diagram', version: 0 };
  var store = new DS.Store(cfg.doc || null, { limit: 500 });
  var r = new DS.Renderer(svg, {
    symbolUrl: function (lib, sym) { return api.symbolSvg(lib, sym); },
    decorate: function (e) { return (sel.els.has(e.id) ? 'ds-selected' : ''); }
  });

  var ed = DS.editor = {
    cfg: cfg, api: api, store: store, r: r, canEdit: canEdit, diagram: diagram,
    sel: { els: new Set(), conns: new Set() },
    settings: { snap: true, grid: 10, guides: true, routing: 'orthogonal', showGrid: true, gridKind: 'square' },
    activeLayer: null, listeners: {}, clipboard: null, pasteN: 0
  };
  var sel = ed.sel;
  ed.on = function (evt, fn) { (ed.listeners[evt] = ed.listeners[evt] || []).push(fn); };
  ed.emit = function (evt, a) { (ed.listeners[evt] || []).forEach(function (fn) { fn(a); }); };

  try {
    var saved = JSON.parse(localStorage.getItem('satom.ds.editor.settings') || '{}');
    ['snap', 'grid', 'guides', 'routing', 'showGrid', 'gridKind'].forEach(function (k) { if (saved[k] !== undefined) ed.settings[k] = saved[k]; });
  } catch (e) { /* defaults */ }
  ed.saveSettings = function () { try { localStorage.setItem('satom.ds.editor.settings', JSON.stringify(ed.settings)); } catch (e) { /* private mode */ } };

  // ------------------------------------------------------------ helpers

  ed.page = function () { return store.page(); };
  ed.layerOf = function (id) { return store.layer(id) || ed.page().layers[0]; };
  ed.isLocked = function (o) { var l = ed.layerOf(o.layer); return !!(l && (l.locked || !l.visible)); };
  ed.selectedEls = function () { return Array.from(sel.els).map(function (id) { return store.el(id); }).filter(Boolean); };
  ed.selectedConns = function () { return Array.from(sel.conns).map(function (id) { return store.conn(id); }).filter(Boolean); };
  ed.editableEls = function () { return ed.selectedEls().filter(function (e) { return !ed.isLocked(e); }); };
  ed.currentLayer = function () {
    var p = ed.page();
    var l = ed.activeLayer && store.layer(ed.activeLayer);
    if (!l || l.locked || !l.visible) l = p.layers.filter(function (x) { return x.visible && !x.locked; }).pop() || p.layers[p.layers.length - 1];
    return l;
  };
  function k() { return r.view.k; }

  // ---------------------------------------------- isometric snapping
  /* With the isometric grid, snapping moves an element's ANCHOR onto the
   * nearest lattice vertex (x = (i - j)·g, y = (i + j)·g/2): the floor-tile
   * centre of a 3D icon (its library "anchor"), the centre of anything else. */
  ed.isIso = function () { return ed.settings.gridKind === 'iso'; };
  ed.isoPoint = function (x, y) {
    var g = ed.settings.grid || 10, a = x / g, b = 2 * y / g;
    var i = Math.round((a + b) / 2), j = Math.round((b - a) / 2);
    return [(i - j) * g, (i + j) * g / 2];
  };
  ed.isoAnchor = function (e) {
    var ref = M.splitSymbol(e.symbol || ''), lib = null;
    (cfg.libraries || []).forEach(function (l) { if (ref && l.id === ref.lib) lib = l; });
    if (!lib || !lib.anchor || e.shape !== 'symbol') return [e.w / 2, e.h / 2];
    var size = Math.min(e.w, e.h) * 0.72;        // the renderer's icon box
    return [(e.w - size) / 2 + size * lib.anchor[0], (e.h - size) / 2 + size * lib.anchor[1]];
  };
  /* Offset that puts box *b* (x, y, w, h; anchor *an* inside it) on the lattice. */
  ed.isoSnapDelta = function (x, y, an) {
    var q = ed.isoPoint(x + an[0], y + an[1]);
    return [q[0] - an[0] - x, q[1] - an[1] - y];
  };

  /* One undoable command (no-op in read-only mode). */
  ed.cmd = function (label, fn, opts) {
    if (!canEdit) { DS.toast('This diagram is read-only for you.', 'warning'); return null; }
    return store.run(label, fn, opts);
  };

  // --------------------------------------------------------- rendering

  var renderedPage = -1;
  function fullRender() {
    renderedPage = store.pageIndex;
    r.setPage(store.page());
    r.setGrid(ed.settings.showGrid, ed.settings.grid);
    var ids = new Set(store.page().elements.map(function (e) { return e.id; }));
    var cids = new Set(store.page().connectors.map(function (c) { return c.id; }));
    sel.els.forEach(function (id) { if (!ids.has(id)) sel.els.delete(id); });
    sel.conns.forEach(function (id) { if (!cids.has(id)) sel.conns.delete(id); });
  }
  store.onChange(function (ch) {
    var page = store.page();
    if (store.pageIndex !== renderedPage || ch.pages) { fullRender(); ed.emit('page'); }
    else if (ch.undo || ch.redo || ch.removed || ch.order || ch.structural) {
      r.page = page;
      r.byId = new Map(page.elements.map(function (e) { return [e.id, e]; }));
      r.applyLayerState();
      var allE = new Set(ch.els), allC = new Set(ch.conns);
      var cids = new Set(page.connectors.map(function (c) { return c.id; }));
      r.els.forEach(function (_, id) { if (!r.byId.has(id)) allE.add(id); });
      page.elements.forEach(function (e) { if (!r.els.has(e.id)) allE.add(e.id); });
      r.conns.forEach(function (_, id) { if (!cids.has(id)) allC.add(id); });
      page.connectors.forEach(function (c) { if (!r.conns.has(c.id)) allC.add(c.id); });
      r.updateEls(Array.from(allE));
      r.updateConns(Array.from(allC));
      r.syncOrder();
      pruneSelection();
      markSelected();
    } else {
      if (ch.els.size) r.updateEls(Array.from(ch.els));
      if (ch.conns.size) r.updateConns(Array.from(ch.conns));
      if (ch.added) r.syncOrder();
      markSelected();
    }
    drawOverlay();
    ed.emit('change', ch);
    updateStatus();
    scheduleAutosave();
  });
  function markSelected() {
    r.els.forEach(function (g, id) { var on = sel.els.has(id); if (g.classList.contains('ds-selected') !== on) g.classList.toggle('ds-selected', on); });
  }
  function pruneSelection() {
    sel.els.forEach(function (id) { if (!store.el(id)) sel.els.delete(id); });
    sel.conns.forEach(function (id) { if (!store.conn(id)) sel.conns.delete(id); });
  }

  // ---------------------------------------------------------- selection

  ed.select = function (els, conns, add) {
    if (!add) { sel.els.clear(); sel.conns.clear(); }
    (els || []).forEach(function (id) { sel.els.add(id); });
    (conns || []).forEach(function (id) { sel.conns.add(id); });
    markSelected();
    drawOverlay();
    ed.emit('selection');
  };
  ed.clearSelection = function () { ed.select([], []); };
  /* Click target -> the element plus its group mates (Alt picks one). */
  function expandGroup(id, single) {
    if (single) return { els: [id], conns: [] };
    var g = store.groupOf(id);
    if (!g) return { els: [id], conns: [] };
    var els = [], conns = [];
    g.members.forEach(function (m) { if (store.el(m)) els.push(m); else if (store.conn(m)) conns.push(m); });
    return { els: els, conns: conns };
  }
  ed.selectAll = function () {
    var p = ed.page();
    ed.select(p.elements.filter(function (e) { return !ed.isLocked(e); }).map(function (e) { return e.id; }),
      p.connectors.filter(function (c) { return !ed.isLocked(c); }).map(function (c) { return c.id; }));
  };
  ed.reveal = function (kind, id) {
    if (kind === 'el') {
      var e = store.el(id); if (!e) return;
      ed.select([id], []);
      r.centerOn(G.bbox(e), true);
    } else {
      var rt = r.routes.get(id); if (!rt) return;
      ed.select([], [id]);
      var xs = rt.pts.map(function (p) { return p[0]; }), ys = rt.pts.map(function (p) { return p[1]; });
      r.centerOn({ x: Math.min.apply(null, xs), y: Math.min.apply(null, ys), w: Math.max.apply(null, xs) - Math.min.apply(null, xs), h: Math.max.apply(null, ys) - Math.min.apply(null, ys) }, true);
    }
  };

  // ------------------------------------------------------------ overlay

  var ov = {};
  ['sel', 'guides', 'ports', 'rubber', 'marquee', 'handles'].forEach(function (n) { ov[n] = s('g', { class: 'ds-ov-' + n }, r.overlay); });
  var hoverEl = null;

  function handle(parent, x, y, h, cls, shape) {
    var z = 8 / k();
    if (shape === 'circle') return s('circle', { cx: x, cy: y, r: z * 0.6, class: 'ds-handle ' + (cls || ''), 'data-h': h }, parent);
    return s('rect', { x: x - z / 2, y: y - z / 2, width: z, height: z, class: 'ds-handle ' + (cls || ''), 'data-h': h }, parent);
  }
  var HANDLES = [['nw', 0, 0], ['n', .5, 0], ['ne', 1, 0], ['e', 1, .5], ['se', 1, 1], ['s', .5, 1], ['sw', 0, 1], ['w', 0, .5]];

  function drawOverlay() {
    DS.clear(ov.sel); DS.clear(ov.handles);
    var els = ed.selectedEls();
    var kk = k();
    els.forEach(function (e) {
      var g = s('g', { transform: 'translate(' + e.x + ' ' + e.y + ')' + (e.rotation ? ' rotate(' + e.rotation + ' ' + e.w / 2 + ' ' + e.h / 2 + ')' : '') }, ov.sel);
      s('rect', { x: -2 / kk, y: -2 / kk, width: e.w + 4 / kk, height: e.h + 4 / kk, class: 'ds-sel-box' + (ed.isLocked(e) ? ' ds-sel-locked' : '') }, g);
    });
    if (canEdit && els.length === 1 && !ed.isLocked(els[0]) && !drag) {
      var e = els[0];
      var g = s('g', { transform: 'translate(' + e.x + ' ' + e.y + ')' + (e.rotation ? ' rotate(' + e.rotation + ' ' + e.w / 2 + ' ' + e.h / 2 + ')' : '') }, ov.handles);
      HANDLES.forEach(function (hd) { handle(g, hd[1] * e.w, hd[2] * e.h, hd[0], 'ds-h-' + hd[0]); });
      s('line', { x1: e.w / 2, y1: 0, x2: e.w / 2, y2: -22 / kk, class: 'ds-rot-stem' }, g);
      handle(g, e.w / 2, -22 / kk, 'rot', 'ds-h-rot', 'circle');
    } else if (els.length > 1) {
      var b = G.union(els.map(G.bbox));
      s('rect', { x: b.x - 4 / kk, y: b.y - 4 / kk, width: b.w + 8 / kk, height: b.h + 8 / kk, class: 'ds-sel-multi' }, ov.sel);
    }
    ed.selectedConns().forEach(function (c) {
      var rt = r.routes.get(c.id);
      if (!rt) return;
      s('path', { d: rt.d, class: 'ds-sel-conn' }, ov.sel);
      if (!canEdit || ed.isLocked(c) || drag) return;
      handle(ov.handles, rt.pts[0][0], rt.pts[0][1], 'src', 'ds-h-end' + (c.source ? ' ds-attached' : ''), 'circle');
      handle(ov.handles, rt.pts[rt.pts.length - 1][0], rt.pts[rt.pts.length - 1][1], 'tgt', 'ds-h-end' + (c.target ? ' ds-attached' : ''), 'circle');
      if (sel.conns.size === 1) {
        (c.points || []).forEach(function (p, i) { handle(ov.handles, p[0], p[1], 'wp:' + i, 'ds-h-wp'); });
        var pts = rt.pts;
        for (var i = 0; i < pts.length - 1; i++) {
          var mx = (pts[i][0] + pts[i + 1][0]) / 2, my = (pts[i][1] + pts[i + 1][1]) / 2;
          if (Math.hypot(pts[i + 1][0] - pts[i][0], pts[i + 1][1] - pts[i][1]) * kk > 24) handle(ov.handles, mx, my, 'mid:' + i, 'ds-h-mid', 'circle');
        }
      }
    });
    drawPorts();
  }
  ed.drawOverlay = drawOverlay;

  function drawPorts() {
    DS.clear(ov.ports);
    if (!canEdit || !hoverEl || (drag && drag.mode !== 'connect' && drag.mode !== 'end')) return;
    var e = store.el(hoverEl);
    if (!e || ed.isLocked(e)) return;
    // on a shape that shows its resize handles, the dots sit just outside it
    var off = (!drag && sel.els.size === 1 && sel.els.has(e.id)) ? 16 / k() : 0;
    R.anchors(e).forEach(function (a) { handle(ov.ports, a.x + a.dx * off, a.y + a.dy * off, 'port:' + e.id + ':' + a.id + ':' + (a.declared ? 1 : 0), 'ds-port', 'circle'); });
  }
  r.on(function (what) { if (what === 'view') { drawOverlay(); positionTextEdit(); } });

  // -------------------------------------------------------------- pointer

  var drag = null;
  var spaceDown = false;

  /* Move zone vs connect zone: a press on a port handle only starts a
   * connector when it is within PORT_GRAB px (screen) of the port itself;
   * further away, inside an element's body, it grabs the element (a port an
   * operator library placed inside a symbol must never block moving it). */
  var PORT_GRAB = 8;
  function portOrBody(t, ev, p) {
    var parts = t.h.split(':'), src = store.el(parts[1]);
    var a = src && R.anchors(src).filter(function (x) { return x.id === parts[2]; })[0];
    if (!a) return t;
    var off = (sel.els.size === 1 && sel.els.has(src.id)) ? 16 / k() : 0;
    var q = r.toScreen(a.x + a.dx * off, a.y + a.dy * off);
    if (Math.hypot(ev.clientX - q[0], ev.clientY - q[1]) <= PORT_GRAB) return t;
    var hit = elementAt(p);
    return hit ? { kind: 'el', id: hit.id } : t;
  }
  ed.portOrBody = portOrBody;

  function targetOf(ev) {
    var t = ev.target;
    var h = t.closest && t.closest('[data-h]');
    if (h) return { kind: 'handle', h: h.getAttribute('data-h') };
    var lab = t.closest && t.closest('.ds-conn-label');
    var c = t.closest && t.closest('.ds-conn');
    if (c) return { kind: 'conn', id: c.getAttribute('data-id'), label: lab ? Number(lab.getAttribute('data-label')) : null };
    var el = t.closest && t.closest('.ds-el');
    if (el) return { kind: 'el', id: el.getAttribute('data-id') };
    return { kind: 'bg' };
  }
  /* Topmost unlocked visible element under a world point (skips `skip`). */
  function elementAt(p, skip) {
    var ids = r.index.query({ x: p[0] - 1, y: p[1] - 1, w: 2, h: 2 });
    var page = ed.page(), order = new Map();
    page.elements.forEach(function (e, i) { order.set(e.id, i); });
    var layerPos = new Map(page.layers.map(function (l, i) { return [l.id, i]; }));
    ids = ids.filter(function (id) {
      var e = store.el(id);
      return e && (!skip || !skip.has(id)) && !ed.isLocked(e) && G.inside(e, p[0], p[1]);
    }).sort(function (a, b) {
      var A = store.el(a), B = store.el(b);
      return (layerPos.get(B.layer) - layerPos.get(A.layer)) || (order.get(b) - order.get(a));
    });
    return ids.length ? store.el(ids[0]) : null;
  }

  svg.addEventListener('pointerdown', function (ev) {
    if (ev.button === 2) return;
    if (r.live) r._endLive(true);
    svg.focus({ preventScroll: true });
    commitTextEdit();
    var p = r.toWorld(ev.clientX, ev.clientY);
    var t = targetOf(ev);
    // Double press, detected here: pointer capture retargets the native
    // dblclick to the <svg>, and the overlay is redrawn between the clicks.
    var now = Date.now();
    if (ev.button === 0 && lastDown && now - lastDown.t < 450 && Math.hypot(ev.clientX - lastDown.x, ev.clientY - lastDown.y) < 6) {
      var first = lastDown.target;
      lastDown = null;
      if (store.tx) store.commit();
      drag = null;
      ev.preventDefault();
      onDouble(first, p);
      return;
    }
    lastDown = { t: now, x: ev.clientX, y: ev.clientY, target: t };
    if (ev.button === 1 || spaceDown || (!canEdit && t.kind === 'bg')) {
      ev.preventDefault();
      drag = { mode: 'pan', sx: ev.clientX, sy: ev.clientY, vx: r.view.x, vy: r.view.y };
      svg.setPointerCapture(ev.pointerId);
      svg.classList.add('ds-panning');
      return;
    }
    if (t.kind === 'handle' && /^port:/.test(t.h)) t = portOrBody(t, ev, p);
    if (t.kind === 'handle') { startHandle(t.h, p, ev); return; }
    if (t.kind === 'conn') {
      if (ev.shiftKey) { if (sel.conns.has(t.id)) sel.conns.delete(t.id); else sel.conns.add(t.id); ed.select(Array.from(sel.els), Array.from(sel.conns)); }
      else if (!sel.conns.has(t.id)) { var gx = store.groupOf(t.id); if (gx && !ev.altKey) { ed.select(gx.members.filter(function (m) { return store.el(m); }), gx.members.filter(function (m) { return store.conn(m); })); } else ed.select([], [t.id]); }
      var cc = store.conn(t.id);
      if (canEdit && cc && !ed.isLocked(cc) && t.label !== null && !isNaN(t.label)) {
        drag = { mode: 'label', id: t.id, idx: t.label, started: false, sx: ev.clientX, sy: ev.clientY };
        svg.setPointerCapture(ev.pointerId);
      }
      return;
    }
    if (t.kind === 'el') {
      var e0 = store.el(t.id);
      if (!e0) return;
      var picked = expandGroup(t.id, ev.altKey);
      if (ev.shiftKey || ev.ctrlKey || ev.metaKey) {
        var allIn = picked.els.every(function (id) { return sel.els.has(id); });
        picked.els.forEach(function (id) { if (allIn) sel.els.delete(id); else sel.els.add(id); });
        picked.conns.forEach(function (id) { if (allIn) sel.conns.delete(id); else sel.conns.add(id); });
        ed.select(Array.from(sel.els), Array.from(sel.conns));
      } else if (!sel.els.has(t.id)) {
        ed.select(picked.els, picked.conns);
      }
      if (canEdit && !ed.isLocked(e0)) startMove(p, ev);
      return;
    }
    // background: marquee
    if (!(ev.shiftKey || ev.ctrlKey || ev.metaKey)) ed.clearSelection();
    drag = { mode: 'marquee', p0: p, add: ev.shiftKey || ev.ctrlKey || ev.metaKey, base: { els: new Set(sel.els), conns: new Set(sel.conns) } };
    svg.setPointerCapture(ev.pointerId);
  });

  svg.addEventListener('pointermove', function (ev) {
    var p = r.toWorld(ev.clientX, ev.clientY);
    if (!drag) {
      var t = targetOf(ev);
      var id = t.kind === 'el' ? t.id : (t.kind === 'handle' && /^port:/.test(t.h) ? t.h.split(':')[1] : null);
      if (id !== hoverEl) { hoverEl = id; drawPorts(); }
      return;
    }
    ev.preventDefault();
    var fn = MOVES[drag.mode];
    if (fn) fn(p, ev);
  });
  svg.addEventListener('pointerup', function (ev) {
    if (!drag) return;
    var d = drag;
    var fn = ENDS[d.mode];
    drag = null;
    try { svg.releasePointerCapture(ev.pointerId); } catch (e) { /* not captured */ }
    svg.classList.remove('ds-panning');
    DS.clear(ov.guides); DS.clear(ov.rubber); DS.clear(ov.marquee);
    if (fn) fn(r.toWorld(ev.clientX, ev.clientY), ev, d);
    else if (store.tx) store.commit();
    drawOverlay();
  });
  svg.addEventListener('pointercancel', function () {
    if (drag && store.tx) store.rollback();
    drag = null;
    DS.clear(ov.guides); DS.clear(ov.rubber); DS.clear(ov.marquee);
    drawOverlay();
  });
  svg.addEventListener('pointerleave', function () { if (!drag && hoverEl) { hoverEl = null; drawPorts(); } });
  svg.addEventListener('contextmenu', function (ev) { if (drag) ev.preventDefault(); });

  svg.addEventListener('wheel', function (ev) {
    ev.preventDefault();
    if (ev.shiftKey && !ev.ctrlKey) { r.setViewLive(r.view.k, r.view.x - ev.deltaY, r.view.y); return; }
    var f = Math.exp(-ev.deltaY * (ev.deltaMode === 1 ? 0.05 : 0.0015));
    r.zoomAt(f, ev.clientX, ev.clientY, true);
  }, { passive: false });

  var MOVES = {}, ENDS = {};

  MOVES.pan = function (p, ev) { r.setViewLive(r.view.k, drag.vx + ev.clientX - drag.sx, drag.vy + ev.clientY - drag.sy); };

  MOVES.marquee = function (p) {
    var a = drag.p0, b = { x: Math.min(a[0], p[0]), y: Math.min(a[1], p[1]), w: Math.abs(p[0] - a[0]), h: Math.abs(p[1] - a[1]) };
    drag.box = b;
    DS.clear(ov.marquee);
    s('rect', { x: b.x, y: b.y, width: b.w, height: b.h, class: 'ds-marquee' }, ov.marquee);
  };
  ENDS.marquee = function (p, ev, d) {
    if (!d.box || d.box.w * k() < 3) return;
    var els = new Set(d.add ? d.base.els : []), conns = new Set(d.add ? d.base.conns : []);
    r.index.query(d.box).forEach(function (id) {
      var e = store.el(id);
      if (e && !ed.isLocked(e) && G.contains(d.box, G.bbox(e))) expandGroup(id).els.forEach(function (x) { els.add(x); });
    });
    ed.page().connectors.forEach(function (c) {
      if (ed.isLocked(c)) return;
      var rt = r.routes.get(c.id);
      if (rt && rt.pts.every(function (q) { return q[0] >= d.box.x && q[0] <= d.box.x + d.box.w && q[1] >= d.box.y && q[1] <= d.box.y + d.box.h; })) conns.add(c.id);
    });
    ed.select(Array.from(els), Array.from(conns));
  };

  // ----------------------------------------------------------------- move

  function startMove(p, ev) {
    var ids = new Set(ed.editableEls().map(function (e) { return e.id; }));
    // children of moved containers travel with them
    Array.from(ids).forEach(function (id) { store.childrenOf(id).forEach(function (c) { if (!ed.isLocked(c)) ids.add(c.id); }); });
    var tops = Array.from(ids).map(function (id) { return store.el(id); });
    var orig = new Map(tops.map(function (e) { return [e.id, [e.x, e.y]]; }));
    // waypoints of connectors with both ends moving (or selected) travel too
    var conns = ed.page().connectors.filter(function (c) {
      return (ids.has(c.source) && ids.has(c.target)) || (sel.conns.has(c.id) && (!c.source || ids.has(c.source)) && (!c.target || ids.has(c.target)));
    });
    var corig = new Map(conns.map(function (c) { return [c.id, { points: DS.clone(c.points), start: DS.clone(c.start), end: DS.clone(c.end) }]; }));
    var bbox = G.union(tops.filter(function (e) { return sel.els.has(e.id); }).map(G.bbox)) || G.union(tops.map(G.bbox));
    // guide candidates: visible, unmoved elements near the viewport
    var sz = r.size(), vk = k();
    var view = { x: -r.view.x / vk - 200, y: -r.view.y / vk - 200, w: sz.w / vk + 400, h: sz.h / vk + 400 };
    var cand = r.index.query(view).filter(function (id) { return !ids.has(id) && r.isVisible(store.el(id) ? store.el(id).layer : ''); }).slice(0, 400)
      .map(function (id) { return r.index.boxes.get(id).box; });
    drag = { mode: 'move', p0: p, ids: ids, orig: orig, conns: conns, corig: corig, bbox: bbox, cand: cand, started: false, sx: ev.clientX, sy: ev.clientY };
    svg.setPointerCapture(ev.pointerId);
  }

  function guideSnap(box, cand, tol) {
    var xs = [box.x, box.x + box.w / 2, box.x + box.w], ys = [box.y, box.y + box.h / 2, box.y + box.h];
    var best = { dx: null, dy: null, gx: null, gy: null, ex: tol, ey: tol };
    cand.forEach(function (b) {
      [b.x, b.x + b.w / 2, b.x + b.w].forEach(function (v) {
        xs.forEach(function (x) { var d = v - x; if (Math.abs(d) < best.ex) { best.ex = Math.abs(d); best.dx = d; best.gx = { v: v, b: b }; } });
      });
      [b.y, b.y + b.h / 2, b.y + b.h].forEach(function (v) {
        ys.forEach(function (y) { var d = v - y; if (Math.abs(d) < best.ey) { best.ey = Math.abs(d); best.dy = d; best.gy = { v: v, b: b }; } });
      });
    });
    return best;
  }

  MOVES.move = function (p, ev) {
    if (!drag.started) {
      if (Math.hypot(ev.clientX - drag.sx, ev.clientY - drag.sy) < 3) return;
      drag.started = true;
      store.begin('Move');
      drag.ids.forEach(function (id) { store.tx.touch('el', id); });
      drag.conns.forEach(function (c) { store.tx.touch('conn', c.id); });
      DS.clear(ov.handles);
    }
    var dx = p[0] - drag.p0[0], dy = p[1] - drag.p0[1];
    var b = drag.bbox;
    var moved = { x: b.x + dx, y: b.y + dy, w: b.w, h: b.h };
    DS.clear(ov.guides);
    var isoSnap = ed.settings.snap && !ev.altKey && ed.isIso();
    var gs = (!isoSnap && ed.settings.guides && !ev.altKey) ? guideSnap(moved, drag.cand, 6 / k()) : {};
    if (isoSnap) {
      var ids0 = Array.from(drag.ids), e0 = ids0.length === 1 ? store.el(ids0[0]) : null;
      var o0 = e0 ? drag.orig.get(e0.id) : [b.x, b.y];
      var sd = ed.isoSnapDelta(o0[0] + dx, o0[1] + dy, e0 ? ed.isoAnchor(e0) : [b.w / 2, b.h / 2]);
      dx += sd[0]; dy += sd[1];
    }
    else if (gs.dx !== null && gs.dx !== undefined) dx += gs.dx;
    else if (ed.settings.snap && !ev.altKey) dx = G.snap(b.x + dx, ed.settings.grid) - b.x;
    if (isoSnap) { /* both axes done */ }
    else if (gs.dy !== null && gs.dy !== undefined) dy += gs.dy;
    else if (ed.settings.snap && !ev.altKey) dy = G.snap(b.y + dy, ed.settings.grid) - b.y;
    if (gs.gx) { var gb = gs.gx.b; s('line', { x1: gs.gx.v, x2: gs.gx.v, y1: Math.min(gb.y, b.y + dy) - 10, y2: Math.max(gb.y + gb.h, b.y + dy + b.h) + 10, class: 'ds-guide' }, ov.guides); }
    if (gs.gy) { var gb2 = gs.gy.b; s('line', { y1: gs.gy.v, y2: gs.gy.v, x1: Math.min(gb2.x, b.x + dx) - 10, x2: Math.max(gb2.x + gb2.w, b.x + dx + b.w) + 10, class: 'ds-guide' }, ov.guides); }
    drag.ids.forEach(function (id) {
      var e = store.el(id), o = drag.orig.get(id);
      e.x = G.round(o[0] + dx); e.y = G.round(o[1] + dy);
    });
    drag.conns.forEach(function (c) {
      var o = drag.corig.get(c.id);
      c.points = o.points.map(function (q) { return [G.round(q[0] + dx), G.round(q[1] + dy)]; });
      if (o.start.length === 2) c.start = [G.round(o.start[0] + dx), G.round(o.start[1] + dy)];
      if (o.end.length === 2) c.end = [G.round(o.end[0] + dx), G.round(o.end[1] + dy)];
    });
    r.moveEls(drag.ids, drag.conns.map(function (c) { return c.id; }));
    DS.clear(ov.sel);
    ed.selectedEls().forEach(function (e) {
      s('rect', { x: e.x - 2 / k(), y: e.y - 2 / k(), width: e.w + 4 / k(), height: e.h + 4 / k(), class: 'ds-sel-box', transform: e.rotation ? 'rotate(' + e.rotation + ' ' + (e.x + e.w / 2) + ' ' + (e.y + e.h / 2) + ')' : null }, ov.sel);
    });
    drag.moved = true;
  };
  ENDS.move = function (p, ev, d) {
    if (!d.started) return;
    // re-parent: an element dropped inside a container becomes its child
    d.ids.forEach(function (id) {
      var e = store.el(id);
      if (d.ids.has(e.parent)) return;
      var box = G.bbox(e);
      var host = null;
      r.index.query(box).forEach(function (cid) {
        if (cid === id || d.ids.has(cid)) return;
        var c = store.el(cid);
        if (!c || !(c.kind === 'container' || c.shape === 'zone' || c.shape === 'swimlane') || ed.isLocked(c)) return;
        if (!G.contains(G.bbox(c), box)) return;
        if (!host || G.bbox(c).w * G.bbox(c).h < G.bbox(host).w * G.bbox(host).h) host = c;
      });
      var np = host ? host.id : '';
      if (np !== e.parent) e.parent = np;
    });
    store.commit();
  };

  /* Fast path while dragging: move transforms, re-route attached connectors. */
  r.moveEls = function (ids, extraConns) {
    var self = r;
    ids.forEach(function (id) {
      var e = store.el(id), g = self.els.get(id);
      if (!e || !g) return;
      var tf = 'translate(' + e.x + ' ' + e.y + ')';
      if (e.rotation) tf += ' rotate(' + e.rotation + ' ' + (e.w / 2) + ' ' + (e.h / 2) + ')';
      g.setAttribute('transform', tf);
      self.index.set(id, G.bbox(e));
    });
    var cids = new Set(extraConns || []);
    self.page.connectors.forEach(function (c) { if (ids.has(c.source) || ids.has(c.target)) cids.add(c.id); });
    self.updateConns(Array.from(cids));
  };

  // -------------------------------------------------------------- handles

  function startHandle(h, p, ev) {
    if (!canEdit) return;
    svg.setPointerCapture(ev.pointerId);
    var parts = h.split(':');
    if (parts[0] === 'port') {
      var src = store.el(parts[1]);
      drag = { mode: 'connect', src: src, port: parts[3] === '1' ? parts[2] : '', p0: R.anchors(src).filter(function (a) { return a.id === parts[2]; })[0] };
      return;
    }
    if (h === 'rot') {
      var e = ed.selectedEls()[0];
      drag = { mode: 'rotate', id: e.id };
      store.begin('Rotate'); store.tx.touch('el', e.id);
      return;
    }
    if (h === 'src' || h === 'tgt') {
      var c = ed.selectedConns()[0];
      drag = { mode: 'end', id: c.id, which: h };
      store.begin('Reconnect'); store.tx.touch('conn', c.id);
      return;
    }
    if (parts[0] === 'wp') {
      var c2 = ed.selectedConns()[0];
      drag = { mode: 'wp', id: c2.id, i: Number(parts[1]) };
      store.begin('Move waypoint'); store.tx.touch('conn', c2.id);
      return;
    }
    if (parts[0] === 'mid') {
      var c3 = ed.selectedConns()[0];
      drag = { mode: 'mid', id: c3.id, seg: Number(parts[1]), started: false, sx: ev.clientX, sy: ev.clientY };
      return;
    }
    // resize
    var el = ed.selectedEls()[0];
    drag = { mode: 'resize', id: el.id, h: h, o: { x: el.x, y: el.y, w: el.w, h: el.h, rot: el.rotation || 0 }, kids: [] };
    store.begin('Resize'); store.tx.touch('el', el.id);
  }

  MOVES.resize = function (p, ev) {
    var e = store.el(drag.id), o = drag.o, h = drag.h;
    var cx = o.x + o.w / 2, cy = o.y + o.h / 2;
    var lp = G.rotate(p[0], p[1], cx, cy, -o.rot);
    var lx = lp[0] - cx, ly = lp[1] - cy;          // pointer in the element's local frame (centre origin)
    var x0 = -o.w / 2, y0 = -o.h / 2, x1 = o.w / 2, y1 = o.h / 2;
    if (h.indexOf('w') >= 0) x0 = lx; if (h.indexOf('e') >= 0) x1 = lx;
    if (h.indexOf('n') >= 0) y0 = ly; if (h.indexOf('s') >= 0) y1 = ly;
    if (!o.rot && ed.settings.snap && !ev.altKey && !ed.isIso()) {
      var g = ed.settings.grid;
      if (h.indexOf('w') >= 0) x0 = G.snap(cx + x0, g) - cx; if (h.indexOf('e') >= 0) x1 = G.snap(cx + x1, g) - cx;
      if (h.indexOf('n') >= 0) y0 = G.snap(cy + y0, g) - cy; if (h.indexOf('s') >= 0) y1 = G.snap(cy + y1, g) - cy;
    }
    var min = 4;
    if (x1 - x0 < min) { if (h.indexOf('w') >= 0) x0 = x1 - min; else x1 = x0 + min; }
    if (y1 - y0 < min) { if (h.indexOf('n') >= 0) y0 = y1 - min; else y1 = y0 + min; }
    if (ev.shiftKey && o.w > 0 && o.h > 0) {
      var ratio = o.w / o.h, w = x1 - x0, hh = y1 - y0;
      if (h.length === 2) { if (w / hh > ratio) w = hh * ratio; else hh = w / ratio; }
      else if (h === 'e' || h === 'w') hh = w / ratio; else w = hh * ratio;
      if (h.indexOf('w') >= 0) x0 = x1 - w; else if (h.indexOf('e') >= 0) x1 = x0 + w; else { x0 = -w / 2; x1 = w / 2; }
      if (h.indexOf('n') >= 0) y0 = y1 - hh; else if (h.indexOf('s') >= 0) y1 = y0 + hh; else { y0 = -hh / 2; y1 = hh / 2; }
    }
    var nc = G.rotate(cx + (x0 + x1) / 2, cy + (y0 + y1) / 2, cx, cy, o.rot);
    e.w = G.round(x1 - x0); e.h = G.round(y1 - y0);
    e.x = G.round(nc[0] - e.w / 2); e.y = G.round(nc[1] - e.h / 2);
    r.updateEls([e.id]);
    drawOverlay();
  };
  ENDS.resize = function () { store.commit(); };

  MOVES.rotate = function (p, ev) {
    var e = store.el(drag.id), c = G.center(e);
    var a = Math.atan2(p[1] - c[1], p[0] - c[0]) * 180 / Math.PI + 90;
    if (ev.shiftKey) a = Math.round(a / 15) * 15;
    else { var near = Math.round(a / 90) * 90; if (Math.abs(a - near) < 3) a = near; }
    a = ((a % 360) + 540) % 360 - 180;
    e.rotation = G.round(a);
    r.updateEls([e.id]);
    drawOverlay();
    ed.emit('live', e);
  };
  ENDS.rotate = function () { store.commit(); };

  // ------------------------------------------------------------ connectors

  function nearestPortHit(e, p) {
    var best = null, bd = (12 / k()) * (12 / k());
    R.anchors(e).forEach(function (a) { var d = G.dist2([a.x, a.y], p); if (d < bd) { bd = d; best = a; } });
    return best;
  }

  MOVES.connect = function (p) {
    DS.clear(ov.rubber);
    var tgt = elementAt(p, new Set([drag.src.id]));
    hoverEl = tgt ? tgt.id : null;
    drawPorts();
    var a = drag.p0;
    var end = p;
    if (tgt) {
      var hit = nearestPortHit(tgt, p);
      end = hit ? [hit.x, hit.y] : R.clip(tgt, a.x, a.y);
      var bb = G.bbox(tgt);
      s('rect', { x: bb.x - 3 / k(), y: bb.y - 3 / k(), width: bb.w + 6 / k(), height: bb.h + 6 / k(), class: 'ds-drop-target' }, ov.rubber);
    }
    s('line', { x1: a.x, y1: a.y, x2: end[0], y2: end[1], class: 'ds-rubber' }, ov.rubber);
    drag.last = p;
  };
  ENDS.connect = function (p, ev, d) {
    if (!d.last || Math.hypot(d.last[0] - d.p0.x, d.last[1] - d.p0.y) * k() < 8) return;
    var tgt = elementAt(p, new Set([d.src.id]));
    var c = M.fillConnector({ source: d.src.id, source_port: d.port, routing: ed.settings.routing, layer: d.src.layer });
    if (tgt) {
      c.target = tgt.id;
      var hit = nearestPortHit(tgt, p);
      if (hit && hit.declared) c.target_port = hit.id;
    } else {
      c.end = [G.round(p[0]), G.round(p[1])];
    }
    ed.cmd('Connect', function (tx) { tx.add('conn', c); });
    ed.select([], [c.id]);
  };

  MOVES.end = function (p) {
    var c = store.conn(drag.id);
    var skip = new Set();
    var other = drag.which === 'src' ? c.target : c.source;
    if (other) skip.add(other);
    var tgt = elementAt(p, null);
    hoverEl = tgt ? tgt.id : null;
    drawPorts();
    DS.clear(ov.rubber);
    if (drag.which === 'src') { c.source = tgt ? tgt.id : ''; c.source_port = ''; c.start = tgt ? [] : [G.round(p[0]), G.round(p[1])]; }
    else { c.target = tgt ? tgt.id : ''; c.target_port = ''; c.end = tgt ? [] : [G.round(p[0]), G.round(p[1])]; }
    if (tgt) {
      var hit = nearestPortHit(tgt, p);
      if (hit && hit.declared) { if (drag.which === 'src') c.source_port = hit.id; else c.target_port = hit.id; }
      var bb = G.bbox(tgt);
      s('rect', { x: bb.x - 3 / k(), y: bb.y - 3 / k(), width: bb.w + 6 / k(), height: bb.h + 6 / k(), class: 'ds-drop-target' }, ov.rubber);
    }
    r.updateConns([c.id]);
    drawOverlay();
  };
  ENDS.end = function () { store.commit(); };

  MOVES.wp = function (p, ev) {
    var c = store.conn(drag.id);
    var q = [p[0], p[1]];
    if (ed.settings.snap && !ev.altKey) q = ed.isIso() ? ed.isoPoint(q[0], q[1]) : [G.snap(q[0], ed.settings.grid), G.snap(q[1], ed.settings.grid)];
    c.points[drag.i] = [G.round(q[0]), G.round(q[1])];
    r.updateConns([c.id]);
    drawOverlay();
  };
  ENDS.wp = function () { store.commit(); };

  /* Dragging a segment midpoint inserts a waypoint there. Orthogonal
   * connectors first freeze their computed bends as waypoints. */
  function insertWaypoint(c, seg, q) {
    var rt = r.routes.get(c.id);
    if (!rt) return -1;
    var interior = rt.pts.slice(1, -1).map(function (x) { return [G.round(x[0]), G.round(x[1])]; });
    if (c.routing === 'orthogonal' || !c.points.length) {
      // the route's vertices become the waypoints (stubs included for orthogonal)
      c.points = interior;
      var at = Math.max(0, Math.min(seg, c.points.length));
      c.points.splice(at, 0, [G.round(q[0]), G.round(q[1])]);
      return at;
    }
    // straight / curved with waypoints: route vertex i+1 == points[i]
    var idx = Math.max(0, Math.min(seg, c.points.length));
    c.points.splice(idx, 0, [G.round(q[0]), G.round(q[1])]);
    return idx;
  }
  MOVES.mid = function (p, ev) {
    if (!drag.started) {
      if (Math.hypot(ev.clientX - drag.sx, ev.clientY - drag.sy) < 3) return;
      drag.started = true;
      store.begin('Add waypoint');
      var c = store.tx.touch('conn', drag.id);
      drag.i = insertWaypoint(c, drag.seg, p);
      drag.mode = 'wp';
    }
  };
  ENDS.mid = function () { if (store.tx) store.commit(); };

  MOVES.label = function (p, ev) {
    if (!drag.started) {
      if (Math.hypot(ev.clientX - drag.sx, ev.clientY - drag.sy) < 3) return;
      drag.started = true;
      store.begin('Move label');
      var c0 = store.tx.touch('conn', drag.id);
      if (drag.idx === -1) { c0.labels = [{ text: c0.label, pos: 0.5 }].concat(c0.labels || []); c0.label = ''; drag.idx = 0; }
    }
    var c = store.conn(drag.id), rt = r.routes.get(c.id);
    if (!rt) return;
    c.labels[drag.idx].pos = G.round(R.posOf(rt.flat, p) * 1000) / 1000;
    r.updateConns([c.id]);
  };
  ENDS.label = function () { if (store.tx) store.commit(); };

  // ----------------------------------------------------------- dblclick

  var lastDown = null;
  function onDouble(t, p) {
    if (!canEdit) return;
    if (t.kind === 'handle') {
      var parts = t.h.split(':');
      var c = ed.selectedConns()[0];
      if (!c) return;
      if (parts[0] === 'wp') { ed.cmd('Remove waypoint', function (tx) { tx.touch('conn', c.id).points.splice(Number(parts[1]), 1); }); }
      else if (parts[0] === 'mid') { ed.cmd('Add waypoint', function (tx) { insertWaypoint(tx.touch('conn', c.id), Number(parts[1]), p); }); }
      return;
    }
    if (t.kind === 'conn') { editConnLabel(t.id, t.label); return; }
    if (t.kind === 'el') { var e = store.el(t.id); if (e && !ed.isLocked(e)) editElementText(e); }
  }

  // ------------------------------------------------------- text editing

  var editing = null;
  function editElementText(e) {
    ed.select([e.id], []);
    editing = { kind: 'el', id: e.id, orig: e.text };
    textEdit.value = e.text || '';
    textEdit.setAttribute('aria-label', 'Text of ' + (e.name || e.shape));
    textEdit.hidden = false;
    positionTextEdit();
    textEdit.focus();
    textEdit.select();
  }
  function editConnLabel(id, idx) {
    var c = store.conn(id);
    if (!c || ed.isLocked(c)) return;
    ed.select([], [id]);
    var useIdx = (idx === null || idx === undefined || isNaN(idx)) ? -1 : idx;
    editing = { kind: 'conn', id: id, idx: useIdx };
    textEdit.value = useIdx >= 0 ? c.labels[useIdx].text : c.label;
    textEdit.setAttribute('aria-label', 'Connector label');
    textEdit.hidden = false;
    positionTextEdit();
    textEdit.focus();
    textEdit.select();
  }
  ed.editText = function () {
    var e = ed.selectedEls()[0], c = ed.selectedConns()[0];
    if (e && !ed.isLocked(e)) editElementText(e); else if (c) editConnLabel(c.id, -1);
  };
  function positionTextEdit() {
    if (!editing) return;
    var wr = wrap.getBoundingClientRect(), kk = k();
    var x, y, w, h, fs;
    if (editing.kind === 'el') {
      var e = store.el(editing.id); if (!e) return;
      var b = G.bbox(e);
      var sp = r.toScreen(b.x, b.y);
      x = sp[0] - wr.left; y = sp[1] - wr.top; w = Math.max(80, b.w * kk); h = Math.max(32, b.h * kk);
      if (e.shape === 'symbol') { y += b.h * kk; h = Math.max(32, 28 * kk); }
      fs = (e.style.font_size || 12) * kk;
      textEdit.style.textAlign = e.style.align === 'left' ? 'left' : e.style.align === 'right' ? 'right' : 'center';
    } else {
      var c = store.conn(editing.id), rt = r.routes.get(editing.id); if (!c || !rt) return;
      var pos = editing.idx >= 0 ? c.labels[editing.idx].pos : 0.5;
      var q = R.pointAlong(rt.flat, pos), sq = r.toScreen(q[0], q[1]);
      w = 160; h = 34; x = sq[0] - wr.left - w / 2; y = sq[1] - wr.top - h / 2; fs = 11 * kk;
      textEdit.style.textAlign = 'center';
    }
    textEdit.style.left = x + 'px'; textEdit.style.top = y + 'px';
    textEdit.style.width = w + 'px'; textEdit.style.height = h + 'px';
    textEdit.style.fontSize = Math.max(11, Math.min(40, fs)) + 'px';
  }
  function commitTextEdit(cancel) {
    if (!editing) return;
    var ctx = editing, val = textEdit.value;
    editing = null;
    textEdit.hidden = true;
    if (cancel) { svg.focus({ preventScroll: true }); return; }
    if (ctx.kind === 'el') {
      var e = store.el(ctx.id);
      if (e && e.text !== val) ed.cmd('Edit text', function (tx) { tx.touch('el', ctx.id).text = val.slice(0, 4000); });
    } else {
      var c = store.conn(ctx.id);
      if (!c) return;
      var cur = ctx.idx >= 0 ? c.labels[ctx.idx].text : c.label;
      if (cur !== val) ed.cmd('Edit label', function (tx) {
        var cc = tx.touch('conn', ctx.id);
        if (ctx.idx >= 0) { if (val.trim()) cc.labels[ctx.idx].text = val.slice(0, 200); else cc.labels.splice(ctx.idx, 1); }
        else cc.label = val.slice(0, 200);
      });
    }
    svg.focus({ preventScroll: true });
  }
  textEdit.addEventListener('keydown', function (ev) {
    ev.stopPropagation();
    if (ev.key === 'Escape') { ev.preventDefault(); commitTextEdit(true); }
    else if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey || (editing && editing.kind === 'conn' && !ev.shiftKey))) { ev.preventDefault(); commitTextEdit(); }
  });
  textEdit.addEventListener('blur', function () { commitTextEdit(); });

  // ------------------------------------------------------------ commands

  ed.addElement = function (proto, at) {
    var layer = ed.currentLayer();
    var e = M.fillElement(DS.clone(proto), layer.id);
    e.id = M.newId('e');
    e.layer = layer.id;
    var c = at || (function () { var sz = r.size(); return r.toWorld(sz.left + sz.w / 2, sz.top + sz.h / 2); })();
    e.x = G.round(c[0] - e.w / 2); e.y = G.round(c[1] - e.h / 2);
    if (ed.settings.snap && ed.isIso()) { var sd0 = ed.isoSnapDelta(e.x, e.y, ed.isoAnchor(e)); e.x = G.round(e.x + sd0[0]); e.y = G.round(e.y + sd0[1]); }
    else if (ed.settings.snap) { e.x = G.snap(e.x, ed.settings.grid); e.y = G.snap(e.y, ed.settings.grid); }
    ed.cmd('Add ' + (proto.name || proto.shape || 'element'), function (tx) { tx.add('el', e); });
    ed.select([e.id], []);
    return e;
  };

  ed.deleteSelection = function () {
    var els = ed.editableEls().map(function (e) { return e.id; });
    var cons = ed.selectedConns().filter(function (c) { return !ed.isLocked(c); }).map(function (c) { return c.id; });
    if (!els.length && !cons.length) return;
    var elSet = new Set(els);
    els.forEach(function (id) { store.childrenOf(id).forEach(function (c) { if (!ed.isLocked(c)) elSet.add(c.id); }); });
    ed.cmd('Delete', function (tx) {
      var p = ed.page();
      // connectors attached to deleted elements go too
      p.connectors.forEach(function (c) { if (elSet.has(c.source) || elSet.has(c.target)) cons.push(c.id); });
      Array.from(new Set(cons)).forEach(function (id) { tx.remove('conn', id); });
      elSet.forEach(function (id) { tx.remove('el', id); });
      p.elements.forEach(function (e) { if (elSet.has(e.parent)) tx.touch('el', e.id).parent = ''; });
      p.groups.slice().forEach(function (g) {
        var left = g.members.filter(function (m) { return !elSet.has(m) && cons.indexOf(m) < 0; });
        if (left.length !== g.members.length) { if (left.length < 2) tx.remove('group', g.id); else tx.touch('group', g.id).members = left; }
      });
    });
    ed.clearSelection();
  };

  function selectionPayload() {
    var p = ed.page();
    var ids = new Set(ed.selectedEls().map(function (e) { return e.id; }));
    ed.selectedEls().forEach(function (e) { store.childrenOf(e.id).forEach(function (c) { ids.add(c.id); }); });
    var els = p.elements.filter(function (e) { return ids.has(e.id); });
    var conns = p.connectors.filter(function (c) { return (sel.conns.has(c.id) || (ids.has(c.source) && ids.has(c.target))) && (!c.source || ids.has(c.source)) && (!c.target || ids.has(c.target)); });
    var cids = new Set(conns.map(function (c) { return c.id; }));
    var groups = p.groups.filter(function (g) { return g.members.every(function (m) { return ids.has(m) || cids.has(m); }); });
    return { satomClip: 1, els: DS.clone(els), conns: DS.clone(conns), groups: DS.clone(groups) };
  }
  ed.copy = function () {
    if (!sel.els.size && !sel.conns.size) return;
    ed.clipboard = selectionPayload();
    ed.pasteN = 0;
    try { if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(JSON.stringify(ed.clipboard)).catch(function () { /* best effort */ }); } catch (e) { /* ignore */ }
    DS.toast('Copied ' + ed.clipboard.els.length + ' element(s) and ' + ed.clipboard.conns.length + ' connector(s).', 'info', 1800);
  };
  ed.cut = function () { ed.copy(); ed.deleteSelection(); };
  function pastePayload(clip, offset) {
    if (!clip || (!clip.els.length && !clip.conns.length)) return;
    var layer = ed.currentLayer();
    var map = new Map();
    var page = ed.page();
    var layerIds = new Set(page.layers.map(function (l) { return l.id; }));
    var els = clip.els.map(function (e) {
      var n = M.fillElement(DS.clone(e), layer.id); n.id = M.newId('e'); map.set(e.id, n.id);
      n.x = G.round(n.x + offset); n.y = G.round(n.y + offset);
      if (!layerIds.has(n.layer)) n.layer = layer.id;
      return n;
    });
    els.forEach(function (e) { e.parent = map.get(e.parent) || ''; });
    var conns = clip.conns.map(function (c) {
      var n = M.fillConnector(DS.clone(c), layer.id); n.id = M.newId('c'); map.set(c.id, n.id);
      n.source = map.get(c.source) || ''; n.target = map.get(c.target) || '';
      if (!n.source && c.source) return null;
      if (!n.target && c.target) return null;
      n.points = n.points.map(function (q) { return [q[0] + offset, q[1] + offset]; });
      if (n.start.length === 2) n.start = [n.start[0] + offset, n.start[1] + offset];
      if (n.end.length === 2) n.end = [n.end[0] + offset, n.end[1] + offset];
      if (!layerIds.has(n.layer)) n.layer = layer.id;
      return n;
    }).filter(Boolean);
    var groups = (clip.groups || []).map(function (g) {
      return { id: M.newId('g'), name: g.name || '', members: g.members.map(function (m) { return map.get(m); }).filter(Boolean), layer: layerIds.has(g.layer) ? g.layer : layer.id };
    }).filter(function (g) { return g.members.length; });
    ed.cmd('Paste', function (tx) {
      els.forEach(function (e) { tx.add('el', e); });
      conns.forEach(function (c) { tx.add('conn', c); });
      groups.forEach(function (g) { tx.add('group', g); });
    });
    ed.select(els.map(function (e) { return e.id; }), conns.map(function (c) { return c.id; }));
  }
  ed.paste = function () {
    if (ed.clipboard) { ed.pasteN++; pastePayload(ed.clipboard, 20 * ed.pasteN); return; }
    if (navigator.clipboard && navigator.clipboard.readText) {
      navigator.clipboard.readText().then(function (t) {
        var d = null;
        try { d = JSON.parse(t); } catch (e) { d = null; }
        if (d && d.satomClip === 1 && Array.isArray(d.els) && Array.isArray(d.conns)) { ed.clipboard = d; ed.pasteN = 1; pastePayload(d, 20); }
      }).catch(function () { /* permission denied: nothing to paste */ });
    }
  };
  ed.duplicate = function () { var c = selectionPayload(); if (c.els.length || c.conns.length) pastePayload(c, 20); };

  ed.group = function () {
    var members = ed.selectedEls().map(function (e) { return e.id; }).concat(ed.selectedConns().map(function (c) { return c.id; }));
    if (members.length < 2) { DS.toast('Select at least two items to group.', 'warning'); return; }
    var set = new Set(members);
    var g = { id: M.newId('g'), name: '', members: members, layer: (ed.selectedEls()[0] || ed.selectedConns()[0]).layer };
    ed.cmd('Group', function (tx) {
      ed.page().groups.slice().forEach(function (og) {
        var left = og.members.filter(function (m) { return !set.has(m); });
        if (left.length !== og.members.length) { if (left.length < 2) tx.remove('group', og.id); else tx.touch('group', og.id).members = left; }
      });
      tx.add('group', g);
    });
  };
  ed.ungroup = function () {
    var ids = new Set(Array.from(sel.els).concat(Array.from(sel.conns)));
    var gs = ed.page().groups.filter(function (g) { return g.members.some(function (m) { return ids.has(m); }); });
    if (!gs.length) { DS.toast('The selection is not grouped.', 'info'); return; }
    ed.cmd('Ungroup', function (tx) { gs.forEach(function (g) { tx.remove('group', g.id); }); });
  };

  ed.zorder = function (front) {
    var ids = new Set(ed.editableEls().map(function (e) { return e.id; }));
    var cids = new Set(ed.selectedConns().map(function (c) { return c.id; }));
    if (!ids.size && !cids.size) return;
    ed.cmd(front ? 'Bring to front' : 'Send to back', function (tx) {
      var p = ed.page();
      if (ids.size) {
        tx.order('el');
        var a = p.elements.filter(function (e) { return ids.has(e.id); }), b = p.elements.filter(function (e) { return !ids.has(e.id); });
        var arr = front ? b.concat(a) : a.concat(b);
        p.elements.length = 0; Array.prototype.push.apply(p.elements, arr);
      }
      if (cids.size) {
        tx.order('conn');
        var c1 = p.connectors.filter(function (c) { return cids.has(c.id); }), c2 = p.connectors.filter(function (c) { return !cids.has(c.id); });
        var arr2 = front ? c2.concat(c1) : c1.concat(c2);
        p.connectors.length = 0; Array.prototype.push.apply(p.connectors, arr2);
      }
    });
  };

  /* Apply {id: {x, y[, w, h]}} as one command; children follow their container. */
  ed.applyPositions = function (label, pos, extra) {
    var ids = Object.keys(pos);
    if (!ids.length) return;
    ed.cmd(label, function (tx) {
      ids.forEach(function (id) {
        var e = store.el(id); if (!e) return;
        var dx = pos[id].x - e.x, dy = pos[id].y - e.y;
        var ee = tx.touch('el', id);
        ee.x = pos[id].x; ee.y = pos[id].y;
        if (pos[id].w !== undefined) { ee.w = pos[id].w; ee.h = pos[id].h; }
        if (dx || dy) store.childrenOf(id).forEach(function (c) { if (pos[c.id]) return; var cc = tx.touch('el', c.id); cc.x = G.round(cc.x + dx); cc.y = G.round(cc.y + dy); });
      });
      if (extra) extra(tx);
    });
  };
  ed.align = function (how) {
    var els = ed.editableEls();
    if (els.length < 2) { DS.toast('Select at least two elements to align.', 'warning'); return; }
    ed.applyPositions('Align ' + how, DS.layout.align(els, how));
  };
  ed.distribute = function (axis) {
    var els = ed.editableEls();
    if (els.length < 3) { DS.toast('Select at least three elements to distribute.', 'warning'); return; }
    ed.applyPositions('Distribute', DS.layout.distribute(els, axis));
  };
  ed.sameSize = function () {
    var els = ed.editableEls();
    if (els.length < 2) { DS.toast('Select at least two elements.', 'warning'); return; }
    ed.applyPositions('Same size', DS.layout.sameSize(els, store.el(lastPicked) || els[0]));
  };
  var lastPicked = null;
  ed.on('selection', function () { var a = Array.from(sel.els); lastPicked = a.length ? a[0] : null; });

  ed.autoLayout = function (mode) {
    var p = ed.page();
    var base = ed.editableEls();
    if (base.length < 2) base = p.elements.filter(function (e) { return !ed.isLocked(e); });
    var els = base.filter(function (e) { return !e.parent || !base.some(function (b) { return b.id === e.parent; }); });
    if (els.length < 2) { DS.toast('Nothing to lay out.', 'info'); return; }
    var ids = new Set(els.map(function (e) { return e.id; }));
    var pos = mode === 'tidy' ? DS.layout.tidy(els) : DS.layout.layered(els, p.connectors, mode === 'LR' ? 'LR' : 'TB');
    ed.applyPositions(mode === 'tidy' ? 'Tidy layout' : 'Automatic layout', pos, function (tx) {
      p.connectors.forEach(function (c) {
        if (ids.has(c.source) && ids.has(c.target) && c.points.length) tx.touch('conn', c.id).points = [];
      });
    });
    r.rerouteAll();
    drawOverlay();
  };

  ed.nudge = function (dx, dy) {
    var els = ed.editableEls();
    if (!els.length) return;
    var ids = new Set(els.map(function (e) { return e.id; }));
    els.forEach(function (e) { store.childrenOf(e.id).forEach(function (c) { ids.add(c.id); }); });
    ed.cmd('Nudge', function (tx) {
      ids.forEach(function (id) { var e = tx.touch('el', id); e.x = G.round(e.x + dx); e.y = G.round(e.y + dy); });
    }, { coalesce: 'nudge' });
  };

  /* Set the routing of the selected connectors (or the default for new ones). */
  ed.setRouting = function (routing) {
    ed.settings.routing = routing; ed.saveSettings();
    var cs = ed.selectedConns().filter(function (c) { return !ed.isLocked(c); });
    if (cs.length) ed.cmd('Routing', function (tx) { cs.forEach(function (c) { var cc = tx.touch('conn', c.id); cc.routing = routing; if (routing === 'orthogonal') cc.points = []; }); });
  };

  // ------------------------------------------------------------ viewport

  ed.zoom = function (f) { r.zoomAt(f); };
  ed.zoomTo = function (kk) { var sz = r.size(); var w = r.toWorld(sz.left + sz.w / 2, sz.top + sz.h / 2); r.setView(kk, sz.w / 2 - w[0] * kk, sz.h / 2 - w[1] * kk); };
  ed.fit = function () { r.fit(); };
  r.on(function (what) {
    if (what !== 'view' && what !== 'liveview') return;
    var z = document.getElementById('dsZoomLabel');
    if (z) z.textContent = Math.round(r.view.k * 100) + ' %';
  });

  // ---------------------------------------------------------------- keys

  function inField(t) { return t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable); }
  function onControl(t) {
    return !!(t && t.closest && t !== document.body && !svg.contains(t) &&
      t.closest('button, a[href], summary, [role="button"], [role="option"], [role="tab"], [role="radio"], [role="menuitem"]'));
  }
  DS.on(document, 'keydown', function (ev) {
    if (!document.body.contains(root)) return;
    var mod = ev.ctrlKey || ev.metaKey;
    var key = ev.key;
    if (mod && (key === 's' || key === 'S')) { ev.preventDefault(); ed.save(); return; }
    if (mod && (key === 'f' || key === 'F')) { ev.preventDefault(); ed.emit('search'); return; }
    if (inField(ev.target) || document.querySelector('.modal.show')) return;
    // a focused button / link / summary (inspector, panels, toolbar) keeps its own
    // Enter and Space: picking a swatch with Enter must not also open the text
    // editor, and Space must press the button, not start panning
    if (!mod && (key === 'Enter' || key === ' ') && onControl(ev.target)) return;
    if (key === ' ' && !spaceDown) { spaceDown = true; svg.classList.add('ds-space'); ev.preventDefault(); return; }
    if (key === 'Escape') { if (drag && store.tx) store.rollback(); drag = null; DS.clear(ov.rubber); DS.clear(ov.marquee); ed.clearSelection(); ed.emit('escape'); return; }
    if (key === '?' ) { ev.preventDefault(); ed.emit('help'); return; }
    if (mod && (key === 'z' || key === 'Z') && !ev.shiftKey) { ev.preventDefault(); ed.undo(); return; }
    if (mod && ((key === 'y' || key === 'Y') || ((key === 'z' || key === 'Z') && ev.shiftKey))) { ev.preventDefault(); ed.redo(); return; }
    if (mod && (key === 'a' || key === 'A')) { ev.preventDefault(); ed.selectAll(); return; }
    if (mod && (key === 'c' || key === 'C')) { ev.preventDefault(); ed.copy(); return; }
    if (mod && (key === 'x' || key === 'X')) { ev.preventDefault(); if (canEdit) ed.cut(); return; }
    if (mod && (key === 'v' || key === 'V')) { ev.preventDefault(); if (canEdit) ed.paste(); return; }
    if (mod && (key === 'd' || key === 'D')) { ev.preventDefault(); if (canEdit) ed.duplicate(); return; }
    if (mod && (key === 'g' || key === 'G')) { ev.preventDefault(); if (ev.shiftKey) ed.ungroup(); else ed.group(); return; }
    if (key === 'Delete' || key === 'Backspace') { ev.preventDefault(); if (canEdit) ed.deleteSelection(); return; }
    if (key === 'F2' || (key === 'Enter' && (sel.els.size || sel.conns.size))) { ev.preventDefault(); if (canEdit) ed.editText(); return; }
    var arrows = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] };
    if (arrows[key]) {
      if (!sel.els.size) { var stp = ev.shiftKey ? 200 : 40; r.setViewLive(r.view.k, r.view.x - arrows[key][0] * stp, r.view.y - arrows[key][1] * stp); ev.preventDefault(); return; }
      ev.preventDefault();
      var step = ev.shiftKey ? 10 : 1;
      if (canEdit) ed.nudge(arrows[key][0] * step, arrows[key][1] * step);
      return;
    }
    if (mod) return;
    if (key === '+' || key === '=') { ed.zoom(1.2); return; }
    if (key === '-' || key === '_') { ed.zoom(1 / 1.2); return; }
    if (key === '0') { ed.fit(); return; }
    if (key === '1') { ed.zoomTo(1); return; }
  });
  DS.on(document, 'keyup', function (ev) { if (ev.key === ' ') { spaceDown = false; svg.classList.remove('ds-space'); } });

  ed.undo = function () { if (!canEdit) return; commitTextEdit(); var c = store.undo(); if (c) DS.announce('Undone: ' + c.label); };
  ed.redo = function () { if (!canEdit) return; var c = store.redo(); if (c) DS.announce('Redone: ' + c.label); };

  // -------------------------------------------------------- drop from library

  wrap.addEventListener('dragover', function (ev) {
    if (!canEdit) return;
    if (Array.prototype.indexOf.call(ev.dataTransfer.types, 'application/x-ds-item') >= 0) { ev.preventDefault(); ev.dataTransfer.dropEffect = 'copy'; }
  });
  wrap.addEventListener('drop', function (ev) {
    if (!canEdit) return;
    var raw = ev.dataTransfer.getData('application/x-ds-item');
    if (!raw) return;
    ev.preventDefault();
    var proto = null;
    try { proto = JSON.parse(raw); } catch (e) { return; }
    var p = r.toWorld(ev.clientX, ev.clientY);
    ed.addElement(proto, p);
  });

  // ---------------------------------------------------------------- save

  var saveState = canEdit ? 'saved' : 'readonly';
  var saving = false, conflict = false;
  var STATES = {
    saved: ['check-circle', 'Saved', 'success'], dirty: ['pencil-square', 'Unsaved changes', 'warning'],
    saving: ['arrow-repeat', 'Saving…', 'info'], conflict: ['exclamation-octagon', 'Conflict', 'danger'],
    error: ['x-octagon', 'Not saved', 'danger'], readonly: ['eye', 'Read-only', 'secondary']
  };
  function setState(st) {
    saveState = st;
    if (!statusEl) return;
    var d = STATES[st];
    DS.clear(statusEl);
    statusEl.className = 'fw-badge fw-badge-' + d[2] + ' ds-save-status';
    statusEl.appendChild(DS.icon(d[0]));
    statusEl.appendChild(document.createTextNode(' ' + d[1]));
    statusEl.setAttribute('title', st === 'dirty' ? 'Ctrl+S saves now' + (autosaveOn() ? '; autosave runs after 3 s idle' : '') : d[1]);
  }
  function updateStatus() {
    if (!canEdit) { setState('readonly'); return; }
    if (conflict) { setState('conflict'); return; }
    if (saving) { setState('saving'); return; }
    if (saveState === 'error' && store.dirty()) return;
    setState(store.dirty() ? 'dirty' : 'saved');
    var u = document.getElementById('dsUndo'), rd = document.getElementById('dsRedo');
    if (u) u.disabled = !store.canUndo();
    if (rd) rd.disabled = !store.canRedo();
  }
  ed.updateStatus = updateStatus;
  function autosaveOn() { return canEdit && cfg.autosave !== false && ed.settings.autosave !== false; }
  var autosaveTimer = DS.debounce(function () { if (autosaveOn() && store.dirty() && !conflict && !drag && !editing) ed.save(true); }, 3000);
  function scheduleAutosave() { if (autosaveOn() && store.dirty() && !conflict) autosaveTimer(); }

  ed.docForSave = function () { if (store.tx) store.commit(); var d = store.doc; d.name = diagram.name || d.name; return d; };
  ed.save = function (auto) {
    if (!canEdit) return Promise.resolve(false);
    if (conflict) { if (!auto) conflictDialog(); return Promise.resolve(false); }
    if (saving) return Promise.resolve(false);
    if (!store.dirty()) { if (!auto) DS.toast('Nothing to save.', 'info', 1500); return Promise.resolve(true); }
    commitTextEdit();
    saving = true; updateStatus();
    var rev = store.revision;
    return DS.http('PUT', api.diagram(diagram.id), { doc: ed.docForSave(), version: diagram.version }).then(function (res) {
      saving = false;
      if (res.ok) {
        diagram.version = res.data && res.data.version !== undefined ? res.data.version : diagram.version;
        if (store.revision === rev) store.markSaved(); else store.savedRevision = rev;
        setState(store.dirty() ? 'dirty' : 'saved');
        updateStatus();
        var w = res.data && res.data.warnings;
        if (w && w.length) DS.toast('Saved. The server adjusted ' + w.length + ' item(s): ' + w.slice(0, 3).join('; '), 'warning', 8000);
        ed.emit('saved');
        return true;
      }
      if (res.status === 409) {
        conflict = true; updateStatus();
        ed.conflictVersion = res.data && res.data.current_version;
        conflictDialog();
        return false;
      }
      setState('error');
      DS.toast(DS.errorText(res, 'Save failed'), 'danger');
      return false;
    }, function (err) { saving = false; setState('error'); DS.toast(err.message, 'danger'); return false; });
  };

  function conflictDialog() {
    return DS.dialog({
      title: 'Someone else saved this diagram',
      body: DS.h('div', null, [
        DS.h('p', { text: 'Version ' + (ed.conflictVersion || 'newer') + ' was saved after you opened the editor. Your changes are not saved yet.' }),
        DS.h('ul', { class: 'mb-0 small' }, [
          DS.h('li', { text: 'Reload: open the latest version and discard your changes.' }),
          DS.h('li', { text: 'Save as a copy: keep your version as a new diagram.' })
        ])
      ]),
      buttons: [{ label: 'Keep editing', value: 'keep' }, { label: 'Reload', value: 'reload', danger: true }, { label: 'Save as a copy', value: 'copy', primary: true }]
    }).then(function (choice) {
      if (choice === 'reload') return ed.reload();
      if (choice === 'copy') return ed.saveAsCopy();
      return null;
    });
  }
  ed.conflictDialog = conflictDialog;
  ed.reload = function () {
    return DS.http('GET', api.diagram(diagram.id)).then(function (res) {
      if (!res.ok) { DS.toast(DS.errorText(res, 'Reload failed'), 'danger'); return; }
      var d = res.data || {};
      diagram.version = d.version !== undefined ? d.version : (d.diagram && d.diagram.version);
      if (d.diagram && d.diagram.name) diagram.name = d.diagram.name;
      conflict = false;
      store.replace(d.doc);
      ed.clearSelection();
      updateStatus();
      DS.toast('Reloaded version ' + diagram.version + '.', 'success');
    });
  };
  ed.saveAsCopy = function () {
    var name = (diagram.name || 'Diagram') + ' (copy)';
    return DS.http('POST', api.diagrams(), { name: name.slice(0, 200), folder_id: diagram.folder_id || null, doc: ed.docForSave() }).then(function (res) {
      if (!res.ok) { DS.toast(DS.errorText(res, 'Save as copy failed'), 'danger'); return; }
      store.markSaved();
      DS.toast('Saved as "' + name + '". Opening it…', 'success');
      var url = (res.data && res.data.url) || api.editorPage(res.data.id);
      setTimeout(function () { if (window.Turbo) window.Turbo.visit(url); else window.location.assign(url); }, 400);
    });
  };

  DS.on(window, 'beforeunload', function (ev) {
    if (canEdit && store.dirty()) { ev.preventDefault(); ev.returnValue = ''; return ''; }
  });
  DS.on(document, 'turbo:before-visit', function (ev) {
    if (document.body.contains(root) && canEdit && store.dirty() && !window.confirm('This diagram has unsaved changes. Leave without saving?')) ev.preventDefault();
  });

  // ------------------------------------------------------------------ boot

  ed.setPage = function (i) {
    commitTextEdit();
    if (store.tx) store.commit();
    if (i === store.pageIndex || i < 0 || i >= store.doc.pages.length) return;
    store.pageIndex = i;
    sel.els.clear(); sel.conns.clear();
    fullRender();
    r.fit();
    drawOverlay();
    ed.emit('page'); ed.emit('selection');
  };

  ed.boot = function () {
    if (ed.booted) return;
    ed.booted = true;
    root.classList.toggle('ds-readonly', !canEdit);
    fullRender();
    requestAnimationFrame(function () { r.fit(); drawOverlay(); });
    updateStatus();
    if (window.DS.EditorPanels) window.DS.EditorPanels(ed);
    ed.emit('page'); ed.emit('selection');
    var mm = document.getElementById('dsMinimap');
    if (mm) { ed.minimap = new DS.Minimap(mm, r); requestAnimationFrame(function () { ed.minimap.draw(); }); }
    DS.on(window, 'resize', DS.debounce(function () { if (ed.minimap) ed.minimap.draw(); }, 100));
  };
  // diagram_studio_panels.js loads after this file and calls ed.boot();
  // the timer is only a fallback if that file is missing.
  setTimeout(function () { if (!ed.booted && document.body.contains(root)) ed.boot(); }, 3000);
})();
