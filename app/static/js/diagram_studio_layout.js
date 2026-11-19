/* diagram_studio_layout.js — alignment and automatic layout for Diagram Studio.
 *
 * Pure functions over element objects: they return {id: {x, y[, w, h]}} and
 * the editor applies the result as ONE undoable command.
 *   align / distribute / sameSize — on the selection;
 *   layered(direction) — longest-path layering + barycentre ordering
 *     (a light Sugiyama: cycles broken by DFS, dummy-free, 4 sweeps);
 *   tidy — a grid sorted by reading order.
 */
(function () {
  'use strict';
  var DS = window.DS;
  var G = DS.geom;
  var L = DS.layout = {};

  L.align = function (els, how) {
    if (els.length < 2) return {};
    var b = G.union(els.map(function (e) { return { x: e.x, y: e.y, w: e.w, h: e.h }; }));
    var out = {};
    els.forEach(function (e) {
      var x = e.x, y = e.y;
      if (how === 'left') x = b.x;
      else if (how === 'center') x = b.x + b.w / 2 - e.w / 2;
      else if (how === 'right') x = b.x + b.w - e.w;
      else if (how === 'top') y = b.y;
      else if (how === 'middle') y = b.y + b.h / 2 - e.h / 2;
      else if (how === 'bottom') y = b.y + b.h - e.h;
      out[e.id] = { x: G.round(x), y: G.round(y) };
    });
    return out;
  };

  /* Equal gaps between neighbours, the extremes stay where they are. */
  L.distribute = function (els, axis) {
    if (els.length < 3) return {};
    var horiz = axis === 'h';
    var sorted = els.slice().sort(function (a, b) { return horiz ? a.x - b.x : a.y - b.y; });
    var first = sorted[0], last = sorted[sorted.length - 1];
    var span = horiz ? (last.x + last.w) - first.x : (last.y + last.h) - first.y;
    var sizes = sorted.reduce(function (acc, e) { return acc + (horiz ? e.w : e.h); }, 0);
    var gap = (span - sizes) / (sorted.length - 1);
    var pos = horiz ? first.x : first.y;
    var out = {};
    sorted.forEach(function (e) {
      out[e.id] = horiz ? { x: G.round(pos), y: e.y } : { x: e.x, y: G.round(pos) };
      pos += (horiz ? e.w : e.h) + gap;
    });
    return out;
  };

  /* Every selected element takes the size of the first (the anchor). */
  L.sameSize = function (els, anchor) {
    var a = anchor || els[0];
    var out = {};
    els.forEach(function (e) { out[e.id] = { x: e.x, y: e.y, w: a.w, h: a.h }; });
    return out;
  };

  /* Layered layout for flows. dir: 'TB' (top-down) or 'LR'. */
  L.layered = function (els, conns, dir, opts) {
    opts = opts || {};
    var gapMain = opts.gapMain || 70, gapCross = opts.gapCross || 40;
    var ids = els.map(function (e) { return e.id; });
    var byId = new Map(els.map(function (e) { return [e.id, e]; }));
    var out = new Map(ids.map(function (id) { return [id, []]; }));
    var inn = new Map(ids.map(function (id) { return [id, []]; }));
    var seenEdge = new Set();
    conns.forEach(function (c) {
      if (!byId.has(c.source) || !byId.has(c.target) || c.source === c.target) return;
      var key = c.source + '>' + c.target;
      if (seenEdge.has(key)) return;
      seenEdge.add(key);
      out.get(c.source).push(c.target); inn.get(c.target).push(c.source);
    });
    // break cycles: DFS, drop back edges
    var state = new Map(), back = new Set();
    function dfs(root) {
      var stack = [[root, 0]];
      state.set(root, 1);
      while (stack.length) {
        var top = stack[stack.length - 1], v = top[0], kids = out.get(v);
        if (top[1] < kids.length) {
          var w = kids[top[1]++];
          var st = state.get(w);
          if (st === 1) back.add(v + '>' + w);
          else if (!st) { state.set(w, 1); stack.push([w, 0]); }
        } else { state.set(v, 2); stack.pop(); }
      }
    }
    // start from sources first so the main flow keeps its direction
    ids.filter(function (id) { return !inn.get(id).length; }).concat(ids).forEach(function (id) { if (!state.get(id)) dfs(id); });
    function fwd(v) { return out.get(v).filter(function (w) { return !back.has(v + '>' + w); }).concat(inn.get(v).filter(function (u) { return back.has(u + '>' + v); })); }
    // longest-path layering (Kahn)
    var indeg = new Map(ids.map(function (id) { return [id, 0]; }));
    ids.forEach(function (v) { fwd(v).forEach(function (w) { indeg.set(w, indeg.get(w) + 1); }); });
    var rank = new Map(), queue = ids.filter(function (id) { return !indeg.get(id); });
    queue.forEach(function (id) { rank.set(id, 0); });
    while (queue.length) {
      var v = queue.shift();
      fwd(v).forEach(function (w) {
        rank.set(w, Math.max(rank.get(w) || 0, rank.get(v) + 1));
        indeg.set(w, indeg.get(w) - 1);
        if (!indeg.get(w)) queue.push(w);
      });
    }
    ids.forEach(function (id) { if (!rank.has(id)) rank.set(id, 0); });
    var layers = [];
    ids.forEach(function (id) { var r = rank.get(id); (layers[r] = layers[r] || []).push(id); });
    layers = layers.filter(Boolean);
    // initial order: reading order of the current drawing
    var horiz = dir === 'LR';
    layers.forEach(function (layer) { layer.sort(function (a, b) { var A = byId.get(a), B = byId.get(b); return horiz ? A.y - B.y : A.x - B.x; }); });
    // barycentre sweeps
    var nbrs = function (v, up) { return up ? inn.get(v).concat(out.get(v).filter(function (w) { return back.has(v + '>' + w); })) : out.get(v); };
    for (var sweep = 0; sweep < 4; sweep++) {
      var down = sweep % 2 === 0;
      var range = down ? layers.map(function (_, i) { return i; }).slice(1) : layers.map(function (_, i) { return i; }).slice(0, -1).reverse();
      range.forEach(function (li) {
        var ref = layers[down ? li - 1 : li + 1];
        var pos = new Map(ref.map(function (id, i) { return [id, i]; }));
        var bc = new Map();
        layers[li].forEach(function (v, i) {
          var ns = nbrs(v, down).filter(function (w) { return pos.has(w); });
          bc.set(v, ns.length ? ns.reduce(function (a, w) { return a + pos.get(w); }, 0) / ns.length : i);
        });
        layers[li].sort(function (a, b) { return bc.get(a) - bc.get(b); });
      });
    }
    // coordinates: each layer centred on the widest one
    var bbox = G.union(els.map(function (e) { return { x: e.x, y: e.y, w: e.w, h: e.h }; }));
    var x0 = opts.origin ? opts.origin[0] : bbox.x, y0 = opts.origin ? opts.origin[1] : bbox.y;
    var layerSpan = layers.map(function (layer) { return layer.reduce(function (a, id) { var e = byId.get(id); return a + (horiz ? e.h : e.w); }, 0) + gapCross * (layer.length - 1); });
    var layerDepth = layers.map(function (layer) { return Math.max.apply(null, layer.map(function (id) { var e = byId.get(id); return horiz ? e.w : e.h; })); });
    var maxSpan = Math.max.apply(null, layerSpan);
    var res = {}, main = horiz ? x0 : y0;
    layers.forEach(function (layer, li) {
      var cross = (horiz ? y0 : x0) + (maxSpan - layerSpan[li]) / 2;
      layer.forEach(function (id) {
        var e = byId.get(id);
        var d = layerDepth[li];
        if (horiz) res[id] = { x: G.round(main + (d - e.w) / 2), y: G.round(cross) };
        else res[id] = { x: G.round(cross), y: G.round(main + (d - e.h) / 2) };
        cross += (horiz ? e.h : e.w) + gapCross;
      });
      main += layerDepth[li] + gapMain;
    });
    return res;
  };

  /* A tidy grid in reading order; cell = the largest element + gap. */
  L.tidy = function (els, opts) {
    opts = opts || {};
    if (!els.length) return {};
    var gap = opts.gap || 40;
    var bbox = G.union(els.map(function (e) { return { x: e.x, y: e.y, w: e.w, h: e.h }; }));
    var cw = Math.max.apply(null, els.map(function (e) { return e.w; })) + gap;
    var ch = Math.max.apply(null, els.map(function (e) { return e.h; })) + gap;
    var cols = Math.max(1, Math.ceil(Math.sqrt(els.length * ch / cw)));
    var rowTol = ch / 2;
    var sorted = els.slice().sort(function (a, b) { return Math.abs(a.y - b.y) > rowTol ? a.y - b.y : a.x - b.x; });
    var res = {};
    sorted.forEach(function (e, i) {
      var c = i % cols, r = Math.floor(i / cols);
      res[e.id] = { x: G.round(bbox.x + c * cw + (cw - gap - e.w) / 2), y: G.round(bbox.y + r * ch + (ch - gap - e.h) / 2) };
    });
    return res;
  };
})();
