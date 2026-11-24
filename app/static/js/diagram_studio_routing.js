/* diagram_studio_routing.js — connector geometry for Diagram Studio.
 *
 * Mirrors app/services/diagram_engine/exporters/_common.py (route_points,
 * route_segments, ARROW_GLYPHS) so what the editor draws is what the
 * exporters write, plus two things the editor adds:
 *   - unfixed ends attach to the NEAREST side (or declared port) of the shape,
 *     re-computed whenever either shape moves;
 *   - "orthogonal" without waypoints is routed AROUND obstacles by A* on a
 *     coarse grid limited to a window around both ends (fast: the grid is
 *     capped at ~6 000 cells, and it falls back to an elbow).
 * DS.routing.bake(doc) writes the computed bends into a COPY of the doc as
 * waypoints, so the server exporters draw the same lines.
 */
(function () {
  'use strict';
  var DS = window.DS;
  var G = DS.geom;
  var R = DS.routing = {};

  var SIDES = [
    { id: 'n', x: 0.5, y: 0, dx: 0, dy: -1 }, { id: 'e', x: 1, y: 0.5, dx: 1, dy: 0 },
    { id: 's', x: 0.5, y: 1, dx: 0, dy: 1 }, { id: 'w', x: 0, y: 0.5, dx: -1, dy: 0 }
  ];
  R.SIDES = SIDES;

  /* Candidate anchor points of an element: its declared ports, else the four
   * side midpoints. Each carries an outward direction. */
  R.anchors = function (e) {
    var c = G.center(e);
    var list = (e.ports && e.ports.length) ? e.ports.map(function (p) {
      var dx = p.x - 0.5, dy = p.y - 0.5;
      var ax = Math.abs(dx) >= Math.abs(dy) ? (dx >= 0 ? 1 : -1) : 0;
      var ay = ax ? 0 : (dy >= 0 ? 1 : -1);
      return { id: p.id, x: p.x, y: p.y, dx: ax, dy: ay, declared: true };
    }) : SIDES;
    return list.map(function (p) {
      var xy = G.rotate(e.x + p.x * e.w, e.y + p.y * e.h, c[0], c[1], e.rotation || 0);
      var d = axisDir(G.rotate(p.dx, p.dy, 0, 0, e.rotation || 0));
      return { id: p.id, x: xy[0], y: xy[1], dx: d[0], dy: d[1], lx: p.x, ly: p.y, declared: !!p.declared };
    });
  };

  /* The stub of an orthogonal route leaves along an AXIS: the rotated side's
   * outward normal snapped to its dominant axis (a tie goes horizontal). A
   * diagonal stub on a rotated shape made the elbow double back on itself. */
  function axisDir(d) {
    var ax = Math.abs(d[0]), ay = Math.abs(d[1]);
    if (ax >= ay || Math.abs(ax - ay) < 1e-9) return [d[0] >= 0 ? 1 : -1, 0];
    return [0, d[1] >= 0 ? 1 : -1];
  }
  R.axisDir = axisDir;

  function portXY(e, pid) {
    var ps = e.ports || [];
    for (var i = 0; i < ps.length; i++) if (ps[i].id === pid) return G.portXY(e, ps[i]);
    for (var j = 0; j < SIDES.length; j++) if (SIDES[j].id === pid) return G.portXY(e, SIDES[j]);
    return null;
  }
  R.portXY = portXY;

  /* Point where the ray from the centre toward q leaves the outline (exporter _clip). */
  function clip(e, qx, qy) {
    var c = G.center(e);
    var rot = e.rotation || 0;
    var q = G.rotate(qx, qy, c[0], c[1], -rot);
    var a = Math.max(e.w / 2, 1e-6), b = Math.max(e.h / 2, 1e-6);
    var dx = q[0] - c[0], dy = q[1] - c[1];
    if (Math.abs(dx) < 1e-9 && Math.abs(dy) < 1e-9) return c;
    var t;
    if (e.shape === 'ellipse' || e.shape === 'cloud') t = 1 / Math.sqrt((dx / a) * (dx / a) + (dy / b) * (dy / b));
    else if (e.shape === 'diamond') t = 1 / (Math.abs(dx) / a + Math.abs(dy) / b);
    else t = Math.min(dx ? a / Math.abs(dx) : Infinity, dy ? b / Math.abs(dy) : Infinity);
    return G.rotate(c[0] + dx * t, c[1] + dy * t, c[0], c[1], rot);
  }
  R.clip = clip;

  function nearestAnchor(e, toward) {
    var best = null, bd = Infinity;
    R.anchors(e).forEach(function (a) {
      var d = G.dist2([a.x, a.y], toward);
      if (d < bd) { bd = d; best = a; }
    });
    return best;
  }
  R.nearestAnchor = nearestAnchor;

  // ------------------------------------------------------------- A* router

  var STUB = 16;
  /* Orthogonal path from anchor a to anchor b avoiding `obstacles` boxes. */
  function astar(a, b, obstacles) {
    var sa = [a.x + a.dx * STUB, a.y + a.dy * STUB];
    var sb = [b.x + b.dx * STUB, b.y + b.dy * STUB];
    var x0 = Math.min(sa[0], sb[0]), y0 = Math.min(sa[1], sb[1]);
    var x1 = Math.max(sa[0], sb[0]), y1 = Math.max(sa[1], sb[1]);
    // grow the window over every obstacle it touches, so a detour exists
    var margin = 40;
    x0 -= margin; y0 -= margin; x1 += margin; y1 += margin;
    for (var pass = 0; pass < 2; pass++) {
      obstacles.forEach(function (o) {
        if (o.x < x1 && o.x + o.w > x0 && o.y < y1 && o.y + o.h > y0) {
          x0 = Math.min(x0, o.x - margin); y0 = Math.min(y0, o.y - margin);
          x1 = Math.max(x1, o.x + o.w + margin); y1 = Math.max(y1, o.y + o.h + margin);
        }
      });
    }
    var cell = 10;
    while (((x1 - x0) / cell) * ((y1 - y0) / cell) > 6000) cell *= 1.5;
    var W = Math.ceil((x1 - x0) / cell) + 1, H = Math.ceil((y1 - y0) / cell) + 1;
    var blocked = new Uint8Array(W * H);
    obstacles.forEach(function (o) {
      var i0 = Math.max(0, Math.floor((o.x - 6 - x0) / cell)), i1 = Math.min(W - 1, Math.ceil((o.x + o.w + 6 - x0) / cell));
      var j0 = Math.max(0, Math.floor((o.y - 6 - y0) / cell)), j1 = Math.min(H - 1, Math.ceil((o.y + o.h + 6 - y0) / cell));
      for (var j = j0; j <= j1; j++) for (var i = i0; i <= i1; i++) blocked[j * W + i] = 1;
    });
    function ix(p) { return [Math.max(0, Math.min(W - 1, Math.round((p[0] - x0) / cell))), Math.max(0, Math.min(H - 1, Math.round((p[1] - y0) / cell)))]; }
    var s = ix(sa), t = ix(sb);
    var sk = s[1] * W + s[0], tk = t[1] * W + t[0];
    blocked[sk] = 0; blocked[tk] = 0;
    // state = cell * 4 + dir (0:E 1:S 2:W 3:N)
    var DX = [1, 0, -1, 0], DY = [0, 1, 0, -1];
    var N = W * H * 4;
    var g = new Float64Array(N).fill(Infinity);
    var from = new Int32Array(N).fill(-1);
    var closed = new Uint8Array(N);
    var heap = [];
    function push(k, f) {
      heap.push([f, k]);
      var i = heap.length - 1;
      while (i > 0) { var p = (i - 1) >> 1; if (heap[p][0] <= heap[i][0]) break; var tmp = heap[p]; heap[p] = heap[i]; heap[i] = tmp; i = p; }
    }
    function pop() {
      var top = heap[0], last = heap.pop();
      if (heap.length) {
        heap[0] = last;
        var i = 0;
        for (;;) {
          var l = 2 * i + 1, r = l + 1, m = i;
          if (l < heap.length && heap[l][0] < heap[m][0]) m = l;
          if (r < heap.length && heap[r][0] < heap[m][0]) m = r;
          if (m === i) break;
          var tmp = heap[m]; heap[m] = heap[i]; heap[i] = tmp; i = m;
        }
      }
      return top;
    }
    function h(c) { var x = c % W, y = (c - x) / W; return Math.abs(x - t[0]) + Math.abs(y - t[1]); }
    var startDir = a.dx > 0.5 ? 0 : a.dy > 0.5 ? 1 : a.dx < -0.5 ? 2 : 3;
    var endDir = b.dx > 0.5 ? 2 : b.dy > 0.5 ? 3 : b.dx < -0.5 ? 0 : 1;  // arriving direction into b
    var st = sk * 4 + startDir;
    g[st] = 0; push(st, h(sk));
    var found = -1, iter = 0;
    while (heap.length && iter++ < 60000) {
      var cur = pop()[1];
      if (closed[cur]) continue;
      closed[cur] = 1;
      var c = cur >> 2, d = cur & 3;
      if (c === tk) { found = cur; break; }
      var cx = c % W, cy = (c - cx) / W;
      for (var nd = 0; nd < 4; nd++) {
        if (nd === ((d + 2) & 3)) continue;
        var nx = cx + DX[nd], ny = cy + DY[nd];
        if (nx < 0 || ny < 0 || nx >= W || ny >= H) continue;
        var nc = ny * W + nx;
        if (blocked[nc]) continue;
        var cost = g[cur] + 1 + (nd !== d ? 6 : 0) + (nc === tk && nd !== endDir ? 6 : 0);
        var nk = nc * 4 + nd;
        if (cost < g[nk]) { g[nk] = cost; from[nk] = cur; push(nk, cost + h(nc)); }
      }
    }
    if (found < 0) return null;
    var cells = [];
    for (var k = found; k >= 0; k = from[k]) cells.push(k >> 2);
    cells.reverse();
    var pts = cells.map(function (c) { var x = c % W; return [x0 + x * cell, y0 + ((c - x) / W) * cell]; });
    pts[0] = sa.slice(); pts[pts.length - 1] = sb.slice();
    // snap the first/last runs onto the stubs so the line leaves straight
    return simplify([[a.x, a.y]].concat(orthogonalise(pts)).concat([[b.x, b.y]]));
  }
  R.astar = astar;

  /* Insert elbows so every segment is horizontal or vertical. */
  function orthogonalise(pts) {
    var out = [pts[0]];
    for (var i = 1; i < pts.length; i++) {
      var p = out[out.length - 1], q = pts[i];
      if (Math.abs(p[0] - q[0]) > 0.5 && Math.abs(p[1] - q[1]) > 0.5) {
        var prevH = out.length > 1 && Math.abs(out[out.length - 2][1] - p[1]) < 0.5;
        out.push(prevH ? [p[0], q[1]] : [q[0], p[1]]);
      }
      out.push(q);
    }
    return out;
  }
  R.orthogonalise = orthogonalise;

  /* Drop duplicate vertices and every vertex between two segments on the
   * same axis -- straight on AND doubling back -- so an orthogonal route never
   * retraces itself. 0.5 px is orthogonalise()'s own alignment tolerance.
   * The first and the last vertex (the two ends) always stay. */
  var TOL = 0.5;
  function sameAxis(a, b, p) {
    return (Math.abs(a[1] - b[1]) <= TOL && Math.abs(b[1] - p[1]) <= TOL) || (Math.abs(a[0] - b[0]) <= TOL && Math.abs(b[0] - p[0]) <= TOL);
  }
  function simplify(pts) {
    var out = [];
    for (var i = 0; i < pts.length; i++) {
      var p = pts[i], dup = false;
      for (;;) {
        var n = out.length;
        if (n && Math.abs(out[n - 1][0] - p[0]) <= TOL && Math.abs(out[n - 1][1] - p[1]) <= TOL && i < pts.length - 1) { dup = true; break; }
        if (n && Math.abs(out[n - 1][0] - p[0]) <= TOL && Math.abs(out[n - 1][1] - p[1]) <= TOL) { if (n > 1) { out.pop(); continue; } dup = true; break; }
        if (n < 2 || !sameAxis(out[n - 2], out[n - 1], p)) break;
        out.pop();
      }
      if (!dup) out.push(p);
    }
    return out;
  }
  /* True when the polyline turns back on itself somewhere (a test helper). */
  R.hasReversal = function (pts) {
    for (var i = 1; i < pts.length - 1; i++) {
      var a = pts[i - 1], b = pts[i], c = pts[i + 1];
      var d1x = b[0] - a[0], d1y = b[1] - a[1], d2x = c[0] - b[0], d2y = c[1] - b[1];
      if (Math.abs(d1y) <= TOL && Math.abs(d2y) <= TOL && d1x * d2x < 0) return true;
      if (Math.abs(d1x) <= TOL && Math.abs(d2x) <= TOL && d1y * d2y < 0) return true;
    }
    return false;
  };
  R.simplify = simplify;

  /* Does an axis-aligned polyline cut into any of the boxes (2 px inset)? */
  function crosses(pts, boxes) {
    for (var i = 0; i < pts.length - 1; i++) {
      var x0 = Math.min(pts[i][0], pts[i + 1][0]), x1 = Math.max(pts[i][0], pts[i + 1][0]);
      var y0 = Math.min(pts[i][1], pts[i + 1][1]), y1 = Math.max(pts[i][1], pts[i + 1][1]);
      for (var j = 0; j < boxes.length; j++) {
        var o = boxes[j];
        if (x1 > o.x + 2 && x0 < o.x + o.w - 2 && y1 > o.y + 2 && y0 < o.y + o.h - 2) return true;
      }
    }
    return false;
  }
  R.crosses = crosses;

  function elbow(a, b) {
    // simple Z/L between two anchors, honouring the leaving directions
    var sa = [a.x + a.dx * STUB, a.y + a.dy * STUB], sb = [b.x + b.dx * STUB, b.y + b.dy * STUB];
    var mid;
    if (Math.abs(a.dx) > 0.5) {
      var mx = (sa[0] + sb[0]) / 2;
      mid = Math.abs(b.dx) > 0.5 ? [[mx, sa[1]], [mx, sb[1]]] : [[sb[0], sa[1]]];
    } else {
      var my = (sa[1] + sb[1]) / 2;
      mid = Math.abs(b.dy) > 0.5 ? [[sa[0], my], [sb[0], my]] : [[sa[0], sb[1]]];
    }
    return simplify(orthogonalise([[a.x, a.y], sa].concat(mid).concat([sb, [b.x, b.y]])));
  }
  R.elbow = elbow;

  // ----------------------------------------------------------- the router

  /* opts: {byId: Map|obj of elements, obstacles: fn(box)->[boxes] (optional)}
   * Returns {pts, d, flat, anchors: {source, target}} in page coordinates. */
  R.route = function (c, byId, opts) {
    opts = opts || {};
    var get = byId instanceof Map ? function (id) { return byId.get(id); } : function (id) { return byId[id]; };
    var src = c.source ? get(c.source) : null, tgt = c.target ? get(c.target) : null;
    var wp = (c.points || []).map(function (p) { return [p[0], p[1]]; });
    var sFree = c.start && c.start.length === 2 ? [c.start[0], c.start[1]] : null;
    var eFree = c.end && c.end.length === 2 ? [c.end[0], c.end[1]] : null;
    var pts;
    if (src && src === tgt && !wp.length) {
      var lx = src.x + src.w, ly = src.y + src.h / 2;
      wp = [[lx + 40, ly - src.h / 4], [lx + 40, ly + src.h / 4]];
    }
    var sc = src ? G.center(src) : null, tc = tgt ? G.center(tgt) : null;
    var afterStart = wp.length ? wp[0] : (tc || eFree || sc || [0, 0]);
    var beforeEnd = wp.length ? wp[wp.length - 1] : (sc || sFree || tc || [0, 0]);

    if (c.routing === 'orthogonal') {
      var aS = src ? (c.source_port && anchorById(src, c.source_port)) || nearestAnchor(src, afterStart) : freeAnchor(sFree || afterStart, afterStart);
      var aE = tgt ? (c.target_port && anchorById(tgt, c.target_port)) || nearestAnchor(tgt, beforeEnd) : freeAnchor(eFree || beforeEnd, beforeEnd);
      if (!wp.length && src && tgt && src !== tgt) {
        var obs = [];
        if (opts.obstacles) {
          var win = { x: Math.min(aS.x, aE.x) - 240, y: Math.min(aS.y, aE.y) - 240, w: Math.abs(aS.x - aE.x) + 480, h: Math.abs(aS.y - aE.y) + 480 };
          obs = opts.obstacles(win, src.id, tgt.id);
        }
        // The plain elbow is what the server draws from the saved connector;
        // only when it runs through another shape does the editor search a
        // detour (and R.bake then hands that detour over as waypoints).
        pts = elbow(aS, aE);
        if (obs.length && crosses(pts, obs)) pts = astar(aS, aE, obs) || pts;
      } else if (!wp.length) {
        pts = elbow(aS, aE);
      } else {
        var s0 = [aS.x, aS.y], e0 = [aE.x, aE.y];
        var body = [s0];
        if (!aS.free) body.push([aS.x + aS.dx * STUB, aS.y + aS.dy * STUB]);
        body = body.concat(wp);
        if (!aE.free) body.push([aE.x + aE.dx * STUB, aE.y + aE.dy * STUB]);
        body.push(e0);
        pts = simplify(orthogonalise(body));
      }
      return finish(c, pts, aS, aE);
    }
    var start, end;
    if (src) start = (c.source_port && portXY(src, c.source_port)) || clip(src, afterStart[0], afterStart[1]);
    else start = sFree || (wp.length ? wp[0] : [0, 0]);
    if (tgt) end = (c.target_port && portXY(tgt, c.target_port)) || clip(tgt, beforeEnd[0], beforeEnd[1]);
    else end = eFree || (wp.length ? wp[wp.length - 1] : start);
    pts = [start].concat(wp).concat([end]);
    return finish(c, pts, null, null);
  };

  function anchorById(e, pid) {
    var all = R.anchors(e);
    for (var i = 0; i < all.length; i++) if (all[i].id === pid) return all[i];
    var xy = portXY(e, pid);
    if (!xy) return null;
    var c = G.center(e), dx = xy[0] - c[0], dy = xy[1] - c[1];
    return Math.abs(dx) / e.w >= Math.abs(dy) / e.h ? { x: xy[0], y: xy[1], dx: dx >= 0 ? 1 : -1, dy: 0 } : { x: xy[0], y: xy[1], dx: 0, dy: dy >= 0 ? 1 : -1 };
  }
  /* A free end: the line leaves p along the dominant axis toward its neighbour. */
  function freeAnchor(p, toward) {
    var dx = toward[0] - p[0], dy = toward[1] - p[1];
    var h = Math.abs(dx) >= Math.abs(dy);
    return { x: p[0], y: p[1], dx: h ? (dx >= 0 ? 1 : -1) : 0, dy: h ? 0 : (dy >= 0 ? 1 : -1), free: true };
  }

  function finish(c, pts, aS, aE) {
    if (pts.length === 1) pts = [pts[0], pts[0]];
    var d = 'M' + n(pts[0][0]) + ' ' + n(pts[0][1]);
    var flat;
    if (c.routing === 'curved') {
      var segs = curve(pts);
      segs.forEach(function (s) { d += ' C' + s.slice(0, 6).map(n).join(' '); });
      flat = flatten(pts[0], segs);
    } else {
      for (var i = 1; i < pts.length; i++) d += ' L' + n(pts[i][0]) + ' ' + n(pts[i][1]);
      flat = pts;
    }
    return { pts: pts, d: d, flat: flat, anchors: { source: aS, target: aE } };
  }
  function n(v) { return String(Math.round(v * 100) / 100); }

  function curve(pts) {
    var out = [];
    if (pts.length === 2) {
      var x0 = pts[0][0], y0 = pts[0][1], x1 = pts[1][0], y1 = pts[1][1];
      if (Math.abs(x1 - x0) >= Math.abs(y1 - y0)) out.push([(x0 + x1) / 2, y0, (x0 + x1) / 2, y1, x1, y1]);
      else out.push([x0, (y0 + y1) / 2, x1, (y0 + y1) / 2, x1, y1]);
      return out;
    }
    for (var i = 0; i < pts.length - 1; i++) {
      var p0 = i > 0 ? pts[i - 1] : pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = i + 2 < pts.length ? pts[i + 2] : pts[i + 1];
      out.push([p1[0] + (p2[0] - p0[0]) / 6, p1[1] + (p2[1] - p0[1]) / 6, p2[0] - (p3[0] - p1[0]) / 6, p2[1] - (p3[1] - p1[1]) / 6, p2[0], p2[1]]);
    }
    return out;
  }
  function flatten(p0, segs) {
    var out = [p0], cx = p0[0], cy = p0[1];
    segs.forEach(function (s) {
      for (var k = 1; k <= 12; k++) {
        var t = k / 12, u = 1 - t;
        out.push([u * u * u * cx + 3 * u * u * t * s[0] + 3 * u * t * t * s[2] + t * t * t * s[4],
          u * u * u * cy + 3 * u * u * t * s[1] + 3 * u * t * t * s[3] + t * t * t * s[5]]);
      }
      cx = s[4]; cy = s[5];
    });
    return out;
  }

  R.pointAlong = function (poly, pos) {
    if (poly.length === 1) return poly[0];
    var lens = [], total = 0;
    for (var i = 0; i < poly.length - 1; i++) { var l = Math.hypot(poly[i + 1][0] - poly[i][0], poly[i + 1][1] - poly[i][1]); lens.push(l); total += l; }
    if (total <= 0) return poly[0];
    var goal = pos * total, acc = 0;
    for (var j = 0; j < lens.length; j++) {
      if (acc + lens[j] >= goal && lens[j] > 0) {
        var t = (goal - acc) / lens[j];
        return [poly[j][0] + (poly[j + 1][0] - poly[j][0]) * t, poly[j][1] + (poly[j + 1][1] - poly[j][1]) * t];
      }
      acc += lens[j];
    }
    return poly[poly.length - 1];
  };
  /* 0..1 position of the projection of p on the polyline. */
  R.posOf = function (poly, p) {
    var total = 0, lens = [];
    for (var i = 0; i < poly.length - 1; i++) { var l = Math.hypot(poly[i + 1][0] - poly[i][0], poly[i + 1][1] - poly[i][1]); lens.push(l); total += l; }
    if (!total) return 0.5;
    var best = Infinity, at = 0, acc = 0;
    for (var j = 0; j < lens.length; j++) {
      var s = G.segDist(p, poly[j], poly[j + 1]);
      if (s.d < best) { best = s.d; at = acc + s.t * lens[j]; }
      acc += lens[j];
    }
    return Math.max(0, Math.min(1, at / total));
  };
  /* Index of the polyline segment nearest to p and the distance. */
  R.nearestSegment = function (poly, p) {
    var best = { i: -1, d: Infinity };
    for (var j = 0; j < poly.length - 1; j++) {
      var s = G.segDist(p, poly[j], poly[j + 1]);
      if (s.d < best.d) best = { i: j, d: s.d, x: s.x, y: s.y };
    }
    return best;
  };

  // Arrow glyphs (exporter ARROW_GLYPHS): tip at the origin, pointing +x.
  R.ARROW_GLYPHS = {
    arrow: [{ t: 'poly', pts: [[0, 0], [-11, -4.5], [-11, 4.5]], fill: 'stroke' }],
    open: [{ t: 'line', pts: [[-11, -5], [0, 0], [-11, 5]], fill: null }],
    diamond: [{ t: 'poly', pts: [[0, 0], [-7, -4.5], [-14, 0], [-7, 4.5]], fill: 'stroke' }],
    diamond_open: [{ t: 'poly', pts: [[0, 0], [-7, -4.5], [-14, 0], [-7, 4.5]], fill: 'white' }],
    circle: [{ t: 'circle', c: [-4.5, 0], r: 4.5, fill: 'stroke' }],
    circle_open: [{ t: 'circle', c: [-4.5, 0], r: 4.5, fill: 'white' }],
    crowfoot: [{ t: 'line', pts: [[0, -6], [-11, 0], [0, 6]], fill: null }, { t: 'line', pts: [[0, 0], [-11, 0]], fill: null }],
    bar: [{ t: 'line', pts: [[-4, -6], [-4, 6]], fill: null }]
  };

  /* A copy of the doc for the server exporters. An orthogonal connector whose
   * on-screen route went AROUND obstacles carries that route's bends as
   * waypoints; every other connector is left exactly as saved, because the
   * server computes the same route from it (exporters/_common.py
   * route_points is a port of R.route without the obstacle search). So an
   * export re-imports with the saved waypoints, and a detour is drawn as seen. */
  R.bake = function (doc, routeOf) {
    var out = DS.clone(doc);
    out.pages.forEach(function (p, pi) {
      var byId = new Map(p.elements.map(function (e) { return [e.id, e]; }));
      p.connectors.forEach(function (c) {
        if (c.routing !== 'orthogonal') return;
        var r = routeOf(pi, c.id);
        if (!r || r.pts.length <= 2) return;
        var plain = R.route(c, byId).pts;
        var same = plain.length === r.pts.length && plain.every(function (q, i) { return Math.abs(q[0] - r.pts[i][0]) < 0.01 && Math.abs(q[1] - r.pts[i][1]) < 0.01; });
        if (same) return;
        c.points = r.pts.slice(1, -1).map(function (q) { return [Math.round(q[0] * 100) / 100, Math.round(q[1] * 100) / 100]; });
      });
    });
    return out;
  };
})();
