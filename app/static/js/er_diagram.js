/* er_diagram.js — zero-dependency interactive ER / SCHEMA diagram (SVG).
 *
 * Renders the PostgreSQL relational model as a real database SCHEMA: every table
 * is a node with a header (table name) and one ROW PER COLUMN — column name,
 * type, and a 🔑 primary-key / ◇ foreign-key marker — and foreign keys are drawn
 * as connectors anchored on the actual FK column. Pure vanilla JS + SVG so it
 * works offline (no CDN), in line with the offline-installer goal.
 *
 * Palette follows the app's FortiWeb template (app/static/css/fortiweb.css):
 * navy headers (--fw-sidebar-bg #1D3452), orange accent (--fw-accent #EF5424)
 * connectors/markers, white nodes on a light gridded canvas — so it reads as
 * part of the product, not a dark island.
 *
 * Features: force-directed auto-layout, drag a table, pan (drag background),
 * wheel zoom, hover-highlight of a table's relationships, "Fit" + "Re-layout".
 * Data shape:
 *   tables = [{name, columns:int, pk:[...], cols:[{name,type,pk,fk,sensitive}]}]
 *   edges  = [{from_table, from_col, to_table, to_col}]
 */
(function () {
  "use strict";
  var NS = "http://www.w3.org/2000/svg";
  var HEADER_H = 28, ROW_H = 18, MAX_ROWS = 20, CHAR_W = 6.4;

  // Theme tokens — mirror the --fw-* CSS variables in fortiweb.css.
  var T = {
    bg:            "#F8F9FB",            // canvas (matches --fw-content-bg family)
    grid:          "rgba(29,52,82,0.05)",
    svgBorder:     "#DEE2E6",            // --fw-border
    nodeBody:      "#FFFFFF",
    nodeBorder:    "#DEE2E6",            // --fw-border
    nodeBorderHi:  "#EF5424",            // --fw-accent (hovered table)
    nodeBorderRef: "#1D3452",            // --fw-sidebar-bg (related tables)
    headerText:    "#FFFFFF",
    zebra:         "rgba(29,52,82,0.035)",
    pk:            "#E0A800",            // gold key
    fk:            "#EF5424",            // --fw-accent diamond
    colName:       "#212529",            // --fw-text-primary
    colNameFk:     "#C2461C",            // accent-tinted FK column
    colType:       "#8A94A0",
    more:          "#6C757D",            // --fw-text-secondary
    edge:          "rgba(239,84,36,0.55)",
    edgeHi:        "#EF5424",
    edgeFade:      "rgba(29,52,82,0.10)",
  };

  function el(name, attrs) {
    var e = document.createElementNS(NS, name);
    if (attrs) { for (var k in attrs) { e.setAttribute(k, attrs[k]); } }
    return e;
  }

  function ERDiagram(host, tables, edges) {
    this.host = host;
    this.tables = tables || [];
    this.edges = edges || [];
    this.scale = 1;
    this.tx = 0;
    this.ty = 0;
    this.W = host.clientWidth || 1000;
    this.H = 660;
    this.nodes = {};
    this._build();
    this._layout(340);
    this._render();
    this.fit();
  }

  ERDiagram.prototype._build = function () {
    var self = this, n = this.tables.length || 1, i = 0;
    var R = Math.min(this.W, this.H) * 0.42 + n * 6;
    this.tables.forEach(function (t) {
      var cols = t.cols || [];
      // width from the widest "name  type" row (or the table name)
      var widest = String(t.name).length + 4;
      cols.forEach(function (c) {
        var len = String(c.name).length + String(c.type || "").length + 6;
        if (len > widest) widest = len;
      });
      var w = Math.max(176, Math.min(340, Math.round(widest * CHAR_W) + 44));
      var visible = Math.min(cols.length, MAX_ROWS);
      var more = cols.length - visible;
      var h = HEADER_H + visible * ROW_H + (more > 0 ? ROW_H : 0) + 6;
      var ang = (i / n) * Math.PI * 2;
      var idx = {};
      cols.forEach(function (c, ci) { idx[c.name] = ci; });
      self.nodes[t.name] = {
        name: t.name, cols: cols, colIdx: idx, visible: visible, more: more,
        pk: (t.pk || []).join(", "),
        x: self.W / 2 + Math.cos(ang) * R + (i % 5) * 4,
        y: self.H / 2 + Math.sin(ang) * R + (i % 7) * 4,
        vx: 0, vy: 0, w: w, h: h, deg: 0,
      };
      i++;
    });
    // links between existing nodes; remember each end's column row index
    this.links = this.edges.filter(function (e) {
      return self.nodes[e.from_table] && self.nodes[e.to_table] &&
             e.from_table !== e.to_table;
    }).map(function (e) {
      var s = self.nodes[e.from_table], t = self.nodes[e.to_table];
      s.deg++; t.deg++;
      var fi = e.from_col in s.colIdx ? s.colIdx[e.from_col] : -1;
      var ti = e.to_col in t.colIdx ? t.colIdx[e.to_col] : -1;
      return { s: s, t: t, from_col: e.from_col, to_col: e.to_col,
               fi: fi, ti: ti };
    });
    // self-references (drawn as a small loop badge on the header)
    this.selfRefs = {};
    this.edges.forEach(function (e) {
      if (e.from_table === e.to_table && self.nodes[e.from_table]) {
        self.selfRefs[e.from_table] = true;
      }
    });
  };

  ERDiagram.prototype._layout = function (iters) {
    var arr = [], k;
    for (k in this.nodes) { arr.push(this.nodes[k]); }
    var W = this.W, H = this.H, links = this.links;
    for (var it = 0; it < iters; it++) {
      for (var i = 0; i < arr.length; i++) {
        for (var j = i + 1; j < arr.length; j++) {
          var a = arr[i], b = arr[j];
          var dx = a.x - b.x, dy = a.y - b.y;
          var d2 = dx * dx + dy * dy || 0.01;
          var d = Math.sqrt(d2);
          var rep = 46000 / d2;
          var fx = dx / d * rep, fy = dy / d * rep;
          a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
        }
      }
      links.forEach(function (l) {
        var dx = l.t.x - l.s.x, dy = l.t.y - l.s.y;
        var d = Math.sqrt(dx * dx + dy * dy) || 0.01;
        var rest = (l.s.w + l.t.w) / 2 + 130;
        var f = (d - rest) * 0.02;
        var fx = dx / d * f, fy = dy / d * f;
        l.s.vx += fx; l.s.vy += fy; l.t.vx -= fx; l.t.vy -= fy;
      });
      for (var m = 0; m < arr.length; m++) {
        var nd = arr[m];
        nd.vx += (W / 2 - nd.x) * 0.0014;
        nd.vy += (H / 2 - nd.y) * 0.0014;
        nd.vx *= 0.85; nd.vy *= 0.85;
        nd.x += Math.max(-30, Math.min(30, nd.vx));
        nd.y += Math.max(-30, Math.min(30, nd.vy));
      }
    }
  };

  ERDiagram.prototype._render = function () {
    var self = this;
    this.host.innerHTML = "";
    this.host.style.position = "relative";

    var bar = document.createElement("div");
    bar.style.cssText = "position:absolute;top:8px;right:8px;z-index:5;display:flex;gap:6px;";
    bar.innerHTML =
      '<button type="button" class="btn btn-outline-secondary btn-sm" data-er="fit">Fit</button>' +
      '<button type="button" class="btn btn-outline-secondary btn-sm" data-er="relayout">Re-layout</button>';
    this.host.appendChild(bar);
    bar.querySelector('[data-er="fit"]').onclick = function () { self.fit(); };
    bar.querySelector('[data-er="relayout"]').onclick = function () {
      for (var k in self.nodes) { self.nodes[k].vx = self.nodes[k].vy = 0; }
      self._layout(340); self._draw(); self.fit();
    };

    var svg = el("svg", { width: "100%", height: this.H,
      style: "display:block;background:" + T.bg +
             ";border-radius:8px;border:1px solid " + T.svgBorder + ";cursor:grab;" });
    var defs = el("defs");
    // grid (schema-paper feel; pans/zooms with the content)
    var pat = el("pattern", { id: "er-grid", width: "26", height: "26",
      patternUnits: "userSpaceOnUse" });
    pat.appendChild(el("path", { d: "M 26 0 L 0 0 0 26", fill: "none",
      stroke: T.grid, "stroke-width": "1" }));
    defs.appendChild(pat);
    var mk = el("marker", { id: "er-arrow", viewBox: "0 0 10 10", refX: "9",
      refY: "5", markerWidth: "7", markerHeight: "7", orient: "auto-start-reverse" });
    mk.appendChild(el("path", { d: "M 0 0 L 10 5 L 0 10 z", fill: T.fk, opacity: "0.7" }));
    defs.appendChild(mk);
    var mkH = el("marker", { id: "er-arrow-hi", viewBox: "0 0 10 10", refX: "9",
      refY: "5", markerWidth: "8", markerHeight: "8", orient: "auto-start-reverse" });
    mkH.appendChild(el("path", { d: "M 0 0 L 10 5 L 0 10 z", fill: T.edgeHi }));
    defs.appendChild(mkH);
    // header gradient — navy (sidebar) deepening for a little depth
    var grad = el("linearGradient", { id: "er-grad", x1: "0", y1: "0", x2: "0", y2: "1" });
    grad.appendChild(el("stop", { offset: "0", "stop-color": "#274163" }));
    grad.appendChild(el("stop", { offset: "1", "stop-color": "#1D3452" }));
    defs.appendChild(grad);
    svg.appendChild(defs);

    this.gRoot = el("g");
    // grid plane (large, centred) behind everything
    this.gRoot.appendChild(el("rect", { x: this.W / 2 - 3000, y: this.H / 2 - 3000,
      width: 6000, height: 6000, fill: "url(#er-grid)" }));
    this.gEdges = el("g");
    this.gNodes = el("g");
    this.gRoot.appendChild(this.gEdges);
    this.gRoot.appendChild(this.gNodes);
    svg.appendChild(this.gRoot);
    this.svg = svg;
    this.host.appendChild(svg);

    this._draw();
    this._wirePanZoom();
  };

  // absolute y of the centre of a column row (clamped to the visible rows)
  ERDiagram.prototype._rowY = function (n, idx) {
    var i = idx < 0 ? -1 : Math.min(idx, n.visible - 1);
    var topY = n.y - n.h / 2;
    if (i < 0) { return n.y; }                 // unknown col → table centre
    return topY + HEADER_H + ROW_H * i + ROW_H / 2;
  };

  ERDiagram.prototype._edgePath = function (l) {
    var s = l.s, t = l.t;
    var sy = this._rowY(s, l.fi), ty = this._rowY(t, l.ti);
    var sRight = t.x >= s.x;
    var x1 = sRight ? s.x + s.w / 2 : s.x - s.w / 2;
    var x2 = sRight ? t.x - t.w / 2 : t.x + t.w / 2;
    var dx = Math.abs(x2 - x1);
    var k = Math.max(34, dx * 0.45);
    var c1 = sRight ? x1 + k : x1 - k;
    var c2 = sRight ? x2 - k : x2 + k;
    return "M " + x1 + " " + sy + " C " + c1 + " " + sy + " " +
           c2 + " " + ty + " " + x2 + " " + ty;
  };

  ERDiagram.prototype._draw = function () {
    var self = this;
    this.gEdges.innerHTML = "";
    this.gNodes.innerHTML = "";

    this.links.forEach(function (l) {
      var p = el("path", { d: self._edgePath(l), fill: "none",
        stroke: T.edge, "stroke-width": "1.6",
        "marker-end": "url(#er-arrow)" });
      var title = el("title");
      title.textContent = l.s.name + "." + l.from_col + " → " + l.t.name + "." + l.to_col;
      p.appendChild(title);
      l._path = p;
      self.gEdges.appendChild(p);
    });

    for (var k in this.nodes) {
      (function (n) {
        var g = el("g", {
          transform: "translate(" + (n.x - n.w / 2) + "," + (n.y - n.h / 2) + ")",
          style: "cursor:move;" });

        // body + border (subtle drop shadow via two rects)
        var shadow = el("rect", { x: 0, y: 2, width: n.w, height: n.h, rx: 8, ry: 8,
          fill: "rgba(29,52,82,0.10)" });
        g.appendChild(shadow);
        var rect = el("rect", { width: n.w, height: n.h, rx: 8, ry: 8,
          fill: T.nodeBody, stroke: T.nodeBorder, "stroke-width": "1.2" });
        g.appendChild(rect);

        // header
        var hdr = el("path", {
          d: "M0," + HEADER_H + " V8 Q0,0 8,0 H" + (n.w - 8) +
             " Q" + n.w + ",0 " + n.w + ",8 V" + HEADER_H + " Z",
          fill: "url(#er-grad)" });
        g.appendChild(hdr);
        var title = el("text", { x: 10, y: 19, fill: T.headerText,
          "font-size": "12.5", "font-weight": "700",
          "font-family": "'Segoe UI',system-ui,sans-serif" });
        title.textContent = n.name;
        g.appendChild(title);
        if (self.selfRefs[n.name]) {
          var loop = el("text", { x: n.w - 16, y: 19, fill: T.headerText, "font-size": "12" });
          loop.textContent = "↺"; g.appendChild(loop);
        }

        // column rows
        for (var ci = 0; ci < n.visible; ci++) {
          var c = n.cols[ci];
          var ry = HEADER_H + ci * ROW_H;
          if (ci % 2 === 1) {
            g.appendChild(el("rect", { x: 1, y: ry, width: n.w - 2, height: ROW_H,
              fill: T.zebra }));
          }
          var marker = c.pk ? "🔑" : (c.fk ? "◇" : "");
          if (marker) {
            var mk = el("text", { x: 8, y: ry + 13, "font-size": c.pk ? "9.5" : "11",
              fill: c.pk ? T.pk : T.fk,
              "font-family": "'Segoe UI',system-ui,sans-serif" });
            mk.textContent = marker; g.appendChild(mk);
          }
          var nm = el("text", { x: 24, y: ry + 13, "font-size": "11",
            fill: c.fk ? T.colNameFk : T.colName,
            "font-weight": (c.pk || c.fk) ? "600" : "400",
            "font-family": "'Segoe UI',system-ui,sans-serif" });
          nm.textContent = c.name + (c.sensitive ? " •" : "");
          g.appendChild(nm);
          var ty = el("text", { x: n.w - 8, y: ry + 13, "text-anchor": "end",
            "font-size": "9.5", fill: T.colType,
            "font-family": "ui-monospace,Menlo,monospace" });
          ty.textContent = c.type; g.appendChild(ty);
        }
        if (n.more > 0) {
          var mr = el("text", { x: n.w / 2, y: HEADER_H + n.visible * ROW_H + 13,
            "text-anchor": "middle", "font-size": "10", fill: T.more,
            "font-style": "italic", "font-family": "'Segoe UI',system-ui,sans-serif" });
          mr.textContent = "+ " + n.more + " more column" + (n.more > 1 ? "s" : "");
          g.appendChild(mr);
        }

        n._g = g; n._rect = rect;
        self._nodeHover(n, g, rect);
        self._nodeDrag(n, g);
        self.gNodes.appendChild(g);
      })(this.nodes[k]);
    }
  };

  ERDiagram.prototype._nodeHover = function (n, g, rect) {
    var self = this;
    g.addEventListener("mouseenter", function () {
      rect.setAttribute("stroke", T.nodeBorderHi);
      rect.setAttribute("stroke-width", "2.2");
      self.links.forEach(function (l) {
        if (l.s.name === n.name || l.t.name === n.name) {
          l._path.setAttribute("stroke", T.edgeHi);
          l._path.setAttribute("stroke-width", "2.6");
          l._path.setAttribute("marker-end", "url(#er-arrow-hi)");
          if (l.s.name === n.name && l.t._rect) l.t._rect.setAttribute("stroke", T.nodeBorderRef);
          if (l.t.name === n.name && l.s._rect) l.s._rect.setAttribute("stroke", T.nodeBorderRef);
        } else {
          l._path.setAttribute("stroke", T.edgeFade);
        }
      });
    });
    g.addEventListener("mouseleave", function () { self._resetStyles(); });
  };

  ERDiagram.prototype._resetStyles = function () {
    for (var k in this.nodes) {
      this.nodes[k]._rect.setAttribute("stroke", T.nodeBorder);
      this.nodes[k]._rect.setAttribute("stroke-width", "1.2");
    }
    this.links.forEach(function (l) {
      l._path.setAttribute("stroke", T.edge);
      l._path.setAttribute("stroke-width", "1.6");
      l._path.setAttribute("marker-end", "url(#er-arrow)");
    });
  };

  ERDiagram.prototype._nodeDrag = function (n, g) {
    var self = this, dragging = false, sx = 0, sy = 0, ox = 0, oy = 0;
    g.addEventListener("mousedown", function (ev) {
      ev.stopPropagation();
      dragging = true; sx = ev.clientX; sy = ev.clientY; ox = n.x; oy = n.y;
      var move = function (e) {
        if (!dragging) return;
        n.x = ox + (e.clientX - sx) / self.scale;
        n.y = oy + (e.clientY - sy) / self.scale;
        g.setAttribute("transform", "translate(" + (n.x - n.w / 2) + "," + (n.y - n.h / 2) + ")");
        self.links.forEach(function (l) {
          if (l.s.name === n.name || l.t.name === n.name) {
            l._path.setAttribute("d", self._edgePath(l));
          }
        });
      };
      var up = function () {
        dragging = false;
        document.removeEventListener("mousemove", move);
        document.removeEventListener("mouseup", up);
      };
      document.addEventListener("mousemove", move);
      document.addEventListener("mouseup", up);
    });
  };

  ERDiagram.prototype._apply = function () {
    this.gRoot.setAttribute("transform",
      "translate(" + this.tx + "," + this.ty + ") scale(" + this.scale + ")");
  };

  ERDiagram.prototype._wirePanZoom = function () {
    var self = this, panning = false, sx = 0, sy = 0, otx = 0, oty = 0;
    this.svg.addEventListener("mousedown", function (ev) {
      panning = true; sx = ev.clientX; sy = ev.clientY; otx = self.tx; oty = self.ty;
      self.svg.style.cursor = "grabbing";
    });
    document.addEventListener("mousemove", function (ev) {
      if (!panning) return;
      self.tx = otx + (ev.clientX - sx);
      self.ty = oty + (ev.clientY - sy);
      self._apply();
    });
    document.addEventListener("mouseup", function () {
      panning = false; if (self.svg) self.svg.style.cursor = "grab";
    });
    this.svg.addEventListener("wheel", function (ev) {
      ev.preventDefault();
      var rect = self.svg.getBoundingClientRect();
      var mx = ev.clientX - rect.left, my = ev.clientY - rect.top;
      var factor = ev.deltaY < 0 ? 1.12 : 0.89;
      var ns = Math.max(0.2, Math.min(3, self.scale * factor));
      self.tx = mx - (mx - self.tx) * (ns / self.scale);
      self.ty = my - (my - self.ty) * (ns / self.scale);
      self.scale = ns;
      self._apply();
    }, { passive: false });
  };

  ERDiagram.prototype.fit = function () {
    var minx = 1e9, miny = 1e9, maxx = -1e9, maxy = -1e9, k;
    for (k in this.nodes) {
      var n = this.nodes[k];
      minx = Math.min(minx, n.x - n.w / 2); maxx = Math.max(maxx, n.x + n.w / 2);
      miny = Math.min(miny, n.y - n.h / 2); maxy = Math.max(maxy, n.y + n.h / 2);
    }
    if (minx > maxx) return;
    var pad = 44;
    var bw = (maxx - minx) + pad * 2, bh = (maxy - miny) + pad * 2;
    var s = Math.min(this.W / bw, this.H / bh, 1.4);
    this.scale = s;
    this.tx = (this.W - (minx + maxx) * s) / 2;
    this.ty = (this.H - (miny + maxy) * s) / 2;
    this._apply();
  };

  window.initERDiagram = function (hostId, tables, edges) {
    var host = document.getElementById(hostId);
    if (!host) return null;
    try { return new ERDiagram(host, tables, edges); }
    catch (e) { host.innerHTML = '<div class="text-danger small p-3">ER diagram error: ' +
      (e && e.message) + "</div>"; return null; }
  };
})();
