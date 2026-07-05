/* er_diagram.js — professional database-schema diagram (pure SVG, zero deps).
 *
 * Renders the PostgreSQL relational model the way a database-design tool does
 * (dbdiagram / pgModeler style): layered left→right layout (referenced parents
 * on the left, dependents to the right), one card per table with its full
 * column list (PK key, FK diamond, type, NOT NULL bold, masked-column lock),
 * and FK connectors drawn column-to-column with crow's-foot notation
 * (many side = crow's foot at the FK column, one side = tick at the PK).
 *
 * Tables are grouped into functional DOMAINS (fleet, device cache, WAF
 * desired-state, automation…) — each domain colors its card headers and the
 * legend, so the model reads as an architecture, not a hairball.
 *
 * Interactions: pan (drag canvas) · wheel zoom · drag a card · hover/click a
 * card to focus its relationships (rest dims) · hover an edge for its FK
 * tooltip · search box · fit / zoom buttons · expand-collapse column lists ·
 * re-layout · export the diagram as a standalone SVG file.
 *
 * CSP-safe: external 'self' script, no eval, styling via attributes.
 * Entry point (unchanged): window.initERDiagram(hostId, tables, edges)
 *   tables = [{name, columns:int, rows:int?, pk:[..],
 *              cols:[{name,type,pk,fk,sensitive,nullable}]}]
 *   edges  = [{from_table, from_col, to_table, to_col}]
 */
(function () {
  "use strict";
  var NS = "http://www.w3.org/2000/svg";

  var FONT_UI = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif";
  var FONT_MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace";

  var T = {
    canvas: "#F7F8FB",
    dot: "rgba(29,52,82,0.12)",
    frame: "#E3E7EE",
    cardBg: "#FFFFFF",
    cardBorder: "#D9DFE9",
    headerText: "#FFFFFF",
    rowLine: "rgba(29,52,82,0.055)",
    zebra: "rgba(29,52,82,0.026)",
    colName: "#1F2937",
    colNameFk: "#C2461C",
    colType: "#93A0B4",
    pk: "#D99E02",
    lock: "#9AA7B8",
    edge: "#9FACBE",
    edgeHi: "#EF5424",
    focusRing: "#EF5424",
    searchRing: "#D97706",
    dim: 0.10
  };

  /* Functional domains — first match wins, colors the card header. */
  var DOMAINS = [
    { key: "fleet",    label: "Fleet",             color: "#2563EB", match: /^appliance/ },
    { key: "cache",    label: "Device cache",      color: "#0E7490", match: /^(device_|inventory_snapshots|sync_runs)/ },
    { key: "waf",      label: "WAF desired-state", color: "#EF5424", match: /^(wpp_|templates$|template_review|baseline)/ },
    { key: "certs",    label: "Certificates",      color: "#15803D", match: /^managed_certificate/ },
    { key: "auto",     label: "Automation",        color: "#7C3AED", match: /^(scheduled_action|change_request)/ },
    { key: "registry", label: "API registry",      color: "#DB2777", match: /^registry_/ },
    { key: "ops",      label: "Ops artifacts",     color: "#B45309", match: /^(config_backups|firmware_images)/ },
    { key: "platform", label: "Platform",          color: "#5B6B7F", match: /.*/ }
  ];
  function domainOf(name) {
    for (var i = 0; i < DOMAINS.length; i++) {
      if (DOMAINS[i].match.test(name)) { return DOMAINS[i]; }
    }
    return DOMAINS[DOMAINS.length - 1];
  }

  var HEADER_H = 34, ROW_H = 21, COLLAPSE_AT = 12, COL_GAP = 130, CARD_GAP = 30;

  var _mctx = null;
  function textW(s, font) {
    if (!_mctx) { _mctx = document.createElement("canvas").getContext("2d"); }
    _mctx.font = font;
    return _mctx.measureText(String(s)).width;
  }
  function el(name, attrs) {
    var e = document.createElementNS(NS, name);
    if (attrs) { for (var k in attrs) { e.setAttribute(k, attrs[k]); } }
    return e;
  }
  function htm(tag, cls, style) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (style) { e.setAttribute("style", style); }
    return e;
  }
  function fmtRows(n) {
    if (n == null || n < 0) { return ""; }
    if (n >= 1000000) { return (n / 1000000).toFixed(1) + "M"; }
    if (n >= 10000) { return Math.round(n / 1000) + "k"; }
    if (n >= 1000) { return (n / 1000).toFixed(1) + "k"; }
    return String(n);
  }

  /* ======================================================================= */
  function ERD(host, tables, edges) {
    this.host = host;
    this.tables = (tables || []).map(function (t) {
      return {
        name: t.name,
        cols: t.cols || [],
        pk: t.pk || [],
        rows: (typeof t.rows === "number" ? t.rows : -1),
        domain: domainOf(t.name),
        x: 0, y: 0, w: 0, h: 0, col: 0,
        expanded: false
      };
    });
    this.byName = {};
    var self = this;
    this.tables.forEach(function (t) { self.byName[t.name] = t; });
    this.edges = (edges || []).filter(function (e) {
      return self.byName[e.from_table] && self.byName[e.to_table];
    });
    this.scale = 1; this.tx = 0; this.ty = 0;
    this.pinned = null; this.hovered = null; this.query = "";
    this.columns = [];           // [[table,...], ...] layout columns
    this.build();
    this.layout();
    this.render();
    this.fit();
  }

  /* ---------------- scaffold ---------------- */

  ERD.prototype.build = function () {
    this.host.innerHTML = "";
    this.host.style.position = "relative";
    this.host.style.display = "flex";
    this.host.style.flexDirection = "column";

    // toolbar
    var tb = htm("div", "d-flex align-items-center gap-2 flex-wrap mb-2");
    this.searchInput = document.createElement("input");
    this.searchInput.type = "search";
    this.searchInput.placeholder = "Find table…";
    this.searchInput.className = "form-control form-control-sm";
    this.searchInput.setAttribute("style", "max-width:220px");
    tb.appendChild(this.searchInput);

    var g1 = htm("div", "btn-group btn-group-sm");
    this.btnFit = this._btn(g1, "⤢ Fit");
    this.btnZoomOut = this._btn(g1, "−");
    this.btnZoomIn = this._btn(g1, "+");
    tb.appendChild(g1);

    var g2 = htm("div", "btn-group btn-group-sm");
    this.btnExpand = this._btn(g2, "Expand all");
    this.btnCollapse = this._btn(g2, "Collapse all");
    tb.appendChild(g2);

    var g3 = htm("div", "btn-group btn-group-sm");
    this.btnRelayout = this._btn(g3, "↻ Re-layout");
    this.btnExport = this._btn(g3, "⤓ SVG");
    tb.appendChild(g3);

    var meta = htm("span", "small text-muted ms-auto");
    meta.textContent = this.tables.length + " tables · " + this.edges.length + " foreign keys";
    tb.appendChild(meta);
    this.host.appendChild(tb);

    // canvas
    var wrap = htm("div", "", "flex:1 1 auto;min-height:0;position:relative;" +
      "border:1px solid " + T.frame + ";border-radius:10px;overflow:hidden;background:" + T.canvas + ";");
    this.svg = el("svg", { width: "100%", height: "100%" });
    this.svg.style.display = "block";
    this.svg.style.cursor = "grab";
    wrap.appendChild(this.svg);

    // tooltip
    this.tip = htm("div", "", "position:absolute;display:none;pointer-events:none;z-index:20;" +
      "background:#1D3452;color:#fff;font:11.5px " + FONT_MONO + ";padding:5px 9px;border-radius:6px;" +
      "box-shadow:0 4px 14px rgba(15,30,60,.25);white-space:nowrap;");
    wrap.appendChild(this.tip);
    this.host.appendChild(wrap);
    this.wrap = wrap;

    // legend
    var lg = htm("div", "d-flex align-items-center gap-3 flex-wrap mt-2 small text-muted");
    var used = {};
    this.tables.forEach(function (t) { used[t.domain.key] = t.domain; });
    DOMAINS.forEach(function (d) {
      if (!used[d.key]) { return; }
      var chip = htm("span", "d-inline-flex align-items-center gap-1");
      var dot = htm("span", "", "display:inline-block;width:10px;height:10px;border-radius:3px;background:" + d.color + ";");
      chip.appendChild(dot);
      chip.appendChild(document.createTextNode(d.label));
      lg.appendChild(chip);
    });
    var hint = htm("span", "ms-auto");
    hint.innerHTML = "<span style=\"color:" + T.pk + "\">⚷</span> primary key · " +
      "<span style=\"color:" + T.edgeHi + "\">◆</span> foreign key · " +
      "crow's foot = many · <b>bold</b> = NOT NULL · 🔒 masked";
    lg.appendChild(hint);
    this.host.appendChild(lg);

    // svg defs + layers
    var defs = el("defs");
    var filt = el("filter", { id: "erdShadow", x: "-20%", y: "-20%", width: "140%", height: "140%" });
    filt.appendChild(el("feDropShadow", {
      dx: "0", dy: "2", stdDeviation: "4", "flood-color": "rgba(15,30,60,0.13)"
    }));
    defs.appendChild(filt);
    var pat = el("pattern", { id: "erdGrid", width: "22", height: "22", patternUnits: "userSpaceOnUse" });
    pat.appendChild(el("circle", { cx: "1.2", cy: "1.2", r: "1.2", fill: T.dot }));
    defs.appendChild(pat);
    this.svg.appendChild(defs);

    this.bgRect = el("rect", { x: "-100000", y: "-100000", width: "200000", height: "200000", fill: "url(#erdGrid)" });
    this.vp = el("g");
    this.vp.appendChild(this.bgRect);
    this.gEdges = el("g");
    this.gCards = el("g");
    this.vp.appendChild(this.gEdges);
    this.vp.appendChild(this.gCards);
    this.svg.appendChild(this.vp);

    this.bindToolbar();
    this.bindCanvas();
  };

  ERD.prototype._btn = function (parent, label) {
    var b = document.createElement("button");
    b.type = "button";
    b.className = "btn btn-outline-light btn-sm";
    b.textContent = label;
    parent.appendChild(b);
    return b;
  };

  /* ---------------- geometry ---------------- */

  ERD.prototype.visibleCols = function (t) {
    if (t.expanded || t.cols.length <= COLLAPSE_AT + 1) { return t.cols; }
    return t.cols.slice(0, COLLAPSE_AT);
  };

  ERD.prototype.measure = function (t) {
    var nameF = "600 13px " + FONT_UI, colF = "12px " + FONT_UI, typeF = "10.5px " + FONT_MONO;
    var w = textW(t.name, nameF) + 24 + (t.rows >= 0 ? textW(fmtRows(t.rows), typeF) + 30 : 0);
    for (var i = 0; i < t.cols.length; i++) {
      var c = t.cols[i];
      var cw = 34 + textW(c.name, colF) + 16 + textW(c.type || "", typeF) + 14 + (c.sensitive ? 14 : 0);
      if (cw > w) { w = cw; }
    }
    t.w = Math.max(225, Math.min(360, Math.ceil(w)));
    var vis = this.visibleCols(t);
    var hasToggle = t.cols.length > COLLAPSE_AT + 1;
    t.h = HEADER_H + vis.length * ROW_H + (hasToggle ? 20 : 0) + 5;
  };

  /* ---------------- layout: layered left -> right ---------------- */

  ERD.prototype.layout = function () {
    var self = this;
    var parentsOf = {};   // child -> {parent:1}
    var touched = {};
    this.edges.forEach(function (e) {
      touched[e.from_table] = touched[e.to_table] = 1;
      if (e.from_table !== e.to_table) {
        (parentsOf[e.from_table] = parentsOf[e.from_table] || {})[e.to_table] = 1;
      }
    });

    var memo = {};
    function layerOf(n, stack) {
      if (memo[n] != null) { return memo[n]; }
      if (stack[n]) { return 0; }             // FK cycle guard
      stack[n] = 1;
      var ps = Object.keys(parentsOf[n] || {}), v = 0;
      for (var i = 0; i < ps.length; i++) {
        var l = layerOf(ps[i], stack) + 1;
        if (l > v) { v = l; }
      }
      delete stack[n];
      memo[n] = v;
      return v;
    }

    var connected = [], islands = [];
    this.tables.forEach(function (t) {
      (touched[t.name] ? connected : islands).push(t);
    });

    var maxLayer = 0;
    connected.forEach(function (t) {
      t.col = layerOf(t.name, {});
      if (t.col > maxLayer) { maxLayer = t.col; }
    });

    var cols = [];
    for (var i = 0; i <= maxLayer; i++) { cols.push([]); }
    connected.forEach(function (t) { cols[t.col].push(t); });

    // initial order: domain, then name
    cols.forEach(function (c) {
      c.sort(function (a, b) {
        var d = DOMAINS.indexOf(a.domain) - DOMAINS.indexOf(b.domain);
        return d !== 0 ? d : (a.name < b.name ? -1 : 1);
      });
    });

    // two barycenter sweeps to reduce edge crossings
    var neigh = {};
    this.edges.forEach(function (e) {
      if (e.from_table === e.to_table) { return; }
      (neigh[e.from_table] = neigh[e.from_table] || []).push(e.to_table);
      (neigh[e.to_table] = neigh[e.to_table] || []).push(e.from_table);
    });
    function sweep() {
      cols.forEach(function (c) {
        var pos = {};
        cols.forEach(function (cc) { cc.forEach(function (t, i) { pos[t.name] = i; }); });
        c.sort(function (a, b) {
          function bary(t) {
            var ns = neigh[t.name] || [], s = 0, k = 0;
            ns.forEach(function (n) { if (pos[n] != null) { s += pos[n]; k++; } });
            return k ? s / k : pos[t.name];
          }
          return bary(a) - bary(b);
        });
      });
    }
    sweep(); sweep();

    // islands: pack into trailing columns of ~7
    if (islands.length) {
      islands.sort(function (a, b) {
        var d = DOMAINS.indexOf(a.domain) - DOMAINS.indexOf(b.domain);
        return d !== 0 ? d : (a.name < b.name ? -1 : 1);
      });
      var per = Math.max(4, Math.ceil(islands.length / Math.ceil(islands.length / 7)));
      for (var j = 0; j < islands.length; j += per) {
        cols.push(islands.slice(j, j + per));
      }
    }

    // measure + position
    this.tables.forEach(function (t) { self.measure(t); });
    var x = 0, heights = [];
    cols.forEach(function (c, ci) {
      var cw = 0, y = 0;
      c.forEach(function (t) {
        t.col = ci;
        t.x = x; t.y = y;
        y += t.h + CARD_GAP;
        if (t.w > cw) { cw = t.w; }
      });
      heights.push(Math.max(0, y - CARD_GAP));
      x += cw + COL_GAP;
    });
    // vertical centering of columns
    var maxH = Math.max.apply(null, heights.concat([0]));
    cols.forEach(function (c, ci) {
      var off = (maxH - heights[ci]) / 2;
      c.forEach(function (t) { t.y += off; });
    });
    this.columns = cols;
  };

  /* re-pack one column after a per-card expand/collapse */
  ERD.prototype.packColumn = function (ci) {
    var c = this.columns[ci];
    if (!c || !c.length) { return; }
    var self = this;
    c.forEach(function (t) { self.measure(t); });
    c.sort(function (a, b) { return a.y - b.y; });
    var y = Math.min.apply(null, c.map(function (t) { return t.y; }));
    var x = Math.min.apply(null, c.map(function (t) { return t.x; }));
    c.forEach(function (t) { t.x = x; t.y = y; y += t.h + CARD_GAP; });
  };

  /* ---------------- rendering ---------------- */

  ERD.prototype.render = function () {
    this.renderCards();
    this.renderEdges();
    this.applyState();
    this.applyTransform();
  };

  ERD.prototype.renderCards = function () {
    var self = this;
    this.gCards.textContent = "";
    this.cardEls = {};
    this.anchorRow = {};   // "table.col" -> visible row index or -1
    this.tables.forEach(function (t) { self.gCards.appendChild(self.cardEl(t)); });
  };

  ERD.prototype.cardEl = function (t) {
    var g = el("g", { transform: "translate(" + t.x + "," + t.y + ")" });
    g.setAttribute("data-t", t.name);
    g.style.cursor = "move";
    var vis = this.visibleCols(t);
    var hasToggle = t.cols.length > COLLAPSE_AT + 1;
    var h = HEADER_H + vis.length * ROW_H + (hasToggle ? 20 : 0) + 5;
    t.h = h;

    var body = el("rect", {
      width: t.w, height: h, rx: 9, fill: T.cardBg,
      stroke: T.cardBorder, "stroke-width": 1, filter: "url(#erdShadow)"
    });
    body.setAttribute("data-role", "body");
    g.appendChild(body);

    // header (rounded top only)
    var r = 9;
    g.appendChild(el("path", {
      d: "M0," + HEADER_H + " L0," + r + " Q0,0 " + r + ",0 L" + (t.w - r) + ",0 Q" + t.w + ",0 " + t.w + "," + r +
         " L" + t.w + "," + HEADER_H + " Z",
      fill: t.domain.color
    }));

    var name = el("text", {
      x: 12, y: 22.5, fill: T.headerText,
      "font-family": FONT_UI, "font-size": "13", "font-weight": "600"
    });
    name.textContent = t.name;
    g.appendChild(name);

    if (t.rows >= 0) {
      var label = fmtRows(t.rows);
      var bw = textW(label, "10.5px " + FONT_MONO) + 14;
      g.appendChild(el("rect", {
        x: t.w - bw - 9, y: 9, width: bw, height: 16, rx: 8,
        fill: "rgba(255,255,255,0.22)"
      }));
      var bt = el("text", {
        x: t.w - 9 - bw / 2, y: 21, fill: "#fff", "text-anchor": "middle",
        "font-family": FONT_MONO, "font-size": "10.5"
      });
      bt.textContent = label;
      g.appendChild(bt);
    }

    for (var i = 0; i < vis.length; i++) {
      var c = vis[i], ry = HEADER_H + i * ROW_H;
      this.anchorRow[t.name + "." + c.name] = i;
      if (i % 2 === 1) {
        g.appendChild(el("rect", { x: 1, y: ry, width: t.w - 2, height: ROW_H, fill: T.zebra }));
      }
      if (c.pk) { g.appendChild(this.keyIcon(c.fk ? 6 : 10, ry + ROW_H / 2)); }
      if (c.fk) { g.appendChild(this.fkIcon(c.pk ? 21 : 10, ry + ROW_H / 2)); }

      var nm = el("text", {
        x: 34, y: ry + 14.5,
        fill: c.fk ? T.colNameFk : T.colName,
        "font-family": FONT_UI, "font-size": "12",
        "font-weight": c.nullable === false ? "600" : "400"
      });
      nm.textContent = c.name;
      g.appendChild(nm);

      var tx = t.w - 12;
      if (c.sensitive) {
        g.appendChild(this.lockIcon(t.w - 16, ry + ROW_H / 2));
        tx = t.w - 26;
      }
      var ty = el("text", {
        x: tx, y: ry + 14.5, fill: T.colType, "text-anchor": "end",
        "font-family": FONT_MONO, "font-size": "10.5"
      });
      ty.textContent = c.type || "";
      g.appendChild(ty);

      g.appendChild(el("line", {
        x1: 1, y1: ry + ROW_H, x2: t.w - 1, y2: ry + ROW_H,
        stroke: T.rowLine, "stroke-width": 1
      }));
    }

    // hidden columns anchor on the header
    for (var k = vis.length; k < t.cols.length; k++) {
      this.anchorRow[t.name + "." + t.cols[k].name] = -1;
    }

    if (hasToggle) {
      var yy = HEADER_H + vis.length * ROW_H;
      var tgHit = el("rect", { x: 0, y: yy, width: t.w, height: 20, fill: "transparent" });
      tgHit.style.cursor = "pointer";
      tgHit.setAttribute("data-role", "toggle");
      g.appendChild(tgHit);
      var tg = el("text", {
        x: t.w / 2, y: yy + 14, "text-anchor": "middle",
        fill: "#6C7A8C", "font-family": FONT_UI, "font-size": "11"
      });
      tg.textContent = t.expanded
        ? "▴ collapse"
        : "▾ " + (t.cols.length - vis.length) + " more columns";
      tg.style.cursor = "pointer";
      tg.setAttribute("data-role", "toggle");
      tg.style.pointerEvents = "all";
      g.appendChild(tg);
    }

    this.cardEls[t.name] = g;
    return g;
  };

  ERD.prototype.keyIcon = function (x, cy) {
    var g = el("g", { transform: "translate(" + x + "," + cy + ")" });
    g.appendChild(el("circle", { cx: 2.6, cy: -2.2, r: 2.6, fill: "none", stroke: T.pk, "stroke-width": 1.6 }));
    g.appendChild(el("path", {
      d: "M4.4,-0.4 L8.6,3.8 M6.6,2 L8.2,0.4 M7.6,3 L9.2,1.4",
      stroke: T.pk, "stroke-width": 1.6, fill: "none", "stroke-linecap": "round"
    }));
    return g;
  };
  ERD.prototype.fkIcon = function (x, cy) {
    return el("path", {
      d: "M" + (x + 4) + "," + (cy - 4.5) + " L" + (x + 8.5) + "," + cy +
         " L" + (x + 4) + "," + (cy + 4.5) + " L" + (x - 0.5) + "," + cy + " Z",
      fill: "none", stroke: T.edgeHi, "stroke-width": 1.5
    });
  };
  ERD.prototype.lockIcon = function (x, cy) {
    var g = el("g", { transform: "translate(" + x + "," + cy + ")" });
    g.appendChild(el("rect", { x: -4, y: -1.5, width: 8, height: 6.5, rx: 1.5, fill: T.lock }));
    g.appendChild(el("path", {
      d: "M-2.4,-1.5 V-3.4 A2.4,2.6 0 0 1 2.4,-3.4 V-1.5",
      fill: "none", stroke: T.lock, "stroke-width": 1.4
    }));
    return g;
  };

  /* ---------------- edges (crow's foot) ---------------- */

  ERD.prototype.anchorFor = function (t, colName) {
    var idx = this.anchorRow[t.name + "." + colName];
    return (idx == null || idx < 0) ? HEADER_H / 2 : HEADER_H + idx * ROW_H + ROW_H / 2;
  };

  ERD.prototype.renderEdges = function () {
    var self = this;
    this.gEdges.textContent = "";
    this.edgeEls = [];
    this.edges.forEach(function (e) {
      var A = self.byName[e.from_table], B = self.byName[e.to_table];
      if (!A || !B) { return; }
      var y1 = A.y + self.anchorFor(A, e.from_col);
      var y2 = B.y + self.anchorFor(B, e.to_col);
      var s1, s2, x1, x2;
      if (e.from_table === e.to_table) {
        s1 = s2 = 1;
        x1 = A.x + A.w; x2 = A.x + A.w;
      } else if (B.x + B.w / 2 >= A.x + A.w / 2) {
        s1 = 1; s2 = -1; x1 = A.x + A.w; x2 = B.x;
      } else {
        s1 = -1; s2 = 1; x1 = A.x; x2 = B.x + B.w;
      }
      var P1 = { x: x1 + s1 * 14, y: y1 };  // crow's-foot apex (many side, FK)
      var P2 = { x: x2 + s2 * 9, y: y2 };   // one-tick point (parent PK)
      var dx = (e.from_table === e.to_table)
        ? 55
        : Math.max(46, Math.min(170, Math.abs(P2.x - P1.x) / 2));
      var d = "M" + P1.x + "," + P1.y +
              " C" + (P1.x + s1 * dx) + "," + P1.y + " " + (P2.x + s2 * dx) + "," + P2.y +
              " " + P2.x + "," + P2.y;

      var g = el("g");
      g.setAttribute("data-from", e.from_table);
      g.setAttribute("data-to", e.to_table);

      var path = el("path", { d: d, fill: "none", stroke: T.edge, "stroke-width": 1.5 });
      path.setAttribute("data-role", "wire");
      g.appendChild(path);

      var foot = "M" + P1.x + "," + P1.y + " L" + x1 + "," + (y1 - 5.5) +
                 " M" + P1.x + "," + P1.y + " L" + x1 + "," + y1 +
                 " M" + P1.x + "," + P1.y + " L" + x1 + "," + (y1 + 5.5);
      var fp = el("path", { d: foot, fill: "none", stroke: T.edge, "stroke-width": 1.5 });
      fp.setAttribute("data-role", "wire");
      g.appendChild(fp);

      var tick = "M" + P2.x + "," + (y2 - 5) + " L" + P2.x + "," + (y2 + 5) +
                 " M" + P2.x + "," + y2 + " L" + x2 + "," + y2;
      var tp = el("path", { d: tick, fill: "none", stroke: T.edge, "stroke-width": 1.5 });
      tp.setAttribute("data-role", "wire");
      g.appendChild(tp);

      var hit = el("path", { d: d, fill: "none", stroke: "transparent", "stroke-width": 12 });
      hit.style.pointerEvents = "stroke";
      g.appendChild(hit);

      hit.addEventListener("mousemove", function (ev) {
        self.showTip(ev, e.from_table + "." + e.from_col + " → " + e.to_table + "." + e.to_col);
        self.setEdgeHot(g, true);
      });
      hit.addEventListener("mouseleave", function () {
        self.hideTip();
        self.setEdgeHot(g, false);
      });

      self.gEdges.appendChild(g);
      self.edgeEls.push(g);
    });
  };

  ERD.prototype.setEdgeHot = function (g, hot) {
    var wires = g.querySelectorAll("[data-role=wire]");
    for (var i = 0; i < wires.length; i++) {
      wires[i].setAttribute("stroke", hot ? T.edgeHi : T.edge);
      wires[i].setAttribute("stroke-width", hot ? "2.2" : "1.5");
    }
  };

  ERD.prototype.showTip = function (ev, textContent) {
    var r = this.wrap.getBoundingClientRect();
    this.tip.textContent = textContent;
    this.tip.style.display = "block";
    var x = ev.clientX - r.left + 14, y = ev.clientY - r.top + 10;
    if (x + this.tip.offsetWidth > r.width - 8) { x = r.width - this.tip.offsetWidth - 8; }
    this.tip.style.left = x + "px";
    this.tip.style.top = y + "px";
  };
  ERD.prototype.hideTip = function () { this.tip.style.display = "none"; };

  /* ---------------- focus / search state ---------------- */

  ERD.prototype.applyState = function () {
    var self = this;
    var focus = this.pinned || this.hovered;
    var q = this.query;

    var related = null;
    if (focus) {
      related = {}; related[focus] = 1;
      this.edges.forEach(function (e) {
        if (e.from_table === focus) { related[e.to_table] = 1; }
        if (e.to_table === focus) { related[e.from_table] = 1; }
      });
    }

    this.tables.forEach(function (t) {
      var g = self.cardEls[t.name];
      if (!g) { return; }
      var op = 1, ring = null;
      if (q) {
        var hitQ = t.name.toLowerCase().indexOf(q) !== -1;
        op = hitQ ? 1 : 0.14;
        if (hitQ) { ring = T.searchRing; }
      } else if (related) {
        op = related[t.name] ? 1 : T.dim;
        if (t.name === focus) { ring = T.focusRing; }
      }
      g.setAttribute("opacity", op);
      var body = g.querySelector("[data-role=body]");
      if (body) {
        body.setAttribute("stroke", ring || T.cardBorder);
        body.setAttribute("stroke-width", ring ? "2" : "1");
      }
    });

    this.edgeEls.forEach(function (g) {
      var f = g.getAttribute("data-from"), t2 = g.getAttribute("data-to");
      var op = 1, hot = false;
      if (q) {
        op = (f.toLowerCase().indexOf(q) !== -1 || t2.toLowerCase().indexOf(q) !== -1) ? 0.9 : 0.06;
      } else if (focus) {
        if (f === focus || t2 === focus) { hot = true; }
        else { op = 0.05; }
      }
      g.setAttribute("opacity", op);
      self.setEdgeHot(g, hot);
    });
  };

  /* ---------------- viewport ---------------- */

  ERD.prototype.applyTransform = function () {
    this.vp.setAttribute("transform",
      "translate(" + this.tx + "," + this.ty + ") scale(" + this.scale + ")");
  };

  ERD.prototype.bbox = function () {
    var x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    this.tables.forEach(function (t) {
      if (t.x < x0) { x0 = t.x; }
      if (t.y < y0) { y0 = t.y; }
      if (t.x + t.w > x1) { x1 = t.x + t.w; }
      if (t.y + t.h > y1) { y1 = t.y + t.h; }
    });
    if (x0 === Infinity) { return { x: 0, y: 0, w: 100, h: 100 }; }
    return { x: x0, y: y0, w: x1 - x0, h: y1 - y0 };
  };

  ERD.prototype.fit = function () {
    var b = this.bbox(), pad = 46;
    var W = this.svg.clientWidth || 1000, H = this.svg.clientHeight || 640;
    var s = Math.min((W - pad * 2) / b.w, (H - pad * 2) / b.h, 1);
    if (!(s > 0) || !isFinite(s)) { s = 0.5; }
    this.scale = s;
    this.tx = (W - b.w * s) / 2 - b.x * s;
    this.ty = (H - b.h * s) / 2 - b.y * s;
    this.applyTransform();
  };

  ERD.prototype.zoomAt = function (cx, cy, factor) {
    var ns = Math.max(0.12, Math.min(2.5, this.scale * factor));
    var k = ns / this.scale;
    this.tx = cx - (cx - this.tx) * k;
    this.ty = cy - (cy - this.ty) * k;
    this.scale = ns;
    this.applyTransform();
  };

  ERD.prototype.centerOn = function (t) {
    var W = this.svg.clientWidth || 1000, H = this.svg.clientHeight || 640;
    if (this.scale < 0.55) { this.scale = 0.85; }
    this.tx = W / 2 - (t.x + t.w / 2) * this.scale;
    this.ty = H / 2 - (t.y + t.h / 2) * this.scale;
    this.applyTransform();
  };

  /* ---------------- events ---------------- */

  ERD.prototype.bindToolbar = function () {
    var self = this;
    this.btnFit.addEventListener("click", function () { self.fit(); });
    this.btnZoomIn.addEventListener("click", function () {
      self.zoomAt((self.svg.clientWidth || 1000) / 2, (self.svg.clientHeight || 640) / 2, 1.25);
    });
    this.btnZoomOut.addEventListener("click", function () {
      self.zoomAt((self.svg.clientWidth || 1000) / 2, (self.svg.clientHeight || 640) / 2, 0.8);
    });
    this.btnExpand.addEventListener("click", function () {
      self.tables.forEach(function (t) { t.expanded = true; });
      self.layout(); self.render(); self.fit();
    });
    this.btnCollapse.addEventListener("click", function () {
      self.tables.forEach(function (t) { t.expanded = false; });
      self.layout(); self.render(); self.fit();
    });
    this.btnRelayout.addEventListener("click", function () {
      self.layout(); self.render(); self.fit();
    });
    this.btnExport.addEventListener("click", function () { self.exportSVG(); });
    this.searchInput.addEventListener("input", function () {
      self.query = self.searchInput.value.trim().toLowerCase();
      self.applyState();
    });
    this.searchInput.addEventListener("keydown", function (ev) {
      if (ev.key !== "Enter" || !self.query) { return; }
      for (var i = 0; i < self.tables.length; i++) {
        if (self.tables[i].name.toLowerCase().indexOf(self.query) !== -1) {
          self.centerOn(self.tables[i]);
          break;
        }
      }
    });
  };

  ERD.prototype.bindCanvas = function () {
    var self = this;
    var drag = null;   // {mode:'pan'|'card', t, sx, sy, ox, oy, moved}

    this.svg.addEventListener("pointerdown", function (ev) {
      if (ev.button !== 0) { return; }
      var cardG = ev.target.closest ? ev.target.closest("g[data-t]") : null;
      if (cardG && ev.target.getAttribute && ev.target.getAttribute("data-role") === "toggle") {
        var t0 = self.byName[cardG.getAttribute("data-t")];
        t0.expanded = !t0.expanded;
        self.packColumn(t0.col);
        self.render();
        return;
      }
      if (cardG) {
        var t = self.byName[cardG.getAttribute("data-t")];
        drag = { mode: "card", t: t, sx: ev.clientX, sy: ev.clientY, ox: t.x, oy: t.y, moved: false };
      } else {
        drag = { mode: "pan", sx: ev.clientX, sy: ev.clientY, ox: self.tx, oy: self.ty, moved: false };
        self.svg.style.cursor = "grabbing";
      }
      self.svg.setPointerCapture(ev.pointerId);
    });

    this.svg.addEventListener("pointermove", function (ev) {
      if (!drag) {
        var g = ev.target.closest ? ev.target.closest("g[data-t]") : null;
        var name = g ? g.getAttribute("data-t") : null;
        if (name !== self.hovered) {
          self.hovered = name;
          if (!self.pinned && !self.query) { self.applyState(); }
        }
        return;
      }
      var dx = ev.clientX - drag.sx, dy = ev.clientY - drag.sy;
      if (Math.abs(dx) + Math.abs(dy) > 3) { drag.moved = true; }
      if (drag.mode === "pan") {
        self.tx = drag.ox + dx; self.ty = drag.oy + dy;
        self.applyTransform();
      } else {
        drag.t.x = drag.ox + dx / self.scale;
        drag.t.y = drag.oy + dy / self.scale;
        var gEl = self.cardEls[drag.t.name];
        if (gEl) { gEl.setAttribute("transform", "translate(" + drag.t.x + "," + drag.t.y + ")"); }
        self.renderEdges();
        if (self.pinned || self.hovered || self.query) { self.applyState(); }
      }
    });

    this.svg.addEventListener("pointerup", function (ev) {
      if (!drag) { return; }
      if (!drag.moved && drag.mode === "card") {
        self.pinned = (self.pinned === drag.t.name) ? null : drag.t.name;
        self.applyState();
      } else if (!drag.moved && drag.mode === "pan") {
        if (self.pinned) { self.pinned = null; self.applyState(); }
      }
      self.svg.style.cursor = "grab";
      drag = null;
    });

    this.svg.addEventListener("pointerleave", function () {
      if (self.hovered) {
        self.hovered = null;
        if (!self.pinned && !self.query) { self.applyState(); }
      }
    });

    this.svg.addEventListener("wheel", function (ev) {
      ev.preventDefault();
      var r = self.svg.getBoundingClientRect();
      self.zoomAt(ev.clientX - r.left, ev.clientY - r.top, ev.deltaY < 0 ? 1.12 : 0.89);
    }, { passive: false });
  };

  /* ---------------- export ---------------- */

  ERD.prototype.exportSVG = function () {
    var b = this.bbox(), pad = 40;
    var clone = this.svg.cloneNode(true);
    clone.setAttribute("xmlns", NS);
    clone.setAttribute("width", Math.ceil(b.w + pad * 2));
    clone.setAttribute("height", Math.ceil(b.h + pad * 2));
    clone.setAttribute("viewBox", (b.x - pad) + " " + (b.y - pad) + " " + (b.w + pad * 2) + " " + (b.h + pad * 2));
    // reset the viewport transform in the export
    var kids = clone.childNodes;
    for (var i = 0; i < kids.length; i++) {
      if (kids[i].nodeName === "g") { kids[i].removeAttribute("transform"); break; }
    }
    var bg = el("rect", {
      x: b.x - pad, y: b.y - pad, width: b.w + pad * 2, height: b.h + pad * 2, fill: T.canvas
    });
    clone.insertBefore(bg, clone.firstChild);
    var src = new XMLSerializer().serializeToString(clone);
    var blob = new Blob(['<?xml version="1.0" encoding="UTF-8"?>\n' + src], { type: "image/svg+xml" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "fortinet-manager-schema.svg";
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 250);
  };

  /* ---------------- entry point ---------------- */

  window.initERDiagram = function (hostId, tables, edges) {
    var host = document.getElementById(hostId);
    if (!host) { return null; }
    return new ERD(host, tables, edges);
  };
})();
