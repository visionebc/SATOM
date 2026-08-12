/* concept_map.js — the SATOM concept map (pure SVG, zero dependencies).
 *
 * A radial mind map: the console at the centre, one card per CONCEPT around
 * it, and every page of that concept listed inside its card as a clickable
 * row. Edges are hub -> card, so the picture answers "where does X live?"
 * in one glance instead of three menu expansions.
 *
 * Light theme only — this product has no dark mode (safeguards §9m). Concept
 * accents are used for the card rule, the hub edge and the icon dot; ALL text
 * is --fw-text-primary / --fw-text-secondary so nothing is ever a pale tone on
 * white.
 *
 * Interactions: drag to pan, wheel to zoom, fit/zoom buttons, click a row to
 * open the page, type in the search box to dim everything that does not match.
 * Search is shared with the list view (main.js is not involved).
 *
 * CSP-safe: external 'self' script, no eval, styling via attributes.
 */
(function () {
  "use strict";

  var NS = "http://www.w3.org/2000/svg";
  var FONT = "'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, Arial, sans-serif";
  var MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";

  var TEXT = "#0C1B33";
  var MUTED = "#51607F";
  var BORDER = "#DCE4F3";
  var SURFACE = "#FFFFFF";
  var ACCENT = "#0A3F9F";

  var CARD_W = 226;
  var ROW_H = 19;
  var HEAD_H = 34;
  var PAD_B = 10;

  function el(name, attrs) {
    var n = document.createElementNS(NS, name);
    if (attrs) { for (var k in attrs) { if (attrs[k] !== null && attrs[k] !== undefined) n.setAttribute(k, attrs[k]); } }
    return n;
  }
  function text(x, y, str, attrs) {
    var t = el("text", attrs || {});
    t.setAttribute("x", x); t.setAttribute("y", y);
    t.textContent = str;
    return t;
  }
  function clip(str, max) {
    return str.length > max ? str.slice(0, max - 1) + "…" : str;
  }

  function cardHeight(c) { return HEAD_H + c.pages.length * ROW_H + PAD_B; }

  /* Deterministic radial placement, then a few separation passes.
   * Deterministic on purpose: a layout that moves between reloads destroys the
   * spatial memory that makes a map worth having in the first place. */
  function layout(clusters) {
    var n = clusters.length, i;
    var tallest = 0;
    for (i = 0; i < n; i++) tallest = Math.max(tallest, cardHeight(clusters[i]));
    var rx = Math.max(340, (CARD_W + 90) * n / (2 * Math.PI) + CARD_W);
    var ry = Math.max(250, (tallest + 60) * n / (2 * Math.PI) + tallest * 0.4);
    var placed = [];
    for (i = 0; i < n; i++) {
      var a = -Math.PI / 2 + (i * 2 * Math.PI / n);
      var h = cardHeight(clusters[i]);
      placed.push({
        c: clusters[i], w: CARD_W, h: h,
        cx: Math.cos(a) * rx, cy: Math.sin(a) * ry, angle: a
      });
    }
    for (var pass = 0; pass < 60; pass++) {
      var moved = false;
      for (i = 0; i < n; i++) {
        for (var j = i + 1; j < n; j++) {
          var A = placed[i], B = placed[j];
          var dx = B.cx - A.cx, dy = B.cy - A.cy;
          var ox = (A.w + B.w) / 2 + 34 - Math.abs(dx);
          var oy = (A.h + B.h) / 2 + 26 - Math.abs(dy);
          if (ox > 0 && oy > 0) {
            moved = true;
            if (ox < oy) {
              var sx = (dx >= 0 ? 1 : -1) * ox / 2;
              A.cx -= sx; B.cx += sx;
            } else {
              var sy = (dy >= 0 ? 1 : -1) * oy / 2;
              A.cy -= sy; B.cy += sy;
            }
          }
        }
      }
      if (!moved) break;
    }
    return placed;
  }

  function build(host, clusters) {
    var placed = layout(clusters);
    var minX = -160, minY = -70, maxX = 160, maxY = 70, i;
    for (i = 0; i < placed.length; i++) {
      var p = placed[i];
      minX = Math.min(minX, p.cx - p.w / 2 - 40);
      maxX = Math.max(maxX, p.cx + p.w / 2 + 40);
      minY = Math.min(minY, p.cy - p.h / 2 - 40);
      maxY = Math.max(maxY, p.cy + p.h / 2 + 40);
    }
    var W = maxX - minX, H = maxY - minY;

    var svg = el("svg", {
      width: "100%", height: "100%", viewBox: minX + " " + minY + " " + W + " " + H,
      style: "display:block;cursor:grab;touch-action:none;font-family:" + FONT
    });
    var root = el("g", {});
    svg.appendChild(root);

    var edges = el("g", { "stroke-linecap": "round", fill: "none" });
    var cards = el("g", {});
    root.appendChild(edges);
    root.appendChild(cards);

    // Edges hub -> card, drawn first so cards sit on top.
    for (i = 0; i < placed.length; i++) {
      var q = placed[i];
      var ex = q.cx - (q.cx > 0 ? q.w / 2 : -q.w / 2);
      var d = "M0,0 C" + (ex * 0.45) + ",0 " + (ex * 0.55) + "," + q.cy + " " + ex + "," + q.cy;
      var path = el("path", {
        d: d, stroke: q.c.accent, "stroke-width": 1.6, "stroke-opacity": 0.45
      });
      path.setAttribute("data-concept", q.c.key);
      edges.appendChild(path);
    }

    // The hub.
    var hub = el("g", {});
    hub.appendChild(el("ellipse", {
      cx: 0, cy: 0, rx: 96, ry: 40, fill: SURFACE,
      stroke: ACCENT, "stroke-width": 2
    }));
    hub.appendChild(text(0, -3, "SATOM", {
      "text-anchor": "middle", "font-size": 17, "font-weight": 700, fill: ACCENT
    }));
    hub.appendChild(text(0, 15, clusters.length + " concepts", {
      "text-anchor": "middle", "font-size": 11, fill: MUTED
    }));
    cards.appendChild(hub);

    // One card per concept.
    for (i = 0; i < placed.length; i++) {
      var pl = placed[i], c = pl.c;
      var x = pl.cx - pl.w / 2, y = pl.cy - pl.h / 2;
      var g = el("g", { transform: "translate(" + x + "," + y + ")" });
      g.setAttribute("data-concept", c.key);

      g.appendChild(el("rect", {
        x: 0, y: 0, width: pl.w, height: pl.h, rx: 8,
        fill: SURFACE, stroke: BORDER, "stroke-width": 1
      }));
      g.appendChild(el("rect", { x: 0, y: 0, width: 4, height: pl.h, rx: 2, fill: c.accent }));
      g.appendChild(el("circle", { cx: 18, cy: 17, r: 5, fill: c.accent }));
      g.appendChild(text(31, 21, clip(c.label, 26), {
        "font-size": 12.5, "font-weight": 700, fill: TEXT
      }));
      g.appendChild(text(pl.w - 10, 21, String(c.pages.length), {
        "text-anchor": "end", "font-size": 11, fill: MUTED
      }));
      g.appendChild(el("line", {
        x1: 8, y1: HEAD_H - 8, x2: pl.w - 8, y2: HEAD_H - 8,
        stroke: BORDER, "stroke-width": 1
      }));

      for (var k = 0; k < c.pages.length; k++) {
        var pg = c.pages[k];
        var ry0 = HEAD_H + k * ROW_H - 4;
        var row = el("g", { style: "cursor:pointer" });
        row.setAttribute("data-hay",
          (pg.label + " " + pg.blurb + " " + pg.keywords + " " + pg.href + " " + c.label).toLowerCase());
        row.appendChild(el("rect", {
          x: 6, y: ry0, width: pl.w - 12, height: ROW_H - 2, rx: 3,
          fill: "transparent"
        }));
        row.appendChild(text(14, ry0 + 13, clip(pg.label, 30), {
          "font-size": 11.5, fill: TEXT
        }));
        var ttl = el("title");
        ttl.textContent = pg.label + " — " + pg.blurb + "\n" + pg.href;
        row.appendChild(ttl);
        (function (href, node) {
          node.addEventListener("click", function (ev) { ev.stopPropagation(); window.location.href = href; });
          node.addEventListener("mouseenter", function () { node.firstChild.setAttribute("fill", "#EAEFF9"); });
          node.addEventListener("mouseleave", function () { node.firstChild.setAttribute("fill", "transparent"); });
        })(pg.href, row);
        g.appendChild(row);
      }
      cards.appendChild(g);
    }

    host.textContent = "";
    host.appendChild(svg);
    return { svg: svg, root: root, base: { minX: minX, minY: minY, W: W, H: H } };
  }

  /* Pan + zoom over the viewBox. Kept on the viewBox rather than a transform
   * so stroke widths and text stay physically sized while zooming. */
  function wire(view) {
    var vb = { x: view.base.minX, y: view.base.minY, w: view.base.W, h: view.base.H };
    function apply() { view.svg.setAttribute("viewBox", vb.x + " " + vb.y + " " + vb.w + " " + vb.h); }
    function zoom(factor, ox, oy) {
      var nw = Math.max(200, Math.min(view.base.W * 4, vb.w * factor));
      var k = nw / vb.w;
      vb.x = ox - (ox - vb.x) * k;
      vb.y = oy - (oy - vb.y) * k;
      vb.w = nw; vb.h = vb.h * k;
      apply();
    }
    function pt(ev) {
      var r = view.svg.getBoundingClientRect();
      return { x: vb.x + (ev.clientX - r.left) / r.width * vb.w,
               y: vb.y + (ev.clientY - r.top) / r.height * vb.h };
    }
    view.svg.addEventListener("wheel", function (ev) {
      ev.preventDefault();
      var p = pt(ev);
      zoom(ev.deltaY > 0 ? 1.12 : 0.89, p.x, p.y);
    }, { passive: false });

    var dragging = false, last = null;
    view.svg.addEventListener("pointerdown", function (ev) {
      dragging = true; last = pt(ev);
      view.svg.style.cursor = "grabbing";
      view.svg.setPointerCapture(ev.pointerId);
    });
    view.svg.addEventListener("pointermove", function (ev) {
      if (!dragging) return;
      var p = pt(ev);
      vb.x -= (p.x - last.x); vb.y -= (p.y - last.y);
      apply();
    });
    view.svg.addEventListener("pointerup", function (ev) {
      dragging = false; view.svg.style.cursor = "grab";
      try { view.svg.releasePointerCapture(ev.pointerId); } catch (e) { /* already released */ }
    });

    return {
      fit: function () {
        vb = { x: view.base.minX, y: view.base.minY, w: view.base.W, h: view.base.H };
        apply();
      },
      zin: function () { zoom(0.8, vb.x + vb.w / 2, vb.y + vb.h / 2); },
      zout: function () { zoom(1.25, vb.x + vb.w / 2, vb.y + vb.h / 2); }
    };
  }

  function init() {
    var host = document.getElementById("cm-canvas");
    if (!host || host.dataset.built === "1") return;
    var q = document.getElementById("cm-q");
    var listWrap = document.getElementById("cm-list");
    var mapCard = document.getElementById("cm-map-card");
    var status = document.getElementById("cm-status");
    var empty = document.getElementById("cm-empty");

    var ctrl = null;

    /* One search box drives BOTH views. Filtering only the visible one would
     * make the toggle silently change the result set. */
    function filter() {
      var term = (q && q.value || "").trim().toLowerCase();
      var hits = 0, total = 0;

      var rows = host.querySelectorAll("g[data-hay]");
      var perConcept = {};
      Array.prototype.forEach.call(rows, function (row) {
        total++;
        var ok = !term || row.getAttribute("data-hay").indexOf(term) !== -1;
        row.setAttribute("opacity", ok ? "1" : "0.18");
        row.style.pointerEvents = ok ? "auto" : "none";
        if (ok) {
          hits++;
          var card = row.parentNode.getAttribute("data-concept");
          perConcept[card] = true;
        }
      });
      Array.prototype.forEach.call(host.querySelectorAll("g[data-concept]"), function (card) {
        var on = !term || perConcept[card.getAttribute("data-concept")];
        card.setAttribute("opacity", on ? "1" : "0.28");
      });
      Array.prototype.forEach.call(host.querySelectorAll("path[data-concept]"), function (e) {
        var on = !term || perConcept[e.getAttribute("data-concept")];
        e.setAttribute("stroke-opacity", on ? "0.45" : "0.1");
      });

      var lhits = 0;
      if (listWrap) {
        Array.prototype.forEach.call(listWrap.querySelectorAll(".cm-node"), function (node) {
          var ok = !term || node.getAttribute("data-hay").indexOf(term) !== -1;
          node.hidden = !ok;
          node.classList.toggle("cm-hit", !!term && ok);
          if (ok) lhits++;
        });
        Array.prototype.forEach.call(listWrap.querySelectorAll(".cm-cluster"), function (cl) {
          var any = cl.querySelector(".cm-node:not([hidden])");
          cl.hidden = !any;
        });
        if (empty) empty.hidden = lhits !== 0;
      }

      if (status) {
        status.textContent = term
          ? (hits || lhits) + " match" + ((hits || lhits) === 1 ? "" : "es") + " for “" + term + "”"
          : total + " pages · " + host.querySelectorAll("g[data-concept]").length + " concepts";
      }
    }

    fetch(host.dataset.src, { headers: { "Accept": "application/json" } })
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (payload) {
        var clusters = (payload && payload.clusters) || [];
        if (!clusters.length) throw new Error("empty map");
        var view = build(host, clusters);
        ctrl = wire(view);
        host.dataset.built = "1";
        filter();
      })
      .catch(function (err) {
        /* A failed map is an ERROR, never an empty canvas: on a white board
         * the two look identical and mean opposite things. The list view below
         * is server-rendered, so the page is still usable. */
        host.innerHTML = "";
        var box = document.createElement("div");
        box.className = "p-4 text-center";
        box.style.color = "#8B1C2A";
        box.innerHTML = "<i class='bi bi-exclamation-octagon'></i> " +
          "Could not draw the map (" + String(err.message || err).replace(/[<>&]/g, "") +
          "). The list view below still works.";
        host.appendChild(box);
      });

    if (q) q.addEventListener("input", filter);
    var bFit = document.getElementById("cm-fit");
    var bIn = document.getElementById("cm-zin");
    var bOut = document.getElementById("cm-zout");
    if (bFit) bFit.addEventListener("click", function () { if (ctrl) ctrl.fit(); });
    if (bIn) bIn.addEventListener("click", function () { if (ctrl) ctrl.zin(); });
    if (bOut) bOut.addEventListener("click", function () { if (ctrl) ctrl.zout(); });

    var vMap = document.getElementById("cm-view-map");
    var vList = document.getElementById("cm-view-list");
    function show(which) {
      if (mapCard) mapCard.hidden = which !== "map";
      if (listWrap) listWrap.hidden = which !== "list";
      if (vMap) vMap.classList.toggle("active", which === "map");
      if (vList) vList.classList.toggle("active", which === "list");
    }
    if (vMap) vMap.addEventListener("click", function () { show("map"); });
    if (vList) vList.addEventListener("click", function () { show("list"); });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
  /* Turbo Drive replaces <body> without a full load — re-init on every visit. */
  document.addEventListener("turbo:load", init);
})();
