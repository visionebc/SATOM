/* Process diagram editor — plain SVG, no dependencies.
 *
 * WHY NOT A FLOWCHART LIBRARY
 * ---------------------------
 * app/static/vendor/ holds bootstrap and chart.js and nothing else, on purpose:
 * SATOM ships as an offline bundle, which is the same reason Grafana was
 * rejected for the metrics work. er_diagram.js already draws a draggable,
 * pannable node graph in this product with zero dependencies, so this follows
 * that precedent rather than adding a first one.
 *
 * WHAT THIS FILE IS NOT ALLOWED TO KNOW
 * ------------------------------------
 * Which parameters a step kind takes, and whether a graph is valid. Both come
 * from the server (`#proc-data`), and the server re-validates every save. An
 * editor that knew the rules would be a second author of them — and the copy
 * that drifts is always the one nobody re-reads.
 */
(function () {
  "use strict";

  var host = document.getElementById("proc-canvas");
  var dataEl = document.getElementById("proc-data");
  if (!host || !dataEl) return;

  var DATA = JSON.parse(dataEl.textContent);
  var KINDS = {};
  DATA.kinds.forEach(function (k) { KINDS[k.key] = k; });
  var GRAPH = DATA.graph || { nodes: [], edges: [] };
  var CAN_EDIT = !!DATA.canEdit;

  var NS = "http://www.w3.org/2000/svg";
  var W = 190, H = 46;               // node box
  var sel = null;                    // {type:'node'|'edge', key|index}
  var connectFrom = null;
  var view = { x: 0, y: 0, k: 1 };
  var dirty = false;

  var statusEl = document.getElementById("proc-status");
  var hintEl = document.getElementById("proc-hint");

  function el(name, attrs) {
    var n = document.createElementNS(NS, name);
    for (var a in attrs) if (attrs[a] !== null && attrs[a] !== undefined) {
      n.setAttribute(a, attrs[a]);
    }
    return n;
  }

  function say(msg, cls) {
    if (!statusEl) return;
    statusEl.textContent = msg || "";
    statusEl.className = cls || "text-muted";
    statusEl.style.fontSize = "12px";
  }

  function markDirty() {
    dirty = true;
    say("Unsaved changes.", "text-warning");
  }

  function nodeByKey(k) {
    for (var i = 0; i < GRAPH.nodes.length; i++) {
      if (GRAPH.nodes[i].key === k) return GRAPH.nodes[i];
    }
    return null;
  }

  function uniqueKey(base) {
    var n = 1, k = base;
    while (nodeByKey(k)) { n += 1; k = base + "-" + n; }
    return k;
  }

  /* ── rendering ───────────────────────────────────────────────────────── */

  var svg = el("svg", { width: "100%", height: "100%" });
  svg.style.display = "block";
  var defs = el("defs");
  ["#5E6C84", "#15692A", "#8B1C2A", "#7A5700"].forEach(function (c, i) {
    var m = el("marker", {
      id: "pa" + i, viewBox: "0 0 10 10", refX: "9", refY: "5",
      markerWidth: "6", markerHeight: "6", orient: "auto-start-reverse"
    });
    m.appendChild(el("path", { d: "M 0 0 L 10 5 L 0 10 z", fill: c }));
    defs.appendChild(m);
  });
  svg.appendChild(defs);
  var root = el("g");
  svg.appendChild(root);
  host.appendChild(svg);

  /* Branch colour is the fw-badge palette, calibrated against white. The dark
   * theme's pastels land near 1.4:1 on this canvas — an arrow labelled "fail"
   * that cannot be read (safeguards §9m). */
  var BRANCH = {
    always: { c: "#5E6C84", m: "pa0", t: "" },
    pass: { c: "#15692A", m: "pa1", t: "pass" },
    fail: { c: "#8B1C2A", m: "pa2", t: "fail" },
    unknown: { c: "#7A5700", m: "pa3", t: "unknown" }
  };

  function draw() {
    while (root.firstChild) root.removeChild(root.firstChild);
    root.setAttribute("transform",
      "translate(" + view.x + "," + view.y + ") scale(" + view.k + ")");

    GRAPH.edges.forEach(function (e, idx) {
      var a = nodeByKey(e.src), b = nodeByKey(e.dst);
      if (!a || !b) return;
      var br = BRANCH[e.branch] || BRANCH.always;
      var x1 = a.x + W / 2, y1 = a.y + H, x2 = b.x + W / 2, y2 = b.y;
      var my = (y1 + y2) / 2;
      var d = "M " + x1 + " " + y1 + " C " + x1 + " " + my + ", " +
        x2 + " " + my + ", " + x2 + " " + y2;
      var hit = el("path", {
        d: d, fill: "none", stroke: "transparent", "stroke-width": 12,
        style: "cursor:pointer"
      });
      hit.addEventListener("click", function (ev) {
        ev.stopPropagation(); select({ type: "edge", index: idx });
      });
      root.appendChild(hit);
      root.appendChild(el("path", {
        d: d, fill: "none", stroke: br.c,
        "stroke-width": (sel && sel.type === "edge" && sel.index === idx) ? 3 : 1.6,
        "marker-end": "url(#" + br.m + ")"
      }));
      if (br.t) {
        var lx = (x1 + x2) / 2, ly = my;
        var lbl = el("text", {
          x: lx, y: ly - 3, "text-anchor": "middle", fill: br.c,
          "font-size": "10", "font-family": "Inter, sans-serif"
        });
        lbl.textContent = br.t;
        root.appendChild(lbl);
      }
    });

    GRAPH.nodes.forEach(function (n) {
      var kind = KINDS[n.kind] || { label: n.kind, colour: "#3D4550", writes: false };
      var g = el("g", { transform: "translate(" + n.x + "," + n.y + ")" });
      g.style.cursor = CAN_EDIT ? "move" : "pointer";
      var selected = sel && sel.type === "node" && sel.key === n.key;
      g.appendChild(el("rect", {
        width: W, height: H, rx: 6,
        fill: "#FFFFFF", stroke: selected ? "#EF5424" : "#DFE1E6",
        "stroke-width": selected ? 2 : 1
      }));
      g.appendChild(el("rect", {
        width: 4, height: H, rx: 2, fill: kind.colour || "#3D4550"
      }));
      var t1 = el("text", {
        x: 12, y: 19, "font-size": "12", "font-weight": "600",
        fill: "#172B4D", "font-family": "Inter, sans-serif"
      });
      t1.textContent = (n.label || n.key).slice(0, 26);
      g.appendChild(t1);
      var t2 = el("text", {
        x: 12, y: 34, "font-size": "10", fill: "#5E6C84",
        "font-family": "Inter, sans-serif"
      });
      t2.textContent = kind.label + " · " + n.key;
      g.appendChild(t2);
      if (kind.writes) {
        var w = el("text", {
          x: W - 10, y: 19, "font-size": "10", "text-anchor": "end",
          fill: "#8B1C2A", "font-family": "Inter, sans-serif"
        });
        w.textContent = "writes";
        g.appendChild(w);
      }
      attachDrag(g, n);
      root.appendChild(g);
    });
  }

  /* ── interaction ─────────────────────────────────────────────────────── */

  function attachDrag(g, n) {
    var down = null;
    g.addEventListener("mousedown", function (ev) {
      ev.stopPropagation();
      if (connectFrom !== null) {
        if (connectFrom !== n.key) addEdge(connectFrom, n.key);
        connectFrom = null;
        setHint("");
        draw();
        return;
      }
      select({ type: "node", key: n.key });
      if (!CAN_EDIT) return;
      down = { x: ev.clientX, y: ev.clientY, nx: n.x, ny: n.y, moved: false };
      ev.preventDefault();
    });
    window.addEventListener("mousemove", function (ev) {
      if (!down) return;
      var dx = (ev.clientX - down.x) / view.k, dy = (ev.clientY - down.y) / view.k;
      if (Math.abs(dx) + Math.abs(dy) > 2) down.moved = true;
      n.x = Math.round(down.nx + dx);
      n.y = Math.round(down.ny + dy);
      draw();
    });
    window.addEventListener("mouseup", function () {
      if (down && down.moved) markDirty();
      down = null;
    });
  }

  var pan = null;
  svg.addEventListener("mousedown", function (ev) {
    pan = { x: ev.clientX, y: ev.clientY, vx: view.x, vy: view.y };
    if (connectFrom !== null) { connectFrom = null; setHint(""); }
    select(null);
  });
  window.addEventListener("mousemove", function (ev) {
    if (!pan) return;
    view.x = pan.vx + (ev.clientX - pan.x);
    view.y = pan.vy + (ev.clientY - pan.y);
    draw();
  });
  window.addEventListener("mouseup", function () { pan = null; });
  svg.addEventListener("wheel", function (ev) {
    ev.preventDefault();
    var f = ev.deltaY < 0 ? 1.1 : 0.9;
    view.k = Math.max(0.35, Math.min(2.5, view.k * f));
    draw();
  }, { passive: false });

  function setHint(t) { if (hintEl) hintEl.textContent = t || ""; }

  function addEdge(src, dst) {
    /* The server refuses two arrows for the same outcome (that rule is what
     * keeps a run a single cursor, and therefore what makes a manual gate
     * resumable from one column). New arrows default to `always`; the operator
     * picks the outcome in the inspector. */
    GRAPH.edges.push({ src: src, dst: dst, branch: "always" });
    markDirty();
  }

  function select(s) {
    sel = s;
    draw();
    renderInspector();
  }

  /* ── inspector ───────────────────────────────────────────────────────── */

  var insp = document.getElementById("proc-inspector");

  function field(label, help) {
    var d = document.createElement("div");
    d.className = "mb-2";
    var l = document.createElement("label");
    l.className = "form-label mb-1";
    l.style.fontSize = "12px";
    l.textContent = label;
    d.appendChild(l);
    if (help) {
      var h = document.createElement("div");
      h.className = "form-text";
      h.style.fontSize = "11px";
      h.textContent = help;
      d.dataset.help = "1";
      d.appendChild(h);
    }
    return d;
  }

  function renderInspector() {
    if (!insp) return;
    insp.innerHTML = "";
    if (!sel) {
      insp.className = "text-muted";
      insp.textContent = "Click a step to edit it.";
      return;
    }
    insp.className = "";

    if (sel.type === "edge") {
      var e = GRAPH.edges[sel.index];
      if (!e) { select(null); return; }
      var t = document.createElement("div");
      t.style.fontSize = "12.5px";
      t.className = "mb-2";
      t.innerHTML = "<strong>Arrow</strong><br><code>" + e.src +
        "</code> → <code>" + e.dst + "</code>";
      insp.appendChild(t);
      var wrap = field("Follow when the step ends");
      var s = document.createElement("select");
      s.className = "form-select form-select-sm";
      ["always", "pass", "fail", "unknown"].forEach(function (b) {
        var o = document.createElement("option");
        o.value = b; o.textContent = b;
        if (e.branch === b) o.selected = true;
        s.appendChild(o);
      });
      s.disabled = !CAN_EDIT;
      s.addEventListener("change", function () {
        e.branch = s.value; markDirty(); draw();
      });
      wrap.insertBefore(s, wrap.querySelector(".form-text"));
      insp.appendChild(wrap);
      var note = document.createElement("div");
      note.className = "form-text";
      note.style.fontSize = "11px";
      note.textContent = "An explicit outcome always wins over always, so a " +
        "recovery branch is reachable in exactly the graphs that need it.";
      insp.appendChild(note);
      return;
    }

    var n = nodeByKey(sel.key);
    if (!n) { select(null); return; }
    var kind = KINDS[n.kind] || { label: n.kind, params: [], summary: "" };

    var head = document.createElement("div");
    head.className = "mb-2";
    head.style.fontSize = "12.5px";
    head.innerHTML = "<strong>" + kind.label + "</strong>";
    insp.appendChild(head);
    if (kind.summary) {
      var sm = document.createElement("div");
      sm.className = "form-text mb-2";
      sm.style.fontSize = "11px";
      sm.textContent = kind.summary;
      insp.appendChild(sm);
    }

    insp.appendChild(textInput("Step key", n.key, function (v) {
      var clean = (v || "").trim().toLowerCase();
      if (!clean || (clean !== n.key && nodeByKey(clean))) return;
      GRAPH.edges.forEach(function (e) {
        if (e.src === n.key) e.src = clean;
        if (e.dst === n.key) e.dst = clean;
      });
      // Decision steps address other steps BY KEY, so a rename has to travel
      // there too or the reference silently stops resolving and the step
      // reports "did not run on this path" about a step that ran.
      GRAPH.nodes.forEach(function (o) {
        if (o.kind === "decision" && o.params && o.params.when_node === n.key) {
          o.params.when_node = clean;
        }
      });
      n.key = clean;
      sel.key = clean;
      markDirty(); draw();
    }, "Referenced by arrows and by Decision steps."));

    insp.appendChild(textInput("Label", n.label || "", function (v) {
      n.label = v; markDirty(); draw();
    }));

    n.params = n.params || {};
    (kind.params || []).forEach(function (p) {
      if (n.kind === "action" && p.name === "action_key") {
        insp.appendChild(actionPicker(n, p));
        return;
      }
      if (p.kind === "select") {
        insp.appendChild(selectInput(p.label, p.choices || [],
          n.params[p.name] || p.default, function (v) {
            n.params[p.name] = v; markDirty();
          }, p.help));
        return;
      }
      insp.appendChild(textInput(
        p.label + (p.required ? " *" : ""),
        n.params[p.name] !== undefined ? n.params[p.name] : p.default,
        function (v) { n.params[p.name] = v; markDirty(); },
        p.help, p.kind === "textarea"));
    });
  }

  function textInput(label, value, onChange, help, big) {
    var wrap = field(label, help);
    var i = document.createElement(big ? "textarea" : "input");
    i.className = "form-control form-control-sm";
    if (big) i.rows = 2;
    i.value = value === undefined || value === null ? "" : value;
    i.disabled = !CAN_EDIT;
    i.addEventListener("change", function () { onChange(i.value); });
    wrap.insertBefore(i, wrap.querySelector(".form-text"));
    return wrap;
  }

  function selectInput(label, choices, value, onChange, help) {
    var wrap = field(label, help);
    var s = document.createElement("select");
    s.className = "form-select form-select-sm";
    choices.forEach(function (c) {
      var o = document.createElement("option");
      o.value = c; o.textContent = c;
      if (c === value) o.selected = true;
      s.appendChild(o);
    });
    s.disabled = !CAN_EDIT;
    s.addEventListener("change", function () { onChange(s.value); });
    wrap.insertBefore(s, wrap.querySelector(".form-text"));
    return wrap;
  }

  function actionPicker(n, p) {
    var wrap = field(p.label + " *",
      "Catalogue actions only. Actions bound to a change request are not " +
      "offered — a process is a plan, not an approval.");
    var s = document.createElement("select");
    s.className = "form-select form-select-sm";
    var none = document.createElement("option");
    none.value = ""; none.textContent = "— choose —";
    s.appendChild(none);
    DATA.actions.forEach(function (a) {
      var o = document.createElement("option");
      o.value = a.key;
      o.textContent = a.label + (a.danger ? "  ⚠" : "");
      o.title = a.summary || "";
      if (n.params.action_key === a.key) o.selected = true;
      s.appendChild(o);
    });
    s.disabled = !CAN_EDIT;
    s.addEventListener("change", function () {
      n.params.action_key = s.value; markDirty(); draw();
    });
    wrap.insertBefore(s, wrap.querySelector(".form-text"));
    return wrap;
  }

  /* ── toolbar ─────────────────────────────────────────────────────────── */

  Array.prototype.forEach.call(document.querySelectorAll(".proc-add"),
    function (b) {
      b.addEventListener("click", function () {
        var kind = b.dataset.kind;
        var k = KINDS[kind] || {};
        var node = {
          key: uniqueKey(kind.replace(/_/g, "-")), kind: kind,
          label: k.label || kind, params: {},
          x: Math.round(60 - view.x / view.k + GRAPH.nodes.length % 3 * 30),
          y: Math.round(60 - view.y / view.k + GRAPH.nodes.length * 26)
        };
        (k.params || []).forEach(function (p) {
          if (p.default) node.params[p.name] = p.default;
        });
        GRAPH.nodes.push(node);
        markDirty();
        select({ type: "node", key: node.key });
      });
    });

  var connectBtn = document.getElementById("proc-connect");
  if (connectBtn) connectBtn.addEventListener("click", function () {
    if (!sel || sel.type !== "node") {
      setHint("Select a step first, then press Connect and click the target.");
      return;
    }
    connectFrom = sel.key;
    setHint("Click the step this arrow points to.");
  });

  var delBtn = document.getElementById("proc-delete");
  if (delBtn) delBtn.addEventListener("click", function () {
    if (!sel) return;
    if (sel.type === "edge") {
      GRAPH.edges.splice(sel.index, 1);
    } else {
      var k = sel.key;
      GRAPH.nodes = GRAPH.nodes.filter(function (n) { return n.key !== k; });
      GRAPH.edges = GRAPH.edges.filter(function (e) {
        return e.src !== k && e.dst !== k;
      });
    }
    markDirty();
    select(null);
  });

  var fitBtn = document.getElementById("proc-fit");
  if (fitBtn) fitBtn.addEventListener("click", function () {
    if (!GRAPH.nodes.length) return;
    var xs = GRAPH.nodes.map(function (n) { return n.x; });
    var ys = GRAPH.nodes.map(function (n) { return n.y; });
    var minx = Math.min.apply(null, xs), miny = Math.min.apply(null, ys);
    var maxx = Math.max.apply(null, xs) + W, maxy = Math.max.apply(null, ys) + H;
    var bw = host.clientWidth || 800, bh = host.clientHeight || 470;
    view.k = Math.max(0.35, Math.min(1.4,
      Math.min((bw - 40) / (maxx - minx || 1), (bh - 40) / (maxy - miny || 1))));
    view.x = 20 - minx * view.k;
    view.y = 20 - miny * view.k;
    draw();
  });

  var saveBtn = document.getElementById("proc-save");
  if (saveBtn) saveBtn.addEventListener("click", function () {
    saveBtn.disabled = true;
    say("Saving…");
    fetch(DATA.saveUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRFToken": DATA.csrf },
      body: JSON.stringify(GRAPH)
    }).then(function (r) { return r.json().then(function (j) { return [r.ok, j]; }); })
      .then(function (pair) {
        saveBtn.disabled = false;
        if (pair[0] && pair[1].ok) {
          dirty = false;
          say("Saved — " + pair[1].nodes + " steps, " + pair[1].edges +
            " arrows. Reload to re-check the diagram.", "text-success");
          return;
        }
        /* The whole list, not the first problem: fixing a diagram one error
         * message at a time is a game of whack-a-mole. */
        say("Not saved: " + (pair[1].errors || ["unknown error"]).join(" · "),
          "text-danger");
      }).catch(function (err) {
        saveBtn.disabled = false;
        say("Not saved: " + err, "text-danger");
      });
  });

  window.addEventListener("beforeunload", function (ev) {
    if (!dirty) return;
    ev.preventDefault();
    ev.returnValue = "";
  });

  draw();
  if (fitBtn) fitBtn.click();
})();
