/* Deep Analysis — the WPP subtree + Server-Policy graph captured at depth.
   Adds: a reusable chart-modal (expand ⤢ any chart, switch type, top-N, CSV/PNG
   export, raw rows) and the deep panels (WPP feature-coverage matrix, sub-element
   counts, orphans, per-WPP/per-policy drill-down trees). Reads only the deep
   cache via /analysis/* — never a live box. ES5 to match analysis.js. */
(function () {
  "use strict";
  var PALETTE = ["#2563eb", "#7c3aed", "#0ea5e9", "#10b981", "#f59e0b",
    "#ef4444", "#14b8a6", "#a855f7", "#84cc16", "#f97316", "#06b6d4", "#ec4899"];
  function $(id) { return document.getElementById(id); }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]; }); }
  function colors(n) { var a = []; for (var i = 0; i < n; i++) a.push(PALETTE[i % PALETTE.length]); return a; }
  function getJSON(path) { return fetch(path, { headers: { Accept: "application/json" } }).then(function (r) { return r.json(); }); }

  function selectedDeviceIds() {
    var sel = $("fDevices"), out = [];
    if (sel) { Array.prototype.forEach.call(sel.selectedOptions, function (o) { out.push(o.value); }); }
    return out;
  }
  function withDevices(path) {
    var q = selectedDeviceIds().map(function (i) { return "device_id=" + encodeURIComponent(i); }).join("&");
    return q ? path + (path.indexOf("?") >= 0 ? "&" : "?") + q : path;
  }

  /* ------------------------------------------------------------------ modal */
  var mChart = null, mState = { labels: [], datasets: [], type: "bar", title: "" };

  function modalEl() { return $("anaModal"); }
  function openModalFromState() {
    var box = modalEl(); if (!box) return;
    box.hidden = false;
    $("anamTitle").textContent = mState.title;
    $("anamType").value = mState.type;
    drawModal();
  }
  function topN() { var n = parseInt($("anamTop").value, 10); return (n && n > 0) ? n : 0; }
  function drawModal() {
    var type = $("anamType").value || "bar";
    var n = topN();
    var labels = mState.labels.slice();
    var datasets = mState.datasets.map(function (ds) { return { label: ds.label, data: ds.data.slice() }; });
    if (n) { labels = labels.slice(0, n); datasets.forEach(function (ds) { ds.data = ds.data.slice(0, n); }); }
    if (mChart) { mChart.destroy(); mChart = null; }
    var el = $("anamCanvas"); if (!el) return;
    var ds2;
    if (type === "doughnut") {
      ds2 = [{ data: datasets[0] ? datasets[0].data : [], backgroundColor: colors(labels.length), borderWidth: 1, borderColor: "#fff" }];
    } else {
      ds2 = datasets.map(function (ds, i) {
        var c = PALETTE[i % PALETTE.length];
        return { label: ds.label, data: ds.data, backgroundColor: type === "line" ? "rgba(37,99,235,.12)" : colors(labels.length), borderColor: c, fill: type === "line", tension: .25, borderRadius: 4, pointRadius: 2 };
      });
    }
    mChart = new Chart(el, {
      type: type, data: { labels: labels, datasets: ds2 },
      options: {
        responsive: true, maintainAspectRatio: false,
        indexAxis: (type === "bar" && labels.length > 8) ? "y" : "x",
        plugins: { legend: { display: type === "doughnut" || datasets.length > 1, position: "bottom", labels: { font: { size: 10 } } } },
        scales: type === "doughnut" ? {} : { y: { beginAtZero: true, ticks: { precision: 0 } } }
      }
    });
    // raw rows table
    var tb = document.querySelector("#anamTbl tbody");
    var head = $("anamTbl").querySelector("thead tr");
    head.innerHTML = "<th>Label</th>" + datasets.map(function (ds) { return "<th>" + esc(ds.label || "Value") + "</th>"; }).join("");
    tb.innerHTML = labels.map(function (lb, i) {
      return "<tr><td>" + esc(lb) + "</td>" + datasets.map(function (ds) { return "<td>" + (ds.data[i] == null ? "" : ds.data[i]) + "</td>"; }).join("") + "</tr>";
    }).join("") || '<tr><td class="ana-empty">No data</td></tr>';
  }
  function closeModal() { var b = modalEl(); if (b) b.hidden = true; if (mChart) { mChart.destroy(); mChart = null; } }

  function openModalForData(title, rows, valueKey, type) {
    mState = { title: title, type: type || "bar",
      labels: rows.map(function (r) { return r.label; }),
      datasets: [{ label: valueKey || "Value", data: rows.map(function (r) { return r.value; }) }] };
    openModalFromState();
  }
  function openModalForChart(chartId, title) {
    var ch = window.__anaCharts && window.__anaCharts[chartId];
    if (!ch) return;
    mState = { title: title || chartId, type: ch.config.type || "bar",
      labels: (ch.data.labels || []).slice(),
      datasets: (ch.data.datasets || []).map(function (ds) { return { label: ds.label, data: (ds.data || []).slice() }; }) };
    openModalFromState();
  }

  function exportCSV() {
    var rows = [["Label"].concat(mState.datasets.map(function (d) { return d.label || "Value"; }))];
    mState.labels.forEach(function (lb, i) {
      rows.push([lb].concat(mState.datasets.map(function (d) { return d.data[i] == null ? "" : d.data[i]; })));
    });
    var csv = rows.map(function (r) { return r.map(function (c) { return '"' + String(c).replace(/"/g, '""') + '"'; }).join(","); }).join("\n");
    var blob = new Blob([csv], { type: "text/csv" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = (mState.title || "chart").replace(/\W+/g, "_") + ".csv";
    a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }
  function exportPNG() {
    if (!mChart) return;
    var a = document.createElement("a");
    a.href = mChart.toBase64Image(); a.download = (mState.title || "chart").replace(/\W+/g, "_") + ".png"; a.click();
  }

  /* ----------------------------------------------- expand ⤢ on every chart */
  function addExpandButtons() {
    var panels = document.querySelectorAll(".ana-panel");
    Array.prototype.forEach.call(panels, function (p) {
      var cv = p.querySelector("canvas"); var h = p.querySelector("h3");
      if (!cv || !h || p.querySelector(".anam-exp")) return;
      var b = document.createElement("button");
      b.className = "anam-exp"; b.title = "Expand"; b.innerHTML = "⤢";
      b.addEventListener("click", function () { openModalForChart(cv.id, h.textContent.trim()); });
      h.appendChild(b);
    });
  }

  /* ----------------------------------------------------------- deep charts */
  function deepBar(id, labels, data, horizontal) {
    var el = $(id); if (!el) return;
    if (window.__anaCharts[id]) { window.__anaCharts[id].destroy(); }
    window.__anaCharts[id] = new Chart(el, {
      type: "bar",
      data: { labels: labels, datasets: [{ data: data, backgroundColor: colors(labels.length), borderRadius: 4 }] },
      options: { indexAxis: horizontal ? "y" : "x", responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0, font: { size: 10 } } }, x: { ticks: { font: { size: 10 } } } } }
    });
  }

  function renderMatrix(rows) {
    deepBar("cDeepWppMatrix", rows.map(function (r) { return r.label; }), rows.map(function (r) { return r.bound; }), true);
    var total = rows.length ? rows[0].total : 0;
    $("deepWppN").textContent = "(" + total + " WPP in scope)";
    document.querySelector("#tDeepWpp tbody").innerHTML = rows.length ? rows.map(function (r) {
      var pct = r.total ? Math.round(r.bound * 100 / r.total) : 0;
      return "<tr><td>" + esc(r.label) + ' <span style="opacity:.4;font-size:.7rem">' + esc(r.field) + "</span></td><td><b>" + r.bound + "</b> / " + r.total + "</td><td style=\"min-width:90px\"><div style=\"background:#eef2ff;border-radius:6px;overflow:hidden\"><div style=\"width:" + pct + "%;background:#2563eb;height:8px\"></div></div></td></tr>";
    }).join("") : '<tr><td colspan="3" class="ana-empty">No deep WPP data — run a deep capture</td></tr>';
  }

  function renderSub(rows) {
    var top = rows.slice(0, 20);
    deepBar("cDeepSub", top.map(function (r) { return r.logical_name; }), top.map(function (r) { return r.count; }), true);
    document.querySelector("#tDeepSub tbody").innerHTML = rows.length ? rows.map(function (r) {
      return "<tr><td>" + esc(r.logical_name) + "</td><td><b>" + r.count + "</b></td></tr>";
    }).join("") : '<tr><td colspan="2" class="ana-empty">No sub-elements — run a deep capture</td></tr>';
  }

  function renderOrphans(rows) {
    $("deepOrphN").textContent = "(" + rows.length + ")";
    $("deepOrphans").innerHTML = rows.length ? rows.map(function (r) {
      return '<span class="ana-pill none" style="margin:.15rem">' + esc(r.mkey) + ' <span style="opacity:.5">#' + r.appliance_id + "</span></span>";
    }).join("") : '<div class="ana-empty">Every captured WPP is bound to a policy</div>';
  }

  function renderFreshness(fr) {
    var ids = Object.keys(fr);
    if (!ids.length) { $("deepFresh").innerHTML = '<span class="ana-pill none">No deep capture yet — enable “Capture full WPP + policy depth” on a device’s Rediscovery page, or run the fleet sweep here.</span>'; return; }
    $("deepFresh").innerHTML = ids.map(function (id) {
      var ts = fr[id].captured_at || "—";
      return '<span class="ana-pill on" style="margin:.15rem">#' + esc(id) + ": " + esc((ts || "").replace("T", " ").slice(0, 19)) + "</span>";
    }).join("");
  }

  function renderInventory(inv) {
    inv = inv || {}; var t = inv.totals || {}; var pool = t.server_pools || {}; var be = t.backends || {};
    var tiles = [
      ["Server policies", t.server_policies || 0, ""],
      ["Server pools", pool.distinct || 0, (pool.unique || 0) + " unique \u00b7 " + (pool.shared || 0) + " shared"],
      ["Back-end servers", be.count || 0, (be.distinct_ips || 0) + " distinct IPs"],
      ["VIPs", t.vips || 0, ""],
      ["SNI policies", t.sni || 0, ""],
      ["Certificates", t.certificates || 0, ""]
    ];
    var box = $("deepInv");
    box.style.display = "flex"; box.style.flexWrap = "wrap"; box.style.gap = ".6rem";
    box.innerHTML = tiles.map(function (x) {
      return '<div style="flex:1 1 130px;min-width:130px;background:#f8fafc;border:1px solid #e8edf5;border-radius:12px;padding:.7rem .9rem">' +
        '<div style="font-size:1.6rem;font-weight:700;color:#2563eb;line-height:1.1">' + esc(x[1]) + '</div>' +
        '<div style="font-size:.8rem;color:#334155">' + esc(x[0]) + '</div>' +
        (x[2] ? '<div style="font-size:.68rem;color:#94a3b8;margin-top:.15rem">' + esc(x[2]) + '</div>' : '') + '</div>';
    }).join("");
    var dev = inv.per_device || [];
    var sc = $("invScope"); if (sc) sc.textContent = "(" + dev.length + " device" + (dev.length === 1 ? "" : "s") + " in scope)";
    var ports = inv.ports || [];
    deepBar("cDeepPorts", ports.slice(0, 15).map(function (r) { return r.port; }), ports.slice(0, 15).map(function (r) { return r.count; }), false);
    document.querySelector("#tDeepPorts tbody").innerHTML = ports.length ? ports.map(function (r) {
      return "<tr><td>" + esc(r.port) + "</td><td><b>" + r.count + "</b></td></tr>";
    }).join("") : '<tr><td colspan="2" class="ana-empty">No back-end ports \u2014 run a deep capture</td></tr>';
    document.querySelector("#tDeepInvDev tbody").innerHTML = dev.length ? dev.map(function (d) {
      return "<tr><td>" + esc(d.device) + "</td><td>" + d.policies + "</td><td>" + d.pools + "</td><td>" + d.backends + "</td><td>" + d.sni + "</td><td>" + d.certificates + "</td></tr>";
    }).join("") : '<tr><td colspan="6" class="ana-empty">No deep data \u2014 run a deep capture</td></tr>';
  }

  /* --------------------------------------------------------- drill-down tree */
  function treeHTML(node, depth) {
    if (!node || !node.logical_name) return "";
    var pay = node.payload || {};
    var keys = Object.keys(pay).filter(function (k) { return k !== "name" && pay[k] !== "" && pay[k] != null && typeof pay[k] !== "object"; }).slice(0, 6);
    var meta = keys.map(function (k) { return esc(k) + "=" + esc(pay[k]); }).join(" · ");
    var hasKids = node.children && node.children.length;
    var head = '<div class="dt-row" style="padding-left:' + (depth * 14) + 'px">' +
      (hasKids ? '<span class="dt-tog">▸</span>' : '<span class="dt-tog" style="opacity:.2">•</span>') +
      '<span class="dt-name">' + esc(node.subtable || node.logical_name) + "</span>" +
      '<span class="dt-key">' + esc(node.mkey || "") + "</span>" +
      (meta ? '<span class="dt-meta">' + meta + "</span>" : "") +
      (hasKids ? '<span class="dt-n">' + node.children.length + "</span>" : "") + "</div>";
    var kids = hasKids ? '<div class="dt-kids" style="display:none">' + node.children.map(function (c) { return treeHTML(c, depth + 1); }).join("") + "</div>" : "";
    return '<div class="dt-node">' + head + kids + "</div>";
  }
  function wireTree(container) {
    container.querySelectorAll(".dt-row").forEach(function (row) {
      row.addEventListener("click", function (e) {
        e.stopPropagation();
        var kids = row.parentNode.querySelector(":scope > .dt-kids");
        if (!kids) return;
        var open = kids.style.display !== "none";
        kids.style.display = open ? "none" : "block";
        var tog = row.querySelector(".dt-tog"); if (tog && tog.textContent !== "•") tog.textContent = open ? "▸" : "▾";
      });
    });
  }
  function loadDrillObjects() {
    var kind = $("deepKind").value;
    getJSON(withDevices("deep/objects?kind=" + kind)).then(function (objs) {
      var sel = $("deepObj");
      sel.innerHTML = objs.length ? objs.map(function (o) {
        return '<option value="' + o.appliance_id + "|" + esc(o.mkey) + '">' + esc(o.device) + " · " + esc(o.mkey) + "</option>";
      }).join("") : '<option value="">(none captured)</option>';
      loadDrill();
    });
  }
  function loadDrill() {
    var v = $("deepObj").value; var cont = $("deepTree");
    if (!v) { cont.innerHTML = '<div class="ana-empty">No object selected</div>'; return; }
    var parts = v.split("|"), aid = parts[0], mkey = parts.slice(1).join("|");
    var kind = $("deepKind").value === "policy" ? "policy" : "wpp";
    cont.innerHTML = '<div class="ana-empty">Loading…</div>';
    getJSON("deep/" + kind + "/" + aid + "/" + encodeURIComponent(mkey)).then(function (tree) {
      if (!tree || !tree.logical_name) { cont.innerHTML = '<div class="ana-empty">Nothing captured for this object</div>'; return; }
      cont.innerHTML = treeHTML(tree, 0);
      wireTree(cont);
    });
  }

  /* ----------------------------------------------------------------- driver */
  function loadDeep() {
    $("deepStatus").textContent = "Loading…";
    Promise.all([
      getJSON(withDevices("wpp-matrix")), getJSON(withDevices("subelements")),
      getJSON(withDevices("orphans")), getJSON(withDevices("freshness")),
      getJSON(withDevices("deep/inventory"))
    ]).then(function (res) {
      renderMatrix(res[0]); renderSub(res[1]); renderOrphans(res[2]); renderFreshness(res[3]);
      renderInventory(res[4]);
      loadDrillObjects();
      $("deepStatus").textContent = "";
      addExpandButtons();
    }).catch(function (e) { $("deepStatus").textContent = "Error: " + e; });
  }

  function runFleetDeep() {
    var btn = $("deepRun"); btn.disabled = true; btn.textContent = "Starting…";
    var token = (document.querySelector('meta[name="csrf-token"]') || {}).content || "";
    var body = selectedDeviceIds().map(function (i) { return "device_id=" + encodeURIComponent(i); }).join("&");
    fetch("deep/run", { method: "POST", headers: { "X-CSRFToken": token, "Content-Type": "application/x-www-form-urlencoded" }, body: body })
      .then(function (r) { return r.json(); }).then(function (j) {
        if (!j.started) { $("deepStatus").textContent = j.reason || "could not start"; btn.disabled = false; btn.textContent = "Run deep capture"; return; }
        pollJob(j.job.job_id, btn);
      });
  }
  function pollJob(jobId, btn) {
    getJSON("deep/job/" + jobId).then(function (st) {
      if (!st || st.error) { btn.disabled = false; btn.textContent = "Run deep capture"; return; }
      $("deepStatus").textContent = "Deep capture: " + (st.done || 0) + "/" + (st.total || 0) + " device(s) · " + (st.percent || 0) + "%";
      if (st.finished) { btn.disabled = false; btn.textContent = "Run deep capture"; loadDeep(); return; }
      setTimeout(function () { pollJob(jobId, btn); }, 2000);
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    if (!$("deepStatus")) return;  // deep section not on this page
    $("anamClose").addEventListener("click", closeModal);
    $("anamType").addEventListener("change", drawModal);
    $("anamTop").addEventListener("input", drawModal);
    $("anamCsv").addEventListener("click", exportCSV);
    $("anamPng").addEventListener("click", exportPNG);
    modalEl().addEventListener("click", function (e) { if (e.target === modalEl()) closeModal(); });
    $("deepReload").addEventListener("click", loadDeep);
    $("deepRun").addEventListener("click", runFleetDeep);
    $("deepKind").addEventListener("change", loadDrillObjects);
    $("deepObj").addEventListener("change", loadDrill);
    // expose for the matrix/sub charts so the generic ⤢ also opens deep charts
    ["anaApply", "anaRefresh", "anaReset"].forEach(function (id) {
      var b = $(id); if (b) b.addEventListener("click", function () { setTimeout(loadDeep, 400); });
    });
    setTimeout(loadDeep, 300);  // after the main dashboard has drawn
  });
})();
