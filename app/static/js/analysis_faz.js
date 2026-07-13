/* Analysis dashboard — FortiAnalyzer variant. DB-first inventory/change
   activity from /analysis/data (product-scoped to FAZ) + LIVE log-rate and
   storage/quota from /analysis/faz-ops (JSON-RPC to the appliance). */
(function () {
  "use strict";
  var PALETTE = ["#2563eb", "#7c3aed", "#0ea5e9", "#10b981", "#f59e0b",
    "#ef4444", "#14b8a6", "#a855f7", "#84cc16", "#f97316", "#06b6d4",
    "#ec4899", "#22c55e", "#eab308", "#6366f1"];
  var charts = {};
  var lastData = null;

  function $(id) { return document.getElementById(id); }
  function colors(n) { var a = []; for (var i = 0; i < n; i++) a.push(PALETTE[i % PALETTE.length]); return a; }
  function labels(d) { return (d || []).map(function (x) { return x.label; }); }
  function counts(d) { return (d || []).map(function (x) { return x.count; }); }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]; }); }
  function destroy(id) { if (charts[id]) { charts[id].destroy(); delete charts[id]; } }

  function fmtBytes(n) {
    n = Number(n) || 0;
    var u = ["B", "KB", "MB", "GB", "TB"], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (n < 10 && i > 0 ? n.toFixed(2) : Math.round(n)) + " " + u[i];
  }

  function bar(id, dist, horizontal) {
    destroy(id); var el = $(id); if (!el) return;
    charts[id] = new Chart(el, {
      type: "bar",
      data: { labels: labels(dist), datasets: [{ data: counts(dist), backgroundColor: colors((dist || []).length), borderRadius: 4 }] },
      options: {
        indexAxis: horizontal ? "y" : "x", responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: { ticks: { font: { size: 10 } } }, y: { beginAtZero: true, ticks: { precision: 0, font: { size: 10 } } } }
      }
    });
  }
  function doughnut(id, dist) {
    destroy(id); var el = $(id); if (!el) return;
    charts[id] = new Chart(el, {
      type: "doughnut",
      data: { labels: labels(dist), datasets: [{ data: counts(dist), backgroundColor: colors((dist || []).length), borderWidth: 1, borderColor: "#fff" }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: "bottom", labels: { font: { size: 10 }, boxWidth: 12 } } } }
    });
  }
  function line(id, series) {
    destroy(id); var el = $(id); if (!el) return;
    var lbls = (series || []).map(function (x) { return x.day; });
    charts[id] = new Chart(el, {
      type: "line",
      data: {
        labels: lbls, datasets: [
          { label: "Config changes", data: (series || []).map(function (x) { return x.changes; }), borderColor: "#2563eb", backgroundColor: "rgba(37,99,235,.12)", fill: true, tension: .25, pointRadius: 2 },
          { label: "Audit events", data: (series || []).map(function (x) { return x.audit; }), borderColor: "#a855f7", backgroundColor: "rgba(168,85,247,.10)", fill: true, tension: .25, pointRadius: 2 }
        ]
      },
      options: { responsive: true, maintainAspectRatio: false, interaction: { mode: "index", intersect: false }, plugins: { legend: { position: "bottom", labels: { font: { size: 10 } } } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } }
    });
  }
  function card(k, v, cls) {
    return '<div class="ana-card ' + (cls || "") + '"><div class="v">' + v + '</div><div class="k">' + esc(k) + '</div></div>';
  }

  // ---- DB-first inventory / devices / changes ------------------------------
  function render(d) {
    lastData = d;
    var s = d.summary || {};
    $("anaStatus").textContent = d.scope.device_count + " device(s) · generated " + (d.generated_at || "").replace("T", " ").replace("Z", "") + " UTC";
    $("anaCards").innerHTML = [
      card("Devices", s.devices || 0),
      card("Objects", s.objects || 0),
      card("Object types", s.object_types || 0),
      card("Changes", (d.changes && d.changes.total) || 0)
    ].join("");

    // Devices
    bar("cDevZone", d.devices.by_zone, true);
    bar("cDevLine", d.devices.by_line, true);
    bar("cDevDept", d.devices.by_department, true);
    doughnut("cDevStatus", d.devices.by_status);

    // Object inventory
    var inv = d.inventory || { sections: [], device_names: [], by_section: [], top_types: [] };
    bar("cInvSection", inv.by_section, true);
    bar("cInvTypes", inv.top_types, true);
    if ($("invN")) $("invN").textContent = "(" + inv.total_objects + " objects · " + inv.type_count + " types)";
    var isel = $("invSection"), icur = isel ? isel.value : "";
    if (isel) {
      isel.innerHTML = '<option value="">All sections</option>' +
        (inv.sections || []).map(function (s2) { return '<option value="' + esc(s2.section) + '">' + esc(s2.section) + " (" + s2.total + ")</option>"; }).join("");
      isel.value = icur;
    }
    drawInventory();

    // Changes
    line("cChgTime", d.changes.timeline);
    bar("cChgAction", d.changes.by_action);
    bar("cAuditAction", d.changes.audit_by_action, true);
    if ($("chgN")) $("chgN").textContent = "(" + d.changes.total + " · " + d.changes.live + " live / " + d.changes.dry_run + " dry-run)";
    var ctb = document.querySelector("#tChanges tbody");
    if (ctb) ctb.innerHTML = (d.changes.recent && d.changes.recent.length)
      ? d.changes.recent.map(function (r) { return "<tr><td>" + esc((r.ts || "").replace("T", " ").slice(0, 19)) + "</td><td>" + esc(r.device) + "</td><td>" + esc(r.action) + "</td><td>" + esc(r.endpoint) + "</td><td>" + esc(r.mkey) + "</td><td>" + (r.dry_run ? '<span class="ana-empty">dry</span>' : "live") + "</td><td>" + esc(r.user) + "</td></tr>"; }).join("")
      : '<tr><td colspan="7" class="ana-empty">No changes in range</td></tr>';
  }

  function drawInventory() {
    var inv = (lastData && lastData.inventory) || { sections: [], device_names: [] };
    var devs = inv.device_names || [];
    if ($("invHead")) $("invHead").innerHTML = "<th>Section</th><th>Object type</th><th>Total</th>" +
      devs.map(function (n) { return "<th>" + esc(n) + "</th>"; }).join("");
    var secSel = $("invSection") ? ($("invSection").value || "") : "";
    var q = $("invFilter") ? ($("invFilter").value || "").toLowerCase() : "";
    var body = [];
    (inv.sections || []).forEach(function (sec) {
      if (secSel && sec.section !== secSel) return;
      (sec.types || []).forEach(function (t) {
        if (q && (t.label + " " + t.logical_name).toLowerCase().indexOf(q) < 0) return;
        body.push("<tr><td>" + esc(sec.section) + "</td><td>" + esc(t.label) +
          ' <span style="opacity:.4;font-size:.7rem">' + esc(t.logical_name) + "</span></td><td><b>" + t.total + "</b></td>" +
          (t.per_device || []).map(function (c) { return "<td>" + (c || "") + "</td>"; }).join("") + "</tr>");
      });
    });
    var tb = document.querySelector("#tInv tbody");
    if (tb) tb.innerHTML = body.length ? body.join("") : '<tr><td colspan="20" class="ana-empty">No objects in scope</td></tr>';
  }

  // ---- LIVE ops: log rate + storage/quota ----------------------------------
  function renderOps(o) {
    if (o.error) { $("opsStatus").innerHTML = '<span style="color:#b45309">Live read failed: ' + esc(o.error) + "</span>"; }
    else { $("opsStatus").textContent = "Live from " + esc((o.devices || []).join(", ") || "FortiAnalyzer") + " · " + (o.generated_at || "").replace("T", " ").replace("Z", "") + " UTC"; }

    var lr = o.lograte || { total: 0, devs: [] };
    var stg = o.storage || { adoms: [], total: {} };
    var t = stg.total || {};
    $("opsCards").innerHTML = [
      card("Log rate (logs/s)", (lr.total || 0)),
      card("Devices logging", (lr.devs || []).length),
      card("Analytics used", fmtBytes(t.analytics_used)),
      card("Analytics quota", fmtBytes(t.analytics_max)),
      card("Archive used", fmtBytes(t.archive_used)),
      card("ADOMs", (stg.adoms || []).length)
    ].join("");

    var rtb = document.querySelector("#tLogRate tbody");
    if (rtb) rtb.innerHTML = (lr.devs && lr.devs.length)
      ? lr.devs.map(function (r) { return "<tr><td>" + esc(r.name) + "</td><td><b>" + (r.rate || 0) + "</b></td></tr>"; }).join("")
      : '<tr><td colspan="2" class="ana-empty">No devices currently sending logs</td></tr>';

    if ($("stgN")) $("stgN").textContent = "(" + (stg.adoms || []).length + " ADOMs)";
    var stb = document.querySelector("#tStorage tbody");
    if (stb) stb.innerHTML = (stg.adoms && stg.adoms.length)
      ? stg.adoms.map(function (a) {
        var pct = a.analytics_max ? Math.round((a.analytics_used / a.analytics_max) * 100) : 0;
        var warn = pct >= 80 ? " warn" : "";
        return "<tr><td><b>" + esc(a.name) + "</b></td><td>" + fmtBytes(a.analytics_used) + "</td><td>" + fmtBytes(a.analytics_max) +
          '</td><td style="min-width:90px">' + pct + '%<div class="fazbar' + warn + '"><span style="width:' + Math.min(pct, 100) + '%"></span></div></td><td>' +
          fmtBytes(a.archive_used) + "</td><td>" + fmtBytes(a.archive_max) + "</td><td>" +
          esc((a.analytics_days_config || 0) + " / " + (a.archive_days_config || 0)) + "</td></tr>";
      }).join("")
      : '<tr><td colspan="7" class="ana-empty">No storage data</td></tr>';
  }

  function loadData() {
    $("anaStatus").textContent = "Loading…";
    fetch("data", { headers: { "Accept": "application/json" } })
      .then(function (r) { return r.json(); })
      .then(render)
      .catch(function (e) { $("anaStatus").textContent = "Error loading data: " + e; });
  }
  function loadOps() {
    $("opsStatus").textContent = "Loading live data from the FortiAnalyzer…";
    fetch("faz-ops", { headers: { "Accept": "application/json" } })
      .then(function (r) { return r.json(); })
      .then(renderOps)
      .catch(function (e) { $("opsStatus").textContent = "Error loading live data: " + e; });
  }

  document.addEventListener("DOMContentLoaded", function () {
    if ($("anaRefresh")) $("anaRefresh").addEventListener("click", function () { loadData(); loadOps(); });
    if ($("invSection")) $("invSection").addEventListener("change", drawInventory);
    if ($("invFilter")) $("invFilter").addEventListener("input", drawInventory);
    loadData();
    loadOps();
  });
})();
