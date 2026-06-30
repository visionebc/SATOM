/* Analysis dashboard — DB-first, dynamic. Fetches /analysis/data with the
   current filters and (re)draws every chart + table client-side. */
(function () {
  "use strict";
  var PALETTE = ["#2563eb", "#7c3aed", "#0ea5e9", "#10b981", "#f59e0b",
    "#ef4444", "#14b8a6", "#a855f7", "#84cc16", "#f97316", "#06b6d4",
    "#ec4899", "#22c55e", "#eab308", "#6366f1"];
  var charts = {};
  var lastData = null;
  window.__anaCharts = charts;  // exposed so analysis_deep's chart-modal can expand any chart


  function $(id) { return document.getElementById(id); }
  function colors(n) { var a = []; for (var i = 0; i < n; i++) a.push(PALETTE[i % PALETTE.length]); return a; }
  function labels(d) { return (d || []).map(function (x) { return x.label; }); }
  function counts(d) { return (d || []).map(function (x) { return x.count; }); }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]; }); }

  function destroy(id) { if (charts[id]) { charts[id].destroy(); delete charts[id]; } }

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

  function rows(tbodyId, arr, fn) {
    var tb = $(tbodyId); if (!tb) return;
    if (!arr || !arr.length) { tb.innerHTML = '<tr><td colspan="12" class="ana-empty">No data</td></tr>'; return; }
    tb.innerHTML = arr.map(fn).join("");
  }

  function pill(on, txt) { return '<span class="ana-pill ' + (on ? "on" : "off") + '">' + txt + '</span>'; }

  function render(d) {
    lastData = d;
    $("anaStatus").textContent = d.scope.device_count + " device(s) · generated " + (d.generated_at || "").replace("T", " ").replace("Z", "") + " UTC";
    var s = d.summary;
    $("anaCards").innerHTML = [
      card("Devices", s.devices),
      card("Server policies", s.server_policies),
      card("Objects", s.objects),
      card("Object types", s.object_types),
      card("WPP", s.wpp),
      card("Pools", s.pools),
      card("Services", s.services),
      card("tlog enabled", s.tlog_enabled),
      card("App IDs", s.appids),
      card("Without App ID", s.policies_without_appid, s.policies_without_appid ? "warn" : ""),
      card("Exceptions", s.exceptions),
      card("Dup. exceptions", s.exception_duplicates, s.exception_duplicates ? "bad" : ""),
      card("Segments", s.segments),
      card("Segment IPs", s.segment_ips)
    ].join("");

    // Devices
    doughnut("cDevPlatform", d.devices.by_platform);
    bar("cDevZone", d.devices.by_zone, true);
    bar("cDevLine", d.devices.by_line, true);
    bar("cDevDept", d.devices.by_department, true);
    doughnut("cDevStatus", d.devices.by_status);
    bar("cObjSection", d.objects_by_section, true);

    // Object inventory (every section & type)
    bar("cInvSection", d.inventory.by_section, true);
    bar("cInvTypes", d.inventory.top_types, true);
    $("invN").textContent = "(" + d.inventory.total_objects + " objects · " + d.inventory.type_count + " types)";
    var _isel = $("invSection"), _icur = _isel.value;
    _isel.innerHTML = '<option value="">All sections</option>' +
      (d.inventory.sections || []).map(function (s2) { return '<option value="' + esc(s2.section) + '">' + esc(s2.section) + " (" + s2.total + ")</option>"; }).join("");
    _isel.value = _icur;
    drawInventory();

    // Policies
    bar("cPolMode", d.policies.by_deployment_mode);
    doughnut("cPolStatus", d.policies.by_status);
    doughnut("cPolTlog", d.policies.tlog);
    doughnut("cPolTls", d.policies.tls);
    bar("cPolDev", d.policies.per_device, true);
    $("polCount").textContent = "(" + d.policies.total + ")";
    window.__polRows = d.policies.rows || [];
    drawPolicies();

    // WPP
    doughnut("cWppKind", d.wpp.by_kind);
    bar("cWppDev", d.wpp.by_device, true);
    bar("cWppUsage", d.wpp.usage, true);
    rows("tWppMatrix tbody" && "tWppMatrixBody", null); // placeholder, replaced below
    var mtb = document.querySelector("#tWppMatrix tbody");
    mtb.innerHTML = (d.wpp.per_device_matrix && d.wpp.per_device_matrix.length)
      ? d.wpp.per_device_matrix.map(function (r) { return "<tr><td>" + esc(r.device) + "</td><td>" + esc(r.wpp) + "</td><td>" + r.policies + "</td></tr>"; }).join("")
      : '<tr><td colspan="3" class="ana-empty">No data</td></tr>';
    $("wppUnusedN").textContent = "(" + d.wpp.unused_count + ")";
    $("wppUnused").innerHTML = (d.wpp.unused && d.wpp.unused.length)
      ? d.wpp.unused.map(function (n) { return '<span class="ana-pill none" style="margin:.15rem">' + esc(n) + "</span>"; }).join("")
      : '<div class="ana-empty">All WPP are bound to at least one policy</div>';

    // Backends / services
    doughnut("cPoolType", d.pools.by_type);
    doughnut("cPoolProto", d.pools.by_protocol);
    bar("cPoolDev", d.pools.per_device, true);
    bar("cSvcPorts", d.services.policy_service_ports);
    bar("cSvcHttps", d.services.policy_https_ports);

    // Exceptions
    doughnut("cExcCat", d.exceptions.by_category);
    bar("cExcType", d.exceptions.by_type, true);
    bar("cExcDev", d.exceptions.by_device, true);
    $("excDupN").textContent = "(" + d.exceptions.duplicate_count + ")";
    rows("tExcDup", null);
    document.querySelector("#tExcDup tbody").innerHTML = (d.exceptions.duplicates && d.exceptions.duplicates.length)
      ? d.exceptions.duplicates.map(function (r) { return "<tr><td>" + esc(r.device) + "</td><td>" + esc(r.wpp) + "</td><td>" + esc(r.exc_type) + "</td><td><b>" + r.count + "</b></td><td>" + esc((r.names || []).join(", ")) + "</td></tr>"; }).join("")
      : '<tr><td colspan="5" class="ana-empty">No duplicate exceptions found</td></tr>';

    // App IDs
    doughnut("cAppidCov", d.appids.coverage);
    $("appidN").textContent = "(" + d.appids.total + " · regex " + esc(d.appids.regex) + ")";
    document.querySelector("#tAppid tbody").innerHTML = (d.appids.rows && d.appids.rows.length)
      ? d.appids.rows.map(function (r) { return '<tr><td><span class="ana-pill app">' + esc(r.appid) + "</span></td><td>" + r.policies + "</td><td>" + esc((r.devices || []).join(", ")) + "</td><td>" + esc((r.policy_names || []).join(", ")) + "</td></tr>"; }).join("")
      : '<tr><td colspan="4" class="ana-empty">No App IDs matched in any server-policy comment</td></tr>';
    $("noAppidN").textContent = "(" + d.appids.without_appid + ")";
    document.querySelector("#tNoAppid tbody").innerHTML = (d.appids.without_appid_rows && d.appids.without_appid_rows.length)
      ? d.appids.without_appid_rows.map(function (r) { return "<tr><td>" + esc(r.device) + "</td><td>" + esc(r.name) + "</td><td>" + esc(r.comment) + "</td></tr>"; }).join("")
      : '<tr><td colspan="3" class="ana-empty">Every policy has an App ID</td></tr>';

    // Segments
    bar("cSegIps", d.segments.ips_by_segment, true);
    $("segN").textContent = "(" + d.segments.total + " · " + d.segments.total_ips + " IPs)";
    document.querySelector("#tSeg tbody").innerHTML = (d.segments.rows && d.segments.rows.length)
      ? d.segments.rows.map(function (r) { return "<tr><td>" + esc(r.name) + "</td><td>" + esc(r.cidr) + "</td><td>" + r.ips + "</td><td>" + esc(r.interface) + "</td><td>" + esc(r.gateway) + "</td><td>" + esc(r.zone) + "</td><td>" + esc(r.line) + "</td><td>" + esc(r.department) + "</td></tr>"; }).join("")
      : '<tr><td colspan="8" class="ana-empty">No segments configured</td></tr>';

    // Changes
    line("cChgTime", d.changes.timeline);
    bar("cChgAction", d.changes.by_action);
    bar("cChgDev", d.changes.by_device, true);
    bar("cAuditAction", d.changes.audit_by_action, true);
    $("chgN").textContent = "(" + d.changes.total + " · " + d.changes.live + " live / " + d.changes.dry_run + " dry-run)";
    document.querySelector("#tChanges tbody").innerHTML = (d.changes.recent && d.changes.recent.length)
      ? d.changes.recent.map(function (r) { return "<tr><td>" + esc((r.ts || "").replace("T", " ").slice(0, 19)) + "</td><td>" + esc(r.device) + "</td><td>" + esc(r.action) + "</td><td>" + esc(r.endpoint) + "</td><td>" + esc(r.mkey) + "</td><td>" + (r.dry_run ? '<span class="ana-pill none">dry</span>' : '<span class="ana-pill on">live</span>') + "</td><td>" + esc(r.user) + "</td></tr>"; }).join("")
      : '<tr><td colspan="7" class="ana-empty">No changes in range</td></tr>';
  }

  function drawInventory() {
    var inv = (lastData && lastData.inventory) || { sections: [], device_names: [] };
    var devs = inv.device_names || [];
    $("invHead").innerHTML = "<th>Section</th><th>Object type</th><th>Total</th>" +
      devs.map(function (n) { return "<th>" + esc(n) + "</th>"; }).join("");
    var secSel = $("invSection").value || "";
    var q = ($("invFilter").value || "").toLowerCase();
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
    document.querySelector("#tInv tbody").innerHTML = body.length ? body.join("")
      : '<tr><td colspan="20" class="ana-empty">No objects in scope</td></tr>';
  }

  function drawPolicies() {
    var q = ($("polFilter").value || "").toLowerCase();
    var arr = (window.__polRows || []).filter(function (r) {
      if (!q) return true;
      return [r.device, r.name, r.deployment_mode, r.wpp, r.appid, r.comment].join(" ").toLowerCase().indexOf(q) >= 0;
    });
    rows("tPolicies", null);
    document.querySelector("#tPolicies tbody").innerHTML = arr.length
      ? arr.map(function (r) {
        return "<tr><td>" + esc(r.device) + "</td><td>" + esc(r.name) + "</td><td>" + esc(r.deployment_mode) + "</td><td>" +
          pill(r.status === "enable" || r.status === "enabled", r.status || "?") + "</td><td>" +
          pill(r.tlog, r.tlog ? "on" : "off") + "</td><td>" + esc(r.wpp) + "</td><td>" + esc(r.service) + "</td><td>" + esc(r.https_service) + "</td><td>" +
          (r.appid ? '<span class="ana-pill app">' + esc(r.appid) + "</span>" : '<span class="ana-pill none">—</span>') + "</td></tr>";
      }).join("")
      : '<tr><td colspan="9" class="ana-empty">No matching policies</td></tr>';
  }

  function collect() {
    var p = new URLSearchParams();
    var pl = $("fPlatform").value, z = $("fZone").value, l = $("fLine").value, dp = $("fDept").value, ff = $("fFrom").value, ft = $("fTo").value;
    if (pl) p.set("platform", pl);
    if (z) p.set("zone", z);
    if (l) p.set("line", l);
    if (dp) p.set("department", dp);
    if (ff) p.set("date_from", ff);
    if (ft) p.set("date_to", ft);
    Array.prototype.forEach.call($("fDevices").selectedOptions, function (o) { p.append("device_ids", o.value); });
    return p.toString();
  }

  function load() {
    $("anaStatus").textContent = "Loading…";
    fetch("data?" + collect(), { headers: { "Accept": "application/json" } })
      .then(function (r) { return r.json(); })
      .then(render)
      .catch(function (e) { $("anaStatus").textContent = "Error loading data: " + e; });
  }

  document.addEventListener("DOMContentLoaded", function () {
    $("anaApply").addEventListener("click", load);
    $("anaRefresh").addEventListener("click", load);
    $("polFilter").addEventListener("input", drawPolicies);
    $("invSection").addEventListener("change", drawInventory);
    $("invFilter").addEventListener("input", drawInventory);
    $("anaReset").addEventListener("click", function () {
      ["fPlatform", "fZone", "fLine", "fDept", "fFrom", "fTo"].forEach(function (id) { $(id).value = ""; });
      Array.prototype.forEach.call($("fDevices").options, function (o) { o.selected = false; });
      load();
    });
    load();
  });
})();
