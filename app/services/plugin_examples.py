"""Plugin Studio — a validated catalog of example custom views.

Each example is a fully-formed plugin (name, datasets, Jinja body, CSS, JS) the
author can insert into the editor with one click and then tweak. They are
organised by GROUP (top-level menu) and SUBGROUP (submenu) so the picker reads
like a gallery of "what can I build".

Hard rules every example in here obeys (they are what the sandbox enforces):

* Every Jinja body reads ONLY the curated ``data`` object (see
  ``plugin_sandbox.DATASETS``). It only references dataset keys it declared in
  ``datasets`` and only the real column names of those datasets — anything else
  raises under ``StrictUndefined`` and is a FAIL.
* Every body renders nicely on an EMPTY result set (a "0 / none" state, never a
  crash), because a fresh or license-locked fleet returns no rows for several of
  the datasets (server_policies, web_protection_profiles, certificates,
  scheduled_actions are all commonly empty).

The ``jinja``/``css``/``js`` values are literal editor source. The Jinja
``{{ }}`` / ``{% %}`` markers stay literal in these Python strings — they are
inserted verbatim into the editor textarea and are NEVER rendered by the page's
own Jinja. This module is pure data — no Flask, no DB.

Public surface (kept stable): ``all_examples()`` and ``categories()``.
"""
from __future__ import annotations

from typing import Any


# Small shared CSS fragments so the bodies stay readable. They are concatenated
# into each example's ``css`` string; each example still renders in its own
# sandboxed iframe so class names never collide.
_BASE = (
    "h2{font-size:18px;margin:0 0 12px;color:#e2e8f0}"
    "h3{font-size:14px;color:#cbd5e1;margin:16px 0 6px}"
    ".hint{font-size:12px;color:#94a3b8;margin:0 0 12px}"
    "table{width:100%;border-collapse:collapse;font-size:13px}"
    "th{text-align:left;color:#94a3b8;font-weight:600;padding:6px 8px;border-bottom:1px solid rgba(148,163,184,.15)}"
    "td{padding:6px 8px;border-bottom:1px solid rgba(148,163,184,.07);color:#e2e8f0}"
)
_CARD = (
    ".card{background:rgba(15,23,42,.6);border:1px solid rgba(148,163,184,.12);"
    "border-radius:14px;padding:16px}"
)
_STATUS = (
    ".st{border-radius:6px;padding:2px 8px;font-size:11px}"
    ".st.on{background:rgba(16,185,129,.15);color:#6ee7b7}"
    ".st.off{background:rgba(239,68,68,.12);color:#fca5a5}"
)
_BAR = (
    ".bar{display:flex;align-items:center;gap:10px;margin:7px 0}"
    ".bar .lbl{width:150px;font-size:13px;color:#cbd5e1;overflow:hidden;"
    "text-overflow:ellipsis;white-space:nowrap}"
    ".bar .track{flex:1;background:rgba(148,163,184,.1);border-radius:8px;height:20px;overflow:hidden}"
    ".bar .fill{height:100%;background:linear-gradient(90deg,#3b82f6,#8b5cf6)}"
    ".bar .val{width:38px;text-align:right;font-size:13px}"
)
_BANNER = (
    ".banner{display:flex;align-items:center;gap:16px;background:rgba(15,23,42,.6);"
    "border:1px solid rgba(148,163,184,.12);border-radius:16px;padding:20px;margin-bottom:18px}"
    ".banner .big{font-size:44px;font-weight:700}"
    ".banner.bad .big{color:#fca5a5}.banner.good .big{color:#6ee7b7}"
    ".banner .sub{font-size:12px;color:#94a3b8;margin-top:2px}"
)
_DONUT = (
    ".donut-wrap{display:flex;align-items:center;gap:24px;flex-wrap:wrap}"
    ".donut{width:150px;height:150px;border-radius:50%;background:rgba(148,163,184,.12)}"
    ".donut .hole{position:relative;top:37px;left:37px;width:76px;height:76px;border-radius:50%;"
    "background:#0b1220;display:flex;align-items:center;justify-content:center;flex-direction:column}"
    ".donut .hole b{font-size:24px;color:#e2e8f0}.donut .hole span{font-size:10px;color:#94a3b8;text-transform:uppercase}"
    ".legend div{display:flex;align-items:center;gap:8px;font-size:13px;margin:6px 0;color:#cbd5e1}"
    ".legend i{width:12px;height:12px;border-radius:3px;display:inline-block}"
)


_EXAMPLES: list[dict[str, Any]] = [

    # =========================================================================
    # GROUP: Fleet Overview
    # =========================================================================
    {
        "id": "fleet_kpis",
        "group": "Fleet Overview", "subgroup": "KPIs",
        "category": "Fleet Overview",
        "title": "Fleet KPIs (cards)", "name": "Fleet KPIs (cards)",
        "icon": "bi-speedometer2",
        "description": "Three big number cards — managed devices, server policies "
                       "and certificates. The classic dashboard header.",
        "tags": ["kpi", "cards", "overview", "counts"],
        "datasets": ["fleet_counts"],
        "params": [],
        "jinja": """{% set c = data.fleet_counts.rows[0] if data.fleet_counts.rows else none %}
<div class="kpi-row">
  <div class="kpi"><div class="kpi-n">{{ c.devices if c else 0 }}</div><div class="kpi-l">Devices</div></div>
  <div class="kpi"><div class="kpi-n">{{ c.server_policies if c else 0 }}</div><div class="kpi-l">Server policies</div></div>
  <div class="kpi"><div class="kpi-n">{{ c.certificates if c else 0 }}</div><div class="kpi-l">Certificates</div></div>
</div>""",
        "css": """.kpi-row{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.kpi{background:rgba(15,23,42,.6);border:1px solid rgba(148,163,184,.12);border-radius:16px;padding:22px;text-align:center}
.kpi-n{font-size:38px;font-weight:700;background:linear-gradient(90deg,#3b82f6,#8b5cf6);-webkit-background-clip:text;background-clip:text;color:transparent}
.kpi-l{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#94a3b8;margin-top:4px}""",
        "js": "",
    },
    {
        "id": "fleet_density_kpi",
        "group": "Fleet Overview", "subgroup": "KPIs",
        "category": "Fleet Overview",
        "title": "Policy density (avg per device)", "name": "Policy density (avg per device)",
        "icon": "bi-calculator",
        "description": "A single derived KPI: average number of server policies per "
                       "managed device, computed from the fleet counts.",
        "tags": ["kpi", "derived", "ratio", "density"],
        "datasets": ["fleet_counts"],
        "params": [],
        "jinja": """{% set c = data.fleet_counts.rows[0] if data.fleet_counts.rows else none %}
{% set dev = (c.devices|int) if c else 0 %}
{% set pol = (c.server_policies|int) if c else 0 %}
<div class="stat">
  <div class="stat-n">{{ (pol / dev)|round(1) if dev else 0 }}</div>
  <div class="stat-l">server policies per device</div>
  <div class="stat-sub">{{ pol }} policies across {{ dev }} device(s)</div>
</div>""",
        "css": """.stat{background:rgba(15,23,42,.6);border:1px solid rgba(148,163,184,.12);border-radius:16px;padding:26px;text-align:center}
.stat-n{font-size:46px;font-weight:700;color:#93c5fd}
.stat-l{font-size:13px;color:#cbd5e1;margin-top:4px}
.stat-sub{font-size:12px;color:#64748b;margin-top:8px}""",
        "js": "",
    },
    {
        "id": "fleet_cert_meter",
        "group": "Fleet Overview", "subgroup": "KPIs",
        "category": "Fleet Overview",
        "title": "Certificate coverage meter", "name": "Certificate coverage meter",
        "icon": "bi-clipboard-data",
        "description": "A horizontal progress meter showing how many certificates "
                       "are tracked relative to the number of devices.",
        "tags": ["kpi", "meter", "progress", "certificates"],
        "datasets": ["fleet_counts"],
        "params": [],
        "jinja": """{% set c = data.fleet_counts.rows[0] if data.fleet_counts.rows else none %}
{% set dev = (c.devices|int) if c else 0 %}
{% set certs = (c.certificates|int) if c else 0 %}
{% set pct = ((certs / dev * 100)|round|int) if dev else 0 %}
{% set pct = 100 if pct > 100 else pct %}
<h2>Certificate coverage</h2>
<div class="meter"><div class="fill" style="width:{{ pct }}%"></div></div>
<div class="cap">{{ certs }} certificate(s) for {{ dev }} device(s) — {{ pct }}%</div>""",
        "css": _BASE + """.meter{height:26px;border-radius:13px;background:rgba(148,163,184,.12);overflow:hidden}
.meter .fill{height:100%;background:linear-gradient(90deg,#10b981,#3b82f6)}
.cap{font-size:12px;color:#94a3b8;margin-top:8px}""",
        "js": "",
    },
    {
        "id": "device_inventory",
        "group": "Fleet Overview", "subgroup": "Inventory",
        "category": "Fleet Overview",
        "title": "Device inventory table", "name": "Device inventory table",
        "icon": "bi-hdd-stack",
        "description": "Every managed appliance with kind, firmware and host — with "
                       "an optional device-kind filter.",
        "tags": ["table", "inventory", "devices", "filter"],
        "datasets": ["fleet_appliances"],
        "params": [{"name": "kind", "label": "Device kind", "type": "select",
                    "options": [{"value": "fortiweb", "label": "FortiWeb"},
                                {"value": "fortiadc", "label": "FortiADC"}],
                    "default": "", "required": False}],
        "jinja": """<h2>Fleet inventory ({{ data.fleet_appliances.rows|length }})</h2>
<table><thead><tr><th>Name</th><th>Kind</th><th>Firmware</th><th>Host</th></tr></thead>
<tbody>
{% for r in data.fleet_appliances.rows if not params.kind or r.kind == params.kind %}
<tr><td>{{ r.name }}</td><td><span class="tag">{{ r.kind }}</span></td><td>{{ r.firmware or '—' }}</td><td>{{ r.host }}:{{ r.port }}</td></tr>
{% else %}
<tr><td colspan="4">No devices registered.</td></tr>
{% endfor %}
</tbody></table>""",
        "css": _BASE + """.tag{background:rgba(59,130,246,.15);color:#93c5fd;border-radius:6px;padding:2px 8px;font-size:11px}""",
        "js": "",
    },
    {
        "id": "device_cards",
        "group": "Fleet Overview", "subgroup": "Inventory",
        "category": "Fleet Overview",
        "title": "Device cards grid", "name": "Device cards grid",
        "icon": "bi-grid-3x3-gap",
        "description": "Each managed appliance rendered as a card with its kind "
                       "badge, firmware and endpoint — a friendlier inventory view.",
        "tags": ["cards", "grid", "devices", "inventory"],
        "datasets": ["fleet_appliances"],
        "params": [],
        "jinja": """<h2>Devices ({{ data.fleet_appliances.rows|length }})</h2>
<div class="grid">
{% for r in data.fleet_appliances.rows %}
  <div class="card">
    <div class="top"><span class="name">{{ r.name }}</span><span class="kind {{ r.kind }}">{{ r.kind }}</span></div>
    <div class="fw">{{ r.firmware or 'firmware unknown' }}</div>
    <div class="host">{{ r.host }}:{{ r.port }}</div>
  </div>
{% else %}
  <div class="card empty">No devices registered.</div>
{% endfor %}
</div>""",
        "css": _CARD + """.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.name{font-weight:600;color:#e2e8f0}
.kind{font-size:10px;text-transform:uppercase;border-radius:6px;padding:2px 8px;background:rgba(59,130,246,.15);color:#93c5fd}
.kind.fortiadc{background:rgba(139,92,246,.15);color:#c4b5fd}
.fw{font-size:12px;color:#94a3b8;margin-bottom:4px}
.host{font-size:12px;color:#64748b;font-family:monospace}
.card.empty{color:#94a3b8;text-align:center}""",
        "js": "",
    },
    {
        "id": "firmware_matrix",
        "group": "Fleet Overview", "subgroup": "Inventory",
        "category": "Fleet Overview",
        "title": "Firmware matrix", "name": "Firmware matrix",
        "icon": "bi-cpu",
        "description": "Groups devices by their firmware build so you can spot fleet "
                       "drift and which boxes need an upgrade.",
        "tags": ["firmware", "grouped", "audit", "drift"],
        "datasets": ["fleet_appliances"],
        "params": [],
        "jinja": """{% set rows = data.fleet_appliances.rows %}
<h2>Firmware across the fleet</h2>
{% if rows %}
<table><thead><tr><th>Firmware</th><th>Devices</th><th>Names</th></tr></thead><tbody>
{% for fw, items in rows|groupby('firmware') %}
<tr><td><code>{{ fw or 'unknown' }}</code></td><td>{{ items|length }}</td>
<td>{{ items|map(attribute='name')|join(', ') }}</td></tr>
{% endfor %}
</tbody></table>
{% else %}<p class="hint">No devices registered.</p>{% endif %}""",
        "css": _BASE + """code{color:#93c5fd;font-size:12px}""",
        "js": "",
    },
    {
        "id": "endpoint_list",
        "group": "Fleet Overview", "subgroup": "Inventory",
        "category": "Fleet Overview",
        "title": "Management endpoints", "name": "Management endpoints",
        "icon": "bi-ethernet",
        "description": "A compact host:port list of every device's management "
                       "endpoint — handy for connectivity checks.",
        "tags": ["endpoints", "hosts", "list", "network"],
        "datasets": ["fleet_appliances"],
        "params": [],
        "jinja": """<h2>Management endpoints</h2>
<ul class="ep">
{% for r in data.fleet_appliances.rows %}
<li><span class="n">{{ r.name }}</span><code>{{ r.host }}:{{ r.port }}</code><span class="k">{{ r.kind }}</span></li>
{% else %}<li class="none">No devices registered.</li>{% endfor %}
</ul>""",
        "css": """.ep{list-style:none;padding:0;margin:0}
.ep li{display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid rgba(148,163,184,.08)}
.ep .n{width:120px;color:#e2e8f0;font-size:13px}
.ep code{flex:1;color:#93c5fd;font-family:monospace;font-size:13px}
.ep .k{font-size:10px;text-transform:uppercase;color:#94a3b8}
.ep .none{color:#94a3b8}""",
        "js": "",
    },
    {
        "id": "devices_by_kind",
        "group": "Fleet Overview", "subgroup": "Charts",
        "category": "Fleet Overview",
        "title": "Devices by kind (bar chart)", "name": "Devices by kind (bar chart)",
        "icon": "bi-bar-chart",
        "description": "A pure-CSS/JS horizontal bar chart of device counts per kind "
                       "(fortiweb / fortiadc). No chart library needed.",
        "tags": ["chart", "bars", "devices", "no-library"],
        "datasets": ["fleet_appliances"],
        "params": [],
        "jinja": """<h2>Devices by kind</h2>
<div id="chart"></div>""",
        "css": _BAR + ".bar .lbl{width:90px;text-transform:capitalize}",
        "js": """var rows=(window.pluginData.fleet_appliances||{}).rows||[];
var counts={};rows.forEach(function(r){counts[r.kind]=(counts[r.kind]||0)+1;});
var el=document.getElementById('chart');
var keys=Object.keys(counts).sort();
if(!keys.length){el.innerHTML='<p style="color:#94a3b8">No devices registered.</p>';}
var max=Math.max(1,...keys.map(function(k){return counts[k];}));
keys.forEach(function(k){
  var pct=Math.round(counts[k]/max*100);
  var d=document.createElement('div');d.className='bar';
  d.innerHTML='<div class="lbl">'+k+'</div><div class="track"><div class="fill" style="width:'+pct+'%"></div></div><div class="val">'+counts[k]+'</div>';
  el.appendChild(d);
});""",
    },
    {
        "id": "fleet_donut",
        "group": "Fleet Overview", "subgroup": "Charts",
        "category": "Fleet Overview",
        "title": "Fleet donut (by kind)", "name": "Fleet donut (by kind)",
        "icon": "bi-pie-chart",
        "description": "A pure-CSS conic-gradient donut of managed devices split by "
                       "kind, with a legend. No chart library.",
        "tags": ["chart", "donut", "devices", "no-library"],
        "datasets": ["fleet_appliances"],
        "params": [],
        "jinja": """<h2>Fleet by device kind</h2>
<div class="donut-wrap"><div id="donut" class="donut"></div><div id="legend" class="legend"></div></div>""",
        "css": _DONUT,
        "js": """var rows=(window.pluginData.fleet_appliances||{}).rows||[];
var counts={};rows.forEach(function(r){counts[r.kind]=(counts[r.kind]||0)+1;});
var total=rows.length||1;var palette=['#3b82f6','#10b981','#8b5cf6','#fbbf24','#ef4444'];
var seg=[],acc=0,i=0,legend='';
Object.keys(counts).sort().forEach(function(k){
  var c=palette[i%palette.length];var pct=counts[k]/total*100;
  seg.push(c+' '+acc.toFixed(1)+'% '+(acc+pct).toFixed(1)+'%');acc+=pct;
  legend+='<div><i style="background:'+c+'"></i>'+k+' — '+counts[k]+'</div>';i++;});
var d=document.getElementById('donut');
d.style.background=seg.length?'conic-gradient('+seg.join(',')+')':'rgba(148,163,184,.12)';
d.innerHTML='<div class="hole"><b>'+rows.length+'</b><span>devices</span></div>';
document.getElementById('legend').innerHTML=legend||'<div>No devices.</div>';""",
    },
    {
        "id": "firmware_bars",
        "group": "Fleet Overview", "subgroup": "Charts",
        "category": "Fleet Overview",
        "title": "Firmware distribution (bars)", "name": "Firmware distribution (bars)",
        "icon": "bi-bar-chart-steps",
        "description": "A pure-Jinja bar chart of how many devices run each firmware "
                       "build — widths computed in the template, no JavaScript.",
        "tags": ["chart", "bars", "firmware", "jinja-only"],
        "datasets": ["fleet_appliances"],
        "params": [],
        "jinja": """{% set rows = data.fleet_appliances.rows %}
<h2>Firmware distribution</h2>
{% if rows %}
{% set total = rows|length %}
{% for fw, items in rows|groupby('firmware') %}
<div class="bar"><div class="lbl" title="{{ fw or 'unknown' }}">{{ fw or 'unknown' }}</div>
<div class="track"><div class="fill" style="width:{{ (items|length / total * 100)|round|int }}%"></div></div>
<div class="val">{{ items|length }}</div></div>
{% endfor %}
{% else %}<p class="hint">No devices registered.</p>{% endif %}""",
        "css": _BASE + _BAR + ".bar .lbl{width:190px;font-family:monospace;font-size:11px}",
        "js": "",
    },

    # =========================================================================
    # GROUP: Server Policies
    # =========================================================================
    {
        "id": "server_policy_table",
        "group": "Server Policies", "subgroup": "Tables",
        "category": "Server Policies",
        "title": "Server policy table (full)", "name": "Server policy table (full)",
        "icon": "bi-table",
        "description": "All cached server policies with deployment mode, virtual "
                       "server, pool, WPP and status — filterable by typing.",
        "tags": ["table", "policies", "searchable", "waf"],
        "datasets": ["server_policies_full"],
        "params": [{"name": "device", "label": "Device", "type": "device",
                    "default": "", "required": False}],
        "jinja": """<h2>Server policies ({{ data.server_policies_full.rows|length }})</h2>
<input id="q" placeholder="Filter…" class="q">
<table id="t"><thead><tr><th>Device</th><th>Policy</th><th>Mode</th><th>Virtual server</th><th>Pool</th><th>WPP</th><th>Status</th></tr></thead>
<tbody>
{% for r in data.server_policies_full.rows if not params.device or (r.appliance_id|string == params.device) %}
<tr><td>{{ r.device or r.appliance_id }}</td><td>{{ r.policy }}</td><td>{{ r.deployment_mode or '—' }}</td>
<td>{{ r.vserver or '—' }}</td><td>{{ r.server_pool or '—' }}</td><td>{{ r.wpp or '—' }}</td>
<td><span class="st {{ 'on' if r.status=='enable' else 'off' }}">{{ r.status or '—' }}</span></td></tr>
{% else %}<tr><td colspan="7">No cached policies. Run a rediscovery.</td></tr>{% endfor %}
</tbody></table>""",
        "css": _BASE + _STATUS + """.q{width:100%;padding:8px 12px;margin-bottom:10px;background:rgba(15,23,42,.6);border:1px solid rgba(148,163,184,.15);border-radius:10px;color:#e2e8f0}""",
        "js": """var q=document.getElementById('q'),t=document.getElementById('t');
q.addEventListener('input',function(){var v=q.value.toLowerCase();
t.querySelectorAll('tbody tr').forEach(function(tr){tr.style.display=tr.textContent.toLowerCase().indexOf(v)>=0?'':'none';});});""",
    },
    {
        "id": "policies_typed_table",
        "group": "Server Policies", "subgroup": "Tables",
        "category": "Server Policies",
        "title": "Typed policy cache", "name": "Typed policy cache",
        "icon": "bi-server",
        "description": "The lighter, typed server-policy cache (name, mode, vserver, "
                       "pool, status). Commonly EMPTY until a rich rediscovery runs.",
        "tags": ["table", "policies", "cache", "empty-safe"],
        "datasets": ["server_policies"],
        "params": [],
        "jinja": """<h2>Typed policy cache ({{ data.server_policies.rows|length }})</h2>
<table><thead><tr><th>Device</th><th>Name</th><th>Mode</th><th>Virtual server</th><th>Pool</th><th>Status</th></tr></thead><tbody>
{% for r in data.server_policies.rows %}
<tr><td>{{ r.appliance_id }}</td><td>{{ r.name }}</td><td>{{ r.deployment_mode or '—' }}</td>
<td>{{ r.vserver or '—' }}</td><td>{{ r.server_pool or '—' }}</td>
<td><span class="st {{ 'on' if r.status=='enable' else 'off' }}">{{ r.status or '—' }}</span></td></tr>
{% else %}<tr><td colspan="6">Typed cache empty — run a rediscovery to populate it.</td></tr>{% endfor %}
</tbody></table>""",
        "css": _BASE + _STATUS,
        "js": "",
    },
    {
        "id": "policy_cards",
        "group": "Server Policies", "subgroup": "Tables",
        "category": "Server Policies",
        "title": "Policy detail cards", "name": "Policy detail cards",
        "icon": "bi-card-list",
        "description": "Each server policy as a detail card showing its vserver, "
                       "pool, WPP, service and traffic-log / monitor-mode flags.",
        "tags": ["cards", "policies", "detail"],
        "datasets": ["server_policies_full"],
        "params": [],
        "jinja": """<h2>Server policies ({{ data.server_policies_full.rows|length }})</h2>
<div class="grid">
{% for r in data.server_policies_full.rows %}
  <div class="card">
    <div class="top"><b>{{ r.policy }}</b><span class="st {{ 'on' if r.status=='enable' else 'off' }}">{{ r.status or '—' }}</span></div>
    <div class="meta">{{ r.device or r.appliance_id }} · {{ r.deployment_mode or 'mode?' }}</div>
    <div class="kv"><span>vserver</span>{{ r.vserver or '—' }}</div>
    <div class="kv"><span>pool</span>{{ r.server_pool or '—' }}</div>
    <div class="kv"><span>WPP</span>{{ r.wpp or '⚠️ none' }}</div>
    <div class="flags">
      <span class="flag {{ 'y' if r.traffic_log=='enable' else 'n' }}">tlog</span>
      <span class="flag {{ 'y' if r.monitor_mode=='enable' else 'n' }}">monitor</span>
    </div>
  </div>
{% else %}<div class="card empty">No cached policies.</div>{% endfor %}
</div>""",
        "css": _CARD + _STATUS + """.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}
.top{display:flex;justify-content:space-between;align-items:center}
.top b{color:#e2e8f0}
.meta{font-size:11px;color:#94a3b8;margin:4px 0 8px}
.kv{display:flex;justify-content:space-between;font-size:12px;color:#cbd5e1;padding:2px 0}
.kv span{color:#64748b}
.flags{margin-top:8px;display:flex;gap:6px}
.flag{font-size:10px;border-radius:5px;padding:2px 7px}
.flag.y{background:rgba(16,185,129,.15);color:#6ee7b7}.flag.n{background:rgba(148,163,184,.1);color:#94a3b8}
.card.empty{color:#94a3b8;text-align:center}""",
        "js": "",
    },
    {
        "id": "traffic_log_policies",
        "group": "Server Policies", "subgroup": "Coverage & Audits",
        "category": "Server Policies",
        "title": "Traffic-log enabled policies", "name": "Traffic-log enabled policies",
        "icon": "bi-journal-text",
        "description": "Every server policy that has Traffic Log ON, plus the ones "
                       "still OFF so you can see the logging coverage gap.",
        "tags": ["audit", "traffic-log", "coverage", "policies"],
        "datasets": ["server_policies_full"],
        "params": [],
        "jinja": """{% set rows = data.server_policies_full.rows %}
{% set on = rows|selectattr('traffic_log','equalto','enable')|list %}
{% set off = rows|rejectattr('traffic_log','equalto','enable')|list %}
<div class="banner good">
  <div class="big">{{ on|length }}</div>
  <div>server policies with <strong>Traffic Log enabled</strong>
  <div class="sub">{{ off|length }} still have it disabled</div></div>
</div>
<h3>Traffic Log ON</h3>
<table><thead><tr><th>Device</th><th>Policy</th><th>Virtual server</th><th>Status</th></tr></thead><tbody>
{% for r in on %}<tr><td>{{ r.device or r.appliance_id }}</td><td>{{ r.policy }}</td><td>{{ r.vserver or '—' }}</td><td>{{ r.status }}</td></tr>
{% else %}<tr><td colspan="4">None yet — no policy has traffic logging enabled.</td></tr>{% endfor %}
</tbody></table>
<h3>Traffic Log OFF ({{ off|length }})</h3>
<table><thead><tr><th>Device</th><th>Policy</th></tr></thead><tbody>
{% for r in off %}<tr><td>{{ r.device or r.appliance_id }}</td><td>{{ r.policy }}</td></tr>
{% else %}<tr><td colspan="2">Everything is logging. 🎉</td></tr>{% endfor %}
</tbody></table>""",
        "css": _BASE + _BANNER,
        "js": "",
    },
    {
        "id": "policies_without_wpp",
        "group": "Server Policies", "subgroup": "Coverage & Audits",
        "category": "Server Policies",
        "title": "Policies without a WAF profile", "name": "Policies without a WAF profile",
        "icon": "bi-shield-exclamation",
        "description": "Security gap finder: server policies with NO Web Protection "
                       "Profile bound — i.e. serving traffic with no WAF in front.",
        "tags": ["audit", "waf", "gap", "security"],
        "datasets": ["server_policies_full"],
        "params": [],
        "jinja": """{% set bad = data.server_policies_full.rows|rejectattr('wpp')|list %}
<h2>Policies without a WAF profile</h2>
{% if bad %}
<div class="warn">{{ bad|length }} policy(ies) are serving traffic with no Web Protection Profile.</div>
<table><thead><tr><th>Device</th><th>Policy</th><th>Virtual server</th><th>Status</th></tr></thead><tbody>
{% for r in bad %}<tr><td>{{ r.device or r.appliance_id }}</td><td>{{ r.policy }}</td><td>{{ r.vserver or '—' }}</td><td>{{ r.status }}</td></tr>{% endfor %}
</tbody></table>
{% else %}<div class="ok">✅ Every cached policy has a WAF profile bound.</div>{% endif %}""",
        "css": _BASE + """.warn{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#fca5a5;border-radius:12px;padding:14px;margin-bottom:14px}
.ok{background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.3);color:#6ee7b7;border-radius:12px;padding:14px}""",
        "js": "",
    },
    {
        "id": "monitor_mode_policies",
        "group": "Server Policies", "subgroup": "Coverage & Audits",
        "category": "Server Policies",
        "title": "Detection-only (monitor mode) policies", "name": "Detection-only (monitor mode) policies",
        "icon": "bi-eye",
        "description": "Policies running the WAF in monitor/detection mode — they "
                       "alert but do not block. Useful before an enforcement push.",
        "tags": ["audit", "monitor-mode", "policies", "waf"],
        "datasets": ["server_policies_full"],
        "params": [],
        "jinja": """{% set m = data.server_policies_full.rows|selectattr('monitor_mode','equalto','enable')|list %}
<h2>Monitor-mode policies ({{ m|length }})</h2>
<p class="hint">These detect and log attacks but do NOT block them.</p>
<table><thead><tr><th>Device</th><th>Policy</th><th>WPP</th></tr></thead><tbody>
{% for r in m %}<tr><td>{{ r.device or r.appliance_id }}</td><td>{{ r.policy }}</td><td>{{ r.wpp or '—' }}</td></tr>
{% else %}<tr><td colspan="3">No policy is in monitor mode.</td></tr>{% endfor %}
</tbody></table>""",
        "css": _BASE,
        "js": "",
    },
    {
        "id": "disabled_policies",
        "group": "Server Policies", "subgroup": "Coverage & Audits",
        "category": "Server Policies",
        "title": "Disabled policies", "name": "Disabled policies",
        "icon": "bi-slash-circle",
        "description": "Every server policy whose status is disabled — dormant config "
                       "that may be stale or forgotten.",
        "tags": ["audit", "status", "disabled", "cleanup"],
        "datasets": ["server_policies_full"],
        "params": [],
        "jinja": """{% set off = data.server_policies_full.rows|selectattr('status','equalto','disable')|list %}
<h2>Disabled policies ({{ off|length }})</h2>
{% if off %}
<table><thead><tr><th>Device</th><th>Policy</th><th>Virtual server</th><th>WPP</th></tr></thead><tbody>
{% for r in off %}<tr><td>{{ r.device or r.appliance_id }}</td><td>{{ r.policy }}</td><td>{{ r.vserver or '—' }}</td><td>{{ r.wpp or '—' }}</td></tr>{% endfor %}
</tbody></table>
{% else %}<p class="hint">No disabled policies — everything cached is active.</p>{% endif %}""",
        "css": _BASE,
        "js": "",
    },
    {
        "id": "https_policies",
        "group": "Server Policies", "subgroup": "Coverage & Audits",
        "category": "Server Policies",
        "title": "HTTPS-terminating policies", "name": "HTTPS-terminating policies",
        "icon": "bi-lock",
        "description": "Policies that expose an HTTPS service — the TLS-terminating "
                       "front doors of the fleet.",
        "tags": ["audit", "https", "tls", "policies"],
        "datasets": ["server_policies_full"],
        "params": [],
        "jinja": """{% set https = data.server_policies_full.rows|selectattr('https_service')|list %}
<h2>HTTPS-terminating policies ({{ https|length }})</h2>
<table><thead><tr><th>Device</th><th>Policy</th><th>HTTPS service</th><th>Service</th></tr></thead><tbody>
{% for r in https %}<tr><td>{{ r.device or r.appliance_id }}</td><td>{{ r.policy }}</td><td>{{ r.https_service }}</td><td>{{ r.service or '—' }}</td></tr>
{% else %}<tr><td colspan="4">No policy exposes an HTTPS service.</td></tr>{% endfor %}
</tbody></table>""",
        "css": _BASE,
        "js": "",
    },
    {
        "id": "policies_per_device",
        "group": "Server Policies", "subgroup": "Grouping & Charts",
        "category": "Server Policies",
        "title": "Policies per device (bars)", "name": "Policies per device (bars)",
        "icon": "bi-bar-chart-line",
        "description": "How many server policies each device carries — a CSS bar "
                       "chart, sorted busiest-first. Spot the overloaded boxes.",
        "tags": ["chart", "bars", "policies", "per-device"],
        "datasets": ["server_policies_full"],
        "params": [],
        "jinja": """<h2>Server policies per device</h2>
<div id="chart"></div>""",
        "css": _BAR,
        "js": """var rows=(window.pluginData.server_policies_full||{}).rows||[];
var by={};rows.forEach(function(r){var k=r.device||r.appliance_id||'?';by[k]=(by[k]||0)+1;});
var arr=Object.keys(by).map(function(k){return[k,by[k]];}).sort(function(a,b){return b[1]-a[1];});
var el=document.getElementById('chart');
if(!arr.length){el.innerHTML='<p style="color:#94a3b8">No cached policies. Run a rediscovery.</p>';}
var max=Math.max(1,...arr.map(function(x){return x[1];}));
arr.forEach(function(x){var d=document.createElement('div');d.className='bar';
  d.innerHTML='<div class="lbl" title="'+x[0]+'">'+x[0]+'</div><div class="track"><div class="fill" style="width:'+Math.round(x[1]/max*100)+'%"></div></div><div class="val">'+x[1]+'</div>';
  el.appendChild(d);});""",
    },
    {
        "id": "policies_by_appid",
        "group": "Server Policies", "subgroup": "Grouping & Charts",
        "category": "Server Policies",
        "title": "Policies grouped by App ID", "name": "Policies grouped by App ID",
        "icon": "bi-diagram-3",
        "description": "Groups every server policy by the App ID parsed from its "
                       "comment (patterns like 'AppID: 123'). Each App ID becomes a "
                       "card listing the policies that share it, across all devices.",
        "tags": ["grouped", "app-id", "policies", "cross-device"],
        "datasets": ["server_policies_full"],
        "params": [],
        "jinja": """<h2>Policies by App ID</h2>
<p class="hint">App ID is read from each policy's comment. Set a comment like
<code>AppID: shop-01</code> on your policies to group them here.</p>
<div id="groups"></div>""",
        "css": """.hint{font-size:12px;color:#94a3b8;margin-bottom:14px}code{color:#93c5fd}
.grp{background:rgba(15,23,42,.6);border:1px solid rgba(148,163,184,.12);border-radius:14px;padding:16px;margin-bottom:12px}
.grp h3{margin:0 0 8px;font-size:15px;color:#c4b5fd}
.grp .cnt{font-size:11px;color:#94a3b8;font-weight:400}
.pill{display:inline-block;background:rgba(139,92,246,.14);color:#ddd6fe;border-radius:8px;padding:4px 10px;margin:3px;font-size:12px}
.none{background:rgba(148,163,184,.06);border-style:dashed}""",
        "js": """var rows=(window.pluginData.server_policies_full||{}).rows||[];
var groups={};
rows.forEach(function(r){var k=(r.appid&&r.appid.trim())?r.appid.trim():'(no App ID)';(groups[k]=groups[k]||[]).push(r);});
var el=document.getElementById('groups');
var keys=Object.keys(groups).sort(function(a,b){if(a.charAt(0)==='(')return 1;if(b.charAt(0)==='(')return -1;return a.localeCompare(b);});
if(!keys.length){el.innerHTML='<div class="grp none">No policies cached.</div>';}
keys.forEach(function(k){
  var g=groups[k];var d=document.createElement('div');d.className='grp'+(k.charAt(0)==='('?' none':'');
  var pills=g.map(function(r){return '<span class="pill">'+(r.device||r.appliance_id)+' · '+r.policy+'</span>';}).join('');
  d.innerHTML='<h3>'+k+' <span class="cnt">— '+g.length+' policy(ies)</span></h3>'+pills;
  el.appendChild(d);
});""",
    },
    {
        "id": "policies_by_mode",
        "group": "Server Policies", "subgroup": "Grouping & Charts",
        "category": "Server Policies",
        "title": "Policies by deployment mode (pivot)", "name": "Policies by deployment mode (pivot)",
        "icon": "bi-columns-gap",
        "description": "A pure-Jinja pivot counting policies per deployment mode "
                       "(server-pool, single-server, …) with an inline share bar.",
        "tags": ["pivot", "grouped", "deployment-mode", "jinja-only"],
        "datasets": ["server_policies_full"],
        "params": [],
        "jinja": """{% set rows = data.server_policies_full.rows %}
<h2>Policies by deployment mode</h2>
{% if rows %}
{% set total = rows|length %}
<table><thead><tr><th>Mode</th><th>Count</th><th>Share</th></tr></thead><tbody>
{% for mode, items in rows|groupby('deployment_mode') %}
<tr><td>{{ mode or 'unset' }}</td><td>{{ items|length }}</td>
<td><div class="mini"><div class="mini-fill" style="width:{{ (items|length / total * 100)|round|int }}%"></div></div>
{{ (items|length / total * 100)|round|int }}%</td></tr>
{% endfor %}
</tbody></table>
{% else %}<p class="hint">No cached policies.</p>{% endif %}""",
        "css": _BASE + """.mini{display:inline-block;width:120px;height:10px;background:rgba(148,163,184,.12);border-radius:5px;overflow:hidden;vertical-align:middle;margin-right:8px}
.mini-fill{height:100%;background:linear-gradient(90deg,#3b82f6,#8b5cf6)}""",
        "js": "",
    },
    {
        "id": "policy_status_donut",
        "group": "Server Policies", "subgroup": "Grouping & Charts",
        "category": "Server Policies",
        "title": "Policy status donut", "name": "Policy status donut",
        "icon": "bi-pie-chart-fill",
        "description": "A CSS donut splitting server policies into enabled vs "
                       "disabled, with counts in the legend.",
        "tags": ["chart", "donut", "status", "policies"],
        "datasets": ["server_policies_full"],
        "params": [],
        "jinja": """<h2>Policy status</h2>
<div class="donut-wrap"><div id="donut" class="donut"></div><div id="legend" class="legend"></div></div>""",
        "css": _DONUT,
        "js": """var rows=(window.pluginData.server_policies_full||{}).rows||[];
var counts={};rows.forEach(function(r){var k=(r.status==='enable')?'enabled':'disabled';counts[k]=(counts[k]||0)+1;});
var total=rows.length||1;var colors={enabled:'#10b981',disabled:'#ef4444'};
var seg=[],acc=0,legend='';
['enabled','disabled'].forEach(function(k){if(!counts[k])return;var pct=counts[k]/total*100;
  seg.push(colors[k]+' '+acc.toFixed(1)+'% '+(acc+pct).toFixed(1)+'%');acc+=pct;
  legend+='<div><i style="background:'+colors[k]+'"></i>'+k+' — '+counts[k]+'</div>';});
var d=document.getElementById('donut');
d.style.background=seg.length?'conic-gradient('+seg.join(',')+')':'rgba(148,163,184,.12)';
d.innerHTML='<div class="hole"><b>'+rows.length+'</b><span>policies</span></div>';
document.getElementById('legend').innerHTML=legend||'<div>No policies.</div>';""",
    },
    {
        "id": "policies_by_pool",
        "group": "Server Policies", "subgroup": "Grouping & Charts",
        "category": "Server Policies",
        "title": "Policies grouped by back-end pool", "name": "Policies grouped by back-end pool",
        "icon": "bi-diagram-2",
        "description": "Groups server policies by the back-end server pool they "
                       "target, so you can see which pools are fronted by which "
                       "policies.",
        "tags": ["grouped", "pools", "policies", "jinja-only"],
        "datasets": ["server_policies_full"],
        "params": [],
        "jinja": """{% set rows = data.server_policies_full.rows %}
<h2>Policies by back-end pool</h2>
{% if rows %}
{% for pool, items in rows|groupby('server_pool') %}
<div class="grp"><h3>{{ pool or '(no pool)' }} <span>— {{ items|length }}</span></h3>
<ul>{% for r in items %}<li>{{ r.device or r.appliance_id }} · {{ r.policy }}</li>{% endfor %}</ul></div>
{% endfor %}
{% else %}<p class="hint">No cached policies.</p>{% endif %}""",
        "css": _BASE + """.grp{background:rgba(15,23,42,.5);border:1px solid rgba(148,163,184,.1);border-radius:12px;padding:12px 16px;margin-bottom:10px}
.grp h3{margin:0 0 6px;color:#93c5fd}.grp h3 span{color:#64748b;font-weight:400;font-size:12px}
.grp ul{margin:0;padding-left:18px;color:#cbd5e1;font-size:13px}""",
        "js": "",
    },
    {
        "id": "policies_for_device",
        "group": "Server Policies", "subgroup": "Inputs",
        "category": "Server Policies",
        "title": "Policies for a device (input: device)", "name": "Policies for a device (input: device)",
        "icon": "bi-hdd-network",
        "description": "Pick a device from the selector and see only its server "
                       "policies; leave it on ‘All’ for the whole fleet. The textbook "
                       "device input filtering a dataset in the body.",
        "tags": ["input", "device", "filter", "policies"],
        "datasets": ["server_policies_full"],
        "params": [{"name": "device", "label": "Device", "type": "device",
                    "default": "", "required": False}],
        "jinja": """{% set rows = data.server_policies_full.rows %}
<h2>Server policies {% if params.device %}on device {{ params.device }}{% else %}(all devices){% endif %}</h2>
<table><thead><tr><th>Device</th><th>Policy</th><th>Mode</th><th>WPP</th><th>Status</th></tr></thead><tbody>
{% for r in rows if not params.device or (r.appliance_id|string == params.device) %}
<tr><td>{{ r.device or r.appliance_id }}</td><td>{{ r.policy }}</td><td>{{ r.deployment_mode or '—' }}</td><td>{{ r.wpp or '—' }}</td><td>{{ r.status or '—' }}</td></tr>
{% else %}<tr><td colspan="5">No policies for this selection.</td></tr>{% endfor %}
</tbody></table>""",
        "css": _BASE,
        "js": "",
    },
    {
        "id": "policies_by_status_input",
        "group": "Server Policies", "subgroup": "Inputs",
        "category": "Server Policies",
        "title": "Policies by status (input: select)", "name": "Policies by status (input: select)",
        "icon": "bi-toggle2-on",
        "description": "A fixed-option select input (Enabled / Disabled) that filters "
                       "the server policies. Author-defined options, no device needed.",
        "tags": ["input", "select", "status", "policies"],
        "datasets": ["server_policies_full"],
        "params": [{"name": "status", "label": "Status", "type": "select",
                    "options": [{"value": "enable", "label": "Enabled"},
                                {"value": "disable", "label": "Disabled"}],
                    "default": "", "required": False}],
        "jinja": """<h2>Server policies {% if params.status %}({{ params.status }}){% else %}(any status){% endif %}</h2>
<table><thead><tr><th>Device</th><th>Policy</th><th>WPP</th><th>Status</th></tr></thead><tbody>
{% for r in data.server_policies_full.rows if not params.status or r.status == params.status %}
<tr><td>{{ r.device or r.appliance_id }}</td><td>{{ r.policy }}</td><td>{{ r.wpp or '—' }}</td>
<td><span class="st {{ 'on' if r.status=='enable' else 'off' }}">{{ r.status or '—' }}</span></td></tr>
{% else %}<tr><td colspan="4">No policies match.</td></tr>{% endfor %}
</tbody></table>""",
        "css": _BASE + _STATUS,
        "js": "",
    },
    {
        "id": "policies_search_text",
        "group": "Server Policies", "subgroup": "Inputs",
        "category": "Server Policies",
        "title": "Search policies by name/comment (input: text)", "name": "Search policies by name/comment (input: text)",
        "icon": "bi-search",
        "description": "Type any substring; matches server policies whose name OR "
                       "comment contains it (case-insensitive). A free text input as "
                       "a contains filter in the body.",
        "tags": ["input", "text", "search", "policies"],
        "datasets": ["server_policies_full"],
        "params": [{"name": "q", "label": "Search", "type": "text",
                    "default": "", "required": False}],
        "jinja": """{% set q = (params.q or '')|lower %}
<h2>Policy search {% if q %}for “{{ params.q }}”{% else %}(all){% endif %}</h2>
<table><thead><tr><th>Device</th><th>Policy</th><th>Comment</th><th>Status</th></tr></thead><tbody>
{% for r in data.server_policies_full.rows if not q or (q in (r.policy or '')|lower) or (q in (r.comment or '')|lower) %}
<tr><td>{{ r.device or r.appliance_id }}</td><td>{{ r.policy }}</td><td>{{ r.comment or '—' }}</td><td>{{ r.status or '—' }}</td></tr>
{% else %}<tr><td colspan="4">No policies match “{{ params.q }}”.</td></tr>{% endfor %}
</tbody></table>""",
        "css": _BASE,
        "js": "",
    },

    # =========================================================================
    # GROUP: Server Pools
    # =========================================================================
    {
        "id": "server_pools_table",
        "group": "Server Pools", "subgroup": "",
        "category": "Server Pools",
        "title": "Server pools & protocols", "name": "Server pools & protocols",
        "icon": "bi-hdd-network",
        "description": "Every cached server pool with its type and protocol — "
                       "filterable by typing.",
        "tags": ["table", "pools", "searchable", "backend"],
        "datasets": ["server_pools"],
        "params": [],
        "jinja": """<h2>Server pools ({{ data.server_pools.rows|length }})</h2>
<input id="q" class="q" placeholder="Filter pools…">
<table id="t"><thead><tr><th>Device</th><th>Pool</th><th>Type</th><th>Protocol</th></tr></thead><tbody>
{% for r in data.server_pools.rows %}
<tr><td>{{ r.appliance_id }}</td><td>{{ r.name }}</td><td>{{ r.type or '—' }}</td><td>{{ r.protocol or '—' }}</td></tr>
{% else %}<tr><td colspan="4">No cached pools. Run a rediscovery.</td></tr>{% endfor %}
</tbody></table>""",
        "css": _BASE + """.q{width:100%;padding:8px 12px;margin-bottom:10px;background:rgba(15,23,42,.6);border:1px solid rgba(148,163,184,.15);border-radius:10px;color:#e2e8f0}""",
        "js": """var q=document.getElementById('q'),t=document.getElementById('t');
q.addEventListener('input',function(){var v=q.value.toLowerCase();
t.querySelectorAll('tbody tr').forEach(function(tr){tr.style.display=tr.textContent.toLowerCase().indexOf(v)>=0?'':'none';});});""",
    },
    {
        "id": "pools_by_type",
        "group": "Server Pools", "subgroup": "",
        "category": "Server Pools",
        "title": "Pools by type (pivot)", "name": "Pools by type (pivot)",
        "icon": "bi-collection",
        "description": "Counts server pools per type (reverse-proxy, true-transparent, "
                       "…) — a pure-Jinja pivot summary.",
        "tags": ["pivot", "pools", "type", "jinja-only"],
        "datasets": ["server_pools"],
        "params": [],
        "jinja": """{% set rows = data.server_pools.rows %}
<h2>Pools by type</h2>
{% if rows %}
<table><thead><tr><th>Type</th><th>Count</th><th>Pools</th></tr></thead><tbody>
{% for t, items in rows|groupby('type') %}
<tr><td>{{ t or 'unset' }}</td><td>{{ items|length }}</td><td>{{ items|map(attribute='name')|join(', ') }}</td></tr>
{% endfor %}
</tbody></table>
{% else %}<p class="hint">No cached pools.</p>{% endif %}""",
        "css": _BASE,
        "js": "",
    },
    {
        "id": "pools_protocol_donut",
        "group": "Server Pools", "subgroup": "",
        "category": "Server Pools",
        "title": "Pools by protocol (donut)", "name": "Pools by protocol (donut)",
        "icon": "bi-pie-chart",
        "description": "A CSS donut splitting server pools by protocol (HTTP / HTTPS "
                       "/ …). No chart library.",
        "tags": ["chart", "donut", "pools", "protocol"],
        "datasets": ["server_pools"],
        "params": [],
        "jinja": """<h2>Pools by protocol</h2>
<div class="donut-wrap"><div id="donut" class="donut"></div><div id="legend" class="legend"></div></div>""",
        "css": _DONUT,
        "js": """var rows=(window.pluginData.server_pools||{}).rows||[];
var counts={};rows.forEach(function(r){var k=r.protocol||'unknown';counts[k]=(counts[k]||0)+1;});
var total=rows.length||1;var palette=['#3b82f6','#10b981','#8b5cf6','#fbbf24','#ef4444','#06b6d4'];
var seg=[],acc=0,i=0,legend='';
Object.keys(counts).sort().forEach(function(k){var c=palette[i%palette.length];var pct=counts[k]/total*100;
  seg.push(c+' '+acc.toFixed(1)+'% '+(acc+pct).toFixed(1)+'%');acc+=pct;
  legend+='<div><i style="background:'+c+'"></i>'+k+' — '+counts[k]+'</div>';i++;});
var d=document.getElementById('donut');
d.style.background=seg.length?'conic-gradient('+seg.join(',')+')':'rgba(148,163,184,.12)';
d.innerHTML='<div class="hole"><b>'+rows.length+'</b><span>pools</span></div>';
document.getElementById('legend').innerHTML=legend||'<div>No pools.</div>';""",
    },
    {
        "id": "pools_per_device",
        "group": "Server Pools", "subgroup": "",
        "category": "Server Pools",
        "title": "Pools per device (bars)", "name": "Pools per device (bars)",
        "icon": "bi-bar-chart-line",
        "description": "A pure-Jinja bar chart of how many back-end pools each device "
                       "hosts. Widths computed in the template.",
        "tags": ["chart", "bars", "pools", "jinja-only"],
        "datasets": ["server_pools"],
        "params": [],
        "jinja": """{% set rows = data.server_pools.rows %}
<h2>Server pools per device</h2>
{% if rows %}
{% set groups = rows|groupby('appliance_id')|list %}
{% set maxc = groups|map('last')|map('length')|max %}
{% for dev, items in groups %}
<div class="bar"><div class="lbl">device {{ dev }}</div>
<div class="track"><div class="fill" style="width:{{ (items|length / maxc * 100)|round|int }}%"></div></div>
<div class="val">{{ items|length }}</div></div>
{% endfor %}
{% else %}<p class="hint">No cached pools.</p>{% endif %}""",
        "css": _BASE + _BAR + ".bar .lbl{width:110px}",
        "js": "",
    },

    # =========================================================================
    # GROUP: Web Protection
    # =========================================================================
    {
        "id": "wpp_coverage",
        "group": "Web Protection", "subgroup": "Coverage",
        "category": "Web Protection",
        "title": "WAF coverage — protected vs unprotected", "name": "WAF coverage — protected vs unprotected",
        "icon": "bi-shield-exclamation",
        "description": "Coverage banner: how many server policies bind a Web "
                       "Protection Profile vs none, with both lists below.",
        "tags": ["waf", "coverage", "banner", "audit"],
        "datasets": ["server_policies_full"],
        "params": [],
        "jinja": """{% set rows = data.server_policies_full.rows %}
{% set gaps = rows|rejectattr('wpp')|list %}
{% set ok = rows|selectattr('wpp')|list %}
<div class="banner {{ 'bad' if gaps else 'good' }}">
  <div class="big">{{ gaps|length }}</div>
  <div>server policies with <strong>no WAF profile</strong>
  <div class="sub">{{ ok|length }} of {{ rows|length }} are protected</div></div>
</div>
<h3>Unprotected</h3>
<table><thead><tr><th>Device</th><th>Policy</th><th>Virtual server</th><th>Status</th></tr></thead><tbody>
{% for r in gaps %}<tr><td>{{ r.device or r.appliance_id }}</td><td>{{ r.policy }}</td><td>{{ r.vserver or '—' }}</td><td>{{ r.status or '—' }}</td></tr>
{% else %}<tr><td colspan="4">Every cached policy has a WPP bound. 🎉</td></tr>{% endfor %}
</tbody></table>
<h3>Protected ({{ ok|length }})</h3>
<table><thead><tr><th>Device</th><th>Policy</th><th>WPP</th></tr></thead><tbody>
{% for r in ok %}<tr><td>{{ r.device or r.appliance_id }}</td><td>{{ r.policy }}</td><td>{{ r.wpp }}</td></tr>
{% else %}<tr><td colspan="3">None protected yet.</td></tr>{% endfor %}
</tbody></table>""",
        "css": _BASE + _BANNER,
        "js": "",
    },
    {
        "id": "wpp_inventory",
        "group": "Web Protection", "subgroup": "Profiles",
        "category": "Web Protection",
        "title": "WAF profile inventory", "name": "WAF profile inventory",
        "icon": "bi-shield-shaded",
        "description": "Every cached Web Protection Profile with its kind and its "
                       "signature / bot-policy references. Empty until profiles cache.",
        "tags": ["waf", "profiles", "table", "empty-safe"],
        "datasets": ["web_protection_profiles"],
        "params": [],
        "jinja": """<h2>Web Protection Profiles ({{ data.web_protection_profiles.rows|length }})</h2>
<table><thead><tr><th>Device</th><th>Profile</th><th>Kind</th><th>Signature rule</th><th>Bot policy</th></tr></thead><tbody>
{% for r in data.web_protection_profiles.rows %}
<tr><td>{{ r.appliance_id }}</td><td>{{ r.name }}</td><td>{{ r.kind or '—' }}</td>
<td>{{ r.signature_rule or '—' }}</td><td>{{ r.bot_policy or '—' }}</td></tr>
{% else %}<tr><td colspan="5">No WAF profiles cached yet.</td></tr>{% endfor %}
</tbody></table>""",
        "css": _BASE,
        "js": "",
    },
    {
        "id": "wpp_by_kind",
        "group": "Web Protection", "subgroup": "Profiles",
        "category": "Web Protection",
        "title": "WAF profiles by kind", "name": "WAF profiles by kind",
        "icon": "bi-diagram-3",
        "description": "Counts WAF profiles per kind (inline vs offline) — a small "
                       "pivot that stays graceful when no profiles are cached.",
        "tags": ["waf", "profiles", "pivot", "empty-safe"],
        "datasets": ["web_protection_profiles"],
        "params": [],
        "jinja": """{% set rows = data.web_protection_profiles.rows %}
<h2>WAF profiles by kind</h2>
{% if rows %}
<table><thead><tr><th>Kind</th><th>Count</th><th>Profiles</th></tr></thead><tbody>
{% for kind, items in rows|groupby('kind') %}
<tr><td>{{ kind or 'unset' }}</td><td>{{ items|length }}</td><td>{{ items|map(attribute='name')|join(', ') }}</td></tr>
{% endfor %}
</tbody></table>
{% else %}<p class="hint">No WAF profiles cached — nothing to summarise yet.</p>{% endif %}""",
        "css": _BASE,
        "js": "",
    },
    {
        "id": "wpp_signature_refs",
        "group": "Web Protection", "subgroup": "Profiles",
        "category": "Web Protection",
        "title": "WAF signature & bot references", "name": "WAF signature & bot references",
        "icon": "bi-fingerprint",
        "description": "Which signature rule set and bot-mitigation policy each WAF "
                       "profile references — the security building blocks behind a "
                       "profile.",
        "tags": ["waf", "signatures", "bot", "references"],
        "datasets": ["web_protection_profiles"],
        "params": [],
        "jinja": """{% set rows = data.web_protection_profiles.rows %}
<h2>Signature & bot references</h2>
<div class="grid">
{% for r in rows %}
  <div class="card">
    <b>{{ r.name }}</b><span class="k">{{ r.kind or '—' }}</span>
    <div class="kv"><span>signature</span>{{ r.signature_rule or '—' }}</div>
    <div class="kv"><span>bot policy</span>{{ r.bot_policy or '—' }}</div>
  </div>
{% else %}<div class="card empty">No WAF profiles cached.</div>{% endfor %}
</div>""",
        "css": _CARD + """.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}
.card b{color:#e2e8f0}.card .k{float:right;font-size:10px;text-transform:uppercase;color:#94a3b8}
.kv{display:flex;justify-content:space-between;font-size:12px;color:#cbd5e1;padding:3px 0;margin-top:4px}
.kv span{color:#64748b}.card.empty{color:#94a3b8;text-align:center}""",
        "js": "",
    },
    {
        "id": "wpp_usage_crossref",
        "group": "Web Protection", "subgroup": "Coverage",
        "category": "Web Protection",
        "title": "WAF profile usage (cross-reference)", "name": "WAF profile usage (cross-reference)",
        "icon": "bi-link-45deg",
        "description": "Cross-references cached WAF profiles against the policies that "
                       "bind them — spotlighting unused profiles and the WPP names "
                       "referenced by policies but not cached.",
        "tags": ["waf", "cross-reference", "usage", "two-datasets"],
        "datasets": ["web_protection_profiles", "server_policies_full"],
        "params": [],
        "jinja": """{% set profs = data.web_protection_profiles.rows %}
{% set pols = data.server_policies_full.rows %}
{% set used = pols|map(attribute='wpp')|select|list %}
<h2>WAF profile usage</h2>
<p class="hint">{{ profs|length }} profile(s) cached · {{ used|length }} policy binding(s).</p>
<h3>Cached profiles</h3>
<table><thead><tr><th>Profile</th><th>Kind</th><th>Bound by (policies)</th></tr></thead><tbody>
{% for p in profs %}
{% set binders = pols|selectattr('wpp','equalto',p.name)|list %}
<tr><td>{{ p.name }}</td><td>{{ p.kind or '—' }}</td>
<td>{% if binders %}{{ binders|map(attribute='policy')|join(', ') }}{% else %}<em class="unused">unused</em>{% endif %}</td></tr>
{% else %}<tr><td colspan="3">No WAF profiles cached.</td></tr>{% endfor %}
</tbody></table>
<h3>WPP names referenced by policies</h3>
<ul class="refs">
{% for name, items in pols|selectattr('wpp')|groupby('wpp') %}
<li><code>{{ name }}</code> — {{ items|length }} policy(ies)</li>
{% else %}<li class="hint">No policy binds a WAF profile.</li>{% endfor %}
</ul>""",
        "css": _BASE + """.unused{color:#fca5a5}code{color:#93c5fd}
.refs{margin:0;padding-left:18px;color:#cbd5e1;font-size:13px}""",
        "js": "",
    },
    {
        "id": "wpp_coverage_device",
        "group": "Web Protection", "subgroup": "Coverage",
        "category": "Web Protection",
        "title": "WAF coverage for a device (input: device)", "name": "WAF coverage for a device (input: device)",
        "icon": "bi-shield-check",
        "description": "Pick a device and see its WAF coverage: how many of its "
                       "policies bind a Web Protection Profile vs none.",
        "tags": ["waf", "coverage", "input", "device"],
        "datasets": ["server_policies_full"],
        "params": [{"name": "device", "label": "Device", "type": "device",
                    "default": "", "required": False}],
        "jinja": """{% set rows = data.server_policies_full.rows|list %}
{% set rows = rows if not params.device else rows|selectattr('appliance_id','equalto', params.device|string)|list %}
{% set gaps = rows|rejectattr('wpp')|list %}
{% set ok = rows|selectattr('wpp')|list %}
<div class="banner {{ 'bad' if gaps else 'good' }}">
  <div class="big">{{ gaps|length }}</div>
  <div>policies with <strong>no WAF profile</strong>
  <div class="sub">{{ ok|length }} of {{ rows|length }} protected {% if params.device %}on device {{ params.device }}{% else %}(all devices){% endif %}</div></div>
</div>
<table><thead><tr><th>Device</th><th>Policy</th><th>WPP</th><th>Status</th></tr></thead><tbody>
{% for r in rows %}
<tr><td>{{ r.device or r.appliance_id }}</td><td>{{ r.policy }}</td><td>{{ r.wpp or '⚠️ none' }}</td><td>{{ r.status or '—' }}</td></tr>
{% else %}<tr><td colspan="4">No policies for this selection.</td></tr>{% endfor %}
</tbody></table>""",
        "css": _BASE + _BANNER,
        "js": "",
    },

    # =========================================================================
    # GROUP: Certificates
    # =========================================================================
    {
        "id": "cert_expiry_board",
        "group": "Certificates", "subgroup": "Expiry",
        "category": "Certificates",
        "title": "Certificate expiry board", "name": "Certificate expiry board",
        "icon": "bi-shield-lock",
        "description": "Managed certificates sorted by expiry, each with a colored "
                       "days-remaining badge (red < 30d, amber < 90d, green beyond).",
        "tags": ["certificates", "expiry", "badges", "empty-safe"],
        "datasets": ["certificates"],
        "params": [],
        "jinja": """<h2>Certificate expiry ({{ data.certificates.rows|length }})</h2>
<table><thead><tr><th>Common name</th><th>Device</th><th>Status</th><th>Not after</th><th>Days left</th></tr></thead>
<tbody id="tb">
{% for r in data.certificates.rows %}
<tr data-exp="{{ r.not_after }}"><td>{{ r.common_name or '—' }}</td><td>{{ r.appliance_id or '—' }}</td>
<td>{{ r.status or '—' }}</td><td>{{ r.not_after or '—' }}</td><td class="days">—</td></tr>
{% else %}<tr><td colspan="5">No managed certificates.</td></tr>{% endfor %}
</tbody></table>""",
        "css": _BASE + """.pill{border-radius:6px;padding:2px 8px;font-size:11px;font-weight:600}
.pill.r{background:rgba(239,68,68,.15);color:#fca5a5}.pill.a{background:rgba(251,191,36,.15);color:#fcd34d}.pill.g{background:rgba(16,185,129,.15);color:#6ee7b7}""",
        "js": """var now=Date.now();
document.querySelectorAll('#tb tr[data-exp]').forEach(function(tr){
  var raw=tr.getAttribute('data-exp');var t=Date.parse(raw);var cell=tr.querySelector('.days');
  if(isNaN(t)){cell.textContent='—';return;}
  var d=Math.round((t-now)/86400000);var cls=d<30?'r':(d<90?'a':'g');
  cell.innerHTML='<span class="pill '+cls+'">'+d+'d</span>';});""",
    },
    {
        "id": "certs_within_days",
        "group": "Certificates", "subgroup": "Expiry",
        "category": "Certificates",
        "title": "Certificates expiring within N days (input: number)", "name": "Certificates expiring within N days (input: number)",
        "icon": "bi-calendar-range",
        "description": "Type a number of days; the list keeps only certificates "
                       "expiring within that window. A number input read from JS.",
        "tags": ["certificates", "expiry", "input", "number"],
        "datasets": ["certificates"],
        "params": [{"name": "days", "label": "Within days", "type": "number",
                    "default": "90", "required": False}],
        "jinja": """<h2>Certificates expiring within <span id="win">…</span> days</h2>
<table><thead><tr><th>Common name</th><th>Device</th><th>Expires</th><th>Days left</th></tr></thead>
<tbody id="tb">
{% for r in data.certificates.rows %}
<tr data-exp="{{ r.not_after }}"><td>{{ r.common_name or '—' }}</td><td>{{ r.appliance_id or '—' }}</td><td>{{ r.not_after or '—' }}</td><td class="days">—</td></tr>
{% else %}<tr><td colspan="4">No managed certificates.</td></tr>{% endfor %}
</tbody></table>""",
        "css": _BASE + """.pill{border-radius:6px;padding:2px 8px;font-size:11px;font-weight:600}
.pill.r{background:rgba(239,68,68,.15);color:#fca5a5}.pill.a{background:rgba(251,191,36,.15);color:#fcd34d}""",
        "js": """var win=parseInt((window.pluginParams||{}).days,10); if(isNaN(win)) win=3650;
document.getElementById('win').textContent=win;
var now=Date.now();
document.querySelectorAll('#tb tr[data-exp]').forEach(function(tr){
  var t=Date.parse(tr.getAttribute('data-exp'));var cell=tr.querySelector('.days');
  if(isNaN(t)){tr.style.display='none';return;}
  var d=Math.round((t-now)/86400000);
  if(d>win){tr.style.display='none';return;}
  cell.innerHTML='<span class="pill '+(d<30?'r':'a')+'">'+d+'d</span>';
});""",
    },
    {
        "id": "certs_expired",
        "group": "Certificates", "subgroup": "Expiry",
        "category": "Certificates",
        "title": "Already-expired certificates", "name": "Already-expired certificates",
        "icon": "bi-calendar-x",
        "description": "Isolates certificates whose not-after date is already in the "
                       "past — the ones actively breaking TLS right now.",
        "tags": ["certificates", "expired", "alert", "empty-safe"],
        "datasets": ["certificates"],
        "params": [],
        "jinja": """<h2>Expired certificates</h2>
<div id="summary" class="warn">Checking…</div>
<table><thead><tr><th>Common name</th><th>Device</th><th>Status</th><th>Expired on</th></tr></thead>
<tbody id="tb">
{% for r in data.certificates.rows %}
<tr data-exp="{{ r.not_after }}"><td>{{ r.common_name or '—' }}</td><td>{{ r.appliance_id or '—' }}</td><td>{{ r.status or '—' }}</td><td>{{ r.not_after or '—' }}</td></tr>
{% else %}<tr class="keep"><td colspan="4">No managed certificates.</td></tr>{% endfor %}
</tbody></table>""",
        "css": _BASE + """.warn{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#fca5a5;border-radius:12px;padding:12px;margin-bottom:14px}
.ok{background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.3);color:#6ee7b7}""",
        "js": """var now=Date.now();var expired=0;
document.querySelectorAll('#tb tr[data-exp]').forEach(function(tr){
  var t=Date.parse(tr.getAttribute('data-exp'));
  if(isNaN(t)||t>=now){tr.style.display='none';return;}expired++;});
var s=document.getElementById('summary');
if(expired){s.textContent=expired+' certificate(s) have already expired.';}
else{s.className='warn ok';s.textContent='✅ No expired certificates.';}""",
    },
    {
        "id": "cert_status_donut",
        "group": "Certificates", "subgroup": "Breakdown",
        "category": "Certificates",
        "title": "Certificates by status (donut)", "name": "Certificates by status (donut)",
        "icon": "bi-pie-chart",
        "description": "A CSS donut of managed certificates grouped by their status "
                       "field. Renders an empty ring when nothing is tracked.",
        "tags": ["certificates", "donut", "status", "empty-safe"],
        "datasets": ["certificates"],
        "params": [],
        "jinja": """<h2>Certificates by status</h2>
<div class="donut-wrap"><div id="donut" class="donut"></div><div id="legend" class="legend"></div></div>""",
        "css": _DONUT,
        "js": """var rows=(window.pluginData.certificates||{}).rows||[];
var counts={};rows.forEach(function(r){var k=r.status||'unknown';counts[k]=(counts[k]||0)+1;});
var total=rows.length||1;var palette=['#10b981','#fbbf24','#ef4444','#3b82f6','#8b5cf6'];
var seg=[],acc=0,i=0,legend='';
Object.keys(counts).sort().forEach(function(k){var c=palette[i%palette.length];var pct=counts[k]/total*100;
  seg.push(c+' '+acc.toFixed(1)+'% '+(acc+pct).toFixed(1)+'%');acc+=pct;
  legend+='<div><i style="background:'+c+'"></i>'+k+' — '+counts[k]+'</div>';i++;});
var d=document.getElementById('donut');
d.style.background=seg.length?'conic-gradient('+seg.join(',')+')':'rgba(148,163,184,.12)';
d.innerHTML='<div class="hole"><b>'+rows.length+'</b><span>certs</span></div>';
document.getElementById('legend').innerHTML=legend||'<div>No certificates.</div>';""",
    },
    {
        "id": "certs_per_device",
        "group": "Certificates", "subgroup": "Breakdown",
        "category": "Certificates",
        "title": "Certificates per device", "name": "Certificates per device",
        "icon": "bi-hdd",
        "description": "Counts managed certificates per appliance so you can see "
                       "which boxes carry the most TLS material.",
        "tags": ["certificates", "grouped", "per-device", "jinja-only"],
        "datasets": ["certificates"],
        "params": [],
        "jinja": """{% set rows = data.certificates.rows %}
<h2>Certificates per device</h2>
{% if rows %}
<table><thead><tr><th>Device</th><th>Certificates</th><th>Common names</th></tr></thead><tbody>
{% for dev, items in rows|groupby('appliance_id') %}
<tr><td>{{ dev or '—' }}</td><td>{{ items|length }}</td><td>{{ items|map(attribute='common_name')|join(', ') }}</td></tr>
{% endfor %}
</tbody></table>
{% else %}<p class="hint">No managed certificates.</p>{% endif %}""",
        "css": _BASE,
        "js": "",
    },
    {
        "id": "cert_timeline",
        "group": "Certificates", "subgroup": "Breakdown",
        "category": "Certificates",
        "title": "Certificate expiry timeline", "name": "Certificate expiry timeline",
        "icon": "bi-calendar3",
        "description": "A vertical timeline of certificates ordered by expiry date "
                       "(the dataset already sorts by not_after) — a chronological "
                       "read of what lapses next.",
        "tags": ["certificates", "timeline", "expiry", "empty-safe"],
        "datasets": ["certificates"],
        "params": [],
        "jinja": """<h2>Expiry timeline</h2>
<ul class="tl">
{% for r in data.certificates.rows %}
<li><span class="dot"></span><div><div class="cn">{{ r.common_name or '(no CN)' }}</div>
<div class="d">{{ r.not_after or 'no date' }} · device {{ r.appliance_id or '—' }} · {{ r.status or '—' }}</div></div></li>
{% else %}<li class="none">No managed certificates.</li>{% endfor %}
</ul>""",
        "css": """.tl{list-style:none;margin:0;padding:0}
.tl li{display:flex;gap:12px;padding:0 0 14px 4px;position:relative;border-left:2px solid rgba(148,163,184,.15);margin-left:6px}
.tl .dot{width:10px;height:10px;border-radius:50%;background:#3b82f6;margin:2px 0 0 -11px;flex:none}
.tl .cn{color:#e2e8f0;font-size:13px;font-weight:600}
.tl .d{color:#94a3b8;font-size:12px}
.tl .none{border:0;color:#94a3b8}""",
        "js": "",
    },

    # =========================================================================
    # GROUP: Audit & Activity
    # =========================================================================
    {
        "id": "audit_feed",
        "group": "Audit & Activity", "subgroup": "Timeline",
        "category": "Audit & Activity",
        "title": "Recent activity feed", "name": "Recent activity feed",
        "icon": "bi-activity",
        "description": "The 200 most recent audit-log entries as a compact feed — who "
                       "did what, where, and when.",
        "tags": ["audit", "feed", "timeline", "activity"],
        "datasets": ["audit_recent"],
        "params": [],
        "jinja": """<h2>Recent activity</h2>
<div class="feed">
{% for r in data.audit_recent.rows %}
<div class="ev"><div class="ic"><i class="dot"></i></div>
  <div><div class="a"><strong>{{ r.username or 'system' }}</strong> · {{ r.action }}</div>
  <div class="m">{{ r.target or '' }} <span class="p">{{ r.product or '' }}</span></div></div>
  <div class="t">{{ r.timestamp }}</div></div>
{% else %}<div class="ev">No audit activity yet.</div>{% endfor %}
</div>""",
        "css": """.feed{display:flex;flex-direction:column}
.ev{display:flex;gap:12px;align-items:flex-start;padding:8px 0;border-bottom:1px solid rgba(148,163,184,.1)}
.ic .dot{width:9px;height:9px;border-radius:50%;background:#3b82f6;display:inline-block;margin-top:5px}
.ev .a{font-size:13px;color:#e2e8f0}.ev .m{font-size:12px;color:#94a3b8}
.ev .p{background:rgba(59,130,246,.15);color:#93c5fd;border-radius:4px;padding:0 6px;font-size:10px}
.ev .t{margin-left:auto;font-size:11px;color:#64748b;white-space:nowrap}""",
        "js": "",
    },
    {
        "id": "audit_by_user",
        "group": "Audit & Activity", "subgroup": "Leaderboards",
        "category": "Audit & Activity",
        "title": "Actions by user (leaderboard)", "name": "Actions by user (leaderboard)",
        "icon": "bi-people",
        "description": "Aggregates the recent audit log into a per-user action count "
                       "leaderboard with bars.",
        "tags": ["audit", "leaderboard", "bars", "users"],
        "datasets": ["audit_recent"],
        "params": [],
        "jinja": """<h2>Actions by user (recent)</h2><div id="board"></div>""",
        "css": """.row{display:flex;align-items:center;gap:10px;margin:6px 0}
.row .u{width:130px;font-size:13px;color:#cbd5e1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row .tr{flex:1;background:rgba(148,163,184,.1);border-radius:8px;height:20px;overflow:hidden}
.row .fl{height:100%;background:linear-gradient(90deg,#3b82f6,#8b5cf6)}
.row .n{width:34px;text-align:right;font-size:13px;color:#e2e8f0}""",
        "js": """var rows=(window.pluginData.audit_recent||{}).rows||[];
var c={};rows.forEach(function(r){var u=r.username||'system';c[u]=(c[u]||0)+1;});
var pairs=Object.keys(c).map(function(k){return [k,c[k]];}).sort(function(a,b){return b[1]-a[1];});
var max=pairs.length?pairs[0][1]:1;var el=document.getElementById('board');
if(!pairs.length){el.textContent='No recent activity.';}
pairs.forEach(function(p){var d=document.createElement('div');d.className='row';
d.innerHTML='<div class="u">'+p[0]+'</div><div class="tr"><div class="fl" style="width:'+Math.round(p[1]/max*100)+'%"></div></div><div class="n">'+p[1]+'</div>';
el.appendChild(d);});""",
    },
    {
        "id": "audit_by_action",
        "group": "Audit & Activity", "subgroup": "Breakdown",
        "category": "Audit & Activity",
        "title": "Actions by type (pivot)", "name": "Actions by type (pivot)",
        "icon": "bi-list-check",
        "description": "A pure-Jinja pivot counting audit entries per action type, "
                       "with an inline share bar — the shape of recent activity.",
        "tags": ["audit", "pivot", "actions", "jinja-only"],
        "datasets": ["audit_recent"],
        "params": [],
        "jinja": """{% set rows = data.audit_recent.rows %}
<h2>Recent activity by action</h2>
{% if rows %}
{% set total = rows|length %}
<table><thead><tr><th>Action</th><th>Count</th><th>Share</th></tr></thead><tbody>
{% for act, items in rows|groupby('action') %}
<tr><td><code>{{ act or '(none)' }}</code></td><td>{{ items|length }}</td>
<td><div class="mini"><div class="mini-fill" style="width:{{ (items|length / total * 100)|round|int }}%"></div></div></td></tr>
{% endfor %}
</tbody></table>
{% else %}<p class="hint">No audit activity.</p>{% endif %}""",
        "css": _BASE + """code{color:#93c5fd;font-size:12px}
.mini{width:100%;height:10px;background:rgba(148,163,184,.12);border-radius:5px;overflow:hidden}
.mini-fill{height:100%;background:linear-gradient(90deg,#3b82f6,#8b5cf6)}""",
        "js": "",
    },
    {
        "id": "audit_by_product_donut",
        "group": "Audit & Activity", "subgroup": "Breakdown",
        "category": "Audit & Activity",
        "title": "Activity by product (donut)", "name": "Activity by product (donut)",
        "icon": "bi-pie-chart",
        "description": "A CSS donut splitting recent audit activity by the product "
                       "each action touched.",
        "tags": ["audit", "donut", "product", "chart"],
        "datasets": ["audit_recent"],
        "params": [],
        "jinja": """<h2>Activity by product</h2>
<div class="donut-wrap"><div id="donut" class="donut"></div><div id="legend" class="legend"></div></div>""",
        "css": _DONUT,
        "js": """var rows=(window.pluginData.audit_recent||{}).rows||[];
var counts={};rows.forEach(function(r){var k=(r.product&&r.product.trim())?r.product:'(none)';counts[k]=(counts[k]||0)+1;});
var total=rows.length||1;var palette=['#3b82f6','#10b981','#8b5cf6','#fbbf24','#ef4444','#06b6d4','#f472b6'];
var seg=[],acc=0,i=0,legend='';
Object.keys(counts).sort().forEach(function(k){var c=palette[i%palette.length];var pct=counts[k]/total*100;
  seg.push(c+' '+acc.toFixed(1)+'% '+(acc+pct).toFixed(1)+'%');acc+=pct;
  legend+='<div><i style="background:'+c+'"></i>'+k+' — '+counts[k]+'</div>';i++;});
var d=document.getElementById('donut');
d.style.background=seg.length?'conic-gradient('+seg.join(',')+')':'rgba(148,163,184,.12)';
d.innerHTML='<div class="hole"><b>'+rows.length+'</b><span>events</span></div>';
document.getElementById('legend').innerHTML=legend||'<div>No activity.</div>';""",
    },
    {
        "id": "audit_top_targets",
        "group": "Audit & Activity", "subgroup": "Breakdown",
        "category": "Audit & Activity",
        "title": "Most-touched targets", "name": "Most-touched targets",
        "icon": "bi-bullseye",
        "description": "The audit targets that appear most often in recent activity — "
                       "the top ten objects people are changing, ranked with bars.",
        "tags": ["audit", "targets", "top-n", "ranking"],
        "datasets": ["audit_recent"],
        "params": [],
        "jinja": """<h2>Most-touched targets</h2>
<div id="top"></div>""",
        "css": _BASE + _BAR + ".bar .lbl{width:200px}.empty{color:#94a3b8}",
        "js": """var rows=(window.pluginData.audit_recent||{}).rows||[];
var c={};rows.forEach(function(r){var t=(r.target&&r.target.trim())?r.target:'(none)';c[t]=(c[t]||0)+1;});
var pairs=Object.keys(c).map(function(k){return [k,c[k]];}).sort(function(a,b){return b[1]-a[1];}).slice(0,10);
var el=document.getElementById('top');
if(!pairs.length){el.innerHTML='<div class="empty">No audit activity.</div>';}
var max=pairs.length?pairs[0][1]:1;
pairs.forEach(function(p){var d=document.createElement('div');d.className='bar';
  d.innerHTML='<div class="lbl" title="'+p[0]+'">'+p[0]+'</div><div class="track"><div class="fill" style="width:'+Math.round(p[1]/max*100)+'%"></div></div><div class="val">'+p[1]+'</div>';
  el.appendChild(d);});""",
    },
    {
        "id": "audit_by_hour",
        "group": "Audit & Activity", "subgroup": "Charts",
        "category": "Audit & Activity",
        "title": "Activity by hour (histogram)", "name": "Activity by hour (histogram)",
        "icon": "bi-clock",
        "description": "A 24-column histogram of when recent activity happened, "
                       "bucketed by hour-of-day from the timestamp. Pure JS.",
        "tags": ["audit", "histogram", "hours", "chart"],
        "datasets": ["audit_recent"],
        "params": [],
        "jinja": """<h2>Activity by hour of day</h2>
<div id="hist" class="hist"></div>""",
        "css": """.hist{display:flex;align-items:flex-end;gap:3px;height:140px;padding-top:10px}
.hist .col{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;height:100%}
.hist .b{width:100%;background:linear-gradient(180deg,#8b5cf6,#3b82f6);border-radius:3px 3px 0 0;min-height:2px}
.hist .h{font-size:9px;color:#64748b;margin-top:3px}
.empty{color:#94a3b8}""",
        "js": """var rows=(window.pluginData.audit_recent||{}).rows||[];
var buckets=new Array(24).fill(0);
rows.forEach(function(r){var m=/\\b(\\d{2}):\\d{2}:\\d{2}/.exec(r.timestamp||'');if(m){buckets[parseInt(m[1],10)]++;}});
var max=Math.max(1,...buckets);var el=document.getElementById('hist');
if(!rows.length){el.className='empty';el.textContent='No activity.';}
else{buckets.forEach(function(n,h){var c=document.createElement('div');c.className='col';
  c.innerHTML='<div class="b" style="height:'+Math.round(n/max*100)+'%" title="'+n+' at '+h+':00"></div><div class="h">'+h+'</div>';
  el.appendChild(c);});}""",
    },
    {
        "id": "audit_for_user",
        "group": "Audit & Activity", "subgroup": "Inputs",
        "category": "Audit & Activity",
        "title": "Audit activity for a user (input: text)", "name": "Audit activity for a user (input: text)",
        "icon": "bi-person-lines-fill",
        "description": "Type a username (or part of one) to filter the recent audit "
                       "log to that person — a text input used as a contains filter.",
        "tags": ["audit", "input", "text", "filter"],
        "datasets": ["audit_recent"],
        "params": [{"name": "user", "label": "Username contains", "type": "text",
                    "default": "", "required": False}],
        "jinja": """{% set q = (params.user or '')|lower %}
<h2>Audit activity {% if q %}for “{{ params.user }}”{% else %}(everyone){% endif %}</h2>
<ul class="feed">
{% for r in data.audit_recent.rows if not q or (r.username and q in (r.username|lower)) %}
<li><span class="who">{{ r.username }}</span> <span class="act">{{ r.action }}</span> <span class="tgt">{{ r.target or '' }}</span><span class="ts">{{ r.timestamp }}</span></li>
{% else %}<li>No matching activity.</li>{% endfor %}
</ul>""",
        "css": """.feed{list-style:none;padding:0;margin:0}
.feed li{padding:8px 0;border-bottom:1px solid rgba(148,163,184,.08);font-size:13px}
.who{color:#93c5fd}.act{color:#c4b5fd;margin:0 6px}.tgt{color:#cbd5e1}.ts{float:right;color:#64748b;font-size:11px}""",
        "js": "",
    },
    {
        "id": "audit_action_input",
        "group": "Audit & Activity", "subgroup": "Inputs",
        "category": "Audit & Activity",
        "title": "Audit filtered by action (input: text)", "name": "Audit filtered by action (input: text)",
        "icon": "bi-funnel",
        "description": "Type part of an action key (e.g. ‘login’, ‘delete’) to keep "
                       "only matching audit rows, with a live match count.",
        "tags": ["audit", "input", "text", "action"],
        "datasets": ["audit_recent"],
        "params": [{"name": "action", "label": "Action contains", "type": "text",
                    "default": "", "required": False}],
        "jinja": """{% set q = (params.action or '')|lower %}
<h2>Audit rows {% if q %}matching “{{ params.action }}”{% else %}(all actions){% endif %}</h2>
<table><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Target</th></tr></thead><tbody>
{% for r in data.audit_recent.rows if not q or (r.action and q in (r.action|lower)) %}
<tr><td>{{ r.timestamp }}</td><td>{{ r.username or 'system' }}</td><td><code>{{ r.action }}</code></td><td>{{ r.target or '—' }}</td></tr>
{% else %}<tr><td colspan="4">No rows match “{{ params.action }}”.</td></tr>{% endfor %}
</tbody></table>""",
        "css": _BASE + "code{color:#c4b5fd;font-size:12px}",
        "js": "",
    },

    # =========================================================================
    # GROUP: Automation
    # =========================================================================
    {
        "id": "scheduled_actions_table",
        "group": "Automation", "subgroup": "",
        "category": "Automation",
        "title": "Scheduled actions overview", "name": "Scheduled actions overview",
        "icon": "bi-clock-history",
        "description": "Every configured automation with its schedule kind, enabled "
                       "state and next run time. Empty until you schedule something.",
        "tags": ["automation", "schedule", "table", "empty-safe"],
        "datasets": ["scheduled_actions"],
        "params": [],
        "jinja": """<h2>Scheduled actions ({{ data.scheduled_actions.rows|length }})</h2>
<table><thead><tr><th>Name</th><th>Action</th><th>Schedule</th><th>Enabled</th><th>Next run</th></tr></thead><tbody>
{% for r in data.scheduled_actions.rows %}
<tr><td>{{ r.name }}</td><td>{{ r.action_key }}</td><td>{{ r.schedule_kind }}</td>
<td>{{ '✅' if r.enabled in (1,'1','true','True',true) else '⏸️' }}</td><td>{{ r.next_run or '—' }}</td></tr>
{% else %}<tr><td colspan="5">No scheduled actions.</td></tr>{% endfor %}
</tbody></table>""",
        "css": _BASE,
        "js": "",
    },
    {
        "id": "scheduled_enabled_split",
        "group": "Automation", "subgroup": "",
        "category": "Automation",
        "title": "Enabled vs paused (donut)", "name": "Enabled vs paused (donut)",
        "icon": "bi-toggles",
        "description": "A CSS donut splitting scheduled actions into enabled vs "
                       "paused, so you can see how much automation is actually live.",
        "tags": ["automation", "donut", "enabled", "empty-safe"],
        "datasets": ["scheduled_actions"],
        "params": [],
        "jinja": """<h2>Automation on/off</h2>
<div class="donut-wrap"><div id="donut" class="donut"></div><div id="legend" class="legend"></div></div>""",
        "css": _DONUT,
        "js": """var rows=(window.pluginData.scheduled_actions||{}).rows||[];
var on=0,off=0;rows.forEach(function(r){var e=r.enabled;
  if(e===1||e==='1'||e==='true'||e==='True'||e===true){on++;}else{off++;}});
var total=rows.length||1;var seg=[],acc=0,legend='';
[['enabled',on,'#10b981'],['paused',off,'#94a3b8']].forEach(function(x){if(!x[1])return;var pct=x[1]/total*100;
  seg.push(x[2]+' '+acc.toFixed(1)+'% '+(acc+pct).toFixed(1)+'%');acc+=pct;
  legend+='<div><i style="background:'+x[2]+'"></i>'+x[0]+' — '+x[1]+'</div>';});
var d=document.getElementById('donut');
d.style.background=seg.length?'conic-gradient('+seg.join(',')+')':'rgba(148,163,184,.12)';
d.innerHTML='<div class="hole"><b>'+rows.length+'</b><span>jobs</span></div>';
document.getElementById('legend').innerHTML=legend||'<div>No scheduled actions.</div>';""",
    },
    {
        "id": "scheduled_by_product",
        "group": "Automation", "subgroup": "",
        "category": "Automation",
        "title": "Scheduled actions by product", "name": "Scheduled actions by product",
        "icon": "bi-boxes",
        "description": "Groups scheduled automations by the product they target — a "
                       "pure-Jinja pivot that stays graceful when nothing is scheduled.",
        "tags": ["automation", "grouped", "product", "empty-safe"],
        "datasets": ["scheduled_actions"],
        "params": [],
        "jinja": """{% set rows = data.scheduled_actions.rows %}
<h2>Scheduled actions by product</h2>
{% if rows %}
<table><thead><tr><th>Product</th><th>Jobs</th><th>Names</th></tr></thead><tbody>
{% for prod, items in rows|groupby('product') %}
<tr><td>{{ prod or '(global)' }}</td><td>{{ items|length }}</td><td>{{ items|map(attribute='name')|join(', ') }}</td></tr>
{% endfor %}
</tbody></table>
{% else %}<p class="hint">No scheduled actions configured.</p>{% endif %}""",
        "css": _BASE,
        "js": "",
    },
    {
        "id": "scheduled_upcoming",
        "group": "Automation", "subgroup": "",
        "category": "Automation",
        "title": "Upcoming runs (timeline)", "name": "Upcoming runs (timeline)",
        "icon": "bi-hourglass-split",
        "description": "The scheduled automations ordered by next run as a timeline "
                       "of what fires next. Only enabled jobs are highlighted.",
        "tags": ["automation", "timeline", "next-run", "empty-safe"],
        "datasets": ["scheduled_actions"],
        "params": [],
        "jinja": """<h2>Upcoming automation runs</h2>
<ul class="tl">
{% for r in data.scheduled_actions.rows %}
{% set live = r.enabled in (1,'1','true','True',true) %}
<li class="{{ 'live' if live else 'paused' }}"><span class="dot"></span>
<div><div class="nm">{{ r.name }} {% if not live %}<em>(paused)</em>{% endif %}</div>
<div class="d">{{ r.action_key }} · next {{ r.next_run or 'unscheduled' }}</div></div></li>
{% else %}<li class="none">No scheduled actions.</li>{% endfor %}
</ul>""",
        "css": """.tl{list-style:none;margin:0;padding:0}
.tl li{display:flex;gap:12px;padding:0 0 14px 4px;border-left:2px solid rgba(148,163,184,.15);margin-left:6px}
.tl .dot{width:10px;height:10px;border-radius:50%;background:#10b981;margin:2px 0 0 -11px;flex:none}
.tl .paused .dot,.tl li.paused .dot{background:#94a3b8}
.tl .nm{color:#e2e8f0;font-size:13px;font-weight:600}.tl .nm em{color:#94a3b8;font-weight:400}
.tl .d{color:#94a3b8;font-size:12px}
.tl .none{border:0;color:#94a3b8}""",
        "js": "",
    },

    # =========================================================================
    # GROUP: Reporting & Aggregation
    # =========================================================================
    {
        "id": "coverage_scorecard",
        "group": "Reporting & Aggregation", "subgroup": "Scorecards",
        "category": "Reporting & Aggregation",
        "title": "Policy coverage scorecard", "name": "Policy coverage scorecard",
        "icon": "bi-clipboard-check",
        "description": "A scorecard of the key WAF hygiene ratios: % of policies with "
                       "a WAF profile, with traffic logging, and enabled — computed "
                       "in the template.",
        "tags": ["report", "scorecard", "coverage", "ratios"],
        "datasets": ["server_policies_full"],
        "params": [],
        "jinja": """{% set rows = data.server_policies_full.rows %}
{% set total = rows|length %}
{% set waf = rows|selectattr('wpp')|list|length %}
{% set tlog = rows|selectattr('traffic_log','equalto','enable')|list|length %}
{% set enabled = rows|selectattr('status','equalto','enable')|list|length %}
<h2>Policy coverage scorecard</h2>
{% if total %}
<div class="cards">
  <div class="sc"><div class="p">{{ (waf/total*100)|round|int }}%</div><div class="l">WAF-protected</div><div class="s">{{ waf }}/{{ total }}</div></div>
  <div class="sc"><div class="p">{{ (tlog/total*100)|round|int }}%</div><div class="l">Traffic logging</div><div class="s">{{ tlog }}/{{ total }}</div></div>
  <div class="sc"><div class="p">{{ (enabled/total*100)|round|int }}%</div><div class="l">Enabled</div><div class="s">{{ enabled }}/{{ total }}</div></div>
</div>
{% else %}<p class="hint">No cached policies to score.</p>{% endif %}""",
        "css": _BASE + """.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.sc{background:rgba(15,23,42,.6);border:1px solid rgba(148,163,184,.12);border-radius:16px;padding:20px;text-align:center}
.sc .p{font-size:34px;font-weight:700;color:#6ee7b7}
.sc .l{font-size:12px;color:#cbd5e1;margin-top:4px}
.sc .s{font-size:11px;color:#64748b;margin-top:4px}""",
        "js": "",
    },
    {
        "id": "executive_summary",
        "group": "Reporting & Aggregation", "subgroup": "Scorecards",
        "category": "Reporting & Aggregation",
        "title": "Executive summary", "name": "Executive summary",
        "icon": "bi-file-earmark-text",
        "description": "A one-glance narrative summary combining fleet counts with "
                       "live policy hygiene — the kind of paragraph you paste into a "
                       "status report.",
        "tags": ["report", "summary", "narrative", "two-datasets"],
        "datasets": ["fleet_counts", "server_policies_full"],
        "params": [],
        "jinja": """{% set c = data.fleet_counts.rows[0] if data.fleet_counts.rows else none %}
{% set rows = data.server_policies_full.rows %}
{% set total = rows|length %}
{% set gaps = rows|rejectattr('wpp')|list|length %}
<h2>Executive summary</h2>
<div class="card">
<p>The fleet has <b>{{ c.devices if c else 0 }}</b> managed device(s) exposing
<b>{{ c.server_policies if c else 0 }}</b> server policy(ies) and tracking
<b>{{ c.certificates if c else 0 }}</b> certificate(s).</p>
{% if total %}
<p>Of the <b>{{ total }}</b> cached policy record(s),
<b class="{{ 'bad' if gaps else 'good' }}">{{ gaps }}</b> have no WAF profile bound
({{ (gaps/total*100)|round|int }}% of the cache).</p>
{% else %}
<p class="hint">No server policies are cached yet — run a rediscovery for coverage detail.</p>
{% endif %}
</div>""",
        "css": _BASE + _CARD + """.card p{color:#cbd5e1;font-size:14px;line-height:1.6;margin:0 0 10px}
.card b{color:#e2e8f0}.bad{color:#fca5a5}.good{color:#6ee7b7}""",
        "js": "",
    },
    {
        "id": "device_crossref",
        "group": "Reporting & Aggregation", "subgroup": "Cross-reference",
        "category": "Reporting & Aggregation",
        "title": "Device cross-reference (policies + pools)", "name": "Device cross-reference (policies + pools)",
        "icon": "bi-diagram-3-fill",
        "description": "One row per managed device joining its policy count and pool "
                       "count from two other datasets — a three-dataset roll-up.",
        "tags": ["report", "cross-reference", "join", "three-datasets"],
        "datasets": ["fleet_appliances", "server_policies_full", "server_pools"],
        "params": [],
        "jinja": """{% set devs = data.fleet_appliances.rows %}
{% set pols = data.server_policies_full.rows %}
{% set pools = data.server_pools.rows %}
<h2>Per-device roll-up</h2>
<table><thead><tr><th>Device</th><th>Kind</th><th>Policies</th><th>Pools</th></tr></thead><tbody>
{% for d in devs %}
{% set pc = pols|selectattr('appliance_id','equalto', d.id)|list|length %}
{% set kc = pools|selectattr('appliance_id','equalto', d.id)|list|length %}
<tr><td>{{ d.name }}</td><td>{{ d.kind }}</td><td>{{ pc }}</td><td>{{ kc }}</td></tr>
{% else %}<tr><td colspan="4">No devices registered.</td></tr>{% endfor %}
</tbody></table>""",
        "css": _BASE,
        "js": "",
    },
    {
        "id": "policy_matrix",
        "group": "Reporting & Aggregation", "subgroup": "Cross-reference",
        "category": "Reporting & Aggregation",
        "title": "Device × deployment-mode matrix", "name": "Device × deployment-mode matrix",
        "icon": "bi-grid-3x3",
        "description": "A pivot matrix: rows are devices, columns are the deployment "
                       "modes present, cells are policy counts. Built purely in Jinja.",
        "tags": ["report", "pivot", "matrix", "jinja-only"],
        "datasets": ["server_policies_full"],
        "params": [],
        "jinja": """{% set rows = data.server_policies_full.rows %}
<h2>Device × deployment-mode</h2>
{% if rows %}
{% set modes = rows|map(attribute='deployment_mode')|unique|list %}
<table><thead><tr><th>Device</th>{% for m in modes %}<th>{{ m or 'unset' }}</th>{% endfor %}<th>Total</th></tr></thead><tbody>
{% for dev, items in rows|groupby('device') %}
<tr><td>{{ dev or '—' }}</td>
{% for m in modes %}<td>{{ items|selectattr('deployment_mode','equalto',m)|list|length }}</td>{% endfor %}
<td><b>{{ items|length }}</b></td></tr>
{% endfor %}
</tbody></table>
{% else %}<p class="hint">No cached policies.</p>{% endif %}""",
        "css": _BASE + "td b{color:#93c5fd}",
        "js": "",
    },

    # =========================================================================
    # GROUP: Charts & Viz
    # =========================================================================
    {
        "id": "kind_proportion_blocks",
        "group": "Charts & Viz", "subgroup": "",
        "category": "Charts & Viz",
        "title": "Device kind proportion bar", "name": "Device kind proportion bar",
        "icon": "bi-distribute-horizontal",
        "description": "A single stacked proportion bar showing the share of each "
                       "device kind across the fleet — a compact 100%-stacked strip.",
        "tags": ["chart", "stacked", "proportion", "jinja-only"],
        "datasets": ["fleet_appliances"],
        "params": [],
        "jinja": """{% set rows = data.fleet_appliances.rows %}
<h2>Fleet composition</h2>
{% if rows %}
{% set total = rows|length %}
<div class="strip">
{% set colors = ['#3b82f6','#8b5cf6','#10b981','#fbbf24','#ef4444'] %}
{% for kind, items in rows|groupby('kind') %}
<div class="seg" style="width:{{ (items|length / total * 100)|round(1) }}%;background:{{ colors[loop.index0 % 5] }}" title="{{ kind }}: {{ items|length }}"></div>
{% endfor %}
</div>
<div class="legend">
{% for kind, items in rows|groupby('kind') %}
<span><i style="background:{{ colors[loop.index0 % 5] }}"></i>{{ kind }} — {{ items|length }}</span>
{% endfor %}
</div>
{% else %}<p class="hint">No devices registered.</p>{% endif %}""",
        "css": _BASE + """.strip{display:flex;height:28px;border-radius:8px;overflow:hidden;background:rgba(148,163,184,.12)}
.seg{height:100%}
.legend{margin-top:12px;display:flex;flex-wrap:wrap;gap:16px}
.legend span{display:flex;align-items:center;gap:6px;font-size:13px;color:#cbd5e1}
.legend i{width:12px;height:12px;border-radius:3px}""",
        "js": "",
    },
    {
        "id": "policy_stacked_status",
        "group": "Charts & Viz", "subgroup": "",
        "category": "Charts & Viz",
        "title": "Enabled/disabled per device (stacked)", "name": "Enabled/disabled per device (stacked)",
        "icon": "bi-bar-chart-steps",
        "description": "A per-device stacked bar of enabled vs disabled policies — "
                       "green sits on red so you read both magnitude and health.",
        "tags": ["chart", "stacked", "status", "policies"],
        "datasets": ["server_policies_full"],
        "params": [],
        "jinja": """<h2>Policies per device (enabled / disabled)</h2>
<div id="chart"></div>
<div class="key"><span><i style="background:#10b981"></i>enabled</span><span><i style="background:#ef4444"></i>disabled</span></div>""",
        "css": """#chart .row{display:flex;align-items:center;gap:10px;margin:7px 0}
#chart .lbl{width:150px;font-size:13px;color:#cbd5e1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#chart .track{flex:1;display:flex;height:20px;border-radius:8px;overflow:hidden;background:rgba(148,163,184,.1)}
#chart .on{background:#10b981}#chart .off{background:#ef4444}
#chart .val{width:44px;text-align:right;font-size:12px;color:#e2e8f0}
.key{margin-top:12px;display:flex;gap:16px}.key span{display:flex;align-items:center;gap:6px;font-size:12px;color:#94a3b8}
.key i{width:12px;height:12px;border-radius:3px}""",
        "js": """var rows=(window.pluginData.server_policies_full||{}).rows||[];
var by={};rows.forEach(function(r){var k=r.device||r.appliance_id||'?';by[k]=by[k]||{on:0,off:0};
  if(r.status==='enable')by[k].on++;else by[k].off++;});
var keys=Object.keys(by).sort(function(a,b){return (by[b].on+by[b].off)-(by[a].on+by[a].off);});
var max=Math.max(1,...keys.map(function(k){return by[k].on+by[k].off;}));
var el=document.getElementById('chart');
if(!keys.length){el.innerHTML='<p style="color:#94a3b8">No cached policies.</p>';}
keys.forEach(function(k){var o=by[k];var tot=o.on+o.off;var w=tot/max*100;
  var d=document.createElement('div');d.className='row';
  d.innerHTML='<div class="lbl" title="'+k+'">'+k+'</div><div class="track" style="width:'+w+'%">'+
    '<div class="on" style="flex:'+o.on+'"></div><div class="off" style="flex:'+o.off+'"></div></div>'+
    '<div class="val">'+o.on+'/'+tot+'</div>';
  el.appendChild(d);});""",
    },
    {
        "id": "audit_sparkline",
        "group": "Charts & Viz", "subgroup": "",
        "category": "Charts & Viz",
        "title": "Activity sparkline", "name": "Activity sparkline",
        "icon": "bi-graph-up",
        "description": "A compact inline SVG sparkline of recent audit volume bucketed "
                       "by hour — a tiny trend line, no chart library.",
        "tags": ["chart", "sparkline", "svg", "audit"],
        "datasets": ["audit_recent"],
        "params": [],
        "jinja": """<h2>Recent activity trend</h2>
<div id="spark" class="spark">…</div>
<div class="cap">Events bucketed by hour of day (0–23).</div>""",
        "css": """.spark{height:60px}.spark svg{width:100%;height:60px}
.cap{font-size:11px;color:#64748b;margin-top:6px}""",
        "js": """var rows=(window.pluginData.audit_recent||{}).rows||[];
var b=new Array(24).fill(0);
rows.forEach(function(r){var m=/\\b(\\d{2}):\\d{2}:\\d{2}/.exec(r.timestamp||'');if(m)b[parseInt(m[1],10)]++;});
var el=document.getElementById('spark');
var max=Math.max(1,...b);var w=300,h=60,step=w/23;
var pts=b.map(function(n,i){return (i*step).toFixed(1)+','+(h-(n/max*(h-6))-3).toFixed(1);}).join(' ');
if(!rows.length){el.textContent='No activity.';}
else{el.innerHTML='<svg viewBox="0 0 '+w+' '+h+'" preserveAspectRatio="none">'+
  '<polyline fill="none" stroke="#3b82f6" stroke-width="2" points="'+pts+'"/></svg>';}""",
    },
    {
        "id": "policy_treemap",
        "group": "Charts & Viz", "subgroup": "",
        "category": "Charts & Viz",
        "title": "Policies-per-device treemap", "name": "Policies-per-device treemap",
        "icon": "bi-bounding-box",
        "description": "A simple flex treemap where each device is a tile sized by its "
                       "policy count — bigger tile, busier box.",
        "tags": ["chart", "treemap", "policies", "no-library"],
        "datasets": ["server_policies_full"],
        "params": [],
        "jinja": """<h2>Policy load by device</h2>
<div id="tm" class="tm"></div>""",
        "css": """.tm{display:flex;flex-wrap:wrap;gap:6px}
.tm .tile{border-radius:10px;padding:12px;color:#fff;display:flex;flex-direction:column;justify-content:center;min-width:70px;min-height:60px}
.tm .tn{font-size:12px;opacity:.9;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tm .tc{font-size:22px;font-weight:700}
.tm .empty{color:#94a3b8}""",
        "js": """var rows=(window.pluginData.server_policies_full||{}).rows||[];
var by={};rows.forEach(function(r){var k=r.device||r.appliance_id||'?';by[k]=(by[k]||0)+1;});
var keys=Object.keys(by).sort(function(a,b){return by[b]-by[a];});
var max=Math.max(1,...keys.map(function(k){return by[k];}));
var pal=['#3b82f6','#6366f1','#8b5cf6','#a855f7','#ec4899','#10b981'];
var el=document.getElementById('tm');
if(!keys.length){el.innerHTML='<div class="empty">No cached policies.</div>';}
keys.forEach(function(k,i){var flex=Math.max(1,Math.round(by[k]/max*4));
  var t=document.createElement('div');t.className='tile';t.style.flex=flex;t.style.background=pal[i%pal.length];
  t.innerHTML='<div class="tc">'+by[k]+'</div><div class="tn" title="'+k+'">'+k+'</div>';
  el.appendChild(t);});""",
    },

]


def categories() -> list[str]:
    seen: list[str] = []
    for ex in _EXAMPLES:
        if ex["category"] not in seen:
            seen.append(ex["category"])
    return seen


def all_examples() -> list[dict[str, Any]]:
    """The full catalog (metadata + source) for the editor's example browser."""
    return _EXAMPLES


def get(example_id: str) -> dict[str, Any] | None:
    for ex in _EXAMPLES:
        if ex["id"] == example_id:
            return ex
    return None
