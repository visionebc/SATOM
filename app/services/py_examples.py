"""Validated example scripts for the sandboxed Python Console.

Every example here has been executed in the REAL bubblewrap sandbox
(``app.services.py_console.run_python``) against BOTH a synthetic fixture
bundle (with edge cases) AND live data on this box, and exits 0 on both — the
empty-result-set case included. Scripts receive the curated datasets as a
global ``data`` mapping ``{key: {"columns": [...], "rows": [...]}}`` where every
``rows`` entry is a dict of column -> value. NOTE: every value arrives as a
string (even numeric-looking ones such as ``port`` or ``devices``), so scripts
coerce with care and never assume a non-empty result set.

The nine curated dataset keys (see ``plugin_sandbox.DATASETS``):
    fleet_appliances, server_policies, server_policies_full, server_pools,
    web_protection_profiles, certificates, audit_recent, fleet_counts,
    scheduled_actions

Public API:
    all_examples() -> list[dict]      # every example, code already dedented
    categories()   -> list[str]       # ordered, de-duplicated group names
"""
from __future__ import annotations

import textwrap as _textwrap

_EXAMPLES = [

    # ================= Fleet — Inventory =================
    {
        "id": "fleet_count_by_kind",
        "group": "Fleet", "subgroup": "Inventory", "category": "Fleet",
        "title": "Count devices by kind", "name": "Count devices by kind",
        "description": "Tally managed appliances grouped by product kind.",
        "tags": ["fleet", "counter", "inventory"],
        "datasets": ["fleet_appliances"],
        "code": """
        from collections import Counter
        rows = data['fleet_appliances']['rows']
        by_kind = Counter(r.get('kind') or 'unknown' for r in rows)
        if not by_kind:
            print('No appliances.')
        else:
            for kind, n in by_kind.most_common():
                print(f"{kind:12} {n}")
            print('total', len(rows))
        """,
    },
    {
        "id": "fleet_inventory_table",
        "group": "Fleet", "subgroup": "Inventory", "category": "Fleet",
        "title": "Appliance inventory table", "name": "Appliance inventory table",
        "description": "Aligned name/kind/host/firmware table of every appliance.",
        "tags": ["fleet", "table", "inventory"],
        "datasets": ["fleet_appliances"],
        "code": """
        rows = data['fleet_appliances']['rows']
        if not rows:
            print('No appliances.')
        else:
            hdr = f"{'name':16}{'kind':12}{'host':28}firmware"
            print(hdr)
            print('-' * len(hdr))
            for r in sorted(rows, key=lambda r: (r.get('kind') or '', r.get('name') or '')):
                fw = (r.get('firmware') or '').split(',')[0] or '—'
                print(f"{(r.get('name') or ''):16}{(r.get('kind') or ''):12}{(r.get('host') or ''):28}{fw}")
        """,
    },
    {
        "id": "fleet_hosts_list",
        "group": "Fleet", "subgroup": "Inventory", "category": "Fleet",
        "title": "Unique appliance hostnames", "name": "Unique appliance hostnames",
        "description": "De-duplicated, sorted list of appliance hostnames.",
        "tags": ["fleet", "hosts", "dedup"],
        "datasets": ["fleet_appliances"],
        "code": """
        rows = data['fleet_appliances']['rows']
        hosts = sorted({r.get('host') for r in rows if r.get('host')})
        print(f"{len(hosts)} unique host(s):")
        for h in hosts:
            print(' -', h)
        """,
    },
    {
        "id": "fleet_port_distribution",
        "group": "Fleet", "subgroup": "Inventory", "category": "Fleet",
        "title": "Management port distribution", "name": "Management port distribution",
        "description": "How many appliances listen on each management port.",
        "tags": ["fleet", "ports", "counter"],
        "datasets": ["fleet_appliances"],
        "code": """
        from collections import Counter
        rows = data['fleet_appliances']['rows']
        ports = Counter(str(r.get('port') or '?') for r in rows)
        if not ports:
            print('No appliances.')
        else:
            for p, n in ports.most_common():
                print(f"port {p:6} {n}")
        """,
    },

    # ================= Fleet — Firmware =================
    {
        "id": "fleet_firmware_versions",
        "group": "Fleet", "subgroup": "Firmware", "category": "Fleet",
        "title": "Group devices by firmware", "name": "Group devices by firmware",
        "description": "List which appliances run each firmware build.",
        "tags": ["fleet", "firmware", "group-by"],
        "datasets": ["fleet_appliances"],
        "code": """
        from collections import defaultdict
        rows = data['fleet_appliances']['rows']
        groups = defaultdict(list)
        for r in rows:
            fw = (r.get('firmware') or '').strip() or '(unknown)'
            groups[fw].append(r.get('name') or '?')
        if not groups:
            print('No appliances.')
        for fw in sorted(groups):
            print(fw)
            for name in sorted(groups[fw]):
                print('    ', name)
        """,
    },
    {
        "id": "fleet_missing_firmware",
        "group": "Fleet", "subgroup": "Firmware", "category": "Fleet",
        "title": "Appliances with no firmware recorded",
        "name": "Appliances with no firmware recorded",
        "description": "Flag appliances whose firmware string is blank.",
        "tags": ["fleet", "firmware", "missing"],
        "datasets": ["fleet_appliances"],
        "code": """
        rows = data['fleet_appliances']['rows']
        missing = [r for r in rows if not (r.get('firmware') or '').strip()]
        print(f"{len(missing)} of {len(rows)} device(s) have no firmware recorded")
        for r in missing:
            print(' -', r.get('name'), '/', r.get('host'))
        """,
    },
    {
        "id": "fleet_firmware_by_kind",
        "group": "Fleet", "subgroup": "Firmware", "category": "Fleet",
        "title": "Firmware spread per kind", "name": "Firmware spread per kind",
        "description": "Distinct firmware trains seen for each device kind.",
        "tags": ["fleet", "firmware", "group-by"],
        "datasets": ["fleet_appliances"],
        "code": """
        from collections import defaultdict
        rows = data['fleet_appliances']['rows']
        seen = defaultdict(set)
        for r in rows:
            fw = (r.get('firmware') or '(unknown)').split(',')[0]
            seen[r.get('kind') or 'unknown'].add(fw)
        if not rows:
            print('No appliances.')
        for kind in sorted(seen):
            print(f"{kind}: {', '.join(sorted(seen[kind]))}")
        """,
    },

    # ================= Fleet — Summary =================
    {
        "id": "fleet_counts_summary",
        "group": "Fleet", "subgroup": "Summary", "category": "Fleet",
        "title": "Fleet counts summary", "name": "Fleet counts summary",
        "description": "Read the one-row device/policy/certificate totals.",
        "tags": ["fleet", "counts", "summary"],
        "datasets": ["fleet_counts"],
        "code": """
        rows = data['fleet_counts']['rows']
        if not rows:
            print('No counts available.')
        else:
            c = rows[0]
            print('Devices      :', c.get('devices'))
            print('Server pols  :', c.get('server_policies'))
            print('Certificates :', c.get('certificates'))
        """,
    },
    {
        "id": "fleet_counts_ratio",
        "group": "Fleet", "subgroup": "Summary", "category": "Fleet",
        "title": "Policies per device ratio", "name": "Policies per device ratio",
        "description": "Average server policies per device (divide-by-zero safe).",
        "tags": ["fleet", "ratio", "counts"],
        "datasets": ["fleet_counts"],
        "code": """
        rows = data['fleet_counts']['rows']
        if not rows:
            print('No counts available.')
        else:
            c = rows[0]
            def _i(x):
                try:
                    return int(x)
                except (TypeError, ValueError):
                    return 0
            dev, pol = _i(c.get('devices')), _i(c.get('server_policies'))
            if dev == 0:
                print('No devices to average over.')
            else:
                print(f"{pol} policies across {dev} device(s) = {pol/dev:.1f} per device")
        """,
    },

    # ================= Server Policies — Coverage =================
    {
        "id": "pol_missing_wpp",
        "group": "Server Policies", "subgroup": "Coverage", "category": "Server Policies",
        "title": "Policies with no WAF profile", "name": "Policies with no WAF profile",
        "description": "List server policies that reference no web-protection profile.",
        "tags": ["policies", "waf", "missing"],
        "datasets": ["server_policies_full"],
        "code": """
        rows = data['server_policies_full']['rows']
        missing = [r for r in rows if not (r.get('wpp') or '').strip()]
        print(f"{len(missing)} of {len(rows)} policies have NO WAF profile")
        for r in missing:
            print(' -', r.get('device'), '/', r.get('policy'))
        """,
    },
    {
        "id": "pol_wpp_coverage_pct",
        "group": "Server Policies", "subgroup": "Coverage", "category": "Server Policies",
        "title": "WAF coverage percentage", "name": "WAF coverage percentage",
        "description": "Share of policies protected by a WAF profile.",
        "tags": ["policies", "waf", "percentage"],
        "datasets": ["server_policies_full"],
        "code": """
        rows = data['server_policies_full']['rows']
        if not rows:
            print('No policies.')
        else:
            covered = sum(1 for r in rows if (r.get('wpp') or '').strip())
            print(f"WAF coverage: {covered}/{len(rows)} = {100*covered/len(rows):.0f}%")
        """,
    },
    {
        "id": "pol_disabled",
        "group": "Server Policies", "subgroup": "Coverage", "category": "Server Policies",
        "title": "Disabled server policies", "name": "Disabled server policies",
        "description": "Policies whose status is not 'enable'.",
        "tags": ["policies", "status", "disabled"],
        "datasets": ["server_policies_full"],
        "code": """
        rows = data['server_policies_full']['rows']
        off = [r for r in rows if (r.get('status') or '').lower() != 'enable']
        print(f"{len(off)} non-enabled policy(ies):")
        for r in off:
            print(' -', r.get('device'), '/', r.get('policy'), '->', r.get('status') or '(blank)')
        """,
    },
    {
        "id": "pol_monitor_mode",
        "group": "Server Policies", "subgroup": "Coverage", "category": "Server Policies",
        "title": "Policies in monitor-only mode", "name": "Policies in monitor-only mode",
        "description": "Detection-only policies that do not block traffic.",
        "tags": ["policies", "monitor", "risk"],
        "datasets": ["server_policies_full"],
        "code": """
        rows = data['server_policies_full']['rows']
        mon = [r for r in rows if (r.get('monitor_mode') or '').lower() == 'enable']
        print(f"{len(mon)} policy(ies) in MONITOR (detection-only) mode:")
        for r in mon:
            print(' -', r.get('device'), '/', r.get('policy'))
        if rows and not mon:
            print('(all policies are enforcing)')
        """,
    },
    {
        "id": "pol_traffic_log_off",
        "group": "Server Policies", "subgroup": "Coverage", "category": "Server Policies",
        "title": "Policies with traffic log off", "name": "Policies with traffic log off",
        "description": "Policies not emitting traffic logs.",
        "tags": ["policies", "logging", "audit"],
        "datasets": ["server_policies_full"],
        "code": """
        rows = data['server_policies_full']['rows']
        off = [r for r in rows if (r.get('traffic_log') or '').lower() != 'enable']
        print(f"{len(off)} of {len(rows)} policy(ies) have traffic log OFF:")
        for r in off:
            print(' -', r.get('device'), '/', r.get('policy'))
        """,
    },

    # ================= Server Policies — Deployment =================
    {
        "id": "pol_by_deployment_mode",
        "group": "Server Policies", "subgroup": "Deployment", "category": "Server Policies",
        "title": "Policies by deployment mode", "name": "Policies by deployment mode",
        "description": "Distribution of policies across deployment modes.",
        "tags": ["policies", "deployment", "counter"],
        "datasets": ["server_policies_full"],
        "code": """
        from collections import Counter
        rows = data['server_policies_full']['rows']
        modes = Counter(r.get('deployment_mode') or '(none)' for r in rows)
        if not modes:
            print('No policies.')
        for m, n in modes.most_common():
            print(f"{m:22} {n}")
        """,
    },
    {
        "id": "pol_by_device",
        "group": "Server Policies", "subgroup": "Deployment", "category": "Server Policies",
        "title": "Policy count per device", "name": "Policy count per device",
        "description": "How many server policies each device carries.",
        "tags": ["policies", "device", "counter"],
        "datasets": ["server_policies_full"],
        "code": """
        from collections import Counter
        rows = data['server_policies_full']['rows']
        per = Counter(r.get('device') or '?' for r in rows)
        if not per:
            print('No policies.')
        for dev, n in per.most_common():
            print(f"{dev:16} {n} policy(ies)")
        """,
    },
    {
        "id": "pol_content_routing",
        "group": "Server Policies", "subgroup": "Deployment", "category": "Server Policies",
        "title": "Content-routing policies", "name": "Content-routing policies",
        "description": "Policies in http-content-routing mode and their pool binding.",
        "tags": ["policies", "content-routing", "filter"],
        "datasets": ["server_policies_full"],
        "code": """
        rows = data['server_policies_full']['rows']
        cr = [r for r in rows if (r.get('deployment_mode') or '') == 'http-content-routing']
        print(f"{len(cr)} content-routing policy(ies):")
        for r in cr:
            pool = r.get('server_pool') or '(routed by rule)'
            print(' -', r.get('device'), '/', r.get('policy'), 'pool:', pool)
        """,
    },
    {
        "id": "pol_by_vserver",
        "group": "Server Policies", "subgroup": "Deployment", "category": "Server Policies",
        "title": "Policies grouped by virtual server", "name": "Policies grouped by virtual server",
        "description": "Which policies bind to each virtual server.",
        "tags": ["policies", "vserver", "group-by"],
        "datasets": ["server_policies_full"],
        "code": """
        from collections import defaultdict
        rows = data['server_policies_full']['rows']
        vs = defaultdict(list)
        for r in rows:
            vs[r.get('vserver') or '(none)'].append(r.get('policy') or '?')
        if not rows:
            print('No policies.')
        for v in sorted(vs):
            print(f"{v}: {', '.join(sorted(vs[v]))}")
        """,
    },
    {
        "id": "pol_service_distribution",
        "group": "Server Policies", "subgroup": "Deployment", "category": "Server Policies",
        "title": "Policies by listener service", "name": "Policies by listener service",
        "description": "Distribution of the front-end service each policy listens on.",
        "tags": ["policies", "service", "counter"],
        "datasets": ["server_policies_full"],
        "code": """
        from collections import Counter
        rows = data['server_policies_full']['rows']
        svc = Counter(r.get('service') or '(none)' for r in rows)
        if not svc:
            print('No policies.')
        for s, n in svc.most_common():
            print(f"{s:12} {n}")
        """,
    },

    # ================= Server Policies — App ID =================
    {
        "id": "pol_missing_appid",
        "group": "Server Policies", "subgroup": "App ID", "category": "Server Policies",
        "title": "Policies missing an App-ID tag", "name": "Policies missing an App-ID tag",
        "description": "Policies whose comment carries no parsed App-ID.",
        "tags": ["policies", "appid", "missing"],
        "datasets": ["server_policies_full"],
        "code": """
        rows = data['server_policies_full']['rows']
        missing = [r for r in rows if not (r.get('appid') or '').strip()]
        print(f"{len(missing)} of {len(rows)} policy(ies) have no App-ID tag")
        for r in missing[:25]:
            print(' -', r.get('device'), '/', r.get('policy'))
        """,
    },
    {
        "id": "pol_appid_list",
        "group": "Server Policies", "subgroup": "App ID", "category": "Server Policies",
        "title": "App-ID usage", "name": "App-ID usage",
        "description": "How many policies carry each parsed App-ID.",
        "tags": ["policies", "appid", "counter"],
        "datasets": ["server_policies_full"],
        "code": """
        from collections import Counter
        rows = data['server_policies_full']['rows']
        ids = Counter((r.get('appid') or '').strip() for r in rows if (r.get('appid') or '').strip())
        if not ids:
            print('No App-IDs tagged on any policy.')
        else:
            for a, n in ids.most_common():
                print(f"{a:20} {n} policy(ies)")
        """,
    },

    # ================= Server Policies — Cached (typed) =================
    {
        "id": "sp_typed_by_status",
        "group": "Server Policies", "subgroup": "Cached", "category": "Server Policies",
        "title": "Cached policies by status", "name": "Cached policies by status",
        "description": "Status breakdown of the typed (cached) server_policies dataset.",
        "tags": ["policies", "cached", "status"],
        "datasets": ["server_policies"],
        "code": """
        from collections import Counter
        rows = data['server_policies']['rows']
        st = Counter((r.get('status') or '(none)') for r in rows)
        if not st:
            print('No cached (typed) server policies.')
        else:
            for s, n in st.most_common():
                print(f"{s:12} {n}")
        """,
    },
    {
        "id": "sp_typed_by_deployment",
        "group": "Server Policies", "subgroup": "Cached", "category": "Server Policies",
        "title": "Cached policies by deployment mode",
        "name": "Cached policies by deployment mode",
        "description": "Deployment-mode spread of the typed server_policies dataset.",
        "tags": ["policies", "cached", "deployment"],
        "datasets": ["server_policies"],
        "code": """
        from collections import Counter
        rows = data['server_policies']['rows']
        m = Counter(r.get('deployment_mode') or '(none)' for r in rows)
        if not m:
            print('No cached (typed) server policies.')
        else:
            for k, n in m.most_common():
                print(f"{k:22} {n}")
        """,
    },
    {
        "id": "sp_typed_inventory",
        "group": "Server Policies", "subgroup": "Cached", "category": "Server Policies",
        "title": "Cached policy inventory", "name": "Cached policy inventory",
        "description": "One line per typed cached policy with vserver/pool/status.",
        "tags": ["policies", "cached", "inventory"],
        "datasets": ["server_policies"],
        "code": """
        rows = data['server_policies']['rows']
        if not rows:
            print('No cached (typed) server policies.')
        else:
            for r in sorted(rows, key=lambda r: (str(r.get('appliance_id')), r.get('name') or '')):
                print(f"appliance {r.get('appliance_id')}  {(r.get('name') or '?'):24} "
                      f"vs={r.get('vserver') or '-'} pool={r.get('server_pool') or '-'} {r.get('status')}")
        """,
    },

    # ================= Server Pools — Distribution =================
    {
        "id": "pool_by_type",
        "group": "Server Pools", "subgroup": "Distribution", "category": "Server Pools",
        "title": "Pools by type", "name": "Pools by type",
        "description": "Count of server pools grouped by pool type.",
        "tags": ["pools", "type", "counter"],
        "datasets": ["server_pools"],
        "code": """
        from collections import Counter
        rows = data['server_pools']['rows']
        t = Counter(r.get('type') or '(none)' for r in rows)
        if not t:
            print('No pools.')
        for k, n in t.most_common():
            print(f"{k:18} {n}")
        """,
    },
    {
        "id": "pool_by_protocol",
        "group": "Server Pools", "subgroup": "Distribution", "category": "Server Pools",
        "title": "Pools by protocol", "name": "Pools by protocol",
        "description": "Count of server pools grouped by back-end protocol.",
        "tags": ["pools", "protocol", "counter"],
        "datasets": ["server_pools"],
        "code": """
        from collections import Counter
        rows = data['server_pools']['rows']
        p = Counter((r.get('protocol') or '(none)').upper() for r in rows)
        if not p:
            print('No pools.')
        for k, n in p.most_common():
            print(f"{k:10} {n}")
        """,
    },
    {
        "id": "pool_type_protocol_matrix",
        "group": "Server Pools", "subgroup": "Distribution", "category": "Server Pools",
        "title": "Pool type x protocol matrix", "name": "Pool type x protocol matrix",
        "description": "Cross-tabulate pools by (type, protocol).",
        "tags": ["pools", "matrix", "cross-tab"],
        "datasets": ["server_pools"],
        "code": """
        from collections import Counter
        rows = data['server_pools']['rows']
        mat = Counter((r.get('type') or '(none)', (r.get('protocol') or '(none)').upper()) for r in rows)
        if not mat:
            print('No pools.')
        else:
            for (t, p), n in sorted(mat.items()):
                print(f"{t:18} {p:8} {n}")
        """,
    },

    # ================= Server Pools — Inventory =================
    {
        "id": "pool_by_device",
        "group": "Server Pools", "subgroup": "Inventory", "category": "Server Pools",
        "title": "Pool count per appliance", "name": "Pool count per appliance",
        "description": "How many pools belong to each appliance id.",
        "tags": ["pools", "device", "counter"],
        "datasets": ["server_pools"],
        "code": """
        from collections import Counter
        rows = data['server_pools']['rows']
        per = Counter(str(r.get('appliance_id') or '?') for r in rows)
        if not per:
            print('No pools.')
        for aid, n in sorted(per.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"appliance {aid}: {n} pool(s)")
        """,
    },
    {
        "id": "pool_name_list",
        "group": "Server Pools", "subgroup": "Inventory", "category": "Server Pools",
        "title": "Distinct pool names", "name": "Distinct pool names",
        "description": "Sorted, de-duplicated list of server-pool names.",
        "tags": ["pools", "names", "dedup"],
        "datasets": ["server_pools"],
        "code": """
        rows = data['server_pools']['rows']
        names = sorted({r.get('name') for r in rows if r.get('name')})
        print(f"{len(names)} pool name(s):")
        for n in names:
            print(' -', n)
        """,
    },

    # ================= Web Protection =================
    {
        "id": "wpp_by_kind",
        "group": "Web Protection", "subgroup": "Profiles", "category": "Web Protection",
        "title": "WAF profiles by kind", "name": "WAF profiles by kind",
        "description": "Inline vs offline breakdown of cached WAF profiles.",
        "tags": ["waf", "profiles", "counter"],
        "datasets": ["web_protection_profiles"],
        "code": """
        from collections import Counter
        rows = data['web_protection_profiles']['rows']
        k = Counter(r.get('kind') or '(none)' for r in rows)
        if not k:
            print('No web protection profiles cached.')
        else:
            for kind, n in k.most_common():
                print(f"{kind:12} {n}")
        """,
    },
    {
        "id": "wpp_missing_signature",
        "group": "Web Protection", "subgroup": "Profiles", "category": "Web Protection",
        "title": "WAF profiles without a signature rule",
        "name": "WAF profiles without a signature rule",
        "description": "Profiles that reference no signature-rule set.",
        "tags": ["waf", "profiles", "missing"],
        "datasets": ["web_protection_profiles"],
        "code": """
        rows = data['web_protection_profiles']['rows']
        missing = [r for r in rows if not (r.get('signature_rule') or '').strip()]
        print(f"{len(missing)} of {len(rows)} WAF profile(s) have no signature rule set")
        for r in missing:
            print(' -', r.get('name'), '(appliance', str(r.get('appliance_id')) + ')')
        """,
    },
    {
        "id": "wpp_bot_policy",
        "group": "Web Protection", "subgroup": "Profiles", "category": "Web Protection",
        "title": "WAF profiles with bot mitigation", "name": "WAF profiles with bot mitigation",
        "description": "Profiles that reference a bot-mitigation policy.",
        "tags": ["waf", "bot", "profiles"],
        "datasets": ["web_protection_profiles"],
        "code": """
        rows = data['web_protection_profiles']['rows']
        withbot = [r for r in rows if (r.get('bot_policy') or '').strip()]
        print(f"{len(withbot)} of {len(rows)} WAF profile(s) reference a bot-mitigation policy")
        for r in withbot:
            print(' -', r.get('name'), '->', r.get('bot_policy'))
        """,
    },
    {
        "id": "wpp_inventory",
        "group": "Web Protection", "subgroup": "Profiles", "category": "Web Protection",
        "title": "WAF profile inventory", "name": "WAF profile inventory",
        "description": "One line per WAF profile with its signature/bot refs.",
        "tags": ["waf", "inventory", "profiles"],
        "datasets": ["web_protection_profiles"],
        "code": """
        rows = data['web_protection_profiles']['rows']
        if not rows:
            print('No web protection profiles.')
        else:
            for r in sorted(rows, key=lambda r: (str(r.get('appliance_id')), r.get('name') or '')):
                print(f"[{(r.get('kind') or '?'):8}] {(r.get('name') or '?'):22} "
                      f"sig={r.get('signature_rule') or '-'} bot={r.get('bot_policy') or '-'}")
        """,
    },
    {
        "id": "wpp_by_device",
        "group": "Web Protection", "subgroup": "Profiles", "category": "Web Protection",
        "title": "WAF profiles per appliance", "name": "WAF profiles per appliance",
        "description": "Group cached WAF profiles by owning appliance.",
        "tags": ["waf", "device", "group-by"],
        "datasets": ["web_protection_profiles"],
        "code": """
        from collections import defaultdict
        rows = data['web_protection_profiles']['rows']
        per = defaultdict(list)
        for r in rows:
            per[str(r.get('appliance_id'))].append(r.get('name') or '?')
        if not per:
            print('No web protection profiles.')
        else:
            for aid in sorted(per):
                print(f"appliance {aid}: {', '.join(sorted(per[aid]))}")
        """,
    },

    # ================= Certificates — Expiry =================
    {
        "id": "cert_soonest_expiry",
        "group": "Certificates", "subgroup": "Expiry", "category": "Certificates",
        "title": "Soonest-expiring certificates", "name": "Soonest-expiring certificates",
        "description": "The 15 certificates closest to their not-after date.",
        "tags": ["certificates", "expiry", "sort"],
        "datasets": ["certificates"],
        "code": """
        rows = [r for r in data['certificates']['rows'] if r.get('not_after')]
        rows.sort(key=lambda r: str(r.get('not_after')))
        if not rows:
            print('No certificates with an expiry date.')
        else:
            print('Soonest-expiring certificates:')
            for r in rows[:15]:
                print(f"{str(r.get('not_after'))[:10]}  {r.get('common_name') or '(no CN)'}")
        """,
    },
    {
        "id": "cert_expiring_window",
        "group": "Certificates", "subgroup": "Expiry", "category": "Certificates",
        "title": "Certificates expiring within 30 days",
        "name": "Certificates expiring within 30 days",
        "description": "Certs whose not-after falls in the next 30 days.",
        "tags": ["certificates", "expiry", "window"],
        "datasets": ["certificates"],
        "code": """
        from datetime import date
        def _p(s):
            try:
                return date.fromisoformat(str(s)[:10])
            except (ValueError, TypeError):
                return None
        today = date.today()
        soon = []
        for r in data['certificates']['rows']:
            d = _p(r.get('not_after'))
            if d is not None:
                days = (d - today).days
                if 0 <= days <= 30:
                    soon.append((days, r))
        soon.sort()
        print(f"{len(soon)} certificate(s) expiring within 30 days:")
        for days, r in soon:
            print(f"  in {days:3} day(s)  {r.get('common_name') or '(no CN)'}")
        """,
    },
    {
        "id": "cert_expired",
        "group": "Certificates", "subgroup": "Expiry", "category": "Certificates",
        "title": "Expired certificates", "name": "Expired certificates",
        "description": "Certificates whose not-after date is already in the past.",
        "tags": ["certificates", "expired", "risk"],
        "datasets": ["certificates"],
        "code": """
        from datetime import date
        def _p(s):
            try:
                return date.fromisoformat(str(s)[:10])
            except (ValueError, TypeError):
                return None
        today = date.today()
        exp = [(d, r) for r in data['certificates']['rows']
               for d in [_p(r.get('not_after'))] if d is not None and d < today]
        exp.sort()
        print(f"{len(exp)} EXPIRED certificate(s):")
        for d, r in exp:
            print(f"  {d}  ({(today - d).days} day(s) ago)  {r.get('common_name') or '(no CN)'}")
        """,
    },
    {
        "id": "cert_expiry_buckets",
        "group": "Certificates", "subgroup": "Expiry", "category": "Certificates",
        "title": "Certificate expiry buckets", "name": "Certificate expiry buckets",
        "description": "Bucket certs into expired / 0-30d / 31-90d / 90d+ / no-date.",
        "tags": ["certificates", "expiry", "buckets"],
        "datasets": ["certificates"],
        "code": """
        from datetime import date
        def _p(s):
            try:
                return date.fromisoformat(str(s)[:10])
            except (ValueError, TypeError):
                return None
        today = date.today()
        buckets = {'expired': 0, '0-30d': 0, '31-90d': 0, '90d+': 0, 'no-date': 0}
        for r in data['certificates']['rows']:
            d = _p(r.get('not_after'))
            if d is None:
                buckets['no-date'] += 1
                continue
            days = (d - today).days
            if days < 0:
                buckets['expired'] += 1
            elif days <= 30:
                buckets['0-30d'] += 1
            elif days <= 90:
                buckets['31-90d'] += 1
            else:
                buckets['90d+'] += 1
        for k in ('expired', '0-30d', '31-90d', '90d+', 'no-date'):
            print(f"{k:8} {buckets[k]}")
        """,
    },

    # ================= Certificates — Inventory =================
    {
        "id": "cert_by_status",
        "group": "Certificates", "subgroup": "Inventory", "category": "Certificates",
        "title": "Certificates by status", "name": "Certificates by status",
        "description": "Count managed certificates grouped by status.",
        "tags": ["certificates", "status", "counter"],
        "datasets": ["certificates"],
        "code": """
        from collections import Counter
        rows = data['certificates']['rows']
        st = Counter((r.get('status') or '(none)') for r in rows)
        if not st:
            print('No certificates.')
        else:
            for s, n in st.most_common():
                print(f"{s:14} {n}")
        """,
    },
    {
        "id": "cert_by_device",
        "group": "Certificates", "subgroup": "Inventory", "category": "Certificates",
        "title": "Certificates per appliance", "name": "Certificates per appliance",
        "description": "How many managed certificates each appliance holds.",
        "tags": ["certificates", "device", "counter"],
        "datasets": ["certificates"],
        "code": """
        from collections import Counter
        rows = data['certificates']['rows']
        per = Counter(str(r.get('appliance_id')) for r in rows)
        if not per:
            print('No certificates.')
        else:
            for aid, n in per.most_common():
                print(f"appliance {aid}: {n} cert(s)")
        """,
    },
    {
        "id": "cert_common_names",
        "group": "Certificates", "subgroup": "Inventory", "category": "Certificates",
        "title": "Distinct certificate common names",
        "name": "Distinct certificate common names",
        "description": "Sorted, de-duplicated list of certificate CNs.",
        "tags": ["certificates", "cn", "dedup"],
        "datasets": ["certificates"],
        "code": """
        rows = data['certificates']['rows']
        cns = sorted({(r.get('common_name') or '').strip() for r in rows if (r.get('common_name') or '').strip()})
        print(f"{len(cns)} distinct common name(s):")
        for c in cns:
            print(' -', c)
        """,
    },

    # ================= Audit & Activity — Users =================
    {
        "id": "audit_by_user",
        "group": "Audit & Activity", "subgroup": "Users", "category": "Audit & Activity",
        "title": "Audit events per user", "name": "Audit events per user",
        "description": "Count recent audit-log events grouped by username.",
        "tags": ["audit", "users", "counter"],
        "datasets": ["audit_recent"],
        "code": """
        from collections import Counter
        rows = data['audit_recent']['rows']
        u = Counter(r.get('username') or '(anon)' for r in rows)
        if not u:
            print('No audit rows.')
        for name, n in u.most_common():
            print(f"{name:16} {n}")
        """,
    },
    {
        "id": "audit_top_actor",
        "group": "Audit & Activity", "subgroup": "Users", "category": "Audit & Activity",
        "title": "Most active user", "name": "Most active user",
        "description": "Identify the busiest actor and their share of activity.",
        "tags": ["audit", "users", "top-n"],
        "datasets": ["audit_recent"],
        "code": """
        from collections import Counter
        rows = data['audit_recent']['rows']
        u = Counter(r.get('username') or '(anon)' for r in rows)
        if not u:
            print('No audit activity.')
        else:
            name, n = u.most_common(1)[0]
            print(f"Most active: {name} with {n} of {len(rows)} events ({100*n/len(rows):.0f}%)")
        """,
    },
    {
        "id": "audit_user_action_matrix",
        "group": "Audit & Activity", "subgroup": "Users", "category": "Audit & Activity",
        "title": "User x action matrix", "name": "User x action matrix",
        "description": "Top 20 (user, action) pairs by frequency.",
        "tags": ["audit", "matrix", "cross-tab"],
        "datasets": ["audit_recent"],
        "code": """
        from collections import Counter
        rows = data['audit_recent']['rows']
        m = Counter((r.get('username') or '(anon)', r.get('action') or '?') for r in rows)
        if not m:
            print('No audit rows.')
        else:
            for (u, a), n in m.most_common(20):
                print(f"{u:12} {a:26} {n}")
        """,
    },

    # ================= Audit & Activity — Actions =================
    {
        "id": "audit_by_action",
        "group": "Audit & Activity", "subgroup": "Actions", "category": "Audit & Activity",
        "title": "Top audit actions", "name": "Top audit actions",
        "description": "The 15 most frequent audit action types.",
        "tags": ["audit", "actions", "top-n"],
        "datasets": ["audit_recent"],
        "code": """
        from collections import Counter
        rows = data['audit_recent']['rows']
        a = Counter(r.get('action') or '?' for r in rows)
        if not a:
            print('No audit rows.')
        else:
            print('Top actions:')
            for act, n in a.most_common(15):
                print(f"{act:28} {n}")
        """,
    },
    {
        "id": "audit_errors",
        "group": "Audit & Activity", "subgroup": "Actions", "category": "Audit & Activity",
        "title": "Error events", "name": "Error events",
        "description": "Audit rows whose action mentions an error.",
        "tags": ["audit", "errors", "filter"],
        "datasets": ["audit_recent"],
        "code": """
        rows = data['audit_recent']['rows']
        errs = [r for r in rows if 'error' in (r.get('action') or '').lower()]
        print(f"{len(errs)} error event(s):")
        for r in errs[:20]:
            print(f"  {str(r.get('timestamp'))[:19]}  {r.get('username')}  {r.get('action')}")
        """,
    },
    {
        "id": "audit_denied",
        "group": "Audit & Activity", "subgroup": "Actions", "category": "Audit & Activity",
        "title": "Access-denied events", "name": "Access-denied events",
        "description": "Audit rows where an action was denied.",
        "tags": ["audit", "denied", "security"],
        "datasets": ["audit_recent"],
        "code": """
        rows = data['audit_recent']['rows']
        d = [r for r in rows if 'deni' in (r.get('action') or '').lower()]
        print(f"{len(d)} access-denied event(s):")
        for r in d[:20]:
            print(f"  {str(r.get('timestamp'))[:19]}  {r.get('username')}  {r.get('target')}")
        """,
    },
    {
        "id": "audit_by_product",
        "group": "Audit & Activity", "subgroup": "Actions", "category": "Audit & Activity",
        "title": "Audit events by product", "name": "Audit events by product",
        "description": "Count audit rows grouped by product tag.",
        "tags": ["audit", "product", "counter"],
        "datasets": ["audit_recent"],
        "code": """
        from collections import Counter
        rows = data['audit_recent']['rows']
        p = Counter(r.get('product') or '(none)' for r in rows)
        if not p:
            print('No audit rows.')
        for prod, n in p.most_common():
            print(f"{prod:12} {n}")
        """,
    },

    # ================= Audit & Activity — Timeline =================
    {
        "id": "audit_by_day",
        "group": "Audit & Activity", "subgroup": "Timeline", "category": "Audit & Activity",
        "title": "Audit volume per day", "name": "Audit volume per day",
        "description": "Daily audit event counts with a tiny inline bar.",
        "tags": ["audit", "timeline", "histogram"],
        "datasets": ["audit_recent"],
        "code": """
        from collections import Counter
        rows = data['audit_recent']['rows']
        days = Counter(str(r.get('timestamp'))[:10] for r in rows if r.get('timestamp'))
        if not days:
            print('No timestamped audit rows.')
        else:
            for day in sorted(days):
                print(f"{day}  {days[day]:4}  {'#' * min(days[day], 50)}")
        """,
    },
    {
        "id": "audit_by_hour",
        "group": "Audit & Activity", "subgroup": "Timeline", "category": "Audit & Activity",
        "title": "Audit volume per hour", "name": "Audit volume per hour",
        "description": "Distribution of audit events across the hour of day.",
        "tags": ["audit", "timeline", "hour"],
        "datasets": ["audit_recent"],
        "code": """
        from collections import Counter
        rows = data['audit_recent']['rows']
        hours = Counter()
        for r in rows:
            ts = str(r.get('timestamp') or '')
            if len(ts) >= 13:
                hours[ts[11:13]] += 1
        if not hours:
            print('No timestamped audit rows.')
        else:
            for h in sorted(hours):
                print(f"{h}:00  {hours[h]}")
        """,
    },
    {
        "id": "audit_recent_slice",
        "group": "Audit & Activity", "subgroup": "Timeline", "category": "Audit & Activity",
        "title": "Ten most recent events", "name": "Ten most recent events",
        "description": "Show the newest ten audit-log rows.",
        "tags": ["audit", "recent", "slice"],
        "datasets": ["audit_recent"],
        "code": """
        rows = data['audit_recent']['rows']
        if not rows:
            print('No audit rows.')
        else:
            print('Most recent events:')
            for r in rows[:10]:
                print(f"{str(r.get('timestamp'))[:19]}  {(r.get('username') or '?'):10}  {r.get('action')}")
        """,
    },
    {
        "id": "audit_login_events",
        "group": "Audit & Activity", "subgroup": "Timeline", "category": "Audit & Activity",
        "title": "Login / logout activity", "name": "Login / logout activity",
        "description": "Summarise and list authentication events.",
        "tags": ["audit", "login", "security"],
        "datasets": ["audit_recent"],
        "code": """
        from collections import Counter
        rows = data['audit_recent']['rows']
        ev = [r for r in rows if (r.get('action') or '') in ('login', 'logout')]
        c = Counter(r.get('action') for r in ev)
        print(f"login: {c.get('login', 0)}   logout: {c.get('logout', 0)}")
        for r in ev[:15]:
            print(f"  {str(r.get('timestamp'))[:19]}  {r.get('username')}  {r.get('action')}")
        """,
    },

    # ================= Reporting & Aggregation =================
    {
        "id": "report_fleet_overview",
        "group": "Reporting & Aggregation", "subgroup": "Summaries", "category": "Reporting & Aggregation",
        "title": "Fleet overview report", "name": "Fleet overview report",
        "description": "Combine live appliances with the counts summary row.",
        "tags": ["report", "fleet", "cross-reference"],
        "datasets": ["fleet_appliances", "fleet_counts"],
        "code": """
        from collections import Counter
        apps = data['fleet_appliances']['rows']
        counts = data['fleet_counts']['rows']
        print('=== Fleet overview ===')
        print(f"Appliances: {len(apps)}")
        for k, n in Counter(r.get('kind') or 'unknown' for r in apps).most_common():
            print(f"  {k:12} {n}")
        if counts:
            c = counts[0]
            print(f"Server policies (db): {c.get('server_policies')}")
            print(f"Certificates (db)   : {c.get('certificates')}")
        """,
    },
    {
        "id": "report_policy_health",
        "group": "Reporting & Aggregation", "subgroup": "Summaries", "category": "Reporting & Aggregation",
        "title": "Policy health report", "name": "Policy health report",
        "description": "Enabled / WAF / traffic-logging rates across policies.",
        "tags": ["report", "policies", "health"],
        "datasets": ["server_policies_full"],
        "code": """
        rows = data['server_policies_full']['rows']
        if not rows:
            print('No policies to assess.')
        else:
            n = len(rows)
            waf = sum(1 for r in rows if (r.get('wpp') or '').strip())
            enabled = sum(1 for r in rows if (r.get('status') or '').lower() == 'enable')
            tlog = sum(1 for r in rows if (r.get('traffic_log') or '').lower() == 'enable')
            print(f"Policies         : {n}")
            print(f"Enabled          : {enabled} ({100*enabled/n:.0f}%)")
            print(f"WAF-protected    : {waf} ({100*waf/n:.0f}%)")
            print(f"Traffic-logging  : {tlog} ({100*tlog/n:.0f}%)")
        """,
    },
    {
        "id": "agg_policies_per_device_stats",
        "group": "Reporting & Aggregation", "subgroup": "Summaries", "category": "Reporting & Aggregation",
        "title": "Policies-per-device statistics", "name": "Policies-per-device statistics",
        "description": "min / mean / median / max of policies per device.",
        "tags": ["report", "statistics", "policies"],
        "datasets": ["server_policies_full"],
        "code": """
        import statistics
        from collections import Counter
        rows = data['server_policies_full']['rows']
        per = Counter(r.get('device') or '?' for r in rows)
        vals = list(per.values())
        if not vals:
            print('No policies.')
        else:
            print(f"devices with policies: {len(vals)}")
            print(f"min/mean/median/max  : {min(vals)} / {statistics.mean(vals):.1f} / "
                  f"{statistics.median(vals)} / {max(vals)}")
        """,
    },
    {
        "id": "agg_pool_members_summary",
        "group": "Reporting & Aggregation", "subgroup": "Summaries", "category": "Reporting & Aggregation",
        "title": "Pool distribution summary", "name": "Pool distribution summary",
        "description": "Total pools and average per appliance.",
        "tags": ["report", "pools", "statistics"],
        "datasets": ["server_pools"],
        "code": """
        import statistics
        from collections import Counter
        rows = data['server_pools']['rows']
        per = Counter(str(r.get('appliance_id') or '?') for r in rows)
        vals = list(per.values())
        if not vals:
            print('No pools.')
        else:
            print(f"total pools: {sum(vals)} across {len(vals)} appliance(s)")
            print(f"avg pools/appliance: {statistics.mean(vals):.1f}")
        """,
    },
    {
        "id": "report_waf_scorecard",
        "group": "Reporting & Aggregation", "subgroup": "Summaries", "category": "Reporting & Aggregation",
        "title": "WAF coverage scorecard", "name": "WAF coverage scorecard",
        "description": "Letter-grade the fleet's WAF coverage with a bar.",
        "tags": ["report", "waf", "scorecard"],
        "datasets": ["server_policies_full"],
        "code": """
        rows = data['server_policies_full']['rows']
        if not rows:
            print('No policies — scorecard N/A.')
        else:
            n = len(rows)
            waf = sum(1 for r in rows if (r.get('wpp') or '').strip())
            pct = 100 * waf / n
            grade = ('A' if pct >= 90 else 'B' if pct >= 75 else 'C'
                     if pct >= 50 else 'D' if pct > 0 else 'F')
            bar = '#' * int(pct / 5)
            print(f"WAF coverage {pct:5.1f}%  [{bar:<20}]  grade {grade}")
        """,
    },

    # ================= Data Quality / Audits =================
    {
        "id": "dq_policy_checklist",
        "group": "Data Quality / Audits", "subgroup": "Checks", "category": "Data Quality / Audits",
        "title": "Per-policy hygiene checklist", "name": "Per-policy hygiene checklist",
        "description": "Flag no-WAF / disabled / monitor-only issues per policy.",
        "tags": ["quality", "policies", "checklist"],
        "datasets": ["server_policies_full"],
        "code": """
        rows = data['server_policies_full']['rows']
        if not rows:
            print('No policies.')
        else:
            for r in rows:
                issues = []
                if not (r.get('wpp') or '').strip():
                    issues.append('no-WAF')
                if (r.get('status') or '').lower() != 'enable':
                    issues.append('disabled')
                if (r.get('monitor_mode') or '').lower() == 'enable':
                    issues.append('monitor-only')
                tag = 'OK' if not issues else ','.join(issues)
                print(f"{(r.get('device') or '?'):10} {(r.get('policy') or '?'):20} {tag}")
        """,
    },
    {
        "id": "dq_empty_fields_policies",
        "group": "Data Quality / Audits", "subgroup": "Checks", "category": "Data Quality / Audits",
        "title": "Blank-value counts per column", "name": "Blank-value counts per column",
        "description": "For each policy column, how many rows are blank.",
        "tags": ["quality", "completeness", "columns"],
        "datasets": ["server_policies_full"],
        "code": """
        from collections import Counter
        ds = data['server_policies_full']
        rows = ds['rows']
        if not rows:
            print('No policies.')
        else:
            cols = ds['columns'] or list(rows[0].keys())
            blanks = Counter()
            for r in rows:
                for c in cols:
                    if not str(r.get(c) or '').strip():
                        blanks[c] += 1
            print('Blank-value counts by column:')
            for c in cols:
                print(f"  {c:16} {blanks.get(c, 0)}/{len(rows)}")
        """,
    },
    {
        "id": "dq_duplicate_policy_names",
        "group": "Data Quality / Audits", "subgroup": "Checks", "category": "Data Quality / Audits",
        "title": "Policy names shared across devices",
        "name": "Policy names shared across devices",
        "description": "Find policy names that appear on more than one device.",
        "tags": ["quality", "duplicates", "policies"],
        "datasets": ["server_policies_full"],
        "code": """
        from collections import defaultdict
        rows = data['server_policies_full']['rows']
        byname = defaultdict(list)
        for r in rows:
            byname[r.get('policy') or '?'].append(r.get('device') or '?')
        dupes = {k: v for k, v in byname.items() if len(v) > 1}
        if not dupes:
            print('No policy names shared across devices.')
        else:
            print('Policy names used on multiple devices:')
            for name, devs in sorted(dupes.items()):
                print(f"  {name}: {', '.join(sorted(devs))}")
        """,
    },
    {
        "id": "dq_cert_no_expiry",
        "group": "Data Quality / Audits", "subgroup": "Checks", "category": "Data Quality / Audits",
        "title": "Certificates missing an expiry date",
        "name": "Certificates missing an expiry date",
        "description": "Managed certs with no not-after recorded.",
        "tags": ["quality", "certificates", "missing"],
        "datasets": ["certificates"],
        "code": """
        rows = data['certificates']['rows']
        noexp = [r for r in rows if not str(r.get('not_after') or '').strip()]
        print(f"{len(noexp)} of {len(rows)} certificate(s) have no expiry date recorded")
        for r in noexp:
            print(' -', r.get('common_name') or '(no CN)', 'appliance', r.get('appliance_id'))
        """,
    },
    {
        "id": "dq_pool_naming",
        "group": "Data Quality / Audits", "subgroup": "Checks", "category": "Data Quality / Audits",
        "title": "Pool naming-convention audit", "name": "Pool naming-convention audit",
        "description": "Pools whose name does not start with the 'pool-' prefix.",
        "tags": ["quality", "pools", "naming"],
        "datasets": ["server_pools"],
        "code": """
        rows = data['server_pools']['rows']
        bad = [r for r in rows if not (r.get('name') or '').startswith('pool-')]
        print(f"{len(bad)} of {len(rows)} pool(s) do not follow the 'pool-' convention:")
        for r in bad:
            print(' -', r.get('name') or '(unnamed)')
        if rows and not bad:
            print('(all pools follow the convention)')
        """,
    },

    # ================= Cross-reference =================
    {
        "id": "xref_policy_pool",
        "group": "Cross-reference", "subgroup": "Joins", "category": "Cross-reference",
        "title": "Resolve each policy to its pool", "name": "Resolve each policy to its pool",
        "description": "Join policies to pools by (appliance, pool name).",
        "tags": ["cross-reference", "policies", "pools"],
        "datasets": ["server_policies_full", "server_pools"],
        "code": """
        rows = data['server_policies_full']['rows']
        pools = data['server_pools']['rows']
        poolnames = {(str(p.get('appliance_id')), p.get('name')) for p in pools}
        if not rows:
            print('No policies.')
        else:
            print('Policy -> pool resolution:')
            for r in rows:
                sp = (r.get('server_pool') or '').strip()
                if not sp:
                    state = '(no pool / content-routing)'
                elif (str(r.get('appliance_id')), sp) in poolnames:
                    state = 'OK -> ' + sp
                else:
                    state = 'MISSING pool: ' + sp
                print(f"  {(r.get('policy') or '?'):20} {state}")
        """,
    },
    {
        "id": "xref_policy_device",
        "group": "Cross-reference", "subgroup": "Joins", "category": "Cross-reference",
        "title": "Policy count by device name", "name": "Policy count by device name",
        "description": "Join policies to appliances to label counts by name.",
        "tags": ["cross-reference", "policies", "device"],
        "datasets": ["server_policies_full", "fleet_appliances"],
        "code": """
        from collections import Counter
        apps = {str(a.get('id')): a.get('name') for a in data['fleet_appliances']['rows']}
        rows = data['server_policies_full']['rows']
        per = Counter(str(r.get('appliance_id')) for r in rows)
        if not per:
            print('No policies.')
        else:
            for aid, n in per.most_common():
                print(f"{apps.get(aid, 'appliance ' + aid):16} {n} policy(ies)")
        """,
    },
    {
        "id": "xref_missing_pool",
        "group": "Cross-reference", "subgroup": "Joins", "category": "Cross-reference",
        "title": "Policies referencing an absent pool",
        "name": "Policies referencing an absent pool",
        "description": "Policies whose server_pool is not present in the pool cache.",
        "tags": ["cross-reference", "orphan", "integrity"],
        "datasets": ["server_policies_full", "server_pools"],
        "code": """
        rows = data['server_policies_full']['rows']
        pools = data['server_pools']['rows']
        known = {(str(p.get('appliance_id')), p.get('name')) for p in pools}
        orphans = [r for r in rows if (r.get('server_pool') or '').strip()
                   and (str(r.get('appliance_id')), r.get('server_pool')) not in known]
        print(f"{len(orphans)} policy(ies) reference a pool not in the cache:")
        for r in orphans:
            print(f"  {r.get('device')}/{r.get('policy')} -> {r.get('server_pool')}")
        if rows and not orphans:
            print('(every referenced pool exists)')
        """,
    },
    {
        "id": "xref_pool_usage",
        "group": "Cross-reference", "subgroup": "Joins", "category": "Cross-reference",
        "title": "Pool usage and unused pools", "name": "Pool usage and unused pools",
        "description": "Count policies per pool and flag unused pools.",
        "tags": ["cross-reference", "pools", "usage"],
        "datasets": ["server_pools", "server_policies_full"],
        "code": """
        from collections import Counter
        pools = data['server_pools']['rows']
        rows = data['server_policies_full']['rows']
        used = Counter((str(r.get('appliance_id')), r.get('server_pool'))
                       for r in rows if (r.get('server_pool') or '').strip())
        if not pools:
            print('No pools.')
        else:
            for p in sorted(pools, key=lambda p: (str(p.get('appliance_id')), p.get('name') or '')):
                n = used.get((str(p.get('appliance_id')), p.get('name')), 0)
                flag = '' if n else '  <- UNUSED'
                print(f"  {(p.get('name') or '?'):20} used by {n} policy(ies){flag}")
        """,
    },
    {
        "id": "xref_device_no_policies",
        "group": "Cross-reference", "subgroup": "Joins", "category": "Cross-reference",
        "title": "Devices with no cached policies", "name": "Devices with no cached policies",
        "description": "Appliances that carry zero cached server policies.",
        "tags": ["cross-reference", "device", "idle"],
        "datasets": ["fleet_appliances", "server_policies_full"],
        "code": """
        rows = data['server_policies_full']['rows']
        apps = data['fleet_appliances']['rows']
        with_pol = {str(r.get('appliance_id')) for r in rows}
        idle = [a for a in apps if str(a.get('id')) not in with_pol]
        print(f"{len(idle)} of {len(apps)} device(s) have no cached server policies:")
        for a in idle:
            print(' -', a.get('name'), '(', a.get('kind'), ')')
        """,
    },

    # ================= Formatting & Export — Export =================
    {
        "id": "fmt_csv_appliances",
        "group": "Formatting & Export", "subgroup": "Export", "category": "Formatting & Export",
        "title": "Export appliances as CSV", "name": "Export appliances as CSV",
        "description": "Emit the appliance inventory as CSV text.",
        "tags": ["format", "csv", "export"],
        "datasets": ["fleet_appliances"],
        "code": """
        import csv, io
        ds = data['fleet_appliances']
        rows = ds['rows']
        cols = ds['columns'] or (list(rows[0].keys()) if rows else [])
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(cols)
        for r in rows:
            w.writerow([r.get(c, '') for c in cols])
        print(buf.getvalue().rstrip() or '(no rows)')
        """,
    },
    {
        "id": "fmt_markdown_policies",
        "group": "Formatting & Export", "subgroup": "Export", "category": "Formatting & Export",
        "title": "Policies as a Markdown table", "name": "Policies as a Markdown table",
        "description": "Render selected policy columns as GitHub Markdown.",
        "tags": ["format", "markdown", "export"],
        "datasets": ["server_policies_full"],
        "code": """
        rows = data['server_policies_full']['rows']
        cols = ['device', 'policy', 'deployment_mode', 'status', 'wpp']
        if not rows:
            print('_No policies._')
        else:
            print('| ' + ' | '.join(cols) + ' |')
            print('|' + '|'.join(['---'] * len(cols)) + '|')
            for r in rows:
                print('| ' + ' | '.join(str(r.get(c) or '') for c in cols) + ' |')
        """,
    },
    {
        "id": "fmt_json_pretty",
        "group": "Formatting & Export", "subgroup": "Export", "category": "Formatting & Export",
        "title": "Pretty-print a filtered slice", "name": "Pretty-print a filtered slice",
        "description": "JSON dump of policies lacking a WAF profile.",
        "tags": ["format", "json", "filter"],
        "datasets": ["server_policies_full"],
        "code": """
        import json
        rows = data['server_policies_full']['rows']
        slim = [{'device': r.get('device'), 'policy': r.get('policy')}
                for r in rows if not (r.get('wpp') or '').strip()]
        print(json.dumps({'policies_without_waf': slim, 'count': len(slim)}, indent=2))
        """,
    },

    # ================= Formatting & Export — Charts =================
    {
        "id": "fmt_ascii_bar_kind",
        "group": "Formatting & Export", "subgroup": "Charts", "category": "Formatting & Export",
        "title": "ASCII bar chart of device kinds",
        "name": "ASCII bar chart of device kinds",
        "description": "Horizontal ASCII bars for appliance kind counts.",
        "tags": ["format", "chart", "ascii"],
        "datasets": ["fleet_appliances"],
        "code": """
        from collections import Counter
        rows = data['fleet_appliances']['rows']
        c = Counter(r.get('kind') or 'unknown' for r in rows)
        if not c:
            print('No appliances.')
        else:
            mx = max(c.values())
            for k, n in c.most_common():
                bar = '#' * int(round(20 * n / mx))
                print(f"{k:12} {bar} {n}")
        """,
    },
    {
        "id": "fmt_ascii_bar_actions",
        "group": "Formatting & Export", "subgroup": "Charts", "category": "Formatting & Export",
        "title": "ASCII bar chart of top actions",
        "name": "ASCII bar chart of top actions",
        "description": "Horizontal ASCII bars for the top-10 audit actions.",
        "tags": ["format", "chart", "audit"],
        "datasets": ["audit_recent"],
        "code": """
        from collections import Counter
        rows = data['audit_recent']['rows']
        top = Counter(r.get('action') or '?' for r in rows).most_common(10)
        if not top:
            print('No audit rows.')
        else:
            mx = top[0][1]
            for act, n in top:
                bar = '#' * int(round(30 * n / mx))
                print(f"{act:26} {bar} {n}")
        """,
    },

    # ================= Formatting & Export — Tables =================
    {
        "id": "fmt_table_pools",
        "group": "Formatting & Export", "subgroup": "Tables", "category": "Formatting & Export",
        "title": "Auto-width pool table", "name": "Auto-width pool table",
        "description": "Column-aligned table of pools with computed widths.",
        "tags": ["format", "table", "pools"],
        "datasets": ["server_pools"],
        "code": """
        rows = data['server_pools']['rows']
        if not rows:
            print('No pools.')
        else:
            cols = ['name', 'type', 'protocol', 'appliance_id']
            widths = {c: max([len(c)] + [len(str(r.get(c) or '')) for r in rows]) for c in cols}
            print('  '.join(c.ljust(widths[c]) for c in cols))
            print('  '.join('-' * widths[c] for c in cols))
            for r in sorted(rows, key=lambda r: r.get('name') or ''):
                print('  '.join(str(r.get(c) or '').ljust(widths[c]) for c in cols))
        """,
    },
    {
        "id": "fmt_dedup_devices",
        "group": "Formatting & Export", "subgroup": "Tables", "category": "Formatting & Export",
        "title": "Device set difference", "name": "Device set difference",
        "description": "Compare device names in inventory vs. policy rows.",
        "tags": ["format", "set", "cross-reference"],
        "datasets": ["fleet_appliances", "server_policies_full"],
        "code": """
        apps = {a.get('name') for a in data['fleet_appliances']['rows'] if a.get('name')}
        polic = {r.get('device') for r in data['server_policies_full']['rows'] if r.get('device')}
        print('In inventory but no policies:', ', '.join(sorted(apps - polic)) or '(none)')
        print('In policies but not inventory:', ', '.join(sorted(polic - apps)) or '(none)')
        print('In both                     :', ', '.join(sorted(apps & polic)) or '(none)')
        """,
    },

    # ================= Automation (scheduled actions) =================
    {
        "id": "sched_disabled",
        "group": "Automation", "subgroup": "", "category": "Automation",
        "title": "Disabled scheduled actions", "name": "Disabled scheduled actions",
        "description": "Configured automation entries that are turned off.",
        "tags": ["automation", "scheduled", "disabled"],
        "datasets": ["scheduled_actions"],
        "code": """
        rows = data['scheduled_actions']['rows']
        if not rows:
            print('No scheduled actions configured.')
        else:
            off = [r for r in rows if str(r.get('enabled')).lower() in ('false', '0', 'disable', 'no', 'none', '')]
            print(f"{len(off)} of {len(rows)} scheduled action(s) are disabled:")
            for r in off:
                print(' -', r.get('name'), '/', r.get('action_key'))
        """,
    },
    {
        "id": "sched_next_runs",
        "group": "Automation", "subgroup": "", "category": "Automation",
        "title": "Upcoming scheduled runs", "name": "Upcoming scheduled runs",
        "description": "Scheduled actions sorted by their next-run time.",
        "tags": ["automation", "scheduled", "sort"],
        "datasets": ["scheduled_actions"],
        "code": """
        rows = data['scheduled_actions']['rows']
        withrun = [r for r in rows if str(r.get('next_run') or '').strip()]
        withrun.sort(key=lambda r: str(r.get('next_run')))
        if not withrun:
            print('No scheduled actions with a next-run time.')
        else:
            print('Upcoming scheduled actions:')
            for r in withrun[:15]:
                print(f"  {str(r.get('next_run'))[:19]}  {r.get('name')}  ({r.get('action_key')})")
        """,
    },
    {
        "id": "sched_by_kind",
        "group": "Automation", "subgroup": "", "category": "Automation",
        "title": "Scheduled actions by schedule kind",
        "name": "Scheduled actions by schedule kind",
        "description": "Count automation entries grouped by schedule kind.",
        "tags": ["automation", "scheduled", "counter"],
        "datasets": ["scheduled_actions"],
        "code": """
        from collections import Counter
        rows = data['scheduled_actions']['rows']
        k = Counter(r.get('schedule_kind') or '(none)' for r in rows)
        if not k:
            print('No scheduled actions.')
        else:
            for kind, n in k.most_common():
                print(f"{kind:14} {n}")
        """,
    },
]

# Normalise every stored ``code``: strip the source indentation used for
# readability above so the sandbox receives clean top-level Python.
for _e in _EXAMPLES:
    _e["code"] = _textwrap.dedent(_e["code"]).strip() + "\n"


def all_examples() -> list[dict]:
    """Return the full list of example dicts (code already dedented)."""
    return _EXAMPLES


def categories() -> list[str]:
    """Ordered, de-duplicated list of top-level group names."""
    seen: list[str] = []
    for e in _EXAMPLES:
        g = e.get("group")
        if g and g not in seen:
            seen.append(g)
    return seen
