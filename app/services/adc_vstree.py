"""FortiADC virtual-server tree and the child-table depth behind it.

The ADC counterpart of the FortiWeb deep layer. Two halves, one data shape:

* **Depth capture** (:func:`child_plan`, :func:`capture_children`). The
  rediscovery sweep reads every registered parent table; the 27
  ``<parent>_child_<x>`` tables need a ``?pkey=<parent mkey>`` and were never
  read. Measured on fortiadc10 (7.6.7, 2026-10-12): pool members, routing and
  rewriting match conditions and the interface lists come EMBEDDED in their
  parent row, but the members of local / CA / intermediate-CA certificate
  groups and of schedule groups are served ONLY by the child table. Without
  this pass a VS's certificate chain cannot be drawn at all.

* **The tree** (:func:`build_vs_tree`). Every reference a virtual server
  makes, followed to the end: content routing -> pool -> member -> real server
  + health check, client SSL profile -> certificate group -> certificates,
  auth policy -> user group -> RADIUS / LDAP / local user, WAF profile -> its
  sub-profiles, and so on. The reference map is EXPLICIT and measured: a
  lookup by value alone was tried and is wrong (a VS ``comments`` text matched
  a service name, numeric timeouts matched reputation rows).

The index (``{"tables": {logical: {mkey: row}}, "children": {child: {pkey:
[rows]}}}``) is built either live (:func:`index_live`, the VS Inspector) or
from the last rediscovery (:func:`index_from_capture`, no device call), and
the same builder draws both.
"""
from __future__ import annotations

from typing import Any, Callable

from .inspector import _attrs, render_tree

CHILD_MARK = "_child_"

#: Depth guard: the deepest measured chain is VS -> client SSL profile ->
#: certificate group -> member -> certificate (5). Past this the tree stops
#: and says so instead of recursing.
MAX_DEPTH = 8


class ChildCaptureStopped(Exception):
    """A Stop was honoured between two child-table reads."""

    def __init__(self, done: int, total: int, current: str = ""):
        super().__init__(f"stopped at {done}/{total}")
        self.done, self.total, self.current = done, total, current


# --------------------------------------------------------------------------- #
#  Child tables                                                               #
# --------------------------------------------------------------------------- #

def split_child(name: str) -> tuple[str, str]:
    """``load_balance_pool_child_pool_member`` -> ``(load_balance_pool,
    pool_member)``; ``("", "")`` for a name that is not a child table."""
    if CHILD_MARK not in (name or ""):
        return "", ""
    parent, sub = name.split(CHILD_MARK, 1)
    return parent, sub


def child_plan(registry: dict | None = None) -> list[dict]:
    """Every registered ADC child table with the parent it hangs off. Must run
    in app context when ``registry`` is not given (the registry is DB-first).
    A path that changes the box on GET is never planned (same rule as the
    sweep: the registry is editable)."""
    from .adc_ops import side_effect_path
    if registry is None:
        from ..registry import loader
        registry = loader.load_adc_registry()
    plan = []
    for name, urn in sorted(registry.items()):
        parent, sub = split_child(name)
        if not parent or side_effect_path(urn or ""):
            continue
        plan.append({"name": name, "urn": urn, "parent": parent, "sub": sub})
    return plan


def parent_rows(sections: dict) -> dict[str, list[dict]]:
    """The sweep's ``{section: {endpoint: rows}}`` flattened to
    ``{endpoint: rows}``."""
    out: dict[str, list[dict]] = {}
    for eps in (sections or {}).values():
        for name, rows in (eps or {}).items():
            out[name] = [r for r in rows or [] if isinstance(r, dict)]
    return out


def capture_children(probe: Callable, plan: list[dict], parents: dict,
                     *, should_stop: Callable[[], bool] = lambda: False,
                     progress: Callable[[dict], None] | None = None) -> dict:
    """Read every child table once per parent row (``?pkey=<mkey>``).

    ``probe(ep)`` is the sweep's ADC probe: ``(rows, verdict, detail)``.
    A table the box answers 404 for is NOT served by this build: it is
    recorded once as absent and its other parents are skipped (asking again
    per parent would only repeat the same 404). Raises
    :class:`ChildCaptureStopped` when a stop is asked between two reads.
    """
    work = []
    for ep in plan:
        for row in parents.get(ep["parent"]) or []:
            mkey = row.get("mkey")
            if mkey is not None and str(mkey) != "":
                work.append((ep, str(mkey)))
    total = len(work)
    tables: dict[str, dict[str, list]] = {}
    ledger: dict[str, dict] = {}
    errors: list[dict] = []
    absent: set[str] = set()
    reads = rows_total = 0
    for i, (ep, mkey) in enumerate(work):
        if ep["name"] in absent:
            continue
        if should_stop():
            raise ChildCaptureStopped(i, total, f"{ep['name']} ← {mkey}")
        if progress:
            progress({"total": total, "done": i, "current": f"{ep['name']} ← {mkey}"})
        reads += 1
        try:
            rows, verdict, detail = probe({**ep, "params": {"pkey": mkey}})
        except Exception as exc:  # noqa: BLE001 — one read never sinks the pass
            rows, verdict, detail = [], "error", f"{type(exc).__name__}: {exc}"[:200]
        led = ledger.setdefault(ep["name"], {"urn": ep["urn"], "parent": ep["parent"],
                                             "verdict": "ok", "parents": 0, "rows": 0})
        if verdict == "absent":
            absent.add(ep["name"])
            led.update(verdict="absent", detail=(detail or "")[:200])
            continue
        if verdict != "ok":
            errors.append({"endpoint": ep["name"], "pkey": mkey,
                           "error": (detail or "unknown error")[:200]})
            led["verdict"] = "error"
            continue
        rows = [r for r in rows or [] if isinstance(r, dict)]
        led["parents"] += 1
        led["rows"] += len(rows)
        rows_total += len(rows)
        if rows:
            tables.setdefault(ep["name"], {})[mkey] = rows
    if progress:
        progress({"total": total, "done": total, "current": ""})
    return {"children": tables, "endpoint_status": ledger, "errors": errors,
            "reads": reads, "rows": rows_total, "pairs": total}


# --------------------------------------------------------------------------- #
#  Index                                                                      #
# --------------------------------------------------------------------------- #

def _by_mkey(rows) -> dict[str, dict]:
    return {str(r.get("mkey")): r for r in rows or []
            if isinstance(r, dict) and r.get("mkey") is not None}


def index_from_capture(snapshot: dict, deep: dict | None) -> dict:
    """The tree's index out of the last sweep snapshot and its depth capture
    (``_config.json`` + ``_deep.json``). No device call."""
    tables = {name: _by_mkey(rows)
              for name, rows in parent_rows((snapshot or {}).get("sections")).items()}
    return {"tables": tables, "children": dict((deep or {}).get("children") or {})}


def _tables_needed() -> set[str]:
    need = {"load_balance_virtual_server"}
    for refs in REFS.values():
        for _f, _l, target in refs:
            need.add(target)
    for parent, _sub, _emb, _f, target in MEMBERS.values():
        need.add(parent)
        if target:
            need.add(target)
    need.update(WAF_SUBS_OF)
    return need


def index_live(client, registry: dict | None = None) -> dict:
    """Read, once, every table the tree can reach plus the child tables of the
    groups it draws. ``client`` is a connected FortiADC client."""
    if registry is None:
        from ..registry import loader
        registry = loader.load_adc_registry()
    tables: dict[str, dict] = {}
    errors: list[dict] = []

    def _read(names) -> None:
        for name in sorted(names):
            if name not in registry or name in tables:
                continue
            rows, err = client.list_with_error(name)
            if err:
                errors.append({"endpoint": name, "error": str(err)[:200]})
                continue
            tables[name] = _by_mkey(rows)

    _read(_tables_needed())
    # Only the WAF sub-profile tables a profile actually names: the registry
    # has ~40 ``security_waf_*`` tables and reading all of them doubled the
    # page's time for nothing the tree draws.
    _read({f"security_waf_{field}"
           for table in WAF_SUBS_OF
           for row in (tables.get(table) or {}).values()
           for field, value in row.items() if _values(value)})
    children: dict[str, dict] = {}
    for child, (parent, *_rest) in MEMBERS.items():
        if child not in registry:
            continue
        for mkey in tables.get(parent, {}):
            rows, err = client.list_with_error(child, pkey=mkey)
            if err:
                errors.append({"endpoint": child, "pkey": mkey, "error": str(err)[:200]})
                continue
            rows = [r for r in rows or [] if isinstance(r, dict)]
            if rows:
                children.setdefault(child, {})[mkey] = rows
    return {"tables": tables, "children": children, "errors": errors}


# --------------------------------------------------------------------------- #
#  Reference map (measured on fortiadc10 7.6.7, 2026-10-12)                   #
# --------------------------------------------------------------------------- #

#: ``table -> ((field, label, target table), ...)``. List fields are
#: space-separated on the ADC (``content-routing-list: "cr-a cr-b "``); every
#: value is split. Field spellings are the box's own, mixed ``-`` and ``_``
#: included (``client_ssl_profile`` beside ``waf-profile``).
REFS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "load_balance_virtual_server": (
        ("interface", "Interface", "system_interface"),
        ("profile", "Profile", "load_balance_profile"),
        ("client_ssl_profile", "Client SSL Profile", "load_balance_client_ssl_profile"),
        ("method", "Method", "load_balance_method"),
        ("persistence", "Persistence", "load_balance_persistence"),
        ("pool", "Real Server Pool", "load_balance_pool"),
        ("content-routing-list", "Content Routing", "load_balance_content_routing"),
        ("content-rewriting-list", "Content Rewriting", "load_balance_content_rewriting"),
        ("schedule-pool-list", "Schedule Pool", "load_balance_schedule_pool"),
        ("clone-pool", "Clone Pool", "load_balance_clone_pool"),
        ("source-pool-list", "Source (SNAT) Pool", "load_balance_ippool"),
        ("connection-pool", "Connection Pool", "load_balance_connection_pool"),
        ("waf-profile", "WAF Profile", "security_waf_profile"),
        ("av-profile", "Antivirus Profile", "security_antivirus_profile"),
        ("ips_profile", "IPS Profile", "security_ips_profile"),
        ("dos_profile", "DoS Profile", "security_dos_dos_protection_profile"),
        ("ztna_profile", "ZTNA Profile", "security_ztna_profile"),
        ("auth_policy", "Auth Policy", "load_balance_auth_policy"),
        ("captcha-profile", "Captcha Profile", "load_balance_captcha_profile"),
        ("error-page", "Error Page", "load_balance_error_page"),
        ("l2-exception-list", "L2 Exception List", "load_balance_l2_exception_list"),
        ("pagespeed", "PageSpeed", "load_balance_pagespeed"),
        ("scripting_list", "Script", "system_scripting"),
        ("stream_scripting_list", "Stream Script", "system_stream_scripting"),
        ("traffic-group", "Traffic Group", "system_traffic_group"),
    ),
    "load_balance_content_routing": (
        ("pool", "Real Server Pool", "load_balance_pool"),
        ("method", "Method", "load_balance_method"),
        ("persistence", "Persistence", "load_balance_persistence"),
        ("schedule-pool-list", "Schedule Pool", "load_balance_schedule_pool"),
    ),
    "load_balance_schedule_pool": (
        ("schedule", "Schedule Group", "system_schedule_group"),
        ("pool", "Real Server Pool", "load_balance_pool"),
    ),
    "load_balance_pool": (
        ("health_check_list", "Health Check", "system_health_check"),
        ("rs_profile", "Real Server SSL Profile", "load_balance_real_server_ssl_profile"),
    ),
    "load_balance_pool_child_pool_member": (
        ("real_server_id", "Real Server", "load_balance_real_server"),
        ("m_health_check_list", "Health Check", "system_health_check"),
        ("rs_profile", "Real Server SSL Profile", "load_balance_real_server_ssl_profile"),
    ),
    "load_balance_client_ssl_profile": (
        ("local_certificate_group", "Local Certificate Group",
         "system_certificate_local_cert_group"),
        ("client_certificate_verify", "Client Certificate Verify",
         "system_certificate_certificate_verify"),
        ("forward_proxy_local_signing_ca", "Forward-Proxy Signing CA",
         "system_certificate_local"),
        ("forward_proxy_certificate_caching", "Certificate Caching",
         "load_balance_certificate_caching"),
    ),
    "load_balance_profile": (
        ("http2_profile", "HTTP/2 Profile", "load_balance_http2_profile"),
        ("http3_profile", "HTTP/3 Profile", "load_balance_http3_profile"),
        ("compression", "Compression", "load_balance_compression"),
        ("ram_caching", "RAM Caching", "load_balance_caching"),
        ("geoip_list", "GeoIP List", "load_balance_geoip_list"),
        ("local_cert_group", "Local Certificate Group",
         "system_certificate_local_cert_group"),
    ),
    "system_certificate_local_cert_group_child_group_member": (
        ("local_cert", "Local Certificate", "system_certificate_local"),
        ("intermediate_cag", "Intermediate CA Group",
         "system_certificate_intermediate_ca_group"),
    ),
    "system_certificate_intermediate_ca_group_child_group_member": (
        ("intmed_ca", "Intermediate CA", "system_certificate_intermediate_ca"),
    ),
    "system_certificate_ca_group_child_group_member": (
        ("ca", "CA", "system_certificate_ca"),
    ),
    "system_certificate_certificate_verify_child_group_member": (
        ("ca", "CA", "system_certificate_ca"),
        ("ocsp", "OCSP", "system_certificate_ocsp"),
        ("crl", "CRL", "system_certificate_crl"),
    ),
    "load_balance_auth_policy.member": (
        ("user_group_id", "User Group", "user_user_group"),
    ),
    "user_user_group.member": (
        ("local_user", "Local User", "user_local"),
        ("radius_server", "RADIUS Server", "user_radius"),
        ("ldap_server", "LDAP Server", "user_ldap"),
    ),
}

#: Member rows of a group: ``child table -> (parent table, child suffix,
#: embedded field, label, target)``. The child table wins when it answered;
#: otherwise the list embedded in the parent row is used (measured: routing
#: matches and pool members are embedded, certificate-group members are not).
MEMBERS: dict[str, tuple[str, str, str, str, str]] = {
    "load_balance_pool_child_pool_member":
        ("load_balance_pool", "pool_member", "pool_member", "Member", ""),
    "load_balance_clone_pool_child_pool_member":
        ("load_balance_clone_pool", "pool_member", "pool_member", "Member", ""),
    "load_balance_content_routing_child_match_condition":
        ("load_balance_content_routing", "match_condition", "match", "Match", ""),
    "load_balance_content_rewriting_child_match_condition":
        ("load_balance_content_rewriting", "match_condition", "match", "Match", ""),
    "system_certificate_local_cert_group_child_group_member":
        ("system_certificate_local_cert_group", "group_member", "group_member",
         "Member", ""),
    "system_certificate_intermediate_ca_group_child_group_member":
        ("system_certificate_intermediate_ca_group", "group_member", "group_member",
         "Member", ""),
    "system_certificate_ca_group_child_group_member":
        ("system_certificate_ca_group", "group_member", "group_member", "Member", ""),
    "system_certificate_certificate_verify_child_group_member":
        ("system_certificate_certificate_verify", "group_member", "member",
         "Member", ""),
    "system_schedule_group_child_schedule_member":
        ("system_schedule_group", "schedule_member", "member_list", "Schedule", ""),
    "load_balance_ippool_child_node_member":
        ("load_balance_ippool", "node_member", "node_member", "Node", ""),
    "load_balance_l2_exception_list_child_member":
        ("load_balance_l2_exception_list", "member", "member", "Member", ""),
}

#: Lists embedded in a parent row with NO child table behind them.
EMBEDDED: dict[str, tuple[tuple[str, str, str], ...]] = {
    "load_balance_auth_policy": (("member", "Rule", "load_balance_auth_policy.member"),),
    "user_user_group": (("member", "Member", "user_user_group.member"),),
}

#: A WAF profile names its sub-profiles by the table's own suffix
#: (``web_attack_signature`` -> ``security_waf_web_attack_signature``,
#: measured on the three lab profiles). Read by name, not by a fixed list, so
#: a sub-profile type a newer build adds is still followed.
WAF_SUBS_OF = {"security_waf_profile"}

#: What each object's own line shows.
ATTRS: dict[str, tuple[str, ...]] = {
    "load_balance_virtual_server": ("type", "status", "availability", "interface",
                                    "packet-fwd-method"),
    "load_balance_pool": ("pool_type", "type"),
    "load_balance_pool_child_pool_member": ("status", "availability", "weight",
                                            "backup", "ssl"),
    "load_balance_real_server": ("address", "address6", "type", "status"),
    "system_health_check": ("type", "port", "send_string", "receive_string"),
    "load_balance_content_routing": ("type",),
    "load_balance_content_rewriting": ("action_type", "action"),
    "load_balance_persistence": ("type",),
    "load_balance_method": ("type",),
    "load_balance_profile": ("type",),
    "load_balance_client_ssl_profile": ("client_sni_required",
                                        "client_certificate_verify_mode",
                                        "ssl_allowed_versions"),
    "system_certificate_local": ("type", "status", "validto", "subject"),
    "system_certificate_ca": ("type", "validto", "subject"),
    "system_certificate_intermediate_ca": ("type", "validto", "subject"),
    "system_certificate_local_cert_group_child_group_member": ("default",),
    "load_balance_auth_policy.member": ("auth_path", "user_realm", "type"),
    "user_user_group.member": ("type",),
    "user_radius": ("server", "port", "auth_type"),
    "user_ldap": ("server", "port", "dn"),
    "load_balance_ippool": ("interface", "ip-start", "ip-end"),
    "load_balance_schedule_pool": ("type",),
    "load_balance_error_page": ("vpath",),
    "system_schedule_group_child_schedule_member": ("type", "day-of-week",
                                                    "starttime-of-startdate",
                                                    "endtime-of-enddate"),
}

_DEFAULT_ATTRS = ("type", "status")
#: Values that mean "nothing bound". ``NONE`` is the box's own spelling for an
#: unset real-server SSL profile (measured: every pool without one says it).
_EMPTY = ("", "none", "disable", "0")


def _values(v) -> list[str]:
    items = v if isinstance(v, list) else str(v or "").split()
    return [t for t in (str(x).strip() for x in items) if t.lower() not in _EMPTY]


def _members(index: dict, child: str, mkey: str, row: dict) -> list[dict]:
    parent, _sub, embedded, _label, _t = MEMBERS[child]
    got = ((index.get("children") or {}).get(child) or {}).get(mkey)
    if got:
        return [r for r in got if isinstance(r, dict)]
    emb = row.get(embedded)
    return [r for r in emb if isinstance(r, dict)] if isinstance(emb, list) else []


def _match_label(m: dict) -> str:
    neg = " NOT" if str(m.get("reverse")) == "enable" else ""
    return (f"Match:{neg} {m.get('object') or '?'} "
            f"{m.get('type') or ''} '{m.get('content') or ''}'").replace("  ", " ")


def _member_label(child: str, m: dict) -> str:
    if child.endswith("match_condition"):
        return _match_label(m)
    if child.startswith("load_balance_pool") or child.startswith("load_balance_clone_pool"):
        ip = m.get("address") or m.get("FQDN") or m.get("real_server_id") or "-"
        port = str(m.get("port") or "").strip()
        return (f"Member: {ip}:{port}" if port else f"Member: {ip}") + _attrs(
            m, ATTRS["load_balance_pool_child_pool_member"])
    return (f"{MEMBERS[child][3]} {m.get('mkey', '')}".strip()
            + _attrs(m, ATTRS.get(child, ())))


def _node(index: dict, table: str, mkey: str, label: str, depth: int,
          path: tuple) -> dict:
    """One referenced object and everything it references in turn."""
    row = ((index.get("tables") or {}).get(table) or {}).get(mkey)
    head = f"{label}: {mkey}" if label else mkey
    if row is None:
        tables = index.get("tables") or {}
        why = ("not found on the device" if table in tables
               else "table not captured")
        return {"label": f"{head}  ({why})", "children": []}
    node = {"label": head + _attrs(row, ATTRS.get(table, _DEFAULT_ATTRS)),
            "children": []}
    key = (table, mkey)
    if key in path:
        node["label"] += "  (cycle)"
        return node
    if depth >= MAX_DEPTH:
        node["children"].append({"label": "… (depth limit)", "children": []})
        return node
    _expand(index, table, row, node, depth + 1, path + (key,))
    return node


def _refs_into(index: dict, refs_key: str, row: dict, node: dict, depth: int,
               path: tuple) -> None:
    for field, label, target in REFS.get(refs_key, ()):
        if not target:
            continue
        for value in _values(row.get(field)):
            node["children"].append(_node(index, target, value, label, depth, path))


def _expand(index: dict, table: str, row: dict, node: dict, depth: int,
            path: tuple) -> None:
    mkey = str(row.get("mkey") or "")
    # Members first, in the box's order — they are what the object IS.
    for child, (parent, _sub, _emb, _label, _t) in MEMBERS.items():
        if parent != table:
            continue
        for m in _members(index, child, mkey, row):
            mnode = {"label": _member_label(child, m), "children": []}
            _refs_into(index, child, m, mnode, depth + 1, path)
            node["children"].append(mnode)
    for field, label, refs_key in EMBEDDED.get(table, ()):
        rows = row.get(field)
        for m in rows if isinstance(rows, list) else []:
            if not isinstance(m, dict):
                continue
            mnode = {"label": f"{label} {m.get('mkey', '')}".strip()
                     + _attrs(m, ATTRS.get(refs_key, _DEFAULT_ATTRS)), "children": []}
            _refs_into(index, refs_key, m, mnode, depth + 1, path)
            node["children"].append(mnode)
    _refs_into(index, table, row, node, depth, path)
    if table in WAF_SUBS_OF:
        tables = index.get("tables") or {}
        for field, value in sorted(row.items()):
            target = f"security_waf_{field}"
            if target == table or target not in tables:
                continue
            for v in _values(value):
                node["children"].append(_node(index, target, v,
                                              field.replace("_", " ").title(),
                                              depth, path))


def build_vs_tree(vs: dict, index: dict) -> dict:
    """``{label, children}`` for one virtual server, every reference followed."""
    name = str(vs.get("mkey") or "(unnamed)")
    root = {"label": f"Virtual Server: {name}"
            + _attrs(vs, ATTRS["load_balance_virtual_server"]), "children": []}
    addr = str(vs.get("address") or "").strip()
    if addr and addr != "0.0.0.0":
        ports = " ".join(_values(vs.get("port"))) or "-"
        root["children"].append({"label": f"Listener: {addr}:{ports}"
                                 + _attrs(vs, ("addr-type", "public-ip")),
                                 "children": []})
    _expand(index, "load_balance_virtual_server", vs, root, 1,
            (("load_balance_virtual_server", name),))
    return root


def trees(index: dict, only: str = "") -> list[dict]:
    """Every VS (or the one named) as the inspector's ``{name, tree, full}``."""
    out = []
    vss = (index.get("tables") or {}).get("load_balance_virtual_server") or {}
    for mkey, vs in sorted(vss.items()):
        if only and mkey != only:
            continue
        node = build_vs_tree(vs, index)
        out.append({"name": mkey, "full": {"vs": vs}, "tree": render_tree(node),
                    "node": node})
    return out


def count_nodes(node: dict) -> int:
    return 1 + sum(count_nodes(c) for c in node.get("children") or [])


__all__: list[Any] = [
    "ChildCaptureStopped", "build_vs_tree", "capture_children", "child_plan",
    "index_from_capture", "index_live", "parent_rows", "split_child", "trees",
]
