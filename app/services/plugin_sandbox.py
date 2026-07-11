"""Plugin Sandbox — safe rendering + the curated read-only data API.

Two hard guarantees back the whole feature:

1. **Sandboxed templating.** The author's body renders in an
   ``ImmutableSandboxedEnvironment`` (jinja2.sandbox). Attribute access to
   mutating methods, ``__class__``/``__mro__`` gadget chains, and unsafe
   callables all raise ``SecurityError`` — the plugin can only read the data we
   hand it, never touch app internals or the ORM.
2. **Curated data only.** A plugin declares which DATASETS it wants; each is a
   fixed SELECT-only query run through ``dbintrospect.run_query`` (the same
   masked, read-only path the SQL console uses). There is NO way for a plugin to
   run arbitrary SQL or reach a write.

The rendered document is served ONLY inside a ``sandbox="allow-scripts"`` iframe
without ``allow-same-origin`` (see views.plugins), so the plugin's JavaScript
runs in an opaque origin and cannot read the app's cookies / DOM / session.
"""
from __future__ import annotations

import json
import re
from typing import Any

from jinja2.sandbox import ImmutableSandboxedEnvironment
from jinja2 import TemplateError, StrictUndefined

from . import dbintrospect


# --- Curated datasets -------------------------------------------------------
# key -> (label, description, SQL). Every query is SELECT-only and runs through
# dbintrospect.run_query (sensitive columns masked, row-capped). To offer a new
# dataset, add a row here — never accept SQL from the plugin author.
DATASETS: dict[str, tuple[str, str, str]] = {
    "fleet_appliances": (
        "Fleet appliances",
        "Every managed device: name, kind, firmware, host.",
        "SELECT id, name, kind, firmware, host, port FROM appliances ORDER BY kind, name",
    ),
    "server_policies": (
        "Server policies (cached)",
        "Cached FortiWeb server policies with their key columns.",
        "SELECT appliance_id, name, \"deployment-mode\" AS deployment_mode, "
        "vserver, \"server-pool\" AS server_pool, status "
        "FROM device_server_policies ORDER BY appliance_id, name",
    ),
    "server_policies_full": (
        "Server policies (rich)",
        "Every cached server policy with traffic-log, WPP, monitor-mode, "
        "comment AND the App ID parsed from the comment. This is the dataset "
        "for traffic-log / App-ID / WAF-coverage views.",
        "SELECT o.appliance_id, a.name AS device, o.mkey AS policy, "
        "o.payload->>'deployment-mode' AS deployment_mode, "
        "o.payload->>'vserver' AS vserver, "
        "o.payload->>'server-pool' AS server_pool, "
        "o.payload->>'web-protection-profile' AS wpp, "
        "o.payload->>'status' AS status, "
        "o.payload->>'tlog' AS traffic_log, "
        "o.payload->>'monitor-mode' AS monitor_mode, "
        "o.payload->>'https-service' AS https_service, "
        "o.payload->>'service' AS service, "
        "o.payload->>'comment' AS comment, "
        "substring(o.payload->>'comment' from "
        "'(?i)app[ _-]?id[ :=]+([A-Za-z0-9_.-]+)') AS appid "
        "FROM device_objects o LEFT JOIN appliances a ON a.id = o.appliance_id "
        "WHERE o.logical_name = 'server_policy' AND o.layer = 'config' "
        "ORDER BY o.appliance_id, o.mkey",
    ),
    "server_pools": (
        "Server pools + members",
        "Cached back-end pools with their type/protocol columns.",
        "SELECT appliance_id, name, type, protocol "
        "FROM device_server_pools ORDER BY appliance_id, name",
    ),
    "web_protection_profiles": (
        "Web Protection Profiles",
        "Cached WAF profiles (inline/offline) with their signature/bot refs.",
        "SELECT appliance_id, name, kind, \"signature-rule\" AS signature_rule, "
        "\"bot-mitigate-policy\" AS bot_policy "
        "FROM device_web_protection_profiles ORDER BY appliance_id, name",
    ),
    "certificates": (
        "Managed certificates",
        "Certificates tracked by the Certificate Manager (no key material).",
        "SELECT id, common_name, appliance_id, status, not_after "
        "FROM managed_certificate ORDER BY not_after",
    ),
    "audit_recent": (
        "Recent audit activity",
        "The 200 most recent audit-log rows.",
        "SELECT timestamp, username, action, target, product "
        "FROM audit_logs ORDER BY id DESC LIMIT 200",
    ),
    "fleet_counts": (
        "Fleet counts",
        "One-row summary: device / policy / certificate totals.",
        "SELECT (SELECT COUNT(*) FROM appliances) AS devices, "
        "(SELECT COUNT(*) FROM device_server_policies) AS server_policies, "
        "(SELECT COUNT(*) FROM managed_certificate) AS certificates",
    ),
    "scheduled_actions": (
        "Scheduled actions",
        "Configured automation schedule (name, action, next run).",
        "SELECT name, action_key, schedule_kind, enabled, next_run, product "
        "FROM scheduled_action ORDER BY next_run",
    ),
}


def dataset_catalog() -> list[dict[str, str]]:
    """List the offerable datasets for the editor picker."""
    return [
        {"key": k, "label": v[0], "description": v[1]}
        for k, v in DATASETS.items()
    ]


def load_datasets(keys: list[str]) -> dict[str, Any]:
    """Run each requested dataset's fixed query; return {key: {columns, rows}}.

    A dataset the plugin isn't entitled to (not in DATASETS) is skipped. A query
    that errors (e.g. a table absent on this deployment) yields an empty set with
    an ``error`` note — it never raises into the caller.
    """
    out: dict[str, Any] = {}
    for key in keys or []:
        spec = DATASETS.get(key)
        if not spec:
            continue
        _label, _desc, sql = spec
        try:
            # run_query is SELECT-only + masked + row-capped by construction.
            res = dbintrospect.run_query(sql)
            cols = res.get("columns") if isinstance(res, dict) else None
            rows = res.get("rows") if isinstance(res, dict) else None
            dict_rows = []
            if cols and rows:
                for r in rows:
                    dict_rows.append({c: r[i] for i, c in enumerate(cols)})
            out[key] = {"columns": cols or [], "rows": dict_rows}
        except Exception as exc:  # noqa: BLE001 — never fatal to the render
            out[key] = {"columns": [], "rows": [], "error": str(exc)[:200]}
    return out


# --- Sandboxed render -------------------------------------------------------
_SANDBOX = ImmutableSandboxedEnvironment(autoescape=True, undefined=StrictUndefined)


def render_body(jinja_src: str, data: dict[str, Any],
                params: dict[str, Any] | None = None) -> str:
    """Render the plugin body in the immutable sandbox. Raises on error.

    ``params`` (the resolved input-selector values) is exposed to the body as
    ``params`` so the author can filter the curated data. Filters are OPTIONAL
    by design — a body that never reads ``params`` renders exactly as before.
    """
    template = _SANDBOX.from_string(jinja_src or "")
    return template.render(data=data, params=params or {}, **data)


def safe_render(jinja_src: str, data: dict[str, Any],
                params: dict[str, Any] | None = None) -> tuple[str, str | None]:
    """Render, but convert any failure into an error card string.

    Returns (html, error_message). A broken plugin can therefore never take the
    host page down — the worst case is a visible red card.
    """
    try:
        return render_body(jinja_src, data, params), None
    except TemplateError as exc:
        msg = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001 — sandbox SecurityError et al.
        msg = f"{type(exc).__name__}: {exc}"
    card = (
        '<div style="border:1px solid #ef4444;background:rgba(239,68,68,.08);'
        'border-radius:12px;padding:16px;color:#fca5a5;font-family:monospace;'
        'font-size:13px;white-space:pre-wrap">Plugin render error:\n'
        + _escape(msg) + "</div>"
    )
    return card, msg


def _escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(name: str) -> str:
    s = _SLUG_RE.sub("-", (name or "").strip().lower()).strip("-")
    return s or "plugin"


# --- Input parameters (author-defined selectors) ----------------------------
# A plugin may declare INPUT PARAMETERS so the consumer of the view can filter
# it (pick a device, a status, type a name...). Definitions are curated by the
# author; the VALUES are supplied at view time (?p_<name>=..) and reach the body
# as ``params.<name>``. Values NEVER touch SQL — the datasets stay fixed — so a
# param can only filter data already loaded, never widen access.
_PARAM_TYPES = ("device", "select", "text", "number", "date")


def clean_param_defs(raw: Any) -> list[dict[str, Any]]:
    """Validate + normalise author param definitions (JSON text or a list).

    Drops malformed entries and duplicate names; never raises. Returns a list of
    {name,label,type,options,default,required} with safe, length-capped values.
    """
    try:
        data = raw if isinstance(raw, list) else json.loads(raw or "[]")
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        name = slugify(str(item.get("name") or "")).replace("-", "_")[:40]
        if not name or name in seen:
            continue
        typ = item.get("type")
        if typ not in _PARAM_TYPES:
            typ = "text"
        opts: list[dict[str, str]] = []
        for o in (item.get("options") or []):
            if isinstance(o, dict):
                v = str(o.get("value", "")).strip()
                lbl = (str(o.get("label", "")).strip() or v)
            else:
                v = str(o).strip()
                lbl = v
            if v:
                opts.append({"value": v[:120], "label": lbl[:120]})
        out.append({
            "name": name,
            "label": (str(item.get("label") or name))[:80],
            "type": typ,
            "options": opts if typ == "select" else [],
            "default": (str(item.get("default") or ""))[:120],
            "required": bool(item.get("required")),
        })
        seen.add(name)
    return out


def _coerce(raw: Any, typ: str, d: dict[str, Any]) -> Any:
    s = str(raw)[:120]
    if typ == "number":
        if s == "":
            return ""
        try:
            f = float(s)
            return int(f) if f.is_integer() else f
        except ValueError:
            return ""
    if typ == "select":
        opts = [str(o.get("value")) for o in (d.get("options") or [])]
        if opts and s not in opts:
            return str(d.get("default") or "")
        return s
    # device / text / date -> string
    return s


def resolve_params(defs: list[dict[str, Any]], args: Any) -> dict[str, Any]:
    """Coerce raw request values (``p_<name>``) into a {name: value} map.

    ``args`` is any mapping with ``.get`` (Flask ``request.args``/``request.form``
    or a plain dict). Unknown args are ignored; a missing/blank value falls back
    to the def's ``default``; wrong-typed values fall back too. Never raises.
    """
    out: dict[str, Any] = {}
    for d in defs or []:
        name = d.get("name")
        if not name:
            continue
        typ = d.get("type", "text")
        raw = args.get("p_" + name) if hasattr(args, "get") else None
        if raw is None or str(raw) == "":
            out[name] = _coerce(d.get("default", ""), typ, d)
        else:
            out[name] = _coerce(raw, typ, d)
    return out


def _appliance_options(product: str | None = None) -> list[dict[str, str]]:
    """Live appliance list for a ``device`` selector, scoped by product.

    Read through the same masked/read-only path as every dataset. A product of
    ``fortiweb``/``fortiadc`` filters by device kind; ``global``/empty = all.
    """
    try:
        res = dbintrospect.run_query(
            "SELECT id, name, kind FROM appliances ORDER BY kind, name")
        cols = res.get("columns") or []
        rows = res.get("rows") or []
        idx = {c: i for i, c in enumerate(cols)}
        if "id" not in idx or "name" not in idx:
            return []
        out = []
        for r in rows:
            kind = r[idx["kind"]] if "kind" in idx else ""
            if product in ("fortiweb", "fortiadc") and kind != product:
                continue
            aid = r[idx["id"]]
            out.append({"value": str(aid),
                        "label": r[idx["name"]] or f"device {aid}"})
        return out
    except Exception:
        return []


def param_options(defs: list[dict[str, Any]],
                  product: str | None = None) -> list[dict[str, Any]]:
    """A render-ready copy of the param defs with ``device`` selectors' options
    populated from the live appliance list (scoped by product)."""
    devices: list[dict[str, str]] | None = None
    out = []
    for d in defs or []:
        d2 = dict(d)
        if d2.get("type") == "device":
            if devices is None:
                devices = _appliance_options(product)
            d2["options"] = devices
        out.append(d2)
    return out
