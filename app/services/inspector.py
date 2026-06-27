"""Policy Inspector — render each FortiWeb **server policy** as a readable tree.

Web port of the desktop Policy Inspector. The desktop walks the whole policy
subtree with a versioned client + a 1500-line WAF deep-renderer; here we build
the tree straight off the web client's composite
:meth:`FortiWebClient.policy_full` read (virtual server + VIPs, server pool +
back-ends, health check, web-protection profile) and render the classic
``├──/└──`` text tree the operator expects, plus the raw composite JSON.

Pure rendering (``render_tree`` / ``build_policy_node``) is network-free; the
fetch helpers need a connected client.
"""
from __future__ import annotations

from typing import Any

# server-managed / noise keys never worth showing as a leaf
_NOISE_KEYS = {"_ref", "ref", "mkey_ref", "can_view", "is_default", "sz_vip-list",
               "sz_pserver-list", "name", "mkey"}
_NOISE_PREFIXES = ("q_",)


def _clean_items(obj: dict) -> list[tuple[str, Any]]:
    """Non-noise (key, value) pairs of a cmdb object, scalars only, non-empty."""
    out: list[tuple[str, Any]] = []
    for k, v in (obj or {}).items():
        # drop server-managed noise: q_* prefixes, GUI can_*/sz_* flags, and the
        # redundant <field>_val numeric mirrors FortiWeb emits alongside enums.
        if k in _NOISE_KEYS or any(k.startswith(p) for p in _NOISE_PREFIXES):
            continue
        if k.startswith("can_") or k.startswith("sz_") or k.endswith("_val"):
            continue
        if isinstance(v, (dict, list)):
            continue
        s = str(v).strip()
        if s == "" or s == "0.0.0.0":
            continue
        out.append((k, s))
    return out


def _attrs(obj: dict, keys: tuple[str, ...]) -> str:
    """A compact ``[k=v, k=v]`` suffix for the named keys that are present."""
    parts = []
    for k in keys:
        v = str((obj or {}).get(k, "")).strip()
        if v:
            parts.append(f"{k}={v}")
    return f"  [{', '.join(parts)}]" if parts else ""


def build_policy_node(full: dict) -> dict:
    """Turn a ``policy_full`` composite into a nested ``{label, children}`` tree."""
    policy = full.get("policy") or {}
    name = policy.get("name") or policy.get("mkey") or "(unnamed)"
    root: dict[str, Any] = {
        "label": f"Server Policy: {name}"
        + _attrs(policy, ("deployment-mode", "service", "ssl", "status", "vserver",
                          "server-pool", "web-protection-profile")),
        "children": [],
    }

    # Virtual server + VIPs
    vs = full.get("vserver") or {}
    vips = full.get("vips") or []
    if vs or vips or policy.get("vserver"):
        vs_node = {
            "label": f"Virtual Server: {policy.get('vserver') or vs.get('name') or '-'}"
            + _attrs(vs, ("status",)),
            "children": [],
        }
        for vip in vips:
            ip = vip.get("ip") or vip.get("vip-ip") or vip.get("vip") or "-"
            vs_node["children"].append({
                "label": f"VIP: {ip}" + _attrs(vip, ("interface", "status", "vip")),
                "children": [],
            })
        root["children"].append(vs_node)

    # Server pool + back-ends + health
    pool = full.get("pool") or {}
    backends = full.get("backends") or []
    if pool or backends or policy.get("server-pool"):
        pool_node = {
            "label": f"Server Pool: {policy.get('server-pool') or pool.get('name') or '-'}"
            + _attrs(pool, ("type", "lb-algo", "server-balance", "health", "comment")),
            "children": [],
        }
        for m in backends:
            ip = m.get("ip") or m.get("server-ip") or m.get("domain") or "-"
            port = m.get("port")
            label = f"Back-end: {ip}:{port}" if port else f"Back-end: {ip}"
            pool_node["children"].append({
                "label": label + _attrs(m, ("status", "weight", "ssl", "server-id")),
                "children": [],
            })
        root["children"].append(pool_node)

    health = full.get("health") or {}
    if health:
        root["children"].append({
            "label": f"Health Check: {health.get('name') or '-'}"
            + _attrs(health, ("type", "interval", "timeout", "retry-times", "url-path")),
            "children": [],
        })

    # Web-protection profile + its bound sub-policies
    wpp = full.get("wpp") or {}
    if wpp or policy.get("web-protection-profile"):
        wpp_node = {
            "label": f"Web Protection Profile: "
                     f"{policy.get('web-protection-profile') or wpp.get('name') or '-'}",
            "children": [],
        }
        for k, v in _clean_items(wpp):
            wpp_node["children"].append({"label": f"{k}: {v}", "children": []})
        root["children"].append(wpp_node)

    return root


def render_tree(node: dict, prefix: str = "", is_root: bool = True, is_last: bool = True) -> str:
    """Render a ``{label, children}`` node as an indented ``├──/└──`` text tree."""
    lines: list[str] = []
    if is_root:
        lines.append(node["label"])
        child_prefix = ""
    else:
        connector = "└── " if is_last else "├── "
        lines.append(prefix + connector + node["label"])
        child_prefix = prefix + ("    " if is_last else "│   ")
    kids = node.get("children") or []
    for i, child in enumerate(kids):
        lines.append(render_tree(child, child_prefix, False, i == len(kids) - 1))
    return "\n".join(lines)


def inspect_policy(client, name: str) -> dict:
    """Composite read + rendered tree for one server policy."""
    full = client.policy_full(name)
    return {"name": name, "full": full, "tree": render_tree(build_policy_node(full))}


def inspect_all(client) -> dict:
    """Inspect every server policy on the appliance.

    Returns ``{"policies": [{name, tree, full}], "errors": [{name, error}], "count": n}``.
    """
    policies: list[dict] = []
    errors: list[dict] = []
    rows = client._results_list(client.list_server_policies())
    names = [str(r.get("name") or r.get("mkey") or "").strip() for r in rows]
    for name in [n for n in names if n]:
        try:
            policies.append(inspect_policy(client, name))
        except Exception as exc:  # noqa: BLE001 — one policy never sinks the page
            errors.append({"name": name, "error": f"{type(exc).__name__}: {exc}"})
    return {"policies": policies, "errors": errors, "count": len(policies)}


__all__ = ["build_policy_node", "render_tree", "inspect_policy", "inspect_all"]
