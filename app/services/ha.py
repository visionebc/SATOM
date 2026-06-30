"""HA cluster connection resolution + live primary detection.

A cluster is modelled as a self-referential ``Appliance``: node 0 (``is_cluster``)
is a logical container; member nodes (``is_cluster_member``, ``parent_id`` -> node 0)
are ordinary appliances with their own host/creds. Writes must always land on the
LIVE primary, so ``resolve_write_target`` detects it before each write (per-node
mode) or trusts the shared VIP (vip mode).
"""
from __future__ import annotations


class HAError(RuntimeError):
    """Raised when a cluster's write target cannot be resolved (no reachable primary)."""


def parse_ha_role(status: dict) -> str:
    """Normalize a FortiWeb/FortiADC HA status dict to one of
    'primary' | 'secondary' | 'standalone' | 'unknown'. Tolerant of the several
    shapes FortiOS-family boxes use (is_master / master / ha_role / mode)."""
    if not isinstance(status, dict):
        return "unknown"
    # explicit role string
    for key in ("ha_role", "role", "ha-role"):
        v = str(status.get(key, "")).strip().lower()
        if v in ("primary", "master", "active"):
            return "primary"
        if v in ("secondary", "slave", "backup", "standby"):
            return "secondary"
    # boolean master flags
    for key in ("is_master", "master", "is_primary"):
        if key in status:
            v = str(status.get(key)).strip().lower()
            if v in ("1", "true", "yes", "enable", "enabled"):
                return "primary"
            if v in ("0", "false", "no", "disable", "disabled"):
                return "secondary"
    # HA mode -> standalone when not clustered
    mode = str(status.get("ha_mode", status.get("mode", ""))).strip().lower()
    if mode in ("standalone", "", "off", "disable", "disabled"):
        return "standalone"
    return "unknown"


def member_role(member, timeout: float = 6.0) -> str:
    """Live HA role of one member appliance (never raises -> 'unknown')."""
    try:
        client = member._own_client(timeout=timeout)
        return parse_ha_role(client.ha_status())
    except Exception:
        return "unknown"


def detect_primary(members, timeout: float = 6.0):
    """Return the member reporting 'primary' (live), else None."""
    for m in members:
        if member_role(m, timeout=timeout) == "primary":
            return m
    return None


def resolve_write_target(node0, timeout: float = 6.0):
    """The appliance a write must target for a cluster node 0.

    vip mode  -> node 0 itself (its host is the shared VIP that lands on primary).
    per_node  -> the live primary member (raises HAError if none is reachable).
    """
    if (node0.ha_mode or "").lower() == "vip":
        return node0
    members = list(node0.members)
    if not members:
        raise HAError(f"Cluster {node0.name!r} has no member nodes configured.")
    primary = detect_primary(members, timeout=timeout)
    if primary is None:
        raise HAError(
            f"Cluster {node0.name!r}: no member is reporting HA primary right now "
            f"(checked {len(members)} node(s)). Refusing to write to a standby."
        )
    return primary
