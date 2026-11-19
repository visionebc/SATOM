"""Live per-backend health of one FortiWeb server policy.

A DEVICE read (``policystatus.detail``), so it runs only when someone asks:
Workspace's topology card and DNS & LB Lookup's *Show > Check live health*
(``views.workspace.policy_health``), and the Plugin Studio step
``lb_policy_health`` (services.studio_dns). One function, one audit line
whichever way the read went.

Mapping: healthCheckStatus enable = UP, disable = DOWN, anything else (N/A)
= no health check -- the same authoritative field the team's
fortiweb_pool_health.py script keys on.
"""
from __future__ import annotations

_HC_UP = {"enable", "enabled", "up", "ok"}
_HC_DOWN = {"disable", "disabled", "down", "dead"}


class NotFortiWeb(ValueError):
    pass


def hc_state(v) -> str:
    v = str(v or "").strip().lower()
    if v in _HC_UP:
        return "up"
    if v in _HC_DOWN:
        return "down"
    return "na"


def probe(appl, name: str) -> dict:
    """``{"ok", "members", "error"}`` -- a refusal by the device is ok=False
    with its reason (never "all down"). Raises for a transport failure (after
    auditing it) and :class:`NotFortiWeb` for another product."""
    from ..clients.fortiweb import FortiWebClient
    from .audit import log_action
    if getattr(appl, "kind", "") != "fortiweb":
        raise NotFortiWeb("FortiWeb-only")
    try:
        rows, err = FortiWebClient(appl).policy_health(name)
    except Exception as exc:
        log_action("policy.health_probe", target=f"{appl.name}:{name}",
                   appliance_id=appl.id, detail=f"failed: {exc}"[:400])
        raise
    log_action("policy.health_probe", target=f"{appl.name}:{name}", appliance_id=appl.id,
               detail=(f"refused: {err}" if err else f"{len(rows or [])} member(s)")[:400])
    if err:
        return {"ok": False, "error": str(err), "members": []}
    return {"ok": True, "error": "", "members": [{
        "pool": str(m.get("pool") or ""),
        "ip": str(m.get("ipDomainName") or m.get("ip") or ""),
        "port": str(m.get("port") or ""),
        "health": hc_state(m.get("healthCheckStatus")),
        "raw": str(m.get("healthCheckStatus") or ""),
    } for m in (rows or []) if isinstance(m, dict)]}
