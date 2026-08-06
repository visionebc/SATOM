"""Infrastructure health snapshot for the Monitoring + Global dashboards.

Aggregates, WITHOUT any SSH, the cross-node / off-box state the operator wants
to see "at a glance, arriba":

  * both HA nodes' CPU / RAM / disk — local via /proc (``system_health``), the
    PEER via its own ``/healthz`` (now embeds ``host_stats`` under ``host``), so
    no SSH to the secondary is needed,
  * the Gitea source-of-truth repo: reachable + branch/commit + last reports/
    (device SoT) publish,
  * the external backup server (backup-server): reachable + filesystem usage (SFTP
    ``statvfs``) + top-level counts.  CPU/RAM of backup-server are deliberately NOT
    exposed — it is an SFTP-jailed box (chroot + ForceCommand internal-sftp), a
    separate failure domain, and giving the web worker a shell there would break
    that isolation on purpose.

This does network I/O (peer HTTP, Gitea HTTP, backup-server SFTP) with short
timeouts, so it is served from a SEPARATE endpoint the card fetches AFTER the
page renders — a page load itself never touches the network (same contract the
rest of /monitoring keeps).  Everything is best-effort: a failed probe degrades
to ``reachable=False`` and never raises.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from . import self_update as su
from . import system_health as shealth

PEER_PORT = 8000
_HTTP_TIMEOUT = 2.0


# ---------------------------------------------------------------------------
# HA nodes
# ---------------------------------------------------------------------------
def _peer_health(host: str) -> dict:
    """Read a peer node's ``/healthz`` over HTTPS :8443 (fallback :8000), plus its
    authoritative role from ``/healthz/primary``. Records whether the probe rode
    TLS (``secure``) and whether the peer accepted our identity key
    (``authenticated``)."""
    from . import node_security as nsec
    out = {"reachable": False, "role": None, "app_up": False,
           "revision": None, "host_stats": None, "secure": None,
           "authenticated": None}
    st, body, secure = nsec.peer_get(host, "/healthz", timeout=_HTTP_TIMEOUT)
    if st is not None:
        out["reachable"] = True
        out["secure"] = secure
        try:
            d = json.loads(body.decode("utf-8", "replace"))
            out["app_up"] = bool(d.get("ok"))
            out["revision"] = d.get("revision")
            out["host_stats"] = d.get("host")
            out["role"] = (d.get("db") or {}).get("role")
            out["authenticated"] = d.get("peer_authenticated")
        except Exception:
            pass
    if out["role"] is None:
        st2, body2, secure2 = nsec.peer_get(host, "/healthz/primary", timeout=_HTTP_TIMEOUT)
        if st2 is not None:
            out["reachable"] = True
            out["secure"] = secure2
            out["role"] = "primary" if st2 == 200 else ("standby" if st2 == 503 else None)
    return out

def _nodes() -> list[dict]:
    this = su.this_node_name()
    this_role = su.node_role()
    out = []
    for n in su.node_reports():
        name = n.get("name") or ""
        host = n.get("host") or ""
        desc = n.get("desc") or ""
        if name == this:
            out.append({"name": name, "host": host, "desc": desc,
                        "is_local": True, "reachable": True, "role": this_role,
                        "app_up": True, "host_stats": shealth.host_stats()})
        else:
            pr = _peer_health(host) if host else {"reachable": False}
            out.append({"name": name, "host": host, "desc": desc,
                        "is_local": False, "reachable": bool(pr.get("reachable")),
                        "role": pr.get("role"), "app_up": bool(pr.get("app_up")),
                        "host_stats": pr.get("host_stats")})
    return out


def nodes() -> list[dict]:
    """Public alias for :func:`_nodes` — the HA node list with each node's
    ``host_stats``. :mod:`app.services.host_health` grades these, and a private
    name there would be a second implementation waiting to drift."""
    return _nodes()


# ---------------------------------------------------------------------------
# Git source of truth (Gitea)
# ---------------------------------------------------------------------------
def _git() -> dict:
    from . import git_service as gs
    try:
        info = gs.git_info()
    except Exception:
        info = {}
    out = {"remote": info.get("remote") or "—",
           "branch": info.get("branch") or "—",
           "commit": info.get("commit") or "—",
           "commit_local": info.get("commit_local") or "",
           "dirty": bool(info.get("dirty")),
           "base": None, "reachable": False, "reports_last": None}
    remote = info.get("remote") or ""
    try:
        u = urlsplit(remote)
        if u.scheme and u.netloc:
            base = "%s://%s" % (u.scheme, u.netloc)
            out["base"] = base
            try:  # Gitea answers /api/v1/version unauthenticated
                with urllib.request.urlopen(base + "/api/v1/version",
                                            timeout=_HTTP_TIMEOUT) as r:
                    out["reachable"] = 200 <= r.status < 500
            except urllib.error.HTTPError:
                out["reachable"] = True  # it answered → server is up
            except Exception:
                out["reachable"] = False
    except Exception:
        pass
    try:
        hist = gs.reports_history(limit=1)
        if hist:
            h = hist[0]
            out["reports_last"] = {"hash": h.get("hash"), "date": h.get("date"),
                                   "datetime": h.get("datetime"),
                                   "subject": h.get("subject")}
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# External backup server (backup-server)
# ---------------------------------------------------------------------------
def _backup() -> dict:
    from . import backup_server as bk
    try:
        return bk.infra_probe()
    except Exception as exc:  # noqa: BLE001
        return {"configured": False, "reachable": False, "error": str(exc)[:200],
                "host": None, "port": None, "disk": None,
                "devices": None, "firmware": None}


# ---------------------------------------------------------------------------
def snapshot() -> dict:
    t0 = time.monotonic()
    payload = {
        "nodes": _nodes(),
        "git": _git(),
        "backup": _backup(),
        "mode": su.ha_mode(),
    }
    payload["took_ms"] = round((time.monotonic() - t0) * 1000, 0)
    return payload
