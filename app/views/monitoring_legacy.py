"""Old Monitoring URLs -> their place under /observability/monitoring/.

Monitoring moved into the Observability area on 2026-11-17 (operator request:
"everything in the Monitoring menu goes into /observability, with its style").
Bookmarks, e-mailed report links, notification "open" links and runbooks
still carry the old paths, so every one of them answers a permanent redirect
to the same page at its new address. 308, not 301: a 301 lets a browser turn a
POST into a GET, and a stale form posting to the old path must not silently
become a read.

Left where it was ON PURPOSE: ``/monitoring/collection/`` (Administrator ›
Collection, ``metrics_admin``). It is a settings page, not a Monitoring view,
and its ``peer/ingest`` / ``peer/store`` routes are the node-to-node API the
other HA node calls — moving them would break a pair running mixed versions
during an update. Its routes are more specific than the catch-all below, so
Werkzeug keeps routing them to ``metrics_admin``.
"""
from __future__ import annotations

from flask import Blueprint, redirect, request

bp = Blueprint("monitoring_legacy", __name__)

NEW_ROOT = "/observability/monitoring"

#: old prefix -> new prefix. Longest first: /monitoring/analytics must win
#: over /monitoring.
MOVES: tuple[tuple[str, str], ...] = (
    ("/monitoring/analytics", NEW_ROOT + "/dashboards"),
    ("/monitoring", NEW_ROOT),
    ("/metrics", NEW_ROOT + "/metrics"),
    ("/analysis", NEW_ROOT + "/analysis"),
)

METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]


def new_path(path: str) -> str | None:
    """The new address of an old Monitoring *path*, or ``None``."""
    for old, new in MOVES:
        if path == old or path.startswith(old + "/"):
            return new + path[len(old):]
    return None


def _go(rest: str = ""):
    target = new_path(request.path)
    if target is None:  # pragma: no cover — every rule below maps
        return ("Not found", 404)
    qs = request.query_string.decode("latin-1")
    return redirect(request.script_root + target + ("?" + qs if qs else ""), code=308)


for _old, _new in MOVES:
    _ep = _old.strip("/").replace("/", "_")
    bp.add_url_rule(_old, "old_" + _ep, _go, methods=METHODS, strict_slashes=False)
    bp.add_url_rule(_old + "/<path:rest>", "old_" + _ep + "_rest", _go, methods=METHODS)
