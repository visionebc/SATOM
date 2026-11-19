"""The Observability sidebar — ONE definition for both halves of the area.

/observability/ is two applications behind one menu since 2026-11-17 (operator
request: "everything in the Monitoring menu goes into /observability, with its
style"):

* the Observability app (``app/observability_lab``), proxied by
  ``views.observability_lab`` — Overview, Explore, Diagrams, Events…;
* SATOM's own Monitoring views, served at ``/observability/monitoring/`` and
  drawn in the Observability shell by ``base.html`` (``obs_shell``).

Both draw THIS list, so the menu cannot differ depending on which half
rendered the page: SATOM renders it directly, and the proxy hands the same
list to the app in the WSGI environ (``satom.obs_nav``) — the app cannot call
SATOM's ``url_for`` itself.

Rules the list obeys (each has a test in ``tests/test_observability_shell.py``):

* a SATOM entry is offered only when ``may_open`` passes (route stamp AND the
  ``observability.access`` gate), so the menu never links a 403;
* the app's entries are offered in the Global ADOM to an unconfined account
  only (:func:`lab_offered`): the app has no ADOM filter, and the proxy refuses
  a confined account; the Monitoring entries stay everywhere, because those
  SATOM views ARE scoped by ADOM;
* SATOM health is offered in the Global ADOM only — its route enforces that;
* the active entry is the longest href that prefixes the current path.
"""
from __future__ import annotations

from flask import request, url_for

PREFIX = "/observability"

#: The app's own pages, by path under the prefix. Paths, not endpoints: SATOM
#: cannot build the app's URLs. ``test_lab_paths_are_routable`` pins every one
#: of them to a rule of the app's url_map, so a renamed page fails a test
#: instead of becoming a dead link.
#: (section, label, icon, path, extra active prefixes)
LAB_ENTRIES: tuple[tuple[str, str, str, str, tuple[str, ...]], ...] = (
    ("Monitor", "Overview", "speedometer2", "/", ()),
    ("Monitor", "Infrastructure", "hdd-rack", "/infrastructure", ()),
    ("Monitor", "Network", "ethernet", "/network", ()),
    ("Monitor", "Applications", "window-stack", "/applications", ()),
    ("Visualize", "Data Flows", "bezier", "/flows", ()),
    ("Visualize", "Architecture Maps", "diagram-3", "/diagrams/", ()),
    ("Visualize", "Dependencies", "share", "/dependencies", ()),
    ("Analyze", "Analytics", "graph-up-arrow", "/analytics", ()),
    ("Analyze", "Events & Alerts", "bell", "/events", ()),
    ("Analyze", "Incidents", "fire", "/incidents", ()),
    ("Configure", "Integrations", "plug", "/sources/", ()),
    ("Configure", "Collection jobs", "list-task", "/jobs/", ()),
    ("Configure", "Administration", "shield-check", "/audit", ("/account",)),
)

#: Where the app's own "Reports" page went: it is the On-demand tab of
#: Monitoring › Reports now (one Reports entry, not two).
LAB_REPORTS_PATH = "/reports"

#: SATOM's Monitoring entries: (label, icon, endpoint, global_only, extra
#: active path prefixes relative to the prefix).
MONITORING_ENTRIES: tuple[tuple[str, str, str, bool, tuple[str, ...]], ...] = (
    ("Device health", "hdd-rack", "monitoring.index", False, ()),
    ("SATOM health", "hdd-network", "monitoring.satom", True,
     ("/monitoring/infra", "/monitoring/encryption")),
    ("Metrics", "bar-chart-line", "metrics.index", False, ()),
    ("Analysis", "graph-up", "analysis.index", False, ()),
    ("Deep monitors", "broadcast-pin", "deep_monitor.index", False, ()),
    ("Service Monitor", "speedometer2", "service_monitor.index", False, ()),
    ("Service checks", "heart-pulse", "service_checks.index", False, ()),
    ("Dashboards", "grid-1x2", "monitor_analytics.index", False, ()),
    ("Reports", "file-earmark-bar-graph", "monitor_reports.index", False,
     (LAB_REPORTS_PATH,)),
)

SECTION_ORDER = ("Monitor", "Monitoring", "Visualize", "Analyze", "Configure")


def _confined() -> bool:
    from .services.product_scope import restricted_adoms
    return restricted_adoms() is not None


def lab_offered(adom: str) -> bool:
    """Whether the app's own pages are offered: Global ADOM, unconfined
    account. The app shows the WHOLE inventory with no ADOM filter, so a
    device ADOM (and an ADOM-confined account) gets the Monitoring section
    only — exactly as SATOM health is Global-only."""
    return adom == "global" and not _confined()


def _endpoint_exists(endpoint: str) -> bool:
    from flask import current_app
    return endpoint in current_app.view_functions


def build(path: str | None = None, adom: str | None = None) -> list[dict]:
    """The sections for the current user and request.

    ``[{"title": str, "items": [{"label", "icon", "href", "active",
    "kind"}]}]`` — ``kind`` is ``lab`` (full page load into the app) or
    ``satom``. Needs a SATOM request context.
    """
    from flask import current_app
    from flask_login import current_user
    from .services.concept_map import may_open

    app = current_app._get_current_object()
    root = request.script_root
    path = request.path if path is None else path
    if adom is None:
        try:
            from .services.product_scope import product_keys, session_product
            adom = session_product()
            if adom not in product_keys():
                adom = "global"
        except Exception:  # noqa: BLE001 — the menu never 500s a page
            adom = "global"

    rows: list[tuple[str, dict, tuple[str, ...]]] = []
    if lab_offered(adom):
        for section, label, icon, sub, extra in LAB_ENTRIES:
            href = root + PREFIX + sub
            rows.append((section, {"label": label, "icon": icon, "href": href,
                                   "kind": "lab"},
                         (PREFIX + sub,) + tuple(PREFIX + e for e in extra)))
    for label, icon, endpoint, global_only, extra in MONITORING_ENTRIES:
        if global_only and adom != "global":
            continue
        if not _endpoint_exists(endpoint) or not may_open(current_user, endpoint, app):
            continue
        href = url_for(endpoint, _adom=adom)
        if extra == (LAB_REPORTS_PATH,) and not lab_offered(adom):
            extra = ()
        bare = href.split("?", 1)[0]
        rows.append(("Monitoring", {"label": label, "icon": icon, "href": href,
                                    "kind": "satom"},
                     (bare[len(root):],) + tuple(PREFIX + e for e in extra)))
    # Administrator › Collection is offered here to a config_write holder
    # without user management, exactly as the old Monitoring submenu did
    # (it is reachable from Administrator for everyone else).
    if (_endpoint_exists("metrics_admin.index") and current_user.is_authenticated
            and current_user.can("config_write") and not current_user.can("user_manage")
            and may_open(current_user, "metrics_admin.index", app)):
        href = url_for("metrics_admin.index", _adom=adom)
        rows.append(("Monitoring", {"label": "Collection", "icon": "collection",
                                    "href": href, "kind": "satom"},
                     (href.split("?", 1)[0][len(root):],)))

    # Active: the longest prefix match wins ("/" only matches itself).
    best, best_len = None, -1
    for i, (_s, _item, prefixes) in enumerate(rows):
        for pre in prefixes:
            pre_n = pre.rstrip("/") or "/"
            hit = (path == pre_n or path == pre_n + "/") if pre_n in (PREFIX, PREFIX + "/") \
                else (path == pre_n or path.startswith(pre_n.rstrip("/") + "/"))
            if hit and len(pre_n) > best_len:
                best, best_len = i, len(pre_n)
    sections: dict[str, list[dict]] = {}
    for i, (section, item, _p) in enumerate(rows):
        item = dict(item, active=(i == best))
        sections.setdefault(section, []).append(item)
    return [{"title": t, "items": sections[t]} for t in SECTION_ORDER if t in sections]
