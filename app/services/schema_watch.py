"""New-firmware watch: a build nobody has harvested the schema of.

When an appliance reports a build the API library holds no schema evidence
for (``cli_tree`` -- or ``schema`` for FortiAnalyzer, whose only schema is the
JSON-RPC syntax -- from its product's adapter), the operator must hear about
it ONCE, with a way to fix it in one click:

* :func:`observe` -- called by ``firmware_probe`` after every firmware read (the
  place the running build is recorded) and by the ``schema_watch`` scheduled
  action. Raises ONE bell notification per ``product@version`` to the
  admin-capable users ("New build 8.0.7 on fw-01: schema not harvested"),
  linking to the Schema builds page, where the harvest is one button.
* :func:`diff_after_harvest` -- once the build is harvested: the comparison with
  the CLOSEST harvested build of the same product (``api_library.compare``),
  and every new or changed item with its channel on the new build. A new item
  whose REST side nobody measured on that build reads ``unknown`` -- that is the
  library's own rule (``channels_at``), nothing is stored to say it -- and is
  listed as "to verify" until a sweep/probe measures it.

Never raises into its callers: a probe or a scheduler must not fail because
the library could not be read.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime

_log = logging.getLogger(__name__)

#: AppSetting key: ``{"<product>@<version>": "<iso time notified>"}``.
NOTIFIED_KEY = "apilib.schema_watch.notified"
ACTION_KEY = "schema_watch"
#: Most items a diff report lists one by one (the totals are always complete).
MAX_ITEMS = 500


def _version_of(appliance) -> str:
    from . import firmware_versions as fv
    raw = getattr(appliance, "fw_version", "") or getattr(appliance, "firmware", "") or ""
    v = fv.normalize(raw)
    return "" if not v or fv.is_line_only(v) else v


def _harvested_versions(product: str, source: str) -> list:
    """Versions of ``product`` with HEALTHY build-scoped ``source`` evidence."""
    from sqlalchemy import select

    from ..extensions import db
    from ..models_apilib import ApiLibBuild, ApiLibEvidence
    rows = db.session.execute(
        select(ApiLibBuild.version, ApiLibBuild.sort_key).join(
            ApiLibEvidence, ApiLibEvidence.build_id == ApiLibBuild.id).where(
            ApiLibBuild.product == product, ApiLibEvidence.source == source,
            ApiLibEvidence.healthy.is_(True), ApiLibEvidence.scope_kind == "build",
            ApiLibBuild.line_only.is_(False)).distinct()).all()
    return [v for v, _k in sorted(rows, key=lambda r: r[1] or "")]


def closest_known(product: str, version: str, source: str = "cli_tree") -> str | None:
    """The harvested build to compare ``version`` with: the newest one BELOW
    it (the upgrade path), else the oldest one above it. None when no other
    build is harvested."""
    from . import api_library as lib
    key = lib.version_key(version)
    others = [v for v in _harvested_versions(product, source) if v != version]
    below = [v for v in others if lib.version_key(v) < key]
    if below:
        return max(below, key=lib.version_key)
    above = [v for v in others if lib.version_key(v) > key]
    return min(above, key=lib.version_key) if above else None


def pending_for(appliance) -> dict | None:
    """What is missing for this appliance's build, or None (nothing to do)."""
    from . import schema_adapters as sa
    product = getattr(appliance, "kind", "") or ""
    adapter = sa.get(product)
    if adapter is None:
        return None
    version = _version_of(appliance)
    if not version:
        return None
    if version in _harvested_versions(product, adapter.cli_source):
        return None
    return {"appliance_id": getattr(appliance, "id", None),
            "appliance": getattr(appliance, "name", "") or "",
            "product": product, "version": version, "source": adapter.cli_source,
            "live": bool(adapter.live and sa.harvester(product)),
            "verified": adapter.verified,
            "closest": closest_known(product, version, adapter.cli_source)}


def _notified() -> dict:
    from ..models import AppSetting
    try:
        val = json.loads(AppSetting.get(NOTIFIED_KEY) or "{}")
    except (TypeError, ValueError):
        val = {}
    return val if isinstance(val, dict) else {}


def _mark_notified(tag: str) -> None:
    from ..extensions import db
    from ..models import AppSetting
    seen = _notified()
    seen[tag] = datetime.utcnow().isoformat(timespec="seconds")
    AppSetting.set(NOTIFIED_KEY, json.dumps(seen, sort_keys=True))
    db.session.commit()


def _link(appliance_id) -> str:
    try:
        from flask import url_for
        return url_for("schema_builds.index", appliance=appliance_id)
    except Exception:  # noqa: BLE001 — no request context (scheduler)
        return "/schema-builds/?appliance=%s" % (appliance_id or "")


def observe(appliance, *, notify: bool = True) -> dict | None:
    """Check one appliance; notify once per new ``product@version``. NEVER raises.

    Returns the :func:`pending_for` answer plus ``notified`` (sent now) and
    ``already`` (sent before), or None when the build is harvested.
    """
    try:
        pend = pending_for(appliance)
        if pend is None:
            return None
        tag = "%s@%s" % (pend["product"], pend["version"])
        pend["already"] = tag in _notified()
        pend["notified"] = 0
        if notify and not pend["already"]:
            from ..models_notifications import Notification
            from . import notifications as notify_svc
            from .alerts import _admin_ids
            how = ("one-click harvest on the Schema builds page" if pend["live"]
                   else "import a harvester pack for it (no live adapter)")
            body = ("SATOM has no %s evidence for %s %s. Harvest it to compare it with %s; "
                    "%s." % (pend["source"], pend["product"], pend["version"],
                             pend["closest"] or "(no other harvested build)", how))
            pend["notified"] = notify_svc.push_many(
                _admin_ids(), "New build %s on %s: schema not harvested"
                % (pend["version"], pend["appliance"]),
                kind=Notification.KIND_WARNING, body=body,
                link=_link(pend["appliance_id"]), product=pend["product"])
            _mark_notified(tag)
        return pend
    except Exception as exc:  # noqa: BLE001 — a probe/scheduler must not fail here
        try:
            from ..extensions import db
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        _log.warning("schema_watch.observe failed: %s", exc, exc_info=True)
        return None


def scan(*, notify: bool = True) -> list:
    """Every appliance with a schema adapter: the pending builds (notified once)."""
    from ..models import Appliance
    from . import schema_adapters as sa
    products = [a.product for a in sa.all_adapters()]
    out = []
    for ap in Appliance.query.filter(Appliance.kind.in_(products)).order_by(Appliance.id):
        if getattr(ap, "is_cluster", False):
            continue
        pend = observe(ap, notify=notify)
        if pend is not None:
            out.append(pend)
    return out


def diff_after_harvest(product: str, version: str, base: str | None = None) -> dict:
    """The new build against the closest harvested one, item by item.

    ``items`` = every object/field added or changed in the CLI schema (or, for
    a product whose only schema is ``schema`` evidence, in the REST schema),
    each with its ``channel`` on the new build and ``to_verify`` = the REST
    side of that item was not measured on the new build (channel ``unknown``).
    """
    from . import api_library as lib
    from . import schema_adapters as sa
    adapter = sa.get(product)
    source = adapter.cli_source if adapter else "cli_tree"
    base = base or closest_known(product, version, source)
    out = {"product": product, "version": version, "base": base, "source": source,
           "items": [], "totals": {}, "to_verify": 0, "truncated": False}
    if not base:
        out["reason"] = "no other harvested build of %s to compare with" % product
        return out
    cmp = lib.compare(product, base, version)
    view = lib.channels_at(product, version)["endpoints"]

    def channel(key, field=None):
        ep = view.get(key) or {}
        if field is None:
            return ep.get("channel") or lib.CH_UNKNOWN
        return ((ep.get("fields") or {}).get(field) or {}).get("channel") or lib.CH_UNKNOWN

    items = []
    tree = (cmp.get("channels") or {}).get("tree")
    if source == "cli_tree" and tree:
        for key in tree["endpoints_added"]:
            items.append({"endpoint": key, "field": None, "change": "object added"})
        for key in tree["endpoints_removed"]:
            items.append({"endpoint": key, "field": None, "change": "object removed"})
        for key, d in tree["endpoints"].items():
            for f in d["added"]:
                items.append({"endpoint": key, "field": f, "change": "field added"})
            for f in d["removed"]:
                items.append({"endpoint": key, "field": f, "change": "field removed"})
            for o in d["options"]:
                items.append({"endpoint": key, "field": o["field"], "change": "options changed",
                              "detail": {"added": o["added"], "removed": o["removed"]}})
            for r in d["retyped"]:
                items.append({"endpoint": key, "field": r["field"], "change": "retyped",
                              "detail": {"from": r["from"], "to": r["to"]}})
            for r in d["ranges"]:
                items.append({"endpoint": key, "field": r["field"], "change": "range changed",
                              "detail": {"from": r["from"], "to": r["to"]}})
            for r in d["defaults"]:
                items.append({"endpoint": key, "field": r["field"], "change": "default changed",
                              "detail": {"from": r["from"], "to": r["to"]}})
        out["totals"] = dict(tree["totals"], endpoints_added=len(tree["endpoints_added"]),
                             endpoints_removed=len(tree["endpoints_removed"]))
    else:
        for e in cmp["endpoints_added"]:
            items.append({"endpoint": lib.urn_key(e["urn"]) or e["endpoint"], "field": None,
                          "change": "object added"})
        for e in cmp["endpoints_removed"]:
            items.append({"endpoint": lib.urn_key(e["urn"]) or e["endpoint"], "field": None,
                          "change": "object removed"})
        for name, d in cmp["endpoints"].items():
            if d.get("unknown"):
                continue
            for f in d["added"]:
                items.append({"endpoint": name, "field": f, "change": "field added"})
            for f in d["removed"]:
                items.append({"endpoint": name, "field": f, "change": "field removed"})
            for r in d["retyped"]:
                items.append({"endpoint": name, "field": r["field"], "change": "retyped",
                              "detail": {"from": r["from"], "to": r["to"]}})
        out["totals"] = dict(cmp["totals"], endpoints_added=len(cmp["endpoints_added"]),
                             endpoints_removed=len(cmp["endpoints_removed"]))
    for it in items:
        if it["change"].endswith("removed") and it["field"] is None:
            it["channel"] = "absent"
        elif it["change"] == "field removed":
            it["channel"] = "absent"
        else:
            it["channel"] = channel(it["endpoint"], it["field"])
        # New or changed on the new build, REST side not measured there:
        # unknown until a sweep/probe of that build verifies it.
        it["to_verify"] = it["channel"] == lib.CH_UNKNOWN
    out["to_verify"] = sum(1 for it in items if it["to_verify"])
    out["truncated"] = len(items) > MAX_ITEMS
    out["items"] = items[:MAX_ITEMS]
    out["count"] = len(items)
    return out


__all__ = ["NOTIFIED_KEY", "ACTION_KEY", "closest_known", "pending_for", "observe", "scan",
           "diff_after_harvest"]
