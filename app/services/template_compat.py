"""Which firmware a template was authored for, and does it fit another one?

A template body is a payload for ONE API surface. FortiWeb 7.6 and 8.0 both
speak ``v2.0`` and still differ in FIELDS, and a cmdb write carrying a field
the build does not know answers **200 and discards it** — so a template saved
on one build and applied to another can report success and land incomplete.
Nothing in the body says which build it was written for, so nothing could
tell.

This module is the template side of that question. It never grades a payload
itself: the verdicts come from :mod:`services.version_compat`, the engine the
clone pre-flight and the upgrade flow already ask, so the three surfaces cannot
disagree about the same appliance. What it adds:

* **the stamp** — every save records the build (``source_firmware``), the REST
  API version and, when captured, the appliance it was read from;
* **the self-check** — the body against its OWN build, at save time;
* **the device check** — the body against each target's running build, at
  apply time, with a gate (``absent``/``dropped``/``renamed`` block; an
  approver may override with a reason, audited);
* **approval bound to builds** — approving records the builds the approver
  validated; a fleet rollout to a build outside that set must be revalidated;
* **adapt** — a new version of the body rewritten for a target build: mapped
  renames carried to the new name, fields the build does not serve removed,
  and both listed in the version note.

Three body shapes reach here (all measured on a live library 2026-10-05):
``{"endpoint": <logical>, "data": {...}, "subobjects": [...]}`` (Web
Protection Profile capture), ``{"subobjects": [{"endpoint": "/api/v2.0/cmdb/…",
"data": {"data": {...}}}]}`` (config-section capture: note the cmdb
envelope) and ``{"items": [{"endpoint": <logical>, "data": {...}}]}`` (system
profile). :func:`iter_nodes` walks all three.
"""
from __future__ import annotations

import copy
import json
from datetime import datetime
from typing import Any, Iterable

from . import firmware_versions as fv
from . import version_compat as vc

#: Verdict levels a gate reads. ``renamed`` is a block HERE although the engine
#: reports it as a rename and not a loss: a template carries the OLD name, and
#: a build that only knows the new one discards it exactly like a dropped
#: field. "Adapt to firmware" is the fix, and the message says so.
BLOCKING_STATES = (vc.STATE_ABSENT, vc.STATE_DROPPED)


# ---------------------------------------------------------------------------
# body -> (logical, fields)
# ---------------------------------------------------------------------------

def iter_nodes(body) -> Iterable[dict]:
    """Every node of a template body that names an ``endpoint``, any shape.

    Yields the node dicts THEMSELVES (not copies), so :func:`adapt` can edit
    them in place on a deep copy of the body.
    """
    def _walk(node):
        if not isinstance(node, dict):
            return
        for sub in node.get("subobjects") or []:
            yield from _walk(sub)
        if node.get("endpoint"):
            yield node

    if isinstance(body, list):
        for n in body:
            yield from _walk(n)
        return
    if not isinstance(body, dict):
        return
    yield from _walk(body)
    for item in body.get("items") or []:          # system-profile shape
        if isinstance(item, dict) and item.get("endpoint"):
            yield item


def payload_of(node: dict) -> dict:
    """The authored field dict of a node, with the cmdb ``{"data": …}`` envelope
    removed (config-section captures carry it; profile captures do not)."""
    data = node.get("data")
    if not isinstance(data, dict):
        return {}
    if set(data) == {"data"} and isinstance(data["data"], dict):
        return data["data"]
    return data


def _registry(product: str, version: str = "") -> tuple[dict, dict]:
    """``(logical -> urn, collection -> logical)`` for ``product`` at ``version``.

    The pure registry UNION the build's view. The build view carries the URN a
    box on that build was measured serving, which can differ from the
    registry's: resolving against the view alone made a body written with the
    registry spelling fall "outside" (unchecked) the moment a sweep measured
    the build — silently shrinking every verdict.
    """
    from ..registry.loader import registry_for
    from .objform import collection_of
    product = product or "fortiweb"
    pure = registry_for(product, "") or {}
    view = registry_for(product, version) if version else {}
    reg = {**pure, **(view or {})}
    idx = {collection_of(urn): logical for logical, urn in pure.items()}
    idx.update({collection_of(urn): logical for logical, urn in (view or {}).items()})
    return reg, idx


def logical_of(endpoint: str, reg: dict, idx: dict) -> str:
    """The API-library key for a node's ``endpoint``, ``""`` when unknown.

    A body names its endpoint either by registry LOGICAL name (``signature``,
    ``dns``) or by REST path (``/api/v2.0/cmdb/system/ntp?mkey=…``).
    """
    from .objform import collection_of
    ep = (endpoint or "").strip()
    if not ep:
        return ""
    if ep in reg:
        return ep
    return idx.get(collection_of(ep), "") if "/" in ep else ""


def build_objects(body) -> list:
    """``[(endpoint, {field: value})]`` of every node a push would write, sub-rows
    included: the CLI schema knows sub-tables the REST sweep never reached, so
    the build check reads them too (by REST path or registry name)."""
    out = []
    for node in iter_nodes(body):
        if (node.get("action") or "create") == "delete":
            continue
        data = payload_of(node)
        if node.get("endpoint") and data:
            out.append((str(node["endpoint"]), dict(data)))
    return out


def template_targets(body, product: str = "fortiweb",
                     version: str = "") -> tuple[list, list]:
    """``([(logical, fields)], outside)`` for a template body.

    ``outside`` names what the API sweep cannot judge: endpoints the registry
    does not know, and sub-table rows (``kind == "subrow"`` / ``*_item``
    logicals — no sweep reaches them). They are REPORTED on every verdict and
    kept out of its level, the same split the clone pre-flight makes: a check
    that warns on every template because of them is a check operators learn to
    click past.
    """
    reg, idx = _registry(product, version)
    targets: dict[str, set] = {}
    outside: set = set()
    for node in iter_nodes(body):
        if (node.get("action") or "create") == "delete":
            continue
        key = logical_of(node.get("endpoint", ""), reg, idx)
        if not key:
            outside.add(str(node.get("endpoint")))
            continue
        if node.get("kind") == "subrow" or key.endswith("_item"):
            outside.add(key)
            continue
        fields = payload_of(node)
        if fields:
            targets.setdefault(key, set()).update(str(f) for f in fields)
    return sorted((k, sorted(v)) for k, v in targets.items()), sorted(outside)


# ---------------------------------------------------------------------------
# the stamp
# ---------------------------------------------------------------------------

def api_version_for(product: str) -> str:
    from ..registry.loader import API_VERSION
    return API_VERSION.get(product or "fortiweb", "")


def known_builds(product: str = "fortiweb") -> list[dict]:
    """The builds an author may stamp a hand-written template with.

    Exactly what the API library knows (measured, vendor-documented, declared
    or running in the fleet) — a free-text version would let a typo become a
    stamp nothing can ever be compared against.
    """
    try:
        from . import api_library as lib
        rows = lib.builds(product or "fortiweb")
    except Exception:  # noqa: BLE001 — no library -> nothing to offer
        try:
            from ..extensions import db
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        return []
    out = []
    for r in rows:
        if r.get("line_only"):
            continue        # "8.0" names a line, not a build an API can be read off
        out.append({"version": r["version"], "measured": bool(r.get("measured")),
                    "vendor_only": bool(r.get("vendor_only")),
                    "in_fleet": bool(r.get("in_fleet"))})
    return sorted(out, key=lambda r: fv.sort_key(r["version"]), reverse=True)


def stamp_from_appliance(appliance) -> dict:
    """The stamp of a body READ OFF ``appliance`` (its exact running build)."""
    product = vc._product_of(appliance) or "fortiweb"
    res = vc._resolved(appliance)
    return {"source_firmware": res.get("version") or "",
            "api_version": api_version_for(product),
            "source_appliance_id": getattr(appliance, "id", None),
            "source_appliance": getattr(appliance, "name", "") or "",
            "provenance": "captured"}


def stamp_authored(product: str, firmware: str) -> dict:
    """The stamp of a hand-written body. ``firmware`` must be a known build."""
    v = fv.normalize(firmware)
    if not v:
        raise ValueError("Choose the firmware build this template is written for")
    known = {b["version"] for b in known_builds(product)}
    if v not in known:
        raise ValueError("Firmware %s is not a build SATOM knows for %s — pick "
                         "one from the list" % (firmware, product or "fortiweb"))
    return {"source_firmware": v, "api_version": api_version_for(product),
            "source_appliance_id": None, "source_appliance": "",
            "provenance": "authored"}


def session_product() -> str:
    """The product a template saved in this request is filed under."""
    try:
        from .product_scope import stamp
        return stamp() or "fortiweb"
    except Exception:  # noqa: BLE001 — outside a request / unresolved ADOM
        return "fortiweb"


def stamp_from_form(value: str, previous=None, product: str | None = None) -> dict:
    """The stamp for a hand-saved body.

    A new version keeps its predecessor's stamp (provenance included: an edited
    capture is still a capture of that build) unless the author picks another
    build. A body with no predecessor stamp MUST name its build — unless the
    library knows NO build of the product yet (a fresh install, nothing swept,
    no appliance reporting a firmware): there is then nothing to choose from,
    and refusing would make authoring impossible. That save is kept
    unstamped, and its check says so.
    """
    v = fv.normalize(value)
    prev_fw = getattr(previous, "source_firmware", "") or ""
    if prev_fw and (not v or v == prev_fw):
        return inherit_stamp(previous)
    product = product or session_product()
    if not v and not known_builds(product):
        return {}
    return stamp_authored(product, v)


def inherit_stamp(row) -> dict:
    """A new version of ``row`` keeps the build its body was written for."""
    if row is None or not (row.source_firmware or ""):
        return {}
    return {"source_firmware": row.source_firmware,
            "api_version": row.api_version or "",
            "source_appliance_id": row.source_appliance_id,
            "source_appliance": row.source_appliance or "",
            "provenance": row.provenance or "authored"}


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------

def is_blocking(rep: dict) -> bool:
    return (rep.get("level") == "block"
            or bool(rep.get("dropped_total"))
            or bool(rep.get("renamed_total")))


def check(template, target_version: str, *, product: str | None = None,
          self_check: bool = False) -> dict:
    """The body of ``template`` against ``target_version`` (one build).

    ``self_check`` compares against the target WITHOUT a source build: the
    engine treats ``source == target`` as "same API" and stops, which is right
    for an unchanged box and useless for asking whether the body fits the very
    build it was stamped with.
    """
    product = product or getattr(template, "product", "") or "fortiweb"
    stamped = getattr(template, "source_firmware", "") or ""
    # The body spells endpoints the way its OWN build did.
    targets, outside = template_targets(template.body_dict, product,
                                        stamped or target_version)
    source = "" if self_check else stamped
    rep = vc.compare_many(product, target_version, targets, source_version=source)
    rep["outside"] = outside
    rep["blocking"] = is_blocking(rep)
    return rep


def summarize(rep: dict) -> dict:
    """The part of a report worth storing next to the template."""
    return {
        "target_version": rep.get("target_version") or "",
        "state": rep.get("state") or "",
        "level": rep.get("level") or "",
        "blocking": bool(rep.get("blocking")),
        "dropped_total": rep.get("dropped_total") or 0,
        "renamed_total": rep.get("renamed_total") or 0,
        "absent_total": rep.get("absent_total") or 0,
        "absent_keys": list(rep.get("absent_keys") or []),
        "dropped": {r["key"]: r["dropped"] for r in rep.get("rows") or []
                    if r.get("dropped")},
        "renamed": {r["key"]: r["renamed"] for r in rep.get("rows") or []
                    if r.get("renamed")},
        "objects": len(rep.get("rows") or []),
        "outside": list(rep.get("outside") or []),
        "counts": dict(rep.get("counts") or {}),
        "at": datetime.utcnow().isoformat(timespec="seconds"),
    }


def self_check_summary(template) -> dict:
    """Check a freshly saved body against the build it is stamped with."""
    v = getattr(template, "source_firmware", "") or ""
    if not v:
        return {"state": "unstamped", "level": "warn", "blocking": False,
                "reason": "no firmware recorded — the body cannot be checked "
                          "against the build it was written for",
                "at": datetime.utcnow().isoformat(timespec="seconds")}
    return summarize(check(template, v, self_check=True))


def record_self_check(template) -> dict:
    """Run and store :func:`self_check_summary`. Never raises: a library that
    cannot be read stores the error, it does not block the save."""
    try:
        summary = self_check_summary(template)
    except Exception as exc:  # noqa: BLE001
        summary = {"state": "error", "level": "warn", "blocking": False,
                   "reason": "%s: %s" % (type(exc).__name__, exc),
                   "at": datetime.utcnow().isoformat(timespec="seconds")}
    template.compat_check = json.dumps(summary, sort_keys=True)
    return summary


def validate(template, builds: Iterable[str], *, by: str = "") -> dict:
    """Check ``template`` against each build and record the verdicts.

    This is what "approved for 8.0.5" means: the approver's validation of this
    version for those builds, stored. A verdict that blocks is recorded too —
    the gate still refuses it; recording it says it was looked at.
    """
    current = template.validated_builds_dict
    out = {}
    for b in sorted({fv.normalize(x) for x in builds if fv.normalize(x)},
                    key=fv.sort_key):
        s = summarize(check(template, b))
        s["by"] = by or ""
        current[b] = out[b] = s
    template.validated_builds = json.dumps(current, sort_keys=True)
    return out


def fleet_builds(appliances) -> list[str]:
    seen = []
    for a in appliances or []:
        v = vc._resolved(a).get("version") or ""
        if v and v not in seen:
            seen.append(v)
    return seen


def for_appliances(template, appliances, *, require_validated: bool = False) -> dict:
    """Per-device verdicts for applying ``template`` to ``appliances``.

    One engine call per distinct build. ``require_validated`` is the fleet
    rollout rule: a build the approval does not cover blocks until an approver
    revalidates it.
    """
    validated = template.validated_builds_dict
    by_build: dict[str, dict] = {}
    devices, blocks, warnings = [], [], []
    for a in appliances or []:
        name = getattr(a, "name", "") or "device %s" % getattr(a, "id", "?")
        v = vc._resolved(a).get("version") or ""
        if not v:
            devices.append({"appliance_id": a.id, "appliance": name, "build": "",
                            "state": vc.STATE_UNMEASURED, "level": "warn",
                            "blocking": False,
                            "reason": "reports no firmware — cannot be checked"})
            warnings.append("%s reports no firmware: the template could not be "
                            "checked against it" % name)
            continue
        if v not in by_build:
            by_build[v] = check(template, v, product=vc._product_of(a) or None)
        rep = by_build[v]
        reasons = []
        blocking = rep["blocking"]
        if rep.get("absent_keys"):
            reasons.append("%s does not serve %s" % (v, ", ".join(rep["absent_keys"][:4])))
        for r in rep.get("rows") or []:
            if r.get("dropped"):
                reasons.append("%s would discard %s.%s" % (
                    v, r["key"], ", ".join(r["dropped"][:6])))
            for x in r.get("renamed") or []:
                reasons.append("%s renamed %s.%s → %s (adapt the template)" % (
                    v, r["key"], x["from"], x["to"]))
        if require_validated and v not in validated:
            blocking = True
            reasons.append("the approval does not cover build %s — revalidate "
                           "the template for it" % v)
        if not blocking and rep.get("level") == "warn":
            warnings.append("%s (%s): %s" % (name, v, vc.STATE_LABEL.get(
                rep["state"], rep["state"])))
        if blocking:
            blocks.extend("%s: %s" % (name, r) for r in reasons)
        devices.append({"appliance_id": a.id, "appliance": name, "build": v,
                        "state": rep["state"], "level": rep["level"],
                        "blocking": blocking, "validated": v in validated,
                        "reason": "; ".join(reasons) or vc.STATE_LABEL.get(
                            rep["state"], rep["state"])})
    outside = sorted({o for r in by_build.values() for o in r.get("outside") or []})
    # Both channels of each target's exact build (services.build_compat via
    # version_compat.build_check): per-appliance field warnings, the fields to
    # strip per device, and blocks for invalid values / objects the build lacks.
    product = getattr(template, "product", "") or next(
        (vc._product_of(a) for a in appliances or [] if vc._product_of(a)), "fortiweb")
    build = vc.build_check(product, list(appliances or []), build_objects(template.body_dict))
    by_dev = {d.get("appliance_id"): d for d in build.get("devices") or []}
    block_texts = {(m["build"], m["text"]) for m in build.get("messages") or []
                   if m["level"] == "block"}
    for d in devices:
        bd = by_dev.get(d["appliance_id"]) or {}
        d["build_level"] = bd.get("level", "ok")
        d["skips"] = bd.get("skips") or {}
        d["build_findings"] = (bd.get("findings") or [])[:50]
        if bd.get("blocking"):
            d["blocking"] = True
            own = [t for b, t in sorted(block_texts) if b == d["build"]]
            blocks.extend("%s: %s" % (d["appliance"], t) for t in own)
            d["reason"] = "; ".join(x for x in [d.get("reason") or ""] + own if x)
    warnings.extend(m["text"] for m in build.get("messages") or [] if m["level"] != "block")
    if not (getattr(template, "source_firmware", "") or ""):
        warnings.append("no firmware is recorded for this template (it predates "
                        "build stamps) — fields are checked against each "
                        "target, renames cannot be")
    return {"template_id": template.id, "name": template.name,
            "version": template.version,
            "source_firmware": getattr(template, "source_firmware", "") or "",
            "provenance": getattr(template, "provenance", "") or "",
            "devices": devices,
            "builds": {b: summarize(r) for b, r in by_build.items()},
            "blocked": any(d["blocking"] for d in devices),
            "blocks": blocks, "warnings": warnings, "outside": outside,
            "build_messages": build.get("messages") or [],
            "skips": build.get("skips") or {}}


def merge_skips(reports) -> dict:
    """Union of several ``{appliance_id: {endpoint: [field]}}`` skip maps."""
    out: dict = {}
    for rep in reports or []:
        for aid, eps in (rep or {}).items():
            for ep, fields in (eps or {}).items():
                cur = out.setdefault(aid, {}).setdefault(ep, [])
                cur.extend(f for f in fields if f not in cur)
    return out


def enforce(template, appliances, *, user=None, override_reason: str = "",
            require_validated: bool = False, action: str = "template.apply") -> tuple[bool, dict]:
    """The apply gate. ``(allowed, report)``.

    A blocked report passes only with an override: a non-empty reason from a
    user holding ``operations.template_approve``. Every override is audited
    with the reason and what it overrode.
    """
    rep = for_appliances(template, appliances, require_validated=require_validated)
    rep["overridden"] = False
    if not rep["blocked"]:
        return True, rep
    reason = (override_reason or "").strip()
    can = bool(user is not None and getattr(user, "can", None)
               and user.can("operations.template_approve"))
    if reason and can:
        from .audit import log_action
        log_action("template.compat.override",
                   target="%s/%s v%s" % (template.kind, template.name, template.version),
                   detail=("%s; reason: %s; overrode: %s"
                           % (action, reason[:300], " | ".join(rep["blocks"])[:1500])))
        rep["overridden"] = True
        return True, rep
    rep["override_hint"] = ("an approver (Approve templates permission) can "
                            "override with a reason" if not can else
                            "give an override reason to proceed")
    return False, rep


# ---------------------------------------------------------------------------
# adapt
# ---------------------------------------------------------------------------

def adapt_plan(template, target_version: str) -> dict:
    """What "Adapt to ``target_version``" would change, without saving anything."""
    target = fv.normalize(target_version)
    if not target:
        raise ValueError("Choose the firmware build to adapt to")
    rep = check(template, target)
    renames = {r["key"]: {x["from"]: x["to"] for x in r.get("renamed") or []}
               for r in rep.get("rows") or [] if r.get("renamed")}
    drops = {r["key"]: list(r.get("dropped") or [])
             for r in rep.get("rows") or [] if r.get("dropped")}
    return {"target_version": target, "state": rep["state"],
            "absent_keys": list(rep.get("absent_keys") or []),
            "renames": renames, "drops": drops,
            "outside": rep.get("outside") or [],
            "unmeasured": [r["key"] for r in rep.get("rows") or []
                           if r["state"] in (vc.STATE_UNMEASURED, vc.STATE_BLIND)],
            "changes": sum(len(v) for v in renames.values())
                       + sum(len(v) for v in drops.values())}


def adapted_body(template, plan: dict) -> dict:
    body = copy.deepcopy(template.body_dict)
    product = getattr(template, "product", "") or "fortiweb"
    reg, idx = _registry(product, getattr(template, "source_firmware", "")
                         or plan["target_version"])
    for node in iter_nodes(body):
        key = logical_of(node.get("endpoint", ""), reg, idx)
        if not key:
            continue
        data = payload_of(node)
        for old, new in (plan["renames"].get(key) or {}).items():
            if old in data and new not in data:
                data[new] = data.pop(old)
        for f in plan["drops"].get(key) or []:
            data.pop(f, None)
    return body


def adapt(template, target_version: str, *, author: str = "") -> tuple[Any, dict]:
    """Save a NEW VERSION of ``template`` rewritten for ``target_version``.

    Refused when the target does not serve an object the body creates (no
    rewrite of a field list can make an endpoint exist) or when there is
    nothing to change. The new version is pending: adapting is authoring.
    """
    plan = adapt_plan(template, target_version)
    if plan["absent_keys"]:
        raise ValueError("%s does not serve %s — adapting fields cannot fix a "
                         "missing object" % (plan["target_version"],
                                             ", ".join(plan["absent_keys"])))
    if not plan["changes"]:
        raise ValueError("nothing to adapt: every checked field of this "
                         "template is served by %s" % plan["target_version"])
    from .templates import save_template
    lines = ["Adapted from v%s (%s) to %s." % (
        template.version, template.source_firmware or "no firmware recorded",
        plan["target_version"])]
    for key, m in sorted(plan["renames"].items()):
        lines.append("Renamed in %s: %s." % (
            key, ", ".join("%s → %s" % kv for kv in sorted(m.items()))))
    for key, fields in sorted(plan["drops"].items()):
        lines.append("Removed from %s (not served by %s): %s." % (
            key, plan["target_version"], ", ".join(sorted(fields))))
    product = getattr(template, "product", "") or "fortiweb"
    row = save_template(
        template.kind, template.name, adapted_body(template, plan),
        note=" ".join(lines), author=author,
        exceptions=template.exceptions or None,
        stamp={"source_firmware": plan["target_version"],
               "api_version": api_version_for(product),
               "source_appliance_id": None, "source_appliance": "",
               "provenance": "adapted", "adapted_from_id": template.id})
    return row, plan
