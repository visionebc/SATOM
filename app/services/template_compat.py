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
import re
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
    """A verdict the apply gate refuses.

    ``unmeasured`` (no evidence for that build at all) blocks like ``absent``:
    a build nobody measured is not a build the template was shown to fit, and
    letting it through as a warning turns "unknown" into "accepted" by
    omission. ``blind`` (the endpoint is served, its fields were never read)
    stays a warning — it still proves the object can exist there.
    """
    return (rep.get("level") == "block"
            or bool(rep.get("dropped_total"))
            or bool(rep.get("renamed_total"))
            or bool((rep.get("counts") or {}).get(vc.STATE_UNMEASURED)))


def verdict_text(summary: dict) -> str:
    """One sentence for a :func:`summarize` result (or a raw report)."""
    if not summary:
        return "not checked"
    if summary.get("state") == "unstamped":
        return summary.get("reason") or "no firmware recorded"
    target = summary.get("target_version") or "the target build"
    parts = []
    absent = summary.get("absent_keys") or []
    if absent:
        parts.append("%s does not serve %s" % (target, ", ".join(absent[:4])))
    dropped = summary.get("dropped") or {}
    if dropped:
        parts.append("%d field(s) would be discarded (%s)" % (
            sum(len(v) for v in dropped.values()),
            "; ".join("%s: %s" % (k, ", ".join(v[:4])) for k, v in sorted(dropped.items())[:3])))
    renamed = summary.get("renamed") or {}
    if renamed:
        parts.append("%d field(s) renamed (%s) — adapt the template" % (
            sum(len(v) for v in renamed.values()),
            "; ".join("%s: %s" % (k, ", ".join("%s→%s" % (x["from"], x["to"]) for x in v[:3]))
                      for k, v in sorted(renamed.items())[:3])))
    if (summary.get("counts") or {}).get(vc.STATE_UNMEASURED):
        parts.append("no evidence for %s on %d object(s) — measure the build "
                     "(harvester) before trusting it" % (
                         target, summary["counts"][vc.STATE_UNMEASURED]))
    if parts:
        return "; ".join(parts)
    if summary.get("level") == "warn":
        return "fits %s with warnings (%s)" % (target, ", ".join(
            "%s %s" % (n, k) for k, n in sorted((summary.get("counts") or {}).items())))
    return "fits %s" % target


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
        "new_fields": {r["key"]: list(r["new_fields"]) for r in rep.get("rows") or []
                       if r.get("new_fields")},
        "new_unmeasured": rep.get("new_unmeasured") or 0,
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
                            "state": vc.STATE_UNMEASURED, "level": "block",
                            "blocking": True,
                            "reason": "reports no firmware — cannot be checked"})
            blocks.append("%s: reports no firmware, so the template cannot be "
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
            if r.get("state") == vc.STATE_UNMEASURED:
                reasons.append("no evidence for %s on %s — measure the build "
                               "before applying" % (v, r["key"]))
        undecided = undecided_new_fields(template, rep)
        if undecided:
            warnings.append("%s (%s) adds %d field(s) this template does not "
                            "decide — the device default applies: %s. Adapt the "
                            "template to %s to decide them." % (
                                name, v, sum(len(x) for x in undecided.values()),
                                "; ".join("%s: %s" % (k, ", ".join(f[:5]))
                                          for k, f in sorted(undecided.items())[:3]), v))
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

def field_decisions(template) -> dict:
    """``{build: {key: {field: {"mode": "default"|"set", "value": …}}}}``."""
    try:
        data = json.loads(getattr(template, "field_decisions", "") or "{}")
        return data if isinstance(data, dict) else {}
    except (ValueError, TypeError):
        return {}


def undecided_new_fields(template, rep: dict) -> dict:
    """The fields ``rep``'s build adds (over the template's own build) that
    the template neither carries nor decided. ``{key: [field]}``."""
    target = rep.get("target_version") or ""
    decided = field_decisions(template).get(target) or {}
    out = {}
    for r in rep.get("rows") or []:
        left = [f for f in r.get("new_fields") or []
                if f not in (decided.get(r["key"]) or {})]
        if left:
            out[r["key"]] = left
    return out


def adapt_plan(template, target_version: str) -> dict:
    """What "Adapt to ``target_version``" would change, without saving anything.

    ``new_fields`` are the fields the target build adds over the template's
    own build: the adaptation must decide each one (keep the device default or
    set a value) — leaving them out silently is how a template "passes" and
    the upgraded device still behaves differently.
    """
    target = fv.normalize(target_version)
    if not target:
        raise ValueError("Choose the firmware build to adapt to")
    rep = check(template, target)
    renames = {r["key"]: {x["from"]: x["to"] for x in r.get("renamed") or []}
               for r in rep.get("rows") or [] if r.get("renamed")}
    drops = {r["key"]: list(r.get("dropped") or [])
             for r in rep.get("rows") or [] if r.get("dropped")}
    new_fields = {r["key"]: list(r["new_fields"]) for r in rep.get("rows") or []
                  if r.get("new_fields")}
    specs = {r["key"]: {f: r["new_field_specs"].get(f) or {} for f in r["new_fields"]}
             for r in rep.get("rows") or [] if r.get("new_fields")}
    return {"target_version": target, "state": rep["state"],
            "source_firmware": getattr(template, "source_firmware", "") or "",
            "absent_keys": list(rep.get("absent_keys") or []),
            "renames": renames, "drops": drops,
            "new_fields": new_fields, "new_field_specs": specs,
            "new_fields_unknown": [r["key"] for r in rep.get("rows") or []
                                   if r.get("new_fields_state") not in ("measured", "same")],
            "outside": rep.get("outside") or [],
            "unmeasured": [r["key"] for r in rep.get("rows") or []
                           if r["state"] in (vc.STATE_UNMEASURED, vc.STATE_BLIND)],
            "changes": sum(len(v) for v in renames.values())
                       + sum(len(v) for v in drops.values())
                       + sum(len(v) for v in new_fields.values())}


#: A new field whose value is a secret is never stored in a template body
#: (secrets are entered at apply time): only "keep the device default".
_SECRET_FIELD = re.compile(r"(secret|passw|psk|private|passphrase|-key$|^key$)", re.I)


def _is_secret_field(field: str, spec: dict | None) -> bool:
    t = str((spec or {}).get("type") or "").lower()
    return t in ("password", "secret") or bool(_SECRET_FIELD.search(field or ""))


def clean_decisions(plan: dict, raw) -> dict:
    """Validate the operator's decisions against ``plan["new_fields"]``.

    Every new field must be decided; a decision for a field the plan does not
    list is refused (it would be a write nobody was shown). Raises ``ValueError``.
    """
    if isinstance(raw, str):
        try:
            raw = json.loads(raw or "{}")
        except ValueError as exc:
            raise ValueError("decisions must be JSON: %s" % exc) from exc
    raw = raw if isinstance(raw, dict) else {}
    out: dict = {}
    missing = []
    for key, fields in sorted((plan.get("new_fields") or {}).items()):
        given = raw.get(key) if isinstance(raw.get(key), dict) else {}
        for f in fields:
            d = given.get(f)
            if not isinstance(d, dict) or d.get("mode") not in ("default", "set"):
                missing.append("%s.%s" % (key, f))
                continue
            if d["mode"] == "set":
                spec = ((plan.get("new_field_specs") or {}).get(key) or {}).get(f)
                if _is_secret_field(f, spec):
                    raise ValueError("%s.%s is a secret: a template never stores "
                                     "one — keep the device default and set it "
                                     "on the device" % (key, f))
                if d.get("value") in (None, ""):
                    raise ValueError("%s.%s: give a value or keep the device default"
                                     % (key, f))
                out.setdefault(key, {})[f] = {"mode": "set", "value": d["value"]}
            else:
                out.setdefault(key, {})[f] = {"mode": "default"}
        extra = sorted(set(given) - set(fields))
        if extra:
            raise ValueError("%s: %s is not a new field of %s" % (
                key, ", ".join(extra), plan["target_version"]))
    unknown_keys = sorted(set(raw) - set(plan.get("new_fields") or {}))
    if unknown_keys:
        raise ValueError("no new fields to decide for %s" % ", ".join(unknown_keys))
    if missing:
        raise ValueError("decide every field %s adds (keep the device default or "
                         "set a value): %s" % (plan["target_version"],
                                               ", ".join(missing[:12])
                                               + (" (+%d more)" % (len(missing) - 12)
                                                  if len(missing) > 12 else "")))
    return out


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
        if (node.get("action") or "create") == "delete" or node.get("kind") == "subrow":
            continue
        for f, d in ((plan.get("decisions") or {}).get(key) or {}).items():
            if d.get("mode") == "set" and isinstance(node.get("data"), dict):
                data[f] = d["value"]
    return body


def adapt(template, target_version: str, *, author: str = "",
          decisions=None) -> tuple[Any, dict]:
    """Save a NEW VERSION of ``template`` rewritten for ``target_version``.

    Refused when the target does not serve an object the body creates (no
    rewrite of a field list can make an endpoint exist), when there is
    nothing to change, or when a field the target adds is left undecided.
    The new version is pending: adapting is authoring.
    """
    plan = adapt_plan(template, target_version)
    plan["decisions"] = clean_decisions(plan, decisions)
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
    for key, dec in sorted(plan["decisions"].items()):
        kept = sorted(f for f, d in dec.items() if d["mode"] == "default")
        set_ = sorted(f for f, d in dec.items() if d["mode"] == "set")
        if set_:
            lines.append("New in %s on %s, set: %s." % (
                key, plan["target_version"],
                ", ".join("%s=%s" % (f, dec[f]["value"]) for f in set_)))
        if kept:
            lines.append("New in %s on %s, device default kept: %s." % (
                key, plan["target_version"], ", ".join(kept)))
    product = getattr(template, "product", "") or "fortiweb"
    row = save_template(
        template.kind, template.name, adapted_body(template, plan),
        note=" ".join(lines), author=author,
        exceptions=template.exceptions or None,
        stamp={"source_firmware": plan["target_version"],
               "api_version": api_version_for(product),
               "source_appliance_id": None, "source_appliance": "",
               "provenance": "adapted", "adapted_from_id": template.id})
    decided = field_decisions(template)
    if plan["decisions"]:
        decided[plan["target_version"]] = plan["decisions"]
    row.field_decisions = json.dumps(decided, sort_keys=True) if decided else ""
    return row, plan


# ---------------------------------------------------------------------------
# stamping a legacy template
# ---------------------------------------------------------------------------

def _fit_score(summary: dict, version: str) -> tuple:
    counts = summary.get("counts") or {}
    return (bool(summary.get("blocking")),
            len(summary.get("absent_keys") or []),
            sum(len(v) for v in (summary.get("dropped") or {}).values())
            + sum(len(v) for v in (summary.get("renamed") or {}).values()),
            counts.get(vc.STATE_UNMEASURED, 0),
            counts.get(vc.STATE_BLIND, 0),
            fv.sort_key(version))


def stamp_candidates(template) -> list[dict]:
    """Every MEASURED build of the template's ADOM, best fit first.

    A legacy body was written for SOME build and nobody recorded which. The
    build its fields fit best (nothing discarded, nothing unmeasured, the
    oldest on a tie — the baseline upgrades are then judged forward from) is
    the evidence-backed answer; :func:`stamp_legacy` records it as AUTHORED,
    never as captured.
    """
    product = getattr(template, "product", "") or "fortiweb"
    out = []
    for b in known_builds(product):
        if not b["measured"]:
            continue
        try:
            s = summarize(check(template, b["version"], self_check=True))
        except Exception as exc:  # noqa: BLE001 — one unreadable build never hides the rest
            s = {"state": "error", "level": "warn", "blocking": True,
                 "reason": "%s: %s" % (type(exc).__name__, exc)}
        s["build"] = b["version"]
        s["in_fleet"] = b["in_fleet"]
        s["text"] = verdict_text(s)
        out.append(s)
    out.sort(key=lambda s: _fit_score(s, s["build"]))
    return out


def stamp_legacy(template, build: str = "", *, by: str = "") -> dict:
    """Record the build a LEGACY template (no stamp) was written for.

    ``build`` empty = the best fit of :func:`stamp_candidates`; a named build
    must be a measured one. Refused when the template already carries a
    stamp (a stamp is never rewritten: adapt makes a new version instead) and
    when no measured build fits the body without discarding fields.
    """
    if (getattr(template, "source_firmware", "") or ""):
        raise ValueError("%r v%s already records firmware %s — adapt it to "
                         "another build instead" % (template.name, template.version,
                                                    template.source_firmware))
    cands = stamp_candidates(template)
    if not cands:
        raise ValueError("no measured build of %s is known — measure one first"
                         % (template.product or "fortiweb"))
    want = fv.normalize(build)
    pick = next((c for c in cands if c["build"] == want), None) if want else cands[0]
    if pick is None:
        raise ValueError("%s is not a measured build of %s" % (build, template.product))
    if pick.get("blocking"):
        raise ValueError("%r does not fit %s (%s) — no measured build fits this "
                         "body; re-capture it from a device" % (
                             template.name, pick["build"], pick.get("text")))
    product = getattr(template, "product", "") or "fortiweb"
    template.source_firmware = pick["build"]
    template.api_version = api_version_for(product)
    template.provenance = "authored"
    stamp_note = ("Firmware %s recorded on %s by %s: the build this legacy body "
                  "fits best (%s)." % (pick["build"],
                                       datetime.utcnow().strftime("%Y-%m-%d"),
                                       by or "system", pick["text"]))
    template.note = ((template.note or "").rstrip() + "\n" + stamp_note).strip()
    record_self_check(template)
    return {"build": pick["build"], "candidates": cands, "note": stamp_note}


# ---------------------------------------------------------------------------
# matrix and comparison
# ---------------------------------------------------------------------------

#: Matrix cell verdicts, worst first.
CELL_BLOCK, CELL_ADAPT, CELL_UNMEASURED, CELL_WARN, CELL_OK = (
    "block", "adapt", "unmeasured", "warn", "ok")


def cell_of(summary: dict, template=None) -> str:
    """One matrix cell from a :func:`summarize` result."""
    if summary.get("absent_keys") or summary.get("state") == "error":
        return CELL_BLOCK
    if (summary.get("counts") or {}).get(vc.STATE_UNMEASURED):
        return CELL_UNMEASURED
    if summary.get("dropped") or summary.get("renamed"):
        return CELL_ADAPT
    if summary.get("blocking"):
        return CELL_BLOCK
    target = summary.get("target_version") or ""
    decided = field_decisions(template).get(target) or {} if template is not None else {}
    if any(f not in (decided.get(k) or {})
           for k, fs in (summary.get("new_fields") or {}).items() for f in fs):
        return CELL_ADAPT
    if summary.get("level") == "warn":
        return CELL_WARN
    return CELL_OK


def matrix_builds(product: str = "fortiweb", extra: Iterable[str] = ()) -> list[dict]:
    """The columns of the matrix: every measured or fleet build, newest first,
    plus ``extra`` (a target an operator is considering)."""
    cols = [b for b in known_builds(product) if b["measured"] or b["in_fleet"]]
    have = {b["version"] for b in cols}
    for e in extra or []:
        v = fv.normalize(e)
        if v and v not in have:
            cols.append({"version": v, "measured": False, "vendor_only": False,
                         "in_fleet": False})
            have.add(v)
    return sorted(cols, key=lambda r: fv.sort_key(r["version"]), reverse=True)


def matrix(templates, builds: Iterable[str]) -> list[dict]:
    """``[{template, cells: {build: {cell, text, summary}}}]``."""
    from . import api_library as lib
    with lib.channel_memo():
        return _matrix(templates, builds)


def _matrix(templates, builds) -> list[dict]:
    out = []
    for t in templates or []:
        cells = {}
        for b in builds:
            try:
                s = summarize(check(t, b))
            except Exception as exc:  # noqa: BLE001
                s = {"state": "error", "level": "warn", "blocking": True,
                     "target_version": b, "reason": "%s: %s" % (type(exc).__name__, exc)}
            cells[b] = {"cell": cell_of(s, t), "text": verdict_text(s)
                        if s.get("state") != "error" else s["reason"], "summary": s}
        out.append({"template": t, "cells": cells})
    return out


def _nodes_by_key(template) -> dict:
    """``{(logical or endpoint, object name): {field: value}}`` of a body."""
    product = getattr(template, "product", "") or "fortiweb"
    reg, idx = _registry(product, getattr(template, "source_firmware", "") or "")
    out: dict = {}
    for i, node in enumerate(iter_nodes(template.body_dict)):
        if (node.get("action") or "create") == "delete":
            continue
        ep = str(node.get("endpoint") or "")
        key = logical_of(ep, reg, idx) or ep
        data = payload_of(node)
        ident = (data.get("name") or node.get("mkey") or data.get("id")
                 or ("#%d" % i if node.get("kind") == "subrow" else ""))
        slot = (key, str(ident))
        if slot in out:
            slot = (key, "%s#%d" % (ident, i))
        out[slot] = dict(data)
    return out


def body_diff(a, b) -> dict:
    """Field-level difference of two template bodies (``a`` → ``b``)."""
    na, nb = _nodes_by_key(a), _nodes_by_key(b)
    objects = []
    for slot in sorted(set(na) | set(nb)):
        key, ident = slot
        if slot not in na:
            objects.append({"key": key, "object": ident, "change": "added",
                            "fields": sorted(nb[slot])})
            continue
        if slot not in nb:
            objects.append({"key": key, "object": ident, "change": "removed",
                            "fields": sorted(na[slot])})
            continue
        fa, fb = na[slot], nb[slot]
        added = sorted(set(fb) - set(fa))
        removed = sorted(set(fa) - set(fb))
        changed = [{"field": f, "from": fa[f], "to": fb[f]}
                   for f in sorted(set(fa) & set(fb)) if fa[f] != fb[f]]
        if added or removed or changed:
            objects.append({"key": key, "object": ident, "change": "changed",
                            "added": {f: fb[f] for f in added},
                            "removed": {f: fa[f] for f in removed},
                            "changed": changed})
    return {"objects": objects,
            "counts": {c: sum(1 for o in objects if o["change"] == c)
                       for c in ("added", "removed", "changed")},
            "identical": not objects}


def compare(current, newer, build: str = "", *, appliance=None) -> dict:
    """Is ``newer`` a valid replacement for ``current`` on ``build``?

    ``build`` defaults to the device's running build when ``appliance`` is
    given, else to the newer template's own build. The verdict is VALID only
    when ``newer`` fits the build (nothing discarded, renamed, absent or
    unmeasured), decides every field the build adds, and — on a device — has
    no unresolved variable for it. Approval is reported apart: a valid but
    pending version still cannot be rolled out to the fleet.
    """
    if (current.product or "fortiweb") != (newer.product or "fortiweb"):
        raise ValueError("the two templates belong to different ADOMs")
    if current.kind != newer.kind:
        raise ValueError("compare two templates of the same kind (%s vs %s)"
                         % (current.kind, newer.kind))
    if appliance is not None and not build:
        build = vc._resolved(appliance).get("version") or ""
    build = fv.normalize(build) or (newer.source_firmware or "")
    if not build:
        raise ValueError("choose the firmware build to compare against")
    sides = {}
    for label, t in (("current", current), ("newer", newer)):
        s = summarize(check(t, build))
        sides[label] = {"id": t.id, "name": t.name, "version": t.version,
                        "status": t.status, "source_firmware": t.source_firmware or "",
                        "provenance": t.provenance or "",
                        "validated_for_build": build in t.validated_builds_dict,
                        "summary": s, "cell": cell_of(s, t), "text": verdict_text(s),
                        "undecided": {k: [f for f in fs if f not in
                                          ((field_decisions(t).get(build) or {}).get(k) or {})]
                                      for k, fs in (s.get("new_fields") or {}).items()}}
        sides[label]["undecided"] = {k: v for k, v in sides[label]["undecided"].items() if v}
    reasons = []
    n = sides["newer"]
    if n["summary"].get("blocking"):
        reasons.append(n["text"])
    if n["undecided"]:
        reasons.append("%s adds field(s) the newer template does not decide: %s" % (
            build, "; ".join("%s: %s" % (k, ", ".join(v[:6]))
                             for k, v in sorted(n["undecided"].items()))))
    device = None
    if appliance is not None:
        from . import template_bindings as tb
        missing = tb.render(newer.body_dict,
                            tb.variables_for(newer, [appliance.id]).get(appliance.id))[1]
        dev = for_appliances(newer, [appliance])
        device = {"appliance_id": appliance.id, "appliance": appliance.name,
                  "build": build, "blocked": dev["blocked"], "blocks": dev["blocks"],
                  "warnings": dev["warnings"], "missing_variables": missing}
        if missing:
            reasons.append("%s has no value for %s" % (appliance.name, ", ".join(missing)))
        reasons.extend(x for x in dev["blocks"] if x not in reasons)
    valid = not reasons
    return {"build": build, "current": sides["current"], "newer": n,
            "diff": body_diff(current, newer), "device": device,
            "valid": valid, "reasons": reasons,
            "approved": newer.status == "approved",
            "verdict": ("valid for %s" % build if valid else "not valid for %s" % build)
                       + ("" if newer.status == "approved" or not valid
                          else " (pending approval: not deployable to the fleet yet)")}

