"""Which build a carve-out was authored for, and does it fit the box it is pushed to?

The carve-out side of :mod:`services.template_compat`. A carve-out payload is
written into one sub-table of one API surface, and a FortiWeb that does not
know a field answers **200 and discards it** — so a carve-out authored on 7.6
and pushed to 8.0 (or placed from a 7.6 box onto an 8.0 one) can land without
the field that made it a carve-out, and report success.

* **the stamp** — every placement records the build (``source_firmware``) and
  REST API version of the appliance it was authored on; a placement copied to
  another scope keeps the SOURCE stamp, because its payload was written against
  the source build, not against the destination's;
* **the push check** — the payload against the target's running build, one
  :func:`version_compat.compare_object` call, the same engine templates, the
  clone pre-flight and the upgrade flow ask;
* **the gate** — ``absent`` / ``dropped`` / ``renamed`` block, exactly the
  template rule; an approver may override with a reason, audited.

**Today the gate is mostly a label.** The API sweep does not reach the
carve-out sub-tables (``*_item``), so on every measured build their fields are
``unmeasured`` or ``blind`` (checked on a live library 2026-10-06). The verdict
says so — never green — and the gate starts to bite on its own the day a sweep
records those fields. An endpoint the target does not serve is already refused
by :func:`exception_inject.plan_injection` (``no-endpoint``).
"""
from __future__ import annotations

from datetime import datetime

from . import version_compat as vc

BLOCKING_STATES = (vc.STATE_ABSENT, vc.STATE_DROPPED)


def stamp_for(appliance) -> dict:
    """``{source_firmware, api_version}`` of a payload authored on ``appliance``."""
    if appliance is None:
        return {"source_firmware": "", "api_version": ""}
    from .template_compat import api_version_for
    product = vc._product_of(appliance) or "fortiweb"
    return {"source_firmware": vc._resolved(appliance).get("version") or "",
            "api_version": api_version_for(product)}


def stamp_of(row) -> dict:
    """The stamp a row already carries (``""`` = authored before stamps)."""
    return {"source_firmware": getattr(row, "source_firmware", "") or "",
            "api_version": getattr(row, "api_version", "") or ""}


def apply_stamp(row, stamp: dict) -> None:
    row.source_firmware = (stamp or {}).get("source_firmware") or ""
    row.api_version = (stamp or {}).get("api_version") or ""


def _item_logical(exc_type: str) -> str:
    from .exception_inject import rest_for
    rest = rest_for(exc_type)
    return rest.item_logical if rest else ""


def check(exc, appliance) -> dict:
    """The carve-out ``exc`` against ``appliance``'s running build.

    Never raises: a library that cannot be read is a ``warn`` verdict saying
    so, never a silent pass.
    """
    stamped = getattr(exc, "source_firmware", "") or ""
    out = {"source_firmware": stamped,
           "api_version": getattr(exc, "api_version", "") or "",
           "target_version": "", "key": _item_logical(exc.exc_type),
           "state": vc.STATE_UNMEASURED, "level": "warn", "blocking": False,
           "dropped": [], "renamed": [], "reason": "",
           "at": datetime.utcnow().isoformat(timespec="seconds")}
    target = vc._resolved(appliance).get("version") or ""
    out["target_version"] = target
    if not target:
        out["reason"] = "the device reports no firmware — the carve-out cannot " \
                        "be checked against it"
        return out
    if not out["key"]:
        out["reason"] = "no inject mapping for %r" % exc.exc_type
        return out
    try:
        rep = vc.compare_object(
            vc._product_of(appliance) or "fortiweb", target, out["key"],
            sorted((exc.payload_dict or {}).keys()),
            # A stamp equal to the target answers "same API" without looking,
            # which is right: the payload was authored against that very build.
            source_version=stamped)
    except Exception as exc_:  # noqa: BLE001
        try:
            from ..extensions import db
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        out["reason"] = "%s: %s" % (type(exc_).__name__, exc_)
        return out
    out.update(state=rep.get("state") or vc.STATE_UNMEASURED,
               level=rep.get("level") or "warn",
               dropped=list(rep.get("dropped") or []),
               renamed=list(rep.get("renamed") or []),
               reason=rep.get("reason") or "")
    out["blocking"] = (out["state"] in BLOCKING_STATES or bool(out["dropped"])
                       or bool(out["renamed"]))
    reasons = []
    if out["state"] == vc.STATE_ABSENT:
        reasons.append("%s does not serve %s" % (target, out["key"]))
    if out["dropped"]:
        reasons.append("%s would discard %s" % (target, ", ".join(out["dropped"][:8])))
    for x in out["renamed"]:
        reasons.append("%s renamed %s → %s (edit the carve-out for this build)"
                       % (target, x.get("from"), x.get("to")))
    if not stamped:
        reasons.append("no firmware is recorded for this carve-out (it predates "
                       "build stamps) — renames cannot be checked")
    elif stamped != target and not out["blocking"]:
        reasons.append("authored on %s, pushed to %s" % (stamped, target))
    out["summary"] = "; ".join(reasons) or vc.STATE_LABEL.get(out["state"], out["state"])
    return out


def gate(exc, appliance, *, apply: bool, user=None,
         override_reason: str = "") -> tuple[bool, dict]:
    """``(allowed, verdict)`` for pushing ``exc`` onto ``appliance``.

    A dry-run is always allowed (it is how the operator SEES the verdict). A
    real push of a blocking verdict needs a reason from a user holding
    ``operations.template_approve`` — the same permission and the same audit
    the template gate uses, so "who may write past a compatibility verdict"
    has one answer.
    """
    rep = check(exc, appliance)
    rep["overridden"] = False
    if not rep["blocking"] or not apply:
        return True, rep
    reason = (override_reason or "").strip()
    can = bool(user is not None and getattr(user, "can", None)
               and user.can("operations.template_approve"))
    if reason and can:
        from .audit import log_action
        log_action("exception.compat.override",
                   target="wpp_exception:%s" % getattr(exc, "id", "?"),
                   detail="push to %s (%s); reason: %s; overrode: %s" % (
                       getattr(appliance, "name", "?"), rep["target_version"],
                       reason[:300], rep.get("summary", "")[:1500]))
        rep["overridden"] = True
        return True, rep
    rep["override_hint"] = ("an approver (Approve templates permission) can "
                            "override with a reason" if not can else
                            "give an override reason to proceed")
    return False, rep


__all__ = ["stamp_for", "stamp_of", "apply_stamp", "check", "gate",
           "BLOCKING_STATES"]
