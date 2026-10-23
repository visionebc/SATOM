"""Operations > Automation > Mass Deploy (2026-10-24).

The approved templates of the active ADOM, pushed to one or many of its devices
in one audited job — an SMTP server change, an NTP or DNS change, a special Web
Protection Profile for some devices. The page owns no deploy logic: preview,
firmware check, variables, secrets and the canary job are
``services.template_apply``, the engine Template Library > Apply uses.

What the page adds:

* the catalog: the newest APPROVED version of each template family of the
  ADOM (an older approved version is not offered: a device bound to it keeps
  it through its binding, which is what a pin is for);
* the targets: the ADOM's devices, each with its build, its fit for the
  template and its binding. A device bound to another version of the family is
  not selectable (``template_apply.pin_state``);
* Web Protection Profiles: a family that governs only its bound devices
  (bindings, or rollout scope ``selected``) BINDS each device it is deployed
  to, so the lock and the next approval follow; a family that governs every
  FortiWeb can be limited to the selected devices from here (``limit``);
* the history (``models_mass_deploy.MassDeploy``), finished by the job.
"""
from __future__ import annotations

import json
from datetime import datetime

from ..extensions import db
from ..models import Appliance, Template, visible_appliances
from ..models_mass_deploy import (MassDeploy, SCOPE_FLEET, SCOPE_SELECTED)
from . import secret_mask
from . import template_apply as ta
from . import template_bindings as tb
from . import templates as lib
from .bulk import iter_push_items

#: Device ADOMs the page deploys in (adom_menu reads it).
PRODUCTS = ta.SUPPORTED_KINDS

HISTORY_LIMIT = 50


def catalog(product: str) -> list[dict]:
    """The newest approved version of every template family of ``product``."""
    latest: dict = {}
    for t in lib.list_templates(None):
        if (t.product or "fortiweb") != product or t.status != Template.STATUS_APPROVED:
            continue
        key = (t.kind, t.name)
        if key not in latest or t.version > latest[key].version:
            latest[key] = t
    out = []
    for t in sorted(latest.values(), key=lambda r: (lib.KIND_LABELS.get(r.kind, r.kind),
                                                    r.name.lower())):
        items = iter_push_items(t.body_dict)
        out.append({"t": t, "items": len(items),
                    "kind_label": lib.KIND_LABELS.get(t.kind, _config_label(t.kind)),
                    "secrets": [f["label"] for f in secret_mask.secret_fields(items)],
                    "validated": sorted(t.validated_builds_dict),
                    "scope": scope_info(t)})
    return out


def _config_label(kind: str) -> str:
    if (kind or "").startswith(Template.KIND_CONFIG_PREFIX):
        return "Config · " + kind[len(Template.KIND_CONFIG_PREFIX):].replace("_", " ").title()
    return kind


def get_deployable(template_id: int, product: str) -> Template | None:
    """The template if it is the newest approved version of its family in
    ``product``'s ADOM — what the catalog offers, nothing else."""
    row = lib.get_template(template_id)
    if row is None or (row.product or "fortiweb") != product \
            or row.status != Template.STATUS_APPROVED:
        return None
    newer = (Template.query.filter_by(kind=row.kind, name=row.name,
                                      status=Template.STATUS_APPROVED)
             .filter(Template.version > row.version).first())
    return None if newer is not None else row


def scope_info(t: Template) -> dict:
    """Who a family governs, as the page explains it."""
    bound = [b.appliance_id for b in tb.for_template(t)]
    scope = tb.family_scope(t.kind, t.name)
    wpp = t.kind == Template.KIND_WEB_PROTECTION
    if bound:
        text = "Governs its %d bound device(s)" % len(bound)
    elif scope == SCOPE_SELECTED:
        text = "Governs only the devices it is deployed to (none yet)"
    else:
        text = "Governs every device of the ADOM"
    return {"scope": scope, "bound": bound, "scoped": bool(bound) or scope == SCOPE_SELECTED,
            "wpp": wpp, "text": text}


def device_rows(t: Template, product: str) -> list[dict]:
    """The ADOM's devices against template ``t``: build, fit, binding, and
    whether they can be selected."""
    from . import template_compat as tc
    from . import version_compat as vc
    rows = []
    devs = visible_appliances().filter(Appliance.kind == product) \
        .order_by(Appliance.name).all()
    binds = {b.appliance_id: b for b in tb.for_template(t)}
    for a in devs:
        build = vc._resolved(a).get("version") or ""
        if build:
            try:
                s = tc.summarize(tc.check(t, build))
                fit = {"cell": tc.cell_of(s, t), "text": tc.verdict_text(s),
                       "blocking": bool(s.get("blocking"))}
            except Exception as exc:  # noqa: BLE001 — one bad build never hides the rest
                fit = {"cell": "unmeasured", "text": "%s: %s" % (type(exc).__name__, exc),
                       "blocking": False}
        else:
            fit = {"cell": "unmeasured", "text": "the device reports no firmware",
                   "blocking": False}
        b = binds.get(a.id)
        pin = ta.pin_state(t, a.id)
        if b is None:
            binding = "—"
        elif b.pinned_version:
            binding = "pinned v%s" % b.pinned_version
        else:
            binding = "follows newest"
        rows.append({"a": a, "build": build, "fit": fit, "binding": binding,
                     "bound": b is not None, "selectable": pin is None,
                     "reason": pin["reason"] if pin else ""})
    return rows


def bind_targets(t: Template, device_ids, *, limit: bool, by: str) -> list[int]:
    """WPP only: bind the deployed devices when the family governs only its
    bound devices (or the operator limits it here). Returns the ids it bound;
    the caller commits."""
    if t.kind != Template.KIND_WEB_PROTECTION:
        return []
    info = scope_info(t)
    if not (info["scoped"] or limit):
        return []
    if limit and not info["scoped"]:
        tb.set_family_scope(t, SCOPE_SELECTED, by=by)
    have = set(info["bound"])
    out = []
    for a in visible_appliances().filter(Appliance.id.in_(list(device_ids))).all():
        if a.id in have:
            continue
        tb.bind(a, t, note="bound by Mass Deploy", by=by)
        out.append(a.id)
    return out


def record(t: Template, plan, *, by: str, bound: list[int]) -> MassDeploy:
    """The history row of a confirmed deploy (caller commits)."""
    row = MassDeploy(product=t.product or "fortiweb", template_id=t.id, kind=t.kind,
                     name=t.name, version=t.version,
                     devices=json.dumps([{"id": a.id, "name": a.name} for a in plan.targets]),
                     secrets_supplied=json.dumps(plan.secrets["sent"]),
                     bound=json.dumps(bound), by=by or "", total=len(plan.targets),
                     status=MassDeploy.STATUS_RUNNING)
    db.session.add(row)
    db.session.flush()
    return row


def finisher(flask_app, deploy_id: int):
    """``on_done`` for the job: writes the outcome into the history row."""
    def _done(job_id, summary):
        with flask_app.app_context():
            row = db.session.get(MassDeploy, deploy_id)
            if row is None:
                return
            apply_summary(row, summary)
            db.session.commit()
    return _done


def apply_summary(row: MassDeploy, summary: dict) -> None:
    detail = summary.get("detail") or {}
    runs = (detail.get("canary") or []) + (detail.get("rest") or [])
    errors = {}
    for r in runs:
        for res in r.get("results") or []:
            if isinstance(res, dict) and not res.get("ok") and res.get("error"):
                errors.setdefault(r.get("appliance"), str(res.get("error"))[:300])
    devices = [{"appliance": d.get("appliance"), "ok": bool(d.get("ok")),
                "cancelled": bool(d.get("cancelled")),
                "error": errors.get(d.get("appliance"), "")}
               for d in summary.get("devices") or []]
    done = {d["appliance"] for d in devices}
    # Devices the canary abort left untouched are listed as not run.
    devices += [{"appliance": d["name"], "ok": False, "cancelled": False,
                 "error": "not run (the canary failed)" if summary.get("aborted") else "not run"}
                for d in row.devices_list if d["name"] not in done]
    row.result = json.dumps(devices)
    row.ok_count = int(summary.get("ok") or 0)
    if summary.get("cancelled"):
        row.status = MassDeploy.STATUS_STOPPED
    elif summary.get("aborted"):
        row.status = MassDeploy.STATUS_ABORTED
    elif row.ok_count < row.total:
        row.status = MassDeploy.STATUS_FAILED
    else:
        row.status = MassDeploy.STATUS_OK
    row.finished_at = datetime.utcnow()


def history(product: str) -> list[MassDeploy]:
    """The ADOM's deploys, newest first. A row still ``running`` whose job is
    gone or ended without reporting (worker killed) is closed from the job
    state, so the list never shows a deploy running forever."""
    from . import jobs
    rows = (MassDeploy.query.filter_by(product=product)
            .order_by(MassDeploy.created_at.desc(), MassDeploy.id.desc())
            .limit(HISTORY_LIMIT).all())
    changed = False
    for r in rows:
        if r.status != MassDeploy.STATUS_RUNNING:
            continue
        st = jobs.get_job(r.job_id) if r.job_id else None
        if st is None:
            r.status, r.message = MassDeploy.STATUS_FAILED, "the job record is gone"
        elif st.get("status") in ("success", "error", "cancelled"):
            if isinstance(st.get("result"), dict):
                apply_summary(r, st["result"])
            else:
                r.status = MassDeploy.STATUS_FAILED
            r.message = st.get("message") or st.get("error") or ""
        else:
            continue
        r.finished_at = r.finished_at or datetime.utcnow()
        changed = True
    if changed:
        db.session.commit()
    return rows


def scope_text(scope: str) -> str:
    return {SCOPE_FLEET: "every device", SCOPE_SELECTED: "bound devices only"}.get(scope, scope)
