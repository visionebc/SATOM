"""Change Requests — maintenance-window approval gating for risky changes.

Thin Flask blueprint over :mod:`app.services.change_requests` (the headless
status workflow, scheduling, maintenance notice and affected-policy discovery). A
Change Request is the control record for a windowed, risky change — above all a
firmware UPGRADE: which devices/policies are affected, when, an approval gate, and
the bound one-shot ``ScheduledAction`` that executes it inside the window.

The view layer only persists the ``draft`` record and drives the service-side
transitions (approve / schedule / cancel / mark-notified). The actual firing is
the scheduler sidecar's job, re-gated at fire time by ``cr_runnable``.

Import side-effect-free: importing this module touches no DB and contacts no
device.
"""
from __future__ import annotations

import json
from datetime import datetime

from flask import (Blueprint, flash, redirect, render_template, request,
                   url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Appliance, ChangeRequest, ChangeRequestEvent, Permission, db
from ..models import visible_appliances, visible_appliance_or_404
from ..services import change_requests as svc
from ..services import scheduled_actions as sa
from ..services.audit import log_action

bp = Blueprint('change_requests', __name__, url_prefix='/change-requests')

# The actions a CR may carry are DERIVED from the automation catalog, never
# re-listed here by hand. A hand-kept list is exactly how 'upgrade_prep' came to
# be offered by this form while the executor's gate honoured only 'upgrade': the
# destructive action was on the menu and ungated. Eligible = it touches a device
# AND it is destructive (danger) or mutates objects (user scope) - so a newly
# registered dangerous action appears here the day it is registered.
def _cr_specs() -> list:
    return [s for s in sa.ALL_ACTIONS.values()
            if s.needs_targets and (s.danger or s.scope == 'user')]


def cr_type_entries(lang: str = "") -> list[dict]:
    """Every type of change this form may offer, compiled AND administrator-
    defined, each under the name Administration -> Change Types gives it.

    ``executable`` is DERIVED from the automation registry on every call, never
    read from a row. A type an administrator invented has no executor; if that
    fact were storable, somebody could tick it, bind the change to a one-shot
    action, and have it resolve to nothing at fire time - inside the window,
    hours after anyone could act on it.

    Answers WITHOUT an application context, returning the compiled catalog
    alone: "which dangerous actions are change-controlled" is a property of the
    product, and a caller asking that must not need a database to find out.
    """
    from flask import current_app, has_app_context
    from ..services import cr_types, langs as lang_registry

    code = lang or lang_registry.DEFAULT
    rows: dict = {}
    if has_app_context():
        try:
            rows = {r.key: r for r in cr_types.all_types()}
        except Exception:  # noqa: BLE001 - the picker degrades, it does not 500
            current_app.logger.warning(
                "change types unavailable; offering the compiled catalog only",
                exc_info=True)
            rows = {}

    def _label(key: str, fallback: str) -> str:
        return (cr_types.label(key, code) if rows else "") or fallback

    out: list[dict] = []
    for spec in _cr_specs():
        row = rows.get(spec.key)
        # Hiding a built-in removes it from the FORM only. The action itself
        # stays in the product and keeps running: a menu is not a permission.
        if row is not None and not row.enabled:
            continue
        out.append({"key": spec.key, "label": _label(spec.key, spec.label),
                    "products": list(spec.products),
                    "single_target": bool(spec.single_target),
                    "executable": True,
                    "order": (row.sort_order if row is not None else 100)})
    if rows:
        for row in cr_types.options_for(cr_kinds()):
            out.append({"key": row.key, "label": _label(row.key, row.key),
                        # No product declared = the change is about work, not
                        # about a product, so every device this console can see
                        # is a legitimate target.
                        "products": row.products_list or list(cr_kinds()),
                        "single_target": False,
                        "executable": False,
                        "order": row.sort_order})
    out.sort(key=lambda e: (e["order"], e["label"].lower()))
    return out


def cr_actions() -> list[tuple[str, str]]:
    """[(key, label)] for the form's Action dropdown."""
    return [(e["key"], e["label"]) for e in cr_type_entries()]


def cr_action_keys() -> set[str]:
    return {e["key"] for e in cr_type_entries()}


def cr_kinds() -> tuple[str, ...]:
    """Appliance kinds a CR may target: the union of the eligible actions'
    products. A maintenance window is a property of the DEVICE, not of one
    product - FortiWeb, FortiADC, FortiAnalyzer and FortiAuthenticator are all
    first-class here, and this form used to show only FortiWeb.
    """
    kinds: list[str] = []
    for spec in _cr_specs():
        for kind in spec.products:
            if kind not in kinds:
                kinds.append(kind)
    return tuple(kinds)

# Bootstrap-ish badge class per status for the list / detail header.
_STATUS_BADGE = {
    "draft": "fw-badge-secondary",
    "approved": "fw-badge-info",
    "scheduled": "fw-badge-primary",
    "in_progress": "fw-badge-primary",
    "completed": "fw-badge-success",
    "failed": "fw-badge-danger",
    "cancelled": "fw-badge-secondary",
}
_RISK_BADGE = {
    "low": "fw-badge-success",
    "medium": "fw-badge-info",
    "high": "fw-badge-danger",
}


def _parse_dt(value: str | None):
    """A ``datetime-local`` form value -> naive **UTC** datetime, or None.

    The value is read in the timezone configured under Settings -> General, via
    the one conversion path (:func:`settings_store.parse_local`). It used to be
    stored verbatim, i.e. as if the operator had typed UTC: a window entered as
    22:00 on a Europe/Zurich console opened at midnight local — two hours after
    the customer had been told the outage would start. Nothing errored; the
    change simply ran at the wrong time, and the notice and the schedule agreed
    with each other while both disagreed with the operator."""
    value = (value or '').strip()
    if not value:
        return None
    from ..services import settings_store
    return settings_store.parse_local(value)


def _next_ref(cr) -> str:
    """``CR-<year>-<0000 id>`` — the human change id printed on the document.

    Derived from the row id at CREATION and then stored, never recomputed on
    read: a restore that reseeds the sequence would otherwise silently renumber
    every document already circulating with a different reference on it."""
    year = (cr.created_at or datetime.utcnow()).year
    return f"CR-{year}-{int(cr.id):04d}"


def _freeze_inventory(cr, device_ids, preps=None) -> None:
    """Store the affected published services AS THEY ARE NOW on the CR.

    Prefers the inventory captured by the pre-upgrade run this change was
    raised from (free, and it is the very evidence the approver is looking at).
    Falls back to a live read. Either way the snapshot is stored: rendering the
    document from a live read would let the fleet drift between approval and
    execution, so the document somebody signed and the document that describes
    what ran would not be the same document."""
    rows = []
    if preps:
        # MERGED across every bound run: a change over twenty appliances whose
        # frozen inventory held one box's policies understated the outage by
        # nineteen devices, and the customer-impact export is generated from
        # exactly this field.
        from ..services import prep_store
        rows = prep_store.merged_inventory(preps)
    if not rows:
        try:
            rows = svc.affected_policies(device_ids, timeout=6.0)
        except Exception:  # noqa: BLE001 - planning must survive a dead device
            rows = []
    cr.policies = json.dumps(rows or [], default=str)
    cr.inventory_at = datetime.utcnow()


# --------------------------------------------------------------------------- #
#  Routes                                                                       #
# --------------------------------------------------------------------------- #
def _tz_name() -> str:
    """The timezone every window field on this blueprint is expressed in."""
    from ..services import settings_store
    try:
        return settings_store.tz_name()
    except Exception:  # noqa: BLE001
        return "UTC"


def _visible_appliance_ids() -> set[int]:
    """Appliance ids the ACTIVE ADOM may see."""
    return {row[0] for row in
            visible_appliances().with_entities(Appliance.id).all()}


def _cr_in_scope(cr, visible: set[int] | None = None) -> bool:
    """Is this change visible in the active ADOM?

    A CR is scoped by the devices it NAMES: the ADOM that owns a box owns the
    window that takes it down, and a change naming boxes in two products is
    legitimately visible in both. A CR naming NO device belongs to no product
    and stays visible everywhere - hiding it would make it unreachable from any
    console at all.
    """
    ids = cr.device_ids_list
    if not ids:
        return True
    vis = _visible_appliance_ids() if visible is None else visible
    return any(i in vis for i in ids)


def _cr_in_scope_or_404(id):
    """Load one CR by id, honouring the same scope as the list.

    Filtering the LIST while the by-id routes read the table raw is not scoping,
    it is decoration - the exact hole closed fleet-wide for appliances on
    2026-08-06. 404, never 403: do not confirm the row exists.
    """
    from flask import abort
    row = ChangeRequest.query.get_or_404(id)
    if not _cr_in_scope(row):
        abort(404)
    return row


@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    visible = _visible_appliance_ids()
    crs = [c for c in (ChangeRequest.query
                       .order_by(ChangeRequest.created_at.desc())
                       .all())
           if _cr_in_scope(c, visible)]
    # Group by status, in the canonical lifecycle order, dropping empty buckets.
    groups = []
    for status in ChangeRequest.STATUSES:
        members = [c for c in crs if c.status == status]
        if members:
            groups.append({'status': status, 'items': members})
    return render_template('change_requests/index.html',
                           groups=groups,
                           total=len(crs),
                           status_badge=_STATUS_BADGE,
                           risk_badge=_RISK_BADGE)



def _prep_draft_context(prep):
    """The pre-flight run reduced to the plain facts a draft sentence may cite.

    Built HERE, not in :mod:`app.services.cr_document`, so that module keeps
    touching neither the ORM nor a timezone. The backup is only quoted when the
    run actually took one: naming a backup that failed would put a rollback in
    writing that has nothing to roll back to.
    """
    if prep is None:
        return None
    from ..services import settings_store
    result = prep.result_dict
    backup = result.get('backup') if isinstance(result.get('backup'), dict) else {}
    return {
        'id': prep.id,
        'at': settings_store.to_local(prep.created_at, '%Y-%m-%d %H:%M %Z'),
        'ok': bool(prep.ok),
        'services': len(prep.inventory_list),
        'firmware': (prep.firmware or '').strip(),
        'backup': ((backup.get('name') or '').strip()
                   if backup.get('ok') else ''),
    }


def create_change_request(fields: dict):
    """Create ONE change request from already-parsed fields. ``(cr, error)``.

    THE one implementation of "raise a change", extracted from this
    blueprint's own POST handler so that the batched (wave) route can create N
    of them without becoming a second author of these rules. That is not
    hypothetical tidiness: the defect this whole feature was built to remove
    was two implementations of "upgrade prep" that differed in what they
    recorded, and neither ever failed.

    ``fields`` carries plain values — ``device_ids`` and ``prep_ids`` as lists,
    the windows as datetimes already converted out of the operator's timezone.
    Parsing a form is the caller's job; deciding what a legal change is, is
    this function's.

    Returns ``(None, message)`` on refusal. Every message names what was wrong
    AND that nothing was created, because a batched caller may be several waves
    in when one fails.
    """
    title = (fields.get('title') or '').strip()
    if not title:
        return None, 'A title is required.'

    action = (fields.get('action') or '').strip()
    # An unrecognised action is REJECTED, never coerced. The old fallback
    # silently rewrote a glitched form into 'upgrade' - the most destructive
    # entry on the menu - which is the opposite of what a fallback is for.
    entry = {e['key']: e for e in cr_type_entries()}.get(action)
    if entry is None:
        return None, f'{action or "(none)"} is not a change-controlled action.'
    risk = (fields.get('risk') or 'medium').strip()
    if risk not in svc.RISKS:
        risk = 'medium'
    device_ids = [n for n in ((_to_int(x)) for x in (fields.get('device_ids') or []))
                  if n is not None]

    # The devices must exist, be visible to this user, and be a product the
    # chosen action actually runs against. Without this last check the CR
    # saves happily and the SCHEDULED RUN resolves to zero targets (targets
    # are filtered by spec.products), reporting 'skipped' - which closes the
    # change as failed long after anyone could act on it.
    picked = (visible_appliances().filter(Appliance.id.in_(device_ids)).all()
              if device_ids else [])
    if len(picked) != len(set(device_ids)):
        return None, ('One or more selected devices do not exist or are not '
                      'visible to you. Nothing was created.')
    wrong = [d for d in picked if (d.kind or 'fortiweb') not in entry['products']]
    if wrong:
        return None, (f'{entry["label"]} does not run against '
                      + ', '.join(sorted({(d.kind or "?") for d in wrong}))
                      + ' (' + ', '.join(d.name for d in wrong)
                      + '). It supports: ' + ', '.join(entry['products']) + '.')
    if entry['single_target'] and len(device_ids) > 1:
        return None, (f'{entry["label"]} acts on exactly one appliance; '
                      f'{len(device_ids)} were selected.')

    from ..services import cr_document, prep_store
    preps = []
    seen_preps: set[int] = set()
    for raw in (fields.get('prep_ids') or []):
        prep = prep_store.get(raw)
        # A pre-upgrade run may only be cited by a change that targets ITS
        # appliance. Without this an operator could attach somebody else's
        # green pre-flight as the evidence for a change to a different box -
        # a document that reads correct and certifies the wrong machine.
        # The check is PER RUN, not "the first one matched": a bulk change
        # must not inherit permission for twenty devices from one.
        if prep is None or prep.appliance_id not in device_ids:
            continue
        if prep.id in seen_preps:
            continue
        seen_preps.add(prep.id)
        preps.append(prep)

    cr = ChangeRequest(
        title=title[:200],
        reason=(fields.get('reason') or '').strip(),
        status='draft',
        action=action,
        device_ids=json.dumps(device_ids),
        window_start=fields.get('window_start'),
        window_end=fields.get('window_end'),
        risk=risk,
        rollback=(fields.get('rollback') or '').strip(),
        notify_to=(fields.get('notify_to') or '').strip(),
        owner=(fields.get('owner') or '').strip()[:64],
        doc_lang=cr_document.normalize_lang(fields.get('doc_lang')),
        requested_by=(fields.get('requested_by') or '').strip(),
        # An unrecognised value falls back to 'manual', NOT to 'external':
        # a form glitch must not silently bind a change to an approver
        # nobody configured, which would strand it un-runnable forever.
        approval_mode=('external'
                       if (fields.get('approval_mode') or '').strip() == 'external'
                       else 'manual'),
    )
    db.session.add(cr)
    db.session.commit()
    cr.ref = _next_ref(cr)
    _freeze_inventory(cr, device_ids, preps)
    db.session.commit()
    if preps:
        prep_store.bind_many(cr, preps)
    log_action('change_request.create', target=cr.title,
               detail=f'{cr.ref} / {action} / risk={risk}'
                      + (' / preps ' + ', '.join(f'#{p.id}' for p in preps)
                         if preps else ''))
    return cr, ''


@bp.route('/new', methods=['GET', 'POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def new():
    if request.method == 'POST':
        # 'prep_id' (singular) is still accepted so an existing form post, link
        # or test keeps working; it is simply the one-element case.
        prep_ids = (request.form.getlist('prep_ids')
                    or ([request.form.get('prep_id')]
                        if request.form.get('prep_id') else []))
        cr, error = create_change_request({
            'title': request.form.get('title'),
            'action': request.form.get('action'),
            'risk': request.form.get('risk'),
            'reason': request.form.get('reason'),
            'device_ids': request.form.getlist('device_ids'),
            'prep_ids': prep_ids,
            'window_start': _parse_dt(request.form.get('window_start')),
            'window_end': _parse_dt(request.form.get('window_end')),
            'rollback': request.form.get('rollback'),
            'notify_to': request.form.get('notify_to'),
            'owner': request.form.get('owner'),
            'doc_lang': request.form.get('doc_lang'),
            'approval_mode': request.form.get('approval_mode'),
            'requested_by': current_user.username,
        })
        if cr is None:
            flash(error, 'danger')
            return redirect(url_for('change_requests.new'))
        flash(f'Change request {cr.ref} "{cr.title}" created.', 'success')
        return redirect(url_for('change_requests.detail', id=cr.id))

    from ..services import cr_document, prep_store
    appliances = (visible_appliances()
                  .filter(Appliance.kind.in_(cr_kinds()))
                  .order_by(Appliance.kind, Appliance.name)
                  .all())
    # Arriving from an appliance's "Upgrade preparation" page: the run to cite,
    # the device it ran against and a sensible action are all pre-selected, and
    # the operator only fills in the window. That link is the whole point of
    # persisting the pre-flight.
    prep = prep_store.get(request.args.get('prep_id'))
    if prep is not None and prep.appliance_id not in {a.id for a in appliances}:
        prep = None            # not visible in this ADOM: do not leak that it exists
    # The guided form asks two questions - document language, then change type -
    # and proposes the prose that follows from them. Every proposal is authored
    # SERVER-side, in both languages, for every action, and handed to the page as
    # data; the page only substitutes the device names. Composing sentences in
    # JavaScript would give the printed document a second author.
    from ..services import cr_types, email_service
    prep_ctx = _prep_draft_context(prep)
    lang_codes = [code for code, _label in cr_document.document_langs()]
    entries = cr_type_entries()
    keys = sorted(e['key'] for e in entries)
    # Through cr_types, not cr_document: an administrator's wording wins per
    # FIELD, and falls back to the compiled sentence for every field they left
    # alone. Reading cr_document here would print the shipped paragraph next to
    # the corrected one on the same page.
    drafts = {key: {code: cr_types.draft_fields(key, code, prep=prep_ctx)
                    for code in lang_codes} for key in keys}
    action_labels = {key: {code: cr_types.label(key, code)
                           for code in lang_codes} for key in keys}
    # Proposed, VISIBLE and editable - not silently applied. An owner the
    # operator never saw is exactly the attribution this field refuses to make.
    defaults = {
        'owner': (getattr(current_user, 'username', '') or ''),
        'notify_to': (email_service.config().get('default_to') or '').strip(),
    }
    # Question 1 is answered from the operator's PROFILE, and only from there.
    # A pre-checked first radio is not an answer: nobody chose it, and the
    # document that comes out of this form is signed in whatever it says. A
    # preference for a language no complete document exists in is NOT quietly
    # downgraded to English either -- the form says so and still asks.
    from ..services import user_settings_store as user_store
    from ..services import langs as lang_registry
    pref_lang = user_store.language(getattr(current_user, 'id', 0) or 0)
    lang_preset = pref_lang if pref_lang in set(lang_codes) else ''
    return render_template('change_requests/form.html',
                           appliances=appliances,
                           cr_actions=[(e['key'], e['label'])
                                       for e in entries],
                           action_products={e['key']: e['products']
                                            for e in entries},
                           action_executable={e['key']: e['executable']
                                              for e in entries},
                           risks=svc.RISKS,
                           prep=prep,
                           preset_action=(request.args.get('action') or '').strip(),
                           langs=cr_document.document_langs(),
                           lang_preset=lang_preset,
                           lang_pref=pref_lang,
                           lang_pref_label=(lang_registry.label(pref_lang)
                                            if pref_lang else ''),
                           lang_pref_unrenderable=bool(pref_lang) and not lang_preset,
                           drafts=drafts,
                           action_labels=action_labels,
                           devices_token=cr_document.DEVICES_TOKEN,
                           devices_none={code: cr_document.devices_placeholder(code)
                                         for code in lang_codes},
                           action_prompt={code: cr_document.action_placeholder(code)
                                          for code in lang_codes},
                           defaults=defaults,
                           tz_name=_tz_name())


@bp.route('/<int:id>')
@login_required
@require_permission(Permission.USER_MANAGE)
def detail(id):
    cr = _cr_in_scope_or_404(id)
    events = (ChangeRequestEvent.query
              .filter_by(cr_id=cr.id)
              .order_by(ChangeRequestEvent.ts.asc())
              .all())
    device_ids = cr.device_ids_list
    devices = (Appliance.query.filter(Appliance.id.in_(device_ids)).all()
               if device_ids else [])
    runnable_ok, runnable_reason = svc.cr_runnable(cr)
    # Best-effort LIVE read of the affected policies (the clients to warn). With
    # no/unreachable devices this returns [] quickly rather than raising.
    # The FROZEN inventory is what this change is about — the services that were
    # published when it was raised, which is what the approver signed for. A
    # live re-read is offered separately (below) as DRIFT, never as the record.
    from ..services import cr_document, prep_store
    policies = svc.frozen_policies(cr)
    live_drift = None
    if request.args.get('drift') == '1':
        live = svc.affected_policies(device_ids)
        frozen_keys = {(p.get('device'), p.get('policy'))
                       for p in policies if isinstance(p, dict)}
        live_keys = {(p.get('device'), p.get('policy')) for p in live}
        live_drift = {
            'added': sorted(k[1] or '?' for k in live_keys - frozen_keys),
            'removed': sorted(k[1] or '?' for k in frozen_keys - live_keys),
            'total': len(live),
        }
    return render_template('change_requests/detail.html',
                           cr=cr,
                           # Derived, not stored: whether this change has an
                           # executor is a question for the registry, asked
                           # now. The Schedule button is hidden when the answer
                           # is no, and the service refuses it anyway.
                           executable=sa.get_spec(cr.action) is not None,
                           events=events,
                           devices=devices,
                           notice=svc.maintenance_notice(cr),
                           runnable_ok=runnable_ok,
                           runnable_reason=runnable_reason,
                           policies=policies,
                           live_drift=live_drift,
                           prep=prep_store.get(cr.prep_id),
                           # EVERY bound run, plus the appliances that have
                           # none. "Captured by upgrade preparation #88" is a
                           # true sentence about a one-device change and a
                           # false one about a window over twenty: the frozen
                           # inventory below is merged across all of them.
                           evidence=prep_store.coverage(cr, devices),
                           langs=cr_document.document_langs(),
                           fields=prep_store.FIELDS,
                           default_fields=prep_store.DEFAULT_FIELDS,
                           tz_name=_tz_name(),
                           terminal=cr.status in ChangeRequest.TERMINAL,
                           status_badge=_STATUS_BADGE,
                           risk_badge=_RISK_BADGE)


@bp.route('/<int:id>/document')
@login_required
@require_permission(Permission.USER_MANAGE)
def document(id):
    """The formal change document (13 sections, English or German).

    Rendered from the STORED record only — the frozen inventory, the stored
    pre-upgrade evidence, the stored window. Nothing here re-reads a device, so
    printing an approved change twice yields the same document twice."""
    from flask import Response
    from ..services import cr_document, prep_store
    cr = _cr_in_scope_or_404(id)
    lang = cr_document.normalize_lang(request.args.get('lang') or cr.doc_lang)
    device_ids = cr.device_ids_list
    devices = (Appliance.query.filter(Appliance.id.in_(device_ids)).all()
               if device_ids else [])
    prep = prep_store.get(cr.prep_id)
    # The wording FROZEN when this change was approved wins over today's. A
    # change type is editable, so re-reading it here would let a correction
    # made this morning rewrite a document signed last month - and the reprint
    # would differ from the paper in the file with nothing saying so. A draft
    # has no snapshot yet and renders live, which is correct: it has not been
    # signed against anything.
    from ..services import cr_types
    frozen = cr.doc_profile_dict.get(lang)
    profile = (frozen if isinstance(frozen, dict) and frozen
               else cr_types.profile_text(cr.action, lang))
    text = cr_document.render(cr, lang=lang, devices=devices,
                              policies=svc.frozen_policies(cr),
                              prep=(prep.result_dict if prep else None),
                              profile=profile)
    log_action('change_request.document', target=cr.title, detail=f'lang={lang}')
    if request.args.get('download') == '1':
        return Response(
            text, mimetype='text/markdown; charset=utf-8',
            headers={'Content-Disposition':
                     f'attachment; filename="{cr_document.filename(cr, lang)}"'})
    return render_template('change_requests/document.html', cr=cr, lang=lang,
                           langs=cr_document.document_langs(), text=text)


@bp.route('/<int:id>/inventory.<fmt>')
@login_required
@require_permission(Permission.USER_MANAGE)
def inventory_export(id, fmt):
    """Export the frozen affected-service inventory with the operator's chosen
    columns. ``fmt`` is ``xlsx`` or ``csv``; anything else is a 404 rather than
    a silent fallback to a format the caller did not ask for."""
    from flask import Response, abort
    from ..services import cr_document, prep_store
    cr = _cr_in_scope_or_404(id)
    if fmt not in ('xlsx', 'csv'):
        abort(404)
    rows = svc.frozen_policies(cr)
    keys = request.args.getlist('field')
    ref = cr_document.change_ref(cr)
    if fmt == 'csv':
        return Response(
            prep_store.export_csv(rows, keys), mimetype='text/csv; charset=utf-8',
            headers={'Content-Disposition':
                     f'attachment; filename="{ref}-affected-services.csv"'})
    return Response(
        prep_store.export_xlsx(rows, keys),
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={'Content-Disposition':
                 f'attachment; filename="{ref}-affected-services.xlsx"'})


@bp.route('/<int:id>/approve', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def approve(id):
    _cr_in_scope_or_404(id)
    try:
        cr = svc.approve(id, current_user.username)
        log_action('change_request.approve', target=cr.title)
        flash('Change request approved.', 'success')
    except ValueError as exc:
        flash(str(exc), 'danger')
    return redirect(url_for('change_requests.detail', id=id))


@bp.route('/<int:id>/schedule', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def schedule(id):
    _cr_in_scope_or_404(id)
    try:
        action_id = svc.schedule_change_request(id, current_user.username)
        log_action('change_request.schedule', target=str(id),
                   detail=f'scheduled_action={action_id}')
        flash(f'Change request scheduled — bound action #{action_id}.', 'success')
    except ValueError as exc:
        flash(str(exc), 'danger')
    return redirect(url_for('change_requests.detail', id=id))


@bp.route('/<int:id>/cancel', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def cancel(id):
    _cr_in_scope_or_404(id)
    reason = (request.form.get('reason') or '').strip()
    try:
        cr = svc.cancel(id, current_user.username, reason)
        log_action('change_request.cancel', target=cr.title, detail=reason)
        flash('Change request cancelled.', 'success')
    except ValueError as exc:
        flash(str(exc), 'danger')
    return redirect(url_for('change_requests.detail', id=id))


@bp.route('/<int:id>/mark-notified', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def mark_notified(id):
    """Send the client maintenance notice by email when email is configured
    (Settings -> Email); otherwise just record it as sent. Best-effort: a send
    failure is reported and logged, never a 500."""
    from ..services import email_service as email
    cr = _cr_in_scope_or_404(id)
    recipients = (request.form.get('recipients') or '').strip()
    stamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')

    if email.is_configured():
        notice = svc.maintenance_notice(cr)
        subject = 'Scheduled maintenance window'
        body = notice
        lines = notice.splitlines()
        if lines and lines[0].lower().startswith('subject:'):
            subject = lines[0].split(':', 1)[1].strip() or subject
            body = '\n'.join(lines[1:]).lstrip('\n')
        result = email.send_email(recipients, subject, body)
        if result.get('ok'):
            cr.notify_status = 'sent'
            cr.notify_log = (cr.notify_log or '') + f"\n[{stamp}] sent: {result.get('detail', '')}"
            db.session.commit()
            log_action('change_request.notified', target=cr.title,
                       detail=result.get('detail', ''))
            flash('Maintenance notice emailed to the client(s).', 'success')
        else:
            cr.notify_log = (cr.notify_log or '') + f"\n[{stamp}] FAILED: {result.get('detail', '')}"
            db.session.commit()
            log_action('change_request.notify_failed', target=cr.title,
                       detail=result.get('detail', ''))
            flash(f"Email send failed: {result.get('detail', '')}", 'danger')
    else:
        cr.notify_status = 'sent'
        cr.notify_log = (cr.notify_log or '') + f"\n[{stamp}] marked sent (email not configured)"
        db.session.commit()
        log_action('change_request.notified', target=cr.title)
        flash('Notice marked as sent. Configure Settings -> Email to deliver it automatically.', 'info')
    return redirect(url_for('change_requests.detail', id=id))


@bp.route('/<int:id>/request-crq', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def request_crq(id):
    """Raise the external change ticket by queueing the ``change.requested``
    hooks.

    Returns immediately with a count of what was QUEUED, never with a ticket id:
    hooks run out of process, so the CRM's answer arrives later. Blocking this
    request until somebody else's CRM replies would hand a third party the
    ability to hang the console."""
    from ..services import cr_orchestrator as orch
    cr = _cr_in_scope_or_404(id)
    had_ref = (cr.crq_ref or '').strip()
    result = orch.request_crq(cr, by=current_user.username)
    log_action('change_request.crq_requested', target=cr.title,
               detail=f"dispatched={result.get('dispatched', 0)} "
                      f"evidence={result.get('evidence', 0)} "
                      f"uncovered={len(result.get('uncovered') or [])}")
    if result.get('dispatched'):
        flash(f"Queued {result['dispatched']} integration hook(s). The ticket "
              f"reference appears here once your system answers.", 'success')
        # What the ticket actually CARRIES, said here rather than left to be
        # discovered in the receiving system. A bulk change whose evidence
        # covers eleven of twenty appliances is not a failure — but nobody
        # should learn which nine were bare from the approver.
        uncovered = result.get('uncovered') or []
        if uncovered:
            flash(f"{result.get('evidence', 0)} pre-upgrade run(s) travelled "
                  f"with it. No baseline for: " + ', '.join(uncovered) + '.',
                  'warning')
        if result.get('truncated'):
            flash(f"The ticket lists the first {orch.MAX_POLICY_NAMES} of "
                  f"{result.get('policy_count', 0)} affected services; the full "
                  f"count travels with it and the whole list is in the "
                  f"customer-impact export.", 'info')
        if had_ref:
            # Re-requesting is legitimate (the window moved, the scope grew),
            # but it is not a new change. The existing reference rides in the
            # payload so a receiver can update rather than open a second
            # ticket — and the operator is told that is what was sent.
            flash(f"This change already carries {had_ref}; it was sent as a "
                  f"re-request, not as a new ticket.", 'info')
    else:
        # An enabled-but-unbound integration silently doing nothing is the
        # failure mode this message exists to prevent.
        flash('No enabled hook is bound to change.requested — nothing was sent.',
              'warning')
    return redirect(url_for('change_requests.detail', id=id))


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
