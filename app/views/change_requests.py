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

    # An inverted window can never contain an instant, so a change carrying
    # one can never fire: it sits in 'approved' looking healthy until
    # somebody notices, on the morning after, that nothing ran. The form
    # never checked, and CR-0011 was stored ending a DAY before it began.
    # The rule itself lives in svc.validate_window - ONE author, so raising a
    # change and EDITING one cannot disagree about what a legal window is. A
    # second copy here is exactly how the edit form would have been free to
    # store the window this check refuses.
    window_error = svc.validate_window(fields.get('window_start'),
                                       fields.get('window_end'))
    if window_error:
        return None, window_error + ' Nothing was created.'

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

    # Executor params ride on the CHANGE. schedule_change_request rebuilds the
    # bound action from the CR each time, so anything written only onto the
    # action row is silently reset to the executor default on the next
    # reschedule. Reserved keys are STRIPPED, never trusted: params carries the
    # binding the executor reads as its authorization
    # ('change_request_id'), and a caller that could set it would be
    # self-approving a change nobody looked at.
    raw_params = fields.get('params')
    params = {str(k): v for k, v in raw_params.items()
              if str(k) not in ('change_request_id', 'target_version')} \
        if isinstance(raw_params, dict) else {}

    # --- WHERE this change is going -------------------------------------
    # One author. 'target_version' is STRIPPED out of params above and
    # recomputed here, so a caller cannot post a destination past the two
    # checks below by hiding it in the executor's parameter bag — which is the
    # same reason 'change_request_id' is stripped.
    #
    # The evidence CORROBORATES the declaration rather than replacing it: the
    # runs cited were each swept towards a version, and a change that claims a
    # different destination from the pre-flights it rests on is a document
    # whose prerequisites section proves the wrong move. Both halves are
    # refusals, not corrections — silently adopting either value would produce
    # exactly the misleading-but-green document this whole feature removes.
    from ..services import firmware_versions as _fv
    declared = _fv.normalize(fields.get('target_version'))
    cited = {_fv.normalize(getattr(p, 'target_version', '') or '')
             for p in preps}
    cited.discard('')
    if len(cited) > 1:
        return None, ('The pre-upgrade runs cited here were run towards '
                      'different versions (' + ', '.join(sorted(cited)) +
                      '). One change request is one move — raise one per '
                      'destination. Nothing was created.')
    if cited and declared and declared not in cited:
        return None, (f'This change declares an upgrade to {declared}, but the '
                      f'pre-upgrade evidence it cites was run towards '
                      f'{sorted(cited)[0]}. Re-run the pre-flight towards '
                      f'{declared}, or cite the runs that match. Nothing was '
                      f'created.')
    # Declared wins where both agree; the evidence answers when nothing was
    # declared (the flow's Create draft posts no field — the destination
    # travels on the runs it mirrors). Absent stays ABSENT: a change citing no
    # evidence and naming no version declares no destination, and inventing
    # one would put a firmware number on a document nobody chose it for.
    target_version = declared or (sorted(cited)[0] if cited else '')
    if target_version:
        params['target_version'] = target_version

    cr = ChangeRequest(
        title=title[:200],
        params=json.dumps(params),
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
        # At least one appliance -- for the UPGRADE FLOW only. There the
        # devices are not a field of this form at all: they were ticked in
        # step 1 and mirrored in, so a device-less post means the operator
        # never answered step 1, and the change it would raise resolves to
        # zero targets and reports itself 'skipped' after the window closed.
        #
        # The STANDALONE page keeps accepting one, and that is not an
        # oversight: a change naming no device belongs to no product and stays
        # readable from every console -- test_cr_action_catalog's
        # `test_a_change_naming_no_device_stays_reachable_everywhere` is the
        # guard that says so by name. Narrowing that here would have deleted a
        # documented product decision to answer a question about another page.
        # Refused here rather than inside create_change_request for the same
        # reason: the calendar plans from a SELECTOR, where "matched nothing"
        # is its own, differently worded refusal.
        device_ids = [x for x in request.form.getlist('device_ids')
                      if (x or '').strip()]
        if not device_ids and _back_token() == 'upgrade_flow':
            cr, error = None, ('Select at least one appliance. '
                               'Nothing was created.')
        else:
            cr, error = create_change_request({
                'title': request.form.get('title'),
                'action': request.form.get('action'),
                'risk': request.form.get('risk'),
                'reason': request.form.get('reason'),
                'device_ids': device_ids,
                'prep_ids': prep_ids,
                'window_start': _parse_dt(request.form.get('window_start')),
                'window_end': _parse_dt(request.form.get('window_end')),
                'rollback': request.form.get('rollback'),
                'notify_to': request.form.get('notify_to'),
                'owner': request.form.get('owner'),
                'doc_lang': request.form.get('doc_lang'),
                'approval_mode': request.form.get('approval_mode'),
                # Accepted but NOT required. The upgrade flow's Create draft
                # posts no such field: its destination travels on the
                # pre-upgrade runs it mirrors, and create_change_request reads
                # it from there. A page that DOES ask can still say so, and
                # the two are reconciled in one place, not two.
                'target_version': request.form.get('target_version'),
                'requested_by': current_user.username,
            })
        if cr is None:
            flash(error, 'danger')
            # A refusal must not be a way OUT of the page the button was
            # pressed on either: the operator reads the reason where they
            # typed, not on a screen they never asked for.
            if _back_token() == 'upgrade_flow':
                from .appliances import _adom_arg
                return redirect(url_for('upgrade_flow.index', **_adom_arg()))
            return redirect(url_for('change_requests.new'))
        flash(f'Change request {cr.ref} "{cr.title}" created.', 'success')
        # Resolved from the same TOKEN the lifecycle buttons use, never from a
        # URL the request carried. Raising a change from inside a staged page
        # stays on that page, citing what it just raised; the standalone page
        # sets no token and still opens the change's own page.
        return redirect(_after(cr.id))

    from ..services import prep_store
    prep = prep_store.get(request.args.get('prep_id'))
    return render_template(
        'change_requests/form.html',
        **new_form_context(
            prep=prep,
            preset_action=(request.args.get('action') or '').strip()))


def new_form_context(prep=None, preset_action=''):
    """Everything `change_requests/_new_form.html` needs, in ONE dict.

    Splatted by the caller rather than enumerated at each render call:
    enumerating the keys is how a value computed here fails to reach the
    template with every assertion about it still green (the missing
    ledger banner, 2026-09-18). The upgrade flow merges this same dict
    for its stage 2, so the embedded form and the stand-alone page can
    never be fed two different catalogues, two different proposals or
    two different device lists.
    """
    from ..services import cr_document
    appliances = (visible_appliances()
                  .filter(Appliance.kind.in_(cr_kinds()))
                  .order_by(Appliance.kind, Appliance.name)
                  .all())
    # Arriving from an appliance's "Upgrade preparation" page: the run to cite,
    # the device it ran against and a sensible action are all pre-selected, and
    # the operator only fills in the window. That link is the whole point of
    # persisting the pre-flight.
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
    return dict(
                           appliances=appliances,
                           cr_actions=[(e['key'], e['label'])
                                       for e in entries],
                           action_products={e['key']: e['products']
                                            for e in entries},
                           action_executable={e['key']: e['executable']
                                              for e in entries},
                           risks=svc.RISKS,
        prep=prep,
        preset_action=preset_action,
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


# What an edit may touch. ACTION and DEVICE_IDS are deliberately absent: the
# frozen inventory, the bound pre-flight evidence and the printed document all
# describe THOSE devices doing THAT thing, and a form that quietly re-pointed
# them would leave a document in circulation that certifies a change nobody
# planned. Re-target by raising a new change; the record of the old one stays
# true.
EDITABLE_FIELDS = ('title', 'risk', 'reason', 'window_start', 'window_end',
                   'rollback', 'notify_to', 'owner', 'doc_lang',
                   'approval_mode')

# Changing one of these makes an existing approval a statement about something
# that is no longer the case, so the change goes back to 'draft' and must be
# approved again. The window is the obvious one - an approval is a human saying
# yes to a specific outage at a specific time. 'risk' is here because the
# approver weighed it; 'approval_mode' because switching a change off external
# authorisation after the fact would silently REMOVE the gate it is running
# under.
APPROVAL_CRITICAL = ('window_start', 'window_end', 'risk', 'approval_mode')


def _shown(field, value):
    """A field value as the timeline should print it (windows in local time)."""
    if field in ('window_start', 'window_end'):
        if value is None:
            return '(none)'
        from ..services import settings_store
        return settings_store.to_local(value)
    text = '' if value is None else str(value)
    text = ' '.join(text.split())
    return (text[:60] + '...') if len(text) > 60 else (text or '(empty)')


def _unchanged(field, before, after) -> bool:
    """Is this field the SAME after the edit?

    Windows compare at MINUTE resolution, because minutes are the resolution a
    ``datetime-local`` field has. A window carrying seconds (written by any
    other path - a batched wave, the API, a restore) cannot be expressed in
    that field at all, so treating the truncation as an edit would void the
    approval of an approved change every time somebody corrected its TITLE -
    the approval control firing on a change nobody made, which trains people to
    re-approve without reading.
    """
    if field in ('window_start', 'window_end'):
        def _minute(value):
            return value.replace(second=0, microsecond=0) if value else None
        return _minute(before) == _minute(after)
    return before == after


def update_change_request(cr, fields: dict, by: str):
    """Apply an edit to an EXISTING change. ``(changed, error)``.

    ``changed`` is the list of human-readable field diffs actually written, so
    the caller can say nothing happened rather than claim a save that changed
    nothing.

    Every refusal returns a message that says the record is untouched: this
    runs against a row somebody may already have circulated a document for.
    """
    if cr.status in ChangeRequest.TERMINAL:
        return [], (f'This change request is {cr.status}; a closed record is '
                    f'history and is never rewritten. Nothing was changed.')

    title = (fields.get('title') or '').strip()
    if not title:
        return [], 'A title is required. Nothing was changed.'

    risk = (fields.get('risk') or '').strip()
    if risk not in svc.RISKS:
        return [], (f'{risk or "(none)"} is not a risk level. '
                    f'Nothing was changed.')

    # Validated through the SAME function the create path uses, against the two
    # values as they would be AFTER the edit - not against the one the operator
    # happened to touch. Checking only the changed half is how an edit that
    # moves the start past an untouched end stores an unfireable window.
    window_error = svc.validate_window(fields.get('window_start'),
                                       fields.get('window_end'))
    if window_error:
        return [], window_error + ' Nothing was changed.'

    from ..services import cr_document
    proposed = {
        'title': title[:200],
        'risk': risk,
        'reason': (fields.get('reason') or '').strip(),
        'window_start': fields.get('window_start'),
        'window_end': fields.get('window_end'),
        'rollback': (fields.get('rollback') or '').strip(),
        'notify_to': (fields.get('notify_to') or '').strip(),
        'owner': (fields.get('owner') or '').strip()[:64],
        'doc_lang': cr_document.normalize_lang(fields.get('doc_lang')),
        # Same fallback as creation, and for the same reason: an unrecognised
        # value must not bind a change to an approver nobody configured.
        'approval_mode': ('external'
                          if (fields.get('approval_mode') or '').strip() == 'external'
                          else 'manual'),
    }

    changed, critical = [], []
    for field in EDITABLE_FIELDS:
        before = getattr(cr, field)
        after = proposed[field]
        if _unchanged(field, before, after):
            continue
        setattr(cr, field, after)
        changed.append(f'{field}: {_shown(field, before)} -> {_shown(field, after)}')
        if field in APPROVAL_CRITICAL:
            critical.append(field)
    if not changed:
        return [], ''

    db.session.add(ChangeRequestEvent(
        cr_id=cr.id, kind='edited', by=by, detail='; '.join(changed),
        ts=datetime.utcnow()))
    db.session.commit()

    if critical and cr.status in ('approved', 'scheduled'):
        svc.revoke_approval(
            cr, by,
            detail=('Approval voided: ' + ', '.join(critical)
                    + ' changed after approval. Re-approve and re-schedule.'))
    log_action('change_request.update', target=cr.title,
               detail=f'{cr.ref or cr.id} / ' + '; '.join(changed))
    return changed, ''


@bp.route('/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def edit(id):
    """Correct a change that is still open.

    This route exists because ``window_start`` is optional at creation while
    :func:`svc.cr_runnable` refuses a change without one - so a change raised
    with the field left blank was un-runnable FOREVER, with no way back: the
    blueprint had approve / schedule / cancel / notify and nothing that could
    set a window. CR-2026-0012 was stored that way, and the only remedy was to
    cancel it and re-type the whole change.
    """
    cr = _cr_in_scope_or_404(id)
    if cr.status in ChangeRequest.TERMINAL:
        # A closed change is the record of what happened. Refused on GET too:
        # rendering the form and failing on save is an invitation to retype a
        # change that was never going to be written.
        flash(f'This change request is {cr.status} and can no longer be edited.',
              'warning')
        return redirect(_after(id))

    if request.method == 'POST':
        changed, error = update_change_request(cr, {
            'title': request.form.get('title'),
            'risk': request.form.get('risk'),
            'reason': request.form.get('reason'),
            'window_start': _parse_dt(request.form.get('window_start')),
            'window_end': _parse_dt(request.form.get('window_end')),
            'rollback': request.form.get('rollback'),
            'notify_to': request.form.get('notify_to'),
            'owner': request.form.get('owner'),
            'doc_lang': request.form.get('doc_lang'),
            'approval_mode': request.form.get('approval_mode'),
        }, getattr(current_user, 'username', '') or '')
        if error:
            flash(error, 'danger')
            return redirect(url_for('change_requests.edit', id=id,
                                    **_back_arg()))
        if not changed:
            flash('Nothing to save — no field was changed.', 'info')
            return redirect(_after(id))
        if cr.status == 'draft' and any(f.split(':')[0] in APPROVAL_CRITICAL
                                        for f in changed):
            flash(f'Change request {cr.ref or cr.id} updated. It is a draft '
                  f'again and needs approval before it can be scheduled.',
                  'warning')
        else:
            flash(f'Change request {cr.ref or cr.id} updated.', 'success')
        return redirect(_after(id))

    from ..services import cr_document, settings_store
    device_ids = cr.device_ids_list
    devices = (Appliance.query.filter(Appliance.id.in_(device_ids)).all()
               if device_ids else [])

    def _field_value(dt):
        """A stored (naive UTC) window as the operator's clock reads it.

        Through settings_store.to_local - the ONE conversion path parse_local
        inverts. Formatting here with strftime would put the operator's own
        window back into the form shifted by the console's offset, which is the
        defect parse_local exists to stop, arriving from the other side."""
        return settings_store.to_local(dt, '%Y-%m-%dT%H:%M') if dt else ''

    return render_template('change_requests/edit.html',
                           cr=cr,
                           # Carried through the edit screen so saving a change
                           # opened FROM the flow lands back in the flow. Read as
                           # a token, printed as a hidden field, resolved by
                           # _after() - the URL is never the form's to choose.
                           back=_back_token(),
                           back_url=_after(cr.id),
                           devices=devices,
                           risks=svc.RISKS,
                           langs=cr_document.document_langs(),
                           window_start_value=_field_value(cr.window_start),
                           window_end_value=_field_value(cr.window_end),
                           approval_critical=APPROVAL_CRITICAL,
                           will_void_approval=cr.status in ('approved', 'scheduled'),
                           tz_name=_tz_name())


def cr_view_context(cr, *, drift=False, back='',
                    self_endpoint='change_requests.detail',
                    self_args=None) -> dict:
    """Everything the change-request VIEW renders, as plain data.

    ONE author for a screen that now has two homes: the change's own page, and
    stage 2 of the upgrade flow, which renders the change it has just raised
    inline. A second copy of these blocks would drift, and the embedded copy -
    read once, at the end of a window nobody re-opens - would drift first.

    ``back`` is a TOKEN, never a URL. The lifecycle forms post it so approve /
    schedule / cancel / notify return to the page the button was pressed on; a
    redirect target read straight from a request field is an open redirect, and
    these buttons now sit on a page reachable with BACKUP alone.

    Returned as ONE dict and splatted nowhere: enumerating these keys at the
    render call is how a value this function computes can fail to reach the
    template with every assertion about it still green.
    """
    from ..services import cr_document, prep_store
    self_args = dict(self_args) if self_args else {'id': cr.id}
    events = (ChangeRequestEvent.query
              .filter_by(cr_id=cr.id)
              .order_by(ChangeRequestEvent.ts.asc())
              .all())
    device_ids = cr.device_ids_list
    devices = (Appliance.query.filter(Appliance.id.in_(device_ids)).all()
               if device_ids else [])
    runnable_ok, runnable_reason = svc.cr_runnable(cr)
    # The FROZEN inventory is what this change is about - the services that were
    # published when it was raised, which is what the approver signed for. A
    # live re-read is offered separately as DRIFT, never as the record.
    policies = svc.frozen_policies(cr)
    live_drift = None
    if drift:
        # Best-effort LIVE read of the affected policies (the clients to warn).
        # With no/unreachable devices this returns [] quickly rather than raising.
        live = svc.affected_policies(device_ids)
        frozen_keys = {(p.get('device'), p.get('policy'))
                       for p in policies if isinstance(p, dict)}
        live_keys = {(p.get('device'), p.get('policy')) for p in live}
        live_drift = {
            'added': sorted(k[1] or '?' for k in live_keys - frozen_keys),
            'removed': sorted(k[1] or '?' for k in frozen_keys - live_keys),
            'total': len(live),
        }
    return dict(
        cr=cr,
        # Derived, not stored: whether this change has an executor is a
        # question for the registry, asked now. The Schedule button is hidden
        # when the answer is no, and the service refuses it anyway.
        executable=sa.get_spec(cr.action) is not None,
        events=events,
        devices=devices,
        notice=svc.maintenance_notice(cr),
        runnable_ok=runnable_ok,
        runnable_reason=runnable_reason,
        policies=policies,
        live_drift=live_drift,
        prep=prep_store.get(cr.prep_id),
        # EVERY bound run, plus the appliances that have none. "Captured by
        # upgrade preparation #88" is a true sentence about a one-device change
        # and a false one about a window over twenty: the frozen inventory is
        # merged across all of them.
        evidence=prep_store.coverage(cr, devices),
        langs=cr_document.document_langs(),
        fields=prep_store.FIELDS,
        default_fields=prep_store.DEFAULT_FIELDS,
        tz_name=_tz_name(),
        terminal=cr.status in ChangeRequest.TERMINAL,
        status_badge=_STATUS_BADGE,
        risk_badge=_RISK_BADGE,
        # --- the answers that differ between the two homes ---
        back=back,
        # Asking for the live comparison from inside the flow must not be a way
        # OUT of the flow, and neither must pressing Edit.
        drift_url=url_for(self_endpoint, drift=1, **self_args),
        edit_url=url_for('change_requests.edit', id=cr.id,
                         **({'back': back} if back else {})),
        # A button that answers 403 is worse than no button: it reads as an
        # action this operator may take, on a page they reached legitimately.
        can_act=bool(getattr(current_user, 'can', None)
                     and current_user.can('user_manage')),
        # Whether pressing the NetBox button could do anything at all. A button
        # that is enabled, sends, and reports "netbox not configured" teaches
        # the operator the integration is broken; the answer is a dropdown.
        netbox_ready=_netbox_ready(),
        # A configured NetBox is NOT enough. NetBox only knows the devices its
        # owner documented; an appliance it cannot resolve gets no window, and
        # before this the only way to find that out was to press the button —
        # which then marked the change as a NetBox error.
        **_mw_plan(devices),
        # Whether pressing the change-ticket button could reach anything, and
        # through which channel. Same question, same answer shape, same reason.
        crq=_crq_channels(),
    )


def _mw_plan(devices) -> dict:
    """What NetBox can and cannot document for this change.

    Three outcomes, kept apart on purpose:

    * ``mw_unmapped`` — asked, and NetBox has no such device. This is the only
      one that may switch the button off, because it is the only one that is a
      PROVEN refusal.
    * ``mw_unverified`` — NetBox could not be asked (down, slow, switched off
      mid-page). Unknown must never be rendered as absent, and must never
      disable a control: the press may well succeed.
    * resolved — nothing to say.

    ``mw_detail`` carries the per-appliance reason so the page can name the
    remedy instead of repeating the symptom. Asked through
    :func:`netbox_client.resolve_plan`, the SAME author the POST uses, in ONE
    bounded request for the whole change."""
    out = {'mw_unmapped': [], 'mw_unverified': [], 'mw_detail': {}}
    try:
        from ..services import netbox_client
        plan = netbox_client.resolve_plan(
            devices or [], budget=netbox_client.GATE_BUDGET_S)
    except Exception:
        # A page that cannot ask reports nothing rather than an accusation.
        return out
    for dev in (devices or []):
        key = str(getattr(dev, 'id', '') or '')
        name = getattr(dev, 'name', '') or key
        entry = plan.get(key) or plan.get(name) or {}
        if entry.get('device_id'):
            continue
        bucket = 'mw_unmapped' if entry.get('checked', True) else 'mw_unverified'
        out[bucket].append(name)
        out['mw_detail'][name] = entry.get('error', '')
    return out


def _crq_channels() -> dict:
    """What, if anything, is wired behind "Raise change ticket".

    Answered BEFORE the button is drawn. Measured on a live node 2026-09-20:
    tracker backend ``none`` and zero hooks on disk, so the press dispatched to
    nobody and flashed a warning — which teaches the operator that the
    integration is broken when the truth is that none was ever selected. This
    is the gate its NetBox sibling already carries, one row down.

    Two independent channels, and either one is enough: gating on the tracker
    alone would switch the button off for every operator running their own CRM
    glue as a hook, which is the older half of the feature.
    """
    backend, hooks = '', 0
    try:
        from ..services import tracker_client
        if tracker_client.is_configured():
            cfg = tracker_client.config() or {}
            backend = cfg.get('backend_label') or cfg.get('backend') or 'tracker'
    except Exception:
        pass
    try:
        from ..services import integration_hooks
        hooks = len(integration_hooks.hooks_for_event('change.requested') or [])
    except Exception:
        pass
    return {'backend': backend, 'hooks': hooks,
            'ready': bool(backend) or hooks > 0}


def _netbox_ready() -> bool:
    """True when the NetBox integration is switched on and bound."""
    try:
        from ..services import netbox_client
        return bool(netbox_client.is_configured())
    except Exception:
        return False


def _back_token() -> str:
    """The return-to token this request carries, or ''."""
    return (request.form.get('back') or request.args.get('back') or '').strip()


def _back_arg() -> dict:
    """``{'back': <token>}`` or nothing - never ``back=`` with no value."""
    token = _back_token()
    return {'back': token} if token else {}


def _after(cr_id: int) -> str:
    """Where a lifecycle POST returns to: the page the button was pressed on.

    Resolved from a TOKEN (form field, or query string for the edit round
    trip), never from a URL the request carried. An unknown token falls back to
    the change's own page rather than being honoured - an open redirect is what
    this function exists to not be.
    """
    if _back_token() == 'upgrade_flow':
        from .appliances import _adom_arg
        return url_for('upgrade_flow.index', cr=cr_id, **_adom_arg())
    return url_for('change_requests.detail', id=cr_id)


@bp.route('/<int:id>')
@login_required
@require_permission(Permission.USER_MANAGE)
def detail(id):
    cr = _cr_in_scope_or_404(id)
    return render_template(
        'change_requests/detail.html',
        crv=cr_view_context(cr, drift=request.args.get('drift') == '1'))


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


def _flash_rollout(cr) -> None:
    """Say in words what the approval just created, if anything.

    A rollout plan saved while the change was a draft becomes real scheduled
    rows the instant it is approved. An approval that silently created six
    timed outages is an approval whose blast radius the approver was never
    told about; one that silently FAILED to create them is worse, because the
    card will keep showing the plan as though it were going to run.

    The success sentence is the SAME message the rollout card prints, from the
    same msgid: two spellings of "it is saved and on the calendar" is how one
    of them comes to claim it over a row that was never written.
    """
    from flask_babel import gettext

    from ..models import ScheduledAction

    outcome = getattr(cr, 'rollout_outcome', None) or {}
    if not outcome:
        return
    plan = outcome.get('plan') or {}
    if outcome.get('error'):
        flash(gettext('This change was approved, but its saved rollout plan '
                      'could NOT be scheduled: %(why)s The plan is still on '
                      'the change — fix it and save it again.',
                      why=outcome.get('error') or ''), 'danger')
        return
    action_id = outcome.get('action_id')
    action = db.session.get(ScheduledAction, action_id) if action_id else None
    name = action.name if action is not None else f'CR #{cr.id}'
    flash(gettext('The task “%(name)s” has been added to Scheduled '
                  'Actions and is on the calendar.', name=name), 'success')
    total = int(plan.get('total') or 1)
    if total > 1:
        flash(gettext('It runs in %(total)d rounds of at most %(size)d '
                      'appliance(s), %(gap)d minute(s) apart.',
                      total=total, size=int(plan.get('size') or 1),
                      gap=int(plan.get('gap') or 0)), 'info')


@bp.route('/<int:id>/approve', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def approve(id):
    _cr_in_scope_or_404(id)
    try:
        cr = svc.approve(id, current_user.username)
        log_action('change_request.approve', target=cr.title)
        flash('Change request approved.', 'success')
        _flash_rollout(cr)
    except ValueError as exc:
        flash(str(exc), 'danger')
    return redirect(_after(id))


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
    return redirect(_after(id))


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
    return redirect(_after(id))


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
    return redirect(_after(id))


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
    tracker = result.get('tracker') or {}
    if tracker.get('ok') and tracker.get('ref'):
        # The native backend already has the answer, so say the answer. This
        # branch must come first: telling an operator to wait for a reference
        # that is already on the page is how a working integration gets
        # reported as broken.
        where = tracker.get('url') or ''
        flash(f"Opened {tracker['ref']} in "
              f"{tracker.get('backend', 'the tracker')}"
              + (f" — {where}" if where else '') + '.', 'success')
    elif tracker.get('attempted'):
        flash(f"The {tracker.get('backend', 'tracker')} integration is enabled "
              f"but did NOT open a ticket: {tracker.get('detail') or 'no detail'}",
              'danger')
    elif tracker.get('detail') and not tracker.get('attempted') \
            and tracker.get('backend', 'none') != 'none':
        flash(tracker['detail'] + '.', 'info')
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
    elif not tracker.get('ok') and not tracker.get('attempted'):
        # An enabled-but-unbound integration silently doing nothing is the
        # failure mode this message exists to prevent. It now names BOTH paths:
        # since the native backend exists, "no hook is bound" alone would send
        # an operator to write Python when the fix is a dropdown.
        flash('Nothing was sent: no tracker backend is configured in '
              'Settings -> Integrations and no enabled hook is bound to '
              'change.requested.', 'warning')
    return redirect(_after(id))


@bp.route('/<int:id>/record-crq', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def record_crq(id):
    """Write the external ticket reference BY HAND.

    Until now this field had exactly two writers: a configured tracker backend
    and a Python hook calling back through the API. An operator whose change
    board is a person, an e-mail or a system SATOM has no adapter for had NO
    way to put the reference on the change — the row read "none recorded"
    permanently, and the only control offered was a button that, with nothing
    wired behind it, could not fill it either.

    Every refusal leaves the record untouched AND says nothing was saved. A
    half-save (reference stored, link rejected) would leave an approver with a
    ticket id the page offers no way to open.
    """
    from ..services import cr_orchestrator as orch
    cr = _cr_in_scope_or_404(id)
    if cr.status in ChangeRequest.TERMINAL:
        # A cancelled or failed change is the record of something that did not
        # happen. Stamping a live ticket id on it makes it read as if it did.
        flash('This change is closed, so its ticket reference can no longer '
              'change. Nothing was saved.', 'warning')
        return redirect(_after(id))
    ref = (request.form.get('crq_ref') or '').strip()
    url = (request.form.get('crq_url') or '').strip()
    if not ref:
        # An empty field is a slipped click far more often than an intent to
        # erase, and clearing silently would strip the approver's only link to
        # the ticket. Correcting a reference is typing the right one over it.
        flash('Type the ticket reference your change board gave you. Nothing '
              'was saved.', 'warning')
        return redirect(_after(id))
    if url and not url.lower().startswith(('http://', 'https://')):
        # This value is rendered as an <a href>. A javascript: URL typed here
        # is a click-to-run script for the next person who opens the change.
        flash('The ticket link must start with http:// or https://. Nothing '
              'was saved.', 'danger')
        return redirect(_after(id))
    previous = (cr.crq_ref or '').strip()
    # ONE author for "this change now carries a reference": the same service
    # call the tracker backend makes, so the event, the log line and the field
    # cannot drift between the two ways in.
    orch.record_crq(cr, ref, url, by=f'{current_user.username} (by hand)')
    log_action('change_request.crq_recorded', target=cr.title,
               detail=f"ref={ref} previous={previous or '-'} "
                      f"link={'yes' if url else 'no'}")
    flash(f"Recorded {ref} on this change"
          + (f", replacing {previous}" if previous and previous != ref else '')
          + '.', 'success')
    return redirect(_after(id))


@bp.route('/<int:id>/open-window', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def open_window(id):
    """Open the NetBox maintenance window for this change, by hand, now.

    The scheduler already opens it when the run starts (cr_orchestrator.
    on_start). This is the SAME call for the operator who needs NetBox to show
    the devices in maintenance before the window begins. It is idempotent: a
    change whose window is already open does not get a second one.

    Refuses locally on a change with no window times instead of calling NetBox.
    The client rejects an unusable timestamp, and that rejection would be
    stored as ``mw_state='error'`` - whose wording on this page states a device
    may be sitting in maintenance in NetBox. Nothing was sent, so nothing here
    may say that.
    """
    from ..services import cr_orchestrator as orch
    cr = _cr_in_scope_or_404(id)
    if not (cr.window_start and cr.window_end):
        flash('This change has no maintenance window yet: set a start AND an '
              'end first. NetBox was not asked and nothing was recorded.',
              'warning')
        return redirect(_after(id))
    result = orch.open_window(cr, by=current_user.username)
    log_action('change_request.window_opened', target=cr.title,
               detail=f"opened={result.get('opened', 0)} "
                      f"failed={result.get('failed', 0)} "
                      f"detail={result.get('detail', '')}")
    if result.get('detail') == 'already open':
        flash('The window for this change is already open in NetBox; a second '
              'one was not created.', 'info')
    elif result.get('ok'):
        flash(f"Maintenance window opened in NetBox for "
              f"{result.get('opened', 0)} device(s). It stays open until the "
              f"run finishes - closing it is not automatic for a change that "
              f"is never run.", 'success')
    elif result.get('opened'):
        flash(f"NetBox opened {result.get('opened')} window(s) and refused "
              f"{result.get('failed')}. This change is now marked as window "
              f"error: some devices may show as in maintenance there.",
              'danger')
    else:
        # The reason arrives already punctuated (it ends in "Map it in
        # Settings -> Integrations first."), so a bare period would double it.
        why = (result.get('detail') or 'NetBox gave no detail').rstrip('. ')
        flash(f"No maintenance window was opened: {why}.", 'danger')
    return redirect(_after(id))


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
