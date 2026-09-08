"""New Server Policy from a line profile — the wizard's three endpoints.

GET  /web/workspace/<id>/spo-wizard        the form
POST /web/workspace/<id>/spo-wizard/plan   inspect only, changes NOTHING
POST /web/workspace/<id>/spo-wizard/apply  dry-run unless apply=true

The blueprint is separate from ``views.workspace`` on purpose: workspace is a
2000-line module four sessions edit, and this feature commits without touching
it. It shares workspace's URL prefix so the device scope gate (which keys on
``appliance_id`` in the view args) covers it exactly as it covers the rest of
the device pages.

All judgement lives in ``services.spo_wizard``; this module translates the
form and enforces the permission. In particular it does NOT decide whether a
plan may be applied — ``apply_plan`` refuses a blocked plan itself, so a second
opinion here could only disagree with it.

One domain or twenty go down the SAME path: :func:`_plans_from` always builds a
list and always hands it to ``build_batch``. A shortcut for the single-domain
case is how the batch rules (one shared pool, no duplicate rows) stop applying
to the case operators use most.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import visible_appliance_or_404
from ..services import dns_providers as ddi
from ..services import line_profiles as lp
from ..services import pool_catalog
from ..services import spo_wizard as wiz
from ..services import settings_store as store
from ..services.audit import log_action

bp = Blueprint('spo_wizard', __name__, url_prefix='/workspace')


def _backends(body: dict) -> list[dict]:
    out = []
    for row in body.get('backends') or []:
        ip = str((row or {}).get('ip') or '').strip()
        if not ip:
            continue
        out.append({'ip': ip, 'port': str((row or {}).get('port') or '80')})
    return out


def _rows(body: dict) -> list[dict]:
    """The domains to build, newest form first, old form as the fallback.

    The single ``web_address``/``hostname``/``address`` triple is still
    accepted verbatim: it is what every existing caller (and every existing
    test) posts, and a wizard that started refusing it would be a silent
    break for anyone with the page already open.
    """
    rows = []
    for raw in body.get('web_addresses') or []:
        web = str((raw or {}).get('web_address') or '').strip()
        if not web:
            continue
        rows.append({
            'web_address': web,
            'hostname': str((raw or {}).get('hostname') or '').strip(),
            'address': str((raw or {}).get('address') or '').strip(),
        })
    if rows:
        return rows
    web = str(body.get('web_address') or '').strip()
    if not web:
        return []
    return [{'web_address': web,
             'hostname': str(body.get('hostname') or '').strip(),
             'address': str(body.get('address') or '').strip()}]


def _common(body: dict) -> dict:
    return dict(
        line=str(body.get('line') or ''),
        segment_name=str(body.get('segment') or ''),
        department=str(body.get('department') or ''),
        use_ipam=bool(body.get('use_ipam')),
        issue_cert=bool(body.get('issue_cert')),
        ipam_backend_id=body.get('ipam_backend_id'),
        dns_backend_id=body.get('dns_backend_id'),
        backends=_backends(body),
    )


def _plans_from(appliance, body: dict) -> list[wiz.SpoPlan]:
    rows = _rows(body)
    common = _common(body)
    if not rows:
        # ONE plan carrying the "no web address" blocker, rather than an empty
        # list: an empty batch would render as "nothing wrong", which is the
        # opposite of what an empty form means.
        return [wiz.build_plan(appliance, web_address='', hostname='',
                               address='', **common)]
    return wiz.build_batch(
        appliance, rows=rows,
        existing_pool=str(body.get('existing_pool') or '').strip(),
        # Threaded through EXPLICITLY. "existing" with nothing named has to
        # reach the planner as a refusal, not be quietly downgraded here into
        # "build a new one" — that is a different pool from the one the
        # operator had on screen.
        pool_mode=str(body.get('pool_mode') or wiz.POOL_NEW),
        pool_from=str(body.get('pool_from') or '').strip(),
        **common)


def _payload(plans, extra=None):
    """The response shape. ``plans`` is the list; ``plan`` is the first one,
    kept because every caller written before batches reads that key."""
    out = {'plans': [p.as_dict() for p in plans],
           'plan': plans[0].as_dict() if plans else None}
    out.update(extra or {})
    return out


@bp.route('/<int:appliance_id>/spo-wizard')
@login_required
def index(appliance_id: int):
    appl = visible_appliance_or_404(appliance_id)
    return render_template(
        'workspace/spo_wizard.html', appliance=appl,
        lines=store.classification('lines'),
        line_plans={l: lp.line_plan(l, appl.kind or 'fortiweb').as_dict()
                    for l in store.classification('lines')},
        # ENABLED rows only, and via ``public()`` — the same shape the
        # Settings page renders, so the two lists cannot describe the same
        # registry differently. A disabled backend is not a choice, and
        # ``public()`` is where the secret is already known not to cross.
        dns_backends=[r.public() for r in ddi.enabled_backends()],
        # Cache-only, ADOM-scoped, local pools first. Served inline for the
        # same reason the backends are: the picker filters client-side, and a
        # dropdown that opens an SSL session per appliance per keystroke is a
        # page nobody can leave open.
        pools=pool_catalog.fleet_pools(local_appliance_id=appl.id),
    )


@bp.route('/<int:appliance_id>/spo-wizard/plan', methods=['POST'])
@login_required
def plan(appliance_id: int):
    """Inspection only. Safe to press at any time, at any permission level
    that can already see the device."""
    appl = visible_appliance_or_404(appliance_id)
    plans = _plans_from(appl, request.get_json(silent=True) or {})
    return jsonify(ok=True, **_payload(plans))


@bp.route('/<int:appliance_id>/spo-wizard/apply', methods=['POST'])
@login_required
@require_permission('config_write')
def apply(appliance_id: int):
    appl = visible_appliance_or_404(appliance_id)
    body = request.get_json(silent=True) or {}
    do_apply = bool(body.get('apply'))
    plans = _plans_from(appl, body)
    res = wiz.apply_batch(appl, plans, dry_run=not do_apply,
                          actor=getattr(current_user, 'username', ''))
    if do_apply:
        # One line PER DOMAIN. A single line naming the batch would hide which
        # domains actually got built when a later one failed, and that is the
        # only fact an operator needs from the log at 3am.
        for p, run in zip(plans, res.get('runs') or []):
            r = run.get('result') or {}
            log_action('spo_wizard.apply',
                       detail='device=%s line=%s dept=%s segment=%s addr=%s '
                              'pool=%s(%s) ipam=%s dns=%s ok=%s stranded=%d'
                              % (appl.name, p.line, p.department or '-',
                                 p.segment.get('name') or '-', p.web_address,
                                 p.pool_name or '-', p.pool_mode,
                                 (p.ipam_backend or '-')
                                 + ('(chosen)' if p.ipam_pick else ''),
                                 (p.dns_backend or '-')
                                 + ('(chosen)' if p.dns_pick else ''),
                                 r.get('ok'), len(r.get('stranded') or [])))
    first = (res.get('runs') or [{}])[0].get('result')
    return jsonify(ok=res.get('ok'), batch=res,
                   # ``result`` is the FIRST run, for the same
                   # backwards-compatibility reason ``plan`` is the first plan.
                   result=first if first is not None else
                   {'ok': res.get('ok'), 'error': res.get('error', ''),
                    'steps': [], 'compensated': [], 'stranded': []},
                   **_payload(plans))
