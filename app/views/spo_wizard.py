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
"""
from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import visible_appliance_or_404
from ..services import dns_providers as ddi
from ..services import line_profiles as lp
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


def _plan_from(appliance, body: dict):
    return wiz.build_plan(
        appliance,
        line=str(body.get('line') or ''),
        web_address=str(body.get('web_address') or ''),
        segment_name=str(body.get('segment') or ''),
        department=str(body.get('department') or ''),
        hostname=str(body.get('hostname') or ''),
        use_ipam=bool(body.get('use_ipam')),
        address=str(body.get('address') or ''),
        issue_cert=bool(body.get('issue_cert')),
        ipam_backend_id=body.get('ipam_backend_id'),
        dns_backend_id=body.get('dns_backend_id'),
        backends=_backends(body),
    )


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
    )


@bp.route('/<int:appliance_id>/spo-wizard/plan', methods=['POST'])
@login_required
def plan(appliance_id: int):
    """Inspection only. Safe to press at any time, at any permission level
    that can already see the device."""
    appl = visible_appliance_or_404(appliance_id)
    p = _plan_from(appl, request.get_json(silent=True) or {})
    return jsonify(ok=True, plan=p.as_dict())


@bp.route('/<int:appliance_id>/spo-wizard/apply', methods=['POST'])
@login_required
@require_permission('config_write')
def apply(appliance_id: int):
    appl = visible_appliance_or_404(appliance_id)
    body = request.get_json(silent=True) or {}
    do_apply = bool(body.get('apply'))
    p = _plan_from(appl, body)
    res = wiz.apply_plan(appl, p, dry_run=not do_apply,
                         actor=getattr(current_user, 'username', ''))
    if do_apply:
        log_action('spo_wizard.apply',
                   detail='device=%s line=%s dept=%s segment=%s addr=%s '
                          'ipam=%s dns=%s ok=%s stranded=%d'
                          % (appl.name, p.line, p.department or '-',
                             p.segment.get('name') or '-', p.web_address,
                             (p.ipam_backend or '-')
                             + ('(chosen)' if p.ipam_pick else ''),
                             (p.dns_backend or '-')
                             + ('(chosen)' if p.dns_pick else ''),
                             res.get('ok'), len(res.get('stranded') or [])))
    return jsonify(ok=res.get('ok'), result=res, plan=p.as_dict())
