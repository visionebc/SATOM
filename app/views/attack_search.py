"""Search Attack ID — resolve the reference printed on a WAF block page.

The block page hands the end user ``id-<device>-<msgid>``. That string carries
BOTH halves of the lookup: which appliance blocked the request, and which log row
it was. So the search box takes the whole reference and resolves the appliance
itself — asking the operator to also pick the device from a dropdown would be
asking them to re-type information they already pasted, and would let them pick
the WRONG box and get a confident "not found" for a request that was blocked
somewhere else.

Every lookup is written to the audit log, hit or miss. An attack-ID search is the
first step of a false-positive investigation that may end in a rule carve-out;
the carve-out is auditable only if the evidence that motivated it is too.
"""
from __future__ import annotations

from flask import Blueprint, render_template, request

from flask_login import login_required

from ..models import Appliance, visible_appliances, visible_appliance_or_404
from ..services import attack_log
from ..services.audit import log_action

bp = Blueprint('attack_search', __name__, url_prefix='/waf/attack-search')


def _resolve_appliance(ref: attack_log.LogReference, explicit_id):
    """Which box to ask, and why.

    An explicitly chosen appliance always wins — the operator may be searching a
    reference produced before a rename. Otherwise the device segment of the
    reference is matched against appliance names, case-insensitively.
    """
    if explicit_id:
        return visible_appliance_or_404(int(explicit_id)), 'selected'
    if not ref.has_device:
        return None, 'no-device'
    wanted = ref.device.strip().lower()
    for a in visible_appliances().all():
        if (a.name or '').strip().lower() == wanted:
            return a, 'reference'
    # A hostname match is the sane fallback for references minted before a rename.
    for a in visible_appliances().all():
        if (a.host or '').strip().lower() == wanted:
            return a, 'reference-host'
    return None, 'unknown-device'


@bp.route('/', methods=['GET'])
@login_required
def index():
    appliances = visible_appliances().order_by(Appliance.name).all()
    query = (request.args.get('q') or '').strip()
    explicit_id = request.args.get('appliance_id') or ''

    ctx = {
        'appliances': appliances,
        'query': query,
        'explicit_id': explicit_id,
        'primary_fields': attack_log.PRIMARY_FIELDS,
        'ref': None,
        'appliance': None,
        'rows': None,
        'error': None,
        'warning': None,
        'recent': None,
    }
    if not query:
        return render_template('attack_search/index.html', **ctx)

    try:
        ref = attack_log.parse_reference(query)
    except ValueError as exc:
        ctx['error'] = str(exc)
        return render_template('attack_search/index.html', **ctx)
    ctx['ref'] = ref

    appliance, how = _resolve_appliance(ref, explicit_id)
    if appliance is None:
        ctx['error'] = (
            'This reference does not name a device, so pick the appliance to '
            'search.' if how == 'no-device' else
            f'No appliance in SATOM is named "{ref.device}". Pick the device '
            f'explicitly, or add it under Appliances.')
        return render_template('attack_search/index.html', **ctx)
    ctx['appliance'] = appliance
    if how == 'reference-host':
        ctx['warning'] = (
            f'Matched "{ref.device}" by management address, not by name — the '
            f'appliance may have been renamed since this block page was served.')

    try:
        rows = attack_log.search_by_msg_id(appliance, ref.msg_id)
    except attack_log.AttackLogUnavailable as exc:
        ctx['error'] = f'Attack-log feed unavailable: {exc}'
        log_action('attack_search', target=ref.raw,
                   extra={'appliance': appliance.name, 'msg_id': ref.msg_id,
                          'result': 'feed-unavailable', 'detail': str(exc)})
        return render_template('attack_search/index.html', **ctx)
    except attack_log.AttackLogError as exc:
        ctx['error'] = str(exc)
        log_action('attack_search', target=ref.raw,
                   extra={'appliance': appliance.name, 'msg_id': ref.msg_id,
                          'result': 'error', 'detail': str(exc)})
        return render_template('attack_search/index.html', **ctx)

    ctx['rows'] = rows
    if not rows:
        # A miss and a broken feed look identical on screen, so prove the feed
        # works by showing what the box DOES have.
        try:
            ctx['recent'] = attack_log.recent(appliance, limit=10)
        except attack_log.AttackLogError:
            ctx['recent'] = None
    log_action('attack_search', target=ref.raw,
               extra={'appliance': appliance.name, 'msg_id': ref.msg_id,
                      'result': 'hit' if rows else 'miss', 'matches': len(rows)})
    return render_template('attack_search/index.html', **ctx)
