"""Regex Lab — the pattern calculator behind every ".*" button on regex-capable
WAF fields (objedit, exceptions). Pure helper endpoints: nothing here touches a
device or the DB; it exists so the operator can PROVE a pattern against sample
values before it lands in a rule."""
from flask import Blueprint, jsonify, request
from flask_login import login_required

from ..services import regex_lab

bp = Blueprint('regex_lab', __name__, url_prefix='/regex-lab')


@bp.route('/examples')
@login_required
def examples():
    """Curated + admin-guide examples for a section context, plus the
    FortiWeb regex-flavor notes shown in the lab's help strip."""
    ctx = request.args.get('context', '')
    return jsonify(ok=True, context=ctx,
                   examples=regex_lab.examples_for(ctx),
                   notes=regex_lab.guide_notes())


@bp.route('/test', methods=['POST'])
@login_required
def test():
    """Test a pattern against sample values (size-capped, see regex_lab)."""
    body = request.get_json(silent=True) or {}
    samples = body.get('samples') or []
    if isinstance(samples, str):
        samples = samples.splitlines()
    res = regex_lab.test_pattern(
        body.get('pattern', ''), samples,
        case_insensitive=bool(body.get('case_insensitive')))
    status = 200 if res.get('ok') or res.get('error', '').startswith('invalid') \
        or res.get('error') == 'empty pattern' else 400
    return jsonify(res), status
