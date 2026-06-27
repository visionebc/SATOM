"""FortiWeb endpoint registry browser.

Driven entirely by the real ``endpoints.yaml`` via :mod:`app.registry.loader`
(previously this used a small hardcoded table and never passed ``endpoints`` to
the index template, so the catalog rendered empty).
"""
from flask import Blueprint, render_template, request, abort
from flask_login import login_required

from ..registry import loader

bp = Blueprint('registry', __name__, url_prefix='/registry')


@bp.route('/')
@login_required
def index():
    return render_template(
        'registry/index.html',
        sections=loader.get_all_sections(),
        endpoints=loader.get_all_endpoints(),
        current_section=None,
    )


# ``<path:section>`` (not ``<section>``) because section names contain "/" and
# spaces (e.g. "Dashboard / Monitor", "Log & Report").
@bp.route('/<path:section>')
@login_required
def section_detail(section):
    if section not in loader.get_all_sections():
        abort(404)
    return render_template(
        'registry/section.html',
        section=section,
        current_section=section,
        sections=loader.get_all_sections(),
        endpoints=loader.get_endpoints_by_section(section),
    )


@bp.route('/search')
@login_required
def search():
    term = request.args.get('q', '').strip().lower()
    results = []
    if term:
        for e in loader.get_all_endpoints():
            if term in e['name'].lower() or term in (e['urn'] or '').lower():
                results.append({'section': e['section'], 'endpoint': e})
    return render_template(
        'registry/search.html',
        term=term,
        results=results,
        sections=loader.get_all_sections(),
    )
