"""ADOM Search — free-text search over the synced configuration of the active
ADOM's appliances (see :mod:`app.services.adom_search`). Read-only and
DB-first: no device is called on a search."""
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required
from ..auth.decorators import require_permission
from ..models import Appliance, Permission
from ..models import visible_appliances
from ..services import adom_search

bp = Blueprint('search', __name__, url_prefix='/search')


@bp.route('/')
@login_required
@require_permission(Permission.VIEW)
def index():
    appliances = visible_appliances().order_by(Appliance.name).all()
    return render_template(
        'search/index.html', appliances=appliances,
        sections=adom_search.sections_for([a.id for a in appliances]))


@bp.route('/results')
@login_required
@require_permission(Permission.VIEW)
def results():
    term = request.args.get('q', '').strip()
    # The form's single-select is ``appliance_id``; ``appliances`` (repeatable)
    # is still honoured for bookmarked links.
    appliance_ids = (request.args.getlist('appliance_id', type=int)
                     + request.args.getlist('appliances', type=int))
    section = request.args.get('section', '').strip()

    if not term:
        flash('Please enter a search term.', 'warning')
        return redirect(url_for('search.index'))

    in_adom = visible_appliances().order_by(Appliance.name).all()
    appliances = ([a for a in in_adom if a.id in appliance_ids]
                  if appliance_ids else in_adom)
    sections = adom_search.sections_for([a.id for a in in_adom])
    if section not in sections:
        section = ''

    return render_template(
        'search/results.html',
        term=term,
        result=adom_search.search(term, appliances, section=section or None),
        appliances=in_adom,
        appliance_ids=appliance_ids,
        sections=sections,
        section=section,
    )
