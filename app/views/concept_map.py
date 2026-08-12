"""Concept Map — /map.

A navigation aid, so it carries no permission of its own: every node it draws
is already gated by the page behind it, and
:func:`app.services.concept_map.build` hides the ones this user cannot open.
Gating the map itself would hide the index from exactly the junior operator who
needs it most.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, render_template
from flask_login import current_user, login_required

from ..services import concept_map as cmap

bp = Blueprint('concept_map', __name__, url_prefix='/map')


@bp.route('/')
@login_required
def index():
    clusters = cmap.build(current_user)
    return render_template(
        'concept_map/index.html',
        clusters=clusters,
        total=sum(len(c['pages']) for c in clusters),
        coverage=cmap.coverage(),
    )


@bp.route('/data')
@login_required
def data():
    """The same clusters as JSON — the SVG map's only input."""
    clusters = cmap.build(current_user)
    return jsonify({'clusters': clusters,
                    'total': sum(len(c['pages']) for c in clusters)})
