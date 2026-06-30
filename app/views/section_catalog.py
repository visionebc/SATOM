"""FortiWeb Sections — the APPROVED-TEMPLATE CATALOG.

NOT a live device browser (that is the *Configuration* area -> section_config).
This page is desired-state only: it lists the templates users saved that an admin
has APPROVED, grouped by the FortiWeb section each belongs to. From here they flow
into Provisioning to be assembled into baselines. Clean by construction — only
``status == approved`` templates ever appear.
"""
from __future__ import annotations

import json

from flask import Blueprint, render_template, abort, jsonify
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import Permission, Template
from ..services import section_taxonomy as tax
from ..services.templates import KIND_LABELS, get_template

bp = Blueprint('section_catalog', __name__, url_prefix='/section-catalog')


@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    approved = (Template.query
                .filter_by(status=Template.STATUS_APPROVED)
                .order_by(Template.kind, Template.name, Template.version.desc())
                .all())
    # Group by section, preserving the canonical section order.
    by_section: dict[str, list[Template]] = {}
    for t in approved:
        by_section.setdefault(tax.section_for_kind(t.kind), []).append(t)
    groups = []
    for sec in tax.known_sections():
        rows = by_section.pop(sec["key"], [])
        if rows:
            groups.append({"key": sec["key"], "label": sec["label"], "templates": rows})
    # Any leftover (unknown) sections last.
    for key, rows in by_section.items():
        groups.append({"key": key, "label": tax.section_label(key), "templates": rows})
    return render_template(
        'section_catalog/index.html',
        groups=groups,
        total=len(approved),
        kind_labels=KIND_LABELS,
    )


@bp.route('/<int:template_id>')
@login_required
@require_permission(Permission.USER_MANAGE)
def detail(template_id: int):
    row = get_template(template_id)
    if row is None or row.status != Template.STATUS_APPROVED:
        abort(404)
    return jsonify({
        'id': row.id, 'kind': row.kind, 'name': row.name, 'version': row.version,
        'section': tax.section_for_kind(row.kind),
        'note': row.note or '', 'author': row.author or '',
        'body': json.dumps(row.body_dict, indent=2, sort_keys=True),
    })
