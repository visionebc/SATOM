"""FortiWeb Configuration — the admin-only **Settings → FortiWeb → Configuration**
area, web port.

Surfaces every config GUI section (System, Network, Server Objects, …) as a
registry-derived catalog of object TYPES, plus the per-section config-template
library. The catalog is data-only and renders WITHOUT a device (it comes from the
endpoint registry, not a live appliance). Choosing a device is optional and is
carried through so a later live-object browser can use it; applying a config
template to live devices is the audited Templates apply flow (reused via
``url_for('templates.apply', ...)``).
"""
from __future__ import annotations

from flask import Blueprint, render_template, request, abort
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import Appliance, Permission
from ..services import config_catalog
from ..services.templates import KIND_LABELS, list_templates

bp = Blueprint('section_config', __name__, url_prefix='/configuration')


@bp.route('/')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def index():
    """Section grid + optional device picker. Renders with no device selected."""
    device_id = request.args.get('device', type=int)
    sections = [
        {
            'key': s.key, 'label': s.label, 'emoji': s.emoji,
            'danger': s.danger, 'readonly': s.readonly,
            'count': len(config_catalog.section_catalog(s.key)),
        }
        for s in config_catalog.CONFIG_SECTIONS
    ]
    return render_template(
        'section_config/index.html',
        sections=sections,
        appliances=Appliance.query.order_by(Appliance.name).all(),
        device_id=device_id,
    )


@bp.route('/<section_key>')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def section(section_key: str):
    """One section: its object-type catalog + its config-template library."""
    sec = config_catalog.SECTION_BY_KEY.get(section_key)
    if sec is None:
        abort(404)
    device_id = request.args.get('device', type=int)
    kind = config_catalog.config_template_kind(section_key)
    return render_template(
        'section_config/section.html',
        section=sec,
        object_types=config_catalog.section_catalog(section_key),
        kind=kind,
        kind_labels=KIND_LABELS,
        templates=list_templates(kind),
        appliances=Appliance.query.order_by(Appliance.name).all(),
        device_id=device_id,
    )
