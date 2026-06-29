"""FortiWeb Configuration — the admin-only **Settings → FortiWeb → Configuration**
area, web port.

Surfaces every config GUI section (System, Network, Server Objects, API
Protection, …). Each section page is now a **live browser** for the sections that
have a GUI-faithful menu (:mod:`app.services.config_sections`): device → menu
(groups → object types) → the live object list of a chosen type → the SAME
generic recursive editor (:mod:`app.views.objedit`) every other config area uses,
so by-parent sub-tables (rules, members, match conditions, schema files…) are
edited in place several levels deep — exactly the Server Objects experience.

Sections without a curated menu fall back to the registry-derived object-type
catalog (data-only, no device). The per-section config-template library (author /
clone / apply-to-fleet) is kept on every section. Reads are open to any signed-in
user via the menu; New/Edit/Delete are ``config_write`` + audited + dry-run
default, exactly like ``objedit``.
"""
from __future__ import annotations

from flask import Blueprint, render_template, request, abort, redirect, url_for
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import Appliance, Permission
from ..clients.fortiweb import FortiWebClient
from ..services import config_catalog
from ..services import device_context
from ..services import config_sections
from ..services import objform
from ..services.templates import KIND_LABELS, list_templates

bp = Blueprint('section_config', __name__, url_prefix='/configuration')


def _row_view(obj: dict) -> dict:
    """A compact list-row projection (name + a couple of GUI-meaningful fields)."""
    if not isinstance(obj, dict):
        return {'name': str(obj), 'status': '', 'detail': ''}
    name = obj.get('name') or obj.get('mkey') or obj.get('id') or '—'
    status = obj.get('status') or ''
    detail = ''
    for k in ('comment', 'comments', 'type', 'action', 'host', 'url',
              'request-file', 'schema-file', 'protocol', 'mode', 'severity'):
        v = obj.get(k)
        if v not in (None, '', []):
            detail = '%s: %s' % (k, v)
            break
    return {'name': name, 'status': status, 'detail': detail}


def _first_loaded_type(client, section_key, menu, cap=14):
    """Probe menu leaves in GUI order; return the logical name of the FIRST
    object type that returns at least one live object, else None. Bounded so a
    genuinely-empty section never hammers the device."""
    tried = 0
    for group in menu:
        for item in group.items:
            if tried >= cap:
                return None
            tried += 1
            try:
                raw = client._safe_list(objform.rest_path(item.collection))
            except Exception:  # noqa: BLE001 - skip a bad leaf, keep probing
                continue
            if raw:
                return item.logical
    return None


def _first_logical(menu):
    for group in menu:
        if group.items:
            return group.items[0].logical
    return None


@bp.route('/')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def index():
    """Section grid. The device is the session-selected one (device-first
    nav); there is no in-page picker."""
    _cur = device_context.current_appliance()
    device_id = _cur.id if _cur else None
    sections = [
        {
            'key': s.key, 'label': s.label, 'emoji': s.emoji,
            'danger': s.danger, 'readonly': s.readonly,
            'count': len(config_catalog.section_catalog(s.key)),
            'live': config_sections.has_menu(s.key),
        }
        for s in config_catalog.CONFIG_SECTIONS
    ]
    return render_template(
        'section_config/index.html',
        sections=sections,
        device_id=device_id,
    )


@bp.route('/<section_key>')
@login_required
@require_permission(Permission.CONFIG_WRITE)
def section(section_key: str):
    """One section: a live object browser (when it has a menu) + its template lib.

    ``?device=<id>`` picks the appliance to browse; ``?type=<logical>`` selects a
    menu leaf, whose live objects are listed and linked into the ``objedit``
    editor. Sections with no curated menu keep the static object-type catalog.
    """
    sec = config_catalog.SECTION_BY_KEY.get(section_key)
    if sec is None:
        abort(404)

    appliance = device_context.current_appliance()
    if appliance is None:
        # device-first nav: no device chosen yet -> go pick one on the map
        return redirect(url_for('architecture.index'))
    device_id = appliance.id
    menu = config_sections.section_menu(section_key)

    selected = None
    rows: list[dict] = []
    error = None
    is_singleton = False
    logical = (request.args.get('type') or '').strip()

    # Land the section on REAL DATA: with no explicit ?type=, auto-select the
    # first object type that actually has objects on this device (falling back
    # to the first leaf) so opening a section shows the FortiWeb's config
    # immediately instead of an empty "pick a type" pane. An explicit click wins.
    if menu and not logical:
        try:
            _probe = FortiWebClient(appliance)
            logical = _first_loaded_type(_probe, section_key, menu) or _first_logical(menu)
        except Exception as exc:  # noqa: BLE001 - dead device -> leave unselected
            error = str(exc)

    if menu and logical:
        selected = config_sections.type_for(section_key, logical)
        if selected is None:
            abort(404)
        try:
            client = FortiWebClient(appliance)
            raw = client._safe_list(objform.rest_path(selected.collection))
            # A singleton config object (global, dns, ntp, ha, log settings…) GETs
            # as ONE keyless blob — no name/mkey/id. Detect it at runtime so the
            # page edits it as a whole-object PUT (mkey-less) instead of listing a
            # nameless row that can't be opened.
            is_singleton = (
                len(raw) == 1 and isinstance(raw[0], dict)
                and not (raw[0].get('name') or raw[0].get('mkey') or raw[0].get('id'))
            )
            rows = [_row_view(o) for o in raw]
        except Exception as exc:  # noqa: BLE001 — dead device → empty list + note
            error = str(exc)

    kind = config_catalog.config_template_kind(section_key)
    return render_template(
        'section_config/section.html',
        section=sec,
        menu=menu,
        appliance=appliance,
        selected=selected,
        rows=rows,
        error=error,
        is_singleton=is_singleton,
        object_types=config_catalog.section_catalog(section_key),
        kind=kind,
        kind_labels=KIND_LABELS,
        templates=list_templates(kind),
        appliances=Appliance.query.order_by(Appliance.name).all(),
        device_id=device_id,
    )
