"""Operator-authored field renames for the API library (``api_lib_field_map``).

Without a mapping, a field the vendor renamed between two builds reads as
"field lost + field added": the clone pre-flight warns that the old name is
dropped and offers the new one as an unrelated gain, and the upgrade summary
counts a loss that the firmware migrates on its own. A row here tells
``api_library.compare`` and ``version_compat`` that the two are ONE field.

Rows are never deleted (``docs/api-library.md``: no code path in the library
deletes a row). A wrong or superseded mapping is RETIRED — ``retired_at`` is
set, every reader skips it, and the list keeps showing what was believed, by
whom and until when. Re-adding it later is a new row with its own author.

Writes are gated on ``Permission.REGISTRY_EDIT`` (the same gate as the API
versions page that reads these rows) and audited through
``services.audit.log_action``.
"""
from __future__ import annotations

import re
from datetime import datetime

from flask import (Blueprint, flash, jsonify, redirect, render_template,
                   request, url_for)
from flask_babel import gettext as _
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..extensions import db
from ..models import Permission
from ..models_apilib import ApiLibFieldMap
from ..services import api_library as lib
from ..services import firmware_versions as fv
from ..services.audit import log_action

bp = Blueprint('apilib_fieldmap', __name__, url_prefix='/registry/field-map')

_NAME_RE = re.compile(r'^[A-Za-z0-9_.\-]{1,160}$')
_LIST_LIMIT = 500


def _username() -> str:
    return (getattr(current_user, 'username', '') or '')[:64]


def _history(product: str, endpoint: str, field: str) -> dict:
    """Where the library has seen ``endpoint.field`` — shown beside each row."""
    try:
        h = lib.field_history(product, endpoint, field)
    except Exception:  # noqa: BLE001 — a hint, never a reason to 500 the page
        db.session.rollback()
        return {'known': False, 'first_build': '', 'last_build': '', 'sources': []}
    return {'known': bool(h.get('known')), 'first_build': h.get('first_build') or '',
            'last_build': h.get('last_build') or '', 'sources': h.get('sources') or []}


def _row(m: ApiLibFieldMap, with_history: bool) -> dict:
    out = {'id': m.id, 'product': m.product, 'endpoint': m.endpoint,
           'from_version': m.from_version or '', 'from_field': m.from_field,
           'to_version': m.to_version or '', 'to_field': m.to_field,
           'note': m.note or '', 'created_by': m.created_by or '',
           'created_at': m.created_at, 'retired_at': m.retired_at,
           'retired_by': m.retired_by or ''}
    if with_history:
        out['from_seen'] = _history(m.product, m.endpoint, m.from_field)
        out['to_seen'] = _history(m.product, m.endpoint, m.to_field)
    return out


@bp.route('/')
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def index():
    product = (request.args.get('product') or '').strip()
    endpoint = (request.args.get('endpoint') or '').strip()
    show_retired = request.args.get('retired') == '1'
    q = ApiLibFieldMap.query
    if product:
        q = q.filter(ApiLibFieldMap.product == product)
    if endpoint:
        q = q.filter(ApiLibFieldMap.endpoint == endpoint)
    rows = q.order_by(ApiLibFieldMap.product, ApiLibFieldMap.endpoint,
                      ApiLibFieldMap.id.desc()).limit(_LIST_LIMIT).all()
    active = [_row(m, True) for m in rows if m.retired_at is None]
    retired = [_row(m, False) for m in rows if m.retired_at is not None]
    return render_template(
        'registry/field_map.html', active=active,
        retired=retired if show_retired else [], retired_count=len(retired),
        show_retired=show_retired, products=list(lib.PRODUCTS),
        f_product=product, f_endpoint=endpoint, limit=_LIST_LIMIT,
        truncated=len(rows) >= _LIST_LIMIT)


def _clean(form) -> tuple[dict, str]:
    """``(row, error)`` for the add form."""
    product = (form.get('product') or '').strip()
    if product not in lib.PRODUCTS:
        return {}, _('Unknown product.')
    out = {'product': product}
    for k in ('endpoint', 'from_field', 'to_field'):
        v = (form.get(k) or '').strip()
        if not _NAME_RE.match(v):
            return {}, _('%(field)s must be a name (letters, digits, "_", "-", "."), '
                         'at most 160 characters.', field=k.replace('_', ' '))
        out[k] = v
    if out['from_field'] == out['to_field']:
        return {}, _('A rename needs two different field names.')
    for k in ('from_version', 'to_version'):
        raw = (form.get(k) or '').strip()
        v = fv.normalize(raw) if raw else ''
        if raw and not v:
            return {}, _('%(v)r is not a firmware version.', v=raw)
        out[k] = v
    if out['from_version'] and out['to_version'] \
            and lib.version_key(out['from_version']) >= lib.version_key(out['to_version']):
        return {}, _('The old name must belong to an EARLIER build than the new one.')
    note = (form.get('note') or '').strip()
    if len(note) > 500:
        return {}, _('The note is limited to 500 characters.')
    out['note'] = note
    return out, ''


@bp.route('/add', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def add():
    row, err = _clean(request.form)
    back = url_for('apilib_fieldmap.index', product=request.form.get('product') or None)
    if err:
        flash(err, 'danger')
        return redirect(back)
    dup = ApiLibFieldMap.query.filter_by(
        product=row['product'], endpoint=row['endpoint'],
        from_field=row['from_field'], to_field=row['to_field'],
        from_version=row['from_version'], to_version=row['to_version'],
        retired_at=None).first()
    if dup is not None:
        flash(_('That mapping is already in force (#%(id)s).', id=dup.id), 'warning')
        return redirect(back)
    m = ApiLibFieldMap(created_by=_username(), created_at=datetime.utcnow(), **row)
    db.session.add(m)
    db.session.commit()
    log_action('apilib.field_map_add',
               target='%s %s: %s -> %s' % (row['product'], row['endpoint'],
                                           row['from_field'], row['to_field']),
               extra={'id': m.id, **row})
    # The mapping is kept either way; the library only honours it where both
    # builds were measured, so say when that is not the case yet.
    miss = [f for f in (row['from_field'], row['to_field'])
            if not _history(row['product'], row['endpoint'], f)['known']]
    if miss:
        flash(_('Mapping saved. The library has no evidence yet for %(f)s on '
                '%(ep)s — it applies once a build that serves it is measured.',
                f=', '.join(miss), ep=row['endpoint']), 'warning')
    else:
        flash(_('Mapping saved: %(a)s is now read as a rename to %(b)s.',
                a=row['from_field'], b=row['to_field']), 'success')
    return redirect(back)


@bp.route('/<int:map_id>/retire', methods=['POST'])
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def retire(map_id: int):
    """Retire, never delete. JSON in/out — the list page calls it with fetch."""
    m = db.session.get(ApiLibFieldMap, map_id)
    if m is None:
        return jsonify(ok=False, error=_('No such mapping.')), 404
    if m.retired_at is not None:
        return jsonify(ok=False, error=_('Already retired.')), 409
    m.retired_at = datetime.utcnow()
    m.retired_by = _username()
    db.session.commit()
    log_action('apilib.field_map_retire',
               target='%s %s: %s -> %s' % (m.product, m.endpoint, m.from_field,
                                           m.to_field),
               extra={'id': m.id})
    return jsonify(ok=True, id=m.id, retired_by=m.retired_by,
                   retired_at=m.retired_at.isoformat(timespec='seconds'))
