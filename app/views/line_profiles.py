"""Line Profiles — declare what a classification line receives.

The page that turns a string match into a declaration. Everything it renders
comes from ``services.line_profiles.line_plan``; this module translates the
form and never re-derives a plan of its own, because a second author of that
answer is the whole defect the feature exists to remove.

Admin-only (USER_MANAGE), mirroring /classification and /segments.
"""
from __future__ import annotations

from flask import (Blueprint, flash, redirect, render_template, request,
                   url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..extensions import db
from ..models import Permission, Template
from ..models_lineprofile import LineProfile
from ..services import line_profiles as lp
from ..services import settings_store as store
from ..services.audit import log_action

bp = Blueprint('line_profiles', __name__, url_prefix='/line-profiles')


def _product() -> str:
    from flask import g, session
    return getattr(g, 'product', None) or session.get('product') or 'fortiweb'


def _wpp_choices(product: str):
    """Approved-or-not, every WPP template in this product, with its status.

    Rejected ones are listed too rather than filtered out: an operator whose
    template was rejected needs to SEE that, not to find their template
    missing from a dropdown with no explanation. The plan is what refuses to
    instantiate it.
    """
    return (Template.query
            .filter(Template.kind == Template.KIND_WEB_PROTECTION,
                    Template.product == product)
            .order_by(Template.name, Template.version.desc())
            .all())


def _view_model(product: str) -> dict:
    return {
        'product': product,
        'lines': lp.lines_overview(product),
        'profiles': {p.line: p.public() for p in
                     LineProfile.query.filter_by(product=product).all()},
        'all_segments': store.segments(),
        'cert_classes': list(store.CERT_CLASSES),
        'wpp_templates': _wpp_choices(product),
        'template_statuses': {t.id: t.status for t in _wpp_choices(product)},
    }


@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    return render_template('lineprofiles/index.html', **_view_model(_product()))


@bp.route('/save', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def save():
    product = _product()
    f = request.form
    line = (f.get('line') or '').strip()
    if not line:
        flash('No line was given.', 'error')
        return redirect(url_for('line_profiles.index'))
    if line not in store.classification('lines'):
        # A profile for a line the catalog does not list would be invisible on
        # this page and unreachable from the wizard — a row that exists and
        # does nothing.
        flash(f'{line!r} is not in the Lines catalog.', 'error')
        return redirect(url_for('line_profiles.index'))

    cert_class = (f.get('cert_class') or '').strip()
    if cert_class and cert_class not in store.CERT_CLASSES:
        flash(f'{cert_class!r} is not a certificate class.', 'error')
        return redirect(url_for('line_profiles.index'))

    wpp_raw = (f.get('wpp_template_id') or '').strip()
    wpp_id = int(wpp_raw) if wpp_raw.isdigit() else None
    if wpp_id is not None:
        tpl = db.session.get(Template, wpp_id)
        if tpl is None or tpl.kind != Template.KIND_WEB_PROTECTION \
                or (tpl.product or '') != product:
            flash('That Web Protection Profile template does not belong to '
                  'this product.', 'error')
            return redirect(url_for('line_profiles.index'))

    known = {(s.get('name') or '').strip() for s in store.segments()}
    picked = [n for n in f.getlist('segments') if n]
    unknown = [n for n in picked if n not in known]
    if unknown:
        # Refused rather than dropped: a form that silently discards a choice
        # teaches the operator the choice was saved.
        flash('Unknown segment(s): ' + ', '.join(sorted(unknown)), 'error')
        return redirect(url_for('line_profiles.index'))

    prof = lp.profile_for(line, product)
    created = prof is None
    if created:
        prof = LineProfile(product=product, line=line,
                           created_by=getattr(current_user, 'username', ''))
        db.session.add(prof)
    prof.set_segments(picked)
    prof.cert_class = cert_class
    prof.wpp_template_id = wpp_id
    prof.ipam_pool = (f.get('ipam_pool') or '').strip()[:128]
    prof.note = (f.get('note') or '').strip()[:2000]
    db.session.commit()
    log_action('line_profile.save',
               detail=f'line={line} product={product} '
                      f'segments={len(picked)} cert={cert_class or "-"} '
                      f'wpp={wpp_id or "-"}')
    flash(f'Line profile for {line!r} {"created" if created else "updated"}.',
          'success')
    return redirect(url_for('line_profiles.index'))


@bp.route('/delete', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def delete():
    product = _product()
    line = (request.form.get('line') or '').strip()
    prof = lp.profile_for(line, product)
    if prof is None:
        flash(f'No profile for {line!r}.', 'error')
        return redirect(url_for('line_profiles.index'))
    db.session.delete(prof)
    db.session.commit()
    log_action('line_profile.delete', detail=f'line={line} product={product}')
    # Said plainly: deleting does not leave the line without an answer, it
    # leaves it with the GUESS, and the operator should know which one they
    # are back on.
    flash(f'Profile for {line!r} deleted — this line falls back to matching '
          'segments by name, which is a guess, not a declaration.', 'success')
    return redirect(url_for('line_profiles.index'))
