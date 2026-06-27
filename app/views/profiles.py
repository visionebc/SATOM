"""Profiles admin — define granular permission profiles.

Gated by ``profiles.manage``. System profiles (readonly/operator/admin) are
code-managed (re-synced on every boot) and therefore read-only here. Custom
profiles are fully editable, with a capability-based anti-lockout guard that
never lets the fleet lose its last admin-capable user.
"""
from __future__ import annotations

from flask import (Blueprint, render_template, request, flash, redirect,
                   url_for, abort)
from flask_login import login_required, current_user

from .. import permissions as perm
from ..auth.decorators import require_permission
from ..models import db, Profile, User
from ..services import access
from ..services.audit import log_action

bp = Blueprint('profiles', __name__, url_prefix='/profiles')

MANAGE = 'profiles.manage'


def _posted_perms() -> set[str]:
    raw = request.form.getlist('perms')
    return {k for k in raw if perm.is_valid_key(k)}


def _user_count(pid: int) -> int:
    return User.query.filter_by(profile_id=pid).count()


def _sync_roles_for_profile(profile: Profile) -> None:
    """Keep the legacy ``role`` column on a profile's users in step with the
    profile's effective capabilities, so role badges/counters stay honest."""
    label = profile.role_label
    for u in User.query.filter_by(profile_id=profile.id).all():
        u.role = label


@bp.route('/')
@login_required
@require_permission(MANAGE)
def index():
    profiles = Profile.query.order_by(Profile.is_system.desc(), Profile.name).all()
    counts = {p.id: _user_count(p.id) for p in profiles}
    return render_template(
        'profiles/index.html',
        profiles=profiles, counts=counts,
        areas=perm.AREAS, catalog=perm.GRANULAR_PERMISSIONS,
    )


@bp.route('/', methods=['POST'])
@login_required
@require_permission(MANAGE)
def create():
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    if not name:
        flash('Profile name is required.', 'danger')
        return redirect(url_for('profiles.index'))
    if Profile.query.filter(db.func.lower(Profile.name) == name.lower()).first():
        flash(f'A profile named “{name}” already exists.', 'danger')
        return redirect(url_for('profiles.index'))

    p = Profile(name=name, description=description, is_system=False)
    p.permission_set = _posted_perms()  # may be empty — matrix is filled on the edit page
    db.session.add(p)
    db.session.commit()
    log_action('profile.create', target=name,
               extra={'perms': sorted(p.permission_set)})
    flash(f'Profile “{name}” created — set its permissions below.', 'success')
    return redirect(url_for('profiles.edit', id=p.id))


@bp.route('/<int:id>/edit')
@login_required
@require_permission(MANAGE)
def edit(id):
    p = db.session.get(Profile, id) or abort(404)
    return render_template(
        'profiles/edit.html',
        profile=p, areas=perm.AREAS, catalog=perm.GRANULAR_PERMISSIONS,
        selected=p.permission_set, user_count=_user_count(p.id),
    )


@bp.route('/<int:id>/edit', methods=['POST'])
@login_required
@require_permission(MANAGE)
def edit_save(id):
    p = db.session.get(Profile, id) or abort(404)
    if p.is_system:
        flash('System profiles are managed automatically and cannot be edited.', 'warning')
        return redirect(url_for('profiles.edit', id=id))

    name = request.form.get('name', p.name).strip() or p.name
    # name uniqueness (excluding self)
    clash = Profile.query.filter(
        db.func.lower(Profile.name) == name.lower(), Profile.id != p.id
    ).first()
    if clash:
        flash(f'A profile named “{name}” already exists.', 'danger')
        return redirect(url_for('profiles.edit', id=id))

    new_perms = _posted_perms()
    p.name = name
    p.description = request.form.get('description', p.description or '').strip()
    p.permission_set = new_perms
    _sync_roles_for_profile(p)

    # Anti-lockout: simulate, then refuse if no admin-capable user remains.
    db.session.flush()
    if access.active_admin_count() == 0:
        db.session.rollback()
        flash('Refused: that change would remove the last administrator '
              '(no remaining user could manage users AND profiles).', 'danger')
        return redirect(url_for('profiles.edit', id=id))

    db.session.commit()
    log_action('profile.update', target=p.name,
               extra={'perms': sorted(new_perms)})
    flash(f'Profile “{p.name}” updated.', 'success')
    return redirect(url_for('profiles.edit', id=id))


@bp.route('/<int:id>/clone', methods=['POST'])
@login_required
@require_permission(MANAGE)
def clone(id):
    src = db.session.get(Profile, id) or abort(404)
    base = f'{src.name} copy'
    name = base
    n = 2
    while Profile.query.filter(db.func.lower(Profile.name) == name.lower()).first():
        name = f'{base} {n}'
        n += 1
    p = Profile(name=name, description=src.description, is_system=False)
    p.permission_set = src.permission_set
    db.session.add(p)
    db.session.commit()
    log_action('profile.clone', target=name, extra={'source': src.name})
    flash(f'Cloned “{src.name}” → “{name}”.', 'success')
    return redirect(url_for('profiles.edit', id=p.id))


@bp.route('/<int:id>/delete', methods=['POST'])
@login_required
@require_permission(MANAGE)
def delete(id):
    p = db.session.get(Profile, id) or abort(404)
    if p.is_system:
        flash('System profiles cannot be deleted.', 'danger')
        return redirect(url_for('profiles.index'))
    assigned = _user_count(p.id)
    if assigned > 0:
        flash(f'“{p.name}” is assigned to {assigned} user(s). Reassign them first.', 'danger')
        return redirect(url_for('profiles.index'))

    name = p.name
    db.session.delete(p)
    db.session.flush()
    # Safety net (an unassigned profile can't be holding the last admin, but
    # never let a delete orphan administration).
    if access.active_admin_count() == 0:
        db.session.rollback()
        flash('Refused: deleting that profile would remove the last administrator.', 'danger')
        return redirect(url_for('profiles.index'))
    db.session.commit()
    log_action('profile.delete', target=name)
    flash(f'Profile “{name}” deleted.', 'success')
    return redirect(url_for('profiles.index'))
