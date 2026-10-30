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
from ..services import product_scope
from ..services.audit import log_action

bp = Blueprint('profiles', __name__, url_prefix='/profiles')

MANAGE = 'profiles.manage'


def _posted_perms() -> set[str]:
    raw = request.form.getlist('perms')
    return {k for k in raw if perm.is_valid_key(k)}


def _beyond_actor(keys: set[str]) -> set[str]:
    """The keys in ``keys`` the signed-in user does not hold. A
    ``profiles.manage`` holder composes profiles out of what they have; they
    cannot mint a key (``users.manage`` above all) they were never given."""
    return set(keys) - current_user.effective_permissions


def _posted_adoms() -> frozenset[str] | None:
    """The ADOMs ticked on the form; ``None`` (every ADOM) when none is."""
    known = {k for k, _ in product_scope.device_products()}
    keys = {k.strip().lower() for k in request.form.getlist('adoms')}
    keys &= known
    return frozenset(keys) if keys else None


def _adoms_beyond_actor(adoms: frozenset[str] | None) -> bool:
    """True when a profile confined to ``adoms`` reaches an ADOM the signed-in
    user cannot. An unconfined actor may set anything; a confined one composes
    only out of its own ADOMs — and can never mint an UNconfined profile,
    which would be every ADOM one assignment away."""
    mine = product_scope.adoms_of(current_user)
    if mine is None:
        return False
    return adoms is None or not set(adoms) <= mine


def _adom_names() -> dict[str, str]:
    return dict(product_scope.device_products())


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
        adom_names=_adom_names(),
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

    posted = _posted_perms()
    if _beyond_actor(posted):
        flash('Refused: you cannot grant permissions you do not hold yourself '
              f'({", ".join(sorted(_beyond_actor(posted)))}).', 'danger')
        return redirect(url_for('profiles.index'))
    # A confined creator's new profile starts confined to the creator's own
    # ADOMs; an unconfined one starts unconfined, as before.
    adoms = _posted_adoms() or product_scope.adoms_of(current_user)
    if _adoms_beyond_actor(adoms):
        flash('Refused: you cannot grant ADOMs you do not have yourself.', 'danger')
        return redirect(url_for('profiles.index'))
    kind = request.form.get('kind', 'console')
    p = Profile(name=name, description=description, is_system=False,
                kind=kind if kind in Profile.KINDS else 'console')
    p.permission_set = posted  # may be empty — matrix is filled on the edit page
    p.adom_set = adoms
    db.session.add(p)
    db.session.commit()
    log_action('profile.create', target=name,
               extra={'perms': sorted(p.permission_set), 'kind': p.kind})
    flash(f'Profile “{name}” created — set its apps access in Access > App sign-in.'
          if p.is_apps_only else f'Profile “{name}” created — set its permissions below.',
          'success')
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
        adom_choices=product_scope.device_products(),
    )


@bp.route('/<int:id>/edit', methods=['POST'])
@login_required
@require_permission(MANAGE)
def edit_save(id):
    p = db.session.get(Profile, id) or abort(404)
    if p.is_system:
        flash('System profiles are managed automatically and cannot be edited.', 'warning')
        return redirect(url_for('profiles.edit', id=id))
    if current_user.profile_id == p.id:
        flash('Refused: you cannot edit the profile you are assigned to. '
              'Ask another administrator.', 'danger')
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
    added_beyond = _beyond_actor(new_perms - p.permission_set)
    if added_beyond:
        flash('Refused: you cannot grant permissions you do not hold yourself '
              f'({", ".join(sorted(added_beyond))}).', 'danger')
        return redirect(url_for('profiles.edit', id=id))
    new_adoms = _posted_adoms()
    if _adoms_beyond_actor(new_adoms):
        flash('Refused: you cannot grant ADOMs you do not have yourself.', 'danger')
        return redirect(url_for('profiles.edit', id=id))
    old_adoms = p.adom_set
    old_kind = p.kind or 'console'
    kind = request.form.get('kind', old_kind)
    p.name = name
    p.description = request.form.get('description', p.description or '').strip()
    # The type first: the permission setter writes nothing for Apps only.
    p.kind = kind if kind in Profile.KINDS else old_kind
    p.permission_set = new_perms
    p.adom_set = new_adoms
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
               extra={'perms': sorted(p.permission_set), 'kind': p.kind,
                      'kind_before': old_kind,
                      'adoms': sorted(new_adoms) if new_adoms else 'all',
                      'adoms_before': sorted(old_adoms) if old_adoms else 'all'})
    flash(f'Profile “{p.name}” updated.', 'success')
    return redirect(url_for('profiles.edit', id=id))


@bp.route('/<int:id>/clone', methods=['POST'])
@login_required
@require_permission(MANAGE)
def clone(id):
    src = db.session.get(Profile, id) or abort(404)
    if _adoms_beyond_actor(src.adom_set):
        flash('Refused: that profile reaches ADOMs you do not have yourself.', 'danger')
        return redirect(url_for('profiles.index'))
    base = f'{src.name} copy'
    name = base
    n = 2
    while Profile.query.filter(db.func.lower(Profile.name) == name.lower()).first():
        name = f'{base} {n}'
        n += 1
    p = Profile(name=name, description=src.description, is_system=False,
                kind=src.kind or "console")
    p.permission_set = src.permission_set
    p.adom_set = src.adom_set
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
