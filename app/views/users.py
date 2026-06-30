"""User management — create/edit users and assign permission PROFILES.

Authorization model: a user's capabilities come from their assigned ``Profile``
(``role`` is kept synced only for display/back-compat). Anti-lockout is
capability-based (``services.access``): the app never lets the number of ACTIVE
admin-capable users — those who can manage BOTH users and profiles — reach zero.
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for, abort
from flask_login import login_required, current_user

from .. import permissions as perm
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission, Profile, User
from ..services import access
from ..services.audit import log_action

bp = Blueprint('users', __name__, url_prefix='/users')

# Legacy roles still accepted on the create/edit forms for back-compat.
VALID_ROLES = {'readonly', 'operator', 'admin'}


def _get_user_model():
    return User


def _profiles_for_picker():
    return Profile.query.order_by(Profile.is_system.desc(), Profile.name).all()


def _system_profile(name: str) -> Profile | None:
    return Profile.query.filter_by(name=name, is_system=True).first()


def _assign_profile(user: User, profile: Profile) -> None:
    """Point a user at a profile and keep the legacy role column in sync.

    Assigns the RELATIONSHIP (not just the FK) so ``user.is_admin_capable``
    reflects the new profile immediately — the anti-lockout simulate depends on
    that being current before flush."""
    user.profile = profile
    user.role = profile.role_label


def _is_last_admin(user: User) -> bool:
    """True when ``user`` is the only currently-enabled admin-capable user."""
    return (
        user.is_active
        and user.is_admin_capable
        and access.active_admin_count(exclude_id=user.id) == 0
    )


def _commit_unless_orphans_admins(action_label: str, target: str) -> bool:
    """Flush the pending change; commit if at least one admin-capable user
    remains, otherwise roll back. Returns True on commit."""
    db.session.flush()
    if access.active_admin_count() == 0:
        db.session.rollback()
        flash('Refused: that change would remove the last administrator '
              '(no remaining user could manage users AND profiles).', 'danger')
        return False
    db.session.commit()
    log_action(action_label, target=target)
    return True


@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    User = _get_user_model()
    users = User.query.order_by(User.username).all()
    return render_template('users/index.html', users=users,
                           profiles=_profiles_for_picker())


@bp.route('/', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def create():
    User = _get_user_model()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    confirm = request.form.get('confirm_password', '')
    profile_id = (request.form.get('profile_id') or '').strip()
    role = request.form.get('role', 'readonly').strip()

    if not username or not password:
        flash('Username and password are required.', 'danger')
        return redirect(url_for('users.index'))
    if confirm and confirm != password:
        flash('Passwords do not match.', 'danger')
        return redirect(url_for('users.index'))
    if User.query.filter_by(username=username).first():
        flash(f'Username {username} already exists.', 'danger')
        return redirect(url_for('users.index'))

    # Profile assignment takes precedence; fall back to the legacy role picker.
    profile = None
    if profile_id:
        profile = db.session.get(Profile, int(profile_id)) if profile_id.isdigit() else None
        if profile is None:
            flash('Selected profile no longer exists.', 'danger')
            return redirect(url_for('users.index'))
    else:
        if role not in VALID_ROLES:
            flash(f'Invalid role: {role}.', 'danger')
            return redirect(url_for('users.index'))
        profile = _system_profile(perm.role_to_profile_name(role))

    user = User(username=username)
    if profile is not None:
        _assign_profile(user, profile)
    else:
        user.role = role  # extreme fallback (profiles not seeded) — keeps boot-safe
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    log_action('user.create', target=username,
               extra={'profile': profile.name if profile else None, 'role': user.role})
    flash(f'User {username} created.', 'success')
    return redirect(url_for('users.index'))


@bp.route('/<int:id>/edit')
@login_required
@require_permission(Permission.USER_MANAGE)
def edit(id):
    User = _get_user_model()
    user = User.query.get_or_404(id)
    return render_template('users/edit.html', user=user,
                           profiles=_profiles_for_picker())


@bp.route('/<int:id>/edit', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def edit_save(id):
    User = _get_user_model()
    user = User.query.get_or_404(id)
    user.username = request.form.get('username', user.username).strip()

    profile_id = (request.form.get('profile_id') or '').strip()
    if profile_id and profile_id.isdigit():
        profile = db.session.get(Profile, int(profile_id))
        if profile is not None:
            _assign_profile(user, profile)
    else:
        role = request.form.get('role', user.role).strip()
        if role in VALID_ROLES:
            sp = _system_profile(perm.role_to_profile_name(role))
            if sp is not None:
                _assign_profile(user, sp)
            else:
                user.role = role

    if not _commit_unless_orphans_admins('user.update', user.username):
        return redirect(url_for('users.index'))
    flash(f'User {user.username} updated.', 'success')
    return redirect(url_for('users.index'))


@bp.route('/<int:id>/profile', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def set_profile(id):
    User = _get_user_model()
    user = User.query.get_or_404(id)
    profile_id = (request.form.get('profile_id') or '').strip()
    if not profile_id.isdigit():
        flash('No profile selected.', 'danger')
        return redirect(url_for('users.index'))
    profile = db.session.get(Profile, int(profile_id))
    if profile is None:
        flash('Selected profile no longer exists.', 'danger')
        return redirect(url_for('users.index'))

    old = user.profile.name if user.profile else user.role
    _assign_profile(user, profile)
    if not _commit_unless_orphans_admins('user.profile.set', user.username):
        return redirect(url_for('users.index'))
    log_action('user.profile.set', target=user.username,
               extra={'from': old, 'to': profile.name})
    flash(f'{user.username} is now on profile “{profile.name}”.', 'success')
    return redirect(url_for('users.index'))


@bp.route('/<int:id>/delete', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def delete(id):
    User = _get_user_model()
    user = User.query.get_or_404(id)
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('users.index'))
    if _is_last_admin(user):
        flash('Cannot delete the last remaining administrator.', 'danger')
        return redirect(url_for('users.index'))
    username = user.username
    db.session.delete(user)
    db.session.commit()
    log_action('user.delete', target=username)
    flash(f'User {username} deleted.', 'success')
    return redirect(url_for('users.index'))


@bp.route('/<int:id>/reset-password', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def reset_password(id):
    User = _get_user_model()
    user = User.query.get_or_404(id)
    new_password = request.form.get('new_password', '')
    if not new_password:
        flash('New password is required.', 'danger')
        return redirect(url_for('users.index'))
    user.set_password(new_password)
    db.session.commit()
    log_action('user.reset_password', target=user.username)
    flash(f'Password for {user.username} reset successfully.', 'success')
    return redirect(url_for('users.index'))


@bp.route('/<int:id>/clear-2fa', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def clear_2fa(id):
    """Admin break-glass: clear a user's TOTP 2FA so they can sign in with just
    their password (e.g. lost authenticator). Local accounts only."""
    User = _get_user_model()
    user = User.query.get_or_404(id)
    user.totp_enabled = False
    user.totp_secret = None
    user.backup_codes = None
    db.session.commit()
    log_action('user.clear_2fa', target=user.username)
    flash(f'Two-factor authentication cleared for {user.username}.', 'success')
    return redirect(url_for('users.index'))


@bp.route('/<int:id>/toggle-active', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def toggle_active(id):
    User = _get_user_model()
    user = User.query.get_or_404(id)
    if user.id == current_user.id:
        flash('You cannot change your own account status.', 'danger')
        return redirect(url_for('users.index'))
    if user.is_active and _is_last_admin(user):
        flash('Cannot disable the last remaining administrator.', 'danger')
        return redirect(url_for('users.index'))
    user.is_active = not user.is_active
    db.session.commit()
    state = 'enabled' if user.is_active else 'disabled'
    log_action('user.enabled.set', target=user.username, extra={'state': state})
    flash(f'User {user.username} {state}.', 'success')
    return redirect(url_for('users.index'))


@bp.route('/<int:id>/role', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def role(id):
    """Legacy role switcher — maps the chosen role to its system profile."""
    User = _get_user_model()
    user = User.query.get_or_404(id)
    new_role = request.form.get('role', '').strip()
    if new_role not in VALID_ROLES:
        flash(f'Invalid role: {new_role}.', 'danger')
        return redirect(url_for('users.index'))
    sp = _system_profile(perm.role_to_profile_name(new_role))
    old_role = user.role
    if sp is not None:
        _assign_profile(user, sp)
    else:
        user.role = new_role
    if not _commit_unless_orphans_admins('user.role.set', user.username):
        return redirect(url_for('users.index'))
    log_action('user.role.set', target=user.username,
               extra={'from': old_role, 'to': user.role})
    flash(f'Role for {user.username} updated to {user.role}.', 'success')
    return redirect(url_for('users.index'))
