from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, abort
from flask_login import login_required, current_user
from ..auth.decorators import require_permission
from ..models import Appliance, db, Permission
from ..clients.fortiweb import FortiWebClient
from ..clients.fortiadc import FortiADCClient
from ..services.audit import log_action

bp = Blueprint('users', __name__, url_prefix='/users')

# Roles that may be assigned via the UI.
VALID_ROLES = {'readonly', 'operator', 'admin'}
# Usernames that are structurally protected: they cannot be disabled,
# downgraded, or deleted, to prevent an administrative lock-out.
PROTECTED_USERNAMES = {'admin'}


def _get_user_model():
    from ..models import User
    return User


def _active_admin_count(User, exclude_id=None):
    q = User.query.filter_by(role='admin', is_active=True)
    if exclude_id is not None:
        q = q.filter(User.id != exclude_id)
    return q.count()


def _is_last_active_admin(User, user):
    """True when ``user`` is the only currently-enabled administrator."""
    return (
        user.role == 'admin'
        and user.is_active
        and _active_admin_count(User, exclude_id=user.id) == 0
    )


@bp.route('/')
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    User = _get_user_model()
    users = User.query.order_by(User.username).all()
    return render_template('users/index.html', users=users)


@bp.route('/', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def create():
    User = _get_user_model()
    username = request.form.get('username', '').strip()
    role = request.form.get('role', 'readonly').strip()
    password = request.form.get('password', '')
    confirm = request.form.get('confirm_password', '')

    if not username or not password:
        flash('Username and password are required.', 'danger')
        return redirect(url_for('users.index'))

    if confirm and confirm != password:
        flash('Passwords do not match.', 'danger')
        return redirect(url_for('users.index'))

    if role not in VALID_ROLES:
        flash(f'Invalid role: {role}.', 'danger')
        return redirect(url_for('users.index'))

    if User.query.filter_by(username=username).first():
        flash(f'Username {username} already exists.', 'danger')
        return redirect(url_for('users.index'))

    user = User(username=username, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    log_action('user.create', detail=f'Created user {username} with role {role}')
    flash(f'User {username} created.', 'success')
    return redirect(url_for('users.index'))


@bp.route('/<int:id>/edit')
@login_required
@require_permission(Permission.USER_MANAGE)
def edit(id):
    User = _get_user_model()
    user = User.query.get_or_404(id)
    return render_template('users/edit.html', user=user)


@bp.route('/<int:id>/edit', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def edit_save(id):
    User = _get_user_model()
    user = User.query.get_or_404(id)
    user.username = request.form.get('username', user.username).strip()
    user.role = request.form.get('role', user.role).strip()
    db.session.commit()
    log_action('user.update', detail=f'Updated user {user.username}')
    flash(f'User {user.username} updated.', 'success')
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
    if user.username in PROTECTED_USERNAMES:
        flash(f'User {user.username} is protected and cannot be deleted.', 'danger')
        return redirect(url_for('users.index'))
    if _is_last_active_admin(User, user):
        flash('Cannot delete the last remaining administrator.', 'danger')
        return redirect(url_for('users.index'))
    username = user.username
    db.session.delete(user)
    db.session.commit()
    log_action('user.delete', detail=f'Deleted user {username}')
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
    log_action('user.reset_password', detail=f'Reset password for user {user.username}')
    flash(f'Password for {user.username} reset successfully.', 'success')
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
    # Disabling must never lock out the last administrator.
    if user.is_active:
        if user.username in PROTECTED_USERNAMES:
            flash(f'User {user.username} is protected and cannot be disabled.', 'danger')
            return redirect(url_for('users.index'))
        if _is_last_active_admin(User, user):
            flash('Cannot disable the last remaining administrator.', 'danger')
            return redirect(url_for('users.index'))
    user.is_active = not user.is_active
    db.session.commit()
    state = 'enabled' if user.is_active else 'disabled'
    log_action('user.enabled.set', detail=f'{state} user {user.username}')
    flash(f'User {user.username} {state}.', 'success')
    return redirect(url_for('users.index'))


@bp.route('/<int:id>/role', methods=['POST'])
@login_required
@require_permission(Permission.USER_MANAGE)
def role(id):
    User = _get_user_model()
    user = User.query.get_or_404(id)
    new_role = request.form.get('role', '').strip()
    if new_role not in VALID_ROLES:
        flash(f'Invalid role: {new_role}.', 'danger')
        return redirect(url_for('users.index'))
    # Downgrading away from admin must never lock out the last administrator.
    if user.role == 'admin' and new_role != 'admin':
        if user.username in PROTECTED_USERNAMES:
            flash(f'User {user.username} is protected and must remain an administrator.', 'danger')
            return redirect(url_for('users.index'))
        if _is_last_active_admin(User, user):
            flash('Cannot downgrade the last remaining administrator.', 'danger')
            return redirect(url_for('users.index'))
    old_role = user.role
    user.role = new_role
    db.session.commit()
    log_action('user.role.set', detail=f'Changed role of {user.username}: {old_role} -> {new_role}')
    flash(f'Role for {user.username} updated to {new_role}.', 'success')
    return redirect(url_for('users.index'))
