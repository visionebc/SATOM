from functools import wraps
from flask import abort, flash, redirect, url_for
from flask_login import current_user
from ..models import ROLE_PERMISSIONS


def require_permission(perm):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))
            if perm not in ROLE_PERMISSIONS.get(current_user.role, set()):
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator


def require_admin(f):
    return require_permission('user_manage')(f)
