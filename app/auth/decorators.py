from functools import wraps
from flask import abort, redirect, url_for
from flask_login import current_user


def require_permission(perm):
    """Gate a view on *perm*. Resolves the permission through the user's
    assigned profile (falling back to the legacy role) via ``User.can`` — so
    granular keys (e.g. ``appliances.apply``) and legacy coarse keys (e.g.
    ``config_write``) both work."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))
            if not current_user.can(perm):
                abort(403)
            return f(*args, **kwargs)
        # The gate, stated on the wrapper. Read by services.concept_map so the
        # map filters itself to what a user can actually open — a hand-copied
        # permission column drifts, and a drifted map advertises a 403.
        decorated.__required_permission__ = perm
        return decorated
    return decorator


def require_admin(f):
    return require_permission('user_manage')(f)
