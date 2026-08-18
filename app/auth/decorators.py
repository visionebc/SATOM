from functools import wraps
from flask import abort, flash, jsonify, redirect, request, url_for
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


def require_device_scope(f):
    """Gate a view on the row being the one that speaks for the CHASSIS.

    A FortiWeb in ADOM mode is registered one row per ADOM (the auth token
    carries exactly one), but firmware, the config-backup vault and the CLI
    console act on the BOX: one flash partition, one boot image, and an
    ``execute backup`` that emits every ADOM. Offering those verbs on each
    ADOM row offers the same action N times, and "restore adom_dev" would
    quietly have restored the other ADOMs too.

    This is a ROUTE gate, not a hidden button: the templates ask
    ``owns_device_scope`` for the same answer, and a page that only hides a
    link is decorated, not scoped (the lesson of ``visible_appliance_or_404``).

    Redirects a browser to the owning row with a flash that NAMES it — a gate
    that says "no" without saying where the button moved is a dead end. JSON
    callers get 409 instead, because a redirect renders as a parse error.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        from ..models import (chassis_device_row, owns_device_scope,
                              visible_appliance_or_404, can_view_maintenance)
        appliance = visible_appliance_or_404(kwargs.get('id', args[0] if args else None),
                                             current_user)
        if owns_device_scope(appliance):
            return f(*args, **kwargs)
        owner = chassis_device_row(appliance)
        hidden = owner is None or (getattr(owner, 'maintenance', False)
                                   and not can_view_maintenance(current_user))
        adom = (appliance.vdom or '').strip() or 'this ADOM'
        if hidden:
            msg = ('Firmware, the backup vault and the console act on the whole '
                   'appliance, not on %s. The row that carries them is not '
                   'visible to you.' % adom)
        else:
            msg = ('Firmware, the backup vault and the console act on the whole '
                   'appliance, not on %s — they live on %s.' % (adom, owner.name))
        if request.is_json or request.accept_mimetypes.best == 'application/json':
            return jsonify({'ok': False, 'error': msg,
                            'device_appliance_id': None if hidden else owner.id}), 409
        flash(msg, 'warning')
        if hidden:
            return redirect(url_for('appliances.index'))
        return redirect(url_for('appliances.detail', id=owner.id))
    decorated.__device_scope__ = True
    return decorated
