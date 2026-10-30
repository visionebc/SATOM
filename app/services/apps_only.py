"""Apps-only accounts: they reach the Plugin Studio apps they are given and
nothing else.

An account is Apps only when its profile's ``kind`` is ``apps``
(``Profile.is_apps_only``) or, with no profile, when an app's sign-in made it
(``User.is_app_account``). The gate below is DENY BY DEFAULT: an authenticated
Apps-only request is answered only by the endpoints in :data:`ALLOWED` or the
blueprints in :data:`ALLOWED_BLUEPRINTS`; everything else is a 404 -- not a
403, the existence of a console page is not theirs to learn -- and one
``ACCESS_DENY reason=apps_only`` line. The pages that are allowed still check
the app itself (``studio_apps.can_use``); the gate only decides which doors
exist.

Registered right after the idle session lock and before every other gate, so
a confined session never reaches the ADOM / device gates either.
``tests/test_apps_only_gate.py`` walks the whole URL map with such an account:
a route added later is closed to it until someone adds it here on purpose.
"""
from __future__ import annotations

from flask import abort, redirect, request, url_for
from flask_login import current_user

#: Blueprints whose every endpoint checks the app it serves (``can_use``).
ALLOWED_BLUEPRINTS = frozenset({"apps", "apps_portal"})

#: Single endpoints outside those blueprints.
ALLOWED = frozenset({
    "static",
    "auth.logout",
    # the theme's logo / favicon the portal layout shows (public by design)
    "settings.theme_asset",
    # a script app's run page, its run, its database-field choices and the
    # run status -- each one checks the script's app (script_schedules.runnable)
    "scripts.run_page", "scripts.run_now", "scripts.lookup_options", "scripts.run_status",
})

#: Where a confined account asking for the console's front door is sent.
HOME_ENDPOINTS = frozenset({"index", "auth.login", "product.select"})


def is_apps_only(user) -> bool:
    try:
        return bool(user is not None and getattr(user, "is_authenticated", False)
                    and getattr(user, "is_apps_only", False))
    except Exception:  # noqa: BLE001 -- an unreadable profile confines
        return True


def endpoint_allowed(endpoint: str | None) -> bool:
    ep = endpoint or ""
    if ep in ALLOWED:
        return True
    return ep.split(".", 1)[0] in ALLOWED_BLUEPRINTS and "." in ep


def _gate():
    if not is_apps_only(current_user):
        return None
    ep = request.endpoint or ""
    if endpoint_allowed(ep):
        return None
    if ep in HOME_ENDPOINTS:
        return redirect(url_for("apps_portal.home"))
    from flask import current_app
    from ..extensions import real_client_ip
    current_app.logger.warning("ACCESS_DENY reason=apps_only user=%s ip=%s endpoint=%s",
                               getattr(current_user, "username", "?"), real_client_ip(), ep)
    abort(404)


def layout() -> str | None:
    """The page layout for the current account: the portal's own (no console
    sidebar, no console polling) for an Apps-only account, else None."""
    return "apps_portal/layout.html" if is_apps_only(current_user) else None


def init_app(app) -> None:
    app.before_request(_gate)

    @app.context_processor
    def _apps_only_layout():
        try:
            return {"portal_layout": layout()}
        except Exception:  # noqa: BLE001 -- e.g. rendering outside a request
            return {"portal_layout": None}
