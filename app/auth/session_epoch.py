"""Sessions issued before a deploy-clone import do not survive it.

The user loader resolves a session by numeric user id alone. A clone import
replaces the ``users`` table, so a browser that was logged in as user #3 of
the target would, after the import, be user #3 of the SOURCE -- possibly an
administrator. Rotating SECRET_KEY would end those sessions too, but on a pair
the key is shared by both nodes through the join key and is not in the
database, so one node would be left accepting what the other refuses.

The epoch lives in ``app_settings`` instead: replicated with the rows it
protects, rotated in the same transaction that replaces them. Every login is
stamped with the current epoch; a session whose stamp differs is anonymous.
Until the first import there is no epoch and every session is accepted as
before, so this costs nothing to a deploy that never clones.
"""
from __future__ import annotations

import secrets

from flask import session
from flask_login import user_logged_in

KEY = "auth.session_epoch"
SESSION_KEY = "_satom_epoch"


def current() -> str:
    from ..models import AppSetting
    return AppSetting.get(KEY) or ""


def new_value() -> str:
    return secrets.token_hex(16)


def session_is_current() -> bool:
    epoch = current()
    return not epoch or session.get(SESSION_KEY) == epoch


def _stamp(sender, user, **_kw) -> None:  # noqa: ARG001 - signal signature
    epoch = current()
    if epoch:
        session[SESSION_KEY] = epoch
    else:
        session.pop(SESSION_KEY, None)


def init_app(app) -> None:
    user_logged_in.connect(_stamp, app)
