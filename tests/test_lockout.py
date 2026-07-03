"""Per-account lockout: N failed logins lock the account for a window,
independent of source IP (complements the per-IP rate limit)."""
from __future__ import annotations

from datetime import datetime, timedelta

from tests.conftest import make_user


def _post_login(client, username, password):
    return client.post("/auth/login", data={"username": username,
                                            "password": password},
                       follow_redirects=True)


def test_lockout_after_threshold_and_expiry(app, client):
    from app.auth.routes import LOCKOUT_THRESHOLD
    from app.extensions import db
    from app.models import User

    uid = make_user(app, "victim", role="readonly")

    for _ in range(LOCKOUT_THRESHOLD):
        _post_login(client, "victim", "wrong-password")

    with app.app_context():
        u = db.session.get(User, uid)
        assert u.locked_until is not None and u.locked_until > datetime.utcnow()

    # Correct password is refused while locked.
    resp = _post_login(client, "victim", "pw")
    assert b"temporarily locked" in resp.data

    # Once the window passes, the correct password works and state resets.
    with app.app_context():
        u = db.session.get(User, uid)
        u.locked_until = datetime.utcnow() - timedelta(seconds=1)
        db.session.commit()
    resp = _post_login(client, "victim", "pw")
    assert b"temporarily locked" not in resp.data
    with app.app_context():
        u = db.session.get(User, uid)
        assert u.failed_logins == 0 and u.locked_until is None


def test_failure_counter_resets_on_success(app, client):
    from app.extensions import db
    from app.models import User

    uid = make_user(app, "bouncer", role="readonly")
    for _ in range(3):
        _post_login(client, "bouncer", "nope")
    with app.app_context():
        assert db.session.get(User, uid).failed_logins == 3

    _post_login(client, "bouncer", "pw")
    with app.app_context():
        assert db.session.get(User, uid).failed_logins == 0
