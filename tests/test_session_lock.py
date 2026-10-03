"""Idle session lock (Settings -> General -> Session Lock).

Documentation Center audit, 2026-10-03 (GS-01, AD-63): the setting was saved
but never enforced. It is now an idle timeout; background polls do not extend
it, Bearer-token requests are not touched.
"""
from __future__ import annotations

import logging
import time

from conftest import admin_user_id, login

LAST = "_last_seen"


def _set_last_seen(client, ago_seconds):
    with client.session_transaction() as s:
        s[LAST] = int(time.time()) - ago_seconds


def _last_seen(client):
    with client.session_transaction() as s:
        return s.get(LAST)


def _rows(app, action):
    from app.models import AuditLog
    with app.app_context():
        return AuditLog.query.filter_by(action=action).count()


def test_an_active_session_is_stamped_and_stays_signed_in(app, client):
    login(client, admin_user_id(app))
    assert client.get("/settings/").status_code == 200
    assert isinstance(_last_seen(client), int)
    _set_last_seen(client, 30 * 60)          # 30 min idle < 60 min default
    assert client.get("/settings/").status_code == 200
    assert time.time() - _last_seen(client) < 5, "a page load must refresh the stamp"


def test_an_idle_session_is_signed_out_with_a_message(app, client):
    login(client, admin_user_id(app))
    client.get("/settings/")
    _set_last_seen(client, 61 * 60)
    r = client.get("/settings/")
    assert r.status_code == 302 and "/auth/login" in r.headers["Location"]
    html = client.get("/auth/login").get_data(as_text=True)
    assert "locked after 60 minutes of inactivity" in html
    assert client.get("/settings/").status_code == 302, "still signed in after the lock"
    assert _rows(app, "session.idle_lock") == 1


def test_a_script_caller_gets_json_401(app, client):
    login(client, admin_user_id(app))
    client.get("/settings/")
    _set_last_seen(client, 61 * 60)
    r = client.get("/notifications/unread", headers={"Accept": "application/json"})
    assert r.status_code == 401
    assert r.get_json()["session_locked"] is True


def test_background_polls_do_not_extend_the_session(app, client):
    login(client, admin_user_id(app))
    client.get("/settings/")
    _set_last_seen(client, 50 * 60)
    before = _last_seen(client)
    assert client.get("/notifications/unread").status_code == 200       # bell
    assert client.get("/jobs/?active=1").status_code == 200              # job dock
    assert client.get("/settings/", headers={"Sec-Fetch-Mode": "cors",
                                             "Sec-Fetch-Dest": "empty"}).status_code == 200
    assert client.get("/settings/", headers={"X-Requested-With": "XMLHttpRequest"}).status_code == 200
    assert _last_seen(client) == before, "a background poll kept the session alive"
    # A Turbo Drive visit is a user navigation and does count.
    client.get("/settings/", headers={"Sec-Fetch-Mode": "cors",
                                      "X-Turbo-Request-Id": "abc"})
    assert _last_seen(client) > before


def test_the_configured_timeout_is_the_one_enforced(app, client):
    login(client, admin_user_id(app))
    r = client.post("/settings/general", data={"app_name": "SATOM", "session_timeout": "5",
                                               "log_levels": ["INFO", "WARNING", "ERROR"],
                                               "log_format": "detailed"})
    assert r.status_code == 302
    _set_last_seen(client, 6 * 60)
    r = client.get("/settings/")
    assert r.status_code == 302 and "/auth/login" in r.headers["Location"]


def test_bearer_requests_are_not_touched(app, client):
    login(client, admin_user_id(app))
    client.get("/settings/")
    _set_last_seen(client, 61 * 60)
    client.get("/api/v1/appliances", headers={"Authorization": "Bearer fmk_x_y"})
    assert _rows(app, "session.idle_lock") == 0


def test_general_tab_no_longer_offers_the_dead_fields(app, client):
    login(client, admin_user_id(app))
    html = client.get("/settings/").get_data(as_text=True)
    assert 'name="session_timeout"' in html
    assert 'name="poll_interval"' not in html
    assert 'name="show_raw_config"' not in html


def _file_handler():
    from app.errors import logger
    hs = [h for h in logger.handlers if getattr(h, "_fortinet_file", False)]
    if hs:
        return hs[0], None
    h = logging.StreamHandler()
    h._fortinet_file = True
    logger.addHandler(h)
    return h, h


def test_log_levels_and_format_are_applied_on_save(app, client):
    from app.errors import _JsonFormatter, logger
    h, added = _file_handler()
    try:
        login(client, admin_user_id(app))
        client.post("/settings/general", data={"app_name": "SATOM", "session_timeout": "60",
                                               "log_levels": ["WARNING", "ERROR"],
                                               "log_format": "json"})
        assert isinstance(h.formatter, _JsonFormatter)
        info = logging.LogRecord("app.x", logging.INFO, __file__, 1, "hello", None, None)
        warn = logging.LogRecord("app.x", logging.WARNING, __file__, 1, "hello", None, None)
        assert not h.filter(info) and h.filter(warn)
        client.post("/settings/general", data={"app_name": "SATOM", "session_timeout": "60",
                                               "log_levels": ["INFO", "WARNING", "ERROR"],
                                               "log_format": "detailed"})
        assert not isinstance(h.formatter, _JsonFormatter)
        assert "%(name)s" in h.formatter._fmt
        assert h.filter(info)
    finally:
        if added:
            logger.removeHandler(added)
