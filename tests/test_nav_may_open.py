"""The sidebar never offers a page its route refuses.

Sidebar entries ask ``may_open(endpoint)``, which reads the stamp the route's
``require_permission`` leaves -- the same source the concept map uses. Found
by a production smoke on 2026-10-03: a profile with no keys was shown 137
entries and 16 of them answered 403 (the routes had been gated, the links had
not); a readonly user saw Log Collection and got 403 too.
"""
from __future__ import annotations

import re

import pytest

from tests.conftest import login, make_user
from tests.test_access_gates_audit import _zero_key_user

ADOMS = ("/", "/web/", "/adc/", "/faz/", "/fac/")
_SKIP = re.compile(r"logout|/delete|/export|download|\.csv|/stream|/events|/run\b|/start|/stop|/apply|/sync")


def _seed_devices(app):
    from app.extensions import db
    from app.models import Appliance
    with app.app_context():
        for n, k in (("fw-nav", "fortiweb"), ("adc-nav", "fortiadc"),
                     ("faz-nav", "fortianalyzer"), ("fac-nav", "fortiauthenticator")):
            db.session.add(Appliance(name=n, kind=k, host="192.0.2.9", port=443,
                                     username="u", password_enc="x", verify_ssl=False))
        db.session.commit()


def _sidebar_links(client):
    seen, rendered = set(), 0
    for adom in ADOMS:
        r = client.get(adom, follow_redirects=True)
        if r.status_code != 200:
            continue
        html = r.get_data(as_text=True)
        if 'data-nav-group=' not in html:
            continue
        rendered += 1
        nav = html.split('class="fw-sidebar', 1)[-1]
        for href in re.findall(r'href="(/[^"#?]*)', nav):
            if not href.startswith("/static") and not _SKIP.search(href):
                seen.add(href)
    return seen, rendered


@pytest.mark.parametrize("who", ["readonly", "operator", "zero-keys"])
def test_no_sidebar_link_answers_403(app, client, who):
    _seed_devices(app)
    if who == "zero-keys":
        login(client, _zero_key_user(app))
    else:
        login(client, make_user(app, username="nav-" + who, role=who))
    links, rendered = _sidebar_links(client)
    assert rendered, "no page with a sidebar rendered -- the scan saw nothing"
    refused = sorted(h for h in links if client.get(h).status_code == 403)
    assert not refused, f"{who}: the sidebar offers pages that answer 403: {refused}"


def test_the_scan_sees_links_for_a_readonly_user(app, client):
    """Anti-vacuity: the parametrised test passes on an empty sidebar too."""
    _seed_devices(app)
    login(client, make_user(app, username="nav-census", role="readonly"))
    links, _ = _sidebar_links(client)
    assert len(links) > 20, links
    assert "/monitoring/" in links or any(l.startswith("/monitoring") for l in links)


def test_may_open_reads_the_route_stamp(app):
    from flask_login import login_user
    from app.models import User
    with app.app_context():
        uid = make_user(app, username="nav-ro", role="readonly")
        with app.test_request_context("/"):
            login_user(User.query.get(uid))
            may_open = app.jinja_env.globals["may_open"]
            assert may_open("monitoring.index") is True      # readonly holds view
            assert may_open("users.index") is False          # users.manage / users.view
            assert may_open("no.such.endpoint") is True      # unknown: not hidden
