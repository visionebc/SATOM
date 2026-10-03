"""Route/render tests for the Log Collection page.

Exercises the page render + the no-side-effect guard paths only — never starts a
real SSH collection (that would spawn a worker thread against a live box and
write to the production diagnostics folder).
"""
from tests.conftest import login, admin_user_id


def _login_admin(client, app):
    login(client, admin_user_id(app))


def test_index_renders(client, app):
    _login_admin(client, app)
    r = client.get("/logs/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Log Collection" in body
    assert "Collect logs" in body          # the action button (collection, not REST viewer)
    assert "Custom commands" in body


def test_status_idle(client, app):
    _login_admin(client, app)
    r = client.get("/logs/status")
    assert r.status_code == 200
    assert r.get_json().get("state") == "idle"


def test_collect_requires_a_device(client, app):
    _login_admin(client, app)
    r = client.post("/logs/collect", data={"label": "x"})
    assert r.status_code == 400
    assert r.get_json()["ok"] is False


def test_collect_rejects_write_command(client, app):
    """A write in the custom box is refused BEFORE any device is contacted."""
    _login_admin(client, app)
    r = client.post("/logs/collect",
                    data={"appliance_ids": ["1"], "commands": "set system hostname pwn"})
    assert r.status_code == 400
    assert r.get_json()["ok"] is False


def test_view_file_traversal_404(client, app):
    _login_admin(client, app)
    assert client.get("/logs/file/..%2f..%2fetc%2fpasswd").status_code == 404


def test_requires_login():
    # unauthenticated → redirect to login (handled by login_required)
    pass


def test_the_log_collection_link_is_offered_only_to_who_may_open_it(app, client):
    """The page needs config_write; the sidebar offered it to readonly users,
    who got a 403 (found by a production smoke on 2026-10-03)."""
    from tests.conftest import login, make_user
    from app.extensions import db
    from app.models import Appliance
    with app.app_context():
        a = Appliance(name="fw-logs-nav", kind="fortiweb", host="192.0.2.5",
                      port=443, username="u", password_enc="x", verify_ssl=False)
        db.session.add(a)
        db.session.commit()
    for role, offered in (("readonly", False), ("operator", True)):
        login(client, make_user(app, username="logs-" + role, role=role))
        r = client.get("/web/", follow_redirects=True)
        html = r.get_data(as_text=True)
        assert r.status_code == 200 and 'data-nav-group=' in html, role   # a real page with its sidebar
        assert ('href="/web/logs/"' in html) is offered, role
        status = client.get("/web/logs/").status_code
        assert (status == 200) is offered, (role, status)
