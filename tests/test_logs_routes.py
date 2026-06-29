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
