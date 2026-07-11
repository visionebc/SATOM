"""View-layer contract for the sandboxed Python console (views.database).

Complements tests/test_py_console.py (the sandbox itself). Here we exercise the
HTTP surface: the page renders, an authenticated admin can run a script, the
requested dataset keys cannot widen access, secrets stay invisible even through
the web endpoint, and an anonymous client cannot execute code.

The run-invoking tests need bubblewrap; skipped otherwise.
"""
from __future__ import annotations

import shutil
import pytest

pytestmark = pytest.mark.skipif(
    shutil.which("bwrap") is None, reason="bubblewrap not installed")


def _login(client, uid, product="global"):
    with client.session_transaction() as s:
        s["_user_id"] = str(uid)
        s["_fresh"] = True
        s["product"] = product


def _admin_id(app):
    from app.models import User
    with app.app_context():
        return User.query.filter_by(username="admin").first().id


def test_page_renders(client, app):
    _login(client, _admin_id(app))
    r = client.get("/database/py-console")
    assert r.status_code == 200
    assert b"Python Console" in r.data


def test_run_executes(client, app):
    _login(client, _admin_id(app))
    r = client.post("/database/py-console/run",
                    json={"source": "print('X', 1 + 1)", "datasets": []})
    assert r.status_code == 200
    j = r.get_json()
    assert j["ok"] is True
    assert "X 2" in j["stdout"]


def test_requested_datasets_cannot_widen_access(client, app):
    _login(client, _admin_id(app))
    r = client.post("/database/py-console/run",
                    json={"source": "print(sorted(data.keys()))",
                          "datasets": ["fleet_appliances", "__nope__", "fleet_appliances"]})
    j = r.get_json()
    # unknown key dropped, duplicate deduped
    assert j["datasets"] == ["fleet_appliances"]


def test_secrets_isolated_through_endpoint(client, app):
    _login(client, _admin_id(app))
    r = client.post("/database/py-console/run",
                    json={"source": "import os\n"
                                    "print('ENV', os.path.exists('/opt/fortinet-manager/.env'))\n"
                                    "print('FK', os.environ.get('FERNET_KEY'))",
                          "datasets": []})
    out = r.get_json()["stdout"]
    assert "ENV False" in out
    assert "FK None" in out


def test_anonymous_cannot_run(client):
    r = client.post("/database/py-console/run", json={"source": "print(1)"})
    assert r.status_code != 200
