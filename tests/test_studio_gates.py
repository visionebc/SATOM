"""Studio (Plugin Studio, Lua Studio, Python Console) gates and menus.

Documentation Center audit, 2026-10-03. The studio pages are gated on their
own granular ``studio.*`` keys; these guards keep the previews and the menus on
the same keys, so a custom profile that holds a key reaches the page and one
that does not never sees a link that answers 403.
"""
from __future__ import annotations

from tests.conftest import admin_user_id, login, make_user


def _profile_user(app, name, keys):
    from app.extensions import db
    from app.models import Profile, User
    with app.app_context():
        p = Profile(name="p-" + name, is_system=False)
        p.permission_set = set(keys)
        db.session.add(p)
        db.session.commit()
        u = User(username=name, role="readonly", is_active=True, profile_id=p.id)
        u.set_password("pw")
        db.session.add(u)
        db.session.commit()
        return u.id


def _draft_plugin(app, slug="draft-view"):
    from app.extensions import db
    from app.models import Plugin
    with app.app_context():
        p = Plugin(name="Draft view", slug=slug, status="draft",
                   jinja="<p>hello</p>", product="fortiweb")
        db.session.add(p)
        db.session.commit()
        return p.id


# --------------------------------------------------------------------------- #
#  Plugin drafts follow studio.plugin_studio, not is_admin_capable            #
# --------------------------------------------------------------------------- #
def test_a_plugin_author_who_is_not_admin_capable_can_preview_drafts(app, client):
    pid = _draft_plugin(app)
    uid = _profile_user(app, "author", {"studio.plugin_studio", "monitoring.view"})
    with app.app_context():
        from app.models import User
        assert not User.query.get(uid).is_admin_capable
    login(client, uid)
    assert client.get(f"/plugins/{pid}/frame?_adom=fortiweb").status_code == 200
    assert client.get(f"/plugins/{pid}/frame?_adom=fortiweb&live=x").status_code == 200
    assert client.get("/plugins/view/draft-view?_adom=fortiweb").status_code == 200


def test_a_viewer_without_the_studio_key_cannot_see_drafts(app, client):
    pid = _draft_plugin(app)
    uid = make_user(app, username="ro-plg", role="readonly")
    login(client, uid)
    assert client.get(f"/plugins/{pid}/frame?_adom=fortiweb").status_code == 403
    assert client.get("/plugins/view/draft-view?_adom=fortiweb").status_code == 403


# --------------------------------------------------------------------------- #
#  Lua deploy: a real push with no target is an error, never "deployed"      #
# --------------------------------------------------------------------------- #
def _lua(app, appliance_id=None):
    from app.extensions import db
    from app.models import LuaScript
    with app.app_context():
        s = LuaScript(name="probe", target="fortiweb", product="fortiweb",
                      code="return true", appliance_id=appliance_id)
        db.session.add(s)
        db.session.commit()
        return s.id


def test_a_real_lua_deploy_without_an_appliance_is_refused(app, client):
    sid = _lua(app)
    login(client, admin_user_id(app))
    r = client.post(f"/lua/{sid}/deploy?_adom=fortiweb", data={"confirm": "yes"})
    assert r.status_code == 400
    assert "target appliance" in r.get_json()["error"]
    from app.models import LuaScript
    with app.app_context():
        s = LuaScript.query.get(sid)
        assert s.status == "draft" and s.deployed_at is None


def test_the_deploy_service_never_reports_a_targetless_push_as_sent(app):
    from app.models import LuaScript
    from app.services import lua_studio
    s = LuaScript(name="x", target="fortiweb", code="return true")
    res = lua_studio.deploy(s, s.code, None, dry_run=False)
    assert res["dry_run"] is True and "no target appliance" in res["error"]
    assert not lua_studio.deploy(s, s.code, None, dry_run=True).get("error")


# --------------------------------------------------------------------------- #
#  Menus follow the same keys as the pages                                    #
# --------------------------------------------------------------------------- #
def _sidebar(client, url):
    r = client.get(url, follow_redirects=True)
    assert r.status_code == 200
    return r.get_data(as_text=True)


def test_global_studio_menu_reaches_a_key_holder_without_user_manage(app, client):
    uid = _profile_user(app, "luaonly", {"studio.lua_studio", "monitoring.view"})
    login(client, uid, product="global")
    html = _sidebar(client, "/?_adom=global")
    assert 'data-nav-group="Studio"' in html
    assert 'href="/lua/"' in html
    assert 'href="/plugins/"' not in html
    assert 'data-nav-group="Administrator"' not in html
    assert client.get("/lua/?_adom=global").status_code == 200


def test_adom_plugins_group_links_follow_their_own_keys(app, client):
    uid = _profile_user(app, "plgonly", {"studio.plugin_studio", "monitoring.view"})
    login(client, uid, product="fortiweb")
    html = _sidebar(client, "/web/?_adom=fortiweb")
    assert 'href="/plugins/"' in html
    assert 'href="/lua/"' not in html


def test_adc_admin_group_hides_the_python_console_without_its_key(app, client):
    from app import permissions as perm
    keys = set(perm.ADMIN_CAPABILITIES) | {"monitoring.view", "users.manage"}
    uid = _profile_user(app, "admnopyc", keys)
    login(client, uid, product="fortiadc")
    html = _sidebar(client, "/adc/?_adom=fortiadc")
    assert 'data-nav-group="Administrator"' in html, "positive control"
    assert "/database/py-console" not in html
    login(client, admin_user_id(app), product="fortiadc")
    assert "/database/py-console" in _sidebar(client, "/adc/?_adom=fortiadc")


def test_the_lua_editor_shows_a_top_level_deploy_refusal():
    """Refusals ("No target appliance…", "Lint failed…") are answered as a
    top-level ``error``; the editor only read ``result.error`` and showed an
    empty red "Deploy result"."""
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "app" / "templates"
           / "lua_studio" / "editor.html").read_text()
    body = src.split("function doDeploy", 1)[1].split("\n  }\n", 1)[0]
    assert "d.error" in body
