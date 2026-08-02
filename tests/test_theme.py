"""UI theme engine — Settings -> Appearance.

The guards here exist because of specific failure modes, not for coverage:

* **Drift.** The token registry is generated from the stylesheet. If someone
  adds a ``--fw-*`` variable without an entry in the generator's metadata, the
  editor silently stops offering it. ``--check`` fails the suite instead.
* **Stored CSS injection.** A token value lands inside a nonced ``<style>``.
  A value carrying ``}`` would close the rule and open a new one, with the app's
  own nonce on it. Every kind is allowlisted, and ``css_for`` re-validates
  because the DB (backup restores, replicas, psql) is not a trust boundary.
* **Lock-out.** An operator can pick two dark colours and lose the page that
  would fix it. Built-ins must stay immutable and deleting the active theme must
  fall back, not leave the console themeless.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

import pytest

from conftest import admin_user_id, login, make_user, profile_id

from app.services import theme_service as ts
from app.services import theme_tokens as tt

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# -- the registry cannot drift from the stylesheet --------------------------
def test_generated_registry_matches_the_stylesheet():
    rc = subprocess.call([sys.executable,
                          os.path.join(REPO, "deploy", "gen_theme_tokens.py"),
                          "--check"],
                         cwd=REPO, stdout=subprocess.DEVNULL)
    assert rc == 0, ("theme_tokens.py is stale - run "
                     "python3 deploy/gen_theme_tokens.py")


def test_registry_covers_exactly_the_css_root_variables():
    css = open(os.path.join(REPO, "app", "static", "css", "fortiweb.css"),
               encoding="utf-8").read()
    body = css[css.index("{", css.index(":root")) + 1: css.index("}", css.index(":root"))]
    in_css = set(re.findall(r"--fw-([a-z0-9-]+)\s*:", body))
    assert in_css == set(tt.TOKENS), (
        "stylesheet and registry disagree: %r" % (in_css ^ set(tt.TOKENS),))


def test_every_token_declares_a_group_kind_and_help():
    for name, meta in tt.TOKENS.items():
        assert meta["group"] in tt.GROUP_ORDER, name
        assert meta["kind"] in ts.VALIDATORS, name
        assert meta["label"] and meta["help"], name
        # A default that its own validator rejects would make the editor
        # unable to round-trip the shipped look.
        assert ts.VALIDATORS[meta["kind"]].match(meta["default"]), name


def test_by_group_returns_every_token_once():
    seen = [n for _g, rows in tt.by_group() for n, _m in rows]
    assert sorted(seen) == sorted(tt.TOKENS)


# -- validation -------------------------------------------------------------
@pytest.mark.parametrize("payload", [
    "#fff; } body{display:none}",
    "#fff</style><script>alert(1)</script>",
    "url(https://evil.example/x.png)",
    "expression(alert(1))",
    "@import 'https://evil.example/x.css'",
    "rgb(1,2,3);}",
    "javascript:alert(1)",
    "red",
    "#fff\n  --fw-accent: red",
])
def test_hostile_values_are_refused(payload):
    clean, errors = ts.validate_tokens({"accent": payload})
    assert errors and clean == {}, payload


@pytest.mark.parametrize("token,payload", [
    # The shadow and font kinds allow a WIDER character class than colours do
    # (a shadow legitimately contains letters, digits, dots and parentheses), so
    # their regex alone would let these through. The shared reject list is what
    # stops them — a mutation removing it must fail here, and originally did not
    # because every hostile case above targeted a colour.
    ("card-shadow", "0 0 0 url(evil)"),
    ("card-shadow", "0 0 0 expression(alert(1))"),
    ("font", "Inter, javascript:alert(1)"),
    ("font", "Inter @import x"),
])
def test_wide_kinds_are_still_protected_by_the_shared_reject_list(token, payload):
    clean, errors = ts.validate_tokens({token: payload})
    assert errors and clean == {}, (token, payload)


@pytest.mark.parametrize("token,value", [
    ("accent", "#4F46E5"),
    ("accent", "#4F46E5CC"),
    ("accent", "#abc"),
    ("accent-light", "rgba(79, 70, 229, 0.10)"),
    ("sidebar-width", "264px"),
    ("radius", "0"),
    ("transition", "0.2s ease"),
    ("transition", "150ms ease-in-out"),
    ("card-shadow", "0 1px 2px rgba(16,32,52,0.06), 0 3px 12px rgba(16,32,52,0.06)"),
    ("font", "'Inter', system-ui, sans-serif"),
])
def test_legitimate_values_pass(token, value):
    clean, errors = ts.validate_tokens({token: value})
    assert not errors, errors
    norm = " ".join(value.split())
    if norm == tt.DEFAULTS[token]:
        # A value equal to the stylesheet default is accepted but deliberately
        # NOT persisted as an override — see the dedicated test below.
        assert token not in clean
    else:
        assert clean.get(token) == norm


def test_unknown_token_is_reported_not_dropped():
    clean, errors = ts.validate_tokens({"not-a-token": "#fff"})
    assert clean == {} and errors and "unknown" in errors[0]


def test_value_equal_to_the_default_is_not_stored():
    clean, errors = ts.validate_tokens({"accent": tt.DEFAULTS["accent"]})
    assert not errors and clean == {}


def test_oversized_value_is_refused():
    clean, errors = ts.validate_tokens({"font": "a" * 300})
    assert errors and clean == {}


# -- CSS emission -----------------------------------------------------------
def test_css_emits_only_overrides_and_nothing_structural():
    css = ts.css_for({"accent": "#4F46E5", "sidebar-bg": "#1E293B"})
    assert css.count("--fw-") == 2
    assert css.count("{") == 1 and css.count("}") == 1
    assert "accent: #4F46E5" in css


def test_css_for_revalidates_a_hostile_stored_row():
    # Simulates a row that arrived from a restore or a hand-edited psql session.
    assert ts.css_for({"accent": "#fff; } html{display:none}"}) == ""


def test_no_overrides_emits_no_style_at_all():
    assert ts.css_for({}) == ""


# -- contrast auditing ------------------------------------------------------
def test_known_contrast_ratios():
    assert abs(ts.contrast_ratio("#FFFFFF", "#000000") - 21.0) < 0.01
    assert abs(ts.contrast_ratio("#FFFFFF", "#FFFFFF") - 1.0) < 0.01


def test_translucent_foreground_is_composited_over_its_background():
    solid = ts.contrast_ratio("#000000", "#FFFFFF")
    faded = ts.contrast_ratio("rgba(0,0,0,0.5)", "#FFFFFF")
    assert faded is not None and faded < solid


def test_shipped_palette_has_two_known_warnings_and_nothing_unreadable():
    # Pre-existing debt in the stylesheet, pinned so a change that makes either
    # WORSE trips this test: accent #EF5424 on white is 3.52:1 and the sidebar
    # section caption is 4.0:1 - under AA 4.5 but over the unreadable floor.
    findings = ts.audit_contrast({})
    assert sorted(f["token"] for f in findings) == ["accent", "sidebar-section"]
    assert all(f["level"] == "warn" for f in findings)
    assert not ts.has_unreadable({})


def test_shipped_alternate_themes_are_clean():
    for spec in ts.BUILTINS:
        if spec["tokens"]:
            assert ts.audit_contrast(spec["tokens"]) == [], spec["name"]


def test_unreadable_text_is_flagged_as_fail():
    findings = ts.audit_contrast({"text-primary": "#EDEDED"})
    assert findings and findings[0]["level"] == "fail"
    assert ts.has_unreadable({"text-primary": "#EDEDED"})


# -- seeding ----------------------------------------------------------------
def test_seed_is_insert_only_and_leaves_exactly_one_active(app):
    from app.extensions import db
    from app.models_theme import UiTheme
    with app.app_context():
        assert UiTheme.query.filter_by(is_active=True).count() == 1
        classic = UiTheme.query.filter_by(slug=ts.BUILTIN_SLUG).first()
        assert classic.is_active and classic.builtin
        # Classic carries NO overrides on purpose: it *is* the stylesheet.
        assert classic.tokens == {}

        custom = UiTheme(slug="mine", name="Mine", builtin=False)
        custom.tokens = {"accent": "#4F46E5"}
        db.session.add(custom)
        classic.description = "operator edited"
        db.session.commit()

        assert ts.seed_defaults() == 0
        assert UiTheme.query.filter_by(slug="mine").first() is not None
        assert UiTheme.query.filter_by(
            slug=ts.BUILTIN_SLUG).first().description == "operator edited"


def test_corrupt_tokens_json_degrades_instead_of_raising(app):
    from app.extensions import db
    from app.models_theme import UiTheme
    with app.app_context():
        row = UiTheme.query.filter_by(slug=ts.BUILTIN_SLUG).first()
        row.tokens_json = "{not json"
        db.session.commit()
        assert row.tokens == {}
        ts.invalidate()
        assert ts.active_theme()["css"] == ""


# -- routes -----------------------------------------------------------------
def _mk(client, name="Ocean", **extra):
    data = {"name": name, "description": "test", "tok_accent": "#4F46E5"}
    data.update(extra)
    return client.post("/settings/appearance/themes", data=data,
                       follow_redirects=False)


def test_admin_can_create_activate_and_the_style_block_reaches_the_page(app, client):
    from app.models_theme import UiTheme
    login(client, admin_user_id(app))
    assert _mk(client).status_code in (302, 303)
    with app.app_context():
        row = UiTheme.query.filter_by(name="Ocean").first()
        assert row is not None and row.tokens == {"accent": "#4F46E5"}
        tid = row.id

    # Classic is still active, so no override block is emitted.
    html = client.get("/settings/").get_data(as_text=True)
    assert "--fw-accent: #4F46E5" not in html

    client.post("/settings/appearance/themes/%d/activate" % tid)
    html = client.get("/settings/").get_data(as_text=True)
    assert "--fw-accent: #4F46E5" in html
    assert "<style nonce=" in html


def test_non_admin_cannot_touch_any_theme_route(app, client):
    uid = make_user(app, "bob", role="readonly",
                    profile_id=profile_id(app, "readonly"))
    login(client, uid)
    for url in ("/settings/appearance/themes",
                "/settings/appearance/preview",
                "/settings/appearance/reset",
                "/settings/appearance/import"):
        assert client.post(url, data={}).status_code == 403, url


def test_builtin_themes_cannot_be_edited_or_deleted(app, client):
    from app.models_theme import UiTheme
    login(client, admin_user_id(app))
    with app.app_context():
        tid = UiTheme.query.filter_by(slug=ts.BUILTIN_SLUG).first().id
    client.post("/settings/appearance/themes/%d" % tid,
                data={"name": "Hijacked", "tok_accent": "#000000"})
    client.post("/settings/appearance/themes/%d/delete" % tid)
    with app.app_context():
        row = UiTheme.query.get(tid)
        assert row is not None, "a built-in theme was deleted"
        assert row.name == "SATOM Classic" and row.tokens == {}


def test_deleting_the_active_theme_falls_back_to_the_builtin(app, client):
    from app.models_theme import UiTheme
    login(client, admin_user_id(app))
    _mk(client, name="Doomed")
    with app.app_context():
        tid = UiTheme.query.filter_by(name="Doomed").first().id
    client.post("/settings/appearance/themes/%d/activate" % tid)
    client.post("/settings/appearance/themes/%d/delete" % tid)
    with app.app_context():
        active = UiTheme.query.filter_by(is_active=True).all()
        assert len(active) == 1 and active[0].slug == ts.BUILTIN_SLUG


def test_reset_restores_the_builtin(app, client):
    from app.models_theme import UiTheme
    login(client, admin_user_id(app))
    _mk(client, name="Temp")
    with app.app_context():
        tid = UiTheme.query.filter_by(name="Temp").first().id
    client.post("/settings/appearance/themes/%d/activate" % tid)
    client.post("/settings/appearance/reset")
    with app.app_context():
        assert UiTheme.query.filter_by(is_active=True).first().slug == ts.BUILTIN_SLUG


def test_only_one_theme_is_ever_active(app, client):
    from app.models_theme import UiTheme
    login(client, admin_user_id(app))
    _mk(client, name="A")
    _mk(client, name="B")
    with app.app_context():
        ids = [t.id for t in UiTheme.query.filter(UiTheme.name.in_(["A", "B"]))]
    for tid in ids:
        client.post("/settings/appearance/themes/%d/activate" % tid)
        with app.app_context():
            assert UiTheme.query.filter_by(is_active=True).count() == 1


def test_hostile_token_is_refused_by_the_route_too(app, client):
    from app.models_theme import UiTheme
    login(client, admin_user_id(app))
    _mk(client, name="Evil", tok_accent="#fff; } html{display:none}")
    with app.app_context():
        assert UiTheme.query.filter_by(name="Evil").first() is None


def test_an_unreadable_palette_needs_explicit_confirmation(app, client):
    from app.models_theme import UiTheme
    login(client, admin_user_id(app))
    client.post("/settings/appearance/themes",
                data={"name": "Ghost", "tok_text-primary": "#EDEDED"})
    with app.app_context():
        assert UiTheme.query.filter_by(name="Ghost").first() is None
    client.post("/settings/appearance/themes",
                data={"name": "Ghost", "tok_text-primary": "#EDEDED",
                      "confirm_unreadable": "1"})
    with app.app_context():
        assert UiTheme.query.filter_by(name="Ghost").first() is not None


def test_preview_returns_the_server_css_and_the_contrast_report(app, client):
    login(client, admin_user_id(app))
    r = client.post("/settings/appearance/preview",
                    json={"tokens": {"text-primary": "#EDEDED"}})
    body = r.get_json()
    assert body["ok"] is True
    assert "--fw-text-primary: #EDEDED" in body["css"]
    assert any(f["level"] == "fail" for f in body["contrast"])

    r = client.post("/settings/appearance/preview",
                    json={"tokens": {"accent": "}evil{"}})
    body = r.get_json()
    assert body["ok"] is False and body["css"] == ""


def test_export_import_round_trip(app, client):
    import io as _io
    from app.models_theme import UiTheme
    login(client, admin_user_id(app))
    _mk(client, name="Exported")
    with app.app_context():
        tid = UiTheme.query.filter_by(name="Exported").first().id
    payload = client.get("/settings/appearance/themes/%d/export" % tid).get_json()
    assert payload["schema"] == "satom.ui-theme/1"
    assert payload["tokens"] == {"accent": "#4F46E5"}

    client.post("/settings/appearance/import", data={
        "themefile": (_io.BytesIO(json.dumps(payload).encode()), "t.json")},
        content_type="multipart/form-data")
    with app.app_context():
        assert UiTheme.query.filter_by(name="Exported (imported)").first() is not None


def test_import_refuses_a_hostile_file(app, client):
    import io as _io
    from app.models_theme import UiTheme
    login(client, admin_user_id(app))
    evil = {"schema": "satom.ui-theme/1", "name": "Evil",
            "tokens": {"accent": "#fff; } html{display:none}"}}
    client.post("/settings/appearance/import", data={
        "themefile": (_io.BytesIO(json.dumps(evil).encode()), "t.json")},
        content_type="multipart/form-data")
    with app.app_context():
        assert UiTheme.query.filter_by(name="Evil").first() is None


def test_asset_route_rejects_any_path_separator(app, client):
    # The filename is DB state, so the route requires a bare filename rather
    # than screening for traversal patterns. TWO independent layers produce the
    # 404 — this check and werkzeug's own safe_join — and this test deliberately
    # asserts the OUTCOME rather than which layer fired: removing either one
    # must still leave the request refused.
    from app.extensions import db
    from app.models_theme import UiTheme
    login(client, admin_user_id(app))
    with app.app_context():
        row = UiTheme.query.filter_by(slug="satom-slate").first()
        row.logo = "..%sup%ssecret.svg" % (chr(47), chr(47))
        db.session.commit()
        tid = row.id
    assert client.get("/settings/appearance/asset/%d/logo" % tid).status_code == 404
    assert client.get("/settings/appearance/asset/%d/nope" % tid).status_code == 404


def test_appearance_tab_renders_for_admin_only(app, client):
    login(client, admin_user_id(app))
    html = client.get("/settings/").get_data(as_text=True)
    assert 'id="tab-appearance"' in html
    assert 'data-bs-target="#tab-appearance"' in html
    # Every token must have a control, or the editor silently omits one.
    for name in tt.TOKENS:
        assert 'data-theme-token="%s"' % name in html, name

    uid = make_user(app, "carol", role="readonly",
                    profile_id=profile_id(app, "readonly"))
    login(client, uid)
    html = client.get("/settings/").get_data(as_text=True)
    assert 'id="tab-appearance"' not in html
