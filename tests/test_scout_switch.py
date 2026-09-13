"""Guards for ``scout.enabled`` — the switch, and where it is enforced.

A feature flag that only hides a menu entry is not a switch. The URL still
works, the bookmark still works, and the link pasted into a ticket still walks
the ladder — so the operator who was told Scout is off gets a full report, and
the administrator who switched it off believes they switched it off. The guard
that matters here is therefore the one that hits the ROUTE, not the one that
inspects the navigation.

The second thing being defended is subtler: OFF must not look like ABSENT. A
removed menu entry reads as 'this product does not have that feature', which
sends the operator to look for an installer instead of for a checkbox. So the
entry stays, disabled, carrying the reason — and the page answers 503 rather
than 404, because 'switched off' and 'does not exist' are different answers to
the operator's next question.
"""
from __future__ import annotations

from app.services import scout_config
from tests.conftest import login, make_user, profile_id


def _admin(app):
    return make_user(app, "scswadmin", role="admin",
                     profile_id=profile_id(app, "admin"))


def _viewer(app):
    return make_user(app, "scswview", role="readonly",
                     profile_id=profile_id(app, "readonly"))


def _set(app, on):
    with app.app_context():
        scout_config.set_value("enabled", on)


# --------------------------------------------------------------------------- #
#  The setting                                                                  #
# --------------------------------------------------------------------------- #
def test_scout_ships_on(app):
    """A new install must not arrive with its troubleshooting tool switched off."""
    with app.app_context():
        assert scout_config.enabled() is True


def test_the_switch_is_a_real_setting_in_the_catalog():
    """SPEC is the catalog the settings form is GENERATED from. A flag the code
    reads but SPEC does not declare is an unconfigurable knob — the exact defect
    scout_config's own docstring was written against."""
    spec = {s["key"]: s for s in scout_config.SPEC}
    assert "enabled" in spec
    assert spec["enabled"]["kind"] == "bool"
    assert spec["enabled"]["default"] is True
    assert spec["enabled"]["group"] == "switch"
    assert any(g[0] == "switch" for g in scout_config.GROUPS)


def test_the_switch_appears_on_the_settings_form(app):
    with app.app_context():
        groups = dict((g, rows) for g, _lbl, rows in scout_config.form_groups())
    assert "switch" in groups
    assert any(r["key"] == "enabled" for r in groups["switch"])


def test_a_broken_settings_table_leaves_scout_ON(app, monkeypatch):
    """Degrade to available. Scout is opened during an incident, which is the
    worst possible moment to meet a feature that failed closed because a query
    raised."""
    monkeypatch.setattr(scout_config, "get",
                        lambda k: (_ for _ in ()).throw(RuntimeError("db gone")))
    with app.app_context():
        assert scout_config.enabled() is True


# --------------------------------------------------------------------------- #
#  Enforcement — on the blueprint, not on the menu                              #
# --------------------------------------------------------------------------- #
def test_the_page_is_closed_when_the_switch_is_off(app, client):
    login(client, _admin(app))
    assert client.get("/scout/").status_code == 200
    _set(app, False)
    r = client.get("/scout/")
    assert r.status_code == 503, "hiding the menu entry closes nothing"
    assert b"switched off" in r.data.lower()


def test_a_POSTed_walk_is_refused_too(app, client):
    """The form posts to the same URL. A gate that only covers GET leaves the
    ladder reachable by anyone who still has the page open."""
    login(client, _admin(app))
    _set(app, False)
    assert client.post("/scout/", data={}).status_code == 503


def test_the_json_endpoint_answers_json_when_off(app, client):
    """``/scout/objects`` is fetched by the page. An HTML error body here is
    parsed as JSON by the caller and surfaces as a syntax error, which tells the
    operator nothing about a switch."""
    login(client, _admin(app))
    _set(app, False)
    r = client.get("/scout/objects?appliance_id=1")
    assert r.status_code == 503
    d = r.get_json()
    assert d and d.get("disabled") is True
    assert "switched off" in d["error"].lower()


def test_off_is_503_and_not_404(app, client):
    """'Switched off' and 'does not exist' are different answers, and only one of
    them has a checkbox at the end of it."""
    login(client, _admin(app))
    _set(app, False)
    assert client.get("/scout/").status_code != 404


def test_turning_it_back_on_restores_the_page(app, client):
    login(client, _admin(app))
    _set(app, False)
    assert client.get("/scout/").status_code == 503
    _set(app, True)
    assert client.get("/scout/").status_code == 200


# --------------------------------------------------------------------------- #
#  The chrome                                                                   #
# --------------------------------------------------------------------------- #
def test_the_chrome_is_told_about_the_switch(app, client):
    """``scout_on`` reaches every template, resolved once per request.

    Functional, and it is the half that can be driven: the sidebar branch that
    carries Scout is not rendered by any page the test client can reach (the
    landing renders a different nav variant), so the markup itself is guarded by
    the source test below rather than by a page fetch. Saying so here is the
    point — a guard that silently covers less than its name claims is the defect
    this whole round is about."""
    login(client, _admin(app))
    with app.test_request_context("/"):
        from flask import render_template_string
        _set(app, False)
        assert render_template_string("{{ scout_on }}") == "False"
        _set(app, True)
        assert render_template_string("{{ scout_on }}") == "True"


def test_the_menu_entry_is_disabled_rather_than_removed():
    """Shown, disabled, carrying the reason.

    Removing it is the failure mode: an absent entry reads as 'this product does
    not have Scout', and the operator goes looking for an installer instead of
    for a checkbox. Both copies of the entry are checked — base.html renders the
    Scout link in two branches, and a fix applied to one of them is the oldest
    bug in this template."""
    from pathlib import Path
    src = Path(__file__).resolve().parents[1] / "app" / "templates" / "base.html"
    body = src.read_text(encoding="utf-8")
    links = body.count("url_for('scout.index')")
    assert links == 2, links
    guarded = body.count("{% if scout_on %}")
    assert guarded == 2, "every Scout entry must sit behind the switch"
    # the off-branch exists, says why, and is NOT an anchor
    offs = body.count("Scout is switched off for this site")
    assert offs == 2, offs
    assert body.count("cursor:not-allowed") >= 2


# --------------------------------------------------------------------------- #
#  The switch beside the advisory                                               #
# --------------------------------------------------------------------------- #
def test_the_advisory_is_closed_by_the_same_switch(app, client):
    login(client, _admin(app))
    _set(app, False)
    r = client.get("/release-notes/advisory?current=7.6.9&target=8.0.7")
    assert r.status_code == 503
    assert r.get_json().get("disabled") is True


def test_the_modal_reports_the_switch_state(app, client):
    login(client, _admin(app))
    _set(app, False)
    assert client.get("/release-notes/data").get_json()["scout_enabled"] is False
    _set(app, True)
    assert client.get("/release-notes/data").get_json()["scout_enabled"] is True


def test_an_admin_can_flip_it_from_the_modal(app, client):
    """Switched on from where its absence is noticed — the user asked for the
    option to live beside the advisory, not only three pages away."""
    login(client, _admin(app))
    _set(app, False)
    r = client.post("/release-notes/scout-switch", json={"enabled": True})
    assert r.status_code == 200
    assert r.get_json()["enabled"] is True
    with app.app_context():
        assert scout_config.enabled() is True
    assert client.get("/scout/").status_code == 200, \
        "the modal switch and the page must be the SAME flag"


def test_the_modal_switch_can_turn_it_off_again(app, client):
    login(client, _admin(app))
    _set(app, True)
    assert client.post("/release-notes/scout-switch",
                       json={"enabled": False}).get_json()["enabled"] is False
    assert client.get("/scout/").status_code == 503


def test_a_read_only_user_cannot_flip_it(app, client):
    login(client, _viewer(app))
    assert client.post("/release-notes/scout-switch",
                       json={"enabled": False}).status_code == 403
