"""Sentinel operating modes — the label may never outlive the configuration.

The operator asked for four named postures (*alert only, alert and block,
high, ultra high*). The whole risk of that feature is a name that goes on
being displayed after the values under it have been edited: an operator who
reads *Alert only* on a page whose kill switch was armed by hand has been told
the opposite of the truth by the product, and nothing anywhere fails.

So the mode is DERIVED on every read and never stored, and that is what most
of this file holds. The rest holds the second rule: a mode is a preset over
knobs that already exist, so it must not be able to reach the two classes of
setting that are not sensitivity — consent (does this fleet's data leave the
node?) and containment (what can never be blocked, whatever the score says).
"""
from __future__ import annotations

import pytest

from app.models import db
from app.models_sentinel import SentinelPolicy
from tests.conftest import admin_user_id, login


@pytest.fixture()
def admin(app, client):
    login(client, admin_user_id(app), product="global")
    return client


# ------------------------------------------------------ the catalog itself --

def test_every_preset_names_the_same_settings(app):
    """A preset that says less is a preset that matches more easily.

    If *Alert only* named three keys and *High* named ten, then any
    configuration matching those three would report *Alert only* — including a
    fully armed one that happened to agree on them. Recognition has to be
    decided by the same set of questions for every mode.
    """
    from app.services.sentinel import modes
    keys = {m["key"]: set(m["settings"]) for m in modes.MODES}
    first = next(iter(keys.values()))
    for name, ks in keys.items():
        assert ks == first, (
            "%s names a different set of settings from the others: %s"
            % (name, sorted(ks ^ first))
        )
    levels = {m["key"]: set(m["levels"]) for m in modes.MODES}
    assert len(set(map(frozenset, levels.values()))) == 1, levels


def test_no_two_presets_are_the_same_configuration(app):
    """Two identical presets would make one of them unreachable by name: the
    first match wins in :func:`current`, so the second could be applied and
    would then be reported as the first."""
    from app.services.sentinel import modes
    seen = {}
    for m in modes.MODES:
        # Compared as STORED, not as wished: two presets differing only above
        # a catalog ceiling write the same rows, and the second could then be
        # applied and reported as the first for ever.
        sig = (tuple(sorted(m["settings"].items())),
               tuple(sorted((a, modes._effective_level(a, v))
                            for a, v in m["levels"].items())),
               m["enabled_actions"])
        assert sig not in seen, (
            "%s and %s are the same configuration under two names"
            % (seen.get(sig), m["key"])
        )
        seen[sig] = m["key"]


def test_a_mode_can_never_write_consent_or_containment(app):
    """The two classes of setting a sensitivity preset must not touch.

    ``ai_enabled`` / ``vuln_sync_enabled`` / the API key decide whether this
    fleet's data leaves the node — that is consent, and "be more thorough"
    must not quietly mean "start talking to a vendor". ``protect_cidrs`` and
    the hardened-profile list are the containment: they are what stops Ultra
    high from being dangerous, so a mode that could widen them would be a mode
    that removes its own safety rail.
    """
    from app.services.sentinel import modes
    for m in modes.MODES:
        for forbidden in modes.FORBIDDEN:
            assert forbidden not in m["settings"], (
                "preset %s writes %s" % (m["key"], forbidden)
            )
    assert not (set(modes.WRITABLE) & set(modes.FORBIDDEN))


def test_every_preset_key_is_a_real_setting(app):
    """A typo here is silent: :func:`config.set_value` raises on an unknown
    key, so a bad preset would 500 the apply — but a bad key in a preset that
    is never applied would sit there being compared against nothing."""
    from app.services.sentinel import config, modes
    known = {s["key"] for s in config.SPEC}
    for m in modes.MODES:
        for key in m["settings"]:
            assert key in known, "%s presets unknown setting %s" % (m["key"], key)


def test_every_preset_level_is_a_real_action(app):
    from app.services.sentinel import actions, modes
    for m in modes.MODES:
        for action_type in m["levels"]:
            assert action_type in actions.CATALOG, (
                "%s presets unknown action %s" % (m["key"], action_type)
            )


# --------------------------------------------------------- derived, not kept --

def test_applying_a_mode_makes_it_the_current_mode(app):
    from app.services.sentinel import modes
    with app.app_context():
        for want in ("alert_only", "alert_block", "high", "ultra_high"):
            modes.apply(want)
            assert modes.current()["key"] == want, (
                "applied %s and the page would report %s"
                % (want, modes.current()["key"])
            )


def test_touching_one_knob_by_hand_makes_the_mode_custom(app):
    """The half the operator asked for in so many words.

    A stored label would survive this edit and go on claiming a posture that
    is no longer configured. Nothing would fail: the page renders, the badge
    is there, and it is wrong.
    """
    from app.services.sentinel import config, modes
    with app.app_context():
        modes.apply("alert_block")
        assert modes.current()["key"] == "alert_block"
        config.set_value("max_actions_per_hour", 11)
        assert modes.current()["key"] == "custom", (
            "a hand-edited knob still reports a named mode"
        )
        assert "max_actions_per_hour" in modes.drift()["alert_block"], \
            "the drift report does not name the knob that moved"


def test_a_policy_level_moved_by_hand_also_makes_it_custom(app):
    """Autonomy is half the meaning of a mode, so a level edited on the
    Response policy table has to count exactly as a setting does."""
    from app.services.sentinel import modes
    with app.app_context():
        modes.apply("alert_block")
        row = SentinelPolicy.query.filter_by(action_type="block_ip").first()
        row.level = SentinelPolicy.LEVEL_OBSERVE
        db.session.commit()
        assert modes.current()["key"] == "custom"
        assert "block_ip" in modes.drift()["alert_block"]


def test_exactly_one_mode_is_marked_active_in_the_render_model(app):
    from app.services.sentinel import modes
    with app.app_context():
        modes.apply("high")
        rows = modes.rows()
        assert [r["key"] for r in rows if r["active"]] == ["high"]
        assert rows[0]["settings"], "a mode card shows no values at all"


def test_custom_marks_nothing_active(app):
    from app.services.sentinel import config, modes
    with app.app_context():
        modes.apply("high")
        config.set_value("baseline_k", 5.5)
        assert modes.current()["key"] == "custom"
        assert not [r for r in modes.rows() if r["active"]]


# ----------------------------------------------------------- the ceilings --

def test_no_preset_asks_for_more_autonomy_than_the_catalog_allows(app):
    """Ultra high included. ``block_country`` is capped at *recommend* by the
    catalog because one mis-attributed source address takes a market offline,
    and a mode is a preset over knobs rather than a way past a knob's
    ceiling."""
    from app.services.sentinel import actions, modes
    for m in modes.MODES:
        for action_type, want in m["levels"].items():
            ceiling = actions.CATALOG[action_type].max_level
            assert want <= ceiling, (
                "%s asks for level %d on %s, whose ceiling is %d"
                % (m["key"], want, action_type, ceiling)
            )


def test_a_preset_over_the_ceiling_is_clamped_and_still_recognised(app,
                                                                   monkeypatch):
    """The clamp is defence for the preset nobody has written yet.

    Driven with a preset deliberately over the ceiling because none of the
    four shipped ones is — which means without this test the clamp would be
    unexercised, and the assertion "ultra high does not lift the ceiling"
    would be true for a reason that has nothing to do with the clamp.

    Two halves, and the second is the one that is easy to miss: an UNCLAMPED
    write would store a level the catalog refuses AND make the mode
    permanently unrecognisable, because ``policy_save`` clamps and the stored
    value could then never equal what the preset asked for. The page would
    read Custom for ever with no knob to move.
    """
    from app.services.sentinel import modes
    greedy = dict(modes.MODES[-1])
    greedy["key"] = "greedy"
    greedy["levels"] = dict(greedy["levels"], block_country=3)
    # Also differs in a setting, because an over-the-ceiling WISH clamps to a
    # value another preset already stores -- and two presets that store the
    # same configuration are indistinguishable by construction (the first one
    # wins). That is asserted separately, above; here it would only disguise
    # what this test is about.
    greedy["settings"] = dict(greedy["settings"], max_actions_per_hour=30)
    monkeypatch.setattr(modes, "MODES", modes.MODES + [greedy])
    with app.app_context():
        modes.apply("greedy")
        row = SentinelPolicy.query.filter_by(action_type="block_country").first()
        assert row.level == SentinelPolicy.LEVEL_RECOMMEND, (
            "a preset stored level %s on block_country" % row.level
        )
        assert modes.current()["key"] == "greedy", (
            "the mode cannot recognise the configuration it just wrote"
        )


def test_ultra_high_recognises_the_configuration_it_writes(app):
    from app.services.sentinel import modes
    with app.app_context():
        modes.apply("ultra_high")
        assert modes.current()["key"] == "ultra_high"


def test_settings_are_clamped_by_their_own_spec(app):
    """Every value goes through the same coercion the form goes through, so a
    preset cannot store something a typed form could not."""
    from app.services.sentinel import config, modes
    with app.app_context():
        modes.apply("ultra_high")
        for spec in config.SPEC:
            if spec["kind"] not in ("int", "float"):
                continue
            value = config.get(spec["key"])
            if spec.get("min") is not None:
                assert value >= spec["min"], spec["key"]
            if spec.get("max") is not None:
                assert value <= spec["max"], spec["key"]


def test_apply_reports_what_changed_before_and_after(app):
    """The audit line is built from this. "Someone chose Ultra high" does not
    answer "why did this appliance start blocking by itself"; the list of
    values that moved does."""
    from app.services.sentinel import modes
    with app.app_context():
        modes.apply("alert_only")
        result = modes.apply("ultra_high")
        assert result["changed"], "applying a different mode changed nothing"
        for row in result["changed"]:
            assert set(row) == {"key", "before", "after"}
            assert str(row["before"]) != str(row["after"])
        assert not modes.apply("ultra_high")["changed"], \
            "re-applying the live mode reports changes that did not happen"


def test_an_unknown_mode_raises(app):
    from app.services.sentinel import modes
    with app.app_context():
        with pytest.raises(KeyError):
            modes.apply("paranoid")


# ------------------------------------------------------------- the route --

def test_the_route_applies_and_returns_to_the_pane(app, admin):
    from app.services.sentinel import modes
    r = admin.post("/sentinel/policies/mode",
                   data={"mode": "alert_block", "return_to": "pane"})
    assert r.status_code == 302
    assert r.headers["Location"].endswith("#tab-sentinel-policy"), \
        r.headers["Location"]
    with app.app_context():
        assert modes.current()["key"] == "alert_block"


def test_the_route_returns_to_the_page_when_fired_from_it(app, admin):
    r = admin.post("/sentinel/policies/mode", data={"mode": "high"})
    assert r.status_code == 302
    assert r.headers["Location"].endswith("/sentinel/policies"), \
        r.headers["Location"]


def test_the_route_refuses_an_unknown_mode(admin):
    r = admin.post("/sentinel/policies/mode", data={"mode": "paranoid"})
    assert r.status_code == 400


def test_the_route_writes_the_values_into_the_audit_log(app, admin):
    admin.post("/sentinel/policies/mode", data={"mode": "alert_only"})
    admin.post("/sentinel/policies/mode", data={"mode": "ultra_high"})
    with app.app_context():
        from app.models import AuditLog
        row = (AuditLog.query.filter(AuditLog.action == "sentinel.mode")
               .order_by(AuditLog.id.desc()).first())
        assert row is not None, "applying a mode was not audited"
        # detail= lands in the JSON `extra` blob (log_action folds unknown
        # kwargs into it), so that is where this reads it from.
        blob = (row.extra or "")
        assert "ultra_high" in blob
        assert "->" in blob, \
            "the audit line records the mode name but not the values it wrote"


def test_the_policy_page_shows_the_live_mode(app, admin):
    with app.app_context():
        from app.services.sentinel import modes
        modes.apply("high")
    body = admin.get("/sentinel/policies").get_data(as_text=True)
    assert "Operating mode" in body
    assert "High" in body
    # The three modes that are NOT live each offer an apply button; the live
    # one must not, because a button that re-applies what is already there is
    # a control whose only possible effect is to look like it failed.
    assert body.count('name="mode" value=') == len(
        [m for m in __import__(
            "app.services.sentinel.modes", fromlist=["x"]).MODES]) - 1
