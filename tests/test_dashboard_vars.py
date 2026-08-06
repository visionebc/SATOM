"""Guards for dashboard variables (Fase 3).

The failure modes here are quiet ones: a picker that changes nothing, a chart
that shows MORE than it claims, and a value the store never produced reaching
a query.
"""
import pytest

from app.models_analytics import MonitorDashboard
from app.services import dashboard_vars as dv


class _Board:
    def __init__(self, variables):
        self.variables = variables


@pytest.fixture()
def store(monkeypatch):
    """Fake label store. The point of every test below is that options come
    from HERE and nowhere else."""
    data = {
        "device": ["fortiweb08", "fortiadc02", "fac01"],
        "policy": ["pol-satom-lab", "pol-shop-main"],
    }
    calls = []

    def label_values(label, match=""):
        calls.append((label, match))
        return list(data.get(label, []))

    from app.services import vm_store
    monkeypatch.setattr(vm_store, "label_values", label_values)
    return calls


# ── the allowlist ────────────────────────────────────────────────────────────

def test_a_value_the_store_never_produced_is_not_interpolated(store):
    """The resolved options ARE the allowlist. This is what makes substituting
    into a MetricsQL expression safe at all."""
    b = _Board([{"name": "device", "label_key": "device"}])
    res = dv.resolve(b, {"device": 'evil"} or vector(1) #'})
    assert res[0]["value"] == dv.ALL, "an unknown value was accepted"
    expr = dv.interpolate('up{device=~"$device"}', res)
    assert "evil" not in expr and "vector(1)" not in expr


def test_substitution_re_checks_the_allowlist_itself(store):
    """Two layers, and this test exercises the SECOND one.

    ``resolve`` already refuses an unknown selection, so a test that only goes
    through it passes even with this check deleted (caught by mutation,
    2026-08-06). ``substitution`` is reachable on its own — anything that
    builds or edits a resolved list reaches it — so it must not trust the
    ``value`` field it is handed.
    """
    poisoned = [{"name": "device", "label": "Device",
                 "options": ["fortiweb08"], "value": 'evil"} or vector(1) #',
                 "error": ""}]
    subs = dv.substitution(poisoned)
    assert "device" not in subs, (
        "substitution trusted a value that is not among its own options")
    assert dv.interpolate('up{device=~"$device"}', poisoned) is None


def test_a_known_value_is_used_verbatim(store):
    b = _Board([{"name": "device", "label_key": "device"}])
    res = dv.resolve(b, {"device": "fortiweb08"})
    assert res[0]["value"] == "fortiweb08"
    assert dv.interpolate('up{device=~"$device"}',
                          res) == 'up{device=~"fortiweb08"}'


def test_all_expands_to_every_option(store):
    b = _Board([{"name": "device", "label_key": "device"}])
    res = dv.resolve(b, {"device": dv.ALL})
    out = dv.interpolate('up{device=~"$device"}', res)
    for name in ("fortiweb08", "fortiadc02", "fac01"):
        assert name in out


# ── the RE2 escape (a real outage, 2026-08-06) ───────────────────────────────

def test_a_hyphen_is_not_escaped():
    """RE2 rejects a backslash-hyphen as an INVALID ESCAPE, so ``re.escape``
    made the store answer 422 for every ordinary hostname. Every device and
    policy name in this fleet has a hyphen: the common case was broken and the
    rare one worked."""
    assert dv._escape_regex("pol-satom-lab") == "pol-satom-lab"


@pytest.mark.parametrize("raw,must_contain", [
    ("fw.08", "\\."), ("a|b", "\\|"), ("x*", "\\*"),
    ("a+b", "\\+"), ("g(1)", "\\("),
])
def test_regex_metacharacters_are_escaped(raw, must_contain):
    """A chart that matches MORE than it claims is the same class of lie as one
    that shows less: an unescaped ``.`` silently widens to other devices."""
    assert must_contain in dv._escape_regex(raw)


def test_the_escaper_output_is_a_valid_re2_style_escape():
    """Guard against re-introducing re.escape: it escapes characters RE2 does
    not accept escaped."""
    import re as _re
    for value in ("pol-satom-lab", "a-b-c", "x~y", "a b"):
        out = dv._escape_regex(value)
        # every backslash must precede a genuinely special character
        for i, ch in enumerate(out):
            if ch == "\\":
                assert out[i + 1] in dv._RE2_SPECIAL, (
                    "escaped a character RE2 does not treat as special: %r"
                    % out[i + 1])
        assert _re.escape(value) != out or "-" not in value


# ── unresolvable variables ───────────────────────────────────────────────────

def test_an_unresolved_variable_yields_none_not_a_broken_query():
    """Running the query with the token still in it makes the store reject a
    PARSE error, which on screen is indistinguishable from the store being
    down."""
    assert dv.interpolate('up{device=~"$device"}', []) is None


def test_a_store_failure_is_reported_and_offers_nothing(monkeypatch):
    from app.services import vm_store

    def boom(label, match=""):
        raise RuntimeError("store down")

    monkeypatch.setattr(vm_store, "label_values", boom)
    res = dv.resolve(_Board([{"name": "device", "label_key": "device"}]),
                     {"device": "fortiweb08"})
    assert res[0]["error"], "the failure was swallowed"
    assert res[0]["options"] == []
    # and crucially it does NOT fall back to the requested value
    assert dv.interpolate('up{device=~"$device"}', res) is None


# ── chaining ─────────────────────────────────────────────────────────────────

def test_a_later_variable_is_scoped_by_an_earlier_one(store):
    """Without chaining the service picker offers every policy in the fleet
    rather than the ones on the selected appliance."""
    b = _Board([
        {"name": "device", "label_key": "device"},
        {"name": "policy", "label_key": "policy",
         "match": 'satom_policy_up{device=~"$device"}'},
    ])
    dv.resolve(b, {"device": "fortiweb08"})
    matches = [m for label, m in store if label == "policy"]
    assert matches and "fortiweb08" in matches[0], (
        "the policy enumeration was not scoped by the device selection: %r"
        % matches)
    assert "$device" not in matches[0]


# ── definition parsing ───────────────────────────────────────────────────────

@pytest.mark.parametrize("bad", [
    {"name": ""}, {"name": "9leading"}, {"name": "has space"},
    "not-a-dict", {},
])
def test_a_malformed_variable_is_dropped_not_repaired(bad):
    """A half-existing variable renders a picker whose selection changes
    nothing, which reads as a broken board rather than a misconfigured one."""
    assert dv.parse([bad]) == []


def test_a_name_is_normalised_to_lower_case():
    """``$NAME`` is not a token the interpolator recognises, so accepting an
    upper-case definition and lowering it keeps definition and reference in
    step instead of silently defining a variable nothing can reference."""
    assert dv.parse([{"name": "UPPER"}])[0]["name"] == "upper"


def test_duplicate_names_collapse():
    out = dv.parse([{"name": "device"}, {"name": "device", "label": "Other"}])
    assert len(out) == 1


# ── the built-in boards ──────────────────────────────────────────────────────

@pytest.fixture()
def seeded(app):
    """Built-in boards are reconciled from code at boot; the test app does not
    run that step, so these tests seed explicitly rather than asserting against
    whatever a previous test happened to leave behind."""
    from app import _seed_analytics_boards
    with app.app_context():
        _seed_analytics_boards()
        yield


def test_the_drilldown_boards_ship_with_variables(app, seeded):
    with app.app_context():
        for slug in ("device-drilldown", "service-drilldown"):
            b = MonitorDashboard.query.filter_by(slug=slug).first()
            assert b is not None, "%s was not seeded" % slug
            names = [v["name"] for v in dv.parse(b.variables)]
            assert "device" in names, "%s has no device picker" % slug
            # every panel must actually USE a variable, or the picker is decor
            for p in b.panels:
                assert dv.uses_variables(p.vm_expr or ""), (
                    "%s panel %r ignores the board's variables"
                    % (slug, p.title))


def test_the_service_board_chains_its_pickers(app, seeded):
    with app.app_context():
        b = MonitorDashboard.query.filter_by(slug="service-drilldown").first()
        vars_ = dv.parse(b.variables)
        policy = next(v for v in vars_ if v["name"] == "policy")
        assert "$device" in policy["match"], (
            "the service picker is not scoped to the selected device")
