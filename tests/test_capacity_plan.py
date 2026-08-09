"""Guards for per-object-TYPE capacity checking (services.capacity).

``check_headroom(appliance, 'web_protection_profile', want=1)`` was the whole
capacity story for a WPP clone, and it was sufficient for exactly as long as the
clone created one object. A deep same-device clone creates dozens across ~15
types, and the failure it has to prevent is not a rejected POST: it is a clone
that dies HALF-written, because ``clone_and_rebind`` then refuses to re-bind the
policy and leaves orphans to be found by hand.

The second rule here is that a check which silently skipped most of the plan is
worse than no check, because it reads as "capacity verified". Anything without a
cap comes back in ``unchecked``.
"""
from app.services import capacity


class FakeAppliance:
    id = 1
    name = "fw-test"
    model = "FortiWeb-VM04"
    firmware = "7.6.8"
    kind = "fortiweb"


def _stub_headroom(monkeypatch, caps):
    """``caps`` = ``{object_type: (used, effective_cap)}``; missing = no cap."""
    def fake(appliance, object_type, want=0):
        used, eff = caps.get(object_type, (0, None))
        free = (eff - used) if eff is not None else None
        return capacity.Headroom(
            object_type, capacity.OBJECT_TYPES.get(object_type, {}).get(
                "label", object_type),
            used, eff, None, eff, free,
            True if eff is None else (used + max(want, 0) <= eff),
            eff is not None)
    monkeypatch.setattr(capacity, "headroom", fake)


def test_logical_maps_to_its_capped_type():
    assert capacity.object_type_for_logical("server_policy") == "server_policy"
    assert capacity.object_type_for_logical(
        "webprotection_profile_inline") == "web_protection_profile"
    assert capacity.object_type_for_logical(
        "webprotection_profile_offline") == "web_protection_profile"
    assert capacity.object_type_for_logical("allow_method_policy") is None


def test_counts_are_summed_per_type_not_checked_one_at_a_time():
    """Inline and offline profiles share one cap; checking them separately
    would pass two +1s against a ceiling that has room for one."""
    calls = []

    def fake_check(appliance, object_type, want=1):
        calls.append((object_type, want))
        return True, "ok"
    import app.services.capacity as cap
    orig = cap.check_headroom
    cap.check_headroom = fake_check
    try:
        cap.check_plan_headroom(FakeAppliance(), {
            "webprotection_profile_inline": 2,
            "webprotection_profile_offline": 3})
    finally:
        cap.check_headroom = orig
    assert calls == [("web_protection_profile", 5)]


def test_a_type_over_its_cap_fails_the_whole_plan(monkeypatch):
    _stub_headroom(monkeypatch, {"web_protection_profile": (9, 10)})
    ok, msgs, unchecked = capacity.check_plan_headroom(
        FakeAppliance(), {"webprotection_profile_inline": 4})
    assert ok is False
    assert any("Capacity limit reached" in m for m in msgs)


def test_a_plan_that_fits_is_allowed(monkeypatch):
    _stub_headroom(monkeypatch, {"web_protection_profile": (2, 10)})
    ok, msgs, _ = capacity.check_plan_headroom(
        FakeAppliance(), {"webprotection_profile_inline": 4})
    assert ok is True and msgs


def test_uncapped_object_types_are_reported_never_silently_skipped():
    """A capacity report that covered 1 of 16 types while saying nothing about
    the other 15 would read as 'verified'."""
    ok, msgs, unchecked = capacity.check_plan_headroom(
        FakeAppliance(), {"allow_method_policy": 1, "signature": 2,
                          "cookie_security": 1})
    assert ok is True
    assert msgs == []
    assert unchecked == ["allow_method_policy", "cookie_security", "signature"]


def test_an_empty_plan_checks_nothing_and_allows():
    ok, msgs, unchecked = capacity.check_plan_headroom(FakeAppliance(), {})
    assert (ok, msgs, unchecked) == (True, [], [])
