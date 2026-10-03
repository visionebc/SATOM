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


# --- Capacity Limits admin page: Add / Delete model carry the product -------

def test_add_model_creates_rows_for_the_chosen_product(app, client):
    from tests.conftest import admin_user_id, login
    from app.models import CapacityLimit
    login(client, admin_user_id(app), product="global")
    r = client.post("/capacity/add-model", data={
        "product": "fortiadc", "model": "FortiADC-VM", "firmware_major": "8.0"},
        headers={"X-ADOM": "global"})
    assert r.status_code in (302, 303)
    with app.app_context():
        rows = CapacityLimit.query.filter_by(model="FortiADC-VM").all()
        assert rows and {x.product for x in rows} == {"fortiadc"}
    # A product this ADOM may not create is refused.
    login(client, admin_user_id(app), product="fortiweb")
    client.post("/capacity/add-model", data={
        "product": "fortiadc", "model": "Sneaky", "firmware_major": "8.0"},
        headers={"X-ADOM": "fortiweb"})
    with app.app_context():
        assert CapacityLimit.query.filter_by(model="Sneaky").count() == 0


def test_delete_model_removes_one_products_catalog_only(app, client):
    from tests.conftest import admin_user_id, login
    from app.models import CapacityLimit
    with app.app_context():
        capacity.ensure_rows_for("Shared-1", "7.6", product="fortiweb")
        capacity.ensure_rows_for("Shared-1", "7.6", product="fortiadc")
    login(client, admin_user_id(app), product="global")
    r = client.post("/capacity/delete-model", data={
        "product": "fortiadc", "model": "Shared-1", "firmware_major": "7.6"},
        headers={"X-ADOM": "global"})
    assert r.status_code in (302, 303)
    with app.app_context():
        left = {x.product for x in CapacityLimit.query.filter_by(model="Shared-1")}
        assert left == {"fortiweb"}
