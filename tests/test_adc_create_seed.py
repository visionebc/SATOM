"""FortiADC create-field seed + required validation (the -56 guard)."""
from app.services import adc_objform as af


def test_vs_seed_renders_pool_field_with_zero_siblings():
    # a fresh box: no sibling objects -> sample empty, but the seed still shows
    groups = af.create_field_groups("load_balance_virtual_server", {})
    keys = [f["key"] for g in groups for f in g["fields"]]
    assert "pool" in keys and "interface" in keys and "address" in keys
    pool = next(f for g in groups for f in g["fields"] if f["key"] == "pool")
    assert pool["required"] is True and pool.get("help")


def test_required_fields_are_the_verified_ones():
    assert af.required_fields("load_balance_virtual_server") == {"pool"}
    assert af.required_fields("load_balance_real_server") == {"address"}
    assert af.required_fields("load_balance_pool_child_pool_member") == {"real_server_id"}
    assert af.required_fields("unknown_thing") == set()


def test_seed_merges_extra_sibling_keys_after_seed():
    groups = af.create_field_groups("load_balance_real_server", {"comments": ""})
    keys = [f["key"] for g in groups for f in g["fields"]]
    assert keys[0] == "address"          # seed first
    assert "comments" in keys            # sibling extra kept


def test_create_hint_present_for_vs():
    assert "pool" in af.create_hint("load_balance_virtual_server").lower()
    assert af.create_hint("system_interface") == ""


def test_toggle_seed_defaults_to_enable():
    groups = af.create_field_groups("load_balance_virtual_server", {})
    st = next(f for g in groups for f in g["fields"] if f["key"] == "status")
    assert st["widget"] == "toggle" and st["on"] is True and st["value"] == "enable"
