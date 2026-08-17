"""Guards for the INTERFACE half of device registration and clone/migrate.

The defect this exists for is not a crash — it is a SUCCESS. ``interface`` is
an ordinary payload field: ``sanitize_payload`` does not strip it (it is not
read-only), the dependency map has no node for ``system/interface`` (creating
one is explicitly forbidden in ``objedit._NO_REF_CREATE``), and the destination
FortiWeb accepts ``interface: port3`` for any ``port3`` it happens to have.
Two boxes almost always both have a ``port3``. They very often do not mean the
same network by it.

So the whole point is to separate three states that used to be one:

  * the destination does NOT have that port           → block  (loud)
  * it has it, but nobody said what either one is for → warn   (honest)
  * it has it and both are documented as the same use → ok

and to give the operator a way to say "bind it to port5 instead" — a mapping
that must reach the device payload, not just the checklist text.

Every list here is DERIVED from the artefact (the role vocabulary from
``models``, the interface fields from ``fortiweb_field_schema``). A re-typed
copy is how a guard starts agreeing with itself instead of with the product.
"""
import re
from pathlib import Path

import pytest

from app import models
from app.services import clone
from app.services import policy_ops


APP = Path(__file__).resolve().parents[1] / "app"


# --------------------------------------------------------------------------- #
#  1. The role vocabulary                                                       #
# --------------------------------------------------------------------------- #
def test_roles_are_pairs_of_nonempty_strings():
    assert models.INTERFACE_ROLES, "the vocabulary may not be empty"
    for entry in models.INTERFACE_ROLES:
        assert isinstance(entry, tuple) and len(entry) == 2, entry
        key, label = entry
        assert key and label and isinstance(key, str) and isinstance(label, str)
        assert key == key.lower() and " " not in key, key


def test_role_keys_are_unique():
    keys = list(models.INTERFACE_ROLE_KEYS)
    assert len(keys) == len(set(keys))


def test_unspecified_is_the_default_and_is_first():
    """'Not declared' must be the default AND the first option offered.

    A form whose first option is a real role turns every hurried save into an
    assertion the operator never made — and the clone gate believes it."""
    assert models.INTERFACE_ROLE_KEYS[0] == "unspecified"
    assert models.ApplianceInterface.role.default.arg == "unspecified"


def test_unspecified_is_distinct_from_other():
    """'never declared' and 'declared, none of these fit' are different facts."""
    assert "other" in models.INTERFACE_ROLE_KEYS
    assert models.interface_role_label("unspecified") != models.interface_role_label("other")


def test_unknown_role_is_normalised_not_stored():
    for bad in ("", None, "   ", "backend", "MANAGEMENT-ish", "'; DROP TABLE"):
        assert models.clean_interface_role(bad) == "unspecified"


def test_known_role_survives_normalisation_case_insensitively():
    assert models.clean_interface_role("MANAGEMENT") == "management"
    assert models.clean_interface_role(" traffic_in ") == "traffic_in"


def test_unspecified_is_not_a_traffic_role():
    """The traffic set is what tells 'has a port called port3' from 'has a
    port called port3 that carries data-plane traffic'. If the undeclared
    default counted as traffic, that distinction would be free and false."""
    assert "unspecified" not in models.INTERFACE_TRAFFIC_ROLES
    assert "management" not in models.INTERFACE_TRAFFIC_ROLES
    assert models.INTERFACE_TRAFFIC_ROLES <= set(models.INTERFACE_ROLE_KEYS)


def test_role_label_falls_back_to_the_key_not_to_a_blank():
    assert models.interface_role_label("no-such-role") == "no-such-role"


# --------------------------------------------------------------------------- #
#  2. The form and the vocabulary are the SAME list                             #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("tpl", ["appliances/edit.html", "appliances/index.html"])
def test_templates_render_roles_from_the_server_not_a_typed_copy(tpl):
    """Both the server-rendered row and the JS-added row must build their
    options from ``interface_roles``. A hand-typed <option> list is how the
    two rows start offering different roles, and only one of them is validated
    on save."""
    body = (APP / "templates" / tpl).read_text(encoding="utf-8")
    assert 'name="if_role"' in body
    assert "interface_roles" in body, "the role list must come from the server"
    # No literal role key spelled into an <option value="..."> in the markup.
    literal = re.findall(r'<option value="(traffic_in|management|ha_sync|traffic_out)"', body)
    assert not literal, f"{tpl} hard-codes role options: {literal}"


def test_edit_and_add_forms_post_the_same_field_names():
    """The two forms feed ONE parser (``_rebuild_interfaces``). A field named
    differently in one of them is silently dropped — the row saves, the value
    does not."""
    edit = (APP / "templates" / "appliances" / "edit.html").read_text(encoding="utf-8")
    add = (APP / "templates" / "appliances" / "index.html").read_text(encoding="utf-8")
    for field in ("if_name", "if_role", "if_segment", "if_ip", "if_notes"):
        assert f'name="{field}"' in edit, f"edit.html lost {field}"
        assert f'name="{field}"' in add, f"the Add dialog lost {field}"


def test_create_view_persists_interfaces():
    """The Add dialog collects interfaces; the create path must actually write
    them. Without this the form is a control that does nothing."""
    src = (APP / "views" / "appliances.py").read_text(encoding="utf-8")
    create = src[src.index("\ndef create("):src.index("\ndef edit(")]
    assert "_rebuild_interfaces" in create


def test_rebuild_parses_role_and_segment():
    src = (APP / "views" / "appliances.py").read_text(encoding="utf-8")
    fn = src[src.index("def _rebuild_interfaces"):src.index("bp = Blueprint")]
    assert 'getlist("if_role")' in fn and 'getlist("if_segment")' in fn
    assert "clean_interface_role" in fn, "a posted role must be normalised, not trusted"


def test_rediscovery_never_writes_a_role():
    """Discovery reads name/type/IP off the device. The device has no field
    saying what a port is FOR, so a discovered role would be manufactured."""
    src = (APP / "services" / "rediscovery.py").read_text(encoding="utf-8")
    fn = src[src.index("def apply_inventory"):src.index("def maybe_apply_inventory")]
    # Strip docstrings AND comments before asserting: this very guard is
    # explained in a docstring that names `role`, and a substring assertion
    # that can match its own commentary proves nothing.
    body = re.sub(r'"{3}.*?"{3}', "", fn, flags=re.S)
    body = re.sub(r"#[^\n]*", "", body)
    assert not re.search(r"\brole\s*=", body), "rediscovery must not set a role"
    assert not re.search(r"\bsegment\s*=", body), "rediscovery must not set a segment"


# --------------------------------------------------------------------------- #
#  3. Which payload fields name an interface                                    #
# --------------------------------------------------------------------------- #
def test_interface_fields_come_from_the_schema():
    """Derived, not restated. The three known fields must be in the set, AND
    the set must equal what the schema says — a guard that only checked the
    three would pass while a fourth silently went unchecked."""
    from app.services.fortiweb_field_schema import REF_ENDPOINTS
    expected = {k for k, v in REF_ENDPOINTS.items() if v == "system/interface"}
    got = clone.interface_fields()
    assert got == expected
    assert {"interface", "data-capture-port", "block-port"} <= got


# --------------------------------------------------------------------------- #
#  4. Reading and rewriting bindings in a plan                                  #
# --------------------------------------------------------------------------- #
def _it(urn, mkey, payload, status="create", kind="object"):
    return clone.CloneItem(label=urn.rsplit("/", 1)[-1], urn=urn, logical="x",
                           mkey=mkey, parent_mkey="", kind=kind, depth=1,
                           payload=dict(payload), status=status)


def _plan():
    return [
        _it("cmdb/server-policy/policy", "pol", {"name": "pol", "data-capture-port": "port2"}),
        _it("cmdb/system/vip", "vip1", {"name": "vip1", "vip": "192.0.2.9/24",
                                        "interface": "port3"}),
        _it("cmdb/server-policy/vserver", "vs1", {"interface": "port3"},
            kind="subrow"),
        _it("cmdb/server-policy/server-pool", "pool1", {"name": "pool1"}),
    ]


def test_interface_refs_finds_every_binding_with_its_field():
    refs = clone.interface_refs(_plan())
    got = {(r["interface"], r["field"]) for r in refs}
    assert got == {("port2", "data-capture-port"), ("port3", "interface")}
    assert len(refs) == 3, "the two port3 bindings are separate rows"


def test_interface_refs_ignores_empty_and_placeholder_values():
    items = [_it("cmdb/system/vip", "v", {"interface": ""}),
             _it("cmdb/system/vip", "w", {"interface": "disable"}),
             _it("cmdb/system/vip", "x", {"interface": "none"})]
    assert clone.interface_refs(items) == []


def test_interface_refs_reports_existing_items_too():
    """An object that already exists at the destination is not proof that the
    port it names exists there — skip-if-exists matches the object's mkey, not
    its bindings. The ref must still be visible to the gate."""
    items = [_it("cmdb/system/vip", "v", {"interface": "port9"}, status="exists")]
    refs = clone.interface_refs(items)
    assert [r["interface"] for r in refs] == ["port9"]
    assert refs[0]["status"] == "exists"


def test_set_interface_rewrites_every_field_that_names_the_port():
    items = _plan()
    changed = clone.set_interface(items, {"port3": "port5"})
    assert items[1].payload["interface"] == "port5"
    assert items[2].payload["interface"] == "port5"
    assert items[0].payload["data-capture-port"] == "port2", "unmapped port untouched"
    assert len(changed) == 2


def test_set_interface_is_per_name_not_global():
    """One tree can bind several ports for different reasons. A single-value
    rewrite would collapse a front-side and a back-side port onto one."""
    items = _plan()
    clone.set_interface(items, {"port2": "port7"})
    assert items[0].payload["data-capture-port"] == "port7"
    assert items[1].payload["interface"] == "port3", "port3 was not in the map"


def test_set_interface_never_touches_a_non_create_item():
    items = [_it("cmdb/system/vip", "v", {"interface": "port3"}, status="exists")]
    assert clone.set_interface(items, {"port3": "port5"}) == []
    assert items[0].payload["interface"] == "port3"


def test_set_interface_records_the_change_on_the_item_note():
    items = _plan()
    clone.set_interface(items, {"port3": "port5"})
    assert "port3" in items[1].note and "port5" in items[1].note


def test_set_interface_ignores_identity_mappings():
    items = _plan()
    assert clone.set_interface(items, {"port3": "port3"}) == []


# --------------------------------------------------------------------------- #
#  5. The gate                                                                  #
# --------------------------------------------------------------------------- #
def _refs(*pairs):
    return [{"interface": i, "field": f, "urn": "u", "mkey": "m",
             "kind": "object", "status": "create"} for i, f in pairs]


def _dev(*names):
    return [{"name": n, "ip": "0.0.0.0/0", "status": "up"} for n in names]


def _gate(refs, **kw):
    kw.setdefault("cross_box", True)
    kw.setdefault("dest_name", "fwb2")
    kw.setdefault("dest_ifaces", _dev("port1", "port2", "port3"))
    kw.setdefault("src_roles", {})
    kw.setdefault("dst_roles", {})
    return policy_ops._iface_gate(refs, **kw)


def test_missing_interface_at_the_destination_is_a_hard_block():
    chk, _ = _gate(_refs(("port9", "interface")))
    assert chk["level"] == "block"
    assert "port9" in chk["label"] and "fwb2" in chk["label"]


def test_block_names_the_ports_the_destination_actually_has():
    """A block that only says 'no' costs the operator a second round-trip to
    find out what IS available."""
    chk, _ = _gate(_refs(("port9", "interface")))
    assert "port1" in chk["detail"] and "port3" in chk["detail"]


def test_unreadable_destination_warns_and_never_blocks():
    """'could not be measured' is not 'broken'. A wall of blocks against a
    device that merely did not answer trains operators to click through."""
    chk, _ = _gate(_refs(("port3", "interface")), dest_ifaces=None)
    assert chk["level"] == "warn"
    assert "not" in chk["detail"].lower()


def test_destination_with_zero_ports_blocks_it_does_not_warn():
    """[] and None are opposite facts: a device that answered and has no
    ports genuinely cannot host the binding."""
    chk, _ = _gate(_refs(("port3", "interface")), dest_ifaces=[])
    assert chk["level"] == "block"


def test_same_box_clone_is_ok_without_touching_the_destination_list():
    chk, _ = _gate(_refs(("port9", "interface")), cross_box=False, dest_ifaces=[])
    assert chk["level"] == "ok"


def test_no_binding_in_the_tree_is_ok():
    chk, sug = _gate([])
    assert chk["level"] == "ok"
    assert sug["interfaces"] == []


def test_nothing_to_check_is_not_worded_as_a_passed_check():
    """Both are level ok, and only one of them measured anything. A row
    reading "Interfaces resolve on fwb2" after looking at zero bindings is an
    assertion the gate never earned — and it is the row an operator scans past
    fastest."""
    none_chk, _ = _gate([])
    real_chk, _ = _gate(
        _refs(("port3", "interface")),
        src_roles={"port3": {"role": "traffic_in", "role_label": "F", "segment": "", "ip": ""}},
        dst_roles={"port3": {"role": "traffic_in", "role_label": "F", "segment": "", "ip": ""}})
    assert real_chk["level"] == none_chk["level"] == "ok"
    assert none_chk["label"] != real_chk["label"]
    assert "resolve" not in none_chk["label"].lower()
    assert none_chk["detail"], "an empty detail reads as a check that ran and found nothing"


def test_present_but_undeclared_is_a_warn_not_an_ok():
    """THE point of the feature. Matching names are exactly the case that used
    to read as success and is the one that silently lands on another network."""
    chk, _ = _gate(_refs(("port3", "interface")))
    assert chk["level"] == "warn"
    assert "not declared" in (chk["label"] + chk["detail"]).lower()


def test_matching_declared_roles_are_ok():
    chk, _ = _gate(_refs(("port3", "interface")),
                   src_roles={"port3": {"role": "traffic_in", "role_label": "T", "segment": "", "ip": ""}},
                   dst_roles={"port3": {"role": "traffic_in", "role_label": "T", "segment": "", "ip": ""}})
    assert chk["level"] == "ok"


def test_differing_declared_roles_warn_and_name_both_sides():
    chk, _ = _gate(_refs(("port3", "interface")),
                   src_roles={"port3": {"role": "traffic_in", "role_label": "Front", "segment": "", "ip": ""}},
                   dst_roles={"port3": {"role": "ha_sync", "role_label": "HA sync", "segment": "", "ip": ""}})
    assert chk["level"] == "warn"
    assert "Front" in chk["detail"] and "HA sync" in chk["detail"]


def test_one_undeclared_side_is_enough_to_lose_the_ok():
    chk, _ = _gate(_refs(("port3", "interface")),
                   src_roles={"port3": {"role": "traffic_in", "role_label": "F", "segment": "", "ip": ""}})
    assert chk["level"] == "warn"


def test_matching_roles_but_different_segment_still_warns():
    chk, _ = _gate(_refs(("port3", "interface")),
                   src_roles={"port3": {"role": "traffic_in", "role_label": "F", "segment": "VLAN10", "ip": ""}},
                   dst_roles={"port3": {"role": "traffic_in", "role_label": "F", "segment": "VLAN20", "ip": ""}})
    assert chk["level"] == "warn"
    assert "VLAN10" in chk["detail"] and "VLAN20" in chk["detail"]


def test_the_gate_evaluates_the_CHOSEN_port_not_the_source_name():
    """The operator remapped port3→port5. A gate that kept checking port3
    would report on an operation Apply is not going to perform."""
    chk, sug = _gate(_refs(("port3", "interface")),
                     dest_ifaces=_dev("port1", "port5"),
                     chosen={"port3": "port5"})
    assert chk["level"] != "block", chk
    assert sug["interfaces"][0]["target"] == "port5"


def test_a_choice_pointing_at_a_nonexistent_port_blocks():
    chk, _ = _gate(_refs(("port3", "interface")), chosen={"port3": "port42"})
    assert chk["level"] == "block" and "port42" in chk["label"]


def test_suggest_carries_the_destination_inventory_for_the_selector():
    _, sug = _gate(_refs(("port3", "interface")))
    assert [d["name"] for d in sug["dest_interfaces"]] == ["port1", "port2", "port3"]
    assert all("role_label" in d for d in sug["dest_interfaces"])


def test_suggest_lists_the_fields_each_port_is_used_by():
    _, sug = _gate(_refs(("port3", "interface"), ("port3", "block-port")))
    row = sug["interfaces"][0]
    assert sorted(row["fields"]) == ["block-port", "interface"]


def test_unreadable_destination_offers_no_fake_inventory():
    _, sug = _gate(_refs(("port3", "interface")), dest_ifaces=None)
    assert sug["dest_interfaces"] == []


# --------------------------------------------------------------------------- #
#  6. The mapping reaches the device payload                                    #
# --------------------------------------------------------------------------- #
class _Planner:
    def __init__(self, items):
        self._items = items

    def plan(self, root, mkey, **kw):
        return list(self._items)


class _Ops:
    def __init__(self):
        self.writes = []

    class _R(dict):
        @property
        def ok(self):
            return bool(self.get("ok"))

    def create(self, endpoint, data, *, mkey=None, dry_run=True):
        self.writes.append((endpoint, data))
        return self._R(ok=True, dry_run=dry_run, request={}, error="")


def test_clone_policy_applies_the_iface_map_to_what_is_written():
    items = _plan()
    ops = _Ops()
    policy_ops.clone_policy(_Planner(items), ops, "pol", new_name="pol2",
                            dry_run=False, iface_map={"port3": "port5"})
    bound = [d["data"].get("interface") for _ep, d in ops.writes
             if "interface" in d["data"]]
    assert bound and set(bound) == {"port5"}, ops.writes


def test_clone_policy_without_a_map_carries_the_source_names_over():
    items = _plan()
    ops = _Ops()
    policy_ops.clone_policy(_Planner(items), ops, "pol", new_name="pol2",
                            dry_run=False)
    bound = [d["data"].get("interface") for _ep, d in ops.writes
             if "interface" in d["data"]]
    assert set(bound) == {"port3"}


def test_iface_map_survives_the_vip_ip_rewrite():
    """Both rewrites edit the SAME vip payload. Whichever runs second must not
    replace the object built by the first — that is how one of two settled
    fields silently reverts."""
    items = _plan()
    ops = _Ops()
    policy_ops.clone_policy(_Planner(items), ops, "pol", new_name="pol2",
                            dry_run=False, vip_ip="192.0.2.9",
                            iface_map={"port3": "port5"})
    vip = [d["data"] for _ep, d in ops.writes if d["data"].get("name") == "vip1"][0]
    assert vip["interface"] == "port5"
    assert vip["vip"].startswith("192.0.2.9")


def test_migrate_passes_the_iface_map_through():
    src = (Path(__file__).resolve().parents[1] / "app" / "services"
           / "policy_ops.py").read_text(encoding="utf-8")
    start = src.index("def migrate_policy")
    # To the NEXT top-level def, not to a named one: slicing to a function that
    # happens to sit EARLIER in the file yields an empty string, and every
    # substring assertion against "" passes for the wrong reason.
    fn = src[start:src.index("\ndef ", start + 1)]
    assert "iface_map=iface_map" in fn, \
        "migrate must forward the mapping or a migrated copy binds the source's ports"


# --------------------------------------------------------------------------- #
#  7. The route validates what it relays to a device                            #
# --------------------------------------------------------------------------- #
def test_route_rejects_a_port_name_that_is_not_a_port_name():
    from app.views.workspace import _IFACE_NAME_RE
    for bad in ("", " ", "port 3", "port3;reboot", "../etc", "a" * 65, "-port"):
        assert not _IFACE_NAME_RE.match(bad), bad
    for good in ("port1", "port1.100", "aggr-0", "vzone_1"):
        assert _IFACE_NAME_RE.match(good), good


def test_route_only_accepts_a_map_for_cross_box_actions():
    """Executed, not grepped. The previous version of this guard asserted that
    the word ``_NEEDS_TARGET`` appeared in the route — and it still appears
    there for the destination lookup, so deleting the interface-map half of
    the rule left the guard green."""
    from app.views.workspace import clean_iface_map
    raw = {"port3": "port5"}
    for cross in ("clone_to", "migrate_to"):
        assert clean_iface_map(cross, raw) == ({"port3": "port5"}, None), cross
    for same in ("clone_here", "enable", "disable", "delete"):
        assert clean_iface_map(same, raw) == ({}, None), same


def test_route_refuses_a_bad_port_name_rather_than_dropping_it():
    """Silently discarding the mapping would clone onto the SOURCE's ports
    while the operator watched a selector claim otherwise."""
    from app.views.workspace import clean_iface_map
    mapping, bad = clean_iface_map("clone_to", {"port3": "port5; reboot"})
    assert mapping == {} and bad == "port5; reboot"
    mapping, bad = clean_iface_map("clone_to", {"../etc": "port5"})
    assert mapping == {} and bad == "../etc"


def test_route_drops_identity_and_blank_entries_without_erroring():
    from app.views.workspace import clean_iface_map
    assert clean_iface_map("clone_to", {"port3": "port3", "": "port5",
                                        "port4": ""}) == ({}, None)


def test_route_tolerates_a_non_dict_payload():
    from app.views.workspace import clean_iface_map
    for junk in (None, [], "port3", 7):
        assert clean_iface_map("clone_to", junk) == ({}, None)
