""""Offer the destination's new fields" — the clone half of version_compat.

The contract under guard: by DEFAULT the write is exactly what it was before
this feature; a value is added only when the operator filled one; it is
validated server-side against the destination build's type/options; a field
the destination build is not known to serve is never sent; a mapped rename is
offered under its new name; and only objects the run CREATES receive values.
"""
from __future__ import annotations

import copy

import pytest

from app.extensions import db
from app.models_apilib import ApiLibFieldMap
from app.services import api_library as lib
from app.services import clone, policy_ops
from app.services import version_compat as vc


@pytest.fixture()
def ctx(app):
    with app.app_context():
        yield app


def _ep(fields):
    return {"urn": "/u", "section": "s", "verdict": "ok", "rows": None, "fields": fields}


def _ingest(version, fields, key="server_policy"):
    lib.ingest({"product": "fortiweb", "source": "sweep", "captured_at": "2026-01-01",
                "origin_ref": "t@" + version,
                "device": {"appliance_id": None, "name": "fw", "serial": "", "model": "",
                           "hw_type": "vm", "firmware_raw": version},
                "scope": {"kind": "build", "version": version, "build": ""},
                "healthy": True, "skip_reason": "", "endpoints": {key: _ep(fields)}})


def _seed():
    _ingest("7.6.8", {"name": {"type": "str"}, "status": {"type": "str"},
                      "legacy": {"type": "str"}})
    _ingest("8.0.5", {"name": {"type": "str"}, "status": {"type": "str"},
                      "modern": {"type": "str"},
                      "mode": {"type": "str", "options": ["strict", "loose"]},
                      "limit": {"type": "int"},
                      "rules": {"type": "list", "children": ["id", "action"]}})


class _Appl:
    def __init__(self, name, fw, ident):
        self.name, self.fw_version, self.kind, self.id = name, fw, "fortiweb", ident


SRC, DST = _Appl("src", "7.6.8", 1), _Appl("dst", "8.0.5", 2)


# --------------------------------------------------------------------------
#  validation — server-side, authoritative
# --------------------------------------------------------------------------
def test_nothing_filled_means_nothing_added(ctx):
    _seed()
    assert vc.validate_for_clone(SRC, DST, {}) == ({}, [])
    assert vc.validate_for_clone(SRC, DST, {"server_policy": {"mode": "", "limit": "  "}}) \
        == ({}, [])


def test_values_are_checked_against_options_and_coerced_to_type(ctx):
    _seed()
    clean, err = vc.validate_for_clone(SRC, DST, {"server_policy": {"mode": "strict",
                                                                    "limit": "42"}})
    assert err == []
    assert clean == {"server_policy": {"mode": "strict", "limit": 42}}


@pytest.mark.parametrize("field,value,needle", [
    ("mode", "medium", "not one of"),
    ("limit", "lots", "not an integer"),
    ("rules", "x", "sub-table"),
    ("modern", "a\x00b", "control characters"),
    ("modern", "x" * 1025, "longer than"),
])
def test_a_value_that_does_not_fit_the_spec_is_refused(ctx, field, value, needle):
    _seed()
    clean, err = vc.validate_for_clone(SRC, DST, {"server_policy": {field: value}})
    assert clean == {} and err and needle in err[0]


def test_a_field_the_destination_is_not_known_to_serve_is_refused(ctx):
    _seed()
    clean, err = vc.validate_for_clone(SRC, DST, {"server_policy": {"invented": "1"}})
    assert clean == {} and "not offered" in err[0]


def test_a_field_the_source_already_has_is_not_new_and_is_refused(ctx):
    _seed()
    _clean, err = vc.validate_for_clone(SRC, DST, {"server_policy": {"status": "enable"}})
    assert err and "not offered" in err[0]


def test_an_unmeasured_destination_offers_nothing_and_accepts_nothing(ctx):
    _seed()
    clean, err = vc.validate_for_clone(SRC, _Appl("dst", "8.0.6", 3),
                                       {"server_policy": {"modern": "x"}})
    assert clean == {} and err


def test_one_bad_value_refuses_the_whole_set(ctx):
    _seed()
    clean, err = vc.validate_for_clone(SRC, DST, {"server_policy": {"mode": "strict",
                                                                    "limit": "x"}})
    assert clean == {} and len(err) == 1


def test_a_mapped_rename_is_offered_under_its_new_name(ctx):
    _seed()
    db.session.add(ApiLibFieldMap(product="fortiweb", endpoint="server_policy",
                                  from_version="7.6.8", from_field="legacy",
                                  to_version="8.0.5", to_field="modern"))
    db.session.commit()
    off = vc.offer("fortiweb", "7.6.8", "8.0.5", "server_policy")
    assert off["modern"]["renamed_from"] == "legacy"
    clean, err = vc.validate_for_clone(SRC, DST, {"server_policy": {"modern": "v"}})
    assert err == [] and clean == {"server_policy": {"modern": "v"}}


# --------------------------------------------------------------------------
#  merge — create objects only, never over the source's own values
# --------------------------------------------------------------------------
def _item(status="create", kind="object", mkey="pol", payload=None, logical="server_policy"):
    return clone.CloneItem(label="Server Policy", urn=clone.ROOT_SERVER_POLICY.urn,
                           logical=logical, mkey=mkey, parent_mkey="", kind=kind, depth=0,
                           payload=payload if payload is not None
                           else {"name": mkey, "status": "enable"}, status=status)


def test_values_land_only_on_objects_this_run_creates():
    made, there = _item("create", mkey="a"), _item("exists", mkey="b")
    upd = _item("update", mkey="c")
    rep = vc.merge_new_values([made, there, upd], {"server_policy": {"mode": "strict"}})
    assert made.payload["mode"] == "strict"
    assert "mode" not in there.payload and "mode" not in upd.payload
    assert rep["applied"] == [{"key": "server_policy", "mkey": "a", "field": "mode"}]


def test_a_value_for_an_object_the_run_does_not_create_is_reported_not_dropped():
    rep = vc.merge_new_values([_item("exists")], {"server_policy": {"mode": "strict"}})
    assert rep["applied"] == []
    assert rep["not_applied"][0]["field"] == "mode"


def test_a_value_never_overwrites_what_the_source_copies():
    it = _item(payload={"name": "pol", "mode": "loose"})
    with pytest.raises(RuntimeError, match="already carries"):
        vc.merge_new_values([it], {"server_policy": {"mode": "strict"}})
    assert it.payload["mode"] == "loose"


# --------------------------------------------------------------------------
#  through the real clone engine
# --------------------------------------------------------------------------
class _Ops:
    class _R(dict):
        @property
        def ok(self):
            return bool(self.get("ok"))

    def __init__(self):
        self.calls = []

    def create(self, endpoint, data, *, mkey=None, dry_run=True):
        self.calls.append(copy.deepcopy(data))
        return self._R(ok=True)

    def update(self, *a, **k):
        return self._R(ok=True)


class _Planner:
    def __init__(self, items):
        self._items = items
        self.dst = None

    def plan(self, root, mkey, **kw):
        return list(self._items)


def test_without_values_the_write_is_exactly_as_before():
    ops = _Ops()
    policy_ops.clone_policy(_Planner([_item()]), ops, "pol", new_name="pol",
                            dry_run=False, disable=False)
    base = ops.calls[0]
    ops2 = _Ops()
    policy_ops.clone_policy(_Planner([_item()]), ops2, "pol", new_name="pol",
                            dry_run=False, disable=False, new_fields=None)
    ops3, empty = _Ops(), {"values": {}}
    policy_ops.clone_policy(_Planner([_item()]), ops3, "pol", new_name="pol",
                            dry_run=False, disable=False, new_fields=empty)
    assert "report" not in empty          # nothing asked, nothing done, no trace
    assert base == ops2.calls[0] == ops3.calls[0] == {
        "data": {"name": "pol", "status": "enable"}}


def test_an_opted_in_value_is_merged_into_the_create_payload_and_reported():
    ops, ctx_ = _Ops(), {"values": {"server_policy": {"mode": "strict"}}}
    policy_ops.clone_policy(_Planner([_item()]), ops, "pol", new_name="pol",
                            dry_run=False, disable=False, new_fields=ctx_)
    assert ops.calls[0]["data"]["mode"] == "strict"
    assert ctx_["report"]["applied"][0]["field"] == "mode"


def test_perform_one_refuses_invalid_values_before_touching_any_device(ctx, monkeypatch):
    _seed()

    def boom(*a, **k):
        raise AssertionError("a device was read")

    monkeypatch.setattr(policy_ops, "_planner", boom)
    monkeypatch.setattr(policy_ops, "_ops", boom)
    rec = policy_ops.perform_one("clone_to", source_appl=SRC, dest_appl=DST, policy="pol",
                                 dry_run=True,
                                 opts={"new_field_values": {"server_policy": {"invented": "1"}}})
    assert rec["ok"] is False
    assert "refused" in rec["error"] and "invented" in rec["error"]


def test_perform_one_hands_validated_values_to_the_clone(ctx, monkeypatch):
    _seed()
    seen = {}

    def fake_clone(planner, ops, policy, **kw):
        seen["new_fields"] = kw.get("new_fields")
        return []

    monkeypatch.setattr(policy_ops, "_planner", lambda s, d: object())
    monkeypatch.setattr(policy_ops, "_ops", lambda a: object())
    monkeypatch.setattr(policy_ops, "clone_policy", fake_clone)
    policy_ops.perform_one("clone_to", source_appl=SRC, dest_appl=DST, policy="pol",
                           dry_run=True,
                           opts={"new_field_values": {"server_policy": {"limit": "7"}}})
    assert seen["new_fields"] == {"values": {"server_policy": {"limit": 7}}}


# --------------------------------------------------------------------------
#  the checklist's offer rows
# --------------------------------------------------------------------------
def test_the_offer_rows_cover_created_objects_only_and_carry_the_rename_value():
    rep = {"target_version": "8.0.5", "rows": [
        {"key": "server_policy", "new_field_specs": {
            "mode": {"type": "str", "options": ["strict"], "claim": "measured",
                     "sources": ["sweep"]},
            "modern": {"type": "str", "renamed_from": "legacy", "claim": "measured"}}},
        {"key": "pool", "new_field_specs": {"x": {"type": "int"}}},
    ]}
    items = [_item(payload={"name": "pol", "legacy": "old-val"}),
             _item("exists", logical="pool", mkey="p1")]
    rows = policy_ops._new_fields_offer(rep, items)
    assert [(r["key"], r["field"]) for r in rows] == [("server_policy", "mode"),
                                                      ("server_policy", "modern")]
    ren = rows[1]
    assert ren["renamed_from"] == "legacy" and ren["source_value"] == "old-val"
    assert rows[0]["options"] == ["strict"] and rows[0]["claim"] == "measured"


# --------------------------------------------------------------------------
#  the HTTP shape check
# --------------------------------------------------------------------------
def test_the_request_parser_drops_blanks_and_refuses_bad_shapes():
    from app.views.workspace import clean_new_field_values as c
    assert c("clone_to", {"server_policy": {"mode": "", "limit": 3}}) == (
        {"server_policy": {"limit": 3}}, None)
    assert c("delete", {"server_policy": {"mode": "x"}}) == ({}, None)
    assert c("clone_to", None) == ({}, None)
    assert c("clone_to", ["x"])[1]
    assert c("clone_to", {"bad key!": {"a": "b"}})[1]
    assert c("clone_to", {"k": {"f": {"nested": 1}}})[1]
    assert c("clone_to", {"k": {"f": "x" * 1025}})[1]
