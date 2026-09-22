"""The two call sites. The engine being right is worth nothing if nobody asks it.

Surface A: ``policy_ops.preflight`` → the ``apiver`` family in the clone dialog.
Surface B: ``upgrade.prepare`` → the ``apisurface`` section of the pre-upgrade.
"""
import pytest

from app.services import policy_ops
from app.services import prep_store
from app.services import upgrade
from app.services import version_compat as vc


class _Item:
    def __init__(self, logical, payload, kind="object", status="create",
                 urn="", mkey="m"):
        self.logical, self.payload, self.kind = logical, payload, kind
        self.status, self.urn, self.mkey = status, urn, mkey


class _Appl:
    def __init__(self, name="box", fw="7.6.8", kind="fortiweb", ident=1):
        self.name, self.fw_version, self.kind, self.id = name, fw, kind, ident


# --------------------------------------------------------------------------
#  Surface A — which plan items become questions
# --------------------------------------------------------------------------
def test_only_objects_that_are_actually_written_are_compared():
    """``exists`` / ``untouched`` / ``cert`` never carry a payload to the
    destination, so a field verdict about them is a verdict about a write
    nobody makes."""
    items = [_Item("a", {"x": 1}, status="create"),
             _Item("b", {"x": 1}, status="update"),
             _Item("c", {"x": 1}, status="exists"),
             _Item("d", {"x": 1}, status="untouched"),
             _Item("e", {"x": 1}, status="cert")]
    targets, _outside = policy_ops._apiver_targets(items)
    assert [k for k, _f in targets] == ["a", "b"]


def test_subtable_rows_are_reported_as_not_compared_never_as_a_verdict():
    """188 of the registry's 513 logicals are ``*_item`` sub-tables no sweep
    reaches. Counting them as verdicts makes the family answer 'warn' on every
    clone, and a check that always fires is a check operators click past."""
    items = [_Item("parent", {"x": 1}),
             _Item("child_item", {"y": 1}, kind="subrow")]
    targets, outside = policy_ops._apiver_targets(items)
    assert [k for k, _f in targets] == ["parent"]
    assert outside == ["child_item"]


def test_rows_of_one_object_contribute_all_their_fields():
    items = [_Item("a", {"x": 1}), _Item("a", {"y": 2})]
    targets, _ = policy_ops._apiver_targets(items)
    assert targets == [("a", ["x", "y"])]


def test_an_item_with_no_payload_asks_nothing():
    targets, outside = policy_ops._apiver_targets(
        [_Item("a", {}), _Item("b", None)])
    assert targets == [] and outside == []


def test_an_item_with_no_logical_falls_back_to_its_urn():
    """A tree urn finds its logical through the registry; dropping it would
    silently shrink the comparison."""
    from app.services import clone
    urn = next(iter(clone.registry_urn_index()))
    items = [_Item(None, {"x": 1}, urn=urn)]
    targets, _ = policy_ops._apiver_targets(items)
    assert targets and targets[0][0] == clone.registry_urn_index()[urn]


# --------------------------------------------------------------------------
#  Surface B — the pre-upgrade section
# --------------------------------------------------------------------------
def test_no_target_version_means_no_api_section_at_all(monkeypatch):
    """Absent, not empty: a section rendered with nothing in it reads as
    'compared, found nothing'."""
    monkeypatch.setattr(upgrade, "firmware_version", lambda c: "7.6.8")
    monkeypatch.setattr(upgrade, "check_permission", lambda c: True)
    appl = _Appl()
    appl.build_client = lambda: object()
    out = upgrade.prepare(appl, do_backup=False, do_health=False,
                          do_services=False)
    assert "apisurface" not in out


def test_a_never_harvested_appliance_is_not_reported_as_losing_nothing(monkeypatch):
    monkeypatch.setattr(upgrade, "firmware_version", lambda c: "7.6.8")
    monkeypatch.setattr(upgrade, "check_permission", lambda c: True)
    monkeypatch.setattr(vc, "cached_config_fields", lambda aid: ([], 0))
    appl = _Appl()
    appl.build_client = lambda: object()
    out = upgrade.prepare(appl, do_backup=False, do_health=False,
                          do_services=False, target_version="8.0.5")
    assert out["apisurface"]["ok"] is False
    assert "never been harvested" in out["apisurface"]["error"]


def test_the_comparison_never_crashes_the_preflight(monkeypatch):
    def boom(aid):
        raise RuntimeError("matrix on fire")
    monkeypatch.setattr(upgrade, "firmware_version", lambda c: "7.6.8")
    monkeypatch.setattr(upgrade, "check_permission", lambda c: True)
    monkeypatch.setattr(vc, "cached_config_fields", boom)
    appl = _Appl()
    appl.build_client = lambda: object()
    out = upgrade.prepare(appl, do_backup=False, do_health=False,
                          do_services=False, target_version="8.0.5")
    assert out["apisurface"]["ok"] is False
    assert "matrix on fire" in out["apisurface"]["error"]





# --------------------------------------------------------------------------
#  the verdict — reported, never graded
# --------------------------------------------------------------------------






def test_a_preupgrade_without_the_section_keeps_its_old_summary_exactly():
    """The section is additive. Every row written before this feature existed
    must read the same as it did."""
    ok, summary = prep_store.verdict({"backup": {"ok": True},
                                      "health": {"ok": True}})
    assert ok is True
    assert summary == "backup ok, health ok"


# The ``prep_store`` guards for this feature live in
# ``test_version_compat_prep.py``. They exercise
# ``run_for(target_version=...)`` and ``verdict()``'s apisurface branch, both
# of which ride on an earlier round that is still UNCOMMITTED; keeping them
# here would put six red tests on the branch for a dependency that is not on
# it.
