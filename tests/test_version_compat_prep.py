"""``prep_store`` half of the version_compat surfaces.

SEPARATE FILE, and deliberately not on the branch yet: every guard here needs
``prep_store.run_for(target_version=...)``, a parameter an earlier round added
and left uncommitted along with the ``upgrade_prep.target_version`` column it
feeds. They land together.
"""
import pytest

from app.services import prep_store
from app.services import upgrade


class _Appl:
    def __init__(self, name="box", fw="7.6.8", kind="fortiweb", ident=1):
        self.name, self.fw_version, self.kind, self.id = name, fw, kind, ident


def test_the_target_reaches_prepare_from_prep_store(monkeypatch):
    """The column exists, the select exists, and the comparison is worthless
    if the destination stops at the row."""
    seen = {}

    def spy(appliance, **kw):
        seen.update(kw)
        return {"appliance": "x"}

    from app.services import change_requests as crsvc
    monkeypatch.setattr(upgrade, "prepare", spy)
    monkeypatch.setattr(crsvc, "affected_policies", lambda *a, **k: [])
    monkeypatch.setattr(prep_store, "record", lambda *a, **k: object())
    prep_store.run_for(_Appl(), do_backup=False, do_health=False,
                       do_services=False, target_version="8.0.5")
    assert seen.get("target_version") == "8.0.5"


def test_an_empty_target_does_not_travel_as_a_version(monkeypatch):
    """``None`` from a form must not reach ``prepare`` as a truthy string."""
    from app.services import change_requests as crsvc
    seen = {}
    monkeypatch.setattr(upgrade, "prepare",
                        lambda appliance, **kw: seen.update(kw) or {})
    monkeypatch.setattr(crsvc, "affected_policies", lambda *a, **k: [])
    monkeypatch.setattr(prep_store, "record", lambda *a, **k: object())
    prep_store.run_for(_Appl(), do_backup=False, do_health=False,
                       do_services=False)
    assert seen.get("target_version") == ""


def test_a_field_delta_does_not_fail_the_preupgrade():
    """A field the new build drops is something to decide about, not a reason
    the window cannot open. Grading it red is how people learn to re-run a
    pre-flight until it goes green."""
    ok, summary = prep_store.verdict({
        "backup": {"ok": True}, "health": {"ok": True},
        "apisurface": {"ok": True, "dropped_total": 11, "new_total": 57,
                       "absent_total": 0, "target_version": "8.0.5"}})
    assert ok is True
    assert "11 field(s) dropped by 8.0.5" in summary


def test_an_object_type_the_target_drops_is_named_in_the_summary():
    """It carries ZERO dropped fields, so a summary that only totals fields
    renders the whole loss as nothing."""
    _ok, summary = prep_store.verdict({
        "backup": {"ok": True},
        "apisurface": {"ok": True, "dropped_total": 0, "new_total": 3,
                       "absent_total": 1, "target_version": "8.0.5"}})
    assert "1 object type(s)" in summary


def test_a_comparison_that_could_not_run_says_so_instead_of_going_quiet():
    ok, summary = prep_store.verdict({
        "backup": {"ok": True},
        "apisurface": {"ok": False, "error": "no cache"}})
    assert "NOT compared" in summary
    # And it still does not fail the pre-flight. A comparison SATOM could not
    # run is a gap in SATOM's evidence, not a defect in the appliance, and
    # failing the window over it would train people to re-run until green.
    assert ok is True


def test_no_field_change_is_stated_rather_than_left_blank():
    _ok, summary = prep_store.verdict({
        "backup": {"ok": True},
        "apisurface": {"ok": True, "dropped_total": 0, "new_total": 0,
                       "absent_total": 0, "target_version": "8.0.5"}})
    assert "no field change measured" in summary
