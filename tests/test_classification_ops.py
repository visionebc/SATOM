"""Guards for the classification catalog editor.

The thing under test is not "can we store three lists of strings" -- the old
textarea did that fine. It is that a value in a catalog is a KEY that
``Appliance``, ``Baseline`` and every network segment hold as a plain string
with no foreign key behind it. Every test here exists because some edit used to
break those references without raising, without logging, and without changing
anything an operator could see on this page.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Appliance, Baseline
from app.services import classification_ops as ops
from app.services import settings_store as store
from app.services.baselines import combo_name, missing_combos


# --------------------------------------------------------------------------- #
#  fixtures                                                                    #
# --------------------------------------------------------------------------- #
def _appl(name, **kw):
    a = Appliance(name=name, kind=kw.pop("kind", "fortiweb"),
                  host=kw.pop("host", "192.0.2.13"), port=443,
                  username="admin", password_enc="x", verify_ssl=False, **kw)
    db.session.add(a)
    db.session.commit()
    return a.id


def _combo(zone="", line="", department="", name=None):
    b = Baseline(name=name or combo_name(zone, line, department),
                 zone=zone, line=line, department=department)
    db.session.add(b)
    db.session.commit()
    return b.id


def _seed(session):
    store.save_classification("zones", ["internal", "external"])
    store.save_classification("lines", ["A", "P"])
    store.save_classification("departments", ["WAF/LB"])
    return session


def _rows(*specs):
    """(orig, value) or (orig, value, action, reassign, decided)."""
    out = []
    for s in specs:
        s = tuple(s) + ("keep", "", False)[len(s) - 2:]
        out.append(ops.Row(orig=s[0], value=s[1], action=s[2],
                           reassign=s[3], decided=s[4]))
    return out


@pytest.fixture()
def seeded(session):
    return _seed(session)


# --------------------------------------------------------------------------- #
#  usage — counted from live rows, not from the catalog                        #
# --------------------------------------------------------------------------- #
def test_usage_counts_each_reference_kind_separately(seeded):
    _appl("a1", zone="internal")
    _appl("a2", zone="internal")
    _combo(zone="internal", line="A")
    store.save_segments([{"name": "s1", "zone": "internal", "line": "",
                          "department": "", "cidr": "192.0.2.0/24",
                          "interface": "port1", "gateway": "", "note": ""}])
    u = ops.usage("zones")["internal"]
    assert (u.appliances, u.baselines, u.segments, u.total) == (2, 1, 1, 4)


def test_usage_does_not_fold_case(seeded):
    """`Appliance.zone == "internal"` never matches a row holding "Internal".
    Folding the two here would report a reference the query cannot resolve."""
    _appl("a1", zone="internal")
    _appl("a2", zone="Internal")
    u = ops.usage("zones")
    assert u["internal"].appliances == 1
    assert u["Internal"].appliances == 1


def test_usage_ignores_blank_and_null_references(seeded):
    _appl("a1", zone=None)
    _appl("a2", zone="   ")
    assert ops.usage("zones") == {}


def test_unregistered_lists_live_values_absent_from_the_catalog(seeded):
    """Exactly what the old textarea produced. The page must show them: an
    operator cannot re-adopt a value the page pretends does not exist."""
    _appl("a1", zone="dmz")
    _appl("a2", zone="internal")
    assert set(ops.unregistered("zones")) == {"dmz"}


# --------------------------------------------------------------------------- #
#  rename cascades                                                             #
# --------------------------------------------------------------------------- #
def test_rename_moves_appliance_references(seeded):
    aid = _appl("a1", zone="internal")
    ops.apply_rows("zones", _rows(("internal", "Internal"), ("external", "external")))
    assert Appliance.query.get(aid).zone == "Internal"
    assert store.classification("zones") == ["Internal", "external"]


def test_rename_moves_baseline_scope(seeded):
    """A baseline left on the old string does not raise -- it silently scopes
    to nothing, which reads like 'no appliance matches yet'."""
    bid = _combo(zone="internal", line="A", department="WAF/LB")
    ops.apply_rows("zones", _rows(("internal", "Internal"), ("external", "external")))
    assert Baseline.query.get(bid).zone == "Internal"


def test_rename_moves_segment_references(seeded):
    store.save_segments([{"name": "s1", "zone": "internal", "line": "P",
                          "department": "", "cidr": "192.0.2.0/24",
                          "interface": "port1", "gateway": "", "note": ""}])
    ops.apply_rows("zones", _rows(("internal", "Internal"), ("external", "external")))
    assert store.segments()[0]["zone"] == "Internal"


def test_rename_relabels_the_auto_generated_combo_name(seeded):
    """A combo named "internal / A / WAF/LB" scoped to zone "Internal" is
    readable, wrong, and invisible in a list of 24."""
    bid = _combo(zone="internal", line="A", department="WAF/LB")
    ops.apply_rows("zones", _rows(("internal", "Internal"), ("external", "external")))
    assert Baseline.query.get(bid).name == "Internal / A / WAF/LB"


def test_rename_leaves_a_hand_named_combo_alone(seeded):
    """Only names the generator itself produced are regenerated. Overwriting a
    name an operator typed would destroy the one field they own."""
    bid = _combo(zone="internal", line="A", department="WAF/LB", name="Crown jewels")
    ops.apply_rows("zones", _rows(("internal", "Internal"), ("external", "external")))
    b = Baseline.query.get(bid)
    assert b.name == "Crown jewels" and b.zone == "Internal"


def test_rename_keeps_the_combo_grid_from_doubling(seeded):
    """The failure that costs the most and shows the least: leave the combos on
    the old triple and generate_missing_combos() builds a SECOND full grid."""
    store.save_classification("lines", ["A"])
    _combo(zone="internal", line="A", department="WAF/LB")
    _combo(zone="external", line="A", department="WAF/LB")
    ops.apply_rows("zones", _rows(("internal", "Internal"), ("external", "external")))
    assert missing_combos() == []


def test_rename_that_changes_nothing_touches_nothing(seeded):
    aid = _appl("a1", zone="internal")
    rep = ops.apply_rows("zones", _rows(("internal", "internal"), ("external", "external")))
    assert rep.touched == 0 and rep.renamed == []
    assert Appliance.query.get(aid).zone == "internal"


def test_rename_to_empty_is_refused_as_a_disguised_delete(seeded):
    """Blanking the field would skip the reference check that makes deletes
    safe, and delete is exactly what it means."""
    aid = _appl("a1", zone="internal")
    with pytest.raises(ops.ClassificationError, match="empty"):
        ops.apply_rows("zones", _rows(("internal", ""), ("external", "external")))
    assert Appliance.query.get(aid).zone == "internal"
    assert store.classification("zones") == ["internal", "external"]


# --------------------------------------------------------------------------- #
#  deletes must decide what happens to the references                          #
# --------------------------------------------------------------------------- #
def test_delete_of_a_referenced_value_is_refused_without_a_decision(seeded):
    _appl("a1", zone="internal")
    with pytest.raises(ops.ClassificationError, match="1 appliance"):
        ops.apply_rows("zones", _rows(("internal", "", "delete", "", False),
                                      ("external", "external")))
    assert store.classification("zones") == ["internal", "external"]


def test_delete_of_an_unreferenced_value_needs_no_decision(seeded):
    rep = ops.apply_rows("zones", _rows(("internal", "", "delete", "", False),
                                        ("external", "external")))
    assert rep.deleted == ["internal"]
    assert store.classification("zones") == ["external"]


def test_delete_with_clear_unsets_the_references(seeded):
    aid = _appl("a1", zone="internal")
    ops.apply_rows("zones", _rows(("internal", "", "delete", "", True),
                                  ("external", "external")))
    assert Appliance.query.get(aid).zone is None
    assert store.classification("zones") == ["external"]


def test_delete_with_reassign_moves_the_references(seeded):
    aid = _appl("a1", zone="internal")
    ops.apply_rows("zones", _rows(("internal", "", "delete", "external", True),
                                  ("external", "external")))
    assert Appliance.query.get(aid).zone == "external"


def test_an_untouched_dropdown_never_reads_as_clear_them(seeded):
    """"Clear them" and "not decided" both carry an empty target. If the flag
    is dropped, a default dropdown silently wipes every reference."""
    _appl("a1", zone="internal")
    undecided = ops.Row(orig="internal", value="", action="delete",
                        reassign="", decided=False)
    with pytest.raises(ops.ClassificationError):
        ops.apply_rows("zones", [undecided, ops.Row(orig="external", value="external")])


def test_reassign_target_must_survive_the_same_save(seeded):
    _appl("a1", zone="internal")
    with pytest.raises(ops.ClassificationError, match="not in the catalog"):
        ops.apply_rows("zones", _rows(("internal", "", "delete", "external", True),
                                      ("external", "", "delete", "", True)))


def test_a_row_the_form_never_sends_back_still_faces_the_reference_check(seeded):
    """The textarea's behaviour: a value simply vanishes from the submission.
    Routing it through the delete path is what stops that from orphaning rows."""
    _appl("a1", zone="internal")
    with pytest.raises(ops.ClassificationError, match="1 appliance"):
        ops.apply_rows("zones", _rows(("external", "external")))


# --------------------------------------------------------------------------- #
#  combo collisions                                                            #
# --------------------------------------------------------------------------- #
def test_reassign_absorbs_a_combo_that_would_duplicate_a_scope(seeded):
    """Two combos on one triple make missing_combos() consider the pair
    satisfied forever, so the duplicate never surfaces anywhere."""
    dup = _combo(zone="internal", line="A", department="WAF/LB")
    _combo(zone="external", line="A", department="WAF/LB")
    rep = ops.apply_rows("zones", _rows(("internal", "", "delete", "external", True),
                                        ("external", "external")))
    assert rep.baselines_absorbed == 1
    assert Baseline.query.get(dup) is None


def test_absorbing_never_drops_template_assignments(seeded):
    from app.models import BaselineTemplate
    src = _combo(zone="internal", line="A", department="WAF/LB")
    dst = _combo(zone="external", line="A", department="WAF/LB")
    db.session.add(BaselineTemplate(baseline_id=src, template_id=4242))
    db.session.commit()
    with pytest.raises(ops.ClassificationError, match="template"):
        ops.apply_rows("zones", _rows(("internal", "", "delete", "external", True),
                                      ("external", "external")))
    assert Baseline.query.get(src) is not None
    assert Baseline.query.get(dst) is not None
    assert store.classification("zones") == ["internal", "external"]


# --------------------------------------------------------------------------- #
#  validation runs to completion before anything is written                    #
# --------------------------------------------------------------------------- #
def test_a_refusal_in_one_catalog_leaves_the_others_untouched(seeded):
    """AppSetting.set() commits on its own, so validating-then-writing one
    catalog at a time would leave zones saved and lines refused."""
    _appl("a1", line="A")
    with pytest.raises(ops.ClassificationError, match="lines"):
        ops.apply_all({
            "zones": _rows(("internal", "Internal"), ("external", "external")),
            "lines": _rows(("A", "", "delete", "", False), ("P", "P")),
            "departments": _rows(("WAF/LB", "WAF/LB")),
        })
    db.session.rollback()
    assert store.classification("zones") == ["internal", "external"]


def test_duplicate_values_are_refused_by_name(seeded):
    """save_classification() drops the second one, so without this the
    operator types two values, sees one, and is never told which."""
    with pytest.raises(ops.ClassificationError, match="twice"):
        ops.apply_rows("zones", _rows(("internal", "Internal"), ("external", "internal")))


def test_duplicates_are_caught_across_case(seeded):
    with pytest.raises(ops.ClassificationError, match="twice"):
        ops.apply_rows("zones", _rows(("internal", "internal"), ("external", "INTERNAL")))


def test_swapping_two_values_in_one_save_is_refused(seeded):
    """A->B then B->A applies sequentially: the second move sweeps up the
    references the first just placed, and both sets land on one value."""
    _appl("a1", zone="internal")
    _appl("a2", zone="external")
    with pytest.raises(ops.ClassificationError, match="two steps"):
        ops.apply_rows("zones", _rows(("internal", "external"),
                                      ("external", "internal")))


def test_editing_a_value_someone_else_already_changed_is_refused(seeded):
    """Two admins on this page at once: the stale form would otherwise
    resurrect a value that was removed a second ago."""
    with pytest.raises(ops.ClassificationError, match="no longer in the catalog"):
        ops.apply_rows("zones", _rows(("dmz", "DMZ"), ("internal", "internal"),
                                      ("external", "external")))


def test_an_unknown_action_is_refused(seeded):
    with pytest.raises(ops.ClassificationError, match="action"):
        ops.apply_rows("zones", _rows(("internal", "internal", "purge", "", False),
                                      ("external", "external")))


def test_adding_a_value_leaves_every_reference_alone(seeded):
    aid = _appl("a1", zone="internal")
    rep = ops.apply_rows("zones", _rows(("internal", "internal"),
                                        ("external", "external"), ("", "dmz")))
    assert rep.added == ["dmz"] and rep.touched == 0
    assert Appliance.query.get(aid).zone == "internal"
    assert store.classification("zones") == ["internal", "external", "dmz"]


def test_lines_and_departments_cascade_on_their_own_columns(seeded):
    """The field mapping is the one thing that, if wrong, moves the RIGHT
    number of rows on the WRONG column -- a report that looks perfect."""
    aid = _appl("a1", zone="internal", line="A", department="WAF/LB")
    ops.apply_rows("lines", _rows(("A", "Alpha"), ("P", "P")))
    a = Appliance.query.get(aid)
    assert (a.line, a.zone, a.department) == ("Alpha", "internal", "WAF/LB")
    ops.apply_rows("departments", _rows(("WAF/LB", "Edge"),))
    a = Appliance.query.get(aid)
    assert (a.department, a.line, a.zone) == ("Edge", "Alpha", "internal")


def test_segments_survive_two_axes_moving_in_one_save(seeded):
    """Segments are ONE json blob shared by all three axes. Writing it per
    axis makes the second write clobber the first."""
    store.save_segments([{"name": "s1", "zone": "internal", "line": "A",
                          "department": "WAF/LB", "cidr": "192.0.2.0/24",
                          "interface": "port1", "gateway": "", "note": ""}])
    ops.apply_all({
        "zones": _rows(("internal", "Internal"), ("external", "external")),
        "lines": _rows(("A", "Alpha"), ("P", "P")),
        "departments": _rows(("WAF/LB", "WAF/LB")),
    })
    seg = store.segments()[0]
    assert (seg["zone"], seg["line"], seg["department"]) == ("Internal", "Alpha", "WAF/LB")
