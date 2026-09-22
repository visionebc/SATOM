"""Guards for ``services.version_compat`` — "does this config fit that API?".

The defect class these exist against is a SILENT one: a cmdb POST carrying a
field the destination build does not understand answers **200 and discards
it**, so the copy looks complete in the destination GUI. Nothing raises,
nothing logs, and the only thing that can catch it is a comparison that
refuses to render absence of evidence as a green light.
"""
import pytest

from app.services import api_matrix as am
from app.services import version_compat as vc


# --------------------------------------------------------------------------
#  A matrix built by hand, so every guard states its own evidence.
# --------------------------------------------------------------------------
def _matrix():
    return {
        "product": "fortiweb",
        "lines": {
            "7.6": {"measured_versions": ["7.6.8"],
                    "endpoints": {"widget": {"verdict": "ok",
                                             "fields": ["name", "old-only", "shared"]}},
                    "objects": {}},
            "8.0": {"measured_versions": ["8.0.5"],
                    "endpoints": {"widget": {"verdict": "ok",
                                             "fields": ["name", "shared", "brand-new"]}},
                    "objects": {}},
        },
        "versions": {
            "7.6.8": {"endpoints": {
                "widget": {"verdict": "ok",
                           "fields": ["name", "old-only", "shared",
                                      "shared_val", "q_type", "sz_rows"]},
                "goner": {"verdict": "ok", "fields": ["name", "x"]},
                "blindspot": {"verdict": "ok", "fields": []},
            }, "objects": {}},
            "8.0.5": {"endpoints": {
                "widget": {"verdict": "ok",
                           "fields": ["name", "shared", "shared_val",
                                      "brand-new", "q_type", "sz_rows"]},
                "goner": {"verdict": "absent", "fields": []},
                "blindspot": {"verdict": "ok", "fields": []},
            }, "objects": {}},
        },
    }


class _Appl:
    def __init__(self, name="box", fw="7.6.8", kind="fortiweb", ident=1):
        self.name, self.fw_version, self.kind, self.id = name, fw, kind, ident


# --------------------------------------------------------------------------
#  split_fields — the transport echoes
# --------------------------------------------------------------------------
def test_a_val_companion_is_not_counted_as_a_second_field():
    authored, ignored = vc.split_fields(["http2", "http2_val"])
    assert authored == ["http2"]
    assert ignored == ["http2_val"]


def test_an_orphan_val_field_is_kept_because_its_base_was_never_seen():
    """The rule is "strip the echo", not "strip anything ending in _val".

    A ``_val`` with no base name is a field this evidence has never seen
    whole, and swallowing it would hide exactly the surprise worth reporting.
    """
    authored, ignored = vc.split_fields(["lonely_val"])
    assert authored == ["lonely_val"]
    assert ignored == []


def test_the_subtable_census_counter_is_transport_and_is_reported_as_stripped():
    authored, ignored = vc.split_fields(["name", "sz_public-ip-list", "q_ref_string"])
    assert authored == ["name"]
    assert set(ignored) == {"sz_public-ip-list", "q_ref_string"}


def test_what_was_stripped_travels_with_the_answer():
    """A wrong call about what counts as transport has to be VISIBLE."""
    r = vc.compare_object("fortiweb", "8.0.5", "widget",
                          ["name", "shared", "shared_val", "q_type"],
                          source_version="7.6.8", matrix=_matrix())
    assert "shared_val" in r["ignored"] and "q_type" in r["ignored"]


# --------------------------------------------------------------------------
#  the six verdicts
# --------------------------------------------------------------------------
def test_same_build_is_its_own_verdict_and_not_a_flavour_of_ok():
    r = vc.compare_object("fortiweb", "7.6.8", "widget", ["name"],
                          source_version="7.6.8", matrix=_matrix())
    assert r["state"] == vc.STATE_SAME
    assert r["state"] != vc.STATE_OK
    assert r["level"] == "ok"


def test_a_field_with_no_evidence_on_the_target_is_reported_as_dropped():
    r = vc.compare_object("fortiweb", "8.0.5", "widget",
                          ["name", "shared", "old-only"],
                          source_version="7.6.8", matrix=_matrix())
    assert r["state"] == vc.STATE_DROPPED
    assert r["dropped"] == ["old-only"]


def test_the_dropped_reason_says_the_write_succeeds_because_that_is_the_trap():
    r = vc.compare_object("fortiweb", "8.0.5", "widget", ["old-only"],
                          source_version="7.6.8", matrix=_matrix())
    assert "200" in r["reason"]


def test_an_endpoint_the_target_rejects_is_absent_and_that_one_blocks():
    r = vc.compare_object("fortiweb", "8.0.5", "goner", ["name", "x"],
                          source_version="7.6.8", matrix=_matrix())
    assert r["state"] == vc.STATE_ABSENT
    assert r["level"] == "block"


def test_only_absent_blocks_because_only_absent_is_the_appliance_talking():
    """Everything else is an inference off a field census. A census that runs
    thin one night must not wall off legitimate clones."""
    assert vc.LEVEL_FOR[vc.STATE_ABSENT] == "block"
    for state in (vc.STATE_DROPPED, vc.STATE_BLIND, vc.STATE_UNMEASURED):
        assert vc.LEVEL_FOR[state] == "warn", state


def test_an_empty_collection_is_blind_and_never_renders_as_ok():
    """The measured trap: a build with no rows of an object records no fields
    for it, and "nothing contradicted the payload" is not "it is served"."""
    r = vc.compare_object("fortiweb", "8.0.5", "blindspot", ["anything"],
                          source_version="7.6.8", matrix=_matrix())
    assert r["state"] == vc.STATE_BLIND
    assert r["state"] != vc.STATE_OK
    assert r["dropped"] == []


def test_a_build_with_no_evidence_is_unmeasured_and_is_not_answered_from_its_line():
    r = vc.compare_object("fortiweb", "8.0.6", "widget", ["name"],
                          source_version="7.6.8", matrix=_matrix())
    assert r["state"] == vc.STATE_UNMEASURED


def test_every_field_served_is_ok():
    r = vc.compare_object("fortiweb", "8.0.5", "widget", ["name", "shared"],
                          source_version="7.6.8", matrix=_matrix())
    assert r["state"] == vc.STATE_OK
    assert r["dropped"] == []


# --------------------------------------------------------------------------
#  new fields — the half the operator can ACT on
# --------------------------------------------------------------------------
def test_new_fields_are_the_ones_the_target_gained_over_the_source():
    r = vc.compare_object("fortiweb", "8.0.5", "widget", ["name", "shared"],
                          source_version="7.6.8", matrix=_matrix())
    assert r["new_fields"] == ["brand-new"]
    assert r["new_fields_state"] == "measured"


def test_a_gain_the_payload_already_carries_is_not_offered_as_new():
    r = vc.compare_object("fortiweb", "8.0.5", "widget",
                          ["name", "shared", "brand-new"],
                          source_version="7.6.8", matrix=_matrix())
    assert r["new_fields"] == []
    assert r["new_fields_present"] == ["brand-new"]


def test_gains_are_indeterminate_without_a_source_and_that_is_not_an_empty_list():
    """``[]`` beside a populated list reads as "this object gained nothing"."""
    r = vc.compare_object("fortiweb", "8.0.5", "widget", ["name"],
                          matrix=_matrix())
    assert r["new_fields"] == []
    assert r["new_fields_state"] == "unmeasured"
    assert "cannot say" in r["new_fields_reason"]


def test_gains_are_indeterminate_when_the_target_records_no_fields():
    r = vc.compare_object("fortiweb", "8.0.5", "blindspot", ["x"],
                          source_version="7.6.8", matrix=_matrix())
    assert r["new_fields_state"] == "unmeasured"


def test_gains_are_indeterminate_when_the_SOURCE_records_no_fields():
    """Without a baseline there is nothing to call new. Treating an
    unmeasured source as an EMPTY one would offer every field the target
    serves as a fresh gain — a page full of invented news."""
    m = _matrix()
    m["versions"]["7.6.8"]["endpoints"]["widget"]["fields"] = []
    r = vc.compare_object("fortiweb", "8.0.5", "widget", ["name"],
                          source_version="7.6.8", matrix=m)
    assert r["new_fields"] == []
    assert r["new_fields_state"] == "unmeasured"
    assert "no baseline" in r["new_fields_reason"]


def test_a_gained_val_echo_is_not_offered_as_a_new_field():
    m = _matrix()
    m["versions"]["8.0.5"]["endpoints"]["widget"]["fields"].append("brand-new_val")
    r = vc.compare_object("fortiweb", "8.0.5", "widget", ["name", "shared"],
                          source_version="7.6.8", matrix=m)
    assert r["new_fields"] == ["brand-new"]


# --------------------------------------------------------------------------
#  rollup
# --------------------------------------------------------------------------
def test_the_rollup_takes_the_worst_verdict_not_the_commonest():
    """``goner`` sorts AFTER ``blindspot`` and ``widget`` on purpose: with the
    worst row first, "take the worst" and "take the first" are the same
    answer and the rule under test is never exercised."""
    m = _matrix()
    rep = vc.compare_many("fortiweb", "8.0.5",
                          [("widget", ["name"]), ("blindspot", ["x"]),
                           ("goner", ["name"])],
                          source_version="7.6.8", matrix=m)
    assert rep["rows"][0]["key"] != "goner"
    assert rep["state"] == vc.STATE_ABSENT
    assert rep["level"] == "block"


def test_unmeasured_outranks_blind_because_it_is_the_weaker_footing():
    assert (vc.SEVERITY.index(vc.STATE_UNMEASURED)
            < vc.SEVERITY.index(vc.STATE_BLIND))
    assert vc.worst([vc.STATE_BLIND, vc.STATE_UNMEASURED]) == vc.STATE_UNMEASURED


def test_an_absent_object_is_counted_apart_from_dropped_fields():
    """It would otherwise render as ZERO fields lost — invisible in a summary
    that only totals dropped fields. Measured on fortiweb15: the 8.0.5 build
    does not serve ``web_protection_profile`` at all."""
    rep = vc.compare_many("fortiweb", "8.0.5", [("goner", ["name", "x"])],
                          source_version="7.6.8", matrix=_matrix())
    assert rep["absent_total"] == 1
    assert rep["absent_keys"] == ["goner"]
    assert rep["dropped_total"] == 0


def test_objects_whose_gains_are_unknown_are_counted_and_not_folded_into_zero():
    rep = vc.compare_many("fortiweb", "8.0.5",
                          [("widget", ["name"]), ("blindspot", ["x"])],
                          source_version="7.6.8", matrix=_matrix())
    assert rep["new_unmeasured"] == 1


def test_a_same_build_comparison_reports_no_unknown_gains():
    """There is no upgrade, so "nothing was gained" is MEASURED. Counting it
    as unknown printed 'gains unknown for 14 object(s)' directly underneath
    'same API surface' — a hole in the evidence where there is none."""
    rep = vc.compare_many("fortiweb", "7.6.8",
                          [("widget", ["name"]), ("goner", ["name"])],
                          source_version="7.6.8", matrix=_matrix())
    assert rep["state"] == vc.STATE_SAME
    assert rep["new_unmeasured"] == 0


def test_rows_of_one_key_are_merged_into_a_single_question():
    """A plan carries a dozen rows of one sub-table. Asking per row would
    multiply the same verdict across the page and hide that a field seen only
    on row 7 still has to be checked."""
    rep = vc.compare_many("fortiweb", "8.0.5",
                          [("widget", ["name"]), ("widget", ["old-only"])],
                          source_version="7.6.8", matrix=_matrix())
    assert len(rep["rows"]) == 1
    # BOTH rows' fields survive the merge. Asserting only the second one
    # passes just as happily when the later row REPLACES the earlier.
    assert rep["rows"][0]["fields"] == ["name", "old-only"]
    assert rep["rows"][0]["dropped"] == ["old-only"]


def test_an_empty_object_list_does_not_claim_a_clean_comparison():
    rep = vc.compare_many("fortiweb", "8.0.5", [], source_version="7.6.8",
                          matrix=_matrix())
    assert rep["rows"] == []
    assert rep["dropped_total"] == 0


# --------------------------------------------------------------------------
#  the two adapters
# --------------------------------------------------------------------------
def test_for_clone_asks_about_the_destinations_exact_build_never_its_line():
    """The false positive ``api_matrix`` was rebuilt to remove: the line
    rollup answering for a build it does not cover."""
    seen = {}
    real = vc.compare_many

    def spy(product, target_version, objects, **kw):
        seen["target"] = target_version
        seen["source"] = kw.get("source_version")
        return real(product, target_version, objects, **kw)

    vc.compare_many = spy
    try:
        vc.for_clone(_Appl("src", "7.6.8", ident=1),
                     _Appl("dst", "8.0.5", ident=2), [("widget", ["name"])])
    finally:
        vc.compare_many = real
    assert seen["target"] == "8.0.5"
    assert seen["source"] == "7.6.8"


def test_a_destination_with_no_firmware_is_unmeasured_and_says_which_box():
    rep = vc.for_clone(_Appl("src", "7.6.8", ident=1),
                       _Appl("nofw", "", ident=2), [("widget", ["name"])])
    assert rep["state"] == vc.STATE_UNMEASURED
    assert "nofw" in rep["reason"]
    # the early return must still carry the rollup keys its callers read
    for k in ("rows", "counts", "dropped_total", "absent_total", "new_total",
              "new_unmeasured"):
        assert k in rep, k


def test_for_upgrade_compares_the_box_against_where_it_is_going():
    seen = {}
    real = vc.compare_many

    def spy(product, target_version, objects, **kw):
        seen["target"] = target_version
        seen["source"] = kw.get("source_version")
        return real(product, target_version, objects, **kw)

    vc.compare_many = spy
    try:
        vc.for_upgrade(_Appl("box", "7.6.8"), "8.0.5", [("widget", ["name"])])
    finally:
        vc.compare_many = real
    assert (seen["target"], seen["source"]) == ("8.0.5", "7.6.8")


def test_a_build_string_with_a_build_tag_is_normalised_before_it_is_asked():
    r = vc.compare_object("fortiweb", "8.0.5,build0123(GA.F)", "widget",
                          ["name", "shared"], source_version="7.6.8",
                          matrix=_matrix())
    assert r["state"] == vc.STATE_OK
    assert r["target_version"] == "8.0.5"


# --------------------------------------------------------------------------
#  the shared accessor — one author of "which fields does this scope serve"
# --------------------------------------------------------------------------
def test_known_fields_unions_schema_and_sweep_and_names_both_origins():
    doc = {"objects": {"k": {"fields": ["a"]}},
           "endpoints": {"k": {"fields": ["b"]}}}
    fields, origins = am.known_fields(doc, "k")
    assert fields == {"a", "b"}
    assert origins == ["schema", "sweep"]


def test_known_fields_reports_no_evidence_as_empty_origins_not_as_no_fields():
    doc = {"objects": {}, "endpoints": {"k": {"fields": []}}}
    fields, origins = am.known_fields(doc, "k")
    assert fields == set()
    assert origins == []
