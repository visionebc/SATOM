"""Guards for corroborated disappearances.

Written 2026-09-17, after the operator asked why a comparison kept reporting an
object as absent when a sweep HAD asked the build about it. The page was
right — and it could not tell that reading apart from its opposite, "the path
this catalogue holds is wrong for that firmware line". Both produce the same
measured rejection and they need opposite work.

What must never rot here, in the order it would:

1. The **rule**. Its whole value is the case it refuses: a second source that
   shows nothing is not a second source that says no. Widen that one branch and
   every uncorroborated guess is promoted to a fact, silently, on a page that
   still renders perfectly.
2. The **bucket mapping**, because ``no_block`` is a datum and ``unknown`` is
   the absence of one, and a product that already invented ~96 phantom removals
   by folding those two has proved it can do it again.
3. The **ledger**'s treatment of a row it has just created — the branch that
   handles a brand-new finding is the one whose default is not applied yet.
4. The **severity split** in the alert engine: a correct measurement of the
   firmware and an accusation against our own catalogue must not arrive at the
   same level, or the family gets muted before the second one ever fires.
"""
from datetime import datetime, timedelta

import pytest

from app.services import absence_corroboration as corr


# ---------------------------------------------------------------------------
# 1. the rule
# ---------------------------------------------------------------------------
#: ``(second_now, second_before) -> state``. A table rather than four asserts:
#: the interesting content of this function is the SHAPE of the mapping, and a
#: table makes an added-or-removed branch visible as a diff.
_RULE = {
    (corr.SRC_PRESENT, corr.SRC_PRESENT): corr.STATE_CONTRADICTED,
    (corr.SRC_PRESENT, corr.SRC_ABSENT): corr.STATE_CONTRADICTED,
    (corr.SRC_PRESENT, corr.SRC_SILENT): corr.STATE_CONTRADICTED,
    (corr.SRC_PRESENT, corr.SRC_INAPPLICABLE): corr.STATE_CONTRADICTED,
    (corr.SRC_ABSENT, corr.SRC_PRESENT): corr.STATE_CONFIRMED,
    (corr.SRC_ABSENT, corr.SRC_ABSENT): corr.STATE_UNCORROBORATED,
    (corr.SRC_ABSENT, corr.SRC_SILENT): corr.STATE_UNCORROBORATED,
    (corr.SRC_ABSENT, corr.SRC_INAPPLICABLE): corr.STATE_UNCORROBORATED,
    (corr.SRC_SILENT, corr.SRC_PRESENT): corr.STATE_UNMEASURED,
    (corr.SRC_SILENT, corr.SRC_ABSENT): corr.STATE_UNMEASURED,
    (corr.SRC_SILENT, corr.SRC_SILENT): corr.STATE_UNMEASURED,
    (corr.SRC_SILENT, corr.SRC_INAPPLICABLE): corr.STATE_UNMEASURED,
    (corr.SRC_INAPPLICABLE, corr.SRC_PRESENT): corr.STATE_UNCORROBORATED,
    (corr.SRC_INAPPLICABLE, corr.SRC_ABSENT): corr.STATE_UNCORROBORATED,
    (corr.SRC_INAPPLICABLE, corr.SRC_SILENT): corr.STATE_UNCORROBORATED,
    (corr.SRC_INAPPLICABLE, corr.SRC_INAPPLICABLE): corr.STATE_UNCORROBORATED,
}


@pytest.mark.parametrize("pair,expected", sorted(_RULE.items()))
def test_the_rule_is_exactly_this_table(pair, expected):
    now, before = pair
    assert corr.corroborate(second_now=now, second_before=before) == expected


def test_a_negative_now_needs_a_positive_before_to_conclude():
    """THE lock. Without it the module claims proof from one source's silence.

    Stated as its own guard rather than trusted to the table above because the
    table can be regenerated from the implementation by anybody tidying up,
    and this sentence cannot: it names the reason. An empty-but-existing table
    still answers over REST, so the rejection excludes the empty-table story —
    but only the earlier block proves the object was ever there to lose.
    """
    assert corr.corroborate(second_now=corr.SRC_ABSENT,
                            second_before=corr.SRC_PRESENT) == corr.STATE_CONFIRMED
    for before in (corr.SRC_ABSENT, corr.SRC_SILENT, corr.SRC_INAPPLICABLE):
        assert corr.corroborate(second_now=corr.SRC_ABSENT,
                                second_before=before) != corr.STATE_CONFIRMED


def test_exactly_one_state_is_actionable():
    states = [corr.STATE_CONFIRMED, corr.STATE_CONTRADICTED,
              corr.STATE_UNCORROBORATED, corr.STATE_UNMEASURED]
    assert [s for s in states if corr.is_actionable(s)] == [corr.STATE_CONTRADICTED]


def test_every_state_has_a_distinct_label_and_a_next_step():
    seen = set()
    for state, entry in corr.STATE_LABEL.items():
        assert len(entry) == 4, state
        text, _css, why, nxt = entry
        assert text and why and nxt, state
        assert text not in seen, "two states print the same words: %s" % state
        seen.add(text)


def test_an_unknown_state_degrades_to_the_least_claiming_label():
    """A verdict is not worth a 500, and the fallback must claim least."""
    assert corr.label("something-new") == corr.STATE_LABEL[corr.STATE_UNMEASURED]


# ---------------------------------------------------------------------------
# 2. the adapter
# ---------------------------------------------------------------------------
def test_a_dump_with_no_block_is_a_datum_and_a_missing_dump_is_not():
    """The two blanks that must never be folded together.

    ``no_block`` means a dump WAS read and does not mention the object;
    ``unknown`` means none was read. Mapping the second one to a negative is
    how a fleet with no captures at all reports every catalogue entry as gone.
    """
    assert corr.source_of({"bucket": "no_block"}) == corr.SRC_ABSENT
    assert corr.source_of({"bucket": "unknown"}) == corr.SRC_SILENT
    assert corr.source_of(None) == corr.SRC_SILENT
    assert corr.source_of({}) == corr.SRC_SILENT


def test_a_runtime_readout_can_never_corroborate_anything():
    """Distinct from silence: no capture will ever fix it, so the advice differs."""
    assert corr.source_of({"bucket": "monitor_only"}) == corr.SRC_INAPPLICABLE
    assert corr.corroborate(second_now=corr.SRC_INAPPLICABLE,
                            second_before=corr.SRC_PRESENT) != corr.STATE_CONFIRMED


def test_every_bucket_that_holds_a_block_counts_as_present():
    for bucket in ("both", "near_match", "cli_only"):
        assert corr.source_of({"bucket": bucket}) == corr.SRC_PRESENT


def test_the_bucket_vocabulary_is_the_one_cli_coverage_publishes():
    """A mapping keyed on strings the other module renamed is a silent SILENT."""
    from app.services import cli_coverage as cc
    for bucket in (cc.BUCKET_BOTH, cc.BUCKET_NEAR, cc.BUCKET_CLI_ONLY,
                   cc.BUCKET_NO_BLOCK, cc.BUCKET_MONITOR, cc.PROV_UNKNOWN):
        assert corr.source_of({"bucket": bucket}) != corr.SRC_SILENT or \
            bucket == cc.PROV_UNKNOWN


def test_only_a_near_match_offers_an_alternative_spelling():
    assert corr.proposed_path({"bucket": "near_match", "path": "config x y"}) \
        == "config x y"
    for bucket in ("both", "cli_only", "no_block", "monitor_only", "unknown"):
        assert corr.proposed_path({"bucket": bucket, "path": "config x y"}) == ""
    assert corr.proposed_path(None) == ""


# ---------------------------------------------------------------------------
# 3. the ledger
# ---------------------------------------------------------------------------
def _finding(**over):
    base = {"product": "fortiweb", "name": "user_group", "urn": "/api/x",
            "base_scope": "7.6", "target_scope": "8.0",
            "state": corr.STATE_CONFIRMED, "cli_base": "both",
            "cli_target": "no_block", "cli_device": "fw17",
            "cli_captured_at": "2026-09-17", "proposed_path": "",
            "api_detail": ""}
    base.update(over)
    return base


@pytest.fixture()
def ledger(app, monkeypatch):
    from app.services import absence_record as ar
    with app.app_context():
        yield ar


def _record(ar, monkeypatch, findings):
    monkeypatch.setattr(ar, "evaluate", lambda product: list(findings))
    return ar.record("fortiweb")


def test_a_brand_new_corroborated_finding_is_acknowledged(ledger, monkeypatch):
    """The branch whose column default has NOT been applied yet.

    A row created in the same loop carries ``None`` in ``correction`` until the
    INSERT runs, so a membership test written against the default alone is
    False for precisely the rows it exists to treat — and the code still reads
    as though it handles them. Caught in production on the first live run.
    """
    from app.models_lifecycle import CORR_APPLIED, ObjectAbsence
    summary = _record(ledger, monkeypatch, [_finding()])
    assert summary["created"] == 1 and summary["persisted"]
    row = ObjectAbsence.query.one()
    assert row.correction == CORR_APPLIED
    assert row.reviewed_by == "system" and row.reviewed_at is not None


def test_re_proving_updates_the_row_and_never_mints_a_second(ledger, monkeypatch):
    from app.models_lifecycle import ObjectAbsence
    _record(ledger, monkeypatch, [_finding()])
    first = ObjectAbsence.query.one()
    born, count = first.first_seen_at, first.seen_count
    _record(ledger, monkeypatch, [_finding()])
    rows = ObjectAbsence.query.all()
    assert len(rows) == 1
    assert rows[0].first_seen_at == born
    assert rows[0].seen_count == count + 1


def test_a_contradiction_is_never_acknowledged_automatically(ledger, monkeypatch):
    """The state that needs the human is the one this would replace."""
    from app.models_lifecycle import CORR_APPLIED, CORR_PROPOSED, ObjectAbsence
    _record(ledger, monkeypatch, [_finding(state=corr.STATE_CONTRADICTED,
                                           cli_target="near_match",
                                           proposed_path="config user grp")])
    row = ObjectAbsence.query.one()
    assert row.correction == CORR_PROPOSED
    assert row.correction != CORR_APPLIED
    assert row.reviewed_by == ""
    assert row.proposed_path == "config user grp"


def test_a_contradiction_with_no_alternative_spelling_stays_open(
        ledger, monkeypatch):
    """The hole the first version of the guard above could not see.

    A contradiction only carries a candidate path when the dump spells it
    differently; a ``both`` or ``cli_only`` contradiction carries none. The
    branch that files a proposal is guarded on the path, so a pathless
    contradiction falls through to the automatic pass -- and would be closed
    without anybody looking at the one verdict that names work we owe.
    Surfaced by mutation 8, which the path-carrying case survived.
    """
    from app.models_lifecycle import CORR_APPLIED, CORR_NONE, ObjectAbsence
    _record(ledger, monkeypatch, [_finding(state=corr.STATE_CONTRADICTED,
                                           cli_target="both",
                                           proposed_path="")])
    row = ObjectAbsence.query.one()
    assert row.correction == CORR_NONE
    assert row.correction != CORR_APPLIED
    assert row.reviewed_by == ""
    assert [r.name for r in ledger.actionable("fortiweb")] == [row.name]


def test_an_alternative_spelling_belongs_only_to_the_actionable_verdict():
    """Pinned on the mapping, where it is true, and not as a runtime re-check.

    A spelling is offered for exactly one bucket, and that bucket holds a
    block, so it can only ever reach the contradicted verdict. Break the
    coupling -- let a spelling come from a bucket that reads as a negative --
    and the page starts offering a fix for a finding that needs none, with no
    conditional anywhere that could notice.
    """
    for bucket in ("both", "near_match", "cli_only", "no_block",
                   "monitor_only", "unknown"):
        rec = {"bucket": bucket, "path": "config a b"}
        if not corr.proposed_path(rec):
            continue
        for before in (corr.SRC_PRESENT, corr.SRC_ABSENT, corr.SRC_SILENT,
                       corr.SRC_INAPPLICABLE):
            state = corr.corroborate(second_now=corr.source_of(rec),
                                     second_before=before)
            assert corr.is_actionable(state), (bucket, before, state)


def test_a_human_decision_survives_the_timer(ledger, monkeypatch):
    from app.models_lifecycle import CORR_DISMISSED, ObjectAbsence
    _record(ledger, monkeypatch, [_finding(state=corr.STATE_CONTRADICTED,
                                           cli_target="near_match",
                                           proposed_path="config a b")])
    row = ObjectAbsence.query.one()
    ok, _msg, _row = ledger.review(row.id, "dismiss", actor="operator")
    assert ok
    _record(ledger, monkeypatch, [_finding(state=corr.STATE_CONTRADICTED,
                                           cli_target="near_match",
                                           proposed_path="config a b")])
    row = ObjectAbsence.query.one()
    assert row.correction == CORR_DISMISSED
    assert row.reviewed_by == "operator"


def test_evidence_is_refreshed_even_on_a_row_a_human_closed(ledger, monkeypatch):
    """A ledger that froze its first answer records what we used to believe."""
    from app.models_lifecycle import ObjectAbsence
    _record(ledger, monkeypatch, [_finding(cli_device="fw17")])
    _record(ledger, monkeypatch, [_finding(cli_device="fw19",
                                           state=corr.STATE_UNCORROBORATED)])
    row = ObjectAbsence.query.one()
    assert row.cli_device == "fw19"
    assert row.state == corr.STATE_UNCORROBORATED


def test_the_automatic_pass_can_be_turned_off(ledger, monkeypatch):
    from app.models import AppSetting
    from app.models_lifecycle import CORR_APPLIED, ObjectAbsence
    AppSetting.set(ledger.K_AUTOACK, "0")
    _record(ledger, monkeypatch, [_finding()])
    assert ObjectAbsence.query.one().correction != CORR_APPLIED


def test_a_failed_commit_reports_that_nothing_was_written(ledger, monkeypatch):
    """A write that did not happen must not be reported as one.

    This is the read-only standby: the findings are real and reportable, the
    row is not. An ``[OK]`` on an origin log is how three backup holes went
    fourteen days unnoticed.
    """
    from app.extensions import db

    def _boom():
        raise RuntimeError("read-only transaction")

    monkeypatch.setattr(db.session, "commit", _boom)
    summary = _record(ledger, monkeypatch, [_finding()])
    assert summary["persisted"] is False
    assert summary["evaluated"] == 1
    assert summary["findings"]


def test_actionable_narrows_to_the_state_that_accuses_us(ledger, monkeypatch):
    _record(ledger, monkeypatch, [
        _finding(),
        _finding(name="http_auth_rule", state=corr.STATE_CONTRADICTED,
                 cli_target="near_match", proposed_path="config a b"),
    ])
    names = [r.name for r in ledger.actionable("fortiweb")]
    assert names == ["http_auth_rule"]


def test_a_finding_that_stopped_being_re_proved_falls_out_of_the_window(
        ledger, monkeypatch):
    from app.models_lifecycle import ObjectAbsence
    from app.extensions import db
    _record(ledger, monkeypatch, [_finding(name="ghost",
                                           state=corr.STATE_CONTRADICTED,
                                           cli_target="near_match",
                                           proposed_path="config a b")])
    row = ObjectAbsence.query.one()
    row.last_seen_at = datetime.utcnow() - timedelta(hours=48)
    db.session.commit()
    assert ledger.actionable("fortiweb") != []
    assert ledger.actionable("fortiweb", since_hours=6) == []


def test_line_pairs_are_adjacent_and_version_ordered(ledger):
    matrix = {"lines": {"8.0": {}, "10.0": {}, "7.6": {}, "9.2": {}}}
    assert ledger.line_pairs("fortiweb", matrix) == [
        ("7.6", "8.0"), ("8.0", "9.2"), ("9.2", "10.0")]


def test_no_cross_pair_is_asked(ledger):
    """7.6 -> 8.2 is already answered by the two adjacent questions.

    Asking it as well double-counts every object 8.0 removed, and a headline
    number that double-counts is a page the operator learns to ignore.
    """
    pairs = ledger.line_pairs("fortiweb", {"lines": {"7.6": {}, "8.0": {},
                                                     "8.2": {}}})
    assert ("7.6", "8.2") not in pairs
    assert len(pairs) == 2


def test_there_is_no_apply_verb(ledger, monkeypatch):
    """The catalogue write is refused, and refused by ABSENCE of a control.

    ``RegistryEndpoint`` is keyed without a firmware dimension and a
    contradicted row's base scope is, by construction, still served by the
    current URN — so writing the other spelling breaks the base line every
    time. A verb that always refuses teaches the operator the page is broken.
    """
    from app.models_lifecycle import ObjectAbsence
    _record(ledger, monkeypatch, [_finding(state=corr.STATE_CONTRADICTED,
                                           cli_target="near_match",
                                           proposed_path="config a b")])
    row = ObjectAbsence.query.one()
    ok, msg, _r = ledger.review(row.id, "apply", actor="operator")
    assert not ok and "apply" in msg


def test_the_refusal_says_why_it_cannot_be_written(ledger):
    """The reason names the structural limit, not a missing feature."""
    text = ledger.BLOCKED_REASON.lower()
    assert "one urn per name" in text
    assert "firmware" in text


# ---------------------------------------------------------------------------
# 4. the alert engine
# ---------------------------------------------------------------------------
def test_the_check_is_registered_and_maskable(app):
    from app.services import alert_routing as routing
    from app.services import alerts
    with app.app_context():
        assert alerts.K_CHK_CATALOG in dict(alerts._CHECKS)
        assert alerts.DEFAULTS[alerts.K_CHK_CATALOG] == "1"
        assert "catalog" in alerts.config()["checks"]
    fam = routing.family_of("catalog.registry_suspect")
    assert fam in routing.FAMILIES
    assert fam not in routing.UNFILTERABLE
    assert fam in routing.FAMILY_LABELS


def _run_check(app, monkeypatch, findings, created=1):
    from app.services import absence_record, alerts
    monkeypatch.setattr(absence_record, "record",
                        lambda product: {"product": product,
                                         "evaluated": len(findings),
                                         "created": created, "updated": 0,
                                         "persisted": True,
                                         "findings": list(findings)})
    monkeypatch.setattr(alerts, "concrete_products", lambda: ["fortiweb"])
    with app.app_context():
        return alerts._check_catalog()


def test_an_accusation_against_our_catalogue_outranks_a_firmware_fact(
        app, monkeypatch):
    """The severity split. Equal levels get the whole family muted.

    A corroborated disappearance is a correct measurement and arrives often; a
    contradiction is rare and names work SATOM must do to itself. Ship them at
    the same level and the operator silences the family before the rare one
    ever fires.
    """
    from app.services import alerts
    out = _run_check(app, monkeypatch, [
        _finding(),
        _finding(name="http_auth_rule", state=corr.STATE_CONTRADICTED,
                 cli_target="near_match", proposed_path="config user grp"),
    ])
    by_key = {f["key"]: f for f in out}
    assert by_key["catalog.registry_suspect"]["severity"] == alerts.SEV_WARNING
    assert by_key["catalog.object_gone"]["severity"] == alerts.SEV_INFO
    ranks = alerts._SEV_RANK
    assert (ranks[by_key["catalog.registry_suspect"]["severity"]]
            > ranks[by_key["catalog.object_gone"]["severity"]])


def test_the_warning_carries_the_evidence_and_the_refusal(app, monkeypatch):
    from app.services import absence_record
    out = _run_check(app, monkeypatch, [
        _finding(name="http_auth_rule", state=corr.STATE_CONTRADICTED,
                 cli_target="near_match", proposed_path="config user grp",
                 cli_device="fw17")])
    detail = next(f for f in out if f["key"] == "catalog.registry_suspect")["detail"]
    assert "http_auth_rule" in detail
    assert "config user grp" in detail
    assert "fw17" in detail
    assert absence_record.BLOCKED_REASON in detail


def test_nothing_actionable_fires_no_warning(app, monkeypatch):
    out = _run_check(app, monkeypatch, [_finding()], created=0)
    assert [f for f in out if f["severity"] == "warning"] == []
    assert [f for f in out if f["key"] == "catalog.object_gone"] == []


def test_a_ledger_that_could_not_be_written_says_so(app, monkeypatch):
    from app.services import absence_record, alerts
    monkeypatch.setattr(absence_record, "record",
                        lambda product: {"product": product, "evaluated": 1,
                                         "created": 0, "updated": 0,
                                         "persisted": False,
                                         "error": "read-only transaction",
                                         "findings": []})
    monkeypatch.setattr(alerts, "concrete_products", lambda: ["fortiweb"])
    with app.app_context():
        out = alerts._check_catalog()
    assert any(f["key"] == "catalog.error" for f in out)


def test_one_bad_product_never_sinks_the_check(app, monkeypatch):
    from app.services import absence_record, alerts

    def _boom(product):
        raise RuntimeError("matrix unreadable")

    monkeypatch.setattr(absence_record, "record", _boom)
    monkeypatch.setattr(alerts, "concrete_products", lambda: ["fortiweb"])
    with app.app_context():
        out = alerts._check_catalog()
    assert [f["key"] for f in out] == ["catalog.error"]


# ---------------------------------------------------------------------------
# 5. the page and the copy that leaves the building
# ---------------------------------------------------------------------------
def _prov(product, by_name, device="fw17"):
    from app.services.cli_coverage import Provenance
    return Provenance(product, supported=True, reason="", counts={},
                      evidence={"appliance": device, "created_at": "2026-09-17",
                                "line": "8.0"},
                      by_name=by_name, by_tokens={}, cli_only=[])


_FAKE_DELTA = {
    "base": "7.6", "target": "8.0", "base_kind": "line", "target_kind": "line",
    "endpoints_added": [{"endpoint": "added_one", "urn": "/a", "origin": "sweep",
                         "attested_on": [], "silent_on": []}],
    "endpoints_removed": [
        {"endpoint": "gone_one", "urn": "/g", "origin": "sweep",
         "attested_on": [], "silent_on": []},
        {"endpoint": "suspect_one", "urn": "/s", "origin": "sweep",
         "attested_on": [], "silent_on": []},
    ],
    "endpoints_unknown": [{"endpoint": "unknown_one", "urn": "/u",
                           "origin": "sweep", "measured_on": "7.6"}],
    "fields_changed": [], "fields_unknown": [], "fields_incomparable": [],
}


def _resolve_with_stubs(app, monkeypatch):
    from app.services import api_matrix, cli_coverage, firmware_versions
    from app.views import _apiversions as V

    matrix = {"product": "fortiweb", "lines": {"7.6": {}, "8.0": {}},
              "versions": {}, "fleet_lines": [], "fleet_versions": [],
              "witnesses": [], "notes": [], "built_at": "", "sweepable": True}
    monkeypatch.setattr(api_matrix, "load", lambda p, **k: dict(matrix))
    monkeypatch.setattr(firmware_versions, "overlay", lambda p, m: m)
    monkeypatch.setattr(api_matrix, "diff",
                        lambda p, b, t, matrix=None: {
                            k: ([dict(x) for x in v] if isinstance(v, list) else v)
                            for k, v in _FAKE_DELTA.items()})
    by_name = {
        # corroborated: the dump had it on 7.6 and does not on 8.0
        "gone_one": {"bucket": "no_block", "why": "", "path": "",
                     "catalog": "gone_one", "urn": "/g", "configured": False},
        # contradicted: the 8.0 dump still prints a block, spelled differently
        "suspect_one": {"bucket": "near_match", "why": "",
                        "path": "config suspect one", "catalog": "suspect_one",
                        "urn": "/s", "configured": True},
    }
    base_names = {k: dict(v, bucket="both") for k, v in by_name.items()}
    monkeypatch.setattr(
        cli_coverage, "provenance",
        lambda product, backup_id=None, line="", version="":
        _prov(product, base_names if line == "7.6" else by_name,
              device="fw15" if line == "7.6" else "fw17"))
    with app.test_request_context("/?base=7.6&target=8.0"):
        return V._resolved("fortiweb")


def test_only_the_bucket_that_claims_a_disappearance_is_judged(app, monkeypatch):
    """Every other bucket is a gap or a delta and asked no such question.

    Stamping a verdict on them would answer for rows that never made the
    claim — the same fabrication as printing an evidence kind for a record
    that never carried one, or a URN for an object that has none.
    """
    with app.app_context():
        R = _resolve_with_stubs(app, monkeypatch)
    delta = R["delta"]
    for bucket in ("endpoints_added", "endpoints_unknown", "fields_changed",
                   "fields_unknown", "fields_incomparable"):
        for row in delta.get(bucket) or []:
            assert "corroboration" not in row, bucket
    assert all("corroboration" in r for r in delta["endpoints_removed"])


def test_the_page_reaches_both_verdicts_from_real_provenance(app, monkeypatch):
    with app.app_context():
        R = _resolve_with_stubs(app, monkeypatch)
    got = {r["endpoint"]: r["corroboration"] for r in R["delta"]["endpoints_removed"]}
    assert got == {"gone_one": corr.STATE_CONFIRMED,
                   "suspect_one": corr.STATE_CONTRADICTED}


def test_the_alternative_spelling_travels_only_with_the_verdict_it_serves(
        app, monkeypatch):
    """On a corroborated disappearance there is no fix to offer."""
    with app.app_context():
        R = _resolve_with_stubs(app, monkeypatch)
    rows = {r["endpoint"]: r for r in R["delta"]["endpoints_removed"]}
    assert rows["suspect_one"]["proposed_path"] == "config suspect one"
    assert rows["gone_one"]["proposed_path"] == ""


def test_the_counter_counts_what_the_rows_say(app, monkeypatch):
    with app.app_context():
        R = _resolve_with_stubs(app, monkeypatch)
    delta = R["delta"]
    assert sum(delta["corroboration_counts"].values()) == \
        len(delta["endpoints_removed"])
    assert delta["corroboration_actionable"] == 1


def test_the_export_keeps_the_gap_column_where_the_pdf_looks_for_it(app):
    """An inserted column renumbers every later one, and the PDF addresses
    cells by index. The new column is appended, never inserted."""
    from app.views import _apiversions as V
    cols = V._columns("7.6", "8.0", None, None)
    heads = [h for h, _why in cols]
    assert heads[17].startswith("why the evidence")
    assert heads[18] == "corroboration"
    assert len(cols) == 19


def test_the_pdf_prints_every_column_exactly_once_bar_the_join_key(app):
    from app.views import _apiversions as V
    cols = V._columns("7.6", "8.0", None, None)
    used = list(V._PDF_TABLE_A) + list(V._PDF_TABLE_B)
    assert sorted(set(used)) == list(range(len(cols)))
    twice = [i for i in set(used) if used.count(i) > 1]
    assert twice == [2], "only the name may repeat, as the join key"
    assert len(V._PDF_TABLE_A) <= 10 and len(V._PDF_TABLE_B) <= 10


def test_the_legend_documents_the_new_column_in_its_own_terms(app):
    from app.views import _apiversions as V
    why = dict(V._columns("7.6", "8.0", None, None))["corroboration"]
    low = why.lower()
    assert "second source" in low
    # It must say what a blank means, or a spreadsheet reads every non-gone
    # row as an uncorroborated one.
    assert "blank" in low


def test_the_unmeasured_verdict_renders_as_text_and_not_as_a_badge():
    """Rendered, not grepped.

    A guard that reads the macro's SOURCE survives a mutation that disables the
    branch entirely — the strings stay in the file while the rendered page says
    nothing. Caught here on 2026-09-17 in a guard of exactly that shape.
    """
    import re
    import jinja2
    src = open("app/templates/registry/versions.html", encoding="utf-8").read()
    start = src.index("{% macro corroboration_badge")
    end = src.index("{%- endmacro %}", start) + len("{%- endmacro %}")
    macro = jinja2.Environment().from_string(
        src[start:end]).module.corroboration_badge
    badged = str(macro({"corroboration_label": corr.label(corr.STATE_CONTRADICTED),
                        "proposed_path": "config a b"}))
    muted = str(macro({"corroboration_label": corr.label(corr.STATE_UNMEASURED),
                       "proposed_path": ""}))
    assert "fw-badge" in badged and corr.label(corr.STATE_CONTRADICTED)[0] in badged
    assert "config a b" in badged
    assert "fw-badge" not in muted
    assert re.search(r"text-muted", muted)
    # A row the view never judged prints nothing at all.
    assert str(macro({})).strip() == ""
