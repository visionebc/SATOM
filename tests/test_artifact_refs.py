"""Guards for the policy→artifact index, the file surface and the two pages.

Everything pinned here fails SILENTLY if it breaks — the page still renders, the
numbers still look like numbers, and the answer is wrong in the direction that
sends someone into a migration unprepared:

  * a walk that FAILED must never delete an edge a successful walk recorded, or
    one unreachable appliance "proves" that none of its policies need any
    artifact — a clean bill of health manufactured out of an outage;
  * a walk that SUCCEEDED must delete the edges it no longer produces, or the
    index only ever grows and an artifact looks used forever after one
    historical reference;
  * "walked, needs nothing" and "never walked" must not render the same, since
    the first clears a migration and the second means nobody looked;
  * a missing artifact of one of the three unreadable kinds is UNRECOVERABLE,
    not merely absent, and the two lead to different work;
  * a bounded sweep must report its remainder, or a truncated run reads exactly
    like a complete one;
  * content that is not clean UTF-8 must not be editable in a textarea, or the
    save writes U+FFFD over the real bytes and the file still looks fine;
  * deleting one version must not unlink a blob another version still names.

No device, no network: the walk itself is stubbed, because what is under test is
the bookkeeping around it, not the clone planner (which has its own suites).
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta

import pytest


# --- helpers ----------------------------------------------------------------
def _art(kind="xml_schema", name="xsd-order", urn="cmdb/waf/xml-schema.file"):
    return {"kind": kind, "name": name, "urn": urn, "label": kind,
            "status": "create", "readable": False, "name_warning": ""}


@pytest.fixture()
def store(app, tmp_path, monkeypatch):
    """App context with the blob store redirected into the test's tmp dir."""
    monkeypatch.setenv("SATOM_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    with app.app_context():
        yield


# ── the index: what a successful and a failed walk each do ───────────────────
def test_a_failed_walk_never_deletes_the_edges_a_good_one_recorded(store):
    """The false all-clear. An appliance that went down must not be able to
    report that none of its policies need any file-backed object."""
    from app.services import artifact_refs as ar
    from app.models_artifact_refs import WafArtifactRef

    ar.record(1, "pol-a", [_art()])
    assert WafArtifactRef.query.count() == 1

    ar.record_failure(1, "pol-a", "ConnectError: device unreachable")

    assert WafArtifactRef.query.count() == 1, (
        "a failed walk deleted a previously observed edge")
    cov = ar.policy_coverage(1, "pol-a")
    assert cov["scanned"] is False
    assert cov["ready"] is False
    assert "unreachable" in cov["scan_error"]


def test_a_successful_walk_drops_the_edges_it_no_longer_produces(store):
    """Otherwise the index grows monotonically and every artifact looks used
    forever after a single historical reference."""
    from app.services import artifact_refs as ar
    from app.models_artifact_refs import WafArtifactRef

    ar.record(1, "pol-a", [_art(name="xsd-order"), _art(name="xsd-legacy")])
    assert WafArtifactRef.query.count() == 2

    ar.record(1, "pol-a", [_art(name="xsd-order")])

    names = {r.name for r in WafArtifactRef.query.all()}
    assert names == {"xsd-order"}


def test_edges_are_scoped_by_appliance_not_by_policy_name(store):
    """Two boxes can hold different content under one artifact name — that
    drift is what a clone carries. Collapsing them fabricates an all-clear."""
    from app.services import artifact_refs as ar
    from app.models_artifact_refs import WafArtifactRef

    ar.record(1, "pol-a", [_art()])
    ar.record(2, "pol-a", [_art()])

    assert WafArtifactRef.query.count() == 2
    assert len(ar.refs_for("xml_schema", "xsd-order", appliance_id=1)) == 1
    assert len(ar.refs_for("xml_schema", "xsd-order")) == 2


def test_re_recording_advances_seen_at_and_keeps_first_seen_at(store):
    from app.models import db
    from app.services import artifact_refs as ar
    from app.models_artifact_refs import WafArtifactRef

    ar.record(1, "pol-a", [_art()])
    row = WafArtifactRef.query.one()
    row.first_seen_at = row.seen_at = datetime.utcnow() - timedelta(days=30)
    db.session.commit()
    old_first = row.first_seen_at

    ar.record(1, "pol-a", [_art()])
    row = WafArtifactRef.query.one()
    assert row.first_seen_at == old_first
    assert not ar.is_stale(row.seen_at), (
        "a re-observed edge is current; staleness must be measured from "
        "seen_at, not first_seen_at")


def test_a_deleted_policy_takes_its_edges_with_it(store):
    """An index that keeps a deleted policy's requirements makes an artifact
    look used by something that is not there — the orphan report backwards."""
    from app.services import artifact_refs as ar
    from app.models_artifact_refs import WafArtifactRef, WafArtifactScan

    ar.record(1, "pol-a", [_art()])
    ar.record(1, "pol-gone", [_art(name="xsd-old")])

    ar._prune_scans(1, {"pol-a"})

    assert {r.policy_mkey for r in WafArtifactRef.query.all()} == {"pol-a"}
    assert {s.policy_mkey for s in WafArtifactScan.query.all()} == {"pol-a"}


# ── coverage: the migration answer ───────────────────────────────────────────
def test_walked_with_no_artifacts_is_ready_but_never_walked_is_not(store):
    """The distinction the second table exists for. Both produce an empty
    artifact list and they are opposite answers."""
    from app.services import artifact_refs as ar

    ar.record(1, "walked", [])
    walked = ar.policy_coverage(1, "walked")
    never = ar.policy_coverage(1, "never-walked")

    assert walked["artifacts"] == [] and never["artifacts"] == []
    assert walked["scanned"] is True and walked["ready"] is True
    assert never["scanned"] is False and never["ready"] is False


def test_a_missing_unreadable_artifact_is_reported_as_unrecoverable(store):
    """'Capture it off the source' is not available for XML Schema, WSDL or
    gRPC IDL. Presenting it as merely missing sends someone to a dead end."""
    from app.services import artifact_refs as ar
    from app.services import waf_artifacts as wa

    assert "xml_schema" in wa.UNREADABLE  # the premise, pinned
    ar.record(1, "pol-a", [_art(kind="xml_schema", name="xsd-order")])

    cov = ar.policy_coverage(1, "pol-a")
    assert cov["missing"] == 1
    assert cov["unrecoverable"] == 1
    assert cov["ready"] is False
    assert "cannot be recovered" in cov["artifacts"][0]["reason"]


def test_a_missing_readable_artifact_is_recoverable_and_says_how(store):
    from app.services import artifact_refs as ar
    from app.services import waf_artifacts as wa

    assert wa.is_readable("json_schema")
    ar.record(1, "pol-a", [_art(kind="json_schema", name="js-a",
                                urn="cmdb/waf/json-schema.file")])

    cov = ar.policy_coverage(1, "pol-a")
    assert cov["missing"] == 1
    assert cov["unrecoverable"] == 0
    assert "captured off the source device" in cov["artifacts"][0]["reason"]


def test_holding_the_content_clears_the_policy(store):
    from app.services import artifact_refs as ar
    from app.services import waf_artifacts as wa

    wa.put("xml_schema", "xsd-order", b"<xs:schema/>", appliance_id=1)
    ar.record(1, "pol-a", [_art()])

    cov = ar.policy_coverage(1, "pol-a")
    assert cov["missing"] == 0
    assert cov["ready"] is True
    assert cov["artifacts"][0]["held"] is True


def test_stats_separate_orphans_from_migration_blockers(store):
    """Held-but-unused and needed-but-unheld are different problems and must
    never be summed into one 'mismatch' count."""
    from app.services import artifact_refs as ar
    from app.services import waf_artifacts as wa

    wa.put("xml_schema", "kept-unused", b"<a/>", appliance_id=None)
    ar.record(1, "pol-a", [_art(name="never-uploaded")])

    st = ar.stats()
    assert st["orphans"] == 1
    assert st["unheld"] == 1
    assert st["edges"] == 1


# ── sweeps: bounded, oldest-first, and honest about it ───────────────────────
class _FakeReader:
    def __init__(self, policies):
        self.client = self
        self._policies = policies
        self.walked = []

    def list_with_error(self, path):
        return [{"name": n} for n in self._policies], ""


class _Appl:
    id = 7
    name = "fortiweb-lab"


def test_a_bounded_sweep_reports_what_it_did_not_walk(store, monkeypatch):
    """A run that stopped at its budget and did not say so reads exactly like a
    run that finished — and the difference is whether the coverage report
    covers the fleet."""
    from app.services import artifact_refs as ar

    monkeypatch.setattr(ar, "artifacts_of_policy",
                        lambda reader, name: ([_art(name="x-" + name)], 3))
    reader = _FakeReader(["p1", "p2", "p3", "p4", "p5"])

    res = ar.sync_appliance(_Appl(), budget=2, reader=reader)

    assert res["scanned"] == 2
    assert res["remaining"] == 3
    assert "3 still queued" in res["summary"]


def test_the_sweep_walks_never_scanned_policies_before_re_walking_old_ones(
        store, monkeypatch):
    """A fleet converges only if the unknown policies go first; re-walking the
    same box's known policies leaves the rest permanently invisible."""
    from app.services import artifact_refs as ar

    seen = []
    monkeypatch.setattr(ar, "artifacts_of_policy",
                        lambda reader, name: (seen.append(name), ([], 1))[1])
    ar.record(7, "known", [])
    reader = _FakeReader(["known", "fresh-a", "fresh-b"])

    ar.sync_appliance(_Appl(), budget=2, reader=reader)

    assert set(seen) == {"fresh-a", "fresh-b"}, (
        "the sweep re-walked an already-scanned policy while two had never "
        "been looked at")


def test_a_device_that_cannot_list_its_policies_is_an_error_not_an_empty_sweep(
        store):
    from app.services import artifact_refs as ar

    class _Dead(_FakeReader):
        def list_with_error(self, path):
            return [], "connection refused"

    res = ar.sync_appliance(_Appl(), reader=_Dead([]))
    assert res["ok"] is False
    assert "connection refused" in res["summary"]


def test_derive_policy_turns_a_crashing_walk_into_a_recorded_failure(
        store, monkeypatch):
    """The failure has to reach the database. Smoothing it into 'no artifacts'
    is the all-clear this whole module refuses to manufacture."""
    from app.services import artifact_refs as ar
    from app.models_artifact_refs import WafArtifactScan

    def _boom(reader, name):
        raise RuntimeError("cmdb is busy")

    monkeypatch.setattr(ar, "artifacts_of_policy", _boom)
    res = ar.derive_policy(object(), 1, "pol-a")

    assert res["ok"] is False
    scan = WafArtifactScan.query.one()
    assert scan.ok is False
    assert "cmdb is busy" in scan.error


def test_the_walk_is_source_only_and_never_classifies_against_a_destination(
        store, monkeypatch):
    """``collect()`` reads the source; ``plan()`` reads the DESTINATION too. A
    derivation that called plan() would hit a box the operator never named."""
    from app.services import artifact_refs as ar
    from app.services import clone

    calls = {"collect": 0, "plan": 0, "ctor": []}

    class _SpyPlanner:
        def __init__(self, src, dst):
            calls["ctor"].append((src, dst))

        def collect(self, root, mkey, **kw):
            calls["collect"] += 1
            return []

        def plan(self, *a, **kw):  # pragma: no cover - must never run
            calls["plan"] += 1
            return []

    monkeypatch.setattr(clone, "ClonePlanner", _SpyPlanner)
    sentinel = object()
    ar.artifacts_of_policy(sentinel, "pol-a")

    assert calls["collect"] == 1
    assert calls["plan"] == 0
    assert calls["ctor"] == [(sentinel, sentinel)], (
        "the planner was given a destination reader")


class _PlanItem:
    """The shape ``plan_artifacts`` reads off a real ``CloneItem``."""

    def __init__(self, urn="cmdb/waf/xml-schema.file", mkey="xsd-order",
                 status="create"):
        self.kind, self.urn, self.mkey, self.status = "object", urn, mkey, status


def test_a_preflight_donation_needs_both_a_device_and_a_policy(store):
    """An edge with no attribution is an edge nobody can re-derive.

    The plan handed in here is DELIBERATELY non-empty and would otherwise
    record: with an empty list the function returns 0 for the wrong reason
    (nothing to write), so the assertion would pass with the attribution
    check deleted — a guard that cannot fail is not a guard.
    """
    from app.services import artifact_refs as ar
    from app.models_artifact_refs import WafArtifactRef

    plan = [_PlanItem()]

    # control: the SAME plan, fully attributed, does write — otherwise the two
    # refusals below could be explained by the plan itself being unrecordable.
    assert ar.record_from_plan(1, "pol-a", plan) == 1
    assert WafArtifactRef.query.count() == 1

    assert ar.record_from_plan(0, "pol-a", plan) == 0, (
        "a donation with no appliance was recorded")
    assert ar.record_from_plan(2, "", plan) == 0, (
        "a donation with no policy was recorded")

    rows = WafArtifactRef.query.all()
    assert len(rows) == 1 and rows[0].appliance_id == 1, (
        "an unattributable donation left a row behind")


# ── the file surface: view, edit, version, diff, delete ──────────────────────
def test_content_that_is_not_clean_utf8_is_shown_but_refused_for_editing(store):
    """A textarea round-trip would save U+FFFD over the real bytes: the file
    still looks fine, still pushes, and is no longer the file."""
    from app.services import artifact_files as af

    ok, why = af.editability(b"<a>\xff\xfe</a>")
    assert ok is False
    assert "UTF-8" in why
    text, clean = af.decode(b"<a>\xff\xfe</a>")
    assert clean is False and text, "unreadable content must still be viewable"


def test_binary_content_is_refused_for_editing(store):
    from app.services import artifact_files as af

    ok, why = af.editability(b"pk\x00\x01")
    assert ok is False and "NUL" in why


def test_content_past_the_inline_limit_is_refused_for_editing(store):
    from app.services import artifact_files as af

    ok, why = af.editability(b"x" * (af.INLINE_LIMIT + 1))
    assert ok is False and "inline limit" in why
    assert af.editability(b"x" * 10)[0] is True


def test_saving_an_empty_body_is_refused(store):
    """A stored emptiness satisfies every 'SATOM has a copy' check and pushes
    an object the referencing rule answers -7694 for."""
    from app.services import artifact_files as af

    row, created, err = af.save_text("xml_schema", "xsd-order", "   \n ")
    assert row is None and created is False
    assert "empty" in err


def test_saving_unchanged_content_mints_no_new_version(store):
    from app.services import artifact_files as af

    af.save_text("xml_schema", "xsd-order", "<a/>")
    row, created, err = af.save_text("xml_schema", "xsd-order", "<a/>")
    assert err == ""
    assert created is False
    assert len(af.versions("xml_schema", "xsd-order", any_scope=True)) == 1


def test_saving_changed_content_mints_a_version_and_keeps_the_old_one(store):
    from app.services import artifact_files as af

    af.save_text("xml_schema", "xsd-order", "<a/>")
    row, created, err = af.save_text("xml_schema", "xsd-order", "<b/>")
    assert created is True and err == ""
    assert len(af.versions("xml_schema", "xsd-order", any_scope=True)) == 2


def test_deleting_a_version_keeps_a_blob_another_version_still_names(store):
    """Two objects legitimately share content. Unlinking the file out from
    under the survivor leaves an index row pointing at nothing — which
    resolve() reports as a broken store and an operator chases as a missing
    upload."""
    from app.services import artifact_files as af
    from app.services import waf_artifacts as wa

    a, _ = wa.put("xml_schema", "one", b"<same/>", appliance_id=None)
    b, _ = wa.put("xml_schema", "two", b"<same/>", appliance_id=None)
    assert a.sha256 == b.sha256

    ok, msg, removed = af.delete_version(a.id)
    assert ok and removed is False
    assert wa.load(b.sha256) == b"<same/>"

    ok, msg, removed = af.delete_version(b.id)
    assert ok and removed is True
    assert wa.load(b.sha256) is None


def test_the_diff_header_is_not_coloured_as_a_deletion(store):
    """``---`` starts with a minus. A diff whose header renders as a removed
    line is a diff that lies about its own first row."""
    from app.services import artifact_files as af

    rows = af.diff_lines(b"a\nb\n", b"a\nc\n", old_label="v1", new_label="v2")
    kinds = {r["cls"] for r in rows}
    assert "meta" in kinds and "hunk" in kinds
    assert all(r["cls"] == "meta" for r in rows
               if r["text"].startswith("---") or r["text"].startswith("+++"))
    assert af.diff_stat(rows) == {"added": 1, "removed": 1, "identical": False}


def test_identical_versions_diff_to_nothing_and_say_so(store):
    from app.services import artifact_files as af

    rows = af.diff_lines(b"same\n", b"same\n")
    assert rows == []
    assert af.diff_stat(rows)["identical"] is True


def test_object_index_groups_versions_into_one_row_per_object(store):
    """The inventory counts OBJECTS. Listing versions there makes one
    much-edited schema look like ten files that must travel."""
    from app.services import artifact_files as af
    from app.services import waf_artifacts as wa

    wa.put("xml_schema", "xsd-order", b"<v1/>", appliance_id=None)
    wa.put("xml_schema", "xsd-order", b"<v2/>", appliance_id=None)
    wa.put("xml_schema", "xsd-order", b"<v1/>", appliance_id=3)

    idx = af.object_index()
    assert len(idx) == 2, "distinct (kind, name, appliance) scopes"
    lib = next(o for o in idx if o["appliance_id"] is None)
    assert lib["versions"] == 2
    assert lib["latest"]["short_sha"]


# ── the pages ────────────────────────────────────────────────────────────────
def test_the_two_new_pages_are_registered(app):
    rules = {r.endpoint for r in app.url_map.iter_rules()}
    for endpoint in ("artifacts.manage", "artifacts.inventory",
                     "artifacts.object_page", "artifacts.save",
                     "artifacts.delete", "artifacts.refresh_refs",
                     "artifacts.raw", "artifacts.api_refs",
                     "artifacts.api_coverage"):
        assert endpoint in rules, "%s is not routed" % endpoint


def test_the_mutating_endpoints_are_behind_config_write(app):
    """``save``/``delete``/``refresh_refs`` write SATOM state; ``push`` writes a
    device. None may be reachable by a read-only operator."""
    import inspect

    from app.views import artifacts as v

    for fn in (v.save, v.delete, v.refresh_refs, v.push, v.upload, v.capture):
        src = inspect.getsource(fn)
        assert "config_write" in src or hasattr(fn, "__wrapped__"), fn.__name__
    module_src = inspect.getsource(v)
    for name in ("def save", "def delete", "def refresh_refs"):
        idx = module_src.index(name)
        head = module_src[max(0, idx - 220):idx]
        assert 'require_permission("config_write")' in head, name


def test_the_scheduled_action_exists_and_needs_no_targets_but_lists_them(app):
    from app.services import scheduled_actions as sa

    spec = sa.ALL_ACTIONS.get("artifact_refs")
    assert spec is not None, "artifact_refs is not in the action catalog"
    assert spec.scope == "admin"
    assert spec.products == ("fortiweb",)


def test_the_action_dry_run_touches_no_device(app, monkeypatch):
    from app.services import scheduled_actions as sa
    from app.services import artifact_refs as ar

    def _boom(*a, **kw):  # pragma: no cover - must never run
        raise AssertionError("a dry run contacted an appliance")

    monkeypatch.setattr(ar, "sweep", _boom)
    with app.app_context():
        res = sa._do_artifact_refs({}, dry_run=True)
    assert res["ok"] is True
    assert "dry-run" in res["summary"]


def test_stale_is_a_presentation_threshold_and_deletes_nothing(store):
    from app.services import artifact_refs as ar
    from app.models_artifact_refs import WafArtifactRef

    ar.record(1, "pol-a", [_art()])
    row = WafArtifactRef.query.one()
    assert ar.is_stale(row.seen_at - ar.STALE_AFTER - timedelta(seconds=1))
    assert not ar.is_stale(row.seen_at)
    assert ar.is_stale(None), "an edge with no timestamp is not current"
    assert WafArtifactRef.query.count() == 1
