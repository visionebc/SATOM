"""The change request must run on the operator's clock, and must rest on
evidence that cannot change under it.

Four defects are guarded here. None of them ever raised an exception, which is
exactly why they survived:

1. **The window was stored in the wrong timezone.** Every timestamp in the
   product was DISPLAYED through ``settings_store.to_local``, while every form
   value was STORED as if the operator had typed UTC. A window entered as 22:00
   on a Europe/Zurich console opened at midnight local — two hours after the
   customer had been told the outage would begin. The schedule and the
   maintenance notice agreed with each other and both disagreed with the human.

2. **Wall-clock schedules drifted twice a year.** "Back up every night at
   02:00" was computed in UTC, so on a Zurich fleet it fired at 03:00 in winter
   and 04:00 in summer. Nothing logged the move.

3. **The pre-upgrade left no evidence.** ``upgrade.prepare()`` painted its
   result into the browser and vanished with the tab, so a change request could
   not cite the pre-flight that justified it.

4. **The inventory was read live at render time.** The list of affected
   customer services in an approved change would silently become a different
   list by the time the change ran — and the approver signed the first one.

The load-bearing assertions are the round-trip ones (2 and 4 below): a
conversion that is wrong in BOTH directions looks perfectly consistent from
inside the product.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------- #
#  1. settings_store.parse_local — the inverse that did not exist               #
# --------------------------------------------------------------------------- #
def _store(app):
    from app.services import settings_store
    return settings_store


def test_parse_local_reads_the_configured_zone_not_utc(app):
    """22:00 typed in Zurich is 20:00 UTC in summer, not 22:00 UTC."""
    with app.app_context():
        store = _store(app)
        store.set_str(store.K_TIMEZONE, "Europe/Zurich")
        got = store.parse_local("2026-08-10T22:00")
        assert got == datetime(2026, 8, 10, 20, 0), got


def test_parse_local_honours_dst(app):
    """The offset is read from the tz database per date, never hard-coded."""
    with app.app_context():
        store = _store(app)
        store.set_str(store.K_TIMEZONE, "Europe/Zurich")
        summer = store.parse_local("2026-08-10T12:00")   # CEST, UTC+2
        winter = store.parse_local("2026-01-10T12:00")   # CET,  UTC+1
        assert summer == datetime(2026, 8, 10, 10, 0)
        assert winter == datetime(2026, 1, 10, 11, 0)


def test_parse_local_and_to_local_round_trip(app):
    """THE guard. A conversion that is wrong in both directions is invisible
    from inside the product, so the pair is asserted together."""
    with app.app_context():
        store = _store(app)
        for tz in ("Europe/Zurich", "America/Mexico_City", "UTC"):
            store.set_str(store.K_TIMEZONE, tz)
            typed = "2026-08-10T22:30"
            stored = store.parse_local(typed)
            shown = store.to_local(stored, "%Y-%m-%dT%H:%M")
            assert shown == typed, (tz, shown)


def test_parse_local_respects_an_explicit_offset(app):
    """A value that already states its offset is an assertion about an instant;
    re-reading it in the console's zone would overrule the caller."""
    with app.app_context():
        store = _store(app)
        store.set_str(store.K_TIMEZONE, "Europe/Zurich")
        assert store.parse_local("2026-08-10T22:00+00:00") == datetime(2026, 8, 10, 22, 0)


@pytest.mark.parametrize("bad", ["", None, "not a date", "2026-13-45T99:99"])
def test_parse_local_rejects_junk_without_raising(app, bad):
    with app.app_context():
        assert _store(app).parse_local(bad) is None


def test_tz_name_falls_back_to_a_valid_zone(app):
    with app.app_context():
        store = _store(app)
        store.set_str(store.K_TIMEZONE, "Mars/Olympus_Mons")
        assert store.tz_name() == store.DEFAULT_TIMEZONE


# --------------------------------------------------------------------------- #
#  2. scheduler — wall-clock kinds honour a timezone, durations do not          #
# --------------------------------------------------------------------------- #
def test_daily_is_computed_in_the_given_zone():
    from app.services import scheduler
    now = datetime(2026, 8, 10, 12, 0)          # 14:00 in Zurich (CEST)
    utc = scheduler.compute_next_run("daily", {"time": "02:00"}, now)
    zrh = scheduler.compute_next_run("daily", {"time": "02:00"}, now,
                                     tz="Europe/Zurich")
    assert utc == datetime(2026, 8, 11, 2, 0)
    # 02:00 Zurich on the 11th == 00:00 UTC on the 11th.
    assert zrh == datetime(2026, 8, 11, 0, 0)
    assert utc != zrh


def test_weekly_and_monthly_honour_the_zone():
    from app.services import scheduler
    now = datetime(2026, 8, 10, 12, 0)          # Monday
    for kind, spec in (("weekly", {"weekday": 2, "time": "02:00"}),
                       ("monthly", {"day": 15, "time": "02:00"})):
        utc = scheduler.compute_next_run(kind, spec, now)
        zrh = scheduler.compute_next_run(kind, spec, now, tz="Europe/Zurich")
        assert utc is not None and zrh is not None
        assert (utc - zrh) == timedelta(hours=2), (kind, utc, zrh)


def test_interval_is_a_duration_and_is_never_shifted():
    """"Every 30 minutes" means every 30 minutes through a DST change too."""
    from app.services import scheduler
    now = datetime(2026, 8, 10, 12, 0)
    spec = {"every": 30, "unit": "minutes"}
    assert (scheduler.compute_next_run("interval", spec, now)
            == scheduler.compute_next_run("interval", spec, now, tz="Europe/Zurich")
            == now + timedelta(minutes=30))


def test_once_is_an_absolute_instant_and_is_never_shifted():
    """The view already converted it when the operator typed it. Converting a
    second time here would double-apply the offset."""
    from app.services import scheduler
    now = datetime(2026, 8, 10, 12, 0)
    spec = {"at": "2026-08-10T20:00:00"}
    assert (scheduler.compute_next_run("once", spec, now)
            == scheduler.compute_next_run("once", spec, now, tz="Europe/Zurich")
            == datetime(2026, 8, 10, 20, 0))


def test_tz_none_preserves_the_pre_existing_utc_behaviour():
    """Every stored schedule predates the parameter and meant UTC."""
    from app.services import scheduler
    now = datetime(2026, 8, 10, 12, 0)
    for kind, spec in (("daily", {"time": "07:00"}),
                       ("weekly", {"weekday": 4, "time": "07:00"}),
                       ("monthly", {"day": 3, "time": "07:00"})):
        assert (scheduler.compute_next_run(kind, spec, now)
                == scheduler.compute_next_run(kind, spec, now, tz=None))


def test_an_unusable_timezone_degrades_to_utc_instead_of_raising():
    """A corrupt settings value must not stop the fleet from scheduling."""
    from app.services import scheduler
    now = datetime(2026, 8, 10, 12, 0)
    assert (scheduler.compute_next_run("daily", {"time": "02:00"}, now,
                                       tz="Not/AZone")
            == scheduler.compute_next_run("daily", {"time": "02:00"}, now))


def test_scheduler_module_never_reads_the_database():
    """The timezone is passed DOWN. A DB read here would make the pure schedule
    math untestable and would couple the sidecar's hot loop to a query."""
    src = open(os.path.join(REPO, "app", "services", "scheduler.py")).read()
    for forbidden in ("settings_store", "from ..models", "db.session"):
        assert forbidden not in src, forbidden


def test_every_wall_clock_caller_passes_a_timezone():
    """A caller that forgets silently reverts to the UTC bug for its schedules."""
    import ast
    for rel in ("app/views/scheduled_actions.py", "app/scheduler_runtime.py",
                "app/services/scheduled_actions.py"):
        tree = ast.parse(open(os.path.join(REPO, rel)).read())
        calls = [n for n in ast.walk(tree)
                 if isinstance(n, ast.Call)
                 and getattr(n.func, "attr", getattr(n.func, "id", "")) == "compute_next_run"]
        assert calls, rel
        for call in calls:
            assert any(kw.arg == "tz" for kw in call.keywords), (rel, call.lineno)


# --------------------------------------------------------------------------- #
#  3. prep_store.verdict — grade only what was asked for                        #
# --------------------------------------------------------------------------- #
def test_verdict_does_not_fail_a_section_that_was_not_requested():
    from app.services import prep_store
    ok, summary = prep_store.verdict({"backup": {"ok": True}})
    assert ok is True and "backup ok" in summary
    assert "health" not in summary


def test_verdict_fails_on_a_failed_backup_or_health():
    from app.services import prep_store
    assert prep_store.verdict({"backup": {"ok": False}})[0] is False
    assert prep_store.verdict({"health": {"ok": False}})[0] is False


def test_an_unreachable_service_is_a_baseline_not_a_failure():
    """Discovering that a policy is ALREADY down before the change is the most
    valuable thing this pre-flight produces. Grading it red would train
    operators to re-run until it turns green."""
    from app.services import prep_store
    result = {"backup": {"ok": True},
              "services": {"ok": True,
                           "probes": [{"target": {"policy": "a"}, "result": {"ok": False}},
                                      {"target": {"policy": "b"}, "result": {"ok": True}}]}}
    ok, summary = prep_store.verdict(result)
    assert ok is True
    assert "1/2 reachable" in summary


def test_a_failed_probe_SWEEP_is_a_failure():
    """Not being able to enumerate the services at all is a missing baseline."""
    from app.services import prep_store
    assert prep_store.verdict({"services": {"ok": False, "error": "boom"}})[0] is False


def test_missing_maintenance_permission_fails_the_run():
    from app.services import prep_store
    ok, summary = prep_store.verdict({"backup": {"ok": True}, "permission": False})
    assert ok is False and "permission" in summary


def test_a_run_with_no_checks_is_not_a_pass():
    from app.services import prep_store
    ok, summary = prep_store.verdict({})
    assert ok is False and "no checks" in summary


# --------------------------------------------------------------------------- #
#  4. build_inventory — the policy list is the spine                            #
# --------------------------------------------------------------------------- #
_POLICIES = [
    {"device": "fw08", "device_id": 1, "policy": "shop", "vserver": "vip1",
     "service": "HTTPS", "status": "enable"},
    {"device": "fw08", "device_id": 1, "policy": "unprobed", "vserver": "vip2",
     "service": "HTTP", "status": "enable"},
]
_RESULT = {"services": {"ok": True, "probes": [
    {"target": {"policy": "shop", "url": "https://x/", "pool": "p1",
                "backends": ["192.0.2.1:443"], "note": ""},
     "result": {"ok": True, "status": 200, "elapsed_ms": 42}}]}}


def test_a_policy_with_no_probe_still_appears():
    """"We could not probe it" and "it is not affected" are opposite
    statements; dropping the first under-states the outage."""
    from app.services import prep_store
    rows = prep_store.build_inventory(_POLICIES, _RESULT)
    assert [r["policy"] for r in rows] == ["shop", "unprobed"]


def test_probe_data_is_merged_onto_the_matching_policy():
    from app.services import prep_store
    rows = {r["policy"]: r for r in prep_store.build_inventory(_POLICIES, _RESULT)}
    assert rows["shop"]["url"] == "https://x/"
    assert rows["shop"]["http_status"] == 200
    assert rows["shop"]["probe_ok"] is True
    assert rows["shop"]["backends"] == "192.0.2.1:443"


def test_never_probed_and_probed_and_failed_do_not_read_alike():
    from app.services import prep_store
    rows = {r["policy"]: r for r in prep_store.build_inventory(_POLICIES, _RESULT)}
    assert rows["unprobed"]["probe_ok"] == ""      # unknown
    failed = prep_store.build_inventory(
        [{"device": "d", "policy": "x"}],
        {"services": {"ok": True, "probes": [
            {"target": {"policy": "x"}, "result": {"ok": False}}]}})
    assert failed[0]["probe_ok"] is False          # measured


def test_build_inventory_survives_a_result_with_no_probes():
    from app.services import prep_store
    assert len(prep_store.build_inventory(_POLICIES, None)) == 2
    assert len(prep_store.build_inventory([], _RESULT)) == 0


# --------------------------------------------------------------------------- #
#  5. field selection + export                                                  #
# --------------------------------------------------------------------------- #
def test_an_empty_selection_exports_the_defaults_not_nothing():
    """A zero-column spreadsheet is a corrupt file, not an expression of intent."""
    from app.services import prep_store
    assert prep_store.select_fields([]) == list(prep_store.DEFAULT_FIELDS)
    assert prep_store.select_fields(None) == list(prep_store.DEFAULT_FIELDS)


def test_unknown_fields_are_dropped_not_exported_blank():
    from app.services import prep_store
    assert prep_store.select_fields(["device", "; DROP TABLE", "policy"]) == ["device", "policy"]


def test_column_order_is_fixed_regardless_of_tick_order():
    """Two exports of the same change have to be comparable."""
    from app.services import prep_store
    assert (prep_store.select_fields(["status", "device", "policy"])
            == prep_store.select_fields(["policy", "status", "device"])
            == ["device", "policy", "status"])


def test_export_matrix_has_a_header_and_one_row_per_policy():
    from app.services import prep_store
    rows = prep_store.build_inventory(_POLICIES, _RESULT)
    matrix = prep_store.export_matrix(rows, ["device", "policy", "probe_ok"])
    assert matrix[0] == ["Device", "Policy / virtual server", "Reachable"]
    assert len(matrix) == 3
    assert matrix[1] == ["fw08", "shop", "yes"]
    assert matrix[2][2] == ""          # never probed -> blank, never "False"


def test_export_xlsx_produces_a_real_zip():
    import io
    import zipfile
    from app.services import prep_store
    blob = prep_store.export_xlsx(prep_store.build_inventory(_POLICIES, _RESULT),
                                  ["device", "policy"])
    assert blob[:2] == b"PK"
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        assert "xl/worksheets/sheet1.xml" in zf.namelist()


def test_export_csv_quotes_a_comma_bearing_cell():
    from app.services import prep_store
    csv = prep_store.export_csv([{"device": "a,b", "policy": "p"}],
                                ["device", "policy"])
    assert '"a,b"' in csv


# --------------------------------------------------------------------------- #
#  6. persistence + the change-request link                                     #
# --------------------------------------------------------------------------- #
def _appliance(db):
    from app.models import Appliance
    a = Appliance(name="fw08", kind="fortiweb", host="192.0.2.8",
                  username="admin", port=443)
    a.password = "pw"
    db.session.add(a)
    db.session.commit()
    return a


def test_record_is_append_only(app):
    """A re-run must not overwrite the run an approved change already cites."""
    from app.models import db
    from app.services import prep_store
    with app.app_context():
        a = _appliance(db)
        first = prep_store.record(a, {"backup": {"ok": True}, "firmware": "7.6.8"},
                                  inventory=_POLICIES, created_by="alice")
        second = prep_store.record(a, {"backup": {"ok": False}}, created_by="bob")
        assert first.id != second.id
        assert prep_store.get(first.id).ok is True
        assert prep_store.latest_for(a.id).id == second.id


def test_record_freezes_the_inventory_it_was_given(app):
    from app.models import db
    from app.services import prep_store
    with app.app_context():
        a = _appliance(db)
        prep = prep_store.record(a, {}, inventory=_POLICIES)
        assert [r["policy"] for r in prep.inventory_list] == ["shop", "unprobed"]


def test_bind_change_request_records_both_directions(app):
    from app.models import ChangeRequest, db
    from app.services import prep_store
    with app.app_context():
        a = _appliance(db)
        prep = prep_store.record(a, {}, inventory=_POLICIES)
        cr = ChangeRequest(title="t", action="upgrade",
                           device_ids=json.dumps([a.id]))
        db.session.add(cr)
        db.session.commit()
        prep_store.bind_change_request(prep, cr)
        assert prep.cr_id == cr.id and cr.prep_id == prep.id


def test_get_and_latest_for_tolerate_junk_ids(app):
    from app.services import prep_store
    with app.app_context():
        assert prep_store.get("not-an-id") is None
        assert prep_store.get(None) is None
        assert prep_store.latest_for("nope") is None
        assert prep_store.recent("nope") == []


# --------------------------------------------------------------------------- #
#  7. the view layer: frozen, not live                                          #
# --------------------------------------------------------------------------- #
def test_the_detail_and_document_routes_read_the_frozen_inventory():
    """A live read at render time is the defect. Assert on the CODE, because a
    behavioural test would need two different fleets to tell them apart."""
    import ast
    src = open(os.path.join(REPO, "app", "views", "change_requests.py")).read()
    tree = ast.parse(src)
    for name in ("detail", "document", "inventory_export"):
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == name)
        body = ast.dump(fn)
        assert "frozen_policies" in body, name
        # affected_policies (the LIVE read) is allowed only inside the explicit
        # opt-in drift comparison, never as the source of the record.
        if name != "detail":
            assert "affected_policies" not in body, name


def test_creating_a_change_stamps_a_reference_and_freezes_the_inventory():
    """Both are done at CREATION. Deriving the reference at print time would
    renumber circulating documents the day the id sequence is reseeded."""
    src = open(os.path.join(REPO, "app", "views", "change_requests.py")).read()
    assert "cr.ref = _next_ref(cr)" in src
    assert "_freeze_inventory(cr, device_ids, prep)" in src


def test_a_prep_from_another_appliance_cannot_be_cited():
    src = open(os.path.join(REPO, "app", "views", "change_requests.py")).read()
    assert "prep.appliance_id not in device_ids" in src


def test_the_window_form_no_longer_parses_a_naive_value_as_utc():
    """The regression guard: fromisoformat straight into the model is the bug."""
    src = open(os.path.join(REPO, "app", "views", "change_requests.py")).read()
    fn = src.split("def _parse_dt", 1)[1].split("\ndef ", 1)[0]
    code = "\n".join(l for l in fn.splitlines() if not l.strip().startswith("#"))
    code = code.split('"""')[0] + code.split('"""')[-1]
    assert "settings_store.parse_local" in code
    assert "fromisoformat" not in code


def test_the_window_labels_name_the_timezone():
    """A datetime-local input carries no zone; an unlabelled field is a guess
    the operator makes and the server silently overrules."""
    html = open(os.path.join(REPO, "app", "templates", "change_requests",
                             "form.html")).read()
    assert html.count("{{ tz_name }}") >= 2
    assert "(UTC)" not in html


# --------------------------------------------------------------------------- #
#  8. the upgrade gate itself — behavioural, not just structural                #
# --------------------------------------------------------------------------- #
#  The first mutation pass proved this section was missing: neutering
#  _upgrade_authorization so it always returns "authorised" broke nothing,
#  because every guard was asserting on the CALLER. A gate whose decision
#  function is untested is a gate you can delete by accident.
def _cr(db, *, device_ids, status="approved", action="upgrade",
        start_offset=-60, end_offset=60, approval_mode="manual", title="t"):
    from app.models import ChangeRequest
    now = datetime.utcnow()
    cr = ChangeRequest(
        title=title, action=action, status=status,
        device_ids=json.dumps(device_ids),
        window_start=(now + timedelta(minutes=start_offset)
                      if start_offset is not None else None),
        window_end=(now + timedelta(minutes=end_offset)
                    if end_offset is not None else None),
        approval_mode=approval_mode)
    db.session.add(cr)
    db.session.commit()
    return cr


def test_no_change_request_means_no_live_flash(app):
    from app.models import db
    from app.views.appliances import _upgrade_authorization
    with app.app_context():
        a = _appliance(db)
        cr, ok, reason = _upgrade_authorization(a)
        assert ok is False and cr is None
        assert "no approved change request" in reason


def test_an_open_approved_window_authorises(app):
    from app.models import db
    from app.views.appliances import _upgrade_authorization
    with app.app_context():
        a = _appliance(db)
        want = _cr(db, device_ids=[a.id])
        cr, ok, reason = _upgrade_authorization(a)
        assert ok is True and cr.id == want.id


def test_a_window_that_has_not_opened_yet_does_not_authorise(app):
    """And the refusal NAMES the change and the reason. An operator who cannot
    see what is blocking them routes around the gate."""
    from app.models import db
    from app.views.appliances import _upgrade_authorization
    with app.app_context():
        a = _appliance(db)
        _cr(db, device_ids=[a.id], start_offset=120, end_offset=180,
            title="future")
        cr, ok, reason = _upgrade_authorization(a)
        assert ok is False
        assert "before the maintenance window" in reason


def test_a_draft_change_does_not_authorise(app):
    from app.models import db
    from app.views.appliances import _upgrade_authorization
    with app.app_context():
        a = _appliance(db)
        _cr(db, device_ids=[a.id], status="draft")
        _, ok, reason = _upgrade_authorization(a)
        assert ok is False
        assert "no approved change request" in reason   # drafts are not candidates


def test_a_change_for_another_appliance_does_not_authorise_this_one(app):
    from app.models import Appliance, db
    from app.views.appliances import _upgrade_authorization
    with app.app_context():
        a = _appliance(db)
        other = Appliance(name="fw09", kind="fortiweb", host="192.0.2.9",
                          username="admin", port=443)
        other.password = "pw"
        db.session.add(other)
        db.session.commit()
        _cr(db, device_ids=[other.id])
        _, ok, _reason = _upgrade_authorization(a)
        assert ok is False


def test_a_change_for_another_action_does_not_authorise_a_flash(app):
    """An approved REBOOT window is not permission to install firmware."""
    from app.models import db
    from app.views.appliances import _upgrade_authorization
    with app.app_context():
        a = _appliance(db)
        _cr(db, device_ids=[a.id], action="reboot")
        _, ok, _reason = _upgrade_authorization(a)
        assert ok is False


def test_the_soonest_starting_runnable_window_is_the_one_consumed(app):
    """Not the newest row: an operator with two open changes must not silently
    burn the wrong window."""
    from app.models import db
    from app.views.appliances import _upgrade_authorization
    with app.app_context():
        a = _appliance(db)
        # Created EARLIEST-WINDOW FIRST on purpose: if the newest row also had
        # the earliest window, a "sort by id" implementation would pass this
        # test by coincidence. It must not.
        earlier = _cr(db, device_ids=[a.id], start_offset=-90, title="earlier")
        later = _cr(db, device_ids=[a.id], start_offset=-10, title="later")
        cr, ok, _reason = _upgrade_authorization(a)
        assert ok is True
        assert cr.id == earlier.id and cr.id != later.id


def test_external_approval_is_fail_closed_here_too(app):
    """The gate delegates to cr_runnable, so an unanswered external authority
    blocks the human button exactly as it blocks the scheduler."""
    from app.models import db
    from app.views.appliances import _upgrade_authorization
    with app.app_context():
        a = _appliance(db)
        _cr(db, device_ids=[a.id], approval_mode="external")
        _, ok, reason = _upgrade_authorization(a)
        assert ok is False
        assert reason


def test_the_live_push_actually_consults_the_gate():
    """Structural companion: the decision function above is only worth anything
    if the destructive route calls it."""
    import ast
    src = open(os.path.join(REPO, "app", "views", "appliances.py")).read()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "upgrade_push")
    body = ast.dump(fn)
    assert "_upgrade_authorization" in body
    assert "needs_change_request" in body      # the JSON caller is refused too


def test_a_dry_run_is_never_gated():
    """It sends nothing to the appliance; gating it would push operators to
    skip validation entirely."""
    src = open(os.path.join(REPO, "app", "views", "appliances.py")).read()
    block = src.split("# CHANGE CONTROL", 1)[1].split("if _wants_json", 1)[0]
    assert "if not dry_run:" in block


def test_the_flash_job_closes_its_change_through_one_seam():
    """Six terminal paths stamped by hand is how one gets missed and leaves a
    change parked at in_progress forever."""
    src = open(os.path.join(REPO, "app", "views", "appliances.py")).read()
    assert "_flash_under_change" in src
    seam = src.split("def _flash_under_change", 1)[1].split("\ndef ", 1)[0]
    assert "finally:" in seam
    assert "crsvc.start(" in seam and "crsvc.finish(" in seam
    # The worker itself must NOT also stamp the change: two writers to one
    # lifecycle is how they disagree.
    worker = src.split("def _flash_worker", 1)[1].split("\ndef ", 1)[0]
    assert "crsvc.finish(" not in worker
