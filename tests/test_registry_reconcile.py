"""Guards for the sweep→catalog return path (services/registry_reconcile.py).

Nothing here fails on its own when it breaks. A reconciler that quietly stops
distinguishing "this firmware has no such endpoint" from "this appliance is
sick" still renders a page, still shows a table, and still lets an operator
click Disable — it just proposes deleting the catalog. The verdicts, the
witness gate and the server-side re-derivation are the whole product; every
test below exists because the failure mode it covers is SILENT.

Live grounding for the constants (2026-08-13, against the real fleet):
  * fortiweb09/10 — 283 ok, 38 absent, 0 error
  * fortiweb08    — 0 ok, 38 absent, 283 error ("The license of peer VM
    FortiWeb is not valid"), while the inventory still called it ``online``
  * fortiadc02    — a URN the appliance does not implement answers HTTP 404
"""
from __future__ import annotations

import json

import pytest

from app.extensions import db
from app.models import Appliance, AuditLog, RegistryEndpoint
from app.services import registry_reconcile as rr
from app.services import rediscovery
from tests.conftest import admin_user_id, login, make_user, profile_id


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

class _Resp:
    """The three shapes a FortiWeb answers with — verbatim from the wire."""

    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body)

    def json(self):
        return self._body


def _absent_resp():
    return _Resp(500, {"errcode": "-20001", "message": "The REST API has invalid URL."})


def _sick_resp():
    return _Resp(423, {"errcode": "-20010",
                       "message": "The license of peer VM FortiWeb is not valid."})


def _ok_resp(rows):
    return _Resp(200, {"results": rows})


@pytest.fixture()
def isolated_data(app, tmp_path, monkeypatch):
    """Redirect the rediscovery store — the production tree is NOT a fixture.

    conftest isolates jobs/SoT/trust for exactly this reason; ``data/rediscovery``
    has no env hook, so a test that forgets this writes real snapshots onto the
    live node and the reconcile page starts proposing from test fixtures.
    """
    root = tmp_path / "rediscovery"
    root.mkdir()
    monkeypatch.setattr(rediscovery, "_data_dir", lambda: root)
    return root


def _appliance(name, kind="fortiweb", host=None, maintenance=False):
    a = Appliance(name=name, kind=kind, host=host or f"{name}.test",
                  port=443, username="admin", verify_ssl=False,
                  maintenance=maintenance)
    a.password = "secret"
    db.session.add(a)
    db.session.commit()
    return a


def _endpoint(name, urn=None, product="fortiweb", enabled=True):
    row = RegistryEndpoint(product=product, api_version="v2.0", name=name,
                           urn=urn or f"/api/v2.0/cmdb/system/{name}", enabled=enabled)
    db.session.add(row)
    db.session.commit()
    return row


def _write_ledger(appliance, entries, generated_at="2099-01-01T00:00:00",
                  firmware="7.6.8"):
    """entries: {name: (verdict, rows)} → the snapshot the sweep would write."""
    ledger = {n: {"urn": f"/api/v2.0/cmdb/system/{n}", "section": "S",
                  "verdict": v, "rows": r, "detail": ""}
              for n, (v, r) in entries.items()}
    snap = {"device": appliance.name, "appliance_id": appliance.id,
            "generated_at": generated_at, "endpoint_status": ledger,
            "firmware": firmware, "errors": [], "absent": [], "sections": {}}
    path = rediscovery._dev_dir(appliance.id) / "_config.json"
    path.write_text(json.dumps(snap), encoding="utf-8")


def _all_plan(monkeypatch, *names):
    """Pretend every named endpoint is in the sweep plan."""
    plan = [{"name": n, "urn": f"/api/v2.0/cmdb/system/{n}", "section": "S"} for n in names]
    monkeypatch.setattr(rediscovery, "sweep_plan", lambda: plan)
    monkeypatch.setattr(rediscovery, "sweep_plan_adc", lambda: plan)


# --------------------------------------------------------------------------
# 1. the probe: three verdicts that are never collapsed
# --------------------------------------------------------------------------

def _probe(app, resp):
    """Run the REAL FortiWebClient classification over one canned response."""
    from app.clients.fortiweb import FortiWebClient
    with app.app_context():
        appliance = _appliance("probe-dev")
        client = FortiWebClient(appliance, timeout=1)
        client.get = lambda path: resp  # noqa: ARG005
        return rediscovery._probe_fortiweb(client, {"urn": "/api/v2.0/cmdb/system/x"})


def test_invalid_url_errcode_is_absent_not_error(app):
    rows, verdict, detail = _probe(app, _absent_resp())
    assert verdict == rediscovery.VERDICT_ABSENT
    assert rows == []
    assert "-20001" in detail


def test_licence_failure_is_error_not_absent(app):
    """The fortiweb08 incident. Reading -20010 as 'gone' proposes deleting the
    catalog from one sick appliance."""
    _rows, verdict, detail = _probe(app, _sick_resp())
    assert verdict == rediscovery.VERDICT_ERROR
    assert "-20010" in detail


def test_empty_collection_is_ok_not_absent(app):
    """Zero rows is a fact about the CONFIG. Calling it absent is the original
    defect wearing a new name."""
    rows, verdict, _d = _probe(app, _ok_resp([]))
    assert (rows, verdict) == ([], rediscovery.VERDICT_OK)


def test_populated_collection_is_ok_with_rows(app):
    rows, verdict, _d = _probe(app, _ok_resp([{"name": "a"}, {"name": "b"}]))
    assert verdict == rediscovery.VERDICT_OK
    assert len(rows) == 2


def test_http_error_without_errcode_is_error(app):
    _rows, verdict, _d = _probe(app, _Resp(502, {"message": "bad gateway"}))
    assert verdict == rediscovery.VERDICT_ERROR


# --------------------------------------------------------------------------
# 2. the sweep writes the ledger, and 'absent' stays out of 'errors'
# --------------------------------------------------------------------------

def test_sweep_writes_a_verdict_for_every_planned_endpoint(app, isolated_data, monkeypatch):
    from types import SimpleNamespace

    with app.app_context():
        appliance = _appliance("sweep-dev")
        snap = rediscovery._client_snapshot(appliance)

    plan = [{"name": "alive", "urn": "/api/v2.0/cmdb/system/alive", "section": "S"},
            {"name": "gone", "urn": "/api/v2.0/cmdb/system/gone", "section": "S"},
            {"name": "broken", "urn": "/api/v2.0/cmdb/system/broken", "section": "S"}]
    canned = {"/api/v2.0/cmdb/system/alive": _ok_resp([{"name": "x"}]),
              "/api/v2.0/cmdb/system/gone": _absent_resp(),
              "/api/v2.0/cmdb/system/broken": _sick_resp()}

    class _Client:
        _ABSENT_ERRCODES = {"-20001", "-3"}

        def __init__(self, *a, **k):
            pass

        def get(self, path):
            return canned[path]

        def status_check(self):
            # The shape the real endpoint returns — the sweep must normalise it
            # to a LINE, or "8.0.3 build0093,260401" becomes its own firmware
            # line on every rebuild and no two sweeps ever agree.
            return {"results": {"firmwareVersion": "FortiWeb-KVM 7.6.8,build1128(GA.M)"}}

        _errcode = staticmethod(
            __import__("app.clients.fortiweb", fromlist=["FortiWebClient"]).FortiWebClient._errcode)
        _results_list = staticmethod(
            __import__("app.clients.fortiweb", fromlist=["FortiWebClient"]).FortiWebClient._results_list)

    monkeypatch.setattr(rediscovery, "FortiWebClient", _Client)
    rediscovery._run(SimpleNamespace(**vars(snap)), by="test", deep=False, plan=plan)

    written = json.loads((rediscovery._dev_dir(snap.id) / "_config.json").read_text())
    ledger = written["endpoint_status"]
    assert ledger["alive"]["verdict"] == "ok" and ledger["alive"]["rows"] == 1
    assert ledger["gone"]["verdict"] == "absent"
    assert ledger["broken"]["verdict"] == "error"
    assert written["verdict_counts"] == {"ok": 1, "absent": 1, "error": 1}
    # An endpoint this firmware simply does not have is not a sweep failure:
    # folding it into errors[] buries the real ones under dozens of benign rows.
    assert [e["endpoint"] for e in written["errors"]] == ["broken"]
    assert [e["endpoint"] for e in written["absent"]] == ["gone"]
    # The firmware the verdicts were taken against, normalised to a line.
    # Without it every verdict is an unattributable claim.
    assert written["firmware"] == "7.6.8"


# --------------------------------------------------------------------------
# 2b. the FortiADC probe — same three verdicts, a different wire shape
# --------------------------------------------------------------------------

class _AdcResp:
    def __init__(self, status, body, text=None):
        self.status_code = status
        self._body = body
        self.text = text if text is not None else json.dumps(body)

    def json(self):
        if self._body is None:
            raise ValueError("not json")
        return self._body


def _adc_probe(app, monkeypatch, resp):
    """Run make_probe over one canned answer, keeping the REAL _device_error /
    _payload so the test exercises the shipped classification."""
    from app.clients import fortiadc as adc_mod

    class _Fake(adc_mod.FortiADCClient):
        def __init__(self, *a, **k):  # noqa: D107 — no login in a unit test
            pass

        def _api(self, method, urn, *a, **k):  # noqa: ARG002
            return resp

    monkeypatch.setattr(adc_mod, "FortiADCClient", _Fake)
    from app.services import adc_ops
    with app.app_context():
        probe = adc_ops.make_probe(_appliance("adc-probe", kind="fortiadc"))
        return probe({"urn": "/api/whatever", "name": "x", "section": "S"})


def test_adc_404_is_absent(app, monkeypatch):
    """The ADC does not answer an unimplemented URN with a JSON envelope — it
    answers a plain-text 404, so _device_error alone cannot tell it from a
    transport failure. Verified live on fortiadc02."""
    _rows, verdict, _d = _adc_probe(app, monkeypatch,
                                    _AdcResp(404, None, text="404 page not found"))
    assert verdict == "absent"


def test_adc_refusal_payload_is_error(app, monkeypatch):
    _rows, verdict, _d = _adc_probe(app, monkeypatch, _AdcResp(200, {"payload": -12}))
    assert verdict == "error"


def test_adc_answer_is_ok(app, monkeypatch):
    rows, verdict, _d = _adc_probe(app, monkeypatch,
                                   _AdcResp(200, {"payload": [{"mkey": "a"}]}))
    assert verdict == "ok" and len(rows) == 1


# --------------------------------------------------------------------------
# 3. who counts as a witness
# --------------------------------------------------------------------------

def test_retired_appliances_are_not_witnesses(app, isolated_data):
    with app.app_context():
        live = _appliance("live-fw")
        _appliance("retired-fw", host="retired.invalid", maintenance=True)
        names = [a.name for a in rr.witnesses("fortiweb")]
        assert names == [live.name]


def test_other_products_are_not_witnesses(app, isolated_data):
    with app.app_context():
        _appliance("fw", kind="fortiweb")
        _appliance("adc", kind="fortiadc")
        assert [a.name for a in rr.witnesses("fortiadc")] == ["adc"]


def test_a_product_without_a_sweep_is_refused(app, isolated_data):
    """FortiAnalyzer has a catalog and no sweep. Returning an empty, clean
    report for it would read as 'nothing wrong' — it means 'nothing known'."""
    with app.app_context():
        with pytest.raises(rr.UnsupportedProduct):
            rr.reconcile("fortianalyzer")


def test_device_wide_failure_is_not_evidence(app, isolated_data, monkeypatch):
    """fortiweb08, verbatim: correct per-endpoint verdicts, useless witness."""
    with app.app_context():
        sick = _appliance("sick-fw")
        entries = {f"e{i}": ("error", 0) for i in range(9)}
        entries["e9"] = ("absent", 0)
        _write_ledger(sick, entries)
        led = rr.device_ledger(sick)
        assert led["trusted"] is False
        assert "device-wide failure" in led["reason"]


def test_a_healthy_ledger_is_trusted(app, isolated_data):
    with app.app_context():
        good = _appliance("good-fw")
        _write_ledger(good, {f"e{i}": ("ok", 1) for i in range(9)} | {"e9": ("absent", 0)})
        assert rr.device_ledger(good)["trusted"] is True


def test_legacy_snapshot_is_refused(app, isolated_data):
    """A pre-ledger snapshot cannot tell 'empty' from 'absent'. Reading it
    optimistically IS the defect this module exists to fix."""
    with app.app_context():
        old = _appliance("old-fw")
        path = rediscovery._dev_dir(old.id) / "_config.json"
        path.write_text(json.dumps({"generated_at": "2099-01-01T00:00:00",
                                    "sections": {}, "errors": []}), encoding="utf-8")
        led = rr.device_ledger(old)
        assert led["trusted"] is False and "legacy snapshot" in led["reason"]


def test_stale_evidence_is_refused(app, isolated_data):
    with app.app_context():
        old = _appliance("stale-fw")
        _write_ledger(old, {"e": ("absent", 0)}, generated_at="2000-01-01T00:00:00")
        led = rr.device_ledger(old)
        assert led["trusted"] is False and "days old" in led["reason"]


def test_ghost_snapshot_of_a_deleted_appliance_is_ignored(app, isolated_data, monkeypatch):
    """Six of the twelve snapshot dirs on the primary belong to appliances that
    no longer exist. A quorum built from ghosts is a deletion nobody can
    reproduce."""
    with app.app_context():
        ghost = _appliance("ghost-fw")
        _endpoint("orphan")
        _all_plan(monkeypatch, "orphan")
        _write_ledger(ghost, {"orphan": ("absent", 0)})
        ghost_id = ghost.id
        db.session.delete(ghost)
        db.session.commit()
        assert (rediscovery._dev_dir(ghost_id) / "_config.json").exists()
        report = rr.reconcile("fortiweb")
        assert report["proposals"] == []


# --------------------------------------------------------------------------
# 4. what may be proposed
# --------------------------------------------------------------------------

def test_unanimous_absence_is_proposed(app, isolated_data, monkeypatch):
    with app.app_context():
        a = _appliance("fw-a")
        b = _appliance("fw-b")
        _endpoint("dead_urn")
        _all_plan(monkeypatch, "dead_urn")
        _write_ledger(a, {"dead_urn": ("absent", 0)})
        _write_ledger(b, {"dead_urn": ("absent", 0)})
        report = rr.reconcile("fortiweb")
        assert [p["name"] for p in report["proposals"]] == ["dead_urn"]
        assert len(report["proposals"][0]["evidence"]) == 2


def test_one_appliance_serving_it_blocks_the_proposal(app, isolated_data, monkeypatch):
    """A firmware split is not a dead endpoint. Disabling it would break the
    catalog for the appliance that still serves it."""
    with app.app_context():
        a = _appliance("fw-a")
        b = _appliance("fw-b")
        _endpoint("split_urn")
        _all_plan(monkeypatch, "split_urn")
        _write_ledger(a, {"split_urn": ("absent", 0)})
        _write_ledger(b, {"split_urn": ("ok", 3)})
        report = rr.reconcile("fortiweb")
        assert report["proposals"] == []
        assert [p["name"] for p in report["divergent"]] == ["split_urn"]


def test_partial_coverage_does_not_propose(app, isolated_data, monkeypatch):
    """Absent on the appliance that measured it, unmeasured on the other. That
    is one witness short of unanimity, and the page must say which one."""
    with app.app_context():
        a = _appliance("fw-a")
        b = _appliance("fw-b")
        _endpoint("maybe_dead")
        _all_plan(monkeypatch, "maybe_dead", "other")
        _write_ledger(a, {"maybe_dead": ("absent", 0), "other": ("ok", 1)})
        _write_ledger(b, {"other": ("ok", 1)})
        report = rr.reconcile("fortiweb")
        assert report["proposals"] == []
        partial = [p for p in report["partial"] if p["name"] == "maybe_dead"]
        assert partial and partial[0]["missing_from"] == ["fw-b"]


def test_error_only_evidence_does_not_propose(app, isolated_data, monkeypatch):
    with app.app_context():
        a = _appliance("fw-a")
        _endpoint("flaky")
        _all_plan(monkeypatch, "flaky", *[f"ok{i}" for i in range(9)])
        _write_ledger(a, {"flaky": ("error", 0)}
                      | {f"ok{i}": ("ok", 1) for i in range(9)})
        report = rr.reconcile("fortiweb")
        assert report["proposals"] == []
        assert [p["name"] for p in report["partial"]] == ["flaky"]


def test_unmeasured_planned_endpoint_is_unproven_not_proposed(app, isolated_data, monkeypatch):
    with app.app_context():
        a = _appliance("fw-a")
        _endpoint("never_seen")
        _all_plan(monkeypatch, "never_seen", "seen")
        _endpoint("seen")
        _write_ledger(a, {"seen": ("ok", 1)})
        report = rr.reconcile("fortiweb")
        assert [p["name"] for p in report["unproven"]] == ["never_seen"]
        assert report["proposals"] == []


def test_endpoint_outside_the_plan_is_not_reported_as_unmeasured(app, isolated_data, monkeypatch):
    """185 of the 506 enabled FortiWeb rows are sub-tables the list sweep skips.
    Filing them under 'never measured' tells the operator to run a sweep that
    structurally cannot answer."""
    with app.app_context():
        a = _appliance("fw-a")
        _endpoint("child_table")
        _endpoint("top_level")
        _all_plan(monkeypatch, "top_level")
        _write_ledger(a, {"top_level": ("ok", 1)})
        report = rr.reconcile("fortiweb")
        # The app seeds the real 507-row catalog at boot, so assert membership,
        # not equality — every seeded row is legitimately out of this test plan.
        unsweepable = {p["name"] for p in report["unsweepable"]}
        assert "child_table" in unsweepable
        assert "top_level" not in unsweepable
        assert report["unproven"] == []


def test_disabled_rows_are_never_proposed_again(app, isolated_data, monkeypatch):
    with app.app_context():
        a = _appliance("fw-a")
        _endpoint("already_off", enabled=False)
        _all_plan(monkeypatch, "already_off")
        _write_ledger(a, {"already_off": ("absent", 0)})
        assert rr.reconcile("fortiweb")["proposals"] == []


# --------------------------------------------------------------------------
# 4b. absence is a claim about a FIRMWARE, not about an endpoint
# --------------------------------------------------------------------------

def test_a_proposal_carries_the_firmware_that_produced_it(app, isolated_data, monkeypatch):
    """Without the line, "absent everywhere" reads as "dead" — and 7 of the 38
    real findings are 8.0 features that a 7.6.8 fleet legitimately lacks."""
    with app.app_context():
        a = _appliance("fw-a")
        b = _appliance("fw-b")
        _endpoint("only_in_8")
        _all_plan(monkeypatch, "only_in_8")
        _write_ledger(a, {"only_in_8": ("absent", 0)}, firmware="7.6.8")
        _write_ledger(b, {"only_in_8": ("absent", 0)}, firmware="7.6.8")
        report = rr.reconcile("fortiweb")
        proposal = report["proposals"][0]
        assert proposal["firmware_lines"] == ["7.6.8"]
        assert "7.6.8" in proposal["why"]
        assert all(e["firmware"] == "7.6.8" for e in proposal["evidence"])


def test_a_single_firmware_fleet_is_flagged(app, isolated_data, monkeypatch):
    """The catalog is a cross-firmware superset. One line across the quorum
    cannot tell 'withdrawn' from 'not yet released'."""
    with app.app_context():
        a = _appliance("fw-a")
        _endpoint("x")
        _all_plan(monkeypatch, "x")
        _write_ledger(a, {"x": ("absent", 0)}, firmware="7.6.8")
        assert rr.reconcile("fortiweb")["fleet_spans_one_firmware"] is True
        assert rr.reconcile("fortiweb")["fleet_firmware_lines"] == ["7.6.8"]


def test_a_multi_firmware_fleet_is_not_flagged(app, isolated_data, monkeypatch):
    with app.app_context():
        a = _appliance("fw-a")
        b = _appliance("fw-b")
        _endpoint("x")
        _all_plan(monkeypatch, "x")
        _write_ledger(a, {"x": ("absent", 0)}, firmware="7.6.8")
        _write_ledger(b, {"x": ("absent", 0)}, firmware="8.0.5")
        report = rr.reconcile("fortiweb")
        assert report["fleet_spans_one_firmware"] is False
        assert report["proposals"][0]["firmware_lines"] == ["7.6.8", "8.0.5"]


def test_unknown_firmware_still_flags_the_fleet(app, isolated_data, monkeypatch):
    """An unknown line is not a second line. Treating "" as diversity would
    clear the warning on exactly the fleet that needs it most."""
    with app.app_context():
        a = _appliance("fw-a")
        b = _appliance("fw-b")
        _endpoint("x")
        _all_plan(monkeypatch, "x")
        _write_ledger(a, {"x": ("absent", 0)}, firmware="")
        _write_ledger(b, {"x": ("absent", 0)}, firmware="")
        report = rr.reconcile("fortiweb")
        assert report["fleet_firmware_lines"] == []
        assert report["fleet_spans_one_firmware"] is True


# --------------------------------------------------------------------------
# 5. apply — the POST is a filter over the evidence, never the authority
# --------------------------------------------------------------------------

def test_apply_soft_disables_and_audits_with_its_witnesses(app, isolated_data, monkeypatch):
    with app.app_context():
        a = _appliance("fw-a")
        row = _endpoint("dead_urn")
        _all_plan(monkeypatch, "dead_urn")
        _write_ledger(a, {"dead_urn": ("absent", 0)})

        result = rr.apply_disable("fortiweb", ["dead_urn"], actor="alice")
        assert [x["name"] for x in result["applied"]] == ["dead_urn"]

        fresh = db.session.get(RegistryEndpoint, row.id)
        assert fresh is not None            # SOFT delete — the row must survive
        assert fresh.enabled is False       # or the boot seeder resurrects it
        assert fresh.updated_by == "alice"

        entry = AuditLog.query.filter_by(action="registry.reconcile_disable").first()
        assert entry is not None
        assert "fw-a" in json.dumps(entry.extra if isinstance(entry.extra, (dict, list))
                                    else str(entry.extra))


def test_apply_refuses_a_name_the_evidence_does_not_back(app, isolated_data, monkeypatch):
    """Without server-side re-derivation the reconcile form is a way to disable
    ANY endpoint in the catalog — the checkbox list is client input."""
    with app.app_context():
        a = _appliance("fw-a")
        healthy = _endpoint("very_much_alive")
        _all_plan(monkeypatch, "very_much_alive")
        _write_ledger(a, {"very_much_alive": ("ok", 7)})

        result = rr.apply_disable("fortiweb", ["very_much_alive"], actor="mallory")
        assert result["applied"] == []
        assert result["rejected"][0]["name"] == "very_much_alive"
        assert db.session.get(RegistryEndpoint, healthy.id).enabled is True


def test_apply_refuses_an_endpoint_of_another_product(app, isolated_data, monkeypatch):
    with app.app_context():
        a = _appliance("fw-a")
        _endpoint("dead_urn")
        _all_plan(monkeypatch, "dead_urn")
        _write_ledger(a, {"dead_urn": ("absent", 0)})
        result = rr.apply_disable("fortiadc", ["dead_urn"], actor="alice")
        assert result["applied"] == []
        assert db.session.get(RegistryEndpoint,
                              RegistryEndpoint.query.filter_by(name="dead_urn")
                              .first().id).enabled is True


def test_apply_with_no_names_changes_nothing(app, isolated_data, monkeypatch):
    with app.app_context():
        a = _appliance("fw-a")
        row = _endpoint("dead_urn")
        _all_plan(monkeypatch, "dead_urn")
        _write_ledger(a, {"dead_urn": ("absent", 0)})
        result = rr.apply_disable("fortiweb", [], actor="alice")
        assert result["applied"] == [] and result["rejected"] == []
        assert db.session.get(RegistryEndpoint, row.id).enabled is True


def test_a_refused_apply_is_itself_audited(app, isolated_data, monkeypatch):
    """Probing the surface has to leave a trace, or the only visible attempts
    are the successful ones."""
    with app.app_context():
        a = _appliance("fw-a")
        _endpoint("very_much_alive")
        _all_plan(monkeypatch, "very_much_alive")
        _write_ledger(a, {"very_much_alive": ("ok", 7)})
        rr.apply_disable("fortiweb", ["very_much_alive"], actor="mallory")
        assert AuditLog.query.filter_by(action="registry.reconcile_rejected").count() == 1


# --------------------------------------------------------------------------
# 6. the routes
# --------------------------------------------------------------------------

def _reader(app):
    return make_user(app, username="reader", role="readonly")


def test_page_requires_registry_edit(app, client, isolated_data):
    uid = _reader(app)
    login(client, uid)
    for url in ("/web/registry/reconcile", "/adc/api/reconcile"):
        assert client.get(url).status_code in (302, 403), url


def test_admin_can_open_both_hubs(app, client, isolated_data, monkeypatch):
    _all_plan(monkeypatch)
    uid = admin_user_id(app)
    login(client, uid)
    assert client.get("/web/registry/reconcile").status_code == 200
    login(client, uid, product="fortiadc")
    assert client.get("/adc/api/reconcile").status_code == 200


def test_apply_post_is_gated_too(app, client, isolated_data, monkeypatch):
    with app.app_context():
        a = _appliance("fw-a")
        row = _endpoint("dead_urn")
        _all_plan(monkeypatch, "dead_urn")
        _write_ledger(a, {"dead_urn": ("absent", 0)})
        rid = row.id
    uid = _reader(app)
    login(client, uid)
    client.post("/web/registry/reconcile/apply", data={"endpoint": "dead_urn"})
    with app.app_context():
        assert db.session.get(RegistryEndpoint, rid).enabled is True
