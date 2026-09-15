"""The sweep's third pass: capturing what the CLI serves.

The sweep reads REST. ``show full-configuration`` reads the CLI. The gap between
them is the CLI-coverage report — and until now that report was compared against
whatever dump happened to be sitting in the vault, which on this fleet meant
dumps belonging to appliances that no longer exist. Hooking the capture into the
sweep is what makes the report describe the box *as swept*.

Every way that can go wrong looks like success from the outside, which is why
each guard below fixes a RELATION rather than the presence of a feature:

* a capture folded INLINE would put a 300 s SSH session in front of every
  sweep, including the silent one behind device registration — so the pass runs
  last, opt-in, and only after the sweep's own snapshot is already on disk;
* an SSH failure on a box whose REST just answered perfectly must not turn a
  successful sweep into a failed one;
* "no dump was taken" and "a dump was attempted and lost" send the operator to
  opposite places, so skipped and failed never share a key or a word;
* an UNUSABLE dump (encrypted, wrong appliance, unknown age) counting as
  freshness would suppress every future capture and leave the coverage section
  permanently empty on exactly the appliances that need it most;
* the dump is written to the configuration vault through a route that only asks
  for ``appliances.apply``, so the vault permission is enforced and the refusal
  is returned rather than swallowed.

Targeted suite: nothing here touches the network.
"""
from __future__ import annotations

import ast
import inspect
import pathlib
from datetime import datetime, timedelta

import pytest

from tests.conftest import admin_user_id, login, make_user, profile_id

REPO = pathlib.Path(__file__).resolve().parents[1]
PAGE = REPO / "app" / "templates" / "appliances" / "rediscover.html"
VIEWS = REPO / "app" / "views" / "appliances.py"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _code_of(fn) -> str:
    """A function's source with comments AND its docstring removed.

    Mandatory in this repo: the comment that EXPLAINS a rule quotes the very
    strings the rule forbids, and an assertion satisfied by its own explanation
    is not an assertion. It has cost a false result ten separate times here.
    """
    tree = ast.parse(inspect.getsource(fn))
    node = tree.body[0]
    body = node.body
    if (body and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        body = body[1:]
    return "\n".join(ast.unparse(stmt) for stmt in body)


def _ev(appliance_id=7, *, usable=True, hours_ago=1.0, backup_id=1, iso=None,
        now=None):
    """One ``evidence_index`` record, aged relative to *now*."""
    now = now or datetime.utcnow()
    if iso is None:
        iso = (now - timedelta(hours=hours_ago)).isoformat()
    return {"backup_id": backup_id, "appliance_id": appliance_id,
            "appliance": "fw", "filename": "f.conf", "created_at": "2026-09-14 22:46",
            "created_iso": iso, "firmware": "FortiWeb-KVM 7.6.8,build1128(GA.M),260602",
            "product": "fortiweb", "line": "7.6", "size_kb": 690,
            "source": "device", "usable": usable, "reason": ""}


def _decide(**kw):
    from app.services import rediscovery
    base = dict(requested=True, kind="fortiweb", appliance_id=7, evidence=[],
                maintenance=False, may_write_vault=True)
    base.update(kw)
    return rediscovery.cli_capture_decision(**base)


def _make_appliance(app, name="fw-sweep", kind="fortiweb", maintenance=False):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name=name, kind=kind, host="192.0.2.99", port=443,
                      username="admin", verify_ssl=False)
        a.password = "secret"
        a.maintenance = maintenance
        db.session.add(a)
        db.session.commit()
        return a.id


# ==========================================================================
# the decision — one authority, and every "no" says which no
# ==========================================================================

def test_not_requested_is_its_own_reason(app):
    from app.services import rediscovery
    d = _decide(requested=False)
    assert d["capture"] is False
    assert d["reason"] == rediscovery.CLI_SKIP_NOT_REQUESTED


def test_unsupported_product_answers_with_that_product_s_own_reason(app):
    """FortiAnalyzer speaks JSON-RPC and FortiAuthenticator has no config dump.

    The reason must be the one ``cli_coverage`` already publishes for that
    product, not a second sentence written here: two explanations of the same
    refusal drift, and the operator is then told different things by the page
    and by the sweep.
    """
    from app.services import cli_coverage
    for kind in ("fortianalyzer", "fortiauthenticator"):
        d = _decide(kind=kind)
        assert d["capture"] is False
        assert d["reason"] == cli_coverage.UNSUPPORTED_REASON[kind]


def test_unknown_kind_still_refuses_with_a_sentence(app):
    d = _decide(kind="fortimanager")
    assert d["capture"] is False and d["reason"]


def test_supported_products_are_exactly_the_ones_with_a_parser(app):
    """The gate delegates to ``cli_coverage.SUPPORTED_PRODUCTS``.

    A second list here is how a product ends up capturable but not diffable —
    700 KB into the vault and nothing able to read it.
    """
    from app.services import cli_coverage, rediscovery
    code = _code_of(rediscovery.cli_capture_decision)
    assert "SUPPORTED_PRODUCTS" in code
    for kind in cli_coverage.SUPPORTED_PRODUCTS:
        assert _decide(kind=kind)["capture"] is True


def test_missing_vault_permission_beats_a_fresh_dump(app):
    """Ordering, not just presence.

    With freshness checked first, a user who may not write the vault would be
    told "there is already a recent dump" — true, and the wrong reason. They
    would go on believing they can capture.
    """
    from app.services import rediscovery
    d = _decide(may_write_vault=False, evidence=[_ev(hours_ago=0.2)])
    assert d["capture"] is False
    assert d["reason"] == rediscovery.CLI_SKIP_NO_PERMISSION


def test_maintenance_suppresses_the_capture(app):
    from app.services import rediscovery
    d = _decide(maintenance=True)
    assert d["capture"] is False
    assert d["reason"] == rediscovery.CLI_SKIP_MAINTENANCE


def test_a_fresh_usable_dump_spends_no_session(app):
    now = datetime.utcnow()
    d = _decide(evidence=[_ev(hours_ago=3.0, now=now)], now=now)
    assert d["capture"] is False
    assert d["age_h"] == pytest.approx(3.0, abs=0.1)
    assert "budget" in d["reason"]
    assert d["existing"]["backup_id"] == 1


def test_a_dump_older_than_the_budget_is_captured_again(app):
    now = datetime.utcnow()
    d = _decide(evidence=[_ev(hours_ago=30.0, now=now)], now=now)
    assert d["capture"] is True and d["reason"] == ""


def test_the_budget_is_a_parameter_not_a_constant_in_the_branch(app):
    now = datetime.utcnow()
    ev = [_ev(hours_ago=3.0, now=now)]
    assert _decide(evidence=ev, now=now, max_age_h=1)["capture"] is True
    assert _decide(evidence=ev, now=now, max_age_h=48)["capture"] is False


def test_an_unusable_dump_is_not_freshness(app):
    """An encrypted dump can never be parsed.

    Counting it as freshness would suppress every future capture forever, and
    the coverage section would stay empty on precisely the appliance whose
    operator set a backup password.
    """
    now = datetime.utcnow()
    d = _decide(evidence=[_ev(hours_ago=0.5, usable=False, now=now)], now=now)
    assert d["capture"] is True


def test_another_appliance_s_dump_is_not_freshness(app):
    now = datetime.utcnow()
    d = _decide(appliance_id=7, evidence=[_ev(appliance_id=8, hours_ago=0.5,
                                              now=now)], now=now)
    assert d["capture"] is True


def test_an_age_that_cannot_be_established_never_suppresses(app):
    """No timestamp, or an unparseable one, means UNKNOWN age.

    Treating unknown as fresh is the silent-suppression failure again, this
    time triggered by a vault row written before the column existed.
    """
    for iso in ("", "not-a-date"):
        d = _decide(evidence=[_ev(iso=iso)])
        assert d["capture"] is True, iso


def test_the_newest_usable_dump_is_the_one_measured(app):
    """``evidence_index`` is newest-first; the decision must respect that order
    rather than picking the first row that merely matches the appliance."""
    now = datetime.utcnow()
    ev = [_ev(hours_ago=2.0, backup_id=9, now=now),
          _ev(hours_ago=99.0, backup_id=1, now=now)]
    d = _decide(evidence=ev, now=now)
    assert d["capture"] is False and d["existing"]["backup_id"] == 9


def test_age_is_read_from_the_machine_readable_stamp(app):
    """``created_at`` is formatted for a table cell.

    Deriving a budget from a presentation format leaves the budget one column
    change away from silently never firing again.
    """
    from app.services import rediscovery
    code = _code_of(rediscovery._dump_age_hours)
    assert "created_iso" in code
    assert "created_at" not in code


def test_evidence_index_publishes_that_stamp(app):
    from app.services import cli_coverage
    from tests.test_cli_coverage import _seed_dump
    _seed_dump(app)
    with app.app_context():
        rows = cli_coverage.evidence_index()
    assert rows and rows[0]["created_iso"]
    datetime.fromisoformat(rows[0]["created_iso"])   # parses, or this fails


def test_every_refusal_carries_a_distinct_sentence(app):
    """Four different "no"s. If two collapsed into one string the progress line
    would stop telling the operator which one happened."""
    from app.services import rediscovery
    reasons = {
        _decide(requested=False)["reason"],
        _decide(kind="fortianalyzer")["reason"],
        _decide(may_write_vault=False)["reason"],
        _decide(maintenance=True)["reason"],
        _decide(evidence=[_ev(hours_ago=1.0)])["reason"],
    }
    assert len(reasons) == 5
    assert all(reasons)
    assert _decide()["reason"] == ""       # and a yes says nothing


# ==========================================================================
# the sweep — the pass is last, opt-in, and cannot sink the sweep
# ==========================================================================

def test_the_flag_defaults_to_off_in_both_entry_points(app):
    from app.services import rediscovery
    assert inspect.signature(rediscovery._run).parameters["cli"].default is False
    assert inspect.signature(rediscovery.start).parameters["cli"].default is False


def test_device_registration_never_captures():
    """``views.appliances`` runs a sweep inline after registering a device.

    That call must stay REST-only: a 300 s SSH session inside the registration
    round-trip would look like a hung form.
    """
    src = VIEWS.read_text(encoding="utf-8")
    call = src[src.index("rediscovery._run(_rsnap"):]
    call = call[:call.index(")") + 1]
    assert "cli=True" not in call


def test_the_capture_runs_after_the_snapshot_is_already_on_disk(app):
    """Order is the safety property.

    ``_config.json`` — the sweep's product — is written before this pass opens
    a session, so nothing the capture does, including hanging to its 300 s
    ceiling, can cost the operator the sweep that already succeeded.
    """
    from app.services import rediscovery
    # ``_sweep``, not ``_run``: on 2026-09-15 ``_run`` became a thin guarded
    # wrapper whose only job is to write a TERMINAL state when the worker dies
    # (a crash used to leave "running" on disk forever). The ordering rule this
    # guard protects lives in the body, which is now ``_sweep``.
    code = _code_of(rediscovery._sweep)
    assert code.index("_config.json") < code.index("_run_cli")
    assert "if cli:" in code


def test_a_sweep_without_the_flag_never_opens_the_pass(app, monkeypatch):
    """The behavioural half of the default.

    A signature default is a promise; this is the delivery. Device registration
    and every other internal caller run ``_run`` without the flag, and they
    stay REST-only because of THIS.
    """
    from types import SimpleNamespace
    from app.services import rediscovery
    rediscovery._APP = app
    monkeypatch.setattr(rediscovery, "_device_firmware", lambda *a, **k: "7.6.8")
    called: list = []
    monkeypatch.setattr(rediscovery, "_run_cli",
                        lambda *a, **k: called.append(1))
    snap = SimpleNamespace(id=_make_appliance(app, name="fw-noflag"),
                           name="fw-noflag", host="192.0.2.99", port=443,
                           verify_ssl=False, username="admin", password="x",
                           vdom="", kind="fortiweb")
    rediscovery._run(snap, by="t", deep=False, plan=[], cli=False)
    assert called == []
    rediscovery._run(snap, by="t", deep=False, plan=[], cli=True)
    assert called == [1]


def test_start_forwards_the_flag_across_the_thread_boundary(app, monkeypatch):
    """``start`` is the last place that can ask; the worker cannot.

    A flag that is accepted by the route, recorded in the progress file and
    then dropped on the way into the thread would be invisible from every
    direction: the page would say the capture was requested and nothing would
    ever happen.
    """
    from app.services import rediscovery
    aid = _make_appliance(app, name="fw-fwd")
    captured: dict = {}

    class _Stub:
        def __init__(self, target=None, args=(), daemon=None):
            captured["args"] = args

        def start(self):
            pass

    monkeypatch.setattr(rediscovery.threading, "Thread", _Stub)
    with app.app_context():
        from app.models import Appliance, db
        row = db.session.get(Appliance, aid)
        res = rediscovery.start(row, by="t", cli=True)
    assert captured["args"][-1] is True
    assert res["progress"]["cli"] is True


def test_a_capture_failure_leaves_the_sweep_done(app, tmp_path, monkeypatch):
    from app.services import backup as backup_svc, rediscovery
    from types import SimpleNamespace
    aid = _make_appliance(app)
    rediscovery._APP = app
    monkeypatch.setattr(backup_svc, "fetch_device_backup_auto",
                        lambda *a, **k: (_ for _ in ()).throw(
                            RuntimeError("ssh: connection refused")))
    state = {"state": "done", "by": "tester"}
    path = tmp_path / "progress.json"
    rediscovery._run_cli(SimpleNamespace(id=aid, name="fw-sweep"), path, state)
    assert state["state"] == "done"
    assert "ssh: connection refused" in state["cli_error"]
    assert "cli_skipped" not in state


def test_a_skip_and_a_failure_never_share_a_key(app, tmp_path, monkeypatch):
    """Two outcomes that send the operator to opposite places."""
    from app.services import backup as backup_svc, rediscovery
    from types import SimpleNamespace
    aid = _make_appliance(app, name="fw-maint", maintenance=True)
    rediscovery._APP = app

    def _boom(*a, **k):
        raise AssertionError("a suppressed appliance must not be dialled")

    monkeypatch.setattr(backup_svc, "fetch_device_backup_auto", _boom)
    state = {"state": "done", "by": "tester"}
    rediscovery._run_cli(SimpleNamespace(id=aid, name="fw-maint"),
                         tmp_path / "p.json", state)
    assert state["cli_skipped"]
    assert "cli_error" not in state
    assert state["state"] == "done"


def test_a_capture_records_the_row_and_audits_it(app, tmp_path, monkeypatch):
    from types import SimpleNamespace
    from app.services import backup as backup_svc, rediscovery
    aid = _make_appliance(app, name="fw-ok")
    rediscovery._APP = app
    monkeypatch.setattr(backup_svc, "fetch_device_backup_auto",
                        lambda *a, **k: SimpleNamespace(
                            id=4242, size_bytes=690 * 1024, firmware="7.6.8"))
    state = {"state": "done", "by": "tester"}
    rediscovery._run_cli(SimpleNamespace(id=aid, name="fw-ok"),
                         tmp_path / "p.json", state)
    assert state["cli_backup_id"] == 4242 and state["cli_kb"] == 690
    with app.app_context():
        from app.models import AuditLog
        assert AuditLog.query.filter_by(action="appliance.cli_capture").count() == 1


def test_the_capture_uses_the_ssh_transport_explicitly(app, tmp_path, monkeypatch):
    """``auto`` would try a REST backup first.

    REST is exactly what the sweep just finished reading — and on a
    license-locked box (HTTP 423) it is what fails. This pass exists for the
    CLI text, so it asks for the CLI text.
    """
    from types import SimpleNamespace
    from app.services import backup as backup_svc, rediscovery
    aid = _make_appliance(app, name="fw-tr")
    rediscovery._APP = app
    seen = {}

    def _cap(row, **kw):
        seen.update(kw)
        return SimpleNamespace(id=1, size_bytes=1024, firmware="")

    monkeypatch.setattr(backup_svc, "fetch_device_backup_auto", _cap)
    rediscovery._run_cli(SimpleNamespace(id=aid, name="fw-tr"),
                         tmp_path / "p.json", {"state": "done", "by": "t"})
    assert seen.get("method") == "ssh"


def test_the_row_is_re_read_inside_the_thread_s_own_context(app):
    """A request's ORM instance carried into a worker thread is what made every
    status badge read "offline" on 2026-09-14 — and the credential this capture
    needs may live in the vault, which reads the DB."""
    from app.services import rediscovery
    code = _code_of(rediscovery._run_cli)
    assert "app_context()" in code
    assert "db.session.get(Appliance" in code


def test_a_dead_appliance_row_is_an_error_not_a_capture(app, tmp_path, monkeypatch):
    from types import SimpleNamespace
    from app.services import backup as backup_svc, rediscovery
    rediscovery._APP = app
    monkeypatch.setattr(backup_svc, "fetch_device_backup_auto",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("must not dial a row that is gone")))
    state = {"state": "done", "by": "t"}
    rediscovery._run_cli(SimpleNamespace(id=999999, name="ghost"),
                         tmp_path / "p.json", state)
    assert "cli_error" in state and state["state"] == "done"


# ==========================================================================
# the route — the vault permission the sweep endpoint never asked for
# ==========================================================================

def _start(client, app, aid, **form):
    return client.post(f"/appliances/{aid}/rediscover/start", data=form)


def test_the_flag_reaches_start_when_the_user_may_write_the_vault(
        app, client, monkeypatch):
    from app.services import rediscovery
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    seen = {}
    monkeypatch.setattr(rediscovery, "start",
                        lambda a, **kw: seen.update(kw) or {"started": True,
                                                            "progress": {}})
    _start(client, app, aid, deep="0", cli="1")
    assert seen["cli"] is True


def test_the_flag_is_refused_out_loud_without_the_vault_permission(
        app, client, monkeypatch):
    """Silently dropping it would let a user create vault rows through a door
    that never mentions the vault — and leave them waiting for a dump that was
    never going to be taken."""
    from app.services import rediscovery
    from app.models import Permission, User
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    # Everything EXCEPT the vault permission, so the request still passes the
    # route's own ``appliances.apply`` gate and the refusal under test is the
    # only thing that can stop the flag.
    monkeypatch.setattr(User, "can",
                        lambda self, perm: perm != Permission.BACKUP)
    seen = {}
    monkeypatch.setattr(rediscovery, "start",
                        lambda a, **kw: seen.update(kw) or {"started": True,
                                                            "progress": {}})
    r = _start(client, app, aid, cli="1")
    assert seen["cli"] is False
    assert rediscovery.CLI_SKIP_NO_PERMISSION in r.get_json()["cli_skipped"]


def test_no_flag_means_no_capture(app, client, monkeypatch):
    from app.services import rediscovery
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    seen = {}
    monkeypatch.setattr(rediscovery, "start",
                        lambda a, **kw: seen.update(kw) or {"started": True,
                                                            "progress": {}})
    _start(client, app, aid, deep="1")
    assert seen["cli"] is False and seen["deep"] is True


# ==========================================================================
# the page
# ==========================================================================

def test_the_in_flight_state_is_handled_everywhere_the_others_are(app):
    """``cli-running`` must appear in paint(), in poll()'s keep-polling test and
    in the server-rendered "resume polling" condition.

    Missing it in poll() is invisible in review and fatal in use: polling stops
    the moment the capture starts, so the operator watches a finished-looking
    bar and never learns the outcome.
    """
    html = PAGE.read_text(encoding="utf-8")
    assert html.count("'cli-running'") == html.count("'deep-running'")
    assert html.count("'cli-running'") >= 3


def test_the_switch_is_gated_on_the_product(app):
    html = PAGE.read_text(encoding="utf-8")
    assert "{% if allow_cli %}" in html
    src = VIEWS.read_text(encoding="utf-8")
    assert "cli_coverage.SUPPORTED_PRODUCTS" in src


def test_the_page_shows_the_switch_and_the_decision(app, client):
    aid = _make_appliance(app, name="fw-page")
    login(client, admin_user_id(app))
    body = client.get(f"/appliances/{aid}/rediscover").get_data(as_text=True)
    assert 'id="redisc-cli"' in body
    assert "CLI dump: none captured" in body


def test_the_page_states_the_reason_it_will_not_capture(app, client):
    """The preview comes from the SAME function the worker obeys, so the page
    cannot promise a capture the sweep then declines to take."""
    aid = _make_appliance(app, name="fw-maint-page", maintenance=True)
    login(client, admin_user_id(app))
    body = client.get(f"/appliances/{aid}/rediscover").get_data(as_text=True)
    assert "maintenance mode" in body


def test_the_body_sends_the_flag(app):
    html = PAGE.read_text(encoding="utf-8")
    assert "'&cli=' + (cli ? '1' : '0')" in html
