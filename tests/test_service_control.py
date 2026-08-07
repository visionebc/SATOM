"""Guards for web service control (Settings -> General -> Services).

The thing that can go wrong here is not a crash: it is a button that reaches a
unit it was never meant to reach, or one that removes the only way to undo
itself and still reports success. Every guard below is about that.

The allowlist exists TWICE on purpose -- once in ``app/services/service_control``
for the web side and once inside ``deploy/self_update_runner`` for the root side
-- because the runner must not import the Flask package out of a tree the
service account can write (that is the escalation the curated pip allowlist was
moved out of). A duplicate is only safe while something fails when the copies
drift, and that is the first test here.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest

from app.services import service_control as sc

RUNNER = Path(__file__).resolve().parents[1] / "deploy" / "self_update_runner.py"


def _load_runner(app_dir: Path | None = None):
    """Import the root runner by path (stdlib-only module, no app imports)."""
    if app_dir is not None:
        os.environ["FM_APP_DIR"] = str(app_dir)
    spec = importlib.util.spec_from_file_location("_satom_runner_under_test", RUNNER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# the two copies of the allowlist
# ---------------------------------------------------------------------------

def test_runner_and_web_allowlists_are_identical():
    """Drift here is invisible: the web offers a button the runner refuses, or
    the runner accepts a unit the web never meant to expose."""
    runner = _load_runner()
    web = {u: tuple(e["actions"]) for u, e in sc.POLICY.items()}
    assert runner._SERVICE_POLICY == web


def test_runner_and_web_agree_on_the_action_vocabulary():
    runner = _load_runner()
    assert tuple(runner._SVC_ACTIONS) == tuple(sc.ACTIONS)
    assert tuple(runner._SVC_FORBIDDEN) == tuple(sc.FORBIDDEN)


# ---------------------------------------------------------------------------
# the updater is never controllable
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("unit", ["satom-updater.service", "satom-updater.path"])
@pytest.mark.parametrize("action", ["start", "stop", "restart"])
def test_the_privileged_runner_is_not_controllable_from_the_console(unit, action):
    """Stopping the updater means no later request can be processed -- including
    the one that would start it again. The button would brick its own escalation
    path and report success."""
    assert unit not in sc.POLICY
    assert sc.allowed(unit, action) is False
    with pytest.raises(ValueError):
        sc.request_service_action(unit, action, by="test")


# ---------------------------------------------------------------------------
# no action removes its own undo
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("unit", ["satom.service", "nginx.service",
                                  "postgresql.service"])
def test_units_that_serve_this_console_cannot_be_stopped(unit):
    """Stopping any of these leaves recovery possible only from a shell, and
    this page exists for the operator who has the browser and not the shell."""
    assert "stop" not in sc.POLICY[unit]["actions"]
    assert sc.allowed(unit, "stop") is False


def test_every_stoppable_unit_can_also_be_started_again():
    """A stop with no matching start is a one-way door with a button on it."""
    for unit, entry in sc.POLICY.items():
        if "stop" in entry["actions"]:
            assert "start" in entry["actions"], unit


# ---------------------------------------------------------------------------
# the shape of a request
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("unit", [
    "", "sshd.service", "satom", "satom.service; rm -rf /",
    "../../etc/passwd", "satom.service\nnginx.service", "*.service",
    "/usr/lib/systemd/system/satom.service", "satom.mount", "satom.socket",
])
def test_hostile_or_unknown_unit_names_are_refused(unit):
    assert sc.allowed(unit, "restart") is False
    with pytest.raises(ValueError):
        sc.request_service_action(unit, "restart", by="test")


@pytest.mark.parametrize("action", ["", "enable", "disable", "mask", "kill",
                                    "reload", "RESTART; ls", "daemon-reload"])
def test_only_start_stop_restart_are_emitted(action):
    """enable/disable are durable changes to what the node arms at boot and are
    deliberately not reachable from here."""
    assert sc.allowed("satom-scheduler.service", action) is False
    with pytest.raises(ValueError):
        sc.request_service_action("satom-scheduler.service", action, by="test")


def test_every_entry_explains_itself():
    """The note is what tells an operator what stopping it costs. An empty one
    turns the table into a row of unlabelled switches."""
    for unit, entry in sc.POLICY.items():
        assert entry["label"].strip(), unit
        assert len(entry["note"].strip()) > 20, unit
        assert entry["actions"], unit
        assert set(entry["actions"]) <= set(sc.ACTIONS), unit
        assert sc.UNIT_RE.match(unit), unit


# ---------------------------------------------------------------------------
# the runner re-validates (defence in depth)
# ---------------------------------------------------------------------------

def _run_forged(tmp_path, payload):
    """Feed the ROOT handler a request the web side would never have written."""
    (tmp_path / "data" / "update-requests").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / "update-status").mkdir(parents=True, exist_ok=True)
    runner = _load_runner(tmp_path)
    req = tmp_path / "data" / "update-requests" / "forged.json"
    body = {"id": "forged", "kind": "service", "requested_by": "attacker"}
    body.update(payload)
    req.write_text(json.dumps(body))
    runner.service_action(str(req))
    return json.loads((tmp_path / "data" / "update-status" / "forged.json").read_text())


@pytest.mark.parametrize("payload", [
    {"unit": "satom-updater.service", "action": "stop"},
    {"unit": "sshd.service", "action": "stop"},
    {"unit": "satom.service", "action": "stop"},
    {"unit": "nginx.service", "action": "stop"},
    {"unit": "postgresql.service", "action": "stop"},
    {"unit": "satom-scheduler.service", "action": "mask"},
    {"unit": "satom.service; touch /tmp/pwned", "action": "restart"},
])
def test_the_root_handler_refuses_a_forged_request(tmp_path, payload):
    """The web layer validating is not enough: the queue is a file, and the
    handler that reads it runs as root."""
    st = _run_forged(tmp_path, payload)
    assert st["state"] == "failed"
    assert not Path("/tmp/pwned").exists()


def test_the_root_handler_dequeues_even_when_it_refuses(tmp_path):
    """A refused request left on disk re-fires satom-updater.path forever."""
    _run_forged(tmp_path, {"unit": "sshd.service", "action": "stop"})
    left = list((tmp_path / "data" / "update-requests").glob("*.json"))
    assert left == []


# ---------------------------------------------------------------------------
# reading state is unprivileged and honest about absence
# ---------------------------------------------------------------------------

def test_states_covers_the_table_and_never_invents_buttons(monkeypatch):
    """A unit that is not installed on this node (satom-ha-datasync.timer on a
    standalone install) must come back neutral with no actions -- not as a red
    'stopped' the operator would try to fix."""
    monkeypatch.setattr(sc, "_show", lambda unit, prop: "not-found"
                        if prop == "LoadState" else "")
    rows = sc.states()
    assert [r["unit"] for r in rows] == list(sc.POLICY)
    for r in rows:
        assert r["installed"] is False
        assert r["actions"] == []
        assert r["ok"] is None          # neutral, not a failure


def test_states_offers_the_table_actions_when_the_unit_is_installed(monkeypatch):
    fake = {"LoadState": "loaded", "ActiveState": "active",
            "SubState": "running", "UnitFileState": "enabled"}
    monkeypatch.setattr(sc, "_show", lambda unit, prop: fake.get(prop, ""))
    for r in sc.states():
        assert r["installed"] is True
        assert r["ok"] is True
        assert tuple(r["actions"]) == sc.POLICY[r["unit"]]["actions"]


def test_reading_state_never_changes_it(monkeypatch):
    """states() is called on every card render; it must not be able to run a
    systemctl verb even if the property name were attacker-controlled."""
    seen = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        class R:
            stdout = "loaded"
        return R()

    monkeypatch.setattr(sc.subprocess, "run", fake_run)
    sc.states()
    assert seen, "expected systemctl reads"
    for cmd in seen:
        assert cmd[:2] == ["systemctl", "show"], cmd
        assert not ({"start", "stop", "restart", "enable", "disable", "mask"}
                    & set(cmd))


def test_the_forbidden_deny_survives_a_table_that_lists_the_updater(tmp_path):
    """``_SVC_FORBIDDEN`` promises the updater is refused *even if* a future
    edit adds it to the policy table. Without this test that promise is
    untested -- the absence from the table would be doing all the work, and the
    deny could be deleted with nothing going red. This is the one failure mode
    with no recovery path: a stopped updater cannot process the request that
    would start it again.
    """
    (tmp_path / "data" / "update-requests").mkdir(parents=True)
    (tmp_path / "data" / "update-status").mkdir(parents=True)
    runner = _load_runner(tmp_path)
    runner._SERVICE_POLICY["satom-updater.service"] = ("start", "stop", "restart")

    req = tmp_path / "data" / "update-requests" / "forged.json"
    req.write_text(json.dumps({"id": "forged", "kind": "service",
                               "unit": "satom-updater.service", "action": "stop",
                               "requested_by": "attacker"}))
    runner.service_action(str(req))
    st = json.loads((tmp_path / "data" / "update-status" / "forged.json").read_text())
    assert st["state"] == "failed"
    assert st["error"] == "unit forbidden"


def test_the_unit_regex_is_second_line_only():
    """Documented redundancy, not a gap.

    A mutation that widens ``UNIT_RE`` to ``.*`` does NOT make the guards fail,
    and that is correct: the table lookup is the gate, and a hostile string is
    refused because it is not a key in POLICY, not because a pattern rejected
    it. The regex earns its place by keeping the TABLE honest -- it is what
    stops a future entry from being a path, a glob or a name with a shell
    metacharacter in it. That is what this asserts, rather than pretending to
    test a check that cannot fail alone.
    """
    for unit in sc.POLICY:
        assert sc.UNIT_RE.match(unit), unit
    assert sc.UNIT_RE.match("satom.service; rm -rf /") is None
