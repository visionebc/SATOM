"""Integration Hooks — the guards that make user-supplied Python survivable.

Pure logic + REAL short-lived subprocesses: no Flask app, no DB, no network
(same shape as ``test_self_update.py``, which locks the app-side contract of the
other enqueue-then-privileged-runner feature).

Where a guard is about PROCESS behaviour — the timeout killing a process group,
a grandchild not outliving its parent, an undeclared secret not being in the
child's environment — it spawns a real interpreter against a real temp tree.
Mocking ``subprocess`` to prove things about ``subprocess`` proves nothing; the
2026-07-27 lesson in ``test_deploy_scripts.py`` is the same lesson.

The one thing every test here exists to protect: this product administers
production WAFs, and this feature runs code an operator typed into a textarea.
The web worker must never be the thing that runs it.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

from app.services import hook_runner as HR
from app.services import integration_hooks as IH
from app.services import integration_sdk as SDK

DEPLOY = Path(__file__).resolve().parent.parent / "deploy"

OK_HOOK = """
from satom_sdk import ctx
ctx.log("handling %s" % ctx.event)
ctx.result(True, {"crq_id": "CRQ-" + str(ctx.payload.get("cr_id"))})
"""


# ---------------------------------------------------------------------------
#  fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def store(tmp_path, monkeypatch):
    """Point BOTH halves of the feature at a throwaway tree.

    They import the directories by name, so each module has its own binding —
    patching one and not the other would let a test write requests the runner
    never sees (and pass anyway, which is worse).
    """
    dirs = {
        "HOOKS_DIR": tmp_path / "integrations",
        "REQ_DIR": tmp_path / "integration-requests",
        "STATUS_DIR": tmp_path / "integration-status",
    }
    for mod in (IH, HR):
        for name, path in dirs.items():
            monkeypatch.setattr(mod, name, path, raising=True)
    monkeypatch.setattr(HR, "CLAIM_DIR", tmp_path / "integration-claimed")
    # The venv interpreter does not exist in a test tree; the one running the
    # suite does, and it is the same CPython.
    monkeypatch.setattr(HR, "PYTHON", Path(sys.executable))
    for path in list(dirs.values()) + [HR.CLAIM_DIR]:
        path.mkdir(parents=True, exist_ok=True)

    class _Store:
        hooks = dirs["HOOKS_DIR"]
        reqs = dirs["REQ_DIR"]
        status = dirs["STATUS_DIR"]
        claims = HR.CLAIM_DIR
        tmp = tmp_path

    return _Store()


def mk_hook(slug, source=OK_HOOK, *, event="change.requested", enabled=True,
            timeout=10, secrets=()):
    return IH.save_hook(slug, source, {
        "name": slug, "event": event, "enabled": enabled,
        "timeout": timeout, "secrets": list(secrets)}, by="tester")


def run_one(event="change.requested", payload=None, *, resolver=None, by="tester"):
    """dispatch → drain → the final status of the single request produced."""
    rows = IH.dispatch(event, payload or {"cr_id": 412}, by=by)
    assert len(rows) == 1, "helper expects exactly one bound hook"
    for path in sorted(HR.REQ_DIR.glob("*.json")):
        HR.process_request_file(path, resolver=resolver)
    return IH.result(rows[0]["request_id"])


# ===========================================================================
#  1. The published contract
# ===========================================================================
def test_published_events_are_exactly_the_documented_set():
    """The catalogue is a published contract: a hook author binds to a name and
    a payload shape, so an event may not appear without both being written
    down. The count deliberately does NOT live in this function's name -- a
    literal in a name is a second place to update, and the two drift."""
    assert IH.EVENT_NAMES == (
        "change.requested", "change.approved", "window.opening",
        "window.closing", "upgrade.finished", "upgrade.failed",
        "alert.fired")


def test_every_event_documents_a_payload_shape_and_an_example():
    for name, spec in IH.EVENTS.items():
        assert spec["description"].strip(), name
        assert spec["payload"], "%s documents no payload" % name
        # The example must be a concrete instance of the documented shape, so
        # the editor's "what will I receive?" panel cannot drift from the docs.
        assert set(spec["example"]) == set(spec["payload"]), name


# ===========================================================================
#  2. save_hook — everything is rejected BEFORE it reaches the disk
# ===========================================================================
def test_syntax_error_is_rejected_at_save_not_at_run(store):
    """The author sees SyntaxError in the editor, not at 22:00 in a window."""
    with pytest.raises(ValueError) as exc:
        mk_hook("broken", "def f(:\n    pass\n")
    assert "syntax error" in str(exc.value).lower()
    assert "line 1" in str(exc.value)
    # and nothing was left behind — a hook that does not parse cannot be queued
    assert not (store.hooks / "broken").exists()
    assert IH.list_hooks() == []


def test_save_writes_source_and_normalised_meta(store):
    hook = mk_hook("crm", secrets=["crm_token"])
    assert (store.hooks / "crm" / "hook.py").read_text() == OK_HOOK
    meta = json.loads((store.hooks / "crm" / "meta.json").read_text())
    assert meta["event"] == "change.requested"
    assert meta["secrets"] == ["CRM_TOKEN"]        # upper-cased on the way in
    assert meta["created_by"] == "tester"
    assert hook["meta"]["timeout"] == 10
    # case is normalised, not rejected: "CRM" and "crm" are one hook, never two
    # directories that differ only by case on a case-insensitive filesystem
    assert IH.validate_slug("  CRM  ") == "crm"


@pytest.mark.parametrize("bad", [
    "", "x", "../etc", "/abs", "has space", "trailing/slash",
    "a" * 49, "-leading", "dot.dot",
])
def test_save_rejects_slugs_outside_the_charset(store, bad):
    """The slug becomes a directory name; the allow-list IS the traversal
    defence, which is why it is a regex and not a normalisation."""
    with pytest.raises(ValueError):
        mk_hook(bad)


def test_save_rejects_an_unknown_event(store):
    with pytest.raises(ValueError) as exc:
        mk_hook("crm", event="change.requsted")
    assert "unknown event" in str(exc.value)


def test_save_clamps_the_timeout_to_the_documented_ceiling(store):
    assert mk_hook("slow", timeout=99999)["meta"]["timeout"] == IH.MAX_TIMEOUT
    assert mk_hook("fast", timeout=0)["meta"]["timeout"] == IH.MIN_TIMEOUT
    assert mk_hook("junk", timeout="banana")["meta"]["timeout"] == IH.DEFAULT_TIMEOUT


def test_save_rejects_secret_names_outside_the_charset(store):
    with pytest.raises(ValueError):
        mk_hook("crm", secrets=["not a name"])
    with pytest.raises(ValueError):
        mk_hook("crm", secrets=["1LEADING_DIGIT"])
    assert not (store.hooks / "crm").exists()


def test_save_rejects_an_oversized_source(store):
    with pytest.raises(ValueError):
        mk_hook("fat", "x = 1\n" * (IH.MAX_SOURCE_BYTES // 3))


def test_save_keeps_the_previous_source_in_version_history(store):
    mk_hook("crm", "a = 1\n")
    mk_hook("crm", "a = 2\n")
    mk_hook("crm", "a = 3\n")
    hook = IH.get_hook("crm")
    assert hook["source"] == "a = 3\n"
    assert len(hook["versions"]) == 2          # the two superseded revisions
    archived = sorted((store.hooks / "crm" / "versions").glob("*.py"))
    assert [p.read_text() for p in archived] == ["a = 1\n", "a = 2\n"]


def test_save_writes_an_audit_row(store, monkeypatch):
    rows = []
    monkeypatch.setattr(IH, "_audit", lambda a, target, extra: rows.append((a, target, extra)))
    mk_hook("crm")
    assert rows[0][0] == "integration.hook.save"
    assert rows[0][1] == "crm"
    assert rows[0][2]["event"] == "change.requested"


def test_list_hooks_skips_a_corrupt_meta_instead_of_blanking_the_page(store):
    mk_hook("good")
    bad = store.hooks / "bad"
    bad.mkdir()
    (bad / "meta.json").write_text("{not json")
    (bad / "hook.py").write_text("pass\n")
    assert [h["slug"] for h in IH.list_hooks()] == ["good"]


def test_delete_hook_removes_the_whole_tree(store):
    mk_hook("crm", "a = 1\n")
    mk_hook("crm", "a = 2\n")            # creates versions/
    assert IH.delete_hook("crm") is True
    assert not (store.hooks / "crm").exists()
    assert IH.get_hook("crm") is None
    assert IH.delete_hook("crm") is False


# ===========================================================================
#  3. dispatch — the web worker's half NEVER executes
# ===========================================================================
def test_dispatch_never_executes_anything(store, monkeypatch):
    """The load-bearing guard of the entire feature.

    Every primitive that could start a process is booby-trapped for the
    duration of the call. dispatch must still return queued rows, having done
    nothing but write JSON.
    """
    mk_hook("crm")

    def boom(*a, **kw):
        raise AssertionError("the web worker tried to spawn a process")

    for target, name in ((subprocess, "Popen"), (subprocess, "run"),
                         (subprocess, "call"), (subprocess, "check_output"),
                         (os, "fork"), (os, "posix_spawn"), (os, "system"),
                         (os, "execv"), (os, "popen")):
        monkeypatch.setattr(target, name, boom, raising=False)

    rows = IH.dispatch("change.requested", {"cr_id": 1}, by="alice")

    assert rows == [{"slug": "crm", "request_id": rows[0]["request_id"],
                     "status": "queued"}]
    assert len(list(store.reqs.glob("*.json"))) == 1
    assert IH.result(rows[0]["request_id"])["status"] == "queued"


def test_the_web_worker_module_has_no_way_to_spawn():
    """Belt to the previous test's braces, checked structurally so no future
    edit can quietly reintroduce in-worker execution.

    (``compile()`` is allowed and used: it parses and byte-compiles, it does not
    run anything. That distinction is the whole reason save-time validation is
    safe in the worker.)
    """
    import ast

    tree = ast.parse(Path(IH.__file__).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not imported & {"subprocess", "multiprocessing", "pty", "ctypes"}

    called = {n.func.id for n in ast.walk(tree)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert not called & {"exec", "eval", "__import__"}

    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not attrs & {"fork", "system", "popen", "posix_spawn", "execv",
                        "execvp", "spawnv", "Popen", "run"}


def test_dispatch_writes_one_request_per_bound_hook(store):
    mk_hook("crm")
    mk_hook("pager")
    rows = IH.dispatch("change.requested", {"cr_id": 7}, by="alice")
    assert [r["slug"] for r in rows] == ["crm", "pager"]
    files = sorted(store.reqs.glob("*.json"))
    assert len(files) == 2
    req = json.loads(files[0].read_text())
    assert req["event"] == "change.requested"
    assert req["payload"] == {"cr_id": 7}
    assert req["requested_by"] == "alice"


def test_a_disabled_hook_is_not_dispatched(store):
    mk_hook("crm", enabled=False)
    mk_hook("pager", enabled=True)
    rows = IH.dispatch("change.requested", {"cr_id": 1}, by="alice")
    assert [r["slug"] for r in rows] == ["pager"]
    assert len(list(store.reqs.glob("*.json"))) == 1


def test_dispatch_ignores_hooks_bound_to_another_event(store):
    mk_hook("on-approve", event="change.approved")
    assert IH.dispatch("change.requested", {"cr_id": 1}, by="a") == []
    assert list(store.reqs.glob("*.json")) == []


def test_dispatch_rejects_an_unknown_event(store):
    mk_hook("crm")
    with pytest.raises(ValueError) as exc:
        IH.dispatch("change.requsted", {}, by="alice")
    assert "unknown event" in str(exc.value)
    assert list(store.reqs.glob("*.json")) == []


def test_dry_run_resolves_the_hooks_without_writing_anything(store):
    mk_hook("crm")
    rows = IH.dispatch("change.requested", {"cr_id": 1}, by="a", dry_run=True)
    assert rows == [{"slug": "crm", "request_id": "", "status": "dry-run"}]
    assert list(store.reqs.glob("*.json")) == []
    assert list(store.status.glob("*.json")) == []


# ===========================================================================
#  4. Atomicity — a half-written file is never visible to the drain
# ===========================================================================
def _observe_replace(monkeypatch, watch_dir: Path):
    """Record what a concurrent drain would see at each ``os.replace``."""
    seen = []
    real = os.replace

    def spy(src, dst):
        src_p = Path(src)
        seen.append({
            "src": src_p.name,
            "src_parses": _parses(src_p),
            "queue": sorted(p.name for p in watch_dir.glob("*.json")),
        })
        return real(src, dst)

    monkeypatch.setattr(os, "replace", spy)
    return seen


def _parses(path: Path) -> bool:
    try:
        json.loads(path.read_text())
        return True
    except Exception:
        return False


def test_a_request_file_is_never_visible_half_written(store, monkeypatch):
    mk_hook("crm")
    seen = _observe_replace(monkeypatch, store.reqs)
    rows = IH.dispatch("change.requested", {"cr_id": 1}, by="alice")
    rid = rows[0]["request_id"]

    for step in seen:
        # the temp is invisible to the runner's glob AND to `ls`
        assert step["src"].startswith("."), step
        assert not step["src"].endswith(".json"), step
        # it is COMPLETE before the swap — the swap is what publishes it
        assert step["src_parses"], step
        # the destination name never appears in the queue before its replace
        assert rid + ".json" not in step["queue"], step
    assert (store.reqs / (rid + ".json")).is_file()


def test_a_status_file_is_never_visible_half_written(store, monkeypatch):
    """Same rule on the runner side: the UI polls this file while it is being
    rewritten, so a reader sees the old state or the new one, never half."""
    seen = _observe_replace(monkeypatch, store.status)
    HR.write_status("req-1", slug="crm", status="running")
    HR.write_status("req-1", status="ok", stdout="x")
    assert seen, "no atomic write happened"
    for step in seen:
        assert step["src"].startswith(".") and step["src"].endswith(".tmp"), step
        assert step["src_parses"], step
    assert IH.result("req-1")["status"] == "ok"


def test_the_status_exists_before_the_request_is_publishable(store, monkeypatch):
    """Ordering guard: the runner can pick a request up the instant it lands,
    so its status file has to be there first or the UI renders 'unknown' for a
    job that is already running."""
    mk_hook("crm")
    order = []
    real = os.replace

    def spy(src, dst):
        order.append(Path(dst).parent.name)
        return real(src, dst)

    monkeypatch.setattr(os, "replace", spy)
    IH.dispatch("change.requested", {"cr_id": 1}, by="a")
    assert order == ["integration-status", "integration-requests"]


def test_result_and_recent_read_the_status_back(store):
    mk_hook("crm")
    rows = IH.dispatch("change.requested", {"cr_id": 1}, by="a")
    rid = rows[0]["request_id"]
    st = IH.result(rid)
    assert st["slug"] == "crm" and st["event"] == "change.requested"
    assert st["status"] in IH.STATUSES
    assert [r["request_id"] for r in IH.recent(5)] == [rid]
    assert IH.result("nope") is None
    assert IH.result("../../etc/passwd") is None


# ===========================================================================
#  5. The runner — real subprocesses
# ===========================================================================
def test_a_hook_runs_out_of_process_and_reports_its_result(store):
    mk_hook("crm")
    st = run_one(payload={"cr_id": 412})
    assert st["status"] == "ok"
    assert st["exit_code"] == 0
    assert st["data"] == {"crq_id": "CRQ-412"}
    assert "handling change.requested" in st["stdout"]
    assert st["duration_ms"] >= 0 and st["started_at"] and st["finished_at"]


def test_an_undeclared_secret_is_absent_from_the_child_environment(store):
    """It is not merely unreadable — it was never injected, so there is nothing
    in the process to read."""
    mk_hook("crm", """
import os
from satom_sdk import ctx
ctx.result(True, {"env": sorted(k for k in os.environ)})
""", secrets=["CRM_TOKEN"])

    vault = {"CRM_TOKEN": "declared-value-1234",
             "OTHER_TOKEN": "undeclared-value-1234"}
    st = run_one(resolver=vault.get)

    env_keys = st["data"]["env"]
    assert "SATOM_SECRET_CRM_TOKEN" in env_keys
    assert "SATOM_SECRET_OTHER_TOKEN" not in env_keys
    assert not any(k.endswith("OTHER_TOKEN") for k in env_keys)


def test_the_child_inherits_none_of_the_runners_own_credentials(store, monkeypatch):
    """The unit is started with EnvironmentFile=/opt/satom/.env, so inheriting
    os.environ would hand every hook the DB URI and the Fernet key."""
    monkeypatch.setenv("FERNET_KEY", "runner-only-fernet-key")
    monkeypatch.setenv("SQLALCHEMY_DATABASE_URI", "postgresql://u:p@127.0.0.1/satom")
    monkeypatch.setenv("SECRET_KEY", "runner-only-flask-secret")
    mk_hook("crm", """
import os
from satom_sdk import ctx
ctx.result(True, {"env": sorted(os.environ), "values": list(os.environ.values())})
""")
    st = run_one()
    for leaked in ("FERNET_KEY", "SQLALCHEMY_DATABASE_URI", "SECRET_KEY"):
        assert leaked not in st["data"]["env"]
    assert not any("postgresql://" in v for v in st["data"]["values"])


def test_a_declared_secrets_value_is_redacted_from_captured_stdout(store):
    """A hook that prints its own token must not leak it into a status file the
    web UI renders."""
    token = "sk-live-9f3a2b7c-do-not-log"
    mk_hook("crm", """
from satom_sdk import ctx
print("calling CRM with " + ctx.secret("CRM_TOKEN"))
ctx.result(True, None)
""", secrets=["CRM_TOKEN"])

    st = run_one(resolver={"CRM_TOKEN": token}.get)
    assert st["status"] == "ok"
    assert token not in st["stdout"]
    assert "***REDACTED:CRM_TOKEN***" in st["stdout"]


def test_a_declared_secrets_value_is_redacted_from_the_result_data_too(store):
    token = "sk-live-9f3a2b7c-do-not-log"
    mk_hook("crm", """
from satom_sdk import ctx
ctx.result(True, {"auth_header": "Bearer " + ctx.secret("CRM_TOKEN")})
""", secrets=["CRM_TOKEN"])

    st = run_one(resolver={"CRM_TOKEN": token}.get)
    assert token not in json.dumps(st["data"])
    assert st["data"]["auth_header"] == "Bearer ***REDACTED:CRM_TOKEN***"


def test_redaction_happens_before_truncation(store):
    """Truncating first can cut a token in half and leave the first 40
    characters of it permanently visible."""
    token = "sk-" + "z" * 60
    secrets = {"CRM_TOKEN": token}
    text = ("x" * (IH.STDOUT_CAP - 10)) + token + ("y" * 500)
    out = HR.truncate(HR.redact(text, secrets))
    assert token not in out
    assert token[:20] not in out


def test_a_hook_printing_fake_json_cannot_fake_its_result(store):
    """stdout is a log, and only a log. The result arrives on a descriptor the
    runner owns, so text on stdout can neither invent nor override it."""
    mk_hook("crm", """
from satom_sdk import ctx
print('{"ok": true, "data": {"crq_id": "FORGED"}}')
print('{"ok":true}')
ctx.result(False, {"crq_id": "REAL"})
""")
    st = run_one()
    assert st["status"] == "failed"                  # the channel won, not stdout
    assert st["data"] == {"crq_id": "REAL"}
    assert st["exit_code"] == 0                      # it exited cleanly and still failed
    assert "FORGED" in st["stdout"]                  # printed, and inert


def test_a_hook_that_never_reports_defaults_to_the_exit_code(store):
    mk_hook("crm", "print('did some work')\n")
    st = run_one()
    assert st["status"] == "ok"
    assert st["data"] is None
    assert st["result_reported"] is False


def test_stdout_is_truncated_at_the_documented_cap(store):
    mk_hook("noisy", """
from satom_sdk import ctx
print("A" * 200000)
ctx.result(True, None)
""")
    st = run_one()
    assert st["status"] == "ok"
    assert len(st["stdout"]) <= IH.STDOUT_CAP
    assert "truncated" in st["stdout"]


def test_a_timeout_kills_the_process_group_and_the_grandchild_dies_with_it(store):
    """A hook that shells out would otherwise leave the grandchild holding the
    connection long after the hook it belongs to was declared dead."""
    sentinel = store.tmp / "grandchild-was-here"
    mk_hook("runaway", """
import subprocess, sys, time
from satom_sdk import ctx
child = subprocess.Popen([sys.executable, "-c",
    "import sys, time; time.sleep(30); open(sys.argv[1], 'w').write('alive')",
    ctx.payload["sentinel"]])
print("GRANDCHILD_PID=%d" % child.pid, flush=True)
time.sleep(30)
""", timeout=1)

    t0 = time.monotonic()
    st = run_one(payload={"sentinel": str(sentinel)})
    elapsed = time.monotonic() - t0

    assert st["status"] == "timeout"
    assert "process group killed" in st["error"]
    # If only the direct child had been killed, draining the pipe would have
    # blocked on the grandchild's inherited stdout until REAP_TIMEOUT.
    assert elapsed < 1 + HR.KILL_GRACE + HR.REAP_TIMEOUT

    match = re.search(r"GRANDCHILD_PID=(\d+)", st["stdout"])
    assert match, st["stdout"]
    pid = int(match.group(1))
    time.sleep(0.2)
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    assert not sentinel.exists()


def test_a_nonzero_exit_is_a_failure_with_the_traceback_kept(store):
    mk_hook("crm", "raise RuntimeError('the CRM said no')\n")
    st = run_one()
    assert st["status"] == "failed"
    assert st["exit_code"] != 0
    assert "the CRM said no" in st["stdout"]     # stderr is merged into stdout


def test_a_hook_cannot_import_the_application(store):
    """cwd is a private temp dir and PYTHONPATH is not inherited, so /opt/satom
    is not on sys.path: no ORM, no Fernet key, no appliance credentials."""
    mk_hook("nosy", """
from satom_sdk import ctx
import app.models
ctx.result(True, None)
""")
    st = run_one()
    assert st["status"] == "failed"
    assert "ModuleNotFoundError" in st["stdout"] or "ImportError" in st["stdout"]


def test_disabling_a_hook_stops_work_that_is_already_queued(store):
    """The kill switch has to apply to the queue, not only to requests that do
    not exist yet — that is the button an operator hits during an outage."""
    mk_hook("crm")
    rows = IH.dispatch("change.requested", {"cr_id": 1}, by="a")
    IH.set_enabled("crm", False)
    for path in sorted(HR.REQ_DIR.glob("*.json")):
        HR.process_request_file(path)
    st = IH.result(rows[0]["request_id"])
    assert st["status"] == "failed"
    assert "disabled" in st["error"]


def test_a_declared_but_unconfigured_secret_is_reported_not_guessed(store):
    mk_hook("crm", """
from satom_sdk import ctx
try:
    ctx.secret("CRM_TOKEN")
    ctx.result(True, "got one")
except KeyError as exc:
    ctx.result(False, str(exc))
""", secrets=["CRM_TOKEN"])
    st = run_one(resolver=lambda name: None)
    assert st["status"] == "failed"
    assert "CRM_TOKEN" in st["error"] and "not configured" in st["error"]


# ===========================================================================
#  6. Draining the queue
# ===========================================================================
def test_main_drains_the_queue_and_leaves_no_claims_behind(store, monkeypatch):
    monkeypatch.setattr(HR, "_push_app_context", lambda: None)
    mk_hook("crm")
    mk_hook("pager")
    rows = IH.dispatch("change.requested", {"cr_id": 9}, by="a")
    assert HR.main() == 0
    assert list(store.reqs.glob("*.json")) == []
    assert list(store.claims.glob("*.json")) == []
    assert {IH.result(r["request_id"])["status"] for r in rows} == {"ok"}


def test_the_runner_ignores_temp_and_non_json_files(store, monkeypatch):
    monkeypatch.setattr(HR, "_push_app_context", lambda: None)
    (store.reqs / ".half-written.json.tmp").write_text("{")
    (store.reqs / "README.txt").write_text("not a request")
    assert HR.main() == 0
    assert (store.reqs / ".half-written.json.tmp").exists()
    assert (store.reqs / "README.txt").exists()


def test_a_malformed_request_is_dropped_instead_of_crash_looping_the_unit(store):
    """DirectoryNotEmpty is level-triggered: a request the runner cannot parse
    and does not remove re-fires the unit forever."""
    bad = store.reqs / "20260809-000000-x-abc.json"
    bad.write_text("{not json")
    assert HR.process_request_file(bad) is None
    assert not bad.exists()


def test_a_request_is_claimed_out_of_the_watched_directory_before_it_runs(store):
    """At-most-once: a crash mid-hook must not replay and open a second CRQ."""
    mk_hook("crm", """
import os
from satom_sdk import ctx
ctx.result(True, {"queue": sorted(os.listdir(ctx.payload["reqdir"]))})
""")
    st = run_one(payload={"reqdir": str(store.reqs)})
    assert st["data"]["queue"] == []          # already claimed while running


def test_a_stale_claim_becomes_a_visible_failure(store):
    """A node rebooted mid-hook must not leave the UI spinning on 'running'."""
    HR.write_status("req-stale", slug="crm", status="running")
    claim = store.claims / "req-stale.json"
    claim.write_text("{}")
    old = time.time() - HR.STALE_CLAIM_AFTER - 60
    os.utime(claim, (old, old))
    assert HR.reconcile_stale_claims() == ["req-stale"]
    st = IH.result("req-stale")
    assert st["status"] == "failed"
    assert "stopped while this hook was running" in st["error"]
    assert not claim.exists()


# ===========================================================================
#  7. The SDK's http wrapper
# ===========================================================================
class _FakeResponse:
    status = 200
    headers = {"Content-Type": "application/json"}

    def read(self, n=None):
        return b'{"id": "CRQ-1"}'

    def geturl(self):
        return "https://crm.example/api"

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_every_http_request_carries_a_forced_timeout(monkeypatch):
    """A hook that hangs on somebody else's CRM must not hold a runner slot."""
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["timeout"] = timeout
        return _FakeResponse()

    monkeypatch.setattr(SDK.urllib.request, "urlopen", fake_urlopen)
    ctx = SDK.Context(timeout=30)
    assert ctx.http.get("https://crm.example/api").json() == {"id": "CRQ-1"}
    assert isinstance(seen["timeout"], float) and 0 < seen["timeout"] <= 30

    ctx.http.post("https://crm.example/api", json={"a": 1}, timeout=None)
    assert seen["timeout"] == SDK.DEFAULT_HTTP_TIMEOUT


def test_an_http_timeout_cannot_exceed_the_hooks_own_budget(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["timeout"] = timeout
        return _FakeResponse()

    monkeypatch.setattr(SDK.urllib.request, "urlopen", fake_urlopen)
    ctx = SDK.Context(timeout=2)
    ctx.http.get("https://crm.example/api", timeout=300)
    assert seen["timeout"] <= 2


def test_ctx_http_refuses_schemes_that_are_not_http(monkeypatch):
    """urllib speaks file:// and ftp://; ctx.http is for reaching YOUR systems,
    not for reading this node."""
    ctx = SDK.Context(timeout=10)
    for url in ("file:///etc/passwd", "ftp://x/y", "/etc/passwd"):
        with pytest.raises(SDK.HookHttpError):
            ctx.http.get(url)


def test_ctx_result_can_only_be_reported_once():
    ctx = SDK.Context(timeout=10)
    ctx.result(True, {"a": 1})
    with pytest.raises(RuntimeError):
        ctx.result(True, {"a": 2})


# ===========================================================================
#  8. The systemd units
# ===========================================================================
def test_the_units_mirror_the_updater_pattern_and_watch_the_right_queue():
    path_unit = (DEPLOY / "satom-integrations.path").read_text()
    service = (DEPLOY / "satom-integrations.service").read_text()

    # Against the module constant, never a literal: dispatch() writes to
    # IH.REQ_DIR, so THAT is what the unit has to watch. A hardcoded path
    # here fails when the queue legitimately moves and says nothing when
    # the two actually drift apart.
    assert f"DirectoryNotEmpty={IH.REQ_DIR}" in path_unit
    assert "Unit=satom-integrations.service" in path_unit
    assert "WantedBy=multi-user.target" in path_unit
    # the documented incident: a .path disabled on the standby silently parks
    # every enqueued request in `queued` forever
    assert "BOTH HA NODES" in path_unit

    assert "Type=oneshot" in service
    assert "WorkingDirectory=/opt/satom" in service
    assert "/opt/satom/venv/bin/python -m app.services.hook_runner" in service
    # the deliberate inversion of the updater: this one runs untrusted code
    assert "User=satom" in service and "Group=satom" in service
    assert "User=root" not in service
    assert "NoNewPrivileges=true" in service
    assert "ProtectSystem=strict" in service
