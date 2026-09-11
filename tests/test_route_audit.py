"""Guards for the template/url_map audit and for the updater's restart policy.

WHAT THESE PROTECT (2026-08-17 incident). satom-node-2 served HTTP 500 on every
authenticated page for ~15 hours while the self-update reported SUCCESS:

* the updater assumed a standby's app is stopped, so it never restarted the
  workers -- the code on disk advanced, their url_map did not;
* ``import app`` (the standby's validation) runs in a FRESH interpreter, so it
  is green EXACTLY when the running workers are stale;
* ``/healthz`` renders no template, so a BuildError in ``base.html`` is
  invisible to it by construction.

Nothing failed. The page 500'd, the update said ok. These tests make both
halves of that impossible to reintroduce silently.
"""
import importlib.util
import os
import re
import subprocess
import types
from pathlib import Path

import pytest

from app.services import route_audit as ra

REPO = Path(__file__).resolve().parents[1]
RUNNER_PATH = REPO / "deploy" / "self_update_runner.py"


def _load_runner():
    """Import the privileged runner by path (it lives in deploy/, not a package)."""
    spec = importlib.util.spec_from_file_location("_sur", RUNNER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fake_app(endpoints):
    rules = [types.SimpleNamespace(endpoint=e) for e in endpoints]
    return types.SimpleNamespace(
        url_map=types.SimpleNamespace(iter_rules=lambda: iter(rules)))


def _write(tmp_path, name, body):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


# --------------------------------------------------------------------------
# the scanner
# --------------------------------------------------------------------------
def test_literal_endpoint_is_found_with_its_line(tmp_path):
    _write(tmp_path, "a.html", "<p>x</p>\n<a href=\"{{ url_for('bp.view') }}\">go</a>\n")
    refs, dynamic, count = ra.scan_template_endpoints(tmp_path)
    assert count == 1 and dynamic == []
    assert refs == [("a.html", 2, "bp.view")]


def test_both_quote_styles_are_scanned(tmp_path):
    _write(tmp_path, "a.html", "{{ url_for('one') }}{{ url_for(\"two\") }}")
    refs, _, _ = ra.scan_template_endpoints(tmp_path)
    assert {r[2] for r in refs} == {"one", "two"}


def test_nested_template_directories_are_scanned(tmp_path):
    _write(tmp_path, "partials/deep/x.html", "{{ url_for('deep.view') }}")
    refs, _, count = ra.scan_template_endpoints(tmp_path)
    assert count == 1
    assert refs[0][0].replace("\\", "/") == "partials/deep/x.html"
    assert refs[0][2] == "deep.view"


def test_jinja_comments_are_not_references(tmp_path):
    """{# ... #} is never evaluated, so an endpoint named inside one cannot
    raise. Counting it would produce a finding nobody can act on."""
    _write(tmp_path, "a.html", "{# {{ url_for('ghost.view') }} #}\n{{ url_for('real.view') }}")
    refs, _, _ = ra.scan_template_endpoints(tmp_path)
    assert [r[2] for r in refs] == ["real.view"]


def test_multiline_jinja_comment_does_not_shift_line_numbers(tmp_path):
    """Stripping comments must preserve line numbering, or every finding after
    a block comment points at the wrong line -- and a wrong line is worse than
    no line, because it sends the reader to innocent code."""
    _write(tmp_path, "a.html", "{#\ncomment\nspanning\n#}\n{{ url_for('real.view') }}")
    refs, _, _ = ra.scan_template_endpoints(tmp_path)
    assert refs == [("a.html", 5, "real.view")]


def test_html_comments_ARE_references(tmp_path):
    """Jinja evaluates inside <!-- -->; the browser hides the output, the
    BuildError still happens."""
    _write(tmp_path, "a.html", "<!-- {{ url_for('hidden.view') }} -->")
    refs, _, _ = ra.scan_template_endpoints(tmp_path)
    assert [r[2] for r in refs] == ["hidden.view"]


def test_dynamic_endpoints_are_reported_separately_not_dropped(tmp_path):
    _write(tmp_path, "a.html", "{{ url_for(target) }}")
    refs, dynamic, _ = ra.scan_template_endpoints(tmp_path)
    assert refs == []
    assert dynamic == [("a.html", 1)]


# --------------------------------------------------------------------------
# the audit
# --------------------------------------------------------------------------
def test_missing_endpoint_is_a_finding(tmp_path):
    _write(tmp_path, "base.html", "{{ url_for('bookmarks.panel') }}")
    res = ra.audit_template_endpoints(_fake_app(["auth.login"]), tmp_path)
    assert res["missing"] == [
        {"template": "base.html", "line": 1, "endpoint": "bookmarks.panel"}]


def test_registered_endpoint_is_not_a_finding(tmp_path):
    _write(tmp_path, "base.html", "{{ url_for('bookmarks.panel') }}")
    res = ra.audit_template_endpoints(_fake_app(["bookmarks.panel"]), tmp_path)
    assert res["missing"] == []


def test_dynamic_call_is_never_a_missing_finding(tmp_path):
    """A dynamic endpoint is unresolvable, not broken. Failing an update on one
    would block every legitimate release that uses the pattern."""
    _write(tmp_path, "a.html", "{{ url_for(whatever) }}")
    res = ra.audit_template_endpoints(_fake_app([]), tmp_path)
    assert res["missing"] == [] and len(res["dynamic"]) == 1


def test_blueprint_relative_endpoint_is_not_a_missing_finding(tmp_path):
    """url_for('.view') resolves against the blueprint that renders it, which
    is unknown statically."""
    _write(tmp_path, "a.html", "{{ url_for('.view') }}")
    res = ra.audit_template_endpoints(_fake_app([]), tmp_path)
    assert res["missing"] == []
    assert res["relative"][0]["endpoint"] == ".view"


def test_report_names_endpoint_template_and_line(tmp_path):
    _write(tmp_path, "base.html", "\n\n{{ url_for('gone.view') }}")
    text = ra.format_report(ra.audit_template_endpoints(_fake_app([]), tmp_path))
    assert "gone.view" in text and "base.html:3" in text


# --------------------------------------------------------------------------
# exit codes: 'could not check' must not read as 'checked and clean'
# --------------------------------------------------------------------------
def test_exit_codes_are_three_distinct_values():
    assert len({ra.EXIT_OK, ra.EXIT_MISSING, ra.EXIT_UNMEASURED}) == 3
    assert ra.EXIT_OK == 0


def test_unmeasured_is_not_ok_when_the_app_cannot_be_built(monkeypatch, capsys):
    """A build failure must not be reported as a clean audit."""
    import app as app_pkg

    def _boom():
        raise RuntimeError("no database")

    monkeypatch.setattr(app_pkg, "create_app", _boom)
    assert ra.main() == ra.EXIT_UNMEASURED
    assert "unmeasured" in capsys.readouterr().out


def test_main_does_not_leave_the_process_in_another_directory(tmp_path):
    """main() chdirs into the app root; leaking that would move the cwd of
    whatever called it. Start from somewhere ELSE than the app root, or the
    chdir is a no-op and this proves nothing."""
    import os as _os
    before = _os.getcwd()
    _os.chdir(tmp_path)
    try:
        ra.main()
        assert _os.getcwd() == str(tmp_path)
    finally:
        _os.chdir(before)


# --------------------------------------------------------------------------
# the live tree
# --------------------------------------------------------------------------
def test_the_real_templates_all_resolve(app):
    """The guard, pointed at production reality."""
    res = ra.audit_template_endpoints(app)
    assert res["templates"] > 100, "template root looks wrong"
    assert res["checked"] > 500, "scanner found almost no url_for -- it broke"
    assert res["missing"] == [], ra.format_report(res)


def test_base_html_is_covered_by_the_scan(app):
    """base.html:985 is where the incident actually fired; if the scanner ever
    stops reaching the base layout, the guard is decorative."""
    refs, _, _ = ra.scan_template_endpoints()
    assert any(r[0] == "base.html" for r in refs)


def test_removing_a_blueprint_reproduces_the_incident(app):
    """The exact 2026-08-17 failure: a url_map without the bookmarks blueprint
    must produce the finding the production log showed."""
    stale = [r for r in app.url_map.iter_rules()
             if not r.endpoint.startswith("bookmarks.")]
    res = ra.audit_template_endpoints(_fake_app([r.endpoint for r in stale]))
    assert any(m["endpoint"] == "bookmarks.panel" and m["template"] == "base.html"
               for m in res["missing"]), ra.format_report(res)


# --------------------------------------------------------------------------
# the updater's restart policy
# --------------------------------------------------------------------------
class _Steps:
    def __init__(self):
        self.steps = []

    def step(self, name, ok, detail=""):
        self.steps.append((name, ok, detail))

    def names(self):
        return [s[0] for s in self.steps]


@pytest.fixture()
def runner():
    return _load_runner()


def _patch_restart(runner, monkeypatch, *, healthy=True, audit=("ok", "templates=1"),
                   smoke=(True, "")):
    calls = []
    monkeypatch.setattr(runner.subprocess, "run",
                        lambda cmd, **kw: calls.append(list(cmd)) or
                        types.SimpleNamespace(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr(runner, "health_ok", lambda *a, **k: healthy)
    monkeypatch.setattr(runner, "route_audit_ok", lambda: audit)
    monkeypatch.setattr(runner, "import_smoke_ok", lambda: smoke)
    return calls


def test_running_app_is_restarted_even_on_a_standby(runner, monkeypatch):
    """THE regression. A standby that serves traffic must have its workers
    restarted; skipping it is what left a2 500ing on stale code."""
    calls = _patch_restart(runner, monkeypatch)
    st = _Steps()
    runner.restart_and_validate(st, True, True, "revision abc")
    assert any(runner.SERVICE in c for c in calls), calls
    assert "health check" in st.names()


def test_stopped_app_is_not_started_by_an_update(runner, monkeypatch):
    """The other half: an update must not turn a deliberately stopped node into
    a serving one."""
    calls = _patch_restart(runner, monkeypatch)
    st = _Steps()
    runner.restart_and_validate(st, True, False, "revision abc")
    assert not any(runner.SERVICE in c for c in calls), calls
    assert "import smoke" in st.names()


def test_scheduler_is_restarted_in_both_states(runner, monkeypatch):
    for was_active in (True, False):
        calls = _patch_restart(runner, monkeypatch)
        runner.restart_and_validate(_Steps(), True, was_active, "x")
        assert any(runner.SCHED in c for c in calls), (was_active, calls)


def test_failed_health_check_aborts_so_the_rollback_runs(runner, monkeypatch):
    _patch_restart(runner, monkeypatch, healthy=False)
    with pytest.raises(RuntimeError, match="health check"):
        runner.restart_and_validate(_Steps(), False, True, "x")


def test_a_broken_template_reference_fails_the_update(runner, monkeypatch):
    _patch_restart(runner, monkeypatch, audit=("missing", "MISSING bookmarks.panel"))
    with pytest.raises(RuntimeError, match="route audit"):
        runner.restart_and_validate(_Steps(), False, True, "x")


def test_an_unmeasurable_audit_does_not_roll_a_healthy_update_back(runner, monkeypatch):
    """'could not check' is not 'broken'. Rolling back on it would make every
    environment quirk look like a code defect."""
    _patch_restart(runner, monkeypatch, audit=("unmeasured", "venv missing"))
    st = _Steps()
    runner.restart_and_validate(st, False, True, "x")
    assert ("route audit", False, "venv missing") in st.steps


def test_audit_status_is_read_from_output_not_from_the_return_code(runner, monkeypatch):
    """A non-zero rc from a check that never started (runuser denied, missing
    venv) must not be reported as 'the templates are broken'."""
    monkeypatch.setattr(runner, "run", lambda *a, **k: types.SimpleNamespace(
        returncode=1, stdout="", stderr="runuser: may not be used by non-root users"))
    assert runner.route_audit_ok()[0] == "unmeasured"


def test_audit_status_missing_requires_a_real_finding(runner, monkeypatch):
    monkeypatch.setattr(runner, "run", lambda *a, **k: types.SimpleNamespace(
        returncode=1, stdout="templates=1 url_for=1 endpoints=0 missing=1 dynamic=0\n"
                            "  MISSING x -> a.html:1", stderr=""))
    assert runner.route_audit_ok()[0] == "missing"


def test_audit_status_ok_requires_the_audit_marker(runner, monkeypatch):
    """rc=0 from something that printed nothing recognisable is not a pass."""
    monkeypatch.setattr(runner, "run", lambda *a, **k: types.SimpleNamespace(
        returncode=0, stdout="", stderr=""))
    assert runner.route_audit_ok()[0] == "unmeasured"


# --------------------------------------------------------------------------
# structural: no update path may decide the restart from the ROLE again
# --------------------------------------------------------------------------
def _runner_source():
    return RUNNER_PATH.read_text()


def test_no_update_path_restarts_the_app_outside_the_shared_helper():
    """Every code/package/library update must go through restart_and_validate,
    which decides from the node's OBSERVED state. A branch that restarts (or
    skips restarting) the app on its own is how the assumption came back."""
    src = _runner_source()
    for fn in ("def process(", "def pip_change(", "def package_change("):
        body = src.split(fn, 1)[1].split("\ndef ", 1)[0]
        # Everything before the function's own `except` clause is the happy
        # path; the restarts after it are the rollback, which restores the
        # node rather than deciding its state.
        happy = body.split("\n    except Exception", 1)[0]
        strays = [ln.strip() for ln in happy.splitlines()
                  if 'systemctl", "restart", SERVICE' in ln]
        assert strays == [], "%s restarts the app outside the helper:\n%s" % (
            fn, "\n".join(strays))
        assert "restart_and_validate(" in happy, "%s never calls the helper" % fn


def test_the_false_premise_is_gone_from_the_source():
    """The comment that justified the bug ('app stays stopped' on a standby)
    must not come back -- it is the assumption, written down."""
    src = _runner_source()
    assert "app stays stopped" not in src
    assert "gunicorn crashes on a read-only replica" not in src


def test_every_update_entrypoint_snapshots_the_service_state():
    """process(), pip_change() and package_change() must each capture
    app_was_active BEFORE touching the node."""
    src = _runner_source()
    assert src.count("app_was_active = _svc_active(SERVICE) == \"active\"") == 3


def test_the_snapshot_is_taken_before_any_restart():
    """Taken after a restart, the snapshot would report the state the updater
    itself just created -- always 'active' -- and the check would be circular."""
    src = _runner_source()
    for fn in ("def process(", "def pip_change(", "def package_change("):
        body = src.split(fn, 1)[1].split("\ndef ", 1)[0]
        snap = body.index("app_was_active = _svc_active")
        restarts = [m.start() for m in re.finditer(r'systemctl", "restart"', body)]
        assert all(r > snap for r in restarts), fn


def test_the_runner_still_compiles(tmp_path):
    # PYTHONPYCACHEPREFIX, not a chmod: deploy/ is root-owned so the web
    # worker cannot rewrite the updater that runs as root. Compiling in
    # place would need that property relaxed to satisfy a test.
    env = dict(os.environ, PYTHONPYCACHEPREFIX=str(tmp_path))
    r = subprocess.run(["python3", "-m", "py_compile", str(RUNNER_PATH)],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
