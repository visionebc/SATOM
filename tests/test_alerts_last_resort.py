"""The alert engine's one blind spot, and the line that covers it.

Every finding this product raises is recorded and dispatched THROUGH the
database, which means the single condition the alert engine can never report is
the one that takes the database down with it.

Measured, 2026-08-22, on the primary node: the filesystem reached 100 %,
PostgreSQL could not write ``pg_logical/replorigin_checkpoint.tmp``, and spent
five hours in crash -> recovery -> PANIC. ``satom-alerts.service`` failed every
fifteen minutes for that whole window with an SQLAlchemy connection trace.
Disk thresholds existed and had existed since 2026-08-06 (warn 80 %, crit
92 %) -- and were useless, because evaluating them needs the thing that was
already broken. Nowhere in any log did the words "filesystem full" appear,
while ``/healthz`` answered 200 throughout.

So the wrapper prints the machine's own numbers when the engine fails: read
with ``df``/``free``/``/proc/loadavg``, with no database, no network and no
dependency that can be down at the same moment. These tests pin the three
properties that make that line worth having.
"""
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy" / "satom-alerts.sh"


def _harness(tmp_path, engine: str) -> subprocess.CompletedProcess:
    """Run the wrapper with the engine replaced by ``engine``.

    The .env source and the ``cd`` are stubbed too: this exercises the
    last-resort BLOCK, which must work on any machine, not the node's config.
    """
    body = SCRIPT.read_text()
    body = body.replace("set -a; . /opt/satom/.env; set +a", "")
    body = body.replace("cd /opt/satom", "")
    body = body.replace("env FLASK_APP=wsgi:app venv/bin/flask alerts-run", engine)
    p = tmp_path / "wrapper.sh"
    p.write_text(body)
    return subprocess.run(["bash", str(p)], capture_output=True, text=True,
                          timeout=60)


def test_a_failed_run_states_the_machine_state_it_could_not_alert_about(tmp_path):
    out = _harness(tmp_path, "(exit 3)")
    blob = out.stdout + out.stderr
    assert "filesystem" in blob and "used" in blob, blob
    assert "memory" in blob, blob
    assert "load" in blob, blob


def test_the_failing_exit_code_survives(tmp_path):
    """systemd decides the unit failed from this number.

    The first version of this block read ``rc=$?`` AFTER an ``if``, which is the
    status of the if-statement (always 0): the unit would have reported the
    outage as a clean run.
    """
    assert _harness(tmp_path, "(exit 3)").returncode == 3
    assert "rc=3" in (_harness(tmp_path, "(exit 3)").stdout
                      + _harness(tmp_path, "(exit 3)").stderr)


def test_a_successful_run_says_nothing_extra(tmp_path):
    """A last-resort line on every healthy run is noise, and noise is how the
    one that matters gets skipped."""
    out = _harness(tmp_path, "true")
    assert out.returncode == 0
    assert "FAILED" not in (out.stdout + out.stderr)


def test_the_diagnosis_does_not_depend_on_the_database_or_the_network():
    """What the block is allowed to call. `psql`, `curl` or a flask command
    here would reintroduce exactly the dependency that failed."""
    body = SCRIPT.read_text()
    tail = body.split("[ \"$rc\" = 0 ] && exit 0", 1)[1]
    for forbidden in ("psql", "curl", "flask", "python", "wget", "nc "):
        assert forbidden not in tail, (
            "the last-resort block must read the machine directly; %r can be "
            "down at the same time as the thing it is reporting" % forbidden)
    for needed in ("df", "free", "/proc/loadavg"):
        assert needed in tail, needed
