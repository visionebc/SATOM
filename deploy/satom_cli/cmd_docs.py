"""'show' commands that are pure reference. STDLIB ONLY (see context.py).

Reference material that is only in the wiki, in docs/ or on the public site is
reference material that is unavailable on a node with no web UI, no browser and
no route to the internet — which is the situation this CLI is for. So it ships
inside the binary.
"""
from pathlib import Path

from .context import UNITS
from .render import Result
from .runbooks import ORDER, RUNBOOKS

# The canonical layout. Written out because half of a recovery is knowing where
# to look, and because the rename from fortinet-manager left stale paths in DB
# rows and documentation for weeks after the code was clean.
PATHS = [
    ("/opt/satom", "application tree, owned by the service account"),
    ("/opt/satom/.env", "secrets — 0640 root:<service account>, app only READS it"),
    ("/opt/satom/venv", "per-node virtualenv; NOT in git, NOT replicated"),
    ("/opt/satom/data", "replicated to the standby by rsync (--delete)"),
    ("/opt/satom/data/acme", "0700 — the ACME account key MUST persist"),
    ("/opt/satom/data/jobs", "background-job ledger, one JSON per job"),
    ("/opt/satom/data/system_backups", "pg_dump bundles"),
    ("/opt/satom/data/git-bundles", "git bundle --all, includes refs/backup/*"),
    ("/opt/satom/data/update-requests", "the web worker writes here; it never applies"),
    ("/opt/satom/data/update-status", "what the privileged runner did"),
    ("/opt/satom/state", "node-local, NOT replicated (cert-renew journal)"),
    ("/opt/satom/pki", "node-local; the CA key exists only on the primary"),
    ("/opt/satom/reports", "device source of truth, versioned in git"),
    ("/var/log/satom", "application logs"),
    ("/usr/local/sbin/satom*", "deployed scripts — the units run THESE, not deploy/"),
    ("/usr/local/lib/satom-cli", "this CLI, root-owned, outside the app tree"),
    ("/etc/systemd/system/satom*", "units; User= lives in a .d/ drop-in, not the unit"),
    ("/etc/sudoers.d/satom", "the service account's two allowed commands"),
    ("/etc/nginx/sites-enabled", "satom-tls.conf must own default_server on :443"),
]

PORTS = [
    ("443", "nginx", "the application, fleet wildcard certificate"),
    ("8443", "nginx", "authenticated node-to-node channel (peer probes)"),
    ("80", "nginx", "redirect + the ACME http-01 challenge location"),
    ("8000", "gunicorn", "the app itself; the edge path kept as a rollback"),
    ("5432", "postgresql", "local + the replication line, hostssl clientcert=verify-ca"),
    ("22", "sshd", "the standby pulls data/ over a forced-command key"),
]

SCHEDULE = [
    ("satom-scheduler", "continuous", "fires scheduled actions — PRIMARY only"),
    ("satom-updater.path", "on demand", "watches data/update-requests (root runner)"),
    ("satom-alerts.timer", "every 15 min", "evaluates the health signals"),
    ("satom-cert-renew.timer", "03:30 daily", "renews a CA-issued service cert"),
    ("satom-git-publish.timer", "hourly", "publishes reports/ to git (copy 3)"),
    ("satom-ha-datasync.timer", "every 5 min", "STANDBY pulls data/ from the primary"),
    ("action: device_sync", "hourly", "refresh the device source of truth"),
    ("action: system_backup", "01:30", "pg_dump bundle (+ git, + external server)"),
    ("action: device_inspect", "02:45", "nightly SoT snapshot -> git"),
    ("action: git_bundle", "03:15", "git bundle --all (copy on 4 destinations)"),
    ("action: deep_monitor", "every 3 min", "probe sweep"),
]


def paths(ctx, args):
    r = Result("info", "filesystem layout")
    rows = []
    for p, what in PATHS:
        probe = Path(p.replace("/opt/satom", str(ctx.app_dir)).rstrip("*"))
        mark = "" if ("*" in p or probe.exists()) else "   [absent]"
        rows.append((p, what + mark))
    r.rows("", rows)
    r.note("data/ is replicated with rsync --delete: deleting on the standby is "
           "undone within 5 minutes. state/ and pki/ are node-local ON PURPOSE — "
           "the node that fails to renew a certificate is the one that must be "
           "able to record its own failure.")
    return r


def ports(ctx, args):
    r = Result("info", "ports")
    r.rows("", [("%-5s %-12s" % (p, owner), what) for p, owner, what in PORTS])
    r.lines("check what is actually listening", ["  satom diagnose network",
                                                 "  satom diagnose nginx"])
    return r


def schedule(ctx, args):
    r = Result("info", "what SHOULD run, and how often")
    r.rows("", [("%-26s %-13s" % (name, when), what) for name, when, what in SCHEDULE])
    r.lines("what actually runs here", ["  satom get timer status",
                                        "  satom get scheduler status"])
    r.note("The timers ship with the installer. The ACTIONS do not: no "
           "ScheduledAction row is ever seeded, so a fresh node runs none of "
           "them. 'satom diagnose install' says whether this one does.")
    return r


def runbook(ctx, args):
    """Recovery procedures, offline."""
    if not args:
        r = Result("info", "runbooks — satom show runbook <topic>")
        r.rows("", [(t, RUNBOOKS[t][0]) for t in ORDER if t in RUNBOOKS])
        return r
    topic = args[0]
    if topic not in RUNBOOKS:
        import difflib
        r = Result("bad", "no runbook '%s'" % topic, exit_code=2)
        near = difflib.get_close_matches(topic, list(RUNBOOKS), n=3, cutoff=0.4)
        if near:
            r.lines("did you mean", near)
        r.lines("topics", [t for t in ORDER if t in RUNBOOKS])
        return r
    title, lines = RUNBOOKS[topic]
    r = Result("info", "%s — %s" % (topic, title))
    r.lines("", lines)
    return r


def changelog(ctx, args):
    """The most recent release notes, from the tree."""
    p = ctx.app_dir / "CHANGELOG.md"
    if not p.exists():
        return Result("warn", "no CHANGELOG.md at %s" % p, exit_code=4)
    try:
        text = p.read_text()
    except Exception as exc:  # noqa: BLE001
        return Result("bad", "unreadable: %s" % exc, exit_code=4)
    out, seen = [], 0
    for line in text.splitlines():
        if line.startswith("## "):
            seen += 1
            if seen > 3:
                break
        if seen:
            out.append(line)
    r = Result("info", "CHANGELOG — %s (version %s)" % (ctx.app_dir, ctx.version()))
    r.lines("", out[:120] or ["(no sections found)"])
    return r


def services(ctx, args):
    """Alias table -> unit, with what each one is FOR."""
    what = {
        "web": "gunicorn: the application itself",
        "scheduler": "sidecar that fires scheduled actions (primary only)",
        "reconciler": "pulls the repo and reconciles the deployed tree",
        "updater": "PRIVILEGED root runner: installs units, pip, restarts",
        "alerts": "evaluates the health signals every 15 minutes",
        "cert-renew": "renews a CA-issued service certificate at 03:30",
        "git-publish": "publishes reports/ to git — backup copy 3",
        "datasync": "STANDBY pulls data/ from the primary every 5 minutes",
        "nginx": "front door: :443, :8443, :80 + the ACME challenge",
        "postgres": "shared state; the standby streams from the primary",
    }
    r = Result("info", "services")
    r.rows("", [("%-12s %-26s" % (a, UNITS[a]), what.get(a, "")) for a in sorted(UNITS)])
    r.note("'updater' and 'postgres' are excluded from start/stop/restart on "
           "purpose: the first IS the privilege boundary, the second is shared "
           "state the peer streams from.")
    return r
