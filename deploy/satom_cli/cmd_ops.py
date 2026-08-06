"""'get' commands for the AUTOMATED layer — the half of this product that has
no console of its own. STDLIB ONLY (see context.py).

Everything here is read-only and works at ANY privilege level, degrading to a
stated 'unknown' when it cannot read a credential. The rule this file exists to
enforce: **absence of data is never rendered as health.** A missing bundle, an
empty action table and an unreadable database all read as a problem, because
each of them silently WAS one in this product's history.
"""
import json
import os
import time
from pathlib import Path

from . import dbq
from .context import UNITS, run
from .render import Result

# Freshness budgets, in hours. Deliberately generous: the point is to catch
# "this stopped days ago and nobody noticed", not to nag about jitter.
FRESH = {"db_bundle": 48, "sot": 26, "datasync": 1}


def _age_h(path):
    try:
        return (time.time() - Path(path).stat().st_mtime) / 3600.0
    except Exception:  # noqa: BLE001
        return None


def _newest(directory, pattern="*"):
    try:
        files = [p for p in Path(directory).glob(pattern) if p.is_file()]
    except Exception:  # noqa: BLE001
        return None, 0, 0
    if not files:
        return None, 0, 0
    newest = max(files, key=lambda p: p.stat().st_mtime)
    total = sum(p.stat().st_size for p in files)
    return newest, len(files), total


def _mb(n):
    return "%.1f MB" % (n / 1e6)


def _fresh_badge(age_h, budget):
    if age_h is None:
        return "never", "bad"
    if age_h > budget * 2:
        return "%.1fh old" % age_h, "bad"
    if age_h > budget:
        return "%.1fh old" % age_h, "warn"
    return "%.1fh old" % age_h, "ok"


# -- backups --------------------------------------------------------------
def backup_status(ctx, args):
    """The four copies, side by side.

    They fail independently and they fail QUIETLY: git-publish reported success
    with exit 0 for days while publishing nothing, and the nightly push to the
    external server broke for a month because the server's DNS name changed
    under it. One table is the only way an operator sees all four.
    """
    r = Result("ok", "backups — %s (%s)" % (ctx.host, ctx.role))
    d = ctx.app_dir / "data"

    # The product's bundle is a tar.gz holding db.dump + reports/ + manifest —
    # NOT a bare pg_dump. Globbing for *.dump silently found nothing here while
    # seven real bundles sat in the same directory.
    newest, count, total = _newest(d / "system_backups", "fmw-backup-*.tar.gz")
    txt, st = _fresh_badge(_age_h(newest) if newest else None, FRESH["db_bundle"])
    r.worst(st)
    r.rows("1. database bundles (pg_dump + reports)", [
        ("directory", str(d / "system_backups")),
        ("bundles", "%d (%s)" % (count, _mb(total))),
        ("newest", newest.name if newest else "(none)"),
        ("age", txt),
    ])

    # Git bundles are a MANUAL code-recovery artifact since 2026-08-05 (the
    # device SoT left git), so their age is informational, never graded — a
    # freshness budget here would go permanently red on every healthy node.
    newest, count, total = _newest(d / "git-bundles", "*.bundle")
    r.rows("2. git repository bundles (code, manual)", [
        ("directory", str(d / "git-bundles")),
        ("bundles", "%d (%s)" % (count, _mb(total))),
        ("newest", newest.name if newest else "(none)"),
    ])

    # data/reports since the git-SoT retirement; the repo-root path survives
    # as a compat symlink, so resolve the real one first.
    reports = ctx.app_dir / "data" / "reports"
    if not reports.exists():
        reports = ctx.app_dir / "reports"
    cfgs = []
    try:
        cfgs = sorted(reports.glob("*/_config.json"))
    except Exception:  # noqa: BLE001
        pass
    newest_cfg = max(cfgs, key=lambda p: p.stat().st_mtime) if cfgs else None
    txt, st = _fresh_badge(_age_h(newest_cfg) if newest_cfg else None, FRESH["sot"])
    r.worst(st)
    sot_objects = ctx.app_dir / "data" / "sot" / "objects"
    n_blobs = 0
    try:
        n_blobs = sum(1 for _ in sot_objects.glob("*/*.json.gz"))
    except Exception:  # noqa: BLE001
        pass
    r.rows("3. device source of truth (local store)", [
        ("directory", str(reports)),
        ("devices", str(len(cfgs))),
        ("newest", newest_cfg.parent.name if newest_cfg else "(none)"),
        ("age", txt),
        ("versioned blobs", "%d in %s" % (n_blobs, sot_objects)),
    ])

    ds = ctx.unit_state("datasync")
    if ctx.role == "standby":
        ok = ds["active"] in ("active", "waiting") and ds["result"] in ("success", "-", "")
        r.worst("ok" if ok else "bad")
        state = "%s (%s)" % (ds["active"], ds["result"])
    else:
        state = "inert — the STANDBY pulls (correct on a %s)" % ctx.role
    r.rows("4. standby copy of data/", [("timer", ds["unit"]), ("state", state)])

    val, err = dbq.setting(ctx, "backup_server.config")
    if val is None:
        ext = "unknown — %s" % err
        r.worst("warn")
    elif val.strip():
        ext = "configured (credentials encrypted in app_settings)"
    else:
        ext = "NOT configured — copy 4 does not exist"
        r.worst("warn")
    r.rows("5. external backup server", [("state", ext)])

    r.set(role=ctx.role)
    if ctx.role == "standby":
        r.note("Deleting bundles here is futile: the primary's rsync --delete "
               "resurrects them within 5 minutes. Delete on the primary.")
    return r


def backup_list(ctx, args):
    """The database bundles you can hand to 'execute restore db'."""
    d = ctx.app_dir / "data" / "system_backups"
    try:
        files = sorted([p for p in d.glob("fmw-backup-*.tar.gz") if p.is_file()],
                       key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception as exc:  # noqa: BLE001
        return Result("bad", "cannot list %s: %s" % (d, exc), exit_code=4)
    if not files:
        r = Result("warn", "no database bundles in %s" % d)
        r.lines("make one", ["  sudo satom execute backup db"])
        return r
    r = Result("info", "%d database bundles — %s" % (len(files), d))
    r.rows("", [(p.name, "%8s   %s" % (_mb(p.stat().st_size),
                 time.strftime("%Y-%m-%d %H:%M", time.localtime(p.stat().st_mtime))))
                for p in files[:30]])
    r.lines("each bundle contains", ["db.dump (pg_dump -Fc), reports/ and manifest.txt"])
    r.lines("restore", ["  sudo satom execute restore db %s --yes" % files[0].name])
    r.note("Retention prunes these. The off-node copies are the standby "
           "(data/ via rsync) and the external backup server.")
    return r


# -- the scheduler --------------------------------------------------------
def scheduler_status(ctx, args):
    """Scheduled actions: what exists, when it last ran, what is overdue.

    Zero rows is a FINDING, not an empty list: no action is ever seeded, so a
    fresh install runs none of its own protections and looks identical to a
    node where the operator disabled everything on purpose.
    """
    rows, err = dbq.query(ctx, dbq.ACTIONS)
    if rows is None:
        r = Result("warn", "scheduled actions — unavailable", exit_code=4)
        r.rows("", [("reason", err)])
        r.note("Unknown is not healthy. Fix the read, then judge the state.")
        return r
    if not rows:
        r = Result("bad", "no scheduled actions exist on this node")
        r.lines("what that means", [
            "No source-of-truth refresh, no database bundles, no git bundles,",
            "no probe sweep. The alert signals are still computed and are",
            "delivered to nobody. This is the fresh-install state: actions are",
            "DATA and nothing seeds them.",
            "",
            "  sudo satom execute seed actions",
        ])
        return r

    streaks, _serr = dbq.fail_streaks(ctx)
    streaks = streaks or {}
    r = Result("ok", "scheduled actions — %d on %s (%s)" % (len(rows), ctx.host, ctx.role))
    table, overdue, broken = [], [], []
    for row in rows:
        (aid, name, action, enabled, last_status, last_run, next_run,
         product, kind, sched, late_s) = (row + [""] * 11)[:11]
        on = dbq.bool_of(enabled)
        try:
            late_h = int(late_s) / 3600.0 if late_s and int(late_s) >= 0 else None
        except ValueError:
            late_h = None
        streak = streaks.get(int(aid), 0) if aid.isdigit() else 0
        flag = ""
        if on and streak >= 3:
            flag = "  <- FAILING x%d" % streak
            broken.append(name)
            r.worst("bad")
        elif on and streak:
            flag = "  <- failed x%d" % streak
            r.worst("warn")
        if on and late_h is not None and late_h > 3:
            flag += "  <- OVERDUE %.1fh" % late_h
            overdue.append(name)
            r.worst("bad" if late_h > 12 else "warn")
        table.append(("%s %-14s" % (aid, action),
                      "%-8s %-6s last=%s next=%s%s"
                      % ("enabled" if on else "off", last_status or "-",
                         last_run or "never", next_run or "-", flag)))
    r.rows("actions", table)
    if ctx.role == "standby":
        r.status = "info" if r.status == "ok" else r.status
        r.note("Actions fire on the PRIMARY only. Ages seen from a standby "
               "reflect the primary's work arriving by streaming replication.")
    if broken:
        r.note("Consecutive scheduled failures: %s. 'satom diagnose scheduler'."
               % ", ".join(sorted(set(broken))))
    if overdue:
        r.note("Overdue means the sidecar did not fire, not that the work "
               "failed. Check satom-scheduler before the action itself.")
    r.set(count=len(rows), broken=broken, overdue=overdue)
    return r


# -- devices and probes ---------------------------------------------------
def device_status(ctx, args):
    rows, err = dbq.query(ctx, dbq.APPLIANCES)
    if rows is None:
        r = Result("warn", "devices — unavailable", exit_code=4)
        r.rows("", [("reason", err)])
        return r
    if not rows:
        return Result("info", "no appliances are registered")
    r = Result("ok", "appliances — %d" % len(rows))
    table = []
    for row in rows:
        (aid, name, kind, host, status, maint, checked, fw, verify) = (row + [""] * 9)[:9]
        parked = dbq.bool_of(maint)
        note = ""
        if parked:
            note = "  [maintenance]"
        elif status in ("error", "unreachable", "fail"):
            note = "  <- %s" % status
            r.worst("warn")
        elif status in ("", "unknown"):
            note = "  <- never synced"
            r.worst("warn")
            if dbq.bool_of(verify):
                note += " (verify_ssl=true — self-signed appliances need false)"
        table.append(("%-3s %-14s %-13s" % (aid, name, kind),
                      "%-22s %-9s last=%s%s" % (host, status or "-", checked or "never", note)))
    r.rows("", table)
    r.note("A parked device is skipped by AUTOMATIC runs and by its alerts; a "
           "manual run still reaches it.")
    return r


def monitor_status(ctx, args):
    rows, err = dbq.query(ctx, dbq.PROBES)
    if rows is None:
        r = Result("warn", "monitors — unavailable", exit_code=4)
        r.rows("", [("reason", err)])
        return r
    if not rows:
        r = Result("warn", "no monitor probes are defined")
        r.lines("", ["Nothing is watching the appliances between harvests.",
                     "Create them from Monitoring -> Deep monitors -> Discover."])
        return r
    counts, bad, parked, disabled, disabled_parked = {}, [], [], 0, 0
    for row in rows:
        (pid, kind, name, enabled, status, last, interval, detail, dev,
         maint) = (row + [""] * 10)[:10]
        if not dbq.bool_of(enabled):
            # Disabling the probes of a device you have parked is the correct
            # response to parking it, not lost coverage. Counting it as loss
            # is how this check sat at a permanent FAIL, and the first thing a
            # permanent FAIL teaches is that the check can be ignored. The
            # rule already exists a few lines below for ENABLED probes on a
            # parked device; this applies it consistently.
            if dbq.bool_of(maint):
                disabled_parked += 1
            else:
                disabled += 1
            continue
        label = ("%-4s %-16s %s" % (kind, dev, name),
                 "%s — %s" % (status, detail[:70]))
        if dbq.bool_of(maint):
            if status in ("warn", "crit", "error"):
                parked.append(label)
            continue
        counts[status or "-"] = counts.get(status or "-", 0) + 1
        if status in ("warn", "crit", "error"):
            bad.append(label)
    r = Result("ok", "monitor probes — %d (%d disabled, %d parked+disabled)"
               % (len(rows), disabled, disabled_parked))
    r.rows("by state", sorted(counts.items()) or [("(none active)", "")])
    if bad:
        r.rows("not ok", bad[:40])
        r.worst("bad" if any("crit" in b[1] for b in bad) else "warn")
    if parked:
        r.rows("not ok, but the device is PARKED (not counted)", parked[:20])
    if disabled:
        r.note("A disabled probe is NOT a passing probe — it is lost coverage. "
               "%d probe(s) are disabled here." % disabled)
    if parked:
        r.note("%d probe(s) are failing against appliances in maintenance. "
               "They do not raise this roll-up — un-park the device and they "
               "will." % len(parked))
    if disabled_parked:
        r.note("%d probe(s) are disabled on appliances in maintenance. That is "
               "the expected state for a parked device, so they are not counted "
               "as lost coverage." % disabled_parked)
    r.set(total=len(rows), disabled=disabled, parked=len(parked),
          disabled_parked=disabled_parked)
    return r


# -- jobs, updates, git ---------------------------------------------------
def job_list(ctx, args):
    """The background-job ledger, including the ghosts."""
    d = Path(os.environ.get("SATOM_JOBS_DIR", str(ctx.app_dir / "data" / "jobs")))
    try:
        files = [p for p in d.glob("*.json") if p.is_file()]
    except Exception as exc:  # noqa: BLE001
        return Result("bad", "cannot read the ledger at %s: %s" % (d, exc), exit_code=4)
    active, ghosts, total = [], [], len(files)
    for p in sorted(files, key=lambda q: q.stat().st_mtime, reverse=True)[:400]:
        try:
            j = json.loads(p.read_text())
        except Exception:  # noqa: BLE001
            continue
        if j.get("status") not in ("pending", "running"):
            continue
        age = (time.time() - p.stat().st_mtime) / 60.0
        label = "%s %s" % (j.get("type", "?"), j.get("title", ""))
        if not j.get("pid") and age > 10:
            ghosts.append((p.stem, "%s — no pid, %.0f min old" % (label, age)))
        else:
            active.append((p.stem, "%s — pid %s, %.0f min" % (label, j.get("pid"), age)))
    r = Result("ok", "job ledger — %d records, %d active, %d ghost"
               % (total, len(active), len(ghosts)))
    if active:
        r.rows("running", active)
    if ghosts:
        r.rows("ghosts", ghosts)
        r.worst("warn")
        r.note("A ghost job keeps the dock's toast open with a Stop button that "
               "cannot work. Sweep them:  sudo satom execute repair jobs --yes")
    if total > 500:
        r.worst("warn")
        r.note("%d ledger files. Nothing prunes them automatically and every "
               "dock poll globs the directory." % total)
    r.set(total=total, active=len(active), ghosts=len(ghosts))
    return r


def update_history(ctx, args):
    d = ctx.app_dir / "data" / "update-status"
    try:
        files = sorted([p for p in d.glob("*.json")],
                       key=lambda p: p.stat().st_mtime, reverse=True)[:12]
    except Exception as exc:  # noqa: BLE001
        return Result("bad", "cannot read %s: %s" % (d, exc), exit_code=4)
    if not files:
        return Result("info", "no update records in %s" % d)
    r = Result("info", "recent updates — %s" % ctx.host)
    table = []
    for p in files:
        try:
            j = json.loads(p.read_text())
        except Exception:  # noqa: BLE001
            continue
        steps = j.get("steps") or []
        failed = [s.get("name") for s in steps if not s.get("ok")]
        table.append((p.stem[:20], "%-9s %s  steps=%d%s"
                      % (j.get("state", "?"), j.get("kind", j.get("type", "")),
                         len(steps), ("  FAILED: " + ", ".join(failed[:3])) if failed else "")))
        if j.get("state") == "queued" and not steps:
            r.worst("warn")
    r.rows("", table)
    st = ctx.unit_state("updater")
    r.rows("privileged runner", [("unit", st["unit"]), ("state", st["active"]),
                                 ("enabled", st["enabled"])])
    if st["enabled"] not in ("enabled", "enabled-runtime"):
        r.status = "bad"
        r.note("satom-updater.path is %s. Every enqueued update will sit at "
               "'queued' forever and nothing will report an error. "
               "Fix:  sudo satom execute enable updater" % st["enabled"])
    return r


def git_status(ctx, args):
    """Repository state — the copy of the source of truth that lives here."""
    # --no-optional-locks is NOT cosmetic. `git status` refreshes and rewrites
    # .git/index; run as root in a tree owned by the service account that hands
    # the index to root and breaks every later write by the app. A read command
    # with a destructive side effect is worse than no command.
    g = ["git", "--no-optional-locks", "-c", "safe.directory=%s" % ctx.app_dir,
         "-C", str(ctx.app_dir)]
    r = Result("ok", "git — %s" % ctx.app_dir)

    rc, branch, _ = run(g + ["rev-parse", "--abbrev-ref", "HEAD"])
    if rc != 0:
        r.status = "bad"
        r.rows("", [("error", "not a usable git repository")])
        return r
    _, head, _ = run(g + ["log", "-1", "--format=%h %cs %s"])
    _, remote, _ = run(g + ["config", "--get", "remote.origin.url"])
    _, dirty, _ = run(g + ["status", "--porcelain"])
    dirty_n = len([x for x in dirty.splitlines() if x.strip()])

    ahead = behind = "?"
    rc, counts, _ = run(g + ["rev-list", "--left-right", "--count", "@{upstream}...HEAD"])
    if rc == 0 and counts:
        parts = counts.split()
        if len(parts) == 2:
            behind, ahead = parts[0], parts[1]

    rows = [("branch", branch), ("head", head),
            ("remote", (remote or "(none)").replace("://", "://").split("@")[-1]),
            ("uncommitted files", str(dirty_n)),
            ("ahead / behind", "%s / %s" % (ahead, behind))]

    if ahead not in ("0", "?"):
        rc, oldest, _ = run(g + ["log", "@{upstream}..HEAD", "--format=%ct", "--reverse"])
        if rc == 0 and oldest.strip():
            age_h = (time.time() - int(oldest.splitlines()[0])) / 3600.0
            rows.append(("oldest unpushed", "%.1f h" % age_h))
            r.worst("bad" if age_h > 48 else "warn")

    rc, refs, _ = run(g + ["for-each-ref", "refs/backup/",
                           "--format=%(refname:short)  %(committerdate:short)"])
    r.rows("", rows)
    r.lines("safety refs (parked by the update runner)",
            refs.splitlines() or ["(none — nothing has been rescued from a reset)"])

    if remote.startswith("http://"):
        r.worst("warn")
        r.note("origin is plain HTTP. It should be https:// — the token travels "
               "on every fetch and push.")
    if dirty_n:
        r.note("Uncommitted changes present. The update runner parks them "
               "(git stash create + refs/backup/) before any reset, and ABORTS "
               "the update if it cannot. It is not a licence to leave them.")
    r.set(branch=branch, ahead=ahead, behind=behind, dirty=dirty_n)
    return r


# -- users and alerting ---------------------------------------------------
def user_list(ctx, args):
    rows, err = dbq.query(ctx, dbq.USERS)
    if rows is None:
        r = Result("warn", "users — unavailable", exit_code=4)
        r.rows("", [("reason", err)])
        return r
    r = Result("ok", "users — %d" % len(rows))
    table, usable_admin = [], 0
    for row in rows:
        (name, role, active, src, fails, locked, last, totp) = (row + [""] * 8)[:8]
        on = dbq.bool_of(active)
        note = ""
        if not on:
            note = "  [inactive]"
        if locked:
            note += "  [LOCKED until %s]" % locked
            r.worst("warn")
        if on and not locked and role in ("admin", "superadmin") and src == "local":
            usable_admin += 1
        table.append(("%-20s %-10s" % (name, role),
                      "%-6s %-6s fails=%s last=%s%s"
                      % (src, "2fa" if dbq.bool_of(totp) else "-", fails,
                         last or "never", note)))
    r.rows("", table)
    if usable_admin == 0:
        r.status = "bad"
        r.note("No usable LOCAL admin: every admin is inactive, locked, or "
               "authenticates against the external IdP. If the IdP is down you "
               "cannot get in. 'satom show runbook locked-out'.")
    r.set(users=len(rows), local_admins=usable_admin)
    return r


def alerts_status(ctx, args):
    """Will anyone actually be told? That is the whole question here."""
    rows, err = dbq.query(ctx, dbq.SETTINGS_ALERTS)
    if rows is None:
        r = Result("warn", "alerting — unavailable", exit_code=4)
        r.rows("", [("reason", err)])
        return r
    s = {k: v for k, v in (row[:2] for row in rows if len(row) >= 2)}
    enabled = dbq.bool_of(s.get("alerts.enabled", ""))
    to = (s.get("alerts.email_to") or s.get("email.default_to") or "").strip()
    # email_service.py reads email.mode / email.host — 'local' means a local
    # MTA on :25, not a missing configuration.
    host = (s.get("email.host") or "").strip()
    mode = (s.get("email.mode") or "").strip()
    mail_on = dbq.bool_of(s.get("email.enabled", ""))

    r = Result("ok", "alerting — %s" % ctx.host)
    r.rows("delivery", [
        ("engine", "enabled" if enabled else "DISABLED"),
        ("recipient", to or "(none)"),
        ("mail transport", "%s via %s:%s" % (mode or "?", host or "?",
                                             s.get("email.port", "?"))),
        ("mail enabled", "yes" if mail_on else "NO"),
        ("from", s.get("email.from_addr", "(unset)")),
        ("cooldown", s.get("alerts.cooldown_hours", "6") + " h"),
        ("timer", "%s (%s)" % (ctx.unit_state("alerts")["active"],
                               ctx.unit_state("alerts")["result"])),
    ])
    checks = sorted((k.split(".")[-1], v) for k, v in s.items() if k.startswith("alerts.check"))
    if checks:
        r.rows("checks", [(k, "on" if dbq.bool_of(v) else "OFF") for k, v in checks])
    off = [k for k, v in checks if not dbq.bool_of(v)]

    if not enabled:
        r.status = "warn"
        r.note("Every signal is still computed on schedule and then discarded.")
    elif not to or not host or not mail_on:
        r.status = "bad"
        missing = ("recipient" if not to else
                   "mail transport (email.enabled=0)" if not mail_on else "mail host")
        r.note("Alerting is ON with no %s. The engine runs every 15 minutes, "
               "finds problems, and delivers them to nobody — the worst of the "
               "three states, because the page looks armed." % missing)
    elif mode == "local":
        r.note("Transport is 'local': delivery depends on an MTA listening on "
               "%s:%s. If that MTA is missing or refuses to relay, the alert "
               "is accepted and silently dropped — check the mail log, not "
               "this page." % (host, s.get("email.port", "25")))
    if off:
        r.worst("warn")
        r.note("Disabled checks: %s" % ", ".join(off))
    n, _ = dbq.query(ctx, dbq.NOTIF_RECENT)
    if n:
        r.rows("notifications (24h)", [(k, v) for k, v in (x[:2] for x in n)])
    r.set(enabled=enabled, recipient=bool(to), smtp=bool(host))
    return r


# -- host-level reads -----------------------------------------------------
def system_disk(ctx, args):
    """Space, inodes, and the directories that actually grow here."""
    r = Result("ok", "disk — %s" % ctx.host)
    rc, out, _ = run(["df", "-P", "-h", str(ctx.app_dir), "/var", "/"])
    lines = out.splitlines()
    r.lines("filesystems", lines or ["(df unavailable)"])
    for ln in lines[1:]:
        parts = ln.split()
        if len(parts) >= 5 and parts[4].endswith("%"):
            try:
                pct = int(parts[4].rstrip("%"))
            except ValueError:
                continue
            r.worst("bad" if pct >= 90 else "warn" if pct >= 80 else "ok")
    rc, out, _ = run(["df", "-P", "-i", str(ctx.app_dir)])
    r.lines("inodes", out.splitlines() or ["(unavailable)"])
    for ln in out.splitlines()[1:]:
        parts = ln.split()
        if len(parts) >= 5 and parts[4].endswith("%"):
            try:
                if int(parts[4].rstrip("%")) >= 85:
                    r.worst("bad")
                    r.note("Inodes are nearly exhausted. Millions of small "
                           "files exhaust these long before the bytes run out.")
            except ValueError:
                pass

    watch = [ctx.app_dir / "data" / "tmp", ctx.app_dir / "data" / "jobs",
             ctx.app_dir / "data" / "system_backups", ctx.app_dir / "data" / "git-bundles",
             ctx.app_dir / "data" / "backups", ctx.app_dir / "reports",
             Path("/var/log/satom"), Path("/var/log/journal")]
    rows = []
    for p in watch:
        if not p.exists():
            continue
        rc, out, _ = run(["du", "-sh", str(p)], timeout=120)
        size = out.split()[0] if rc == 0 and out else "?"
        try:
            n = sum(1 for _ in p.iterdir())
        except Exception:  # noqa: BLE001
            n = -1
        rows.append((str(p), "%-8s %s entries" % (size, n if n >= 0 else "?")))
    r.rows("directories that grow", rows)
    r.lines("nothing prunes these automatically", [
        "data/tmp     scratch from harvests and uploads",
        "data/jobs    one file per background job; jobs.prune() has no caller",
        "  sudo satom execute repair tmp --older-than 7 --yes",
        "  sudo satom execute repair jobs --yes",
    ])
    return r


def system_time(ctx, args):
    """Clock and NTP. A skewed clock breaks TLS, JWTs, ACME and the scheduler
    in ways that look like four unrelated faults."""
    r = Result("ok", "time — %s" % ctx.host)
    rc, out, _ = run(["timedatectl", "show", "--no-pager"])
    d = {}
    for ln in out.splitlines():
        k, _, v = ln.partition("=")
        d[k] = v
    if not d:
        rc, out, _ = run(["date", "-u"])
        r.rows("", [("utc", out or "?"), ("ntp", "timedatectl unavailable")])
        r.worst("warn")
        return r
    synced = d.get("NTPSynchronized", "no") == "yes"
    r.rows("", [
        ("utc", d.get("TimeUSec", "?")),
        ("timezone", d.get("Timezone", "?")),
        ("ntp enabled", d.get("NTP", "?")),
        ("ntp synchronised", "yes" if synced else "NO"),
    ])
    if not synced:
        r.status = "warn"
        r.note("The clock is not disciplined. Certificate validation, the "
               "replication handshake and every 'age' this CLI prints become "
               "unreliable in the same instant.")
    return r


def timer_status(ctx, args):
    """Every SATOM timer: enabled, last fire, next fire, last result."""
    r = Result("ok", "timers — %s (%s)" % (ctx.host, ctx.role))
    rows = []
    for alias, unit in sorted(UNITS.items()):
        if not unit.endswith((".timer", ".path")):
            continue
        st = ctx.unit_state(alias)
        if st["enabled"] == "not-found":
            rows.append((alias, "not installed"))
            r.worst("warn")
            continue
        rc, out, _ = run(["systemctl", "show", unit, "--no-pager",
                          "--property=NextElapseUSecRealtime,LastTriggerUSec"])
        p = {}
        for ln in out.splitlines():
            k, _, v = ln.partition("=")
            p[k] = v
        svc = unit.rsplit(".", 1)[0] + ".service"
        rc, sout, _ = run(["systemctl", "show", svc, "--no-pager", "--property=Result"])
        result = sout.partition("=")[2] or "-"
        excused = (alias == "datasync" and ctx.role in ("primary", "standalone"))
        state = "%s/%s" % (st["active"], st["enabled"])
        if st["enabled"] not in ("enabled", "enabled-runtime") and not excused:
            r.worst("bad" if alias == "updater" else "warn")
            state += "  <- NOT ENABLED"
        if result not in ("success", "-", ""):
            r.worst("warn")
            state += "  <- last run %s" % result
        rows.append((alias, "%-28s last=%s next=%s"
                     % (state, p.get("LastTriggerUSec", "-") or "-",
                        p.get("NextElapseUSecRealtime", "-") or "-")))
    r.rows("", rows)
    r.note("satom-ha-datasync is inert on a primary by design — the standby "
           "pulls. It is only a finding on a standby.")
    return r


def certificate_list(ctx, args):
    """Every certificate this node holds, not just the one nginx serves."""
    pki = ctx.app_dir / "pki"
    targets = [("public/server.crt", "served by nginx (:443/:8443)"),
               ("node/leaf.crt", "inter-node identity + Postgres replication"),
               ("internal-ca/ca.crt", "internal CA (primary mints, standby trusts)")]
    r = Result("ok", "certificates — %s" % pki)
    if not ctx.have("openssl"):
        r.rows("", [(t, "present" if (pki / t).exists() else "absent")
                    for t, _ in targets])
        r.note("openssl is not installed, so expiry cannot be read here.")
        r.worst("warn")
        return r
    rows = []
    for rel, what in targets:
        p = pki / rel
        if not p.exists():
            rows.append((rel, "absent — %s" % what))
            if rel != "internal-ca/ca.crt":
                r.worst("warn")
            continue
        rc, out, err = run(["openssl", "x509", "-in", str(p), "-noout",
                            "-subject", "-enddate", "-checkend", "1209600"])
        if rc not in (0, 1):
            rows.append((rel, "unreadable as %s: %s" % (ctx.user, (err or "?").splitlines()[0])))
            r.worst("warn")
            continue
        end = ""
        for ln in out.splitlines():
            if ln.startswith("notAfter="):
                end = ln.split("=", 1)[1]
        expiring = "Certificate will expire" in out
        rows.append((rel, "%s  expires %s%s" % (what, end or "?",
                                                "   <- WITHIN 14 DAYS" if expiring else "")))
        if expiring:
            r.worst("warn")
    r.rows("", rows)
    meta = pki / "public" / "meta.json"
    try:
        j = json.loads(meta.read_text())
        r.rows("public cert metadata", [(k, str(v)) for k, v in sorted(j.items())][:8])
        if j.get("source") == "imported":
            r.note("source=imported: this node CANNOT renew it by itself. It is "
                   "copied in, and meta.json — not app_settings — is the record.")
    except Exception:  # noqa: BLE001
        pass
    return r
