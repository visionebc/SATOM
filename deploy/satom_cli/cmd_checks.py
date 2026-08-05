"""Additional 'diagnose' probes. STDLIB ONLY (see context.py).

These answer questions the web UI structurally cannot answer about itself:
whether the sidecar is really running the code that is on disk, whether the
protections a fresh install never seeds are armed, whether the vhost that makes
the app reachable by name still wins, and whether the privilege model survived
the last update. Each one exists because the corresponding failure happened
here and reported success while it did.
"""
import json
import os
import shutil
import re
import stat
from pathlib import Path

from . import dbq
from .context import UNITS, run
from .render import Result

# satom-git-publish.timer left this list 2026-08-05: the reports/ SoT moved
# from git commits to the local versioned store (services.sot_store), so the
# hourly publisher retired with it. A node that still has the timer is fine;
# a node without it is no longer broken.
REQUIRED_UNITS = ("satom.service", "satom-scheduler.service", "satom-reconciler.service",
                  "satom-updater.path", "satom-updater.service", "satom-alerts.timer",
                  "satom-cert-renew.timer")

# Units whose file is a template in deploy/ and is therefore re-copied verbatim
# by the update runner. Their User= only survives as a drop-in.
DROPIN_UNITS = ("satom.service", "satom-scheduler.service", "satom-reconciler.service")

# The protections a node needs to actually protect itself. Nothing seeds these:
# ScheduledAction rows are DATA and operator edits win, so a fresh install has
# every capability and zero coverage.
MIN_ACTIONS = {
    "device_sync": "hourly source-of-truth refresh",
    "device_inspect": "nightly SoT off-box push",
    "system_backup": "nightly database bundle",
    "deep_monitor": "probe sweep",
    "metrics_scrape": "fleet metrics collection (VictoriaMetrics)",
    # The sweep records; this is what carries the record to a human. Without it
    # the rollups accumulate for ninety days and nobody is told anything unless
    # they open the console, which is the same shape of gap as an unarmed
    # backup: full capability, zero delivery.
    "monitor_report": "period summary (daily / weekly / monthly)",
}


def _pass(rows, name, ok, detail=""):
    rows.append((name, ("pass" if ok else "FAIL") + ("  " + detail if detail else "")))
    return ok


def _proc_start_epoch(pid):
    """Absolute start time of a pid, from /proc. No date parsing, no ps."""
    try:
        with open("/proc/stat") as fh:
            btime = next(int(l.split()[1]) for l in fh if l.startswith("btime "))
        with open("/proc/%d/stat" % int(pid)) as fh:
            fields = fh.read().rsplit(") ", 1)[1].split()
        return btime + (int(fields[19]) / os.sysconf("SC_CLK_TCK"))
    except Exception:  # noqa: BLE001
        return None


def _main_pid(ctx, alias):
    rc, out, _ = run(["systemctl", "show", ctx.unit(alias), "--no-pager",
                      "--property=MainPID"])
    try:
        pid = int(out.partition("=")[2])
        return pid or None
    except ValueError:
        return None


def _newest_source(ctx):
    """(path, mtime) of the newest .py that a long-running process LOADS.

    ``app/`` only. deploy/ is deliberately excluded: the operator CLI runs from
    a root-owned copy in /usr/local/lib and the update runner is a separate
    root process, so editing either of them says nothing about whether gunicorn
    is stale. Including them made this check fire every time the CLI itself was
    touched — and a check that always complains is a check the operator learns
    to skip.
    """
    newest, newest_m = None, 0
    root = ctx.app_dir / "app"
    candidates = list(root.rglob("*.py")) if root.is_dir() else []
    candidates += [p for p in ctx.app_dir.glob("*.py")]
    for p in candidates:
        if "__pycache__" in p.parts:
            continue
        try:
            m = p.stat().st_mtime
        except OSError:
            continue
        if m > newest_m:
            newest, newest_m = p, m
    return newest, newest_m


def code(ctx, args):
    """Is each long-running process actually running the code on disk?

    satom-scheduler carries its OWN copy of the application. Editing an action
    spec or a probe registry and restarting only the web service leaves the
    sidecar on the old code, and the symptom is pathognomonic: the manual run
    succeeds while the scheduled run fails with 'Unknown action'.
    """
    newest, newest_m = _newest_source(ctx)
    r = Result("ok", "code freshness")
    if not newest:
        r.status = "warn"
        r.rows("", [("source tree", "no .py files found under %s" % ctx.app_dir)])
        return r
    rows = [("newest source", str(newest.relative_to(ctx.app_dir)))]
    stale = []
    for alias in ("web", "scheduler", "reconciler"):
        st = ctx.unit_state(alias)
        if st["enabled"] == "not-found" or st["active"] != "active":
            rows.append((alias, "not running (%s)" % st["active"]))
            continue
        pid = _main_pid(ctx, alias)
        started = _proc_start_epoch(pid) if pid else None
        if started is None:
            rows.append((alias, "running, start time unavailable"))
            continue
        delta_h = (newest_m - started) / 3600.0
        if delta_h > 0:
            rows.append((alias, "STALE — started %.1f h before the newest source" % delta_h))
            stale.append(alias)
        else:
            rows.append((alias, "current (started %.1f h after)" % (-delta_h)))
    r.rows("", rows)
    if stale:
        r.status = "warn"
        r.note("Restart: %s" % "  ".join("sudo satom execute restart %s" % a for a in stale))
        if "scheduler" in stale:
            r.note("The scheduler is the dangerous one: it fails only on the "
                   "SCHEDULED path, so a manual test of the same action passes.")
    return r


def scheduler(ctx, args):
    """Is anything automated actually firing on this node?"""
    r = Result("ok", "scheduler — %s (%s)" % (ctx.host, ctx.role))
    st = ctx.unit_state("scheduler")
    rows = [("unit", "%s/%s" % (st["active"], st["sub"])), ("enabled", st["enabled"])]

    should_fire = ctx.role in ("primary", "standalone")
    pid = _main_pid(ctx, "scheduler")
    cmdline = ""
    if pid:
        try:
            cmdline = Path("/proc/%d/cmdline" % pid).read_bytes().replace(b"\0", b" ").decode()
        except Exception:  # noqa: BLE001
            cmdline = ""
    rows.append(("main pid", "%s" % (pid or "-")))
    rows.append(("process", cmdline.strip()[:90] or "-"))

    if st["active"] != "active":
        r.status = "bad"
        rows.append(("verdict", "the sidecar is not running"))
    elif should_fire and "scheduler_runtime" not in cmdline:
        r.status = "bad"
        rows.append(("verdict", "unit is active but the runtime is NOT in the "
                                "process — it is idling in a guard loop"))
    else:
        rows.append(("verdict", "firing here" if should_fire else
                     "idle — correct on a standby, actions are primary-only"))
    r.rows("", rows)

    actions, err = dbq.query(ctx, dbq.ACTIONS)
    if actions is None:
        r.worst("warn")
        r.rows("actions", [("state", "unreadable: %s" % err)])
        return r
    if not actions:
        r.status = "bad"
        r.rows("actions", [("count", "0 — nothing to fire")])
        r.note("No ScheduledAction row exists. Nothing seeds them: "
               "sudo satom execute seed actions")
        return r
    overdue = []
    for row in actions:
        try:
            late = int(row[10])
        except (IndexError, ValueError):
            continue
        if dbq.bool_of(row[3]) and late > 3 * 3600:
            overdue.append("%s (%.1fh)" % (row[2], late / 3600.0))
    r.rows("actions", [("total", str(len(actions))),
                       ("overdue > 3h", str(len(overdue)))])
    if overdue and should_fire:
        r.worst("bad" if len(overdue) > 1 else "warn")
        r.lines("overdue", overdue[:10])
        r.note("Overdue means the sidecar did not FIRE them. That is a "
               "scheduler fault, not a fault in the actions themselves.")

    j = ctx.journal("scheduler", 200)
    unknown = sorted(set(re.findall(r"Unknown action '([a-z_]+)'", j)))
    if unknown:
        r.status = "bad"
        r.lines("journal", ["Unknown action: %s" % ", ".join(unknown)])
        r.note("The sidecar is running older code than the tree. "
               "sudo satom execute restart scheduler")
    return r


def units(ctx, args):
    """Unit inventory, and whether the privilege model survived the last update."""
    r = Result("ok", "systemd units")
    rows = []
    for unit in REQUIRED_UNITS:
        rc, out, _ = run(["systemctl", "show", unit, "--no-pager",
                          "--property=UnitFileState,ActiveState,LoadState"])
        d = {}
        for ln in out.splitlines():
            k, _, v = ln.partition("=")
            d[k] = v
        if d.get("LoadState") == "not-found":
            _pass(rows, unit, False, "not installed")
            r.status = "bad"
            continue
        enabled = d.get("UnitFileState", "")
        excused = unit.startswith("satom-ha-datasync") and ctx.role != "standby"
        ok = enabled in ("enabled", "enabled-runtime", "static", "generated") or excused
        _pass(rows, unit, ok, "%s / %s" % (enabled, d.get("ActiveState", "?")))
        if not ok:
            r.worst("bad" if unit == "satom-updater.path" else "warn")
    r.rows("inventory", rows)

    drops = []
    want_user = ctx.app_user
    for unit in DROPIN_UNITS:
        p = Path("/etc/systemd/system/%s.d/10-app-user.conf" % unit)
        if not p.exists():
            drops.append((unit, "FAIL  no drop-in — User= will revert on the next update"))
            r.worst("bad" if want_user != "root" else "warn")
            continue
        try:
            txt = p.read_text()
        except Exception:  # noqa: BLE001
            drops.append((unit, "drop-in unreadable as %s" % ctx.user))
            continue
        m = re.search(r"^User=(\S+)", txt, re.M)
        got = m.group(1) if m else "(unset)"
        ok = (got == want_user)
        drops.append((unit, ("pass" if ok else "FAIL") + "  User=%s" % got))
        if not ok:
            r.worst("warn")
    r.rows("User= drop-ins (tree owner: %s)" % want_user, drops)

    running_as = []
    for alias in ("web", "scheduler", "reconciler"):
        pid = _main_pid(ctx, alias)
        who = "-"
        if pid:
            try:
                for ln in Path("/proc/%d/status" % pid).read_text().splitlines():
                    if ln.startswith("Uid:"):
                        import pwd
                        who = pwd.getpwuid(int(ln.split()[1])).pw_name
            except Exception:  # noqa: BLE001
                who = "?"
        running_as.append((alias, who))
        if who == "root" and want_user != "root":
            r.worst("bad")
    r.rows("actually running as", running_as)
    if any(w == "root" for _, w in running_as) and want_user != "root":
        r.note("A unit reverted to root. Editing the unit file does NOT survive: "
               "the update runner re-copies deploy/<unit> every time. "
               "sudo satom execute reinstall units")
    r.note("satom-updater stays root deliberately — it is the privileged runner. "
           "A second root unit is how the boundary gets rebuilt by accident.")
    return r


def config(ctx, args):
    """.env: present, correctly owned, and internally consistent."""
    r = Result("ok", "configuration")
    env_file = ctx.app_dir / ".env"
    if not env_file.exists():
        r.status = "bad"
        r.rows("", [(".env", "MISSING at %s" % env_file)])
        r.note("Without it the app falls back to sqlite and fails in confusing "
               "ways rather than refusing to start.")
        return r
    rows = []
    try:
        stt = env_file.stat()
        mode = stat.S_IMODE(stt.st_mode)
        import grp
        import pwd
        owner = pwd.getpwuid(stt.st_uid).pw_name
        group = grp.getgrgid(stt.st_gid).gr_name
        rows.append(("path", str(env_file)))
        rows.append(("owner", "%s:%s" % (owner, group)))
        rows.append(("mode", oct(mode)))
        if mode & 0o007:
            r.status = "bad"
            rows.append(("exposure", "WORLD-READABLE — every secret on this node is public"))
        elif mode not in (0o640, 0o600):
            r.worst("warn")
    except Exception as exc:  # noqa: BLE001
        rows.append(("stat", "failed: %s" % exc))
    r.rows("file", rows)

    if not ctx.env_readable:
        r.worst("warn")
        r.rows("contents", [("state", "not readable as %s — checks below skipped" % ctx.user)])
        r.note("This is expected for an operator who is not root and not in the "
               "'%s' group. It is a limit of your session, not a fault of the "
               "node." % ctx.app_user)
        return r

    checks = []
    e = ctx.env
    _pass(checks, "SECRET_KEY", bool(e.get("SECRET_KEY", "").strip()))
    fk = e.get("FERNET_KEY", "").strip()
    ok_fk = len(fk) == 44 and fk.endswith("=")
    _pass(checks, "FERNET_KEY", ok_fk, "" if ok_fk else "not a 44-char Fernet key")
    parts = ctx.db_parts()
    _pass(checks, "SQLALCHEMY_DATABASE_URI", bool(parts),
          "" if parts else "unparseable")
    if parts:
        checks.append(("database", "%s@%s:%s/%s" % (parts[0], parts[2], parts[3], parts[4])))
        if parts[4].startswith("sqlite") or "sqlite" in ctx.db_uri():
            r.worst("bad")
            checks.append(("engine", "SQLITE — the app fell back; Postgres is expected"))
    if not all(x[1].startswith("pass") or ":" in x[1] for x in checks):
        r.worst("bad")
    r.rows("required keys", checks)
    if not ok_fk:
        r.status = "bad"
        r.note("A wrong FERNET_KEY does not fail at boot. It fails later, when "
               "something tries to decrypt an appliance password or an SFTP "
               "credential — and it looks like a wrong password.")
    return r


# Directorios de vhost que el instalador puede haber usado, por familia.
NGINX_VHOST_DIRS = ("/etc/nginx/sites-enabled", "/etc/nginx/vhosts.d",
                    "/etc/nginx/conf.d")


def bare_host_vhosts(bodies):
    """Proxying vhosts that pass `Host $host`, which DROPS the port.

    Takes [(name, text)] and returns the offending names. Pure on purpose: the
    caller reads /etc/nginx, this decides, and a test can pin the decision
    without standing up nginx.
    """
    return [n for n, t in bodies
            if re.search(r"\bproxy_pass\s", t)
            and re.search(r"proxy_set_header\s+Host\s+\$host\s*;", t)]


def uncovered_names(served, san_names):
    """Served FQDNs the certificate does not cover.

    Single-label names are reported by the caller but NOT graded here: no public
    CA issues a certificate for a bare hostname, so grading it would leave every
    node that imports a wildcard in a permanent warn -- the chronic false
    positive this codebase keeps having to delete.
    """
    return [n for n in served if "." in n and not cert_covers(n, san_names)]


def vhost_server_names(txt):
    """DNS names a vhost answers for. Drops the catch-all and bare IPs.

    An IP is never gradeable against a certificate: a public CA will not put one
    in a SAN, so counting it as a miss would make the check complain forever on
    a node whose certificate is exactly right.
    """
    out = []
    for m in re.finditer(r"^\s*server_name\s+([^;]+);", txt, re.M):
        for tok in m.group(1).split():
            tok = tok.strip().lower().rstrip(".")
            if not tok or tok == "_":
                continue
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", tok):
                continue
            out.append(tok)
    return out


def cert_covers(name, san_names):
    """RFC 6125 matching. A '*' covers exactly ONE leftmost label.

    Written out rather than assumed: `*.example.tld` covers `node.example.tld`
    but NOT `a.b.example.tld` and NOT the bare `example.tld`. Treating the
    wildcard as "matches anything under the domain" is the usual mistake and it
    turns this check into a rubber stamp.
    """
    name = (name or "").lower().rstrip(".")
    for pat in san_names:
        pat = (pat or "").lower().rstrip(".")
        if not pat:
            continue
        if pat == name:
            return True
        if pat.startswith("*."):
            head, _, rest = name.partition(".")
            if head and rest and rest == pat[2:]:
                return True
    return False


def cert_san_names(path):
    """DNS entries of a certificate's subjectAltName, [] if unreadable."""
    rc, out, _ = run(["openssl", "x509", "-noout", "-ext", "subjectAltName",
                      "-in", str(path)])
    if rc != 0:
        return []
    names = []
    for chunk in out.replace("\n", ",").split(","):
        chunk = chunk.strip()
        if chunk.upper().startswith("DNS:"):
            names.append(chunk[4:].strip())
    return names


def satom_vhosts():
    """(path, text) of every vhost that proxies to the local gunicorn."""
    out = []
    for d in NGINX_VHOST_DIRS:
        p = Path(d)
        if not p.is_dir():
            continue
        for f in sorted(p.iterdir()):
            if not f.is_file():
                continue
            try:
                t = f.read_text()
            except Exception:  # noqa: BLE001
                continue
            if "proxy_pass" in t and "127.0.0.1:8000" in t:
                out.append((f, t))
    return out


def nginx(ctx, args):
    """The front door: syntax, which vhost wins, and the ACME trap."""
    r = Result("ok", "nginx")
    rc, out, err = run(["nginx", "-t"])
    if rc == 127:
        r.status = "warn"
        r.rows("", [("nginx", "not installed on this node")])
        return r
    ok = (rc == 0)
    r.rows("syntax", [("nginx -t", "ok" if ok else "INVALID")])
    if not ok:
        r.status = "bad"
        r.lines("error", (err or out).splitlines()[:12])
        r.note("Do NOT reload until this is clean. 'execute reload nginx' "
               "validates first and refuses, which is the behaviour you want.")
        return r

    # [SATOM-NGINX-DIRS] install-satom.sh picks the vhost directory by family:
    # sites-enabled (Debian/Ubuntu), vhosts.d (openSUSE/SLES) or conf.d
    # (RHEL/Arch). This check only knew the first and third, so on openSUSE it
    # read ZERO files and reported "listeners (none found)" plus
    # "default_server holder NONE" for a node whose vhost was correct — a FAIL
    # that no configuration change could ever clear, on the check whose entire
    # job is telling you the console is about to become unreachable. Scan every
    # directory the installer may have used; a vhost in any of them is real.
    confs = []
    for _d, _pat in (
        ("/etc/nginx/sites-enabled", "*"),
        ("/etc/nginx/vhosts.d", "*.conf"),
        ("/etc/nginx/conf.d", "*.conf"),
    ):
        _p = Path(_d)
        if _p.is_dir():
            confs.extend(sorted(x for x in _p.glob(_pat) if x.is_file()))
    default_443, listens, findings, bodies = [], [], [], []
    for c in confs:
        try:
            txt = c.read_text()
        except Exception:  # noqa: BLE001
            findings.append((c.name, "unreadable as %s" % ctx.user))
            continue
        bodies.append((c.name, txt))
        if re.search(r"listen\s+[^;]*443[^;]*default_server", txt):
            default_443.append(c.name)
        for m in re.finditer(r"listen\s+([^;]+);", txt):
            listens.append("%s: %s" % (c.name, m.group(1).strip()))
        # A `return 301` at SERVER level runs in the rewrite phase, BEFORE a
        # location is chosen, so it swallows the ACME challenge. The redirect
        # has to live inside `location /`.
        depth, server_level_redirect = 0, False
        for line in txt.splitlines():
            s = line.split("#", 1)[0]
            if depth == 1 and re.match(r"\s*return\s+30[12]\b", s):
                server_level_redirect = True
            depth += s.count("{") - s.count("}")
        if server_level_redirect and "acme-challenge" not in txt:
            findings.append((c.name, "server-level 'return 301' and no ACME "
                                     "challenge location — HTTP-01 will fail here"))
            r.worst("warn")
    r.lines("listeners", listens[:14] or ["(none found)"])
    r.rows("default_server on :443", [
        ("holder", ", ".join(default_443) or "NONE"),
    ])
    if len(default_443) != 1:
        r.worst("bad" if not default_443 else "warn")
        r.note("Exactly one vhost must own default_server on :443. With none, "
               "the alphabetically first config wins and the application "
               "becomes unreachable by hostname while the static site keeps "
               "serving — which looks like a DNS fault, not an nginx one.")
    if findings:
        r.rows("findings", findings)
    # [SATOM-VHOST-HOST] `$host` DESCARTA el puerto. Flask-WTF construye el
    # origen esperado del token CSRF con el host que la app cree tener y lo
    # compara con el Referer del navegador INCLUYENDO el puerto, asi que detras
    # de un NAT o un proxy en puerto no estandar TODO POST -- el login incluido
    # -- se rechaza con un mensaje que habla de la sesion caducada. El sintoma
    # apunta al sitio equivocado, que es justo por lo que esto tiene que ser un
    # chequeo y no una nota.
    proxied = [(n, t) for n, t in bodies if re.search(r"\bproxy_pass\s", t)]
    if proxied:
        bare = bare_host_vhosts(proxied)
        r.rows("proxied Host header", [
            (n, "$host - DROPS the port" if n in bare else "$http_host")
            for n, _ in proxied])
        if bare:
            r.worst("bad")
            r.note("A vhost passes `Host $host`, which strips the port. Every "
                   "POST behind a non-standard port fails CSRF and reports a "
                   "stale form. Fix: `satom execute repair nginx --yes`.")

    # [SATOM-SERVED-NAMES] Lo que sirve el vhost y lo que cubre el certificado
    # tienen que ser el MISMO conjunto. El instalador acunaba ambos desde
    # `hostname` (el nombre CORTO), asi que un nodo alcanzado por su FQDN tenia
    # un certificado sin ese SAN -- aviso del navegador sobre un certificado que
    # el instalador acababa de reportar como bueno.
    crt = ctx.app_dir / "pki" / "public" / "server.crt"
    served = sorted({n for _, t in proxied for n in vhost_server_names(t)})
    if served and crt.exists():
        sans = cert_san_names(crt)
        r.rows("certificate SAN", [("DNS names", ", ".join(sans) or "(none)")])
        r.rows("certificate covers server_name",
               [(n, "covered" if cert_covers(n, sans) else "NOT COVERED")
                for n in served])
        # Solo se GRADUAN los FQDN. Un nombre de una sola etiqueta no puede
        # estar en un certificado publico -- ninguna CA lo emite -- y solo se
        # alcanza desde el dominio de busqueda local, asi que contarlo como
        # fallo dejaria en warn permanente a todo nodo que importe un wildcard.
        # Se IMPRIME igual: no graduar no es ocultar.
        missing = uncovered_names(served, sans)
        if missing:
            r.worst("warn")
            r.note("The vhost answers for %s but the served certificate has no "
                   "matching SAN, so a browser reaching the node by that name "
                   "gets a name-mismatch warning. Re-issue with the name in the "
                   "SAN, or import one that covers it." % ", ".join(missing))
    elif served and not crt.exists():
        r.rows("certificate covers server_name",
               [("state", "%s missing - cannot verify" % crt)])
        r.worst("warn")

    # SATOM-NGINX-PEER: :8443 is the authenticated node-to-node channel. A
    # standalone install has no peer, so grading it there makes EVERY fresh
    # single-node install open with "[warn] nginx" forever, over a feature it
    # deliberately does not have. Same chronic false positive already removed
    # from `get system health` for the datasync timer that is inert by design
    # on a primary (see cmd_ops.py "excused"). A check that always complains is
    # a check the operator learns to skip.
    # The row is still PRINTED, so the channel is never silently unreported --
    # what changes is that it stops counting as a finding.
    probes = nginx_probes(bool(configured_peers(ctx)))
    if len(probes) == 1:
        r.rows("peer channel :8443",
               [("state", "n/a - no peer configured (standalone)")])
    for probe, url in probes:
        code_, _ = ctx.http(url, timeout=5)
        r.rows(probe, [("GET /healthz", code_ or "no answer")])
        if code_ != 200:
            r.worst("warn")
    return r


def nginx_probes(has_peer):
    """Which HTTP probes the nginx check is allowed to GRADE.

    SATOM-NGINX-PEER. Takes a boolean, not a role string, and stays pure: a
    test can pin the standalone case without standing up nginx, a peer or a
    database.

    Deliberately NOT keyed on ctx.role. `role` is derived from
    pg_is_in_recovery(), so it can only ever be primary/standby/unknown -- a
    STANDALONE node reports "primary", and the "standalone" value promised by
    that property's docstring is unreachable. Keying on it silently graded
    every standalone install anyway, which is the bug this exists to fix.
    """
    probes = [("app :443", "https://127.0.0.1/healthz")]
    if has_peer:
        probes.append(("peer channel :8443", "https://127.0.0.1:8443/healthz"))
    return probes


def configured_peers(ctx):
    """Hosts in the peer registry that are not this node.

    Same discovery the `get node status` command uses: local IPs compared
    against data/ha_nodes.json. A standalone install has no such file, so it
    has no peer and nothing should be answering on :8443.
    """
    import json as _json
    try:
        nodes = _json.loads((ctx.app_dir / "data" / "ha_nodes.json").read_text())
    except Exception:  # noqa: BLE001 - absent file IS the standalone answer
        return []
    if isinstance(nodes, dict):
        nodes = nodes.get("nodes", [])
    if not isinstance(nodes, list):
        return []
    _rc, out, _e = run(["hostname", "-I"])
    mine = set(out.split())
    peers = []
    for n in nodes:
        if not isinstance(n, dict):
            continue
        host = n.get("host") or n.get("ip") or ""
        if host and host not in mine and n.get("name") != ctx.host:
            peers.append(host)
    return peers


def git(ctx, args):
    """Repository integrity, including the ownership trap."""
    # See cmd_ops.git_status: without --no-optional-locks a root `git status`
    # rewrites .git/index and takes it away from the service account — the very
    # drift this check reports.
    g = ["git", "--no-optional-locks", "-c", "safe.directory=%s" % ctx.app_dir,
         "-C", str(ctx.app_dir)]
    r = Result("ok", "git integrity")
    # SATOM-GIT-PKG: until 1.3.3 no offline bundle carried git, so an air-gapped
    # node reported "repository unusable" — true, and it sends the operator to
    # look at the repository instead of at the one missing package.
    if shutil.which("git") is None:
        r.status = "bad"
        r.rows("", [("git binary", "not installed")])
        r.note("code updates (reconciler / self-update) and manual git bundles "
               "shell out to git. The device SoT no longer depends on it "
               "(services.sot_store), but code delivery does. Install it from "
               "the distribution media or the offline bundle.")
        return r
    rc, out, _ = run(g + ["rev-parse", "--is-inside-work-tree"])
    if rc != 0:
        r.status = "bad"
        r.rows("", [("repository", "unusable at %s" % ctx.app_dir)])
        return r
    rows = []
    rc, root_in_git, _ = run(["find", str(ctx.app_dir / ".git"), "-user", "root"],
                             timeout=60)
    n_git = len([x for x in root_in_git.splitlines() if x.strip()]) if rc == 0 else -1
    _pass(rows, "no root-owned files in .git", n_git == 0,
          "" if n_git <= 0 else "%d found" % n_git)
    if n_git > 0:
        r.worst("warn")

    # Excluded because root owning them is CORRECT, not drift:
    #   .env               0640 root:<service account> by design — the app only
    #                      reads it, so a write primitive cannot rewrite its
    #                      own secrets
    #   data/lib-versions  written by the privileged runner, which IS root
    #   dist/              build output from the offline-bundle builders
    #   venv/, .git/       covered separately / not application state
    # Flagging these would put a permanent FAIL on a healthy node, and the
    # first thing a permanent FAIL teaches is that this check can be ignored.
    exclude = ["*/venv/*", "*/venv", "*/.git/*", "*/.git", "*/dist/*", "*/dist",
               "*/data/lib-versions/*", "*/data/lib-versions"]
    cmd = ["find", str(ctx.app_dir), "-user", "root", "-not", "-name", ".env"]
    for pat in exclude:
        cmd += ["-not", "-path", pat]
    rc, root_in_tree, _ = run(cmd, timeout=90)
    offenders = [x for x in root_in_tree.splitlines() if x.strip()]
    n_tree = len(offenders) if rc == 0 else -1
    _pass(rows, "no root-owned files in the tree", n_tree == 0,
          "" if n_tree <= 0 else "%d found" % n_tree)
    if n_tree > 0:
        r.worst("warn")

    rc, url, _ = run(g + ["config", "--get", "remote.origin.url"])
    _pass(rows, "origin uses TLS", url.startswith("https://") or url.startswith("ssh://")
          or url.startswith("git@"), url.split("@")[-1][:48])
    if url.startswith("http://"):
        r.worst("warn")
    r.rows("", rows)
    if offenders:
        r.lines("root-owned", [x.replace(str(ctx.app_dir) + "/", "")
                               for x in offenders[:12]])
    if n_tree > 0 or n_git > 0:
        r.note("Running anything as root inside the tree (pytest, git, a "
               "script) leaves files the service account cannot rewrite. "
               "sudo satom execute repair permissions")
    return r


def acme(ctx, args):
    """The ACME path, end to end, without issuing anything."""
    r = Result("ok", "ACME / Let's Encrypt")
    rows = []
    lego = "/usr/local/bin/lego"
    have = Path(lego).exists() or ctx.have("lego")
    _pass(rows, "client installed", have, lego)
    if not have:
        r.worst("warn")

    acct = ctx.app_dir / "data" / "acme"
    exists = acct.is_dir()
    _pass(rows, "account directory", exists, str(acct))
    if exists:
        try:
            mode = stat.S_IMODE(acct.stat().st_mode)
            _pass(rows, "account directory is 0700", mode == 0o700, oct(mode))
            if mode != 0o700:
                r.worst("warn")
            n = sum(1 for _ in acct.rglob("*.key"))
            rows.append(("account keys", str(n) if n else "none yet (never registered)"))
        except Exception:  # noqa: BLE001
            rows.append(("account directory", "unreadable as %s" % ctx.user))
    else:
        r.worst("warn")

    webroot = Path("/var/www/acme")
    _pass(rows, "http-01 webroot", webroot.is_dir(), str(webroot))
    if not webroot.is_dir():
        r.worst("warn")
    r.rows("", rows)

    n, err = dbq.query(ctx, "SELECT count(*) FROM acme_dns_providers")
    if n:
        r.rows("catalogue", [("dns providers seeded", n[0][0])])
    creds, _ = dbq.query(
        ctx, "SELECT count(*) FROM app_settings WHERE key LIKE 'certmgr.acme.creds.%'")
    if creds:
        got = int(creds[0][0] or 0)
        r.rows("credentials", [("configured providers", str(got))])
        if not got:
            r.worst("warn")
            r.note("No DNS provider credentials are stored, so DNS-01 cannot "
                   "complete. That is the operator's step: Settings -> "
                   "Certificate Manager -> DNS provider credentials.")
    r.note("The account key under data/acme MUST persist. Registering a new "
           "account on every issue burns the CA's rate limit and loses the "
           "ability to revoke what was issued before.")
    return r


def install(ctx, args):
    """Is this node fully ARMED, as opposed to merely installed?

    The installer delivers code, units, TLS and a database. It does not deliver
    the automated protections, because those are DATA and operator edits win
    over code defaults here. A fresh node therefore looks perfect and defends
    nothing. This is the check that says so out loud.
    """
    r = Result("ok", "installation completeness — %s" % ctx.host)
    rows = []

    missing_units = []
    for unit in REQUIRED_UNITS:
        rc, out, _ = run(["systemctl", "show", unit, "--no-pager", "--property=LoadState"])
        if out.partition("=")[2] == "not-found":
            missing_units.append(unit)
    if not _pass(rows, "systemd units installed", not missing_units,
                 ", ".join(missing_units)):
        r.status = "bad"

    st = ctx.unit_state("updater")
    if not _pass(rows, "privileged runner enabled",
                 st["enabled"] in ("enabled", "enabled-runtime"), st["enabled"]):
        r.status = "bad"

    drop_ok = all(Path("/etc/systemd/system/%s.d/10-app-user.conf" % u).exists()
                  for u in DROPIN_UNITS)
    if not _pass(rows, "User= drop-ins present", drop_ok or ctx.app_user == "root"):
        r.worst("warn")

    cli = Path("/usr/local/sbin/satom")
    cli_ok = cli.exists() and not cli.is_symlink()
    if not _pass(rows, "operator CLI installed", cli_ok, str(cli)):
        r.worst("warn")

    sudoers = Path("/etc/sudoers.d/satom")
    if not _pass(rows, "service-account sudoers", sudoers.exists(), str(sudoers)):
        r.worst("warn")

    pki_ok = (ctx.app_dir / "pki" / "public" / "server.crt").exists()
    if not _pass(rows, "service certificate present", pki_ok):
        r.worst("bad")

    venv_ok = (ctx.app_dir / "venv" / "bin" / "python3").exists()
    if not _pass(rows, "venv present", venv_ok):
        r.status = "bad"

    r.rows("infrastructure", rows)

    # -- the half nothing seeds -------------------------------------------
    armed = []
    actions, err = dbq.query(ctx, dbq.ACTIONS)
    if actions is None:
        armed.append(("scheduled actions", "unreadable: %s" % err))
        r.worst("warn")
    else:
        present = {row[2] for row in actions if dbq.bool_of(row[3])}
        for key, what in sorted(MIN_ACTIONS.items()):
            ok = key in present
            armed.append((key, ("pass" if ok else "MISSING") + "  — " + what))
            if not ok:
                r.worst("bad")

    # The mailer's real keys are email.mode / email.host (email_service.py).
    # Do not invent a key name here: a check that reads a setting nobody writes
    # reports a permanent, false failure — worse than no check at all.
    to, _ = dbq.setting(ctx, "alerts.email_to")
    fallback, _ = dbq.setting(ctx, "email.default_to")
    mode, _ = dbq.setting(ctx, "email.mode")
    mhost, _ = dbq.setting(ctx, "email.host")
    menabled, _ = dbq.setting(ctx, "email.enabled")
    recipient = (to or fallback or "").strip()
    armed.append(("alert recipient", recipient or "NONE — signals computed and discarded"))
    armed.append(("mail transport", "%s via %s%s"
                  % ((mode or "?").strip() or "?", (mhost or "?").strip() or "?",
                     "" if dbq.bool_of(menabled) else "   (email.enabled=0)")))
    if not recipient or not dbq.bool_of(menabled) or not (mhost or "").strip():
        r.worst("warn")

    ext, _ = dbq.setting(ctx, "backup_server.config")
    armed.append(("external backup server", "configured" if (ext or "").strip()
                  else "not configured — the off-node copy does not exist"))
    if not (ext or "").strip():
        r.worst("warn")

    admins, _ = dbq.query(ctx, "SELECT count(*) FROM users WHERE is_active "
                               "AND COALESCE(auth_source,'local')='local' "
                               "AND role IN ('admin','superadmin')")
    if admins:
        n = int(admins[0][0] or 0)
        armed.append(("local admin accounts", str(n) if n else "NONE — IdP outage locks you out"))
        if not n:
            r.worst("bad")
    r.rows("protections that must be ARMED", armed)

    # Only tell the operator to arm things when something is NOT armed. Advice
    # printed unconditionally is advice that gets skipped on the one node where
    # it mattered.
    if any(v.startswith("MISSING") for _, v in armed):
        r.lines("arm the minimum set", [
            "  sudo satom execute seed actions          # shows the plan",
            "  sudo satom execute seed actions --yes    # applies it",
        ])
    if not recipient or not dbq.bool_of(menabled) or not (mhost or "").strip():
        r.lines("alerting", [
            "Settings -> Alerts needs a recipient and a working transport, or",
            "every signal is computed on schedule and delivered to nobody.",
        ])
    return r
