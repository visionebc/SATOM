"""'get' — read state. Every command here works as ANY user.

That is the load-bearing property: the operator staring at a dead node is often
not root yet, and a diagnostic that refuses to run is a diagnostic that does not
exist. Where a probe needs a credential it cannot read, it degrades to a stated
'unavailable', never to a silent 'ok'.
"""
import os
import time
from pathlib import Path

from .context import RESTARTABLE, UNITS, run
from .render import Result


def _uptime():
    try:
        with open("/proc/uptime") as fh:
            s = float(fh.read().split()[0])
        d, r = divmod(int(s), 86400)
        h, r = divmod(r, 3600)
        return "%dd %dh %dm" % (d, h, r // 60)
    except Exception:  # noqa: BLE001
        return "?"


def system_status(ctx, args):
    r = Result("info", "SATOM %s on %s" % (ctx.version(), ctx.host))
    r.rows("node", [
        ("hostname", ctx.host),
        ("ha role", ctx.role),
        ("app dir", str(ctx.app_dir)),
        ("app version", ctx.version()),
        ("git head", ctx.git_head()),
        ("service account", ctx.app_user),
        ("uptime", _uptime()),
    ])
    r.rows("you", [
        ("user", "%s (uid %s)" % (ctx.user, ctx.uid)),
        ("privilege", "root" if ctx.is_root else "unprivileged"),
        (".env readable", "yes" if ctx.env_readable else
         "no — credential-backed checks will degrade"),
    ])
    r.set(host=ctx.host, version=ctx.version(), role=ctx.role, root=ctx.is_root)
    if ctx.role == "unknown":
        r.note("HA role unknown: the database did not answer. Run 'diagnose database'.")
    return r


def _expected_inactive(alias, role):
    """Units that are inert BY DESIGN on this node.

    satom-ha-datasync is role-guarded: only the standby pulls. Flagging it on a
    primary would be a permanent amber on a healthy node, and a check that
    always complains is a check the operator learns to skip — the same failure
    the disabled-probe and stale-card fixes were about.
    """
    if alias == "datasync":
        return role in ("primary", "standalone")
    return False


def system_health(ctx, args):
    """Roll-up: units + local health endpoint + disk. The one command to type
    first."""
    role = ctx.role
    r = Result("ok", "health — %s (%s)" % (ctx.host, role))
    rows = []
    for alias in UNITS:
        st = ctx.unit_state(alias)
        if st["enabled"] == "not-found":
            rows.append((alias, "not installed"))
            continue
        failed = st["active"] == "failed" or st["result"] not in ("success", "-", "")
        # A .timer/.path is healthy 'waiting'; a service 'running'; postgresql's
        # Debian meta-unit is healthy 'active/exited'. 'active' covers all three.
        running = st["active"] in ("active", "activating")
        excused = _expected_inactive(alias, role)
        note = ""
        if excused and not running:
            note = "  (inert on a %s — by design)" % role
        rows.append((alias, "%s/%s%s%s" % (
            st["active"], st["sub"],
            "" if st["result"] in ("success", "-", "") else "  result=%s" % st["result"],
            note)))
        if failed:
            r.worst("bad")
        elif not running and not excused:
            r.worst("warn")
    r.rows("units", rows)

    code, _ = ctx.http("http://127.0.0.1:8000/healthz")
    if code != 200:
        code, _ = ctx.http("https://127.0.0.1/healthz")
    r.rows("web", [("GET /healthz", code if code else "unreachable")])
    if code != 200:
        r.worst("bad")

    rc, out, _ = run(["df", "-h", str(ctx.app_dir)])
    disk = out.splitlines()[-1].split() if rc == 0 and len(out.splitlines()) > 1 else []
    if disk:
        pct = disk[4].rstrip("%")
        r.rows("disk", [(disk[5] if len(disk) > 5 else str(ctx.app_dir),
                         "%s used of %s (%s%% full)" % (disk[2], disk[1], pct))])
        try:
            if int(pct) >= 90:
                r.worst("bad")
                r.note("Disk at %s%% — a full disk breaks pg, git and the job "
                       "ledger before it breaks anything visible." % pct)
            elif int(pct) >= 80:
                r.worst("warn")
        except ValueError:
            pass
    r.set(role=ctx.role, healthz=code)
    return r


def system_performance(ctx, args):
    r = Result("info", "performance — %s" % ctx.host)
    try:
        load = os.getloadavg()
        ncpu = os.cpu_count() or 1
        r.rows("cpu", [("load 1/5/15", "%.2f %.2f %.2f" % load),
                       ("cores", ncpu),
                       ("load per core", "%.2f" % (load[0] / ncpu))])
        if load[0] / ncpu > 2:
            r.worst("warn")
    except Exception:  # noqa: BLE001
        pass
    mem = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, _, v = line.partition(":")
            mem[k] = int(v.split()[0])
        total, avail = mem["MemTotal"], mem["MemAvailable"]
        used_pct = 100 * (total - avail) / total
        r.rows("memory", [("total", "%d MB" % (total // 1024)),
                          ("available", "%d MB" % (avail // 1024)),
                          ("used", "%.1f%%" % used_pct)])
        if used_pct > 92:
            r.worst("warn")
    except Exception:  # noqa: BLE001
        pass
    rc, out, _ = run(["df", "-h"])
    if rc == 0:
        r.lines("filesystems", out.splitlines()[:12])
    return r


def system_interface(ctx, args):
    r = Result("info", "interfaces — %s" % ctx.host)
    rc, out, err = run(["ip", "-brief", "address"])
    if rc != 0:
        rc, out, err = run(["ip", "address"])
    r.lines("addresses", (out or err).splitlines())
    rc, out, _ = run(["ss", "-lntp"])
    if rc == 0:
        keep = [l for l in out.splitlines()
                if any(p in l for p in (":80 ", ":443 ", ":8000 ", ":8443 ", ":5432 ", "State"))]
        r.lines("listening (satom-relevant)", keep or out.splitlines()[:15])
    return r


def service_status(ctx, args):
    aliases = [args[0]] if args else list(UNITS)
    unknown = [a for a in aliases if a not in UNITS]
    if unknown:
        r = Result("bad", "unknown service: %s" % unknown[0], exit_code=2)
        r.lines("known services", sorted(UNITS))
        return r
    r = Result("ok", "services — %s" % ctx.host)
    rows = []
    for a in aliases:
        st = ctx.unit_state(a)
        rows.append((a, "%-24s %s/%s  enabled=%s  restarts=%s"
                     % (st["unit"], st["active"], st["sub"], st["enabled"], st["restarts"])))
        if st["active"] == "failed":
            r.worst("bad")
    r.rows("", rows)
    r.set(services={a: ctx.unit_state(a) for a in aliases})
    if len(aliases) == 1:
        r.lines("last 15 journal lines", ctx.journal(aliases[0], 15).splitlines()[-15:])
    return r


def node_status(ctx, args):
    r = Result("info", "HA node — %s (%s)" % (ctx.host, ctx.role))
    rows = [("role", ctx.role)]
    peers = []
    try:
        import json as _json
        nodes = _json.loads((ctx.app_dir / "data" / "ha_nodes.json").read_text())
        rc, out, _ = run(["hostname", "-I"])
        mine = set(out.split())
        for n in (nodes if isinstance(nodes, list) else nodes.get("nodes", [])):
            host = n.get("host") or n.get("ip") or ""
            tag = "self" if (host in mine or n.get("name") == ctx.host) else "peer"
            rows.append(("%s (%s)" % (n.get("name", "?"), tag), host))
            if tag == "peer":
                peers.append(host)
    except Exception as exc:  # noqa: BLE001
        r.note("ha_nodes.json unreadable: %s" % exc)
    r.rows("cluster", rows)
    for p in peers:
        code, body = ctx.http("https://%s:8443/healthz" % p)
        r.rows("peer %s" % p, [("GET :8443/healthz", code or "unreachable")])
        if code != 200:
            r.worst("warn")
            r.note("Peer %s did not answer on :8443. If this is the standby, its "
                   "datasync pull and the side-by-side backup view are blind." % p)
    r.set(role=ctx.role, peers=peers)
    return r


def database_status(ctx, args):
    parts = ctx.db_parts()
    if not parts:
        r = Result("warn", "database — credentials unavailable", exit_code=4)
        r.lines("why", [
            ".env is 640 root:%s by design; you are %s." % (ctx.app_user, ctx.user),
            "Re-run as root (sudo satom get database status) for the full check.",
        ])
        return r
    user, _pw, host, port, dbname = parts
    r = Result("ok", "database %s@%s:%s/%s" % (user, host, port, dbname))
    rc, out, err = ctx.psql("SELECT version();")
    if rc != 0:
        r.status = "bad"
        r.lines("connect failed", (err or "no output").splitlines())
        return r
    rows = [("server", out.split(",")[0])]
    for label, sql in (("in recovery", "SELECT pg_is_in_recovery();"),
                       ("size", "SELECT pg_size_pretty(pg_database_size(current_database()));"),
                       ("connections", "SELECT count(*) FROM pg_stat_activity;"),
                       ("tables", "SELECT count(*) FROM information_schema.tables "
                                  "WHERE table_schema='public';")):
        c, o, _ = ctx.psql(sql)
        rows.append((label, o if c == 0 else "?"))
    r.rows("", rows)
    if ctx.role == "primary":
        c, o, _ = ctx.psql("SELECT client_addr, state, sync_state FROM pg_stat_replication;")
        r.lines("replication", o.splitlines() or ["(no standby connected)"])
        if not o.strip():
            r.worst("warn")
            r.note("No streaming standby attached — copy 2 of the backup "
                   "architecture is not receiving anything.")
    return r


def certificate_status(ctx, args):
    r = Result("ok", "service certificate — %s" % ctx.host)
    meta = ctx.app_dir / "pki" / "public" / "meta.json"
    try:
        import json as _json
        m = _json.loads(meta.read_text())
        r.rows("meta.json", sorted((k, v) for k, v in m.items()
                                   if not isinstance(v, (dict, list))))
    except Exception as exc:  # noqa: BLE001
        r.note("pki/public/meta.json unreadable (%s) — likely a permissions "
               "issue, not a missing cert." % exc)
    crt = ctx.app_dir / "pki" / "public" / "server.crt"
    if crt.exists() and ctx.have("openssl"):
        rc, out, _ = run(["openssl", "x509", "-in", str(crt), "-noout",
                          "-subject", "-issuer", "-enddate"])
        r.lines("on disk", out.splitlines())
        rc2, _, _ = run(["openssl", "x509", "-in", str(crt), "-noout",
                         "-checkend", str(14 * 86400)])
        if rc2 != 0:
            r.worst("bad")
            r.note("Certificate expires within 14 days. "
                   "Check 'diagnose certificate' for the renewal journal.")
    jrn = ctx.app_dir / "state" / "cert-renew.jsonl"
    if jrn.exists():
        try:
            tail = jrn.read_text().splitlines()[-3:]
            r.lines("last renewal attempts", tail)
        except Exception:  # noqa: BLE001
            pass
    return r


def log_show(ctx, args):
    if not args:
        r = Result("bad", "usage: get log <service> [lines]", exit_code=2)
        r.lines("known services", sorted(UNITS))
        return r
    alias = args[0]
    if alias not in UNITS:
        r = Result("bad", "unknown service: %s" % alias, exit_code=2)
        r.lines("known services", sorted(UNITS))
        return r
    n = args[1] if len(args) > 1 and args[1].isdigit() else "40"
    r = Result("info", "journal — %s (last %s)" % (ctx.unit(alias), n))
    r.lines("", ctx.journal(alias, n).splitlines())
    return r
