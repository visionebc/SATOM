"""Maintenance with pool drain (Web Server Manager, Linux ADOM).

A managed Linux server is very often a real server behind a FortiWeb server
pool or a FortiADC real-server pool. Restarting its web server, or running a
change on it, while the load balancer still sends it traffic is an outage the
operator caused. This module takes the server OUT of the pools first, does
the work, checks the server, and puts it BACK -- one job, every step visible.

LINKS. :func:`discover` asks every FortiWeb and FortiADC the user reaches for
the pool members whose address is the server's (a READ, run as a job: every
call is a step). The operator keeps the ones that are this server
(:func:`save_links`); nothing is linked by guess.

THE RUN (:func:`start`) follows the six steps of every SATOM write:

1. **Pre-check** -- each device answers, each member still exists, and
   draining it does not empty its pool (refused unless the operator allows
   it); the server's health is read (recorded, not blocking: the server may
   be the broken thing being fixed).
2. **Backup** -- each member's status BEFORE the run, kept in the job and in
   the server's pending record; that is what goes back, never a blind
   "enable".
3. **Dry run** -- the exact changes, and nothing else, when asked for.
4. **Drain** -- the member's status only (``maintenance`` on FortiWeb,
   ``maintain`` on FortiADC, or ``disable``), re-read from the device after
   each write: a device that answered 200 and kept the old value is a FAILED
   step. One member that cannot be drained puts back the ones already drained
   and stops before the server is touched.
5. **The work** -- hold (members stay out until *Return to service*), restart
   or reload a service, or run a library script, with the operator's own
   credential and the Web Server Manager's checks (profile, credential,
   Allow changes, sudo).
6. **Post-check and return** -- the server is read again (health, the unit is
   active, the site answers on the member's port), then each member gets its
   ORIGINAL status back and is re-read. When the work or the check fails the
   members STAY drained by default (traffic to a broken server is the outage
   this exists to avoid); the operator may choose to return them anyway.

Device writes need ``network.apply`` and the device in the user's scope (the
job carries the scope, the clients refuse the rest); server work needs what
the Web Server Manager asks for that operation.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import time
from datetime import datetime
from urllib.parse import quote

_log = logging.getLogger(__name__)

LINKS_KEY = "wsm.maint.links."
PENDING_KEY = "wsm.maint.pending."
FOUND_KEY = "wsm.maint.found."
APPLY_PERM = "network.apply"
KINDS = ("fortiweb", "fortiadc")
#: kind -> (default drain status, statuses that take a member out of service)
DRAIN = {"fortiweb": ("maintenance", ("maintenance", "disable")),
         "fortiadc": ("maintain", ("maintain", "disable"))}
FWB_POOLS = "/api/v2.0/cmdb/server-policy/server-pool"
FWB_MEMBERS = "/api/v2.0/cmdb/server-policy/server-pool/pserver-list"
ADC_POOLS = "load_balance_pool"
ADC_MEMBERS = "load_balance_pool_child_pool_member"
ADC_REAL = "load_balance_real_server"
ACTIONS = ("hold", "restart", "reload", "script")
MAX_DRAIN_WAIT = 900


class MaintError(Exception):
    """A refusal or a failed step, in SATOM's own words."""


def _st():
    from . import settings_store as ST
    return ST


# --------------------------------------------------------------------------- #
#  the server's addresses                                                      #
# --------------------------------------------------------------------------- #
def addresses(host: str) -> set[str]:
    """The IP addresses a server connection's host stands for."""
    try:
        return {str(ipaddress.ip_address(host))}
    except ValueError:
        pass
    try:
        return {ai[4][0] for ai in socket.getaddrinfo(host, None)}
    except OSError:
        return set()


# --------------------------------------------------------------------------- #
#  reading pools                                                               #
# --------------------------------------------------------------------------- #
def _fwb_rows(client, path):
    rows, err = client.list_with_error(path)
    if err:
        raise MaintError(str(err)[:300])
    return [r for r in rows if isinstance(r, dict)]


def fwb_members(client) -> list[dict]:
    """Every pserver of every server pool: ``{pool, member, address, port,
    status, domain}``."""
    out = []
    for pool in _fwb_rows(client, FWB_POOLS):
        name = str(pool.get("name") or pool.get("mkey") or "")
        if not name:
            continue
        for m in _fwb_rows(client, "%s?mkey=%s" % (FWB_MEMBERS, quote(name, safe=""))):
            out.append({"pool": name, "member": str(m.get("id") or m.get("mkey") or ""),
                        "address": str(m.get("ip") or "").strip(),
                        "domain": str(m.get("domain") or "").strip().lower(),
                        "port": str(m.get("port") or ""), "status": str(m.get("status") or "")})
    return out


def adc_members(client) -> list[dict]:
    """Every member of every real-server pool. A member names a real server;
    its address lives on that object (``load_balance_real_server``).
    # TODO verify: FortiADC 7.6/8.0 member row keys (real_server / real-server)
    """
    real, err = client.list_with_error(ADC_REAL)
    if err:
        raise MaintError(str(err)[:300])
    addr = {str(r.get("mkey") or ""): str(r.get("address") or r.get("address6")
                                          or r.get("fqdn") or "").strip()
            for r in real if isinstance(r, dict)}
    pools, err = client.list_with_error(ADC_POOLS)
    if err:
        raise MaintError(str(err)[:300])
    out = []
    for p in pools:
        name = str((p or {}).get("mkey") or "")
        if not name:
            continue
        rows, err = client.list_with_error(ADC_MEMBERS, pkey=name)
        if err:
            raise MaintError(str(err)[:300])
        for m in rows:
            rs = str(m.get("real_server") or m.get("real-server") or "")
            out.append({"pool": name, "member": str(m.get("mkey") or ""),
                        "address": str(m.get("address") or addr.get(rs) or "").strip(),
                        "domain": "", "real_server": rs,
                        "port": str(m.get("port") or ""), "status": str(m.get("status") or "")})
    return out


def members_of(appliance, client=None) -> list[dict]:
    client = client or appliance.build_client(timeout=20.0)
    return fwb_members(client) if appliance.kind == "fortiweb" else adc_members(client)


def matches(rows: list[dict], addrs: set[str], host: str) -> list[dict]:
    host = (host or "").strip().lower()
    return [r for r in rows if r["address"] in addrs or (host and r["domain"] == host)]


# --------------------------------------------------------------------------- #
#  links                                                                       #
# --------------------------------------------------------------------------- #
def links(slug: str) -> list[dict]:
    ST = _st()
    raw = ST.get_json_checked(LINKS_KEY + slug, [], list)
    if raw is ST.MALFORMED or not isinstance(raw, list):
        return []
    return [l for l in raw if isinstance(l, dict) and l.get("appliance_id")]


def link_key(l: dict) -> str:
    return "%s|%s|%s" % (l["appliance_id"], l["pool"], l["member"])


def last_found(slug: str) -> dict:
    """The last discovery of this server, as the job saved it (never what a
    browser sends back)."""
    ST = _st()
    raw = ST.get_json_checked(FOUND_KEY + slug, {}, dict)
    return raw if isinstance(raw, dict) and raw is not ST.MALFORMED else {}


def save_links(slug: str, chosen: list, by: str) -> list[dict]:
    """Keep the ``chosen`` keys among what the last discovery found -- a link
    is always a member a device answered, never one a request names."""
    rows = [f for f in last_found(slug).get("found") or [] if isinstance(f, dict)]
    keys = {str(k) for k in chosen}
    keep = [{k: f.get(k) for k in ("appliance_id", "appliance", "kind", "pool", "member",
                                   "address", "port")}
            for f in rows if link_key(f) in keys]
    _st().set_json(LINKS_KEY + slug, keep)
    from .audit import log_action
    log_action("wsm.maint.links", target=slug,
               extra={"by": by, "links": [link_key(l) for l in keep]})
    return keep


def pending(slug: str) -> dict:
    ST = _st()
    raw = ST.get_json_checked(PENDING_KEY + slug, {}, dict)
    return raw if isinstance(raw, dict) and raw is not ST.MALFORMED else {}


def _set_pending(slug: str, value: dict | None) -> None:
    _st().set_json(PENDING_KEY + slug, value or {})


# --------------------------------------------------------------------------- #
#  one member: read, write, verify                                             #
# --------------------------------------------------------------------------- #
def read_member(appliance, link: dict, client=None) -> dict:
    """The member as the device holds it now; MaintError when it is gone."""
    client = client or appliance.build_client(timeout=20.0)
    if appliance.kind == "fortiweb":
        rows = _fwb_rows(client, "%s?mkey=%s" % (FWB_MEMBERS, quote(link["pool"], safe="")))
        row = next((r for r in rows if str(r.get("id") or r.get("mkey")) == link["member"]),
                   None)
    else:
        rows, err = client.list_with_error(ADC_MEMBERS, pkey=link["pool"])
        if err:
            raise MaintError(str(err)[:300])
        row = next((r for r in rows if str(r.get("mkey")) == link["member"]), None)
    if row is None:
        raise MaintError("member %s of pool %s is no longer on %s"
                         % (link["member"], link["pool"], appliance.name))
    return row


def set_status(appliance, link: dict, status: str, *, expect: str) -> dict:
    """Write the member's status ONLY, then judge by re-reading it.
    Returns ``{"ok", "error", "verify"}``; ``ok`` needs the re-read to show
    ``status``."""
    if appliance.kind == "fortiweb":
        from .fortiweb_ops import FortiWebOps
        # {"data": ...}: the bare body answers HTTP 500 (fortiweb18 8.0.6, the
        # same write as the backend_set_status scheduled action)
        r = FortiWebOps(appliance).update(FWB_MEMBERS, link["pool"],
                                          {"data": {"status": status}},
                                          dry_run=False, sub_mkey=link["member"],
                                          expect={"status": expect})
        verdict = (r.get("verify") or {}).get("verdict") or ""
        err = r.get("error") or ""
        if r.get("conflict") or (not r.ok and "conflict" in str(err).lower()):
            err = err or "the member changed on the device since it was read"
    else:
        from . import device_verify
        client = appliance.build_client(timeout=20.0)
        err, verdict = "", ""
        try:
            # TODO verify: FortiADC 7.6.7 / 8.0.4 PUT of a child pool member with
            # only "status" -- the full row is sent to be safe on builds that
            # reset fields a PUT leaves out.
            row = dict(read_member(appliance, link, client))
            if str(row.get("status")) != expect:
                raise MaintError("member %s/%s is %s on the device, expected %s"
                                 % (link["pool"], link["member"], row.get("status"), expect))
            row["status"] = status
            client.update(ADC_MEMBERS, link["member"], row, pkey=link["pool"])
            v = device_verify.adc_after_write(appliance, client, "update", logical=ADC_MEMBERS,
                                              mkey=link["member"], pkey=link["pool"],
                                              sent={"status": status}, compare=["status"])
            verdict = v.get("verdict") or ""
        except Exception as exc:  # noqa: BLE001
            err = str(exc)[:300]
    now = ""
    try:
        now = str(read_member(appliance, link).get("status") or "")
    except Exception as exc:  # noqa: BLE001
        err = err or "re-read failed: %s" % exc
    ok = not err and now == status
    if not err and now != status:
        err = "the device accepted the change but still holds %r" % now
    from .audit import log_action
    log_action("wsm.maint.member_status", target="%s %s/%s" % (appliance.name, link["pool"],
                                                                link["member"]),
               appliance_id=appliance.id, extra={"from": expect, "to": status, "ok": ok,
                                                 "now": now, "verify": verdict,
                                                 "error": err[:200]})
    return {"ok": ok, "error": err, "verify": verdict, "now": now}


# --------------------------------------------------------------------------- #
#  the run                                                                     #
# --------------------------------------------------------------------------- #
def _step(label, pct=None):
    from . import job_progress
    job_progress.step(label[:160], percent=pct)


def _appliance(aid):
    from ..models import Appliance, db
    a = db.session.get(Appliance, int(aid))
    if a is None:
        raise MaintError("device %s no longer exists" % aid)
    return a


def plan(slug: str, *, drain_status: str = "") -> list[dict]:
    """``[{link, appliance, from, to}]`` -- what a run would change, read live
    (call inside the job)."""
    out = []
    for l in links(slug):
        a = _appliance(l["appliance_id"])
        row = read_member(a, l)
        cur = str(row.get("status") or "")
        to = drain_status if drain_status in DRAIN[a.kind][1] else DRAIN[a.kind][0]
        out.append({"link": l, "appliance": a, "from": cur, "to": to})
    return out


def _last_member(appliance, link) -> bool:
    """True when every OTHER member of the pool is already out of service."""
    rows = (fwb_members if appliance.kind == "fortiweb" else adc_members)(
        appliance.build_client(timeout=20.0))
    others = [r for r in rows if r["pool"] == link["pool"] and r["member"] != link["member"]]
    return not any(r["status"] == "enable" for r in others)


def _drain(items: list[dict]) -> list[dict]:
    done = []
    for it in items:
        if it["from"] in DRAIN[it["appliance"].kind][1]:
            _step("%s %s/%s already out of service (%s): left as it is"
                  % (it["appliance"].name, it["link"]["pool"], it["link"]["member"], it["from"]))
            it["skipped"] = True
            continue
        r = set_status(it["appliance"], it["link"], it["to"], expect=it["from"])
        _step("Drain %s %s/%s: %s -> %s · %s" % (
            it["appliance"].name, it["link"]["pool"], it["link"]["member"], it["from"], it["to"],
            "ok (re-read)" if r["ok"] else "FAILED: " + r["error"]))
        if not r["ok"]:
            back = _return(done)
            raise MaintError("could not drain %s %s/%s (%s); %s" % (
                it["appliance"].name, it["link"]["pool"], it["link"]["member"], r["error"],
                "the members already drained are back" if all(x["ok"] for x in back)
                else "NOT every member drained before could be put back: see the steps"))
        done.append(it)
    return done


def _return(items: list[dict]) -> list[dict]:
    out = []
    for it in items:
        r = set_status(it["appliance"], it["link"], it["from"], expect=it["to"])
        _step("Return %s %s/%s: %s -> %s · %s" % (
            it["appliance"].name, it["link"]["pool"], it["link"]["member"], it["to"], it["from"],
            "ok (re-read)" if r["ok"] else "FAILED: " + r["error"]))
        out.append(dict(r, member="%s %s/%s" % (it["appliance"].name, it["link"]["pool"],
                                                it["link"]["member"])))
    return out


def _server_work(slug, cred_id, action, opts, *, user, run_as, provided) -> dict:
    from . import wsm as W
    from ..models_wsm import WsmScript
    from ..extensions import db
    if action == "hold":
        return {"ok": True, "detail": "held: the members stay drained until Return to service"}
    if action in ("restart", "reload"):
        r = W.execute(slug, cred_id, "svc.action", {"name": opts["unit"], "action": action},
                      user=user, run_as=run_as, provided=provided, timeout=300)
        res = r["result"] if isinstance(r["result"], dict) else {}
        return {"ok": bool(res.get("ok")) and res.get("active") == "active",
                "detail": "%s %s: now %s%s" % (action, opts["unit"], res.get("active"),
                                              (" -- " + str(res.get("output"))[:300])
                                              if res.get("output") else "")}
    s = db.session.get(WsmScript, int(opts["script_id"]))
    r = W.execute(slug, cred_id, "script.run",
                  {"interpreter": s.interpreter, "content": s.content, "args": s.args,
                   "cwd": s.cwd or "", "timeout": int(s.timeout or 300)},
                  user=user, run_as=run_as, provided=provided, timeout=int(s.timeout or 300) + 60)
    res = r["result"] if isinstance(r["result"], dict) else {}
    return {"ok": res.get("exit_code") == 0,
            "detail": "script %s: exit %s%s" % (s.name, res.get("exit_code"),
                                                 (" -- " + str(res.get("stderr") or "")[-300:])
                                                 if res.get("exit_code") else "")}


def _post_check(c, slug, cred_id, action, opts, items, *, user, run_as, provided) -> list[str]:
    """Problems found after the work ([] = fine)."""
    from . import server_health as SH
    from . import wsm as W
    probs = []
    rec = SH.collect(c, by=getattr(user, "username", "") or "maintenance", notify=False)
    if not rec["ok"]:
        probs.append("health: %s" % rec["error"])
    else:
        probs += ["health: %s" % p["text"] for p in rec["problems"]
                  if p["severity"] in ("critical", "unreachable")]
    if action in ("restart", "reload"):
        r = W.execute(slug, cred_id, "svc.status", {"name": opts["unit"]}, user=user,
                      run_as=run_as, provided=provided)
        res = r["result"] if isinstance(r["result"], dict) else {}
        state = (res.get("props") or {}).get("ActiveState") or ""
        _step("Post-check: %s is %s" % (opts["unit"], state or "unknown"))
        if state != "active":
            probs.append("%s is %s" % (opts["unit"], state or "unknown"))
    for port in sorted({str(it["link"].get("port") or "") for it in items} - {""}):
        if not port.isdigit():
            continue
        try:
            r = W.execute(slug, cred_id, "http.check",
                          {"host": "localhost", "port": int(port), "path": opts.get("path") or "/",
                           "scheme": "https" if port == "443" else "http"},
                          user=user, run_as=run_as, provided=provided)
            res = r["result"] if isinstance(r["result"], dict) else {}
            st = int(res.get("status") or 0)
            _step("Post-check: HTTP on the server, port %s: %s" % (port, st or res.get("reason")))
            if not st or st >= 500:
                probs.append("port %s answers %s" % (port, st or res.get("reason") or "nothing"))
        except Exception as exc:  # noqa: BLE001
            probs.append("port %s: %s" % (port, str(exc)[:200]))
    return probs


def validate(slug: str, form: dict, *, user) -> dict:
    """Refuse NOW (in the request) what the job would refuse later."""
    from . import wsm as W
    if not links(slug):
        raise MaintError("this server has no pool member linked: Find pool members first")
    if pending(slug).get("members"):
        raise MaintError("a maintenance is still open on this server (members drained "
                         "since %s): Return to service first" % pending(slug).get("at"))
    if not W.can(user, APPLY_PERM):
        raise MaintError("changing a pool member needs %s" % APPLY_PERM)
    action = str(form.get("action") or "")
    if action not in ACTIONS:
        raise MaintError("pick what to do on the server")
    opts = {"path": str(form.get("path") or "/")[:200]}
    if not opts["path"].startswith("/"):
        raise MaintError("the check path starts with /")
    if action in ("restart", "reload"):
        unit = str(form.get("unit") or "").strip()
        if not unit.endswith(".service") or len(unit) > 120:
            raise MaintError("name the service, e.g. nginx.service")
        opts["unit"] = unit
        W.check_op(user, "svc.action", elevated=False)
    if action == "script":
        try:
            opts["script_id"] = int(form.get("script_id") or 0)
        except (TypeError, ValueError):
            opts["script_id"] = 0
        from ..models_wsm import WsmScript
        from ..extensions import db
        s = db.session.get(WsmScript, opts["script_id"]) if opts["script_id"] else None
        if s is None or not (s.shared or s.owner == user.username):
            raise MaintError("pick a script of the library")
        W.check_op(user, "script.run", elevated=False)
    try:
        wait = int(form.get("drain_wait") or 30)
    except (TypeError, ValueError):
        wait = 30
    if not 0 <= wait <= MAX_DRAIN_WAIT:
        raise MaintError("wait between 0 and %d seconds after draining" % MAX_DRAIN_WAIT)
    on_fail = str(form.get("on_failure") or "keep")
    if on_fail not in ("keep", "return"):
        raise MaintError("on failure: keep drained or return")
    if action != "hold" and not form.get("cred"):
        raise MaintError("pick the credential that does the work on the server")
    return {"action": action, "opts": opts, "drain_wait": wait, "on_failure": on_fail,
            "drain_status": str(form.get("drain_status") or ""),
            "allow_last": bool(form.get("allow_last")), "dry_run": bool(form.get("dry_run"))}


def start(app, slug: str, form: dict, *, user, provided: dict | None = None) -> dict:
    """Enqueue one maintenance run (policy checked now, see :func:`validate`)."""
    from . import jobs
    from . import wsm as W
    v = validate(slug, form, user=user)
    c = W.server(slug)
    cred_id = form.get("cred") or None
    run_as = str(form.get("run_as") or "")
    if cred_id and v["action"] != "hold":
        cred = W.pick_credential(c, user, cred_id)
        if not cred.store_secret:
            W._account(cred, provided or {})          # NeedSecret now, not in the worker
    uid = user.id
    title = "Maintenance of %s: %s%s" % (c.name, v["action"],
                                         " (dry run)" if v["dry_run"] else "")
    job = jobs.create_job("wsm_maintenance", title, by=user.username,
                          meta={"server": slug, "action": v["action"],
                                "dry_run": v["dry_run"]}, reversible=True)

    def worker(app_, job_id):
        from ..models import User
        from ..extensions import db
        from . import job_progress
        sink = job_progress.JobSink(job_id, exclusive=not v["dry_run"])
        job_progress.bind(sink)
        try:
            with app_.app_context():
                u = db.session.get(User, uid)
                return _run(c.slug, v, user=u, cred_id=cred_id, run_as=run_as,
                            provided=provided or {})
        finally:
            job_progress.unbind()

    jobs.run_async(app, job["id"], worker)
    return {"job_id": job["id"]}


def _run(slug, v, *, user, cred_id, run_as, provided) -> dict:
    from . import wsm as W
    from . import server_health as SH
    c = W.server(slug)
    result = {"server": slug, "action": v["action"], "dry_run": v["dry_run"], "members": []}
    # 1. pre-check ---------------------------------------------------------
    _step("Pre-check: reading the linked pool members", 5)
    items = plan(slug, drain_status=v["drain_status"])
    for it in items:
        if not v["allow_last"] and it["from"] == "enable" and _last_member(it["appliance"],
                                                                           it["link"]):
            raise MaintError("%s %s/%s is the last member in service of its pool: draining "
                             "it stops the service (tick Allow the last member to do it anyway)"
                             % (it["appliance"].name, it["link"]["pool"], it["link"]["member"]))
    try:
        h = SH.read(c, by=user.username)
        _step("Pre-check: server health read through %s" % h["via"])
    except SH.HealthError as exc:
        _step("Pre-check: server health could not be read (%s) -- not blocking" % exc)
    # 2. backup -------------------------------------------------------------
    result["members"] = [{"appliance": it["appliance"].name, "appliance_id": it["appliance"].id,
                          "kind": it["appliance"].kind, "pool": it["link"]["pool"],
                          "member": it["link"]["member"], "before": it["from"], "drain": it["to"]}
                         for it in items]
    _step("Backup: original status %s" % ", ".join(
        "%s %s/%s=%s" % (m["appliance"], m["pool"], m["member"], m["before"])
        for m in result["members"]), 15)
    # 3. dry run -----------------------------------------------------------
    if v["dry_run"]:
        _step("Dry run: would drain %d member(s), %s, then return each to its status above"
              % (len(items), v["action"]), 100)
        result["outcome"] = "dry-run"
        return result
    # 4. drain ----------------------------------------------------------------
    drained = _drain(items)
    pend = {"at": datetime.utcnow().isoformat(timespec="seconds"), "by": user.username,
            "members": [{"appliance_id": it["appliance"].id, "pool": it["link"]["pool"],
                         "member": it["link"]["member"], "before": it["from"], "drain": it["to"]}
                        for it in drained]}
    _set_pending(slug, pend)
    if v["drain_wait"]:
        _step("Waiting %d s for open connections to finish" % v["drain_wait"], 35)
        from . import jobs
        end = time.time() + v["drain_wait"]
        while time.time() < end:
            time.sleep(min(2.0, max(0.0, end - time.time())))
            jid = jobs.current_job_id()
            if jid:
                jobs.checkpoint(jid)
    # 5. the work ----------------------------------------------------------------
    if v["action"] == "hold":
        _step("Held: %d member(s) out of service until Return to service" % len(drained), 100)
        result["outcome"] = "held"
        return result
    _step("Work on the server: %s" % v["action"], 50)
    try:
        work = _server_work(slug, cred_id, v["action"], v["opts"], user=user, run_as=run_as,
                            provided=provided)
    except Exception as exc:  # noqa: BLE001 -- refused or failed: the same decision below
        work = {"ok": False, "detail": str(exc)[:300]}
    _step("Work: %s · %s" % (work["detail"], "ok" if work["ok"] else "FAILED"), 65)
    # 6. post-check and return -------------------------------------------------
    probs = [] if not work["ok"] else _post_check(
        c, slug, cred_id, v["action"], v["opts"], items, user=user, run_as=run_as,
        provided=provided)
    if not work["ok"]:
        probs = ["the work failed: %s" % work["detail"]]
    result["problems"] = probs
    if probs and v["on_failure"] == "keep":
        _step("Post-check failed (%s): the members STAY drained -- fix the server, then "
              "Return to service" % "; ".join(probs)[:120], 100)
        _notify(c, "Maintenance of %s stopped: members stay drained" % c.name,
                "; ".join(probs))
        raise MaintError("post-check failed, the members stay out of service: %s"
                         % "; ".join(probs))
    back = _return(drained)
    if all(r["ok"] for r in back):
        _set_pending(slug, None)
    result["returned"] = back
    if not all(r["ok"] for r in back):
        raise MaintError("the work is done but NOT every member is back in service: %s"
                         % "; ".join("%s: %s" % (r["member"], r["error"]) for r in back
                                     if not r["ok"]))
    if probs:
        raise MaintError("returned to service as asked, but the post-check failed: %s"
                         % "; ".join(probs))
    _step("Done: every member is back to its original status (re-read)", 100)
    result["outcome"] = "done"
    return result


def start_return(app, slug: str, *, user) -> dict:
    """Put the members of an open (held or stopped) maintenance back."""
    from . import jobs
    from . import wsm as W
    p = pending(slug)
    if not p.get("members"):
        raise MaintError("no maintenance is open on this server")
    if not W.can(user, APPLY_PERM):
        raise MaintError("changing a pool member needs %s" % APPLY_PERM)
    c = W.server(slug)
    job = jobs.create_job("wsm_maintenance_return", "Return %s to service" % c.name,
                          by=user.username, meta={"server": slug})

    def worker(app_, job_id):
        from . import job_progress
        sink = job_progress.JobSink(job_id, exclusive=True)
        job_progress.bind(sink)
        try:
            with app_.app_context():
                items = []
                for m in p["members"]:
                    a = _appliance(m["appliance_id"])
                    l = next((x for x in links(slug) if x["appliance_id"] == m["appliance_id"]
                              and x["pool"] == m["pool"] and x["member"] == m["member"]),
                             {"appliance_id": m["appliance_id"], "pool": m["pool"],
                              "member": m["member"]})
                    items.append({"appliance": a, "link": l, "from": m["before"],
                                  "to": m["drain"]})
                back = _return(items)
                if all(r["ok"] for r in back):
                    _set_pending(slug, None)
                    _step("Every member is back to its original status (re-read)", 100)
                    return {"returned": back}
                raise MaintError("NOT every member is back: %s" % "; ".join(
                    "%s: %s" % (r["member"], r["error"]) for r in back if not r["ok"]))
        finally:
            job_progress.unbind()

    jobs.run_async(app, job["id"], worker)
    return {"job_id": job["id"]}


def reachable_ids(user) -> list[int]:
    """The FortiWeb and FortiADC this user reaches -- by the profile's ADOMs
    and device scope, NOT by the ADOM the page is open in (the Linux ADOM has
    no load balancers of its own). The job carries the same answer
    (``allowed_appliance_ids``) and the clients refuse anything else."""
    from ..models import Appliance, can_view_maintenance
    from .product_scope import allowed_appliance_ids
    allowed = allowed_appliance_ids()
    q = Appliance.query.filter(Appliance.kind.in_(KINDS))
    if not can_view_maintenance(user):
        q = q.filter(Appliance.maintenance.is_(False))
    return [a.id for a in q.order_by(Appliance.name) if allowed is None or a.id in allowed]


def start_discover(app, slug: str, *, user) -> dict:
    """Find the pool members whose address is this server's, on every FortiWeb
    and FortiADC the user reaches (a read, as a job)."""
    from . import jobs
    from . import wsm as W
    c = W.server(slug)
    ids = reachable_ids(user)
    if not ids:
        raise MaintError("you reach no FortiWeb or FortiADC")
    job = jobs.create_job("wsm_maintenance_discover", "Find pool members of %s" % c.name,
                          by=user.username, meta={"server": slug})

    def worker(app_, job_id):
        from . import job_progress
        sink = job_progress.JobSink(job_id, exclusive=False)
        job_progress.bind(sink)
        try:
            with app_.app_context():
                addrs = addresses(c.host)
                _step("%s stands for %s" % (c.host, ", ".join(sorted(addrs)) or "no address"))
                found, errors = [], []
                for aid in ids:
                    a = _appliance(aid)
                    try:
                        rows = members_of(a)
                    except Exception as exc:  # noqa: BLE001 -- a refusal is a named error
                        errors.append("%s: %s" % (a.name, str(exc)[:200]))
                        _step("%s: ERROR %s" % (a.name, str(exc)[:120]))
                        continue
                    hit = matches(rows, addrs, c.host)
                    _step("%s: %d member(s) read, %d are this server" % (a.name, len(rows),
                                                                        len(hit)))
                    found += [dict(h, appliance_id=a.id, appliance=a.name, kind=a.kind)
                              for h in hit]
                out = {"found": found, "errors": errors, "addresses": sorted(addrs),
                       "at": datetime.utcnow().isoformat(timespec="seconds"), "job": job_id}
                _st().set_json(FOUND_KEY + slug, out)
                return out
        finally:
            job_progress.unbind()

    jobs.run_async(app, job["id"], worker)
    return {"job_id": job["id"]}


def _notify(c, title: str, body: str) -> None:
    try:
        from ..models_notifications import Notification
        from . import notifications as N
        from .alerts import _admin_ids
        from ..branding import PRODUCTS
        N.push_many(_admin_ids(), title[:200], body=body[:1000],
                    link="/webserver/%s/maintenance" % c.slug, kind=Notification.KIND_ERROR,
                    product="linux" if "linux" in PRODUCTS else "global")
    except Exception:  # noqa: BLE001 -- a bell never fails the run
        _log.warning("maintenance notification failed", exc_info=True)
