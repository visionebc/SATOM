"""Server health (Web Server Manager, Linux ADOM) -- memory, disks, load,
processes and failed systemd units of every managed server, in time.

One reading is the ``host.health`` operation (hostctl/satom-webctl.py, also
answered by the session helper satom-wsm). It is a READ: no sudo, no write,
nothing the server's account could not read by itself. Each server says HOW
it is read -- the operator's choice, never a guess SATOM keeps silent:

* ``agent`` -- the installed satom-webctl agent (account ``satom-mon``,
  forced command, SATOM's own key; nothing typed by anyone);
* ``ssh``   -- plain SSH with a stored SHARED credential of the server (the
  operator's account: password or key, kept by SATOM); nothing installed,
  the helper travels on the session and is gone when it ends;
* ``auto``  -- the agent when the server has one, else the first shared
  credential that keeps its secret;
* ``off``   -- not read at all.

Every reading goes through the ingestion gate (closed schema HOST_HEALTH),
leaves a Web Server Manager audit row, and lands in this node's
VictoriaMetrics store (mirrored to the HA peer like every collector). A
reading that FAILS writes ``satom_scrape_up 0``: an unreachable server is a
state, never a gap. Problems are judged against the server's thresholds and
each new problem (or a worse one) rings the administrators' bell once;
recovery rings once too.
"""
from __future__ import annotations

import fnmatch
import json
import logging
import time
from datetime import datetime, timedelta

_log = logging.getLogger(__name__)

ACTION = "wsm_health"
ACTION_NAME = "Web Server Manager -- server health"
CONF_KEY = "wsm.health.conf."
LAST_KEY = "wsm.health.last."
NOTIFIED_KEY = "wsm.health.notified"
VIAS = ("auto", "agent", "ssh", "off")
#: Seconds one run of the scheduled action may spend before it leaves the
#: remaining servers to the next minute.
RUN_BUDGET_S = 50
#: Consecutive failed readings before "unreachable" rings the bell: one lost
#: SSH session is noise, two in a row is a server problem.
UNREACHABLE_AFTER = 2
DEFAULTS = {
    "via": "auto", "credential_id": None, "interval_min": 5,
    "disk_warn": 85, "disk_crit": 95, "inode_warn": 90,
    "mem_warn": 15, "mem_crit": 5, "swap_warn": 80,
    "load_warn": 2.0, "ignore_units": [],
}
LIMITS = {"interval_min": (1, 1440), "disk_warn": (1, 100), "disk_crit": (1, 100),
          "inode_warn": (1, 100), "mem_warn": (0, 100), "mem_crit": (0, 100),
          "swap_warn": (1, 100)}
SEVERITY = {"ok": 0, "warning": 1, "critical": 2, "unreachable": 3}


class HealthError(Exception):
    """A reading that could not be made; the message is SATOM's own text."""


# --------------------------------------------------------------------------- #
#  configuration                                                               #
# --------------------------------------------------------------------------- #
def conf(slug: str) -> dict:
    """The server's settings, defaults filled in. A row that cannot be read
    counts as the defaults (reading health is not a security decision)."""
    from . import settings_store as ST
    raw = ST.get_json_checked(CONF_KEY + slug, {}, dict)
    if raw is ST.MALFORMED or not isinstance(raw, dict):
        raw = {}
    out = dict(DEFAULTS)
    out.update({k: raw[k] for k in DEFAULTS if k in raw})
    if out["via"] not in VIAS:
        out["via"] = "auto"
    if not isinstance(out["ignore_units"], list):
        out["ignore_units"] = []
    return out


def _num(value, lo, hi, what):
    try:
        n = float(value)
    except (TypeError, ValueError):
        raise ValueError("%s must be a number" % what) from None
    if not lo <= n <= hi:
        raise ValueError("%s must be between %s and %s" % (what, lo, hi))
    return n


def save_conf(slug: str, form: dict, by: str) -> dict:
    """Validate and store the settings of one server. Raises ValueError with
    the operator-facing reason."""
    from . import settings_store as ST
    from . import wsm as W
    via = str(form.get("via") or "auto")
    if via not in VIAS:
        raise ValueError("pick how SATOM reads this server")
    cred_id = None
    if via == "ssh":
        try:
            cred_id = int(form.get("credential_id") or 0)
        except (TypeError, ValueError):
            cred_id = 0
        if cred_id not in {c.id for c in W.service_credentials(slug)}:
            raise ValueError("pick a shared credential that keeps its secret (Overview > "
                             "Credentials: Shared + Keep the secret)")
    out = {"via": via, "credential_id": cred_id}
    for k, (lo, hi) in LIMITS.items():
        out[k] = int(_num(form.get(k, DEFAULTS[k]), lo, hi, k.replace("_", " ")))
    out["load_warn"] = _num(form.get("load_warn", DEFAULTS["load_warn"]), 0.1, 1000,
                            "load per CPU")
    if out["disk_warn"] > out["disk_crit"]:
        raise ValueError("the disk warning must be at or below the critical level")
    if out["mem_crit"] > out["mem_warn"]:
        raise ValueError("the critical free-memory level must be at or below the warning")
    pats = form.get("ignore_units") or ""
    if isinstance(pats, str):
        pats = pats.replace(",", "\n").splitlines()
    pats = [p.strip() for p in pats if isinstance(p, str) and p.strip()]
    if len(pats) > 100 or any(len(p) > 120 or any(ord(ch) < 32 for ch in p) for p in pats):
        raise ValueError("ignored services: at most 100 patterns of up to 120 characters")
    out["ignore_units"] = pats
    ST.set_json(CONF_KEY + slug, out)
    from .audit import log_action
    log_action("wsm.health.settings", target=slug, extra=dict(out, by=by))
    if via != "off":
        ensure_scheduled()
    return out


def last(slug: str) -> dict:
    """The last reading of the server (``{}`` when there is none)."""
    from . import settings_store as ST
    raw = ST.get_json_checked(LAST_KEY + slug, {}, dict)
    return raw if isinstance(raw, dict) and raw is not ST.MALFORMED else {}


# --------------------------------------------------------------------------- #
#  reading                                                                     #
# --------------------------------------------------------------------------- #
def channel(c, cfg: dict | None = None) -> dict:
    """How this server would be read now: ``{"via": agent|ssh|off|none,
    "credential": WsmCredential|None, "why": str}``."""
    from . import studio_connections as SC
    from . import wsm as W
    cfg = cfg or conf(c.slug)
    via = cfg["via"]
    if via == "off":
        return {"via": "off", "credential": None, "why": "health reading is switched off"}
    if via in ("agent", "auto") and SC.has_secret(c.slug):
        return {"via": "agent", "credential": W.ensure_agent_credential(c), "why": ""}
    if via == "agent":
        return {"via": "none", "credential": None,
                "why": "the server has no satom-webctl agent key: generate one and install "
                       "the agent, or read it over SSH with a shared credential"}
    creds = W.service_credentials(c.slug)
    if via == "ssh":
        cred = next((r for r in creds if r.id == cfg.get("credential_id")), None)
        if cred is None:
            return {"via": "none", "credential": None,
                    "why": "the credential picked for health is gone, revoked, not shared or "
                           "no longer keeps its secret: pick another one"}
        return {"via": "ssh", "credential": cred, "why": ""}
    if creds:
        return {"via": "ssh", "credential": creds[0], "why": ""}
    return {"via": "none", "credential": None,
            "why": "no way to read it unattended: install the satom-webctl agent, or add a "
                   "credential marked Shared that keeps its secret"}


def read(c, by: str = "scheduler", cfg: dict | None = None) -> dict:
    """ONE ``host.health`` reading. Returns ``{"data", "via", "credential",
    "ms"}``; raises HealthError (named reason, never the server's bytes)."""
    from . import studio_connections as SC
    from . import wsm as W
    ch = channel(c, cfg)
    if ch["via"] in ("off", "none"):
        raise HealthError(ch["why"])
    started = time.time()
    if ch["via"] == "agent":
        cred = ch["credential"]
        try:
            data = SC.server_call(c, "host.health")
        except Exception as exc:  # noqa: BLE001
            text = str(exc)
            if "unknown_op" in text or "unknown operation" in text:
                text = ("the satom-webctl agent on the server is older than 1.2.0 and does not "
                        "read host health: run the installer of this SATOM again on the server")
            if cred is not None:
                W._audit(user=by, c=c, cred=cred, op="host.health", module="", args={},
                         ok=False, error="agent", detail=text, who={"user": cred.ssh_user},
                         mode="agent")
            raise HealthError(text[:300]) from None
        ms = int((time.time() - started) * 1000)
        if cred is not None:
            W._audit(user=by, c=c, cred=cred, op="host.health", module="", args={}, ok=True,
                     who={"user": cred.ssh_user}, ms=ms, mode="agent")
        return {"data": data, "via": "agent",
                "credential": cred.name if cred else "satom-webctl agent", "ms": ms}
    cred = ch["credential"]
    try:
        data = W.read_as_service(c, "host.health", cred=cred, by=by)
    except Exception as exc:  # noqa: BLE001 -- WsmError / WsmDenied carry SATOM's text
        raise HealthError(str(exc)[:300]) from None
    return {"data": data, "via": "ssh", "credential": cred.name,
            "ms": int((time.time() - started) * 1000)}


# --------------------------------------------------------------------------- #
#  judging                                                                     #
# --------------------------------------------------------------------------- #
def _pct(part, whole) -> float:
    return 100.0 * part / whole if whole else 0.0


def ignored(unit: str, patterns) -> bool:
    return any(fnmatch.fnmatchcase(unit, p) for p in patterns or [])


def evaluate(data: dict, cfg: dict) -> list[dict]:
    """Problems of one reading: ``[{"key", "severity", "text"}]``, worst first."""
    out = []
    for fs in data.get("filesystems") or []:
        used = _pct(fs["used_bytes"], fs["size_bytes"])
        if used >= cfg["disk_crit"]:
            sev = "critical"
        elif used >= cfg["disk_warn"]:
            sev = "warning"
        else:
            sev = ""
        if sev:
            out.append({"key": "disk:" + fs["mount"], "severity": sev,
                        "text": "%s is %.0f %% full" % (fs["mount"], used)})
        if fs.get("inodes_total"):
            iu = _pct(fs.get("inodes_used", 0), fs["inodes_total"])
            if iu >= cfg["inode_warn"]:
                out.append({"key": "inodes:" + fs["mount"], "severity": "warning",
                            "text": "%s has used %.0f %% of its inodes" % (fs["mount"], iu)})
    mem = data.get("memory") or {}
    if mem.get("total_bytes"):
        free = _pct(mem["available_bytes"], mem["total_bytes"])
        if free <= cfg["mem_crit"]:
            out.append({"key": "memory", "severity": "critical",
                        "text": "only %.0f %% of the memory is available" % free})
        elif free <= cfg["mem_warn"]:
            out.append({"key": "memory", "severity": "warning",
                        "text": "only %.0f %% of the memory is available" % free})
    if mem.get("swap_total_bytes"):
        sw = _pct(mem.get("swap_used_bytes", 0), mem["swap_total_bytes"])
        if sw >= cfg["swap_warn"]:
            out.append({"key": "swap", "severity": "warning",
                        "text": "swap is %.0f %% used" % sw})
    cpus = max(1, int(data.get("cpus") or 1))
    # in a container /proc/loadavg is usually the host's: shown, not judged
    if not data.get("container") and data.get("load5", 0) / cpus >= float(cfg["load_warn"]):
        out.append({"key": "load", "severity": "warning",
                    "text": "load %.2f over 5 minutes on %d CPU(s)" % (data["load5"], cpus)})
    for s in data.get("services") or []:
        if s["active"] == "failed" and not ignored(s["unit"], cfg.get("ignore_units")):
            out.append({"key": "unit:" + s["unit"], "severity": "warning",
                        "text": "service %s has failed" % s["unit"]})
    out.sort(key=lambda p: (-SEVERITY[p["severity"]], p["key"]))
    return out


def state_of(problems: list[dict]) -> str:
    worst = max((SEVERITY[p["severity"]] for p in problems), default=0)
    return {0: "ok", 1: "warning", 2: "critical", 3: "unreachable"}[worst]


# --------------------------------------------------------------------------- #
#  storing                                                                     #
# --------------------------------------------------------------------------- #
def metric_lines(c, data: dict | None, ok: bool, ts_ms: int) -> list[str]:
    """Exposition lines of one reading. A failed reading is ONE line:
    ``satom_scrape_up 0`` -- never zeros that would read as an idle server."""
    from . import vm_store as V
    base = {"server": c.slug, "host": c.host}
    lines = [V.line("satom_scrape_up", {"device": c.slug, "kind": "linux",
                                        "collector": "host_health"}, 1 if ok else 0, ts_ms)]
    if not ok or not data:
        return lines

    def put(name, value, **extra):
        lines.append(V.line(name, dict(base, **extra), value, ts_ms))

    put("satom_host_cpus", data["cpus"])
    put("satom_host_cpu_pct", data["cpu_pct"])
    for k in ("load1", "load5", "load15"):
        put("satom_host_" + k, data[k])
    put("satom_host_uptime_seconds", data["uptime_s"])
    mem = data["memory"]
    put("satom_host_mem_total_bytes", mem["total_bytes"])
    put("satom_host_mem_available_bytes", mem["available_bytes"])
    if "swap_total_bytes" in mem:
        put("satom_host_swap_total_bytes", mem["swap_total_bytes"])
        put("satom_host_swap_used_bytes", mem.get("swap_used_bytes", 0))
    for fs in data["filesystems"]:
        lab = {"mount": fs["mount"], "fstype": fs["fstype"]}
        put("satom_host_fs_size_bytes", fs["size_bytes"], **lab)
        put("satom_host_fs_used_bytes", fs["used_bytes"], **lab)
        if "inodes_total" in fs:
            put("satom_host_fs_inodes_total", fs["inodes_total"], **lab)
            put("satom_host_fs_inodes_used", fs.get("inodes_used", 0), **lab)
    for state, n in data["processes"]["counts"].items():
        put("satom_host_processes", n, state=state)
    units = data.get("services") or []
    put("satom_host_services_failed", sum(1 for s in units if s["active"] == "failed"))
    put("satom_host_services_active", sum(1 for s in units if s["active"] == "active"))
    return [l for l in lines if l]


def _store_metrics(lines: list[str]) -> str:
    """Write locally, mirror to the HA peer. '' or the local write's error."""
    from . import metrics_collect as MC
    from . import vm_store as V
    ing = V.ingest(lines)
    try:
        MC.peer_write(lines)
    except Exception:  # noqa: BLE001 -- the peer copy is optional; peer_health() reports it
        pass
    return "" if ing["ok"] else "metrics store: %s" % ing["detail"]


def _snapshot(data: dict) -> dict:
    """What the page needs from a reading, without the 2 000-unit list."""
    units = data.get("services") or []
    keep = dict(data)
    keep["services"] = [s for s in units if s["active"] == "failed"][:200]
    keep["services_total"] = len(units)
    keep["services_active"] = sum(1 for s in units if s["active"] == "active")
    return keep


def collect(c, *, by: str = "scheduler", notify: bool = True) -> dict:
    """Read one server, judge, store, ring. NEVER raises; returns the saved
    record ``{at, ok, state, via, credential, error, problems, data, fails}``."""
    from . import settings_store as ST
    cfg = conf(c.slug)
    prev = last(c.slug)
    now = datetime.utcnow()
    ts_ms = int(time.time() * 1000)
    rec = {"at": now.isoformat(timespec="seconds"), "ok": False, "via": "", "credential": "",
           "error": "", "problems": [], "data": None, "ms": None,
           "fails": int(prev.get("fails") or 0)}
    try:
        r = read(c, by=by, cfg=cfg)
        rec.update(ok=True, via=r["via"], credential=r["credential"], ms=r["ms"],
                   data=_snapshot(r["data"]), fails=0)
        rec["problems"] = evaluate(r["data"], cfg)
        lines = metric_lines(c, r["data"], True, ts_ms)
    except HealthError as exc:
        rec.update(error=str(exc), fails=rec["fails"] + 1, data=prev.get("data"),
                   via=channel(c, cfg)["via"])
        rec["problems"] = [{"key": "unreachable", "severity": "unreachable",
                            "text": "cannot read the server: %s" % exc}]
        lines = metric_lines(c, None, False, ts_ms)
    except Exception as exc:  # noqa: BLE001 -- one server must not stop the others
        _log.warning("server health of %s failed", c.slug, exc_info=True)
        rec.update(error="internal error: %s" % exc.__class__.__name__,
                   fails=rec["fails"] + 1, data=prev.get("data"))
        rec["problems"] = [{"key": "unreachable", "severity": "unreachable",
                            "text": "SATOM could not read the server (%s)"
                                    % exc.__class__.__name__}]
        lines = metric_lines(c, None, False, ts_ms)
    rec["state"] = state_of(rec["problems"])
    rec["metrics_error"] = _store_metrics(lines)
    try:
        ST.set_json(LAST_KEY + c.slug, rec)
    except Exception:  # noqa: BLE001
        _log.warning("saving the health of %s failed", c.slug, exc_info=True)
    if notify:
        _ring(c, rec)
    return rec


# --------------------------------------------------------------------------- #
#  the bell                                                                    #
# --------------------------------------------------------------------------- #
def _ring(c, rec: dict) -> int:
    """Ring once per NEW problem (or a worse one), once on recovery. Unreachable
    rings after UNREACHABLE_AFTER failed readings in a row."""
    from . import settings_store as ST
    try:
        seen = ST.get_json_checked(NOTIFIED_KEY, {}, dict)
        if seen is ST.MALFORMED or not isinstance(seen, dict):
            seen = {}
        mine = seen.get(c.slug) if isinstance(seen.get(c.slug), dict) else {}
        now_p = {p["key"]: p for p in rec["problems"]
                 if p["key"] != "unreachable" or rec["fails"] >= UNREACHABLE_AFTER}
        if not rec["ok"] and rec["fails"] < UNREACHABLE_AFTER:
            return 0                # one lost reading: keep the previous judgement
        fresh = [p for k, p in now_p.items()
                 if SEVERITY[p["severity"]] > SEVERITY.get(mine.get(k, "ok"), 0)]
        recovered = bool(mine) and not now_p
        sent = 0
        if fresh or recovered:
            from ..models_notifications import Notification
            from . import notifications as N
            from .alerts import _admin_ids
            from ..branding import PRODUCTS
            adom = "linux" if "linux" in PRODUCTS else "global"
            link = "/webserver/%s/health" % c.slug
            admins = _admin_ids()
            if fresh:
                worst = max(SEVERITY[p["severity"]] for p in fresh)
                title = "%s: %s" % (c.name, fresh[0]["text"]) if len(fresh) == 1 else \
                    "%s: %d health problems" % (c.name, len(fresh))
                body = "; ".join(p["text"] for p in fresh[:10])
                sent = N.push_many(admins, title[:200], body=body[:1000], link=link,
                                   kind=(Notification.KIND_ERROR if worst >= 2
                                         else Notification.KIND_WARNING), product=adom)
            else:
                sent = N.push_many(admins, "%s is healthy again" % c.name,
                                   body="Every problem SATOM reported on %s has cleared."
                                        % c.name, link=link,
                                   kind=Notification.KIND_SUCCESS, product=adom)
        seen[c.slug] = {k: p["severity"] for k, p in now_p.items()}
        ST.set_json(NOTIFIED_KEY, seen)
        return sent
    except Exception:  # noqa: BLE001 -- a bell must never fail the reading
        _log.warning("health notification for %s failed", c.slug, exc_info=True)
        return 0


# --------------------------------------------------------------------------- #
#  the scheduled action                                                        #
# --------------------------------------------------------------------------- #
def due(c, now: datetime | None = None) -> bool:
    cfg = conf(c.slug)
    if cfg["via"] == "off":
        return False
    rec = last(c.slug)
    try:
        at = datetime.fromisoformat(rec["at"])
    except (KeyError, TypeError, ValueError):
        return True
    return (now or datetime.utcnow()) - at >= timedelta(minutes=cfg["interval_min"]) \
        - timedelta(seconds=20)


def run_due(now: datetime | None = None, *, dry_run: bool = False) -> dict:
    """Read every server whose interval has passed, within RUN_BUDGET_S."""
    from . import wsm as W
    out = {"servers": 0, "read": 0, "failed": [], "problems": 0, "skipped": 0, "deferred": 0}
    if not W.module_active():
        return out
    started = time.time()
    for c in W.servers():
        out["servers"] += 1
        if not due(c, now):
            out["skipped"] += 1
            continue
        if time.time() - started > RUN_BUDGET_S:
            out["deferred"] += 1
            continue
        if dry_run:
            out["read"] += 1
            continue
        rec = collect(c)
        out["read"] += 1
        if not rec["ok"]:
            out["failed"].append("%s: %s" % (c.slug, rec["error"]))
        out["problems"] += len([p for p in rec["problems"] if p["key"] != "unreachable"])
    return out


def ensure_scheduled(by: str = "system:server-health") -> bool:
    """Create the every-minute action when it does not exist yet (each server
    keeps its own interval). Rows are data: an administrator's edits stay."""
    from ..models import ScheduledAction, db
    from . import scheduled_actions as sa
    from .scheduler import compute_next_run
    try:
        if ScheduledAction.query.filter_by(action=ACTION).first() is not None:
            return False
        sched = {"every": 1, "unit": "minutes"}
        row = ScheduledAction(
            name=ACTION_NAME, scope="admin", product="global", action=ACTION,
            targets="[]", params="{}", schedule_kind="interval", schedule=json.dumps(sched),
            enabled=True, catch_up=False, created_by=by)
        row.next_run = compute_next_run("interval", sched, tz=sa._configured_tz())
        db.session.add(row)
        db.session.commit()
        return True
    except Exception:  # noqa: BLE001
        _log.warning("server_health.ensure_scheduled failed", exc_info=True)
        db.session.rollback()
        return False


# --------------------------------------------------------------------------- #
#  history (the page's charts)                                                 #
# --------------------------------------------------------------------------- #
SERIES = {
    "cpu": 'max(satom_host_cpu_pct{server="%(s)s"})',
    "memory": '100 * (1 - max(satom_host_mem_available_bytes{server="%(s)s"}) '
              '/ max(satom_host_mem_total_bytes{server="%(s)s"}))',
    "disk": 'max(100 * satom_host_fs_used_bytes{server="%(s)s"} '
            '/ satom_host_fs_size_bytes{server="%(s)s"})',
    "load": 'max(satom_host_load1{server="%(s)s"})',
    "up": 'max(satom_scrape_up{device="%(s)s",collector="host_health"})',
}
RANGES = {"6h": (6 * 3600, "120s"), "24h": (86400, "300s"), "7d": (7 * 86400, "1800s")}


def history(slug: str, rng: str = "24h") -> dict:
    """``{"ok", "series": {name: [[ts, value], ...]}, "errors": {name: text}}``.
    A query that fails is an ERROR the page shows -- never an empty chart."""
    from . import vm_store as V
    span, step = RANGES.get(rng, RANGES["24h"])
    end = time.time()
    out = {"ok": True, "range": rng if rng in RANGES else "24h", "series": {}, "errors": {}}
    for name, expr in SERIES.items():
        try:
            res = V.query_range(expr % {"s": slug}, end - span, end, step, nocache=True)
            if res.get("status") != "success":
                raise RuntimeError(res.get("error") or "the metrics store refused the query")
            pts = []
            for r in (res.get("data") or {}).get("result") or []:
                pts = [[int(float(t)), round(float(v), 2)] for t, v in r.get("values") or []]
                break
            out["series"][name] = pts
        except Exception as exc:  # noqa: BLE001
            out["ok"] = False
            out["errors"][name] = str(exc)[:200]
    return out
