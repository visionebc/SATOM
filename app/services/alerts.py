"""Proactive alert engine — the *push* side of observability.

Everything else in SATOM is *pull*: you open the Monitoring / System Backup /
Node TLS page and read a live badge. This engine flips that around — it evaluates
a handful of cheap health checks on a timer and, when one crosses a threshold,
*pushes* a notice out through email (``email_service``) and the in-app bell
(``notifications``) so nobody has to be looking at the page.

Design notes
------------
* **Config lives in ``app_settings``** (one source of truth across gunicorn
  workers), same pattern as ``email_service``/``settings_store``.
* **Cooldown**: a fired alert is suppressed for ``alerts.cooldown_hours`` (default
  6h) so a persistent condition (cert 13 days out) does not email every run. The
  last-fired timestamp per alert key lives in the ``alerts.state`` JSON blob.
* **Per-node**: cert / device-reachability / git-lag are node-local truths, so the
  timer runs on BOTH nodes and each reports about itself. The node hostname is in
  every message so a two-node fleet is legible.
* **Never raises**: a broken individual check degrades to a logged skip; the run
  keeps going. Email delivery is best-effort (``send_email`` never raises).
"""
from __future__ import annotations

import json
import socket
from datetime import datetime, timezone

from ..models import AppSetting
from . import email_service
from . import notifications as notify

# ---- config keys ----------------------------------------------------------
K_ENABLED = "alerts.enabled"              # "1" / "0"
K_EMAIL_TO = "alerts.email_to"            # falls back to email.default_to
K_COOLDOWN_H = "alerts.cooldown_hours"    # per-alert suppression window
K_CERT_DAYS = "alerts.cert_days"          # warn when cert has <= N days left
K_GIT_BEHIND_MAX = "alerts.git_behind_max"  # warn when standby lags > N commits
K_GIT_AHEAD_MAX_H = "alerts.git_ahead_max_hours"  # warn when a commit stays unpushed
K_BACKUP_MAX_H = "alerts.backup_max_hours"  # warn when newest bundle older than N h
K_STATE = "alerts.state"                  # JSON {alert_key: last_fired_iso}
# per-check enable toggles (default on)
K_CHK_CERT = "alerts.check.cert"
K_CHK_GIT = "alerts.check.git"
K_CHK_DEVICE = "alerts.check.device"
K_CHK_BACKUP = "alerts.check.backup"
K_CHK_DRIFT = "alerts.check.drift"
K_CHK_ACTIONS = "alerts.check.actions"
K_ACT_STREAK_CRIT = "alerts.action_fail_streak_crit"  # crit at N straight failures
K_ACT_OVERDUE_H = "alerts.action_overdue_hours"       # enabled action this late to fire
K_DRIFT_WINDOW_MIN = "alerts.drift_window_min"  # only alert on drift newer than this
K_DEV_MIN = "alerts.device_min_status"    # "warn" (default) or "crit"

DEFAULTS = {
    K_ENABLED: "0",
    K_COOLDOWN_H: "6",
    K_CERT_DAYS: "14",
    K_GIT_BEHIND_MAX: "25",
    K_GIT_AHEAD_MAX_H: "6",
    K_BACKUP_MAX_H: "48",
    K_CHK_CERT: "1",
    K_CHK_GIT: "1",
    K_CHK_DEVICE: "1",
    K_CHK_BACKUP: "1",
    K_CHK_DRIFT: "1",
    K_CHK_ACTIONS: "1",
    K_ACT_STREAK_CRIT: "3",
    K_ACT_OVERDUE_H: "3",
    K_DRIFT_WINDOW_MIN: "90",
    K_DEV_MIN: "warn",
}

_REPO_ROOT = "/opt/satom"

# How far back _check_actions reads a scheduled action history. A streak that
# hits this cap is reported as "N+": a floor, not a count.
_RUN_WINDOW = 50

SEV_CRITICAL = "critical"
SEV_WARNING = "warning"
SEV_INFO = "info"
_SEV_RANK = {SEV_INFO: 0, SEV_WARNING: 1, SEV_CRITICAL: 2}


# ---- small helpers --------------------------------------------------------
def _get(key: str) -> str:
    v = AppSetting.get(key)
    return DEFAULTS.get(key, "") if v is None else v


def _flag(key: str) -> bool:
    return _get(key) in ("1", "on", "true", "True")


def _int(key: str, fallback: int) -> int:
    try:
        return int(str(_get(key)).strip())
    except (TypeError, ValueError):
        return fallback


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _node() -> str:
    try:
        return socket.gethostname()
    except Exception:  # noqa: BLE001
        return "node"


def _is_read_only_replica() -> bool:
    """True when this node's Postgres is a streaming replica (standby), where any
    write (notifications, cooldown state) would fail. Self-detecting via
    ``pg_is_in_recovery()`` so no role config is needed and a promoted standby
    starts dispatching automatically. SQLite / unknown → treated as writable."""
    from ..extensions import db
    try:
        from sqlalchemy import text
        return bool(db.session.execute(text("SELECT pg_is_in_recovery()")).scalar())
    except Exception:  # noqa: BLE001
        return False


def is_enabled() -> bool:
    return _flag(K_ENABLED)


# ---- admin-console config (read + save) -----------------------------------
def config() -> dict:
    """Current alert-engine settings for the admin console. Never raises."""
    return {
        "enabled": _flag(K_ENABLED),
        "email_to": _get(K_EMAIL_TO),
        "email_fallback": email_service.config().get("default_to") or "",
        "cooldown_hours": _int(K_COOLDOWN_H, 6),
        "cert_days": _int(K_CERT_DAYS, 14),
        "git_behind_max": _int(K_GIT_BEHIND_MAX, 25),
        "git_ahead_max_hours": _int(K_GIT_AHEAD_MAX_H, 6),
        "backup_max_hours": _int(K_BACKUP_MAX_H, 48),
        "drift_window_min": _int(K_DRIFT_WINDOW_MIN, 90),
        "action_fail_streak_crit": _int(K_ACT_STREAK_CRIT, 3),
        "action_overdue_hours": _int(K_ACT_OVERDUE_H, 3),
        "device_min_status": _get(K_DEV_MIN) or "warn",
        "checks": {
            "cert": _flag(K_CHK_CERT),
            "git": _flag(K_CHK_GIT),
            "device": _flag(K_CHK_DEVICE),
            "backup": _flag(K_CHK_BACKUP),
            "drift": _flag(K_CHK_DRIFT),
            "actions": _flag(K_CHK_ACTIONS),
        },
    }


def save_config(form) -> None:
    """Persist alert-engine settings from the admin-console form. Checkbox
    fields are 'on'/absent; numeric fields are clamped to sane ranges."""
    def g(key, default=""):
        try:
            return (form.get(key, default) or "").strip()
        except AttributeError:
            return str(form.get(key, default) or "").strip()

    def cb(key):  # checkbox → "1"/"0"
        return "1" if form.get(key) in ("on", "1", "true", "True", True) else "0"

    def clamp(key, lo, hi, default):
        try:
            n = int(g(key) or default)
        except ValueError:
            n = default
        return str(max(lo, min(hi, n)))

    AppSetting.set(K_ENABLED, cb("enabled"))
    AppSetting.set(K_EMAIL_TO, g("email_to"))
    AppSetting.set(K_COOLDOWN_H, clamp("cooldown_hours", 0, 168, 6))
    AppSetting.set(K_CERT_DAYS, clamp("cert_days", 1, 365, 14))
    AppSetting.set(K_GIT_BEHIND_MAX, clamp("git_behind_max", 1, 10000, 25))
    AppSetting.set(K_GIT_AHEAD_MAX_H, clamp("git_ahead_max_hours", 1, 8760, 6))
    AppSetting.set(K_BACKUP_MAX_H, clamp("backup_max_hours", 1, 8760, 48))
    AppSetting.set(K_DRIFT_WINDOW_MIN, clamp("drift_window_min", 1, 43200, 90))
    AppSetting.set(K_ACT_STREAK_CRIT, clamp("action_fail_streak_crit", 2, 100, 3))
    AppSetting.set(K_ACT_OVERDUE_H, clamp("action_overdue_hours", 1, 8760, 3))
    # Only "warn" and "crit" are dispatchable floors: "ok"/"unknown" would mail
    # about every device on every run.
    _dev_min = g("device_min_status")
    AppSetting.set(K_DEV_MIN, _dev_min if _dev_min in ("warn", "crit") else "warn")
    # per-check toggles (absent checkbox = off)
    AppSetting.set(K_CHK_CERT, cb("check_cert"))
    AppSetting.set(K_CHK_GIT, cb("check_git"))
    AppSetting.set(K_CHK_DEVICE, cb("check_device"))
    AppSetting.set(K_CHK_BACKUP, cb("check_backup"))
    AppSetting.set(K_CHK_DRIFT, cb("check_drift"))
    AppSetting.set(K_CHK_ACTIONS, cb("check_actions"))
    # AppSetting.set commits per call — no trailing commit needed.


def recipients() -> list[str]:
    to = email_service.parse_recipients(_get(K_EMAIL_TO))
    if not to:
        cfg = email_service.config()
        to = email_service.parse_recipients(cfg.get("default_to"))
    return to


# ---- cooldown state -------------------------------------------------------
def _load_state() -> dict:
    raw = AppSetting.get(K_STATE)
    if not raw:
        return {}
    try:
        return json.loads(raw) or {}
    except (ValueError, TypeError):
        return {}


def _save_state(state: dict) -> None:
    AppSetting.set(K_STATE, json.dumps(state))


def _in_cooldown(state: dict, key: str, cooldown_h: int) -> bool:
    last = state.get(key)
    if not last:
        return False
    try:
        prev = datetime.fromisoformat(last)
    except ValueError:
        return False
    if prev.tzinfo is None:
        prev = prev.replace(tzinfo=timezone.utc)
    return (_now() - prev).total_seconds() < cooldown_h * 3600


# ---- individual checks ----------------------------------------------------
# Each returns a list of findings: {key, severity, title, detail}.
def _renewal_failures() -> list[dict]:
    """A renewal that FAILED is its own alert — until now the only e-mail was the
    T-N days expiry warning, which means a broken pipeline stayed silent for weeks
    and then surfaced as an emergency. The failure detail (and the page that shows
    the full error) goes in the mail body."""
    try:
        from . import cert_renew_log as jrn
        summ = jrn.summary()
    except Exception:  # noqa: BLE001
        return []
    streak = summ.get("fail_streak") or 0
    if streak <= 0:
        return []
    last = summ.get("last_error") or {}
    sev = SEV_CRITICAL if streak >= 3 else SEV_WARNING
    return [{"key": "cert.renew_failed", "severity": sev,
             "title": f"Certificate renewal failing on {_node()} ({streak} consecutive)",
             "detail": (f"Channel {last.get('channel')}: {last.get('summary')}\n"
                        f"Error: {last.get('error') or 'n/a'}\n"
                        f"Last attempt: {last.get('at')}\n"
                        f"Full history: /cert-manager/renewals")}]


def _check_cert() -> list[dict]:
    from . import cert_service
    out = _renewal_failures()
    try:
        cur = cert_service.current()
    except Exception as exc:  # noqa: BLE001
        return out + [{"key": "cert.error", "severity": SEV_WARNING,
                       "title": "Certificate status unreadable",
                       "detail": f"cert_service.current() failed: {exc}"}]
    days = cur.get("days_left")
    if days is None:
        return out
    thresh = _int(K_CERT_DAYS, 14)
    if days > thresh:
        return out
    sev = SEV_CRITICAL if days <= 3 else SEV_WARNING
    src = cur.get("source") or "?"
    return out + [{"key": "cert.expiry", "severity": sev,
             "title": f"TLS certificate expires in {days} day(s)",
             "detail": (f"The service certificate on {_node()} expires in {days} "
                        f"day(s) (source={src}, not_after={cur.get('not_after')}). "
                        f"Renew or re-copy the wildcard before it lapses. "
                        f"Renewal history + errors: /cert-manager/renewals")}]


def _check_git() -> list[dict]:
    from . import git_service
    try:
        info = git_service.git_info()
    except Exception as exc:  # noqa: BLE001
        return [{"key": "git.error", "severity": SEV_WARNING,
                 "title": "Git status unreadable",
                 "detail": f"git_info() failed: {exc}"}]
    ahead, behind = int(info.get("ahead") or 0), int(info.get("behind") or 0)
    # True divergence: local has commits the upstream doesn't AND is behind it →
    # the branches forked and a fast-forward is impossible. This is the dangerous
    # one (the HA pair can silently disagree).
    if ahead > 0 and behind > 0:
        return [{"key": "git.diverged", "severity": SEV_CRITICAL,
                 "title": f"Git history diverged on {_node()}",
                 "detail": (f"Local branch is {ahead} ahead AND {behind} behind "
                            f"origin — the histories have forked and cannot "
                            f"fast-forward. Reconcile before the nodes disagree.")}]
    # ahead>0 with behind==0 is the signature of an unreachable remote (Gitea
    # down, token expired, DNS): the hourly reports/ publisher keeps committing
    # locally and the push silently fails — `satom-git-publish.timer` still
    # exits 0, so nothing else notices. Those local-only commits are the off-box
    # copy of the device source of truth, and the update runner's reset would
    # discard them (it parks them under refs/backup/ now, but recovering a ref
    # is not the same as having published). Age, not count, is the signal: one
    # unpushed commit for three days is worse than twenty in the last hour.
    if ahead > 0:
        from . import git_backup
        state = git_backup.unpushed_state()
        age = float(state.get("oldest_age_h") or 0.0)
        max_h = _int(K_GIT_AHEAD_MAX_H, 6)
        if age >= max_h:
            crit = age >= max_h * 8
            return [{"key": "git.ahead_unpushed",
                     "severity": SEV_CRITICAL if crit else SEV_WARNING,
                     "title": (f"{_node()} has {ahead} commit(s) unpushed for "
                               f"{age:.0f}h"),
                     "detail": (f"The oldest local commit has been waiting "
                                f"{age:.0f}h to reach {state.get('upstream') or 'origin'} "
                                f"(threshold {max_h}h). The push is failing "
                                f"silently — check the git remote / Gitea. Until "
                                f"it succeeds these commits exist on this node "
                                f"only: take a git bundle from System Backup & "
                                f"Restore to get them off-box.")}]
    # Benign lag is expected between syncs; only shout when it is stuck far behind.
    behind_max = _int(K_GIT_BEHIND_MAX, 25)
    if behind > behind_max:
        return [{"key": "git.behind", "severity": SEV_WARNING,
                 "title": f"{_node()} is {behind} commits behind origin",
                 "detail": (f"This node is {behind} commits behind origin (> "
                            f"{behind_max}). If it is the standby, the git sync "
                            f"may be stuck — check the reconciler / datasync.")}]
    return []


def _reachable(host: str, port: int) -> bool:
    """TCP liveness. The ONLY signal in this module that touches the network —
    the Monitoring page is DB-first by contract and deliberately cannot probe."""
    try:
        with socket.create_connection((host, int(port or 443)), timeout=4):
            return True
    except Exception:  # noqa: BLE001 — unreachable is the finding, not an error
        return False


_PRODUCT_KINDS = ("fortiweb", "fortiadc", "fortianalyzer")


def _product_of(appliance) -> str:
    """ADOM a device-scoped finding belongs to, '' when the kind is unknown.

    The alert engine runs in a background thread with NO request context, so
    ``product_scope.stamp()`` returns '' for everything it raises — and an
    unscoped notification is visible in the FortiWeb ADOM by construction. That
    made the FortiWeb bell the catch-all for fadc and faz01 too. A device
    finding's ADOM is not the session's, it is the DEVICE's kind."""
    kind = (getattr(appliance, "kind", "") or "").strip().lower()
    return kind if kind in _PRODUCT_KINDS else ""


def _check_devices() -> list[dict]:
    """One finding per unhealthy appliance, graded on the SAME ladder the
    Monitoring page prints.

    Until 2026-07-28 this check opened a TCP socket and nothing else, so it was
    blind to every failure where the box answers the port but stops being
    useful: fw6 and fw7 accepted :443 for a week while their harvest died on an
    invalid licence — the page went red and no mail was ever sent. The socket
    probe stays (it is the only network-touching signal here) but it is now one
    input among the four DB-first signals from :mod:`device_health`, merged into
    a single per-device message: one device, one alert, every failing signal
    listed. Sharing ``device_health`` is the point — two ladders would let the
    page and the mailbox disagree about the same box."""
    from ..models import Appliance
    from . import device_health as devhealth

    try:
        appliances = Appliance.query.all()
    except Exception as exc:  # noqa: BLE001
        return [{"key": "device.error", "severity": SEV_WARNING,
                 "title": "Appliance list unreadable",
                 "detail": f"Appliance.query failed: {exc}"}]

    floor = devhealth.RANK.get(_get(K_DEV_MIN), 0) or devhealth.RANK["warn"]
    try:
        warn_pct, crit_pct = devhealth.thresholds()
    except Exception:  # noqa: BLE001
        warn_pct, crit_pct = 80.0, 95.0

    findings: list[dict] = []
    for a in appliances:
        if getattr(a, "maintenance", False):
            continue
        host, port = a.host, int(a.port or 443)
        reachable = _reachable(host, port)
        try:
            health = devhealth.collect_for(a, warn_pct, crit_pct)
        except Exception as exc:  # noqa: BLE001 — one bad device never sinks the run
            findings.append({"key": f"device.error.{a.name}", "severity": SEV_WARNING,
                             "title": f"Health roll-up failed for {a.name}",
                             "product": _product_of(a),
                             "detail": f"device_health.collect_for() raised: {exc}"})
            continue

        lines = [] if reachable else [
            f"- Reachability: no TCP connection to {host}:{port} within 4s "
            f"(probed from {_node()}) — down or network-partitioned"]
        lines += [f"- {r['label']}: {r['text']}" for r in health["reasons"]
                  if r["status"] in ("warn", "crit")]

        status = devhealth.worst_of([health["status"]] +
                                    ([] if reachable else ["warn"]))
        if not lines or devhealth.RANK.get(status, 0) < floor:
            continue

        crit = status == "crit"
        findings.append({
            # The status is part of the key ON PURPOSE: an escalation from warn
            # to crit inside the cooldown window must still reach the operator.
            "key": f"device.health.{a.name}.{status}",
            "severity": SEV_CRITICAL if crit else SEV_WARNING,
            "title": f"Device {a.name} is {'critical' if crit else 'degraded'}",
            "product": _product_of(a),
            "detail": ("\n".join(lines) +
                       f"\n\n{a.kind} appliance at {host}:{port}, probed from "
                       f"{_node()}. Full picture: /monitoring/")})
    return findings



def _check_actions() -> list[dict]:
    """One finding per broken scheduled automation — silent unless it breaks.

    This is the push half of the housekeeping contract. Background sweeps were
    made silent on 2026-07-28 (a run that worked is not news), which is only
    safe if the FAILING run is loud somewhere. It was not: ``scheduled_actions``
    contains no ``notify`` call and this engine had no check for it, so on the
    day this was written action 5 (device_sync) had failed **24 consecutive
    scheduled runs** and nobody was told. The day before, ``scheduler_guard.sh``
    broke on ``runuser`` and the sidecar fired *nothing at all* for hours while
    systemd still showed the unit ``active`` — also silent.

    Two failure modes, therefore, not one:

    * **failing** — the action fires and errors. Graded on the consecutive
      scheduled-failure streak.
    * **overdue** — the action is enabled and its ``next_run`` is long past. A
      scheduler that stops firing produces *no* failed runs at all, so a
      streak-only check would call a dead scheduler healthy.

    Only ``trigger='schedule'`` runs count. A manual run is user-initiated and
    its result is already on the operator's screen; worse, mixing the two hides
    exactly the case seen on 2026-07-28 where the scheduled path failed
    (``Unknown action``: the sidecar held stale code) while the manual path
    succeeded in the freshly restarted web worker.
    """
    from ..models import ScheduledAction, ScheduledActionRun

    try:
        actions = ScheduledAction.query.filter_by(enabled=True).all()
    except Exception as exc:  # noqa: BLE001
        return [{"key": "action.error", "severity": SEV_WARNING,
                 "title": "Scheduled action list unreadable",
                 "detail": f"ScheduledAction.query failed: {exc}"}]

    streak_crit = max(2, _int(K_ACT_STREAK_CRIT, 3))
    overdue_h = max(1, _int(K_ACT_OVERDUE_H, 3))
    now = datetime.utcnow()
    findings: list[dict] = []

    for a in actions:
        product = (a.product or "").strip().lower()
        product = product if product in _PRODUCT_KINDS else ""
        label = f"{a.name or a.action} (#{a.id})"
        lines: list[str] = []
        crit = False

        try:
            runs = (ScheduledActionRun.query
                    .filter_by(action_id=a.id, trigger="schedule")
                    .order_by(ScheduledActionRun.id.desc()).limit(_RUN_WINDOW).all())
        except Exception as exc:  # noqa: BLE001 — one bad action never sinks the run
            findings.append({"key": f"action.error.{a.id}", "severity": SEV_WARNING,
                             "title": f"Run history unreadable for {label}",
                             "product": product,
                             "detail": f"ScheduledActionRun.query raised: {exc}"})
            continue

        # -- failing --------------------------------------------------------
        streak, last_fail = 0, None
        for r in runs:
            if r.status == "failed":
                streak += 1
                last_fail = last_fail or r
            elif r.status in ("ok", "skipped"):
                # A skip terminates the streak as surely as a success does.
                # Stepping over it looks safer and is not: an action whose whole
                # target set is parked reports 'skipped' forever, so old
                # failures would never clear and the alert would stay critical
                # permanently — the always-red state this check exists to
                # prevent. A skip is a legitimate outcome, not a fault; if the
                # action really is broken its next real run restarts the streak.
                break
            # 'running' is the row this very sweep opened — neither outcome yet.
        if streak:
            crit = crit or streak >= streak_crit
            when = last_fail.started_at.strftime("%Y-%m-%d %H:%M") if last_fail else "?"
            why = ((last_fail.summary or "").strip() if last_fail else "") or "no summary recorded"
            # The history window is bounded; at the cap the streak is a floor,
            # not a count. Saying "50" when it may be 500 is a lie the operator
            # would use to judge how long this has been broken.
            shown = f"{streak}+" if streak >= _RUN_WINDOW else str(streak)
            lines.append(f"- Failing: {shown} consecutive scheduled run(s) failed, "
                         f"latest {when} UTC — {why[:200]}")

        # -- overdue --------------------------------------------------------
        if a.next_run:
            late_h = (now - a.next_run).total_seconds() / 3600.0
            if late_h >= overdue_h:
                crit = crit or late_h >= overdue_h * 4
                last = a.last_run.strftime("%Y-%m-%d %H:%M") if a.last_run else "never"
                lines.append(f"- Overdue: due {a.next_run.strftime('%Y-%m-%d %H:%M')} UTC, "
                             f"{late_h:.1f}h ago and still not fired (last run: {last}). "
                             f"The scheduler sidecar may not be running on the primary.")

        if not lines:
            continue

        findings.append({
            # Severity is in the key ON PURPOSE (same reason as device health):
            # an escalation from warn to crit inside the cooldown must get out.
            "key": f"action.broken.{a.id}.{'crit' if crit else 'warn'}",
            "severity": SEV_CRITICAL if crit else SEV_WARNING,
            "title": f"Scheduled automation {'failing' if streak else 'not firing'}: {label}",
            "product": product,
            "detail": ("\n".join(lines) +
                       f"\n\nAction '{a.action}', schedule {a.schedule_kind}, "
                       f"evaluated on {_node()}. Details: /scheduled-actions/")})
    return findings

def _check_backup() -> list[dict]:
    from . import system_backup
    try:
        inv = system_backup.local_inventory()
    except Exception as exc:  # noqa: BLE001
        return [{"key": "backup.error", "severity": SEV_INFO,
                 "title": "Backup inventory unreadable",
                 "detail": f"local_inventory() failed: {exc}"}]
    bundles = inv.get("bundles") or []
    if not bundles:
        return [{"key": "backup.none", "severity": SEV_WARNING,
                 "title": "No database backup bundles present",
                 "detail": f"No pg_dump bundles found on {_node()}."}]
    # Newest bundle mtime; each entry carries an ISO 'modified' or epoch 'mtime'.
    newest = None
    for b in bundles:
        ts = b.get("created") or b.get("modified") or b.get("mtime") or b.get("date")
        dt = None
        if isinstance(ts, (int, float)):
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        elif isinstance(ts, str) and ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                dt = None
        if dt is not None and (newest is None or dt > newest):
            newest = dt
    if newest is None:
        return []
    if newest.tzinfo is None:
        newest = newest.replace(tzinfo=timezone.utc)
    age_h = (_now() - newest).total_seconds() / 3600
    max_h = _int(K_BACKUP_MAX_H, 48)
    if age_h > max_h:
        return [{"key": "backup.stale", "severity": SEV_WARNING,
                 "title": f"Newest DB backup is {int(age_h)}h old",
                 "detail": (f"The most recent database bundle on {_node()} is "
                            f"{int(age_h)}h old (> {max_h}h). Backups may have "
                            f"stopped running.")}]
    return []


# Keys that change on every harvest (wall-clock, rotating crypto material,
# device uptime) and are NOT config drift — the device embeds its own live state
# in the config dump. Stripped at ANY depth before comparing. Operator-tunable
# via ``alerts.drift_volatile_keys`` (comma list, replaces the default). Matched
# case-insensitively on the exact key name so a schedule field like
# ``start-hour`` is NOT stripped (only a bare ``hour``).
_DRIFT_VOLATILE_DEFAULT = {
    "generated_at", "harvested_at", "captured_at", "timestamp",
    "system_datetime", "system_time", "current_time", "datetime",
    "uptime", "hour", "minute", "second",
}


def _drift_volatile_keys() -> set[str]:
    raw = _get("alerts.drift_volatile_keys")
    if raw:
        return {s.strip().lower() for s in raw.replace(";", ",").split(",") if s.strip()}
    return set(_DRIFT_VOLATILE_DEFAULT)


def _drift_exclude_slugs() -> set[str]:
    # faz01 embeds rotating base64 session/crypto tokens that survive key-name
    # normalisation; excluded by default until its volatile fields are mapped.
    raw = AppSetting.get("alerts.drift_exclude")
    raw = "faz01" if raw is None else raw
    return {s.strip() for s in raw.replace(";", ",").split(",") if s.strip()}


def _strip_volatile(obj, vol: set[str]):
    """Recursively drop volatile keys (by lowercased name) at any depth."""
    if isinstance(obj, dict):
        return {k: _strip_volatile(v, vol) for k, v in obj.items()
                if k.lower() not in vol}
    if isinstance(obj, list):
        return [_strip_volatile(v, vol) for v in obj]
    return obj


def _normalize_snapshot(blob: str):
    """Parse a snapshot and drop volatile keys at any depth so a pure clock /
    token refresh doesn't read as config drift. Returns a canonical string, or
    None if the blob isn't parseable JSON (fall back to raw compare then)."""
    try:
        doc = json.loads(blob)
    except (ValueError, TypeError):
        return None
    return json.dumps(_strip_volatile(doc, _drift_volatile_keys()), sort_keys=True)


def _check_drift() -> list[dict]:
    """Config-drift: for each device, compare the two most recent git-committed
    versions of its source-of-truth (``reports/<slug>/_config.json``) with
    volatile fields normalised out. A surviving change means the live device
    config diverged from the prior baseline — typically a device-side (CLI/GUI)
    edit made outside SATOM. Only fresh drift (newer than the window) alerts,
    keyed by commit sha so each distinct drift fires once. Near-zero cost: reads
    git history, never touches the appliance. Noisy devices (rotating fields that
    survive normalisation) can be listed in ``alerts.drift_exclude``."""
    import subprocess
    from ..models import Appliance
    findings: list[dict] = []
    try:
        appliances = Appliance.query.all()
    except Exception as exc:  # noqa: BLE001
        return [{"key": "drift.error", "severity": SEV_INFO,
                 "title": "Drift scan: appliance list unreadable", "detail": str(exc)}]
    window_min = _int(K_DRIFT_WINDOW_MIN, 90)
    excluded = _drift_exclude_slugs()
    for a in appliances:
        slug = a.name
        if slug in excluded:
            continue
        path = f"reports/{slug}/_config.json"
        try:
            log = subprocess.run(
                ["git", "-C", _REPO_ROOT, "log", "-2", "--format=%H %ct", "--", path],
                capture_output=True, text=True, timeout=15)
        except Exception:  # noqa: BLE001
            continue
        lines = [ln for ln in log.stdout.splitlines() if ln.strip()]
        if len(lines) < 2:
            continue
        try:
            new_sha, new_ct = lines[0].split()
            old_sha = lines[1].split()[0]
            age_min = (_now().timestamp() - int(new_ct)) / 60
        except (ValueError, IndexError):
            continue
        if age_min > window_min:
            continue  # drift is old — already seen / not this run's concern
        try:
            blob_new = subprocess.run(["git", "-C", _REPO_ROOT, "show", f"{new_sha}:{path}"],
                                      capture_output=True, text=True, timeout=20).stdout
            blob_old = subprocess.run(["git", "-C", _REPO_ROOT, "show", f"{old_sha}:{path}"],
                                      capture_output=True, text=True, timeout=20).stdout
        except Exception:  # noqa: BLE001
            continue
        norm_new, norm_old = _normalize_snapshot(blob_new), _normalize_snapshot(blob_old)
        # If either won't parse, fall back to raw text compare (conservative).
        if norm_new is None or norm_old is None:
            if blob_new == blob_old:
                continue
        elif norm_new == norm_old:
            continue  # only volatile fields changed — not drift
        findings.append({
            "key": f"drift.{slug}.{new_sha[:12]}", "severity": SEV_WARNING,
            "title": f"Config drift on {slug}",
            "product": _product_of(a),
            "detail": (f"{a.kind} '{slug}' changed in the source-of-truth "
                       f"(commit {new_sha[:8]}, {int(age_min)}m ago) after volatile "
                       f"fields were normalised out. If nobody edited it via "
                       f"SATOM, a device-side (CLI/GUI) change has drifted from "
                       f"the baseline — review the A→B diff under reports/{slug}.")})
    return findings


_CHECKS = [
    (K_CHK_CERT, _check_cert),
    (K_CHK_GIT, _check_git),
    (K_CHK_DEVICE, _check_devices),
    (K_CHK_BACKUP, _check_backup),
    (K_CHK_DRIFT, _check_drift),
    (K_CHK_ACTIONS, _check_actions),
]


def evaluate() -> list[dict]:
    """Run every enabled check and return the merged findings list (no dispatch,
    no cooldown) — used by the run loop AND by the Settings 'Preview' button."""
    findings: list[dict] = []
    for toggle_key, fn in _CHECKS:
        if not _flag(toggle_key):
            continue
        try:
            findings.extend(fn() or [])
        except Exception as exc:  # noqa: BLE001 — one bad check never sinks the run
            findings.append({"key": "engine.error", "severity": SEV_INFO,
                             "title": f"Alert check {fn.__name__} errored",
                             "detail": str(exc)})
    findings.sort(key=lambda f: _SEV_RANK.get(f.get("severity"), 0), reverse=True)
    return findings


# ---- dispatch -------------------------------------------------------------
def _admin_ids() -> list[int]:
    from ..models import User
    ids = []
    for u in User.query.all():
        try:
            # is_admin_capable is a @property (bool), not a method — no parens.
            if u.is_admin_capable:
                ids.append(u.id)
        except Exception:  # noqa: BLE001
            pass
    return ids


def _email_body(new_findings: list[dict]) -> tuple[str, str]:
    node = _node()
    lines = [f"SATOM alerts from {node} — {len(new_findings)} new:", ""]
    for f in new_findings:
        lines.append(f"[{f['severity'].upper()}] {f['title']}")
        lines.append(f"    {f['detail']}")
        lines.append("")
    text = "\n".join(lines)
    rows = "".join(
        f"<tr><td style='padding:4px 8px;font-weight:600'>{f['severity'].upper()}</td>"
        f"<td style='padding:4px 8px'><b>{f['title']}</b><br>"
        f"<span style='color:#555'>{f['detail']}</span></td></tr>"
        for f in new_findings)
    html = (f"<h3>SATOM alerts — {node}</h3>"
            f"<table style='border-collapse:collapse'>{rows}</table>")
    return text, html


def run(*, force: bool = False, dry_run: bool = False) -> dict:
    """Evaluate, apply cooldown, and dispatch new findings via email + in-app bell.

    ``force`` ignores the cooldown; ``dry_run`` evaluates and reports what WOULD
    fire without sending anything or touching state. Returns a summary dict."""
    findings = evaluate()
    if dry_run:
        return {"node": _node(), "evaluated": len(findings),
                "findings": findings, "dispatched": 0, "dry_run": True}

    # On a read-only standby, dispatch (in-app + cooldown state) can't be written
    # and email would spam without persistable cooldown. Evaluate + log only; the
    # writable primary owns dispatch. A promoted standby flips writable and starts.
    if _is_read_only_replica():
        return {"node": _node(), "evaluated": len(findings), "fresh": 0,
                "dispatched": 0, "email": None, "enabled": is_enabled(),
                "skipped": "read-only replica — dispatch is primary-only"}

    state = _load_state()
    cooldown_h = _int(K_COOLDOWN_H, 6)
    fresh = [f for f in findings
             if force or not _in_cooldown(state, f["key"], cooldown_h)]

    result = {"node": _node(), "evaluated": len(findings),
              "fresh": len(fresh), "dispatched": 0, "email": None,
              "enabled": is_enabled()}
    if not fresh:
        return result

    # In-app bell always fires (cheap, local). Email only when the engine is on.
    admin_ids = _admin_ids()
    for f in fresh:
        kind = (notify.Notification.KIND_ERROR
                if f["severity"] in (SEV_CRITICAL, SEV_WARNING)
                else notify.Notification.KIND_INFO)
        if admin_ids:
            # product=None means "stamp from the session", which is '' in this
            # worker thread. Device findings carry the device's ADOM instead.
            notify.push_many(admin_ids, f["title"], kind=kind,
                             body=f["detail"][:400],
                             product=f.get("product") or None)

    if is_enabled():
        to = recipients()
        if to:
            subject = (f"[SATOM/{_node()}] {len(fresh)} alert(s) — "
                       f"{fresh[0]['title']}")
            text, html = _email_body(fresh)
            result["email"] = email_service.send_email(to, subject, text, html=html)
        else:
            result["email"] = {"ok": False, "detail": "no recipients configured"}

    now_iso = _now().isoformat()
    for f in fresh:
        state[f["key"]] = now_iso
    _save_state(state)
    result["dispatched"] = len(fresh)
    return result


__all__ = ["evaluate", "run", "is_enabled", "recipients", "DEFAULTS"]
