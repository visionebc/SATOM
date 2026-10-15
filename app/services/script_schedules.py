"""Script Library -- who may run what, and saved runs on a cron schedule.

ACCESS
    A published script is offered to a user when its audience is
    ``operators`` and the user holds ``operations.scripts_run``, or when the user holds
    ``studio.script_library`` (administrators, any audience). Drafts are
    never offered here.

SAVED RUNS (``data/scripts/schedules/<id>.json``)
    A saved set of form values plus a cron expression, owned by the user who
    created it and PINNED to the published version it was created against:
    publishing a new version never changes what an existing schedule runs.
    The page offers "move to vN" instead (re-validated against the new form).

    Password field values of a saved run go to the vault
    (``<mount>/scripts-saved/<slug>/<id>``), never into the schedule file;
    each fire hands the runner a single-use wrapped copy, exactly like the
    script's own credentials. Without a vault a saved run cannot keep a
    password value.

    The scheduler sidecar (primary only) calls :func:`fire_due` every tick.
    A schedule whose owner was deactivated, lost ``operations.scripts_run`` or lost
    access to the script is PAUSED with the reason, never run on their behalf.
    A fire missed by more than five minutes (node down) is skipped, not
    replayed.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta

from . import script_library as SL
from . import scheduler

_ID_RE = re.compile(r"^[0-9a-f]{12}$")
MISSED_GRACE = timedelta(minutes=5)
MAX_PER_USER = 50


def _dir():
    # Follows SL.ROOT so tests (and FM_APP_DIR) move both together.
    return SL.ROOT / "schedules"


def _now():
    return datetime.utcnow()


def _tz() -> str:
    try:
        from . import settings_store
        return settings_store.tz_name()
    except Exception:  # noqa: BLE001
        return "UTC"


# ---------------------------------------------------------------------------
#  access
# ---------------------------------------------------------------------------
def can_run(user, meta: dict) -> bool:
    if user is None or not getattr(user, "is_authenticated", True):
        return False
    if not meta or not meta.get("published"):
        return False
    if user.can("studio.script_library"):
        return True
    return meta.get("audience") == "operators" and user.can("operations.scripts_run")


def visible_scripts(user) -> list[dict]:
    out = []
    for s in SL.list_scripts():
        meta = SL._read_json(SL._dir(s["slug"]) / "meta.json")
        if can_run(user, meta):
            v = SL.version(s["slug"], meta["published"]) or {}
            out.append({**s, "version": meta["published"],
                        "description": meta.get("description") or "",
                        "fields": v.get("fields") or [],
                        "network": v.get("network"), "timeout": v.get("timeout"),
                        "credentials": [c["name"] for c in v.get("credentials") or []]})
    return out


def runnable(user, slug: str) -> tuple[dict, dict]:
    """(meta, frozen published version) or ScriptError."""
    meta = SL._read_json(SL._dir(slug) / "meta.json")
    if not can_run(user, meta):
        raise SL.ScriptError("no published script %r is available to you" % slug)
    v = SL.version(slug, meta["published"])
    if v is None:
        raise SL.ScriptError("the published version of %r is missing" % slug)
    return meta, v


# ---------------------------------------------------------------------------
#  storage
# ---------------------------------------------------------------------------
def _path(sid: str):
    if not _ID_RE.match(sid or ""):
        raise SL.ScriptError("no such schedule")
    return _dir() / (sid + ".json")


def get(sid: str) -> dict | None:
    d = SL._read_json(_path(sid))
    return d or None


def _save(s: dict) -> dict:
    s["updated_at"] = SL._utcnow()
    SL._write_json(_path(s["id"]), s)
    return s


def all_schedules() -> list[dict]:
    d = _dir()
    if not d.is_dir():
        return []
    out = []
    for p in sorted(d.glob("*.json")):
        s = SL._read_json(p)
        if s.get("id") and _ID_RE.match(s["id"]):
            out.append(s)
    return out


def list_for(user, slug: str | None = None) -> list[dict]:
    """The user's own schedules; administrators see everyone's."""
    admin = user.can("studio.script_library")
    me = getattr(user, "username", "")
    return [s for s in all_schedules()
            if (admin or s.get("owner") == me) and (slug is None or s.get("slug") == slug)]


def may_manage(user, s: dict) -> bool:
    return bool(s) and (s.get("owner") == getattr(user, "username", None)
                        or user.can("studio.script_library"))


def validate_cron(expr: str) -> str:
    expr = " ".join((expr or "").split())
    try:
        if not scheduler.cron_preview(expr, 1):
            raise SL.ScriptError("that cron expression never fires")
    except scheduler.CronError as exc:
        raise SL.ScriptError("cron: %s" % exc)
    return expr


def _next(expr: str, now=None):
    return scheduler.compute_next_run("cron", {"expr": expr}, now or _now(), tz=_tz())


def _secret_path(slug: str, sid: str) -> str:
    return "scripts-saved/%s/%s" % (SL.validate_slug(slug), sid)


def _split(fields: list[dict], inputs: dict) -> tuple[dict, dict]:
    pw = {f["name"] for f in fields if f["type"] == "password"}
    plain = {k: v for k, v in inputs.items() if k not in pw}
    secret = {k: v for k, v in inputs.items() if k in pw and v}
    return plain, secret


def create(user, slug: str, *, name: str, cron: str, raw_inputs) -> dict:
    meta, v = runnable(user, slug)
    me = getattr(user, "username", "")
    if sum(1 for s in all_schedules() if s.get("owner") == me) >= MAX_PER_USER:
        raise SL.ScriptError("at most %d saved runs per user" % MAX_PER_USER)
    expr = validate_cron(cron)
    inputs = SL.resolve_inputs(v["fields"], raw_inputs)
    plain, secret = _split(v["fields"], inputs)
    sid = uuid.uuid4().hex[:12]
    if secret:
        from . import script_vault as SV
        if not SV.available():
            raise SL.ScriptError("a saved run cannot keep a password value without a "
                                 "vault (Settings > Vault)")
        from . import secret_backend as sb
        sb.write(_secret_path(slug, sid), secret)
    s = {"id": sid, "slug": slug, "version": int(meta["published"]),
         "name": (name or "").strip()[:120] or "%s schedule" % slug,
         "cron": expr, "owner": me, "inputs": plain,
         "secret_fields": sorted(secret), "enabled": True, "paused_reason": "",
         "created_at": SL._utcnow(), "next_run": _iso(_next(expr)),
         "last_run": None, "last_request_id": None, "last_status": ""}
    return _save(s)


def _iso(dt):
    return dt.isoformat() if dt else None


def set_enabled(s: dict, enabled: bool) -> dict:
    s["enabled"] = bool(enabled)
    if enabled:
        s["paused_reason"] = ""
        s["next_run"] = _iso(_next(s["cron"]))
    return _save(s)


def delete(s: dict) -> None:
    if s.get("secret_fields"):
        try:
            from . import secret_backend as sb
            sb.delete(_secret_path(s["slug"], s["id"]))
        except Exception:  # noqa: BLE001
            pass
    try:
        _path(s["id"]).unlink()
    except OSError:
        pass


def move_to_published(user, s: dict) -> dict:
    """Re-pin a schedule to the current published version, re-validating its
    saved values against THAT version's form."""
    meta, v = runnable(user, s["slug"])
    fields = v["fields"]
    names = {f["name"] for f in fields}
    pw_now = {f["name"] for f in fields if f["type"] == "password"}
    keep_secret = [n for n in s.get("secret_fields") or [] if n in pw_now]
    trial = dict(s.get("inputs") or {})
    relaxed = [dict(f, required=False) if f["name"] in keep_secret else f for f in fields]
    try:
        inputs = SL.resolve_inputs(relaxed, {k: v_ for k, v_ in trial.items() if k in names})
    except SL.ScriptError as exc:
        raise SL.ScriptError("v%s needs different values (%s): delete this saved run "
                             "and create it again" % (meta["published"], exc))
    s["inputs"], _ = _split(fields, {k: v_ for k, v_ in inputs.items() if k not in keep_secret})
    s["secret_fields"] = keep_secret
    s["version"] = int(meta["published"])
    return _save(s)


# ---------------------------------------------------------------------------
#  firing (scheduler sidecar)
# ---------------------------------------------------------------------------
def _owner(username: str):
    from ..models import User
    return User.query.filter_by(username=username).first()


def _pause(s: dict, why: str) -> dict:
    s["enabled"] = False
    s["paused_reason"] = why
    s["last_status"] = "paused"
    return _save(s)


def fire(s: dict, now=None) -> dict:
    """Queue one run of a saved schedule. Returns the updated schedule."""
    now = now or _now()
    s["next_run"] = _iso(_next(s["cron"], now))
    user = _owner(s.get("owner") or "")
    if user is None or not user.is_active:
        return _pause(s, "owner %s is no longer active" % s.get("owner"))
    meta = SL._read_json(SL._dir(s["slug"]) / "meta.json")
    if not can_run(user, meta):
        return _pause(s, "owner %s can no longer run this script" % s.get("owner"))
    from . import script_vault as SV
    sealed = None
    if s.get("secret_fields"):
        sealed = {"fields": list(s["secret_fields"]),
                  "wrap": lambda: SV.wrap_path(_secret_path(s["slug"], s["id"]))}
    try:
        st = SL.enqueue_run(s["slug"], version_ref=int(s["version"]),
                            raw_inputs=dict(s.get("inputs") or {}),
                            by=s.get("owner") or "?", trigger="schedule",
                            wrap=SV.wrap_for_run, sealed=sealed)
    except SL.ScriptError as exc:
        s["last_status"] = "not queued: %s" % str(exc)[:200]
        s["last_run"] = _iso(now)
        return _save(s)
    s.update({"last_run": _iso(now), "last_request_id": st["request_id"],
              "last_status": "queued"})
    return _save(s)


def fire_due(now=None) -> list[str]:
    """Called by the scheduler tick (primary only). Returns fired ids."""
    now = now or _now()
    fired = []
    for s in all_schedules():
        if not s.get("enabled") or not s.get("next_run"):
            continue
        try:
            due = datetime.fromisoformat(s["next_run"])
        except (TypeError, ValueError):
            continue
        if due > now:
            continue
        if now - due > MISSED_GRACE:
            s["next_run"] = _iso(_next(s["cron"], now))
            s["last_status"] = "missed (node was not running the scheduler)"
            _save(s)
            continue
        fire(s, now)
        fired.append(s["id"])
    return fired
