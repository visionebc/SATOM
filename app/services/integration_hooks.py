"""Integration Hooks — the app-side half. It ENQUEUES; it never executes.

The operator wants to run their OWN small Python against SATOM events: on
``change.requested``, POST to their CRM and hand back a CRQ ticket id. Running
that code inside the gunicorn worker of a product that administers production
WAFs is remote-code-execution-as-a-feature — the worker holds the DB session,
the Fernet key and every appliance credential. So it never runs there.

The pattern is the house precedent (``self_update`` + ``satom-updater.path``):
the unprivileged web worker drops a JSON request into a watched directory, a
SEPARATE systemd oneshot picks it up and does the work, and progress comes back
as a status JSON the UI polls. Same shape here, one deliberate inversion — the
updater's runner is privileged because it installs files; the integrations
runner is *de*-privileged (``User=satom``) because it runs somebody else's code.

This module is import-side-effect-free and stdlib-only at module scope: the
runner imports it without dragging in Flask, and every DB touch (audit rows,
the secret vault) is a lazy import inside a function guarded by try/except.

WHAT LIVES WHERE
    data/integrations/<slug>/hook.py             the author's source
    data/integrations/<slug>/meta.json           name/event/enabled/timeout/secrets
    data/integrations/<slug>/versions/<ts>.py    every previous source
    data/integration-requests/<request_id>.json  the queue the runner drains
    data/integration-status/<request_id>.json    what the UI polls
"""
from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

# NOTE: `subprocess` is deliberately absent from this module, and
# tests/test_integration_hooks.py asserts that the name never appears in this
# file. The web worker's half of the feature must have no way to spawn.

APP_DIR = Path(os.environ.get("FM_APP_DIR", "/opt/satom"))
# ONE parent for the whole queue. These four directories must share a
# single parent because the runner claims a request with os.replace(), and
# the systemd unit makes each ReadWritePaths= its own bind-mount: a rename
# across two of them is EXDEV (errno 18, proven on this node), which
# process_request_file cannot tell apart from "already claimed" - the
# request is then never run and the .path unit re-fires forever.
INTEGRATIONS_ROOT = APP_DIR / "data" / "integrations"
HOOKS_DIR = INTEGRATIONS_ROOT / "hooks"
REQ_DIR = INTEGRATIONS_ROOT / "queue"
STATUS_DIR = INTEGRATIONS_ROOT / "status"

# ---- caps (documented; the runner enforces the runtime ones) ---------------
MAX_SOURCE_BYTES = 128 * 1024   # a hook is glue, not an application
STDOUT_CAP = 8_000              # chars kept in the status file (the UI renders it)
DEFAULT_TIMEOUT = 30            # seconds
MIN_TIMEOUT = 1
MAX_TIMEOUT = 120               # hard ceiling — save_hook clamps, runner re-clamps
MAX_SECRETS = 8
MAX_VERSIONS = 20               # version history is pruned oldest-first
MIN_SECRET_LEN = 4              # below this a value cannot be redacted safely

STATUSES = ("queued", "running", "ok", "failed", "timeout")

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,47}$")
_SECRET_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")

# The secret vault: one encrypted AppSetting row per credential name. Same
# storage contract as certmgr's domain password — Fernet at rest, never git,
# never returned to the browser.
K_SECRET_PREFIX = "integrations.secret."


# ---------------------------------------------------------------------------
#  The published event catalog
# ---------------------------------------------------------------------------
# This is the CONTRACT. A hook binds to exactly one event name and receives the
# payload shape documented here as ``ctx.payload``. Adding a field is
# backward-compatible; renaming or removing one is a breaking change and needs a
# new event name. Every payload is plain JSON — no ORM objects ever cross the
# queue, because the runner has no business holding a live model instance.
EVENTS: dict[str, dict[str, Any]] = {
    "change.requested": {
        "description": "A Change Request was submitted for approval.",
        "payload": {
            "cr_id": "int — ChangeRequest.id",
            "title": "str",
            "status": "str — the CR lifecycle state at emit time ('draft')",
            "action": "str — the action the CR will run, e.g. 'upgrade'",
            "risk": "str — low | medium | high",
            "reason": "str — free text the requester typed",
            "device_ids": "list[int] — Appliance ids in scope",
            "policies": "list[str] — affected server-policy names (may be empty)",
            "window_start": "str|null — ISO-8601 UTC",
            "window_end": "str|null — ISO-8601 UTC",
            "requested_by": "str — username",
        },
        "example": {
            "cr_id": 412, "title": "FortiWeb fleet 7.6.2", "status": "draft",
            "action": "upgrade", "risk": "high", "reason": "CVE-2026-1234",
            "device_ids": [3, 7], "policies": ["pol-shop", "pol-api"],
            "window_start": "2026-08-15T22:00:00Z",
            "window_end": "2026-08-16T02:00:00Z", "requested_by": "alice",
        },
    },
    "change.approved": {
        "description": "A Change Request passed its approval gate.",
        "payload": {
            "cr_id": "int", "title": "str", "action": "str", "risk": "str",
            "device_ids": "list[int]", "policies": "list[str]",
            "window_start": "str|null — ISO-8601 UTC",
            "window_end": "str|null — ISO-8601 UTC",
            "requested_by": "str", "approved_by": "str",
            "approved_at": "str — ISO-8601 UTC",
        },
        "example": {
            "cr_id": 412, "title": "FortiWeb fleet 7.6.2", "action": "upgrade",
            "risk": "high", "device_ids": [3, 7], "policies": ["pol-shop"],
            "window_start": "2026-08-15T22:00:00Z",
            "window_end": "2026-08-16T02:00:00Z",
            "requested_by": "alice", "approved_by": "bob",
            "approved_at": "2026-08-12T09:14:03Z",
        },
    },
    "window.opening": {
        "description": "The maintenance window of a scheduled CR just opened; "
                       "the bound action is about to run.",
        "payload": {
            "cr_id": "int", "title": "str", "action": "str",
            "device_ids": "list[int]", "policies": "list[str]",
            "window_start": "str — ISO-8601 UTC",
            "window_end": "str|null — ISO-8601 UTC",
        },
        "example": {
            "cr_id": 412, "title": "FortiWeb fleet 7.6.2", "action": "upgrade",
            "device_ids": [3, 7], "policies": ["pol-shop"],
            "window_start": "2026-08-15T22:00:00Z",
            "window_end": "2026-08-16T02:00:00Z",
        },
    },
    "window.closing": {
        "description": "The maintenance window ended (or the CR reached a "
                       "terminal state inside it).",
        "payload": {
            "cr_id": "int", "title": "str",
            "outcome": "str — completed | failed | cancelled | in_progress",
            "device_ids": "list[int]",
            "window_start": "str — ISO-8601 UTC",
            "window_end": "str|null — ISO-8601 UTC",
            "result_summary": "str — the CR's own summary text",
        },
        "example": {
            "cr_id": 412, "title": "FortiWeb fleet 7.6.2", "outcome": "completed",
            "device_ids": [3, 7], "window_start": "2026-08-15T22:00:00Z",
            "window_end": "2026-08-16T02:00:00Z",
            "result_summary": "2/2 devices upgraded, health OK",
        },
    },
    "upgrade.finished": {
        "description": "A firmware upgrade completed and passed post-flight.",
        "payload": {
            "appliance_id": "int", "appliance": "str — device name",
            "kind": "str — fortiweb | fortiadc | ...",
            "from_version": "str",
            # OPTIONAL: only the firmware executor watched the box come
            # back, so only it can fill these. A change request closing
            # omits them rather than sending null - null is a measurement
            # nobody took.
            "to_version": "str (optional)",
            "image": "str — image filename", "dry_run": "bool",
            "cr_id": "int|null — the CR that authorised it",
            "duration_ms": "int (optional)",
        },
        "example": {
            "appliance_id": 3, "appliance": "fw-dmz-01", "kind": "fortiweb",
            "from_version": "7.6.1", "to_version": "7.6.2",
            "image": "FWB_VM64-v760-build0412.out", "dry_run": False,
            "cr_id": 412, "duration_ms": 481_233,
        },
    },
    "upgrade.failed": {
        "description": "A firmware upgrade aborted, failed post-flight, or the "
                       "device did not come back.",
        "payload": {
            "appliance_id": "int", "appliance": "str", "kind": "str",
            "from_version": "str", "image": "str",
            "stage": "str — prepare | push | recovery | postflight",
            "error": "str — operator-facing message",
            "cr_id": "int|null", "duration_ms": "int (optional)",
        },
        "example": {
            "appliance_id": 7, "appliance": "fw-dmz-02", "kind": "fortiweb",
            "from_version": "7.6.1", "image": "FWB_VM64-v760-build0412.out",
            "stage": "recovery", "error": "device did not answer after 900s",
            "cr_id": 412, "duration_ms": 912_004,
        },
    },
}

EVENT_NAMES: tuple[str, ...] = tuple(EVENTS)


def event_catalog() -> list[dict[str, Any]]:
    """Render-ready event list for the hook editor's picker + docs panel."""
    return [{"event": name, "description": spec["description"],
             "payload": spec["payload"], "example": spec["example"]}
            for name, spec in EVENTS.items()]


# ---------------------------------------------------------------------------
#  Atomic writes — the ONE rule every producer in this feature obeys
# ---------------------------------------------------------------------------
def _atomic_write(path: Path, text: str, mode: int = 0o640) -> None:
    """Write ``text`` to ``path`` so no reader ever observes a partial file.

    The temp name is BOTH dot-prefixed and ``.tmp``-suffixed: the runner globs
    ``*.json``, so a half-written request is invisible to it even before the
    ``os.replace`` makes the swap atomic. Never ``open(path, 'w')`` directly —
    a request file caught mid-write is a hook that runs against a truncated
    payload, and this queue is watched by a systemd ``.path`` unit that fires on
    directory change, i.e. exactly at the wrong moment.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / ("." + path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    try:
        os.chmod(tmp, mode)
    except OSError:
        pass
    os.replace(tmp, path)


def _atomic_write_json(path: Path, obj: Any, mode: int = 0o640) -> None:
    _atomic_write(path, json.dumps(obj, indent=2, sort_keys=True, default=str), mode)


def _utcnow() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _audit(action: str, target: str, extra: dict[str, Any]) -> None:
    """Best-effort audit row. Swallows everything, including the app-context
    RuntimeError you get when this is called from a CLI or a test — audit must
    never be the reason a hook save fails."""
    try:
        from .audit import log_action
        log_action(action, target=target, extra=extra)
    except Exception:  # noqa: BLE001 — audit is best-effort, never fatal
        pass


# ---------------------------------------------------------------------------
#  Validation
# ---------------------------------------------------------------------------
def validate_slug(slug: str) -> str:
    """Lowercase ``[a-z0-9_-]``, 2-48 chars. The slug becomes a DIRECTORY name,
    so the charset is the security boundary against ``../`` and absolute paths;
    a regex allow-list beats any amount of normalising."""
    slug = (slug or "").strip().lower()
    if not _SLUG_RE.match(slug):
        raise ValueError(
            "slug must be 2-48 chars of a-z, 0-9, '-' or '_' and start "
            "alphanumeric (got %r)" % (slug,))
    return slug


def validate_source(source: str) -> str:
    """Compile the hook source and RAISE on a syntax error.

    This runs at SAVE time, in the web worker, so the author sees
    ``SyntaxError: line 12`` in the editor instead of discovering it three weeks
    later when a real change request fires at 22:00 inside a maintenance window.
    ``compile()`` parses and byte-compiles — it does NOT execute — so it is safe
    in the worker in a way ``exec`` never is.
    """
    if source is None:
        raise ValueError("hook source is empty")
    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError("hook source exceeds %d bytes" % MAX_SOURCE_BYTES)
    if not source.strip():
        raise ValueError("hook source is empty")
    try:
        compile(source, "<hook>", "exec")
    except SyntaxError as exc:
        raise ValueError("syntax error on line %s: %s" % (exc.lineno, exc.msg)) from exc
    except ValueError as exc:  # e.g. source with NUL bytes
        raise ValueError("invalid hook source: %s" % exc) from exc
    return source


def validate_secret_name(name: str) -> str:
    name = (name or "").strip().upper()
    if not _SECRET_RE.match(name):
        raise ValueError(
            "secret name must be UPPER_SNAKE, start with a letter, "
            "max 64 chars (got %r)" % (name,))
    return name


def clamp_timeout(value: Any) -> int:
    try:
        secs = int(value)
    except (TypeError, ValueError):
        secs = DEFAULT_TIMEOUT
    return max(MIN_TIMEOUT, min(MAX_TIMEOUT, secs))


def _clean_meta(slug: str, meta: dict[str, Any] | None,
                by: str, previous: dict[str, Any] | None) -> dict[str, Any]:
    meta = dict(meta or {})
    event = str(meta.get("event") or "").strip()
    if event not in EVENTS:
        raise ValueError(
            "unknown event %r — must be one of: %s" % (event, ", ".join(EVENT_NAMES)))
    secrets: list[str] = []
    for raw in (meta.get("secrets") or []):
        name = validate_secret_name(str(raw))
        if name not in secrets:
            secrets.append(name)
    if len(secrets) > MAX_SECRETS:
        raise ValueError("a hook may declare at most %d secrets" % MAX_SECRETS)
    prev = previous or {}
    return {
        "slug": slug,
        "name": (str(meta.get("name") or "").strip() or slug)[:120],
        "event": event,
        "enabled": bool(meta.get("enabled", True)),
        "timeout": clamp_timeout(meta.get("timeout", DEFAULT_TIMEOUT)),
        "secrets": secrets,
        "created_by": prev.get("created_by") or by or "system",
        "created_at": prev.get("created_at") or _utcnow(),
        "updated_by": by or "system",
        "updated_at": _utcnow(),
    }


# ---------------------------------------------------------------------------
#  CRUD
# ---------------------------------------------------------------------------
def _hook_dir(slug: str) -> Path:
    return HOOKS_DIR / slug


def _read_meta(slug: str) -> dict[str, Any] | None:
    try:
        data = json.loads((_hook_dir(slug) / "meta.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    data.setdefault("slug", slug)
    return data


def list_hooks() -> list[dict[str, Any]]:
    """Every hook's metadata (no source), slug-sorted. A directory whose
    ``meta.json`` is missing or corrupt is SKIPPED rather than raising — one bad
    hook must not blank the whole Integrations page."""
    if not HOOKS_DIR.exists():
        return []
    out: list[dict[str, Any]] = []
    for d in sorted(p for p in HOOKS_DIR.iterdir() if p.is_dir()):
        if not _SLUG_RE.match(d.name):
            continue
        meta = _read_meta(d.name)
        if meta is None:
            continue
        meta["has_source"] = (d / "hook.py").is_file()
        out.append(meta)
    return out


def hooks_for_event(event: str) -> list[dict[str, Any]]:
    """Enabled hooks bound to ``event`` that actually have a source on disk."""
    return [h for h in list_hooks()
            if h.get("event") == event and h.get("enabled") and h.get("has_source")]


def get_hook(slug: str) -> dict[str, Any] | None:
    """``{slug, meta, source, versions}`` or ``None``. ``versions`` is a list of
    ``{ts, bytes}`` newest first."""
    try:
        slug = validate_slug(slug)
    except ValueError:
        return None
    meta = _read_meta(slug)
    if meta is None:
        return None
    src_path = _hook_dir(slug) / "hook.py"
    try:
        source = src_path.read_text(encoding="utf-8")
    except OSError:
        source = ""
    versions = []
    vdir = _hook_dir(slug) / "versions"
    if vdir.is_dir():
        for p in sorted(vdir.glob("*.py"), reverse=True):
            try:
                versions.append({"ts": p.stem, "bytes": p.stat().st_size})
            except OSError:
                pass
    return {"slug": slug, "meta": meta, "source": source, "versions": versions}


def save_hook(slug: str, source: str, meta: dict[str, Any] | None,
              by: str = "system") -> dict[str, Any]:
    """Create or update a hook. Returns the same shape as :func:`get_hook`.

    Validation order is load-bearing: slug, then SOURCE COMPILE, then meta —
    all before a single byte is written. A hook that does not parse never
    reaches the disk, so it can never reach the queue, so the runner never has
    to have an opinion about broken Python.
    """
    slug = validate_slug(slug)
    source = validate_source(source)
    previous = _read_meta(slug)
    clean = _clean_meta(slug, meta, by, previous)

    d = _hook_dir(slug)
    vdir = d / "versions"
    vdir.mkdir(parents=True, exist_ok=True)

    src_path = d / "hook.py"
    if src_path.is_file():
        # Snapshot the OUTGOING source before overwriting. Version history is
        # the only undo an operator has at 22:00 on a Friday, so the stamp
        # carries MICROSECONDS: with second resolution, two saves in the same
        # second sort by whatever tie-breaker follows and the "previous
        # version" an operator restores is not the one they clicked.
        try:
            _atomic_write(_version_path(vdir), src_path.read_text(encoding="utf-8"))
        except OSError:
            pass
        _prune_versions(vdir)

    _atomic_write(src_path, source)
    _atomic_write_json(d / "meta.json", clean)
    _audit("integration.hook.save", target=slug,
           extra={"event": clean["event"], "enabled": clean["enabled"],
                  "timeout": clean["timeout"], "secrets": clean["secrets"],
                  "bytes": len(source.encode("utf-8")),
                  "created": previous is None})
    return get_hook(slug)  # type: ignore[return-value]


def _version_path(vdir: Path) -> Path:
    """A version filename that sorts lexicographically == chronologically."""
    base = datetime.utcnow().strftime("%Y%m%d-%H%M%S.%f")
    path = vdir / (base + ".py")
    n = 0
    while path.exists() and n < 100:   # same microsecond: keep append order
        n += 1
        path = vdir / ("%s-%02d.py" % (base, n))
    return path


def _prune_versions(vdir: Path) -> None:
    try:
        files = sorted(vdir.glob("*.py"))
    except OSError:
        return
    for old in files[:-MAX_VERSIONS] if len(files) > MAX_VERSIONS else []:
        try:
            old.unlink()
        except OSError:
            pass


def delete_hook(slug: str, by: str = "system") -> bool:
    """Remove a hook and its history. In-flight requests already on the queue
    still carry their own copy of the source path — the runner skips a request
    whose hook has vanished and records it as ``failed``."""
    slug = validate_slug(slug)
    d = _hook_dir(slug)
    if not d.is_dir():
        return False
    import shutil  # local: only the delete path needs it
    shutil.rmtree(d, ignore_errors=True)
    _audit("integration.hook.delete", target=slug, extra={})
    return not d.exists()


def set_enabled(slug: str, enabled: bool, by: str = "system") -> dict[str, Any] | None:
    """Flip the kill switch without touching the source. This is the button an
    operator hits when someone's CRM is down and every dispatch is timing out."""
    hook = get_hook(slug)
    if hook is None:
        return None
    meta = dict(hook["meta"])
    meta["enabled"] = bool(enabled)
    return save_hook(slug, hook["source"], meta, by=by)


# ---------------------------------------------------------------------------
#  The secret vault (declared by name in meta.json, injected by the runner)
# ---------------------------------------------------------------------------
def list_secret_names() -> list[str]:
    """Names only — a value never leaves this module except via
    :func:`secret_value`, which only the runner calls."""
    try:
        from ..models import AppSetting
        rows = AppSetting.query.filter(
            AppSetting.key.like(K_SECRET_PREFIX + "%")).all()
        return sorted(r.key[len(K_SECRET_PREFIX):] for r in rows)
    except Exception:  # noqa: BLE001 — no DB (runner/CLI/tests) → env fallback
        prefix = "SATOM_HOOK_SECRET_"
        return sorted(k[len(prefix):] for k in os.environ if k.startswith(prefix))


def set_secret(name: str, value: str, by: str = "system") -> str:
    """Store a credential Fernet-encrypted in ``app_settings``.

    Values shorter than :data:`MIN_SECRET_LEN` are REFUSED: the runner redacts
    a secret from captured output by literal substring replacement, and a
    2-character secret would either redact half the log or not be redactable at
    all. Refusing at the door beats leaking at the exit.
    """
    name = validate_secret_name(name)
    value = str(value or "")
    if len(value) < MIN_SECRET_LEN:
        raise ValueError(
            "secret value must be at least %d characters (shorter values "
            "cannot be redacted from hook output)" % MIN_SECRET_LEN)
    from .encryption import encrypt
    from ..models import AppSetting
    AppSetting.set(K_SECRET_PREFIX + name, encrypt(value))
    _audit("integration.secret.set", target=name, extra={})
    return name


def delete_secret(name: str, by: str = "system") -> bool:
    name = validate_secret_name(name)
    try:
        from ..models import AppSetting, db
        row = AppSetting.query.get(K_SECRET_PREFIX + name)
        if row is None:
            return False
        db.session.delete(row)
        db.session.commit()
    except Exception:  # noqa: BLE001
        return False
    _audit("integration.secret.delete", target=name, extra={})
    return True


def secret_value(name: str) -> str | None:
    """Decrypt one credential. RUNNER-SIDE ONLY — never call this from a view;
    the web worker has no business materialising a plaintext token it is not
    going to use. Falls back to ``SATOM_HOOK_SECRET_<NAME>`` in the process
    environment so a node can be driven without the DB (and so the tests can run
    without one)."""
    try:
        name = validate_secret_name(name)
    except ValueError:
        return None
    try:
        from ..models import AppSetting
        from .encryption import decrypt
        raw = AppSetting.get(K_SECRET_PREFIX + name)
        if raw:
            return decrypt(raw)
    except Exception:  # noqa: BLE001 — no app context / no DB / bad key
        pass
    return os.environ.get("SATOM_HOOK_SECRET_" + name)


# ---------------------------------------------------------------------------
#  Dispatch — writes files, spawns nothing
# ---------------------------------------------------------------------------
def _new_request_id(slug: str) -> str:
    return "%s-%s-%s" % (datetime.utcnow().strftime("%Y%m%d-%H%M%S"),
                         slug[:24], uuid.uuid4().hex[:6])


def dispatch(event: str, payload: dict[str, Any], *, by: str = "system",
             dry_run: bool = False) -> list[dict[str, Any]]:
    """Enqueue one request per enabled hook bound to ``event``.

    Returns ``[{slug, request_id, status}, ...]`` — one row per hook, in slug
    order. ``status`` is ``queued`` (or ``dry-run``). It is NEVER ``ok``,
    because nothing has run: this function does not execute, import, exec,
    fork or spawn. It writes JSON. The systemd ``.path`` unit watching
    ``data/integration-requests/`` is what turns a file into a process, in a
    different unit, as a different, unprivileged concern.

    ``dry_run=True`` resolves the hook list and returns it WITHOUT writing
    anything, so the UI can answer "who would this fire?" for free.

    Unknown event names raise ``ValueError`` — a typo'd emit site must fail
    loudly at the caller, not silently dispatch to nobody.
    """
    if event not in EVENTS:
        raise ValueError(
            "unknown event %r — must be one of: %s" % (event, ", ".join(EVENT_NAMES)))
    if payload is not None and not isinstance(payload, dict):
        raise ValueError("payload must be a dict")

    now = _utcnow()
    node = os.environ.get("FM_NODE_NAME") or ""
    out: list[dict[str, Any]] = []

    for hook in hooks_for_event(event):
        slug = hook["slug"]
        if dry_run:
            out.append({"slug": slug, "request_id": "", "status": "dry-run"})
            continue

        rid = _new_request_id(slug)
        # Status FIRST, request SECOND. The runner may pick a request up the
        # instant it lands; if the status file were written after, there would
        # be a window where the UI polls a request id that has no status and
        # renders "unknown" for a job that is already running.
        _atomic_write_json(STATUS_DIR / (rid + ".json"), {
            "request_id": rid, "slug": slug, "event": event,
            "status": "queued", "queued_at": now, "requested_by": by,
            "started_at": None, "finished_at": None, "duration_ms": None,
            "exit_code": None, "stdout": "", "data": None, "error": "",
            "node": node,
        })
        _atomic_write_json(REQ_DIR / (rid + ".json"), {
            "request_id": rid, "slug": slug, "event": event,
            "payload": payload or {}, "requested_by": by, "queued_at": now,
            "timeout": clamp_timeout(hook.get("timeout")),
            "secrets": list(hook.get("secrets") or []),
            "node": node,
        })
        out.append({"slug": slug, "request_id": rid, "status": "queued"})

    if out and not dry_run:
        _audit("integration.dispatch", target=event,
               extra={"hooks": [r["slug"] for r in out], "count": len(out)})
    return out


# ---------------------------------------------------------------------------
#  Reading results
# ---------------------------------------------------------------------------
def result(request_id: str) -> dict[str, Any] | None:
    """The status JSON for one request, or ``None``.

    Shape: ``{request_id, slug, event, status, queued_at, started_at,
    finished_at, duration_ms, exit_code, stdout (TRUNCATED to STDOUT_CAP),
    data, error, node}``. ``status`` is one of :data:`STATUSES`.
    """
    rid = (request_id or "").strip()
    # The id lands in a path; keep it to the charset dispatch generates.
    if not rid or not re.match(r"^[A-Za-z0-9._-]{1,120}$", rid) or "/" in rid:
        return None
    p = STATUS_DIR / (rid + ".json")
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def recent(limit: int = 25) -> list[dict[str, Any]]:
    """Newest-first status rows for the Integrations activity panel."""
    if not STATUS_DIR.exists():
        return []
    try:
        files = sorted(STATUS_DIR.glob("*.json"),
                       key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        return []
    out: list[dict[str, Any]] = []
    for p in files[:max(0, int(limit or 0))]:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            out.append(data)
    return out


def dispatch_one(slug: str, *, sample: bool = True, payload: dict | None = None,
                 by: str = "system") -> dict[str, Any]:
    """Enqueue ONE named hook — the editor's "dry run" button.

    Deliberately different from :func:`dispatch` in exactly one way: it will
    queue a hook that is **disabled**. Testing a hook before turning it on is
    the whole point of the button, and a dry run that silently did nothing for
    a disabled hook would be indistinguishable from a broken runner. The
    enabled check stays where it belongs - on the EVENT path, which is the one
    that fires without a human deciding to.

    Everything else is the production path: same request file, same runner,
    same timeout and secret rules. A dry run that took a different execution
    path would be testing something other than what production does.

    ``sample=True`` sends the event's documented example payload, so the hook
    sees the real key set rather than an empty dict.
    """
    slug = validate_slug(slug)
    hook = _read_meta(slug)
    if hook is None:
        raise ValueError(f"no such hook: {slug}")
    if not (_hook_dir(slug) / "hook.py").is_file():
        raise ValueError(f"hook {slug} has no source to run")
    event = hook.get("event") or ""
    if event not in EVENTS:
        raise ValueError(f"hook {slug} is bound to unknown event {event!r}")

    body = payload if payload is not None else (
        dict(EVENTS[event].get("example") or {}) if sample else {})
    now = _utcnow()
    node = os.environ.get("FM_NODE_NAME") or ""
    rid = _new_request_id(slug)
    # Status first, request second - same ordering rule as dispatch().
    _atomic_write_json(STATUS_DIR / (rid + ".json"), {
        "request_id": rid, "slug": slug, "event": event,
        "status": "queued", "queued_at": now, "requested_by": by,
        "started_at": None, "finished_at": None, "duration_ms": None,
        "exit_code": None, "stdout": "", "data": None, "error": "",
        "node": node, "manual": True,
    })
    _atomic_write_json(REQ_DIR / (rid + ".json"), {
        "request_id": rid, "slug": slug, "event": event,
        "payload": body, "requested_by": by, "queued_at": now,
        "timeout": clamp_timeout(hook.get("timeout")),
        "secrets": list(hook.get("secrets") or []),
        "node": node, "manual": True,
    })
    _audit("integration.dry_run", target=slug, extra={"event": event})
    return {"slug": slug, "request_id": rid, "status": "queued", "event": event}
