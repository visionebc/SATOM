"""Integration Hooks — the half that actually runs user Python.

Imported by ``satom-integrations.service``, the systemd oneshot that
``satom-integrations.path`` fires whenever ``data/integration-requests/``
becomes non-empty. Structurally this is ``satom-updater.{path,service}``; the
one deliberate inversion is privilege. The updater's runner is ROOT because it
installs files and restarts units. This runner executes code an operator typed
into a textarea, so it runs as ``satom`` and is hardened *further* than the web
app, not less.

WHAT THE CHILD GETS
    argv        venv/bin/python -E -s -B hook.py
    cwd         a fresh temp dir holding exactly hook.py + satom_sdk.py
    sys.path    that temp dir, the stdlib, the venv's site-packages.
                NOT /opt/satom — ``import app.models`` raises ImportError, so a
                hook cannot reach the ORM, the Fernet key or device credentials.
    env         built from scratch (never ``os.environ``), plus exactly the
                secrets the hook DECLARED in meta.json. FERNET_KEY,
                SQLALCHEMY_DATABASE_URI and every other credential this process
                holds are simply not there to be read.
    fd          one inherited descriptor for the result line.

AND HOW IT ENDS
    A timeout kills the process GROUP (``start_new_session=True`` +
    ``os.killpg``), not just the child. A hook that shells out to ``curl`` would
    otherwise leave the grandchild running long after the hook it belongs to was
    declared dead — the classic "the timeout fired and the load kept climbing".
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .integration_hooks import (APP_DIR, EVENTS, HOOKS_DIR, MIN_SECRET_LEN,
                                REQ_DIR, STATUS_DIR, STDOUT_CAP, clamp_timeout,
                                secret_value, validate_slug)

# Claimed requests are moved OUT of the watched directory before they run.
# It must not be a subdirectory of REQ_DIR: ``DirectoryNotEmpty=`` is level
# triggered, so a leftover child there would re-fire this unit forever.
# Sibling of REQ_DIR under INTEGRATIONS_ROOT - see the EXDEV note there.
CLAIM_DIR = APP_DIR / "data" / "integrations" / "claimed"

PYTHON = APP_DIR / "venv" / "bin" / "python"
SDK_SRC = Path(__file__).resolve().parent / "integration_sdk.py"

MAX_DRAIN = 50          # requests per invocation; the .path unit re-fires
KILL_GRACE = 3.0        # seconds between SIGTERM and SIGKILL of the group
REAP_TIMEOUT = 5.0      # seconds to drain pipes after killing the group
STALE_CLAIM_AFTER = 15 * 60  # a claim older than this = the runner died


# ---------------------------------------------------------------------------
#  small helpers
# ---------------------------------------------------------------------------
def _utcnow() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _atomic_write_json(path: Path, obj: Any) -> None:
    """Same temp+replace rule as the enqueue side. A status file is polled by
    the UI while it is being rewritten; a reader must see the old state or the
    new one, never half of either."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / ("." + path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, indent=2, sort_keys=True, default=str))
        fh.flush()
        os.fsync(fh.fileno())
    try:
        os.chmod(tmp, 0o640)
    except OSError:
        pass
    os.replace(tmp, path)


def _read_status(request_id: str) -> dict[str, Any]:
    p = STATUS_DIR / (request_id + ".json")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def write_status(request_id: str, **fields: Any) -> dict[str, Any]:
    """Merge ``fields`` into the request's status file, atomically."""
    status = _read_status(request_id)
    status["request_id"] = request_id
    status.update(fields)
    _atomic_write_json(STATUS_DIR / (request_id + ".json"), status)
    return status


def redact(text: str, secrets: dict[str, str]) -> str:
    """Replace every declared secret VALUE with a marker naming it.

    Runs BEFORE truncation, deliberately: truncating first can cut a token in
    half and leave the first 40 characters of it permanently visible in a status
    file the web UI renders. Longest values first so a secret that contains
    another is not partially unmasked.
    """
    if not text:
        return text or ""
    for name, value in sorted(secrets.items(), key=lambda kv: -len(kv[1] or "")):
        if not value or len(value) < MIN_SECRET_LEN:
            continue
        if value in text:
            text = text.replace(value, "***REDACTED:%s***" % name)
    return text


def truncate(text: str, cap: int = STDOUT_CAP) -> str:
    """Cap captured output. The returned string never exceeds ``cap`` chars,
    marker included — the cap is on what we store, not on what we meant to."""
    text = text or ""
    if len(text) <= cap:
        return text
    marker = "\n… [truncated, %d chars dropped]" % (len(text) - cap)
    keep = max(0, cap - len(marker))
    return text[:keep] + marker


def _redact_obj(obj: Any, secrets: dict[str, str]) -> Any:
    """Redact secrets inside the structured result too. A hook that echoes its
    own auth header into ``data`` must not leak it via the JSON the UI renders,
    same as it must not leak it via stdout."""
    if obj is None:
        return None
    try:
        return json.loads(redact(json.dumps(obj, default=str), secrets))
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
#  secrets
# ---------------------------------------------------------------------------
def resolve_secrets(names: list[str],
                    resolver: Callable[[str], str | None] | None = None
                    ) -> tuple[dict[str, str], list[str]]:
    """``({NAME: value}, missing)`` for the DECLARED names only.

    A name the hook did not declare is never looked up, so it can never be
    injected. A declared name with no stored value is reported as missing and
    simply absent from the child's environment — ``ctx.secret()`` then raises a
    KeyError naming it, which is a far better failure than sending an
    unauthenticated request to somebody's CRM.
    """
    resolver = resolver or secret_value
    out: dict[str, str] = {}
    missing: list[str] = []
    for name in names or []:
        val = None
        try:
            val = resolver(name)
        except Exception:  # noqa: BLE001 — a vault miss must not kill the run
            val = None
        if val:
            out[str(name).upper()] = str(val)
        else:
            missing.append(str(name).upper())
    return out, missing


def build_env(*, slug: str, event: str, request_id: str, timeout: int,
              workdir: str, ctx_path: str, result_fd: int,
              secrets: dict[str, str]) -> dict[str, str]:
    """The child's COMPLETE environment. Built from nothing.

    Inheriting ``os.environ`` here would hand every hook the database URI, the
    Fernet key and the Flask secret, because this process is started with
    ``EnvironmentFile=/opt/satom/.env``. The allow-list is the whole point.
    """
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": workdir,
        "TMPDIR": workdir,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "SATOM_HOOK_SLUG": slug,
        "SATOM_HOOK_EVENT": event,
        "SATOM_HOOK_REQUEST_ID": request_id,
        "SATOM_HOOK_TIMEOUT": str(timeout),
        "SATOM_HOOK_CTX": ctx_path,
        "SATOM_RESULT_FD": str(result_fd),
    }
    for name, value in (secrets or {}).items():
        env["SATOM_SECRET_" + str(name).upper()] = str(value)
    return env


# ---------------------------------------------------------------------------
#  process control
# ---------------------------------------------------------------------------
def kill_process_group(proc: subprocess.Popen, grace: float = KILL_GRACE) -> None:
    """SIGTERM then SIGKILL the child's whole process GROUP.

    ``start_new_session=True`` made the child a session+group leader, so its
    pgid IS its pid — no ``getpgid`` race with an already-reaped child. Killing
    the group is what reaches the ``curl`` / ``ssh`` / ``python`` a hook spawned:
    killing only ``proc`` leaves those alive, still holding the CRM connection
    the timeout was supposed to end.
    """
    pgid = proc.pid
    try:
        os.killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    deadline = time.monotonic() + max(0.0, grace)
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        time.sleep(0.05)
    # Unconditional SIGKILL of the GROUP even when the direct child is gone:
    # the grandchildren are the reason this function exists.
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


# ---------------------------------------------------------------------------
#  running one hook
# ---------------------------------------------------------------------------
def run_request(req: dict[str, Any], *,
                resolver: Callable[[str], str | None] | None = None
                ) -> dict[str, Any]:
    """Execute one queued request and return (and persist) its final status."""
    request_id = str(req.get("request_id") or "")
    event = str(req.get("event") or "")
    payload = req.get("payload") if isinstance(req.get("payload"), dict) else {}
    started_wall = _utcnow()
    t0 = time.monotonic()

    def _fail(msg: str, status: str = "failed") -> dict[str, Any]:
        return write_status(
            request_id, slug=req.get("slug", ""), event=event, status=status,
            started_at=started_wall, finished_at=_utcnow(),
            duration_ms=int((time.monotonic() - t0) * 1000),
            exit_code=None, stdout="", data=None, error=msg)

    try:
        slug = validate_slug(str(req.get("slug") or ""))
    except ValueError as exc:
        return _fail("invalid hook slug: %s" % exc)
    if event not in EVENTS:
        return _fail("unknown event %r" % event)

    hook_dir = HOOKS_DIR / slug
    src_path = hook_dir / "hook.py"
    try:
        meta = json.loads((hook_dir / "meta.json").read_text(encoding="utf-8"))
        source = src_path.read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:
        return _fail("hook %r is not readable (deleted mid-flight?): %s" % (slug, exc))
    if not isinstance(meta, dict):
        return _fail("hook %r has a corrupt meta.json" % slug)

    # meta.json on DISK is authoritative, not the copy embedded in the request.
    # Disabling a hook, shortening its timeout or revoking a declared secret has
    # to take effect for work that is already queued — otherwise the kill switch
    # only applies to requests that do not exist yet.
    if not meta.get("enabled", True):
        return _fail("hook %r was disabled before this request ran" % slug)
    if meta.get("event") and meta["event"] != event:
        return _fail("hook %r is no longer bound to %s" % (slug, event))
    timeout = clamp_timeout(meta.get("timeout"))
    declared = [str(s).upper() for s in (meta.get("secrets") or [])]

    secrets, missing = resolve_secrets(declared, resolver)

    write_status(request_id, slug=slug, event=event, status="running",
                 started_at=started_wall, finished_at=None, duration_ms=None,
                 exit_code=None, stdout="", data=None, error="",
                 secrets_missing=missing)

    workdir = tempfile.mkdtemp(prefix="satom-hook-%s-" % slug)
    # The result file lives in a SEPARATE directory that is not the hook's cwd
    # and not its parent, so a hook cannot stumble onto it with a relative path.
    resdir = tempfile.mkdtemp(prefix="satom-hookres-")
    resfd = -1
    try:
        os.chmod(workdir, 0o700)
        os.chmod(resdir, 0o700)
        shutil.copyfile(SDK_SRC, os.path.join(workdir, "satom_sdk.py"))
        hook_path = os.path.join(workdir, "hook.py")
        with open(hook_path, "w", encoding="utf-8") as fh:
            fh.write(source)
        ctx_path = os.path.join(workdir, "_satom_ctx.json")
        with open(ctx_path, "w", encoding="utf-8") as fh:
            json.dump({"event": event, "payload": payload, "slug": slug,
                       "request_id": request_id, "secrets": sorted(secrets),
                       "timeout": timeout}, fh)

        res_path = os.path.join(resdir, "result.jsonl")
        resfd = os.open(res_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)

        env = build_env(slug=slug, event=event, request_id=request_id,
                        timeout=timeout, workdir=workdir, ctx_path=ctx_path,
                        result_fd=resfd, secrets=secrets)

        # -E ignores PYTHONPATH (nothing the parent env could smuggle in),
        # -s drops the user site-dir, -B writes no .pyc into the temp tree.
        # NOT -I: that implies -P, which would remove the script's directory
        # from sys.path and make `import satom_sdk` fail.
        argv = [str(PYTHON), "-E", "-s", "-B", "hook.py"]

        status = "ok"
        error = ""
        try:
            proc = subprocess.Popen(
                argv, cwd=workdir, env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                start_new_session=True, pass_fds=(resfd,), close_fds=True,
                text=True, errors="replace",
            )
        except OSError as exc:
            return _fail("could not start the hook interpreter %s: %s" % (PYTHON, exc))

        try:
            out, _ = proc.communicate(timeout=timeout)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            kill_process_group(proc)
            try:
                out, _ = proc.communicate(timeout=REAP_TIMEOUT)
            except subprocess.TimeoutExpired:
                out = ""
            exit_code = proc.returncode
            status = "timeout"
            error = "hook exceeded its %ds timeout; process group killed" % timeout

        # -- the result channel: FIRST well-formed JSON line, nothing else ----
        ok_flag: bool | None = None
        data: Any = None
        try:
            os.lseek(resfd, 0, os.SEEK_SET)
            raw = os.read(resfd, 256 * 1024).decode("utf-8", "replace")
        except OSError:
            raw = ""
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except ValueError:
                continue
            if isinstance(parsed, dict) and "ok" in parsed:
                ok_flag = bool(parsed.get("ok"))
                data = parsed.get("data")
            break  # first line wins; a hook gets one result, not a stream

        if status != "timeout":
            if exit_code != 0:
                status = "failed"
                error = "hook exited %s" % exit_code
            elif ok_flag is False:
                # Exit 0 but ctx.result(False, …): the author's own verdict wins.
                status = "failed"
                error = "hook reported failure via ctx.result(False, …)"
            else:
                status = "ok"

        # Redact BEFORE truncating, and redact the structured data too.
        out_txt = truncate(redact(out or "", secrets))
        error = redact(error, secrets)
        if missing:
            note = "declared secret(s) not configured: %s" % ", ".join(missing)
            error = (error + " | " if error else "") + note

        return write_status(
            request_id, slug=slug, event=event, status=status,
            started_at=started_wall, finished_at=_utcnow(),
            duration_ms=int((time.monotonic() - t0) * 1000),
            exit_code=exit_code, stdout=out_txt,
            data=_redact_obj(data, secrets), error=error,
            result_reported=ok_flag is not None, secrets_missing=missing)
    finally:
        if resfd >= 0:
            try:
                os.close(resfd)
            except OSError:
                pass
        shutil.rmtree(workdir, ignore_errors=True)
        shutil.rmtree(resdir, ignore_errors=True)


# ---------------------------------------------------------------------------
#  the queue
# ---------------------------------------------------------------------------
def process_request_file(path: Path, *,
                         resolver: Callable[[str], str | None] | None = None
                         ) -> dict[str, Any] | None:
    """Claim one request file, run it, then drop the claim.

    The request is MOVED out of the watched directory before the hook starts, so
    a crash mid-run cannot replay it. At-most-once is the right side of that
    trade here: a duplicated ``change.requested`` means a duplicate CRQ ticket in
    somebody's CRM, while a dropped one leaves a claim file and a ``running``
    status that :func:`reconcile_stale_claims` turns into a visible failure.
    """
    path = Path(path)
    try:
        req = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        try:
            path.unlink()      # malformed → drop it, never crash-loop the unit
        except OSError:
            pass
        return None
    if not isinstance(req, dict) or not req.get("request_id"):
        try:
            path.unlink()
        except OSError:
            pass
        return None

    CLAIM_DIR.mkdir(parents=True, exist_ok=True)
    claim = CLAIM_DIR / path.name
    try:
        os.replace(path, claim)
    except OSError:
        return None            # somebody else claimed it first
    try:
        return run_request(req, resolver=resolver)
    finally:
        try:
            claim.unlink()
        except OSError:
            pass


def reconcile_stale_claims(now: float | None = None) -> list[str]:
    """Turn claims abandoned by a dead runner into visible failures.

    Without this a node that is rebooted mid-hook leaves a status stuck on
    ``running`` forever, and the operator's only clue is a spinner.
    """
    if not CLAIM_DIR.is_dir():
        return []
    now = now if now is not None else time.time()
    out: list[str] = []
    for p in sorted(CLAIM_DIR.glob("*.json")):
        try:
            age = now - p.stat().st_mtime
        except OSError:
            continue
        if age < STALE_CLAIM_AFTER:
            continue
        rid = p.stem
        write_status(rid, status="failed", finished_at=_utcnow(),
                     error="the integrations runner stopped while this hook "
                           "was running (node restart?)")
        try:
            p.unlink()
        except OSError:
            pass
        out.append(rid)
    return out


_APP = None


def _push_app_context():
    """Push a Flask app context so the encrypted secret vault (``app_settings``
    + Fernet) is reachable. Optional by design: if the app cannot be built —
    Postgres down, running from a checkout — the run continues and
    ``secret_value`` falls back to ``SATOM_HOOK_SECRET_<NAME>`` in the
    environment. A vault outage must not stop hooks that use no secrets.
    """
    global _APP
    try:
        if _APP is None:
            from .. import create_app
            _APP = create_app()
        ctx = _APP.app_context()
        ctx.push()
        return ctx
    except Exception:  # noqa: BLE001
        return None


def main() -> int:
    """Drain ``data/integration-requests/``. Entry point of the systemd unit.

    Bounded at :data:`MAX_DRAIN` per invocation: the ``.path`` unit is
    ``DirectoryNotEmpty=``, so anything left re-fires us instead of one oneshot
    holding the queue open for an unbounded time.
    """
    appctx = _push_app_context()
    try:
        reconcile_stale_claims()
        if not REQ_DIR.is_dir():
            return 0
        for path in sorted(REQ_DIR.glob("*.json"))[:MAX_DRAIN]:
            try:
                process_request_file(path)
            except Exception as exc:  # noqa: BLE001 — one bad hook, not a loop
                sys.stderr.write("hook_runner: %s failed: %s\n" % (path.name, exc))
                try:
                    path.unlink()
                except OSError:
                    pass
    finally:
        if appctx is not None:
            try:
                appctx.pop()
            except Exception:  # noqa: BLE001
                pass
    return 0


if __name__ == "__main__":  # pragma: no cover — exercised by the systemd unit
    raise SystemExit(main())
