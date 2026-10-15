"""Runs Script Library requests. Entry point of ``satom-scripts.service``.

DATABASE-FREE BY DESIGN. The unit has no ``EnvironmentFile`` (no
``DATABASE_URL``, no ``FERNET_KEY``) and this module never imports the ORM:
it reads a frozen file tree from ``data/scripts/library/`` and writes status
files to ``data/scripts/status/``. Whatever a script does, the process that
launched it holds nothing worth stealing, and the script itself runs in the
jail of ``app.services.sandbox`` (no SATOM files, no other process, network
only through the egress proxy and only when the script asks for it).

At-most-once, like the hooks runner: a request is MOVED out of the queue
before it runs, so a crash cannot replay it. The claimed copy is rewritten
WITHOUT the inputs the moment it is read -- a password typed into the form
does not stay on disk for the length of the run.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from . import sandbox
from . import script_library as SL

PYTHON = SL.APP_DIR / "venv" / "bin" / "python"
SDK_SRC = Path(__file__).resolve().parent / "script_sdk.py"
NET_SDK_SRC = Path(__file__).resolve().parent / "integration_sdk.py"

MAX_DRAIN = 20
MAX_PARALLEL = 4
STALE_CLAIM_AFTER = SL.TIMEOUT_MAX + 300
EGRESS_VERDICT = sandbox.egress_verdict


def _write_status(rid: str, **fields: Any) -> dict:
    p = SL.STATUS_DIR / (rid + ".json")
    st = SL._read_json(p)
    st["request_id"] = rid
    st.update(fields)
    SL._write_json(p, st)
    return st


def redact(text: str, secrets: dict[str, str]) -> str:
    for name, value in sorted(secrets.items(), key=lambda kv: -len(kv[1])):
        if value and len(value) >= 3:
            text = text.replace(value, "[%s redacted]" % name)
    return text


def _redact_obj(obj: Any, secrets: dict[str, str]) -> Any:
    if isinstance(obj, str):
        return redact(obj, secrets)
    if isinstance(obj, list):
        return [_redact_obj(v, secrets) for v in obj]
    if isinstance(obj, dict):
        return {redact(str(k), secrets): _redact_obj(v, secrets) for k, v in obj.items()}
    return obj


def _cap(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n[... output truncated at %d KiB]" % (limit // 1024)


def _resolve(req: dict) -> tuple[dict[str, str], dict]:
    """(files, frozen settings) for the request's version, read NOW."""
    slug = SL.validate_slug(req.get("slug") or "")
    ref = req.get("version")
    if ref == "draft":
        meta = SL._read_json(SL._dir(slug) / "meta.json")
        if not meta:
            raise SL.ScriptError("the script %r no longer exists" % slug)
        files = SL._read_tree(SL._dir(slug) / "draft")
        settings = meta
    else:
        frozen = SL.version(slug, int(ref))
        if frozen is None:
            raise SL.ScriptError("version %s of %r no longer exists" % (ref, slug))
        files, settings = frozen.pop("files"), frozen
    SL.validate_files(files)
    return files, {"fields": settings.get("fields") or [],
                   "network": settings.get("network") or "none",
                   "timeout": int(settings.get("timeout") or SL.TIMEOUT_DEFAULT)}


def run_request(req: dict) -> dict:
    rid = req["request_id"]
    t0 = time.monotonic()
    _write_status(rid, status="running", started_at=SL._utcnow())
    try:
        files, settings = _resolve(req)
    except (SL.ScriptError, ValueError, TypeError) as exc:
        return _write_status(rid, status="failed", finished_at=SL._utcnow(),
                             error=str(exc))
    inputs = req.get("inputs") if isinstance(req.get("inputs"), dict) else {}
    secrets = SL.secret_inputs(settings["fields"], inputs)
    network = settings["network"] if settings["network"] in SL.NETWORK_MODES else "none"
    timeout = max(SL.TIMEOUT_MIN, min(SL.TIMEOUT_MAX, settings["timeout"]))

    workdir = tempfile.mkdtemp(prefix="satom-script-")
    resfh = tempfile.TemporaryFile()
    try:
        os.chmod(workdir, 0o700)
        for rel, content in files.items():
            dst = Path(workdir) / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(content, encoding="utf-8")
        shutil.copyfile(SDK_SRC, os.path.join(workdir, "satom_script.py"))
        shutil.copyfile(NET_SDK_SRC, os.path.join(workdir, "satom_sdk.py"))
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": workdir,
               "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
               "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1",
               "SATOM_RESULT_FD": str(resfh.fileno())}
        stdin = json.dumps({"inputs": inputs, "script": req.get("slug"),
                            "version": req.get("version")})
        out = sandbox.execute(str(PYTHON), SL.ENTRY, workdir, env=env,
                              timeout=timeout, network=network,
                              pass_fds=(resfh.fileno(),), stdin_data=stdin,
                              verdict=EGRESS_VERDICT)
        if out.error:
            return _write_status(rid, status="failed", finished_at=SL._utcnow(),
                                 duration_ms=int((time.monotonic() - t0) * 1000),
                                 error=out.error)
        resfh.seek(0)
        raw = resfh.read(SL.RESULT_CAP + 1)
        result, note = None, ""
        if raw:
            if len(raw) > SL.RESULT_CAP:
                note = "result() larger than %d KiB was dropped" % (SL.RESULT_CAP // 1024)
            else:
                try:
                    result = json.loads(raw.decode("utf-8", "replace"))
                except ValueError:
                    note = "result() was not valid JSON"
        if out.timed_out:
            status, error = "timeout", "exceeded its %ds timeout; stopped" % timeout
        elif out.exit_code != 0:
            status, error = "failed", "exited with code %s" % out.exit_code
        else:
            status, error = "ok", ""
        if note:
            error = (error + " | " if error else "") + note
        return _write_status(
            rid, status=status, finished_at=SL._utcnow(),
            duration_ms=int((time.monotonic() - t0) * 1000),
            exit_code=out.exit_code,
            output=_cap(redact(out.output or "", secrets), SL.OUTPUT_CAP),
            result=_redact_obj(result, secrets), error=redact(error, secrets),
            egress=[redact(e, secrets) for e in out.egress])
    finally:
        resfh.close()
        shutil.rmtree(workdir, ignore_errors=True)


def process_request_file(path: Path) -> dict | None:
    path = Path(path)
    SL.CLAIM_DIR.mkdir(parents=True, exist_ok=True)
    claim = SL.CLAIM_DIR / path.name
    try:
        os.replace(path, claim)
    except OSError:
        return None                       # another runner took it
    try:
        try:
            req = json.loads(claim.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(req, dict) or not SL._RID_RE.match(str(req.get("request_id") or "")):
            return None
        # The claim stays as the "running" marker, minus the inputs.
        SL._write_json(claim, {"request_id": req["request_id"],
                               "claimed_at": SL._utcnow()}, mode=0o600)
        try:
            return run_request(req)
        except Exception as exc:  # noqa: BLE001 -- never leave "running" behind
            return _write_status(req["request_id"], status="failed",
                                 finished_at=SL._utcnow(),
                                 error="runner error: %s" % exc)
    finally:
        try:
            claim.unlink()
        except OSError:
            pass


def reconcile_stale_claims(now: float | None = None) -> list[str]:
    if not SL.CLAIM_DIR.is_dir():
        return []
    now = now if now is not None else time.time()
    out = []
    for p in sorted(SL.CLAIM_DIR.glob("*.json")):
        try:
            if now - p.stat().st_mtime < STALE_CLAIM_AFTER:
                continue
        except OSError:
            continue
        _write_status(p.stem, status="failed", finished_at=SL._utcnow(),
                      error="the scripts runner stopped while this run was "
                            "in progress (node restart?)")
        try:
            p.unlink()
        except OSError:
            pass
        out.append(p.stem)
    return out


def main() -> int:
    reconcile_stale_claims()
    if not SL.REQ_DIR.is_dir():
        return 0
    batch = sorted(p for p in SL.REQ_DIR.glob("*.json")
                   if not p.name.startswith("."))[:MAX_DRAIN]
    if not batch:
        return 0

    def one(p):
        try:
            return process_request_file(p)
        except Exception as exc:  # noqa: BLE001 -- one bad run, not the queue
            sys.stderr.write("script_runner: %s failed: %s\n" % (p.name, exc))
            try:
                p.unlink()
            except OSError:
                pass
            return None

    with ThreadPoolExecutor(max_workers=MAX_PARALLEL) as pool:
        list(pool.map(one, batch))
    return 0


if __name__ == "__main__":  # pragma: no cover -- exercised by the systemd unit
    raise SystemExit(main())
