"""Per-thread progress sink for device actions running as background jobs.

``services.device_jobs`` replays a device action inside a job thread and binds
a :class:`JobSink` to that thread. Every call the device clients make
(``clients/base.py::BaseClient._request`` and the read-only SSH console) asks
the bound sink first, so a job reports *where it is* without any per-action
code: each REST call / SSH command becomes one step of the job
(``GET /api/v2.0/cmdb/server-policy/policy · 200 · 0.4 s``).

The sink is also the device-level queue. The first call an *exclusive* (write)
job makes to a device takes that device's lock; a second write to the same
device waits — visibly, as ``Queued — waiting for …`` — until the first one
finishes. A job holds at most ONE device lock and only waits while it holds
none, so two jobs can never deadlock each other. The lock is an ``flock`` on a
file under ``data/jobs/locks/``: it works across gunicorn workers and the
kernel drops it if the worker process dies, so a crash never leaves a device
locked.

Cancellation: before every call the sink runs :func:`jobs.checkpoint`, so a
Stop takes effect between two calls. An exclusive job becomes NOT cancelable
the moment it holds the device lock: stopping a multi-call write between two
calls would leave the device half-changed, and the UI must not promise that.

Outside a job (no sink bound) every hook is a no-op.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import threading
import time
from datetime import datetime
from pathlib import Path

from . import jobs

_TL = threading.local()

#: Steps kept in the job file. The count keeps going; the list is a tail.
MAX_STEPS = 200
#: How long a queued write waits for another job's device lock.
LOCK_MAX_WAIT_S = float(os.environ.get("SATOM_DEVICE_LOCK_MAX_WAIT_S", "1800"))
_LOCK_POLL_S = 0.5


def current():
    """The sink bound to this thread, or None."""
    return getattr(_TL, "sink", None)


def bind(sink) -> None:
    _TL.sink = sink


def unbind() -> None:
    sink = current()
    _TL.sink = None
    if sink is not None:
        sink.release()


def step(label: str, percent: int | None = None) -> None:
    """Record a named phase for the job running on this thread (no-op outside
    a job). Use where an action has known phases, e.g. ``step("Restoring", 40)``."""
    sink = current()
    if sink is not None:
        sink.add_step(label, percent=percent)


def _locks_dir() -> Path:
    d = jobs._state_dir() / "locks"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe(key: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", key)[:120] or "device"


def _strip_query(path: str) -> str:
    # Query strings can carry tokens or filters nobody needs in a job log.
    return (path or "").split("?", 1)[0]


class JobSink:
    """Progress + queue state for one device job on one thread."""

    def __init__(self, job_id: str, *, exclusive: bool):
        self.job_id = job_id
        self.exclusive = exclusive
        self.calls = 0
        self._lock_fd = None
        self._lock_key = ""
        self._stamped = False

    # -- device lock -------------------------------------------------------
    def _holder_path(self, key: str) -> Path:
        return _locks_dir() / f"{_safe(key)}.holder.json"

    def _acquire(self, key: str) -> None:
        path = _locks_dir() / f"{_safe(key)}.lock"
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o640)
        waited_from = None
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if waited_from is None:
                        waited_from = time.monotonic()
                        holder = {}
                        try:
                            holder = json.loads(self._holder_path(key)
                                                .read_text(encoding="utf-8"))
                        except Exception:  # noqa: BLE001 — holder file is advisory
                            pass
                        who = holder.get("title") or "another action"
                        msg = f"Queued — waiting for “{who}” on this device"
                        jobs.mutate_job(self.job_id, lambda st: (
                            st["meta"].update(queued=True,
                                              queued_behind=holder.get("job_id", "")),
                            st.update(message=msg)))
                    # A queued job has touched nothing: Stop is always safe here.
                    jobs.checkpoint(self.job_id)
                    if time.monotonic() - waited_from > LOCK_MAX_WAIT_S:
                        raise TimeoutError(
                            f"Gave up after {int(LOCK_MAX_WAIT_S)} s waiting for "
                            f"another action on this device to finish.")
                    time.sleep(_LOCK_POLL_S)
        except BaseException:
            os.close(fd)
            raise
        self._lock_fd, self._lock_key = fd, key
        st = jobs.get_job(self.job_id) or {}
        try:
            self._holder_path(key).write_text(json.dumps({
                "job_id": self.job_id, "title": st.get("title", ""),
                "since": datetime.utcnow().isoformat()}), encoding="utf-8")
        except Exception:  # noqa: BLE001
            pass

        def _started(s):
            s["meta"]["queued"] = False
            # From here on the job writes to the device: a Stop between two
            # calls would leave it half-changed, so the UI stops offering one.
            s["cancelable"] = False
        jobs.mutate_job(self.job_id, _started)

    def release(self) -> None:
        if self._lock_fd is None:
            return
        try:
            hp = self._holder_path(self._lock_key)
            try:
                if json.loads(hp.read_text(encoding="utf-8")).get("job_id") == self.job_id:
                    hp.unlink()
            except Exception:  # noqa: BLE001
                pass
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(self._lock_fd)
            self._lock_fd = None

    # -- hooks called by the device clients -------------------------------
    def before_call(self, target: str) -> None:
        """``target`` is ``https://host:port`` (REST) or ``ssh://host:port``."""
        jobs.checkpoint(self.job_id)
        key = re.sub(r"^[a-z]+://", "", target or "").rstrip("/")
        if not self._stamped:
            self._stamped = True
            self._stamp_appliance(key)
        if self.exclusive and self._lock_fd is None and key:
            self._acquire(key)

    def after_call(self, method: str, path: str, status, started: float,
                   error: BaseException | None = None) -> None:
        self.calls += 1
        secs = time.monotonic() - started
        if error is not None:
            outcome = type(error).__name__
        else:
            outcome = str(status)
        label = f"{method.upper()} {_strip_query(path)}"[:160]
        failed = isinstance(status, int) and status >= 400
        self._record(label, outcome, secs, ok=error is None and not failed)

    def add_step(self, label: str, percent: int | None = None) -> None:
        self._record(str(label)[:160], "", None, ok=True, percent=percent)

    def _record(self, label: str, outcome: str, secs, *, ok: bool,
                percent: int | None = None) -> None:
        n = self.calls
        entry = {"at": datetime.utcnow().isoformat(timespec="seconds"),
                 "label": label, "outcome": outcome, "ok": bool(ok)}
        if secs is not None:
            entry["ms"] = int(secs * 1000)
        msg = label + (f" · {outcome}" if outcome else "") + \
            ("" if secs is None else
             f" · {int(secs * 1000)} ms" if secs < 1 else f" · {secs:.1f} s")

        def _apply(st):
            meta = st.setdefault("meta", {})
            steps = meta.setdefault("steps", [])
            steps.append(entry)
            if len(steps) > MAX_STEPS:
                del steps[: len(steps) - MAX_STEPS]
            meta["device_calls"] = n
            meta["step_count"] = int(meta.get("step_count") or 0) + 1
            st["message"] = msg
            if percent is not None:
                st["percent"] = max(0, min(99, int(percent)))
            elif not meta.get("phased"):
                # No known end: an asymptotic bar that keeps moving per call
                # and never claims to be done before the job is.
                st["percent"] = min(95, int(95 * (1 - 0.9 ** max(1, n))))
            if percent is not None:
                meta["phased"] = True
        jobs.mutate_job(self.job_id, _apply)

    def _stamp_appliance(self, key: str) -> None:
        """Name the device on a job whose route did not carry its id (the
        device came from the session, e.g. the Workspace)."""
        st = jobs.get_job(self.job_id) or {}
        if (st.get("meta") or {}).get("appliance_id"):
            return
        host = key.rsplit(":", 1)[0]
        try:
            from ..models import Appliance
            a = Appliance.query.filter_by(host=host).first()
        except Exception:  # noqa: BLE001 — naming is cosmetic
            a = None
        if a is None:
            jobs.mutate_job(self.job_id, lambda s: s["meta"].setdefault("device", host))
            return

        def _apply(s):
            s["meta"].update(appliance_id=a.id, appliance=a.name)
            if " · " not in (s.get("title") or ""):
                s["title"] = f"{s.get('title') or 'Device action'} · {a.name}"
        jobs.mutate_job(self.job_id, _apply)
