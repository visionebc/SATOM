"""Headless reconciler loop -- runs on BOTH HA nodes.

Its own systemd unit (``ofortmaut-reconciler.service``), NOT inside the
gunicorn workers and NOT the scheduler (which is primary-only). This loop is
role-aware and DB-free, so it runs safely on the standby too (where Flask
cannot boot). Every tick calls ``reconciler.tick()`` which decides + logs +
publishes. In MANUAL mode it only observes; in AUTO it drives the staged
self-update. See ``app/services/reconciler.py``.

Launch:  ``python -m app.reconciler_runtime`` (from /opt/ofortmaut).
"""
from __future__ import annotations

import logging
import signal
import sys
import time

from app.services import reconciler

TICK_SECONDS = 60
_stop = False


def _handle_stop(signum, frame):  # noqa: ANN001
    global _stop
    _stop = True


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [fm.reconciler] %(message)s",
        stream=sys.stdout,
    )
    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)
    log = logging.getLogger("fm.reconciler")
    log.info("reconciler starting (tick=%ss)", TICK_SECONDS)
    while not _stop:
        try:
            reconciler.tick()
        except Exception as e:  # noqa: BLE001 -- a bad tick must not kill the loop
            log.exception("tick failed: %s", e)
        for _ in range(TICK_SECONDS):  # SIGTERM-responsive sleep
            if _stop:
                break
            time.sleep(1)
    log.info("reconciler stopped")


if __name__ == "__main__":
    main()
