"""Run a Sentinel sweep as a background job over a chosen set of devices.

The console's "Run sweep now" used to call :func:`pipeline.sweep` inside the
request. That is fine with five appliances and wrong at the ninety this
product is sized for: one gunicorn worker is held for as long as the slowest
device takes, the operator sees a spinner with no detail, and a browser that
gives up mid-request leaves a sweep running that nobody is told about.

Here the same work goes through the shared job ledger
(:mod:`app.services.jobs`), which every other long operation in this product
already uses. That buys three things the synchronous version could not have:

* **progress per device**, so a sweep that is slow and a sweep that is stuck
  stop looking identical;
* **a stop**, honoured between devices — never mid-write, because a device is
  read and its events committed as one step;
* **survival of the page**, so the operator can navigate away.

What it deliberately does NOT buy is concurrency. Devices are swept one at a
time on purpose: a sweep is a read of an appliance that is, by hypothesis,
already the subject of an incident, and turning "collect from ninety devices"
into ninety simultaneous sessions is how a monitoring tool becomes part of
the outage it was watching.
"""
from __future__ import annotations

from .. import jobs

JOB_TYPE = "sentinel_sweep"


def start(flask_app, names: list, *, by: str = "") -> dict:
    """Create the job and run it. Returns the job dict immediately.

    ``names`` empty means every eligible device — the historical meaning of
    the button, preserved so that pressing it without opening the picker does
    what it always did.
    """
    picked = [str(n) for n in (names or [])]
    title = ("Sentinel sweep — %s" %
             (", ".join(picked[:3]) + ("…" if len(picked) > 3 else "")
              if picked else "all eligible devices"))
    job = jobs.create_job(JOB_TYPE, title, by=by,
                          meta={"devices": picked}, cancelable=True,
                          reversible=False)

    def _worker(app, jid):
        with app.app_context():
            return run(jid, picked)

    jobs.run_async(flask_app, job["id"], _worker)
    return job


def run(job_id: str, names: list) -> dict:
    """The worker body. Split out so the tests can drive it without a thread.

    Reports through :func:`jobs.set_progress` and checks for a Stop between
    devices. The result is the pipeline's own result dict, unchanged — the
    job is a way of RUNNING the sweep, not a second opinion about what it
    found.
    """
    from . import pipeline

    def _progress(done: int, total: int, device: str):
        jobs.checkpoint(job_id)
        pct = int(done * 100 / total) if total else 0
        jobs.set_progress(job_id, min(pct, 99),
                          "%d/%d — %s" % (done, total, device))

    result = pipeline.sweep(devices=names or None, on_device=_progress)
    if result.get("skipped"):
        # Not an error: the operator switched Sentinel off, and a job that
        # goes red for a configuration the operator chose teaches them to
        # ignore red.
        jobs.finish_success(job_id, message=result["detail"], result=result)
        return result
    jobs.finish_success(job_id, message=result["detail"], result=result)
    return result
