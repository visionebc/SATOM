"""Run a connector as a job: every read is a visible step, facts are replaced
per endpoint, and a failed read leaves its old facts marked ERROR (via
EndpointStatus) instead of presenting them as current."""
from __future__ import annotations

import time
from datetime import timedelta

import httpx
from flask import current_app

from . import connectors, crypto
from .extensions import db
from .models import EndpointStatus, Fact, Job, JobStep, Source, audit, utcnow


def _redact(text: str, secret: str) -> str:
    if secret and text:
        text = text.replace(secret, "***")
    return text


def connector_for(source: Source, transport=None):
    if (source.config or {}).get("fortinet_source") == "satom":
        # Inside SATOM: configuration from SATOM's cache, secret from SATOM.
        from .connectors.satom import BY_PRODUCT
        return BY_PRODUCT[source.kind](source, transport=transport)
    cls = connectors.get(source.kind)
    return cls(source, secret=crypto.decrypt(source.secret_enc), transport=transport)


def test_source(source: Source, user: str = "", transport=None) -> dict:
    conn = connector_for(source, transport)
    job = Job(kind="test", source_id=source.id, created_by=user, started_at=utcnow())
    db.session.add(job)
    started = time.monotonic()
    try:
        out = conn.test()
    except Exception as exc:  # noqa: BLE001
        out = {"ok": False, "detail": "%s: %s" % (type(exc).__name__, exc), "build": ""}
    out["detail"] = _redact(out.get("detail", ""), conn.secret)
    job.steps.append(JobStep(name="connection test", ok=out["ok"], detail=out["detail"],
                             elapsed_ms=int((time.monotonic() - started) * 1000)))
    job.status = "done" if out["ok"] else "failed"
    job.summary = out["detail"]
    job.finished_at = utcnow()
    if out.get("build"):
        source.build = out["build"][:160]
    audit(user, "source.test", source.name, "ok" if out["ok"] else out["detail"][:300])
    db.session.commit()
    return out


def run_source(source: Source, user: str = "", transport=None) -> Job:
    conn = connector_for(source, transport)
    job = Job(kind="collect", source_id=source.id, created_by=user or "scheduler", started_at=utcnow())
    db.session.add(job)
    db.session.commit()
    try:
        results = conn.collect()
    except Exception as exc:  # noqa: BLE001
        results = []
        job.steps.append(JobStep(name="collect", ok=False,
                                 detail=_redact("%s: %s" % (type(exc).__name__, exc), conn.secret)))
    now = utcnow()
    metrics, failed = [], 0
    for r in results:
        err = _redact(r.error, conn.secret)
        detail = ("absent on this build" if r.absent else
                  (err if not r.ok else "%d rows%s" % (r.rows, (" · " + err) if err else "")))
        step = r.path if (r.path or "").startswith("SATOM cache") else "GET %s" % (r.path or r.endpoint)
        job.steps.append(JobStep(name=step, ok=r.ok, detail=detail,
                                 elapsed_ms=r.elapsed_ms))
        st = EndpointStatus.query.filter_by(source_id=source.id, endpoint=r.endpoint).first()
        if st is None:
            st = EndpointStatus(source_id=source.id, endpoint=r.endpoint)
            db.session.add(st)
        st.layers, st.ok, st.absent = ",".join(r.layers), r.ok, r.absent
        st.error, st.rows, st.read_at = (err if not r.ok else ""), r.rows, now
        if not r.ok:
            failed += 1
        else:
            Fact.query.filter_by(source_id=source.id, endpoint=r.endpoint).delete()
            seen = set()
            for f in r.facts:
                k = (f.object_ref, f.layer, f.key)
                if k in seen:
                    continue
                seen.add(k)
                Fact.query.filter_by(source_id=source.id, object_ref=f.object_ref,
                                     layer=f.layer, key=f.key).delete()
                db.session.add(Fact(source_id=source.id, object_ref=f.object_ref[:255],
                                    layer=f.layer, key=f.key[:80], value=f.value,
                                    endpoint=r.endpoint, read_at=now))
        metrics.extend(r.metrics)
    pushed = push_metrics(source, metrics)
    if pushed:
        job.steps.append(JobStep(name="metrics → VictoriaMetrics", ok=pushed[0], detail=pushed[1]))
    total = len(results)
    source.last_run_at = now
    source.last_status = "ok" if results and not failed else ("partial" if results and failed < total else "error")
    source.last_error = "" if not failed else "%d of %d reads failed" % (failed, total)
    job.status = "done" if source.last_status == "ok" else "failed"
    job.summary = "%d/%d reads ok" % (total - failed, total) if total else "no reads"
    job.finished_at = utcnow()
    db.session.commit()
    return job


def push_metrics(source: Source, metrics) -> tuple | None:
    if not metrics:
        return None
    url = current_app.config.get("METRICS_URL", "")
    if not url:
        return None
    lines = []
    for name, labels, value in metrics:
        lab = dict(labels, source=source.name)
        body = ",".join('%s="%s"' % (k, str(v).replace("\\", "\\\\").replace('"', '\\"'))
                        for k, v in sorted(lab.items()))
        lines.append("%s{%s} %s" % (name, body, value))
    try:
        # Loopback store we own: the GET-only transport is for devices, not for this.
        r = httpx.post(url.rstrip("/") + "/api/v1/import/prometheus",
                       content="\n".join(lines) + "\n", timeout=10)
        return (r.status_code < 300, "%d series, HTTP %s" % (len(lines), r.status_code))
    except Exception as exc:  # noqa: BLE001
        return (False, "metrics store unreachable: %s" % exc)


def due_sources():
    now = utcnow()
    for s in Source.query.filter_by(enabled=True).order_by(Source.id):
        if s.last_run_at is None or s.last_run_at + timedelta(seconds=max(60, s.interval_s)) <= now:
            yield s
