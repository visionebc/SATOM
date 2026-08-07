"""Thin client for the node's VictoriaMetrics store (satom-metrics.service).

Loopback HTTP only. Every caller goes through the app — the store itself has
no auth, which is exactly why it must never listen beyond 127.0.0.1 (the unit
enforces that). Stdlib urllib on purpose: this module is imported inside the
scheduler sidecar and must not add a dependency to the pinned set.

Ingestion uses the Prometheus text exposition endpoint
(``/api/v1/import/prometheus``): plain lines of
``name{label="value"} <number> <ms-timestamp>`` — trivially composable from
Python and immune to client-library drift.
"""
from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8428"


def base_url() -> str:
    """The metrics store this node talks to.

    ``settings_store.get`` has never existed -- the accessor is ``get_str`` --
    so this raised ``AttributeError`` on every call, the broad ``except`` ate
    it, and ``metrics.vm_url`` was silently unconfigurable: the default was
    always returned no matter what the operator set. Same shape as
    ``hypervisors.base`` importing a ``trust_store.verify_target`` that was
    never defined. A name error is a programming mistake, not an environment
    problem, so it is no longer folded in with "we are outside an app context".
    """
    try:
        from . import settings_store
        configured = settings_store.get_str("metrics.vm_url", "") or ""
    except AttributeError:
        # Never silently: a missing accessor means this function is wrong, and
        # the whole point of this comment is that it went unnoticed for months.
        raise
    except Exception:  # noqa: BLE001 — outside app context (tests, CLI)
        return DEFAULT_URL
    return (configured or DEFAULT_URL).rstrip("/")


def _http(path: str, *, data: bytes | None = None, timeout: float = 10.0,
          method: str | None = None):
    req = urllib.request.Request(base_url() + path, data=data,
                                 method=method or ("POST" if data else "GET"))
    if data is not None:
        req.add_header("Content-Type", "text/plain; charset=utf-8")
    return urllib.request.urlopen(req, timeout=timeout)  # noqa: S310 — loopback


def escape_label(v) -> str:
    return (str(v).replace("\\", "\\\\").replace('"', '\\"')
            .replace("\n", " "))


def line(name: str, labels: dict, value, ts_ms: int | None = None) -> str:
    """One exposition line. ``None``/non-numeric values yield '' (skip)."""
    try:
        num = float(value)
    except (TypeError, ValueError):
        return ""
    lab = ",".join('%s="%s"' % (k, escape_label(v))
                   for k, v in sorted(labels.items()) if v is not None)
    ts = " %d" % (ts_ms if ts_ms is not None else int(time.time() * 1000))
    return "%s{%s} %s%s" % (name, lab, ("%g" % num), ts)


def ingest(lines: list) -> dict:
    """POST exposition lines. Returns {ok, count, detail}. Never raises."""
    body = "\n".join(l for l in lines if l)
    if not body:
        return {"ok": True, "count": 0, "detail": "nothing to ingest"}
    try:
        with _http("/api/v1/import/prometheus",
                   data=body.encode("utf-8")) as r:
            r.read()
        return {"ok": True, "count": body.count("\n") + 1, "detail": ""}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "count": 0, "detail": str(exc)[:200]}


def query(expr: str, ts: float | None = None, timeout: float = 15.0) -> dict:
    qs = {"query": expr}
    if ts:
        qs["time"] = "%f" % ts
    try:
        with _http("/api/v1/query?" + urllib.parse.urlencode(qs),
                   timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "error": str(exc)[:200]}


def query_range(expr: str, start: float, end: float, step: str = "60s",
                timeout: float = 25.0) -> dict:
    qs = urllib.parse.urlencode({"query": expr, "start": "%f" % start,
                                 "end": "%f" % end, "step": step})
    try:
        with _http("/api/v1/query_range?" + qs, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "error": str(exc)[:200]}


def label_values(label: str, match: str = "") -> list:
    qs = {"start": "%d" % (time.time() - 7 * 86400)}
    if match:
        qs["match[]"] = match
    try:
        with _http("/api/v1/label/%s/values?%s"
                   % (urllib.parse.quote(label), urllib.parse.urlencode(qs))) as r:
            data = json.loads(r.read().decode("utf-8"))
        return data.get("data") or []
    except Exception:  # noqa: BLE001
        return []


def health() -> dict:
    """Store liveness + headline stats for the Collection page and diagnose."""
    out = {"up": False, "url": base_url(), "series": None, "detail": ""}
    try:
        with _http("/health", timeout=3.0) as r:
            out["up"] = (r.read().decode("utf-8", "replace").strip() == "OK")
    except Exception as exc:  # noqa: BLE001
        out["detail"] = str(exc)[:200]
        return out
    try:
        with _http("/api/v1/status/tsdb?topN=1", timeout=5.0) as r:
            data = json.loads(r.read().decode("utf-8"))
        out["series"] = (data.get("data") or {}).get("totalSeries")
    except Exception:  # noqa: BLE001
        pass
    return out
