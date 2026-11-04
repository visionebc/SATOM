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
import math
import re
import time
import os
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
        # The environment still applies HERE, and this is the branch that
        # matters most: this module is imported inside the scheduler
        # sidecar, which has no application context, so returning
        # DEFAULT_URL made every sidecar write go to a loopback store that
        # does not exist in a container. Verified in the running stack.
        return _env_url() or DEFAULT_URL
    return (configured or _env_url() or DEFAULT_URL).rstrip("/")


def _env_url() -> str:
    """Deployment-supplied default, ranked BELOW the operator's setting.

    The container stack runs VictoriaMetrics as a sibling service, so
    ``127.0.0.1:8428`` -- correct on every host install -- is the app container
    itself there. ``deploy/docker/compose.yaml`` sets ``SATOM_METRICS_URL``.

    The precedence is the point. Putting the environment ABOVE
    ``metrics.vm_url`` would make the settings field silently ineffective on a
    container node, which is precisely the failure ``base_url``'s own docstring
    already records once: ``settings_store.get`` never existed, the broad
    ``except`` ate the AttributeError, and the setting was unconfigurable for
    months while the default was always returned.
    """
    return os.environ.get("SATOM_METRICS_URL", "").strip()


#: [SATOM-METRICS-AUTHKEYS] The store's /snapshot* endpoints take this key
#: (``-snapshotAuthKey``, set from the root-only env file the unit reads).
#: deploy/install-metrics-store.sh writes the same value here, root:<service
#: account> 0640, because the app is the one legitimate caller. The other admin
#: keys (delete_series, force_merge, reload, ...) are never readable by the app.
SNAPSHOT_KEY_FILE = "/etc/satom/metrics-snapshot.key"
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def snapshot_auth_key() -> str:
    """The snapshot authKey for the LOOPBACK store, or '' (none provisioned /
    the configured store is not this node's -- the key is never sent off-box).
    A store started before the key existed ignores the extra parameter."""
    host = (urllib.parse.urlsplit(base_url()).hostname or "").lower()
    if host not in _LOOPBACK_HOSTS:
        return ""
    path = os.environ.get("SATOM_METRICS_SNAPSHOT_KEY_FILE") or SNAPSHOT_KEY_FILE
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _http(path: str, *, data: bytes | None = None, timeout: float = 10.0,
          method: str | None = None):
    req = urllib.request.Request(base_url() + path, data=data,
                                 method=method or ("POST" if data else "GET"))
    if data is not None:
        req.add_header("Content-Type", "text/plain; charset=utf-8")
    return urllib.request.urlopen(req, timeout=timeout)  # noqa: S310 — loopback


#: The store's limit on ONE label value, in UTF-8 bytes. Measured on the
#: shipped binary (v1.148, 2026-11-04): 4096 bytes is stored, 4097 is not --
#: and the import still answers 204. The whole SERIES is dropped, logged only
#: as a store-side warning and ``vm_rows_ignored_total{reason=
#: "too_long_label_value"}``, so a collector reported "ok" for a sample that
#: never landed. A value is cut to fit instead; a truncated label is visible,
#: a missing series is not.
MAX_LABEL_VALUE_BYTES = 4096
_TRUNC_MARK = "…"
_NAME_RE = re.compile(r"[A-Za-z_:][A-Za-z0-9_:]*\Z")
_LABEL_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
# C0 controls and DEL. The store keeps a CR inside a quoted value as a byte of
# the value (measured: it does NOT start a new line), so this is about what a
# page or a CSV later prints, not about the exposition format.
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def escape_label(v) -> str:
    """A label value the store keeps verbatim: no control characters, and no
    longer than :data:`MAX_LABEL_VALUE_BYTES` once escaped (cut on a character
    boundary, never mid-UTF-8 sequence and never mid-escape)."""
    s = _CTRL_RE.sub(" ", str(v))
    out = s.replace("\\", "\\\\").replace('"', '\\"')
    if len(out.encode("utf-8")) <= MAX_LABEL_VALUE_BYTES:
        return out
    budget = MAX_LABEL_VALUE_BYTES - len(_TRUNC_MARK.encode("utf-8"))
    kept, used = [], 0
    for ch in s:
        piece = "\\\\" if ch == "\\" else '\\"' if ch == '"' else ch
        size = len(piece.encode("utf-8"))
        if used + size > budget:
            break
        kept.append(piece)
        used += size
    return "".join(kept) + _TRUNC_MARK


def line(name: str, labels: dict, value, ts_ms: int | None = None) -> str:
    """One exposition line, or '' (skip) for a value that is not a finite
    number or a metric/label name the format cannot carry.

    NaN is skipped because the store files it as a staleness marker (measured:
    the series reads as absent), and +/-Inf because no gauge here can be
    infinite -- it is a division by zero or a value someone made up, and it
    would sit in a panel as a real sample. "A reading we do not have is
    skipped, never written" is the rule every collector already keeps."""
    try:
        num = float(value)
    except (TypeError, ValueError):
        return ""
    if not math.isfinite(num):
        return ""
    if not _NAME_RE.match(str(name)):
        return ""
    if any(not _LABEL_RE.match(str(k)) for k, v in labels.items() if v is not None):
        return ""
    lab = ",".join('%s="%s"' % (k, escape_label(v))
                   for k, v in sorted(labels.items()) if v is not None)
    ts = " %d" % (ts_ms if ts_ms is not None else int(time.time() * 1000))
    # %.15g, not %g: %g keeps SIX significant digits, so a byte counter of
    # 2687240704 was stored as 2.68724e+09 and rate() over it moved in steps of
    # ten kilobytes (measured in the store 2026-10-30: 550529000 for a counter
    # the device reported as 550442541). 15 digits are exact for every integer
    # a counter reaches and still print 0.1 as 0.1.
    return "%s{%s} %s%s" % (name, lab, ("%.15g" % num), ts)


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
                timeout: float = 25.0, nocache: bool = False) -> dict:
    """``nocache`` bypasses the store's response cache. Measured on a1
    (v1.148, 2026-10-21): a series whose first sample was a few minutes old
    came back from 1 h and 2 h ranges and was MISSING from 3 h, 6 h, 24 h and
    90 d ranges; it appeared once that sample was about 5 minutes old (the
    store's -search.cacheTimestampOffset), or at once with ``nocache``."""
    params = {"query": expr, "start": "%f" % start, "end": "%f" % end,
              "step": step}
    if nocache:
        params["nocache"] = "1"
    qs = urllib.parse.urlencode(params)
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
