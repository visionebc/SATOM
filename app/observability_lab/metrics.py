"""Read side of the metrics store (VictoriaMetrics on loopback, no auth — the
bind is the only protection, so the browser never reaches it: the UI asks for
a NAMED series and the expression is built here, never taken from a request).

A failed query is an ERROR the UI must show, never an empty chart."""
from __future__ import annotations

import time

import httpx
from flask import current_app

#: UI time ranges (seconds).
RANGES = {"5m": 300, "15m": 900, "1h": 3600, "6h": 21600, "12h": 43200,
          "24h": 86400, "7d": 604800, "30d": 2592000}
DEFAULT_RANGE = "1h"
#: Collection runs at most every 60 s and by default every 300 s, so finer
#: steps only repeat points.
MIN_STEP = 60
POINTS = 120

#: name -> (title, unit, [(legend, expression template)]). ``{sel}`` is the
#: label selector, ``{w}`` the rate window. Units of the FortiWeb latency
#: fields are as reported by the device (not verified on 7.6.8 with traffic).
SERIES = {
    "throughput": ("Interface throughput", "bps", [
        ("In", "sum(rate(obs_if_rx_bytes{sel}[{w}])) * 8"),
        ("Out", "sum(rate(obs_if_tx_bytes{sel}[{w}])) * 8")]),
    "packets": ("Interface packets", "pps", [
        ("In", "sum(rate(obs_if_rx_packets{sel}[{w}]))"),
        ("Out", "sum(rate(obs_if_tx_packets{sel}[{w}]))")]),
    "sessions": ("Active sessions (server policies)", "count", [
        ("Sessions", "sum(obs_policy_sessions{sel})")]),
    "connections": ("New connections per second", "cps", [
        ("Connections/s", "sum(obs_policy_conn_per_s{sel})")]),
    "latency": ("Latency, average over server policies", "ms", [
        ("Client RTT", "avg(obs_policy_client_rtt{sel})"),
        ("Server RTT", "avg(obs_policy_server_rtt{sel})"),
        ("App response", "avg(obs_policy_app_response_time{sel})")]),
    "resources": ("Device CPU and memory", "pct", [
        ("CPU", "avg(obs_dev_cpu_pct{sel})"),
        ("Memory", "avg(obs_dev_mem_pct{sel})")]),
    "fw_traffic": ("Firewall policy traffic", "bps", [
        ("Through policies", "sum(rate(obs_fwpolicy_bytes{sel}[{w}])) * 8")]),
    "fw_sessions": ("Firewall sessions", "count", [
        ("Active sessions", "sum(last_over_time(obs_fwpolicy_active_sessions{sel}[{w}]))")]),
    "reads": ("Successful reads", "ratio", [
        ("Reads OK", "sum(obs_endpoint_up{sel}) / count(obs_endpoint_up{sel})")]),
}

#: name -> (expression template, unit) for single "now" values.
INSTANT = {
    "throughput_in": ("sum(rate(obs_if_rx_bytes{sel}[{w}])) * 8", "bps"),
    "throughput_out": ("sum(rate(obs_if_tx_bytes{sel}[{w}])) * 8", "bps"),
    # Gauges: the last collected value within the window. A raw instant query
    # can come back empty around a collection (samples arrive every few minutes
    # and the store hides the newest seconds), which the UI would show as "—".
    "sessions": ("sum(last_over_time(obs_policy_sessions{sel}[{w}]))", "count"),
    "connections": ("sum(last_over_time(obs_policy_conn_per_s{sel}[{w}]))", "cps"),
    "app_response": ("avg(last_over_time(obs_policy_app_response_time{sel}[{w}]))", "ms"),
    "client_rtt": ("avg(last_over_time(obs_policy_client_rtt{sel}[{w}]))", "ms"),
    "server_rtt": ("avg(last_over_time(obs_policy_server_rtt{sel}[{w}]))", "ms"),
    "cpu": ("avg(last_over_time(obs_dev_cpu_pct{sel}[{w}]))", "pct"),
    "mem": ("avg(last_over_time(obs_dev_mem_pct{sel}[{w}]))", "pct"),
    "fw_sessions": ("sum(last_over_time(obs_fwpolicy_active_sessions{sel}[{w}]))", "count"),
    # Over the whole range: share of reads that succeeded.
    "read_availability": ("avg(avg_over_time(obs_endpoint_up{sel}[{r}]))", "ratio"),
}


class MetricsError(Exception):
    pass


def selector(source_name: str | None) -> str:
    """Label selector. The name must already be a known source (the caller
    checks it against the table), and it is escaped anyway."""
    if not source_name:
        return ""
    return '{source="%s"}' % source_name.replace("\\", "\\\\").replace('"', '\\"')


def window(step: int) -> str:
    # rate() needs two samples inside the window; collection is every 300 s.
    return "%ds" % max(900, 2 * step)


def plan(range_key: str) -> tuple[int, int, int]:
    """(start, end, step) for a range key."""
    span = RANGES.get(range_key, RANGES[DEFAULT_RANGE])
    end = int(time.time())
    step = max(MIN_STEP, span // POINTS)
    return end - span, end, step


def _get(path: str, params: dict) -> dict:
    url = current_app.config.get("METRICS_URL", "")
    if not url:
        raise MetricsError("metrics store not configured")
    try:
        r = httpx.get(url.rstrip("/") + path, params=params, timeout=10)
    except httpx.HTTPError as exc:
        raise MetricsError("metrics store unreachable: %s" % type(exc).__name__) from exc
    try:
        body = r.json()
    except ValueError as exc:
        raise MetricsError("metrics store answered HTTP %s, not JSON" % r.status_code) from exc
    if r.status_code >= 400 or body.get("status") != "success":
        raise MetricsError("query failed: %s" % (body.get("error") or "HTTP %s" % r.status_code)[:200])
    return body.get("data") or {}


def _num(v):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return None if f != f or f in (float("inf"), float("-inf")) else f


def series(name: str, range_key: str, source_name: str | None) -> dict:
    title, unit, parts = SERIES[name]
    start, end, step = plan(range_key)
    sel, w = selector(source_name), window(step)
    out = {"name": name, "title": title, "unit": unit, "range": range_key,
           "start": start, "end": end, "step": step, "series": []}
    for legend, tpl in parts:
        data = _get("/api/v1/query_range", {"query": tpl.format(sel=sel, w=w),
                                            "start": start, "end": end, "step": step})
        res = data.get("result") or []
        try:
            pts = [[int(float(t)), _num(v)] for t, v in (res[0]["values"] if res else [])]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise MetricsError("unexpected answer from the metrics store") from exc
        out["series"].append({"legend": legend, "points": pts})
    return out


def instant(name: str, range_key: str, source_name: str | None):
    tpl, unit = INSTANT[name]
    _s, _e, step = plan(range_key)
    expr = tpl.format(sel=selector(source_name), w=window(step),
                      r="%ds" % RANGES.get(range_key, RANGES[DEFAULT_RANGE]))
    res = _get("/api/v1/query", {"query": expr}).get("result") or []
    try:
        return {"value": _num(res[0]["value"][1]) if res else None, "unit": unit}
    except (KeyError, IndexError, TypeError) as exc:
        raise MetricsError("unexpected answer from the metrics store") from exc


def top_policies(metric: str, source_name: str | None, k: int = 10) -> list[dict]:
    """Current top-k server policies by one metric (sessions, app response…)."""
    allowed = {"sessions": "obs_policy_sessions", "app_response": "obs_policy_app_response_time",
               "connections": "obs_policy_conn_per_s", "fw_sessions": "obs_fwpolicy_active_sessions"}
    expr = "topk(%d, last_over_time(%s%s[%s]))" % (k, allowed[metric], selector(source_name), window(MIN_STEP))
    res = _get("/api/v1/query", {"query": expr}).get("result") or []
    try:
        rows = [{"policy": r["metric"].get("policy", "?"), "source": r["metric"].get("source", ""),
                 "value": _num(r["value"][1])} for r in res]
    except (KeyError, IndexError, TypeError) as exc:
        raise MetricsError("unexpected answer from the metrics store") from exc
    return sorted(rows, key=lambda r: -(r["value"] or 0))


def _topk(expr: str, labels: tuple) -> list[dict]:
    res = _get("/api/v1/query", {"query": expr}).get("result") or []
    try:
        rows = [dict({k: r["metric"].get(k, "") for k in labels}, value=_num(r["value"][1])) for r in res]
    except (KeyError, IndexError, TypeError) as exc:
        raise MetricsError("unexpected answer from the metrics store") from exc
    return sorted(rows, key=lambda r: -(r["value"] or 0))


def top_interfaces(source_name: str | None, range_key: str, k: int = 10) -> list[dict]:
    """Busiest interfaces now (bits/s, in + out)."""
    _s, _e, step = plan(range_key)
    sel, w = selector(source_name), window(step)
    expr = ("topk(%d, (sum by (source, interface) (rate(obs_if_rx_bytes%s[%s])) + "
            "sum by (source, interface) (rate(obs_if_tx_bytes%s[%s]))) * 8)" % (k, sel, w, sel, w))
    return _topk(expr, ("source", "interface"))


def top_fw_bytes(source_name: str | None, range_key: str, k: int = 10) -> list[dict]:
    """Firewall policies by bytes moved over the whole range."""
    span = RANGES.get(range_key, RANGES[DEFAULT_RANGE])
    expr = "topk(%d, sum by (source, policy) (increase(obs_fwpolicy_bytes%s[%ds])))" % (
        k, selector(source_name), span)
    return _topk(expr, ("source", "policy"))


def stats(points: list) -> dict:
    """min / avg / max / p95 / last over the non-missing values of one series."""
    vals = [v for _t, v in points if v is not None]
    if not vals:
        return {"n": 0, "min": None, "avg": None, "max": None, "p95": None, "last": None}
    s = sorted(vals)
    p95 = s[min(len(s) - 1, int(round(0.95 * (len(s) - 1))))]
    return {"n": len(vals), "min": s[0], "avg": sum(vals) / len(vals), "max": s[-1], "p95": p95, "last": vals[-1]}
