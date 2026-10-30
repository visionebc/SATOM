"""Path Diagnostics — what the metrics store saw around a walk.

The ladder (:mod:`app.services.scout_ladder`) answers *which layer is broken*
from reads it makes now. This module answers the question the operator asks
next — *was the box or the object already struggling?* — from what the
collectors wrote to VictoriaMetrics over the same window. It never touches a
device: it reads the cache the Collector layer filled (NAF: Observability ->
Presentation), so it adds no load to a box that may be the one in trouble.

It does NOT change the verdict. A rung is a measurement; a deviation from a
seven-day average is context. Mixing them would make the ladder's FAULT depend
on a baseline nobody chose for that purpose.

Rules every caller relies on, each of which fails silently if broken:

* **A collector that failed is an ERROR, never an empty panel.** Collectors
  write ``satom_scrape_up 0`` when a scrape fails (``metrics_collect``); a
  missing graph would read as "quiet", which is the opposite of the truth.
* **A store that does not answer is an ERROR** with its own reason.
* **No series at all is said in words** ("not collected"), never painted as
  healthy: the appliance may simply have no scrape target.
* Label values go through :func:`vm_store.escape_label`; a policy name with a
  quote must not become a different query.
"""
from __future__ import annotations

from datetime import datetime, timezone

from . import vm_store

#: A reading counts as a deviation when it is this many times its seven-day
#: average (or this many times BELOW it, for metrics where a drop is the
#: symptom). Shown on the page next to every flag, so a reader can judge it.
DEVIATION_FACTOR = 2.0

#: Baseline span. The window itself is excluded (``offset``), so a fault that
#: started inside the window cannot raise its own baseline.
BASELINE = "7d"

#: (key, label, unit, direction). direction: "up" = higher is worse,
#: "down" = a drop is the symptom, "state" = 1 up / 0 down.
BOX_METRICS = (
    ("satom_box_cpu_pct", "CPU", "%", "up"),
    ("satom_box_mem_pct", "Memory", "%", "up"),
    ("satom_box_sessions", "Sessions (box)", "", "up"),
    ("satom_box_conn_per_sec", "New connections/s (box)", "/s", "up"),
)
POLICY_METRICS = (
    ("satom_policy_up", "Object status", "", "state"),
    ("satom_policy_throughput_bps", "Throughput", "bit/s", "down"),
    ("satom_policy_sessions", "Sessions", "", "up"),
    ("satom_policy_conn_per_sec", "New connections/s", "/s", "up"),
    ("satom_policy_transactions_window", "Transactions", "", "down"),
    ("satom_policy_client_rtt_ms", "Client RTT", "ms", "up"),
    ("satom_policy_server_rtt_ms", "Server RTT", "ms", "up"),
    ("satom_policy_app_response_ms", "Application response", "ms", "up"),
)


def _sel(name: str, labels: dict) -> str:
    inner = ",".join('%s="%s"' % (k, vm_store.escape_label(v))
                     for k, v in labels.items())
    return "%s{%s}" % (name, inner)


class StoreDown(RuntimeError):
    pass


def _scalar_rows(expr: str, at: float) -> list[tuple[dict, float]]:
    """Instant query -> [(labels, value)]. Raises :class:`StoreDown` when the
    store refused or did not answer: that is a fact to report, not a 0."""
    out = vm_store.query(expr, ts=at)
    if out.get("status") != "success":
        raise StoreDown(str(out.get("error") or "no answer from the metrics store"))
    rows = []
    for r in (out.get("data") or {}).get("result") or []:
        try:
            rows.append((r.get("metric") or {}, float(r["value"][1])))
        except (KeyError, IndexError, TypeError, ValueError):
            continue
    return rows


def _one(expr: str, at: float):
    rows = _scalar_rows(expr, at)
    return rows[0][1] if rows else None


def _flag(direction: str, now, base) -> str:
    if now is None:
        return ""
    if direction == "state":
        return "down" if now < 0.5 else ""
    if base is None or base <= 0:
        return ""
    if direction == "up" and now >= base * DEVIATION_FACTOR:
        return "above"
    if direction == "down" and now <= base / DEVIATION_FACTOR:
        return "below"
    return ""


def _row(name, label, unit, direction, labels, w, at) -> dict:
    sel = _sel(name, labels)
    now = _one("last_over_time(%s[%dm])" % (sel, w), at)
    avg = _one("avg_over_time(%s[%dm])" % (sel, w), at)
    base = _one("avg_over_time(%s[%s] offset %dm)" % (sel, BASELINE, w), at)
    flag = _flag(direction, now, base)
    return {"key": name, "label": label, "unit": unit, "direction": direction,
            "now": now, "avg": avg, "baseline": base, "flag": flag}


def _flag_text(group_title: str, r: dict) -> str:
    if r["flag"] == "down":
        return "%s: %s reported DOWN" % (group_title, r["label"])
    word = "above" if r["flag"] == "above" else "below"
    return ("%s: %s %s is %s %g× its %s average (%s)"
            % (group_title, r["label"], _fmt(r["now"], r["unit"]), word,
               DEVIATION_FACTOR, BASELINE, _fmt(r["baseline"], r["unit"])))


def _fmt(v, unit: str) -> str:
    if v is None:
        return "—"
    if unit == "bit/s":
        for div, suf in ((1e9, "Gbit/s"), (1e6, "Mbit/s"), (1e3, "kbit/s")):
            if abs(v) >= div:
                return "%.1f %s" % (v / div, suf)
        return "%.0f bit/s" % v
    s = ("%.1f" % v).rstrip("0").rstrip(".")
    return (s + " " + unit).strip() if unit not in ("%",) else s + "%"


def context(device: str, policy: str, window_minutes: int,
            at: datetime | None = None) -> dict:
    """Everything the store holds about ``device``/``policy`` for the window
    ending at ``at``. Never raises: a failure is the ``error`` status with its
    reason, because this panel sits under a verdict and must not take it down."""
    at = at or datetime.now(timezone.utc)
    ts = at.timestamp()
    w = max(1, int(window_minutes or 15))
    out = {"status": "ok", "detail": "", "device": device, "policy": policy,
           "window_minutes": w, "at": at.isoformat(timespec="seconds"),
           "baseline": BASELINE, "factor": DEVIATION_FACTOR,
           "collectors": [], "groups": [], "flags": []}
    try:
        scr = _scalar_rows("last_over_time(%s[%dm])"
                           % (_sel("satom_scrape_up", {"device": device}), w), ts)
        scr_min = {(m.get("collector") or ""): v for m, v in _scalar_rows(
            "min_over_time(%s[%dm])"
            % (_sel("satom_scrape_up", {"device": device}), w), ts)}
        for m, v in sorted(scr, key=lambda mv: mv[0].get("collector") or ""):
            c = m.get("collector") or ""
            out["collectors"].append({"collector": c, "up": v >= 0.5,
                                      "failed_in_window": scr_min.get(c, v) < 0.5})

        groups = (
            ("box", "Appliance %s" % device, BOX_METRICS, {"device": device}),
            ("policy", "Object %s" % policy, POLICY_METRICS,
             {"device": device, "policy": policy}),
        )
        for key, title, metrics, labels in groups:
            rows = [_row(n, lab, u, d, labels, w, ts) for n, lab, u, d in metrics]
            have = [r for r in rows if r["now"] is not None or r["avg"] is not None]
            note = "" if have else (
                "No series in the window — the collector does not report this %s."
                % ("appliance" if key == "box" else "object"))
            out["groups"].append({"key": key, "title": title, "rows": have,
                                  "note": note})
            out["flags"] += [_flag_text(title, r) for r in have if r["flag"]]

        iface = []
        for direction, name in (("rx", "satom_iface_rx_bytes_total"),
                                ("tx", "satom_iface_tx_bytes_total")):
            for m, v in _scalar_rows(
                    "rate(%s[%dm]) * 8" % (_sel(name, {"device": device}), w), ts):
                iface.append({"iface": m.get("iface") or "?", "dir": direction,
                              "bps": v})
        iface.sort(key=lambda r: (r["iface"], r["dir"]))
        out["interfaces"] = iface
    except StoreDown as exc:
        out.update(status="error",
                   detail="The metrics store did not answer: %s" % exc)
        return out

    down = [c["collector"] for c in out["collectors"] if not c["up"]]
    flapped = [c["collector"] for c in out["collectors"]
               if c["up"] and c["failed_in_window"]]
    any_rows = any(g["rows"] for g in out["groups"]) or out.get("interfaces")
    if down:
        out.update(status="error",
                   detail="Collector(s) failing for %s: %s — the numbers below "
                          "stop where the collector stopped."
                          % (device, ", ".join(down)))
    elif not out["collectors"] and not any_rows:
        out.update(status="not_collected",
                   detail="SATOM collects no metrics for %s (no scrape target "
                          "under Monitoring → Collection). This is not health."
                          % device)
    elif flapped:
        out["detail"] = ("Collector(s) failed at least once in the window: %s."
                         % ", ".join(flapped))
    return out


def fmt(v, unit: str) -> str:
    """Template helper: the same formatting the flag sentences use."""
    return _fmt(v, unit)
