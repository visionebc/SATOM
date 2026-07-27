"""Deep monitor parsers and graders.

These are the network-free layers on purpose: all four appliances were
unreachable when this feature was written, so anything that can only be
exercised against a live box is untested code. Every rule the UI shows a colour
for is asserted here.
"""
from __future__ import annotations

import pytest

from app.services import deep_monitor as dm


# --------------------------------------------------------------------------
# `diagnose system top` parsing
# --------------------------------------------------------------------------

# Captured VERBATIM from fw6 (FortiWeb 7.6) on 2026-07-27 — a second proxyd
# worker line was added to exercise multi-worker aggregation. Do not "tidy" the
# spacing: the column alignment and the decimal-less "100% idle" are the exact
# shapes the parser has to survive.
TOP_SAMPLE = """Mem: 2274272K used, 1542012K free, 18004K shrd, 12380K buff, 263320K cached
CPU:  0.0% usr  0.0% sys  0.0% nic  100% idle  0.0% io  0.0% irq  0.0% sirq
Load average: 1.33 1.04 0.65 1/367 23435
  PID  PPID USER     STAT   VSZ %VSZ CPU %CPU COMMAND
 3460     1 root     S    2232m 59.7   0  0.0 /bin/proxyd
 3461     1 root     S     512m 13.7   0  0.0 /bin/proxyd
 3542     1 root     S    1628m 43.5   0  0.0 /bin/filebeat -c /data/etc/filebeat/filebeat.yml
 3428     1 root     S     998m 26.7   0  0.0 /bin/node /node-scripts/index.js > /dev/null 2>&1
 3462  3429 root     S     453m 12.1   0  0.0 /bin/mysqld --defaults-file=/data/etc/mysql/my-fortiweb.cnf
"""

# The pre-7.6 / FortiOS-style layout the fallback branch must still read.
TOP_LEGACY = """Run Time:  4 days, 2 hours and 11 minutes
1U, 0N, 3S, 95I, 0WA, 0HI, 1SI, 0ST; 7962T, 3110F
        proxyd      3120      S       2.4     3.1
       httpsd        981      S       0.3     1.4
"""


def test_parse_top_reads_busybox_processes_and_summary():
    out = dm.parse_top(TOP_SAMPLE)
    assert out["parsed"] is True
    assert len(out["processes"]) == 5
    s = out["summary"]
    assert s["cpu_idle"] == 100          # "100% idle" — no decimal point
    assert s["cpu_busy"] == 0.0
    assert s["mem_total_mb"] == pytest.approx(3726.8, abs=1.0)
    assert s["mem_used_pct"] == pytest.approx(59.6, abs=0.5)
    assert out["load"] == "1.33 1.04 0.65"


def test_parse_top_takes_basename_of_the_command_path():
    """COMMAND is a full path with arguments — the operator types 'proxyd'."""
    names = [p["name"] for p in dm.parse_top(TOP_SAMPLE)["processes"]]
    assert names == ["proxyd", "proxyd", "filebeat", "node", "mysqld"]


def test_parse_top_reads_vsz_suffix():
    p = dm.parse_top(TOP_SAMPLE)["processes"][0]
    assert p["vsz_mb"] == pytest.approx(2232)
    assert p["cmd"] == "/bin/proxyd"


def test_parse_top_flags_per_process_cpu_as_unreliable():
    """BusyBox top's first iteration reports 0.0% CPU for every process, so the
    grader must not threshold on it. Verified live: a loaded box still printed
    0.0 on every row."""
    out = dm.parse_top(TOP_SAMPLE)
    assert out["cpu_per_process_reliable"] is False
    assert all(p["cpu"] == 0.0 for p in out["processes"])


def test_parse_top_falls_back_to_the_fortios_layout():
    out = dm.parse_top(TOP_LEGACY)
    assert out["parsed"] is True
    assert out["cpu_per_process_reliable"] is True
    assert [p["name"] for p in out["processes"]] == ["proxyd", "httpsd"]
    assert out["summary"]["mem_total_mb"] == 7962


def test_parse_top_marks_unparseable_output():
    """A firmware that answers something else must read as an ERROR, never as
    'zero workers' — that would look identical to a dead daemon. This is the
    literal reply FortiADC gives to the command."""
    out = dm.parse_top("Parsing error at 'system'. err=1\n"
                       "Command fail. Return code is -284 (CLI parsing error.)")
    assert out["parsed"] is False
    assert out["processes"] == []


def test_select_process_aggregates_every_worker():
    agg = dm.select_process(dm.parse_top(TOP_SAMPLE), "proxyd")
    assert agg["count"] == 2
    assert agg["mem"] == pytest.approx(73.4)
    assert agg["vsz_mb"] == pytest.approx(2744)
    assert agg["pids"] == [3460, 3461]
    assert agg["pid_fingerprint"]


def test_select_process_matches_on_basename():
    assert dm.select_process(dm.parse_top(TOP_SAMPLE), "/bin/proxyd")["count"] == 2


def test_select_process_absent_daemon():
    agg = dm.select_process(dm.parse_top(TOP_SAMPLE), "nosuchd")
    assert agg["count"] == 0 and agg["pid_fingerprint"] == ""


def test_classify_proxyd_absent_is_critical():
    parsed = dm.parse_top(TOP_SAMPLE)
    agg = dm.select_process(parsed, "nosuchd")
    st, detail = dm.classify_proxyd(agg, parsed, "", memory=parsed["summary"])
    assert st == "crit" and "NOT running" in detail


def test_classify_proxyd_unparseable_is_error_not_crit():
    parsed = dm.parse_top("garbage")
    agg = dm.select_process(parsed, "proxyd")
    st, detail = dm.classify_proxyd(agg, parsed, "", memory=parsed["summary"])
    assert st == "error" and "parse" in detail


def test_classify_proxyd_pid_change_is_a_restart():
    parsed = dm.parse_top(TOP_SAMPLE)
    agg = dm.select_process(parsed, "proxyd")
    st, detail = dm.classify_proxyd(agg, parsed, "deadbeef",
                                    memory=parsed["summary"])
    assert st == "warn" and "restarted" in detail
    # same fingerprint -> healthy
    st2, _ = dm.classify_proxyd(agg, parsed, agg["pid_fingerprint"],
                                memory=parsed["summary"])
    assert st2 == "ok"


def test_parse_top_reports_memory_consumed_in_megabytes():
    """The `Mem:` header is the only honest consumption figure in this output."""
    s = dm.parse_top(TOP_SAMPLE)["summary"]
    assert s["mem_used_mb"] == pytest.approx(2221.0, abs=1.0)
    assert s["mem_free_mb"] == pytest.approx(1505.9, abs=1.0)
    # used + free must reconstruct the total, or the two numbers on screen
    # would not describe the same machine.
    assert s["mem_used_mb"] + s["mem_free_mb"] == pytest.approx(s["mem_total_mb"], abs=0.2)


def test_proxyd_reports_used_and_free_never_the_daemon_vsz():
    """%VSZ is VIRTUAL size and is not memory consumed.

    Live proof from fw6: the eight largest processes report 240 % of RAM
    between them, because every shared mapping is counted once per process. A
    figure that can exceed 100 % must never be labelled 'memory used'.
    """
    parsed = dm.parse_top(TOP_SAMPLE)
    assert sum(p["mem"] for p in parsed["processes"]) > 100.0

    agg = dm.select_process(parsed, "proxyd")
    assert agg["mem"] == pytest.approx(73.4)          # %VSZ, still in the payload
    st, detail = dm.classify_proxyd(agg, parsed, agg["pid_fingerprint"],
                                    memory=parsed["summary"])
    assert st == "ok"
    assert "2,221 MB used" in detail and "1,506 MB free" in detail
    assert "73.4" not in detail                       # the virtual share is not shown
    assert "%" not in detail                          # nor any other percentage
    assert "2 workers" in detail


def test_classify_proxyd_grades_only_the_daemon():
    """Box CPU and box RAM live in their own probes. A proxyd row that graded
    them too would re-merge exactly what was split apart."""
    parsed = dm.parse_top(TOP_SAMPLE.replace("100% idle", "6.0% idle"))
    agg = dm.select_process(parsed, "proxyd")
    assert agg["cpu"] == 0.0            # BusyBox per-process CPU: never usable
    st, detail = dm.classify_proxyd(agg, parsed, agg["pid_fingerprint"],
                                    memory=parsed["summary"])
    assert st == "ok"
    assert "box CPU" not in detail and "box mem" not in detail


def test_classify_proxyd_says_so_when_the_mem_header_is_missing():
    """Silence about memory must read as 'unreadable', never as zero."""
    raw = "\n".join(l for l in TOP_SAMPLE.splitlines() if not l.startswith("Mem:"))
    parsed = dm.parse_top(raw)
    agg = dm.select_process(parsed, "proxyd")
    st, detail = dm.classify_proxyd(agg, parsed, agg["pid_fingerprint"],
                                    memory=parsed["summary"])
    assert st == "ok" and "memory unreadable" in detail


def test_fmt_memory_is_empty_without_both_halves():
    assert dm.fmt_memory({}) == ""
    assert dm.fmt_memory({"mem_used_mb": 10}) == ""
    assert dm.fmt_memory({"mem_used_mb": 10, "mem_free_mb": 5}) == \
        "10 MB used · 5 MB free"


# --------------------------------------------------------------------------
# interface fingerprint / drift
# --------------------------------------------------------------------------

IFACES = [
    {"name": "port1", "ip_address": "192.0.2.80/24", "status": "up", "mtu": "1500"},
    {"name": "port2", "ip_address": "", "status": "down"},
]


def test_fingerprint_is_order_independent():
    a, _ = dm.iface_rows_fingerprint(IFACES)
    b, _ = dm.iface_rows_fingerprint(list(reversed(IFACES)))
    assert a == b


def test_fingerprint_ignores_cosmetic_fields():
    """An MTU or description edit must not read as 'the network moved'."""
    other = [dict(IFACES[0], mtu="9000", description="uplink"), IFACES[1]]
    assert dm.iface_rows_fingerprint(IFACES)[0] == dm.iface_rows_fingerprint(other)[0]


def test_fingerprint_changes_when_ip_changes():
    moved = [dict(IFACES[0], ip_address="192.0.2.99/24"), IFACES[1]]
    assert dm.iface_rows_fingerprint(IFACES)[0] != dm.iface_rows_fingerprint(moved)[0]


def test_diff_ifaces_reports_ip_status_and_membership():
    _, cur = dm.iface_rows_fingerprint(
        [dict(IFACES[0], ip_address="192.0.2.99/24"),
         {"name": "port3", "ip_address": "192.168.1.1/24", "status": "up"}])
    _, prev = dm.iface_rows_fingerprint(IFACES)
    changes = dm.diff_ifaces(prev, cur)
    joined = " | ".join(changes)
    assert "port1: IP" in joined
    assert "port2" in joined and "disappeared" in joined
    assert "port3: new" in joined


def test_classify_interface_ip_move_is_critical():
    fp_new, cur = dm.iface_rows_fingerprint(
        [dict(IFACES[0], ip_address="192.0.2.99/24"), IFACES[1]])
    fp_old, prev = dm.iface_rows_fingerprint(IFACES)
    st, detail = dm.classify_interface(fp_new, fp_old, cur, prev,
                                       cache_age_h=1.0, stale_after_h=6)
    assert st == "crit" and "CHANGED" in detail


def test_classify_interface_steady_state_is_ok():
    fp, cur = dm.iface_rows_fingerprint(IFACES)
    st, detail = dm.classify_interface(fp, fp, cur, cur,
                                       cache_age_h=1.0, stale_after_h=6)
    # port2 is administratively down -> warn, not ok; that is intentional.
    assert st == "warn" and "down: port2" in detail


def test_classify_interface_stale_harvest_warns():
    fp, cur = dm.iface_rows_fingerprint([IFACES[0]])
    st, detail = dm.classify_interface(fp, fp, cur, cur,
                                       cache_age_h=48.0, stale_after_h=6)
    assert st == "warn" and "stale" in detail


def test_parse_ports_accepts_the_form_encodings():
    assert dm.parse_ports("") == []
    assert dm.parse_ports(None) == []
    assert dm.parse_ports("port1,port2") == ["port1", "port2"]
    assert dm.parse_ports(" port1 ; port2 \n port3 ") == ["port1", "port2", "port3"]


def test_select_ports_empty_selection_means_every_port():
    rows = [{"name": "port1"}, {"name": "port2"}]
    kept, missing = dm.select_ports(rows, [])
    assert len(kept) == 2 and missing == []


def test_select_ports_filters_and_reports_what_vanished():
    rows = [{"name": "port1"}, {"name": "port2"}]
    kept, missing = dm.select_ports(rows, ["PORT1", "port9"])
    assert [r["name"] for r in kept] == ["port1"]
    assert missing == ["port9"]                 # never silently dropped


def test_classify_interface_missing_watched_port_is_critical():
    """A port the operator explicitly selected disappearing from the harvest is
    the loudest drift there is — it must not degrade to 'fewer interfaces'."""
    st, detail = dm.classify_interface("a", "a", [{"name": "port1", "ip": "192.0.2.1",
                                                   "status": "up"}], [],
                                       cache_age_h=0.1, stale_after_h=6,
                                       missing=["port9"])
    assert st == "crit" and "port9" in detail


def test_classify_interface_empty_cache_is_error():
    st, detail = dm.classify_interface("", "", [], [],
                                       cache_age_h=None, stale_after_h=6)
    assert st == "error" and "device sync" in detail


# --------------------------------------------------------------------------
# HTTPS grading
# --------------------------------------------------------------------------

def test_classify_https_healthy():
    st, detail = dm.classify_https({"status": 200, "elapsed_ms": 120},
                                   expect_status=0, warn_ms=2000,
                                   tls_days=300, tls_warn_days=21)
    assert st == "ok" and "HTTP 200" in detail and "TLS 300d" in detail


def test_classify_https_error_status_is_critical():
    st, _ = dm.classify_https({"status": 502, "elapsed_ms": 30},
                              expect_status=0, warn_ms=0,
                              tls_days=None, tls_warn_days=21)
    assert st == "crit"


def test_classify_https_expected_status_is_honoured():
    """A policy that legitimately answers 302 must be gradeable as healthy."""
    st, _ = dm.classify_https({"status": 302, "elapsed_ms": 30},
                              expect_status=302, warn_ms=0,
                              tls_days=None, tls_warn_days=21)
    assert st == "ok"
    st2, _ = dm.classify_https({"status": 200, "elapsed_ms": 30},
                               expect_status=302, warn_ms=0,
                               tls_days=None, tls_warn_days=21)
    assert st2 == "crit"


def test_classify_https_unreachable():
    st, detail = dm.classify_https({"error": "connection refused"},
                                   expect_status=0, warn_ms=0,
                                   tls_days=None, tls_warn_days=21)
    assert st == "crit" and "unreachable" in detail


def test_classify_https_slow_and_expiring_are_warnings():
    st, _ = dm.classify_https({"status": 200, "elapsed_ms": 5000},
                              expect_status=0, warn_ms=2000,
                              tls_days=None, tls_warn_days=21)
    assert st == "warn"
    st2, _ = dm.classify_https({"status": 200, "elapsed_ms": 10},
                               expect_status=0, warn_ms=2000,
                               tls_days=5, tls_warn_days=21)
    assert st2 == "warn"


def test_classify_https_expired_cert_is_critical():
    st, detail = dm.classify_https({"status": 200, "elapsed_ms": 10},
                                   expect_status=0, warn_ms=0,
                                   tls_days=-3, tls_warn_days=21)
    assert st == "crit" and "EXPIRED" in detail


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

@pytest.mark.parametrize("url,expect", [
    ("https://192.0.2.80/", ("https", "192.0.2.80", 443)),
    ("https://192.0.2.80:8443/x", ("https", "192.0.2.80", 8443)),
    ("http://host.example", ("http", "host.example", 80)),
    ("http://host.example:8080/a/b", ("http", "host.example", 8080)),
    ("https://[2001:db8::1]:8443/", ("https", "2001:db8::1", 8443)),
])
def test_split_url(url, expect):
    assert dm._split_url(url) == expect


PERF_SAMPLE = """CPU states:    5% used, 95% idle
Memory states: 52% used
Up:            0 days,  0 hours,  18 minutes.
"""


def test_parse_performance_is_the_authoritative_box_reading():
    out = dm.parse_performance(PERF_SAMPLE)
    assert out["cpu_busy"] == 5.0
    assert out["cpu_idle"] == 95.0
    assert out["mem_used_pct"] == 52.0
    assert out["uptime"] == "0 days,  0 hours,  18 minutes"


def test_parse_performance_tolerates_missing_command():
    assert dm.parse_performance("Unknown action 0") == {}


# FortiADC answers the same command with different wording — captured live
# from fadc (2026-07-28). One parser has to read both or the CPU and memory
# probes silently produce nothing on half the fleet.
PERF_SAMPLE_ADC = """CPU usage:     2% used, 98% idle
Memory usage: 62% used
Up:           14 days,  3 hours,  2 minutes.
"""


def test_parse_performance_reads_the_fortiadc_wording_too():
    out = dm.parse_performance(PERF_SAMPLE_ADC)
    assert out["cpu_busy"] == 2.0
    assert out["cpu_idle"] == 98.0
    assert out["mem_used_pct"] == 62.0


def test_perf_is_the_source_for_the_box_metrics_not_top():
    """`diagnose system top`'s CPU line swung 100/100/90.9/0 %idle across four
    consecutive reads of an IDLE fw6. `get system performance` said 5% used.
    The box probes read performance; top is never their source."""
    top = dm.parse_top(TOP_SAMPLE.replace("100% idle", "0.0% idle"))
    assert top["summary"]["cpu_busy"] == 100.0          # what top claimed
    perf = dm.parse_performance(PERF_SAMPLE)
    assert perf["cpu_busy"] == 5.0                      # what is true
    st, detail = dm.classify_box("cpu", perf, warn_pct=80, crit_pct=95)
    assert st == "ok" and "CPU 5.0%" in detail


def test_classify_box_two_levels():
    st, detail = dm.classify_box("cpu", {"cpu_busy": 84.0, "cpu_idle": 16.0},
                                 warn_pct=80, crit_pct=95)
    assert st == "warn" and "warning threshold" in detail
    st, detail = dm.classify_box("cpu", {"cpu_busy": 97.0},
                                 warn_pct=80, crit_pct=95)
    assert st == "crit" and "critical threshold" in detail
    st, _ = dm.classify_box("memory", {"mem_used_pct": 62.0},
                            warn_pct=80, crit_pct=95)
    assert st == "ok"


def test_classify_box_zero_threshold_disables_that_level():
    st, _ = dm.classify_box("cpu", {"cpu_busy": 99.0}, warn_pct=0, crit_pct=0)
    assert st == "ok"


def test_classify_box_missing_reading_is_error_not_zero():
    """A firmware that does not answer the command must never be graded as 0%
    load — that is a fabricated healthy reading."""
    st, detail = dm.classify_box("memory", dm.parse_performance("Unknown action"),
                                 warn_pct=80, crit_pct=95)
    assert st == "error" and "no memory reading" in detail


def test_classify_box_rejects_an_unknown_metric():
    st, _ = dm.classify_box("disk", {"cpu_busy": 1.0}, warn_pct=80, crit_pct=95)
    assert st == "error"


def test_vsz_units():
    assert dm._vsz_mb("2232m") == pytest.approx(2232)
    assert dm._vsz_mb("2g") == pytest.approx(2048)
    assert dm._vsz_mb("1024k") == pytest.approx(1)
    assert dm._vsz_mb("2048") == pytest.approx(2)       # bare number is KiB
    assert dm._vsz_mb("") is None


def test_worst_orders_by_severity():
    assert dm.worst(["ok", "warn", "crit"]) == "crit"
    assert dm.worst(["ok", "error"]) == "error"
    assert dm.worst(["ok", "ok"]) == "ok"
    assert dm.worst([]) == "unknown"


def test_kind_labels_cover_every_kind():
    assert set(dm.KINDS) == set(dm.KIND_LABEL)


# --------------------------------------------------------------------------
# Rollups — the storage model behind the 7 / 30 day charts
# --------------------------------------------------------------------------

from datetime import datetime, timedelta  # noqa: E402


def _s(minute, status="ok", v=None, v2=None, fp=""):
    return {"ts": datetime(2026, 7, 27, 10, minute), "status": status,
            "value_num": v, "value2_num": v2, "fingerprint": fp}


def test_bucket_key_floors_to_hour_and_day():
    ts = datetime(2026, 7, 27, 14, 37, 12)
    assert dm.bucket_key(ts, "hour") == datetime(2026, 7, 27, 14, 0)
    assert dm.bucket_key(ts, "day") == datetime(2026, 7, 27, 0, 0)


def test_aggregate_samples_keeps_both_extremes():
    """An average hides the spike. The spike is the reason anyone opens this."""
    agg = dm.aggregate_samples([_s(0, v=10), _s(5, v=90), _s(10, v=20)])
    assert (agg["v_min"], agg["v_max"]) == (10, 90)
    assert agg["v_avg"] == pytest.approx(40.0)
    assert agg["samples"] == 3 and agg["ok_n"] == 3


def test_aggregate_samples_counts_statuses_and_ignores_missing_values():
    agg = dm.aggregate_samples([
        _s(0, "ok", v=1), _s(5, "warn"), _s(10, "crit", v=3), _s(15, "error"),
    ])
    assert (agg["ok_n"], agg["warn_n"], agg["crit_n"], agg["error_n"]) == (1, 1, 1, 1)
    assert agg["v_min"] == 1 and agg["v_max"] == 3      # the two Nones skipped
    assert agg["samples"] == 4


def test_aggregate_samples_counts_fingerprint_changes():
    """Three PID sets in an hour is three restarts, and it survives the rollup
    even after the raw samples are pruned."""
    agg = dm.aggregate_samples([_s(0, fp="a"), _s(5, fp="a"), _s(10, fp="b"),
                                _s(15, fp="c")])
    assert agg["changes"] == 2


def test_aggregate_rollups_weights_the_average_by_sample_count():
    """A mean of means would let an hour with one reading outvote a full one."""
    hours = [
        {"samples": 12, "ok_n": 12, "warn_n": 0, "crit_n": 0, "error_n": 0,
         "changes": 0, "v_min": 10, "v_avg": 10, "v_max": 10,
         "v2_min": None, "v2_avg": None, "v2_max": None},
        {"samples": 1, "ok_n": 0, "warn_n": 1, "crit_n": 0, "error_n": 0,
         "changes": 2, "v_min": 100, "v_avg": 100, "v_max": 100,
         "v2_min": None, "v2_avg": None, "v2_max": None},
    ]
    agg = dm.aggregate_rollups(hours)
    assert agg["samples"] == 13 and agg["warn_n"] == 1 and agg["changes"] == 2
    assert agg["v_min"] == 10 and agg["v_max"] == 100
    assert agg["v_avg"] == pytest.approx((10 * 12 + 100) / 13, abs=0.01)
    assert agg["v_avg"] < 55                # a naive mean would have said 55


def test_pick_source_by_span():
    now = datetime(2026, 7, 27, 12, 0)
    old = now - timedelta(days=400)
    assert dm.pick_source(now - timedelta(hours=6), now, old) == "raw"
    assert dm.pick_source(now - timedelta(days=7), now, old) == "hour"
    assert dm.pick_source(now - timedelta(days=200), now, old) == "day"


def test_pick_source_falls_back_when_raw_does_not_reach_back():
    """A one-minute probe holds ~8 h of raw at the default retention. Drawing a
    24 h chart from raw would show 8 h and look like the box went silent."""
    now = datetime(2026, 7, 27, 12, 0)
    shallow = now - timedelta(hours=8)
    deep = now - timedelta(days=20)
    assert dm.pick_source(now - timedelta(hours=24), now, shallow, deep) == "hour"
    assert dm.pick_source(now - timedelta(hours=4), now, shallow, deep) == "raw"


def test_pick_source_keeps_raw_when_buckets_hold_nothing_older():
    """A young probe's buckets were built from the samples still on disk.
    Downgrading there would coarsen the chart and label it an hourly average
    while showing the very same readings."""
    now = datetime(2026, 7, 27, 12, 0)
    young = now - timedelta(hours=2)
    assert dm.pick_source(now - timedelta(hours=24), now, young,
                          dm.bucket_key(young, "hour")) == "raw"
    assert dm.pick_source(now - timedelta(hours=24), now, young, None) == "raw"
    # ...but a 7-day window is still bucket territory, whatever raw holds.
    assert dm.pick_source(now - timedelta(days=7), now, young, young) == "hour"


def test_pick_source_with_no_samples_at_all():
    now = datetime(2026, 7, 27, 12, 0)
    assert dm.pick_source(now - timedelta(hours=6), now, None) == "raw"


def test_metric_meta_covers_every_kind():
    """An unlabelled axis is a lie waiting to happen: 2328 MB and 59.7 % look
    identical without one."""
    assert set(dm.METRIC_META) == set(dm.KINDS)
    assert dm.METRIC_META["proxyd"]["unit"] == "MB"
    assert dm.METRIC_META["cpu"]["unit"] == "%"


def test_rollup_horizons_are_bounded():
    assert dm.HOURLY_KEEP_DAYS <= 400 and dm.DAILY_KEEP_DAYS <= 3660
    assert dm.MAX_RANGE_DAYS <= dm.DAILY_KEEP_DAYS + 1
