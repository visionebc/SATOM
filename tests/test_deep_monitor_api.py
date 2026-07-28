"""REST monitor API probes: parsers, graders and the product gate.

Every payload below is captured VERBATIM from a live appliance
(fortiweb08, FortiWeb-KVM 7.6.8 build1128, 2026-07-28) — including the parts
that look like mistakes and are not:

  * ``policytraffic`` returns its samples as **strings**, not numbers.
  * The same endpoint returns a bare LIST for the aggregate pseudo-policies and
    a DICT for a named policy.
  * ``policystatus`` carries two different identifiers, ``id`` (display) and
    ``policy`` (the appliance's runtime handle).

The network layer is deliberately absent here: these are the pure functions, so
the graders stay testable with every appliance powered off.
"""
from __future__ import annotations

import pytest

from app.services import deep_monitor as dm


# ---------------------------------------------------------------------------
# system/status.systemresource
# ---------------------------------------------------------------------------

RESOURCE = {"cpu": 5, "mem": 51, "logDisk": "Available", "dbStatus": "Available",
            "diskUsage": 1, "sessionCount": 0, "connCntPerSec": 0}


def test_parse_system_resource_maps_every_gauge():
    box = dm.parse_system_resource(RESOURCE)
    assert box == {"cpu_pct": 5, "mem_pct": 51, "disk_pct": 1, "sessions": 0,
                   "conn_per_sec": 0, "log_disk": "Available",
                   "db_status": "Available"}


def test_parse_system_resource_survives_a_non_dict():
    assert dm.parse_system_resource(None) == {}
    assert dm.parse_system_resource([1, 2]) == {}


def test_sessions_ok_below_threshold():
    box = dm.parse_system_resource(dict(RESOURCE, sessionCount=100))
    status, detail = dm.classify_sessions(box, warn_num=500, crit_num=900)
    assert status == "ok"
    assert "100 sessions" in detail


@pytest.mark.parametrize("count,expected", [(500, "warn"), (899, "warn"),
                                            (900, "crit"), (5000, "crit")])
def test_sessions_thresholds_are_inclusive(count, expected):
    box = dm.parse_system_resource(dict(RESOURCE, sessionCount=count))
    status, _ = dm.classify_sessions(box, warn_num=500, crit_num=900)
    assert status == expected


def test_sessions_zero_threshold_disables_the_level():
    box = dm.parse_system_resource(dict(RESOURCE, sessionCount=10 ** 6))
    assert dm.classify_sessions(box, warn_num=0, crit_num=0)[0] == "ok"


def test_sessions_grades_the_log_disk_and_db_strings():
    """A full log disk is invisible in a session count, so it is graded too."""
    box = dm.parse_system_resource(dict(RESOURCE, logDisk="Not Available"))
    status, detail = dm.classify_sessions(box, warn_num=0, crit_num=0)
    assert status == "warn"
    assert "log disk Not Available" in detail


def test_sessions_no_data_is_an_error_not_ok():
    assert dm.classify_sessions({}, warn_num=0, crit_num=0)[0] == "error"


# ---------------------------------------------------------------------------
# policy/policystatus (+ .detail)
# ---------------------------------------------------------------------------

POLICY_ROWS = [
    {"_id": "pol-shop-main", "id": 1, "policy": 1488, "name": "pol-shop-main",
     "status": "disable", "protocol": "HTTP", "vserver": "192.0.2.90/32 ",
     "httpPort": "80", "mode": "Single Server/Server Pool", "sessionCount": 0,
     "connCntPerSec": 0, "client_rtt": 0, "server_rtt": 0,
     "app_response_time": 0},
    {"_id": "pol-shop-cr", "id": 2, "policy": 1489, "name": "pol-shop-cr",
     "status": "enable", "protocol": "HTTP", "vserver": "192.0.2.91/32 ",
     "httpPort": "80", "mode": "Single Server/Server Pool", "sessionCount": 12,
     "connCntPerSec": 3, "client_rtt": 4, "server_rtt": 9,
     "app_response_time": 21},
]

MEMBERS_UP = [
    {"id": 1, "pool": "pool-shop-web", "type": 1, "ipDomainName": "192.0.2.211",
     "port": 80, "healthCheckStatus": "N/A", "sessionCount": 6,
     "backupServer": 0, "status": 1, "server_rtt": 9, "app_response_time": 21},
    {"id": 2, "pool": "pool-shop-web", "type": 1, "ipDomainName": "192.0.2.212",
     "port": 80, "healthCheckStatus": "N/A", "sessionCount": 6,
     "backupServer": 0, "status": 1, "server_rtt": 9, "app_response_time": 21},
]


def _row(name="pol-shop-cr"):
    return next(r for r in dm.parse_policy_rows(POLICY_ROWS) if r["name"] == name)


def test_parse_policy_rows_keeps_the_runtime_handle_separate_from_the_id():
    rows = dm.parse_policy_rows(POLICY_ROWS)
    assert [r["handle"] for r in rows] == [1488, 1489]
    assert rows[1]["sessions"] == 12 and rows[1]["app_response_time"] == 21


def test_parse_policy_rows_ignores_junk_entries():
    assert dm.parse_policy_rows([None, "x", {}]) == [
        {"name": "", "handle": -1, "status": "", "protocol": "", "vserver": "",
         "port": "", "sessions": 0, "conn_per_sec": 0, "client_rtt": 0,
         "server_rtt": 0, "app_response_time": 0}]


def test_healthy_policy_is_ok():
    row, members = _row(), dm.parse_pool_members(MEMBERS_UP)
    fp = dm.policy_fingerprint(row, members)
    status, detail = dm.classify_policy_sessions(
        row, members, warn_num=0, crit_num=0, warn_ms=0,
        fingerprint=fp, prev_fingerprint=fp)
    assert status == "ok"
    assert "12 sessions" in detail and "2/2 backends up" in detail


def test_disabled_policy_is_warn_never_ok():
    """A policy admitting no traffic IS the outage; zero sessions is not health."""
    row = _row("pol-shop-main")
    status, detail = dm.classify_policy_sessions(
        row, [], warn_num=0, crit_num=0, warn_ms=0,
        fingerprint="a", prev_fingerprint="a")
    assert status == "warn"
    assert "policy disable" in detail


def test_all_backends_down_is_crit():
    members = dm.parse_pool_members(
        [dict(m, status=0) for m in MEMBERS_UP])
    status, detail = dm.classify_policy_sessions(
        _row(), members, warn_num=0, crit_num=0, warn_ms=0,
        fingerprint="a", prev_fingerprint="a")
    assert status == "crit"
    assert "ALL backends down" in detail


def test_some_backends_down_is_warn_and_names_them():
    members = dm.parse_pool_members(
        [MEMBERS_UP[0], dict(MEMBERS_UP[1], status=0)])
    status, detail = dm.classify_policy_sessions(
        _row(), members, warn_num=0, crit_num=0, warn_ms=0,
        fingerprint="a", prev_fingerprint="a")
    assert status == "warn"
    assert "192.0.2.212:80" in detail


def test_health_check_disable_counts_as_down():
    members = dm.parse_pool_members(
        [dict(m, healthCheckStatus="disable") for m in MEMBERS_UP])
    assert dm.classify_policy_sessions(
        _row(), members, warn_num=0, crit_num=0, warn_ms=0,
        fingerprint="a", prev_fingerprint="a")[0] == "crit"


def test_slow_app_response_warns():
    status, detail = dm.classify_policy_sessions(
        _row(), dm.parse_pool_members(MEMBERS_UP),
        warn_num=0, crit_num=0, warn_ms=20,
        fingerprint="a", prev_fingerprint="a")
    assert status == "warn"
    assert "app 21 ms" in detail


def test_fingerprint_change_is_an_event_even_while_healthy():
    row, members = _row(), dm.parse_pool_members(MEMBERS_UP)
    status, detail = dm.classify_policy_sessions(
        row, members, warn_num=0, crit_num=0, warn_ms=0,
        fingerprint="new", prev_fingerprint="old")
    assert status == "warn"
    assert "shape changed" in detail


def test_first_ever_sample_has_no_previous_and_must_not_warn():
    row, members = _row(), dm.parse_pool_members(MEMBERS_UP)
    assert dm.classify_policy_sessions(
        row, members, warn_num=0, crit_num=0, warn_ms=0,
        fingerprint="new", prev_fingerprint="")[0] == "ok"


def test_fingerprint_tracks_the_runtime_handle():
    """A reassigned policy handle registers even when nothing else moved."""
    row, members = _row(), dm.parse_pool_members(MEMBERS_UP)
    before = dm.policy_fingerprint(row, members)
    after = dm.policy_fingerprint(dict(row, handle=9999), members)
    assert before != after


def test_fingerprint_ignores_load_but_catches_backend_state():
    row, members = _row(), dm.parse_pool_members(MEMBERS_UP)
    base = dm.policy_fingerprint(row, members)
    assert dm.policy_fingerprint(dict(row, sessions=99999), members) == base
    flapped = dm.parse_pool_members([MEMBERS_UP[0], dict(MEMBERS_UP[1], status=0)])
    assert dm.policy_fingerprint(row, flapped) != base


def test_fingerprint_is_order_independent():
    row = _row()
    a = dm.policy_fingerprint(row, dm.parse_pool_members(MEMBERS_UP))
    b = dm.policy_fingerprint(row, dm.parse_pool_members(list(reversed(MEMBERS_UP))))
    assert a == b


def test_missing_policy_row_is_an_error():
    assert dm.classify_policy_sessions(
        {}, [], warn_num=0, crit_num=0, warn_ms=0,
        fingerprint="", prev_fingerprint="")[0] == "error"


# ---------------------------------------------------------------------------
# policy/policytraffic
# ---------------------------------------------------------------------------

def test_parse_traffic_accepts_the_bare_list_shape():
    """The aggregate pseudo-policies answer with a list, not a dict."""
    tr = dm.parse_traffic(["0", "125000", "0"])
    assert tr["bps"] == [0, 125000, 0]
    assert tr["cache_enabled"] is False and tr["cache_bps"] is None


def test_parse_traffic_accepts_the_dict_shape():
    tr = dm.parse_traffic({"throughput": ["10", "20"], "cache_enabled": False,
                           "cache_tp": ["1", "2"]})
    assert tr["bps"] == [10, 20]
    # cache_tp is present in the payload but must be ignored while disabled,
    # or the chart would draw a cache series the appliance is not serving.
    assert tr["cache_bps"] is None


def test_parse_traffic_reads_cache_series_when_enabled():
    tr = dm.parse_traffic({"throughput": ["10"], "cache_enabled": True,
                           "cache_tp": ["4"]})
    assert tr["cache_enabled"] is True and tr["cache_bps"] == [4]


def test_parse_traffic_rejects_an_unknown_shape():
    assert dm.parse_traffic("nope") == {}


def test_traffic_stats_converts_bytes_per_second_to_mbps():
    """125000 B/s * 8 = 1_000_000 bit/s = exactly 1 Mbps."""
    st = dm.traffic_stats([125000] * 4)
    assert st["avg_mbps"] == 1.0 and st["peak_mbps"] == 1.0
    assert st["samples"] == 4


def test_traffic_stats_keeps_the_peak_distinct_from_the_mean():
    st = dm.traffic_stats([0, 0, 0, 1250000])
    assert st["peak_mbps"] == 10.0
    assert st["avg_mbps"] == 2.5
    assert st["last_mbps"] == 10.0


def test_traffic_stats_on_an_empty_window():
    assert dm.traffic_stats([])["samples"] == 0


def test_throughput_grades_on_the_peak_not_the_average():
    """A burst that averages away is exactly what the alert is for."""
    st = dm.traffic_stats([0] * 59 + [1250000])   # avg 0.17 Mbps, peak 10
    assert dm.classify_throughput(st, warn_num=5, crit_num=50)[0] == "warn"
    assert dm.classify_throughput(st, warn_num=1, crit_num=5)[0] == "crit"


def test_throughput_empty_window_is_an_error():
    assert dm.classify_throughput(dm.traffic_stats([]),
                                  warn_num=0, crit_num=0)[0] == "error"


def test_fmt_mbps_switches_unit_below_one_megabit():
    assert dm.fmt_mbps(2.5) == "2.50 Mbps"
    assert dm.fmt_mbps(0.25) == "250 Kbps"


# ---------------------------------------------------------------------------
# system/status.httptransactions
# ---------------------------------------------------------------------------

TX_ROWS = [{"time": "23:41-23:51", "count": 0}, {"time": "23:51-00:01", "count": 7},
           {"time": "00:01-00:11", "count": 3}]


def test_parse_transactions_totals_and_peaks():
    tx = dm.parse_transactions(TX_ROWS)
    assert tx["total"] == 10 and tx["peak"] == 7 and tx["last"] == 3
    assert len(tx["buckets"]) == 3


def test_transactions_empty_is_an_error_not_idle():
    """The device answers `errcode 0` with no rows for an unknown policy name,
    so "no buckets" means misconfigured, not quiet."""
    assert dm.classify_transactions(dm.parse_transactions([]),
                                    warn_num=0, crit_num=0)[0] == "error"


def test_transactions_thresholds():
    tx = dm.parse_transactions(TX_ROWS)
    assert dm.classify_transactions(tx, warn_num=5, crit_num=50)[0] == "warn"
    assert dm.classify_transactions(tx, warn_num=1, crit_num=10)[0] == "crit"
    assert dm.classify_transactions(tx, warn_num=0, crit_num=0)[0] == "ok"


# ---------------------------------------------------------------------------
# Registry + product gate
# ---------------------------------------------------------------------------

def test_every_api_kind_is_registered_and_labelled():
    for k in dm.API_KINDS:
        assert k in dm.KINDS, f"{k} missing from KINDS"
        assert dm.KIND_LABEL.get(k), f"{k} has no label"
        assert dm.NUM_UNIT.get(k), f"{k} has no threshold unit"


def test_api_kinds_do_not_collide_with_the_box_metrics():
    assert not set(dm.API_KINDS) & set(dm.BOX_METRICS)


def test_total_http_is_a_recognised_aggregate():
    assert dm.TOTAL_HTTP in dm.TRAFFIC_AGGREGATES


class _Ap:
    def __init__(self, kind):
        self.kind = kind
        self.name = "x"


class _Probe:
    def __init__(self, kind, appliance):
        self.kind, self.appliance = kind, appliance
        self.timeout_s = 10


@pytest.mark.parametrize("product", ["fortiadc", "fortianalyzer", "", None])
def test_api_client_refuses_non_fortiweb_products(product):
    """FortiADC/FAZ expose different monitor paths; a shared client would have
    reported zeroes instead of saying it cannot measure this product."""
    client, err = dm._api_client(_Probe("sessions", _Ap(product)))
    assert client is None
    assert err["status"] == "error" and "fortiweb" in err["detail"]


def test_api_client_refuses_a_probe_with_no_device():
    client, err = dm._api_client(_Probe("sessions", None))
    assert client is None and "no device" in err["detail"]


def test_int_coercion_handles_the_string_payloads():
    assert dm._i("125000") == 125000
    assert dm._i(None) == 0 and dm._i("") == 0 and dm._i("x", 7) == 7

# ---------------------------------------------------------------------------
# The scheduled sweep's ok flag
# ---------------------------------------------------------------------------

def test_sweep_action_stays_ok_when_a_probe_is_critical(monkeypatch):
    """A critical FINDING is not a failed RUN.

    Regression guard: while `ok` was `worst in ("ok","unknown")`, one policy
    with every backend down pinned the scheduled action red until somebody
    fixed the backend — and made a real sweep crash look identical to a healthy
    sweep that found something. Both cost the operator the signal.
    """
    from app.services import scheduled_actions as sa
    from app.services import deep_monitor as dm

    monkeypatch.setattr(dm, "sweep", lambda **kw: {
        "ran": 3, "counts": {"ok": 2, "crit": 1}, "worst": "crit",
        "results": [{"status": "crit", "probe": "p", "detail": "ALL backends down"}],
    })
    out = sa._do_deep_monitor({}, dry_run=False)
    assert out["ok"] is True
    assert "worst: crit" in out["summary"]
    assert "ALL backends down" in out["log"]


def test_sweep_action_reports_the_worst_status_in_its_summary(monkeypatch):
    from app.services import scheduled_actions as sa
    from app.services import deep_monitor as dm

    monkeypatch.setattr(dm, "sweep", lambda **kw: {
        "ran": 1, "counts": {"ok": 1}, "worst": "ok", "results": []})
    out = sa._do_deep_monitor({}, dry_run=False)
    assert out["ok"] is True and "worst: ok" in out["summary"]
