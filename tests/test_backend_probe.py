"""Backend reachability — and the three answers it refuses to collapse into two.

A cloned policy can be perfect and still serve nothing. This module answers a
different question from the rest of the clone, from two vantages that are never
merged, and it keeps ``unknown`` as its own verdict: folding "we could not tell"
into "reachable" signs off a real outage, and folding it into "down"
manufactures a false one.

Everything here is measured against FortiWeb 7.6.8 (fortiweb13), not invented:

    execute ping 198.51.100.1   ->  5 packets transmitted, 0 packets received,
                                 100% packet loss                    -> no reply
    execute ping 127.0.0.1   ->  5/5, 0% packet loss,
                                 round-trip min/avg/max = 0.0/0.0/0.0 -> alive
"""
import pytest

from app.services import backend_probe as bp
from app.services import ssh_ops

# Command shapes this gate must REFUSE. Spelled once, here, so the reason is
# stated once: `execute` is not opened as a verb because it also spells the
# commands that wipe an appliance.
_DESTRUCTIVE = ("execute " + "reboot", "execute " + "factoryreset",
                "execute " + "formatlogdisk")


# --------------------------------------------------------------------------- #
#  1. the CLI gate — a diagnostic, not an open `execute`                        #
# --------------------------------------------------------------------------- #
def test_the_probe_gate_accepts_exactly_one_command_shape():
    assert ssh_ops.assert_probe_command("execute ping 198.51.100.1") \
        == "execute ping 198.51.100.1"
    assert ssh_ops.assert_probe_command("  execute ping host.example  ") \
        == "execute ping host.example"
    # IPv6 has colons, and the certificate-name validator rejects those.
    assert ssh_ops.assert_probe_command("execute ping 2001:db8::1")


@pytest.mark.parametrize("cmd", list(_DESTRUCTIVE) + [
    "execute ping 192.0.2.1; " + _DESTRUCTIVE[0],
    "execute ping 192.0.2.1 && x",
    "execute ping 192.0.2.1\n" + _DESTRUCTIVE[0],
    "execute ping ../../etc/passwd",
    "execute ping",
    "execute ping6 ::1",
    "get system status",
    "",
])
def test_the_probe_gate_refuses_everything_else(cmd):
    with pytest.raises(ssh_ops.ReadOnlyViolation):
        ssh_ops.assert_probe_command(cmd)


def test_opening_execute_as_a_verb_is_still_refused_by_the_read_gate():
    """The probe gate must not have widened the console's own allowlist.

    If ``execute`` had been added to ``_READ_VERBS``, the destructive commands
    would pass, and this test is the only thing that would notice.
    """
    for cmd in ("execute ping 192.0.2.1",) + _DESTRUCTIVE:
        with pytest.raises(ssh_ops.ReadOnlyViolation):
            ssh_ops.assert_readonly(cmd)
    assert "execute" not in ssh_ops._READ_VERBS


def test_a_probe_target_must_be_an_address():
    for good in ("198.51.100.1", "backend.example.com", "2001:db8::1", "srv-01"):
        assert bp.assert_probe_target(good) == good
    for bad in ("", "  ", "192.0.2.1; x", "$(x)", "a/../b", "-flag", "a b"):
        with pytest.raises(bp.ProbeRefused):
            bp.assert_probe_target(bad)


# --------------------------------------------------------------------------- #
#  2. parsing a ping — the verdict that is NOT "down"                           #
# --------------------------------------------------------------------------- #
LIVE_DOWN = ("PING 198.51.100.1 (198.51.100.1): 56 data bytes\n"
             "Timeout ...\nTimeout ...\nTimeout ...\nTimeout ...\nTimeout ...\n"
             "\n--- 198.51.100.1 ping statistics ---\n"
             "5 packets transmitted, 0 packets received, 100% packet loss")
LIVE_UP = ("PING 127.0.0.1 (127.0.0.1): 56 data bytes\n"
           "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.0 ms\n"
           "\n--- 127.0.0.1 ping statistics ---\n"
           "5 packets transmitted, 5 packets received, 0% packet loss\n"
           "round-trip min/avg/max = 0.0/0.0/0.0 ms")


def test_a_hundred_percent_loss_is_no_reply():
    r = bp.parse_ping(LIVE_DOWN)
    assert r["verdict"] == "no reply"
    assert r["replied"] is False and r["loss"] == 100.0


def test_a_reply_is_alive_with_its_rtt():
    r = bp.parse_ping(LIVE_UP)
    assert r["verdict"] == "alive" and r["replied"] is True
    assert r["loss"] == 0.0 and r["rtt_ms"] == 0.0


def test_a_truncated_ping_is_NOT_reported_as_a_backend_that_is_down():
    """The header with no statistics line is what a quiet-based read returned.

    ``no answer`` and ``no reply`` must never be the same word: one is a probe
    that failed, the other is a backend that did not respond.
    """
    r = bp.parse_ping("PING 198.51.100.1 (198.51.100.1): 56 data bytes")
    assert r["verdict"] == "no answer"
    assert r["verdict"] != "no reply"
    assert "NOT evidence" in r["detail"]


def test_a_partial_loss_still_counts_as_alive():
    r = bp.parse_ping("5 packets transmitted, 3 packets received, 40% packet loss")
    assert r["verdict"] == "alive" and r["loss"] == 40.0


@pytest.mark.parametrize("text,verdict", [
    ("ping: unknown host nosuch.example", "unresolved"),
    ("Parsing error at 'ping'", "cli error"),
    ("Command fail. Return code -1", "cli error"),
])
def test_the_failure_modes_keep_their_own_names(text, verdict):
    assert bp.parse_ping(text)["verdict"] == verdict


# --------------------------------------------------------------------------- #
#  3. which ports a member actually listens on                                  #
# --------------------------------------------------------------------------- #
def test_only_the_plain_port_is_probed_unless_adaptive_is_on():
    """A member always carries http-port and https-port; they only MEAN
    anything when ``http-https-adaptive`` is enabled. Probing all three would
    report a healthy member as two-thirds unreachable."""
    row = {"ip": "192.0.2.1", "port": 8080, "http-port": 80, "https-port": 443,
           "http-https-adaptive": "disable"}
    assert bp.backend_ports(row) == [8080]
    assert bp.backend_ports(dict(row, **{"http-https-adaptive": "enable"})) \
        == [80, 443]


def test_a_member_with_no_usable_port_yields_none():
    assert bp.backend_ports({"ip": "192.0.2.1", "port": 0}) == []
    assert bp.backend_ports({"ip": "192.0.2.1", "port": "banana"}) == []
    assert bp.backend_ports({"ip": "192.0.2.1", "port": 99999}) == []


# --------------------------------------------------------------------------- #
#  4. flattening pool members                                                   #
# --------------------------------------------------------------------------- #
def test_a_disabled_member_is_carried_through_not_dropped():
    """A pool whose every member is disabled is a FINDING. A silently shorter
    list looks like a pool with fewer servers."""
    rows = [{"seq": 1, "ip": "192.0.2.1", "port": 80, "status": "enable"},
            {"seq": 2, "ip": "192.0.2.2", "port": 80, "status": "disable"}]
    got = bp.backend_targets(rows, policy="p", pool="pool")
    assert len(got) == 2
    assert [t["enabled"] for t in got] == [True, False]


def test_a_domain_member_is_probed_by_its_domain():
    rows = [{"seq": 1, "server-type": "domain", "domain": "b.example",
             "ip": "0.0.0.0", "port": 443}]
    assert bp.backend_targets(rows)[0]["address"] == "b.example"


def test_an_adaptive_member_produces_one_target_per_port():
    rows = [{"seq": 1, "ip": "192.0.2.1", "port": 8080, "http-port": 80,
             "https-port": 443, "http-https-adaptive": "enable"}]
    assert [t["port"] for t in bp.backend_targets(rows)] == [80, 443]


# --------------------------------------------------------------------------- #
#  5. the summary refuses to have two buckets                                   #
# --------------------------------------------------------------------------- #
def _row(app_verdict, local_verdict, ok=False, enabled=True):
    return {"enabled": enabled,
            "appliance": {"verdict": app_verdict},
            "local": {"verdict": local_verdict, "ok": ok}}


def test_unknown_is_its_own_bucket_and_never_folded():
    rows = [_row("alive", "timeout"),
            _row("no reply", "timeout"),
            _row("not probed", "not probed"),
            _row("no answer", "no port"),
            _row("not probed", "open", ok=True, enabled=False)]
    s = bp.summarise(rows)
    assert s == {"total": 5, "reachable": 2, "unreachable": 1,
                 "unknown": 2, "disabled": 1}
    assert s["reachable"] + s["unreachable"] + s["unknown"] == s["total"]


def test_a_refused_port_is_not_counted_as_unreachable():
    """A TCP refusal PROVES the host is up. Counting it as unreachable would
    send an operator chasing routing for a service that is simply not running.
    """
    s = bp.summarise([_row("not probed", "refused")])
    assert s["unreachable"] == 0 and s["unknown"] == 1


# --------------------------------------------------------------------------- #
#  6. probing without any vantage says so                                       #
# --------------------------------------------------------------------------- #
def test_without_ssh_the_appliance_vantage_is_not_probed_never_assumed():
    rows = bp.probe_targets(
        [{"policy": "p", "pool": "q", "address": "", "port": 0,
          "enabled": True}], ssh_session=None)
    assert rows[0]["appliance"]["verdict"] == "not probed"
    assert rows[0]["local"]["verdict"] == "not probed"


def test_a_target_that_carries_an_error_is_never_probed():
    rows = bp.probe_targets([{"policy": "p", "address": "", "port": 0,
                              "error": "the destination does not list this policy"}])
    assert rows[0]["appliance"]["verdict"] == "not probed"
    assert "does not list" in rows[0]["local"]["detail"]


class FakeSSH:
    """Counts pings so the de-duplication can be observed, not assumed."""

    def __init__(self, out):
        self.out, self.calls = out, []

    def run_probe(self, command, **kw):
        self.calls.append(command)
        return self.out


def test_one_address_is_pinged_once_however_many_ports_it_exposes():
    sess = FakeSSH(LIVE_UP)
    targets = [{"policy": "p", "pool": "q", "address": "192.0.2.9", "port": 80,
                "enabled": True},
               {"policy": "p", "pool": "q", "address": "192.0.2.9", "port": 443,
                "enabled": True}]
    rows = bp.probe_targets(targets, ssh_session=sess, tcp_timeout=0.01)
    assert sess.calls == ["execute ping 192.0.2.9"]
    assert [r["appliance"]["verdict"] for r in rows] == ["alive", "alive"]


def test_a_ping_that_raises_becomes_a_cli_error_not_a_dead_backend():
    class Boom:
        def run_probe(self, command, **kw):
            raise RuntimeError("channel closed")

    rows = bp.probe_targets(
        [{"policy": "p", "address": "192.0.2.9", "port": 80, "enabled": True}],
        ssh_session=Boom(), tcp_timeout=0.01)
    assert rows[0]["appliance"]["verdict"] == "cli error"
    assert rows[0]["appliance"]["verdict"] != "no reply"


def test_an_unsafe_address_is_refused_rather_than_interpolated():
    sess = FakeSSH(LIVE_UP)
    rows = bp.probe_targets(
        [{"policy": "p", "address": "192.0.2.1; x", "port": 80,
          "enabled": True}], ssh_session=sess, tcp_timeout=0.01)
    assert sess.calls == []
    assert rows[0]["appliance"]["verdict"] == "cli error"


# --------------------------------------------------------------------------- #
#  7. reading the pools back FROM THE BOX                                       #
# --------------------------------------------------------------------------- #
class FakeResp:
    def __init__(self, payload):
        self._p = payload

    def json(self):
        return self._p


class FakeClient:
    """Serves cmdb paths from a dict; an unlisted path raises like a real one."""

    def __init__(self, routes):
        self.routes = routes

    def get(self, path):
        key = path.replace("/api/v2.0/cmdb/", "")
        if key not in self.routes:
            raise RuntimeError("no route for %s" % key)
        return FakeResp({"results": self.routes[key]})


POLICIES = "server-policy/policy"
MEMBERS = "server-policy/server-pool/pserver-list?mkey=pool-a"


def test_the_members_are_read_from_the_destination():
    c = FakeClient({POLICIES: [{"name": "p1", "server-pool": "pool-a"}],
                    MEMBERS: [{"seq": 1, "ip": "192.0.2.1", "port": 80}]})
    got = bp.dst_pool_targets(c, ["p1"])
    assert [(t["policy"], t["pool"], t["address"], t["port"]) for t in got] \
        == [("p1", "pool-a", "192.0.2.1", 80)]


def test_a_policy_the_destination_does_not_have_yields_an_ERROR_ROW():
    """Never an omission. A shorter list reads as "fewer backends to worry
    about", which is the opposite of what a failed lookup means."""
    c = FakeClient({POLICIES: [{"name": "p1", "server-pool": "pool-a"}]})
    got = bp.dst_pool_targets(c, ["ghost"])
    assert len(got) == 1
    assert "does not list this policy" in got[0]["error"]


def test_a_policy_with_no_pool_says_which_deployment_mode_it_is_in():
    c = FakeClient({POLICIES: [{"name": "p1", "server-pool": "",
                                "deployment-mode": "http-content-routing"}]})
    got = bp.dst_pool_targets(c, ["p1"])
    assert "http-content-routing" in got[0]["error"]


def test_a_pool_whose_members_cannot_be_read_is_an_error_row_not_an_empty_pool():
    c = FakeClient({POLICIES: [{"name": "p1", "server-pool": "pool-a"}]})
    got = bp.dst_pool_targets(c, ["p1"])
    assert got[0]["pool"] == "pool-a"
    assert "could not read the pool members" in got[0]["error"]


def test_an_empty_pool_is_reported_as_such():
    c = FakeClient({POLICIES: [{"name": "p1", "server-pool": "pool-a"}],
                    MEMBERS: []})
    got = bp.dst_pool_targets(c, ["p1"])
    assert got[0]["error"] == "the pool has no real servers"


def test_an_unreadable_policy_list_refuses_rather_than_returning_nothing():
    with pytest.raises(bp.ProbeRefused):
        bp.dst_pool_targets(FakeClient({}), ["p1"])


# --------------------------------------------------------------------------- #
#  8. tcp_check by its own contract                                             #
# --------------------------------------------------------------------------- #
def test_a_refused_connection_is_its_own_verdict_and_says_the_host_is_up():
    """Driven through a REAL refusal, not a hand-built row.

    A test that assembles ``{"verdict": "refused"}`` itself proves the summary
    reads that word — it says nothing about whether anything ever produces it,
    which is how this exact mutation survived the first pass.
    """
    import socket as _s
    srv = _s.socket()
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.close()                      # nothing is listening on `port` now
    r = bp.tcp_check("127.0.0.1", port, timeout=2.0)
    assert r["ok"] is False
    assert r["verdict"] == "refused", r
    assert r["verdict"] != "unreachable"
    assert "UP" in r["detail"]


def test_an_open_port_is_open():
    import socket as _s
    srv = _s.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    try:
        r = bp.tcp_check("127.0.0.1", srv.getsockname()[1], timeout=2.0)
        assert r["ok"] is True and r["verdict"] == "open"
    finally:
        srv.close()


def test_no_port_is_not_a_connection_failure():
    for host, port in (("192.0.2.1", 0), ("192.0.2.1", "x"), ("", 80)):
        assert bp.tcp_check(host, port, timeout=0.01)["verdict"] == "no port"
