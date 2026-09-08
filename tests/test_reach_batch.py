"""Batch backend reachability — the file of ``source;policy;destination`` lines.

What is guarded here is NOT "does it probe". ``test_backend_probe`` already
owns that. What is guarded is everything a batch adds on top, and every one of
these is a way the page could report a clean run over work it never did:

    * a line the file gave and the report does not carry
    * a cap or a budget that cuts coverage without saying so
    * "we could not tell" counted as reachable, or as down
    * a destination failure that swallows the source answer
    * appliance A's ping answer reused for appliance B
    * the table and the verdict disagreeing about the same backend
"""
import pytest

from app.services import backend_probe as bp
from app.services import reach_batch as rb
from tests.conftest import admin_user_id, login


# --------------------------------------------------------------------------- #
#  Doubles                                                                      #
# --------------------------------------------------------------------------- #
class FakeAppl:
    def __init__(self, name, host=None, kind="fortiweb", aid=None):
        self.name = name
        self.host = host or (name + ".example")
        self.kind = kind
        self.id = aid if aid is not None else abs(hash(name)) % 100000


def _member(ip, port=80, status="enable"):
    return {"ip": ip, "port": port, "status": status, "server-type": "physical"}


class FakeClient:
    """Answers the two cmdb reads ``dst_pool_targets`` makes, nothing else."""

    def __init__(self, policies, pools, fail=False):
        self.policies, self.pools, self.fail = policies, pools, fail
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        if self.fail:
            raise RuntimeError("boom")
        client = self

        class R:
            @staticmethod
            def json():
                if path.endswith("server-policy/policy"):
                    return {"results": [{"name": n, "server-pool": p}
                                        for n, p in client.policies.items()]}
                pool = path.split("mkey=")[-1]
                return {"results": client.pools.get(pool, [])}
        return R()


class FakeSSH:
    """An appliance vantage with a scripted answer per address."""

    def __init__(self, answers, name="box"):
        self.answers, self.name = answers, name
        self.pinged = []
        self.closed = False

    def run_probe(self, command):
        addr = command.split()[-1]
        self.pinged.append(addr)
        if addr not in self.answers:
            return "5 packets transmitted, 0 received, 100% packet loss"
        return self.answers[addr]

    def close(self):
        self.closed = True


_ALIVE = ("5 packets transmitted, 5 received, 0% packet loss\n"
          "round-trip min/avg/max = 0.1/0.2/0.3 ms")
_DEAD = "5 packets transmitted, 0 received, 100% packet loss"


def _run(rows, **kw):
    """run_batch with the TCP vantage neutralised unless a test wants it.

    Every test here is about ORDER, GROUPING, CACHING and VERDICTS. Letting a
    real ``socket.create_connection`` fire would make the results depend on
    whatever answers on the build host's network.
    """
    kw.setdefault("tcp_timeout", 0.001)
    return rb.run_batch(rows, **kw)


# --------------------------------------------------------------------------- #
#  1. parsing — the file's lines, all of them, in its own numbering             #
# --------------------------------------------------------------------------- #
def test_parses_the_documented_triple():
    rows, dropped = rb.parse_batch("fw12;spo-a;fw13")
    assert dropped == []
    assert (rows[0]["source"], rows[0]["policy"], rows[0]["destination"]) \
        == ("fw12", "spo-a", "fw13")
    assert rows[0]["lineno"] == 1


def test_line_numbers_point_at_the_operators_file_not_at_the_report():
    rows, _ = rb.parse_batch("# a comment\n\nfw12;spo-a;fw13\n")
    assert len(rows) == 1 and rows[0]["lineno"] == 3


def test_a_two_field_line_is_a_source_only_check_not_an_error():
    rows, _ = rb.parse_batch("fw12;spo-a")
    assert rows[0]["error"] == "" and rows[0]["destination"] == ""


@pytest.mark.parametrize("bad", ["justonefield", "a;b;c;d", ";spo;fw13",
                                 "fw12;;fw13"])
def test_a_malformed_line_becomes_a_row_with_an_error_never_a_missing_row(bad):
    rows, dropped = rb.parse_batch(bad)
    # The row must EXIST. A report with fewer lines than the file reads as
    # "everything else was fine", which is the one thing it must never say.
    assert len(rows) == 1 and rows[0]["error"]
    assert dropped == []


@pytest.mark.parametrize("header", [
    "source;spo;destination",
    "SOURCE FortiWeb;SPO;Destination FortiWeb",
    "  source ; spo ; destination  ",
])
def test_the_format_header_is_skipped_and_said_out_loud(header):
    rows, dropped = rb.parse_batch(header + "\nfw12;spo-a;fw13")
    assert len(rows) == 1
    assert len(dropped) == 1 and dropped[0]["lineno"] == 1


def test_a_device_actually_called_source_is_still_a_line():
    # The header skip matches the WHOLE documented line, not the word.
    rows, dropped = rb.parse_batch("source;spo-a;destination-fw")
    assert len(rows) == 1 and dropped == []


def test_over_the_line_limit_is_reported_never_silently_truncated():
    text = "\n".join("fw12;spo-%d;fw13" % i for i in range(5))
    rows, dropped = rb.parse_batch(text, max_lines=3)
    assert len(rows) == 3
    assert len(dropped) == 2 and all("limit" in d["why"] for d in dropped)


def test_crlf_and_a_bom_are_read_as_lines_not_as_a_broken_first_field():
    rows, _ = rb.parse_batch("﻿fw12;spo-a;fw13\r\nfw12;spo-b;fw13\r\n")
    assert [r["source"] for r in rows] == ["fw12", "fw12"]
    assert rows[0]["source"] == "fw12"


# --------------------------------------------------------------------------- #
#  2. resolution                                                                #
# --------------------------------------------------------------------------- #
def test_a_name_resolves_case_insensitively_and_by_host():
    idx = rb.build_index([FakeAppl("FortiWeb12", host="192.0.2.7")])
    assert rb.resolve("fortiweb12", idx)[0] is not None
    assert rb.resolve("192.0.2.7", idx)[0] is not None


def test_a_host_never_shadows_another_devices_name():
    # 'b' is A's host AND B's name. The NAME must win, whichever order the
    # query returned the rows in — a lookup whose answer depends on row order
    # is not a lookup.
    a, b = FakeAppl("a", host="b"), FakeAppl("b", host="b.example")
    for order in ([a, b], [b, a]):
        assert rb.resolve("b", rb.build_index(order))[0] is b


def test_an_unknown_name_is_an_error_not_a_skipped_line():
    assert rb.resolve("nope", rb.build_index([]))[0] is None
    assert "no appliance is registered" in rb.resolve("nope", {})[1]


def test_a_retired_placeholder_host_is_refused_before_any_connect():
    idx = rb.build_index([FakeAppl("fw6", host="retired-fw6.invalid")])
    appl, err = rb.resolve("fw6", idx)
    assert appl is None and "retired" in err


def test_a_non_fortiweb_device_is_refused_with_the_reason():
    idx = rb.build_index([FakeAppl("adc1", kind="fortiadc")])
    appl, err = rb.resolve("adc1", idx)
    assert appl is None and "fortiadc" in err


# --------------------------------------------------------------------------- #
#  3. the run — order, grouping, caching                                        #
# --------------------------------------------------------------------------- #
def _two_box_world(dst_has_policy=True):
    src = FakeAppl("fw12", aid=1)
    dst = FakeAppl("fw13", aid=2)
    clients = {
        1: FakeClient({"spo-a": "pool-a", "spo-b": "pool-b"},
                      {"pool-a": [_member("192.0.2.1")],
                       "pool-b": [_member("192.0.2.2")]}),
        2: FakeClient({"spo-a": "pool-a"} if dst_has_policy else {},
                      {"pool-a": [_member("192.0.2.1")]}),
    }
    return src, dst, clients


def test_one_api_read_per_appliance_however_many_lines_name_it():
    src, dst, clients = _two_box_world()
    rows, _ = rb.parse_batch("fw12;spo-a;fw13\nfw12;spo-b;fw13")
    _run(rows, appliances=[src, dst],
         client_factory=lambda a: clients[a.id],
         ssh_factory=lambda a: None)
    # Two lines, one policy list read on the source — not two.
    assert sum(1 for c in clients[1].calls
               if c.endswith("server-policy/policy")) == 1


def test_sources_are_read_before_destinations():
    order = []
    src, dst, clients = _two_box_world()

    def factory(a):
        order.append(a.name)
        return clients[a.id]

    rows, _ = rb.parse_batch("fw13;spo-a;fw12")   # fw13 is the SOURCE here
    _run(rows, appliances=[src, dst], client_factory=factory,
         ssh_factory=lambda a: None)
    assert order == ["fw13", "fw12"]


def test_the_appliance_ping_cache_is_never_shared_between_two_boxes():
    """The whole point of the appliance vantage is that it is per-box.

    fw12 reaches 192.0.2.1 and fw13 does not. If one cache were shared, the
    second box would inherit the first's answer and the report would claim a
    route that does not exist — the exact failure the two-vantage design was
    built to prevent.
    """
    src, dst, clients = _two_box_world()
    sessions = {1: FakeSSH({"192.0.2.1": _ALIVE}, "fw12"),
                2: FakeSSH({}, "fw13")}          # fw13: 100% loss for everything
    rows, _ = rb.parse_batch("fw12;spo-a;fw13")
    rep = _run(rows, use_ssh=True, appliances=[src, dst],
               client_factory=lambda a: clients[a.id],
               ssh_factory=lambda a: sessions[a.id])
    line = rep["lines"][0]
    assert line["src"]["rows"][0]["appliance"]["verdict"] == "alive"
    assert line["dst"]["rows"][0]["appliance"]["verdict"] == "no reply"
    # And both boxes were actually asked — the answer was not reused.
    assert sessions[1].pinged == ["192.0.2.1"] == sessions[2].pinged


def test_one_address_is_pinged_once_per_box_across_the_whole_batch():
    src = FakeAppl("fw12", aid=1)
    client = FakeClient({"spo-a": "p", "spo-b": "p"}, {"p": [_member("192.0.2.1")]})
    sess = FakeSSH({"192.0.2.1": _ALIVE})
    rows, _ = rb.parse_batch("fw12;spo-a\nfw12;spo-b")
    _run(rows, use_ssh=True, appliances=[src],
         client_factory=lambda a: client, ssh_factory=lambda a: sess)
    assert sess.pinged == ["192.0.2.1"]


def test_every_session_is_closed_even_when_a_line_blows_up():
    src, dst, clients = _two_box_world()
    sessions = {1: FakeSSH({}, "fw12"), 2: FakeSSH({}, "fw13")}
    rows, _ = rb.parse_batch("fw12;spo-a;fw13")
    _run(rows, use_ssh=True, appliances=[src, dst],
         client_factory=lambda a: clients[a.id],
         ssh_factory=lambda a: sessions[a.id])
    assert all(s.closed for s in sessions.values())


# --------------------------------------------------------------------------- #
#  4. rule 2 — a bad destination never voids the source answer                  #
# --------------------------------------------------------------------------- #
def test_an_unknown_destination_still_leaves_the_source_answered():
    src = FakeAppl("fw12", aid=1)
    client = FakeClient({"spo-a": "p"}, {"p": [_member("192.0.2.1")]})
    rows, _ = rb.parse_batch("fw12;spo-a;nosuchbox")
    rep = _run(rows, appliances=[src], client_factory=lambda a: client,
               ssh_factory=lambda a: None)
    line = rep["lines"][0]
    assert line["src"]["ran"] is True and line["src"]["summary"]["total"] == 1
    assert line["verdict"] == "error"
    assert {f["code"] for f in line["findings"]} >= {"destination_unresolved"}


def test_a_destination_that_cannot_be_read_still_leaves_the_source_answered():
    src, dst, clients = _two_box_world()
    clients[2].fail = True
    rows, _ = rb.parse_batch("fw12;spo-a;fw13")
    rep = _run(rows, appliances=[src, dst],
               client_factory=lambda a: clients[a.id],
               ssh_factory=lambda a: None)
    line = rep["lines"][0]
    assert line["src"]["ran"] is True
    assert line["dst"]["ran"] is False
    assert "destination_unreadable" in {f["code"] for f in line["findings"]}


def test_a_source_that_cannot_be_read_is_an_error_not_an_empty_ok():
    src = FakeAppl("fw12", aid=1)
    rows, _ = rb.parse_batch("fw12;spo-a")
    rep = _run(rows, appliances=[src],
               client_factory=lambda a: FakeClient({}, {}, fail=True),
               ssh_factory=lambda a: None)
    assert rep["lines"][0]["verdict"] == "error"


# --------------------------------------------------------------------------- #
#  5. verdicts                                                                  #
# --------------------------------------------------------------------------- #
def _verdict(text, *, world=None, **kw):
    src, dst, clients = world or _two_box_world()
    rows, _ = rb.parse_batch(text)
    rep = _run(rows, appliances=[src, dst],
               client_factory=lambda a: clients[a.id], **kw)
    return rep["lines"][0]


def test_both_sides_reachable_is_ok():
    src, dst, clients = _two_box_world()
    sessions = {1: FakeSSH({"192.0.2.1": _ALIVE}), 2: FakeSSH({"192.0.2.1": _ALIVE})}
    line = _verdict("fw12;spo-a;fw13", world=(src, dst, clients), use_ssh=True,
                    ssh_factory=lambda a: sessions[a.id])
    assert line["verdict"] == "ok" and line["findings"] == []


def test_a_backend_that_does_not_answer_is_down():
    src, dst, clients = _two_box_world()
    sessions = {1: FakeSSH({"192.0.2.1": _DEAD}), 2: FakeSSH({"192.0.2.1": _ALIVE})}
    line = _verdict("fw12;spo-a;fw13", world=(src, dst, clients), use_ssh=True,
                    ssh_factory=lambda a: sessions[a.id])
    assert line["verdict"] == "down"


def test_no_vantage_at_all_is_unknown_never_down():
    """This is the rule the whole feature exists to hold.

    With no SSH and a TCP probe that cannot connect to a non-routable address,
    NOTHING was measured. That must not be reported as an outage.
    """
    src = FakeAppl("fw12", aid=1)
    client = FakeClient({"spo-a": "p"}, {"p": [{"ip": "192.0.2.1", "port": 0,
                                                "server-type": "physical"}]})
    rows, _ = rb.parse_batch("fw12;spo-a")
    rep = _run(rows, appliances=[src], client_factory=lambda a: client,
               ssh_factory=lambda a: None)
    line = rep["lines"][0]
    assert line["src"]["summary"]["unknown"] == 1
    assert line["src"]["summary"]["unreachable"] == 0
    assert line["verdict"] == "unknown"


def test_a_policy_missing_on_the_source_is_an_error():
    src, dst, clients = _two_box_world()
    line = _verdict("fw12;spo-nope;fw13", world=(src, dst, clients),
                    ssh_factory=lambda a: None)
    assert line["verdict"] == "error"
    assert "policy_absent_on_source" in {f["code"] for f in line["findings"]}


def test_differing_pools_are_a_mismatch_with_the_member_named():
    src = FakeAppl("fw12", aid=1)
    dst = FakeAppl("fw13", aid=2)
    clients = {
        1: FakeClient({"spo-a": "p"}, {"p": [_member("192.0.2.1"),
                                             _member("192.0.2.9")]}),
        2: FakeClient({"spo-a": "p"}, {"p": [_member("192.0.2.1")]}),
    }
    sessions = {1: FakeSSH({"192.0.2.1": _ALIVE, "192.0.2.9": _ALIVE}),
                2: FakeSSH({"192.0.2.1": _ALIVE})}
    line = _verdict("fw12;spo-a;fw13", world=(src, dst, clients), use_ssh=True,
                    ssh_factory=lambda a: sessions[a.id])
    assert line["verdict"] == "mismatch"
    finding = [f for f in line["findings"]
               if f["code"] == "missing_in_destination"][0]
    assert "192.0.2.9:80" in finding["text"]


def test_a_line_with_no_destination_asks_a_source_only_question_and_gets_ok():
    src = FakeAppl("fw12", aid=1)
    client = FakeClient({"spo-a": "p"}, {"p": [_member("192.0.2.1")]})
    sess = FakeSSH({"192.0.2.1": _ALIVE})
    rows, _ = rb.parse_batch("fw12;spo-a")
    rep = _run(rows, use_ssh=True, appliances=[src],
               client_factory=lambda a: client, ssh_factory=lambda a: sess)
    line = rep["lines"][0]
    assert line["verdict"] == "ok"
    assert "no_destination" in {f["code"] for f in line["findings"]}


def test_the_worst_finding_decides_the_verdict():
    # A mismatch AND an unreachable backend on the same line must read "down".
    src = FakeAppl("fw12", aid=1)
    dst = FakeAppl("fw13", aid=2)
    clients = {
        1: FakeClient({"spo-a": "p"}, {"p": [_member("192.0.2.1"),
                                             _member("192.0.2.9")]}),
        2: FakeClient({"spo-a": "p"}, {"p": [_member("192.0.2.1")]}),
    }
    sessions = {1: FakeSSH({"192.0.2.1": _ALIVE, "192.0.2.9": _DEAD}),
                2: FakeSSH({"192.0.2.1": _ALIVE})}
    line = _verdict("fw12;spo-a;fw13", world=(src, dst, clients), use_ssh=True,
                    ssh_factory=lambda a: sessions[a.id])
    codes = {f["code"] for f in line["findings"]}
    assert {"unreachable", "missing_in_destination"} <= codes
    assert line["verdict"] == "down"


# --------------------------------------------------------------------------- #
#  6. the pre-migration fallback                                                #
# --------------------------------------------------------------------------- #
def test_a_destination_without_the_policy_pings_the_sources_backends():
    src, dst, clients = _two_box_world(dst_has_policy=False)
    sessions = {1: FakeSSH({"192.0.2.1": _ALIVE}), 2: FakeSSH({"192.0.2.1": _ALIVE})}
    line = _verdict("fw12;spo-a;fw13", world=(src, dst, clients), use_ssh=True,
                    ssh_factory=lambda a: sessions[a.id])
    assert line["dst"]["from_source_pool"] is True
    assert sessions[2].pinged == ["192.0.2.1"]
    assert "policy_absent_on_destination" in {f["code"] for f in line["findings"]}


def test_the_fallback_never_produces_a_pool_comparison():
    """Comparing the source's list against itself always agrees.

    An agreement nobody measured is worse than no comparison at all, so the
    fallback must not emit missing/extra findings.
    """
    src, dst, clients = _two_box_world(dst_has_policy=False)
    sessions = {1: FakeSSH({"192.0.2.1": _ALIVE}), 2: FakeSSH({"192.0.2.1": _ALIVE})}
    line = _verdict("fw12;spo-a;fw13", world=(src, dst, clients), use_ssh=True,
                    ssh_factory=lambda a: sessions[a.id])
    codes = {f["code"] for f in line["findings"]}
    assert "missing_in_destination" not in codes
    assert "extra_in_destination" not in codes
    # …and the absence is EXPLAINED. Without this the line looks exactly like
    # one whose pools were compared and matched.
    assert "comparison_skipped" in codes


def test_without_an_ssh_vantage_the_fallback_does_not_run():
    # The only probe left would be TCP from SATOM, which repeats the source's
    # own answer and says nothing about the destination.
    src, dst, clients = _two_box_world(dst_has_policy=False)
    line = _verdict("fw12;spo-a;fw13", world=(src, dst, clients),
                    ssh_factory=lambda a: None)
    assert line["dst"]["from_source_pool"] is False


# --------------------------------------------------------------------------- #
#  7. rule 3 — nothing is dropped silently                                      #
# --------------------------------------------------------------------------- #
def test_the_time_budget_carries_the_rest_as_not_probed_and_says_so():
    src = FakeAppl("fw12", aid=1)
    members = [_member("10.1.1.%d" % i) for i in range(1, 60)]
    client = FakeClient({"spo-a": "p"}, {"p": members})
    # t0 = 0, first chunk still inside the budget, everything after it is not.
    ticks = iter([0.0, 0.0])
    rows, _ = rb.parse_batch("fw12;spo-a")
    rep = _run(rows, appliances=[src], client_factory=lambda a: client,
               ssh_factory=lambda a: None,
               clock=lambda: next(ticks, 9999.0))
    assert rep["budget_hit"] is True
    states = [r["state"] for r in rep["lines"][0]["src"]["rows"]]
    assert "unknown" in states
    assert len(rep["lines"][0]["src"]["rows"]) == len(members)


def test_a_capped_target_is_carried_as_not_probed_not_deleted(monkeypatch):
    monkeypatch.setattr(rb, "MAX_TARGETS", 2)
    src = FakeAppl("fw12", aid=1)
    members = [_member("10.1.1.%d" % i) for i in range(1, 6)]
    client = FakeClient({"spo-a": "p"}, {"p": members})
    rows, _ = rb.parse_batch("fw12;spo-a")
    rep = _run(rows, appliances=[src], client_factory=lambda a: client,
               ssh_factory=lambda a: None)
    # The pool still shows five members — a cap that shortens the pool reads
    # as a smaller, healthier pool.
    assert len(rep["lines"][0]["src"]["rows"]) == 5
    assert rep["capped"] and rep["capped"][0]["dropped"] == 3


def test_every_parsed_line_appears_in_the_report():
    src, dst, clients = _two_box_world()
    rows, _ = rb.parse_batch("fw12;spo-a;fw13\nbroken\nfw12;spo-b\n")
    rep = _run(rows, appliances=[src, dst],
               client_factory=lambda a: clients[a.id],
               ssh_factory=lambda a: None)
    assert len(rep["lines"]) == 3
    assert sum(rep["totals"].values()) == 3


# --------------------------------------------------------------------------- #
#  8. one author for "is this backend up?"                                      #
# --------------------------------------------------------------------------- #
def test_the_row_state_is_the_same_call_the_summary_counts_with():
    src = FakeAppl("fw12", aid=1)
    client = FakeClient({"spo-a": "p"},
                        {"p": [_member("192.0.2.1"), _member("192.0.2.2")]})
    sess = FakeSSH({"192.0.2.1": _ALIVE, "192.0.2.2": _DEAD})
    rows, _ = rb.parse_batch("fw12;spo-a")
    rep = _run(rows, use_ssh=True, appliances=[src],
               client_factory=lambda a: client, ssh_factory=lambda a: sess)
    side = rep["lines"][0]["src"]
    # The table's own badges must add up to the summary beside them. A table of
    # green rows under a red summary has no way of telling you which one lied.
    assert sum(1 for r in side["rows"] if r["state"] == "reachable") \
        == side["summary"]["reachable"]
    assert sum(1 for r in side["rows"] if r["state"] == "unreachable") \
        == side["summary"]["unreachable"]
    assert all(r["state"] == bp.classify_row(r) for r in side["rows"])


def test_every_finding_carries_the_verdict_it_implies():
    # The template colours a finding from f.verdict. A finding without one
    # would render grey and read as informational whatever it says.
    src, dst, clients = _two_box_world()
    clients[2].fail = True
    rows, _ = rb.parse_batch("fw12;spo-a;fw13")
    rep = _run(rows, appliances=[src, dst],
               client_factory=lambda a: clients[a.id],
               ssh_factory=lambda a: None)
    for f in rep["lines"][0]["findings"]:
        assert f["verdict"] in rb.VERDICTS


# --------------------------------------------------------------------------- #
#  9. the shared caches in backend_probe                                        #
# --------------------------------------------------------------------------- #
def test_the_tcp_cache_is_keyed_by_address_AND_port():
    """Two ports on one host are two different questions.

    A cache keyed by address alone would answer "is :443 open?" with what it
    learned about :80.
    """
    cache = {}
    targets = [{"policy": "p", "address": "127.0.0.1", "port": 1},
               {"policy": "p", "address": "127.0.0.1", "port": 2}]
    bp.probe_targets(targets, tcp_timeout=0.001, tcp_cache=cache)
    assert len(cache) == 2


def test_a_supplied_cache_makes_the_second_call_skip_the_work():
    cache = {("127.0.0.1", 1): {"ok": True, "verdict": "open", "detail": "cached"}}
    rows = bp.probe_targets([{"policy": "p", "address": "127.0.0.1", "port": 1}],
                            tcp_timeout=0.001, tcp_cache=cache)
    assert rows[0]["local"]["detail"] == "cached"


def test_a_cached_result_is_copied_not_shared():
    # Two rows holding the SAME dict means annotating one silently annotates
    # the other.
    cache = {}
    rows = bp.probe_targets(
        [{"policy": "p", "address": "127.0.0.1", "port": 1},
         {"policy": "q", "address": "127.0.0.1", "port": 1}],
        tcp_timeout=0.001, tcp_cache=cache)
    assert rows[0]["local"] is not rows[1]["local"]


# --------------------------------------------------------------------------- #
#  10. the machine-readable error tag                                           #
# --------------------------------------------------------------------------- #
def test_a_read_failure_carries_a_stable_tag_not_only_prose():
    client = FakeClient({"spo-a": ""}, {})
    rows = bp.dst_pool_targets(client, ["spo-a", "spo-missing"])
    kinds = {r.get("error_kind") for r in rows}
    assert kinds == {"no_pool", "no_such_policy"}
    # And the prose is still there for a human.
    assert all(r["error"] for r in rows)


def test_reach_batch_branches_on_the_tag_and_not_on_the_message():
    """Reword every ``error`` message and the verdicts must not move.

    Prose is written for an operator. A caller that parses it is a second
    author of it, and the next reword changes what the page decides.
    """
    src = FakeAppl("fw12", aid=1)
    client = FakeClient({}, {})
    rows, _ = rb.parse_batch("fw12;spo-a")
    before = _run(rows, appliances=[src], client_factory=lambda a: client,
                  ssh_factory=lambda a: None)["lines"][0]["verdict"]

    real = bp.dst_pool_targets

    def reworded(c, policies):
        out = real(c, policies)
        for r in out:
            if r.get("error"):
                r["error"] = "completely different wording"
        return out

    bp.dst_pool_targets = reworded
    try:
        rows2, _ = rb.parse_batch("fw12;spo-a")
        after = _run(rows2, appliances=[src], client_factory=lambda a: client,
                     ssh_factory=lambda a: None)["lines"][0]["verdict"]
    finally:
        bp.dst_pool_targets = real
    assert before == after == "error"


# --------------------------------------------------------------------------- #
#  11. export                                                                   #
# --------------------------------------------------------------------------- #
def test_the_tsv_carries_one_row_per_line_plus_a_header():
    src, dst, clients = _two_box_world()
    rows, _ = rb.parse_batch("fw12;spo-a;fw13\nfw12;spo-b")
    rep = _run(rows, appliances=[src, dst],
               client_factory=lambda a: clients[a.id],
               ssh_factory=lambda a: None)
    lines = rb.to_tsv(rep).split("\n")
    assert len(lines) == 3
    assert lines[0].startswith("line\tsource\tpolicy\tdestination\tverdict")


# --------------------------------------------------------------------------- #
#  12. the page                                                                 #
# --------------------------------------------------------------------------- #
def test_the_page_renders_without_an_appliance_selected(app, client):
    login(client, admin_user_id(app))
    r = client.get("/reachability/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "source;policy;destination" in body
    # No workspace tab, no device id anywhere in the URL: that is the feature.
    assert "/reachability/" in body


def test_the_page_needs_a_login(client):
    r = client.get("/reachability/")
    assert r.status_code in (302, 401)
    assert "/auth/login" in r.headers.get("Location", "")


def test_an_empty_submission_is_refused_with_the_format(app, client):
    login(client, admin_user_id(app))
    r = client.post("/reachability/", data={"entries": "   "},
                    follow_redirects=True)
    assert r.status_code == 200
    assert "source;policy;destination" in r.get_data(as_text=True)


def test_an_oversized_upload_is_refused_before_it_is_parsed(app, client):
    import io as _io
    login(client, admin_user_id(app))
    blob = b"fw12;spo-a;fw13\n" * 40000       # ~640 KB
    r = client.post("/reachability/",
                    data={"entries": "",
                          "file": (_io.BytesIO(blob), "big.txt")},
                    content_type="multipart/form-data")
    assert r.status_code == 200
    assert "larger than" in r.get_data(as_text=True)
