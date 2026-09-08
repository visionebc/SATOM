"""Guards for Scout's LIVE source — rung 1 and the device vantage.

Everything guarded here failed SILENTLY on a live fleet before it was caught,
and each failure produced a report that reads exactly like a correct one:

* an object created after the last successful harvest was called *absent* with
  the full confidence of a FAIL, while it sat there serving traffic;
* the device-vantage probe called a method its session class does not have, so
  every two-vantage probe raised — and because "a rung that raises is UNKNOWN"
  is a rule of this module, the crash rendered as *"the backends could not be
  probed"* instead of as a crash.

The second one is the reason these guards are functional rather than textual:
the rule that stops our bugs from being read as the customer's outage also
stops them from being read at all.
"""
from __future__ import annotations

import pytest

from app.services import scout_ladder as sl


class Appl:
    def __init__(self, kind="fortiweb", name="fw13", host="192.0.2.14", id=23):
        self.kind, self.name, self.host, self.id = kind, name, host, id
        self.maintenance = False
        self.firmware = "7.6.8"


def _ctx(ports=None, state=None, policy="pol-scout-web-a", **topts):
    c = sl.Ctx(target=sl.Target(appliance=Appl(), policy=policy),
               opts=sl.Options(**topts).clamped(), ports=ports or {})
    c.state.update(state or {})
    return c


def _ports(*, deep=None, live=None, cached=None):
    """Wire rung 1's three sources. ``None`` for a source means "not wired"."""
    p = {"read_policy": lambda a, n: deep}
    if live is not sl:          # sentinel-free: always wire, value decides
        p["live_objects"] = lambda a: live
    if cached is not sl:
        p["object_list"] = lambda a: cached
    return p


ROW_LIVE = {"name": "pol-scout-web-a", "status": "enable",
            "vserver": "192.0.2.251/24 ", "httpPort": "80", "protocol": "HTTP"}
OTHERS = [{"name": "pol-root-erp", "status": "enable"},
          {"name": "pol-root-shop", "status": "enable"}]


# --------------------------------------------------------------------------- #
#  _ask_live — "could not ask" is never "there is nothing"                      #
# --------------------------------------------------------------------------- #
def test_an_unwired_live_reader_is_not_an_empty_appliance():
    assert sl._ask_live(_ctx({})) is None


def test_a_live_reader_that_raises_is_not_an_empty_appliance():
    def boom(_a):
        raise RuntimeError("session refused")
    assert sl._ask_live(_ctx({"live_objects": boom})) is None


def test_a_live_reader_that_returns_a_non_list_is_not_an_empty_appliance():
    # The FortiWeb client hands back the error BODY as a dict when a read is
    # refused. Treating that dict as a sequence is how "-20010" becomes "this
    # appliance serves nothing".
    err = {"errcode": "-20010", "message": "The license of peer VM FortiWeb "
                                           "is not valid."}
    assert sl._ask_live(_ctx({"live_objects": lambda a: err})) is None


def test_an_empty_live_list_is_kept_distinct_from_a_missing_one():
    assert sl._ask_live(_ctx({"live_objects": lambda a: []})) == []


def test_non_dict_rows_are_dropped_rather_than_crashing_the_rung():
    out = sl._ask_live(_ctx({"live_objects": lambda a: [ROW_LIVE, "junk", None]}))
    assert out == [ROW_LIVE]


# --------------------------------------------------------------------------- #
#  Rung 1 — the order of the three sources IS the guard                         #
# --------------------------------------------------------------------------- #
def test_the_deep_harvest_copy_wins_when_it_exists():
    out = sl.layer_policy(_ctx(_ports(deep={"name": "pol-scout-web-a",
                                            "status": "enable"},
                                      live=[], cached=[])))
    assert out["verdict"] == sl.PASS
    assert ("read", "SATOM's deep-harvest copy") in [tuple(e) for e in out["evidence"]]


def test_a_live_hit_passes_and_says_the_appliance_was_asked():
    out = sl.layer_policy(_ctx(_ports(deep=None, live=[ROW_LIVE], cached=[])))
    assert out["verdict"] == sl.PASS
    ev = dict(tuple(e) for e in out["evidence"])
    assert ev["read"] == "the appliance, live"
    assert ev["status"] == "enable"


def test_LIVE_BEATS_A_STALE_CACHE_THAT_DOES_NOT_KNOW_THE_OBJECT():
    """THE regression guard. This is the exact live-fleet failure.

    A policy built minutes ago is absent from a six-day-old cache the harvest
    can no longer refresh. Reading the cache first called it non-existent and
    stopped the ladder dead at rung 1 — a confident wrong localisation that
    sends an operator hunting an object that is serving traffic.
    """
    out = sl.layer_policy(_ctx(_ports(deep=None, live=[ROW_LIVE] + OTHERS,
                                      cached=OTHERS)))
    assert out["verdict"] == sl.PASS, out["headline"]
    assert dict(tuple(e) for e in out["evidence"])["read"] == "the appliance, live"


def test_a_fail_is_authored_by_the_appliance_when_the_appliance_was_asked():
    out = sl.layer_policy(_ctx(_ports(deep=None, live=OTHERS, cached=None)))
    assert out["verdict"] == sl.FAIL
    ev = dict(tuple(e) for e in out["evidence"])
    assert ev["read"] == "live from the appliance"
    assert ev["objects the appliance lists now"] == "2"


def test_a_cache_only_fail_says_so_and_names_staleness_as_the_alternative():
    out = sl.layer_policy(_ctx(_ports(deep=None, live=None, cached=OTHERS)))
    assert out["verdict"] == sl.FAIL
    ev = dict(tuple(e) for e in out["evidence"])
    assert ev["objects cached"] == "2"
    assert "could not be asked live" in ev["read"]
    # Without this sentence the operator cannot tell a deleted object from one
    # that is merely newer than the harvest.
    assert "stale" in out["detail"]


def test_the_cache_carries_the_walk_when_the_appliance_cannot_be_asked():
    out = sl.layer_policy(_ctx(_ports(
        deep=None, live=None, cached=[{"name": "pol-scout-web-a",
                                       "status": "enable"}])))
    assert out["verdict"] == sl.PASS
    assert dict(tuple(e) for e in out["evidence"])["read"] == \
        "SATOM's cached object list"


def test_the_two_sources_disagreeing_is_a_warning_not_a_silent_pass():
    """Cache holds it, the appliance — asked now — does not.

    A FAIL would stop the ladder on a monitor view that can legitimately omit
    an object. A silent PASS would hide that the device no longer admits to it.
    """
    out = sl.layer_policy(_ctx(_ports(
        deep=None, live=OTHERS,
        cached=[{"name": "pol-scout-web-a", "status": "enable"}])))
    assert out["verdict"] == sl.WARN
    assert "does not list it right now" in out["headline"]
    # WARN must not stop the ladder: the rungs below still have to be walked.
    ladder = (sl.Layer("1", "Object", "q", sl.V_DEVICE, sl.layer_policy),
              sl.Layer("2", "After", "q", sl.V_SATOM,
                       lambda c: sl._r(sl.PASS, "walked")))
    rep = sl.run(sl.Target(appliance=Appl(), policy="pol-scout-web-a"),
                 sl.Options(), _ports(deep=None, live=OTHERS,
                                      cached=[{"name": "pol-scout-web-a"}]),
                 ladder=ladder)
    assert [l["verdict"] for l in rep["layers"]] == [sl.WARN, sl.PASS]


def test_neither_source_readable_is_unknown_never_absence():
    out = sl.layer_policy(_ctx(_ports(deep=None, live=None, cached=None)))
    assert out["verdict"] == sl.UNKNOWN
    assert "could not list" in out["headline"]


def test_both_sources_empty_is_unknown_never_absence():
    out = sl.layer_policy(_ctx(_ports(deep=None, live=[], cached=[])))
    assert out["verdict"] == sl.UNKNOWN
    assert "no objects cached for this appliance at all" in out["headline"]


def test_a_disabled_object_read_live_still_fails_the_rung():
    row = dict(ROW_LIVE, status="disable")
    out = sl.layer_policy(_ctx(_ports(deep=None, live=[row], cached=[])))
    assert out["verdict"] == sl.FAIL
    assert "DISABLED" in out["headline"]


# --------------------------------------------------------------------------- #
#  The adapters in default_ports                                                #
# --------------------------------------------------------------------------- #
def _live_port(monkeypatch, payload, kind="fortiweb"):
    """Bind default_ports' live reader to a fake client returning ``payload``."""
    import app.clients as clients

    class FakeClient:
        def policy_status(self):
            return payload

    monkeypatch.setattr(clients, "client_for", lambda a: FakeClient(),
                        raising=True)
    return sl.default_ports(), Appl(kind=kind)


def test_the_live_reader_strips_the_mask_and_the_trailing_space(monkeypatch):
    """``"192.0.2.251/24 "`` dialled verbatim fails as a NAME lookup.

    That surfaces on the DNS rung — the wrong rung entirely — so the split
    happens at the edge and never later.
    """
    ports, ap = _live_port(monkeypatch, ([dict(ROW_LIVE,
                                              vserver="192.0.2.251/24 ")], None))
    ctx = sl.Ctx(target=sl.Target(appliance=ap, policy="pol-scout-web-a"),
                 opts=sl.Options().clamped(), ports=ports)
    ep = sl._endpoint(ctx)
    assert ep is not None
    assert ep["host"] == "192.0.2.251", ep["host"]
    assert "/" not in ep["host"] and ep["host"] == ep["host"].strip()


def test_the_front_door_is_derived_from_what_the_appliance_is_listening_on(
        monkeypatch):
    ports, ap = _live_port(monkeypatch, ([ROW_LIVE], None))
    # `front_end` tries the configuration read first; with no real client that
    # read yields nothing and the live view must carry it.
    ctx = sl.Ctx(target=sl.Target(appliance=ap, policy="pol-scout-web-a"),
                 opts=sl.Options().clamped(), ports=ports)
    ep = sl._endpoint(ctx)
    assert ep is not None, "the live view did not carry the front door"
    assert ep["host"] == "192.0.2.251"
    assert ep["port"] == 80
    assert ep["scheme"] == "http"


def test_an_https_policy_derives_the_https_scheme(monkeypatch):
    row = dict(ROW_LIVE, protocol="HTTPS", httpPort="443")
    ports, ap = _live_port(monkeypatch, ([row], None))
    ctx = sl.Ctx(target=sl.Target(appliance=ap, policy="pol-scout-web-a"),
                 opts=sl.Options().clamped(), ports=ports)
    ep = sl._endpoint(ctx)
    assert ep["scheme"] == "https" and ep["port"] == 443


def test_a_non_default_listener_port_is_taken_from_the_appliance(monkeypatch):
    """The port must come from the appliance, not from the scheme.

    Every earlier case used 80-on-HTTP and 443-on-HTTPS, where ignoring
    ``httpPort`` and falling back to the scheme default produce the SAME
    number — so the guard could not see its own mutation. A WAF published on
    8080 is the common real case, and dialling 80 there fails as "the front
    door did not answer": a fault localised one rung too high, on a service
    that is perfectly up.
    """
    row = dict(ROW_LIVE, protocol="HTTP", httpPort="8080")
    ports, ap = _live_port(monkeypatch, ([row], None))
    ctx = sl.Ctx(target=sl.Target(appliance=ap, policy="pol-scout-web-a"),
                 opts=sl.Options().clamped(), ports=ports)
    ep = sl._endpoint(ctx)
    assert ep["port"] == 8080, ep
    assert ep["scheme"] == "http"


def test_an_unreadable_listener_port_falls_back_to_the_scheme_default(
        monkeypatch):
    row = dict(ROW_LIVE, protocol="HTTPS", httpPort="")
    ports, ap = _live_port(monkeypatch, ([row], None))
    ctx = sl.Ctx(target=sl.Target(appliance=ap, policy="pol-scout-web-a"),
                 opts=sl.Options().clamped(), ports=ports)
    assert sl._endpoint(ctx)["port"] == 443


def test_a_refused_read_is_not_an_appliance_with_no_policies(monkeypatch):
    err = {"errcode": "-20010", "message": "not valid"}
    ports, ap = _live_port(monkeypatch, err)
    assert ports["live_objects"](ap) is None


def test_an_error_with_no_rows_is_a_failed_question_not_an_empty_device(
        monkeypatch):
    ports, ap = _live_port(monkeypatch, ([], "device error -20010"))
    assert ports["live_objects"](ap) is None


def test_a_product_without_this_monitor_view_returns_not_asked(monkeypatch):
    ports, ap = _live_port(monkeypatch, ([ROW_LIVE], None), kind="fortiadc")
    assert ports["live_objects"](ap) is None


# --------------------------------------------------------------------------- #
#  The device vantage — it never ran                                            #
# --------------------------------------------------------------------------- #
def test_the_device_vantage_opens_its_session_the_way_this_product_does(
        monkeypatch):
    """``FortiWebReadonlySSH`` has ``connect()``. It has no ``open()``.

    The first version called ``open()``, so every ``use_ssh`` probe raised
    AttributeError and was reported as "could not probe" — a Scout defect
    wearing the costume of a device that would not answer.
    """
    from app.services import ssh_ops, backend_probe

    seen = {"connected": False, "closed": False}

    class Spy:
        def __init__(self, appliance, *a, **kw):
            self.appliance = appliance

        def connect(self):
            seen["connected"] = True
            return self

        def close(self):
            seen["closed"] = True

    monkeypatch.setattr(ssh_ops, "FortiWebReadonlySSH", Spy, raising=True)
    monkeypatch.setattr(backend_probe, "probe_targets",
                        lambda targets, ssh_session=None: [
                            {"session": ssh_session is not None}],
                        raising=True)

    ports = sl.default_ports()
    out = ports["probe_backends"]([{"address": "192.0.2.246", "port": 443}],
                                  use_ssh=True, appliance=Appl())
    assert seen["connected"], "the device vantage never opened its session"
    assert seen["closed"], "the session was not closed"
    assert out == [{"session": True}]


def test_without_the_device_vantage_no_session_is_opened(monkeypatch):
    from app.services import ssh_ops, backend_probe

    class Boom:
        def __init__(self, *a, **kw):
            raise AssertionError("a session was opened with use_ssh False")

    monkeypatch.setattr(ssh_ops, "FortiWebReadonlySSH", Boom, raising=True)
    monkeypatch.setattr(backend_probe, "probe_targets",
                        lambda targets, ssh_session=None: [
                            {"session": ssh_session is not None}],
                        raising=True)
    ports = sl.default_ports()
    assert ports["probe_backends"]([], use_ssh=False,
                                   appliance=Appl()) == [{"session": False}]


def test_the_live_port_is_registered_under_the_name_the_rung_asks_for():
    # A rung asking for a key nobody registers degrades to UNKNOWN in silence,
    # which is indistinguishable from a device that would not answer.
    assert "live_objects" in sl.default_ports()
