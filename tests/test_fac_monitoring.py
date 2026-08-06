"""Monitoring for FortiAuthenticator — the product whose signals are not traffic.

Everything the other three products measure assumes a *forwarding* appliance:
throughput, sessions per policy, interface link state. A FortiAuthenticator has
none of those. What bounds it is ENTITLEMENT — ``fac01`` ships
``users_usage_detail {max: 5}`` unlicensed and simply refuses the sixth user —
and its token supply. Applying the Monitoring pages here therefore meant
replacing the signals, not copying them.

The guards below protect four properties, each of which has a matching scar in
this repo:

1. **One product map.** ``KIND_PRODUCTS`` is the single source the runner,
   discovery, the baseline builder and the form validator all consult. Four
   copies of a product rule is four chances to add a fifth product and cover it
   in three places.
2. **Nothing is asked in the wrong language.** ``get system performance`` and
   ``diagnose system top`` both answer ``No such command.`` on this product —
   a SUCCESSFUL SSH round trip carrying no reading, which the FortiWeb parser
   turns into a missing value rather than an error. FAC box metrics must ride
   REST and must never open an SSH session.
3. **Absence is never health.** A licence counter with no ceiling and a token
   pool with nothing imported are ``unknown``, never ``ok`` and never a
   fabricated 0 %.
4. **Same threshold direction everywhere.** Both FAC kinds grade on percent
   CONSUMED, so no single row on the page means "at or below is bad".
"""
from __future__ import annotations

import pytest

from app.models import Appliance, MonitorProbe, db
from app.services import deep_monitor as dm
from app.services import ha_inventory
from app.services import metrics_collect as mc

FAC = "fortiauthenticator"

# The payload fac01 (FACVMKVM v8.0.3 build0099) actually returned on 2026-08-05.
LIVE = {
    "cpu": "0%", "memory": "64%", "disk": "0%",
    "memory_usage_detail": {"available": "1427344.0 KB",
                            "total": "4032452.0 KB", "used": "2605108.0 KB"},
    "disk_usage_detail": {"total": "59768832.0 KB", "used": "0.0 KB"},
    "users_usage_detail": {"max": 5, "used": 2},
    "groups_usage_detail": {"max": 3, "used": 0},
    "fsso_usage_detail": {"max": 5, "used": 0},
    "ssoma_usage_detail": {"max": 5, "used": 0},
    "ftk_usage_detail": {"populated": 0, "used": 0},
    "ftm_usage_detail": {"populated": 0, "used": 0},
    "ha_sn": "", "sn": "FAC-VM0000000000",
    "firmware": "FACVMKVM v8.0.3, build0099 (GA)",
}


class FakeProbe:
    """Probe-shaped object: the runners only ever read attributes."""

    def __init__(self, **kw):
        self.kind = "licence"
        self.target = ""
        self.timeout_s = 15
        self.warn_num = 0.0
        self.crit_num = 0.0
        self.warn_pct = 0.0
        self.crit_pct = 0.0
        self.appliance = None
        self.__dict__.update(kw)


class FakeAppliance:
    def __init__(self, kind=FAC, name="fac01"):
        self.kind = kind
        self.name = name
        self.id = 1
        self.host = "192.0.2.19"
        self.port = 443
        self.verify_ssl = False
        self.username = "admin"
        self.password = "key"
        self.maintenance = False


def _fac_probe(**kw):
    return FakeProbe(appliance=FakeAppliance(), **kw)


def _stub_systeminfo(monkeypatch, payload=None):
    """Make every FAC client hand back one canned ``systeminfo``."""
    from app.clients import fortiauthenticator as fac

    monkeypatch.setattr(fac.FortiAuthenticatorClient, "sys_status",
                        lambda self: (LIVE if payload is None else payload),
                        raising=True)


def _explode_on_ssh(monkeypatch):
    """Any SSH attempt becomes a loud failure instead of a slow timeout."""
    from app.services import ssh_ops

    def _boom(*a, **k):  # pragma: no cover - only runs when the guard fails
        raise AssertionError("a FortiAuthenticator probe opened an SSH session")

    monkeypatch.setattr(ssh_ops, "run_command", _boom, raising=True)


# ---------------------------------------------------------------------------
# 1. the product map is complete, and it is the ONLY map
# ---------------------------------------------------------------------------

def test_every_kind_declares_which_products_can_answer_it():
    # A kind missing from the map is refused by `supports` for EVERY product,
    # so it would be creatable from the form and unrunnable by the runner.
    assert set(dm.KIND_PRODUCTS) == set(dm.KINDS)


def test_supports_refuses_an_unknown_kind_rather_than_defaulting_open():
    assert dm.supports("no-such-kind", "fortiweb") is False


def test_supports_refuses_an_unknown_product():
    # "" is what an appliance-less probe reports. Only a product-agnostic kind
    # may pass; a device kind we do not recognise must not be assumed capable.
    assert dm.supports("sessions", "") is False
    assert dm.supports("licence", "netscaler") is False


def test_https_is_product_agnostic_because_it_never_touches_the_device_api():
    assert dm.products_for("https") == ()
    for product in ("fortiweb", FAC, "", "anything"):
        assert dm.supports("https", product) is True


@pytest.mark.parametrize("kind", ["interface", "proxyd", "sessions",
                                  "policy_sessions", "throughput",
                                  "transactions"])
def test_fortiauthenticator_is_never_offered_a_forwarding_signal(kind):
    assert dm.supports(kind, FAC) is False


@pytest.mark.parametrize("kind", ["licence", "tokens"])
def test_the_identity_kinds_are_offered_to_no_other_product(kind):
    assert dm.products_for(kind) == (FAC,)
    for other in ("fortiweb", "fortiadc", "fortianalyzer"):
        assert dm.supports(kind, other) is False


def test_fac_gets_exactly_the_kinds_it_can_answer():
    assert set(dm.kinds_for(FAC)) == {"https", "cpu", "memory",
                                      "licence", "tokens"}


def test_api_products_is_derived_from_the_kind_map_not_relisted():
    # Adding a REST kind must enrol its product in the same edit. A hand-kept
    # tuple is how the Service Monitor page ends up offering a product it has
    # no kinds for.
    expected = {p for k in dm.API_KINDS for p in dm.KIND_PRODUCTS[k]}
    assert set(dm.API_PRODUCTS) == expected
    assert FAC in dm.API_PRODUCTS


# ---------------------------------------------------------------------------
# 2. the device is asked in its own language
# ---------------------------------------------------------------------------

def test_fac_box_metrics_never_open_an_ssh_session(monkeypatch):
    # `get system performance` returns the literal string "No such command." on
    # this product: a SUCCESSFUL round trip with no reading. Routing FAC through
    # the CLI parser would grade a missing value, not report an error.
    _explode_on_ssh(monkeypatch)
    _stub_systeminfo(monkeypatch)
    out = dm.run_box(_fac_probe(kind="memory"), "memory")
    assert out["status"] == "ok"
    assert out["payload"]["transport"] == "rest"
    assert out["value_num"] == 64.0


def test_fac_cpu_reads_the_rest_percentage(monkeypatch):
    _explode_on_ssh(monkeypatch)
    _stub_systeminfo(monkeypatch)
    out = dm.run_box(_fac_probe(kind="cpu"), "cpu")
    assert out["value_num"] == 0.0


def test_a_kind_the_product_cannot_answer_is_refused_by_name(monkeypatch):
    _explode_on_ssh(monkeypatch)
    client, err = dm._api_client(_fac_probe(kind="throughput"))
    assert client is None
    assert "fortiweb" in err["detail"] and FAC in err["detail"]
    assert err["status"] == "error"


def test_the_identity_kinds_are_refused_on_a_fortiweb():
    probe = FakeProbe(kind="licence", appliance=FakeAppliance(kind="fortiweb"))
    client, err = dm._api_client(probe)
    assert client is None
    assert FAC in err["detail"]


# ---------------------------------------------------------------------------
# 3. parsing the one call every FAC reader shares
# ---------------------------------------------------------------------------

def test_percentages_arrive_as_suffixed_strings():
    # float("64%") raises. A naive coercion turns every reading on a healthy box
    # into an exception, and every exception into an `error` sample.
    assert dm.fac_pct("64%") == 64.0
    assert dm.fac_pct("0%") == 0.0
    assert dm.fac_pct(64) == 64.0
    assert dm.fac_pct(None) is None
    assert dm.fac_pct("n/a") is None


def test_usage_details_are_kilobytes():
    assert dm.fac_bytes("4032452.0 KB") == int(4032452.0 * 1024)
    assert dm.fac_bytes("1.0 MB") == 1024 ** 2
    # Unit-less numbers follow the firmware's own convention.
    assert dm.fac_bytes(1024) == 1024 * 1024


def test_parse_maps_the_live_payload():
    p = dm.parse_fac_systeminfo(LIVE)
    assert p["cpu_busy"] == 0.0
    assert p["mem_used_pct"] == 64.0
    assert p["disk_used_pct"] == 0.0
    assert p["capacity"]["users"] == {"used": 2, "total": 5, "pct": 40.0}
    assert p["tokens"]["ftm"] == {"used": 0, "total": 0, "pct": None}
    assert p["ha_peer_sn"] == ""


def test_licence_and_token_ceilings_are_read_by_NAME_not_position():
    # The vendor spells them differently: licences use `max`, token pools use
    # `populated`. They mean different things — permitted vs imported — so a
    # positional read would report an unlicensed feature as a full pool.
    p = dm.parse_fac_systeminfo({
        "users_usage_detail": {"max": 100, "used": 7},
        "ftm_usage_detail": {"populated": 40, "used": 9},
    })
    assert p["capacity"]["users"]["total"] == 100
    assert p["tokens"]["ftm"]["total"] == 40


def test_a_collection_shaped_payload_still_parses():
    # The client unwraps the singleton today; a firmware that starts wrapping it
    # must degrade to correct, not to empty.
    assert dm.parse_fac_systeminfo([LIVE])["mem_used_pct"] == 64.0


def test_no_ceiling_yields_no_percentage_rather_than_zero():
    p = dm.parse_fac_systeminfo({"fsso_usage_detail": {"max": 0, "used": 0}})
    assert p["capacity"]["fsso"]["pct"] is None


# ---------------------------------------------------------------------------
# 4. absence is never health
# ---------------------------------------------------------------------------

def test_a_licence_counter_with_no_ceiling_is_unknown_not_ok():
    status, detail = dm.classify_licence(
        "fsso", {"used": 0, "total": 0, "pct": None}, warn_num=80, crit_num=95)
    assert status == "unknown"
    assert "no ceiling" in detail


def test_an_empty_token_pool_is_unknown_not_ok():
    status, detail = dm.classify_tokens(
        "ftm", {"used": 0, "total": 0, "pct": None}, warn_num=80, crit_num=95)
    assert status == "unknown"
    assert "nothing to assign" in detail


def test_a_counter_the_device_did_not_report_is_an_error():
    status, _ = dm.classify_licence("users", None, warn_num=0, crit_num=0)
    assert status == "error"
    status, _ = dm.classify_tokens("ftm", None, warn_num=0, crit_num=0)
    assert status == "error"


def test_the_capacity_collector_omits_a_percentage_it_cannot_compute(monkeypatch):
    _stub_systeminfo(monkeypatch)
    lines = [l for l in mc._collect_capacity(FakeAppliance(), {}, 1) if l]
    text = "\n".join(lines)
    # Both token pools are empty on this device: used/total are facts, a
    # percentage would be an invention.
    assert "satom_fac_token_total" in text
    assert "satom_fac_token_pct" not in text
    # The licensed-users counter DOES have a ceiling, so its percentage is real.
    assert 'satom_fac_licence_pct{device="fac01",kind="fortiauthenticator",resource="users"} 40' in text


def test_the_capacity_collector_publishes_ha_presence_as_a_series(monkeypatch):
    # FortiAuthenticator exposes no HA resource, and the config harvest excludes
    # systeminfo as volatile — so this series is the ONLY durable HA signal.
    _stub_systeminfo(monkeypatch)
    assert any("satom_fac_ha_peer" in l
               for l in mc._collect_capacity(FakeAppliance(), {}, 1) if l)


# ---------------------------------------------------------------------------
# 5. one threshold direction on the whole page
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("used,total,warn,crit,expect", [
    (2, 5, 80, 95, "ok"),        # 40 %
    (4, 5, 80, 95, "warn"),      # 80 % — at the line is over the line
    (5, 5, 80, 95, "crit"),      # 100 %
    (5, 5, 0, 0, "ok"),          # 0 disables both levels
])
def test_licence_grades_on_percent_consumed(used, total, warn, crit, expect):
    cap = {"used": used, "total": total,
           "pct": round(used / total * 100.0, 1)}
    status, _ = dm.classify_licence("users", cap, warn_num=warn, crit_num=crit)
    assert status == expect


def test_tokens_grade_in_the_same_direction_as_everything_else():
    # The operator's worry is the opposite one ("am I running OUT"), but a page
    # where exactly one row means "at or below is bad" is a page where the next
    # threshold gets set backwards. The free count lives in the detail line.
    full = {"used": 39, "total": 40, "pct": 97.5}
    status, detail = dm.classify_tokens("ftm", full, warn_num=80, crit_num=95)
    assert status == "crit"
    assert "1 free" in detail
    empty_pool_mostly_free = {"used": 1, "total": 40, "pct": 2.5}
    status, _ = dm.classify_tokens("ftm", empty_pool_mostly_free,
                                   warn_num=80, crit_num=95)
    assert status == "ok"


def test_both_identity_kinds_declare_a_percent_unit():
    for kind in ("licence", "tokens"):
        assert "%" in dm.NUM_UNIT[kind]


# ---------------------------------------------------------------------------
# 6. discovery and the baseline create only what the device can answer
# ---------------------------------------------------------------------------

@pytest.fixture()
def fac_device(app):
    with app.app_context():
        a = Appliance(name="fac01", host="192.0.2.19", kind=FAC,
                      username="admin")
        a.password = "key"
        db.session.add(a)
        db.session.commit()
        return a.id


def test_baseline_on_a_fac_creates_no_interface_or_proxyd_row(app, fac_device,
                                                              monkeypatch):
    _explode_on_ssh(monkeypatch)
    with app.app_context():
        a = db.session.get(Appliance, fac_device)
        made = dm.ensure_baseline(a)["created"]
        assert set(made) == {"cpu", "memory"}
        kinds = {p.kind for p in
                 MonitorProbe.query.filter_by(appliance_id=a.id).all()}
        assert "interface" not in kinds and "proxyd" not in kinds


def test_interface_discovery_refuses_with_a_reason(app, fac_device):
    with app.app_context():
        a = db.session.get(Appliance, fac_device)
        out = dm.discover_interface_probes(a)
        assert out["created"] == 0
        assert "no interface resource" in out["error"]


def test_fac_discovery_skips_counters_with_no_ceiling_and_names_them(
        app, fac_device, monkeypatch):
    _stub_systeminfo(monkeypatch, {
        "users_usage_detail": {"max": 5, "used": 2},
        "groups_usage_detail": {"max": 0, "used": 0},
        "ftm_usage_detail": {"populated": 0, "used": 0},
    })
    with app.app_context():
        a = db.session.get(Appliance, fac_device)
        out = dm.discover_api_probes(a)
        rows = MonitorProbe.query.filter_by(appliance_id=a.id).all()
        assert {(p.kind, p.target) for p in rows} == {("licence", "users")}
        # A row that could only ever say "unknown" is not coverage; the reason
        # it was not created has to be visible.
        joined = " ".join(out["not_applicable"])
        assert "user groups" in joined and "FortiToken Mobile" in joined


def test_discovered_fac_probes_carry_thresholds(app, fac_device, monkeypatch):
    # A probe that can never say anything would make "discovery created 4
    # probes" read as coverage.  Since 2026-08-06 discovery stores NULL so the
    # probe inherits, so the assertion has to be about the RESOLVED limit --
    # asserting the stored column would only prove a literal was written and
    # would pass even if the inheritance chain were broken.
    from app.services import thresholds as th
    _stub_systeminfo(monkeypatch)
    with app.app_context():
        a = db.session.get(Appliance, fac_device)
        dm.discover_api_probes(a)
        rows = MonitorProbe.query.filter_by(appliance_id=a.id,
                                            kind="licence").all()
        assert rows, "discovery created no licence probe to grade"
        for p in rows:
            warn = th.num(p, "warn_num", kind="licence")
            crit = th.num(p, "crit_num", kind="licence")
            assert warn and crit and crit > warn
            assert p.interval_min % dm.DEFAULT_PROBE_INTERVAL_MIN == 0


# ---------------------------------------------------------------------------
# 7. collection targets
# ---------------------------------------------------------------------------

def test_every_declared_collector_has_a_runner():
    assert set(mc._RUNNERS) == set(mc.COLLECTORS)


def test_fac_collects_box_and_capacity_only():
    assert set(mc.collectors_for(FAC)) == {"box", "capacity"}


def test_the_forwarding_collectors_stay_off_the_identity_product():
    for key in ("policies", "interfaces", "traffic", "transactions"):
        assert FAC not in mc.COLLECTORS[key]["products"]


def test_fac_box_collection_uses_rest(monkeypatch):
    _explode_on_ssh(monkeypatch)
    _stub_systeminfo(monkeypatch)
    lines = [l for l in mc._collect_box(FakeAppliance(), {}, 1) if l]
    assert any("satom_box_disk_total_bytes" in l for l in lines)


# ---------------------------------------------------------------------------
# 8. HA posture explains itself instead of giving impossible advice
# ---------------------------------------------------------------------------

def test_fac_ha_posture_is_unknown_and_says_why(app, fac_device):
    with app.app_context():
        a = db.session.get(Appliance, fac_device)
        st = ha_inventory.posture(a)
        # unknown, NEVER standalone: we have not measured this box's HA state.
        assert st["status"] == ha_inventory.STATUS_UNKNOWN
        assert st["reason"]
        # The default page copy tells the operator to run a device sync. For
        # this product that advice can never work — the sync already succeeds
        # and there is no HA object to harvest.
        assert "no HA resource" in st["reason"]


def test_the_ha_reason_is_rendered_instead_of_the_sync_advice():
    import io
    import os
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "app", "templates", "monitoring", "index.html")
    src = io.open(path, encoding="utf-8").read()
    # Executable lines only: the comment explaining the guard names the very
    # string the guard is about.
    code = "\n".join(l for l in src.splitlines()
                     if not l.strip().startswith("//"))
    assert "p.reason ? p.reason" in code


# ---------------------------------------------------------------------------
# 9. the form cannot create what the runner will refuse
# ---------------------------------------------------------------------------

def test_the_two_pages_still_partition_every_kind():
    from app.views import deep_monitor as deep
    from app.views import service_monitor as svc

    assert set(deep.KINDS) | set(svc.KINDS) == set(dm.KINDS)
    assert not (set(deep.KINDS) & set(svc.KINDS))


def test_the_identity_kinds_live_on_service_monitor():
    from app.views import service_monitor as svc

    assert {"licence", "tokens"} <= set(svc.KINDS)


def test_the_traffic_rollup_excludes_the_identity_product(app, fac_device):
    """The per-device traffic cards consolidate policy rows and throughput
    stats. A FortiAuthenticator produces neither, so including it would render
    a card that says "no traffic" about a device that has no traffic to have."""
    from app.services import service_rollup

    with app.app_context():
        a = db.session.get(Appliance, fac_device)
        out = service_rollup.device_rollup([a])
        assert out == [] or all(r.get("id") != a.id for r in out)


def test_the_policy_picker_is_not_offered_to_the_identity_product():
    # API_PRODUCTS now spans two products; anything that means "has server
    # policies" must derive from the policy-addressed kind instead.
    assert dm.products_for("policy_sessions") == ("fortiweb",)
    assert FAC in dm.API_PRODUCTS          # ...and the two are NOT the same set


def test_the_form_ships_the_same_target_allowlist_the_validator_uses():
    from app.views import service_monitor as svc

    page = svc.SPEC.as_dict("/monitoring/services")
    assert {o["value"] for o in page["targets"]["licence"]} == set(dm.FAC_CAPACITY)
    assert {o["value"] for o in page["targets"]["tokens"]} == set(dm.FAC_TOKENS)
