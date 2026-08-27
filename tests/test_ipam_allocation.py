"""Guards for IPAM address allocation and the provisioning DNS step.

Every test here exists because of ONE defect class, found 2026-08-27: the
provisioning runner imported four functions that had never been written
(``allocate_address``, ``release_address``, ``create_record``,
``delete_record``), each inside ``try: ... except ImportError``. The
consequences were silent in both directions:

* ticking "allocate from IPAM" ALWAYS failed, with a message blaming the
  provider ("no DNS/IPAM provider exposes address allocation") on an
  installation where a provider was configured and working;
* the DNS step ALWAYS returned **ok** with "no DNS provider configured", on
  an installation where one *was* configured. A run finished green having
  published no name at all.

The second is the dangerous one, and it is the shape this file mostly guards:
a step whose success value does not depend on whether the work happened.
"""
from __future__ import annotations

import ast
import pathlib
import re

import httpx
import pytest

from app.services import dns_providers as dp
from app.services import provision_runner as pr
from app.services.dns_providers import Address, DnsRecord, ProviderError
from app.services.dns_providers.base import mask_from_prefix, prefix_from_size
from app.services.dns_providers.efficientip import EfficientIPProvider
from app.services.dns_providers.netbox import NetBoxProvider
from app.services.dns_providers.phpipam import PhpIpamProvider

ROOT = pathlib.Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
class _Run:
    """The handful of ProvisionRun attributes the two steps touch.

    A plain object rather than the model: these guards are about the DECISION
    the step makes, and a DB row would drag a session into every one of them.
    """

    def __init__(self, **kw):
        self.hostname = kw.get("hostname", "fw99.example.com")
        self.name = kw.get("name", "fw99")
        self.mgmt_ip = kw.get("mgmt_ip", "")
        self.netmask = kw.get("netmask", "")
        self.gateway = kw.get("gateway", "")
        self.ip_from_ipam = kw.get("ip_from_ipam", True)
        self.ip_ref = kw.get("ip_ref", "")
        self.ip_pool = kw.get("ip_pool", "")
        self.dns_record_id = kw.get("dns_record_id", "")


def _caps(**kw) -> dp.Capabilities:
    base = dict(provider="fake", label="Fake DDI", can_write=True,
                record_types=["A"], needs_zone=False, needs_view=False,
                can_allocate=True, needs_pool=True)
    base.update(kw)
    return dp.Capabilities(**base)


def _mock(provider, handler):
    """Bind a provider instance to an httpx MockTransport.

    Patches ``_client`` rather than the verb under test, so the guard exercises
    the provider's REAL request building and response parsing. A guard that
    stubbed ``allocate_address`` would pass against a provider that sends
    nothing at all.
    """
    def _client():
        return httpx.Client(base_url="https://ddi.invalid",
                            transport=httpx.MockTransport(handler),
                            timeout=1.0)
    provider._client = _client
    return provider


# ---------------------------------------------------------------------------
# 1. the functions exist, at module level, and are not import-guarded
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["allocate_address", "release_address",
                                  "create_record", "delete_record",
                                  "capabilities"])
def test_module_level_operation_exists(name):
    assert callable(getattr(dp, name, None)), (
        f"dns_providers.{name} is imported by the provisioning runner; if it "
        "does not exist the runner blames the operator's provider for a bug "
        "in this package")


def test_runner_does_not_swallow_a_missing_provider_module():
    """``except ImportError`` around these imports is how the lie was told.

    The handler turned "this package is broken" into "your provider cannot do
    this". Structural, because any future re-introduction of the pattern would
    again be invisible at runtime.
    """
    tree = ast.parse((ROOT / "app/services/provision_runner.py").read_text())
    guarded = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        imports_ddi = any(
            isinstance(n, (ast.Import, ast.ImportFrom))
            and "dns_providers" in ast.dump(n)
            for n in ast.walk(node) if n is not node)
        if not imports_ddi:
            continue                      # other try/except are none of our
                                          # business (_image_path guards a
                                          # genuinely optional model import)
        for h in node.handlers:
            if h.type is not None and "ImportError" in ast.dump(h.type):
                guarded.append(node.lineno)
    assert guarded == [], (
        f"provision_runner guards a dns_providers import with ImportError at "
        f"line(s) {guarded} — a missing function has to crash loudly, not be "
        "reported as a limitation of the operator's IPAM")


# ---------------------------------------------------------------------------
# 2. "not configured" is raised, never returned as a successful value
# ---------------------------------------------------------------------------
def test_capabilities_is_none_when_no_provider(app, monkeypatch):
    with app.app_context():
        monkeypatch.setattr(dp, "active_provider", lambda: None)
        assert dp.capabilities() is None


@pytest.mark.parametrize("call", [
    lambda: dp.allocate_address(hostname="h"),
    lambda: dp.release_address("192.0.2.5", ref="7"),
    lambda: dp.create_record("h.example.com", "A", "192.0.2.5"),
    lambda: dp.delete_record("7"),
])
def test_operations_raise_when_no_provider(app, monkeypatch, call):
    with app.app_context():
        monkeypatch.setattr(dp, "active_provider", lambda: None)
        with pytest.raises(ProviderError) as exc:
            call()
        assert "no dns/ipam provider is configured" in str(exc.value).lower()


# ---------------------------------------------------------------------------
# 3. the DNS step: three outcomes, and only one of them is a pass
# ---------------------------------------------------------------------------
def test_dns_step_passes_but_says_nothing_was_published(monkeypatch):
    monkeypatch.setattr(dp, "capabilities", lambda: None)
    run = _Run(mgmt_ip="192.0.2.5")
    res = pr._step_dns_created(run)
    assert res.ok is True
    assert "NO DNS PROVIDER IS CONFIGURED" in res.detail
    assert "no record was created" in res.detail
    # The old detail could be read as an ordinary success line. This one may
    # never claim the record exists.
    assert not re.search(r"\bcreated \S+ A ", res.detail)
    assert run.dns_record_id == ""


def test_dns_step_fails_when_the_provider_cannot_write(monkeypatch):
    """A read-only backend + a requested hostname is a FAILURE.

    phpIPAM and plugin-less NetBox both land here. Reporting ok would be the
    original bug wearing a different hat: the name is not published and the
    run says it is fine.
    """
    monkeypatch.setattr(dp, "capabilities",
                        lambda: _caps(can_write=False, label="phpIPAM"))
    res = pr._step_dns_created(_Run(mgmt_ip="192.0.2.5"))
    assert res.ok is False
    assert "phpIPAM" in res.detail and "cannot create DNS records" in res.detail


def test_dns_step_creates_and_records_the_id(monkeypatch):
    seen = {}

    def _create(name, rtype="A", value="", **kw):
        seen.update(name=name, rtype=rtype, value=value)
        return DnsRecord(id="rr-42", name=name, type=rtype, value=value)

    monkeypatch.setattr(dp, "capabilities", lambda: _caps())
    monkeypatch.setattr(dp, "create_record", _create)
    run = _Run(mgmt_ip="192.0.2.5")
    res = pr._step_dns_created(run)
    assert res.ok is True
    assert run.dns_record_id == "rr-42"
    assert seen == {"name": "fw99.example.com", "rtype": "A",
                    "value": "192.0.2.5"}


def test_dns_step_fails_when_the_provider_refuses(monkeypatch):
    monkeypatch.setattr(dp, "capabilities", lambda: _caps())
    monkeypatch.setattr(dp, "create_record", lambda *a, **k: (_ for _ in ()).throw(
        ProviderError("zone is frozen")))
    res = pr._step_dns_created(_Run(mgmt_ip="192.0.2.5"))
    assert res.ok is False and "zone is frozen" in res.detail


def test_dns_step_skips_without_a_hostname(monkeypatch):
    monkeypatch.setattr(dp, "capabilities", lambda: _caps())
    res = pr._step_dns_created(_Run(hostname="", mgmt_ip="192.0.2.5"))
    assert res.ok is True and "no hostname" in res.detail


def test_dns_step_fails_without_an_address(monkeypatch):
    monkeypatch.setattr(dp, "capabilities", lambda: _caps())
    assert pr._step_dns_created(_Run(mgmt_ip="")).ok is False


# ---------------------------------------------------------------------------
# 4. the IP step
# ---------------------------------------------------------------------------
def test_ip_step_blames_the_configuration_not_the_provider(monkeypatch):
    monkeypatch.setattr(dp, "capabilities", lambda: None)
    res = pr._step_ip_reserved(_Run())
    assert res.ok is False
    assert "no dns/ipam provider is configured" in res.detail.lower()


def test_ip_step_names_the_provider_that_cannot_allocate(monkeypatch):
    monkeypatch.setattr(dp, "capabilities",
                        lambda: _caps(can_allocate=False, label="Weird DDI"))
    res = pr._step_ip_reserved(_Run())
    assert res.ok is False and "Weird DDI" in res.detail


def test_ip_step_records_the_reservation_handle(monkeypatch):
    monkeypatch.setattr(dp, "capabilities", lambda: _caps())
    monkeypatch.setattr(dp, "allocate_address", lambda **kw: Address(
        address="198.51.100.7", ref="ip-99", netmask="255.255.255.0",
        gateway="198.51.100.1", pool="198.51.100.0/24"))
    run = _Run()
    res = pr._step_ip_reserved(run)
    assert res.ok is True
    assert (run.mgmt_ip, run.ip_ref) == ("198.51.100.7", "ip-99")
    assert run.netmask == "255.255.255.0" and run.gateway == "198.51.100.1"
    assert "198.51.100.0/24" in res.detail


def test_ip_step_does_not_clobber_operator_values_with_blanks(monkeypatch):
    """An empty netmask from the pool means UNKNOWN, not "no netmask".

    NetBox core has no per-prefix gateway at all, so this is the ordinary case
    for a real backend — and overwriting a hand-entered gateway with "" writes
    a broken default route into the appliance at first boot.
    """
    monkeypatch.setattr(dp, "capabilities", lambda: _caps())
    monkeypatch.setattr(dp, "allocate_address", lambda **kw: Address(
        address="198.51.100.7", ref="ip-99", netmask="", gateway=""))
    run = _Run(netmask="255.255.255.128", gateway="198.51.100.1")
    pr._step_ip_reserved(run)
    assert run.netmask == "255.255.255.128" and run.gateway == "198.51.100.1"


def test_ip_step_passes_the_requested_pool_through(monkeypatch):
    seen = {}
    monkeypatch.setattr(dp, "capabilities", lambda: _caps())
    monkeypatch.setattr(dp, "allocate_address",
                        lambda **kw: seen.update(kw) or Address(
                            address="198.51.100.7", ref="r"))
    pr._step_ip_reserved(_Run(ip_pool="198.51.100.0/24"))
    assert seen["pool"] == "198.51.100.0/24"


def test_ip_step_uses_a_typed_address_without_claiming_it(monkeypatch):
    run = _Run(mgmt_ip="192.0.2.9", ip_from_ipam=False)
    res = pr._step_ip_reserved(run)
    assert res.ok is True and run.ip_ref == ""


# ---------------------------------------------------------------------------
# 5. rollback releases by HANDLE, and only what this run took
# ---------------------------------------------------------------------------
def test_rollback_releases_with_the_recorded_handle(app, monkeypatch):
    from app.extensions import db
    from app.models_provision import ProvisionRun

    seen = {}
    monkeypatch.setattr(dp, "release_address",
                        lambda addr, ref="": seen.update(addr=addr, ref=ref))
    with app.app_context():
        run = ProvisionRun(name="fw99", mode="semi", mgmt_ip="198.51.100.7",
                           ip_from_ipam=True, ip_ref="ip-99")
        db.session.add(run)
        db.session.commit()
        pr.rollback(run)
        assert seen == {"addr": "198.51.100.7", "ref": "ip-99"}
        assert run.ip_ref == "" and run.ip_from_ipam is False


def test_rollback_never_releases_an_address_it_did_not_take(app, monkeypatch):
    from app.extensions import db
    from app.models_provision import ProvisionRun

    called = []
    monkeypatch.setattr(dp, "release_address",
                        lambda *a, **k: called.append(a))
    with app.app_context():
        run = ProvisionRun(name="fw99", mode="semi", mgmt_ip="198.51.100.7",
                           ip_from_ipam=False, ip_ref="")
        db.session.add(run)
        db.session.commit()
        pr.rollback(run)
        assert called == []


# ---------------------------------------------------------------------------
# 6. netmask arithmetic — ONE author, and it refuses to guess
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size,want", [(256, 24), (16, 28), (1, 32),
                                       (65536, 16), (300, None), (0, None),
                                       (-8, None), ("", None), (None, None)])
def test_prefix_from_size(size, want):
    assert prefix_from_size(size) == want


@pytest.mark.parametrize("pfx,want", [(24, "255.255.255.0"), (16, "255.255.0.0"),
                                      (32, "255.255.255.255"), (0, "0.0.0.0"),
                                      (33, ""), (-1, ""), (None, ""), ("x", "")])
def test_mask_from_prefix(pfx, want):
    assert mask_from_prefix(pfx) == want


def test_mask_arithmetic_has_a_single_author():
    """Two copies of this conversion give a subnet two different masks."""
    hits = []
    for path in (ROOT / "app/services/dns_providers").glob("*.py"):
        if path.name == "base.py":
            continue
        body = re.sub(r"#.*", "", path.read_text())
        if "0xFFFFFFFF" in body:
            hits.append(path.name)
    assert hits == [], f"netmask arithmetic duplicated in {hits}"


# ---------------------------------------------------------------------------
# 7. can_allocate is INDEPENDENT of can_write — the whole reason it is its
#    own flag. phpIPAM and plugin-less NetBox are pools that cannot publish.
# ---------------------------------------------------------------------------
def test_phpipam_allocates_but_cannot_write_records():
    caps = PhpIpamProvider({"base_url": "https://x", "app_id": "a"}).capabilities()
    assert caps.can_write is False and caps.can_allocate is True


def test_netbox_core_allocates_without_the_dns_plugin():
    prov = _mock(NetBoxProvider({"base_url": "https://x"}),
                 lambda req: httpx.Response(404))   # plugin absent
    caps = prov.capabilities()
    assert caps.can_write is False and caps.can_allocate is True


def test_efficientip_does_both():
    caps = EfficientIPProvider({"base_url": "https://x"}).capabilities()
    assert caps.can_write is True and caps.can_allocate is True


# ---------------------------------------------------------------------------
# 8. every provider that allocates must also release — and must refuse to
#    release without the handle
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("cls,cfg", [
    (EfficientIPProvider, {"base_url": "https://x"}),
    (PhpIpamProvider, {"base_url": "https://x", "app_id": "a"}),
    (NetBoxProvider, {"base_url": "https://x"}),
])
def test_allocating_providers_implement_release(cls, cfg):
    from app.services.dns_providers.base import DnsProvider
    assert cls.release_address is not DnsProvider.release_address
    assert cls.allocate_address is not DnsProvider.allocate_address


def test_the_base_class_refuses_rather_than_no_ops():
    """A provider that has not implemented allocation must SAY so.

    Inherited no-ops are the same defect this whole file exists for, one level
    down: a backend that cannot release would report every rollback as a clean
    release, and the address would be stranded with nothing in the log to say
    which one. Named ``label`` so the message identifies the backend.
    """
    from app.services.dns_providers.base import DnsProvider

    class _Half(DnsProvider):
        key, label = "half", "Half-built DDI"

    prov = _Half({})
    for call in (lambda: prov.allocate_address(hostname="h"),
                 lambda: prov.release_address("192.0.2.5", ref="7")):
        with pytest.raises(ProviderError) as exc:
            call()
        assert "Half-built DDI" in str(exc.value)


@pytest.mark.parametrize("cls,cfg", [
    (EfficientIPProvider, {"base_url": "https://x"}),
    (PhpIpamProvider, {"base_url": "https://x", "app_id": "a"}),
    (NetBoxProvider, {"base_url": "https://x"}),
])
def test_release_without_a_handle_is_refused(cls, cfg):
    with pytest.raises(ProviderError) as exc:
        cls(cfg).release_address("192.0.2.5", ref="")
    assert "id" in str(exc.value).lower()


# ---------------------------------------------------------------------------
# 9. the wire, per provider — real request building, real response parsing
# ---------------------------------------------------------------------------
def test_efficientip_allocate_walks_subnet_free_add(monkeypatch):
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path, dict(req.url.params)))
        if req.url.path == "/rest/ip_block_subnet_list":
            return httpx.Response(200, json=[{"subnet_id": "12",
                                              "subnet_name": "lan",
                                              "subnet_size": "256",
                                              "subnet_ip_gateway": "198.51.100.1"}])
        if req.url.path == "/rest/ip_find_free_address":
            return httpx.Response(200, json=[{"hostaddr": "198.51.100.7"}])
        if req.url.path == "/rest/ip_add":
            return httpx.Response(201, json=[{"ret_oid": "999"}])
        return httpx.Response(500)

    prov = _mock(EfficientIPProvider({"base_url": "https://x"}), handler)
    addr = prov.allocate_address(hostname="fw99", pool="lan")
    assert (addr.address, addr.ref) == ("198.51.100.7", "999")
    assert addr.netmask == "255.255.255.0" and addr.prefix_len == 24
    assert addr.gateway == "198.51.100.1" and addr.pool == "lan"
    assert [c[1] for c in calls] == ["/rest/ip_block_subnet_list",
                                     "/rest/ip_find_free_address",
                                     "/rest/ip_add"]
    # the reservation must be new_only: edit_only would silently retarget an
    # address somebody else already holds
    assert calls[-1][2].get("add_flag") == "new_only"


def test_efficientip_refuses_a_reservation_with_no_handle():
    """An accepted write with no id is reported, not returned as success.

    Returning it would strand the address: rollback has nothing to release.
    """
    def handler(req):
        if req.url.path == "/rest/ip_block_subnet_list":
            return httpx.Response(200, json=[{"subnet_id": "12",
                                              "subnet_size": "256"}])
        if req.url.path == "/rest/ip_find_free_address":
            return httpx.Response(200, json=[{"hostaddr": "198.51.100.7"}])
        return httpx.Response(201, json=[{}])

    prov = _mock(EfficientIPProvider({"base_url": "https://x"}), handler)
    with pytest.raises(ProviderError) as exc:
        prov.allocate_address(pool="lan")
    assert "198.51.100.7" in str(exc.value)


def test_efficientip_release_deletes_by_ip_id():
    seen = {}

    def handler(req):
        seen.update(method=req.method, path=req.url.path,
                    params=dict(req.url.params))
        return httpx.Response(200, json=[{}])

    _mock(EfficientIPProvider({"base_url": "https://x"}), handler)\
        .release_address("198.51.100.7", ref="999")
    assert seen["method"] == "DELETE" and seen["path"] == "/rest/ip_delete"
    assert seen["params"] == {"ip_id": "999"}


def test_phpipam_allocate_is_a_single_server_side_write():
    """``first_free`` must be a POST.

    Reading the next free address and POSTing it back races two operators into
    the same address; phpIPAM picks AND writes in one call for that reason.
    """
    calls = []

    def handler(req):
        calls.append((req.method, req.url.path))
        if req.url.path.endswith("/addresses/first_free/"):
            return httpx.Response(201, json={"id": "55", "data": "198.51.100.7"})
        if "/subnets/" in req.url.path:
            return httpx.Response(200, json={"data": {
                "subnet": "198.51.100.0", "mask": "24",
                "gateway": {"ip_addr": "198.51.100.1"}}})
        return httpx.Response(404)

    prov = _mock(PhpIpamProvider({"base_url": "https://x", "app_id": "a"}),
                 handler)
    addr = prov.allocate_address(hostname="fw99", pool="7")
    assert (addr.address, addr.ref) == ("198.51.100.7", "55")
    assert addr.netmask == "255.255.255.0" and addr.gateway == "198.51.100.1"
    assert ("POST", "/addresses/first_free/") in [
        (m, p if p.startswith("/addresses") else p) for m, p in calls]
    assert not any(m == "GET" and "first_free" in p for m, p in calls)


def test_phpipam_release_treats_a_missing_row_as_done():
    """Releasing twice is not an error — a rollback retried must converge."""
    prov = _mock(PhpIpamProvider({"base_url": "https://x", "app_id": "a"}),
                 lambda req: httpx.Response(404))
    prov.release_address("198.51.100.7", ref="55")   # must not raise


def test_netbox_allocate_posts_to_available_ips():
    calls = []

    def handler(req):
        calls.append((req.method, req.url.path))
        if req.url.path == "/api/ipam/prefixes/" :
            return httpx.Response(200, json={"results": [{"id": 3}]})
        if req.url.path == "/api/ipam/prefixes/3/available-ips/":
            return httpx.Response(201, json={"id": 88,
                                             "address": "198.51.100.7/24"})
        return httpx.Response(404)

    prov = _mock(NetBoxProvider({"base_url": "https://x"}), handler)
    addr = prov.allocate_address(hostname="fw99", pool="198.51.100.0/24")
    assert (addr.address, addr.ref) == ("198.51.100.7", "88")
    assert addr.netmask == "255.255.255.0"
    # NetBox core does not model a gateway; ".1" is a guess that becomes a
    # default route on a real appliance.
    assert addr.gateway == ""
    assert ("POST", "/api/ipam/prefixes/3/available-ips/") in calls


def test_netbox_reports_an_exhausted_prefix():
    def handler(req):
        if req.url.path == "/api/ipam/prefixes/":
            return httpx.Response(200, json={"results": [{"id": 3}]})
        return httpx.Response(409, json={"detail": "no available ips"})

    prov = _mock(NetBoxProvider({"base_url": "https://x"}), handler)
    with pytest.raises(ProviderError) as exc:
        prov.allocate_address(pool="198.51.100.0/24")
    assert "no free address" in str(exc.value)


def test_allocation_without_a_pool_is_refused_not_guessed(monkeypatch):
    """No pool and no default = an error, never "any pool"."""
    for cls, cfg in ((EfficientIPProvider, {"base_url": "https://x"}),
                     (PhpIpamProvider, {"base_url": "https://x", "app_id": "a"}),
                     (NetBoxProvider, {"base_url": "https://x"})):
        prov = _mock(cls(cfg), lambda req: httpx.Response(200, json={}))
        with pytest.raises(ProviderError) as exc:
            prov.allocate_address(hostname="fw99")
        assert "default" in str(exc.value).lower()


# ---------------------------------------------------------------------------
# 10. the migration actually reaches an installation that predates it
# ---------------------------------------------------------------------------
def test_provision_run_columns_are_in_the_boot_migration():
    """``db.create_all()`` never ALTERs, so a new column on an existing table
    only exists on installs created after it. Without this entry the two
    columns are present in the model and absent in every live database."""
    src = (ROOT / "app/__init__.py").read_text()
    block = src.split("def _ensure_columns")[1].split("insp = inspect")[0]
    assert "'provision_runs'" in block
    assert "('ip_ref'" in block and "('ip_pool'" in block


def test_provision_run_model_declares_the_columns(app):
    from app.models_provision import ProvisionRun
    cols = {c.name for c in ProvisionRun.__table__.columns}
    assert {"ip_ref", "ip_pool"} <= cols
