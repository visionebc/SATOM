"""Per-build resolution in the services (registry.loader.resolve_for / registry_for).

The registry serves ONE URN per name to the whole fleet. Once a baseline pinned
at 7.6.8 disables the names 7.6.8 measured ABSENT, a box on 8.0.5 that DOES
serve them would lose them — silently, as an "unknown endpoint" — and a box on
7.6.8 keeps being sent names it does not have. These guards pin the per-build
contract (docs/api-library.md §9 "Per-build resolution in the services"): an
operator's row wins, then what the library measured on that exact build, then
the enabled registry; the fleet view keeps a disabled name on offer while a
live build serves it.
"""
from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from app.extensions import db
from app.models import Appliance, RegistryEndpoint
from app.registry import loader
from app.services import api_baseline as ab
from app.services import api_library as lib

FW = "fortiweb"
NEW = "8.0.5"      # the build that serves the names the 7.6.8 baseline drops
OLD = "7.6.8"
EXTRA = "waf_mcp_security_policy"          # baseline-owned; disabled by the promotion
EXTRA_URN = "/api/v2.0/cmdb/waf/mcp-security.policy"


@pytest.fixture()
def ctx(app):
    with app.app_context():
        loader.invalidate_build_views()
        yield app
        loader.invalidate_build_views()


def _sweep(product, version, endpoints, device="box1"):
    """Ingest one measured sweep of ``product`` at ``version`` (as in test_api_baseline)."""
    out = lib.ingest({
        "product": product, "source": "sweep", "captured_at": "2026-09-26T00:00:00",
        "origin_ref": "test:%s@%s" % (device, version),
        "device": {"appliance_id": None, "name": device, "serial": "", "model": "",
                   "hw_type": "vm", "firmware_raw": version},
        "scope": {"kind": "build", "version": version, "build": ""},
        "healthy": True, "skip_reason": "",
        "endpoints": endpoints,
    })
    loader.invalidate_build_views()
    return out


def _ep(urn, verdict="ok"):
    return {"urn": urn, "section": "s", "verdict": verdict, "rows": 1, "fields": {}}


def _row(product, name):
    return RegistryEndpoint.query.filter_by(product=product, name=name).one()


def _set(product, name, **kw):
    r = _row(product, name)
    for k, v in kw.items():
        setattr(r, k, v)
    db.session.commit()
    ab._invalidate(product)
    return r


def _disable_owned(product, name):
    """What a promotion does to a name its build measured absent: the row stays
    baseline-owned and is disabled."""
    r = _row(product, name)
    assert ab.is_owned(r.updated_by)
    return _set(product, name, enabled=False)


def _appliance(name, kind="fortiweb", firmware=NEW, **kw):
    a = Appliance(name=name, kind=kind, host="%s.test" % name, port=443,
                  username="admin", verify_ssl=False, firmware=firmware, **kw)
    a.password = "secret"
    db.session.add(a)
    db.session.commit()
    loader.invalidate_build_views()
    return a


def _names(product, n):
    return sorted(loader.load_product_registry(product))[:n]


# --------------------------------------------------------------------------
# EndpointNotServed
# --------------------------------------------------------------------------

def test_endpoint_not_served_is_a_readable_key_error():
    exc = loader.EndpointNotServed(FW, "x_name", NEW, "evidence: sweep")
    assert isinstance(exc, KeyError)
    assert (exc.product, exc.name, exc.version, exc.authority) == (
        FW, "x_name", NEW, "evidence: sweep")
    # str(KeyError) would wrap the text in quotes; the message is the message
    assert str(exc) == "x_name is not served by fortiweb 8.0.5 (evidence: sweep)"


# --------------------------------------------------------------------------
# resolve_for — the four rules
# --------------------------------------------------------------------------

def test_resolve_for_measured_urn_and_measured_absent(ctx):
    moved, absent, unmeasured = _names(FW, 3)
    _sweep(FW, NEW, {moved: _ep("/api/v2.0/cmdb/moved/on-805"),
                     absent: _ep(loader.load_registry()[absent], verdict="absent")})
    assert loader.resolve_for(FW, moved, NEW) == "/api/v2.0/cmdb/moved/on-805"
    with pytest.raises(loader.EndpointNotServed) as ei:
        loader.resolve_for(FW, absent, NEW)
    assert ei.value.version == NEW and "sweep" in ei.value.authority
    assert str(ei.value).startswith("%s is not served by fortiweb 8.0.5 (" % absent)
    # (c) the build has evidence, just not about this name -> the registry
    assert loader.resolve_for(FW, unmeasured, NEW) == loader.resolve(unmeasured)


def test_resolve_for_operator_row_wins_over_the_evidence(ctx):
    kept, off = _names(FW, 2)
    _sweep(FW, NEW, {kept: _ep("", verdict="absent"),
                     off: _ep("/api/v2.0/cmdb/served/here")})
    _set(FW, kept, urn="/api/v2.0/cmdb/operator/fix", updated_by="alice")
    _set(FW, off, enabled=False, updated_by="bob")
    assert loader.resolve_for(FW, kept, NEW) == "/api/v2.0/cmdb/operator/fix"
    with pytest.raises(loader.EndpointNotServed) as ei:
        loader.resolve_for(FW, off, NEW)
    assert "bob" in ei.value.authority


def test_resolve_for_serves_a_disabled_baseline_row_the_build_measured(ctx):
    _disable_owned(FW, EXTRA)
    _sweep(FW, NEW, {EXTRA: _ep(EXTRA_URN)})
    with pytest.raises(KeyError):
        loader.resolve(EXTRA)                       # the pure registry dropped it
    assert loader.resolve_for(FW, EXTRA, NEW) == EXTRA_URN
    with pytest.raises(KeyError):
        loader.resolve_for(FW, EXTRA, OLD)          # unmeasured build: registry


def test_resolve_for_unknown_name_keeps_each_products_message(ctx):
    for product, word in ((FW, "unknown registry endpoint"),
                          ("fortiadc", "unknown FortiADC registry endpoint"),
                          ("fortianalyzer", "unknown FortiAnalyzer registry endpoint"),
                          ("fortiauthenticator",
                           "unknown FortiAuthenticator registry endpoint")):
        with pytest.raises(KeyError) as ei:
            loader.resolve_for(product, "no_such_endpoint", NEW)
        assert not isinstance(ei.value, loader.EndpointNotServed)
        assert word in str(ei.value)


@pytest.mark.parametrize("version", ["", None, "garbage", "8.0"])
def test_resolve_for_without_a_build_is_exactly_the_registry(ctx, version):
    absent, off = _names(FW, 2)
    _sweep(FW, NEW, {absent: _ep("", verdict="absent")})
    _sweep(FW, "8.0", {absent: _ep("", verdict="absent")}, device="line")
    _set(FW, off, enabled=False, updated_by="bob")
    assert loader.resolve_for(FW, absent, version) == loader.resolve(absent)
    with pytest.raises(KeyError) as ei:
        loader.resolve_for(FW, off, version)
    assert not isinstance(ei.value, loader.EndpointNotServed)
    assert str(ei.value) == str(pytest.raises(KeyError, loader.resolve, off).value)


def test_resolve_for_falls_back_to_the_registry_when_evidence_is_unreadable(
        ctx, monkeypatch, caplog):
    name = _names(FW, 1)[0]
    _sweep(FW, NEW, {name: _ep("", verdict="absent")})

    def boom(*_a, **_k):
        raise RuntimeError("database is gone")
    monkeypatch.setattr(ab, "_measured_at", boom)
    with caplog.at_level(logging.WARNING, logger="app.registry.loader"):
        assert loader.resolve_for(FW, name, NEW) == loader.resolve(name)
        assert loader.registry_for(FW, NEW) == loader.load_registry()
    assert "database is gone" in caplog.text


# --------------------------------------------------------------------------
# registry_for — the same rules as a whole map
# --------------------------------------------------------------------------

def test_registry_for_applies_every_rule(ctx):
    absent, moved, op_kept, op_moved, plain = _names(FW, 5)
    _disable_owned(FW, EXTRA)
    op_off = _names(FW, 6)[5]
    _set(FW, op_kept, updated_by="alice")
    _set(FW, op_moved, updated_by="alice")
    _set(FW, op_off, enabled=False, updated_by="bob")
    reg = dict(loader.load_registry())
    _sweep(FW, NEW, {
        absent: _ep("", verdict="absent"),
        moved: _ep("/api/v2.0/cmdb/moved"),
        op_kept: _ep("", verdict="absent"),
        op_moved: _ep("/api/v2.0/cmdb/evidence-says"),
        op_off: _ep("/api/v2.0/cmdb/op-off"),
        EXTRA: _ep(EXTRA_URN),
        "never_registered": _ep("/api/v2.0/cmdb/nobody"),
    })
    got = loader.registry_for(FW, NEW)
    assert absent not in got                        # measured absent: dropped
    assert got[moved] == "/api/v2.0/cmdb/moved"     # measured URN replaces
    assert got[op_kept] == reg[op_kept]             # operator row survives absent
    assert got[op_moved] == reg[op_moved]           # operator URN beats evidence
    assert op_off not in got                        # operator-disabled stays off
    assert got[EXTRA] == EXTRA_URN                  # owned-disabled, served: added
    assert "never_registered" not in got            # only names with a registry row
    assert got[plain] == reg[plain]
    # no build -> the pure registry, untouched
    assert loader.registry_for(FW, "") == loader.load_registry()
    assert EXTRA not in loader.registry_for(FW, OLD)


def test_registry_for_caches_per_version(ctx):
    name = _names(FW, 1)[0]
    _sweep(FW, NEW, {name: _ep("", verdict="absent")})
    _sweep(FW, "8.0.6", {name: _ep("/api/v2.0/cmdb/on-806")}, device="box2")
    assert name not in loader.registry_for(FW, NEW)
    # a second build inside the TTL must not be served the first one's map
    assert loader.registry_for(FW, "8.0.6")[name] == "/api/v2.0/cmdb/on-806"
    assert name not in loader.registry_for(FW, "8.0.5,build0123")   # same build key
    assert ("fortiweb", NEW) in loader._build_cache


@pytest.mark.parametrize("product,invalidate", [
    (FW, loader.invalidate_cache),
    ("fortiadc", loader.invalidate_adc_cache),
    ("fortianalyzer", loader.invalidate_faz_cache),
    ("fortiauthenticator", loader.invalidate_fac_cache),
    (FW, lambda: ab._invalidate(FW)),
    ("fortiauthenticator", lambda: ab._invalidate("fortiauthenticator")),
])
def test_registry_edits_drop_the_per_build_views(ctx, product, invalidate):
    loader.registry_for(product, NEW)
    assert (product, NEW) in loader._build_cache
    invalidate()
    assert (product, NEW) not in loader._build_cache


def test_an_operator_edit_is_seen_by_the_next_per_build_read(ctx):
    name = _names(FW, 1)[0]
    _sweep(FW, NEW, {name: _ep("/api/v2.0/cmdb/evidence")})
    assert loader.registry_for(FW, NEW)[name] == "/api/v2.0/cmdb/evidence"
    r = _row(FW, name)
    r.urn, r.updated_by = "/api/v2.0/cmdb/operator", "alice"
    db.session.commit()
    loader.invalidate_cache()                       # what every registry write calls
    assert loader.registry_for(FW, NEW)[name] == "/api/v2.0/cmdb/operator"


# --------------------------------------------------------------------------
# the fleet view (get_all_endpoints) vs the pure registry
# --------------------------------------------------------------------------

def _names_of(endpoints):
    return {e["name"] for e in endpoints}


def test_fleet_view_offers_a_disabled_name_while_a_live_build_serves_it(ctx):
    _disable_owned(FW, EXTRA)
    _sweep(FW, NEW, {EXTRA: _ep(EXTRA_URN)})
    _appliance("fw-old", firmware=OLD)
    assert EXTRA not in _names_of(loader.get_all_endpoints())   # only 7.6.8 in fleet
    box = _appliance("fw-new", firmware="FortiWeb-VM v8.0.5,build0123")
    assert EXTRA in _names_of(loader.get_all_endpoints())
    assert EXTRA not in _names_of(loader.get_registry_endpoints())
    assert EXTRA not in loader.load_registry()                  # the registry is pure
    # the 8.0.x box leaves the live fleet -> the name leaves the menus
    box.maintenance = True
    db.session.commit()
    loader.invalidate_build_views()
    assert EXTRA not in _names_of(loader.get_all_endpoints())


def test_fleet_view_never_resurrects_an_operator_disable(ctx):
    _set(FW, EXTRA, enabled=False, updated_by="bob")
    _sweep(FW, NEW, {EXTRA: _ep(EXTRA_URN)})
    _appliance("fw-new")
    assert EXTRA not in _names_of(loader.get_all_endpoints())


def test_fleet_view_consumers_see_the_extra_name(ctx):
    from app.services import rediscovery, structure
    _disable_owned(FW, EXTRA)
    _sweep(FW, NEW, {EXTRA: _ep(EXTRA_URN)})
    _appliance("fw-new")
    assert EXTRA in {e["name"] for e in rediscovery.sweep_plan()}
    # coverage accounting reads the pure registry
    assert EXTRA not in set(structure.registry_urn_index().values())


def test_registry_search_page_reads_the_pure_registry(ctx):
    from tests.conftest import admin_user_id, login
    _disable_owned(FW, EXTRA)
    _sweep(FW, NEW, {EXTRA: _ep(EXTRA_URN)})
    _appliance("fw-new")
    assert EXTRA in _names_of(loader.get_all_endpoints())
    client = ctx.test_client()
    login(client, admin_user_id(ctx))
    page = client.get("/registry/search?q=mcp-security.policy").get_data(as_text=True)
    assert EXTRA not in page
    # the page does render hits: an enabled sibling is found
    page = client.get("/registry/search?q=mcp-security.rule").get_data(as_text=True)
    assert "waf_mcp_security_rule" in page


# --------------------------------------------------------------------------
# the clients
# --------------------------------------------------------------------------

@pytest.mark.parametrize("product,module,cls", [
    ("fortiadc", "app.clients.fortiadc", "FortiADCClient"),
    ("fortianalyzer", "app.clients.fortianalyzer", "FortiAnalyzerClient"),
    ("fortiauthenticator", "app.clients.fortiauthenticator", "FortiAuthenticatorClient"),
])
def test_client_resolve_is_per_build(ctx, product, module, cls):
    import importlib
    klass = getattr(importlib.import_module(module), cls)
    moved, absent = _names(product, 2)
    _sweep(product, NEW, {moved: _ep("/moved/on/805"),
                          absent: _ep("", verdict="absent")})
    box = _appliance("%s-box" % product, kind=product, firmware=NEW)
    client = klass(box)
    assert client.fw_version == NEW
    assert client._resolve(moved) == "/moved/on/805"
    with pytest.raises(loader.EndpointNotServed):
        client._resolve(absent)
    # the existing named error, not a 500 -- and nothing was sent
    rows, err = client.list_with_error(absent)
    assert rows == [] and err.startswith("%s is not served by %s 8.0.5" % (absent, product))
    # a box whose build is unknown resolves exactly as before
    blind = klass(SimpleNamespace(host="h", port=443, verify_ssl=False,
                                  username="u", password="p"))
    assert blind._resolve(absent) == loader.load_product_registry(product)[absent]


@pytest.mark.parametrize("product,url", [
    ("fortiadc", "/adc/api/execute"),
    ("fortianalyzer", "/faz/api/execute"),
    ("fortiauthenticator", "/fac/api/execute"),
])
def test_explorer_consoles_refuse_a_name_the_box_does_not_serve(ctx, product, url):
    from tests.conftest import admin_user_id, login
    absent = _names(product, 1)[0]
    _sweep(product, NEW, {absent: _ep("", verdict="absent")})
    box = _appliance("%s-console" % product, kind=product, firmware=NEW)
    client = ctx.test_client()
    login(client, admin_user_id(ctx), product=product)
    body = client.post(url, data={"appliance_id": box.id, "endpoint": absent,
                                  "method": "GET" if product != "fortianalyzer" else "get"}
                       ).get_json()
    assert body["ok"] is False
    assert body["error"].startswith("%s is not served by %s 8.0.5" % (absent, product))


def test_fortiweb_client_resolve_is_per_build(ctx):
    from app.clients.fortiweb import FortiWebClient
    _disable_owned(FW, EXTRA)
    _sweep(FW, NEW, {EXTRA: _ep(EXTRA_URN)})
    assert FortiWebClient(_appliance("fw-new")).resolve(EXTRA) == EXTRA_URN
    with pytest.raises(KeyError):
        FortiWebClient(_appliance("fw-old", firmware=OLD)).resolve(EXTRA)


# --------------------------------------------------------------------------
# per-appliance call sites
# --------------------------------------------------------------------------

class _Resp:
    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body


def test_backup_resolves_for_the_clients_build(ctx):
    from app.services import backup
    _sweep(FW, NEW, {"local_backup_list": _ep("/api/v2.0/system/backup-list-805")})
    seen = []
    fake = SimpleNamespace(fw_version=NEW,
                           get=lambda path: seen.append(path) or _Resp({"results": []}))
    backup.list_backups(fake)
    assert seen == ["/api/v2.0/system/backup-list-805"]


def test_exception_inject_plans_against_the_target_build(ctx):
    from app.services import exception_inject as inj
    rest = inj.rest_for("custom_signature_item")
    _sweep(FW, NEW, {rest.item_logical: _ep("", verdict="absent")})
    payload = {"name": "r1"}
    assert inj.plan_injection("custom_signature_item", payload, "")["status"] != "no-endpoint"
    assert inj.plan_injection("custom_signature_item", payload, "",
                              version=NEW)["status"] == "no-endpoint"
    ops = SimpleNamespace(appliance=SimpleNamespace(fw_version=NEW))
    res = inj.apply_injection(ops, exc_type="custom_signature_item", payload=payload,
                              target="")
    assert res["ok"] is False and res["plan"]["status"] == "no-endpoint"


def test_clone_planner_indexes_the_target_build(ctx):
    from app.services import clone, objform
    _disable_owned(FW, EXTRA)
    _sweep(FW, NEW, {EXTRA: _ep(EXTRA_URN)})
    coll = objform.collection_of(EXTRA_URN)
    src = clone.ClientReader(SimpleNamespace(fw_version=OLD))
    dst_new = clone.ClientReader(SimpleNamespace(fw_version=NEW))
    assert clone.ClonePlanner(src, dst_new).urn_index.get(coll) == EXTRA
    assert coll not in clone.ClonePlanner(dst_new, src).urn_index


def test_write_through_maps_collections_for_the_cached_appliances_build(ctx):
    from app.services import write_through as W
    _disable_owned(FW, EXTRA)
    _sweep(FW, NEW, {EXTRA: _ep(EXTRA_URN)})
    box = _appliance("fw-new")
    assert W._version_for(db.session, box.id) == NEW
    tail = "waf/mcp-security.policy"
    assert W.logical_for_collection(tail, NEW) == EXTRA
    assert W.logical_for_collection(tail) is None


def test_device_sync_sweeps_the_faz_map_of_the_boxs_build(ctx, monkeypatch):
    from app.clients import fortianalyzer as faz_client
    from app.services import device_sync
    product = "fortianalyzer"
    names = [n for n in _names(product, 40) if n not in device_sync._FAZ_SOT_EXCLUDE]
    absent = names[0]
    _sweep(product, NEW, {absent: _ep("", verdict="absent")})
    asked = []
    monkeypatch.setattr(faz_client.FortiAnalyzerClient, "list_with_error",
                        lambda self, name, **kw: (asked.append(name), ([], None))[1])
    monkeypatch.setattr(faz_client.FortiAnalyzerClient, "logout", lambda self: None)
    device_sync.snapshot_from_faz(_appliance("faz-new", kind=product, firmware=NEW))
    assert absent not in asked and names[1] in asked


def test_scheduled_custom_rest_resolves_for_the_target_build(ctx):
    from app.services import scheduled_actions as sa
    _disable_owned(FW, EXTRA)
    _sweep(FW, NEW, {EXTRA: _ep(EXTRA_URN)})
    assert sa.resolve_endpoint(EXTRA, NEW) == EXTRA_URN
    assert sa.resolve_endpoint(EXTRA) == ""
    assert sa.resolve_endpoint("/api/v2.0/raw") == "/api/v2.0/raw"
