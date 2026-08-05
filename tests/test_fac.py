"""Guards for the FortiAuthenticator integration.

Each test here exists because of a specific way this integration can rot
silently — none of these failures raises an error on its own:

* a registry endpoint drops out of the menu   -> unreachable in the UI while
  still being harvested;
* a name in the SoT exclusion set is misspelt -> the operational endpoint is
  harvested anyway and every hourly sweep records churn as a config change;
* the client stops paginating                 -> a prefix of the identity store
  is reported as the whole thing;
* a product-key column narrows again          -> the ADOM becomes unwritable,
  which is exactly how 'fortiauthenticator' stayed a placeholder for months.
"""
from __future__ import annotations

import ast
import glob
import os
import re

import pytest
import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
YAML_PATH = os.path.join(REPO, "endpoints_fortiauthenticator.yaml")

from app.services import fac_menu  # noqa: E402


def _registry() -> dict:
    with open(YAML_PATH) as f:
        return yaml.safe_load(f) or {}


# --------------------------------------------------------------------------- #
#  registry seed                                                              #
# --------------------------------------------------------------------------- #

def test_registry_seed_is_not_empty():
    assert len(_registry()) >= 40


def test_every_urn_is_an_api_v1_collection_path():
    """FortiAuthenticator is Tastypie: every resource lives at
    ``/api/v1/<resource>/`` and the trailing slash is NOT optional — without it
    Django answers a 301 that a POST does not survive."""
    for name, urn in _registry().items():
        assert urn.startswith("/api/v1/"), f"{name}: {urn}"
        assert urn.endswith("/"), f"{name}: {urn} needs a trailing slash"


def test_no_two_logical_names_share_a_urn():
    reg = _registry()
    assert len(set(reg.values())) == len(reg)


# --------------------------------------------------------------------------- #
#  menu <-> registry coverage                                                 #
# --------------------------------------------------------------------------- #

def test_menu_binds_every_registry_endpoint_exactly_once():
    reg = set(_registry())
    bound = fac_menu.bound_logicals()
    assert len(bound) == len(set(bound)), (
        "an endpoint is bound twice — the same table renders on two pages: "
        f"{sorted({b for b in bound if list(bound).count(b) > 1})}")
    assert set(bound) == reg, (
        f"missing from the menu: {sorted(reg - set(bound))} / "
        f"not in the registry: {sorted(set(bound) - reg)}")


def test_menu_item_keys_are_unique():
    keys = [it.key for it in fac_menu.all_items()]
    assert len(keys) == len(set(keys))


def test_every_menu_item_carries_a_real_description():
    """Every pane — bound or not — must describe itself, and must not ship a
    placeholder stub.

    An earlier version of this guard tried to assert that an UNBOUND pane
    "explains why". Four honest descriptions were rejected in a row
    (a 55-character one, "NO REST resource", "not through /api/v1/",
    "answers 405 on GET") before it became clear the guard was policing prose,
    which no assertion does well. What is mechanically checkable is that the
    text exists and is not a stub; that the unbound STATE is visible to the
    operator is enforced structurally by
    ``test_the_section_page_has_an_unbound_state`` instead.
    """
    stubs = ("todo", "tbd", "fixme", "coming soon", "wip", "xxx")
    for it in fac_menu.all_items():
        assert it.desc.strip(), f"{it.key} has no description"
        low = it.desc.lower()
        assert not any(sb in low for sb in stubs), f"{it.key}: stub description"


def test_the_section_page_has_an_unbound_state():
    """A pane with no bound endpoint must render an explicit 'no endpoint
    bound' state. Without it the page shows an empty shell that reads as
    'nothing is configured on this device' — the exact confusion this whole
    integration refuses to create."""
    tpl = os.path.join(REPO, "app", "templates", "fac", "section.html")
    body = open(tpl).read()
    assert "No endpoint bound" in body
    # and it must be reached by testing the binding, not by accident
    assert "not item.logicals" in body


def test_find_item_returns_nothing_for_an_unknown_key():
    g, it = fac_menu.find_item("no-such-pane")
    assert g is None and it is None


# --------------------------------------------------------------------------- #
#  SoT exclusion set                                                          #
# --------------------------------------------------------------------------- #

def test_sot_exclusion_names_are_real_registry_endpoints():
    """A typo here excludes nothing and is invisible: the endpoint keeps being
    harvested and the snapshot hash changes on every sweep."""
    from app.services import device_sync
    reg = set(_registry())
    unknown = device_sync._FAC_SOT_EXCLUDE - reg
    assert not unknown, f"not registry endpoints: {sorted(unknown)}"


def test_the_operational_endpoints_are_excluded_from_the_snapshot():
    """These four change between two reads of an IDLE unit. Harvesting them
    defeats the content-hash dedupe that keeps the SoT store small."""
    from app.services import device_sync
    for name in ("system_info", "token_fortiguard_messages",
                 "token_ftm_licenses", "cert_scep_requests"):
        assert name in device_sync._FAC_SOT_EXCLUDE, name


def test_snapshot_for_dispatches_fortiauthenticator(monkeypatch):
    """Without a live dispatch arm a registered FAC appliance is browsable and
    NEVER harvested — a half-integration that looks complete.

    Asserted by CALLING snapshot_for, not by finding the name in the AST: an
    earlier AST version survived a mutation that changed the kind it matches on
    (the call was still there, just unreachable).
    """
    from app.services import device_sync

    seen = {}

    def _fake(appliance, **_kw):
        seen["kind"] = appliance.kind
        return {"ok": 1}

    monkeypatch.setattr(device_sync, "snapshot_from_fac", _fake)

    class _A:
        kind = "fortiauthenticator"
        name, id = "fac-x", 1

    out = device_sync.snapshot_for(_A())
    assert out == {"ok": 1}, "snapshot_for did not route to the FAC sweep"
    assert seen["kind"] == "fortiauthenticator"


def test_the_fleet_wide_sweeps_cover_the_product():
    from app.services import scheduled_actions as sa
    for key in ("device_sync", "device_inspect"):
        spec = sa.get_spec(key)
        assert spec is not None, f"{key} spec is missing"
        assert "fortiauthenticator" in spec.products, key


# --------------------------------------------------------------------------- #
#  client behaviour                                                           #
# --------------------------------------------------------------------------- #

class _FakeResp:
    def __init__(self, status, payload=None, text=""):
        self.status_code = status
        self._payload = payload
        self.text = text if text else ("{}" if payload is None else "x")

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class _Appl:
    host, port, verify_ssl = "192.0.2.1", 443, False
    username, password = "admin", "KEY"


def _client(monkeypatch, responses):
    from app.clients import fortiauthenticator as fa
    c = fa.FortiAuthenticatorClient(_Appl())
    calls = []

    def fake(method, path, **kw):
        calls.append((method, path, kw.get("params")))
        return responses.pop(0)

    monkeypatch.setattr(c, "_request", fake)
    return c, calls


def test_a_singleton_payload_is_normalised_to_one_row(monkeypatch):
    c, _ = _client(monkeypatch, [_FakeResp(200, {"cpu": "1%", "sn": "X"})])
    rows, err = c.list_path_with_error("/api/v1/systeminfo/")
    assert err is None
    assert rows == [{"cpu": "1%", "sn": "X"}]


def test_a_collection_is_unwrapped_from_objects(monkeypatch):
    payload = {"meta": {"total_count": 2, "offset": 0, "next": None},
               "objects": [{"id": 1}, {"id": 2}]}
    c, _ = _client(monkeypatch, [_FakeResp(200, payload)])
    rows, err = c.list_path_with_error("/api/v1/localusers/")
    assert err is None and len(rows) == 2


def test_pagination_follows_meta_next_to_exhaustion(monkeypatch):
    """The server default page is 20 and ``limit=0`` is clamped to 1000 — both
    measured on the device. A client that trusts either reports a prefix of the
    identity store as the whole thing."""
    p1 = {"meta": {"total_count": 3, "offset": 0, "next": "/api/v1/x/?offset=2"},
          "objects": [{"id": 1}, {"id": 2}]}
    p2 = {"meta": {"total_count": 3, "offset": 2, "next": None},
          "objects": [{"id": 3}]}
    c, calls = _client(monkeypatch, [_FakeResp(200, p1), _FakeResp(200, p2)])
    rows, err = c.list_path_with_error("/api/v1/x/")
    assert err is None
    assert [r["id"] for r in rows] == [1, 2, 3]
    assert len(calls) == 2


def test_a_short_read_is_reported_as_an_error_not_as_success(monkeypatch):
    """total_count says 9, the device sent 1 and offered no next page. Returning
    those rows with err=None would present a truncated harvest as complete."""
    p = {"meta": {"total_count": 9, "offset": 0, "next": None},
         "objects": [{"id": 1}]}
    c, _ = _client(monkeypatch, [_FakeResp(200, p)])
    rows, err = c.list_path_with_error("/api/v1/x/")
    assert len(rows) == 1
    assert err and "short read" in err


def test_a_mid_walk_failure_reports_both_the_rows_and_the_reason(monkeypatch):
    p1 = {"meta": {"total_count": 4, "offset": 0, "next": "/api/v1/x/?offset=2"},
          "objects": [{"id": 1}, {"id": 2}]}
    c, _ = _client(monkeypatch, [_FakeResp(200, p1), _FakeResp(500, None, "boom")])
    rows, err = c.list_path_with_error("/api/v1/x/")
    assert len(rows) == 2
    assert err and "pagination stopped" in err


def test_a_looping_device_does_not_spin_forever(monkeypatch):
    """A device that keeps handing back the same offset must terminate."""
    same = {"meta": {"total_count": 99, "offset": 0, "next": "/api/v1/x/?offset=0"},
            "objects": [{"id": 1}]}
    c, _ = _client(monkeypatch, [_FakeResp(200, same)] * 5)
    rows, _err = c.list_path_with_error("/api/v1/x/")
    assert len(rows) == 1


def test_401_names_the_api_key_instead_of_saying_unauthorized(monkeypatch):
    """The login password is NOT accepted by this API. A bare 'unauthorized'
    sends the operator to rotate the wrong secret."""
    c, _ = _client(monkeypatch, [_FakeResp(401)])
    rows, err = c.list_path_with_error("/api/v1/x/")
    assert rows == []
    assert "API key" in err and "Web service access" in err


def test_a_refusal_never_masquerades_as_an_empty_collection(monkeypatch):
    for status in (403, 405, 500):
        c, _ = _client(monkeypatch, [_FakeResp(status, None, "nope")])
        rows, err = c.list_path_with_error("/api/v1/x/")
        assert rows == [] and err, f"status {status} produced a silent empty read"


def test_the_first_page_asks_for_the_server_max_not_the_default_20(monkeypatch):
    c, calls = _client(monkeypatch, [_FakeResp(200, {"a": 1})])
    c.list_path_with_error("/api/v1/x/")
    assert calls[0][2]["limit"] >= 1000


def test_ha_status_reports_the_raw_peer_serial_only(monkeypatch):
    """FortiAuthenticator exposes no HA resource; deciding
    clustered/standalone/unknown belongs to ha_inventory, which refuses to call
    an un-harvested box 'standalone'."""
    c, _ = _client(monkeypatch, [_FakeResp(200, {"ha_sn": "", "sn": "S1"})])
    assert c.ha_status() == {"ha_sn": "", "sn": "S1"}


# --------------------------------------------------------------------------- #
#  view-level guards                                                          #
# --------------------------------------------------------------------------- #

def test_secret_shaped_fields_are_stripped_before_rendering():
    """Verified 2026-08-05 that the device omits them; this is the belt to that
    braces, because the cost of being wrong is a credential in every screenshot
    of the page."""
    from app.views import fac
    row = {"username": "u", "password": "p", "secret": "s", "id": 1}
    out = fac._scrub(row)
    assert "password" not in out and "secret" not in out
    assert out["username"] == "u"
    assert not (set(fac._columns_for([row])) & set(fac._NEVER_RENDER))


def test_the_console_refuses_paths_outside_the_api_root():
    """A raw-path field that accepts anything is a request forger pointed at
    the appliance GUI, which lives on the same origin."""
    from app.views import fac_api
    for bad in ("/admin/local_user/user/", "/login/", "/api/v2/x/",
                "../../admin/", "/"):
        path, err = fac_api._resolve_target(bad)
        assert path is None and err, bad
    path, err = fac_api._resolve_target("/api/v1/localusers/")
    assert err is None and path == "/api/v1/localusers/"


def test_every_mutating_http_method_is_gated_as_a_write():
    from app.views import fac_api
    assert fac_api._WRITE_METHODS == {"POST", "PUT", "PATCH", "DELETE"}
    assert "GET" not in fac_api._WRITE_METHODS


def test_writes_are_dry_run_unless_apply_is_explicit(monkeypatch):
    """A mutating method must return the preview and touch NOTHING until
    ``apply`` is explicit.

    Asserted by exploding if a client is ever constructed. An earlier version
    compared source positions ("the guard precedes the client call") and
    survived a mutation that neutered the condition to ``if False and ...`` —
    the text order was unchanged, so the test never noticed the write escaping.
    """
    from app.views import fac_api

    def _boom(*a, **kw):
        raise AssertionError("a dry run must not build a device client")

    monkeypatch.setattr(fac_api, "FortiAuthenticatorClient", _boom)

    class _U:
        is_authenticated = True

        def can(self, _p):
            return True

    class _Appl:
        id, kind, name = 1, "fortiauthenticator", "fac01"
        host, port = "192.0.2.1", 443

    monkeypatch.setattr(fac_api, "visible_appliance_or_404", lambda _i: _Appl())
    monkeypatch.setattr(fac_api, "current_user", _U())
    monkeypatch.setattr(fac_api, "log_action", lambda *a, **kw: None)

    from flask import Flask
    app = Flask(__name__)
    app.register_blueprint(fac_api.bp)
    app.config["WTF_CSRF_ENABLED"] = False

    with app.test_request_context(
            "/fac/api/execute", method="POST",
            data={"appliance_id": "1", "endpoint": "/api/v1/localusers/",
                  "method": "DELETE", "body": ""}):
        resp = fac_api.execute.__wrapped__()
    payload = resp.get_json() if hasattr(resp, "get_json") else resp
    assert payload["ok"] is True
    assert payload["dry_run"] is True, "a write escaped without apply=true"


# --------------------------------------------------------------------------- #
#  the schema ceiling that made this ADOM unwritable                          #
# --------------------------------------------------------------------------- #

def test_product_key_columns_can_hold_the_longest_adom_key():
    """'fortiauthenticator' is 18 chars; every product-scoping column was
    declared varchar(16) because the longest key had been 'fortianalyzer' (13).
    A narrowing regression makes the ADOM silently unwritable again."""
    from app.branding import _FALLBACK
    longest = max(len(p["key"]) for p in _FALLBACK)
    pat = re.compile(r"product\s*=\s*db\.Column\(db\.String\((\d+)\)")
    checked = 0
    for path in glob.glob(os.path.join(REPO, "app", "models*.py")):
        for width in pat.findall(open(path).read()):
            checked += 1
            assert int(width) >= longest, (
                f"{os.path.basename(path)}: product varchar({width}) cannot "
                f"hold a {longest}-char ADOM key")
    assert checked, "no product columns found — the guard would pass vacuously"


def test_appliance_kind_can_hold_the_longest_product_kind():
    from app.models import Appliance
    assert Appliance.kind.type.length >= len("fortiauthenticator")


def test_the_adom_is_a_real_product_not_a_placeholder():
    from app.branding import _FALLBACK
    fac = next(p for p in _FALLBACK if p["key"] == "fortiauthenticator")
    assert fac["placeholder"] is False
    assert fac["active"] is True


@pytest.mark.parametrize("bp", ["fac", "fac_api"])
def test_the_product_gate_lets_the_fac_blueprints_through(bp):
    """Without this the ADOM redirects to its own index forever."""
    src = open(os.path.join(REPO, "app", "__init__.py")).read()
    m = re.search(r"fac_bps = \{(.*?)\}", src, re.S)
    assert m, "fac_bps allow-list is missing from the product gate"
    assert f"'{bp}'" in m.group(1)
