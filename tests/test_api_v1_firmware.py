"""TDD for the live firmware check: /api/v1 inventory fields, the
``firmware-check`` endpoint and its three gates, and the per-vendor parsers.

The point of this surface is that an external consumer (VEYRS) can ask SATOM
"what is this box actually running, right now?" and get an answer it is allowed
to trust. So the tests that matter most here are the NEGATIVE ones: a probe that
did not reach a device must leave no trace that looks like a fresh reading.
"""
from __future__ import annotations

import pytest

from tests.conftest import admin_user_id


# --------------------------------------------------------------------- setup

def _mint(app, *, scopes, capabilities=None, product="fortiweb"):
    from app.extensions import db
    from app.models import User
    from app.models_api_token import mint_token
    with app.app_context():
        owner = db.session.get(User, admin_user_id(app))
        _tok, plaintext = mint_token(name="veyrs-test", owner=owner,
                                     scopes=scopes, product=product,
                                     capabilities=capabilities or [])
        return plaintext


def _auth(tokenstr):
    return {"Authorization": f"Bearer {tokenstr}"}


def _make_appliance(app, *, name="fw-probe", kind="fortiweb", firmware=None):
    from app.extensions import db
    from app.models import Appliance
    with app.app_context():
        a = Appliance(name=name, kind=kind, host="192.0.2.99", port=443,
                      username="admin", verify_ssl=False,
                      password_enc="placeholder", firmware=firmware)
        a.set_password("secret")
        db.session.add(a)
        db.session.commit()
        return a.id


def _row(app, aid):
    from app.extensions import db
    from app.models import Appliance
    with app.app_context():
        a = db.session.get(Appliance, aid)
        return {"firmware": a.firmware, "model": a.model,
                "hw_type": a.hw_type, "checked_at": a.firmware_checked_at}


# ------------------------------------------------------------ schema + shape

def test_column_exists_on_a_fresh_database(app):
    from sqlalchemy import inspect
    from app.extensions import db
    with app.app_context():
        cols = {c["name"] for c in inspect(db.engine).get_columns("appliances")}
    assert "firmware_checked_at" in cols


def test_listing_exposes_inventory_fields(app, client):
    _make_appliance(app, firmware="FortiWeb-KVM 7.6.8,build1128(GA.M),260602")
    plaintext = _mint(app, scopes=["read"])
    r = client.get("/api/v1/appliances", headers=_auth(plaintext))
    assert r.status_code == 200
    row = r.get_json()["appliances"][0]
    for key in ("firmware", "firmware_checked_at", "model", "hw_type"):
        assert key in row, f"{key} missing from the /api/v1 serializer"
    assert row["firmware"].startswith("FortiWeb-KVM 7.6.8")
    # Never probed -> the age is NULL, not a fabricated timestamp.
    assert row["firmware_checked_at"] is None


# ------------------------------------------------------------------- gates

def test_read_scope_cannot_trigger_a_check(app, client):
    aid = _make_appliance(app)
    plaintext = _mint(app, scopes=["read"], capabilities=["inventory"])
    r = client.post(f"/api/v1/appliances/{aid}/firmware-check",
                    headers=_auth(plaintext))
    assert r.status_code == 403
    assert r.get_json()["error"] == "insufficient_scope"


def test_empty_capability_list_does_not_grant_inventory(app, client, monkeypatch):
    """The regression this file exists for.

    Catalog actions treat ``capabilities == []`` as "unrestricted". If the
    firmware check reused that gate, every token minted before today would have
    silently gained the power to make SATOM open admin sessions to firewalls.
    """
    aid = _make_appliance(app)
    called = []
    monkeypatch.setattr("app.services.firmware_probe.read",
                        lambda a: called.append(a) or {"ok": True})
    plaintext = _mint(app, scopes=["write"], capabilities=[])
    r = client.post(f"/api/v1/appliances/{aid}/firmware-check",
                    headers=_auth(plaintext))
    assert r.status_code == 403
    assert r.get_json()["error"] == "capability_denied"
    assert called == [], "the device was contacted before the gate ran"


def test_other_adom_appliance_is_404_not_403(app, client):
    """Do not confirm that another product's device exists."""
    aid = _make_appliance(app, kind="fortiadc", name="adc-probe")
    plaintext = _mint(app, scopes=["write"], capabilities=["inventory"],
                      product="fortiweb")
    r = client.post(f"/api/v1/appliances/{aid}/firmware-check",
                    headers=_auth(plaintext))
    assert r.status_code == 404


# ------------------------------------------------------------------ success

def test_successful_check_persists_and_stamps(app, client, monkeypatch):
    aid = _make_appliance(app, firmware="FortiWeb-KVM 7.6.7,build1100,250101")
    monkeypatch.setattr("app.services.firmware_probe.read", lambda a: {
        "ok": True, "firmware": "FortiWeb-KVM 7.6.8,build1128(GA.M),260602",
        "model": "FortiWeb-KVM 7.6.8", "hw_type": "vm", "error": "", "detail": "",
    })
    plaintext = _mint(app, scopes=["write"], capabilities=["inventory"])
    r = client.post(f"/api/v1/appliances/{aid}/firmware-check",
                    headers=_auth(plaintext))
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body["ok"] and body["source"] == "live"
    assert body["firmware"] == "FortiWeb-KVM 7.6.8,build1128(GA.M),260602"
    assert body["changed"] is True
    assert body["previous"] == "FortiWeb-KVM 7.6.7,build1100,250101"
    assert body["checked_at"]

    row = _row(app, aid)
    assert row["firmware"] == "FortiWeb-KVM 7.6.8,build1128(GA.M),260602"
    assert row["model"] == "FortiWeb-KVM 7.6.8"
    assert row["hw_type"] == "vm"
    assert row["checked_at"] is not None


def test_same_version_still_refreshes_the_timestamp(app, client, monkeypatch):
    """A version that did not move is still an OBSERVATION. ``changed=False``
    must not be confused with "not checked" -- that distinction is the whole
    reason the age column is separate from the value."""
    same = "FortiWeb-KVM 7.6.8,build1128(GA.M),260602"
    aid = _make_appliance(app, firmware=same)
    monkeypatch.setattr("app.services.firmware_probe.read", lambda a: {
        "ok": True, "firmware": same, "model": None, "hw_type": None,
        "error": "", "detail": "",
    })
    plaintext = _mint(app, scopes=["write"], capabilities=["inventory"])
    r = client.post(f"/api/v1/appliances/{aid}/firmware-check",
                    headers=_auth(plaintext))
    assert r.status_code == 200
    assert r.get_json()["changed"] is False
    assert _row(app, aid)["checked_at"] is not None


def test_unknown_model_never_erases_an_operator_value(app, client, monkeypatch):
    from app.extensions import db
    from app.models import Appliance
    aid = _make_appliance(app)
    with app.app_context():
        a = db.session.get(Appliance, aid)
        a.model = "FortiWeb 600F (hand-entered)"
        a.hw_type = "hardware"
        db.session.commit()
    monkeypatch.setattr("app.services.firmware_probe.read", lambda a: {
        "ok": True, "firmware": "1.2.3", "model": None, "hw_type": None,
        "error": "", "detail": "",
    })
    plaintext = _mint(app, scopes=["write"], capabilities=["inventory"])
    client.post(f"/api/v1/appliances/{aid}/firmware-check",
                headers=_auth(plaintext))
    row = _row(app, aid)
    assert row["model"] == "FortiWeb 600F (hand-entered)"
    assert row["hw_type"] == "hardware"


# ------------------------------------------------------------------ failure

@pytest.mark.parametrize("failure", [
    {"ok": False, "error": "unreachable", "detail": "ConnectTimeout: ..."},
    {"ok": False, "error": "no_version_in_status", "detail": "keys=['hostName']"},
])
def test_failed_probe_writes_nothing_at_all(app, client, monkeypatch, failure):
    """502, and in particular NO timestamp. A stamped failure would tell the
    consumer the stale version had just been confirmed."""
    old = "FortiWeb-KVM 7.6.7,build1100,250101"
    aid = _make_appliance(app, firmware=old)
    monkeypatch.setattr("app.services.firmware_probe.read",
                        lambda a: dict(failure, firmware="", model=None,
                                       hw_type=None))
    plaintext = _mint(app, scopes=["write"], capabilities=["inventory"])
    r = client.post(f"/api/v1/appliances/{aid}/firmware-check",
                    headers=_auth(plaintext))
    assert r.status_code == 502
    body = r.get_json()
    assert body["error"] == failure["error"]
    # The last known value is echoed, with its (absent) age.
    assert body["firmware"] == old
    assert body["firmware_checked_at"] is None

    row = _row(app, aid)
    assert row["firmware"] == old, "a failed probe overwrote the version"
    assert row["checked_at"] is None, "a failed probe stamped an attestation"


# ------------------------------------------------------- per-vendor parsers

class _FakeClient:
    def __init__(self, payload):
        self._payload = payload

    def status_check(self):
        return self._payload

    def platform_version(self):
        return self._payload


class _FakeAppliance:
    """Only what firmware_probe touches."""

    def __init__(self, kind, payload):
        self.kind = kind
        self._payload = payload

    def build_client(self, timeout=15.0):
        return _FakeClient(self._payload)


# Payloads below are VERBATIM from the live devices on 2026-08-13
# (fortiweb09 192.0.2.14, fortiadc02 192.0.2.76, fac01 192.0.2.19). The
# FortiAnalyzer one is from the documented /sys/status shape -- the only
# registered FAZ is retired, so that branch is unverified by construction.
def test_parses_fortiweb():
    from app.services import firmware_probe
    a = _FakeAppliance("fortiweb", {
        "hostName": "fortiweb09", "serialNumber": "FVVM00UNLICENSED",
        "firmwareVersion": "FortiWeb-KVM 7.6.8,build1128(GA.M),260602",
    })
    res = firmware_probe.read(a)
    assert res["ok"]
    assert res["firmware"] == "FortiWeb-KVM 7.6.8,build1128(GA.M),260602"
    assert res["model"] == "FortiWeb-KVM 7.6.8"
    assert res["hw_type"] == "vm"


def test_parses_fortiadc(monkeypatch):
    from app.services import firmware_probe
    payload = {"build": "build0093,260401", "hostname": "fortiadc02",
               "model": "KVM", "version": "8-0-3"}
    monkeypatch.setattr("app.clients.fortiadc.FortiADCClient",
                        lambda a, timeout=15.0: _FakeClient(payload))
    res = firmware_probe.read(_FakeAppliance("fortiadc", payload))
    assert res["ok"]
    # The SAME string services.rediscovery has always stored -- one formatter.
    assert res["firmware"] == "8.0.3 build0093,260401"
    assert res["model"] == "FortiADC-KVM"
    assert res["hw_type"] == "vm"


def test_parses_fortiauthenticator():
    from app.services import firmware_probe
    a = _FakeAppliance("fortiauthenticator", {
        "firmware": "FACVMKVM v8.0.3, build0099 (GA)", "sn": "FAC-VM0000000000",
    })
    res = firmware_probe.read(a)
    assert res["ok"]
    assert res["firmware"] == "FACVMKVM v8.0.3, build0099 (GA)"
    assert res["model"] == "FortiAuthenticator-FACVMKVM"
    assert res["hw_type"] == "vm"


def test_parses_fortianalyzer():
    from app.services import firmware_probe
    a = _FakeAppliance("fortianalyzer", {
        "Version": "v7.4.3-build2570 240116 (GA)",
        "Platform Type": "FAZVM64-KVM", "Serial Number": "FAZ-VM0000000000",
    })
    res = firmware_probe.read(a)
    assert res["ok"]
    assert res["firmware"] == "v7.4.3-build2570 240116 (GA)"
    assert res["hw_type"] == "vm"


def test_status_without_a_version_is_a_failure_not_an_empty_reading():
    """The single most important parser rule: '' is not a version. Storing it
    would blank a real value and make an unprobed box look probed."""
    from app.services import firmware_probe
    a = _FakeAppliance("fortiweb", {"hostName": "fw", "haStatus": "Standalone"})
    res = firmware_probe.read(a)
    assert res["ok"] is False
    assert res["error"] == "no_version_in_status"


def test_fortiweb_refusal_envelope_is_reported_as_such():
    """FortiWeb answers a refusal with HTTP 200 + {errcode, message}, so no
    exception is raised and no version is present. Live case, fortiweb08 on
    2026-08-13. The operator must read the device's own reason, not 'the
    parser found no key'."""
    from app.services import firmware_probe
    a = _FakeAppliance("fortiweb", {
        "errcode": "-20010",
        "message": "The license of peer VM FortiWeb is not valid.",
    })
    res = firmware_probe.read(a)
    assert res["ok"] is False
    assert res["error"] == "device_refused"
    assert "-20010" in res["detail"]
    assert "license of peer VM" in res["detail"]


def test_device_exception_is_captured_not_raised():
    from app.services import firmware_probe

    class _Boom:
        kind = "fortiweb"

        def build_client(self, timeout=15.0):
            raise RuntimeError("TLS handshake failed")

    res = firmware_probe.read(_Boom())
    assert res["ok"] is False and res["error"] == "unreachable"
    assert "TLS handshake failed" in res["detail"]


def test_unknown_kind_is_refused():
    from app.services import firmware_probe
    res = firmware_probe.read(_FakeAppliance("fortiswitch", {}))
    assert res["ok"] is False and res["error"] == "unsupported_kind"
