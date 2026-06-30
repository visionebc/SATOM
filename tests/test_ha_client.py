"""Live HA status read from the vendor clients (ha_status)."""
from __future__ import annotations

from types import SimpleNamespace

from app.clients.fortiweb import FortiWebClient
from app.services.ha import parse_ha_role


def _stub_appliance():
    return SimpleNamespace(
        host="192.0.2.9", port=443, verify_ssl=False,
        username="admin", password="secret", vdom=None,
    )


class _Resp:
    def __init__(self, payload):
        self._payload = payload
    def json(self):
        return self._payload


def test_ha_status_returns_inner_results():
    client = FortiWebClient(_stub_appliance())
    calls = []

    def fake_get(path):
        calls.append(path)
        return _Resp({"results": {"ha_role": "primary", "serial": "FV-XYZ"}})

    client.get = fake_get
    data = client.ha_status()
    assert data.get("ha_role") == "primary"
    assert parse_ha_role(data) == "primary"
    assert calls  # at least one endpoint was tried


def test_ha_status_skips_empty_envelope_then_succeeds():
    client = FortiWebClient(_stub_appliance())
    seq = [
        _Resp({"results": {"errcode": -3}}),          # error envelope -> {} -> skip
        _Resp({"results": {"ha_mode": "active-passive", "is_master": True}}),
    ]

    def fake_get(path):
        return seq.pop(0)

    client.get = fake_get
    data = client.ha_status()
    assert data.get("is_master") is True
    assert parse_ha_role(data) == "primary"


def test_ha_status_all_fail_returns_empty():
    client = FortiWebClient(_stub_appliance())

    def fake_get(path):
        raise RuntimeError("boom")

    client.get = fake_get
    assert client.ha_status() == {}
    assert parse_ha_role(client.ha_status()) == "standalone"
