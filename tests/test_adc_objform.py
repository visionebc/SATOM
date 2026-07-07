"""ADC form engine (adc_objform) + cert-manager ADC dispatch — pure tests.

Parity guard with the FortiWeb editors: the ADC engine derives child tables
from the registry, infers widgets from device truth, and the cert-manager
removal path fails CLOSED. No device, no network.
"""
from __future__ import annotations

import types

import pytest


# --------------------------------------------------------------------------- #
#  adc_objform — registry-derived structure                                    #
# --------------------------------------------------------------------------- #
def test_child_tables_derive_from_registry(app):
    from app.services import adc_objform
    adc_objform.invalidate()
    with app.app_context():
        subs = adc_objform.subtables_for("load_balance_pool")
        logicals = [s["logical"] for s in subs]
        assert "load_balance_pool_child_pool_member" in logicals
        # child of a child never appears; unknown parent yields nothing
        assert adc_objform.subtables_for("no_such_object") == []


def test_is_known_allow_list(app):
    from app.services import adc_objform
    adc_objform.invalidate()
    with app.app_context():
        assert adc_objform.is_known("load_balance_pool")
        assert adc_objform.is_known("load_balance_pool_child_pool_member")
        assert not adc_objform.is_known("system_totally_fake")
        assert not adc_objform.is_known("")


def test_widget_inference():
    from app.services.adc_objform import descriptor
    assert descriptor("status", "enable")["widget"] == "toggle"
    assert descriptor("status", "disable")["on"] is False
    assert descriptor("port", "443")["widget"] == "number"
    assert descriptor("weight", 5)["widget"] == "number"
    assert descriptor("comment", "hi")["widget"] == "text"
    # inline structures are read-only complex, JSON-encoded for display
    d = descriptor("extension", [{"a": 1}])
    assert d["widget"] == "complex" and '"a"' in d["value"]


def test_field_groups_filters_noise_and_mkey():
    from app.services.adc_objform import field_groups
    obj = {"mkey": "x", "_nondeletable": "1", "port": "80",
           "members": [{"m": 1}]}
    groups = field_groups(obj)
    keys = [f["key"] for g in groups for f in g["fields"]]
    assert "port" in keys and "members" in keys
    assert "mkey" not in keys and "_nondeletable" not in keys
    # a child ROW form keeps mkey editable
    keys2 = [f["key"] for g in field_groups(obj, keep_mkey=True)
             for f in g["fields"]]
    assert "mkey" in keys2


def test_blank_row_sample_union_of_scalars():
    from app.services.adc_objform import blank_row_sample
    rows = [{"mkey": "a", "ip": "1.1.1.1", "_flag": "x", "deep": {"k": 1}},
            {"mkey": "b", "port": "80"}]
    s = blank_row_sample(rows)
    assert set(s) == {"mkey", "ip", "port"}
    assert all(v == "" for v in s.values())
    assert blank_row_sample([]) == {}


# --------------------------------------------------------------------------- #
#  ADC form endpoints — allow-list + permission gates (no device)              #
# --------------------------------------------------------------------------- #
def test_form_endpoints_reject_unknown_logical(app, client):
    from tests.conftest import admin_user_id, login
    login(client, admin_user_id(app), product="fortiadc")
    r = client.post("/adc/obj/not_a_real_logical/save-object",
                    json={"mkey": "x", "fields": {"a": "b"}})
    assert r.status_code in (400, 404)


# --------------------------------------------------------------------------- #
#  cert-manager ADC dispatch — fail-closed removal                             #
# --------------------------------------------------------------------------- #
class _FakeADC:
    id = 999
    name = "fake-adc"
    kind = "fortiadc"

    def __init__(self, client):
        self._client = client

    def build_client(self, timeout=None):
        return self._client


def _patch_usage(monkeypatch, complete, usage):
    from app.services import cert_adc
    monkeypatch.setattr(cert_adc, "enumerate_usage",
                        lambda client, name: (complete, usage))


def test_remove_refuses_bound_adc_cert(app, monkeypatch):
    from app.services import cert_manager as cm
    _patch_usage(monkeypatch, True, [{"label": "Admin GUI (system_global)"}])
    with app.app_context():
        r = cm.remove_device_certificate(_FakeADC(object()), "Local", "c1",
                                         dry_run=False)
    assert r["ok"] is False and r["removed"] is False
    assert "still bound" in r["error"]


def test_remove_refuses_incomplete_binding_check(app, monkeypatch):
    from app.services import cert_manager as cm
    _patch_usage(monkeypatch, False, [])
    with app.app_context():
        r = cm.remove_device_certificate(_FakeADC(object()), "Local", "c1",
                                         dry_run=False)
    assert r["ok"] is False and "refusing" in r["error"]


def test_remove_unbound_adc_cert_deletes_over_rest(app, monkeypatch):
    from app.services import cert_manager as cm
    _patch_usage(monkeypatch, True, [])
    calls = []
    client = types.SimpleNamespace(delete=lambda lg, mk: calls.append((lg, mk)))
    with app.app_context():
        dry = cm.remove_device_certificate(_FakeADC(client), "Local", "c1",
                                           dry_run=True)
        assert dry["ok"] is True and dry["removed"] is False
        assert "REST delete" in dry.get("summary", "")
        assert calls == []          # dry-run never touches the box
        real = cm.remove_device_certificate(_FakeADC(client), "Local", "c1",
                                            dry_run=False)
    assert real["ok"] is True and real["removed"] is True
    assert calls == [("system_certificate_local", "c1")]


def test_swap_gui_cert_adc_dry_run_builds_rest_request(app):
    from app.services import cert_manager as cm
    with app.app_context():
        r = cm.swap_gui_cert(_FakeADC(object()), "wc", dry_run=True)
    assert r["ok"] is True and r["dry_run"] is True
    assert r["request"]["body"] == {"https-server-cert": "wc"}
