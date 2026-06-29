"""field_catalog: schema resolution (+ _default fallback), coercion, type inference."""
from __future__ import annotations

import pytest

from app.services import field_catalog as fc


def test_load_line_specific_schema():
    s = fc.load_object_schema("fortiweb", "8.0", "dns")
    assert s is not None
    assert s.object == "dns" and s.endpoint == "dns" and s.singleton is True
    names = [f.name for f in s.fields]
    assert names == ["primary", "secondary", "domain"]
    assert s.field("primary").type == "ip" and s.field("primary").required is True


def test_falls_back_to_default_when_line_missing_object():
    # 7.6 has no hand-seeded dns.json yet -> must fall back to _default/dns.json
    s = fc.load_object_schema("fortiweb", "7.6", "dns")
    assert s is not None and s.object == "dns"


def test_unknown_object_returns_none():
    assert fc.load_object_schema("fortiweb", "8.0", "does-not-exist") is None


def test_coerce_required_and_optional():
    s = fc.load_object_schema("fortiweb", "8.0", "dns")
    out = fc.coerce(s, {"primary": "192.0.2.3", "secondary": "", "domain": "example.net"})
    # required present, empty optional dropped (partial update), text kept
    assert out == {"primary": "192.0.2.3", "domain": "example.net"}


def test_coerce_missing_required_raises():
    s = fc.load_object_schema("fortiweb", "8.0", "dns")
    with pytest.raises(ValueError):
        fc.coerce(s, {"primary": "", "secondary": "192.0.2.4"})


def test_coerce_bool_and_select():
    s = fc.load_object_schema("fortiweb", "8.0", "ntp")
    # checkbox present -> true_value; absent -> false_value
    on = fc.coerce(s, {"mode": "ntp", "daylightSaving": "on"})
    assert on["daylightSaving"] == "enable" and on["mode"] == "ntp"
    off = fc.coerce(s, {"mode": "ntp"})
    assert off.get("daylightSaving") == "disable"


def test_coerce_rejects_bad_ip():
    s = fc.load_object_schema("fortiweb", "8.0", "dns")
    with pytest.raises(ValueError):
        fc.coerce(s, {"primary": "not-an-ip"})


def test_infer_type():
    assert fc.infer_type("192.0.2.3") == "ip"
    assert fc.infer_type(42) == "number"
    assert fc.infer_type("enable") == "bool"
    assert fc.infer_type("hello") == "text"


def test_available_lines_sorted_desc():
    lines = fc.available_lines("fortiweb")
    assert "8.0" in lines and "_default" not in lines
    assert lines == sorted(lines, reverse=True)


def test_systemprofile_line_roundtrips():
    from app.services.provisioning import SystemProfile, ProvisionItem
    p = SystemProfile("base", [ProvisionItem(key="dns", endpoint="dns", data={"primary": "192.0.2.3"})], line="7.6")
    body = p.to_body()
    assert body["line"] == "7.6"
    p2 = SystemProfile.from_body("base", body)
    assert p2.line == "7.6" and p2.items[0].endpoint == "dns"


def test_systemprofile_line_defaults_when_absent():
    from app.services.provisioning import SystemProfile
    p = SystemProfile.from_body("base", {"items": []})
    assert p.line == "8.0"
