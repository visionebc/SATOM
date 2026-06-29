"""Harvester pure-function tests (no network)."""
from __future__ import annotations

from scripts import build_field_catalog as h


def _find(fields, name):
    return next(f for f in fields if f["name"] == name)


def test_is_readonly_name():
    assert h.is_readonly_name("status_val")
    assert h.is_readonly_name("_id")
    assert h.is_readonly_name("systemTime")
    assert not h.is_readonly_name("primary")


def test_fields_from_live_object_skips_readonly_and_infers_types():
    live = {"primary": "192.0.2.3", "secondary": "192.0.2.4", "domain": "x.mx",
            "status": 1, "status_val": "enable", "_id": 7}
    fields = h.fields_from_live_object(live)
    names = [f["name"] for f in fields]
    assert "status_val" not in names and "_id" not in names
    assert _find(fields, "primary")["type"] == "ip"
    # 'status' int with a sibling *_val => bool
    assert _find(fields, "status")["type"] == "bool"


def test_merge_doc_enriches_label_and_help():
    fields = [{"name": "primary", "label": "primary", "type": "ip", "help": "", "group": "Basic"}]
    doc = {"primary": {"label": "Primary DNS server", "help": "The main resolver", "options": []}}
    merged = h.merge_doc(fields, doc)
    assert _find(merged, "primary")["label"] == "Primary DNS server"
    assert _find(merged, "primary")["help"] == "The main resolver"
