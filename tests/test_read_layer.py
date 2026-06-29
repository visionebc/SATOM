"""Phase 3 — DB-first read layer + freshness + workspace integration."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.services import device_store as ds
from app.services import read_layer as rl
from tests.conftest import admin_user_id, login


SECTIONS = {
    "Server Policy": {"server_policy": [
        {"name": "pol-one", "deployment-mode": "single-server",
         "server-pool": "pool-one", "web-protection-profile": "wpp-one",
         "status": "enable"},
        {"name": "pol-two", "deployment-mode": "server-pool",
         "server-pool": "pool-two", "status": "disable"},
    ]},
}


def _appliance(session, name="fw-rl"):
    from app.models import Appliance
    a = Appliance(name=name, kind="fortiweb", host="192.0.2.9", port=443,
                  username="admin", password_enc="x", verify_ssl=False)
    session.add(a); session.commit()
    return a


def test_read_objects_returns_payloads_and_meta(session):
    a = _appliance(session)
    ds.ingest_sections(a.id, SECTIONS, source="live", session=session)
    payloads, meta = rl.read_objects(a.id, "server_policy", session=session)
    assert {p["name"] for p in payloads} == {"pol-one", "pol-two"}
    # raw hyphenated keys preserved for the template
    assert payloads[0]["deployment-mode"] in ("single-server", "server-pool")
    assert meta["total"] == 2 and meta["source"] == "live"
    assert meta["generated_at"] is not None


def test_read_objects_filter_q(session):
    a = _appliance(session)
    ds.ingest_sections(a.id, SECTIONS, source="live", session=session)
    payloads, meta = rl.read_objects(a.id, "server_policy", q="one", session=session)
    assert [p["name"] for p in payloads] == ["pol-one"]


def test_freshness_label():
    assert rl.freshness_label({}) == "no local data — refresh"
    now = datetime.utcnow()
    assert "just now" in rl.freshness_label({"generated_at": now, "source": "DB"})
    assert "h ago" in rl.freshness_label(
        {"generated_at": now - timedelta(hours=3), "source": "live"})


def test_workspace_page_renders_from_cache(app, client, session):
    a = _appliance(session, name="fw-page")
    ds.ingest_sections(a.id, SECTIONS, source="live", session=session)
    login(client, admin_user_id(app))
    r = client.get(f"/workspace/{a.id}")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "pol-one" in body and "pol-two" in body
    assert "Refresh from device" in body
    assert "DB ·" in body  # freshness badge rendered
