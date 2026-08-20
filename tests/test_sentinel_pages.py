"""Sentinel — the pages actually render, with real data in them.

A blueprint that imports cleanly and 500s on first render is the failure this
file exists to catch, and it is not hypothetical here: the AI settings tab in
this product was restructured precisely because one optional feature could take
the whole Settings page down.

The assertions go further than "HTTP 200". They check for the sentences that
carry the design's meaning — an unknown layer rendered as *unknown*, a refusal
rendered with its reason, the model's output labelled as opinion. A page can
return 200 while saying the opposite of what it should.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.models import db
from app.models_sentinel import (SentinelEvent, SentinelIncident,
                                 SentinelTrustedSource)
from tests.conftest import admin_user_id, login

T0 = datetime(2026, 8, 18, 12, 0, 0)


@pytest.fixture()
def admin(app, client):
    login(client, admin_user_id(app), product="global")
    return client


def _incident(app, **kw):
    with app.app_context():
        ev = SentinelEvent(ts=T0, device="fortiweb12", source="attack_log",
                           policy="pol-root-shop", src_ip="185.10.20.30",
                           country="RU", uri="/admin.php", http_status=200,
                           signature="SQL Injection", attack_family="sqli",
                           severity="high", action="alert", count=1,
                           dedup_key="pagetest")
        db.session.add(ev)
        db.session.flush()
        from app.services.sentinel import incident as inc_svc
        inc = inc_svc.ingest_event(ev)
        for key, value in kw.items():
            setattr(inc, key, value)
        db.session.commit()
        return inc.id


def test_console_renders_empty(admin):
    r = admin.get("/sentinel/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Sentinel" in body
    # The four honesty tiles must be present even with no incidents at all.
    assert "Behavioural baseline" in body
    assert "CVE mirror" in body
    assert "Response engine" in body


def test_console_says_never_run_rather_than_looking_healthy(admin):
    """An empty list plus no heartbeat must read as 'not looking', not 'clear'."""
    body = admin.get("/sentinel/").get_data(as_text=True)
    assert "never run" in body or "ago" in body


def test_console_lists_an_incident(app, admin):
    _incident(app)
    body = admin.get("/sentinel/").get_data(as_text=True)
    assert "INC-2026-" in body
    assert "fortiweb12" in body
    assert "185.10.20.30" in body


def test_incident_page_renders(app, admin):
    iid = _incident(app)
    r = admin.get(f"/sentinel/incident/{iid}")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "How this score was reached" in body
    assert "Evidence" in body
    assert "Every layer, same time axis" in body


def test_incident_page_labels_the_model_as_opinion(app, admin):
    iid = _incident(app)
    body = admin.get(f"/sentinel/incident/{iid}").get_data(as_text=True)
    assert "opinion, not measurement" in body


def test_incident_page_shows_why_each_action_was_refused(app, admin):
    """'Sentinel did nothing' is not an acceptable console state."""
    iid = _incident(app)
    body = admin.get(f"/sentinel/incident/{iid}").get_data(as_text=True)
    assert "refused" in body
    assert "kill_switch" in body or "response engine" in body.lower()


def test_incident_page_renders_unknown_layers_as_unknown(app, admin):
    """The distinction the topology table exists to preserve."""
    iid = _incident(app)
    with app.app_context():
        inc = SentinelIncident.query.get(iid)
        inc.impact_vm = None
        inc.impact_fortinet = True
        db.session.commit()
    body = admin.get(f"/sentinel/incident/{iid}").get_data(as_text=True)
    assert "vm: unknown" in body
    assert "vm: impacted" not in body


def test_charts_endpoint_answers_json(app, admin):
    iid = _incident(app)
    r = admin.get(f"/sentinel/incident/{iid}/charts")
    assert r.status_code == 200
    payload = r.get_json()
    # With no store reachable in the test environment this must say so
    # explicitly rather than returning an empty series list that a chart would
    # draw as a quiet window.
    assert "store_ok" in payload and "series" in payload
    assert "layers_unknown" in payload


def test_context_page_renders(admin):
    r = admin.get("/sentinel/context")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Trusted sources" in body
    assert "Maintenance windows" in body
    assert "Topology" in body
    assert "Local CVE mirror" in body


def test_policies_page_leads_with_what_it_cannot_do(admin):
    r = admin.get("/sentinel/policies")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "0/5 action transports have been verified" in body
    assert "invalid URL" in body      # the provenance of that caution


def test_docs_page_renders_from_live_code(admin):
    """Every number on it must come from the running module, not a copy."""
    from app.services.sentinel import scoring
    r = admin.get("/sentinel/docs")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    for factor in ("http_evasion", "waf_blocked", "trusted_source"):
        assert factor in body
    # The rendered points must equal the live weights, so a tuned weight
    # cannot leave a stale number on the page. Matched on the value alone,
    # not on surrounding markup: an assertion pinned to whitespace inside a
    # badge breaks on a reformat while the defect it guards against — a
    # hand-copied number going stale — sails through.
    assert f"+{scoring.WEIGHTS['http_evasion']}" in body
    assert str(scoring.WEIGHTS["waf_blocked"]) in body


def test_docs_page_lists_every_setting(admin):
    from app.services.sentinel import config
    body = admin.get("/sentinel/docs").get_data(as_text=True)
    for spec in config.SPEC:
        assert f"sentinel.{spec['key']}" in body


def test_settings_tab_renders_inside_the_settings_page(admin):
    """The Sentinel section must not be able to take Settings down with it."""
    r = admin.get("/settings/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert 'id="tab-sentinel"' in body
    assert "Sentinel — security correlation" in body
    assert "sentinel.response_enabled" in body


def test_settings_save_round_trip(admin, app):
    r = admin.post("/settings/sentinel", data={
        "enabled__present": "1", "enabled": "1",
        "response_enabled__present": "1",       # unchecked => must turn OFF
        "ingest_limit": "150",
        "baseline_k": "7.5",
        "protect_cidrs": "10.0.0.0/8",
    }, follow_redirects=True)
    assert r.status_code == 200
    with app.app_context():
        from app.services.sentinel import config
        assert config.get("enabled") is True
        assert config.get("response_enabled") is False
        assert config.get("ingest_limit") == 150
        assert config.get("baseline_k") == 7.5


def test_settings_save_clamps_out_of_range(admin, app):
    """A hand-typed 99999 must be corrected, not become a threshold that can
    never fire."""
    admin.post("/settings/sentinel", data={"ingest_limit": "99999"},
               follow_redirects=True)
    with app.app_context():
        from app.services.sentinel import config
        assert config.get("ingest_limit") == 2000


def test_an_unchecked_switch_can_be_turned_off(admin, app):
    """The __present marker. Without it a switch turns on and never off."""
    with app.app_context():
        from app.services.sentinel import config
        config.set_value("ai_enabled", True)
    admin.post("/settings/sentinel",
               data={"ai_enabled__present": "1"}, follow_redirects=True)
    with app.app_context():
        from app.services.sentinel import config
        assert config.get("ai_enabled") is False


def test_a_field_absent_from_the_post_is_left_alone(admin, app):
    """A partial POST must not reset every other setting to its default."""
    with app.app_context():
        from app.services.sentinel import config
        config.set_value("ingest_limit", 321)
    admin.post("/settings/sentinel", data={"baseline_k": "9"},
               follow_redirects=True)
    with app.app_context():
        from app.services.sentinel import config
        assert config.get("ingest_limit") == 321


def test_blank_secret_keeps_the_stored_one(admin, app):
    with app.app_context():
        from app.services.sentinel import config
        config.set_value("vuln_api_key", "sekrit")
    admin.post("/settings/sentinel", data={"vuln_api_key": ""},
               follow_redirects=True)
    with app.app_context():
        from app.services.sentinel import config
        assert config.get("vuln_api_key") == "sekrit"


def test_secret_is_masked_in_the_form(admin, app):
    with app.app_context():
        from app.services.sentinel import config
        config.set_value("vuln_api_key", "sekrit")
    body = admin.get("/settings/").get_data(as_text=True)
    assert "sekrit" not in body


def test_trusted_source_without_expiry_gets_one_and_says_so(admin, app):
    r = admin.post("/sentinel/context/trusted",
                   data={"cidr": "203.0.113.0/24", "kind": "scanner",
                         "label": "nessus"}, follow_redirects=True)
    assert r.status_code == 200
    assert "permanent blind spot" in r.get_data(as_text=True)
    with app.app_context():
        row = SentinelTrustedSource.query.filter_by(cidr="203.0.113.0/24").one()
        assert row.expires_at is not None


def test_bad_cidr_is_rejected(admin, app):
    r = admin.post("/sentinel/context/trusted",
                   data={"cidr": "banana", "kind": "scanner"},
                   follow_redirects=True)
    assert "not a valid CIDR" in r.get_data(as_text=True)
    with app.app_context():
        assert SentinelTrustedSource.query.count() == 0


def test_a_window_must_end_after_it_starts(admin, app):
    r = admin.post("/sentinel/context/window",
                   data={"label": "backwards",
                         "starts_at": "2026-08-20T10:00",
                         "ends_at": "2026-08-20T09:00"},
                   follow_redirects=True)
    assert "must end after it starts" in r.get_data(as_text=True)


def test_incomplete_topology_is_reported_as_incomplete(admin, app):
    """A half-filled topology row must NOT read as a working mapping.

    The appliance is created here rather than skipping when the fixture has
    none: a skipped test verifies nothing, and this is the guard standing
    between "VM layer unknown" and "VM layer healthy" — the one distinction
    the topology table exists for.
    """
    from app.models import Appliance
    with app.app_context():
        a = Appliance.query.filter_by(kind="fortiweb").first()
        if a is None:
            a = Appliance(name="topo-test", host="192.0.2.99",
                          kind="fortiweb", username="admin", password="x")
            db.session.add(a)
            db.session.commit()
        aid = a.id
    r = admin.post("/sentinel/context/topology",
                   data={"appliance_id": aid, "vm_id": "352"},
                   follow_redirects=True)
    assert "INCOMPLETE" in r.get_data(as_text=True)


def test_closing_a_false_positive_without_a_reason_is_refused(app, admin):
    iid = _incident(app)
    r = admin.post(f"/sentinel/incident/{iid}/close",
                   data={"status": "false_positive"}, follow_redirects=True)
    assert "must record why" in r.get_data(as_text=True)
    with app.app_context():
        assert SentinelIncident.query.get(iid).status == "open"


def test_recording_an_action_never_executes_it(app, admin):
    """The button records a decision. There is no executor behind it yet, and
    the flash must say so rather than implying a firewall changed."""
    iid = _incident(app)
    r = admin.post(f"/sentinel/incident/{iid}/action",
                   data={"action_type": "block_ip", "note": "test"},
                   follow_redirects=True)
    assert r.status_code == 200
    text = r.get_data(as_text=True)
    assert "refused by the policy engine" in text or "NOT executed" in text


def test_unknown_action_type_is_rejected(app, admin):
    iid = _incident(app)
    r = admin.post(f"/sentinel/incident/{iid}/action",
                   data={"action_type": "drop_the_database"})
    assert r.status_code == 400


def test_nav_offers_sentinel_in_the_global_adom(admin):
    body = admin.get("/sentinel/").get_data(as_text=True)
    assert "/sentinel/" in body


def test_every_sentinel_route_requires_login(client):
    for path in ("/sentinel/", "/sentinel/context", "/sentinel/docs",
                 "/sentinel/policies", "/sentinel/data"):
        r = client.get(path)
        assert r.status_code in (302, 401), f"{path} answered {r.status_code}"
