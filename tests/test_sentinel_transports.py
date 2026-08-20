"""Sentinel — the two device transports captured on 2026-08-20, and the gate
chain that stands in front of them.

The fake appliance here models three shapes that made the real device dangerous
to automate against, each of which was observed on fortiweb12 (FortiWeb 7.6.8):

1. **A policy reaches a list only through its profile.** A list nothing
   references accepts members, counts up, and blocks nothing.
2. **A wrong child path is not an error.** ``GET waf/geo-block-list/members``
   answers 200 with the PARENT object. Code that trusted the status code would
   verify a write against an endpoint incapable of holding it.
3. **The device rejects ISO country codes.** The key is ``country-name`` and it
   wants a full name; ``{"country": "AD"}`` answers ``-7950``.

A change that stops re-reading, or that starts guessing a country name, fails
here for the same reason it would fail in production.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

from app.models import db
from app.models_sentinel import (SentinelAction, SentinelIncident,
                                 SentinelPolicy)
from app.services.sentinel import actions, config, normalize, responder, transports

GEO = transports.SENTINEL_GEO_LIST
LIST = transports.SENTINEL_LIST


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload, self.status_code = payload, status
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


class FakeDevice:
    """policies -> profiles -> {ip list, geo list} -> members / country-list."""

    def __init__(self, *, geo_bound=True, geo_list=True, swallow=False,
                 undeletable=False, profile="wpp-root-shop"):
        self.policies = {"pol-root-shop": {"name": "pol-root-shop",
                                           "web-protection-profile": profile}}
        self.profiles = {
            "wpp-root-shop": {"name": "wpp-root-shop", "ip-list-policy": LIST,
                              "geo-block-list-policy": GEO if geo_bound else ""},
            "Inline Extended Protection": {"name": "Inline Extended Protection"},
            "Inline Standard Protection": {"name": "Inline Standard Protection"},
        }
        self.geo = {GEO: {"name": GEO, "action": "block-period"}} if geo_list else {}
        self.countries: list = []
        self.swallow = swallow          # accepts the POST, stores nothing
        self.undeletable = undeletable  # accepts the DELETE, keeps the row
        self.calls: list = []
        self._next = 1

    @staticmethod
    def _mkey(path):
        for part in path.split("?", 1)[-1].split("&"):
            if part.startswith("mkey="):
                return part[5:]
        return ""

    @staticmethod
    def _sub(path):
        for part in path.split("?", 1)[-1].split("&"):
            if part.startswith("sub_mkey="):
                return part[9:]
        return ""

    def _geo_parent(self, key):
        row = dict(self.geo.get(key) or {})
        if not row:
            return FakeResponse({"results": {"errcode": -3,
                                             "message": "The entry is not found."}}, 500)
        row["sz_country-list"] = len(self.countries)
        return FakeResponse({"results": row})

    def get(self, path):
        self.calls.append(("GET", path))
        key = self._mkey(path)
        if "/geo-block-list/country-list" in path:
            return FakeResponse({"results": list(self.countries)})
        if "/geo-block-list/" in path:
            # THE TRAP: a wrong child path answers 200 with the parent object.
            return self._geo_parent(key)
        if "/geo-block-list" in path:
            if key:
                return self._geo_parent(key)
            return FakeResponse({"results": list(self.geo.values())})
        if "web-protection-profile" in path:
            return FakeResponse({"results": self.profiles.get(key, {})})
        if "server-policy/policy" in path:
            return FakeResponse({"results": self.policies.get(key, {})})
        return FakeResponse({"results": {}})

    def post(self, path, data=None):
        self.calls.append(("POST", path))
        body = (data or {}).get("data") or {}
        if "/geo-block-list/country-list" in path:
            if self._mkey(path) not in self.geo:
                return FakeResponse({"results": {"errcode": -3,
                                                 "message": "not found"}}, 500)
            name = body.get("country-name") or ""
            if not name or len(name) <= 3:
                return FakeResponse({"results": {
                    "errcode": -7950,
                    "message": "The country name is empty or wrong."}}, 500)
            row = {"id": str(self._next), "country-name": name}
            self._next += 1
            if not self.swallow:
                self.countries.append(row)
            return FakeResponse({"results": row})
        if "/geo-block-list" in path:
            self.geo[body.get("name")] = dict(body)
            return FakeResponse({"results": dict(body)})
        return FakeResponse({"results": {}})

    def put(self, path, data=None):
        self.calls.append(("PUT", path))
        body = (data or {}).get("data") or {}
        if "server-policy/policy" in path:
            self.policies.setdefault(self._mkey(path), {}).update(body)
        elif "web-protection-profile" in path:
            self.profiles.setdefault(self._mkey(path), {}).update(body)
        return FakeResponse({"results": {"status": "success"}})

    def delete(self, path):
        self.calls.append(("DELETE", path))
        if "/geo-block-list/country-list" in path and not self.undeletable:
            sub = self._sub(path)
            self.countries = [c for c in self.countries if str(c.get("id")) != sub]
        return FakeResponse({"results": {"status": "success"}})


# --------------------------------------------------------------------------- #
#  1. The gate chain is data, and the data matches the engine                    #
# --------------------------------------------------------------------------- #
def _incident(**kw):
    base = dict(ref=f"INC-T-{datetime.utcnow().timestamp()}",
                status=SentinelIncident.STATUS_OPEN, device="fortiweb12",
                policy="pol-root-shop", src_ip="185.10.20.30",
                src_country="Andorra", attack_family="sqli", severity="high",
                score=95, src_trusted=False, opened_at=datetime.utcnow())
    base.update(kw)
    inc = SentinelIncident(**base)
    db.session.add(inc)
    db.session.commit()
    return inc


def test_gate_order_is_exactly_what_evaluate_emits(app):
    """The documentation page draws the ladder from GATE_ORDER. If the engine
    ever gains, loses or reorders a check, the picture would keep showing the
    old chain and nothing would fail — so this is the thing that fails."""
    with app.app_context():
        actions.ensure_policies()
        pol = SentinelPolicy.query.filter_by(action_type="block_ip").first()
        pol.enabled = True
        pol.level = SentinelPolicy.LEVEL_SEMI_AUTO
        pol.min_confidence = 0
        pol.ttl_minutes = 30
        config.set_value("response_enabled", True)
        db.session.commit()

        verdict = actions.evaluate(_incident(), "block_ip")
        assert verdict["allowed"] is True, verdict["reason"]
        emitted = [c["check"] for c in verdict["checks"]]
        declared = [k for k, _label, _why in actions.GATE_ORDER]
        assert emitted == declared, (
            "the engine applies %s; GATE_ORDER (and therefore the diagram) "
            "says %s" % (emitted, declared))


def test_every_gate_carries_a_reason_a_person_can_act_on(app):
    with app.app_context():
        for key, label, why in actions.GATE_ORDER:
            assert label and why, f"{key} has no explanation"
            assert len(why) > 30, (
                f"{key}: '{why}' restates the name instead of giving the reason. "
                f"The console prints these to answer 'why did Sentinel do "
                f"nothing?'")


# --------------------------------------------------------------------------- #
#  2. A wrong child path is not an error on this appliance                       #
# --------------------------------------------------------------------------- #
def test_a_child_read_that_returns_the_parent_counts_as_no_rows(app):
    """The defect this helper exists for: 200 + the parent object."""
    with app.app_context():
        dev = FakeDevice()
        parent = dev.get(f"/api/v2.0/cmdb/waf/geo-block-list/members?mkey={GEO}")
        assert parent.status_code == 200
        assert isinstance(parent.json()["results"], dict), \
            "the fake stopped modelling the trap this test is about"
        rows = transports._child_rows(
            dev, f"/api/v2.0/cmdb/waf/geo-block-list/members?mkey={GEO}")
        assert rows == [], ("a dict answer was treated as rows — a write would "
                            "be 'verified' against an endpoint that cannot "
                            "hold it")


# --------------------------------------------------------------------------- #
#  3. block_country                                                             #
# --------------------------------------------------------------------------- #
def test_geo_preflight_refuses_when_the_profile_does_not_reference_the_list(app):
    with app.app_context():
        t = transports.BlockCountryTransport()
        ok, why = t.preflight(FakeDevice(geo_bound=False),
                              {"policy": "pol-root-shop", "country": "Andorra"})
        assert ok is False
        assert "geo-block-list-policy" in why and "blocks nothing" in why


def test_geo_preflight_refuses_an_iso_code_instead_of_guessing(app):
    """The appliance answers -7950 to 'AD'. Expanding a code here would mean
    inventing the string we are about to hand a firewall."""
    with app.app_context():
        t = transports.BlockCountryTransport()
        ok, why = t.preflight(FakeDevice(),
                              {"policy": "pol-root-shop", "country": "AD"})
        assert ok is False and "-7950" in why


def test_geo_apply_verify_and_rollback_round_trip(app):
    with app.app_context():
        dev = FakeDevice()
        t = transports.BlockCountryTransport()
        assert t.preflight(dev, {"policy": "pol-root-shop",
                                 "country": "Andorra"})[0] is True
        out = t.apply(dev, {"country": "Andorra"})
        assert out.ok and out.handle["member_id"] == "1"
        assert t.verify_applied(dev, out.handle)[0] is True
        back = t.rollback(dev, out.handle)
        assert back.ok
        assert dev.countries == [], "the country survived its own rollback"
        assert t.verify_applied(dev, out.handle)[0] is False


def test_geo_rollback_fails_when_the_delete_did_not_take(app):
    """A device that accepts the DELETE and keeps the row is the case the
    post-delete re-read exists for. Without it the action would be recorded
    "expired" while the country stayed blocked — and nothing would ever look
    at it again, because expiry only runs once."""
    with app.app_context():
        dev = FakeDevice(undeletable=True)
        t = transports.BlockCountryTransport()
        out = t.apply(dev, {"country": "Andorra"})
        assert out.ok
        back = t.rollback(dev, out.handle)
        assert back.ok is False,             "a delete the device ignored was reported as a successful rollback"
        assert "STILL listed" in back.detail
        assert dev.countries, "the fake stopped modelling the trap"


def test_geo_apply_fails_when_the_device_accepts_and_stores_nothing(app):
    """200 is a receipt, not an outcome."""
    with app.app_context():
        dev = FakeDevice(swallow=True)
        out = transports.BlockCountryTransport().apply(dev, {"country": "Andorra"})
        assert out.ok is False and "re-read" in out.detail


# --------------------------------------------------------------------------- #
#  4. raise_protection                                                          #
# --------------------------------------------------------------------------- #
def test_raise_refuses_while_no_hardened_profile_is_approved(app):
    with app.app_context():
        config.set_value("hardened_profiles", "")
        ok, why = transports.RaiseProtectionTransport().preflight(
            FakeDevice(), {"policy": "pol-root-shop"})
        assert ok is False and "no hardened profile has been approved" in why


def test_raise_refuses_a_profile_nobody_approved(app):
    with app.app_context():
        config.set_value("hardened_profiles", "Inline Extended Protection")
        ok, why = transports.RaiseProtectionTransport().preflight(
            FakeDevice(), {"policy": "pol-root-shop",
                           "profile": "Inline Alert Only"})
        assert ok is False and "not an approved hardened profile" in why


def test_raise_refuses_a_profile_absent_from_the_appliance(app):
    with app.app_context():
        config.set_value("hardened_profiles", "Inline Nonexistent")
        ok, why = transports.RaiseProtectionTransport().preflight(
            FakeDevice(), {"policy": "pol-root-shop"})
        assert ok is False and "does not exist on this appliance" in why


def test_raise_restores_the_captured_original_not_a_default(app):
    """The undo is a write, so it needs the value that was actually there."""
    with app.app_context():
        config.set_value("hardened_profiles", "Inline Extended Protection")
        dev = FakeDevice()
        t = transports.RaiseProtectionTransport()
        assert t.preflight(dev, {"policy": "pol-root-shop"})[0] is True
        out = t.apply(dev, {"policy": "pol-root-shop"})
        assert out.ok and out.handle["previous"] == "wpp-root-shop"
        assert dev.policies["pol-root-shop"]["web-protection-profile"] == \
            "Inline Extended Protection"
        assert t.verify_applied(dev, out.handle)[0] is True

        back = t.rollback(dev, out.handle)
        assert back.ok
        assert dev.policies["pol-root-shop"]["web-protection-profile"] == \
            "wpp-root-shop", "the policy did not go back to what it had"


def test_raise_rollback_refuses_to_write_an_empty_binding(app):
    """Unbinding the profile would strip protection from every client of the
    policy — worse than the state being undone."""
    with app.app_context():
        dev = FakeDevice()
        before = len(dev.calls)
        out = transports.RaiseProtectionTransport().rollback(
            dev, {"policy": "pol-root-shop", "profile": "X", "previous": ""})
        assert out.ok is False
        assert "Refusing to write an empty binding" in out.detail
        assert not [c for c in dev.calls[before:] if c[0] == "PUT"], \
            "it wrote to the device anyway"


# --------------------------------------------------------------------------- #
#  5. A hand-off is not something this engine executes                          #
# --------------------------------------------------------------------------- #
def test_handoff_is_refused_before_any_transport_lookup(app):
    with app.app_context():
        actions.ensure_policies()
        pol = SentinelPolicy.query.filter_by(action_type="tune_signature").first()
        pol.enabled = True
        pol.level = SentinelPolicy.LEVEL_AUTONOMOUS
        pol.min_confidence = 0
        config.set_value("response_enabled", True)
        db.session.commit()
        verdict = actions.evaluate(_incident(), "tune_signature")
        assert verdict["allowed"] is False
        assert verdict["reason"] == "hand-off, not executable"
        gate = [c for c in verdict["checks"]
                if c["check"] == "executable_mechanism"][0]
        assert "exception flow" in gate["detail"], \
            "the refusal does not say where the work actually happens"


def test_handoff_never_reaches_a_device(app, monkeypatch):
    with app.app_context():
        dev = FakeDevice()
        monkeypatch.setattr(responder, "_client", lambda d: (dev, ""))
        config.set_value("response_enabled", True)
        actions.ensure_policies()
        pol = SentinelPolicy.query.filter_by(action_type="tune_signature").first()
        pol.enabled, pol.level, pol.min_confidence = True, 3, 0
        db.session.commit()
        inc = _incident()
        a = SentinelAction(incident_id=inc.id, action_type="tune_signature",
                           status=SentinelAction.STATUS_QUEUED,
                           correlation_id=f"{inc.ref}:tune_signature",
                           level=2,
                           expires_at=datetime.utcnow() + timedelta(minutes=30))
        a.params = {"device": inc.device, "policy": inc.policy}
        db.session.add(a)
        db.session.commit()
        responder.drain()
        assert a.status == SentinelAction.STATUS_REJECTED
        assert dev.calls == [], "a hand-off talked to an appliance"


def test_transports_exist_for_exactly_the_verified_device_actions(app):
    """A catalog entry claiming verification with no transport behind it, or a
    transport for an entry still marked unproved, are both lies in opposite
    directions."""
    with app.app_context():
        expected = {k for k, s in actions.CATALOG.items()
                    if s.verified and not s.handoff}
        assert set(transports.TRANSPORTS) == expected
        for key in expected:
            assert actions.CATALOG[key].provenance, \
                f"{key} is marked verified with no provenance — an unsourced claim"


# --------------------------------------------------------------------------- #
#  6. The country string is the device's, verbatim                              #
# --------------------------------------------------------------------------- #
def test_country_is_not_truncated_to_eight_characters(app):
    """It was String(8). 'United States' became 'United S' — which both
    mislabels the source and destroys the only value the geo list accepts."""
    with app.app_context():
        class _Ap:
            id, name = None, "fortiweb12"
        ev = normalize.from_attack_log(_Ap(), {"srccountry": "United States",
                                               "src": "185.10.20.30",
                                               "main_type": "SQL Injection"})
        assert ev.country == "United States"
        from app.models_sentinel import SentinelEvent, SentinelIncident
        assert SentinelEvent.__table__.c.country.type.length >= 64
        assert SentinelIncident.__table__.c.src_country.type.length >= 64


# --------------------------------------------------------------------------- #
#  7. The module is actually armed on a fresh install                           #
# --------------------------------------------------------------------------- #
def test_the_sweep_is_part_of_the_seed_plan():
    """Without the sweep, Sentinel has every table, page and gate, opens no
    incident, and looks exactly like a quiet week."""
    import sys
    from pathlib import Path
    repo = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo / "deploy"))
    from satom_cli import cmd_checks, cmd_fix
    planned = {row[0] for row in cmd_fix.SEED_PLAN}
    for key in ("sentinel_sweep", "sentinel_baseline", "sentinel_vuln_sync"):
        assert key in planned, f"{key} is not seeded on a fresh install"
        assert key in cmd_checks.MIN_ACTIONS, \
            f"{key} is created but 'diagnose install' would not notice it missing"
