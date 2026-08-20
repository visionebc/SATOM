"""Sentinel phase 7 — the response path, from queued row to device and back.

The fake appliance in this file is not a convenience: it is a MODEL of the
transport captured from fortiweb12 on 2026-08-20, including the two shapes that
made the real device dangerous to automate against —

* a policy reaches an IP list only through its web protection profile, so a
  list nobody references accepts members and blocks nothing;
* the device answers 200 for writes whose effect must still be re-read.

Both are reproduced here, so a change that stops re-reading fails against the
fake for the same reason it would fail in production.

The assertions that matter most:

1. ``test_preflight_refuses_when_profile_does_not_reference_the_list`` — the
   ca-group defect, one level up. Applied, green, and protecting nothing.
2. ``test_expiry_runs_with_the_kill_switch_off`` — disarming must stop new
   blocks without stranding live ones. A safety control that causes the outage
   is not a safety control.
3. ``test_gates_are_re_evaluated_at_execution_time`` — approval is not a token
   that stays valid while the world changes underneath it.
4. ``test_effect_unknown_is_never_success`` — no baseline to compare against
   means we do not know, and "we do not know" must not render as a win.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from app.models import db
from app.models_sentinel import (SentinelAction, SentinelEvent,
                                 SentinelIncident, SentinelPolicy)
from app.services.sentinel import actions, config, responder, transports

LIST = transports.SENTINEL_LIST


# --------------------------------------------------------------------------- #
#  A fake FortiWeb that reproduces the real shapes                              #
# --------------------------------------------------------------------------- #
class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload, self.status_code = payload, status
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


class FakeDevice:
    """Minimal FortiWeb: policies -> profiles -> ip lists -> members."""

    def __init__(self, *, bound=True, list_exists=True,
                 swallow_member=False, undeletable=False):
        self.policies = {"pol-root-shop": {"name": "pol-root-shop",
                                           "web-protection-profile": "wpp-root-shop"}}
        self.profiles = {"wpp-root-shop": {"name": "wpp-root-shop",
                                           "ip-list-policy": LIST if bound else ""}}
        self.lists = {LIST: {"name": LIST, "action": "block-period"}} if list_exists else {}
        self.members: list = []
        self.swallow_member = swallow_member    # accepts the POST, stores nothing
        self.undeletable = undeletable          # accepts the DELETE, keeps the row
        self.calls: list = []
        self._next = 1

    # -- helpers
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

    # -- verbs
    def get(self, path):
        self.calls.append(("GET", path))
        key = self._mkey(path)
        if "/ip-list/members" in path:
            return FakeResponse({"results": list(self.members)})
        if "/ip-list" in path:
            if key:
                row = dict(self.lists.get(key) or {})
                if not row:
                    return FakeResponse({"results": {"errcode": -3,
                                                     "message": "not found"}}, 500)
                row["sz_members"] = len(self.members)
                return FakeResponse({"results": row})
            return FakeResponse({"results": list(self.lists.values())})
        if "web-protection-profile" in path:
            return FakeResponse({"results": self.profiles.get(key, {})})
        if "server-policy/policy" in path:
            return FakeResponse({"results": self.policies.get(key, {})})
        return FakeResponse({"results": {}})

    def post(self, path, data=None):
        self.calls.append(("POST", path))
        body = (data or {}).get("data") or {}
        if "/ip-list/members" in path:
            if self._mkey(path) not in self.lists:
                return FakeResponse({"results": {"errcode": -3,
                                                 "message": "not found"}}, 500)
            row = {"id": str(self._next), "type": body.get("type"),
                   "ip": body.get("ip")}
            self._next += 1
            if not self.swallow_member:          # the device that says yes and does nothing
                self.members.append(row)
            return FakeResponse({"results": row})
        if "/ip-list" in path:
            self.lists[body.get("name")] = dict(body)
            return FakeResponse({"results": dict(body)})
        return FakeResponse({"results": {}})

    def put(self, path, data=None):
        self.calls.append(("PUT", path))
        body = (data or {}).get("data") or {}
        if "web-protection-profile" in path:
            self.profiles.setdefault(self._mkey(path), {}).update(body)
        return FakeResponse({"results": {"status": "success"}})

    def delete(self, path):
        self.calls.append(("DELETE", path))
        if "/ip-list/members" in path and not self.undeletable:
            sub = self._sub(path)
            self.members = [m for m in self.members if str(m.get("id")) != sub]
        return FakeResponse({"results": {"status": "success"}})


# --------------------------------------------------------------------------- #
#  Builders                                                                     #
# --------------------------------------------------------------------------- #
def mk_incident(**kw) -> SentinelIncident:
    base = dict(ref=f"INC-TEST-{datetime.utcnow().timestamp()}",
                status=SentinelIncident.STATUS_OPEN, device="fortiweb12",
                policy="pol-root-shop", src_ip="185.10.20.30",
                attack_family="sqli", severity="high", score=95,
                src_trusted=False, waf_blocked=False, passed_count=3,
                opened_at=datetime.utcnow())
    base.update(kw)
    inc = SentinelIncident(**base)
    db.session.add(inc)
    db.session.commit()
    return inc


def arm(monkeypatch, device: FakeDevice):
    """Point the responder's client factory at the fake, and arm the engine."""
    monkeypatch.setattr(responder, "_client", lambda d: (device, ""))
    config.set_value("response_enabled", True)


def enable_policy(action_type="block_ip", **kw):
    actions.ensure_policies()
    p = SentinelPolicy.query.filter_by(action_type=action_type).first()
    p.enabled = True
    p.level = kw.get("level", SentinelPolicy.LEVEL_SEMI_AUTO)
    p.min_confidence = kw.get("min_confidence", 85)
    p.ttl_minutes = kw.get("ttl_minutes", 30)
    db.session.commit()
    return p


def queue(incident, action_type="block_ip", **params):
    a = SentinelAction(incident_id=incident.id, action_type=action_type,
                       status=SentinelAction.STATUS_QUEUED,
                       correlation_id=f"{incident.ref}:{action_type}",
                       level=SentinelPolicy.LEVEL_SEMI_AUTO,
                       expires_at=datetime.utcnow() + timedelta(minutes=30))
    a.params = dict({"src_ip": incident.src_ip, "device": incident.device,
                     "policy": incident.policy}, **params)
    db.session.add(a)
    db.session.commit()
    return a


# --------------------------------------------------------------------------- #
#  1. The catalog now tells the truth about what can be executed                #
# --------------------------------------------------------------------------- #
def test_block_ip_is_the_only_verified_action(app):
    with app.app_context():
        verified = [k for k, s in actions.CATALOG.items() if s.verified]
        assert verified == ["block_ip"], (
            "only mechanisms actually run against a device may be marked "
            "verified; %s claims to be" % verified)
        assert actions.CATALOG["block_ip"].provenance, \
            "a verified action without provenance is an unsourced claim"


def test_rate_limit_ip_was_withdrawn_not_left_unverified(app):
    with app.app_context():
        assert "rate_limit_ip" not in actions.CATALOG
        assert "rate_limit_ip" not in actions.BAND_RECOMMENDATION.values()


def test_prune_removes_the_orphan_policy_but_keeps_audited_ones(app):
    with app.app_context():
        actions.ensure_policies()
        db.session.add(SentinelPolicy(action_type="rate_limit_ip", enabled=True))
        db.session.add(SentinelPolicy(action_type="ghost_action", enabled=True))
        db.session.commit()
        inc = mk_incident()
        db.session.add(SentinelAction(incident_id=inc.id,
                                      action_type="ghost_action",
                                      status=SentinelAction.STATUS_PROPOSED))
        db.session.commit()
        removed = actions.prune_policies()
        assert "rate_limit_ip" in removed, "a switch wired to nothing stayed on screen"
        assert "ghost_action" not in removed, \
            "deleting a policy that has actions takes the audit trail with it"


# --------------------------------------------------------------------------- #
#  2. Preflight — the defect this whole module exists to prevent                #
# --------------------------------------------------------------------------- #
def test_preflight_refuses_when_profile_does_not_reference_the_list(app):
    with app.app_context():
        dev = FakeDevice(bound=False)
        ok, reason = transports.BlockIpTransport().preflight(
            dev, {"policy": "pol-root-shop"})
        assert ok is False
        assert "blocks nothing" in reason, \
            "the refusal must say WHY an apply here would be a lie"


def test_preflight_passes_when_the_binding_exists(app):
    with app.app_context():
        ok, reason = transports.BlockIpTransport().preflight(
            FakeDevice(bound=True), {"policy": "pol-root-shop"})
        assert ok is True and LIST in reason


def test_preflight_refuses_an_unknown_policy(app):
    with app.app_context():
        ok, reason = transports.BlockIpTransport().preflight(
            FakeDevice(), {"policy": "does-not-exist"})
        assert ok is False and "does not exist" in reason


# --------------------------------------------------------------------------- #
#  3. Apply is proved by re-reading, never by the status code                   #
# --------------------------------------------------------------------------- #
def test_apply_fails_when_the_device_accepts_and_stores_nothing(app):
    with app.app_context():
        dev = FakeDevice(swallow_member=True)
        out = transports.BlockIpTransport().apply(
            dev, {"src_ip": "185.10.20.30", "policy": "pol-root-shop"})
        assert out.ok is False, \
            "a 200 whose effect is absent on re-read is not a successful apply"
        assert "re-read" in out.detail


def test_apply_then_rollback_round_trips(app):
    with app.app_context():
        dev, t = FakeDevice(), transports.BlockIpTransport()
        out = t.apply(dev, {"src_ip": "1.2.3.4", "policy": "pol-root-shop"})
        assert out.ok and out.handle["member_id"]
        assert t.verify_applied(dev, out.handle)[0] is True
        back = t.rollback(dev, out.handle)
        assert back.ok and t.verify_applied(dev, out.handle)[0] is False


def test_rollback_that_did_not_remove_the_row_is_a_failure(app):
    with app.app_context():
        dev, t = FakeDevice(undeletable=True), transports.BlockIpTransport()
        out = t.apply(dev, {"src_ip": "1.2.3.4", "policy": "pol-root-shop"})
        back = t.rollback(dev, out.handle)
        assert back.ok is False and "STILL listed" in back.detail


# --------------------------------------------------------------------------- #
#  4. Execution re-checks the world                                             #
# --------------------------------------------------------------------------- #
def test_drain_applies_a_fully_gated_action(app, monkeypatch):
    with app.app_context():
        dev = FakeDevice()
        arm(monkeypatch, dev)
        enable_policy()
        inc = mk_incident()
        a = queue(inc)
        out = responder.drain()
        assert out == [(a.id, SentinelAction.STATUS_APPLIED)], out
        assert [m["ip"] for m in dev.members] == ["185.10.20.30"]


def test_gates_are_re_evaluated_at_execution_time(app, monkeypatch):
    with app.app_context():
        dev = FakeDevice()
        arm(monkeypatch, dev)
        enable_policy()
        inc = mk_incident()
        a = queue(inc)
        # somebody throws the kill switch between approval and execution
        config.set_value("response_enabled", True)
        inc.src_trusted = True                       # ...or adds the source to trust
        db.session.commit()
        responder.drain()
        assert a.status == SentinelAction.STATUS_REJECTED
        assert dev.members == [], "a source trusted since approval was blocked anyway"


def test_drain_is_inert_while_the_kill_switch_is_off(app, monkeypatch):
    with app.app_context():
        dev = FakeDevice()
        monkeypatch.setattr(responder, "_client", lambda d: (dev, ""))
        config.set_value("response_enabled", False)
        enable_policy()
        a = queue(mk_incident())
        assert responder.drain() == []
        assert a.status == SentinelAction.STATUS_QUEUED
        assert dev.calls == [], "the disarmed engine still talked to a device"


def test_unverified_action_cannot_execute(app, monkeypatch):
    with app.app_context():
        dev = FakeDevice()
        arm(monkeypatch, dev)
        enable_policy("block_country", level=SentinelPolicy.LEVEL_AUTONOMOUS)
        a = queue(mk_incident(), action_type="block_country")
        responder.drain()
        assert a.status in (SentinelAction.STATUS_REJECTED,
                            SentinelAction.STATUS_FAILED)
        assert dev.members == []


def test_apply_refused_when_the_appliance_cannot_enforce(app, monkeypatch):
    with app.app_context():
        dev = FakeDevice(bound=False)
        arm(monkeypatch, dev)
        enable_policy()
        a = queue(mk_incident())
        responder.drain()
        assert a.status == SentinelAction.STATUS_FAILED
        assert "preflight" in a.detail and dev.members == []


# --------------------------------------------------------------------------- #
#  5. Expiry — the primary rollback                                             #
# --------------------------------------------------------------------------- #
def test_expiry_runs_with_the_kill_switch_off(app, monkeypatch):
    with app.app_context():
        dev = FakeDevice()
        arm(monkeypatch, dev)
        enable_policy()
        a = queue(mk_incident())
        responder.drain()
        assert dev.members, "precondition: the block is live"
        # operator disarms the engine mid-incident, then the TTL comes due
        config.set_value("response_enabled", False)
        a.expires_at = datetime.utcnow() - timedelta(minutes=1)
        db.session.commit()
        responder.expire_due()
        assert a.status == SentinelAction.STATUS_EXPIRED
        assert dev.members == [], \
            "disarming stranded a live block — the safety control caused the outage"


def test_expiry_that_cannot_run_is_recorded_not_swallowed(app, monkeypatch):
    with app.app_context():
        arm(monkeypatch, FakeDevice())
        enable_policy()
        a = queue(mk_incident())
        responder.drain()
        monkeypatch.setattr(responder, "_client",
                            lambda d: (None, "appliance unreachable"))
        a.expires_at = datetime.utcnow() - timedelta(minutes=1)
        db.session.commit()
        responder.expire_due()
        assert a.status == SentinelAction.STATUS_APPLIED, \
            "a block that could not be lifted must not be marked expired"
        assert any(r.verdict == "expiry_blocked" for r in a.results)


def test_tick_expires_before_it_applies(app, monkeypatch):
    """Freeing must precede acting, and the circuit breaker is how you see it.

    The first version of this test asserted the ORDER OF THE KEYS in tick()'s
    return dict — which does not change when the calls are reordered, so it
    passed against a mutant that applied first. It asserted its own shape, not
    the behaviour. This one puts the breaker one slot away from full: if expiry
    runs first the freed slot lets the new block through, and if it does not,
    the new block is refused by a ceiling that a lapsed action was still
    occupying.
    """
    with app.app_context():
        dev = FakeDevice()
        arm(monkeypatch, dev)
        enable_policy()
        config.set_value("max_actions_per_hour", 2)

        stale = queue(mk_incident(src_ip="203.0.113.9"))
        responder.drain()
        assert stale.status == SentinelAction.STATUS_APPLIED
        stale.expires_at = datetime.utcnow() - timedelta(minutes=1)
        db.session.commit()

        fresh = queue(mk_incident(src_ip="198.51.100.7"))
        responder.tick()

        assert stale.status == SentinelAction.STATUS_EXPIRED
        assert fresh.status == SentinelAction.STATUS_APPLIED, (
            "a lapsed action was still occupying the circuit breaker when the "
            "new one was judged")
        assert [m["ip"] for m in dev.members] == ["198.51.100.7"]


def test_apply_without_a_source_address_writes_nothing(app):
    """An empty source must not become a member row.

    Whatever a blank address would mean to the appliance, it is not the thing
    the incident was about — and a member nobody can account for is one an
    operator has to decide whether to delete.
    """
    with app.app_context():
        dev = FakeDevice()
        out = transports.BlockIpTransport().apply(
            dev, {"src_ip": "", "policy": "pol-root-shop"})
        assert out.ok is False
        assert dev.members == [], "a blank source was written to the device"


# --------------------------------------------------------------------------- #
#  6. Applied is not effective                                                  #
# --------------------------------------------------------------------------- #
def _applied_action(monkeypatch, dev, *, before_events: int):
    enable_policy()
    inc = mk_incident()
    for i in range(before_events):
        ev = SentinelEvent(ts=datetime.utcnow() - timedelta(minutes=1),
                           device="fortiweb12", src_ip=inc.src_ip,
                           attack_family="sqli", severity="high")
        ev.dedup_key = f"b{i}{datetime.utcnow().timestamp()}"
        db.session.add(ev)
    db.session.commit()
    a = queue(inc)
    responder.drain()
    a.applied_at = datetime.utcnow() - timedelta(minutes=30)
    db.session.commit()
    return inc, a


def test_effect_unknown_is_never_success(app, monkeypatch):
    with app.app_context():
        arm(monkeypatch, FakeDevice())
        inc, a = _applied_action(monkeypatch, None, before_events=0)
        responder.verify_effect()
        judged = [r for r in a.results if r.effective is not None or r.verdict
                  in ("unknown", "success", "ineffective", "partial")]
        verdicts = {r.verdict for r in a.results}
        assert "unknown" in verdicts and "success" not in verdicts
        assert all(r.effective is None for r in a.results
                   if r.verdict == "unknown"), \
            "no baseline means we do not know; that must not read as effective"


def test_effect_success_when_the_source_went_quiet(app, monkeypatch):
    with app.app_context():
        arm(monkeypatch, FakeDevice())
        inc, a = _applied_action(monkeypatch, None, before_events=5)
        a.params = dict(a.params or {}, baseline_events=5)
        db.session.commit()
        responder.verify_effect()
        assert any(r.verdict == "success" and r.effective is True
                   for r in a.results)


def test_ineffective_action_escalates_and_unmitigates_the_incident(app, monkeypatch):
    with app.app_context():
        arm(monkeypatch, FakeDevice())
        inc, a = _applied_action(monkeypatch, None, before_events=4)
        a.params = dict(a.params or {}, baseline_events=4)
        inc.status = SentinelIncident.STATUS_MITIGATED
        db.session.commit()
        # the attack kept coming after the action landed
        for i in range(4):
            ev = SentinelEvent(ts=a.applied_at + timedelta(seconds=30 + i),
                               device="fortiweb12", src_ip=inc.src_ip,
                               attack_family="sqli", severity="high")
            ev.dedup_key = f"a{i}{datetime.utcnow().timestamp()}"
            db.session.add(ev)
        db.session.commit()
        responder.verify_effect()
        assert any(r.verdict == "ineffective" and r.effective is False
                   for r in a.results)
        assert inc.status == SentinelIncident.STATUS_OPEN, \
            "an incident stayed 'mitigated' on an action that changed nothing"
        assert "INEFFECTIVE" in (inc.resolution_note or "")


def test_effect_is_judged_once(app, monkeypatch):
    with app.app_context():
        arm(monkeypatch, FakeDevice())
        inc, a = _applied_action(monkeypatch, None, before_events=3)
        a.params = dict(a.params or {}, baseline_events=3)
        db.session.commit()
        responder.verify_effect()
        n = len(a.results)
        responder.verify_effect()
        assert len(a.results) == n, "a verdict was re-recorded on a second pass"


# --------------------------------------------------------------------------- #
#  7. Structural guards                                                         #
# --------------------------------------------------------------------------- #
def test_the_incident_path_never_arms_a_policy(app):
    """Binding an enforcement point is a person's decision, not a response."""
    src = open("app/services/sentinel/responder.py").read()
    body = "\n".join(l for l in src.split("\n") if not l.strip().startswith("#"))
    body = body.split('"""')[0] + '"""'.join(body.split('"""')[2:])
    assert "arm_policy" not in body, \
        "the response runner calls arm_policy — an agent that binds its own " \
        "enforcement point can invent its own authority"


def test_actions_module_opens_no_connections(app):
    src = open("app/services/sentinel/actions.py").read()
    body = src.split('"""', 2)[-1]
    for forbidden in ("client_for(", "urlopen", "requests.", "socket."):
        assert forbidden not in body, \
            f"the decision layer reached the network via {forbidden}"


# --------------------------------------------------------------------------- #
#  8. Autonomy — what level 3 may and may not do                                #
# --------------------------------------------------------------------------- #
def test_autoqueue_needs_level_three(app):
    """At level 2 an action waits for a person, however confident the score."""
    with app.app_context():
        config.set_value("response_enabled", True)
        enable_policy(level=SentinelPolicy.LEVEL_SEMI_AUTO)
        inc = mk_incident(score=100)
        a = actions.propose(inc, "block_ip", autoqueue=True)
        db.session.commit()
        assert a.status == SentinelAction.STATUS_PROPOSED, \
            "a level-2 action queued itself for execution"


def test_autoqueue_at_level_three_skips_the_human(app):
    with app.app_context():
        config.set_value("response_enabled", True)
        enable_policy(level=SentinelPolicy.LEVEL_AUTONOMOUS)
        inc = mk_incident(score=100)
        a = actions.propose(inc, "block_ip", autoqueue=True)
        db.session.commit()
        assert a.status == SentinelAction.STATUS_QUEUED
        assert a.proposed_by.endswith("autonomous")


def test_autonomy_cannot_widen_an_action(app):
    """Level 3 skips approval. It does not raise a ceiling."""
    with app.app_context():
        config.set_value("response_enabled", True)
        actions.ensure_policies()
        p = SentinelPolicy.query.filter_by(action_type="block_country").first()
        p.enabled, p.level, p.min_confidence = True, SentinelPolicy.LEVEL_AUTONOMOUS, 0
        db.session.commit()
        inc = mk_incident(score=100)
        verdict = actions.evaluate(inc, "block_country")
        assert verdict["level"] <= SentinelPolicy.LEVEL_RECOMMEND, \
            "an operator set block_country to autonomous and the engine agreed"
        a = actions.propose(inc, "block_country", autoqueue=True)
        db.session.commit()
        assert a.status != SentinelAction.STATUS_QUEUED


def test_a_live_action_is_never_proposed_twice(app):
    """The sweep runs every three minutes; one decision must stay one row."""
    with app.app_context():
        config.set_value("response_enabled", True)
        enable_policy(level=SentinelPolicy.LEVEL_AUTONOMOUS)
        inc = mk_incident(score=100)
        first = actions.propose(inc, "block_ip", autoqueue=True)
        db.session.commit()
        for _ in range(5):                      # five more sweeps
            again = actions.propose(inc, "block_ip", autoqueue=True)
            db.session.commit()
            assert again.id == first.id
        n = SentinelAction.query.filter_by(incident_id=inc.id,
                                           action_type="block_ip").count()
        assert n == 1, f"{n} rows for one decision — the runner would act {n} times"


def test_a_closed_action_may_be_proposed_again(app):
    """Deduplication must not become a permanent lockout after an expiry."""
    with app.app_context():
        config.set_value("response_enabled", True)
        enable_policy(level=SentinelPolicy.LEVEL_AUTONOMOUS)
        inc = mk_incident(score=100)
        first = actions.propose(inc, "block_ip", autoqueue=True)
        db.session.commit()
        first.status = SentinelAction.STATUS_EXPIRED
        db.session.commit()
        second = actions.propose(inc, "block_ip", autoqueue=True)
        db.session.commit()
        assert second.id != first.id, \
            "the source came back after the TTL and Sentinel could not respond"
