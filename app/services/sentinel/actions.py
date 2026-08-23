"""The closed action catalog and the policy engine that gates it.

Status of this module in THIS release
-------------------------------------
It **decides**. It never executes: nothing in this file opens a connection to a
device, and there is a guard test asserting that. Execution lives in
``responder.py``, which runs as a separate systemd unit.

:data:`CATALOG` entries carry ``verified``, meaning: the mechanism named here
has been proved against a live appliance of this product, by running it. As of
2026-08-20 exactly ONE has — ``block_ip`` (see ``transports.PROVENANCE``). The
rest remain specifications and the last gate refuses them, which is the honest
state and is shown as such on the console.

``rate_limit_ip`` was REMOVED rather than left unverified. Probing fortiweb12
showed ``waf/http-access-limit`` — the route its mechanism named — answers
``-20001 invalid URL``; it does not exist on this firmware. What FortiWeb
actually offers is flood-prevention rules whose thresholds apply to EVERY
client of a profile, not to one address. Keeping the entry would have promised
a blast radius of one source while the only available mechanism has a blast
radius of every client. An action that cannot be built is not a roadmap item on
a live console — it is a lie with a button next to it.

That is not caution theatre. This product measured, on 2026-08-20, that **22 of
237 documented FortiWeb configuration routes answer ``-20001 "invalid URL"``**
and that none of them had ever been captured by a device sync — they were
written from the reference manual and never validated. A blocking action built
the same way would fail at the moment it is most needed, or worse, succeed
against the wrong object. So the catalog ships as a specification with its
provenance stated, and each entry becomes executable only when someone has run
it against fw12/fw13 and recorded the transport — the same discipline
``REBOOT_TRANSPORT`` already applies in ``scheduled_actions``.

The gate order, and why it is this order
----------------------------------------
:func:`evaluate` checks, in sequence:

1. **Global kill switch** — one setting disables every action everywhere.
2. **Protected network** — the source is inside our own ranges. Checked before
   anything about confidence: a correlation bug that concludes the monitoring
   host is an attacker must be structurally unable to act on it.
3. **Trusted source / maintenance window** — authorised activity.
4. **Per-action policy** exists, is enabled, and its level permits acting.
5. **Confidence** meets that action's own floor.
6. **Reversibility and TTL** — every blocking action must expire on its own.
7. **Circuit breaker** — fleet-wide hourly ceiling.
8. **Catalog verification** — the mechanism has been proved on a real device.

Each check returns a REASON, not just a boolean, and the reasons are shown on
the incident. "Sentinel did nothing" is not an acceptable console state; "did
nothing because the source is inside 10.0.0.0/8" is.

TTL is the rollback
-------------------
Every blocking action expires. An undo that must itself succeed is not a
rollback — it is a second operation that can fail, attempted at the moment the
first already has. Expiry needs nothing to work.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from ...models import db
from ...models_sentinel import SentinelAction, SentinelPolicy
from . import config, enrich, transports


@dataclass(frozen=True)
class ActionSpec:
    """One executable response — its mechanism, its limits, its provenance."""

    key: str
    label: str
    summary: str
    mechanism: str          # HOW it would be applied, and on what evidence
    reversible: bool
    requires_ttl: bool
    max_level: int          # the highest autonomy this action may EVER reach
    blast: str              # what it can affect if the correlation is wrong
    verified: bool = False  # proved against a live appliance?
    provenance: str = ""
    #: True when the action writes NOTHING to an appliance and instead hands
    #: the incident to an existing human-driven flow. Kept distinct from
    #: ``verified`` because the two answer different questions: "does the
    #: mechanism work?" and "does this engine execute it?". Collapsing them
    #: would either park a working hand-off behind an appliance test it will
    #: never take, or let the runner try to execute something that has no
    #: device write to perform.
    handoff: bool = False


CATALOG: dict[str, ActionSpec] = {
    "block_ip": ActionSpec(
        "block_ip", "Block source IP",
        "Add the source to the Sentinel IP list bound to the affected policy.",
        mechanism="POST cmdb/waf/ip-list/members?mkey=satom-sentinel-block with "
                  "{type: black-ip, ip: <src>}; undone by DELETE with "
                  "&sub_mkey=<member id>. The list carries action=block-period, "
                  "so THE APPLIANCE expires the block on its own — that expiry "
                  "survives Sentinel being dead. PRECONDITION, re-read from the "
                  "device before every apply: the policy's web protection "
                  "profile must already reference the list. Sentinel never "
                  "binds its own enforcement point during an incident.",
        reversible=True, requires_ttl=True,
        max_level=SentinelPolicy.LEVEL_AUTONOMOUS,
        blast="one source address on one policy",
        verified=True, provenance=transports.PROVENANCE),
    "raise_protection": ActionSpec(
        "raise_protection", "Raise protection profile",
        "Move the policy to a hardened Web Protection Profile.",
        mechanism="PUT cmdb/server-policy/policy?mkey=<policy> "
                  "{web-protection-profile: <approved profile>}. The PREVIOUS "
                  "value is read off the device first and carried in the "
                  "handle: this action has no device-side timer to fall back "
                  "on, so the undo is a write, and a write needs the old value "
                  "rather than a default. Rollback REFUSES an empty binding — "
                  "unbinding the profile would strip protection from every "
                  "client of the policy. The target must already exist on the "
                  "appliance and be listed in Settings -> Sentinel -> hardened "
                  "profiles; creating one mid-incident is how a policy ends up "
                  "bound to an empty profile (the ca-group defect this product "
                  "already shipped once).",
        reversible=True, requires_ttl=False,
        max_level=SentinelPolicy.LEVEL_SEMI_AUTO,
        blast="EVERY client of the affected policy",
        verified=True, provenance=transports.PROVENANCE_WPP),
    "block_country": ActionSpec(
        "block_country", "Block source country",
        "GeoIP block for the source's country on the affected policy.",
        mechanism="POST cmdb/waf/geo-block-list/country-list?mkey="
                  "satom-sentinel-geo {country-name: <name>}; undone by DELETE "
                  "with &sub_mkey=<id>. The child collection is country-list, "
                  "NOT members, and the appliance takes a FULL COUNTRY NAME - "
                  "'AD' answers errcode -7950. The list carries "
                  "action=block-period, so the appliance expires it too. Same "
                  "precondition as block_ip and re-read the same way: the "
                  "policy's profile must already reference the geo list "
                  "(geo-block-list-policy). Verified against a live appliance "
                  "and STILL capped at recommend - a verified mechanism is not "
                  "an argument for autonomy when the blast radius is a country.",
        reversible=True, requires_ttl=True,
        max_level=SentinelPolicy.LEVEL_RECOMMEND,
        verified=True, provenance=transports.PROVENANCE_GEO,
        blast="EVERY client in an entire country — never autonomous, at any "
              "confidence. A single mis-attributed source address would take "
              "a market offline."),
    "block_edge_ip": ActionSpec(
        "block_edge_ip", "List source on the border blocklist",
        "Add the source to the blocklist SATOM publishes for the border "
        "firewall to read.",
        mechanism="Writes a sentinel_block_entry row with a mandatory expiry. "
                  "NOTHING is sent to a FortiGate: this product has no "
                  "FortiGate client and no credential that could write one. "
                  "The border reads /sentinel/feed/<token>/blocklist.txt, "
                  "which is rendered from the database on every request and "
                  "filtered by expires_at, and applies it through a deny "
                  "policy THE OPERATOR pre-created — same rule as block_ip, "
                  "which appends to an IP list somebody else bound to the "
                  "profile. PRECONDITION, checked on every apply and not "
                  "cached: edge.blockable() must accept the address. FortiWeb "
                  "reports the CDN's address when a policy does not read "
                  "X-Forwarded-For and the true client's when it does, and "
                  "nothing in the attack log distinguishes them — listing the "
                  "first kind removes every client behind a shared egress.",
        reversible=True, requires_ttl=True,
        max_level=SentinelPolicy.LEVEL_RECOMMEND,
        blast="EVERY FortiGate and VDOM whose connector reads this feed, and "
              "so every service behind them — not one policy on one "
              "appliance. If the address turns out to be a shared egress, "
              "every legitimate client behind it loses access to everything "
              "the border fronts, not just the attacked application.",
        handoff=True, verified=False,
        provenance="No appliance write from here, so there is no transport and "
                   "the runner refuses this action BY NAME rather than "
                   "attempting it — the listing is made by a person, from the "
                   "Blocklist page or the button on the incident, and that "
                   "route runs the same edge.blockable() veto and the same "
                   "mandatory TTL. HALF proved: the local half (row, expiry, "
                   "veto, render, release, mirror) is exercised by "
                   "tests/test_sentinel_blocklist.py against this code; the "
                   "consuming half is NOT — no FortiGate in this fleet has "
                   "been pointed at the feed, so 'the border enforced it' is a "
                   "specification here, not an observation. Capped at "
                   "recommend for the blast radius regardless of that ever "
                   "changing."),
    "tune_signature": ActionSpec(
        "tune_signature", "Propose a signature carve-out",
        "Hand the incident to the existing false-positive carve-out flow.",
        mechanism="Hands off to app.services.attack_carveout, which builds the "
                  "exception from the entry AS THE DEVICE REPORTED IT. Writes "
                  "NOTHING to an appliance from here: the draft lands in the "
                  "existing exception flow and a person applies it there. "
                  "Never auto-applied - an exception authored from correlated "
                  "data is an exception authored from something a client "
                  "influenced, and the whole point of an exception is that it "
                  "stops the WAF from acting.",
        reversible=True, requires_ttl=False,
        max_level=SentinelPolicy.LEVEL_RECOMMEND,
        blast="one signature on one profile",
        handoff=True, verified=True,
        provenance="no appliance write: the draft is built by "
                   "app.services.attack_carveout (already shipped, already "
                   "used by the FP triage flow) and applied by a person"),
}

#: The gate chain, in the order :func:`evaluate` applies it. ``(key, label,
#: why)``. Order is not cosmetic — each entry is placed where it is for a
#: reason recorded in the third field, and moving one changes what the engine
#: refuses. Rendered by the documentation page; asserted by the test suite.
GATE_ORDER: tuple = (
    ("catalog", "Known action",
     "An action type outside the catalog has no blast radius, no ceiling and "
     "no undo. There is nothing to reason about."),
    ("kill_switch", "Response armed",
     "One switch an operator can reach without reading anything else. Checked "
     "early so that disarming is felt immediately."),
    ("protected_network", "Not our own network",
     "Before trust, deliberately. Our own address space must stay unblockable "
     "even if somebody empties the trust list."),
    ("trusted_source", "Source not trusted",
     "An authorised scanner produces a log byte-for-byte identical to an "
     "intruder's. Only context separates them."),
    ("maintenance_window", "Not inside a window",
     "Work we scheduled must not be answered by a firewall rule."),
    ("policy_exists", "A policy covers this action",
     "No row means nobody has decided anything about this action here."),
    ("policy_enabled", "That policy is enabled",
     "Disabling a policy has to stop the thing, not merely hide it."),
    ("executable_mechanism", "Not a hand-off",
     "Some actions are drafted here and applied by a person elsewhere. Those "
     "are refused here so the refusal names where the work happens."),
    ("level", "Autonomy reaches semi-automatic",
     "Below it the action is a proposal for a person, which is a valid "
     "outcome and not a failure."),
    ("confidence", "Score meets this action's floor",
     "The floor belongs to the action, not to the engine: a country block "
     "does not get to borrow an address block's threshold."),
    ("ttl", "It expires on its own",
     "The primary rollback is expiry. An undo that has to succeed later is "
     "not a rollback."),
    ("circuit_breaker", "Hourly budget remains",
     "A correlation bug during a flood must exhaust a budget rather than a "
     "firewall."),
    ("mechanism_verified", "Mechanism captured from a live appliance",
     "22 of 237 documented routes on this product answer 'invalid URL'. A "
     "mechanism read from a manual is a specification, not a transport."),
)

#: Recommendation the policy engine derives from the score band, per family.
#: Data, not branches, so the documentation page can render it and the tests
#: can assert on it without re-implementing the mapping.
BAND_RECOMMENDATION: dict[str, str] = {
    "observe": "observe",
    "investigate": "investigate",
    "recommend": "investigate",
    "semi_auto": "block_ip",
}


def ensure_policies() -> int:
    """Create a default (disabled, observe-only) policy row per catalog entry.

    Idempotent. Defaults are the SAFE end of every knob: an installation that
    has never been configured cannot act, and adding an action to the catalog
    cannot silently arm it in an existing installation.
    """
    created = 0
    for key, spec in CATALOG.items():
        if SentinelPolicy.query.filter_by(action_type=key).first():
            continue
        db.session.add(SentinelPolicy(
            action_type=key, level=SentinelPolicy.LEVEL_OBSERVE,
            min_confidence=85, ttl_minutes=30, max_ttl_minutes=240,
            max_per_hour=3, enabled=False,
            note=f"auto-created; mechanism {'verified' if spec.verified else 'NOT verified'}"))
        created += 1
    if created:
        db.session.commit()
    return created


def prune_policies() -> list:
    """Drop policy rows whose action left the catalog.

    Removing ``rate_limit_ip`` from the catalog does not remove the row an
    earlier release created, and that row stays visible, editable, and armable
    on the policies page — a switch wired to nothing. Rows that still have
    actions attached are KEPT, because deleting them would take the audit trail
    of what Sentinel once proposed with them.
    """
    from ...models_sentinel import SentinelAction as _A
    removed = []
    for row in SentinelPolicy.query.all():
        if row.action_type in CATALOG:
            continue
        if _A.query.filter_by(action_type=row.action_type).count():
            continue
        removed.append(row.action_type)
        db.session.delete(row)
    if removed:
        db.session.commit()
    return removed


def recent_action_count(minutes: int = 60) -> int:
    since = datetime.utcnow() - timedelta(minutes=minutes)
    return (SentinelAction.query
            .filter(SentinelAction.created_at >= since,
                    SentinelAction.status.in_([SentinelAction.STATUS_APPLIED,
                                               SentinelAction.STATUS_QUEUED]))
            .count())


def recommend(incident) -> str:
    """What the DETERMINISTIC engine proposes for this incident.

    Independent of any model opinion, and computed from the band plus the two
    context facts that override it: a trusted source is never answered with a
    block, and an incident whose requests were all stopped by the appliance
    needs no further action — the appliance already took it.
    """
    if incident.src_trusted:
        return "investigate"
    if incident.waf_blocked and not incident.passed_count:
        return "observe"
    return BAND_RECOMMENDATION.get(incident.band, "observe")


def evaluate(incident, action_type: str) -> dict:
    """May this action be taken for this incident, and at what level?

    Returns ``{allowed, level, reason, checks}``. ``checks`` is the ordered
    audit of every gate with its verdict — so the console can show WHY an
    action was refused instead of leaving an operator to guess.
    """
    checks: list = []

    def check(name: str, ok: bool, detail: str) -> bool:
        checks.append({"check": name, "ok": bool(ok), "detail": detail})
        return bool(ok)

    spec = CATALOG.get(action_type)
    if not check("catalog", spec is not None,
                 f"'{action_type}' is not in the action catalog"
                 if spec is None else f"{spec.label}"):
        return _deny(checks, "unknown action")

    if not check("kill_switch", bool(config.get("response_enabled")),
                 "sentinel.response_enabled is OFF — Sentinel may propose "
                 "actions and may not execute any"
                 if not config.get("response_enabled") else "response engine armed"):
        return _deny(checks, "response engine disarmed", level=SentinelPolicy.LEVEL_RECOMMEND)

    src = incident.src_ip or ""
    protected = enrich.is_protected(src)
    if not check("protected_network", not protected,
                 f"source {src} is inside a protected network — no blocking "
                 f"action may target it" if protected
                 else f"source {src} is outside every protected network"):
        return _deny(checks, "source is protected")

    if not check("trusted_source", not incident.src_trusted,
                 "source is a registered trusted source" if incident.src_trusted
                 else "source is not on the trust list"):
        return _deny(checks, "trusted source")

    suppressed = enrich.actions_suppressed(device=incident.device or "")
    if not check("maintenance_window", not suppressed,
                 "a maintenance window is suppressing actions" if suppressed
                 else "no active maintenance window"):
        return _deny(checks, "maintenance window")

    policy = SentinelPolicy.query.filter_by(action_type=action_type).first()
    if not check("policy_exists", policy is not None,
                 "no policy row for this action" if policy is None
                 else f"policy level {policy.level}"):
        return _deny(checks, "no policy")
    if not check("policy_enabled", bool(policy.enabled),
                 "policy is disabled" if not policy.enabled else "policy enabled"):
        return _deny(checks, "policy disabled")

    # A hand-off has no device write to perform, so "execute" is not a thing
    # this engine can do with it. Denying here — with the reason naming where
    # the work actually happens — beats letting the runner reach a transport
    # lookup and report "no verified transport", which reads like a defect.
    if not check("executable_mechanism", not spec.handoff,
                 "this action is a hand-off, not a device write: Sentinel "
                 "drafts it and a person applies it from the exception flow"
                 if spec.handoff else "the mechanism is a device write"):
        return _deny(checks, "hand-off, not executable", level=0)

    level = min(int(policy.level or 0), spec.max_level)
    if not check("level", level >= SentinelPolicy.LEVEL_SEMI_AUTO,
                 f"effective level {level} — proposal only"
                 if level < SentinelPolicy.LEVEL_SEMI_AUTO
                 else f"effective level {level}"):
        return _deny(checks, "level too low", level=level)

    score = int(incident.score or 0)
    if not check("confidence", score >= int(policy.min_confidence or 0),
                 f"score {score} is below this action's floor of "
                 f"{policy.min_confidence}" if score < (policy.min_confidence or 0)
                 else f"score {score} meets the floor of {policy.min_confidence}"):
        return _deny(checks, "below confidence floor", level=level)

    ttl_ok = (not spec.requires_ttl) or (0 < int(policy.ttl_minutes or 0)
                                         <= int(policy.max_ttl_minutes or 0))
    if not check("ttl", ttl_ok,
                 "this action must expire on its own and has no valid TTL"
                 if not ttl_ok else f"expires after {policy.ttl_minutes} min"):
        return _deny(checks, "no valid TTL", level=level)

    used = recent_action_count(60)
    ceiling = int(config.get("max_actions_per_hour"))
    if not check("circuit_breaker", used < ceiling,
                 f"{used}/{ceiling} actions already taken this hour"):
        return _deny(checks, "circuit breaker open", level=level)

    if not check("mechanism_verified", spec.verified,
                 "the mechanism for this action has NOT been verified against "
                 "a live appliance of this product — it is a specification, "
                 "not yet an executable transport" if not spec.verified
                 else spec.provenance):
        return _deny(checks, "mechanism unverified", level=level)

    return {"allowed": True, "level": level, "reason": "all gates passed",
            "checks": checks, "ttl_minutes": int(policy.ttl_minutes or 0)}


def _deny(checks: list, reason: str, level: int = 0) -> dict:
    return {"allowed": False, "level": level, "reason": reason,
            "checks": checks, "ttl_minutes": 0}


#: Statuses in which an action is still "live" — proposed, awaiting a human,
#: queued for the runner, or in force. A second row for the same incident and
#: action while one of these exists is a duplicate, not a new decision.
LIVE_STATUSES = (SentinelAction.STATUS_PROPOSED, SentinelAction.STATUS_APPROVED,
                 SentinelAction.STATUS_QUEUED, SentinelAction.STATUS_APPLIED)


def existing_live(incident, action_type: str):
    """The live action for this (incident, action), if any."""
    return (SentinelAction.query
            .filter(SentinelAction.incident_id == incident.id,
                    SentinelAction.action_type == action_type,
                    SentinelAction.status.in_(LIVE_STATUSES))
            .order_by(SentinelAction.id.desc()).first())


def propose(incident, action_type: str, *, params: dict | None = None,
            by: str = "policy_engine", rationale: str = "",
            autoqueue: bool = False) -> "SentinelAction":
    """Record a PROPOSED action, or return the live one that already exists.

    The proposal is written whether or not the gates would allow execution,
    because "Sentinel wanted to do X and was refused because Y" is exactly the
    record an operator needs when tuning autonomy — and it is invisible if only
    permitted actions are stored.

    It is written ONCE. The sweep runs every three minutes and re-proposes for
    every open incident; without the live-row check, a single incident that
    stays open for an hour accumulates twenty identical proposals. That was
    harmless while nothing executed. With a runner draining the queue it is
    twenty writes to a firewall for one decision, so the deduplication is not
    tidying — it is the difference between one block and a loop.

    ``autoqueue`` is level 3. It moves the row straight to ``queued`` with no
    human in between, and ONLY when :func:`evaluate` returns an effective level
    of ``LEVEL_AUTONOMOUS``. Note what it does not do: it does not raise the
    level, widen the action, or extend a TTL. Autonomy here means "skip the
    approval step for a decision that was already permitted", never "permit
    more".
    """
    live = existing_live(incident, action_type)
    if live is not None:
        return live
    verdict = evaluate(incident, action_type)
    spec = CATALOG.get(action_type)
    ttl = verdict.get("ttl_minutes") or 0
    action = SentinelAction(
        incident_id=incident.id,
        correlation_id=f"{incident.ref}:{action_type}",
        action_type=action_type, level=verdict.get("level", 0),
        status=SentinelAction.STATUS_PROPOSED, proposed_by=by,
        expires_at=(datetime.utcnow() + timedelta(minutes=ttl)) if ttl else None,
        detail=verdict["reason"],
        rationale=rationale or (spec.summary if spec else ""))
    action.params = dict(params or {}, src_ip=incident.src_ip,
                         device=incident.device, policy=incident.policy)
    if (autoqueue and verdict.get("allowed")
            and int(verdict.get("level") or 0) >= SentinelPolicy.LEVEL_AUTONOMOUS):
        action.status = SentinelAction.STATUS_QUEUED
        action.proposed_by = "policy_engine:autonomous"
        action.detail = (f"queued autonomously: {verdict.get('reason')} "
                         f"(level {verdict.get('level')})")
    db.session.add(action)
    return action


def catalog_rows() -> list:
    """The catalog, for the documentation page and the Settings console."""
    return [{"key": s.key, "label": s.label, "summary": s.summary,
             "mechanism": s.mechanism, "reversible": s.reversible,
             "requires_ttl": s.requires_ttl, "max_level": s.max_level,
             "blast": s.blast, "verified": s.verified,
             "handoff": s.handoff,
             "provenance": s.provenance}
            for s in CATALOG.values()]


def policy_rows() -> list:
    ensure_policies()
    prune_policies()
    rows = SentinelPolicy.query.order_by(SentinelPolicy.action_type).all()
    out = []
    for p in rows:
        spec = CATALOG.get(p.action_type)
        d = p.to_dict()
        d["label"] = spec.label if spec else p.action_type
        d["max_level"] = spec.max_level if spec else 0
        d["verified"] = spec.verified if spec else False
        d["blast"] = spec.blast if spec else ""
        out.append(d)
    return out


def verified_count() -> tuple:
    """(verified, total) — the honest headline for the console.

    An installation whose catalog is 0/5 verified must be told so on the page,
    not in a docstring. A response engine that cannot execute anything is a
    fine state; a response engine that LOOKS armed and cannot execute is not.
    """
    total = len(CATALOG)
    return sum(1 for s in CATALOG.values() if s.verified), total


def handoff_keys() -> list:
    """Actions that are drafted here and applied by a person elsewhere.

    The console needs this to avoid telling an operator that a verified
    mechanism is available for execution when it is, on purpose, not.
    """
    return sorted(k for k, s in CATALOG.items() if s.handoff)
