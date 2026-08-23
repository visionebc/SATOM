"""SATOM Sentinel — the security correlation & response data model.

Sentinel answers one question the rest of SATOM cannot: *"what is actually
happening right now, across every layer at once?"* — attack signatures, HTTP
behaviour, appliance internals, the VM the appliance runs on, the hypervisor
under it, and the backend behind it. The intelligence is not in any single
layer; it is in their agreement (or disagreement) inside a time window.

Naming, deliberately
--------------------
Every table here carries the ``sentinel_`` prefix. ``baselines`` was ALREADY
TAKEN in this product by a completely different concept — a "combo" binding
approved templates to a zone/line/department permutation
(:mod:`app.services.baselines`). A behavioural baseline and a configuration
combo share nothing but a word, and a shared table name would have silently
put a statistics row where a provisioning scope was expected. The prefix is
the guard.

Three kinds of data, never mixed in one column
----------------------------------------------
The product principle from the design review, enforced structurally:

* **Raw** — what a device or hypervisor actually reported: :class:`SentinelEvent`,
  and the samples in VictoriaMetrics (never in this DB; ~875 B/sample in
  Postgres was measured to cost ~450 GB at fleet scale).
* **Derived** — what deterministic code computed from raw: :class:`SentinelBaseline`,
  :class:`SentinelAnomaly`, :class:`SentinelEvidence`, and every ``score_*``
  column on :class:`SentinelIncident`.
* **AI opinion** — what a model said: confined to ``SentinelIncident.ai_json``,
  always stamped with the model name and a prompt hash. A model's opinion is
  never written into a field an operator reads as measurement.

What is intentionally NOT here
------------------------------
Traffic time-series. Rates, CPU, memory, throughput and HTTP status counts all
live in the node's VictoriaMetrics store; Sentinel queries them by label at
correlation time. Storing a second copy per incident would re-open a decision
this product already paid for with a measurement.
"""
from __future__ import annotations

import json
from datetime import datetime

from .models import db


def _json_prop(attr: str, default):
    """A ``Text``-backed JSON property. The project stores JSON in Text columns
    (see ``ScrapeTarget.params_json``) so the schema is identical on Postgres
    and on the SQLite the tests run against."""

    def getter(self):
        try:
            return json.loads(getattr(self, attr) or "null") or default
        except Exception:  # noqa: BLE001
            return default

    def setter(self, value):
        setattr(self, attr, json.dumps(value if value is not None else default))

    return property(getter, setter)


# --------------------------------------------------------------------------- #
#  Topology — the join that makes cross-layer correlation possible              #
# --------------------------------------------------------------------------- #
class SentinelTopology(db.Model):
    """Appliance ↔ VM ↔ hypervisor node ↔ backend services.

    Correlation is a join, and this is the join key. Without a row here an
    appliance's incidents can still carry attack + traffic + box evidence, but
    the VM and host layers are structurally unavailable — which the incident
    reports as ``unknown``, never as ``no impact``. Those two are opposite
    facts and collapsing them is how a saturated hypervisor reads as healthy.
    """

    __tablename__ = "sentinel_topology"

    id = db.Column(db.Integer, primary_key=True)
    appliance_id = db.Column(db.Integer,
                             db.ForeignKey("appliances.id", ondelete="CASCADE"),
                             nullable=False, unique=True, index=True)
    hypervisor_target_id = db.Column(db.Integer)   # hypervisor_targets.id
    vm_id = db.Column(db.String(40), default="")   # vmid / moref
    node = db.Column(db.String(120), default="")   # pve node / esxi host
    backends_json = db.Column(db.Text, default="[]")
    note = db.Column(db.String(300), default="")
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow)

    appliance = db.relationship("Appliance")
    backends = _json_prop("backends_json", [])

    @property
    def complete(self) -> bool:
        """Whether the VM/host layers can be collected for this appliance."""
        return bool(self.hypervisor_target_id and self.vm_id and self.node)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "appliance_id": self.appliance_id,
            "device": self.appliance.name if self.appliance else "",
            "hypervisor_target_id": self.hypervisor_target_id or 0,
            "vm_id": self.vm_id or "", "node": self.node or "",
            "backends": self.backends, "complete": self.complete,
            "note": self.note or "",
        }


# --------------------------------------------------------------------------- #
#  Edge map — the join that lets the border speak about a source                #
# --------------------------------------------------------------------------- #
class SentinelEdgeMap(db.Model):
    """Protected appliance -> the FortiAnalyzer / FortiGate / VDOM in front.

    Same contract as :class:`SentinelTopology`, for the same reason. Without a
    row here the border layer is not evaluated, and the incident says exactly
    that — never that the border saw nothing. Those are opposite facts: one
    means "we did not look", the other means "this address is not a real peer
    at the border", and the second one is what vetoes a border blocklist
    entry. Collapsing them would let an unmapped appliance silently authorise
    every block it proposes.

    Every field is operator-entered on purpose. Nothing here is inferred from
    a hostname or guessed from an ADOM listing: a wrong guess does not fail
    loudly, it points the lookup at a device whose logs belong to somebody
    else's traffic, and the answer still looks like an answer.

    ``fortigate`` empty means EVERY device in the ADOM, and ``vdom`` empty
    means every VDOM on that device. Both are legitimate configurations (a
    single-VDOM firewall, a collector with one customer), which is why neither
    is required for :attr:`complete` — but both are shown in the scope line so
    an operator can see how wide the question actually was.
    """

    __tablename__ = "sentinel_edge_map"

    #: Log types worth searching for a source address. ``traffic`` is the
    #: default because it is the one every FortiGate writes for every session:
    #: an address that opened a connection is in the traffic log whether or
    #: not any security profile had an opinion about it, and existence at the
    #: border is the whole question this table exists to answer.
    LOGTYPES = ("traffic", "attack", "event", "webfilter", "ips")

    id = db.Column(db.Integer, primary_key=True)
    appliance_id = db.Column(db.Integer,
                             db.ForeignKey("appliances.id", ondelete="CASCADE"),
                             nullable=False, unique=True, index=True)
    #: The FortiAnalyzer to ask. Also an appliances row — Sentinel never holds
    #: a second copy of a device's credentials, and a second copy is how one
    #: of them ends up stale after a rotation.
    analyzer_id = db.Column(db.Integer)
    adom = db.Column(db.String(120), default="root")
    fortigate = db.Column(db.String(120), default="")   # "" = all devices
    vdom = db.Column(db.String(120), default="")        # "" = all vdoms
    logtype = db.Column(db.String(24), default="traffic")
    note = db.Column(db.String(300), default="")
    #: Last successful probe, so the Context page can distinguish "configured"
    #: from "configured and proven". They look identical in a form.
    last_ok_at = db.Column(db.DateTime)
    last_error = db.Column(db.String(300), default="")
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow)

    appliance = db.relationship("Appliance", foreign_keys=[appliance_id])

    @property
    def complete(self) -> bool:
        """Whether the border layer can be collected for this appliance."""
        return bool(self.analyzer_id and (self.adom or "").strip())

    @property
    def scope(self) -> str:
        return " / ".join([
            (self.adom or "root"),
            (self.fortigate or "all devices"),
            (self.vdom or "all vdoms"),
        ])

    def to_dict(self) -> dict:
        return {
            "id": self.id, "appliance_id": self.appliance_id,
            "device": self.appliance.name if self.appliance else "",
            "analyzer_id": self.analyzer_id or 0,
            "adom": self.adom or "", "fortigate": self.fortigate or "",
            "vdom": self.vdom or "", "logtype": self.logtype or "traffic",
            "complete": self.complete, "scope": self.scope,
            "note": self.note or "",
            "last_ok_at": self.last_ok_at.isoformat(timespec="seconds")
                          if self.last_ok_at else "",
            "last_error": self.last_error or "",
        }


class SentinelBlockEntry(db.Model):
    """One address on the published border blocklist, with its expiry.

    This table IS the feed. The endpoint renders from it on every request and
    filters by :attr:`expires_at`, so there is no cached artefact in the
    serving path that could go stale — a stopped publisher costs accurate
    bookkeeping (rows still reading ``active``), never an address served past
    its TTL. The file on disk and the git mirror are audit copies of that
    render, deliberately downstream of it.

    ``expires_at`` is NOT NULL and there is no code path that creates a row
    without one. On FortiWeb the equivalent action leans on
    ``action=block-period`` — the appliance expires the block itself and that
    expiry survives Sentinel being dead. A feed has no device-side timer, so
    the expiry has to be a property of the data rather than of a job.

    ``incident_id`` is ``SET NULL`` on delete, NOT cascade, and the difference
    matters: cascading would make deleting an old incident silently unblock an
    address that is still inside its TTL. The block outlives the record of why
    it was made; losing the reason is a documentation problem, losing the
    block is a security one.

    A released entry is kept, not deleted. "Why was this customer blocked last
    Tuesday" is the question that actually gets asked, and a list whose false
    positives vanish without trace cannot be reviewed for the pattern that
    produced them.
    """

    __tablename__ = "sentinel_block_entry"

    ACTIVE = "active"
    RELEASED = "released"
    EXPIRED = "expired"

    id = db.Column(db.Integer, primary_key=True)
    #: The literal address. Single hosts only — a prefix in a border blocklist
    #: is a different decision with a different blast radius, and nothing in
    #: this pipeline produces evidence about a network.
    ip = db.Column(db.String(60), nullable=False, index=True)
    status = db.Column(db.String(16), default=ACTIVE, index=True)
    incident_id = db.Column(db.Integer,
                            db.ForeignKey("sentinel_incident.id",
                                          ondelete="SET NULL"), index=True)
    appliance_id = db.Column(db.Integer)
    source = db.Column(db.String(24), default="manual")  # incident|manual
    reason = db.Column(db.Text, default="")
    detail = db.Column(db.Text, default="")
    created_by = db.Column(db.String(80), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    released_at = db.Column(db.DateTime)
    released_by = db.Column(db.String(80), default="")
    release_reason = db.Column(db.String(400), default="")

    #: The border verdict AS IT STOOD when the entry was created, not a live
    #: re-read. An entry defended by a lookup nobody kept is an entry whose
    #: justification cannot be reviewed — and re-querying at review time
    #: answers a different question (is it corroborated NOW) than the one that
    #: authorised the listing.
    edge_verdict = db.Column(db.String(24), default="")
    edge_scope = db.Column(db.String(300), default="")
    edge_hits = db.Column(db.Integer, default=0)

    #: Set only when a person listed an address the border veto refused. Kept
    #: as two columns rather than a flag: an override with no written reason
    #: is an override nobody can review, and the service refuses to create one.
    override_by = db.Column(db.String(80), default="")
    override_reason = db.Column(db.String(400), default="")

    incident = db.relationship("SentinelIncident")

    @property
    def live(self) -> bool:
        return (self.status == self.ACTIVE and self.expires_at is not None
                and self.expires_at > datetime.utcnow())

    @property
    def hours_left(self) -> float:
        if not self.expires_at:
            return 0.0
        delta = (self.expires_at - datetime.utcnow()).total_seconds() / 3600.0
        return round(max(0.0, delta), 1)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "ip": self.ip, "status": self.status,
            "live": self.live, "hours_left": self.hours_left,
            "incident_id": self.incident_id or 0,
            "appliance_id": self.appliance_id or 0,
            "source": self.source or "", "reason": self.reason or "",
            "detail": self.detail or "", "created_by": self.created_by or "",
            "created_at": self.created_at.isoformat(timespec="seconds")
                          if self.created_at else "",
            "expires_at": self.expires_at.isoformat(timespec="seconds")
                          if self.expires_at else "",
            "released_at": self.released_at.isoformat(timespec="seconds")
                           if self.released_at else "",
            "released_by": self.released_by or "",
            "release_reason": self.release_reason or "",
            "edge_verdict": self.edge_verdict or "",
            "edge_scope": self.edge_scope or "",
            "edge_hits": int(self.edge_hits or 0),
            "override_by": self.override_by or "",
            "override_reason": self.override_reason or "",
        }


# --------------------------------------------------------------------------- #
#  Raw — normalised security events                                             #
# --------------------------------------------------------------------------- #
class SentinelEvent(db.Model):
    """One normalised security event, whatever transport carried it.

    FortiWeb's attack log, FortiADC's, a syslog line and a FortiAnalyzer row
    all become this shape. ``raw_json`` keeps the source record verbatim so a
    normaliser bug is recoverable without re-reading a device that may have
    already rotated the log.

    ``dedup_key`` is content identity, not arrival time — the SoT lesson
    applied here. Without it a 60-second flood writes thousands of rows that
    say the same thing, and every one of them looks like fresh evidence.
    """

    __tablename__ = "sentinel_event"
    __table_args__ = (
        db.Index("ix_sentinel_event_ts_dev", "ts", "appliance_id"),
        db.Index("ix_sentinel_event_src", "src_ip", "ts"),
    )

    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, nullable=False, index=True)
    received_at = db.Column(db.DateTime, default=datetime.utcnow)
    appliance_id = db.Column(db.Integer,
                             db.ForeignKey("appliances.id", ondelete="SET NULL"),
                             index=True)
    device = db.Column(db.String(120), default="")      # survives device delete
    source = db.Column(db.String(24), default="")       # attack_log|syslog|faz
    policy = db.Column(db.String(160), default="")
    src_ip = db.Column(db.String(64), default="", index=True)
    src_port = db.Column(db.Integer)
    dst_ip = db.Column(db.String(64), default="")
    dst_port = db.Column(db.Integer)
    # 64, not 8: FortiWeb reports srccountry as a FULL NAME, and the geo block
    # list refuses anything else (errcode -7950). A short column would both
    # mis-label the source on the page and destroy the one value the block
    # mechanism accepts.
    country = db.Column(db.String(64), default="")
    asn = db.Column(db.Integer)
    http_method = db.Column(db.String(16), default="")
    uri = db.Column(db.Text, default="")
    http_status = db.Column(db.Integer)
    signature_id = db.Column(db.String(64), default="", index=True)
    signature = db.Column(db.String(300), default="")
    attack_family = db.Column(db.String(40), default="", index=True)
    severity = db.Column(db.String(16), default="")     # info|low|medium|high|critical
    action = db.Column(db.String(32), default="")       # alert|deny|block_period|...
    count = db.Column(db.Integer, default=1)
    dedup_key = db.Column(db.String(64), index=True)
    incident_id = db.Column(db.Integer,
                            db.ForeignKey("sentinel_incident.id",
                                          ondelete="SET NULL"), index=True)
    raw_json = db.Column(db.Text, default="{}")

    raw = _json_prop("raw_json", {})

    #: Severity ordering used by scoring and by the UI badges. Kept here so the
    #: two cannot disagree about what "worse" means.
    SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    @property
    def severity_rank(self) -> int:
        return self.SEVERITY_RANK.get((self.severity or "").lower(), 0)

    @property
    def blocked(self) -> bool:
        """Whether the WAF actually STOPPED this request.

        The single most valuable bit in the whole record, and the one a naive
        "count the attack events" design throws away: a source that received a
        WAF block is the opposite of a source that received a 200 on the same
        URI. One is the defence working, the other is the defence evaded.
        """
        a = (self.action or "").lower()
        return any(k in a for k in ("deny", "block", "drop", "reset", "period"))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ts": self.ts.isoformat(timespec="seconds") if self.ts else "",
            "device": self.device or "", "source": self.source or "",
            "policy": self.policy or "", "src_ip": self.src_ip or "",
            "dst_ip": self.dst_ip or "", "country": self.country or "",
            "asn": self.asn or 0, "http_method": self.http_method or "",
            "uri": self.uri or "", "http_status": self.http_status or 0,
            "signature_id": self.signature_id or "",
            "signature": self.signature or "",
            "attack_family": self.attack_family or "",
            "severity": self.severity or "", "action": self.action or "",
            "blocked": self.blocked, "count": int(self.count or 1),
            "incident_id": self.incident_id or 0,
        }


# --------------------------------------------------------------------------- #
#  Derived — behavioural baselines and anomalies                                #
# --------------------------------------------------------------------------- #
class SentinelBaseline(db.Model):
    """Robust behavioural baseline for one series, per hour-of-week.

    Median + MAD, not mean + sigma: a single attack spike drags a mean far
    enough that the NEXT attack looks normal, and the standard deviation it
    inflates hides it further. The median is unmoved by a minority of extreme
    samples, which is exactly the property a security baseline needs.

    168 buckets (hour-of-week) because fleet traffic is not stationary — a
    Tuesday noon peak is not an anomaly, and a Sunday 03:00 peak at the same
    absolute value very much is.
    """

    __tablename__ = "sentinel_baseline"
    __table_args__ = (
        db.UniqueConstraint("series_key", "dow_hour", name="uq_sentinel_baseline"),
    )

    #: Fewer than this many samples in a bucket => the bucket cannot fire.
    MIN_SAMPLES = 12

    STATE_LEARNING = "learning"
    STATE_ACTIVE = "active"
    STATE_FROZEN = "frozen"

    id = db.Column(db.Integer, primary_key=True)
    series_key = db.Column(db.String(200), nullable=False, index=True)
    dow_hour = db.Column(db.Integer, nullable=False)   # 0..167
    median = db.Column(db.Float, default=0.0)
    mad = db.Column(db.Float, default=0.0)
    p95 = db.Column(db.Float, default=0.0)
    n = db.Column(db.Integer, default=0)
    state = db.Column(db.String(16), default=STATE_LEARNING)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow)

    @property
    def usable(self) -> bool:
        """A baseline may only produce a deviation when it is ACTIVE and has
        enough samples. ``learning`` observes and never fires — an immature
        baseline that fires is a false-positive generator with statistics for
        a costume."""
        return self.state == self.STATE_ACTIVE and (self.n or 0) >= self.MIN_SAMPLES

    def to_dict(self) -> dict:
        return {"series_key": self.series_key, "dow_hour": self.dow_hour,
                "median": self.median, "mad": self.mad, "p95": self.p95,
                "n": self.n, "state": self.state, "usable": self.usable}


class SentinelAnomaly(db.Model):
    """A measured deviation from a usable baseline. Evidence, never a verdict."""

    __tablename__ = "sentinel_anomaly"

    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, nullable=False, index=True)
    series_key = db.Column(db.String(200), nullable=False, index=True)
    layer = db.Column(db.String(24), default="")    # traffic|box|vm|host|backend|http_status
    device = db.Column(db.String(120), default="")
    value = db.Column(db.Float)
    baseline = db.Column(db.Float)
    deviation = db.Column(db.Float)                 # robust z (value-median)/MAD
    ratio = db.Column(db.Float)                     # value / median
    incident_id = db.Column(db.Integer,
                            db.ForeignKey("sentinel_incident.id",
                                          ondelete="SET NULL"), index=True)

    def to_dict(self) -> dict:
        return {"id": self.id,
                "ts": self.ts.isoformat(timespec="seconds") if self.ts else "",
                "series_key": self.series_key, "layer": self.layer,
                "device": self.device, "value": self.value,
                "baseline": self.baseline, "deviation": self.deviation,
                "ratio": self.ratio}


# --------------------------------------------------------------------------- #
#  Incidents                                                                    #
# --------------------------------------------------------------------------- #
class SentinelIncident(db.Model):
    """A correlated security scenario — the product's unit of meaning.

    An incident is opened by a deterministic trigger and then ABSORBS matching
    events for as long as its window is live. Identity is the tuple
    (device, src_ip, attack_family), not the timestamp: without absorption a
    DoS produces one incident per request and the console becomes the log it
    was supposed to replace.

    ``status`` includes ``false_positive`` as a first-class terminal state. A
    false positive is not a closed incident — it is the training signal that
    reduces the next one, and burying it inside ``closed`` throws that away.
    """

    __tablename__ = "sentinel_incident"

    STATUS_OPEN = "open"
    STATUS_VERIFYING = "verifying"
    STATUS_MITIGATED = "mitigated"
    STATUS_CLOSED = "closed"
    STATUS_FALSE_POSITIVE = "false_positive"
    STATUSES = (STATUS_OPEN, STATUS_VERIFYING, STATUS_MITIGATED,
                STATUS_CLOSED, STATUS_FALSE_POSITIVE)

    #: Score bands → response level. The boundaries live here because the UI,
    #: the policy engine and the tests must not each own their own copy.
    BAND_OBSERVE = 40
    BAND_RECOMMEND = 70
    BAND_SEMI_AUTO = 85

    id = db.Column(db.Integer, primary_key=True)
    ref = db.Column(db.String(32), unique=True, index=True)   # INC-2026-000123
    opened_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow,
                          index=True)
    last_event_at = db.Column(db.DateTime)
    closed_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), default=STATUS_OPEN, index=True)

    appliance_id = db.Column(db.Integer,
                             db.ForeignKey("appliances.id", ondelete="SET NULL"))
    device = db.Column(db.String(120), default="", index=True)
    policy = db.Column(db.String(160), default="")
    src_ip = db.Column(db.String(64), default="", index=True)
    src_country = db.Column(db.String(64), default="")
    src_asn = db.Column(db.Integer)
    src_trusted = db.Column(db.Boolean, default=False)
    attack_family = db.Column(db.String(40), default="", index=True)
    severity = db.Column(db.String(16), default="")

    event_count = db.Column(db.Integer, default=0)
    blocked_count = db.Column(db.Integer, default=0)
    passed_count = db.Column(db.Integer, default=0)

    score = db.Column(db.Integer, default=0, index=True)
    confidence = db.Column(db.Float, default=0.0)
    score_json = db.Column(db.Text, default="[]")        # per-factor breakdown

    # Impact per layer. NULL is "unknown" and is rendered as such — never as
    # "no impact". The distinction is the whole point of the topology table.
    impact_fortinet = db.Column(db.Boolean)
    impact_vm = db.Column(db.Boolean)
    impact_host = db.Column(db.Boolean)
    impact_backend = db.Column(db.Boolean)

    exploit_available = db.Column(db.Boolean, default=False)
    target_vulnerable = db.Column(db.Boolean, default=False)
    waf_blocked = db.Column(db.Boolean, default=False)

    window_start = db.Column(db.DateTime)
    window_end = db.Column(db.DateTime)

    ai_json = db.Column(db.Text, default="{}")           # model opinion ONLY
    similar_json = db.Column(db.Text, default="[]")
    fp_reason = db.Column(db.String(60), default="")
    resolution_note = db.Column(db.Text, default="")
    closed_by = db.Column(db.String(80), default="")

    appliance = db.relationship("Appliance")
    events = db.relationship("SentinelEvent", backref="incident",
                             foreign_keys="SentinelEvent.incident_id")

    score_factors = _json_prop("score_json", [])
    ai = _json_prop("ai_json", {})
    similar = _json_prop("similar_json", [])

    @property
    def band(self) -> str:
        s = int(self.score or 0)
        if s >= self.BAND_SEMI_AUTO:
            return "semi_auto"
        if s >= self.BAND_RECOMMEND:
            return "recommend"
        if s >= self.BAND_OBSERVE:
            return "investigate"
        return "observe"

    @property
    def open(self) -> bool:
        return self.status in (self.STATUS_OPEN, self.STATUS_VERIFYING)

    def impact_dict(self) -> dict:
        """Impact with ``unknown`` preserved. ``None`` never becomes ``False``."""
        def v(x):
            return "unknown" if x is None else bool(x)
        return {"fortinet": v(self.impact_fortinet), "vm": v(self.impact_vm),
                "host": v(self.impact_host), "backend": v(self.impact_backend)}

    def to_dict(self) -> dict:
        return {
            "id": self.id, "ref": self.ref or "",
            "opened_at": self.opened_at.isoformat(timespec="seconds")
                         if self.opened_at else "",
            "last_event_at": self.last_event_at.isoformat(timespec="seconds")
                             if self.last_event_at else "",
            "status": self.status, "device": self.device or "",
            "policy": self.policy or "", "src_ip": self.src_ip or "",
            "src_country": self.src_country or "", "src_asn": self.src_asn or 0,
            "src_trusted": bool(self.src_trusted),
            "attack_family": self.attack_family or "",
            "severity": self.severity or "",
            "event_count": int(self.event_count or 0),
            "blocked_count": int(self.blocked_count or 0),
            "passed_count": int(self.passed_count or 0),
            "score": int(self.score or 0), "confidence": self.confidence or 0.0,
            "band": self.band, "score_factors": self.score_factors,
            "impact": self.impact_dict(),
            "exploit_available": bool(self.exploit_available),
            "target_vulnerable": bool(self.target_vulnerable),
            "waf_blocked": bool(self.waf_blocked),
            "ai": self.ai, "similar": self.similar,
            "fp_reason": self.fp_reason or "",
        }


class SentinelIncidentEvent(db.Model):
    """One ordered entry of an incident's timeline.

    Separate from :class:`SentinelEvidence` on purpose: the timeline says WHEN
    something happened (including SATOM's own decisions — opened, scored,
    action requested, verified), evidence says WHY the verdict holds. Merging
    them produced, in the design review, a list where an operator could not
    tell a measurement from a decision.
    """

    __tablename__ = "sentinel_incident_event"

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer,
                            db.ForeignKey("sentinel_incident.id",
                                          ondelete="CASCADE"),
                            nullable=False, index=True)
    ts = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    kind = db.Column(db.String(32), default="")     # attack|anomaly|decision|action|verify
    layer = db.Column(db.String(24), default="")
    text = db.Column(db.Text, default="")
    ref_table = db.Column(db.String(40), default="")
    ref_id = db.Column(db.Integer)

    incident = db.relationship("SentinelIncident",
                               backref=db.backref("timeline",
                                                  cascade="all, delete-orphan",
                                                  order_by="SentinelIncidentEvent.ts"))

    def to_dict(self) -> dict:
        return {"ts": self.ts.isoformat(timespec="seconds") if self.ts else "",
                "kind": self.kind, "layer": self.layer, "text": self.text,
                "ref_table": self.ref_table, "ref_id": self.ref_id or 0}


class SentinelEvidence(db.Model):
    """One measured claim supporting (or undermining) an incident's verdict.

    Every row carries the value AND the baseline it is being judged against.
    "CPU is high" is an assertion; "CPU 91% against a Tuesday-12h median of
    22% (13.2x)" is evidence, and only the second can be argued with.
    """

    __tablename__ = "sentinel_evidence"

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer,
                            db.ForeignKey("sentinel_incident.id",
                                          ondelete="CASCADE"),
                            nullable=False, index=True)
    layer = db.Column(db.String(24), default="")
    claim = db.Column(db.Text, default="")
    value = db.Column(db.Float)
    baseline = db.Column(db.Float)
    deviation = db.Column(db.Float)
    unit = db.Column(db.String(24), default="")
    window = db.Column(db.String(40), default="")
    weight_hint = db.Column(db.String(16), default="")   # supports|undermines|context
    detail_json = db.Column(db.Text, default="{}")

    incident = db.relationship("SentinelIncident",
                               backref=db.backref("evidence",
                                                  cascade="all, delete-orphan"))
    detail = _json_prop("detail_json", {})

    def to_dict(self) -> dict:
        return {"layer": self.layer, "claim": self.claim, "value": self.value,
                "baseline": self.baseline, "deviation": self.deviation,
                "unit": self.unit, "window": self.window,
                "weight_hint": self.weight_hint, "detail": self.detail}


# --------------------------------------------------------------------------- #
#  Response — policy, actions, verification                                     #
# --------------------------------------------------------------------------- #
class SentinelPolicy(db.Model):
    """What Sentinel is ALLOWED to do, per action type.

    Autonomy is configuration, not code, and it is off by default. ``level``
    is the ceiling for this action type; an incident may never be answered
    above it however confident the score.
    """

    __tablename__ = "sentinel_policy"

    LEVEL_OBSERVE = 0     # never act
    LEVEL_RECOMMEND = 1   # propose, human executes
    LEVEL_SEMI_AUTO = 2   # pre-authorised, one-click
    LEVEL_AUTONOMOUS = 3  # execute automatically

    id = db.Column(db.Integer, primary_key=True)
    action_type = db.Column(db.String(40), nullable=False, unique=True)
    level = db.Column(db.Integer, default=LEVEL_OBSERVE)
    min_confidence = db.Column(db.Integer, default=85)
    ttl_minutes = db.Column(db.Integer, default=30)
    max_ttl_minutes = db.Column(db.Integer, default=240)
    max_per_hour = db.Column(db.Integer, default=3)     # circuit breaker
    enabled = db.Column(db.Boolean, default=False)
    note = db.Column(db.String(300), default="")
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow)

    def to_dict(self) -> dict:
        return {"action_type": self.action_type, "level": int(self.level or 0),
                "min_confidence": int(self.min_confidence or 0),
                "ttl_minutes": int(self.ttl_minutes or 0),
                "max_ttl_minutes": int(self.max_ttl_minutes or 0),
                "max_per_hour": int(self.max_per_hour or 0),
                "enabled": bool(self.enabled), "note": self.note or ""}


class SentinelAction(db.Model):
    """A requested or executed response, with its expiry and its audit trail.

    ``expires_at`` is mandatory for every blocking action and is the PRIMARY
    rollback mechanism. An undo that must itself succeed is not a rollback —
    it is a second thing that can fail, at the moment the first already has.
    """

    __tablename__ = "sentinel_action"

    STATUS_PROPOSED = "proposed"
    STATUS_APPROVED = "approved"
    STATUS_QUEUED = "queued"
    STATUS_APPLIED = "applied"
    STATUS_FAILED = "failed"
    STATUS_EXPIRED = "expired"
    STATUS_ROLLED_BACK = "rolled_back"
    STATUS_REJECTED = "rejected"

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer,
                            db.ForeignKey("sentinel_incident.id",
                                          ondelete="CASCADE"), index=True)
    correlation_id = db.Column(db.String(40), index=True)
    action_type = db.Column(db.String(40), nullable=False)
    params_json = db.Column(db.Text, default="{}")
    level = db.Column(db.Integer, default=1)
    status = db.Column(db.String(20), default=STATUS_PROPOSED, index=True)
    proposed_by = db.Column(db.String(60), default="")   # policy_engine|ai|user:x
    approved_by = db.Column(db.String(80), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    applied_at = db.Column(db.DateTime)
    expires_at = db.Column(db.DateTime)
    detail = db.Column(db.Text, default="")
    rationale = db.Column(db.Text, default="")

    incident = db.relationship("SentinelIncident",
                               backref=db.backref("actions",
                                                  cascade="all, delete-orphan"))
    params = _json_prop("params_json", {})

    def to_dict(self) -> dict:
        return {"id": self.id, "incident_id": self.incident_id or 0,
                "correlation_id": self.correlation_id or "",
                "action_type": self.action_type, "params": self.params,
                "level": int(self.level or 0), "status": self.status,
                "proposed_by": self.proposed_by or "",
                "approved_by": self.approved_by or "",
                "created_at": self.created_at.isoformat(timespec="seconds")
                              if self.created_at else "",
                "expires_at": self.expires_at.isoformat(timespec="seconds")
                              if self.expires_at else "",
                "detail": self.detail or "", "rationale": self.rationale or ""}


class SentinelActionResult(db.Model):
    """Did the action DO anything? Applied ≠ effective.

    Two separate verdicts, because they fail differently: ``applied`` is "the
    appliance's own config now contains the rule, re-read from the device";
    ``effective`` is "the traffic/CPU/latency actually changed". A rule that is
    present and useless is the case that must escalate, and it is invisible to
    a check that only confirms the write.
    """

    __tablename__ = "sentinel_action_result"

    id = db.Column(db.Integer, primary_key=True)
    action_id = db.Column(db.Integer,
                          db.ForeignKey("sentinel_action.id",
                                        ondelete="CASCADE"),
                          nullable=False, index=True)
    verified_at = db.Column(db.DateTime, default=datetime.utcnow)
    applied_ok = db.Column(db.Boolean)
    effective = db.Column(db.Boolean)
    expected = db.Column(db.String(300), default="")
    observed = db.Column(db.String(300), default="")
    verdict = db.Column(db.String(24), default="")    # success|ineffective|unknown
    detail_json = db.Column(db.Text, default="{}")

    action = db.relationship("SentinelAction",
                             backref=db.backref("results",
                                                cascade="all, delete-orphan"))
    detail = _json_prop("detail_json", {})


# --------------------------------------------------------------------------- #
#  Context — what makes a real attack read as benign                            #
# --------------------------------------------------------------------------- #
class SentinelTrustedSource(db.Model):
    """An authorised scanner / monitor / integration.

    ``expires_at`` is not optional decoration. A pentest window authorised in
    March is not authorisation in September, and a trust list without expiry
    is a permanent blind spot that nobody remembers creating.
    """

    __tablename__ = "sentinel_trusted_source"

    KINDS = ("scanner", "monitor", "pentest", "integration", "internal", "bot")

    id = db.Column(db.Integer, primary_key=True)
    cidr = db.Column(db.String(64), nullable=False)
    kind = db.Column(db.String(24), default="scanner")
    label = db.Column(db.String(120), default="")
    note = db.Column(db.String(300), default="")
    suppress_actions = db.Column(db.Boolean, default=True)
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.String(80), default="")

    @property
    def active(self) -> bool:
        return self.expires_at is None or self.expires_at > datetime.utcnow()

    def to_dict(self) -> dict:
        return {"id": self.id, "cidr": self.cidr, "kind": self.kind,
                "label": self.label or "", "note": self.note or "",
                "suppress_actions": bool(self.suppress_actions),
                "expires_at": self.expires_at.isoformat(timespec="seconds")
                              if self.expires_at else "",
                "active": self.active}


class SentinelMaintenanceWindow(db.Model):
    """A scheduled window in which surprise is expected.

    It suppresses ACTIONS and FREEZES baselines, but never suppresses
    detection: if an authorised pentest saturates the appliance, that is an
    incident regardless of intent, and a window that hides it hides the one
    result the pentest was run to produce.
    """

    __tablename__ = "sentinel_maintenance_window"

    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(120), default="")
    scope_device = db.Column(db.String(120), default="")   # "" = all devices
    starts_at = db.Column(db.DateTime, nullable=False)
    ends_at = db.Column(db.DateTime, nullable=False)
    suppress_actions = db.Column(db.Boolean, default=True)
    freeze_baseline = db.Column(db.Boolean, default=True)
    note = db.Column(db.String(300), default="")
    created_by = db.Column(db.String(80), default="")

    def covers(self, when: datetime, device: str = "") -> bool:
        if not (self.starts_at <= when <= self.ends_at):
            return False
        scope = (self.scope_device or "").strip()
        return not scope or scope == device

    def to_dict(self) -> dict:
        return {"id": self.id, "label": self.label or "",
                "scope_device": self.scope_device or "",
                "starts_at": self.starts_at.isoformat(timespec="seconds")
                             if self.starts_at else "",
                "ends_at": self.ends_at.isoformat(timespec="seconds")
                           if self.ends_at else "",
                "suppress_actions": bool(self.suppress_actions),
                "freeze_baseline": bool(self.freeze_baseline),
                "note": self.note or ""}


# --------------------------------------------------------------------------- #
#  Vulnerability intelligence — LOCAL MIRROR, never a live third-party call     #
# --------------------------------------------------------------------------- #
class SentinelVuln(db.Model):
    """One CVE as this installation knows it — from the local mirror.

    Enrichment NEVER calls a third party inside the incident loop. Querying
    Vulners live, per incident, tells that vendor exactly which signatures and
    CVEs this fleet is seeing: a real-time map of the customer's attack
    surface, shipped to a third party as a side effect of defending. The sync
    is a separate, scheduled, opt-in job; the incident path reads this table
    and only this table.

    ``epss`` and ``in_kev`` outrank ``cvss`` in scoring on purpose: a 9.8 that
    nobody exploits is less urgent than a 7.5 on CISA's Known-Exploited list.
    """

    __tablename__ = "sentinel_vuln"

    id = db.Column(db.Integer, primary_key=True)
    cve = db.Column(db.String(32), nullable=False, unique=True, index=True)
    cvss = db.Column(db.Float)
    cvss_vector = db.Column(db.String(120), default="")
    epss = db.Column(db.Float)
    in_kev = db.Column(db.Boolean, default=False)
    exploit_refs_json = db.Column(db.Text, default="[]")
    affected_cpe_json = db.Column(db.Text, default="[]")
    summary = db.Column(db.Text, default="")
    published = db.Column(db.DateTime)
    source = db.Column(db.String(40), default="")
    fetched_at = db.Column(db.DateTime, default=datetime.utcnow)

    exploit_refs = _json_prop("exploit_refs_json", [])
    affected_cpe = _json_prop("affected_cpe_json", [])

    @property
    def exploit_available(self) -> bool:
        return bool(self.in_kev or self.exploit_refs)

    def to_dict(self) -> dict:
        return {"cve": self.cve, "cvss": self.cvss, "epss": self.epss,
                "in_kev": bool(self.in_kev),
                "exploit_available": self.exploit_available,
                "exploit_refs": self.exploit_refs,
                "affected_cpe": self.affected_cpe,
                "summary": self.summary or "", "source": self.source or "",
                "fetched_at": self.fetched_at.isoformat(timespec="seconds")
                              if self.fetched_at else ""}


class SentinelSignatureCve(db.Model):
    """Signature → CVE mapping. The bridge from "what fired" to "what it is".

    Kept as data, not code, because it is installation-specific and because a
    wrong mapping must be correctable by an operator without a release.
    """

    __tablename__ = "sentinel_signature_cve"
    __table_args__ = (
        db.UniqueConstraint("signature_id", "cve", name="uq_sentinel_sig_cve"),
    )

    id = db.Column(db.Integer, primary_key=True)
    signature_id = db.Column(db.String(64), nullable=False, index=True)
    cve = db.Column(db.String(32), nullable=False)
    product = db.Column(db.String(80), default="")
    source = db.Column(db.String(40), default="")     # manual|signature_catalog|mirror
    confidence = db.Column(db.Float, default=1.0)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow)


__all__ = [
    "SentinelTopology", "SentinelEdgeMap", "SentinelBlockEntry",
    "SentinelEvent", "SentinelBaseline", "SentinelAnomaly",
    "SentinelIncident", "SentinelIncidentEvent", "SentinelEvidence",
    "SentinelPolicy", "SentinelAction", "SentinelActionResult",
    "SentinelTrustedSource", "SentinelMaintenanceWindow", "SentinelVuln",
    "SentinelSignatureCve",
]
