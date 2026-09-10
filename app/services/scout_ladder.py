"""Scout — fault localisation for one published service.

The question
-----------
An operator says *"this service is broken"*. Twelve tools in this product can
each answer a piece of that, and none of them answers the only question the
operator actually has: **WHICH LAYER is broken?** Scout is the ladder that
walks them in dependency order, stops at the first layer that fails, and names
that layer with the evidence that convicted it.

Scout is NOT Sentinel, and the line is not "security vs troubleshooting"
--------------------------------------------------------------------------
That line does not survive the first health incident Sentinel raises. The line
that does survive is **who starts it and what it owns**:

* Sentinel is started by the clock, chooses its own object, and produces an
  *incident*.
* Scout is started by an operator, is handed its object, and produces a
  *localisation verdict*.

A Sentinel incident may link INTO Scout with the object pre-filled. Scout never
opens an incident. One direction only — the day this module starts writing
incidents, Sentinel has been rebuilt inside Sentinel.

Doctrine
--------
**Scout re-implements no judgement.** Every layer delegates to the module that
already owns its question — :mod:`backend_probe` decides what "reachable"
means, :mod:`txn_trace` measures a request, :mod:`device_health` decides what
"stale" means. Scout owns the *order* and the *verdict*, nothing else. A second
author of "is this backend up?" is how a page ends up disagreeing with the
tool it is quoting.

**"Could not look" is a first-class answer and it is never health.** A layer
that could not run returns :data:`UNKNOWN`. It does not stop the ladder, it
does not pass, and it is counted into the verdict as a blind spot — because a
verdict of "no fault found" from a ladder that could only run four of its ten
rungs is a lie of omission, and it is the exact lie that gets an outage signed
off.

**A crash in Scout is not a fault in the customer's path.** A layer that raises
is reported UNKNOWN with the exception text, never FAIL. Rendering our own bug
as their outage sends an operator to reboot a healthy appliance.

**The first FAIL stops the ladder.** Everything below it is SKIPPED, never
passed: a pool cannot be meaningfully judged through a front door that never
opened, and a green rung under a red one is how a report gets read backwards.

**Read only.** No layer issues a write, and no layer issues a mutating HTTP
method. Replaying a POST "to see what happens" is how a diagnosis creates the
ticket it was opened to close — the rule :mod:`txn_trace` already states, kept
here because this module is a second entry point to that same capability.

Vantage is part of every answer
-------------------------------
SATOM lives on the management network. **Its path to a backend is not the
appliance's path to that backend**, so a probe that succeeds from here proves
nothing about the data path and one that fails accuses the wrong device. Every
rung therefore records WHICH vantage produced it, and the three are never
merged:

* :data:`V_SATOM` — this node's own socket.
* :data:`V_DEVICE` — the appliance itself, over its CLI/REST.
* :data:`V_EDGE` — the FortiAnalyzer's record of what the border did.

The distinction between *firewall drop*, *reset* and *routing* exists only in
:data:`V_EDGE`; those three produce an identical silence at :data:`V_SATOM`.
That is why layer ``path`` reads logs instead of opening a socket.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# --------------------------------------------------------------------------- #
#  Vocabulary                                                                   #
# --------------------------------------------------------------------------- #
PASS = "pass"
FAIL = "fail"
WARN = "warn"
UNKNOWN = "unknown"
SKIPPED = "skipped"

#: Ordered worst-first. Used for badges and for nothing else — the ladder's
#: stop condition is FAIL exactly, not "at least this bad", because a WARN that
#: halted the walk would hide the rung that actually broke.
SEVERITY = (FAIL, WARN, UNKNOWN, SKIPPED, PASS)

V_SATOM = "satom"
V_DEVICE = "device"
V_EDGE = "edge"

VANTAGE_LABEL = {
    V_SATOM: "this node",
    V_DEVICE: "the appliance",
    V_EDGE: "the collector",
}

#: Products whose published object this ladder understands. FortiWeb calls it a
#: server policy and FortiADC calls it a virtual server; the ladder is the same
#: shape and the vocabulary is not, so the noun is resolved per product rather
#: than hard-coded into ten messages.
OBJECT_NOUN = {
    "fortiweb": "server policy",
    "fortiadc": "virtual server",
}

SUPPORTED_KINDS = tuple(OBJECT_NOUN)

#: Only these reach a customer's application without changing it.
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")

#: A phase must be both dominant AND slow to be called out. A 12 ms TTFB that
#: is 90 % of a 13 ms request is not "the backend thinking", and reporting it
#: that way sends someone to profile an application that answered instantly.
DOMINANT_SHARE = 0.60
DOMINANT_FLOOR_MS = 400.0

#: Certificate runway. Expired is a FAIL; the warning band is a WARN and must
#: not stop the ladder — a service with a cert expiring on Friday is very
#: often still broken for an entirely different reason today.
CERT_WARN_DAYS = 14

#: Health signals that, when critical, genuinely stop this appliance serving.
#: ``sync`` and ``cache`` critical mean SATOM could not HARVEST the device —
#: a statement about SATOM's reach, not about the data path. Letting those halt
#: the walk blames the box for a stale inventory and skips nine rungs that could
#: have named the real fault.
#:
#: This is not a theoretical softening. Measured against the live fleet on
#: 2026-09-08: EVERY FortiWeb here grades ``crit`` because the VMs are
#: unlicensed and refuse the REST sweep, so a rung that stopped on harvest
#: health would stop on every device, always, and Scout would never reach a
#: single rung below its first. The defect was invisible to the guards and
#: visible on the first real render.
BLOCKING_SIGNALS = ("capacity", "probe")

DEFAULT_WINDOW_MIN = 30
MAX_WINDOW_MIN = 24 * 60


class ScoutRefused(Exception):
    """An input this module will not act on. The text is shown verbatim."""


# --------------------------------------------------------------------------- #
#  Inputs                                                                       #
# --------------------------------------------------------------------------- #
@dataclass
class Target:
    """What is being diagnosed. Named by the operator, never chosen here."""
    appliance: object = None
    policy: str = ""
    #: Published name to test. Empty means "derive it from the policy's VIP",
    #: which is the common case and the one an operator should not have to type.
    hostname: str = ""
    port: int = 0
    scheme: str = "https"
    path: str = "/"
    method: str = "GET"

    @property
    def kind(self) -> str:
        return str(getattr(self.appliance, "kind", "") or "")

    @property
    def noun(self) -> str:
        return OBJECT_NOUN.get(self.kind, "published object")


@dataclass
class Options:
    """Knobs an operator may set. Every one of them is clamped, not trusted."""
    use_ssh: bool = False
    timeout: float = 8.0
    window_minutes: int = DEFAULT_WINDOW_MIN
    #: FortiAnalyzer correlation. Absent means layer ``path`` reports UNKNOWN —
    #: it never reports "the border was fine".
    analyzer: object = None
    faz_adom: str = "root"
    faz_devid: str = ""
    faz_vdom: str = ""

    def clamped(self) -> "Options":
        self.timeout = max(1.0, min(float(self.timeout or 8.0), 30.0))
        try:
            self.window_minutes = max(
                1, min(int(self.window_minutes or DEFAULT_WINDOW_MIN),
                       MAX_WINDOW_MIN))
        except (TypeError, ValueError):
            self.window_minutes = DEFAULT_WINDOW_MIN
        return self


@dataclass
class LayerResult:
    key: str = ""
    title: str = ""
    question: str = ""
    vantage: str = V_SATOM
    verdict: str = UNKNOWN
    headline: str = ""
    evidence: list = field(default_factory=list)   # [(label, value), ...]
    detail: str = ""

    def as_dict(self) -> dict:
        return {"key": self.key, "title": self.title, "question": self.question,
                "vantage": self.vantage, "vantage_label":
                    VANTAGE_LABEL.get(self.vantage, self.vantage),
                "verdict": self.verdict, "headline": self.headline,
                "evidence": [list(e) for e in self.evidence],
                "detail": self.detail}


@dataclass
class Ctx:
    target: Target
    opts: Options
    ports: dict
    state: dict = field(default_factory=dict)

    def port(self, name: str):
        """The injected implementation of one capability.

        Missing means the capability is unavailable in this deployment, and the
        layer that needs it reports UNKNOWN. It does NOT mean the layer passes.
        """
        return self.ports.get(name)


# --------------------------------------------------------------------------- #
#  Pure helpers — the parts worth testing without an appliance                   #
# --------------------------------------------------------------------------- #
def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
    except ValueError:
        return False


def assert_safe_method(method: str) -> str:
    """A mutating method is a real write to somebody's application."""
    m = str(method or "GET").strip().upper()
    if m not in SAFE_METHODS:
        raise ScoutRefused(
            "Scout will not issue %s. A diagnosis that mutates the application "
            "it is diagnosing creates the ticket it was opened to close — use "
            "the Transaction Tracer, which takes an explicit per-call opt-in "
            "and audits it." % m)
    return m


def read_timings(timing: dict | None) -> dict:
    """Which phase dominated a request, in words an operator can act on.

    This is a localiser in its own right and it is the reason the ladder
    measures phases instead of one round-trip number: connect slow means the
    network or the accept backlog, TLS slow means the handshake, TTFB slow
    means the application is thinking, and a single ``elapsed_ms`` cannot tell
    those three apart.
    """
    t = timing or {}

    def _f(key):
        try:
            v = t.get(key)
            return None if v is None else float(v)
        except (TypeError, ValueError):
            return None

    total = _f("total_ms")
    phases = [("tcp", _f("tcp_ms"), "TCP connect — the network path or the "
                                    "listener's accept backlog"),
              ("tls", _f("tls_ms"), "TLS handshake — key exchange, chain size "
                                    "or an OCSP fetch"),
              ("ttfb", _f("ttfb_ms"), "time to first byte — the appliance or "
                                      "the application behind it is thinking")]
    known = [(k, v, why) for k, v, why in phases if v is not None]
    if not known or not total or total <= 0:
        return {"phase": "", "share": None, "note":
                "no phase timings were captured", "ms": None}
    key, ms, why = max(known, key=lambda r: r[1])
    share = ms / total
    if share < DOMINANT_SHARE or ms < DOMINANT_FLOOR_MS:
        return {"phase": "", "share": round(share, 3), "ms": round(ms, 1),
                "note": "no single phase dominates this request"}
    return {"phase": key, "share": round(share, 3), "ms": round(ms, 1),
            "note": "%s took %.0f ms (%.0f%% of the request) — %s"
                    % (key.upper(), ms, share * 100, why)}


#: FortiAnalyzer traffic-log ``action`` values, grouped by what they PROVE.
#: The grouping is the whole content of layer ``path``: these four buckets are
#: the only place in the product where "firewall dropped it", "something sent a
#: reset" and "it was forwarded fine" are distinguishable, because at a socket
#: the first two and a routing black hole are the same silence.
PATH_DENY = ("deny", "block", "blocked", "drop", "dropped")
PATH_RESET = ("reset", "client-rst", "server-rst", "rst")
PATH_TIMEOUT = ("timeout",)
PATH_OK = ("accept", "close", "start", "ip-conn", "dns")

PATH_ORDER = ("deny", "reset", "timeout", "accept")


def _bucket(action: str) -> str:
    a = str(action or "").strip().lower()
    if a in PATH_DENY:
        return "deny"
    if a in PATH_RESET:
        return "reset"
    if a in PATH_TIMEOUT:
        return "timeout"
    if a in PATH_OK:
        return "accept"
    return ""


def classify_path_rows(rows) -> dict:
    """Border log rows → the fault mode of a path.

    ``absent`` is returned for an empty result set and it is NOT a verdict.
    A collector that holds no rows can mean the flow never reached the border
    (routing), or that the ADOM/device selector is wrong, or that logging is
    off for that policy. Those are three different worlds and the logs cannot
    tell them apart, so the caller degrades to UNKNOWN rather than picking one.
    """
    counts = {k: 0 for k in PATH_ORDER}
    unknown = 0
    sample: list = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        b = _bucket(r.get("action"))
        if not b:
            unknown += 1
            continue
        counts[b] += 1
        if len(sample) < 5:
            sample.append({
                "action": str(r.get("action") or ""),
                "srcip": str(r.get("srcip") or ""),
                "dstip": str(r.get("dstip") or ""),
                "dstport": str(r.get("dstport") or ""),
                "policyid": str(r.get("policyid") or ""),
                "date": "%s %s" % (r.get("date") or "", r.get("time") or ""),
            })
    seen = [k for k in PATH_ORDER if counts[k]]
    if not seen:
        return {"mode": "absent", "counts": counts, "unknown_actions": unknown,
                "mixed": False, "sample": sample, "total": unknown}
    return {"mode": seen[0], "counts": counts, "unknown_actions": unknown,
            "mixed": len(seen) > 1, "sample": sample,
            "total": sum(counts.values()) + unknown}


#: What each fault mode means, and what the operator does next. Prose lives in
#: ONE table: a caller that rewrites it is a second author of the diagnosis.
PATH_VERDICT = {
    "deny": (FAIL, "the border DROPPED this flow — this is a firewall policy, "
                   "not the appliance and not the application"),
    "reset": (FAIL, "the flow was RESET — something answered, so the host is "
                    "up: a closed port, a dead service, or a stateful device "
                    "tearing the session down"),
    "timeout": (FAIL, "the flow TIMED OUT at the border — the packets left and "
                      "nothing came back"),
    "accept": (PASS, "the border forwarded this flow — the path itself is not "
                     "the fault"),
    "absent": (UNKNOWN, "the collector holds no rows for this flow in the "
                        "window. That is not proof the flow was blocked: it "
                        "reads the same as a wrong ADOM, a wrong device "
                        "selector, or logging disabled for the policy"),
}


def summarise(results) -> dict:
    """The localisation verdict. Names ONE layer, or admits it named none."""
    rows = [r for r in results or []]
    failed = [r for r in rows if r.verdict == FAIL]
    blind = [r for r in rows if r.verdict == UNKNOWN]
    warned = [r for r in rows if r.verdict == WARN]
    probed = [r for r in rows if r.verdict in (PASS, FAIL, WARN)]

    if failed:
        first = failed[0]
        return {
            "localised": True,
            "layer": first.key,
            "title": first.title,
            "vantage": first.vantage,
            "headline": first.headline,
            "text": "Fault localised at layer %s (%s), observed from %s."
                    % (first.key, first.title,
                       VANTAGE_LABEL.get(first.vantage, first.vantage)),
            "blind_spots": [r.key for r in blind],
            "warnings": [r.key for r in warned],
            "probed": len(probed),
        }
    # No FAIL. This is deliberately NOT called "healthy": the ladder reports
    # what it could reach, and a clean walk with six unprobed rungs is a
    # statement about Scout's reach, not about the service.
    if blind:
        text = ("No layer failed, but %d of %d rungs could not be probed — "
                "this is not a clean bill of health, it is a partial walk."
                % (len(blind), len(rows)))
    else:
        text = ("No layer failed across %d probed rungs. The fault is not on "
                "this path as Scout can observe it." % len(probed))
    return {"localised": False, "layer": "", "title": "", "vantage": "",
            "headline": "", "text": text,
            "blind_spots": [r.key for r in blind],
            "warnings": [r.key for r in warned], "probed": len(probed)}


# --------------------------------------------------------------------------- #
#  The rungs                                                                    #
# --------------------------------------------------------------------------- #
def _r(verdict: str, headline: str, evidence=None, detail: str = "") -> dict:
    return {"verdict": verdict, "headline": headline,
            "evidence": list(evidence or []), "detail": detail}


def _unavailable(capability: str) -> dict:
    return _r(UNKNOWN, "this rung could not be walked",
              [("missing", capability)],
              "The capability %r is not wired in this deployment. That is a "
              "statement about Scout, not about the service." % capability)


# --- 0. the appliance itself ------------------------------------------------ #
_HEALTH_VERDICT = {"crit": FAIL, "warn": WARN, "ok": PASS, "unknown": UNKNOWN}


def layer_device(ctx: Ctx) -> dict:
    """The box first. A licence, a firmware floor or a stale harvest poisons
    every rung below it, and a ladder that reports them last blames the pool
    for a problem the appliance already had."""
    fn = ctx.port("device_health")
    if fn is None:
        return _unavailable("device_health")
    h = fn(ctx.target.appliance) or {}
    status = str(h.get("status") or "unknown")
    reasons = h.get("reasons") or []
    ev = [("status", status),
          ("firmware", str(getattr(ctx.target.appliance, "firmware", "") or "")
           or "not recorded")]
    for r in reasons[:4]:
        ev.append((str(r.get("label") or r.get("signal") or "signal"),
                   str(r.get("text") or "")))
    if h.get("maintenance"):
        # Maintenance is not health, and it is not a fault either. Saying so
        # stops an operator diagnosing a box somebody deliberately parked.
        return _r(WARN, "the appliance is in maintenance — readings below "
                        "describe a device that is not expected to serve", ev)
    blocking = [r for r in reasons
                if str(r.get("signal")) in BLOCKING_SIGNALS
                and str(r.get("status")) == "crit"]
    if blocking:
        return _r(FAIL, "the appliance itself cannot serve: %s"
                  % ", ".join(str(r.get("label") or r.get("signal"))
                              for r in blocking), ev)
    if status in ("crit", "warn"):
        # Degraded, and SAID so — but the walk continues. A stale harvest is
        # context for every rung below; it is not a substitute for them.
        return _r(WARN, "the appliance is degraded, but nothing here stops it "
                        "serving — the walk continues", ev,
                  "Only %s grade this rung as the fault. Everything else in "
                  "this card describes what SATOM could or could not collect."
                  % " and ".join(BLOCKING_SIGNALS))
    return _r(_HEALTH_VERDICT.get(status, UNKNOWN),
              {PASS: "the appliance reports healthy",
               UNKNOWN: "the appliance's health could not be graded"}.get(
                  _HEALTH_VERDICT.get(status, UNKNOWN), "health unclear"), ev)


# --- 1. the object ---------------------------------------------------------- #
def _named(rows, name: str):
    """The row called ``name`` in ``rows``, or ``None``. Never raises."""
    for r in (rows or []):
        if isinstance(r, dict) and str(r.get("name") or "") == str(name):
            return dict(r)
    return None


def _ask_live(ctx: Ctx):
    """The appliance's OWN list of what it serves, or ``None`` for "not asked".

    ``None`` and ``[]`` are different answers and every caller must keep them
    apart: one is a question that could not be put, the other is a device that
    answered "nothing". Collapsing them turns a refused read into an empty
    appliance.
    """
    fn = ctx.port("live_objects")
    if fn is None:
        return None
    try:
        rows = fn(ctx.target.appliance)
    except Exception:                             # noqa: BLE001
        return None
    if not isinstance(rows, list):
        return None
    return [r for r in rows if isinstance(r, dict)]


def layer_policy(ctx: Ctx) -> dict:
    """Does the object exist, and is it enabled?

    THREE SOURCES, AND THEIR ORDER IS THE WHOLE POINT.

    1. the deep-harvest copy — richest, and absent for most of a real fleet
    2. **the appliance, live** — its own list of what it is serving right now
    3. SATOM's cached object list — a fact about the last successful harvest

    Live beats cache for EXISTENCE, and that is not a preference. *"The
    appliance does not list this object"* is a sentence about the appliance,
    and saying it out of a cache attributes to the device a statement the
    device was never asked to make.

    It is not hypothetical. An unlicensed FortiWeb-VM answers ``-20010`` to
    every ``cmdb`` endpoint while answering the monitor endpoints perfectly, so
    its object cache freezes at the last good sweep — and every object created
    after that moment reads as *absent*, with the full confidence of a FAIL,
    while it sits there serving traffic. Measured on this fleet: a policy built
    and verified end to end was called non-existent by a six-day-old cache.

    THE EARLIER TRAP, kept because it is the same class of error:
    ``policy_full_cached`` returns ``None`` for *"not cached"* — its own
    docstring says so — not for *"not present on the device"*.

    The three answers stay three: found, genuinely absent from a list that
    holds other things, or nothing readable at all — which is UNKNOWN, never
    absence.
    """
    fn = ctx.port("read_policy")
    if fn is None:
        return _unavailable("read_policy")
    full = fn(ctx.target.appliance, ctx.target.policy)
    read_via = "SATOM's deep-harvest copy"

    if not full:
        live = _ask_live(ctx)
        listing = ctx.port("object_list")
        cached = None
        if listing is not None:
            try:
                cached = listing(ctx.target.appliance)
            except Exception:                     # noqa: BLE001
                cached = None

        hit_live = _named(live, ctx.target.policy)
        hit_cache = _named(cached, ctx.target.policy)

        if hit_live is not None:
            full, read_via = hit_live, "the appliance, live"
        elif hit_cache is not None and live:
            # The two sources DISAGREE: the cache holds it, the appliance --
            # asked just now -- does not. Neither a silent PASS nor a FAIL is
            # honest. A FAIL would stop the ladder on a monitor view that can
            # legitimately omit an object; a silent PASS would hide that the
            # device no longer admits to it. WARN says both and keeps walking.
            ctx.state["policy_full"] = dict(hit_cache)
            ctx.state["policy_read_via"] = "SATOM's cache (contradicted live)"
            return _r(WARN, "SATOM has this %s cached, but the appliance does "
                            "not list it right now" % ctx.target.noun,
                      [("name", ctx.target.policy),
                       ("cached status", str(hit_cache.get("status")
                                             or "enable")),
                       ("objects the appliance lists now", str(len(live))),
                       ("read", "cache and live disagree")],
                      "Either it was deleted since the last harvest, or the "
                      "live view is scoped differently from the harvest. The "
                      "rungs below are walked against the cached copy, so read "
                      "them knowing the device did not confirm the object.")
        elif hit_cache is not None:
            full, read_via = hit_cache, "SATOM's cached object list"
        elif live:
            # The device itself was asked and named other things. This is the
            # only FAIL on this rung that the appliance actually authored.
            return _r(FAIL, "the appliance does not list this %s"
                      % ctx.target.noun,
                      [("name", ctx.target.policy),
                       ("objects the appliance lists now", str(len(live))),
                       ("read", "live from the appliance")],
                      "The appliance was asked just now and named %d other "
                      "objects, not this one. Either the name is wrong, or it "
                      "lives in a different ADOM from the one this workspace "
                      "is scoped to — both read identically from here, so "
                      "check the ADOM before the name." % len(live))
        elif cached:
            names = [str((r or {}).get("name") or "") for r in cached]
            return _r(FAIL, "the appliance does not list this %s"
                      % ctx.target.noun,
                      [("name", ctx.target.policy),
                       ("objects cached", str(len(names))),
                       ("read", "SATOM's cache — the appliance could not be "
                                "asked live")],
                      "The device's cached object list holds %d other objects "
                      "and not this one. Either the name is wrong, or it lives "
                      "in a different ADOM from the one this workspace is "
                      "scoped to — both read identically from here, so check "
                      "the ADOM before the name. Note this was read from the "
                      "harvest, not from the appliance: if the harvest is "
                      "stale, an object newer than it looks identical to one "
                      "that was never there." % len(names))
        elif live is None and cached is None:
            return _r(UNKNOWN, "SATOM holds no cached copy of this %s and "
                               "could not list the device's objects"
                      % ctx.target.noun, [("name", ctx.target.policy)],
                      "Absence of a cached copy is a fact about the harvest, "
                      "never about the appliance.")
        else:
            return _r(UNKNOWN, "SATOM has no objects cached for this appliance "
                               "at all, so it cannot say whether this %s exists"
                      % ctx.target.noun,
                      [("name", ctx.target.policy),
                       ("note", "a dead harvest and an empty appliance are the "
                                "same picture from here")])

    ctx.state["policy_full"] = full
    ctx.state["policy_read_via"] = read_via
    status = str(full.get("status") or "enable").strip().lower()
    ev = [("name", ctx.target.policy), ("status", status), ("read", read_via)]
    for k in ("deployment-mode", "server-pool", "vserver",
              "web-protection-profile"):
        if full.get(k):
            ev.append((k, str(full.get(k))))
    if status == "disable":
        return _r(FAIL, "the %s exists but is DISABLED" % ctx.target.noun, ev,
                  "Nothing below this rung can serve traffic while the object "
                  "is administratively down.")
    return _r(PASS, "the %s exists and is enabled" % ctx.target.noun, ev)


# --- 2. the name ------------------------------------------------------------ #
def layer_dns(ctx: Ctx) -> dict:
    """Resolve the published name. An IP literal is not a DNS failure."""
    endpoint = _endpoint(ctx)
    if endpoint is None:
        return _r(UNKNOWN, "no published front-end could be resolved for this "
                           "%s" % ctx.target.noun, [],
                  "Scout could not derive the VIP and none was typed. Set the "
                  "host and port on the form to walk the rungs below.")
    host = endpoint["host"]
    if is_ip_literal(host):
        return _r(SKIPPED, "the published front-end is an address literal — "
                           "there is no name to resolve",
                  [("address", host)])
    fn = ctx.port("resolve_name")
    if fn is None:
        return _unavailable("resolve_name")
    addrs = fn(host) or []
    ev = [("name", host)] + [("answer", a) for a in addrs[:6]]
    if not addrs:
        return _r(FAIL, "the published name does not resolve", ev,
                  "Every rung below dials an address. There is none.")
    return _r(PASS, "the published name resolves", ev)


# --- 3. the front door ------------------------------------------------------ #
def layer_frontend(ctx: Ctx) -> dict:
    """One real request to the VIP, measured phase by phase."""
    endpoint = _endpoint(ctx)
    if endpoint is None:
        return _r(UNKNOWN, "no front-end address to dial", [])
    fn = ctx.port("http")
    if fn is None:
        return _unavailable("http")
    leg = fn(endpoint["ip"], endpoint["port"], host=endpoint["host"],
             scheme=endpoint["scheme"], path=ctx.target.path,
             method=ctx.target.method, timeout=ctx.opts.timeout, leg="a")
    ctx.state["leg_a"] = leg
    timing = read_timings((leg or {}).get("timing"))
    ctx.state["timing_a"] = timing
    ev = [("dialled", "%s:%s (%s)" % (endpoint["ip"], endpoint["port"],
                                      endpoint["host"]))]
    for k, label in (("tcp_ms", "TCP"), ("tls_ms", "TLS"),
                     ("ttfb_ms", "TTFB"), ("total_ms", "total")):
        v = ((leg or {}).get("timing") or {}).get(k)
        if v is not None:
            ev.append((label, "%s ms" % v))
    if timing.get("note"):
        ev.append(("reading", timing["note"]))

    if not leg or not leg.get("ok"):
        err = str((leg or {}).get("error") or "no response")
        return _r(FAIL, "the front door did not answer", ev + [("error", err)],
                  "This is measured from %s. It does not by itself accuse the "
                  "appliance: a management-network path that fails proves "
                  "nothing about the data path." % VANTAGE_LABEL[V_SATOM])
    status = leg.get("status")
    ev.insert(1, ("status", "%s %s" % (status, leg.get("reason") or "")))
    if isinstance(status, int) and status >= 400:
        return _r(WARN, "the front door answered %s" % status, ev,
                  "An error status is not yet a localisation — the rungs below "
                  "say whether the appliance decided it or merely relayed it.")
    return _r(PASS, "the front door answered %s" % status, ev)


# --- 4. the certificate ----------------------------------------------------- #
def layer_tls(ctx: Ctx) -> dict:
    leg = ctx.state.get("leg_a") or {}
    endpoint = _endpoint(ctx)
    if endpoint and endpoint.get("scheme") != "https":
        return _r(SKIPPED, "the published front-end is plaintext", [])
    tls = leg.get("tls") or {}
    if not tls:
        return _r(UNKNOWN, "no certificate was captured", [],
                  "The handshake did not complete, or the front-end rung never "
                  "ran. Either way this is not a statement about the chain.")
    days = tls.get("days_left")
    ev = [("protocol", str(tls.get("protocol") or "")),
          ("cipher", str(tls.get("cipher") or "")),
          ("subject CN", str(tls.get("cn") or "")),
          ("issuer CN", str(tls.get("issuer_cn") or "")),
          ("days left", "unknown" if days is None else str(days))]
    if isinstance(days, int) and days <= 0:
        return _r(FAIL, "the certificate has EXPIRED", ev)
    if isinstance(days, int) and days <= CERT_WARN_DAYS:
        return _r(WARN, "the certificate expires in %d days" % days, ev,
                  "Flagged, not fatal — a service that breaks today is very "
                  "rarely broken by a certificate that breaks next week.")
    return _r(PASS, "the presented certificate is inside its validity", ev)


# --- 5. the pool ------------------------------------------------------------ #
_POOL_FAIL = {
    "no_such_policy": "the appliance does not list this object",
    "no_pool": "the object names no server pool",
    "empty_pool": "the pool has no real servers",
}


def _listed_nothing(ctx: Ctx) -> bool:
    """Did the device list ZERO objects of this kind?

    Asked through the SAME reader that produced the per-object answer. A
    different reader here would be the bug: two readers can disagree, and the
    whole point of the question is that the two answers must be comparable.
    ``None`` (the count could not be taken) is NOT "listed nothing" — it leaves
    the original answer standing rather than replacing one guess with another.
    """
    fn = ctx.port("object_count")
    if fn is None:
        return False
    try:
        n = fn(ctx.target.appliance)
    except Exception:                             # noqa: BLE001
        return False
    return n == 0


def layer_pool(ctx: Ctx) -> dict:
    """What the DEVICE says it has behind this object — read from the box."""
    fn = ctx.port("pool_targets")
    if fn is None:
        return _unavailable("pool_targets")
    try:
        rows = fn(ctx.target.appliance, ctx.target.policy) or []
    except Exception as exc:                      # noqa: BLE001
        return _r(UNKNOWN, "the pool could not be read", [],
                  "%s: %s" % (type(exc).__name__, exc))
    ctx.state["pool_rows"] = rows
    bad = [r for r in rows if r.get("error_kind")]
    for r in bad:
        kind = str(r.get("error_kind"))
        if kind == "no_such_policy" and _listed_nothing(ctx):
            # A FortiWeb that refuses REST — an unlicensed VM answers 423 on
            # every read — returns a body with no ``results`` key, and the
            # reader turns that into an EMPTY object list. "The appliance does
            # not list this object" is then indistinguishable from "the
            # appliance would not answer", and it is the more damaging of the
            # two to state confidently: it sends an operator to look for a
            # deleted policy that is sitting right there.
            return _r(UNKNOWN, "the appliance listed NO objects at all, so it "
                               "cannot be asked whether this one exists",
                      [("detail", str(r.get("error") or "")),
                       ("note", "a device refusing REST (licence, "
                                "permissions, firewall) reads exactly like an "
                                "appliance with an empty configuration")])
        if kind in _POOL_FAIL:
            return _r(FAIL, _POOL_FAIL[kind],
                      [("detail", str(r.get("error") or ""))])
        return _r(UNKNOWN, "the pool could not be read",
                  [("detail", str(r.get("error") or ""))])
    members = [r for r in rows if not r.get("error_kind")]
    enabled = [r for r in members if r.get("enabled", True)]
    ev = [("pool", str((members[0].get("pool") if members else "") or "")),
          ("members", str(len(members))),
          ("enabled", str(len(enabled)))]
    for r in members[:6]:
        ev.append(("member", "%s:%s%s" % (r.get("address"), r.get("port"),
                                          "" if r.get("enabled", True)
                                          else "  (disabled)")))
    if not members:
        return _r(FAIL, "the pool has no real servers", ev)
    if not enabled:
        return _r(FAIL, "every member of the pool is administratively "
                        "DISABLED", ev)
    return _r(PASS, "the pool has %d enabled member(s)" % len(enabled), ev)


# --- 6. the backends -------------------------------------------------------- #
def layer_backend(ctx: Ctx) -> dict:
    """Two vantages, never merged. The judgement is :mod:`backend_probe`'s."""
    fn = ctx.port("probe_backends")
    if fn is None:
        return _unavailable("probe_backends")
    targets = [r for r in (ctx.state.get("pool_rows") or [])
               if not r.get("error_kind")]
    if not targets:
        return _r(UNKNOWN, "there were no backends to probe", [])
    try:
        rows = fn(targets, use_ssh=ctx.opts.use_ssh,
                  appliance=ctx.target.appliance) or []
    except Exception as exc:                      # noqa: BLE001
        return _r(UNKNOWN, "the backends could not be probed", [],
                  "%s: %s" % (type(exc).__name__, exc))
    ctx.state["backend_rows"] = rows
    sm = ctx.port("summarise_backends")
    summary = (sm(rows) if sm else {}) or {}
    ev = [(k, str(summary.get(k))) for k in
          ("total", "reachable", "unreachable", "unknown", "disabled")
          if summary.get(k) is not None]
    if not ctx.opts.use_ssh:
        ev.append(("vantage", "SSH was not supplied — the appliance's own "
                              "vantage is reported 'not probed', not assumed"))
    for r in rows[:6]:
        appl = (r.get("appliance") or {}).get("verdict") or "not probed"
        loc = (r.get("local") or {}).get("verdict") or "not probed"
        ev.append(("%s:%s" % (r.get("address"), r.get("port")),
                   "appliance=%s · this node=%s" % (appl, loc)))
    down = int(summary.get("unreachable") or 0)
    up = int(summary.get("reachable") or 0)
    if down and not up:
        return _r(FAIL, "no backend is reachable", ev)
    if down:
        return _r(WARN, "%d backend(s) unreachable, %d still up" % (down, up),
                  ev)
    if up:
        return _r(PASS, "%d backend(s) reachable" % up, ev)
    return _r(UNKNOWN, "no vantage could test the backends", ev,
              "Every row came back 'not probed'. That is not health.")


# --- 7. the path ------------------------------------------------------------ #
def layer_path(ctx: Ctx) -> dict:
    """Firewall / reset / routing — and the ONLY rung that can tell them apart.

    Not because it tries harder, but because it asks a different witness. From
    a socket, a drop, a black hole and a silent host are one silence. The
    border wrote down what it did.
    """
    fn = ctx.port("border_logs")
    if fn is None:
        return _unavailable("border_logs")
    targets = [r for r in (ctx.state.get("pool_rows") or [])
               if not r.get("error_kind") and r.get("address")]
    if not targets:
        return _r(UNKNOWN, "there was no backend flow to look up", [])
    src = str(getattr(ctx.target.appliance, "host", "") or "")
    dst = str(targets[0].get("address") or "")
    rows, err = fn(src=src, dst=dst, minutes=ctx.opts.window_minutes)
    ev = [("flow", "%s → %s" % (src or "?", dst)),
          ("window", "last %d min" % ctx.opts.window_minutes)]
    if err:
        return _r(UNKNOWN, "the collector could not be queried",
                  ev + [("error", str(err))],
                  "A refusal is reported as a refusal. Rendering it as zero "
                  "rows would make it read as evidence the flow never "
                  "happened.")
    report = classify_path_rows(rows)
    ctx.state["path"] = report
    verdict, head = PATH_VERDICT[report["mode"]]
    ev.append(("rows", str(report["total"])))
    for k in PATH_ORDER:
        if report["counts"][k]:
            ev.append((k, str(report["counts"][k])))
    if report["mixed"]:
        ev.append(("note", "more than one action class in the window — the "
                           "worst is reported and the counts are shown"))
    for s in report["sample"][:3]:
        ev.append(("sample", "%s %s → %s:%s  action=%s  policyid=%s"
                   % (s["date"], s["srcip"], s["dstip"], s["dstport"],
                      s["action"], s["policyid"])))
    return _r(verdict, head, ev)


# --- 8. who decided --------------------------------------------------------- #
def layer_decision(ctx: Ctx) -> dict:
    """Leg A against leg C: is the appliance DECIDING or merely relaying?"""
    fn = ctx.port("http")
    diff_fn = ctx.port("diff_legs")
    leg_a = ctx.state.get("leg_a")
    if fn is None or diff_fn is None:
        return _unavailable("http/diff_legs")
    if not leg_a or not leg_a.get("ok"):
        return _r(UNKNOWN, "there is no front-door response to compare", [])
    live = [r for r in (ctx.state.get("backend_rows") or [])
            if (r.get("local") or {}).get("ok")]
    if not live:
        return _r(UNKNOWN, "no backend answered this node directly, so there "
                           "is nothing to compare the front door against", [],
                  "Leg C is a request from %s straight to the backend. Without "
                  "it, 'the WAF is deciding' would be a guess."
                  % VANTAGE_LABEL[V_SATOM])
    row = live[0]
    endpoint = _endpoint(ctx) or {}
    leg_c = fn(str(row.get("address")), int(row.get("port") or 0),
               host=endpoint.get("host") or str(row.get("address")),
               scheme="https" if row.get("ssl") else "http",
               path=ctx.target.path, method=ctx.target.method,
               timeout=ctx.opts.timeout, leg="c")
    ctx.state["leg_c"] = leg_c
    if not leg_c or not leg_c.get("ok"):
        return _r(UNKNOWN, "the direct backend request did not complete",
                  [("error", str((leg_c or {}).get("error") or ""))])
    d = diff_fn(leg_a, leg_c) or {}
    sa, sc = leg_a.get("status"), leg_c.get("status")
    ev = [("front door", str(sa)), ("backend direct", str(sc)),
          ("headers only on the front door",
           ", ".join(d.get("only_a") or []) or "none"),
          ("headers only on the backend",
           ", ".join(d.get("only_c") or []) or "none")]
    tc = read_timings(leg_c.get("timing"))
    if tc.get("note"):
        ev.append(("backend timing", tc["note"]))
    if sa != sc:
        return _r(FAIL, "the appliance is DECIDING — it answered %s where the "
                        "backend answers %s" % (sa, sc), ev,
                  "Same request, same Host, two addresses. A different status "
                  "is the appliance's own verdict, not the application's.")
    if d.get("changed") or d.get("only_a") or d.get("only_c"):
        return _r(WARN, "the appliance is TRANSFORMING — same status, "
                        "different headers", ev)
    return _r(PASS, "front door and backend agree — the appliance is not "
                    "the fault on this request", ev)


# --- 9. the WAF ------------------------------------------------------------- #
def layer_waf(ctx: Ctx) -> dict:
    """Recent blocks for this object.

    Informational by default and that is on purpose: a WAF that blocks things
    is a WAF that is working, and escalating every block would cry wolf on
    every healthy appliance in the fleet. It escalates ONLY when the front door
    itself answered 4xx in the same window — that is a correlation, not a mood.
    """
    fn = ctx.port("recent_attacks")
    if fn is None:
        return _unavailable("recent_attacks")
    try:
        rows = fn(ctx.target.appliance, ctx.target.policy,
                  ctx.opts.window_minutes) or []
    except Exception as exc:                      # noqa: BLE001
        return _r(UNKNOWN, "the attack log could not be read", [],
                  "%s: %s" % (type(exc).__name__, exc))
    ev = [("blocks in window", str(len(rows)))]
    for r in rows[:4]:
        ev.append(("entry", "%s  %s  %s" % (r.get("date") or r.get("time") or "",
                                            r.get("src") or r.get("srcip") or "",
                                            r.get("msg") or r.get("main_type")
                                            or "")))
    status = ((ctx.state.get("leg_a") or {}).get("status"))
    if rows and isinstance(status, int) and 400 <= status < 500:
        return _r(FAIL, "the WAF is blocking: the front door answered %s and "
                        "there are %d block(s) for this object in the window"
                        % (status, len(rows)), ev,
                  "Open False-Positive Triage on one of these entries to build "
                  "the exception rather than disabling the profile.")
    if rows:
        return _r(PASS, "%d block(s) in the window — normal for a WAF, and "
                        "the front door did not answer 4xx" % len(rows), ev)
    return _r(PASS, "no blocks recorded for this object in the window", ev)


# --------------------------------------------------------------------------- #
#  The ladder                                                                   #
# --------------------------------------------------------------------------- #
@dataclass
class Layer:
    key: str
    title: str
    question: str
    vantage: str
    fn: object


LADDER = (
    Layer("0", "Appliance", "is the box itself fit to serve?", V_DEVICE,
          layer_device),
    Layer("1", "Object", "does the policy exist and is it enabled?", V_DEVICE,
          layer_policy),
    Layer("2", "Name", "does the published name resolve?", V_SATOM, layer_dns),
    Layer("3", "Front door", "does the VIP answer, and which phase is slow?",
          V_SATOM, layer_frontend),
    Layer("4", "Certificate", "is the presented chain valid today?", V_SATOM,
          layer_tls),
    Layer("5", "Pool", "does the device have members behind this object?",
          V_DEVICE, layer_pool),
    Layer("6", "Backends", "can the backends be reached, and from where?",
          V_DEVICE, layer_backend),
    Layer("7", "Path", "firewall, reset, or routing?", V_EDGE, layer_path),
    Layer("8", "Decision", "is the appliance deciding or relaying?", V_SATOM,
          layer_decision),
    Layer("9", "WAF", "is the profile blocking this traffic?", V_DEVICE,
          layer_waf),
)


def _endpoint(ctx: Ctx):
    """The published front-end, resolved ONCE and cached on the context.

    Typed values win over derived ones: an operator diagnosing a service knows
    which name is failing, and a derivation that quietly overrode them would
    diagnose a different endpoint from the one in the ticket.
    """
    if "endpoint" in ctx.state:
        return ctx.state["endpoint"]
    t = ctx.target
    ep = None
    if t.hostname:
        ep = {"host": t.hostname, "ip": t.hostname,
              "port": int(t.port or (443 if t.scheme == "https" else 80)),
              "scheme": t.scheme or "https", "derived": False}
    else:
        fn = ctx.port("front_end")
        found = None
        if fn is not None:
            try:
                found = fn(t.appliance, t.policy)
            except Exception:                     # noqa: BLE001
                found = None
        if found:
            ep = {"host": str(found.get("host") or ""),
                  "ip": str(found.get("ip") or found.get("host") or ""),
                  "port": int(found.get("port") or 443),
                  "scheme": str(found.get("scheme") or "https"),
                  "derived": True}
            if not ep["host"]:
                ep = None
    if ep is not None:
        guard = ctx.port("authorise_target")
        if guard is not None:
            try:
                res = guard(ep["host"], ep["port"]) or {}
                ep["ip"] = str(res.get("ip") or ep["ip"])
            except Exception as exc:              # noqa: BLE001
                ctx.state["endpoint_error"] = str(exc)
                ep = None
    ctx.state["endpoint"] = ep
    return ep


def run(target: Target, opts: Options | None = None, ports: dict | None = None,
        ladder=LADDER) -> dict:
    """Walk the ladder. Returns the report the page and the narrator both read.

    Never raises for a fault in the thing being diagnosed. It DOES raise
    :class:`ScoutRefused` for an input this module will not act on, because a
    refusal that degrades into a rung silently changes what was measured.
    """
    if target.appliance is None:
        raise ScoutRefused("Scout needs an appliance to diagnose.")
    if target.kind not in SUPPORTED_KINDS:
        raise ScoutRefused(
            "Scout walks a %s. %r is not one of them — the ladder's rungs read "
            "objects this product does not have, and a partial walk that said "
            "'pass' would be worse than no walk."
            % (" or a ".join(OBJECT_NOUN.values()), target.kind or "unknown"))
    if not str(target.policy or "").strip():
        raise ScoutRefused("Scout needs the name of the %s to diagnose."
                           % target.noun)
    target.method = assert_safe_method(target.method)

    opts = (opts or Options()).clamped()
    ctx = Ctx(target=target, opts=opts, ports=dict(ports or {}))

    results: list[LayerResult] = []
    stopped = False
    for spec in ladder:
        base = LayerResult(key=spec.key, title=spec.title,
                           question=spec.question, vantage=spec.vantage)
        if stopped:
            # NOT "pass". A rung under a localised fault was never walked, and
            # a green badge there is how a report gets read backwards.
            base.verdict = SKIPPED
            base.headline = "not walked — the fault was already localised above"
            results.append(base)
            continue
        try:
            out = spec.fn(ctx) or {}
        except Exception as exc:                  # noqa: BLE001
            # Our bug is not their outage.
            out = _r(UNKNOWN, "this rung raised while being walked",
                     [("error", "%s: %s" % (type(exc).__name__, exc))],
                     "Reported as 'could not look'. Rendering a Scout defect "
                     "as a customer fault sends someone to reboot a healthy "
                     "appliance.")
        base.verdict = str(out.get("verdict") or UNKNOWN)
        base.headline = str(out.get("headline") or "")
        base.evidence = list(out.get("evidence") or [])
        base.detail = str(out.get("detail") or "")
        results.append(base)
        if base.verdict == FAIL:
            stopped = True

    verdict = summarise(results)
    return {
        "target": {"appliance": str(getattr(target.appliance, "name", "") or ""),
                   "appliance_id": getattr(target.appliance, "id", None),
                   "kind": target.kind, "noun": target.noun,
                   "policy": target.policy, "path": target.path,
                   "method": target.method},
        "endpoint": ctx.state.get("endpoint"),
        "endpoint_error": ctx.state.get("endpoint_error", ""),
        "options": {"use_ssh": opts.use_ssh, "timeout": opts.timeout,
                    "window_minutes": opts.window_minutes,
                    "analyzer": str(getattr(opts.analyzer, "name", "") or "")},
        "layers": [r.as_dict() for r in results],
        "verdict": verdict,
        "timing": ctx.state.get("timing_a") or {},
    }


# --------------------------------------------------------------------------- #
#  Wiring — the ONLY place that knows which module owns which question          #
# --------------------------------------------------------------------------- #
def default_ports(*, analyzer=None, faz_adom: str = "root", faz_devid: str = "",
                  faz_vdom: str = "", faz_limit=None, faz_timeout=None) -> dict:
    """Bind the rungs to the services that already own their judgements.

    Every import is local. The ladder must stay importable — and testable —
    without an application context, and a module-level import of the client
    factory would drag half the product into a unit test of a pure classifier.

    Nothing here *decides* anything. Each entry is an adapter of a shape, and
    the moment one of them starts interpreting a result, this product has two
    authors of that interpretation.
    """
    def _client(appliance):
        from ..clients import client_for       # the one kind→client mapping
        return client_for(appliance)

    def _device_health(appliance):
        from . import device_health
        return device_health.collect_for(appliance)

    def _read_policy(appliance, name):
        """The object's OWN fields as a flat dict, or ``None``.

        ``policy_full_cached`` returns ``(data, cr_entries, meta)`` and nests
        the policy under ``data["policy"]``. The first version of this adapter
        handed the tuple straight to the rung, which then called ``.get`` on it
        — and because a rung that raises is reported UNKNOWN by design, the
        breakage rendered as "could not look" on a live device rather than as a
        crash. Only walking it against a real appliance showed it.
        """
        from . import read_layer
        out = read_layer.policy_full_cached(getattr(appliance, "id", None), name)
        data = out[0] if isinstance(out, tuple) else out
        if not data:
            return None
        return dict(data.get("policy") or data)

    def _resolve_name(host):
        from . import dns_tool
        out = []
        for srv in dns_tool.dns_servers() or []:
            for line in dns_tool.dig_lookup(host, srv.get("ip") or srv.get("server") or ""):
                line = str(line or "").strip()
                if line and line not in out:
                    out.append(line)
            if out:
                break
        return out

    def _authorise(host, port):
        from . import net_guard
        return net_guard.resolve_target(host, int(port), mode=net_guard.MODE_FREE)

    def _live_rows(appliance):
        """What the appliance says it is serving RIGHT NOW, or ``None``.

        Deliberately a MONITOR read and not a configuration read. On an
        unlicensed FortiWeb-VM every ``cmdb`` endpoint answers ``-20010`` while
        the monitor endpoints answer normally — so this is the only source that
        is both live and available there, and therefore the only one that can
        honestly carry the sentence "the appliance does not list this object".

        ``None`` means the question could not be put. It never means "none".
        """
        if str(getattr(appliance, "kind", "") or "") != "fortiweb":
            return None
        try:
            from ..clients import client_for
            out = client_for(appliance).policy_status()
        except Exception:                         # noqa: BLE001
            return None
        rows, err = ((out[0], out[1]) if isinstance(out, tuple) and len(out) > 1
                     else (out, None))
        if not isinstance(rows, list):
            return None
        if err and not rows:
            # An error with nothing to show is a question that failed, not an
            # appliance with no policies.
            return None
        return [r for r in rows if isinstance(r, dict)]

    def _live_objects(appliance):
        """Rung 1's live source. Names normalised, nothing interpreted."""
        rows = _live_rows(appliance)
        if rows is None:
            return None
        out = []
        for r in rows:
            name = str(r.get("name") or r.get("_id") or "").strip()
            if not name:
                continue
            row = dict(r)
            row["name"] = name
            out.append(row)
        return out

    def _live_front_end(appliance, policy):
        """The VIP the appliance says it is listening on, or ``None``.

        The monitor row carries ``vserver`` as an address WITH ITS MASK and a
        trailing space (``"192.0.2.251/24 "``). Dialling that verbatim fails
        with a name-resolution error that reads like a DNS fault — the wrong
        rung entirely — so it is split here, at the edge, and never later.
        """
        for r in (_live_objects(appliance) or []):
            if str(r.get("name") or "") != str(policy):
                continue
            host = str(r.get("vserver") or "").strip().split("/")[0].strip()
            if not host:
                return None
            proto = str(r.get("protocol") or "").strip().upper()
            scheme = "https" if proto.startswith("HTTPS") else "http"
            try:
                port = int(str(r.get("httpPort") or "").strip() or 0)
            except (TypeError, ValueError):
                port = 0
            if not port:
                port = 443 if scheme == "https" else 80
            return {"host": host, "port": port, "scheme": scheme}
        return None

    def _front_end(appliance, policy):
        """The published front-end of one object, per product.

        The branch is here and nowhere else. It is a branch over which SERVICE
        owns the resolution, not over which client to build — the client still
        comes from :func:`client_for`, which stays the single kind→client map.
        """
        kind = str(getattr(appliance, "kind", "") or "")
        # THE CONFIGURATION READ IS ALLOWED TO FAIL, and on a licence-refused
        # appliance it always does. Letting it raise out of here loses the live
        # fallback below and the operator is told there is no front door to
        # dial — a fact about the read, dressed as a fact about the service.
        targets = None
        try:
            client = _client(appliance)
            if kind == "fortiadc":
                from . import adc_ops
                targets = adc_ops.resolve_targets(client)
            else:
                from . import service_probe
                targets = service_probe.resolve_targets_from_client(client)
        except Exception:                         # noqa: BLE001
            targets = None
        for t in targets or []:
            if str(getattr(t, "policy", "")) == str(policy):
                return {"host": getattr(t, "host", ""),
                        "port": getattr(t, "port", None) or 443,
                        "scheme": getattr(t, "scheme", "https")}
        # The configuration read found nothing. Ask the appliance what it is
        # actually listening on before telling the operator there is no front
        # door to dial — on a licence-refused device the first read returns
        # empty for every object, and "no VIP" would be a fact about the read.
        if kind != "fortiadc":
            return _live_front_end(appliance, policy)
        return None

    def _http(ip, port, *, host, scheme, path, method, timeout, leg):
        from . import txn_trace
        return txn_trace.send(ip, int(port), host=host, path=path,
                              scheme=scheme, method=method, timeout=timeout,
                              leg=leg)

    def _diff_legs(a, c):
        from . import txn_trace
        return txn_trace.diff(a, c)

    def _object_list(appliance):
        """The device's cached object rows, or ``None`` if they cannot be read.

        ``None`` and ``[]`` are different answers and the rung treats them so:
        one is "we could not look", the other is "we looked and the harvest is
        empty". Collapsing them would turn a missing reader into an empty
        appliance. FortiADC returns ``None`` deliberately — the logical name of
        its object section is not settled here, and guessing one would produce
        an empty list that reads as a device with no virtual servers.
        """
        if str(getattr(appliance, "kind", "") or "") == "fortiadc":
            return None
        from . import read_layer
        try:
            out = read_layer.read_objects(getattr(appliance, "id", None),
                                          "server_policy")
        except Exception:                         # noqa: BLE001
            return None
        rows = out[0] if isinstance(out, tuple) else out
        return [r if isinstance(r, dict) else (getattr(r, "payload", {}) or {})
                for r in (rows or [])]

    def _object_count(appliance):
        """How many objects of this kind the device lists AT ALL, or ``None``.

        Deliberately the same reader :func:`dst_pool_targets` uses. Reading the
        list a second way would produce two answers that cannot be compared,
        and comparing them is the entire purpose.
        """
        from . import backend_probe
        client = _client(appliance)
        kind = str(getattr(appliance, "kind", "") or "")
        try:
            if kind == "fortiadc":
                from . import adc_ops
                return len(adc_ops.inspect_all(client) or {})
            return len(backend_probe._rows(client, "server-policy/policy"))
        except Exception:                         # noqa: BLE001
            return None

    def _pool_targets(appliance, policy):
        from . import backend_probe
        return backend_probe.dst_pool_targets(_client(appliance), [policy])

    def _probe_backends(targets, *, use_ssh, appliance):
        from . import backend_probe
        session = None
        if use_ssh:
            # ``connect()``, not ``open()``. The first version called a method
            # this class does not have, so EVERY device-vantage probe raised
            # AttributeError -- and because a rung that raises is reported
            # UNKNOWN by design, it rendered as "the backends could not be
            # probed" instead of as a crash. The rule that keeps our bugs from
            # being read as their outage also keeps them from being read at
            # all; only probing a live appliance showed it. Every other caller
            # in this product uses ``connect()`` or the context manager.
            from . import ssh_ops
            session = ssh_ops.FortiWebReadonlySSH(appliance, timeout=20.0)
            session.connect()
        try:
            return backend_probe.probe_targets(targets, ssh_session=session)
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:                 # noqa: BLE001
                    pass

    def _summarise_backends(rows):
        from . import backend_probe
        return backend_probe.summarise(rows)

    def _border_logs(*, src, dst, minutes):
        """The border's record of one flow. ``(rows, error)`` — never ``[]``
        for a failure, because absence and refusal are opposite findings."""
        from . import faz_logs
        ok, why = faz_logs.reachable(analyzer)
        if not ok:
            return [], why
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        parts = []
        if src:
            parts.append('srcip="%s"' % src)
        if dst:
            parts.append('dstip="%s"' % dst)
        # None means "whatever faz_logs ships with", not zero: a falsy size
        # passed through would ask the analyzer for no rows and the rung would
        # then report UNKNOWN for a border that answered perfectly.
        return faz_logs.search(
            analyzer, adom=faz_adom,
            devices=faz_logs.device_selector(faz_devid, faz_vdom),
            log_filter=" and ".join(parts), logtype="traffic",
            start=now - timedelta(minutes=int(minutes)), end=now,
            limit=(faz_limit or faz_logs.DEFAULT_LIMIT),
            timeout=(faz_timeout or faz_logs.DEFAULT_TIMEOUT))

    def _recent_attacks(appliance, policy, minutes):
        from . import attack_log
        rows = attack_log.recent(appliance, limit=50) or []
        want = str(policy or "")
        out = [r for r in rows
               if not want or str(r.get("policy") or "") == want]
        return out

    return {
        "device_health": _device_health,
        "read_policy": _read_policy,
        "resolve_name": _resolve_name,
        "authorise_target": _authorise,
        "front_end": _front_end,
        "http": _http,
        "diff_legs": _diff_legs,
        "live_objects": _live_objects,
        "object_list": _object_list,
        "object_count": _object_count,
        "pool_targets": _pool_targets,
        "probe_backends": _probe_backends,
        "summarise_backends": _summarise_backends,
        "border_logs": _border_logs,
        "recent_attacks": _recent_attacks,
    }


__all__ = [
    "PASS", "FAIL", "WARN", "UNKNOWN", "SKIPPED", "SEVERITY", "BLOCKING_SIGNALS",
    "V_SATOM", "V_DEVICE", "V_EDGE", "VANTAGE_LABEL",
    "OBJECT_NOUN", "SUPPORTED_KINDS", "SAFE_METHODS",
    "ScoutRefused", "Target", "Options", "LayerResult", "Ctx",
    "is_ip_literal", "assert_safe_method", "read_timings",
    "classify_path_rows", "PATH_VERDICT", "PATH_ORDER", "summarise",
    "Layer", "LADDER", "run", "default_ports",
]
