"""Scout configuration — what an operator may set, and what they may only read.

TWO catalogs, and the split is the whole design of this file.

:data:`SPEC` is the SITE. Where to look and how long to wait: the default walk
window, the FortiAnalyzer ADOM and device selector the border rung asks, the two
timeouts. Every entry is read back through :func:`walk_defaults` by
``app.views.scout`` — the form is generated from the same catalog the reader
indexes, because this product has already shipped a setting that appeared in a
form and was never read (``metrics.vm_url``, unconfigurable for months behind a
wrong accessor name and a broad ``except``). A knob nothing reads is worse than
an absent knob: the operator changes it, the behaviour does not change, and
nothing anywhere reports that.

:func:`criteria` is the JUDGEMENT, and it is read-only on purpose. Every value
in it is what Scout uses to decide that a phase is *the slow one*, that an
appliance is *unfit to serve*, or that the border *denied* rather than *reset*.
Two reasons it is not a form:

1. An editable threshold makes a SECOND AUTHOR of the verdict. Lower the
   dominant-phase share from 0.60 to 0.30 and Scout starts naming phases that
   are not dominant — with the report still reading exactly like one produced
   under the shipped rule. ``backend_probe.dst_pool_targets`` is documented as
   the single author of "what are this policy's backends" for the same reason.
2. A verdict is archived. Read months later, a report emitted under thresholds
   that have since been edited is not reproducible, and nothing on it says so.
   Editing these would therefore have to come WITH stamping them onto every
   report — a bigger change than a settings pane, and a different decision.

So the criteria are DISPLAYED, with their value, their source symbol and what
breaks at each extreme. Displayed and never re-typed: every number below is
read off the live module attribute, so a constant changed in the engine changes
this page in the same commit. A hand-copied number here would be the same class
of defect as the one this whole file exists to prevent — an explanation that
nothing keeps in agreement with the thing it explains.
"""
from __future__ import annotations

from . import faz_logs
from . import scout_ladder as sl
from . import settings_store

PREFIX = "scout."

#: Display order of the settings cards.
GROUPS = (
    ("walk", "Walk defaults"),
    ("border", "Border correlation (FortiAnalyzer)"),
)

#: One entry per SITE setting. ``kind`` drives the widget and the coercion.
#:
#: Defaults and bounds are taken from the engine's own constants rather than
#: re-typed: a form whose default silently disagrees with the code's default is
#: a page that documents a product nobody is running.
SPEC: list[dict] = [
    # ── walk ────────────────────────────────────────────────────────────────
    {"key": "window_minutes", "kind": "int", "group": "walk",
     "default": sl.DEFAULT_WINDOW_MIN, "min": 1, "max": sl.MAX_WINDOW_MIN,
     "label": "Default look-back window (minutes)",
     "help": "Pre-filled into the walk form. How far back rung 7 asks the "
             "border for flows, and how far back rung 9 reads attack log.",
     "hint": "The window the walk form is pre-filled with, and therefore the "
             "one an operator in a hurry actually uses. Too short and the "
             "border rung finds no flows for an event that happened eleven "
             "minutes ago — which Scout reports as UNKNOWN, never as 'the path "
             "was clean', but the operator still has to notice and widen it. "
             "Too long and every walk drags a large log query across the "
             "analyzer. The ceiling is the engine's own MAX_WINDOW_MIN and is "
             "enforced again in Options.clamped(), so a hand-typed value can "
             "never exceed it."},
    {"key": "probe_timeout", "kind": "float", "group": "walk",
     "default": 8.0, "min": 1.0, "max": 30.0,
     "label": "Front-door probe timeout (seconds)",
     "help": "Per-request ceiling for the HTTP probe on rungs 3 and 8.",
     "hint": "Ceiling on ONE request from this node to the published front "
             "door. It is a diagnostic, so the number is a judgement about "
             "patience, not about correctness: set it under a slow backend's "
             "real response time and Scout reports a timeout for a service "
             "that was merely slow — a wrong layer, not a wrong number. The "
             "engine clamps it to 1–30 s in Options.clamped() whatever is "
             "stored here."},
    {"key": "use_ssh", "kind": "bool", "group": "walk", "default": False,
     "label": "Probe from the appliance by default",
     "help": "Pre-ticks the SSH box. Without it rung 6 has only this node's "
             "vantage and says so; it never assumes the appliance's.",
     "hint": "Pre-ticks 'probe from the appliance too' on the walk form. That "
             "second vantage is the only thing that separates 'SATOM cannot "
             "reach the backend' from 'the WAF cannot reach the backend' — "
             "this node sits on the management network and its path is NOT the "
             "appliance's path. Off, rung 6 reports the appliance vantage as "
             "*not probed* and never merges the two into one word. On, every "
             "walk opens an SSH session to the device, which is real load and "
             "a real audit entry, so it is a site decision rather than a "
             "default."},

    # ── border ──────────────────────────────────────────────────────────────
    {"key": "faz_adom", "kind": "str", "group": "border", "default": "root",
     "label": "Default FortiAnalyzer ADOM",
     "help": "Pre-filled ADOM for the border query. A wrong ADOM returns zero "
             "rows, which Scout reports as UNKNOWN — never as a clean path.",
     "hint": "The ADOM the border rung searches. Getting it wrong does not "
             "produce an error: it produces ZERO ROWS, and zero rows from the "
             "wrong ADOM look identical to zero rows because nothing happened. "
             "That is exactly why rung 7 refuses to read an empty result as "
             "'the path was clean' and reports UNKNOWN instead — but the "
             "operator still spends the walk on a question nobody answered. "
             "Set this to the ADOM your border devices actually log into."},
    {"key": "faz_devid", "kind": "str", "group": "border", "default": "",
     "label": "Default device id (devid)",
     "help": "Narrows the border query to one logging device. Blank asks all "
             "of them.",
     "hint": "Restricts the border search to one device by its FortiAnalyzer "
             "devid. Blank searches every device in the ADOM, which is correct "
             "when you do not yet know which firewall the traffic crossed and "
             "expensive when you do. Same failure shape as the ADOM: a devid "
             "that does not exist yields zero rows, and zero rows is UNKNOWN, "
             "not innocence."},
    {"key": "faz_vdom", "kind": "str", "group": "border", "default": "",
     "label": "Default VDOM",
     "help": "Combined with the devid into the device selector. Blank means "
             "no VDOM restriction.",
     "hint": "Paired with the devid by faz_logs.device_selector to build the "
             "selector the search sends. Blank leaves the query unrestricted "
             "by VDOM. Only meaningful on a device that has VDOMs enabled; on "
             "one that does not, a value here narrows the search to nothing."},
    {"key": "faz_limit", "kind": "int", "group": "border",
     "default": faz_logs.DEFAULT_LIMIT, "min": 1, "max": faz_logs.MAX_LIMIT,
     "label": "Rows per border query",
     "help": "Upper bound on rows one border query returns. Truncation changes "
             "which verdict wins, so this is not a display limit.",
     "hint": "Ceiling on rows returned by ONE border search. It is not a "
             "display limit: rung 7 picks its verdict by scanning the rows it "
             "got, in the order deny > reset > timeout > accept, so a truncated "
             "result can hand back 'accept' for a flow that was also denied "
             "later in the same window. Raise it when a busy window keeps "
             "hitting the cap; the engine clamps to faz_logs.MAX_LIMIT."},
    {"key": "faz_timeout", "kind": "float", "group": "border",
     "default": faz_logs.DEFAULT_TIMEOUT, "min": 1.0, "max": 120.0,
     "label": "Border query timeout (seconds)",
     "help": "How long to wait for the analyzer's search to finish. A timeout "
             "is reported as UNKNOWN, never as an empty path.",
     "hint": "How long the border rung waits for the analyzer to run its "
             "search. A FortiAnalyzer logsearch is asynchronous — it is "
             "submitted, then polled — so this covers the whole exchange and "
             "not one round trip. Expiring is reported as UNKNOWN: 'we did not "
             "get an answer' is not the same statement as 'there was no "
             "traffic', and rung 7 is the one rung where confusing the two "
             "would exonerate a firewall."},
]

_BY_KEY = {s["key"]: s for s in SPEC}


# ---------------------------------------------------------------------------
# coercion / access
# ---------------------------------------------------------------------------
def _coerce(spec: dict, raw):
    """Stored string -> typed value, with the spec's default on anything bad.

    A stored value that no longer parses (a hand-edited row, a kind changed in
    a later release) must not take a page down: it falls back to the shipped
    default, which is the same value a fresh install runs on.
    """
    kind = spec["kind"]
    if raw is None:
        return spec["default"]
    if kind == "bool":
        return str(raw).strip().lower() in ("1", "true", "yes", "on")
    if kind == "int":
        try:
            return _clamp(int(str(raw).strip()), spec)
        except (TypeError, ValueError):
            return spec["default"]
    if kind == "float":
        try:
            return _clamp(float(str(raw).strip()), spec)
        except (TypeError, ValueError):
            return spec["default"]
    return str(raw).strip()


def _clamp(v, spec):
    lo, hi = spec.get("min"), spec.get("max")
    if lo is not None and v < lo:
        return lo
    if hi is not None and v > hi:
        return hi
    return v


def get(key: str):
    """One setting, coerced and clamped. An unknown key RAISES — a typo has to
    fail here rather than hand back a default that looks configured."""
    spec = _BY_KEY.get(key)
    if spec is None:
        raise KeyError("unknown scout setting %r" % key)
    return _coerce(spec, settings_store.get_str(PREFIX + key, None))


def set_value(key: str, value) -> None:
    spec = _BY_KEY.get(key)
    if spec is None:
        raise KeyError("unknown scout setting %r" % key)
    if spec["kind"] == "bool":
        value = "1" if _coerce(spec, value) else "0"
    else:
        value = str(_coerce(spec, value))
    settings_store.set_str(PREFIX + key, value)


def all_values() -> dict:
    return {s["key"]: get(s["key"]) for s in SPEC}


def form_groups() -> list:
    """The render model: [(group_key, label, [spec+value, ...]), ...]."""
    values = all_values()
    out = []
    for gkey, glabel in GROUPS:
        rows = [dict(s, value=values[s["key"]])
                for s in SPEC if s["group"] == gkey]
        if rows:
            out.append((gkey, glabel, rows))
    return out


def walk_defaults() -> dict:
    """Everything the Scout page needs, in ONE call.

    One call site on purpose: a page that reads six settings through six
    accessors is a page where the seventh gets forgotten, and a forgotten
    accessor is the unread-knob failure this module is built against. Degrades
    to the shipped defaults rather than raising — Scout is opened during an
    incident, and a settings table that cannot be read is not a reason to deny
    an operator the ladder.
    """
    try:
        return all_values()
    except Exception:                                       # noqa: BLE001
        return {s["key"]: s["default"] for s in SPEC}


# ---------------------------------------------------------------------------
# criteria — read-only, and READ OFF THE ENGINE
# ---------------------------------------------------------------------------
def _fmt(value, ordered: bool = False) -> str:
    """Sequences are drawn as a PRECEDENCE only when they are one.

    ``PATH_ORDER`` and ``SEVERITY`` are resolution orders and the arrows carry
    that meaning. ``SAFE_METHODS`` and ``BLOCKING_SIGNALS`` are sets — drawing
    them with arrows tells the reader that GET outranks HEAD, or that a
    capacity signal is checked before a probe signal. Neither is true, and an
    invented ordering is the kind of wrong that a reader has no way to detect.
    """
    if isinstance(value, (tuple, list)):
        return (" > " if ordered else ", ").join(str(v) for v in value)
    return str(value)


#: The judgement constants, as
#: (group, label, symbol, accessor, ordered, why).  ``ordered`` says
#: whether the value is a PRECEDENCE; see :func:`_fmt`.
#: ``accessor`` is a callable so the value is read at RENDER time from the live
#: module — the one property that makes this page incapable of going stale.
_CRITERIA: tuple = (
    ("timing", "Dominant-phase share",
     "scout_ladder.DOMINANT_SHARE", lambda: sl.DOMINANT_SHARE, False,
     "A phase is named as the slow one only when it is at least this much of "
     "the total. Lower it and Scout starts blaming phases that were not "
     "dominant; raise it and a genuinely slow handshake goes unnamed."),
    ("timing", "Dominant-phase floor (ms)",
     "scout_ladder.DOMINANT_FLOOR_MS", lambda: sl.DOMINANT_FLOOR_MS, False,
     "The share is not enough on its own. A TTFB of 10 ms that is 77 % of a "
     "13 ms request is not 'the backend thinking' — naming it sends someone "
     "to profile an application that answered instantly. Both tests must pass."),
    ("health", "Signals that BLOCK the walk",
     "scout_ladder.BLOCKING_SIGNALS", lambda: sl.BLOCKING_SIGNALS, False,
     "Only these mean the appliance cannot serve. Every other unhealthy "
     "signal — a stale harvest, a cold cache — is SATOM failing to read the "
     "device, not the device failing to work, and it degrades the rung to WARN "
     "so the walk continues. Treating harvest as blocking stopped every walk "
     "in this fleet at rung 0."),
    ("health", "Certificate warning horizon (days)",
     "scout_ladder.CERT_WARN_DAYS", lambda: sl.CERT_WARN_DAYS, False,
     "A chain expiring inside this many days is a WARN, not a FAIL: it is "
     "still serving today, and reporting it as the broken layer hides the one "
     "that actually is."),
    ("path", "Border verdict precedence",
     "scout_ladder.PATH_ORDER", lambda: sl.PATH_ORDER, True,
     "The order rung 7 resolves conflicting border rows in. A window that "
     "holds both a deny and an accept describes a path that was blocked at "
     "least once, and that is the finding."),
    ("path", "Rows per border query (ceiling)",
     "faz_logs.MAX_LIMIT", lambda: faz_logs.MAX_LIMIT, False,
     "Hard ceiling on the editable rows-per-query above. Truncation can change "
     "which verdict wins, so the cap is part of the judgement and not of the "
     "display."),
    ("safety", "Methods Scout will send",
     "scout_ladder.SAFE_METHODS", lambda: sl.SAFE_METHODS, False,
     "Scout is READ ONLY. assert_safe_method rejects anything else at the "
     "entrance, so a walk can never mutate the service it is diagnosing."),
    ("safety", "Verdict precedence (worst first)",
     "scout_ladder.SEVERITY", lambda: sl.SEVERITY, True,
     "How the walk's own verdict is chosen from ten rungs. UNKNOWN outranks "
     "PASS deliberately: 'we could not look' is not health, and a walk with "
     "blind rungs says so instead of reporting a clean bill."),
    ("safety", "Maximum look-back window (minutes)",
     "scout_ladder.MAX_WINDOW_MIN", lambda: sl.MAX_WINDOW_MIN, False,
     "Hard ceiling on the editable window above, re-applied in "
     "Options.clamped() so a value posted straight at the endpoint cannot "
     "exceed it either."),
)

#: Display order and headings of the criteria cards.
CRITERIA_GROUPS = (
    ("timing", "Which phase is blamed"),
    ("health", "When a layer counts as broken"),
    ("path", "How the border is read"),
    ("safety", "Limits and precedence"),
)


def criteria() -> list:
    """[(group_key, label, [{label, symbol, value, why}, ...]), ...]."""
    rows = [{"group": g, "label": lbl, "symbol": sym,
             "value": _fmt(fn(), ordered), "ordered": ordered, "why": why}
            for g, lbl, sym, fn, ordered, why in _CRITERIA]
    out = []
    for gkey, glabel in CRITERIA_GROUPS:
        got = [r for r in rows if r["group"] == gkey]
        if got:
            out.append((gkey, glabel, got))
    return out


# ---------------------------------------------------------------------------
# the walk form's own help
# ---------------------------------------------------------------------------
#: One entry per control on the WALK form (``/scout/``), keyed by the input's
#: ``name`` attribute, rendered as the "?" beside that control's label.
#:
#: WHY THIS IS NOT :data:`SPEC`'s ``help``, which is the obvious move and the
#: wrong one: SPEC describes a DEFAULT. Its prose is written from the settings
#: pane's point of view -- "Pre-filled into the walk form", "Pre-ticks the SSH
#: box" -- and the same sentence read ON the walk form tells the operator that
#: the box they are typing in pre-fills the box they are typing in. The two
#: catalogs answer different questions: SPEC answers "what does this site
#: default do", this answers "what do I put here, and what does it change".
#:
#: They are LINKED rather than duplicated. ``default_from`` names the SPEC key
#: whose stored value pre-fills the control, and :func:`walk_help` appends the
#: one sentence that says so -- composed once here, not typed into five
#: entries that would then have to be kept in agreement by hand.
#:
#: ``label`` is the control's on-screen label. It is repeated here on purpose
#: and a guard asserts it still matches the template: a hint that names a field
#: by a caption the page stopped using is help for a product nobody is running.
WALK_HELP: dict[str, dict] = {
    "appliance_id": {
        "label": "Appliance",
        "text": "The FortiWeb or FortiADC that publishes the service. Only "
                "devices this workspace's ADOM can see are listed, and Scout "
                "never borrows the workspace's currently selected device: a "
                "walk against the wrong box reads exactly like a walk against "
                "the right one. Rungs 0, 1, 5, 6 and 9 all ask THIS device.",
    },
    "policy": {
        "label": "Server policy / virtual server",
        "text": "The object's exact name as the appliance spells it -- "
                "pol-root-erp -- not the site's hostname and not the pool's "
                "name. Rung 1 asks the device live and falls back to SATOM's "
                "harvest, and it reports which one answered. A name that "
                "exists in a DIFFERENT ADOM reads identically to a name that "
                "does not exist, so check the ADOM before you doubt the "
                "spelling. This is also what the front door is derived from "
                "when Published host is left blank.",
    },
    "window_minutes": {
        "label": "Log window (min)",
        "default_from": "window_minutes",
        "text": "How far back rung 7 asks the border for flows and rung 9 "
                "reads attack log. Minutes, 1 to %(max)s -- a larger number is "
                "clamped, not obeyed. Too short and an event from eleven "
                "minutes ago falls outside it: Scout reports UNKNOWN, never "
                "'the path was clean', but you still have to notice and widen "
                "it.",
    },
    "use_ssh": {
        "label": "Use SSH",
        "default_from": "use_ssh",
        "text": "Ticked, rung 6 probes the backends FROM the appliance as "
                "well, over an SSH session to the device. That second vantage "
                "is the only thing separating 'SATOM cannot reach the backend' "
                "from 'the WAF cannot reach the backend' -- this node sits on "
                "the management network and its path is not the appliance's. "
                "It costs a real login and a real audit entry on every walk.",
    },
    "hostname": {
        "label": "Published host",
        "text": "The name or address of the front door to dial. Leave it "
                "blank and Scout derives it from the object's VIP on the "
                "device, which is the normal case. Type one when the ticket "
                "names a host the device's own configuration does not. A typed "
                "value wins over the derived one for every rung below it.",
    },
    "port": {
        "label": "Port",
        "text": "TCP port of the front door. It is read ONLY when you also "
                "type a Published host: with the host left blank the port "
                "arrives from the device's VIP together with it, and anything "
                "typed here is ignored. Blank alongside a typed host means 443 "
                "for https and 80 for http.",
    },
    "scheme": {
        "label": "Scheme",
        "text": "http or https for the front-door request. Like the port it is "
                "read only when you type a Published host; when the front door "
                "is derived, the scheme arrives off the device with it. It "
                "also decides whether rung 4 has a certificate to inspect at "
                "all -- a plaintext front door skips that rung rather than "
                "failing it.",
    },
    "path": {
        "label": "Path",
        "text": "The path requested on rung 3 and again on rung 8, for "
                "example / or /healthz. Unlike host, port and scheme this is "
                "always used, derived front door or not. Scout reads the phase "
                "timings of this exact request, so a path that is expensive to "
                "render measures the page rather than the service.",
    },
    "analyzer_id": {
        "label": "FortiAnalyzer (layer 7)",
        "text": "Which collector rung 7 asks what the border did with these "
                "flows. Firewall drop, connection reset and a routing black "
                "hole are ONE silence at a socket; only the border wrote down "
                "which it was. Leave this empty and rung 7 reports 'could not "
                "look' -- it never reports a clean path. Retired collectors "
                "are still listed, with the reason.",
    },
    "faz_adom": {
        "label": "FAZ ADOM",
        "default_from": "faz_adom",
        "text": "The FortiAnalyzer ADOM the border query searches, usually "
                "root. A wrong ADOM does not raise an error: it returns zero "
                "rows, and zero rows from the wrong ADOM look identical to "
                "zero rows because nothing happened. Rung 7 reports that as "
                "UNKNOWN rather than as innocence.",
    },
    "faz_devid": {
        "label": "FortiGate devid",
        "default_from": "faz_devid",
        "text": "Narrows the border query to one logging device, by the devid "
                "FortiAnalyzer knows it as. Blank asks every device in the "
                "ADOM -- right when you do not yet know which firewall the "
                "traffic crossed, wasteful when you do. A devid that does not "
                "exist yields zero rows, and zero rows is UNKNOWN, not "
                "innocence.",
    },
    "faz_vdom": {
        "label": "VDOM",
        "default_from": "faz_vdom",
        "text": "Paired with the devid by faz_logs.device_selector to build "
                "the selector the search sends. Blank leaves the query "
                "unrestricted by VDOM. Only meaningful on a device that has "
                "VDOMs enabled; on one that does not, a value here narrows the "
                "search to nothing.",
    },
}

#: Appended to any entry that names a ``default_from``. One sentence, one
#: place: five copies of it is five things to keep true.
DEFAULT_SENTENCE = (" Pre-filled from Settings %s Scout, where the site's "
                    "default for this lives." % "\u2192")


def walk_help() -> dict:
    """``{field name: finished tooltip text}`` for the walk form.

    Degrades to the bare texts rather than raising: this is the help on a page
    an operator opens during an incident, and a catalog that cannot be
    finished is not a reason to deny them the ladder -- the same rule
    :func:`walk_defaults` runs under.
    """
    out = {}
    for key, row in WALK_HELP.items():
        text = row["text"]
        if "%(max)s" in text:
            # The fallback must NOT re-read the attribute that just failed.
            # Written that way it raised again, outside the guard, and took
            # the page down for the one reason this function exists to
            # survive; the degradation test is what caught it.
            try:
                text = text % {"max": sl.MAX_WINDOW_MIN}
            except Exception:                                   # noqa: BLE001
                text = text.replace("%(max)s", "the engine ceiling")
        if row.get("default_from"):
            text += DEFAULT_SENTENCE
        out[key] = text
    return out


__all__ = ["PREFIX", "GROUPS", "SPEC", "CRITERIA_GROUPS", "get", "set_value",
           "all_values", "form_groups", "walk_defaults", "criteria",
           "WALK_HELP", "DEFAULT_SENTENCE", "walk_help"]
