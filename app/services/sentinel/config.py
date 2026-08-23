"""Sentinel configuration — every operator-tunable knob, in one catalog.

The Settings page renders :data:`SPEC` generically, so a knob added here needs
no template edit and cannot end up half-wired: present in the form but unread
by the code, or read by the code but absent from the form. That second failure
is the one that bit this product before — ``metrics.vm_url`` was silently
unconfigurable for months because the accessor name was wrong and a broad
``except`` ate it. Here the accessor is generated from the same spec the form
is generated from.

Every default makes a fresh installation **observant but inert**: collection
on, detection on, actions off, and no traffic to any third party. Enabling
Sentinel must never be the same act as authorising it to change a firewall.
"""
from __future__ import annotations

from .. import settings_store

PREFIX = "sentinel."

#: One entry per setting. ``kind`` drives both the form widget and the coercion.
#: Order is display order; ``group`` is the Settings card it lands in.
#:
#: ``help`` is the one-line summary printed under the field. ``hint`` is the
#: long answer behind the field's "?" — what the knob actually does, where the
#: code reads it, and what breaks at each extreme. Both are required: a knob
#: whose only documentation is its label is a knob an operator has to guess at,
#: and guessing is how the response engine gets armed by someone who thought
#: they were enabling detection. ``tests/test_sentinel_hints.py`` fails a new
#: entry that ships without a hint.
SPEC: list[dict] = [
    # ── detection ────────────────────────────────────────────────────────────
    {"key": "enabled", "kind": "bool", "default": True, "group": "detection",
     "label": "Sentinel enabled",
     "help": "Master switch for the correlation pipeline. Off = the scheduled "
             "sweep returns immediately and no incidents are created. Data "
             "already collected is untouched.",
     "hint": "Master switch for the correlation pipeline. ON, the scheduled "
             "sentinel_sweep (every 3 minutes) reads attack logs, correlates "
             "each event across the HTTP, appliance, VM and hypervisor layers, "
             "and opens or updates incidents. OFF, that sweep returns "
             "immediately: nothing is detected and no incident changes. "
             "Everything already collected — events, past incidents, the "
             "baseline — is left alone, so switching it back on RESUMES; it "
             "does not replay the gap. Turning this on does not authorise "
             "Sentinel to touch any device: that is 'Response engine armed', "
             "the last switch on this page, and it is a separate act on "
             "purpose."},
    {"key": "ingest_limit", "kind": "int", "default": 200, "group": "detection",
     "label": "Attack-log rows per device per sweep", "min": 10, "max": 2000,
     "help": "Upper bound on rows pulled from one appliance in one sweep. The "
             "read is a GUI-session call (FortiWeb exposes no REST attack log), "
             "so this is a real cost against a production box.",
     "hint": "Ceiling on attack-log rows pulled from ONE appliance in ONE "
             "sweep. FortiWeb exposes no REST attack log, so this read is a "
             "GUI-session call against a production box — the number is real "
             "load on the appliance, not a buffer size. Too low and a flood is "
             "truncated: you see the beginning of the burst and never its "
             "shape. Too high and every sweep, on every device, every three "
             "minutes, costs more than the detection is worth. Read in "
             "pipeline.ingest(); default 200, range 10–2000."},
    {"key": "window_pre_s", "kind": "int", "default": 60, "group": "detection",
     "label": "Correlation window — before T0 (seconds)", "min": 10, "max": 3600,
     "hint": "How far BEFORE the first event (T0) the correlator collects "
             "context from every layer: HTTP outcome classes, appliance "
             "counters, VM and hypervisor metrics. It exists to capture what "
             "was already happening when the attack landed — a box that was "
             "saturated before T0 is a different incident from one that "
             "degraded because of the attack, and without this window the two "
             "are indistinguishable. Read in correlate.build(); default 60 s, "
             "range 10–3600."},
    {"key": "window_post_s", "kind": "int", "default": 300, "group": "detection",
     "label": "Correlation window — after T0 (seconds)", "min": 30, "max": 7200,
     "hint": "The same window on the other side of T0: how long after the "
             "first event the correlator keeps collecting effect. This is "
             "where impact is measured, so it has to outlast the attack. Set "
             "it too short and incidents report 'no impact' merely because the "
             "evidence had not happened yet — which reads exactly like a "
             "harmless attack and is the most expensive way for this page to "
             "be wrong. Default 300 s, range 30–7200."},
    {"key": "absorb_minutes", "kind": "int", "default": 15, "group": "detection",
     "label": "Incident absorption window (minutes)", "min": 1, "max": 240,
     "help": "How long an open incident keeps absorbing matching events "
             "(same device + source + attack family) instead of opening a new "
             "one. Too short and a flood becomes thousands of incidents.",
     "hint": "How long an OPEN incident keeps absorbing matching events — same "
             "device, same source, same attack family — instead of opening a "
             "new one. Too short and a single flood becomes thousands of "
             "incidents, each individually meaningless and collectively "
             "unreadable. Too long and two genuinely separate campaigns from "
             "the same source are merged into one, so the second one never "
             "gets its own score, its own policy decision, or its own alert. "
             "Default 15 minutes, range 1–240."},
    {"key": "min_severity", "kind": "choice", "default": "low",
     "group": "detection", "label": "Minimum severity that may open an incident",
     "choices": ["info", "low", "medium", "high", "critical"],
     "hint": "The floor for ESCALATION, not for retention. An event ranked "
             "below this never opens an incident and never joins one — but it "
             "is still written to the event table first (ingest_event returns "
             "None only after the row exists), because 'we saw it and chose "
             "not to escalate' has to stay answerable months later. Raise it "
             "to cut incident noise knowing you lose no data; lower it and "
             "informational signatures start creating incidents of their own."},

    # ── baseline ─────────────────────────────────────────────────────────────
    {"key": "baseline_days", "kind": "int", "default": 21, "group": "baseline",
     "label": "Baseline learning window (days)", "min": 3, "max": 396,
     "help": "How far back the nightly recompute reads from the metrics store. "
             "The store keeps 396 days raw, so this is free to raise.",
     "hint": "How far back the nightly sentinel_baseline recompute reads when "
             "learning what 'normal' looks like for each bucket. The metrics "
             "store keeps 396 days at FULL resolution, so raising this costs "
             "recompute time, never accuracy — nothing is averaged away first. "
             "Set it too short and any weekly rhythm looks like an anomaly "
             "every Monday, because the window never contained a Monday to "
             "learn from. Default 21 days, range 3–396."},
    {"key": "baseline_k", "kind": "float", "default": 6.0, "group": "baseline",
     "label": "Deviation threshold (robust z, k x MAD)", "min": 1.0, "max": 50.0,
     "help": "A sample is anomalous when |value - median| / MAD exceeds this. "
             "MAD-based, so one past spike cannot desensitise the detector the "
             "way it would with mean + standard deviation.",
     "hint": "A sample counts as anomalous when |value − median| / MAD exceeds "
             "this k. Deliberately built on the median and MAD rather than "
             "mean and standard deviation: one past spike inflates σ, and with "
             "σ in the denominator the detector ends up LEAST sensitive "
             "exactly where it was attacked before. Lower k = more sensitive "
             "and more false positives; higher k = only gross deviations "
             "fire. Default 6.0, range 1.0–50.0."},
    {"key": "baseline_min_samples", "kind": "int", "default": 12,
     "group": "baseline", "label": "Minimum samples before a bucket may fire",
     "min": 3, "max": 500,
     "help": "Below this the bucket stays 'learning' and never produces a "
             "deviation. An immature baseline that fires is a false-positive "
             "generator wearing statistics as a costume.",
     "hint": "Below this many samples a bucket stays in 'learning' and can "
             "never produce a deviation, no matter how far out the next value "
             "lands. Two samples do yield a median and a MAD, and both numbers "
             "are meaningless — an immature baseline that fires is a "
             "false-positive generator wearing statistics as a costume. This "
             "is also what the 'Baseline usable' figure at the top of this "
             "section counts against. Default 12, range 3–500."},

    # ── vulnerability intelligence ───────────────────────────────────────────
    {"key": "vuln_enabled", "kind": "bool", "default": True, "group": "vuln",
     "label": "Enrich incidents from the local CVE mirror",
     "help": "Reads the sentinel_vuln table only. Never contacts a third party.",
     "hint": "Lets a finished incident attach CVE context — CVSS, CISA KEV "
             "flag, exploit references — by reading the LOCAL sentinel_vuln "
             "table. It never contacts a third party: no per-incident lookup "
             "path exists in the code at all, which is the point. Off, "
             "incidents simply carry no CVE factor; nothing is invented in its "
             "place. Filling that table is a different switch — the sync "
             "below, or entering CVEs by hand under Context."},
    {"key": "vuln_sync_enabled", "kind": "bool", "default": False,
     "group": "vuln", "label": "Allow the scheduled mirror sync to reach the internet",
     "help": "OFF by default and deliberately separate from the switch above. "
             "A live per-incident lookup would tell the vendor exactly which "
             "CVEs and signatures this fleet is seeing — a real-time map of the "
             "attack surface, sent out as a side effect of defending. The sync "
             "is a scheduled batch, and it is the ONLY component allowed out.",
     "hint": "THE outbound switch — off by default, and deliberately separate "
             "from the enrichment switch above. It authorises one thing: the "
             "scheduled sentinel_vuln_sync job, which is the only Sentinel "
             "component allowed to reach the internet at all. A live "
             "per-incident lookup was rejected outright, because it would tell "
             "the provider exactly which CVEs and signatures this fleet is "
             "seeing — a real-time map of the attack surface, leaked as a side "
             "effect of defending. Leave it off and the mirror only ever holds "
             "what you enter by hand, so it will read 'stale' forever and the "
             "Vulners key below is never used."},
    {"key": "vuln_source", "kind": "choice", "default": "vulners",
     "group": "vuln", "label": "Mirror source",
     "choices": ["vulners", "nvd", "manual"],
     "hint": "Which provider the SCHEDULED sync pulls detail from. 'vulners' "
             "needs the API key below; 'nvd' uses the public feed; 'manual' "
             "means the mirror is only ever filled by hand, under Context. "
             "Whatever this says, CISA KEV is fetched first and separately, "
             "because it is free, keyless and authoritative about actual "
             "exploitation — the one field that most changes an operator's "
             "night. None of this runs while the outbound switch above is off."},
    {"key": "vuln_api_key", "kind": "secret", "default": "", "group": "vuln",
     "label": "Vulners API key",
     "help": "Stored like every other SATOM secret. Only ever sent by the "
             "scheduled sync job.",
     "hint": "Credential for vulners.com, used by ONE thing: the scheduled "
             "mirror sync, and only when the source above is 'vulners'. It is "
             "stored encrypted like every other SATOM secret and is never sent "
             "from a per-incident path — enrichment always reads the local "
             "table. Without a key the sync logs 'vulners: no API key "
             "configured' and still brings the keyless CISA KEV feed, so you "
             "get exploitation status but no CVSS or exploit references. With "
             "the outbound switch off it is never used at all."},
    {"key": "vuln_stale_days", "kind": "int", "default": 7, "group": "vuln",
     "label": "Mirror is 'stale' after (days)", "min": 1, "max": 90,
     "help": "Past this age the incident still enriches, and says the data is "
             "stale. Silently serving old intelligence as current is worse "
             "than serving none.",
     "hint": "The age at which a mirror row is considered old. It does NOT "
             "stop enrichment: the incident still uses the data, and says it "
             "is stale — the badge at the top of this section, and the marker "
             "on the incident. Serving old intelligence silently, as though it "
             "were current, is worse than serving none, and it is the failure "
             "an operator cannot see. If the outbound sync is off the mirror "
             "will report stale permanently; that is honest, not broken. "
             "Default 7 days, range 1–90."},

    # ── AI reasoning ─────────────────────────────────────────────────────────
    {"key": "ai_enabled", "kind": "bool", "default": False, "group": "ai",
     "label": "AI narrative on incidents",
     "help": "The model reads a finished incident and writes an explanation. "
             "It cannot change a score, propose outside the action catalog, or "
             "reach any device. Off = incidents lose prose, nothing else.",
     "hint": "The model reads an ALREADY FINISHED incident and writes an "
             "explanation of it. It cannot change a score, invent an action "
             "outside the catalog, or reach any device — the deterministic "
             "score, the evidence table and the policy decision are all "
             "computed before it runs and stand whether it answers, fails or "
             "times out. Off, incidents lose the narrative and nothing else "
             "changes."},
    {"key": "ai_url", "kind": "str", "default": "http://192.0.2.72:11434",
     "group": "ai", "label": "Local model endpoint (Ollama / OpenAI-compatible)",
     "hint": "Base URL of the model host; the narrative call is a POST to "
             "{url}/api/chat. Local by intent — incident detail (addresses, "
             "signatures, topology, timing) must not leave the fleet to buy a "
             "paragraph of prose. If the host is unreachable the call returns "
             "a reason rather than raising, so a model outage can never change "
             "an incident's fate."},
    {"key": "ai_model", "kind": "str", "default": "qwen3:32b", "group": "ai",
     "label": "Model name",
     "hint": "The model tag requested from that host. It must already be "
             "pulled there — SATOM never downloads a model. Fleet trap worth "
             "knowing: qwen3 thinking models return an EMPTY content field "
             "with the answer hidden in 'thinking' unless think=false is sent, "
             "which this client always sends; a model that looks silent is "
             "usually that, not a broken host."},
    {"key": "ai_timeout_s", "kind": "int", "default": 90, "group": "ai",
     "label": "Model timeout (seconds)", "min": 5, "max": 600,
     "hint": "How long the narrative call may run before it is abandoned. "
             "Bounded on purpose: the sweep must never be held open by a slow "
             "model host, because detection is the job and prose is the "
             "garnish. On timeout the incident keeps its score, its evidence "
             "and its policy decision, and simply has no narrative. Default "
             "90 s, range 5–600."},
    {"key": "ai_min_score", "kind": "int", "default": 40, "group": "ai",
     "label": "Only reason about incidents scoring at least", "min": 0, "max": 100,
     "help": "Every incident costs a model call; below the investigate band "
             "the evidence table already says everything the prose would.",
     "hint": "Incidents scoring below this never get a narrative. Every one "
             "costs a model call, and under the investigate band the evidence "
             "table already says everything the prose would say at greater "
             "length. The default 40 is the observe/recommend boundary, so the "
             "cut lands exactly where an incident starts being worth a human's "
             "attention. Range 0–100."},

    # ── response ─────────────────────────────────────────────────────────────
    {"key": "response_enabled", "kind": "bool", "default": False,
     "group": "response", "label": "Response engine armed",
     "help": "GLOBAL KILL SWITCH. Off = Sentinel may PROPOSE actions and may "
             "not execute any, whatever the per-action policy says. This "
             "switch is checked last and overrides everything.",
     "hint": "THE GLOBAL KILL SWITCH. It is checked LAST, after every band, "
             "confidence and per-action policy, and it overrides all of them: "
             "off, Sentinel may PROPOSE actions and can execute exactly none. "
             "Arming it is a separate, deliberate act from enabling detection "
             "— it is the moment SATOM is allowed to change a firewall by "
             "itself, and that decision deserves its own switch rather than "
             "riding along with 'Sentinel enabled' at the top of the page."},
    {"key": "max_actions_per_hour", "kind": "int", "default": 6,
     "group": "response", "label": "Circuit breaker — max actions per hour",
     "min": 1, "max": 100,
     "help": "Fleet-wide ceiling across all action types. A correlation bug "
             "during a flood must exhaust a budget, not a firewall.",
     "hint": "A fleet-wide ceiling across ALL action types and ALL devices, "
             "not a per-device one — a per-device limit multiplied by ninety "
             "appliances is not a limit. It exists for the case where the "
             "correlator is simply wrong during a flood: the bug has to "
             "exhaust a budget rather than a firewall, and then stop and be "
             "visible. Default 6 per hour, range 1–100."},
    {"key": "effect_window_minutes", "kind": "int", "default": 5,
     "group": "response", "label": "Wait before judging effectiveness (minutes)",
     "min": 1, "max": 120,
     "help": "How long after an action Sentinel compares attack volume from "
             "that source against the same span before it. Applied is not "
             "effective: a rule that is present on the device and changes "
             "nothing is the case that must escalate, and it is invisible to a "
             "check that only confirms the write succeeded.",
     "hint": "After an action lands, how long Sentinel waits before comparing "
             "attack volume from that source against the same span of time "
             "before it. This is the setting that separates APPLIED from "
             "EFFECTIVE: a rule that is present on the device and changes "
             "nothing is precisely the case that must escalate, and it is "
             "completely invisible to a check that only confirms the write "
             "succeeded. Too short and you judge before traffic could react; "
             "too long and the escalation arrives after it mattered. Default "
             "5 minutes, range 1–120."},
    {"key": "device_block_period_s", "kind": "int", "default": 600,
     "group": "response", "label": "Device-side block period (seconds)",
     "min": 30, "max": 3600,
     "help": "Written onto the Sentinel IP list as action=block-period, so the "
             "APPLIANCE lifts the block by itself. This is the rollback that "
             "still works when Sentinel is down — which is exactly when a "
             "stuck block would otherwise never be lifted. Sentinel's own TTL "
             "deletes the member as well; the two are deliberately redundant.",
     "hint": "Written onto the Sentinel IP list as action=block-period, so the "
             "APPLIANCE lifts the block by itself when the period expires. "
             "That is the rollback that still works when SATOM is down — which "
             "is exactly the moment a stuck block would otherwise never be "
             "lifted, and the reason the timer lives on the device rather than "
             "here. Sentinel's own TTL removes the member too; the redundancy "
             "is deliberate, not an oversight. Default 600 s, range 30–3600."},
    {"key": "hardened_profiles", "kind": "text", "default": "",
     "group": "response", "label": "Hardened web protection profiles (one per line)",
     "help": "The ONLY profiles raise_protection may move a policy onto. Empty "
             "means that action can never run, which is the correct default: "
             "the profile bound to a policy is the security posture of every "
             "client behind it, and Sentinel must not be the one choosing it. "
             "Each name must already exist on the appliance.",
     "hint": "One profile name per line, and the ONLY profiles the "
             "raise_protection action may move a policy onto. Empty means that "
             "action can never run — the correct default, because the web "
             "protection profile bound to a policy IS the security posture of "
             "every client behind it, and Sentinel must not be the one "
             "choosing it. Each name has to already exist on the appliance; an "
             "unknown name is a failed action, not a created profile."},
    {"key": "protect_cidrs", "kind": "text",
     "default": "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n127.0.0.0/8",
     "group": "response", "label": "Never-block networks (one CIDR per line)",
     "help": "A source inside any of these can never be the target of a "
             "blocking action, at any confidence, at any level.",
     "hint": "One CIDR per line. A source inside any of them can never be the "
             "target of a blocking action — at any confidence, in any band, "
             "under any per-action policy. The defaults cover RFC1918 and "
             "loopback, so Sentinel cannot lock the fleet out of itself. "
             "Lines that do not parse are DROPPED and reported separately on "
             "this page: a silently discarded protection line is precisely how "
             "a 'safe' list stops protecting, so check for the parse-error "
             "notice after editing."},
]

#: The explanatory text for everything in the section that is NOT a setting —
#: the group headings, the four health chips and the links out. Kept here, next
#: to the knob catalog, so the section has ONE place where its prose lives; two
#: places is how the pane and the page drifted apart before.
UI_HINTS: dict[str, str] = {
    "group.detection":
        "What Sentinel reads, and how it decides that a burst of events is one "
        "incident rather than many. These knobs govern cost against the "
        "appliances and the shape of what lands in the console — nothing here "
        "can change a device.",
    "group.baseline":
        "How 'normal' is learned, per bucket, by the nightly recompute. A "
        "deviation is only meaningful against a mature baseline, so these "
        "three settings mostly decide when the detector is allowed to have an "
        "opinion at all.",
    "group.vuln":
        "CVE context attached to a finished incident, read from a LOCAL "
        "mirror. Two switches on purpose: one to use the mirror, one to let a "
        "scheduled job go and fill it. The second is the only outbound path in "
        "all of Sentinel.",
    "group.ai":
        "Optional narrative on top of a finished incident. The model explains; "
        "it never scores, never decides and never reaches a device. Every "
        "setting here can fail without changing what the incident says.",
    "group.response":
        "The only group that can change a firewall. Read it as a ladder: the "
        "kill switch decides whether anything may run at all, the circuit "
        "breaker bounds how much, the effectiveness window judges whether it "
        "worked, and the last two lists bound what may ever be touched.",
    "health.pipeline":
        "How long ago the scheduled sentinel_sweep last completed, taken from "
        "the satom_sentinel_up series in the metrics store — not from a "
        "counter this page keeps. 'never run' means the scheduled action is "
        "missing or has not fired yet, which looks identical to a quiet "
        "network and is not: nothing is being detected.",
    "health.baseline":
        "Buckets with enough samples to be allowed to fire, over the total "
        "known. The gap is buckets still 'learning' — below the minimum-sample "
        "floor set in the Behavioural baseline group. A low ratio on a fresh "
        "install is expected and resolves itself nightly.",
    "health.vuln":
        "Rows in the local CVE mirror, plus a 'stale' badge when the newest is "
        "older than the staleness threshold. Zero is not a failure: it means "
        "CVE factors simply do not apply, and no incident will invent one.",
    "health.catalog":
        "Action transports that have actually been VERIFIED against a device, "
        "over the total in the catalog. An unverified transport is one nobody "
        "has proven can execute — arming the response engine while this ratio "
        "is low means arming actions whose delivery path is untested.",
    "link.architecture":
        "The full design document: the pipeline stage by stage, the scoring "
        "weights, the gate order the response engine walks, and the ten demo "
        "scenarios you can run against it without touching a device.",
    "link.policies":
        "Per-action policy — for each action type, the band and confidence at "
        "which it may be proposed, and whether it may execute. The global kill "
        "switch on this page is still checked after all of it.",
    "link.context":
        "The inputs that are not single values: trusted sources, the topology "
        "map that binds each appliance to its VM and hypervisor, maintenance "
        "windows, and hand-entered CVEs.",
}

_BY_KEY = {s["key"]: s for s in SPEC}

GROUPS = [
    ("detection", "Detection & correlation"),
    ("baseline", "Behavioural baseline"),
    ("vuln", "Vulnerability intelligence"),
    ("ai", "AI reasoning"),
    ("response", "Response & safety"),
]


def _coerce(spec: dict, raw):
    kind = spec["kind"]
    if raw in (None, ""):
        return spec["default"]
    try:
        if kind == "bool":
            return str(raw).strip().lower() in ("1", "true", "on", "yes")
        if kind == "int":
            v = int(float(raw))
            return _clamp(v, spec)
        if kind == "float":
            return _clamp(float(raw), spec)
        if kind == "choice":
            return raw if raw in spec["choices"] else spec["default"]
    except (TypeError, ValueError):
        return spec["default"]
    return str(raw)


def _clamp(v, spec):
    lo, hi = spec.get("min"), spec.get("max")
    if lo is not None and v < lo:
        return lo
    if hi is not None and v > hi:
        return hi
    return v


def get(key: str):
    """One setting, coerced and clamped. Unknown key raises — a typo must fail
    loudly here rather than silently hand back a default that looks configured."""
    spec = _BY_KEY.get(key)
    if spec is None:
        raise KeyError(f"unknown sentinel setting {key!r}")
    return _coerce(spec, settings_store.get_str(PREFIX + key, None))


def set_value(key: str, value) -> None:
    spec = _BY_KEY.get(key)
    if spec is None:
        raise KeyError(f"unknown sentinel setting {key!r}")
    if spec["kind"] == "bool":
        value = "1" if _coerce(spec, value) else "0"
    else:
        value = str(_coerce(spec, value))
    settings_store.set_str(PREFIX + key, value)


def all_values(*, reveal_secrets: bool = False) -> dict:
    out = {}
    for spec in SPEC:
        v = get(spec["key"])
        if spec["kind"] == "secret" and not reveal_secrets:
            v = "********" if v else ""
        out[spec["key"]] = v
    return out


def form_groups(*, reveal_secrets: bool = False) -> list:
    """The Settings render model: [(group_key, label, [spec+value, ...]), ...]."""
    values = all_values(reveal_secrets=reveal_secrets)
    out = []
    for gkey, glabel in GROUPS:
        rows = [dict(s, value=values[s["key"]])
                for s in SPEC if s["group"] == gkey]
        if rows:
            out.append((gkey, glabel, rows))
    return out


def protected_networks() -> list:
    """The never-block list, parsed. An unparseable line is DROPPED with the
    rest still honoured — but see :func:`protect_errors`: a silently discarded
    protection line is how a 'safe' list stops protecting."""
    import ipaddress
    nets = []
    for line in str(get("protect_cidrs") or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            nets.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue
    return nets


def protect_errors() -> list:
    """Lines of the never-block list that do NOT parse, so the UI can say so."""
    import ipaddress
    bad = []
    for line in str(get("protect_cidrs") or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ipaddress.ip_network(line, strict=False)
        except ValueError:
            bad.append(line)
    return bad
