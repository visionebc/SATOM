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
SPEC: list[dict] = [
    # ── detection ────────────────────────────────────────────────────────────
    {"key": "enabled", "kind": "bool", "default": True, "group": "detection",
     "label": "Sentinel enabled",
     "help": "Master switch for the correlation pipeline. Off = the scheduled "
             "sweep returns immediately and no incidents are created. Data "
             "already collected is untouched."},
    {"key": "ingest_limit", "kind": "int", "default": 200, "group": "detection",
     "label": "Attack-log rows per device per sweep", "min": 10, "max": 2000,
     "help": "Upper bound on rows pulled from one appliance in one sweep. The "
             "read is a GUI-session call (FortiWeb exposes no REST attack log), "
             "so this is a real cost against a production box."},
    {"key": "window_pre_s", "kind": "int", "default": 60, "group": "detection",
     "label": "Correlation window — before T0 (seconds)", "min": 10, "max": 3600},
    {"key": "window_post_s", "kind": "int", "default": 300, "group": "detection",
     "label": "Correlation window — after T0 (seconds)", "min": 30, "max": 7200},
    {"key": "absorb_minutes", "kind": "int", "default": 15, "group": "detection",
     "label": "Incident absorption window (minutes)", "min": 1, "max": 240,
     "help": "How long an open incident keeps absorbing matching events "
             "(same device + source + attack family) instead of opening a new "
             "one. Too short and a flood becomes thousands of incidents."},
    {"key": "min_severity", "kind": "choice", "default": "low",
     "group": "detection", "label": "Minimum severity that may open an incident",
     "choices": ["info", "low", "medium", "high", "critical"]},

    # ── baseline ─────────────────────────────────────────────────────────────
    {"key": "baseline_days", "kind": "int", "default": 21, "group": "baseline",
     "label": "Baseline learning window (days)", "min": 3, "max": 396,
     "help": "How far back the nightly recompute reads from the metrics store. "
             "The store keeps 396 days raw, so this is free to raise."},
    {"key": "baseline_k", "kind": "float", "default": 6.0, "group": "baseline",
     "label": "Deviation threshold (robust z, k x MAD)", "min": 1.0, "max": 50.0,
     "help": "A sample is anomalous when |value - median| / MAD exceeds this. "
             "MAD-based, so one past spike cannot desensitise the detector the "
             "way it would with mean + standard deviation."},
    {"key": "baseline_min_samples", "kind": "int", "default": 12,
     "group": "baseline", "label": "Minimum samples before a bucket may fire",
     "min": 3, "max": 500,
     "help": "Below this the bucket stays 'learning' and never produces a "
             "deviation. An immature baseline that fires is a false-positive "
             "generator wearing statistics as a costume."},

    # ── vulnerability intelligence ───────────────────────────────────────────
    {"key": "vuln_enabled", "kind": "bool", "default": True, "group": "vuln",
     "label": "Enrich incidents from the local CVE mirror",
     "help": "Reads the sentinel_vuln table only. Never contacts a third party."},
    {"key": "vuln_sync_enabled", "kind": "bool", "default": False,
     "group": "vuln", "label": "Allow the scheduled mirror sync to reach the internet",
     "help": "OFF by default and deliberately separate from the switch above. "
             "A live per-incident lookup would tell the vendor exactly which "
             "CVEs and signatures this fleet is seeing — a real-time map of the "
             "attack surface, sent out as a side effect of defending. The sync "
             "is a scheduled batch, and it is the ONLY component allowed out."},
    {"key": "vuln_source", "kind": "choice", "default": "vulners",
     "group": "vuln", "label": "Mirror source",
     "choices": ["vulners", "nvd", "manual"]},
    {"key": "vuln_api_key", "kind": "secret", "default": "", "group": "vuln",
     "label": "Vulners API key",
     "help": "Stored like every other SATOM secret. Only ever sent by the "
             "scheduled sync job."},
    {"key": "vuln_stale_days", "kind": "int", "default": 7, "group": "vuln",
     "label": "Mirror is 'stale' after (days)", "min": 1, "max": 90,
     "help": "Past this age the incident still enriches, and says the data is "
             "stale. Silently serving old intelligence as current is worse "
             "than serving none."},

    # ── AI reasoning ─────────────────────────────────────────────────────────
    {"key": "ai_enabled", "kind": "bool", "default": False, "group": "ai",
     "label": "AI narrative on incidents",
     "help": "The model reads a finished incident and writes an explanation. "
             "It cannot change a score, propose outside the action catalog, or "
             "reach any device. Off = incidents lose prose, nothing else."},
    {"key": "ai_url", "kind": "str", "default": "http://192.0.2.72:11434",
     "group": "ai", "label": "Local model endpoint (Ollama / OpenAI-compatible)"},
    {"key": "ai_model", "kind": "str", "default": "qwen3:32b", "group": "ai",
     "label": "Model name"},
    {"key": "ai_timeout_s", "kind": "int", "default": 90, "group": "ai",
     "label": "Model timeout (seconds)", "min": 5, "max": 600},
    {"key": "ai_min_score", "kind": "int", "default": 40, "group": "ai",
     "label": "Only reason about incidents scoring at least", "min": 0, "max": 100,
     "help": "Every incident costs a model call; below the investigate band "
             "the evidence table already says everything the prose would."},

    # ── response ─────────────────────────────────────────────────────────────
    {"key": "response_enabled", "kind": "bool", "default": False,
     "group": "response", "label": "Response engine armed",
     "help": "GLOBAL KILL SWITCH. Off = Sentinel may PROPOSE actions and may "
             "not execute any, whatever the per-action policy says. This "
             "switch is checked last and overrides everything."},
    {"key": "max_actions_per_hour", "kind": "int", "default": 6,
     "group": "response", "label": "Circuit breaker — max actions per hour",
     "min": 1, "max": 100,
     "help": "Fleet-wide ceiling across all action types. A correlation bug "
             "during a flood must exhaust a budget, not a firewall."},
    {"key": "effect_window_minutes", "kind": "int", "default": 5,
     "group": "response", "label": "Wait before judging effectiveness (minutes)",
     "min": 1, "max": 120,
     "help": "How long after an action Sentinel compares attack volume from "
             "that source against the same span before it. Applied is not "
             "effective: a rule that is present on the device and changes "
             "nothing is the case that must escalate, and it is invisible to a "
             "check that only confirms the write succeeded."},
    {"key": "device_block_period_s", "kind": "int", "default": 600,
     "group": "response", "label": "Device-side block period (seconds)",
     "min": 30, "max": 3600,
     "help": "Written onto the Sentinel IP list as action=block-period, so the "
             "APPLIANCE lifts the block by itself. This is the rollback that "
             "still works when Sentinel is down — which is exactly when a "
             "stuck block would otherwise never be lifted. Sentinel's own TTL "
             "deletes the member as well; the two are deliberately redundant."},
    {"key": "hardened_profiles", "kind": "text", "default": "",
     "group": "response", "label": "Hardened web protection profiles (one per line)",
     "help": "The ONLY profiles raise_protection may move a policy onto. Empty "
             "means that action can never run, which is the correct default: "
             "the profile bound to a policy is the security posture of every "
             "client behind it, and Sentinel must not be the one choosing it. "
             "Each name must already exist on the appliance."},
    {"key": "protect_cidrs", "kind": "text",
     "default": "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n127.0.0.0/8",
     "group": "response", "label": "Never-block networks (one CIDR per line)",
     "help": "A source inside any of these can never be the target of a "
             "blocking action, at any confidence, at any level."},
]

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
