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
    # ── border corroboration ─────────────────────────────────────────────────
    {"key": "edge_enabled", "kind": "bool", "default": True, "group": "edge",
     "label": "Border corroboration enabled",
     "help": "Ask the FortiAnalyzer whether the border independently logged "
             "the source. Inert until an appliance is mapped in Sentinel -> "
             "Context -> Border map.",
     "hint": "Master switch for the border layer. ON, each correlated window "
             "asks the mapped FortiAnalyzer whether the FortiGate in front "
             "logged that source address in the same window, and the answer "
             "becomes evidence (edge_corroboration, edge_multi_target) and a "
             "veto on border blocklist entries. It defaults ON, unlike the "
             "vulnerability mirror, because the GATE here is the map: with no "
             "row in Sentinel -> Context -> Border map nothing is queried and "
             "nothing changes. Requiring a second switch would only create a "
             "state where a filled-in map produces silence. Turn it off to "
             "stop querying a collector that is down without unpicking the "
             "map. OFF, every incident reports the border layer as not "
             "evaluated - never as clean."},
    {"key": "edge_require", "kind": "bool", "default": True, "group": "edge",
     "label": "Require border corroboration before listing an address",
     "help": "An address the border never logged as a source may not enter a "
             "border blocklist. Off = accept that an entry may be a shared "
             "egress.",
     "hint": "The veto, and the reason this layer was built before the "
             "blocklist. FortiWeb reports the TRUE client when the policy "
             "reads X-Forwarded-For, and the CDN's own address when it does "
             "not - and nothing in the attack log tells the two apart. In the "
             "first case a border block is inert (that address never reached "
             "the firewall); in the second it removes EVERY client behind "
             "that egress. ON, an address the border did not confirm never "
             "reaches the feed, and the refusal is recorded with its reason. "
             "OFF is a deliberate decision to accept that blast radius - "
             "which an operator may make and this engine may not. Read by "
             "edge.blockable()."},
    {"key": "edge_scan_dst", "kind": "int", "default": 10, "group": "edge",
     "label": "Distinct border destinations that count as scanning",
     "min": 2, "max": 1000,
     "help": "Distinct destination addresses this source reached at the "
             "border, above which the incident gains edge_multi_target.",
     "hint": "How many DISTINCT destination addresses the source touched at "
             "the border before the window is called scanning rather than a "
             "single conversation. This is the strongest thing the border can "
             "say that the WAF cannot: one IP delivering a SQLi burst to one "
             "site is ambiguous, the same IP simultaneously reaching forty "
             "unrelated hosts is not. Too low and any client with several "
             "backends scores it; too high and a deliberate low-and-slow "
             "sweep never does. Default 10, range 2-1000. Feeds the "
             "edge_multi_target factor (+10)."},
    {"key": "edge_max_rows", "kind": "int", "default": 200, "group": "edge",
     "label": "Border log rows per lookup", "min": 10, "max": 2000,
     "help": "Upper bound on rows fetched from the collector for one window. "
             "Real load on a production FortiAnalyzer.",
     "hint": "Ceiling on rows pulled from the collector for ONE window. The "
             "summary only needs enough rows to count distinct destinations, "
             "so raising this buys precision on the scanning threshold and "
             "nothing else, at real cost against a production FortiAnalyzer "
             "that is also serving reports. Note the interaction: if a source "
             "reached more distinct destinations than this cap, the count is "
             "truncated and edge_multi_target can miss. Default 200, range "
             "10-2000."},
    {"key": "edge_timeout_s", "kind": "float", "default": 20.0, "group": "edge",
     "label": "Border lookup timeout (seconds)", "min": 5.0, "max": 120.0,
     "hint": "How long one logsearch may take before the lookup is abandoned. "
             "A timeout is reported as an ERROR, which means the border layer "
             "reads as not evaluated and - with the veto on - no address is "
             "listed. That is the intended direction: a slow collector must "
             "not become a source of authorisations. Set it too high and a "
             "wedged FortiAnalyzer stretches every sweep; too low and a busy "
             "one is never usable. Default 20 s, range 5-120."},
    {"key": "edge_slack_minutes", "kind": "int", "default": 2, "group": "edge",
     "label": "Extra minutes searched either side of the window",
     "min": 0, "max": 120,
     "help": "Widens the border search beyond the correlation window to "
             "absorb clock skew between the appliances.",
     "hint": "Padding added to BOTH ends of the correlation window when "
             "searching the border. Two devices that disagree by thirty "
             "seconds will otherwise report a source as absent purely because "
             "the session was logged just outside the window - and 'absent' "
             "here vetoes a block, so skew turns into a silent policy. This "
             "is for SKEW, not for timezones: an hours-wide mismatch belongs "
             "in the offset below, because widening by an hour also dilutes "
             "the destination count that edge_multi_target reads. Default "
             "2 minutes, range 0-120."},
    {"key": "edge_tz_offset_min", "kind": "int", "default": 0, "group": "edge",
     "label": "Collector clock offset from UTC (minutes)",
     "min": -900, "max": 900,
     "help": "Minutes to add to UTC to get the FortiAnalyzer's wall clock. "
             "Wrong here = every lookup returns nothing, forever.",
     "hint": "Sentinel stores event timestamps as naive UTC; a "
             "FortiAnalyzer answers in its own configured timezone. If they "
             "disagree the search window lands on the wrong hour and the "
             "collector returns zero rows - which is byte-identical to a "
             "source the border genuinely never saw, so the failure is a "
             "PERMANENT silent veto on every block rather than an error "
             "anyone sees. That is why it is a setting and not an "
             "assumption. Enter the collector's UTC offset in minutes (+60 "
             "for UTC+1, -360 for UTC-6). Use the Test lookup button on the "
             "Context page to confirm before trusting it. Default 0."},

    # ── border blocklist (the published feed) ────────────────────────────────
    {"key": "feed_enabled", "kind": "bool", "default": False,
     "group": "blocklist", "label": "Publish the border blocklist feed",
     "help": "Serves the live list at /sentinel/feed/<token>/blocklist.txt. "
             "OFF, the endpoint answers 404 and entries are still recorded.",
     "hint": "Master switch for the HTTP feed a FortiGate external connector "
             "reads. OFF by default because turning it on makes a URL that "
             "answers WITHOUT a login session — the token is the only thing "
             "in front of it, and the body names addresses that attacked "
             "specific customers. With it off, everything else still works: "
             "entries are created, expire and are audited, and the page shows "
             "the list. The border simply is not being told. Note what this "
             "switch does NOT do: it never writes to a FortiGate. SATOM has "
             "no FortiGate client and gets none — the operator pre-creates the "
             "deny policy that references the feed, exactly as they "
             "pre-create the FortiWeb IP list that block_ip appends to."},
    {"key": "feed_token", "kind": "secret", "default": "", "group": "blocklist",
     "label": "Feed token",
     "help": "The whole authentication of the feed URL. Rotating it breaks "
             "every connector already configured, on purpose.",
     "hint": "A random string that forms part of the feed path. It is the "
             "ONLY thing standing between an anonymous request and this "
             "fleet's blocklist, because a threat-feed connector cannot log "
             "in. An UNSET token does not mean 'no authentication' — it means "
             "the feed refuses everything, including a request that also "
             "omits the token (secrets.compare_digest('','') is True, so the "
             "emptiness check is the guard, not the comparison). Rotate from "
             "the Blocklist page; there is deliberately no grace period and "
             "no second valid token, because a rotation that keeps the old "
             "one working has revoked nothing and leaves you no way to find "
             "which connectors still hold it."},
    {"key": "feed_ttl_hours", "kind": "int", "default": 24, "group": "blocklist",
     "label": "Default entry TTL (hours)", "min": 1, "max": 720,
     "help": "How long a new entry lives when the caller does not say. Hard "
             "ceiling 720h (30 days) regardless of this value.",
     "hint": "Every entry carries an expiry and there is no way to create one "
             "without it — this is the default applied when a caller does not "
             "name a duration. It matters MORE here than on FortiWeb: "
             "block_ip uses action=block-period, so THE APPLIANCE expires that "
             "block and the expiry survives Sentinel being dead. A feed has no "
             "device-side timer. The list is therefore rendered from the "
             "database on every fetch and filtered by expires_at, so a stopped "
             "publisher cannot serve a stale entry — but if SATOM is "
             "UNREACHABLE the border keeps its last successful fetch and those "
             "entries freeze rather than expire. Short TTLs bound that "
             "failure; long ones are a decision to accept it. Ceiling 720 "
             "hours, enforced in code (blocklist.MAX_TTL_HOURS) and not "
             "raisable from this form."},
    {"key": "feed_max_entries", "kind": "int", "default": 500,
     "group": "blocklist", "label": "Maximum live entries", "min": 1,
     "max": 10000,
     "help": "At the ceiling a new entry is REFUSED. Nothing is ever evicted "
             "to make room.",
     "hint": "Upper bound on addresses the feed may carry at once. When it is "
             "reached the next listing is refused with that reason, and the "
             "oldest entry is NOT dropped to make space: evicting a row that "
             "is still inside its TTL silently unblocks an address, and the "
             "only telemetry would be traffic resuming. Sized for what a "
             "border policy can hold and for what a person can review — a "
             "list nobody reads is a list nobody releases from. Raise it "
             "deliberately, or release entries."},
    {"key": "feed_stale_minutes", "kind": "int", "default": 30,
     "group": "blocklist", "label": "Consider a fetched copy stale after "
                                    "(minutes)", "min": 1, "max": 1440,
     "help": "Written into every rendered feed as stale_after, and used by the "
             "console to flag a frozen feed.",
     "hint": "How long a copy of this feed may be trusted after it was "
             "generated. It is stamped into the file header next to "
             "generated_at, because a consumer holding a cached list cannot "
             "otherwise distinguish a current feed from a frozen one — and a "
             "frozen list is a permanent block nobody decided to make. Set it "
             "near the connector's own refresh interval: shorter and every "
             "normal fetch looks stale, much longer and a genuinely dead "
             "publisher goes unnoticed for exactly that long."},
    {"key": "feed_git_remote", "kind": "str", "default": "",
     "group": "blocklist", "label": "Audit mirror repository (git URL)",
     "help": "A SEPARATE repository. Never this product's own source repo — "
             "that one is published publicly.",
     "hint": "Optional git remote that receives a commit of the rendered list "
             "on every publish, so the history of who was blocked and when is "
             "a diff rather than a log line. It must NOT be SATOM's own source "
             "repository: that repository is mirrored to a public host by the "
             "release tooling, so a blocklist committed into it would disclose "
             "which addresses attacked which customer to anyone reading the "
             "mirror. The working copy lives outside data/ as well, because "
             "the standby's rsync --delete datasync would wipe a git working "
             "tree mid-commit. Empty = no mirror; the feed itself is "
             "unaffected either way, since it is served from the database."},
    {"key": "feed_git_branch", "kind": "str", "default": "main",
     "group": "blocklist", "label": "Mirror branch",
     "help": "Branch pushed to in the mirror repository.",
     "hint": "Branch the mirror commit is pushed to (HEAD:<branch>). Default "
             "main. Only read when a mirror remote is set; a wrong value "
             "fails the push and is reported in the mirror log on the "
             "Blocklist page — it never blocks a listing or a release, "
             "because the mirror is the audit copy and the feed is the "
             "enforcement path."},
    {"key": "feed_git_token", "kind": "secret", "default": "",
     "group": "blocklist", "label": "Mirror push credential",
     "help": "Injected into the remote URL for the push and redacted from "
             "every log line this product renders.",
     "hint": "Token for the mirror remote, stored encrypted like every other "
             "SATOM secret. It is spliced into the HTTPS remote at push time "
             "and stripped from every string the mirror returns, so the "
             "command log the page shows cannot leak it. Leave empty for an "
             "SSH remote or an unauthenticated one."},
    {"key": "feed_git_auto", "kind": "bool", "default": False,
     "group": "blocklist", "label": "Mirror automatically on every publish",
     "help": "OFF = the mirror only runs when someone presses the button.",
     "hint": "When on, the scheduled sentinel_feed_publish run commits and "
             "pushes the rendered list every time it runs. Off by default "
             "because an automatic push into a repository somebody later "
             "points at the wrong remote is how operational data escapes, and "
             "that decision should be made once, deliberately, rather than "
             "inherited from a default. With it off the mirror still works "
             "from the Publish now button."},
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
    "group.edge":
        "What the firewall in front of the appliance says about the source. "
        "It answers a question the WAF structurally cannot - whether that "
        "address ever opened a connection to the border at all - and the "
        "answer does two jobs: it adds evidence, and it VETOES listing an "
        "address the border never saw. There is no negative weight here on "
        "purpose: silence at the border is a fact about addressing, not about "
        "hostility, and an attack behind a CDN is still an attack.",
    "group.blocklist":
        "The list SATOM publishes for a border firewall to read, and nothing "
        "else: there is no FortiGate client in this product and no credential "
        "that could write one. The operator pre-creates the deny policy that "
        "references the feed; Sentinel only decides which addresses are in it, "
        "and every entry carries a mandatory expiry. Read the TTL hint before "
        "raising it — a feed has no device-side timer, so this is the one "
        "response path whose expiry depends on SATOM still answering.",
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


#: The "?" prose for everything OUTSIDE Settings — the four console chips, the
#: cards on Context, Response policy and Border blocklist. Same catalog idea as
#: UI_HINTS above and deliberately in the same file: the section already learned
#: that prose in two places drifts, and these pages have the additional problem
#: that each one renders on TWO surfaces (the standalone page and the Settings
#: pane) through the same partial.
#:
#: Keys are namespaced by surface. Where the console shows the same fact the
#: Settings page shows, the key is NOT redefined here — ``hint_for`` falls
#: through to ``UI_HINTS``, so the health chips carry the one description that
#: already existed instead of a second one written today.
PAGE_HINTS: dict[str, str] = {
    # ── Incidents console ────────────────────────────────────────────────
    "console.sweep":
        "Reads the attack log of the appliances you tick, right now, instead "
        "of waiting for the scheduled sweep. It only READS: a sweep can create "
        "incidents and propose actions, it cannot change a device. Appliances "
        "in maintenance, or whose host ends in .invalid, are offered greyed "
        "out because a sweep against them would fail rather than find nothing.",
    "console.response":
        "Whether the response engine may execute at all. 'proposals only' "
        "means every action stops at a recommendation a human has to approve — "
        "which is the shipped default and not a fault. The ratio underneath "
        "counts action mechanisms proved against a real device; arming the "
        "engine while it is low arms actions whose delivery path is untested.",
    "console.blocklist":
        "Addresses this node is currently asking a border firewall to drop, "
        "published as a text feed the firewall fetches. It is on its own row "
        "rather than beside the chips because its enforcement point is OUTSIDE "
        "this product: an address can be listed here while the response engine "
        "above reads 'proposals only'. The feed has no device-side timer, so a "
        "border that cannot reach this node keeps its last copy and those "
        "entries freeze instead of expiring.",
    "console.store":
        "The metrics store answers the behavioural half of every score. While "
        "it is unreachable those factors are ABSENT, not zero: incidents are "
        "still created from attack events, and they are scored on less "
        "evidence than the same events would earn tomorrow.",
    "console.stats":
        "Counts over the last seven days, filtered by the buttons beside them. "
        "'False positives' is the only number here you write yourself — it is "
        "what you marked, so it measures your triage, not the detector's.",
    "console.incidents":
        "One row per correlated incident, not per event: a burst from one "
        "source against one policy is folded into a single row, and 'Events' "
        "is how many were folded. The 'blocked' and 'through' badges are the "
        "APPLIANCE's own verdict on those events — 'through' means the WAF let "
        "them reach the backend, which is why a modest score with traffic "
        "through it can matter more than a high one that was all stopped.",

    # ── Context ──────────────────────────────────────────────────────────
    "context.trusted":
        "Sources you have decided are yours — scanners, monitoring, an office "
        "range. Their events are still recorded and still scored; the entry "
        "here marks the incident 'trusted' so it is not proposed for a "
        "response. It suppresses a REACTION, never the observation: a trusted "
        "source that has been compromised still shows up.",
    "context.maintenance":
        "Windows in which the appliance was expected to behave oddly. Samples "
        "inside them are dropped from the nightly baseline recompute rather "
        "than averaged in — a firmware upgrade teaches the detector that a CPU "
        "spike at that hour is normal, and it would then stay quiet the next "
        "time one is not.",
    "context.topology":
        "What each appliance runs on. Without a row here the VM and host "
        "factors cannot be evaluated at all, so an incident loses up to 18 "
        "points of evidence — and it loses them silently, looking exactly like "
        "an incident that was checked and found clean.",
    "context.edge":
        "Which FortiAnalyzer holds the logs of the firewall in front of each "
        "appliance, and which device and VDOM to ask. Nothing here is inferred, "
        "because a wrong ADOM does not fail: it answers about somebody else's "
        "traffic and the answer still looks like an answer. Use Test lookup "
        "after any edit — a bad ADOM, a bad device name, a clock offset and an "
        "address the border never saw all return zero rows.",
    "context.cve":
        "The local CVE mirror an incident is enriched from. Zero rows is not a "
        "failure: it means CVE factors do not apply and no incident will invent "
        "one. This table is the only thing consulted — a CVE that exists in the "
        "world and not here contributes nothing.",
    "context.arming":
        "Which server policies the response engine is allowed to act on at "
        "all. A policy absent from this list is out of reach of every action, "
        "at any score — this is the bound that is checked before the "
        "per-action rules, not after them. Empty means nothing may be "
        "enforced on anything, which is a safe state and an easy one to leave "
        "by accident.",
    "context.manual_cve":
        "A CVE typed in by hand, for when the mirror does not have one yet. It "
        "is scored exactly like a synced row; the difference is that nobody "
        "revised it afterwards.",

    # ── Response policy ──────────────────────────────────────────────────
    "policy.kill":
        "The switch checked last, after every per-action rule below it. While "
        "it is off nothing on this page can execute, whatever the individual "
        "rows say — read the rows as what WOULD happen if you armed it.",
    "policy.verified":
        "Action mechanisms proved against a live appliance, over the total in "
        "the catalog. An unverified mechanism is rejected by the runner by "
        "name, so it cannot execute even when armed. That is a deliberate "
        "floor, not a to-do list to clear before shipping.",
    "policy.modes":
        "For each action: the score band and confidence at which it may be "
        "proposed, and whether it may run by itself. 'recommend' stops at a "
        "proposal a human approves; 'auto' does not. Raising a row is the only "
        "change on this page that can move traffic.",
    "policy.actions":
        "The catalog itself — every action this build knows how to take, with "
        "the device call behind it. An action with no transport can never "
        "execute regardless of its policy; it exists so an operator can be "
        "told what SHOULD happen and do it themselves.",
    "policy.effects":
        "The exact command each action would send, written out before you arm "
        "anything. Read it as the contract: if the sentence here is not what "
        "you want done to a production appliance at 03:00 without you, the "
        "answer is to leave that row on 'recommend'.",
    "policy.decisions":
        "What the engine actually decided recently, including the proposals "
        "nobody approved. A run of proposals that were never acted on is the "
        "cheapest evidence you have about whether arming a row would have "
        "helped or hurt.",

    # ── Border blocklist ─────────────────────────────────────────────────
    "blocklist.feed":
        "The list served to a border firewall over HTTP, rendered from the "
        "database at every request rather than from a file — so an entry past "
        "its expiry is never served, even if the scheduled job that keeps the "
        "bookkeeping has stopped. With the feed off, entries are still recorded "
        "and simply not published. The URL answers WITHOUT a login, and its "
        "body names addresses that attacked named customers: the token is the "
        "only thing protecting it.",
    "blocklist.mirror":
        "An optional copy of every listing and release pushed to a git "
        "repository, so the record survives this node. It must NOT be the "
        "repository this product is published from — a blocklist committed "
        "there tells the world which addresses attacked which customer.",
    "blocklist.add":
        "Lists one address, with a mandatory expiry. The border is asked first: "
        "if that firewall never saw the address, listing it is either inert or "
        "catastrophic — the address in the WAF log may be the CDN's, and "
        "blocking it at the border drops every customer behind it. Overriding "
        "the veto relaxes only that check, needs a written reason, and never "
        "touches the never-block list.",
    "blocklist.entries":
        "Everything ever listed, not just what is live. Releasing an address "
        "does not delete its row on purpose: 'why was this customer blocked on "
        "Tuesday' is the question that actually gets asked, and it is "
        "unanswerable from a list that only holds the present.",
    "blocklist.preview":
        "Byte for byte what a firewall fetching the feed receives at this "
        "instant, header included. The header carries the generation time and "
        "the staleness horizon so the border — or you — can tell a quiet list "
        "from a list nobody is updating any more.",
}


def hint_for(key: str) -> str:
    """Prose for one explainable thing, from either catalog.

    ``PAGE_HINTS`` first, then ``UI_HINTS``, so a console chip that shows the
    same fact as a Settings chip reuses the one description instead of growing
    a second — the failure this section already had twice, once with the pane
    and once with the site footer.

    An unknown key returns "" and the macro then renders nothing. Deliberate:
    raising would turn a typo in a template into a 500 on the incidents
    console, which is a far worse trade than a missing icon. A typo is supposed
    to be caught by ``tests/test_sentinel_page_hints.py``, which reads the keys
    out of the templates themselves and fails on any that no catalog answers.
    """
    return PAGE_HINTS.get(key) or UI_HINTS.get(key, "")

_BY_KEY = {s["key"]: s for s in SPEC}

GROUPS = [
    ("detection", "Detection & correlation"),
    ("baseline", "Behavioural baseline"),
    ("vuln", "Vulnerability intelligence"),
    ("edge", "Border corroboration"),
    ("blocklist", "Border blocklist feed"),
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
