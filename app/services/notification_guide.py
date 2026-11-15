"""Notification guide — what each recurring notification means and how to fix it.

The bell repeats a small set of findings hundreds of times (the alert engine,
``services.alerts``, raises the same handful of titles for every device and
every run). Each one already carries its evidence in the body; what it did not
carry was the *procedure*: what the words mean, why it usually fires and what
the operator does next. This catalogue is that procedure, written once, shown
in two places:

* the Notifications page drawer, under the notification it matches;
* the Notifications guide page (``/notifications/guide``), as a manual.

Matching is by TITLE, with SQL ``LIKE`` patterns, so the same patterns filter
the page server-side (category filter) and classify a row in Python. Two
rules keep the two in agreement:

* patterns never contain ``_`` — in ``LIKE`` it is a wildcard, and a title
  with an underscore would match where the Python side says it does not;
* every entry's ``example`` must match that entry and no other
  (``tests/test_notification_guide.py``), so categories never overlap.

The text is written against the code that raises the finding. When an alert's
wording or remedy changes in ``services.alerts`` (or ``ha_link``,
``device_health``), the entry here changes with it.
"""
from __future__ import annotations

import re
from functools import lru_cache

#: Category key -> label, in the order the filter and the guide list them.
CATEGORIES = [
    ("drift", "Configuration drift"),
    ("device", "Device health"),
    ("signatures", "Signatures"),
    ("automation", "Scheduled automations"),
    ("satom", "SATOM node & HA"),
    ("certs", "Certificates"),
    ("backup", "Backups"),
    ("intent", "Templates & intent"),
    ("catalog", "API catalog"),
    ("engine", "Alert engine"),
]
CATEGORY_LABEL = dict(CATEGORIES)
#: Rows no entry matches (job results, bug reports, Wiki…).
OTHER = "other"
OTHER_LABEL = "Jobs & other"

#: Links reused by several entries: (label, path).
L_BACKUP = ("System Backup & Restore", "/system-backup/")
L_AUDIT = ("Audit Log", "/audit/")
L_HEALTH = ("Device health", "/monitoring/")
L_DEVICES = ("Appliances", "/appliances/")
L_THRESH = ("Settings › Thresholds", "/settings/#tab-thresholds")
L_ALERTS = ("Settings › Email & Alerts", "/settings/#tab-email")
L_SYSAUTO = ("System Automations", "/web/scheduled-actions/")
L_AUTO = ("Scheduler", "/web/automations/")
L_UPDATE = ("Software Update & HA", "/self-update/")
L_SIG = ("Signatures", "/web/signatures/")
L_CERT = ("Certificate renewals", "/cert-manager/renewals")
L_TMPL = ("Template Library", "/web/templates/")
L_REGISTRY = ("Registry", "/web/registry/")

GUIDE: list[dict] = [
    # ---- configuration drift ---------------------------------------------
    {
        "slug": "drift-device-side",
        "category": "drift",
        "title": "Config drift on <device>",
        "example": "Config drift on fortiweb19",
        "patterns": ["Config drift on %"],
        "stored_kind": "warning",
        "meaning": (
            "The device's configuration changed: the harvest stored a new "
            "source-of-truth version inside the drift window. SATOM then looked "
            "for a write of its own to that device (the Audit Log) between the "
            "last harvest that still saw the previous configuration and the "
            "harvest that saw the new one, and found none. \"SATOM recorded no "
            "write of its own to this device\" therefore means: the change did "
            "not come from SATOM."),
        "causes": [
            "An administrator changed the device directly, on its GUI or CLI.",
            "Another tool wrote to it (FortiManager, Ansible, a script, an API client).",
            "A firmware upgrade, a FortiGuard update or an HA sync rewrote part of the configuration.",
            "The device returns a value that changes on every read, so it \"drifts\" with nobody touching it.",
        ],
        "steps": [
            "Open System Backup & Restore and compare the two versions the message names "
            "(content and previous hash): the A/B diff shows exactly which objects changed.",
            "Find who made the change on the device itself: its admin/event log for the "
            "same window (logins and configuration changes).",
            "Expected and approved: nothing to do. The new version is now the baseline and "
            "the same content never raises this alert twice.",
            "Not expected: put the previous configuration back (restore the object from the "
            "vault, or re-apply the bound template from the Template Library) and review who "
            "holds write access to the device.",
            "It keeps drifting with nobody touching it: a field on that device is volatile. "
            "Report it with the diff (Report a bug) so SATOM normalises the field; until "
            "then, put the device in maintenance from its page to park it.",
        ],
        "links": [L_BACKUP, L_AUDIT, L_DEVICES, L_TMPL],
    },
    {
        "slug": "drift-satom",
        "category": "drift",
        "title": "Config change on <device> — made through SATOM",
        "example": "Config change on fortiweb19 — made through SATOM",
        "patterns": ["Config change on % — made through SATOM"],
        "stored_kind": None,
        "meaning": (
            "The device's configuration changed and SATOM did record write(s) of its "
            "own to that device in the interval the change has to fall in. The "
            "message lists them (who, what, when). This is an expected change, not "
            "drift."),
        "causes": [
            "Somebody deployed, edited or restored something on the device from SATOM.",
        ],
        "steps": [
            "Nothing to do when one of the listed writes is the change.",
            "If none of them explains it, compare the two versions on System Backup & "
            "Restore: a device-side edit can land in the same window.",
            "To stop these notices: Settings › Email & Alerts › changes made through "
            "SATOM → Do not report it (or Report it as drift, to keep them as warnings).",
        ],
        "links": [L_BACKUP, L_AUDIT, L_ALERTS],
    },
    # ---- device health ---------------------------------------------------
    {
        "slug": "device-critical",
        "category": "device",
        "title": "Device <device> is critical",
        "example": "Device fortiadc10 is critical",
        "patterns": ["Device % is critical%"],
        "stored_kind": "error",
        "meaning": (
            "The device's health reached CRITICAL on the same ladder Device health "
            "uses. The body lists every failing signal: Reachability (no TCP "
            "connection to its management port), Harvest (the last syncs failed, "
            "three or more in a row is critical), Cache (configuration older than "
            "4× the stale limit), Deep monitors (a probe reading past its critical "
            "line) or Capacity."),
        "causes": [
            "The device is powered off, or the route/firewall to its management port is down.",
            "Its licence is invalid or expired — REST answers \"Invalid VM License\" or HTTP 423, so every read fails.",
            "The API token or admin password stored in SATOM was changed on the device (401/403).",
            "A deep monitor reading (CPU, memory, sessions…) is above its critical threshold.",
        ],
        "steps": [
            "Read the reason lines in the message, then open Device health: each signal on "
            "the device's card shows its own fix.",
            "Reachability: check the device is on and reachable from the SATOM node "
            "(routing, firewall, management port).",
            "Harvest: read the error after the dash. Connect/timeout → network; 401/403 → "
            "update the credentials on the device form (Edit); licence → the device needs a "
            "valid licence before anything else can work.",
            "Deep monitors: the message shows the reading and the limit and where that limit "
            "is set; fix the load, or adjust the line under Settings › Thresholds for that product.",
            "Planned outage or a lab box that is down on purpose: switch on maintenance on the "
            "device page — device alerts, drift and scheduled runs skip it.",
            "The alert clears on its own after the next good harvest.",
        ],
        "links": [L_HEALTH, L_DEVICES, L_THRESH],
    },
    {
        "slug": "device-degraded",
        "category": "device",
        "title": "Device <device> is degraded",
        "example": "Device faz02 is degraded — Memory 80.1% (warning 80%)",
        "patterns": ["Device % is degraded%"],
        "stored_kind": "warning",
        "meaning": (
            "The device's health is at WARNING: one harvest failed, the cached "
            "configuration is older than the stale limit, a deep monitor is past "
            "its warning line, or the reachability probe failed once. When a probe "
            "is the reason, the title carries its reading (for example \"Memory "
            "80.1% (warning 80%)\")."),
        "causes": [
            "A single failed harvest (a timeout, a reboot, a short network outage).",
            "A resource reading sitting right on its warning threshold.",
        ],
        "steps": [
            "Open Device health and read the signal on the device's card.",
            "A one-off harvest error clears on the next good hourly run — no action needed "
            "unless it becomes critical.",
            "A reading that is normal for this box (a VM that always runs at 80 % memory): "
            "raise that product's warning line under Settings › Thresholds instead of "
            "learning to ignore the alert.",
            "A reading that is not normal: treat it on the device (load, sessions, logs).",
        ],
        "links": [L_HEALTH, L_THRESH],
    },
    # ---- signatures ------------------------------------------------------
    {
        "slug": "signature-stale",
        "category": "signatures",
        "title": "Signature DB on <device> is stale",
        "example": "Signature DB on fortiweb17 is stale",
        "patterns": ["Signature DB on % is stale"],
        "stored_kind": "warning",
        "meaning": (
            "The FortiWeb's attack signature database is older than the allowed age "
            "(alerts.signature_max_days, 7 days by default) or the device reports it "
            "never updated. A WAF on old signatures protects against last month. "
            "SATOM only reads what the signature_check automation stored — it does "
            "not contact the device for this alert."),
        "causes": [
            "The device cannot reach FortiGuard (DNS, route, proxy, firewall).",
            "The FortiGuard / FortiWeb licence is missing or expired (an unlicensed VM never updates).",
        ],
        "steps": [
            "On the device: System › FortiGuard — check the licence and the last update "
            "attempt, and that it resolves and reaches the FortiGuard servers.",
            "Fix the connectivity or the licence, then let the device update (or trigger "
            "the update on the device).",
            "The alert clears after the next signature_check run reads the new version.",
        ],
        "links": [L_SIG, L_SYSAUTO],
    },
    {
        "slug": "signature-unreadable",
        "category": "signatures",
        "title": "Signature DB version unreadable on <device>",
        "example": "Signature DB version unreadable on fortiweb18",
        "patterns": ["Signature DB version unreadable on %"],
        "stored_kind": "warning",
        "meaning": (
            "SATOM could not read the signature database version from the device, "
            "neither over REST nor with the SSH fallback the message names."),
        "causes": [
            "REST access refused (credentials, licence, trusted hosts).",
            "SSH disabled or refused for the stored account.",
        ],
        "steps": [
            "Check the device's REST access first — the same fix as a failing harvest "
            "(see Device health).",
            "The alert clears after the next signature_check run reads a version.",
        ],
        "links": [L_HEALTH, L_SIG],
    },
    {
        "slug": "signature-source",
        "category": "signatures",
        "title": "No signature source configured",
        "example": "No signature source configured",
        "patterns": ["No signature source configured"],
        "stored_kind": "warning",
        "meaning": (
            "FortiWeb devices are registered, but no device is chosen as the source "
            "of the local signature index (or the chosen one was deleted). The "
            "Signatures page would otherwise show a frozen catalogue as if it were "
            "current."),
        "causes": [
            "First install: no source chosen yet.",
            "The appliance that was the source was removed or put in maintenance.",
        ],
        "steps": [
            "Open Signatures and choose a source device (a licensed FortiWeb that updates "
            "from FortiGuard).",
        ],
        "links": [L_SIG],
    },
    # ---- scheduled automations -------------------------------------------
    {
        "slug": "automation-failing",
        "category": "automation",
        "title": "Scheduled automation failing: <name> (#id)",
        "example": "Scheduled automation failing: Hourly fleet sync (source of truth) (#5)",
        "patterns": ["Scheduled automation failing: %"],
        "stored_kind": None,
        "meaning": (
            "An enabled automation failed several SCHEDULED runs in a row (critical "
            "from three). Manual runs do not count. The message quotes the latest "
            "failure's summary."),
        "causes": [
            "One device in its target set fails (no licence, unreachable, wrong "
            "credentials) and the whole run is marked failed — the most common case "
            "for the fleet sync, the nightly snapshot and the deep capture.",
            "The scheduler is running old code (see \"running code older than the disk\").",
            "Something the action needs is not configured (a destination, a token, a source).",
        ],
        "steps": [
            "Open the automation (System Automations or Automations) and read the latest "
            "run's summary: it names the device or the step that failed.",
            "A device that cannot work right now: fix it, or switch on maintenance on the "
            "device page — parked devices are skipped, and a skipped run ends the streak.",
            "\"Unknown action\", or a scheduled run that fails while Run now passes: run "
            "satom execute restart-all on the primary.",
            "After the fix, use Run now to confirm; the alert clears on the next successful "
            "scheduled run.",
        ],
        "links": [L_SYSAUTO, L_AUTO, L_DEVICES],
    },
    {
        "slug": "automation-not-firing",
        "category": "automation",
        "title": "Scheduled automation not firing: <name> (#id)",
        "example": "Scheduled automation not firing: Nightly certificate scan (#7)",
        "patterns": ["Scheduled automation not firing: %"],
        "stored_kind": None,
        "meaning": (
            "The automation is enabled but its next run is hours overdue and it has "
            "not fired. A scheduler that stops produces no failed runs at all, so "
            "this is the only signal that it stopped."),
        "causes": [
            "satom-scheduler is stopped, wedged or running old code on the primary.",
        ],
        "steps": [
            "On the primary: satom get system health — it shows every SATOM unit and "
            "whether it runs current code.",
            "Run satom execute restart-all. Never restart only satom.service: the scheduler "
            "is a separate process and keeps the old code.",
            "The alert clears once the automation fires again.",
        ],
        "links": [L_SYSAUTO, L_AUTO],
    },
    # ---- SATOM node & HA -------------------------------------------------
    {
        "slug": "code-stale",
        "category": "satom",
        "title": "<unit> on <node> is running code older than the disk",
        "example": "satom-scheduler.service on satom-node-1 is running code older than the disk",
        "patterns": ["% is running code older than the disk"],
        "stored_kind": "warning",
        "meaning": (
            "A SATOM process started before the newest source file was written, so it "
            "still runs the previous release. Scheduled work can fail or skip while a "
            "manual run of the same thing passes."),
        "causes": [
            "An update or a deploy restarted only part of the services.",
        ],
        "steps": [
            "On the node named in the title: satom execute restart-all (web, scheduler and "
            "reconciler in order, then /healthz).",
        ],
        "links": [L_UPDATE],
    },
    {
        "slug": "ha-link",
        "category": "satom",
        "title": "HA link broken",
        "example": "HA link broken: standby satom-node-2 cannot fetch code from satom-node-1",
        "patterns": ["HA link broken%"],
        "stored_kind": "error",
        "meaning": (
            "The standby cannot fetch code from the primary (or systemd-logind on the "
            "primary is wedged, which blocks the SSH sessions the standby uses). Until "
            "it is repaired the standby stops following the primary."),
        "causes": [
            "systemd-logind on the primary is stuck.",
            "The repository on the primary became unreadable for the satom user "
            "(for example after git was run there as root).",
        ],
        "steps": [
            "Software Update & HA › HA link, or satom ha check on the primary.",
            "Repair: the Repair HA link button, or sudo satom ha repair --yes (restarts "
            "systemd-logind on the primary).",
            "If the check reports a permission error on the repository: chown it back to "
            "satom; the standby converges on its next cycle.",
        ],
        "links": [L_UPDATE],
    },
    {
        "slug": "host",
        "category": "satom",
        "title": "Host <node> is degraded / critical",
        "example": "Host satom-node-1 is degraded",
        "patterns": ["Host % is degraded%", "Host % is critical%"],
        "stored_kind": None,
        "meaning": (
            "The machine SATOM runs on is short of disk, memory or CPU (load). The "
            "body lists each signal with its reading."),
        "causes": [
            "Disk: release bundles, backups or logs piling up under the data directory.",
            "Memory/load: a heavy job, a runaway process or an undersized VM.",
        ],
        "steps": [
            "On that node: df -h and du -sh on the data directory for disk; top for "
            "memory and load.",
            "Free or grow the resource; thresholds are under Settings › Thresholds › "
            "SATOM host.",
        ],
        "links": [L_THRESH, L_BACKUP],
    },
    {
        "slug": "git-unpushed",
        "category": "satom",
        "title": "<node> has N commit(s) unpushed for Nh",
        "example": "satom-node-1 has 1 commit(s) unpushed for 7h",
        "patterns": ["% commit(s) unpushed for %"],
        "stored_kind": None,
        "meaning": (
            "Local commits have not reached the git remote for longer than the "
            "threshold (6 h by default). Until the push succeeds they exist on this "
            "node only."),
        "causes": [
            "The git server is down or unreachable, or its token expired.",
        ],
        "steps": [
            "Check the remote (Software Update & HA › repository) and push again.",
            "Until it works, take a git bundle from System Backup & Restore to get the "
            "commits off the box.",
        ],
        "links": [L_UPDATE, L_BACKUP],
    },
    {
        "slug": "git-diverged",
        "category": "satom",
        "title": "Git history diverged on <node>",
        "example": "Git history diverged on satom-node-1",
        "patterns": ["Git history diverged on %"],
        "stored_kind": "error",
        "meaning": (
            "The local branch is both ahead of and behind the remote: the histories "
            "forked and cannot fast-forward. The HA pair can end up running different "
            "code."),
        "causes": [
            "A commit was made on the node while the remote moved on.",
        ],
        "steps": [
            "Reconcile by hand (rebase the local commits onto the remote, or drop them) "
            "before the nodes disagree. Take a git bundle first.",
        ],
        "links": [L_UPDATE, L_BACKUP],
    },
    {
        "slug": "git-behind",
        "category": "satom",
        "title": "<node> is N commits behind origin",
        "example": "satom-node-2 is 30 commits behind origin",
        "patterns": ["% commits behind origin"],
        "stored_kind": "warning",
        "meaning": (
            "This node is far behind the remote (more than 25 commits by default). On "
            "the standby it means the code sync is stuck."),
        "causes": [
            "The reconciler cannot fetch (see HA link broken), or it is paused.",
        ],
        "steps": [
            "Software Update & HA: check the reconciler state and the HA link.",
        ],
        "links": [L_UPDATE],
    },
    {
        "slug": "git-unreadable",
        "category": "satom",
        "title": "Git status unreadable",
        "example": "Git status unreadable on satom-node-1",
        "patterns": ["Git status unreadable%", "Git push state unreadable%"],
        "stored_kind": "warning",
        "meaning": (
            "The repository could not be probed, so ahead/behind are not "
            "measurements."),
        "causes": [
            "Wrong ownership or permissions on the repository, or git missing.",
        ],
        "steps": [
            "Run git status in the application directory as the satom user and fix "
            "what it reports.",
        ],
        "links": [L_UPDATE],
    },
    # ---- certificates ----------------------------------------------------
    {
        "slug": "cert-expiry",
        "category": "certs",
        "title": "TLS certificate expires in N day(s)",
        "example": "TLS certificate expires in 13 day(s)",
        "patterns": ["TLS certificate expires in %"],
        "stored_kind": None,
        "meaning": (
            "SATOM's own HTTPS certificate expires within the threshold (14 days by "
            "default; critical from 3 days)."),
        "causes": [
            "An imported certificate (source=imported) is not renewed by SATOM — it "
            "has to be copied again.",
            "An issued certificate whose automatic renewal failed.",
        ],
        "steps": [
            "Open Certificate renewals: it shows the source and the renewal errors.",
            "Imported: install the renewed certificate (with its full chain).",
            "Issued: fix the renewal error shown there and renew.",
        ],
        "links": [L_CERT],
    },
    {
        "slug": "cert-renewal",
        "category": "certs",
        "title": "Certificate renewal failing on <node> (N consecutive)",
        "example": "Certificate renewal failing on satom-node-1 (2 consecutive)",
        "patterns": ["Certificate renewal failing on %"],
        "stored_kind": None,
        "meaning": (
            "The automatic renewal of SATOM's own certificate failed several times "
            "in a row (critical from three). The message quotes the channel and the "
            "last error. Left alone it becomes an expiry alert."),
        "causes": [
            "The issuing CA (ACME or the internal CA) is unreachable or rejected the request.",
            "A DNS or HTTP challenge cannot be satisfied from this node.",
        ],
        "steps": [
            "Open Certificate renewals and read the last error.",
            "Fix the channel it names, then renew from the same page; the streak resets on "
            "the first successful renewal.",
        ],
        "links": [L_CERT],
    },
    # ---- backups ---------------------------------------------------------
    {
        "slug": "backup",
        "category": "backup",
        "title": "No database backup / backup too old",
        "example": "No database backup bundles present",
        "patterns": ["No database backup bundles present", "Newest DB backup is %h old"],
        "stored_kind": "warning",
        "meaning": (
            "No database bundle exists on this node nor on the backup server, or the "
            "newest one is older than the limit (48 h by default)."),
        "causes": [
            "The backup automation is disabled or failing.",
            "The backup server is unreachable, so nothing was uploaded.",
        ],
        "steps": [
            "System Backup & Restore: create a bundle now and check it reaches the backup "
            "server.",
            "Check the backup automation's run history (System Automations).",
        ],
        "links": [L_BACKUP, L_SYSAUTO],
    },
    # ---- templates & intent ----------------------------------------------
    {
        "slug": "intent",
        "category": "intent",
        "title": "Intent deviation on <device>: <template>",
        "example": "Intent deviation on fortiweb19: baseline-waf",
        "patterns": ["Intent deviation on %"],
        "stored_kind": "warning",
        "meaning": (
            "The device no longer matches the template version it is bound to. The "
            "message names the objects and fields that differ (never their values). "
            "The comparison is local — SATOM does not contact the device for it."),
        "causes": [
            "The device was changed after the template was applied (see drift).",
            "The template was never applied to that device.",
        ],
        "steps": [
            "Re-apply the template from the Template Library, or re-bind the device to the "
            "version it actually runs.",
        ],
        "links": [L_TMPL, L_BACKUP],
    },
    # ---- API catalog -----------------------------------------------------
    {
        "slug": "catalog",
        "category": "catalog",
        "title": "Catalog paths / object disappearances",
        "example": "2 fortiweb catalog path(s) look wrong for a firmware line",
        "patterns": ["% catalog path(s) look wrong for a firmware line",
                     "% newly recorded % object disappearance(s)",
                     "% lifecycle ledger pair(s) are no longer tracked"],
        "stored_kind": None,
        "meaning": (
            "Findings about SATOM's own API catalog, not about a device: a REST path "
            "rejected by a firmware line while the device's CLI dump still holds the "
            "block (the catalog is wrong — warning), an object confirmed gone in a "
            "newer firmware (info), or recorded decisions no longer re-proved after a "
            "new firmware line was added (warning)."),
        "causes": [
            "A firmware line renamed or moved an endpoint.",
        ],
        "steps": [
            "Review it on Registry › firmware comparison; report a wrong path with the "
            "message so the catalog is corrected.",
        ],
        "links": [L_REGISTRY],
    },
    # ---- the alert engine itself -----------------------------------------
    {
        "slug": "engine",
        "category": "engine",
        "title": "An alert check could not run",
        "example": "Alert check _check_devices errored",
        "patterns": ["Alert check % errored", "Appliance list unreadable",
                     "Scheduled action list unreadable", "Run history unreadable for %",
                     "Health roll-up failed for %", "Host health unreadable",
                     "Backup inventory unreadable", "Certificate status unreadable",
                     "Drift scan: %", "Intent scan: %", "Catalog absence %"],
        "stored_kind": None,
        "meaning": (
            "One of SATOM's own checks raised an error, so for that run it measured "
            "nothing. It is not a finding about a device; it means a finding could "
            "have been missed."),
        "causes": [
            "A database or file the check reads was unavailable, or a defect in the check.",
        ],
        "steps": [
            "Look up the error text in the application log (data/logs/satom.log) and "
            "report it if it repeats.",
        ],
        "links": [L_AUDIT],
    },
]

_BY_SLUG = {e["slug"]: e for e in GUIDE}


def _like_to_regex(pattern: str) -> "re.Pattern[str]":
    return re.compile("".join(".*" if part == "%" else re.escape(part)
                              for part in re.split(r"(%)", pattern)), re.DOTALL)


@lru_cache(maxsize=1)
def _compiled() -> list[tuple[dict, list]]:
    return [(e, [_like_to_regex(p) for p in e["patterns"]]) for e in GUIDE]


def match(title: str | None) -> dict | None:
    """The guide entry for a notification title, or ``None``."""
    if not title:
        return None
    for entry, regs in _compiled():
        if any(r.fullmatch(title) for r in regs):
            return entry
    return None


def entry(slug: str) -> dict | None:
    return _BY_SLUG.get(slug)


def category_of(title: str | None) -> str:
    e = match(title)
    return e["category"] if e else OTHER


def category_label(key: str) -> str:
    return CATEGORY_LABEL.get(key, OTHER_LABEL)


def patterns_for(category: str) -> list[str]:
    """Every LIKE pattern of a category (the page's server-side filter)."""
    return [p for e in GUIDE if e["category"] == category for p in e["patterns"]]


def all_patterns() -> list[str]:
    return [p for e in GUIDE for p in e["patterns"]]


def filter_category(query, column, category: str):
    """Narrow ``query`` to rows of ``category`` (``other`` = no entry matches)."""
    from sqlalchemy import and_, or_
    if category == OTHER:
        return query.filter(and_(*[~column.like(p) for p in all_patterns()]))
    pats = patterns_for(category)
    if not pats:
        return query
    return query.filter(or_(*[column.like(p) for p in pats]))


def entries(category: str = "", q: str = "") -> list[dict]:
    """Guide entries narrowed by category and a free-text search."""
    raw = (q or "").strip()
    q = raw.lower()
    # A title pasted from the bell ("Config drift on fortiweb19") finds its
    # entry even though the entry spells it "Config drift on <device>".
    hit = match(raw)
    out = []
    for e in GUIDE:
        if category and e["category"] != category:
            continue
        if q and e is not hit:
            hay = " ".join([e["title"], e["example"], e["meaning"],
                            *e["causes"], *e["steps"]]).lower()
            if q not in hay:
                continue
        out.append(e)
    return out


def public(e: dict) -> dict:
    """What the page's drawer needs of an entry (JSON-safe)."""
    return {"slug": e["slug"], "title": e["title"],
            "category": category_label(e["category"]),
            "meaning": e["meaning"], "causes": e["causes"], "steps": e["steps"],
            "links": [{"label": lbl, "href": href} for lbl, href in e["links"]]}


__all__ = ["CATEGORIES", "GUIDE", "OTHER", "OTHER_LABEL", "match", "entry",
           "category_of", "category_label", "patterns_for", "all_patterns",
           "filter_category", "entries", "public"]
