"""Per-sink alert routing — the filter between the engine and its outlets.

Why this module exists
----------------------
:func:`app.services.alerts.evaluate` answers *"what is wrong?"*.  It has no
opinion about *who should hear it*.  Before this module the answer was
"everyone, everything": ``run()`` handed the whole findings list to the in-app
bell and to email, and the only control an operator had was the engine-wide
on/off switch.

That is survivable with two outlets and fatal with five.  An operator who wires
a chat channel and starts receiving every ``info`` drift note turns the
integration off — and takes the ``critical`` ones with it.  Adding sinks on top
of an unfiltered engine does not expand the alerting capability, it multiplies
one hose.

The filter is deliberately two-dimensional and no more:

* **severity floor** (``min_severity``) — how bad it has to be, and
* **check mask** (``checks``) — which family of finding it has to belong to.

Both reuse vocabulary the operator already reads on the same settings page (the
"Checks enabled" row is the same seven families).  A pattern language over
``key`` was considered and rejected: the rule everybody actually writes is
``.*``, which is this module with far more surface to get wrong.

Two things are deliberately NOT filterable
------------------------------------------
``engine`` findings (a health check itself raised) and findings whose key prefix
this module does not recognise.  Both bypass the floor *and* the mask.

* A filter is a statement about what you want to hear.  "The component that
  decides what you hear is broken" is not a coherent thing to opt out of: a
  channel silenced by a crashed check is indistinguishable from a healthy quiet
  one, which is the exact failure alerting exists to prevent.
* An unrecognised prefix means a new check shipped and nobody taught the router
  about it.  Dropping it is a silent loss that no test and no screen would ever
  show; delivering it is noise, which is visible and fixable.  Fail towards
  delivery.

Defaults reproduce the pre-filter behaviour
-------------------------------------------
``in_app`` and ``email`` default to enabled, ``info`` floor, no mask — exactly
what they did before this module existed.  Upgrading an install must not
quietly narrow an alert path nobody asked to narrow.  ``syslog`` and ``webhook`` are new
and therefore off until configured.
"""
from __future__ import annotations

from ..models import AppSetting

# ---- severity -------------------------------------------------------------
SEV_INFO = "info"
SEV_WARNING = "warning"
SEV_CRITICAL = "critical"
SEVERITIES = (SEV_INFO, SEV_WARNING, SEV_CRITICAL)
_RANK = {SEV_INFO: 0, SEV_WARNING: 1, SEV_CRITICAL: 2}

# ---- families -------------------------------------------------------------
# Finding-key prefix -> family.  The prefix is NOT the family name: the engine
# emits ``action.*`` while its toggle, its settings key and its label all say
# "actions".  Those drifted apart long before this module existed, and mapping
# them explicitly here is far cheaper than renaming a settings key in the
# field.  A mask that silently matched nothing would be the worst of both.
_PREFIX_FAMILY = {
    "cert": "cert",
    "git": "git",
    "device": "device",
    "action": "actions",
    "backup": "backup",
    "drift": "drift",
    "host": "host",
}

#: The maskable families, in the order the settings page prints them.
FAMILIES = ("cert", "git", "device", "backup", "drift", "actions", "host")

FAMILY_LABELS = {
    "cert": "Cert expiry",
    "git": "Git divergence",
    "device": "Device health",
    "backup": "Backup freshness",
    "drift": "Config drift",
    "actions": "Scheduled automation",
    "host": "Host resources",
}

#: Families no filter may drop.  See the module docstring.
FAM_ENGINE = "engine"
FAM_UNKNOWN = "unknown"
UNFILTERABLE = (FAM_ENGINE, FAM_UNKNOWN)


def family_of(key: str) -> str:
    """Map a finding key to its family.

    Unrecognised prefixes resolve to :data:`FAM_UNKNOWN`, which is
    unfilterable — a check this router has never heard of still gets delivered.
    """
    prefix = (key or "").split(".", 1)[0].strip()
    if prefix == FAM_ENGINE:
        return FAM_ENGINE
    return _PREFIX_FAMILY.get(prefix, FAM_UNKNOWN)


# ---- sinks ----------------------------------------------------------------
SINK_IN_APP = "in_app"
SINK_EMAIL = "email"
SINK_WEBHOOK = "webhook"
SINK_HOOKS = "hooks"
SINK_SYSLOG = "syslog"

#: Sinks that notify a *person* — these carry the cooldown and decide
#: ``dispatched``.  ``syslog`` is a feed and is handled separately: see
#: :mod:`app.services.alert_syslog`.
#: ``hooks`` is here because it is on the notification path and therefore
#: carries the cooldown -- without it a Telegram starter re-sends every
#: finding every fifteen minutes forever. It is NOT counted in
#: ``dispatched``: dispatching a hook writes a JSON file, and the runner
#: that turns it into a process is a different unit that can be stopped.
NOTIFICATION_SINKS = (SINK_IN_APP, SINK_EMAIL, SINK_WEBHOOK, SINK_HOOKS)
#: Notification sinks first, then the feed: the settings page iterates
#: this tuple, and a record listed among recipients invites the reading
#: that silencing it is as harmless as silencing a mailbox.
SINKS = (SINK_IN_APP, SINK_EMAIL, SINK_WEBHOOK, SINK_HOOKS, SINK_SYSLOG)

SINK_LABELS = {
    SINK_IN_APP: "In-app bell",
    SINK_EMAIL: "Email",
    SINK_WEBHOOK: "Webhook (HTTP POST)",
    SINK_HOOKS: "Integration hooks",
    SINK_SYSLOG: "Syslog / CEF feed",
}

# ``in_app``/``email`` default ON because that is what they did before the
# router existed; upgrading must not quietly narrow a path nobody asked to
# narrow. ``webhook``/``syslog`` are new and have nowhere to point yet.
_DEFAULT_ENABLED = {SINK_IN_APP: "1", SINK_EMAIL: "1",
                    SINK_WEBHOOK: "0", SINK_HOOKS: "0",
                    SINK_SYSLOG: "0"}


def _k(sink: str, field: str) -> str:
    return "alerts.sink.%s.%s" % (sink, field)


def is_enabled(sink: str) -> bool:
    raw = AppSetting.get(_k(sink, "enabled"))
    if raw is None:
        raw = _DEFAULT_ENABLED.get(sink, "0")
    return raw in ("1", "on", "true", "True")


def min_severity(sink: str) -> str:
    raw = (AppSetting.get(_k(sink, "min_severity")) or "").strip()
    return raw if raw in SEVERITIES else SEV_INFO


def mask(sink: str):
    """The sink's family mask, or ``None`` for "every family".

    ``None`` means *never configured* and delivers everything, so a fresh
    install is not silent.  A stored empty string is an operator who ticked no
    family: it is honoured literally and the settings page says so out loud.
    Collapsing "" into "all" would deliver the exact opposite of what the
    screen showed.
    """
    raw = AppSetting.get(_k(sink, "checks"))
    if raw is None:
        return None
    return {p.strip() for p in str(raw).split(",") if p.strip() in FAMILIES}


def accepts(*, family: str, severity: str, floor: str, families) -> bool:
    """Pure predicate — no database, no settings.  ``families`` is ``None``
    for "no mask" or a set of family names."""
    if family in UNFILTERABLE:
        return True
    if _RANK.get(severity, 0) < _RANK.get(floor, 0):
        return False
    return families is None or family in families


def route(findings, sink: str) -> list:
    """The findings this sink should receive.  Reads the sink's config once."""
    if not is_enabled(sink):
        return []
    floor = min_severity(sink)
    families = mask(sink)
    return [f for f in findings
            if accepts(family=family_of(f.get("key", "")),
                       severity=f.get("severity", SEV_INFO),
                       floor=floor, families=families)]


# ---- admin console --------------------------------------------------------
def sink_config(sink: str) -> dict:
    families = mask(sink)
    return {
        "name": sink,
        "label": SINK_LABELS.get(sink, sink),
        "enabled": is_enabled(sink),
        "min_severity": min_severity(sink),
        # ``checks`` is the set to tick in the UI; ``masked`` says whether a
        # mask exists at all, so the template can distinguish "all families"
        # from "every box unticked" instead of rendering both as empty.
        "checks": sorted(families) if families is not None else list(FAMILIES),
        "masked": families is not None,
        "silent": families is not None and not families,
    }


def config() -> dict:
    return {s: sink_config(s) for s in SINKS}


def save(sink: str, form) -> None:
    """Persist one sink's routing from the settings form.

    The mask is only written when the form says it carried the checkboxes
    (``<sink>_checks_submitted``).  Without that marker an unrelated partial
    POST would read "no boxes ticked" and silence the sink — the same shape of
    bug as a checkbox form that forgets its hidden marker field.
    """
    def g(key, default=""):
        try:
            return (form.get(key, default) or "").strip()
        except AttributeError:
            return str(form.get(key, default) or "").strip()

    AppSetting.set(_k(sink, "enabled"),
                   "1" if form.get("%s_enabled" % sink) in
                   ("on", "1", "true", "True", True) else "0")

    sev = g("%s_min_severity" % sink)
    # An unrecognised floor falls back to ``info`` and never to ``critical``:
    # a typo in a settings field must not be able to silence an alert path.
    AppSetting.set(_k(sink, "min_severity"),
                   sev if sev in SEVERITIES else SEV_INFO)

    if form.get("%s_checks_submitted" % sink):
        try:
            picked = form.getlist("%s_checks" % sink)
        except AttributeError:
            raw = form.get("%s_checks" % sink) or []
            picked = raw if isinstance(raw, (list, tuple)) else [raw]
        AppSetting.set(_k(sink, "checks"),
                       ",".join(p for p in picked if p in FAMILIES))


def save_all(form) -> None:
    for sink in SINKS:
        save(sink, form)


__all__ = [
    "FAMILIES", "FAMILY_LABELS", "SEVERITIES", "SINKS", "SINK_LABELS",
    "NOTIFICATION_SINKS", "SINK_IN_APP", "SINK_EMAIL", "SINK_WEBHOOK",
    "SINK_HOOKS", "SINK_SYSLOG",
    "UNFILTERABLE", "FAM_ENGINE", "FAM_UNKNOWN",
    "family_of", "accepts", "route", "is_enabled", "min_severity", "mask",
    "config", "sink_config", "save", "save_all",
]
