"""Sentinel operating modes — named presets over the knobs that already exist.

The operator asked for modes: *alert only, alert and block, high, ultra high*.
This module is deliberately NOT a second engine. A mode is a named set of
values for settings and per-action policy rows that the product already had,
and applying one is exactly equivalent to typing those values by hand. There
is no code path anywhere that asks "which mode are we in?" — every gate keeps
reading the same knob it always read.

That is the whole design, and it is a decision rather than laziness. A mode
that changed behaviour by itself would be a second place where autonomy is
decided, and the two would eventually disagree: the label would say *Alert
only* while a gate consulted a flag that said otherwise. Here the label cannot
lie about what the engine does, because the engine cannot see it.

Two rules follow from that, and they are what the tests hold:

**The mode is DERIVED, never stored.** :func:`current` reads the live values
and reports the mode whose preset they match — or ``custom``. A stored label
would survive a hand edit of any knob and go on claiming a posture that was no
longer configured; a name for a configuration is only worth having if it is
always true. This is the half the operator asked for explicitly.

**A mode never touches consent or containment.** ``ai_enabled``,
``vuln_sync_enabled`` and ``vuln_api_key`` decide whether this fleet's data
leaves the node; ``protect_cidrs`` and ``hardened_profiles`` decide what can
never be touched no matter how confident a score is. None of them is a
sensitivity setting, and rolling them into an aggressiveness preset would make
"be more thorough" quietly mean "start talking to a vendor" or "your
never-block list changed". They are absent from every preset below, and
:func:`apply` cannot write a key a preset does not name.
"""
from __future__ import annotations

from ...models import db
from ...models_sentinel import SentinelPolicy
from . import actions, config

#: The order the UI draws them in, and the order :func:`current` tests them.
#: Ascending sensitivity. Every preset names the SAME setting keys so no mode
#: can be recognised merely because it says less than another.
MODES: list[dict] = [
    {
        "key": "alert_only",
        "label": "Alert only",
        "summary": "Detects, correlates, scores and explains — and can execute "
                   "nothing. The global kill switch is off, so every action "
                   "stays a proposal whatever the per-action policy says.",
        "risk": "None to traffic. The risk is the opposite one: an incident "
                "nobody reads changes nothing on its own.",
        "settings": {
            "enabled": True,
            "response_enabled": False,
            "min_severity": "low",
            "baseline_k": 6.0,
            "ai_min_score": 40,
            "absorb_minutes": 15,
            "window_pre_s": 60,
            "window_post_s": 300,
            "max_actions_per_hour": 6,
            "device_block_period_s": 600,
        },
        "levels": {"block_ip": 0, "raise_protection": 0,
                   "block_country": 0, "tune_signature": 0},
        "enabled_actions": False,
    },
    {
        "key": "alert_block",
        "label": "Alert and block",
        "summary": "The response engine is armed. Source blocking may act "
                   "semi-automatically inside the semi_auto band; everything "
                   "with a wider blast radius stays a recommendation a person "
                   "approves.",
        "risk": "A wrong correlation can block one source address on one "
                "policy, for one TTL, with the appliance expiring it by "
                "itself. Never a network inside the never-block list.",
        "settings": {
            "enabled": True,
            "response_enabled": True,
            "min_severity": "low",
            "baseline_k": 6.0,
            "ai_min_score": 40,
            "absorb_minutes": 15,
            "window_pre_s": 60,
            "window_post_s": 300,
            "max_actions_per_hour": 6,
            "device_block_period_s": 600,
        },
        "levels": {"block_ip": SentinelPolicy.LEVEL_SEMI_AUTO,
                   "raise_protection": SentinelPolicy.LEVEL_RECOMMEND,
                   "block_country": SentinelPolicy.LEVEL_RECOMMEND,
                   "tune_signature": SentinelPolicy.LEVEL_RECOMMEND},
        "enabled_actions": True,
    },
    {
        "key": "high",
        "label": "High",
        "summary": "Sees more and judges sooner: a tighter baseline band, a "
                   "wider correlation window, a lower bar for asking the "
                   "model, and profile hardening allowed semi-automatically.",
        "risk": "MORE INCIDENTS, not more bad blocks. A lower baseline_k "
                "means ordinary busy hours can score as anomalous, so expect "
                "noise before you expect harm — and raise_protection changes "
                "the posture of every client of a policy.",
        "settings": {
            "enabled": True,
            "response_enabled": True,
            "min_severity": "low",
            "baseline_k": 4.0,
            "ai_min_score": 25,
            "absorb_minutes": 30,
            "window_pre_s": 90,
            "window_post_s": 600,
            "max_actions_per_hour": 12,
            "device_block_period_s": 1200,
        },
        "levels": {"block_ip": SentinelPolicy.LEVEL_SEMI_AUTO,
                   "raise_protection": SentinelPolicy.LEVEL_SEMI_AUTO,
                   "block_country": SentinelPolicy.LEVEL_RECOMMEND,
                   "tune_signature": SentinelPolicy.LEVEL_RECOMMEND},
        "enabled_actions": True,
    },
    {
        "key": "ultra_high",
        "label": "Ultra high",
        "summary": "Escalates on informational signatures, keeps the widest "
                   "correlation window, and lets source blocking run "
                   "autonomously — no human in the loop for that one action.",
        "risk": "THIS ONE CAN CUT GOOD TRAFFIC. Autonomous blocking acts "
                "without an approval, and an informational floor means the "
                "correlator is fed everything the appliance logs. The "
                "containment is not the mode: it is the never-block list and "
                "the TTL, and neither is changed by choosing this.",
        "settings": {
            "enabled": True,
            "response_enabled": True,
            "min_severity": "info",
            "baseline_k": 3.0,
            "ai_min_score": 20,
            "absorb_minutes": 60,
            "window_pre_s": 120,
            "window_post_s": 900,
            "max_actions_per_hour": 24,
            "device_block_period_s": 1800,
        },
        "levels": {"block_ip": SentinelPolicy.LEVEL_AUTONOMOUS,
                   "raise_protection": SentinelPolicy.LEVEL_SEMI_AUTO,
                   "block_country": SentinelPolicy.LEVEL_RECOMMEND,
                   "tune_signature": SentinelPolicy.LEVEL_RECOMMEND},
        "enabled_actions": True,
    },
]

CUSTOM = {
    "key": "custom",
    "label": "Custom",
    "summary": "The live values do not match any preset. Nothing is wrong "
               "with that — it is what hand-tuning produces, and it is "
               "reported rather than rounded to the nearest mode.",
    "risk": "Read the knobs. A name that was applied last week does not "
            "describe a configuration that has been edited since.",
}

#: Every setting key any preset writes. :func:`apply` refuses anything else —
#: consent (AI, outbound vulnerability sync) and containment (never-block
#: list, hardened profiles) are not sensitivity, and a preset must not be able
#: to reach them by a typo.
WRITABLE = sorted({k for m in MODES for k in m["settings"]})

#: Never writable by a mode, whatever a preset says. Listed explicitly so the
#: reason survives: these are the keys whose value is a decision about who may
#: see this fleet's data and about what can never be blocked.
FORBIDDEN = ("ai_enabled", "vuln_enabled", "vuln_sync_enabled", "vuln_api_key",
             "vuln_source", "protect_cidrs", "hardened_profiles")


def by_key(key: str) -> dict | None:
    for m in MODES:
        if m["key"] == key:
            return m
    return None


def _effective_level(action_type: str, want: int) -> int:
    """A preset's level as the catalog will actually allow it.

    ``block_country`` is capped at recommend for a reason that outranks any
    mode: one mis-attributed source address takes a market offline. A preset
    asking for more is clamped here exactly as ``policy_save`` clamps a form,
    so :func:`current` compares against what was really stored rather than
    against a wish, and a mode does not become permanently unrecognisable
    because it asked for something the catalog refuses.
    """
    spec = actions.CATALOG.get(action_type)
    return min(int(want), spec.max_level if spec else 0)


def _policy_state() -> dict:
    """``{action_type: (level, enabled)}`` for every row that has a catalog
    entry. Rows for actions that left the catalog are ignored: they are
    switches wired to nothing and must not decide which mode we are in."""
    out = {}
    for row in SentinelPolicy.query.all():
        if row.action_type in actions.CATALOG:
            out[row.action_type] = (int(row.level or 0), bool(row.enabled))
    return out


def matches(mode: dict, values: dict = None, policies: dict = None) -> list:
    """The keys of ``mode`` the live configuration does NOT satisfy.

    Empty list = this is the current mode. Returned as the differing keys
    rather than a bool because the UI shows them: "you are in Custom" is not
    an answer an operator can act on, and "you are in Custom because
    baseline_k and block_ip differ from High" is.
    """
    values = config.all_values() if values is None else values
    policies = _policy_state() if policies is None else policies
    off = []
    for key, want in mode["settings"].items():
        got = values.get(key)
        if isinstance(want, float) or isinstance(got, float):
            same = abs(float(got) - float(want)) < 1e-9
        else:
            same = got == want
        if not same:
            off.append(key)
    for action_type, want in mode["levels"].items():
        got = policies.get(action_type)
        if got is None:
            off.append(action_type)
            continue
        level, enabled = got
        if level != _effective_level(action_type, want):
            off.append(action_type)
        elif enabled != bool(mode["enabled_actions"]):
            off.append(action_type)
    return off


def current() -> dict:
    """The mode the LIVE values are in, or :data:`CUSTOM`.

    Derived on every read, never stored. A remembered label is a claim that
    goes on being made after the configuration under it has been edited, and
    the operator asked for exactly the opposite: touch a knob by hand and the
    posture is Custom, immediately and without anyone having to remember to
    say so.
    """
    values = config.all_values()
    policies = _policy_state()
    for mode in MODES:
        if not matches(mode, values, policies):
            return mode
    return CUSTOM


def drift() -> dict:
    """``{mode_key: [keys that differ]}`` — what stands between here and each
    preset. This is what makes Custom readable: the nearest mode, and the
    exact list of knobs that would have to move."""
    values = config.all_values()
    policies = _policy_state()
    return {m["key"]: matches(m, values, policies) for m in MODES}


def apply(key: str) -> dict:
    """Write one preset. Returns what changed, per key, before → after.

    Every value goes through :func:`config.set_value`, which coerces and
    clamps against the same spec the Settings form is generated from, and
    every level through the same ceiling ``policy_save`` applies. A preset is
    therefore incapable of storing something the form could not.
    """
    mode = by_key(key)
    if mode is None:
        raise KeyError(f"unknown sentinel mode {key!r}")
    changed = []
    for setting, want in mode["settings"].items():
        if setting in FORBIDDEN:
            # Unreachable by construction; asserted by the tests. Kept as code
            # so that a preset edited in a hurry cannot make it reachable.
            continue
        before = config.get(setting)
        config.set_value(setting, want)
        after = config.get(setting)
        if str(before) != str(after):
            changed.append({"key": setting, "before": before, "after": after})

    actions.ensure_policies()
    for action_type, want in mode["levels"].items():
        row = SentinelPolicy.query.filter_by(action_type=action_type).first()
        if row is None:
            continue
        level = _effective_level(action_type, want)
        was = (int(row.level or 0), bool(row.enabled))
        row.level = level
        row.enabled = bool(mode["enabled_actions"])
        if was != (level, bool(row.enabled)):
            changed.append({"key": action_type,
                            "before": "level %d, %s" % (
                                was[0], "enabled" if was[1] else "disabled"),
                            "after": "level %d, %s" % (
                                level, "enabled" if row.enabled else "disabled")})
    db.session.commit()
    return {"mode": mode["key"], "label": mode["label"], "changed": changed}


def rows() -> list:
    """The render model: every mode, with its settings spelled out in the
    operator's units and the live one marked.

    The values are printed rather than summarised on purpose. A mode whose
    only description is an adjective ("more aggressive") is a mode nobody can
    audit — and this one arms a firewall.
    """
    live = current()
    off = drift()
    labels = {s["key"]: s["label"] for s in config.SPEC}
    out = []
    for mode in MODES:
        out.append({
            "key": mode["key"], "label": mode["label"],
            "summary": mode["summary"], "risk": mode["risk"],
            "active": live["key"] == mode["key"],
            "differs": off.get(mode["key"], []),
            "settings": [{"key": k, "label": labels.get(k, k), "value": v}
                         for k, v in mode["settings"].items()],
            "levels": [{"action_type": a,
                        "level": _effective_level(a, v),
                        "capped": _effective_level(a, v) != v,
                        "want": v}
                       for a, v in mode["levels"].items()],
            "enabled_actions": bool(mode["enabled_actions"]),
        })
    return out
