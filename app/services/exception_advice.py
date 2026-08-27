"""Ask an assistant whether this carve-out is the RIGHT remedy — before saving.

The operator asked for a gate: *before implementing anything, offer the option
of using AI to analyse the exception and see whether it is the appropriate one
to implement.* Three properties make that a gate rather than a decoration:

1. **OPT-IN, and it never blocks.** The advisory is requested explicitly and
   returns a recommendation, not a veto. A model that can stop a change becomes
   an outage during an incident, which is exactly when a false positive needs
   waiving fastest.
2. **The deterministic half runs even when no model is configured.**
   :mod:`exception_explain` already knows how broad a carve-out is, what it
   stops and what it keeps, and :mod:`wpp_scope` already knows who else stands
   behind the profile. Those are FACTS and they are the part worth trusting; a
   node with the advisor disabled still gets them. Returning nothing at all
   because a model is unreachable would make the honest checks depend on the
   guessing one.
3. **The model never sees a secret and never sees the fleet.** It is handed the
   carve-out's own fields plus the derived facts, through
   :func:`advisor.redact_with_count` and wrapped as untrusted input the same way
   every other advisor call is.

The verdict vocabulary is closed and deliberately small. "Looks proportionate /
too broad / wrong tool / cannot tell" are four ACTIONS an operator can take; a
free-text opinion is one they have to interpret.
"""
from __future__ import annotations

from typing import Any

from . import exception_explain
from . import wpp_exceptions as store

PROPORTIONATE = "proportionate"
TOO_BROAD = "too-broad"
WRONG_TOOL = "wrong-tool"
UNKNOWN = "cannot-tell"
VERDICTS = (PROPORTIONATE, TOO_BROAD, WRONG_TOOL, UNKNOWN)

VERDICT_LABEL = {
    PROPORTIONATE: "Looks proportionate",
    TOO_BROAD: "Broader than the problem",
    WRONG_TOOL: "Probably the wrong instrument",
    UNKNOWN: "Not enough information",
}

SYSTEM = (
    "You are reviewing a proposed FortiWeb WAF carve-out (an exception or a "
    "signature customisation) BEFORE it is implemented. Judge only whether it "
    "is the appropriate, narrowest instrument for the stated problem.\n"
    "Answer with a short verdict line of exactly one of: proportionate, "
    "too-broad, wrong-tool, cannot-tell — then at most five bullet points, then "
    "one concrete narrower alternative if the verdict is not 'proportionate'.\n"
    "Do not invent device state. You are given the carve-out's own fields and "
    "SATOM's derived analysis; anything not there is unknown to you and must be "
    "reported as unknown rather than assumed."
)


def deterministic(exc_type: str, payload: dict, *, wpp: str = "",
                  policy: str = "", scope_verdict: dict | None = None
                  ) -> dict[str, Any]:
    """The half that needs no model. Facts, plus the concerns they imply.

    Never raises and never calls out. This is what a node with the advisor
    switched off still gets — and it is the part that is actually checkable.
    """
    ex = exception_explain.explain(exc_type, payload, wpp=wpp, policy=policy)
    concerns: list[dict] = []

    if ex["breadth"] in ("broad", "very-broad"):
        concerns.append({
            "key": "breadth", "severity": "high",
            "text": "%s — %s" % (ex["breadth_label"], ex["breadth_why"]),
            "ask": "Can this be pinned to a narrower host, URL or parameter?"})
    if ex["missing_required"]:
        concerns.append({
            "key": "incomplete", "severity": "high",
            "text": "Required field(s) empty: %s."
                    % ", ".join(ex["missing_required"]),
            "ask": "An unset field is not a wildcard on every FortiWeb "
                   "release — fill it or confirm the default."})
    if ex["unknown_fields"]:
        concerns.append({
            "key": "unknown-fields", "severity": "medium",
            "text": "Field(s) SATOM's catalog does not describe: %s."
                    % ", ".join(ex["unknown_fields"]),
            "ask": "They are pushed verbatim and validated only by the box."})
    if not ex["injectable"]:
        concerns.append({
            "key": "not-pushable", "severity": "medium",
            "text": "This type has no device mapping — it can be recorded but "
                    "not pushed from SATOM.",
            "ask": "Somebody will have to make the change by hand; record "
                   "where."})
    if scope_verdict and scope_verdict.get("needs_clone"):
        concerns.append({
            "key": "shared-profile", "severity": "high",
            "text": scope_verdict.get("summary") or
                    "The Web Protection Profile is shared or template-managed.",
            "ask": "Clone the profile for this policy first, or accept that "
                   "the waiver applies to every policy behind it."})

    # The deterministic verdict is deliberately CONSERVATIVE: it can say
    # "too-broad" from a fact, but it never says "proportionate" — that is a
    # judgement about the problem being solved, and nothing here has been told
    # what the problem is.
    verdict = TOO_BROAD if any(c["severity"] == "high" for c in concerns) else UNKNOWN
    return {
        "verdict": verdict,
        "verdict_label": VERDICT_LABEL[verdict],
        "explain": ex,
        "concerns": concerns,
        "source": "satom",
    }


def prompt_for(exc_type: str, payload: dict, *, wpp: str = "", policy: str = "",
               problem: str = "", det: dict | None = None) -> str:
    """The user-visible text that would be sent. Shown BEFORE sending.

    An operator about to hand a carve-out to an external provider is entitled
    to read the exact bytes first — the same contract
    :func:`advisor.preview_outbound` gives every other advisor call.
    """
    from . import advisor
    d = det or deterministic(exc_type, payload, wpp=wpp, policy=policy)
    ex = d["explain"]
    lines = [
        "Proposed carve-out: %s (%s)" % (ex["type_label"], ex["category"]),
        "Where it would live: %s" % " > ".join(ex["gui_path"] or ["(unscoped)"]),
        "What it stops: %s" % ex["stops"],
        "What it keeps: %s" % ex["keeps"],
        "SATOM's breadth analysis: %s — %s" % (ex["breadth_label"], ex["breadth_why"]),
        "",
        "Fields:",
    ]
    for f in ex["fields"]:
        lines.append("  - %s = %s%s" % (f.get("label") or f.get("key"),
                                        f.get("value"),
                                        "" if f.get("known") else "  (not in catalog)"))
    if d["concerns"]:
        lines.append("")
        lines.append("SATOM's own concerns:")
        for c in d["concerns"]:
            lines.append("  - [%s] %s" % (c["severity"], c["text"]))
    lines.append("")
    lines.append("The problem it is meant to solve, as stated by the operator:")
    lines.append(problem.strip() or "(the operator gave no description)")
    body = "\n".join(lines)
    redacted, _n = advisor.redact_with_count(body)
    return advisor.wrap_untrusted("proposed-carve-out", redacted)


def parse_verdict(text: str) -> str:
    """First recognised verdict token in the model's answer, else UNKNOWN.

    Scanned in a FIXED order and matched on the token, not on prose: a reply
    that argues its way to 'not too-broad' must not be read as 'too-broad'
    merely because the string occurs. The order puts the cautious verdicts
    first so an ambiguous answer degrades toward caution.
    """
    low = (text or "").lower()
    head = low.split("\n", 3)
    head = "\n".join(head[:3])
    for token in (WRONG_TOOL, TOO_BROAD, PROPORTIONATE, UNKNOWN):
        if token in head:
            return token
    return UNKNOWN


def available() -> bool:
    """Is a model actually reachable for this? Never guesses True."""
    try:
        from . import advisor
        return bool(advisor.enabled() and advisor.list_providers())
    except Exception:  # noqa: BLE001 — an unconfigured node is not an error
        return False


def analyse(exc_type: str, payload: dict, *, wpp: str = "", policy: str = "",
            problem: str = "", scope_verdict: dict | None = None,
            provider_key: str = "", use_model: bool = True) -> dict[str, Any]:
    """The full advisory: deterministic facts, plus a model opinion if asked.

    Returns the deterministic half even when the model leg fails, and says WHY
    it failed. A blank advisory and a clean advisory look identical and mean
    opposite things.
    """
    det = deterministic(exc_type, payload, wpp=wpp, policy=policy,
                        scope_verdict=scope_verdict)
    out = dict(det, model=None, model_error="", prompt=None,
               model_available=available())
    if not use_model:
        return out
    out["prompt"] = prompt_for(exc_type, payload, wpp=wpp, policy=policy,
                               problem=problem, det=det)
    if not out["model_available"]:
        out["model_error"] = ("No assistant provider is configured or enabled "
                              "on this node — the analysis above is SATOM's own.")
        return out
    try:
        from . import advisor, advisor_providers
        prov = (advisor.get_provider(provider_key) if provider_key
                else advisor.get_provider(advisor.default_provider_key()))
        if not prov:
            out["model_error"] = "The chosen provider no longer exists."
            return out
        res = advisor_providers.send(
            prov["kind"], base_url=prov["base_url"],
            api_key=advisor._provider_secret(prov["key"]),
            model=prov["model"], system=SYSTEM,
            messages=[{"role": "user", "content": out["prompt"]}])
        text = getattr(res, "text", "") or ""
        out["model"] = {
            "provider": prov["key"], "model": prov["model"],
            "text": text, "verdict": parse_verdict(text),
            "verdict_label": VERDICT_LABEL[parse_verdict(text)],
            "source": "model",
        }
    except Exception as exc:  # noqa: BLE001 — an advisory must never block a save
        out["model_error"] = str(exc)[:400]
    return out


def type_suggestions(problem: str) -> list[dict]:
    """Catalog entries whose words overlap the described problem.

    Crude on purpose and labelled as such on screen. Its job is to put "you may
    be reaching for the wrong instrument" in front of somebody who has already
    decided which type to use — not to choose for them.
    """
    words = {w for w in (problem or "").lower().replace("/", " ").split()
             if len(w) > 3}
    if not words:
        return []
    hits: list[tuple[int, dict]] = []
    for t in store.CATALOG:
        hay = ("%s %s" % (t["label"], t["group"])).lower()
        score = sum(1 for w in words if w in hay)
        help_ = store.help_for(t["key"])
        score += sum(1 for w in words
                     if w in (help_.get("what", "") + help_.get("backend", "")).lower())
        if score:
            hits.append((score, {"key": t["key"], "label": t["label"],
                                 "group": t["group"], "score": score}))
    hits.sort(key=lambda kv: (-kv[0], kv[1]["label"]))
    return [h[1] for h in hits[:5]]


__all__ = [
    "PROPORTIONATE", "TOO_BROAD", "WRONG_TOOL", "UNKNOWN", "VERDICTS",
    "VERDICT_LABEL", "SYSTEM", "deterministic", "prompt_for", "parse_verdict",
    "available", "analyse", "type_suggestions",
]
