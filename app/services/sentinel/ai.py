"""AI reasoning — a pure function from an incident to an opinion.

The contract, and why it is this narrow
---------------------------------------
``reason(incident) -> opinion``. The model receives a serialised incident that
already exists, already has a score, and already has evidence. It returns
prose and a recommendation drawn from a CLOSED enum. That is the whole surface.

It has **no tools, no network access of its own, no credentials, and no writer
to any field an operator reads as measurement.** Its output lands in
``SentinelIncident.ai_json`` and nowhere else, stamped with the model name and
a hash of the prompt so that months later it is possible to ask "what exactly
was this model shown when it said that?" — a question that is unanswerable for
most deployed LLM features and is the first one asked in a post-mortem.

Failure is designed to be boring
--------------------------------
Timeout, connection refused, malformed JSON, a recommendation outside the enum:
all of them produce ``{"ok": False, "error": ...}`` and the incident carries on
with its deterministic score, its evidence and its policy decision intact. An
installation whose model host is switched off loses prose. It does not lose
detection, scoring, gating or history. That property is the reason the model
sits here rather than in the middle of the pipeline.

Disagreement is displayed, not resolved
---------------------------------------
When the model's recommendation differs from the policy engine's, both are
shown side by side and the policy engine's stands. There is no code path in
which the model's opinion changes an action, a score, or a band.
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from datetime import datetime

from . import config

#: The ONLY recommendations a model may return. Anything else is rejected as a
#: malformed response — an enum an operator can read is worth more than free
#: text that occasionally invents a capability this product does not have.
ALLOWED_RECOMMENDATIONS = (
    "observe", "investigate", "block_ip", "rate_limit_ip",
    "raise_protection", "tune_signature", "close_false_positive",
)

ALLOWED_ASSESSMENTS = (
    "normal_traffic", "anomaly", "false_positive", "real_attack",
    "real_attack_appliance_impact", "real_attack_infrastructure_impact",
)

SYSTEM_PROMPT = (
    "You are a security analyst reviewing ONE already-correlated incident from "
    "a web application firewall fleet. You are given measured evidence: attack "
    "log entries, HTTP response behaviour, appliance counters, virtual machine "
    "and hypervisor metrics, and vulnerability intelligence. Every number you "
    "are shown was measured; you must not invent any others.\n\n"
    "Rules:\n"
    "1. Reason ONLY from the evidence provided. If a layer is marked unknown, "
    "say it is unknown — do not assume it is healthy.\n"
    "2. Never claim something is an attack without naming which evidence says "
    "so.\n"
    "3. The numeric score was computed deterministically. You may disagree "
    "with it in your explanation, but do not restate it as your own.\n"
    "4. Answer with a single JSON object and nothing else."
)

RESPONSE_SCHEMA = {
    "assessment": f"one of {list(ALLOWED_ASSESSMENTS)}",
    "summary": "two or three sentences an on-call engineer can act on",
    "reasoning": ["one short sentence per piece of evidence you relied on"],
    "recommended_action": f"one of {list(ALLOWED_RECOMMENDATIONS)}",
    "confidence_opinion": "0.0 to 1.0 — YOUR confidence, not the system's",
    "unknowns": ["what you could not determine from the evidence given"],
}


def enabled() -> bool:
    return bool(config.get("ai_enabled"))


def build_prompt(incident, evidence: list, context: dict | None = None) -> str:
    """Serialise an incident for the model. Deterministic: same incident, same
    prompt, same hash — which is what makes ``prompt_hash`` meaningful."""
    payload = {
        "incident": {
            "ref": incident.ref, "opened_at": str(incident.opened_at),
            "device": incident.device, "policy": incident.policy,
            "source_ip": incident.src_ip, "source_country": incident.src_country,
            "source_is_trusted": bool(incident.src_trusted),
            "attack_family": incident.attack_family,
            "worst_severity": incident.severity,
            "events_total": incident.event_count,
            "events_blocked_by_appliance": incident.blocked_count,
            "events_not_blocked": incident.passed_count,
            "deterministic_score": incident.score,
            "impact_by_layer": incident.impact_dict(),
            "exploit_available": bool(incident.exploit_available),
            "target_vulnerable": bool(incident.target_vulnerable),
        },
        "evidence": [
            {"layer": e.get("layer"), "claim": e.get("claim"),
             "value": e.get("value"), "baseline": e.get("baseline"),
             "deviation": e.get("deviation"),
             "weight": e.get("weight_hint")}
            for e in evidence
        ],
        "answer_schema": RESPONSE_SCHEMA,
    }
    if context:
        payload["window"] = context
    return json.dumps(payload, indent=2, default=str, sort_keys=True)


def _post(url: str, body: dict, timeout: float) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _extract_json(text: str) -> dict | None:
    """Pull the JSON object out of a model reply.

    Models wrap JSON in prose and in code fences however firmly they are asked
    not to. Rejecting those replies would discard correct answers over
    packaging, so the object is extracted; but a reply with NO object is a
    failure and is reported as one, never guessed at.
    """
    if not text:
        return None
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    candidate = fenced.group(1) if fenced else None
    if candidate is None:
        start, depth = text.find("{"), 0
        if start < 0:
            return None
        for i in range(start, len(text)):
            depth += 1 if text[i] == "{" else -1 if text[i] == "}" else 0
            if depth == 0:
                candidate = text[start:i + 1]
                break
    if candidate is None:
        return None
    try:
        parsed = json.loads(candidate)
        return parsed if isinstance(parsed, dict) else None
    except ValueError:
        return None


def validate(raw: dict) -> dict:
    """Coerce a model reply into the schema, rejecting what does not fit.

    An out-of-enum recommendation becomes ``observe`` and the original is kept
    in ``rejected`` — visible, not silently normalised. A model that keeps
    proposing a capability this product does not have is a fact worth seeing.
    """
    out = {
        "assessment": "", "summary": "", "reasoning": [],
        "recommended_action": "observe", "confidence_opinion": None,
        "unknowns": [], "rejected": {},
    }
    # Normalise for MATCHING, but report the model's literal words when
    # rejecting. A rejected value that has been tidied up ("rm -rf the
    # firewall" -> "rm_-rf_the_firewall") misrepresents what the model
    # actually said, which is the one thing this field exists to record.
    a_raw = str(raw.get("assessment") or "").strip()
    a = a_raw.lower().replace(" ", "_")
    if a in ALLOWED_ASSESSMENTS:
        out["assessment"] = a
    elif a_raw:
        out["rejected"]["assessment"] = a_raw

    r_raw = str(raw.get("recommended_action") or "").strip()
    r = r_raw.lower().replace(" ", "_")
    if r in ALLOWED_RECOMMENDATIONS:
        out["recommended_action"] = r
    elif r_raw:
        out["rejected"]["recommended_action"] = r_raw

    out["summary"] = str(raw.get("summary") or "")[:2000]
    reasoning = raw.get("reasoning")
    if isinstance(reasoning, list):
        out["reasoning"] = [str(x)[:500] for x in reasoning[:12]]
    elif reasoning:
        out["reasoning"] = [str(reasoning)[:500]]
    unknowns = raw.get("unknowns")
    if isinstance(unknowns, list):
        out["unknowns"] = [str(x)[:300] for x in unknowns[:8]]
    try:
        c = float(raw.get("confidence_opinion"))
        out["confidence_opinion"] = max(0.0, min(1.0, c))
    except (TypeError, ValueError):
        out["confidence_opinion"] = None
    return out


def reason(incident, evidence: list, context: dict | None = None) -> dict:
    """Ask the configured local model about one incident.

    Never raises. Every failure mode returns ``ok: False`` with a reason, so a
    caller cannot accidentally make an incident's fate depend on a model host
    being reachable.
    """
    if not enabled():
        return {"ok": False, "error": "ai disabled", "at": _now()}

    prompt = build_prompt(incident, evidence, context)
    prompt_hash = hashlib.sha256(
        (SYSTEM_PROMPT + prompt).encode("utf-8")).hexdigest()[:16]
    url = str(config.get("ai_url")).rstrip("/")
    model = str(config.get("ai_model"))
    timeout = float(config.get("ai_timeout_s"))

    body = {
        "model": model, "stream": False,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                     {"role": "user", "content": prompt}],
        # qwen3 thinking models return an empty `content` with the answer in
        # `thinking` unless this is switched off — a documented trap in this
        # fleet that turns a working model into a silent empty reply.
        "think": False,
        "options": {"temperature": 0.1},
    }
    try:
        res = _post(f"{url}/api/chat", body, timeout)
        text = ((res.get("message") or {}).get("content")
                or res.get("response") or "")
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:300],
                "model": model, "prompt_hash": prompt_hash, "at": _now()}

    parsed = _extract_json(text)
    if parsed is None:
        return {"ok": False, "error": "model reply contained no JSON object",
                "model": model, "prompt_hash": prompt_hash,
                "raw": text[:1000], "at": _now()}

    opinion = validate(parsed)
    opinion.update({"ok": True, "model": model, "prompt_hash": prompt_hash,
                    "at": _now()})
    return opinion


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds")


def disagreement(incident, policy_recommendation: str) -> dict:
    """Whether the model and the policy engine differ, for display only.

    Shown side by side. The policy engine's recommendation is the one that can
    become an action; the model's is context. Resolving this in the model's
    favour is the exact failure this architecture exists to prevent.
    """
    ai = incident.ai or {}
    model_rec = ai.get("recommended_action") or ""
    if not ai.get("ok") or not model_rec:
        return {"differs": False, "model": "", "policy": policy_recommendation}
    return {"differs": model_rec != policy_recommendation,
            "model": model_rec, "policy": policy_recommendation}
