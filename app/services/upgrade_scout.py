"""Scout, asked the one question the Upgrade page cares about: will the version
we are about to install ruin this window?

The verdicts come from :mod:`app.services.release_advisor` over the harvested
vendor prose — the SAME rules, the same seal and the same coverage statement the
Release-Notes advisory panel shows. Nothing is re-implemented here: a second
rule set would mean the page an operator reads before flashing and the page they
read afterwards could disagree about the same firmware.

WHAT THIS IS NOT
----------------
It is **not a gate**. Change control decides whether a live flash may run; this
only says what the vendor wrote about the move. The distinction is not
squeamishness — the advisory's own vocabulary includes ``unknown`` for "we never
harvested that page", and a gate built on it would refuse upgrades because of a
gap in OUR corpus while looking exactly like a refusal grounded in the vendor's
words. Blocking on that teaches operators to disbelieve the panel.

Conversely it never degrades to a clean result. Every reason an advisory could
not be produced is named and shown; "Scout had nothing to say" and "Scout was
never asked" render differently, because an empty green panel over an unchecked
upgrade is the worst output available here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import release_advisor as ra
from . import release_corpus
from . import scout_config
from .release_notes import version_tuple

#: Why there is no advisory. Declared as constants because the template, the
#: JSON and the guards must all name the same condition — three spellings of
#: "Scout is off" is how a panel ends up claiming a review that never ran.
OFF = "Scout is switched off for this site."
NOT_ASKED = "Scout was not asked to review this move."
NO_CORPUS_FOR_PRODUCT = ("No release notes are harvested for this product, so "
                         "Scout has nothing to read.")
NO_CURRENT = ("Scout needs the appliance's current firmware version and could "
              "not read it. Probe the appliance, then reopen this page.")
NO_TARGET = "Scout needs the version of the selected image."
SAME_VERSION = ("The appliance already runs this version — there is no move for "
                "Scout to review.")

#: A version as the advisor understands it. Firmware strings arrive decorated
#: ("FortiWeb-VM 8.0.7,build1234,250101"), and handing that to the analyser
#: silently produces a span of nothing.
_RE_VER = re.compile(r"\d+(?:\.\d+){1,3}")


def normalise(raw: str | None) -> str:
    """The first dotted numeric token in ``raw``, or ``''``.

    Returning ``''`` rather than the raw string matters: an unparsed version
    reaches :func:`review` as "no version", which is reported, instead of
    reaching the analyser as a version nobody can place on the ladder, which
    comes back as a confident empty result."""
    m = _RE_VER.search(raw or "")
    return m.group(0) if m else ""


@dataclass
class Review:
    """What Scout was asked, and what it answered."""

    asked: bool
    scout_on: bool
    product: str
    current: str
    target: str
    advisory: ra.Advisory | None = None
    reason: str = ""
    counts: dict = field(default_factory=dict)

    @property
    def verdict(self) -> str:
        """``blocker|caution|clear|unknown`` — or ``unavailable``.

        ``unavailable`` is deliberately outside the advisory's vocabulary. A
        review that could not run must not be able to spell itself ``clear``."""
        return self.advisory.verdict if self.advisory is not None else "unavailable"

    @property
    def blocking(self) -> bool:
        return self.verdict == "blocker"


def _counts(adv: ra.Advisory) -> dict:
    out = {s: 0 for s in ra.SEVERITIES}
    for f in adv.findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


def review(appliance, target: str, current: str | None = None, *,
           asked: bool = True) -> Review:
    """Scout's reading of ``current → target`` for ``appliance``.

    Never raises. A firmware flash must not fail because a corpus file was
    unreadable — but the failure is NAMED in ``reason``, never swallowed into a
    result that looks clean."""
    kind = (getattr(appliance, "kind", "") or "").strip().lower()
    cur = normalise(current if current is not None else getattr(appliance, "firmware", ""))
    tgt = normalise(target)
    on = scout_config.enabled()
    base = Review(asked=asked, scout_on=on, product=kind, current=cur, target=tgt)

    if not on:
        base.reason = OFF
        return base
    if not asked:
        base.reason = NOT_ASKED
        return base
    if kind not in release_corpus.SUPPORTED_PRODUCTS:
        base.reason = NO_CORPUS_FOR_PRODUCT
        return base
    if not cur:
        base.reason = NO_CURRENT
        return base
    if not tgt:
        base.reason = NO_TARGET
        return base
    if version_tuple(cur) == version_tuple(tgt):
        base.reason = SAME_VERSION
        return base

    try:
        sections = release_corpus.load(kind).sections
        base.advisory = ra.analyse(sections, cur, tgt, product=kind)
        base.counts = _counts(base.advisory)
    except Exception as exc:                                    # noqa: BLE001
        base.advisory = None
        base.reason = (f"Scout could not read the release-notes corpus "
                       f"({type(exc).__name__}). Nothing was checked.")
    return base


def summary(rv: Review) -> dict:
    """The JSON the flash endpoints echo back.

    Deliberately small: the verdict, the counts, the reason and the hop path.
    The findings themselves are rendered server-side (vendor prose crosses the
    template's autoescape there); shipping them as JSON would invite a second
    renderer in JavaScript and a second chance to emit them unescaped."""
    return {"verdict": rv.verdict, "asked": rv.asked, "scout_on": rv.scout_on,
            "reason": rv.reason, "counts": rv.counts,
            "current": rv.current, "target": rv.target,
            "path": list(rv.advisory.path) if rv.advisory is not None else [],
            "gaps": len(rv.advisory.gaps) if rv.advisory is not None else 0}


__all__ = ["OFF", "NOT_ASKED", "NO_CORPUS_FOR_PRODUCT", "NO_CURRENT", "NO_TARGET",
           "SAME_VERSION", "Review", "normalise", "review", "summary"]
