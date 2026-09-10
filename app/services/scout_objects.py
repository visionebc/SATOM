"""What objects Scout can be pointed at — the picker behind the name field.

THE PICKER OFFERS; RUNG 1 DECIDES.
    This module never says an object exists. It reads the SAME two adapters
    rung 1 reads (``live_objects`` and ``object_list`` off
    :func:`app.services.scout_ladder.default_ports`) and hands their contents
    to a ``<select>``. Written any other way — its own REST call, its own
    cache query — the page would hold a second opinion about what a device
    serves, and an operator would be picking from one list while the ladder
    searched another.

A UNION, NEVER AN INTERSECTION
    The two sources disagree in the field, and the rows they disagree about
    are the interesting ones. Measured on fortiweb13 on 2026-09-10: the
    appliance listed 41 policies, SATOM's harvest held 40, and the missing one
    was the policy built minutes earlier — the same six-day-old cache that
    made rung 1 call a live object *absent* before it read the device. An
    intersection would have hidden exactly that object from the picker, i.e.
    hidden the one an operator opens Scout to walk.

    So both directions are offered and each row carries where it came from.

PROVENANCE IS ONLY CLAIMED WHEN BOTH SOURCES ANSWERED
    ``None`` (could not ask) and ``[]`` (asked, nothing there) stay apart here
    for the same reason they do in the ladder. If the harvest could not be
    read, every row is live-only — and stamping "not in the last harvest" on
    all of them would be a comparison against a list nobody obtained.

THE FREE-TEXT FIELD STAYS
    A picker that is the ONLY way in is a cage: an object the device will not
    list could then never be walked, and that case is real on this fleet (an
    unlicensed FortiWeb-VM answers -20010 to every cmdb endpoint). The select
    writes into the name field; the name field is what is posted.
"""
from __future__ import annotations

from . import scout_ladder as sl

#: A picker is a choice, not a scroll bar. The fleet this product targets runs
#: ~750 policies on a single appliance, and the honest handling of a list that
#: long is to trim it and SAY SO — the silent [:6] slices this same page
#: shipped until 2026-09-10 read as complete lists (docs/safeguards.md §163).
MAX_OPTIONS = 400

#: Sources, spelled once. SOLE is not a synonym of BOTH: it means only one
#: list was obtained, so this row was never compared against anything. A
#: payload that says "both" about an uncompared row is the same lie the
#: docstring above forbids on screen.
BOTH, LIVE_ONLY, HARVEST_ONLY, SOLE = "both", "live", "harvest", "sole"


def plural(noun: str) -> str:
    """``"server policy"`` -> ``"server policies"``.

    The product owns its noun (``sl.OBJECT_NOUN``), so it owns its plural. Both
    halves of this feature appended an "s" instead and the picker's own label
    -- the first thing the page says -- read "41 server policys". Only a
    browser render showed it: every test asserted on names, and no name is
    plural.
    """
    if noun.endswith("y") and noun[-2:-1] not in ("a", "e", "i", "o", "u"):
        return noun[:-1] + "ies"
    return noun + "s"


def _read(fn, appliance):
    """A source's rows, or ``None`` for "the question could not be put".

    Never raises: a picker that 500s takes the whole form with it, and the
    form still works without a picker.
    """
    if fn is None:
        return None
    try:
        rows = fn(appliance)
    except Exception:                                          # noqa: BLE001
        return None
    if not isinstance(rows, list):
        return None
    return [r for r in rows if isinstance(r, dict)]


def _name(row) -> str:
    """The object's name as the device spells it. Normalisation only."""
    return str(row.get("name") or row.get("mkey") or row.get("_id") or "").strip()


def _detail(row) -> str:
    """A one-line hint of what this object publishes. DISPLAY ONLY.

    Nothing downstream reads it and no rung is derived from it. ``vserver``
    arrives as ``'192.0.2.251/24 '`` — mask and trailing space included — which
    is the shape that, marked verbatim, once failed as a *name resolution*
    error three rungs below where the fault was.
    """
    bits = []
    vip = str(row.get("vserver") or row.get("address") or row.get("ip") or "")
    vip = vip.split("/")[0].strip()
    if vip:
        bits.append(vip)
    proto = str(row.get("protocol") or row.get("type") or "").strip()
    port = str(row.get("httpPort") or row.get("port") or "").strip()
    if proto and port:
        bits.append("%s/%s" % (proto, port))
    elif proto:
        bits.append(proto)
    elif port:
        bits.append("port %s" % port)
    status = str(row.get("status") or "").strip()
    if status and status.lower() not in ("enable", "enabled", "up", "1"):
        bits.append(status)
    return " · ".join(bits)


def _harvested_at(appliance) -> str:
    """When the harvest this picker is quoting was taken, or ``""``.

    Freshness only — the MEMBERSHIP of the cached list still comes from the
    one adapter rung 1 uses, so there is no second author of "what is in the
    cache", only a second author of "how old is it".
    """
    try:
        from . import read_layer
        out = read_layer.read_objects(getattr(appliance, "id", None),
                                      "server_policy", per_page=1)
        meta = out[1] if isinstance(out, tuple) and len(out) > 1 else {}
        return str((meta or {}).get("generated_at") or "")[:16].replace("T", " ")
    except Exception:                                          # noqa: BLE001
        return ""


_plural_of = plural


def _note(live, held, age: str, noun: str) -> str:
    """One sentence naming WHICH source is being offered.

    A list of names with no source is the defect this whole module is written
    against: the operator cannot tell a device's own answer from a cache's,
    and those two carry different weight in an incident.
    """
    plural = _plural_of(noun)
    if live is None and held is None:
        return ("Neither the appliance nor SATOM's harvest would list this "
                "device's %s. Type the name — rung 1 reports which source "
                "could answer." % plural)
    if live is not None and held is None:
        if not live:
            return ("The appliance answered and lists no %s at all." % plural)
        return "Live from the appliance."
    if live is None and held is not None:
        if not held:
            return ("The appliance would not answer and SATOM's harvest holds "
                    "no %s." % plural)
        return ("SATOM's harvest%s — NOT what the appliance is serving now; "
                "it would not answer." % (age and " of %s" % age or ""))
    if not live and not held:
        return ("Both sources answered and neither holds any %s." % plural)
    return ("Live from the appliance, merged with SATOM's harvest%s."
            % (age and " of %s" % age or ""))


def offer(appliance, ports: dict | None = None) -> dict:
    """Everything the picker needs for one appliance.

    Returns ``appliance_id`` so the browser can drop an answer that arrived
    for a device the operator has already moved off — two changes in quick
    succession otherwise paint device A's objects under device B's name, and
    nothing on screen would say so.
    """
    kind = str(getattr(appliance, "kind", "") or "")
    noun = sl.OBJECT_NOUN.get(kind, "published object")
    ports = ports if ports is not None else sl.default_ports()

    live = _read(ports.get("live_objects"), appliance)
    held = _read(ports.get("object_list"), appliance)
    compared = live is not None and held is not None

    seen: dict[str, dict] = {}
    for row in (live or []):
        name = _name(row)
        if name:
            seen.setdefault(name, {})["live"] = row
    for row in (held or []):
        name = _name(row)
        if name:
            seen.setdefault(name, {})["held"] = row

    options = []
    for name in sorted(seen):
        got = seen[name]
        row = got.get("live") or got.get("held") or {}
        if compared:
            source = (BOTH if ("live" in got and "held" in got)
                      else (LIVE_ONLY if "live" in got else HARVEST_ONLY))
        else:
            # Only one list was obtained: there is nothing to compare against,
            # so no row may carry a comparative claim.
            source = SOLE
        options.append({"name": name, "source": source,
                        "detail": _detail(row),
                        "note": _SOURCE_NOTE.get(source, "")})

    total = len(options)
    capped = 0
    if total > MAX_OPTIONS:
        capped = total - MAX_OPTIONS
        options = options[:MAX_OPTIONS]

    age = _harvested_at(appliance) if held else ""
    return {
        "appliance_id": getattr(appliance, "id", None),
        "appliance": str(getattr(appliance, "name", "") or ""),
        "kind": kind,
        "noun": noun,
        # Shipped so the browser never invents grammar for a word it does not
        # own; it printed "server policys" when it did.
        "noun_plural": plural(noun),
        "objects": options,
        "total": total,
        "capped": capped,
        "live_answered": live is not None,
        "harvest_answered": held is not None,
        "compared": compared,
        "note": _note(live, held, age, noun),
        #: Empty when only one list was obtained: with nothing to compare
        #: against, grouping the rows by provenance would invent a comparison.
        "group_label": dict(GROUP_LABEL) if compared else {},
        "escape": ("Anything the appliance does not list can still be typed: "
                   "this picker offers, it does not decide what exists."),
    }


#: Per-row provenance, and only ever printed when both lists were obtained.
_SOURCE_NOTE = {
    LIVE_ONLY: "on the appliance, not in the last harvest",
    HARVEST_ONLY: "in the last harvest, not listed by the appliance now",
    BOTH: "",
    SOLE: "",
}

#: The same three facts as headings, because an <option> DOES NOT WRAP.
#: Rendered as a suffix, "on the appliance, not in the last harvest" was cut
#: off by the column -- the exact complaint of the round before this one, in
#: the one control where the cut cannot be marked. Provenance is therefore
#: structure (an <optgroup>) and not a suffix, and the wording is the server's
#: for the same reason the plural is: the browser does not author prose about
#: a fact it did not establish.
#: SHORT on purpose, and measured: the picker's column fits ~40 characters
#: and an <optgroup> label cannot mark its own truncation. The full sentence
#: for each odd group is _SOURCE_NOTE, which the page prints UNDER the control
#: where it can wrap -- so the cut heading is shorthand for something written
#: out in full, rather than the only place a fact was stated.
#: Symmetric and terse: three headings that read as one scale. "40 · on the
#: appliance and harvested" is 35 characters and overflowed the measured
#: budget by one -- fitting the budget to the label instead would have been
#: writing the guard around the defect.
GROUP_LABEL = {
    LIVE_ONLY: "live only",
    HARVEST_ONLY: "harvested only",
    BOTH: "live and harvested",
}

#: The longest heading a label may produce, counting the "N · " the page puts
#: in front of it. The count leads because it is the half worth reading when
#: the rest is cut off.
MAX_LABEL = 34

__all__ = ["offer", "plural", "MAX_OPTIONS", "GROUP_LABEL", "MAX_LABEL",
           "BOTH", "LIVE_ONLY", "HARVEST_ONLY", "SOLE"]
