"""Dashboard variables — one board that answers for the whole fleet.

The problem this solves is arithmetic. A board whose panels name their device
is a board per device: fifty appliances means fifty boards to build and fifty
to keep in step, and the fifty-first is added by remembering to. A *variable*
moves the device out of the panel and into a picker, so "show me everything
about this machine" is one board with the selector moved.

Three rules hold it up.

**Options come from the store, never from a list.** Enumerating
``label_values("device")`` means the picker shows exactly what has actually
reported, so a newly onboarded appliance appears without an edit and a retired
one stops being offered. A hand-written list is a copy, and copies rot.

**A value that did not come from the store is never interpolated.** The
resolved options ARE the allowlist. This is what makes substitution into a
MetricsQL expression safe: the operator picks from what the store produced,
and anything else — a hand-edited query string, a stale bookmark, a value from
a board that has since changed — is refused rather than passed through.

**Regex metacharacters are escaped.** The idiom is ``{device=~"$device"}``, so
a substituted value lands inside a regex. An unescaped ``.`` in a hostname
would quietly widen the match to other devices, and a chart that shows *more*
than it claims is the same class of lie as one that shows less.
"""

from __future__ import annotations

import json
import re

#: Cap on options offered for one variable. A fleet picker is for choosing,
#: not for browsing: past this many the operator wants a filter, and the
#: truncation is REPORTED on the payload rather than silently applied.
MAX_OPTIONS = 500

#: The wildcard option. Substitutes to a regex alternation of every option, so
#: "All" and a single pick go through exactly the same code path.
ALL = "$__all"

_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


def parse(raw) -> list:
    """Board ``variables`` JSON → validated list of variable definitions.

    A malformed definition is DROPPED, not repaired. A variable that half
    exists would render a picker whose selection changes nothing, which reads
    as a broken board rather than a misconfigured one.
    """
    if isinstance(raw, str):
        try:
            raw = json.loads(raw or "[]")
        except (ValueError, TypeError):
            return []
    if not isinstance(raw, list):
        return []
    out, seen = [], set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip().lower()
        if not _NAME_RE.match(name) or name in seen:
            continue
        seen.add(name)
        out.append({
            "name": name,
            "label": str(item.get("label") or name.title())[:60],
            "label_key": str(item.get("label_key") or name)[:40],
            "match": str(item.get("match") or "")[:200],
            "allow_all": bool(item.get("allow_all", True)),
        })
    return out


def dump(variables: list) -> str:
    return json.dumps(parse(variables), separators=(",", ":"))


#: Characters RE2 treats as special OUTSIDE a character class.
#: Deliberately NOT ``re.escape``: Python escapes ``-`` as a backslash-hyphen,
#: which RE2 rejects as an invalid escape -- the store answers HTTP 422 and the
#: panel shows a store error for a perfectly ordinary hostname. Every device and
#: policy name in this fleet contains a hyphen, so ``re.escape`` broke the common
#: case and left the rare one working. Caught end-to-end against the live store
#: on 2026-08-06; a unit test on the escaper alone could not have seen it,
#: because the escaped string is only invalid to the ENGINE.
_RE2_SPECIAL = frozenset('.+*?()|[]{}^$' + '\\')


def _escape_regex(value: str) -> str:
    """Escape a label value for use inside a MetricsQL (RE2) regex matcher."""
    return ''.join(('\\' + ch) if ch in _RE2_SPECIAL else ch
                   for ch in value)


def resolve(board, selected: dict | None = None) -> list:
    """Resolve each variable's options and current value against the store.

    Returns a list of ``{name, label, options, value, truncated, error}``.

    A variable whose options cannot be fetched reports ``error`` and offers no
    options. It does NOT fall back to the requested value: substituting a value
    the store could not confirm is exactly the case the allowlist exists to
    prevent, and a panel drawn from an unconfirmed selector would claim to show
    a device that may not be the one named.
    """
    from . import vm_store

    selected = selected or {}
    resolved = []
    for var in parse(getattr(board, "variables", None)):
        entry = {"name": var["name"], "label": var["label"],
                 "options": [], "value": "", "truncated": False, "error": ""}
        # An earlier variable may scope a later one's match, so substitution
        # runs against what has been resolved SO FAR — never against the raw
        # request, which would re-open the allowlist from the other end.
        match = interpolate(var["match"], resolved) if var["match"] else ""
        if match is None:
            entry["error"] = "filter references an unresolved variable"
            resolved.append(entry)
            continue
        try:
            values = vm_store.label_values(var["label_key"], match)
        except Exception as exc:                     # noqa: BLE001
            entry["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:80])
            resolved.append(entry)
            continue
        opts = sorted({str(v) for v in (values or []) if str(v).strip()})
        if len(opts) > MAX_OPTIONS:
            opts = opts[:MAX_OPTIONS]
            entry["truncated"] = True
        entry["options"] = opts
        entry["allow_all"] = var["allow_all"]

        want = str(selected.get(var["name"]) or "").strip()
        if want == ALL and var["allow_all"]:
            entry["value"] = ALL
        elif want and want in opts:
            entry["value"] = want
        else:
            # Requested value is absent from the store's own answer. Falling
            # back is correct here (unlike substitution) because the operator
            # still gets a working board — but ALL, not the first option: an
            # arbitrary first pick looks like a deliberate selection.
            entry["value"] = ALL if var["allow_all"] else (opts[0] if opts else "")
        resolved.append(entry)
    return resolved


def substitution(resolved: list) -> dict:
    """Resolved variables → ``{name: regex-safe substitution}``."""
    out = {}
    for entry in resolved:
        if entry.get("error"):
            continue
        val = entry.get("value") or ""
        opts = entry.get("options") or []
        if val == ALL:
            if not opts:
                continue          # nothing reported — leave $name unresolved
            out[entry["name"]] = "|".join(_escape_regex(o) for o in opts)
        elif val in opts:
            out[entry["name"]] = _escape_regex(val)
        # A value that is neither ALL nor a known option is deliberately
        # absent: see the module docstring.
    return out


_TOKEN_RE = re.compile(r"\$\{([a-z][a-z0-9_]{0,31})\}|\$([a-z][a-z0-9_]{0,31})")


def interpolate(expr: str, resolved: list) -> str | None:
    """Substitute ``$name`` / ``${name}`` in an expression.

    Returns ``None`` when the expression references a variable that could not
    be resolved. The caller renders that as a panel ERROR — never as an empty
    chart, and never by running the query with the token left in, which would
    make the store reject a parse error that reads like a store outage.
    """
    if not expr:
        return expr
    subs = substitution(resolved)
    missing = []

    def repl(m):
        name = m.group(1) or m.group(2)
        if name in subs:
            return subs[name]
        missing.append(name)
        return m.group(0)

    out = _TOKEN_RE.sub(repl, expr)
    return None if missing else out


def uses_variables(expr: str) -> bool:
    return bool(expr) and bool(_TOKEN_RE.search(expr))
