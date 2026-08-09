"""One structural checker for the panel scripts, shared by the test modules.

``test_attack_search`` and ``test_attack_ask_field`` each carried their own
copy of "every function this script calls is defined in it". Two copies of a
rule agree on the day they are written and drift at the first change — which is
how this one drifted: the copies stayed identical while the script grew a
callback slot neither of them could see, and both then failed against correct
code at the same moment.

The rule itself is worth keeping. The chat shipped broken because a call
resolved to nothing and killed the callback on the line before the redraw, and
nothing server-side can see that: this script never runs during a Flask test.

What counts as a definition:

* a declared function, at any nesting depth;
* a variable initialised with a function expression or an arrow;
* a **callback slot** — declared ``null`` and assigned a function elsewhere in
  the file. ``var onPick = null;`` … ``onPick = refresh;`` resolves at the call
  site to ``refresh``, so it is defined. A slot that is declared and never
  assigned is deliberately NOT defined: a call that can only ever reach ``null``
  is precisely the dead call this guard exists to catch, and accepting bare
  declarations would let it through;
* a **function parameter**. ``function wireShared(box, resend) { … resend(…) }``
  calls something this file never declares, and that is not a defect — the
  callable arrives from the call site. This is the third time a legitimate way
  of holding a function has failed the guard against correct code (after the
  callback slot, and after the closure ``startClock`` used to return), so the
  rule is stated once here rather than patched at each call site.

  Parameters are accepted file-wide rather than per-scope: the checker is
  regex-based and has never been scope-aware — a nested function's name already
  counts everywhere. The trade is deliberate and narrow. A misspelt call is only
  missed if the typo exactly matches some parameter name in the file, whereas
  the false positives it removes are real code the guard was blocking.
"""
from __future__ import annotations

import re

_DECL = r"(?:var|let|const)\s+"
_NAME = r"([A-Za-z_$][\w$]*)"

#: Names that resolve to the platform rather than to this file.
BUILTINS = {
    "function", "if", "for", "while", "switch", "catch", "return", "typeof",
    "JSON", "Object", "Array", "String", "Number", "Boolean", "Math", "Date",
    "parseInt", "parseFloat", "setTimeout", "setInterval", "clearInterval",
    "clearTimeout", "fetch", "Promise", "requestAnimationFrame",
    "KeyboardEvent", "Event", "CustomEvent", "FormData", "URLSearchParams",
    "encodeURIComponent", "decodeURIComponent", "isNaN", "alert", "confirm",
}


def _callback_slots(code: str, defined: set) -> set:
    """Slots declared empty and later assigned something callable."""
    slots = set(re.findall(_DECL + _NAME + r"\s*=\s*(?:null|undefined)\s*[;,\n]",
                           code))
    out = set()
    for name in slots:
        targets = re.findall(
            r"(?<![.\w$=!<>])%s\s*=\s*(?!=)([A-Za-z_$][\w$]*|function\b|\()"
            % re.escape(name), code)
        for target in targets:
            if target in defined or target in ("function", "("):
                out.add(name)
                break
    return out


def _parameters(code: str) -> set:
    """Every parameter name of every function in the file.

    A parameter is bound at runtime, so calling one is not a dangling call; the
    guard flagged ``resend`` in ``function wireShared(box, resend)`` purely
    because it looks for declarations. Covers declarations, function
    expressions and parenthesised arrows. Destructuring and defaults are
    skipped rather than half-parsed — a name this misses is reported as
    undefined, which is the safe direction for a guard to be wrong in.
    """
    out: set = set()
    heads = re.findall(r"function\s*[A-Za-z_$][\w$]*\s*\(([^()]*)\)", code)
    heads += re.findall(r"function\s*\(([^()]*)\)", code)
    heads += re.findall(r"\(([^()]*)\)\s*=>", code)
    for head in heads:
        for part in head.split(","):
            part = part.strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", part):
                out.add(part)
    # A single-identifier arrow parameter: `x => …`
    out |= set(re.findall(r"(?<![.\w$])([A-Za-z_$][\w$]*)\s*=>", code))
    return out


def defined_names(code: str) -> set:
    """Every name this script binds to something callable."""
    defined = set(re.findall(r"function\s+" + _NAME + r"\s*\(", code))
    defined |= set(re.findall(_DECL + _NAME + r"\s*=\s*(?:async\s+)?function",
                              code))
    defined |= set(re.findall(
        _DECL + _NAME + r"\s*=\s*(?:async\s*)?\([^()]*\)\s*=>", code))
    defined |= set(re.findall(_DECL + _NAME + r"\s*=\s*[A-Za-z_$][\w$]*\s*=>",
                              code))
    defined |= _parameters(code)
    defined |= _callback_slots(code, defined)
    return defined


def undefined_calls(code: str) -> set:
    """Lower-case names called in ``code`` that nothing in it defines.

    ``code`` is expected to arrive with comments and strings already stripped;
    a needle inside a string literal is not a call.
    """
    called = set(re.findall(r"(?<![.\w$])" + _NAME + r"\s*\(", code))
    return {n for n in called - defined_names(code) - BUILTINS
            if n[0].islower()}
