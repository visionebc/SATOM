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
  declarations would let it through.
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


def defined_names(code: str) -> set:
    """Every name this script binds to something callable."""
    defined = set(re.findall(r"function\s+" + _NAME + r"\s*\(", code))
    defined |= set(re.findall(_DECL + _NAME + r"\s*=\s*(?:async\s+)?function",
                              code))
    defined |= set(re.findall(
        _DECL + _NAME + r"\s*=\s*(?:async\s*)?\([^()]*\)\s*=>", code))
    defined |= set(re.findall(_DECL + _NAME + r"\s*=\s*[A-Za-z_$][\w$]*\s*=>",
                              code))
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
