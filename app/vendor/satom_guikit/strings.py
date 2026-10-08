"""Structure vs texts: split a template into its layout and Fortinet's strings.

Texts are the values of :data:`TEXT_KEYS` anywhere in the template (field and
column labels, help, section and dialog titles, option labels, toggle labels,
unit suffixes). ``*_key`` lang keys stay in the structure: they are
identifiers, not texts. ``split`` -> ``(structure, strings)`` where strings is
``{json-path: text}``; ``merge`` puts them back, so ``merge(*split(t)) == t``.
"""
from __future__ import annotations

import copy

TEXT_KEYS = frozenset({"label", "help", "title", "suffix", "on", "off", "text"})


def _texts(node) -> bool:
    if isinstance(node, str):
        return True
    if isinstance(node, dict):
        return bool(node) and all(isinstance(v, str) for v in node.values())
    return False


def split(tpl: dict) -> tuple:
    structure = copy.deepcopy(tpl)
    strings: dict = {}

    def walk(node, path):
        if isinstance(node, dict):
            for k in list(node):
                p = "%s/%s" % (path, k)
                if k in TEXT_KEYS and _texts(node[k]):
                    strings[p] = node.pop(k)
                else:
                    walk(node[k], p)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, "%s/%d" % (path, i))

    walk(structure, "")
    return structure, strings


def merge(structure: dict, strings: dict) -> dict:
    out = copy.deepcopy(structure)
    for path, text in strings.items():
        parts = path.split("/")[1:]
        node = out
        for part in parts[:-1]:
            node = node[int(part)] if isinstance(node, list) else node[part]
        node[parts[-1]] = text
    return out
