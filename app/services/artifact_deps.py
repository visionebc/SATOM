"""Content dependencies between file-backed objects: the XSDs a WSDL or XSD imports.

MEASURED on FortiWeb 7.6.8 (2026-10-15): an XML Schema or WSDL upload is
validated against its references AT UPLOAD TIME. A relative ``schemaLocation``
is opened as ``/data/etc/xml_schema/root/<value>`` — an XML Schema object on the
device, by name — and the upload is refused ("Cannot open … to retrieve
schema") if that object is not there yet. An absolute URL is downloaded by the
appliance itself during the upload.

The clone planner walks CONFIGURATION references (a rule names its
``schema-file`` / ``wsdl-file``); it cannot see a reference that lives inside a
file's CONTENT. So a policy whose rule names only a WSDL used to reach the
destination without the schemas that WSDL imports, and the WSDL was refused —
after every object before it had been written. This module reads the content
SATOM is about to push and names what has to exist first.

Pure: it never talks to a device or the store itself. The caller passes
``dst_has(name)`` (does the destination already hold this XML Schema?
True/False/None) and ``content(name)`` (``(blob, origin, reason)`` for an XML
Schema SATOM could push).
"""
from __future__ import annotations

import re
from typing import Callable

#: kinds whose content can import an XML Schema object
IMPORTING_KINDS = ("wsdl", "xml_schema")
MAX_DEPENDENCIES = 50
_ABSOLUTE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def references(kind: str, blob: bytes | None) -> tuple[list[str], list[str]]:
    """``(object names, absolute URLs)`` a WSDL / XML Schema references.

    An unparseable document references nothing here: the upload will fail on
    its own terms, with the device's own reason, and guessing names out of a
    document we could not parse would invent dependencies.
    """
    if kind not in IMPORTING_KINDS or not blob:
        return [], []
    from .artifact_fetch import parse
    try:
        _kind, refs = parse(blob)
    except ValueError:
        return [], []
    names, urls = [], []
    for ref in refs:
        (urls if _ABSOLUTE.match(ref) else names).append(ref)
    return names, urls


class Resolver:
    """Walks references across every file a plan will create.

    ``needed_for`` returns, for one file, the XML Schemas that must be CREATED
    before it and are not already planned or present — dependencies first
    (post-order), each once across the whole plan. ``notes`` records every
    reference and what was decided about it; ``missing`` the ones nobody can
    supply.
    """

    def __init__(self, *, planned: set[str],
                 dst_has: Callable[[str], bool | None],
                 content: Callable[[str], tuple[bytes | None, str, str]],
                 is_empty: Callable[[bytes | None], bool] = lambda b: not (b or b"").strip(),
                 limit: int = MAX_DEPENDENCIES):
        self.planned = set(planned)       # XML Schema names the plan already creates
        self.dst_has = dst_has
        self.content = content
        self.is_empty = is_empty
        self.limit = limit
        self.decided: set[str] = set()
        self.notes: list[dict] = []
        self.missing: list[dict] = []
        self.added = 0

    def _note(self, of: str, ref: str, action: str, ok: bool, reason: str = "") -> None:
        self.notes.append({"of": of, "name": ref, "action": action, "ok": ok,
                           "reason": reason})

    def needed_for(self, kind: str, name: str, blob: bytes | None) -> list[dict]:
        out: list[dict] = []
        self._visit(kind, name, blob, out, stack=(name,))
        return out

    def planned_refs(self, kind: str, blob: bytes | None) -> list[str]:
        """References of this file that the plan itself already creates."""
        names, _urls = references(kind, blob)
        return [n for n in names if n in self.planned]

    def _visit(self, kind: str, of: str, blob: bytes | None, out: list, stack: tuple) -> None:
        names, urls = references(kind, blob)
        for url in urls:
            self._note(of, url, "fetched by the device", True,
                       "FortiWeb downloads an absolute schemaLocation itself when "
                       "the file is uploaded, and refuses the file if it cannot")
        for ref in names:
            if ref in stack:
                self._note(of, ref, "circular reference", False,
                           "the schemas include each other; FortiWeb needs one of "
                           "them on the device before the other can be uploaded")
                continue
            if ref in self.planned:
                self._note(of, ref, "in the plan", True)
                continue
            if ref in self.decided:
                continue
            self.decided.add(ref)
            if "/" in ref or "\\" in ref:
                self._note(of, ref, "not an object name", False,
                           "FortiWeb opens a relative schemaLocation as an object "
                           "name on the device; a path cannot match one")
                self.missing.append({"name": ref, "of": of,
                                     "reason": "references a path, not an object name"})
                continue
            there = self.dst_has(ref)
            if there:
                self._note(of, ref, "already at the destination", True)
                continue
            if self.added >= self.limit:
                self._note(of, ref, "over the limit", False,
                           "more than %d imported schemas" % self.limit)
                self.missing.append({"name": ref, "of": of,
                                     "reason": "over the %d-dependency limit" % self.limit})
                continue
            dep_blob, origin, reason = self.content(ref)
            if dep_blob is None or self.is_empty(dep_blob):
                why = ("the copy SATOM holds is EMPTY" if dep_blob is not None
                       else (reason or "SATOM holds no copy"))
                self._note(of, ref, "missing", False, why)
                self.missing.append({"name": ref, "of": of, "reason": why})
                continue
            # dependencies of the dependency first (post-order)
            self._visit("xml_schema", ref, dep_blob, out, stack + (ref,))
            self.added += 1
            self.planned.add(ref)
            self._note(of, ref, "added to the plan", True,
                       "content from %s (%d bytes)%s"
                       % (origin, len(dep_blob),
                          "" if there is False else
                          "; could not confirm whether the destination has it"))
            out.append({"name": ref, "of": of, "blob": dep_blob, "origin": origin,
                        "unconfirmed": there is None})
