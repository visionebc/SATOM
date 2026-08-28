"""A ``{% block %}`` the parent layout does not define is silently discarded.

WHY THIS FILE EXISTS
--------------------
Jinja renders a child template by filling the blocks its PARENT declares.  A
child that opens a block name the parent never mentions is not an error, not a
warning and not a log line -- the body is simply dropped on the floor.

On 2026-08-05 (commit ``b518206``) the firmware page's image-kind script was
added inside ``{% block firmware_kind_js %}``.  ``base.html`` defines exactly
five blocks and that is not one of them, so for 23 days:

  * the template compiled,
  * ``/firmware/`` returned 200,
  * every server-side test passed,
  * the "Install / new machine" option was present in the ``<select>``,
  * and the script that un-hides the hypervisor picker and widens the file
    input's ``accept`` filter **was never emitted at all**.

The visible symptom was a product that could not accept install media: the
file dialog still filtered to ``.out``, so a ``.qcow2`` could not even be
selected, and the hypervisor field stayed ``d-none`` forever.

The block also carried ``nonce="{{ csp_nonce() }}"``.  ``csp_nonce`` is a
STRING injected by a context processor (``app/__init__.py`` ``_inject_csp_nonce``),
so calling it raises ``TypeError: 'str' object is not callable`` -- a 500 on
the page.  It never fired only because the orphan block meant the expression
was never evaluated.  Two defects, and the first one hid the second.

``tests/test_csp_nonce.py`` could not catch either: ``nonce="{{ csp_nonce() }}"``
contains the substring ``csp_nonce``, so the attribute scan reads as correct.
"""
from __future__ import annotations

import os
import re

TEMPLATES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "app", "templates")

_EXTENDS = re.compile(r"{%-?\s*extends\s+[\"']([^\"']+)[\"']")
_BLOCK = re.compile(r"{%-?\s*block\s+([A-Za-z_][A-Za-z0-9_]*)")
_JINJA_COMMENT = re.compile(r"\{#.*?#\}", re.S)


def _src(rel: str) -> str:
    with open(os.path.join(TEMPLATES, rel), encoding="utf-8") as fh:
        return _JINJA_COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), fh.read())


def _templates() -> list[str]:
    out = []
    for dirpath, _dirs, files in os.walk(TEMPLATES):
        out += [os.path.relpath(os.path.join(dirpath, f), TEMPLATES)
                for f in sorted(files) if f.endswith(".html")]
    return sorted(out)


def _blocks_available(rel: str, _seen: frozenset = frozenset()) -> set:
    """Block names a child of ``rel`` may fill: the parent's own, plus its
    parent's, all the way up the ``extends`` chain."""
    if rel in _seen:
        return set()                      # a cycle is someone else's bug
    src = _src(rel)
    names = set(_BLOCK.findall(src))
    m = _EXTENDS.search(src)
    if m:
        names |= _blocks_available(m.group(1), _seen | {rel})
    return names


def test_the_scan_actually_walks_the_template_tree():
    """An empty walk and a clean tree are indistinguishable from outside."""
    seen = _templates()
    assert len(seen) > 100, f"only {len(seen)} templates walked -- TEMPLATES is wrong"
    assert "base.html" in seen
    assert os.path.join("firmware", "index.html") in seen


def test_no_child_template_defines_a_block_its_parent_does_not():
    orphans = []
    for rel in _templates():
        src = _src(rel)
        m = _EXTENDS.search(src)
        if not m:
            continue                      # a layout: its blocks ARE the contract
        try:
            available = _blocks_available(m.group(1))
        except FileNotFoundError:
            continue                      # dynamic parent name; not our class
        for name in sorted(set(_BLOCK.findall(src))):
            if name not in available:
                orphans.append(f"{rel}:{name}")
    assert not orphans, (
        "these blocks are silently DISCARDED by Jinja -- their markup never "
        "reaches the browser and nothing reports it: " + ", ".join(orphans)
    )


def test_the_scan_can_actually_see_an_orphan(tmp_path):
    """The assertion above reads a tree that is now clean, so it has to be
    shown failing on input it is supposed to reject."""
    parent = "{% block content %}{% endblock %}"
    child = '{% extends "p.html" %}{% block content %}ok{% endblock %}' \
            "{% block nope %}dropped{% endblock %}"
    avail = set(_BLOCK.findall(parent))
    defined = set(_BLOCK.findall(child))
    assert defined - avail == {"nope"}
    # ...and a legitimate override is NOT reported.
    assert "content" not in (defined - avail)


def test_no_template_calls_the_nonce_as_a_function():
    """``csp_nonce`` is a string; ``{{ csp_nonce() }}`` is a 500 when rendered.

    Kept here rather than in test_csp_nonce.py on purpose: that file's scan
    accepts any attribute CONTAINING ``csp_nonce``, so the callable form reads
    as correct to it.
    """
    bad = []
    for rel in _templates():
        src = _src(rel)
        for m in re.finditer(r"csp_nonce\s*\(", src):
            bad.append(f"{rel}:{src.count(chr(10), 0, m.start()) + 1}")
    assert not bad, (
        "csp_nonce is a str (app/__init__.py _inject_csp_nonce); calling it "
        "raises TypeError and 500s the page: " + ", ".join(bad)
    )
