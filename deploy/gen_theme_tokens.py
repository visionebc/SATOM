#!/usr/bin/env python3
"""Generate ``app/services/theme_tokens.py`` from the stylesheet's ``:root``.

The theme editor in Settings -> Appearance must offer exactly the design tokens
the stylesheet actually defines. A hand-maintained list is a *copy*, and copies
rot: the first release that adds a ``--fw-*`` variable leaves the editor silently
incomplete, and the first release that removes one leaves a control that writes a
value nothing reads.

So the registry is DERIVED. This script reads ``:root`` out of
``app/static/css/fortiweb.css``, joins it with the curated metadata below
(group, label, kind, help -- none of which exist in CSS) and writes the module.
``tests/test_theme.py`` runs it with ``--check`` and fails the suite on drift, so
the two cannot diverge without someone noticing.

Adding a token is therefore TWO edits in one commit: the CSS variable, and an
entry in ``META`` here. Forgetting the second fails the suite by design.

Usage::

    python3 deploy/gen_theme_tokens.py            # write the module
    python3 deploy/gen_theme_tokens.py --check    # exit 1 if out of date
"""
from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSS = os.path.join(ROOT, "app", "static", "css", "fortiweb.css")
OUT = os.path.join(ROOT, "app", "services", "theme_tokens.py")

# Curated metadata. Key = CSS variable name without the ``--fw-`` prefix.
#   group : editor section
#   label : human label
#   kind  : validator class (see theme_service.VALIDATORS)
#   help  : one-line explanation shown under the control
#   pair  : optional (foreground, background) contrast partner for the auditor
META: "dict[str, dict]" = {
    # -- Sidebar -----------------------------------------------------------
    "sidebar-bg":         dict(group="Sidebar", label="Background", kind="color",
                               help="Left navigation panel background."),
    "sidebar-active":     dict(group="Sidebar", label="Active marker", kind="color",
                               help="Left edge bar on the active navigation item."),
    "sidebar-text":       dict(group="Sidebar", label="Text", kind="color",
                               help="Navigation item text.", on="sidebar-bg"),
    "sidebar-text-hover": dict(group="Sidebar", label="Text (hover)", kind="color",
                               help="Navigation item text on hover/active.", on="sidebar-bg"),
    "sidebar-section":    dict(group="Sidebar", label="Section heading", kind="color",
                               help="Group captions between navigation blocks.", on="sidebar-bg"),
    # -- Top bar -----------------------------------------------------------
    "topbar-bg":          dict(group="Top bar", label="Background", kind="color",
                               help="Top bar background. A per-ADOM banner can override it."),
    "topbar-text":        dict(group="Top bar", label="Text", kind="color",
                               help="Product name, icons and menus in the top bar.",
                               on="topbar-bg"),
    # -- Surfaces ----------------------------------------------------------
    "content-bg":         dict(group="Surfaces", label="Page background", kind="color",
                               help="Canvas behind cards and tables."),
    "surface":            dict(group="Surfaces", label="Card surface", kind="color",
                               help="Cards, panels, inputs, dropdowns and modals."),
    "surface-alt":        dict(group="Surfaces", label="Muted surface", kind="color",
                               help="Table headers, card footers and inset rows."),
    "border":             dict(group="Surfaces", label="Border", kind="color",
                               help="Card and control outlines."),
    "border-light":       dict(group="Surfaces", label="Border (subtle)", kind="color",
                               help="Internal dividers inside a card."),
    # -- Accent ------------------------------------------------------------
    "accent":             dict(group="Accent", label="Accent", kind="color",
                               help="Primary buttons, links and focus rings.",
                               on="surface"),
    "accent-hover":       dict(group="Accent", label="Accent (hover)", kind="color",
                               help="Hover/pressed state of accent elements."),
    "accent-light":       dict(group="Accent", label="Accent tint", kind="color",
                               help="Translucent accent wash behind selected rows."),
    # -- Text --------------------------------------------------------------
    "text-primary":       dict(group="Text", label="Primary text", kind="color",
                               help="Body copy and headings.", on="surface"),
    "text-secondary":     dict(group="Text", label="Secondary text", kind="color",
                               help="Captions, hints and breadcrumbs.", on="surface"),
    # -- Status ------------------------------------------------------------
    "success":            dict(group="Status", label="Success", kind="color",
                               help="Healthy badges and confirmations."),
    "danger":             dict(group="Status", label="Danger", kind="color",
                               help="Critical badges, destructive actions."),
    "warning":            dict(group="Status", label="Warning", kind="color",
                               help="Degraded badges and cautions."),
    "info":               dict(group="Status", label="Info", kind="color",
                               help="Neutral informational badges."),
    # -- Elevation ---------------------------------------------------------
    "card-shadow":        dict(group="Elevation", label="Card shadow", kind="shadow",
                               help="Resting elevation of cards."),
    "card-shadow-hover":  dict(group="Elevation", label="Card shadow (hover)", kind="shadow",
                               help="Raised elevation on hover."),
    # -- Layout ------------------------------------------------------------
    "sidebar-width":      dict(group="Layout", label="Sidebar width", kind="length",
                               help="Expanded navigation width."),
    "topbar-height":      dict(group="Layout", label="Top bar height", kind="length",
                               help="Fixed header height; layout offsets follow it."),
    "radius":             dict(group="Layout", label="Corner radius", kind="length",
                               help="Buttons, inputs and badges."),
    "radius-lg":          dict(group="Layout", label="Corner radius (large)", kind="length",
                               help="Cards, modals and drawers."),
    "transition":         dict(group="Layout", label="Transition", kind="transition",
                               help="Duration and easing for hover/collapse animations."),
    # -- Typography --------------------------------------------------------
    "font":               dict(group="Typography", label="Font stack", kind="font",
                               help="Interface font stack, first available wins."),
}

GROUP_ORDER = ["Sidebar", "Top bar", "Surfaces", "Accent", "Text", "Status",
               "Elevation", "Layout", "Typography"]

_VAR_RE = re.compile(r"^\s*--fw-([a-z0-9-]+)\s*:\s*(.+?)\s*;\s*$")


def read_root_block(path: str = CSS) -> "dict[str, str]":
    """Parse the first ``:root { ... }`` block into ``{name: default}``."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    start = text.index(":root")
    body = text[text.index("{", start) + 1: text.index("}", start)]
    out: "dict[str, str]" = {}
    for line in body.splitlines():
        m = _VAR_RE.match(line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def build() -> str:
    css_vars = read_root_block()

    missing = [k for k in css_vars if k not in META]
    extra = [k for k in META if k not in css_vars]
    if missing:
        raise SystemExit(
            "CSS defines --fw-%s with no META entry in %s.\nAdd it there in the "
            "SAME commit that adds the variable." % (
                ", --fw-".join(sorted(missing)), os.path.basename(__file__)))
    if extra:
        raise SystemExit(
            "META describes --fw-%s but the stylesheet no longer defines it.\n"
            "Remove it here in the SAME commit that removes the variable." % (
                ", --fw-".join(sorted(extra))))

    lines = [
        '"""Design-token registry for the theme editor — GENERATED, do not edit.',
        "",
        "Source of truth: the ``:root`` block of ``app/static/css/fortiweb.css``",
        "plus the curated metadata in ``deploy/gen_theme_tokens.py``.",
        "Regenerate with ``python3 deploy/gen_theme_tokens.py``;",
        "``tests/test_theme.py`` fails if this file drifts from the stylesheet.",
        '"""',
        "from __future__ import annotations",
        "",
        "# Editor section order.",
        "GROUP_ORDER = %r" % (GROUP_ORDER,),
        "",
        "# name -> {group, label, kind, help, default, on?}",
        "TOKENS: dict[str, dict] = {",
    ]
    for name in sorted(css_vars, key=lambda n: (GROUP_ORDER.index(META[n]["group"]),
                                                list(META).index(n))):
        meta = dict(META[name])
        meta["default"] = css_vars[name]
        parts = ["%r: %r" % (k, meta[k])
                 for k in ("group", "label", "kind", "help", "default", "on")
                 if k in meta]
        lines.append("    %r: {%s}," % (name, ", ".join(parts)))
    lines += [
        "}",
        "",
        "#: Every token name, in editor order.",
        "TOKEN_NAMES = tuple(TOKENS)",
        "",
        "#: name -> stylesheet default, i.e. the built-in look.",
        "DEFAULTS = {k: v['default'] for k, v in TOKENS.items()}",
        "",
        "",
        "def by_group() -> list[tuple[str, list[tuple[str, dict]]]]:",
        '    """``[(group, [(name, meta), ...]), ...]`` in editor order."""',
        "    out: list[tuple[str, list[tuple[str, dict]]]] = []",
        "    for g in GROUP_ORDER:",
        "        rows = [(n, m) for n, m in TOKENS.items() if m['group'] == g]",
        "        if rows:",
        "            out.append((g, rows))",
        "    return out",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    new = build()
    check = "--check" in sys.argv
    old = ""
    if os.path.exists(OUT):
        with open(OUT, encoding="utf-8") as fh:
            old = fh.read()
    if check:
        if old != new:
            sys.stderr.write(
                "theme_tokens.py is out of date — run "
                "python3 deploy/gen_theme_tokens.py\n")
            return 1
        print("theme_tokens.py is up to date (%d tokens)" % new.count("'group':"))
        return 0
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(new)
    print("wrote %s (%d tokens)" % (OUT, new.count("'group':")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
