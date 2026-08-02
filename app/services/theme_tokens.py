"""Design-token registry for the theme editor — GENERATED, do not edit.

Source of truth: the ``:root`` block of ``app/static/css/fortiweb.css``
plus the curated metadata in ``deploy/gen_theme_tokens.py``.
Regenerate with ``python3 deploy/gen_theme_tokens.py``;
``tests/test_theme.py`` fails if this file drifts from the stylesheet.
"""
from __future__ import annotations

# Editor section order.
GROUP_ORDER = ['Sidebar', 'Top bar', 'Surfaces', 'Accent', 'Text', 'Status', 'Elevation', 'Layout', 'Typography']

# name -> {group, label, kind, help, default, on?}
TOKENS: dict[str, dict] = {
    'sidebar-bg': {'group': 'Sidebar', 'label': 'Background', 'kind': 'color', 'help': 'Left navigation panel background.', 'default': '#1D3452'},
    'sidebar-active': {'group': 'Sidebar', 'label': 'Active marker', 'kind': 'color', 'help': 'Left edge bar on the active navigation item.', 'default': '#EF5424'},
    'sidebar-text': {'group': 'Sidebar', 'label': 'Text', 'kind': 'color', 'help': 'Navigation item text.', 'default': '#B8C8D8', 'on': 'sidebar-bg'},
    'sidebar-text-hover': {'group': 'Sidebar', 'label': 'Text (hover)', 'kind': 'color', 'help': 'Navigation item text on hover/active.', 'default': '#FFFFFF', 'on': 'sidebar-bg'},
    'sidebar-section': {'group': 'Sidebar', 'label': 'Section heading', 'kind': 'color', 'help': 'Group captions between navigation blocks.', 'default': '#7A94AD', 'on': 'sidebar-bg'},
    'topbar-bg': {'group': 'Top bar', 'label': 'Background', 'kind': 'color', 'help': 'Top bar background. A per-ADOM banner can override it.', 'default': '#162940'},
    'topbar-text': {'group': 'Top bar', 'label': 'Text', 'kind': 'color', 'help': 'Product name, icons and menus in the top bar.', 'default': '#FFFFFF', 'on': 'topbar-bg'},
    'content-bg': {'group': 'Surfaces', 'label': 'Page background', 'kind': 'color', 'help': 'Canvas behind cards and tables.', 'default': '#F4F5F7'},
    'surface': {'group': 'Surfaces', 'label': 'Card surface', 'kind': 'color', 'help': 'Cards, panels, inputs, dropdowns and modals.', 'default': '#FFFFFF'},
    'surface-alt': {'group': 'Surfaces', 'label': 'Muted surface', 'kind': 'color', 'help': 'Table headers, card footers and inset rows.', 'default': '#FAFBFC'},
    'border': {'group': 'Surfaces', 'label': 'Border', 'kind': 'color', 'help': 'Card and control outlines.', 'default': '#DEE2E6'},
    'border-light': {'group': 'Surfaces', 'label': 'Border (subtle)', 'kind': 'color', 'help': 'Internal dividers inside a card.', 'default': '#E9ECEF'},
    'accent': {'group': 'Accent', 'label': 'Accent', 'kind': 'color', 'help': 'Primary buttons, links and focus rings.', 'default': '#EF5424', 'on': 'surface'},
    'accent-hover': {'group': 'Accent', 'label': 'Accent (hover)', 'kind': 'color', 'help': 'Hover/pressed state of accent elements.', 'default': '#D44A1E'},
    'accent-light': {'group': 'Accent', 'label': 'Accent tint', 'kind': 'color', 'help': 'Translucent accent wash behind selected rows.', 'default': 'rgba(239, 84, 36, 0.1)'},
    'text-primary': {'group': 'Text', 'label': 'Primary text', 'kind': 'color', 'help': 'Body copy and headings.', 'default': '#212529', 'on': 'surface'},
    'text-secondary': {'group': 'Text', 'label': 'Secondary text', 'kind': 'color', 'help': 'Captions, hints and breadcrumbs.', 'default': '#6C757D', 'on': 'surface'},
    'success': {'group': 'Status', 'label': 'Success', 'kind': 'color', 'help': 'Healthy badges and confirmations.', 'default': '#28A745'},
    'danger': {'group': 'Status', 'label': 'Danger', 'kind': 'color', 'help': 'Critical badges, destructive actions.', 'default': '#DC3545'},
    'warning': {'group': 'Status', 'label': 'Warning', 'kind': 'color', 'help': 'Degraded badges and cautions.', 'default': '#FFC107'},
    'info': {'group': 'Status', 'label': 'Info', 'kind': 'color', 'help': 'Neutral informational badges.', 'default': '#17A2B8'},
    'card-shadow': {'group': 'Elevation', 'label': 'Card shadow', 'kind': 'shadow', 'help': 'Resting elevation of cards.', 'default': '0 1px 2px rgba(16,32,52,0.06), 0 3px 12px rgba(16,32,52,0.06)'},
    'card-shadow-hover': {'group': 'Elevation', 'label': 'Card shadow (hover)', 'kind': 'shadow', 'help': 'Raised elevation on hover.', 'default': '0 4px 10px rgba(16,32,52,0.10), 0 12px 30px rgba(16,32,52,0.10)'},
    'sidebar-width': {'group': 'Layout', 'label': 'Sidebar width', 'kind': 'length', 'help': 'Expanded navigation width.', 'default': '264px'},
    'topbar-height': {'group': 'Layout', 'label': 'Top bar height', 'kind': 'length', 'help': 'Fixed header height; layout offsets follow it.', 'default': '50px'},
    'radius': {'group': 'Layout', 'label': 'Corner radius', 'kind': 'length', 'help': 'Buttons, inputs and badges.', 'default': '4px'},
    'radius-lg': {'group': 'Layout', 'label': 'Corner radius (large)', 'kind': 'length', 'help': 'Cards, modals and drawers.', 'default': '8px'},
    'transition': {'group': 'Layout', 'label': 'Transition', 'kind': 'transition', 'help': 'Duration and easing for hover/collapse animations.', 'default': '0.2s ease'},
    'font': {'group': 'Typography', 'label': 'Font stack', 'kind': 'font', 'help': 'Interface font stack, first available wins.', 'default': "'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"},
}

#: Every token name, in editor order.
TOKEN_NAMES = tuple(TOKENS)

#: name -> stylesheet default, i.e. the built-in look.
DEFAULTS = {k: v['default'] for k, v in TOKENS.items()}


def by_group() -> list[tuple[str, list[tuple[str, dict]]]]:
    """``[(group, [(name, meta), ...]), ...]`` in editor order."""
    out: list[tuple[str, list[tuple[str, dict]]]] = []
    for g in GROUP_ORDER:
        rows = [(n, m) for n, m in TOKENS.items() if m['group'] == g]
        if rows:
            out.append((g, rows))
    return out
