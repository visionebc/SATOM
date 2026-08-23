"""Settings → Sentinel — the "?" beside every control.

Why this file exists at all: nothing FAILS when a control ships without an
explanation. The page renders, the form saves, the tests pass — the operator
simply has to guess what the knob does, and on this page the guesses are
expensive. ``response_enabled`` reads like a feature toggle and is the switch
that lets SATOM change a firewall by itself; ``vuln_sync_enabled`` reads like a
convenience and is the only outbound path in the module. The catalog docstring
already makes the argument for generating the FORM from ``SPEC``; this makes
the same argument for the prose.

Two failure modes are guarded, and they are different:

* a knob added to ``SPEC`` with no ``hint`` — the icon is silently absent;
* a hint that exists but never reaches the HTML, on EITHER surface — the pane
  and the standalone page render the same partial today, and a context key
  passed by one view and not the other is precisely how they came apart before.

Both surfaces are therefore asserted against rendered HTML, never against the
view function, because the defect lives between them.
"""
from __future__ import annotations

import re

from conftest import admin_user_id, login

from app.services.sentinel import config as sn_config

SURFACES = ('/settings/', '/settings/sentinel')

#: Every UI_HINTS key the section is supposed to draw. Listed literally rather
#: than derived from UI_HINTS, so DELETING a key fails here instead of quietly
#: shrinking what the test checks — a guard that derives its expectations from
#: the thing under test always passes.
EXPECTED_UI_KEYS = (
    'group.detection', 'group.baseline', 'group.vuln', 'group.ai',
    'group.response',
    'health.pipeline', 'health.baseline', 'health.vuln', 'health.catalog',
    'link.architecture', 'link.policies', 'link.context',
)


def _body(client, url):
    r = client.get(url)
    assert r.status_code == 200, (url, r.status_code)
    return r.get_data(as_text=True)


def _hint_titles(body: str) -> list[str]:
    """The text of every rendered hint button, in document order."""
    return re.findall(r'<button[^>]*data-fw-hint[^>]*title="([^"]*)"', body)


def _esc(text: str) -> str:
    """Jinja's autoescaping, applied to the expectation.

    Not cosmetic: the hints are ordinary prose and several contain an
    apostrophe, which Jinja renders as ``&#39;``. Comparing raw text against
    rendered HTML fails on CORRECT output — and the tempting fix (drop the
    quoted words from the probe) would leave a guard that no longer checks the
    sentence it claims to.
    """
    return (text.replace('&', '&amp;').replace('<', '&lt;')
                .replace('>', '&gt;').replace('"', '&#34;')
                .replace("'", '&#39;'))


def _uncommented(path: str) -> str:
    """A source file with its comments stripped, ready to be asserted against.

    Not optional. ``fw_hints.js`` explains in its own header WHY it needs
    ``container: 'body'`` and ``turbo:before-render`` — so a plain substring
    assert is answered by the prose and passes while the code says the
    opposite. Both mutations survived exactly that way before this helper
    existed, which is the eighth time an assert in this repo has matched the
    comment that justifies it.
    """
    src = open(path, encoding='utf-8').read()
    src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
    return re.sub(r'^\s*//.*$', '', src, flags=re.M)


# --------------------------------------------------------------------------- #
#  The catalog                                                                  #
# --------------------------------------------------------------------------- #
def test_every_setting_carries_a_hint():
    missing = [s['key'] for s in sn_config.SPEC if not str(s.get('hint', '')).strip()]
    assert not missing, f'settings with no explanation behind the "?": {missing}'


def test_every_hint_is_a_real_explanation_not_a_restated_label():
    """A hint shorter than its own label is a label with a question mark."""
    thin = [(s['key'], len(s.get('hint', '')))
            for s in sn_config.SPEC if len(str(s.get('hint', ''))) < 120]
    assert not thin, f'hints too short to explain anything: {thin}'


def test_ui_hints_covers_every_non_setting_element():
    missing = [k for k in EXPECTED_UI_KEYS
               if not str(sn_config.UI_HINTS.get(k, '')).strip()]
    assert not missing, f'section elements with no explanation: {missing}'


def test_every_group_in_groups_has_a_hint():
    """A group added to GROUPS renders a heading; it must explain itself too."""
    missing = [gkey for gkey, _label in sn_config.GROUPS
               if not str(sn_config.UI_HINTS.get(f'group.{gkey}', '')).strip()]
    assert not missing, missing


def test_form_groups_carries_the_hint_through_to_the_render_model(app):
    """``form_groups`` copies the spec; the template reads ``r.hint`` off it."""
    with app.app_context():
        rows = [r for _g, _l, rows in sn_config.form_groups() for r in rows]
    assert rows
    assert all(r.get('hint') for r in rows)


# --------------------------------------------------------------------------- #
#  The render — both surfaces                                                   #
# --------------------------------------------------------------------------- #
def test_both_surfaces_render_one_hint_per_setting(app, client):
    login(client, admin_user_id(app))
    for url in SURFACES:
        titles = _hint_titles(_body(client, url))
        for spec in sn_config.SPEC:
            assert _esc(spec['hint']) in titles, (url, spec['key'])


def test_both_surfaces_render_the_non_setting_hints(app, client):
    login(client, admin_user_id(app))
    for url in SURFACES:
        body = _body(client, url)
        for key in EXPECTED_UI_KEYS:
            assert _esc(sn_config.UI_HINTS[key][:60]) in body, (url, key)


def test_the_hint_button_cannot_submit_the_settings_form(app, client):
    """These buttons sit INSIDE the form. A default <button> saves the page,
    so reading an explanation would write the settings."""
    login(client, admin_user_id(app))
    for url in SURFACES:
        body = _body(client, url)
        for tag in re.findall(r'<button[^>]*data-fw-hint[^>]*>', body):
            assert 'type="button"' in tag, (url, tag)


def test_the_hint_button_is_focusable_and_labelled(app, client):
    """Hover-only help does not exist on a touch device, and an unlabelled
    icon button is announced as 'button' and nothing else."""
    login(client, admin_user_id(app))
    body = _body(client, '/settings/sentinel')
    tags = re.findall(r'<button[^>]*data-fw-hint[^>]*>', body)
    assert tags
    for tag in tags:
        assert tag.startswith('<button'), tag       # focusable by default
        assert 'aria-label="' in tag, tag


def test_the_tooltip_upgrade_script_is_loaded(app, client):
    """The prose lives in ``title``; fw_hints.js is what makes it readable
    (wide, left-aligned, and not clipped by the card). Without the script the
    page still explains itself natively — but silently losing the upgrade is
    worth failing for."""
    login(client, admin_user_id(app))
    assert 'js/fw_hints.js' in _body(client, '/settings/sentinel')


def test_the_tooltip_container_stays_pinned_to_the_body():
    """``.fw-card`` is ``overflow: hidden``, and a panel parented inside it is
    clipped: measured in a headless browser, a 132px explanation in a 123px
    card paints 58px and loses the rest — while still looking like a working
    tooltip.

    Bootstrap 5 happens to default to ``<body>`` already, so this guard is not
    protecting against today's default; it freezes the value against anything
    that would re-parent the panel — a library upgrade whose default moves
    back to the element's parent (Bootstrap 4's behaviour), or a plausible
    ``container: '.fw-card'``.
    """
    assert "container: 'body'" in _uncommented('app/static/js/fw_hints.js')


def test_the_hint_panel_is_wider_than_bootstraps_default():
    """Bootstrap's 200px wraps a 400-character explanation into a column about
    twenty lines tall, which is unreadable at a hover."""
    css = _uncommented('app/static/css/fortiweb.css')
    blocks = re.findall(r'\.fw-hint-tip\s*\{([^}]*)\}', css)
    assert blocks, 'no .fw-hint-tip rule in the stylesheet'
    widths = [int(px) for b in blocks
              for px in re.findall(r'--bs-tooltip-max-width:\s*(\d+)px', b)]
    assert widths, '.fw-hint-tip never widens the panel'
    assert max(widths) >= 320, widths


def test_the_tooltip_is_disposed_across_a_turbo_visit():
    """Popper appends the panel to <body>, which Turbo's body swap does not
    touch: without disposal every visit strands its tooltips and a hover pops
    up help for a control that is no longer on the page."""
    js = _uncommented('app/static/js/fw_hints.js')
    assert 'turbo:before-render' in js
    assert 'dispose' in js
