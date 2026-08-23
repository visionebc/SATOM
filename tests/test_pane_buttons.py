"""A button that reveals a pane from OUTSIDE the tab list.

The defect this file exists to prevent shipped twice and was reported by an
operator, not by a test: the "Response policy" button in the Incidents-console
pane and the "Incidents console" button in the Architecture pane both carried
``data-bs-toggle="tab"`` while sitting inside a ``.fw-card-body``.

Bootstrap 5.3's Tab constructor resolves its tab list with
``closest('.list-group, .nav, [role="tablist"]')`` and simply RETURNS when that
finds nothing — but the element still matches the click data-api, so ``show()``
runs anyway and throws ``Illegal invocation`` inside Bootstrap's own handler.
Nothing fails server-side: the pane exists, the markup is valid, the route is
200 and every render assertion in this repo passes. The only symptom is a
button that does nothing, which is indistinguishable from a button nobody
pressed.

So the rule this file enforces is the Bootstrap rule itself, asserted against
the RENDERED page rather than against a template: no element may carry
``data-bs-toggle="tab"`` unless it has a tab-list ancestor. Static template
scanning cannot see that — the toggle and its ``<aside class="nav">`` live in
different files and meet only at include time.

The second half is the replacement contract: every ``data-fw-pane`` button must
name a pane that exists, a menu entry that can actually be constructed, and a
fallback URL. A no-op is not an available outcome.
"""
from __future__ import annotations

import os
import re
from html.parser import HTMLParser

from conftest import admin_user_id, login

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'app', 'static', 'js', 'fw_pane_link.js')
BASE = os.path.join(ROOT, 'app', 'templates', 'base.html')

#: The surfaces that hold panes. ``/settings/`` carries all of them; the two
#: standalone pages carry none, and must therefore render LINKS.
PANE_SURFACE = '/settings/'
STANDALONE = ('/sentinel/', '/sentinel/docs', '/sentinel/policies')

#: Exactly what Bootstrap 5.3 looks for. Copied deliberately: if a Bootstrap
#: upgrade changes it, this guard has to be re-derived, not silently widened.
TABLIST_CLASSES = {'nav', 'list-group'}


class _Scan(HTMLParser):
    """Walks the document keeping an ancestor stack.

    Records, for every tab toggle and every ``data-fw-pane`` button, whether a
    tab-list ancestor was open at that point.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._stack: list[bool] = []          # is this ancestor a tab list?
        self.toggles: list[tuple[str, bool]] = []      # (target, inside_tablist)
        self.pane_buttons: list[dict] = []
        self.tab_targets_in_list: set[str] = set()
        self.pane_ids: set[str] = set()
        self.elements = 0

    # HTML that is not well nested would corrupt the stack; void elements are
    # the only legitimate source of that, and none of them can be a tab list.
    VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link',
            'meta', 'param', 'source', 'track', 'wbr'}

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        self.elements += 1
        is_list = (a.get('role') == 'tablist'
                   or bool(TABLIST_CLASSES & set((a.get('class') or '').split())))
        inside = is_list or any(self._stack)

        if 'tab-pane' in (a.get('class') or '').split() and a.get('id'):
            self.pane_ids.add('#' + a['id'])
        if a.get('data-bs-toggle') == 'tab':
            target = a.get('data-bs-target') or a.get('href') or ''
            self.toggles.append((target, inside))
            if inside:
                self.tab_targets_in_list.add(target)
        if a.get('data-fw-pane') is not None:
            self.pane_buttons.append({
                'target': a.get('data-fw-pane') or '',
                'href': a.get('data-fw-pane-href') or '',
                'type': a.get('type') or '',
                'bs_toggle': a.get('data-bs-toggle') or '',
            })

        if tag not in self.VOID:
            self._stack.append(is_list)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in self.VOID:
            self._stack.pop()

    def handle_endtag(self, tag):
        if tag not in self.VOID and self._stack:
            self._stack.pop()


def _scan(client, url) -> _Scan:
    r = client.get(url)
    assert r.status_code == 200, (url, r.status_code)
    s = _Scan()
    s.feed(r.get_data(as_text=True))
    return s


def _uncommented(path: str) -> str:
    """Source with its comments stripped.

    ``fw_pane_link.js`` documents the invariants it upholds, naming the very
    attributes and selectors asserted below — so a plain substring check is
    answered by the prose that explains it and passes against code that does
    the opposite. This repo has lost that argument nine times.
    """
    src = open(path, encoding='utf-8').read()
    src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
    return re.sub(r'^\s*//.*$', '', src, flags=re.M)


# --------------------------------------------------------------------------- #
#  The Bootstrap rule                                                           #
# --------------------------------------------------------------------------- #
def test_no_tab_toggle_is_rendered_outside_a_tab_list(app, client):
    login(client, admin_user_id(app))
    orphans = []
    for url in (PANE_SURFACE,) + STANDALONE:
        s = _scan(client, url)
        orphans += [(url, t) for t, inside in s.toggles if not inside]
    assert not orphans, (
        'data-bs-toggle="tab" with no .nav/.list-group/[role=tablist] ancestor: '
        'Bootstrap builds no Tab for these and its click handler throws — '
        f'the button is inert: {orphans}')


def test_the_scan_actually_reads_the_page(app, client):
    """A parser that finds nothing satisfies every assertion above it.

    Discovered by mutation: pointing the scan at an empty string left the
    orphan check green. The settings menu is itself a tab list full of
    toggles, so a working scan cannot come back empty.
    """
    login(client, admin_user_id(app))
    s = _scan(client, PANE_SURFACE)
    assert s.elements > 500, s.elements
    assert len(s.toggles) >= 10, s.toggles
    assert len(s.tab_targets_in_list) >= 10, s.tab_targets_in_list
    assert '#tab-sentinel-console' in s.pane_ids, sorted(s.pane_ids)


# --------------------------------------------------------------------------- #
#  The replacement contract                                                     #
# --------------------------------------------------------------------------- #
def test_the_pane_buttons_are_present_on_the_console_surface(app, client):
    """Both buttons exist, and neither has drifted back to a tab toggle."""
    login(client, admin_user_id(app))
    s = _scan(client, PANE_SURFACE)
    targets = sorted(b['target'] for b in s.pane_buttons)
    assert targets == ['#tab-sentinel-console', '#tab-sentinel-policy'], targets
    assert all(b['bs_toggle'] == '' for b in s.pane_buttons), s.pane_buttons


def test_every_pane_button_can_reach_its_pane(app, client):
    """Target pane exists AND a constructible trigger for it is on the page.

    The second half is the one that matters: the button forwards its click to
    the menu entry, so a pane with no menu entry would leave it inert again —
    for a different reason, with the same symptom.
    """
    login(client, admin_user_id(app))
    s = _scan(client, PANE_SURFACE)
    for b in s.pane_buttons:
        assert b['target'] in s.pane_ids, (b, sorted(s.pane_ids))
        assert b['target'] in s.tab_targets_in_list, (b, sorted(s.tab_targets_in_list))


def test_every_pane_button_carries_a_fallback_url(app, client):
    """No silent no-op where the pane is absent or the entry is hidden."""
    login(client, admin_user_id(app))
    s = _scan(client, PANE_SURFACE)
    for b in s.pane_buttons:
        assert b['href'].startswith('/'), b
        assert b['type'] == 'button', (
            'a bare <button> inside the settings form SUBMITS it', b)


def test_the_standalone_pages_render_links_not_pane_buttons(app, client):
    """Off the console there is no pane to reveal — the entry must navigate."""
    login(client, admin_user_id(app))
    for url in STANDALONE:
        s = _scan(client, url)
        assert not s.pane_buttons, (url, s.pane_buttons)


# --------------------------------------------------------------------------- #
#  The script                                                                   #
# --------------------------------------------------------------------------- #
def test_the_delegating_script_is_loaded_in_head(app, client):
    login(client, admin_user_id(app))
    body = client.get(PANE_SURFACE).get_data(as_text=True)
    head = body.split('</head>')[0]
    assert 'js/fw_pane_link.js' in head, (
        'loaded in the body block it would register a listener per Turbo visit')
    assert 'js/fw_pane_link.js' in _uncommented(BASE)


def test_the_script_forwards_to_a_trigger_inside_a_tab_list():
    """The whole point: it must pick a trigger Bootstrap can construct.

    Without the ancestor filter it could forward the click to the button
    itself, or to another orphan — reproducing the bug through the fix.
    """
    src = _uncommented(SCRIPT)
    assert 'data-fw-pane' in src
    assert '[role="tablist"]' in src and '.nav' in src
    assert 'closest(TABLIST)' in src or "closest('.list-group" in src
    assert 'data-fw-pane-href' in src, 'the fallback is not optional'
    # Reading the attribute is not using it: dropping the navigation while
    # keeping the getAttribute() line survived the first pass of this guard.
    assert re.search(r'window\.location\.href\s*=\s*href', src), (
        'the fallback attribute is read but never navigated to')
    assert 'preventDefault' in src


def test_the_script_is_delegated_and_booted_once():
    src = _uncommented(SCRIPT)
    assert "document.addEventListener('click'" in src, (
        'per-element binding misses panes Turbo swaps in later')
    assert '__fwPaneLinkBooted' in src
