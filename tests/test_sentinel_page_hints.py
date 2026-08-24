"""The "?" on the Sentinel pages themselves — console, context, policy, feed.

Settings → Sentinel already explained every knob (``test_sentinel_hints.py``).
The pages did not, and the gap had a shape worth naming: the prose for the four
health chips ALREADY EXISTED as ``UI_HINTS['health.*']`` and rendered only on
Settings, while the numbers those sentences describe are read on the incidents
console. An operator looking at "4416/4720 buckets usable" had no way, from
that screen, to learn that an immature bucket never fires — the explanation was
one page away and invisible.

Three failure modes are guarded, and they are different from each other:

* a key a template asks for that no catalog answers — the macro renders nothing
  for empty text, so the icon is SILENTLY absent and the page still returns 200;
* a catalog key no template draws — prose nobody can read, which is how a
  hint stays behind after the control it explained was moved or removed;
* a hint that exists in the catalog and never reaches the HTML on one of the
  two surfaces. Each section renders both as a standalone page and as a pane in
  the Admin Console, through the same partial but from different views. That
  seam is exactly where this section came apart before, twice.

The keys are read out of the TEMPLATES rather than listed here, because a list
maintained by hand shrinks quietly when a hint is deleted; the catalog side is
listed against the module, so both directions of the mapping are closed.
"""
from __future__ import annotations

import re

from conftest import admin_user_id, login

from app.services.sentinel import config as sn_config

TPL = "app/templates/sentinel/"

#: section key -> (partial, standalone URL)
SECTIONS = {
    "console": ("_console_section.html", "/sentinel/"),
    "context": ("_context_section.html", "/sentinel/context"),
    "policy": ("_policy_section.html", "/sentinel/policies"),
    "blocklist": ("_blocklist_section.html", "/sentinel/blocklist"),
}

#: The Admin Console surface. ``/settings/`` renders every pane in one
#: response, which is the point: it is the render in which a partial can be
#: reached by a view that forgot to pass something.
PANE = "/settings/"

#: Hints whose control is drawn conditionally, so a render against a quiet test
#: install legitimately does not contain them. Listed EXPLICITLY, with the
#: condition, rather than discovered by "whatever did not show up" — the latter
#: is a guard that excuses its own failures.
#:
#: * ``console.store``     — only when the metrics store is unreachable.
#: * ``console.blocklist`` — only when the feed is on or entries are live.
CONDITIONAL = {"console.store", "console.blocklist"}


def _uncommented(src: str) -> str:
    """Template source with its Jinja comments removed.

    Tenth time this repo needed it: the comment that JUSTIFIES a hint quotes
    the hint's own key, so a substring assert is answered by the prose and
    passes over a template that draws nothing.
    """
    return re.sub(r"\{#.*?#\}", "", src, flags=re.S)


def _keys_in(partial: str) -> list[str]:
    src = _uncommented(open(TPL + partial, encoding="utf-8").read())
    return re.findall(r"sn_hint\(\s*'([^']+)'\s*\)", src)


def _all_template_keys() -> set[str]:
    keys: set[str] = set()
    for partial, _url in SECTIONS.values():
        keys.update(_keys_in(partial))
    return keys


def _esc(text: str) -> str:
    """Jinja's autoescaping applied to the expectation, not stripped from the
    output — several hints contain an apostrophe, which renders as ``&#39;``,
    and comparing raw prose against rendered HTML fails on CORRECT output."""
    return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&#34;")
                .replace("'", "&#39;"))


def _body(client, url):
    r = client.get(url)
    assert r.status_code == 200, (url, r.status_code)
    return r.get_data(as_text=True)


# --------------------------------------------------------------------------- #
#  Census — a scan that reads nothing approves everything                       #
# --------------------------------------------------------------------------- #
def test_every_section_actually_draws_hints():
    """Without this, pointing the scan at an empty set passes every test below."""
    for name, (partial, _url) in SECTIONS.items():
        found = _keys_in(partial)
        assert len(found) >= 5, (name, found)


def test_the_catalog_is_not_empty():
    assert len(sn_config.PAGE_HINTS) >= 20, len(sn_config.PAGE_HINTS)


# --------------------------------------------------------------------------- #
#  The mapping, closed in both directions                                       #
# --------------------------------------------------------------------------- #
def test_every_key_a_template_asks_for_resolves_to_prose():
    """A typo costs a missing icon and a 200, never an exception. This is the
    only place it can be caught, so it has to be caught here."""
    dangling = sorted(k for k in _all_template_keys()
                      if not str(sn_config.hint_for(k)).strip())
    assert not dangling, f"templates ask for keys no catalog answers: {dangling}"


def test_every_catalog_key_is_drawn_somewhere():
    orphans = sorted(set(sn_config.PAGE_HINTS) - _all_template_keys())
    assert not orphans, f"prose nobody can read: {orphans}"


def test_the_health_chips_reuse_the_settings_prose_instead_of_a_second_copy():
    """The console chips describe the same four facts Settings describes.

    Redefining them under a ``console.*`` key would be two authors of one
    sentence — the failure that put two spellings of the licence footer in this
    product. They must fall through to ``UI_HINTS``.
    """
    console = _keys_in(SECTIONS["console"][0])
    for key in ("health.pipeline", "health.baseline", "health.vuln"):
        assert key in console, key
        assert key not in sn_config.PAGE_HINTS, f"{key} was copied, not reused"
        assert sn_config.hint_for(key) == sn_config.UI_HINTS[key]


def test_no_two_keys_carry_the_same_sentence():
    seen: dict[str, str] = {}
    for key, text in sn_config.PAGE_HINTS.items():
        flat = " ".join(text.split())
        assert flat not in seen, f"{key} duplicates {seen.get(flat)}"
        seen[flat] = key


def test_every_hint_is_an_explanation_not_a_restated_label():
    thin = [(k, len(v)) for k, v in sn_config.PAGE_HINTS.items() if len(v) < 120]
    assert not thin, f"hints too short to explain anything: {thin}"


# --------------------------------------------------------------------------- #
#  The render — standalone page AND Admin Console pane                          #
# --------------------------------------------------------------------------- #
def test_the_standalone_pages_render_their_hints(app, client):
    login(client, admin_user_id(app))
    for name, (partial, url) in SECTIONS.items():
        body = _body(client, url)
        for key in _keys_in(partial):
            if key in CONDITIONAL:
                continue
            assert _esc(sn_config.hint_for(key)[:70]) in body, (name, url, key)


def test_the_admin_console_pane_renders_the_same_hints(app, client):
    """The seam. One partial, two views: a page that renders on its own URL and
    is blank inside Settings is the defect this file exists for."""
    login(client, admin_user_id(app))
    body = _body(client, PANE)
    for name, (partial, _url) in SECTIONS.items():
        for key in _keys_in(partial):
            if key in CONDITIONAL:
                continue
            assert _esc(sn_config.hint_for(key)[:70]) in body, (name, PANE, key)


def test_the_baseline_number_explains_itself_where_it_is_read(app, client):
    """The reported defect, pinned: the sentence that explains
    "N/M buckets usable" has to be on the console, not only in Settings."""
    login(client, admin_user_id(app))
    body = _body(client, "/sentinel/")
    assert "buckets usable" in body
    assert _esc(sn_config.UI_HINTS["health.baseline"][:70]) in body


def test_the_hint_buttons_are_buttons_that_cannot_submit_a_form(app, client):
    """These sit inside the Settings <form> on the pane surface. A default
    <button> saves the page, so a curious operator reading a hint would have
    written every setting on it."""
    login(client, admin_user_id(app))
    body = _body(client, PANE)
    buttons = re.findall(r"<button[^>]*data-fw-hint[^>]*>", body)
    assert len(buttons) >= 25, len(buttons)
    assert all('type="button"' in b for b in buttons)
    assert all("aria-label=" in b for b in buttons)


def test_the_hint_survives_javascript_being_unavailable(app, client):
    """The text lives in ``title``, which the browser shows natively. A
    component whose only job is to explain must not go silent when a script
    fails to load."""
    login(client, admin_user_id(app))
    body = _body(client, "/sentinel/")
    for b in re.findall(r"<button[^>]*data-fw-hint[^>]*>", body):
        assert 'title="' in b, b
