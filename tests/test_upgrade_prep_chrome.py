"""Upgrade-preparation page: light chrome, contained values, readable CLI output.

Reported 2026-08-10: on ``/appliances/<id>/upgrade/prep`` the result text ran
past the card edges, the sizing did not match the rest of the product, and the
device CLI output "no se ve por los colores".

Three distinct defects, none of which can ever raise:

1. ``.fw-pre`` was a DARK-THEME LEFTOVER. ``rgba(0,0,0,0.30)`` over a white card
   renders as a light-grey slab, and ``#94a3b8`` text on that slab is about
   1.3:1 -- the health battery was rendered, complete, and unreadable. It is the
   same class of defect as the status pills fixed on 2026-07-28 (safeguards 9m),
   and ``.fw-pre`` is shared by FIVE other templates, so the same invisible
   output was on the inspector JSON dump, the git console in settings and the
   formal change-request document.
2. The four result tiles put device strings -- a firmware build, a backup
   filename -- in a ``.h5`` inside a quarter-width column. Long unbroken tokens
   do not wrap by default, so they overflowed the tile instead of wrapping.
3. The page was built out of raw Bootstrap ``.card`` / ``.badge bg-*`` /
   ``.alert-*``. ``.card`` has NO product override in ``fortiweb.css``, so this
   page rendered with different corners, borders and header padding from every
   other page, and the Bootstrap badge palette is not the one calibrated against
   white (``.fw-badge-*``).

A page that renders is not a page that reads: every guard here is about the
*appearance being true*, which has no exit code of its own.
"""
from __future__ import annotations

import io
import os
import re

import pytest

from app.models import Appliance, db
from tests.conftest import admin_user_id, login

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSS_PATH = os.path.join(REPO, "app", "static", "css", "fortiweb.css")
TPL_PATH = os.path.join(REPO, "app", "templates", "appliances", "upgrade_prep.html")


@pytest.fixture(scope="module")
def css():
    return io.open(CSS_PATH, encoding="utf-8").read()


@pytest.fixture(scope="module")
def tpl():
    return io.open(TPL_PATH, encoding="utf-8").read()


def _block(css_text, selector):
    """The declaration block of ``selector`` (first definition)."""
    m = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", css_text)
    assert m, "selector %s is gone from fortiweb.css" % selector
    return m.group(1)


# ------------------------------------------------- 1. the CLI output panel ---

def test_console_panel_is_not_a_dark_theme_leftover(css):
    """The exact values that made the output invisible must not come back."""
    body = _block(css, ".fw-pre")
    for dark in ("rgba(0,0,0,0.3)", "rgba(0,0,0,.3)", "#94a3b8",
                 "rgba(148,163,184,0.15)", "#cbd5e1", "#93c5fd"):
        assert dark not in body, "dark-theme value %s is back in .fw-pre" % dark


def test_console_panel_paints_from_the_light_token_set(css):
    """Tokens, not literals: the panel has to follow the product palette."""
    body = _block(css, ".fw-pre")
    assert "background: var(--fw-surface-alt)" in body
    assert "color: var(--fw-text-primary)" in body
    assert "border: 1px solid var(--fw-border)" in body


def test_console_panel_contains_its_own_overflow(css):
    """A long CLI line must scroll INSIDE the box, never widen the card.

    ``pre`` (not ``pre-wrap``) because device output is column-aligned and
    wrapping shreds the columns; the scroll is what keeps it contained.
    """
    body = _block(css, ".fw-pre")
    assert "white-space: pre;" in body
    assert re.search(r"overflow:\s*auto", body)
    assert "max-height" in body


# ------------------------------------------------------ 2. the value tiles ---

def test_fact_tile_values_wrap_instead_of_overflowing(css):
    """This is the reported symptom: a backup filename ran past the tile."""
    body = _block(css, ".fw-fact-value")
    assert "overflow-wrap: anywhere" in body
    assert "word-break: break-word" in body
    # A device string is not a headline number: .fw-stat-value's 28px is what
    # made these tiles overflow in the first place.
    size = re.search(r"font-size:\s*(\d+(?:\.\d+)?)px", body)
    assert size and float(size.group(1)) <= 16, "fact values are headline-sized again"


def test_fact_tile_can_shrink_inside_its_grid_column(css):
    """Without min-width:0 a grid/flex child refuses to shrink below content."""
    assert "min-width: 0" in _block(css, ".fw-fact")


def test_page_does_not_size_device_strings_as_headings(tpl):
    """``class="h5"`` on a firmware build is how the overflow was introduced."""
    assert 'class="h5' not in tpl
    assert "fw-fact-value" in tpl


def test_backup_filename_is_evidence_not_a_lozenge(css, tpl):
    """A 50-character filename inside a pill wraps into a two-line lozenge.

    The badge carries the VERDICT; the filename is evidence and gets its own
    breakable mono sub-line.
    """
    body = _block(css, ".fw-fact-sub")
    assert "overflow-wrap: anywhere" in body
    assert "font-family: Menlo" in body
    assert "fw-fact-sub" in tpl
    assert re.search(r"esc\(\s*bk\.name", tpl), "backup filename reaches innerHTML unescaped"
    # the whole filename must not be the badge label again
    assert "pill(d.backup.ok" not in tpl


def test_table_cells_holding_device_strings_can_break(css, tpl):
    """A published URL is long and unbroken; untreated it widens the table."""
    assert "overflow-wrap: anywhere" in _block(css, ".fw-cell-break")
    assert "fw-cell-break" in tpl


# ------------------------------------------------------------- 3. the chrome ---

def test_page_uses_the_product_card_not_the_bootstrap_one(tpl):
    """``.card`` has no override in fortiweb.css -- it renders unlike every
    other page in the product."""
    assert "fw-card" in tpl
    assert not re.search(r'class="card\b', tpl)
    assert not re.search(r'class="card-body\b', tpl)
    assert not re.search(r'class="card-header\b', tpl)


def test_page_uses_the_calibrated_badge_and_alert_palettes(tpl):
    """``.fw-badge-*`` / ``.fw-alert-*`` are the sets calibrated against white."""
    assert "fw-badge fw-badge-" in tpl
    assert "fw-alert-success" in tpl and "fw-alert-warning" in tpl
    assert "badge bg-" not in tpl
    # (?<!fw-) or this matches inside the CORRECT class name: the ninth
    # substring assertion in this repo to match its own right answer.
    assert not re.search(r"(?<!fw-)\balert-(success|warning|danger|secondary)\b", tpl)
    # text-success/text-danger on white is 3.1:1 / 3.9:1 -- below AA for the
    # 12px status text this page renders it at.
    assert "text-success" not in tpl
    assert "text-danger" not in tpl


# --------------------------------------------- device data is never markup ---

def test_device_supplied_values_are_escaped_before_innerhtml(tpl):
    """A policy name carrying '<' silently ate the rest of the row: a layout
    defect that looks exactly like missing data."""
    assert "function esc(" in tpl
    for field in ("t.policy", "t.url", "r.reason", "j.prep_summary", "t.note"):
        assert re.search(r"esc\(\s*" + re.escape(field), tpl), \
            "%s reaches innerHTML unescaped" % field
    # the raw interpolations that were there before must not return
    assert "${t.policy}" not in tpl
    assert "${t.url}" not in tpl


# ------------------------------------------------------- rendered output ---

def test_prep_page_renders_the_light_chrome(app, client):
    """The markup has to survive Jinja, not merely exist in the template."""
    with app.app_context():
        a = Appliance(name="prepbox", host="192.0.2.99", port=443, kind="fortiweb",
                      username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        aid = a.id

    login(client, admin_user_id(app))
    r = client.get("/appliances/%d/upgrade/prep" % aid)
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "fw-fact-value" in html
    assert 'class="fw-pre"' in html
    # Scope the sweep to THIS page's block. base.html's sidebar legitimately
    # paints slate icons on the dark-blue rail; scanning the whole document
    # would fail against correct chrome -- the same over-broad-scan trap that
    # flagged the CHANGELOG page during the brand-mark round.
    body = html[html.index("fw-page-header"):]
    for dark in ("rgba(30,41,59,", "rgba(15,23,42,", "rgba(0,0,0,0.3)",
                 "backdrop-filter", "#94a3b8", "#cbd5e1"):
        assert dark not in body, "dark-theme value %s leaked into the page" % dark
