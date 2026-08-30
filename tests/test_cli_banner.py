"""Guards for the interactive console banner (``satom`` with no arguments).

The banner is the NINTH surface on which SATOM declares its licence, joining
``LICENSE``, ``NOTICE``, ``README.md``, ``CONTRIBUTING.md``, ``DISCLAIMER``,
``SECURITY.md``, the curated ``site/`` pages and the footer template inside
``deploy/gen_site_docs.py``.

Nothing *fails* when a licence surface goes stale -- the claim simply becomes
false, which is how ``Version: 1.0`` survived four releases in the README. Here
it is worse: an operator who reads a grant off a recovery console is relying on
terms that may never have been granted. So the console's wording is pinned to
the same assertions the site footer makes, and the old licence may not appear
at all.

The layout guards exist for a different reason. This CLI is opened on the
serial console of a node that is already broken. Art that wraps, art built from
glyphs that fold to garbage, or a banner that cannot be turned off are all
failures that only show up on the worst possible day.
"""
import io
import os
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
CLI_DIR = REPO / "deploy" / "satom_cli"
sys.path.insert(0, str(REPO / "deploy"))

from satom_cli import main as cli_main  # noqa: E402
from satom_cli.render import Style  # noqa: E402

MAIN_SRC = (CLI_DIR / "main.py").read_text(encoding="utf-8")


class _FakeCtx:
    """Minimal stand-in: the banner must not need a database to render."""

    host = "node-under-test"
    user = "root"
    role = "primary"
    is_root = True

    def version(self):
        return "9.9.9"


def _style(**kw):
    kw.setdefault("color", False)
    kw.setdefault("ascii_only", False)
    kw.setdefault("width", 100)
    return Style(**kw)


def _lines(ctx=None, **kw):
    return cli_main.banner_lines(ctx or _FakeCtx(), _style(**kw))


def _text(ctx=None, **kw):
    return "\n".join(_lines(ctx, **kw))


@pytest.fixture(autouse=True)
def _no_banner_env_leak(monkeypatch):
    monkeypatch.delenv(cli_main.NO_BANNER_ENV, raising=False)


# --------------------------------------------------------------------------
# Layout
# --------------------------------------------------------------------------

def test_wordmark_has_every_letter_on_every_row():
    art = cli_main.art_lines()
    assert len(art) == cli_main._ART_ROWS == 7
    for letter in "SATOM":
        assert len(cli_main._ART_GLYPHS[letter]) == 7, letter


def test_every_letter_is_the_same_width():
    """Letters of unequal width slide the whole word out of column."""
    widths = {len(row) for glyph in cli_main._ART_GLYPHS.values() for row in glyph}
    assert widths == {12}, widths


def test_every_letter_puts_ink_on_the_top_row():
    """The reported defect: a font whose row 0 is blank for some letters reads
    as 'the tops are missing'. figlet's standard 'A' has nothing on row 0."""
    for letter, glyph in cli_main._ART_GLYPHS.items():
        assert glyph[0].strip(), letter


def test_body_rows_share_one_left_margin():
    art = cli_main.art_lines()
    leads = [len(r) - len(r.lstrip()) for r in art]
    # Row 4 is the S's bowl -- that gap is the letterform, not a margin.
    # Pinned to the LITERAL 2, not to len(_ART_INDENT): an assertion that
    # derives its expectation from the constant it exists to pin is satisfied
    # by any value of that constant, and this one was -- the mutation harness
    # caught it as the only survivor of 24.
    body = [leads[i] for i in (1, 2, 3, 5, 6)]
    assert body == [2, 2, 2, 2, 2], leads


def test_top_row_carries_the_operator_requested_offset():
    """Explicitly asked for, twice, after being told it shifts the top bars
    right of their own stems. Pinned so it cannot drift back silently."""
    art = cli_main.art_lines()
    top = len(art[0]) - len(art[0].lstrip())
    body = len(art[1]) - len(art[1].lstrip())
    assert top - body == len(cli_main._ART_TOP_EXTRA) == 2


def test_wordmark_is_pure_ascii_blocks():
    """Unicode blocks fold to garbage on the serial console this tool exists
    for, and would force a second art variant for --ascii."""
    chars = {c for row in cli_main.art_lines() for c in row}
    assert chars <= {"#", " "}, chars


def test_art_is_identical_in_ascii_and_unicode_modes():
    plain = [l for l in _lines(ascii_only=True) if "#" in l]
    fancy = [l for l in _lines(ascii_only=False) if "#" in l]
    assert plain == fancy


def test_banner_fits_eighty_columns():
    assert max(len(l) for l in _lines()) <= 80


def test_no_row_has_trailing_whitespace():
    """Trailing blanks are invisible in review and land in every paste."""
    for line in _lines():
        assert line == line.rstrip(), repr(line)


def test_rows_are_right_trimmed_whatever_the_last_letter_is(monkeypatch):
    """The word happens to end in M, whose rows have no trailing blanks -- so
    on the real banner the trim is unobservable and a guard against it could
    never fail. S's middle row DOES end in blanks; put it last and the trim
    becomes the only thing standing between review and invisible whitespace."""
    monkeypatch.setattr(cli_main, "_ART_WORD", "SS")
    rows = cli_main.art_lines()
    assert any(cli_main._ART_GLYPHS["S"][i].endswith(" ") for i in range(7))
    for line in rows:
        assert line == line.rstrip(), repr(line)


# --------------------------------------------------------------------------
# Licence and attribution
# --------------------------------------------------------------------------

def test_licence_states_every_operative_claim():
    txt = _text()
    for claim in ("Elastic License 2.0", "Source-available",
                  "NOT OSI open source", "AS IS",
                  "licensing@visionebc.com",
                  "hosted or managed service"):
        assert claim in txt, claim


def test_licence_never_names_the_old_one():
    assert "Apache" not in _text()


def test_console_claim_matches_the_site_footer():
    """Two authors of one sentence is how index.html lost its Docs link."""
    html = (REPO / "site" / "index.html").read_text(encoding="utf-8")
    # The footer wraps the licence name in an <a>, so compare on the rendered
    # text. A raw substring check fails against a perfectly correct page.
    footer = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", html))
    phrase = "Licensed under the Elastic License 2.0"
    assert phrase in footer
    assert phrase in _text()


def test_attribution_is_present_and_uses_the_brand_spelling():
    assert "Made by VisionEBC" in _text()


def test_copyright_keeps_the_legal_name_with_a_space():
    """The banner is the marque; the copyright line is the LICENSOR, and it
    has to read the same as the other eight surfaces or the grant is made by
    a name that appears nowhere in LICENSE."""
    copyright_line = [l for l in _lines() if "Copyright" in l]
    assert len(copyright_line) == 1
    assert "Vision EBC" in copyright_line[0]
    assert "VisionEBC" not in copyright_line[0]
    assert "Vision EBC" in (REPO / "LICENSE").read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# Degradation
# --------------------------------------------------------------------------

def test_opt_out_drops_art_and_licence_prose_but_keeps_the_console(monkeypatch):
    monkeypatch.setenv(cli_main.NO_BANNER_ENV, "1")
    txt = _text()
    assert "####" not in txt
    assert "Elastic License" not in txt
    assert "SATOM operator CLI 9.9.9" in txt
    assert "'exit' leaves" in txt


def test_narrow_terminal_collapses_to_the_same_short_form():
    """Suppressing only the art would leave four fixed-width licence sentences
    to wrap into confetti on the recovery console."""
    narrow = _text(width=cli_main._ART_MIN_WIDTH - 1)
    assert "####" not in narrow
    assert "Elastic License" not in narrow
    assert "SATOM operator CLI 9.9.9" in narrow


def test_at_the_threshold_the_art_is_shown():
    assert "####" in _text(width=cli_main._ART_MIN_WIDTH)


def test_a_pipe_never_suppresses_anything():
    """width == 0 means 'do not reflow', not 'narrow'. Suppressing there would
    strip the licence from every redirected transcript."""
    piped = _text(width=0)
    assert "####" in piped
    assert "Elastic License 2.0" in piped


def test_ascii_mode_emits_no_typography():
    leaked = sorted({c for c in _text(ascii_only=True) if ord(c) > 127})
    assert leaked == [], leaked


def test_colour_never_leaks_an_orphan_reset():
    """Style.c() returns the bare text for an unknown palette key AND still
    appends a reset -- a silent way to emit an escape with no opener."""
    for line in _lines(color=True):
        assert line.count("\033[0m") * 2 == line.count("\033["), repr(line)


def test_art_rows_carry_no_escape_sequences():
    for line in _lines(color=True):
        if "####" in line:
            assert "\033" not in line, repr(line)


# --------------------------------------------------------------------------
# Wiring
# --------------------------------------------------------------------------

def test_repl_actually_prints_the_banner():
    """A perfect banner function that nothing calls is the failure this whole
    file would otherwise miss."""
    body = MAIN_SRC[MAIN_SRC.index("def repl("):]
    body = body[:body.index("\ndef ", 1)]
    body = re.sub(r"#.*", "", body)          # a comment naming it is not a call
    assert "banner_lines(ctx, st)" in body


def test_identity_comes_from_the_context_not_a_literal():
    txt = _text()
    assert "9.9.9" in txt
    assert "node-under-test" in txt
    assert "primary" in txt


def test_unprivileged_operator_is_still_warned():
    class _User(_FakeCtx):
        is_root = False
        user = "satom"

    assert "unprivileged" in _text(_User())
