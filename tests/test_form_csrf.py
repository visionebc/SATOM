"""Every POST <form> in a template must carry a CSRF token.

Nothing fails when it doesn't.  The page renders, the button renders, the
button is clickable — and the POST is rejected by Flask-WTF's CSRFProtect,
which the app turns into the flash "Your session expired or the form was
stale".  The operator reads that as *their* session being stale and retries
forever; the form was never submittable.  That is exactly how the Rebuild
button on /registry/versions shipped broken (2026-08-17).

The fetch() shim in ``app/static/js/main.js`` injects ``X-CSRFToken`` on every
same-origin state-changing fetch, so JSON callers are covered app-wide.  It
does NOT cover a native form submit — the browser never goes through fetch().
So the token has to be in the markup.

The guard is derived from the artifact: it re-parses the templates on disk and
resolves every ``<form>`` block itself.  A new POST form without a token breaks
this in the same commit that introduces it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TEMPLATES = Path(__file__).resolve().parent.parent / "app" / "templates"

# A <form …> opening tag through its matching </form>.  Non-greedy so nested
# markup between two sibling forms is not swallowed into one block.
_FORM_RE = re.compile(r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>", re.S | re.I)
_METHOD_RE = re.compile(r"""method\s*=\s*["']?\s*post\s*["']?""", re.I)


def _templates() -> list[Path]:
    return sorted(TEMPLATES.rglob("*.html"))


def _post_forms(path: Path):
    """Yield (line_number, attrs, body) for each POST form in *path*."""
    text = path.read_text(encoding="utf-8")
    for m in _FORM_RE.finditer(text):
        if not _METHOD_RE.search(m.group("attrs")):
            continue
        line = text.count("\n", 0, m.start()) + 1
        yield line, m.group("attrs"), m.group("body")


def _has_token(body: str) -> bool:
    return "csrf_token" in body


# ── the guard ────────────────────────────────────────────────────────────

def test_every_post_form_carries_a_csrf_token():
    missing = []
    for path in _templates():
        for line, _attrs, body in _post_forms(path):
            if not _has_token(body):
                rel = path.relative_to(TEMPLATES.parent.parent)
                missing.append(f"{rel}:{line}")
    assert not missing, (
        "POST form(s) without a csrf_token hidden input — the submit will be "
        "rejected by CSRFProtect and flash 'session expired or the form was "
        "stale':\n  " + "\n  ".join(missing)
    )


def test_the_scan_actually_finds_forms():
    """A scan that matches nothing would pass the guard above vacuously."""
    total = sum(1 for p in _templates() for _ in _post_forms(p))
    assert total > 50, f"only {total} POST forms parsed — the regex stopped matching"


def test_the_scan_reports_a_planted_form(tmp_path, monkeypatch):
    """The guard must be able to SEE a violation, not merely be green today."""
    bad = tmp_path / "bad.html"
    bad.write_text(
        '<form method="post" action="/x"><button type="submit">go</button></form>\n',
        encoding="utf-8",
    )
    found = list(_post_forms(bad))
    assert len(found) == 1
    assert not _has_token(found[0][2])


def test_the_scan_accepts_a_planted_form_with_a_token(tmp_path):
    good = tmp_path / "good.html"
    good.write_text(
        '<form method="post" action="/x">\n'
        '  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">\n'
        "  <button type=\"submit\">go</button></form>\n",
        encoding="utf-8",
    )
    found = list(_post_forms(good))
    assert len(found) == 1
    assert _has_token(found[0][2])


def test_sibling_forms_are_not_merged_into_one_block(tmp_path):
    """Greedy matching would let a tokenless form borrow its neighbour's token."""
    both = tmp_path / "two.html"
    both.write_text(
        '<form method="post" action="/a">'
        '<input type="hidden" name="csrf_token" value="x"></form>\n'
        '<form method="post" action="/b"><button>go</button></form>\n',
        encoding="utf-8",
    )
    found = list(_post_forms(both))
    assert len(found) == 2
    assert _has_token(found[0][2]) and not _has_token(found[1][2])


def test_get_forms_are_not_required_to_carry_a_token(tmp_path):
    g = tmp_path / "get.html"
    g.write_text('<form method="get" action="/s"><input name="q"></form>\n', encoding="utf-8")
    assert list(_post_forms(g)) == []


@pytest.mark.parametrize(
    "page,endpoint_marker",
    [
        ("registry/versions.html", "rebuild_endpoint"),
        ("section_catalog/index.html", "templates.unapprove"),
    ],
)
def test_the_two_regressed_pages_still_name_their_action(page, endpoint_marker):
    """The scan above stays green if someone deletes the form entirely.

    These two pages are the ONLY place an operator learns the action exists,
    so the form has to still be there — with its token.
    """
    text = (TEMPLATES / page).read_text(encoding="utf-8")
    assert endpoint_marker in text
    forms = [b for _l, _a, b in _post_forms(TEMPLATES / page) if endpoint_marker in b or True]
    assert forms, f"{page} lost its POST form"
    assert all(_has_token(b) for b in forms), f"{page} has a tokenless POST form"
