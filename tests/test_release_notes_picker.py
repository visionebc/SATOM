"""Guards for the Discover version picker's layout (2026-09-14).

The picker shipped as one wrapping inline run per major inside a 200px scroll
box. Against the live payload — 59 versions over 5 release lines, 8 to 14 each
— that is unreadable for reasons that are structural, not taste:

1. entries are variable-width (the old ``new`` badge is ~34px), so nothing
   aligns and a line that wraps continues *under the numbers of the line above*;
2. the major label was inline, so a wrapped continuation row was orphaned from
   the header naming it;
3. the ``new`` badge sat on **47 of 59** rows. Straight after Discover,
   ``checked === !in_corpus``, so those 47 badges repeated what 47 ticked boxes
   already said, while the 12 rows worth distinguishing carried no mark at all.
   The marker now rides the minority and keeps its own aligned column;
4. there was no way to take one release line — only new / all / none.

Two defects below were found only by RENDERING, with every assertion green:

* the header count shipped as held/total and sits flush against the take-the-
  line tick, so it read as "selected" while meaning something else — and the two
  numbers genuinely differ (8.0 is 6 held / 2 selected after Discover). It now
  counts ticks, live, which is why ``syncMajorBoxes`` owns it. A future refactor
  that inlines a static ``${held}/${n}`` back into the template string looks
  right and is wrong, so there is a guard for exactly that;
* at 880px the grid wraps to a second row, and the ``max-height`` cap sliced the
  7.0 column off below its header. A column showing a header and no releases
  says "this line has none" — the one thing it must never say. ``.modal-body``
  already scrolls; the grid must not be a second scroll region.

Every assertion here runs over source with comments stripped. The comments
explaining the retired markup necessarily name it, and asserting over raw text
makes an explanation fail its own guard — the recurring trap in this repo.
"""
from __future__ import annotations

import re
from pathlib import Path

_TPL = Path("app/templates/partials/release_notes_modal.html")
_JS = Path("app/static/js/release_notes.js")


def _src(rel: Path) -> str:
    return (Path(__file__).resolve().parents[1] / rel).read_text(encoding="utf-8")


def _markup(rel: Path) -> str:
    src = _src(rel)
    src = re.sub(r"\{#.*?#\}", "", src, flags=re.S)
    src = re.sub(r"<!--.*?-->", "", src, flags=re.S)
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)   # CSS comments too
    return src


def _code(rel: Path) -> str:
    src = _src(rel)
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"^\s*//.*$", "", src, flags=re.M)
    return src


def _fn(name: str) -> str:
    """The body of a top-level JS function, bounded by the NEXT function.

    Bounded by structure, never by a character count: a window measured in
    characters silently shrinks past the thing it was written to watch.
    """
    code = _code(_JS)
    start = code.index(f"function {name}(")
    nxt = code.find("\n  function ", start + 1)
    nxt2 = code.find("\n  async function ", start + 1)
    ends = [e for e in (nxt, nxt2) if e != -1]
    return code[start:min(ends)] if ends else code[start:]


def _cls(text: str, name: str) -> bool:
    """Is `name` present as a whole CSS class token?

    A plain substring test passes against a rename: "rn-vmaj" is inside
    "rn-vmaj-gone", so the guard for the line-level tick matched a mutant that
    had deleted it. \b is no help — a hyphen is already a word boundary.
    """
    return re.search(rf"{re.escape(name)}(?![\w-])", text) is not None


def _in_class_attr(text: str, name: str) -> bool:
    """Is `name` emitted as a class ON AN ELEMENT — not merely present as the
    selector that queries it? Checking one and calling it the other is how a
    renamed class slipped past: the guard read the selector and passed."""
    return re.search(rf'class="[^"]*{re.escape(name)}(?![\w-])', text) is not None


def _picker_css() -> str:
    """The #rnVersionPick rule block from the modal's own <style>."""
    css = _markup(_TPL)
    start = css.index("#rnVersionPick{")
    return css[start:css.index("}", start) + 1]


# --------------------------------------------------------------------------- #
#  Layout: a column per release line, not a wrapping run                       #
# --------------------------------------------------------------------------- #
def test_picker_is_a_grid():
    """auto-fit columns are what make 59 entries align; a flex/inline run is the
    defect this file exists for."""
    block = _picker_css()
    assert "display:grid" in block.replace(" ", "")
    assert "grid-template-columns" in block
    assert "auto-fit" in block


def test_each_release_line_is_its_own_column():
    body = _fn("renderVersions")
    assert _in_class_attr(body, "rn-vcol"), "columns gone — the picker is a flat run again"
    assert _in_class_attr(body, "rn-vcol-head"), "a column without a header orphans its rows"
    assert _in_class_attr(body, "rn-vcol-body")


def test_no_nested_scroll_region_on_the_grid():
    """Clipping a column to its bare header is the worst failure this widget
    has: it reads as 'this release line publishes nothing'."""
    block = _picker_css().replace(" ", "")
    assert "max-height" not in block, "the grid must not cap its own height"
    assert "overflow:auto" not in block and "overflow:scroll" not in block


# --------------------------------------------------------------------------- #
#  The marker rides the minority                                               #
# --------------------------------------------------------------------------- #
def test_marker_is_on_in_corpus_not_on_new():
    body = _fn("renderVersions")
    assert "r.in_corpus" in body, "nothing distinguishes held from missing"
    assert _in_class_attr(body, "rn-vhas")
    # The retired badge, by its markup — not by the word 'new', which legitimately
    # appears in prose and in the bulk-pick link.
    assert "text-bg-warning" not in body, (
        "the 'new' badge is back: it marks 47 of 59 rows and repeats what their "
        "own ticked checkboxes already say")


def test_marker_is_explained_somewhere_the_operator_looks():
    """An unlabelled glyph is a decoration. The legend lives on the bulk-pick
    bar, which is on screen whenever the glyphs are."""
    mk = _markup(_TPL)
    assert "already in the corpus" in mk
    assert "rnPickCount" in mk


# --------------------------------------------------------------------------- #
#  Taking a whole release line                                                 #
# --------------------------------------------------------------------------- #
def test_line_level_tick_exists_and_drives_the_line():
    body = _fn("renderVersions")
    assert _in_class_attr(body, "rn-vmaj"), "no way to take a whole release line"
    assert "data-major" in body
    # The handler must write through to `discovered`, not just to the DOM: the
    # scan posts pickedVersions(), which reads the model.
    assert "discovered.forEach" in body and "r.major === maj" in body


def test_partial_line_is_indeterminate():
    """A half-taken line rendered as an untaken one is a lie about what the
    next scan will fetch."""
    body = _fn("syncMajorBoxes")
    assert "indeterminate" in body
    assert "on > 0 && on < rows.length" in body.replace("  ", " ")


# --------------------------------------------------------------------------- #
#  The header count describes the tick it sits next to                         #
# --------------------------------------------------------------------------- #
def test_header_count_is_owned_by_the_live_sync():
    """Found only by rendering: held/total next to a checkbox reads as selected.
    The count is recomputed wherever the ticks change, so it cannot drift."""
    sync = _fn("syncMajorBoxes")
    assert _cls(sync, "rn-vcol-count"), (
        "the count left syncMajorBoxes — a value baked into the render string "
        "stops moving when the operator ticks, and looks correct doing it")
    assert "selected" in sync, "the count must say what it counts"


def test_render_does_not_bake_a_static_count():
    body = _fn("renderVersions")
    assert "in_corpus).length" not in body.replace(" ", ""), (
        "a held/total count is back in the column header, where it reads as a "
        "selection count and disagrees with one")


def test_line_tick_markup_and_selector_agree():
    """Two authors of one name is how a control goes inert without a trace: the
    class lives in a template literal, the handler binds through a selector."""
    body = _fn("renderVersions")
    sync = _fn("syncMajorBoxes")
    assert _in_class_attr(body, "rn-vmaj"), "the markup no longer emits the line tick"
    assert _cls(body, ".rn-vmaj"), "nothing binds a change handler to the line tick"
    assert _cls(sync, ".rn-vmaj"), "the tri-state never finds the box it describes"
