"""The manual must describe the console the operator is actually looking at.

Why this file exists
--------------------
Nothing fails when a manual goes stale.  The page renders, the suite passes,
the sentence simply stops being true — and the reader acts on it.  §26 opened
with "one page with **22 tabs**" for weeks after Settings became a grouped
sidebar, on a document that is **published publicly**; and three shipped
features (Bookmarks, Concept Map, Upgrade Flow) had no entry at all, so the
only way to find out they existed was to notice them in the sidebar.

So every assertion here is **derived from the artefact**, never from a list
typed into this file:

* the Settings groups and panels are parsed out of the template that renders
  the menu;
* the languages come from ``services.langs.SUPPORTED``;
* the bookmark kinds, scopes and grouping modes from ``services.bookmarks`` /
  ``models_bookmarks``;
* the concept clusters and the page/exclusion counts from
  ``services.concept_map``;
* the two Upgrade Flow limits from ``views.upgrade_flow``.

Adding a group, a language, a bookmark kind, a concept or a page therefore
breaks this suite **in the commit that adds it**, which is the only moment
anybody knows what the new thing does.

Every assertion is scoped to the section that must carry it.  A whole-document
search is how a guard ends up answered by an unrelated paragraph — this repo
has retired several of those, including one that was answered by the comment
explaining it.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

from app.models_bookmarks import KINDS as BM_KINDS, SCOPES as BM_SCOPES
from app.services import langs
from app.services.bookmarks import GROUP_MODES
from app.services.concept_map import CONCEPTS
from app.views.upgrade_flow import MAX_SWEEP, MAX_WAVES

ROOT = pathlib.Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs" / "user-guide.md"
# The menu literal lives in the PARTIAL every settings surface
# includes, not in the console page: reading index.html here would
# have stopped finding it the moment the menu was single-sourced.
SETTINGS_TPL = ROOT / "app" / "templates" / "settings" / "_nav.html"

TEXT = GUIDE.read_text()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def section(num: int) -> str:
    """The body of ``## <num>.`` up to the next top-level section.

    Scoping matters more than it looks: "language", "bookmark" and "wave" all
    appear elsewhere in a 3 000-line manual, so an unscoped search passes with
    the section deleted.
    """
    m = re.search(rf"^## {num}\.[^\n]*\n(.*?)(?=^## \d+\.|\Z)", TEXT,
                  re.M | re.S)
    assert m, f"section {num} not found in the guide"
    return m.group(1)


def subsection(label: str) -> str:
    """The body of ``### <label>`` up to the next ``###``/``##``."""
    m = re.search(rf"^### {re.escape(label)}[^\n]*\n(.*?)(?=^###? |\Z)", TEXT,
                  re.M | re.S)
    assert m, f"subsection {label!r} not found in the guide"
    return m.group(1)


def _nav_groups() -> list[dict]:
    """Parse ``nav_groups`` out of the template that RENDERS the menu.

    Read from the template rather than re-typed here: the template is what the
    operator sees, so it is the only thing that can be wrong in a way this
    guard should catch.
    """
    src = SETTINGS_TPL.read_text()
    m = re.search(r"\{%\s*set nav_groups\s*=\s*(\[.*?\])\s*%\}", src, re.S)
    assert m, "nav_groups literal not found in settings/_nav.html"
    body = m.group(1)
    # `_('...')` is a call, not a literal; unwrap it so the list can be eval'd.
    body = re.sub(r"_\(\s*('([^']*)'|\"([^\"]*)\")\s*\)", r"\1", body)
    body = body.replace("true", "True").replace("false", "False")
    return ast.literal_eval(body)


GROUPS = _nav_groups()
PANELS = [it for g in GROUPS for it in g["items"]]
S26 = section(26)
S38, S39, S40 = section(38), section(39), section(40)
LANG_BODY = subsection("26.12b Languages")


# ---------------------------------------------------------------------------
# §26 — Settings is a grouped sidebar, not a strip of tabs
# ---------------------------------------------------------------------------
def test_settings_intro_states_the_live_group_and_panel_counts():
    head = S26.split("### ")[0]
    assert f"**{len(GROUPS)} groups, {len(PANELS)} panels**" in head, (
        f"§26 must state the live shape ({len(GROUPS)} groups, "
        f"{len(PANELS)} panels); it says: {head.splitlines()[0]!r}"
    )


def test_settings_intro_states_the_admin_only_panel_count():
    admin_panels = [it for g in GROUPS if g["admin"] for it in g["items"]]
    n_admin_groups = len([g for g in GROUPS if g["admin"]])
    head = S26.split("### ")[0]
    assert f"({len(admin_panels)} panels) are admin-only" in head
    assert re.search(rf"{_word(n_admin_groups)} of the groups", head, re.I), (
        f"§26 must say {_word(n_admin_groups)} of the groups are admin-only"
    )


def test_settings_intro_no_longer_claims_a_flat_tab_strip():
    head = S26.split("### ")[0]
    assert "one page with **22 tabs**" not in head
    assert not re.search(r"one page with \*\*\d+ tabs\*\*", head), (
        "§26 describes a flat tab strip; Settings is a grouped sidebar"
    )


def _s26_table() -> str:
    """The `| Group | Panels |` table alone.

    Scoped, not the whole intro: the prose above the table legitimately names
    groups and panels while EXPLAINING them ("Sentinel is its own group…",
    "Architecture, Incidents console"). Asserted against the intro as a whole,
    a deleted table row keeps passing on the strength of the sentence that
    describes it — which is how a reader ends up with a table that no longer
    lists a group the same page just told them about.
    """
    head = S26.split("### ")[0]
    rows = [ln for ln in head.splitlines()
            if ln.startswith("|") and ln.count("|") >= 3
            and not set(ln) <= set("|- ")]
    assert len(rows) >= len(GROUPS), (
        f"§26 has {len(rows)} table rows for {len(GROUPS)} groups"
    )
    return "\n".join(rows)


S26_TABLE = _s26_table()


@pytest.mark.parametrize("group", [g["label"] for g in GROUPS])
def test_every_settings_group_is_named_in_the_intro(group):
    assert f"**{group}**" in S26_TABLE, \
        f"group {group!r} missing from the §26 table"


@pytest.mark.parametrize("panel", sorted({it["label"] for it in PANELS}))
def test_every_settings_panel_is_named_in_the_intro(panel):
    assert panel in S26_TABLE, f"panel {panel!r} missing from the §26 table"


def test_the_table_lists_the_groups_in_the_order_the_menu_draws_them():
    """The reader counts down the table to find a group on screen.

    Nothing fails when the two orders drift: every row is still present and
    every panel still filed correctly, so the guards above stay green while the
    manual describes a menu nobody has. Position carries the instruction here —
    the operator asked for the configure-once groups at the BOTTOM, and a table
    that lists them third is a different answer to the request that made them.
    """
    labels = [g["label"] for g in GROUPS]
    order = []
    for ln in S26_TABLE.splitlines():
        for label in labels:
            if "**%s**" % label in ln and label not in order:
                order.append(label)
    assert order == labels, (
        "the §26 table lists the groups as %s; the menu draws them as %s"
        % (order, labels)
    )


@pytest.mark.parametrize("group", [g["key"] for g in GROUPS])
def test_each_group_row_lists_that_group_s_own_panels(group):
    """A panel named SOMEWHERE in the table is not the same as a panel named
    in its own row: the table is read row by row, and a panel filed under the
    wrong group sends the reader to a menu entry that is not there."""
    g = next(x for x in GROUPS if x["key"] == group)
    row = next((ln for ln in S26_TABLE.splitlines()
                if f'**{g["label"]}**' in ln), None)
    assert row, f'no row for group {g["label"]!r}'
    for it in g["items"]:
        assert it["label"] in row, (
            f'panel {it["label"]!r} is not in the {g["label"]!r} row'
        )


def test_the_intro_describes_sentinel_s_entries_the_way_the_menu_draws_them():
    """Derived from the menu literal, not from a sentence typed in here.

    Every entry in the Sentinel group is a pane (`t`), so the manual may not
    still tell the reader that two of them are "links out" drawn with a
    leaving arrow. Nothing fails when it does: the page renders, the guards
    above stay green because every row and label is still correct, and the
    reader saves their work before clicking a control that was never going to
    take the console away.
    """
    head = S26.split("### ")[0]
    sentinel = next(g for g in GROUPS if g["key"] == "sentinel")
    leaves = [it for it in sentinel["items"] if "ep" in it]
    if not leaves:
        assert "links out" not in head, (
            "§26 says Sentinel's entries are links out of the console; every "
            "one of them is a pane"
        )
        assert "leaving arrow" not in head, (
            "§26 says a Sentinel entry carries the leaving arrow; none does"
        )
        # The COUNT is derived from the menu literal too. Spelling it into
        # this guard is how the sentence would go on saying "three" after a
        # fourth and a fifth entry joined the group -- the same silent-staleness
        # the rest of this file exists to catch, committed by the catcher.
        words = {2: "two", 3: "three", 4: "four", 5: "five", 6: "six",
                 7: "seven", 8: "eight"}
        n = len(sentinel["items"])
        phrase = "all %s of its entries are panes" % words.get(n, n)
        assert phrase in head, (
            "§26 does not tell the reader that Sentinel's %d entries all "
            "render inside the console (looked for %r)" % (n, phrase)
        )


def test_intro_says_the_panel_targets_did_not_change():
    """The regrouping kept `#tab-*` targets, and the manual's ~90 §26.x
    cross-references depend on it.  A reader who believes the deep links moved
    stops using them."""
    head = S26.split("### ")[0]
    assert "#tab-auth" in head


# ---------------------------------------------------------------------------
# §26.12b — Languages
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("code,endonym", list(langs.SUPPORTED))
def test_every_supported_language_is_listed(code, endonym):
    assert f"`{code}`" in LANG_BODY, f"language code {code!r} not listed"
    assert endonym in LANG_BODY, f"endonym {endonym!r} not listed"


def test_the_source_language_is_marked_as_such():
    row = [ln for ln in LANG_BODY.splitlines()
           if ln.startswith(f"| `{langs.DEFAULT}`")]
    assert row, f"no table row for the source language {langs.DEFAULT!r}"
    assert "source" in row[0].lower(), (
        "the source language must be marked in the table — it is the one "
        "an install cannot switch off"
    )


def test_withdrawing_is_documented_as_non_destructive():
    """The rule an operator needs BEFORE clicking: a withdrawn language does
    not delete anybody's stored preference."""
    flat = " ".join(LANG_BODY.split())
    assert "stops being honoured" in flat
    assert "Deleting the row" in flat


def test_unset_means_everything_is_documented():
    flat = " ".join(LANG_BODY.split())
    assert "Unset or unreadable means everything" in flat


# ---------------------------------------------------------------------------
# §38 — Bookmarks
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("kind", BM_KINDS)
def test_every_bookmark_kind_is_documented(kind):
    assert f"**{kind}**" in S38, f"bookmark kind {kind!r} not in §38"


@pytest.mark.parametrize("scope", BM_SCOPES)
def test_every_bookmark_scope_is_documented(scope):
    assert f"**{scope}**" in S38, f"bookmark scope {scope!r} not in §38"


@pytest.mark.parametrize("mode", GROUP_MODES)
def test_every_grouping_mode_is_documented(mode):
    assert f"**{mode}**" in S38, f"grouping mode {mode!r} not in §38"


def test_grouping_section_states_how_many_modes_are_derived():
    body = subsection("38.3 Grouping is computed, not stored")
    derived = len(GROUP_MODES) - 1  # everything but `folder`
    assert f"other {_word(derived)} are recomputed" in body, (
        f"§38.3 must say {derived} modes are derived; the module comment "
        f"says seven and is wrong — GROUP_MODES has {len(GROUP_MODES)}"
    )


def test_the_readers_permissions_decide_the_list():
    """The single most consequential thing about sharing: you cannot hand
    somebody a device by bookmarking it."""
    flat = " ".join(S38.split())
    assert "filtered by **your** permissions, never the sharer's" in flat


def test_maintenance_does_not_destroy_placement():
    flat = " ".join(S38.split())
    assert "comes back where you filed it" in flat
    assert "never deletes its placement" in flat


# ---------------------------------------------------------------------------
# §39 — Concept Map
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("label", [c["label"] for c in CONCEPTS])
def test_every_concept_cluster_is_documented(label):
    assert f"**{label}**" in S39, f"concept {label!r} missing from §39"


def test_page_and_exclusion_counts_match_the_map():
    from app.services import concept_map as cmap
    flat = " ".join(S39.split())
    assert f"({len(cmap.PAGES)} today)" in flat, (
        f"§39 must state the live page count ({len(cmap.PAGES)})")
    assert f"({len(cmap.EXCLUDED)} today" in flat, (
        f"§39 must state the live exclusion count ({len(cmap.EXCLUDED)})")


def test_the_stable_concept_key_url_is_documented():
    """The keys are stable precisely so a cluster can be linked to; a reader
    who does not know that cannot use it."""
    key = CONCEPTS[2]["key"]  # 'waf' — the example the module itself uses
    assert f"/map/?c={key}" in S39


# ---------------------------------------------------------------------------
# §40 — Upgrade Flow
# ---------------------------------------------------------------------------
def test_both_limits_are_stated_with_their_real_numbers():
    body = subsection("40.2 Two limits that refuse rather than truncate")
    assert f"**{MAX_SWEEP}**" in body, f"sweep limit {MAX_SWEEP} not stated"
    assert f"**{MAX_WAVES}**" in body, f"wave limit {MAX_WAVES} not stated"


def test_the_limits_are_documented_as_refusing_not_truncating():
    """An operator who believes the tool silently does fewer devices plans a
    window differently — and wrongly."""
    body = subsection("40.2 Two limits that refuse rather than truncate")
    flat = " ".join(body.split())
    assert "refuse, naming the number" in flat


def test_all_four_stages_are_documented():
    body = subsection("40.1 The four stages")
    for stage in ("Pre-upgrade", "Change request", "Customer impact",
                  "Execution"):
        assert stage in body, f"stage {stage!r} missing from §40.1"


def test_the_flow_is_documented_as_owning_no_second_workflow():
    flat = " ".join(S40.split())
    assert "owns no workflow of its own" in flat


# ---------------------------------------------------------------------------
# the guard itself
# ---------------------------------------------------------------------------
def test_the_parser_actually_reads_the_template():
    """A parser that silently returned [] would make every group/panel test
    vacuous — the failure mode that let `assert not bad` pass for a round."""
    assert len(GROUPS) >= 5
    assert len(PANELS) >= 15
    assert all(g["items"] for g in GROUPS)


def test_section_helper_is_scoped():
    """`section()` must not return the whole document; if it did, every
    assertion above would be answered by an unrelated paragraph."""
    assert len(S38) < len(TEXT) / 3
    assert "## 39." not in S38
    assert "## 40." not in S39


_WORDS = {2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven",
          8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve"}


def _word(n: int) -> str:
    return _WORDS.get(n, str(n))
