"""Guards for line profiles — the declaration that replaces a string match.

The defect being prevented is not a crash. Before this, "which networks does
this line receive?" was answered by matching ``line`` against
``segments[].line``, and a segment typed differently simply stopped matching.
The consumer saw a line with no networks, which is indistinguishable from a
line that legitimately has none — and once that answer chooses the network a
production server policy is built on, the policy is created perfectly, on the
wrong segment, with nothing raised.

So the properties guarded here are all about **the difference between an
answer and a guess staying visible**.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

from app.extensions import db
from app.models import Template
from app.models_lineprofile import LineProfile
from app.services import classification_ops as ops
from app.services import line_profiles as lp
from app.services import settings_store as store

ROOT = pathlib.Path(__file__).resolve().parents[1]

_SEGMENTS = [
    {"name": "dmz-web", "zone": "dmz", "line": "retail", "department": "",
     "cidr": "198.51.100.0/24", "interface": "port3", "gateway": "198.51.100.1",
     "note": ""},
    {"name": "core-app", "zone": "internal", "line": "retail",
     "department": "", "cidr": "192.0.2.0/24", "interface": "port4",
     "gateway": "192.0.2.1", "note": ""},
    {"name": "lab-only", "zone": "lab", "line": "lab", "department": "",
     "cidr": "", "interface": "port9", "gateway": "", "note": ""},
]


@pytest.fixture()
def catalog(app):
    with app.app_context():
        store.save_classification("lines", ["retail", "wholesale", "lab"])
        store.save_segments([dict(s) for s in _SEGMENTS])
        yield


def _tpl(app, name="wpp-retail", status=Template.STATUS_APPROVED,
         product="fortiweb", kind=Template.KIND_WEB_PROTECTION):
    with app.app_context():
        t = Template(kind=kind, name=name, version=1, body="{}",
                     product=product, status=status)
        db.session.add(t)
        db.session.commit()
        return t.id


def _profile(app, line="retail", segments=("dmz-web",), cert="server",
             wpp=None, pool="", product="fortiweb"):
    with app.app_context():
        p = LineProfile(product=product, line=line, cert_class=cert,
                        wpp_template_id=wpp, ipam_pool=pool)
        p.set_segments(list(segments))
        db.session.add(p)
        db.session.commit()
        return p.id


# ---------------------------------------------------------------------------
# 1. declared vs inferred is never blurred
# ---------------------------------------------------------------------------
def test_a_line_with_no_profile_is_labelled_inferred(app, catalog):
    with app.app_context():
        plan = lp.line_plan("retail")
    assert plan.source == "inferred" and plan.declared is False
    # the old string match still works — it is the LABEL that is new
    assert {s["name"] for s in plan.segments} == {"dmz-web", "core-app"}


def test_a_declared_line_ignores_the_string_match(app, catalog):
    """The declaration is the answer, not a hint added to the guess.

    ``core-app`` also carries line="retail", so a plan that merged the two
    sources would return two segments — and the operator who deliberately
    excluded one would get it back without being told.
    """
    _profile(app, segments=("dmz-web",))
    with app.app_context():
        plan = lp.line_plan("retail")
    assert plan.source == "declared"
    assert [s["name"] for s in plan.segments] == ["dmz-web"]


def test_a_broken_declaration_is_a_problem_not_a_shorter_list(app, catalog):
    """This is the whole reason the table exists.

    A profile naming a segment that has since been renamed must SAY so. A plan
    that silently returned one segment instead of two is exactly the
    invisible-drift failure the string match had.
    """
    _profile(app, segments=("dmz-web", "gone-away"))
    with app.app_context():
        plan = lp.line_plan("retail")
    assert lp.P_MISSING_SEGMENT in plan.problem_codes()
    assert plan.blocked is True
    assert [s["name"] for s in plan.segments] == ["dmz-web"]


def test_a_declaration_that_resolves_to_nothing_stays_declared(app, catalog):
    """No falling back to the guess when the declaration fails.

    Falling back would hide the breakage behind an answer that looks fine —
    and the answer would be the one the operator overrode.
    """
    _profile(app, segments=("gone-away",))
    with app.app_context():
        plan = lp.line_plan("retail")
    assert plan.source == "declared"
    assert plan.segments == []
    assert lp.P_MISSING_SEGMENT in plan.problem_codes()


def test_a_line_with_no_segments_at_all_says_so(app, catalog):
    with app.app_context():
        plan = lp.line_plan("wholesale")
    assert lp.P_NO_SEGMENTS in plan.problem_codes() and plan.blocked


def test_an_unknown_line_is_not_a_silent_empty_plan(app, catalog):
    with app.app_context():
        plan = lp.line_plan("")
    assert plan.problem_codes() == [lp.P_NO_SEGMENTS]


# ---------------------------------------------------------------------------
# 2. the WPP template — approval is checked when it is USED
# ---------------------------------------------------------------------------
def test_an_approved_template_resolves(app, catalog):
    tid = _tpl(app)
    _profile(app, wpp=tid)
    with app.app_context():
        plan = lp.line_plan("retail")
    assert plan.wpp_template_id == tid and plan.wpp_template_name == "wpp-retail"
    assert lp.P_WPP_NOT_APPROVED not in plan.problem_codes()


def test_a_pending_template_blocks(app, catalog):
    """Approval is re-checked at plan time, not frozen when the profile was
    saved: a template approved on Monday and rejected on Tuesday must stop
    being instantiable on Tuesday."""
    tid = _tpl(app, status=Template.STATUS_PENDING)
    _profile(app, wpp=tid)
    with app.app_context():
        plan = lp.line_plan("retail")
    assert lp.P_WPP_NOT_APPROVED in plan.problem_codes() and plan.blocked


def test_a_deleted_template_is_named_not_ignored(app, catalog):
    _profile(app, wpp=4242)
    with app.app_context():
        plan = lp.line_plan("retail")
    assert lp.P_WPP_GONE in plan.problem_codes() and plan.blocked
    assert "4242" in " ".join(p.detail for p in plan.problems)


def test_a_template_from_another_product_blocks(app, catalog):
    tid = _tpl(app, product="fortiadc")
    _profile(app, wpp=tid)
    with app.app_context():
        plan = lp.line_plan("retail", product="fortiweb")
    assert lp.P_WPP_WRONG_PRODUCT in plan.problem_codes() and plan.blocked


def test_no_template_named_is_a_problem_but_not_blocking(app, catalog):
    _profile(app, wpp=None)
    with app.app_context():
        plan = lp.line_plan("retail")
    assert lp.P_NO_WPP in plan.problem_codes()
    assert lp.P_NO_WPP not in lp.BLOCKING


# ---------------------------------------------------------------------------
# 3. cert class: blank is NOT DECIDED, never a default
# ---------------------------------------------------------------------------
def test_a_blank_cert_class_is_reported_not_defaulted(app, catalog):
    _profile(app, cert="")
    with app.app_context():
        plan = lp.line_plan("retail")
    assert plan.cert_class == ""
    assert lp.P_NO_CERT_CLASS in plan.problem_codes()
    # 'server' would be a plausible guess; guessing a certificate class is how
    # a client-auth line gets a server-only certificate.
    assert plan.cert_class != "server"


# ---------------------------------------------------------------------------
# 4. the pool: explicit override, else the segment, else ASK
# ---------------------------------------------------------------------------
def test_pool_comes_from_the_segment_by_default(app, catalog):
    _profile(app, segments=("dmz-web",))
    with app.app_context():
        assert lp.pool_for(lp.line_plan("retail")) == "198.51.100.0/24"


def test_an_explicit_pool_wins(app, catalog):
    _profile(app, segments=("dmz-web",), pool="10.99.0.0/22")
    with app.app_context():
        assert lp.pool_for(lp.line_plan("retail")) == "10.99.0.0/22"


def test_a_segment_without_a_cidr_yields_no_pool_and_says_why(app, catalog):
    """Empty means ASK. The provider's configured default is a FLEET-wide
    pool, and reaching for it silently puts a policy on a network this line
    was never given."""
    _profile(app, line="lab", segments=("lab-only",))
    with app.app_context():
        plan = lp.line_plan("lab")
        assert lp.pool_for(plan) == ""
        assert lp.P_SEGMENT_NO_CIDR in plan.problem_codes()


def test_a_plan_with_no_segments_at_all_yields_no_pool(app, catalog):
    """The end of ``pool_for`` must be "" and nothing else.

    A fleet-wide default reached silently here puts a policy on a network the
    line was never given. (The first version of this file only covered a
    segment with a blank CIDR, which returns from inside the loop — so a
    mutation planting a default at the end was unreachable and survived.)
    """
    with app.app_context():
        plan = lp.line_plan("wholesale")       # catalog line, zero segments
        assert plan.segments == []
        assert lp.pool_for(plan) == ""
        assert lp.pool_for(plan, "anything") == ""


def test_pool_for_can_be_asked_about_one_segment(app, catalog):
    _profile(app, segments=("dmz-web", "core-app"))
    with app.app_context():
        plan = lp.line_plan("retail")
        assert lp.pool_for(plan, "core-app") == "192.0.2.0/24"


# ---------------------------------------------------------------------------
# 5. product scope
# ---------------------------------------------------------------------------
def test_a_profile_does_not_leak_across_products(app, catalog):
    _profile(app, product="fortiadc")
    with app.app_context():
        assert lp.line_plan("retail", product="fortiweb").source == "inferred"
        assert lp.line_plan("retail", product="fortiadc").source == "declared"


# ---------------------------------------------------------------------------
# 6. a profile is a REFERENCE — classification must move it and count it
# ---------------------------------------------------------------------------
def test_a_profile_counts_as_usage_of_its_line(app, catalog):
    _profile(app)
    with app.app_context():
        u = ops.usage("lines")["retail"]
        assert u.line_profiles == 1
        assert u.total >= 1
        assert u.as_dict()["line_profiles"] == 1


def test_renaming_a_line_carries_its_profile(app, catalog):
    """An orphaned profile does not error — the line silently reverts to the
    guess, which is the behaviour this feature replaced, restored without
    anybody choosing it."""
    _profile(app, segments=("dmz-web",))
    with app.app_context():
        rows = [ops.Row(orig="retail", value="Retail", action="keep"),
                ops.Row(orig="wholesale", value="wholesale", action="keep"),
                ops.Row(orig="lab", value="lab", action="keep")]
        rep = ops.apply_rows("lines", rows)
        assert rep.line_profiles == 1
        assert lp.profile_for("retail") is None
        moved = lp.profile_for("Retail")
        assert moved is not None and moved.segments() == ["dmz-web"]


def test_deleting_a_line_and_clearing_removes_its_profile(app, catalog):
    _profile(app)
    with app.app_context():
        rows = [ops.Row(orig="retail", value="", action="delete",
                        reassign="", decided=True),
                ops.Row(orig="wholesale", value="wholesale", action="keep"),
                ops.Row(orig="lab", value="lab", action="keep")]
        rep = ops.apply_rows("lines", rows)
        assert rep.line_profiles_deleted == 1
        assert LineProfile.query.count() == 0


def test_reassigning_onto_a_line_that_already_has_a_profile_is_refused(app,
                                                                      catalog):
    """(product, line) is unique, so one of the two would have to go. Picking
    silently means a line quietly starts handing out a different set of
    networks.

    Reached through DELETE-WITH-REASSIGN, not through a rename: a rename onto
    an existing catalog value is refused earlier as a duplicate value, so the
    collision branch is only reachable this way. (My first version of this
    test aimed at the rename and passed on the duplicate-value error instead —
    an assertion satisfied by the wrong mechanism.)
    """
    _profile(app, line="retail", segments=("dmz-web",))
    _profile(app, line="wholesale", segments=("core-app",))
    with app.app_context():
        rows = [ops.Row(orig="retail", value="", action="delete",
                        reassign="wholesale", decided=True),
                ops.Row(orig="wholesale", value="wholesale", action="keep"),
                ops.Row(orig="lab", value="lab", action="keep")]
        with pytest.raises(ops.ClassificationError) as exc:
            ops.apply_rows("lines", rows)
        assert "profile" in str(exc.value).lower()
        # and NOTHING moved — the refusal is before any write lands
        db.session.rollback()
        assert lp.profile_for("retail").segments() == ["dmz-web"]
        assert lp.profile_for("wholesale").segments() == ["core-app"]


# ---------------------------------------------------------------------------
# 7. ONE author. Nothing else may re-derive the line -> segments answer.
# ---------------------------------------------------------------------------
#: Every module allowed to read the raw segment list. Anything else that wants
#: to know what a line receives must go through ``line_plan``.
#:
#: An ALLOWLIST rather than a pattern, deliberately. My first version of this
#: guard looked for "a Compare on a subscript keyed 'line'" and flagged
#: ``views/provisioning.py`` and ``services/analysis.py``, which compare a
#: FILTER dict's line — nothing to do with segments. That is the third guard
#: in this repo to assert the wrong layer; the allowlist cannot make that
#: mistake, and adding a name to it is a review moment, which is the whole
#: value.
#: Each entry carries WHY it is allowed. "It was already there" is not a
#: reason; every one of these was read before being listed.
_SEGMENT_READERS = {
    # owns and edits the blob
    "app/services/settings_store.py": "owns the stored list",
    "app/views/segments.py": "the editor for the list itself",
    # the author of the line -> segments answer, and the module that keeps
    # references to classification values pointing at the right strings
    "app/services/line_profiles.py": "THE author",
    "app/services/classification_ops.py": "retargets references on rename",
    "app/views/line_profiles.py": "renders the picker and validates a save "
                                  "against the live names",
    # display-only readers: they show segments, they never answer "what does
    # this line receive"
    "app/views/settings.py": "renders the whole list read-only",
    "app/views/bookmarks.py": "labels a bookmark with its segment",
    "app/services/adom_assets.py": "labels a device row with its "
                                   "segment through bookmarks."
                                   "dimension_value; never asks what a "
                                   "line receives",
    # A REPORT facet, and deliberately NOT the same question: it filters on
    # zone/line/department together and treats a BLANK facet on a segment as
    # "any", which line_plan does not do. Routing it through line_plan would
    # change what the report counts.
    "app/services/analysis.py": "report facet with blank-means-any semantics",
}


def test_only_one_module_derives_what_a_line_receives():
    """§127 in a new place: several sites re-deriving one verdict.

    A second consumer reading ``store.segments()`` and filtering it by line is
    a second author of "what does this line get?", and the two will drift —
    silently, because both answers look like answers.
    """
    offenders = []
    for path in (ROOT / "app").rglob("*.py"):
        rel = str(path.relative_to(ROOT))
        if rel in _SEGMENT_READERS:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "segments"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in ("store", "settings_store")):
                offenders.append(f"{rel}:{node.lineno}")
    assert offenders == [], (
        "these read the raw segment list instead of calling "
        f"line_profiles.line_plan: {offenders}")


def test_blocking_is_data_not_a_caller_opinion():
    """A caller deciding for itself which problems are serious is how two
    callers come to disagree about the same plan."""
    assert isinstance(lp.BLOCKING, frozenset)
    assert lp.P_MISSING_SEGMENT in lp.BLOCKING
    assert lp.P_NO_CERT_CLASS not in lp.BLOCKING
    for p in (lp.P_NO_SEGMENTS, lp.P_WPP_GONE, lp.P_WPP_NOT_APPROVED,
              lp.P_WPP_WRONG_PRODUCT):
        assert p in lp.BLOCKING


# ---------------------------------------------------------------------------
# 8. the model
# ---------------------------------------------------------------------------
def test_segments_are_stored_by_name_not_by_index(app):
    """The segments list is a JSON blob rewritten whole on every edit, so an
    index means a different segment tomorrow."""
    with app.app_context():
        p = LineProfile(product="fortiweb", line="x")
        p.set_segments(["b", "a", "b", "  ", "a"])
        # Asserted on the STORED blob, not on segments(): the reader dedupes
        # too (defensively, for rows written by hand), so a reader-only check
        # passes against a writer that stores duplicates. A mutation removing
        # the writer's dedup survived exactly that.
        import json as _j
        assert _j.loads(p.segment_names) == ["b", "a"]
        assert p.segments() == ["b", "a"]        # order kept, dupes dropped
        assert all(isinstance(n, str) for n in p.segments())


def test_a_corrupt_segment_blob_reads_as_empty_not_as_a_crash(app):
    with app.app_context():
        p = LineProfile(product="fortiweb", line="x", segment_names="{nope")
        assert p.segments() == []


def test_one_profile_per_product_and_line(app):
    from sqlalchemy.exc import IntegrityError
    with app.app_context():
        db.session.add(LineProfile(product="fortiweb", line="dup"))
        db.session.commit()
        db.session.add(LineProfile(product="fortiweb", line="dup"))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


# ---------------------------------------------------------------------------
# 9. the page
# ---------------------------------------------------------------------------
def test_the_page_is_admin_only(app, client):
    from conftest import login, make_user
    uid = make_user(app, username="ro", role="readonly")
    login(client, uid)
    r = client.get("/web/line-profiles/")
    assert r.status_code in (302, 403)


def test_the_page_renders_and_labels_the_source(app, client, catalog):
    from conftest import admin_user_id, login
    _profile(app, line="retail", segments=("dmz-web",))
    login(client, admin_user_id(app))
    r = client.get("/web/line-profiles/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "declared" in body and "inferred" in body
    assert "dmz-web" in body


def test_the_page_is_not_dark_themed():
    """SATOM is a light product (§9m). The fleet glassmorphism renders here as
    an opaque grey slab on white."""
    body = (ROOT / "app/templates/lineprofiles/index.html").read_text()
    import re
    body = re.sub(r"\{#.*?#\}", "", body, flags=re.S)   # the comment SAYS these
    for bad in ("backdrop-filter", "rgba(30,41,59", "#080d1a", "#8b5cf6"):
        assert bad not in body, f"{bad} is fleet dark-theme chrome"


def test_saving_an_unknown_segment_is_refused_not_dropped(app, client, catalog):
    from conftest import admin_user_id, login
    login(client, admin_user_id(app))
    r = client.post("/web/line-profiles/save",
                    data={"line": "retail", "segments": ["dmz-web", "nope"],
                          "cert_class": "server"},
                    follow_redirects=True)
    assert r.status_code == 200
    with app.app_context():
        assert lp.profile_for("retail") is None   # nothing was written
    assert "nope" in r.get_data(as_text=True)


def test_saving_a_line_outside_the_catalog_is_refused(app, client, catalog):
    from conftest import admin_user_id, login
    login(client, admin_user_id(app))
    client.post("/web/line-profiles/save",
                data={"line": "not-a-line", "segments": []},
                follow_redirects=True)
    with app.app_context():
        assert LineProfile.query.count() == 0


def test_deleting_says_what_the_line_falls_back_to(app, client, catalog):
    from conftest import admin_user_id, login
    _profile(app, line="retail")
    login(client, admin_user_id(app))
    r = client.post("/web/line-profiles/delete", data={"line": "retail"},
                    follow_redirects=True)
    body = r.get_data(as_text=True)
    # The page's own header prose contains the word "guess", so matching on it
    # alone passes against a flash that says nothing. Match the SENTENCE only
    # the delete handler can produce.
    assert "falls back to matching segments by name" in body
    with app.app_context():
        assert lp.profile_for("retail") is None
