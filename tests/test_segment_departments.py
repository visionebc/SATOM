"""Guards for **one row per network**, departments as a list, unique names.

The defect these exist for leaves no trace. Two rows called
``LineP_External_LB`` -- one for WAF/LB, one for WSG, same CIDR -- made three
independent resolvers disagree about which row the name meant:

* ``line_profiles._segments_by_name`` used ``setdefault``      -> the FIRST
* ``spo_wizard``'s dict comprehension                          -> the LAST
* ``line_profiles.pool_for`` looped and returned on first match -> the FIRST

so a plan could describe one row's interface while allocating from the other
row's CIDR. Every value printed was a real value from a real row; nothing was
empty, nothing raised, nothing logged. The only way that surfaces is a policy
built on a network the line was never given.

Two changes close it, and both are needed:

**B** -- ``cidr``/``interface``/``gateway`` are properties of the NETWORK, so a
network shared by two departments is ONE row carrying both department names.
**C** -- ``save_segments`` refuses duplicate names, so the resolvers can never
be handed the ambiguity again.

Plus the structural half: there is now exactly ONE indexer
(``line_profiles.index_by_name``) and exactly ONE form parser
(``views._segments_form.parse_rows``), because two authors of one answer is
how they drifted in the first place.
"""
from __future__ import annotations

import ast
import json
import pathlib
import re

import pytest

from app.extensions import db
from app.models import Appliance
from app.models_lineprofile import LineProfile
from app.services import analysis
from app.services import classification_ops as ops
from app.services import line_profiles as lp
from app.services import settings_store as store
from app.services import spo_wizard as wiz
from app.views import _segments_form as segform

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _stored(app):
    """The raw blob as written, BEFORE segments() normalises it.

    Needed because the reader de-duplicates and drops blanks: a writer that
    emitted ["WSG", "WSG"] or ["", "WSG"] reads back clean, so asserting
    through segments() would let that bug through (it did — two mutations
    survived on exactly this).
    """
    return store.get_json(store.K_SEGMENTS, [])


def _seg(name, line="P", departments=(), cidr="192.0.2.0/24", **kw):
    row = {"name": name, "zone": "", "line": line,
           "departments": list(departments), "cidr": cidr,
           "interface": "port1", "gateway": "", "note": ""}
    row.update(kw)
    return row


# --------------------------------------------------------------------------- #
# 1. normalize_departments — the ONE reader, whatever shape arrives            #
# --------------------------------------------------------------------------- #
def test_a_list_is_kept_in_order():
    assert store.normalize_departments(["WAF/LB", "WSG"]) == ["WAF/LB", "WSG"]


def test_a_comma_string_is_split():
    assert store.normalize_departments(" WAF/LB , WSG ") == ["WAF/LB", "WSG"]


def test_a_legacy_single_value_becomes_a_one_item_list():
    """Every blob written before this change carries ONE string. It must read
    as that one department, not as nothing and not as a crash."""
    assert store.normalize_departments("WSG") == ["WSG"]


def test_junk_is_no_departments_and_never_an_exception():
    """A garbled row must not make the segments page unopenable — the operator
    cannot fix what they cannot open."""
    for junk in (None, 17, {"a": 1}, True):
        assert store.normalize_departments(junk) == []


def test_duplicates_are_dropped_case_insensitively_first_spelling_kept():
    """The same department typed twice is one department. Keeping both would
    print the badge twice and count it twice in usage()."""
    assert store.normalize_departments(["WSG", "wsg", "  WSG "]) == ["WSG"]


def test_blank_entries_are_dropped():
    assert store.normalize_departments(["", "  ", "WSG"]) == ["WSG"]


# --------------------------------------------------------------------------- #
# 2. the store round-trip, including the legacy shape                          #
# --------------------------------------------------------------------------- #
def test_a_legacy_blob_reads_as_the_current_shape(app):
    """Written before B, read after B. No migration flag, no era-aware reader:
    a consumer must never have to know which version wrote its data."""
    with app.app_context():
        store.set_json(store.K_SEGMENTS, [
            {"name": "old", "zone": "", "line": "P", "department": "WSG",
             "cidr": "192.0.2.0/24", "interface": "port1", "gateway": "",
             "note": ""}])
        seg = store.segments()[0]
        assert seg["departments"] == ["WSG"]
        assert "department" not in seg


def test_the_list_column_wins_when_a_row_carries_both(app):
    """A row written by the new page also keeps the old key when some other
    writer put one there. The current column is the answer; falling back to
    the stale scalar would silently drop the second department."""
    with app.app_context():
        store.set_json(store.K_SEGMENTS, [
            {"name": "both", "zone": "", "line": "P", "department": "WAF/LB",
             "departments": ["WAF/LB", "WSG"], "cidr": "192.0.2.0/24",
             "interface": "port1", "gateway": "", "note": ""}])
        assert store.segments()[0]["departments"] == ["WAF/LB", "WSG"]


def test_two_departments_on_one_network_is_one_row(app):
    with app.app_context():
        store.save_segments([_seg("shared", departments=["WAF/LB", "WSG"])])
        rows = store.segments()
        assert len(rows) == 1
        assert rows[0]["departments"] == ["WAF/LB", "WSG"]


# --------------------------------------------------------------------------- #
# 3. C — duplicate names are refused, and refusing writes NOTHING              #
# --------------------------------------------------------------------------- #
def test_saving_two_rows_with_one_name_is_refused(app):
    with app.app_context():
        with pytest.raises(store.SegmentError) as exc:
            store.save_segments([_seg("dup", departments=["WAF/LB"]),
                                 _seg("dup", departments=["WSG"])])
        assert "dup" in str(exc.value)


def test_a_refused_save_leaves_the_previous_list_untouched(app):
    """A rejected save is not a partial save. If the refusal wrote the good
    rows and dropped the rest, the operator would be looking at a list nobody
    asked for."""
    with app.app_context():
        store.save_segments([_seg("keep", departments=["WAF/LB"])])
        with pytest.raises(store.SegmentError):
            store.save_segments([_seg("a"), _seg("a")])
        assert [r["name"] for r in store.segments()] == ["keep"]


def test_the_refusal_names_every_duplicate_not_just_the_first(app):
    with app.app_context():
        with pytest.raises(store.SegmentError) as exc:
            store.save_segments([_seg("a"), _seg("a"), _seg("b"), _seg("b")])
        msg = str(exc.value)
        assert "'a'" in msg and "'b'" in msg


def test_case_differing_names_are_NOT_a_duplicate(app):
    """Deliberate. Every consumer keys on the exact string, so DMZ and dmz
    resolve deterministically and identically — rejecting the pair would
    invent a rule the system does not need and would lock an install that
    already has one out of its own segments page."""
    with app.app_context():
        store.save_segments([_seg("DMZ"), _seg("dmz")])
        assert [r["name"] for r in store.segments()] == ["DMZ", "dmz"]


def test_unnamed_rows_do_not_collide_with_each_other(app):
    """A row with a CIDR and no name is legal and cannot be referenced by a
    profile, so two of them are not the ambiguity this guard is about."""
    with app.app_context():
        store.save_segments([_seg("", cidr="192.0.2.0/24"),
                             _seg("", cidr="192.0.2.0/24")])
        assert len(store.segments()) == 2


def test_duplicate_segment_names_reports_a_hand_written_blob(app):
    """save_segments cannot be bypassed by the UI, but a blob restored from a
    backup or edited by hand can still hold duplicates — so the detector reads
    what is THERE, not what the writer promised."""
    with app.app_context():
        store.set_json(store.K_SEGMENTS, [_seg("x"), _seg("x"), _seg("y")])
        assert store.duplicate_segment_names() == ["x"]


# --------------------------------------------------------------------------- #
# 4. one indexer — the structural half                                         #
# --------------------------------------------------------------------------- #
def test_index_by_name_is_the_only_indexer_in_the_wizard():
    """AST, not a grep for a name: the wizard must not rebuild its own
    name -> row map from the plan's segments. That comprehension is the
    resolver that disagreed with the other two."""
    tree = ast.parse((ROOT / "app/services/spo_wizard.py").read_text())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "build_plan")
    comps = [n for n in ast.walk(fn) if isinstance(n, ast.DictComp)]
    for comp in comps:
        # A dict comprehension keyed on a segment's NAME is the banned shape.
        key_src = ast.dump(comp.key)
        assert "'name'" not in key_src, (
            "build_plan indexes segments by name itself; it must call "
            "line_profiles.index_by_name")


def test_pool_for_and_the_declared_resolver_share_the_indexer():
    src = (ROOT / "app/services/line_profiles.py").read_text()
    tree = ast.parse(src)
    for name in ("_segments_by_name", "pool_for"):
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == name)
        calls = [n.func.id for n in ast.walk(fn)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
        assert "index_by_name" in calls, f"{name} does not use the indexer"


def test_the_indexer_keeps_the_first_row(app):
    """Documented, not incidental: line_plan REFUSES a duplicated name, so
    this branch is only ever reached for data written before the guard."""
    out = lp.index_by_name([_seg("a", cidr="192.0.2.0/24"),
                            _seg("a", cidr="192.0.2.0/24")])
    assert out["a"]["cidr"] == "192.0.2.0/24"


# --------------------------------------------------------------------------- #
# 5. line_plan refuses an ambiguous name                                       #
# --------------------------------------------------------------------------- #
def test_a_duplicated_name_blocks_the_plan(app):
    with app.app_context():
        store.save_classification("lines", ["P"])
        store.set_json(store.K_SEGMENTS, [_seg("dup"), _seg("dup")])
        plan = lp.line_plan("P")
        assert lp.P_DUPLICATE_SEGMENT in plan.problem_codes()
        assert plan.blocked, "an ambiguous segment name must STOP the run"


def test_the_duplicate_is_reported_once_not_once_per_row(app):
    with app.app_context():
        store.save_classification("lines", ["P"])
        store.set_json(store.K_SEGMENTS, [_seg("dup"), _seg("dup"), _seg("dup")])
        codes = lp.line_plan("P").problem_codes()
        assert codes.count(lp.P_DUPLICATE_SEGMENT) == 1


def test_a_duplicate_on_another_line_does_not_block_this_one(app):
    """Scoped to the names this plan actually uses. Blocking every line
    because some unrelated pair collides would make the guard something an
    operator learns to route around."""
    with app.app_context():
        store.save_classification("lines", ["P", "Q"])
        store.set_json(store.K_SEGMENTS, [
            _seg("mine", line="P"),
            _seg("theirs", line="Q"), _seg("theirs", line="Q")])
        assert lp.P_DUPLICATE_SEGMENT not in lp.line_plan("P").problem_codes()
        assert lp.P_DUPLICATE_SEGMENT in lp.line_plan("Q").problem_codes()


def test_duplicate_segment_is_in_the_blocking_set():
    """Membership is data, so a caller cannot invent its own idea of serious."""
    assert lp.P_DUPLICATE_SEGMENT in lp.BLOCKING


# --------------------------------------------------------------------------- #
# 6. the wizard — a shared network appears ONCE, with its departments          #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def wenv(app, monkeypatch):
    with app.app_context():
        store.save_classification("lines", ["P"])
        store.save_classification("departments", ["WAF/LB", "WSG"])
        store.save_segments([
            _seg("shared", departments=["WAF/LB", "WSG"], cidr="198.51.100.0/24"),
            _seg("wsg-only", departments=["WSG"], cidr="10.30.20.0/22"),
            _seg("waf-only", departments=["WAF/LB"], cidr="192.0.2.0/24"),
        ])
        appl = Appliance(name="fwb-a", kind="fortiweb", host="192.0.2.13",
                         port=443, username="admin", password_enc="",
                         verify_ssl=False)
        db.session.add(appl)
        db.session.commit()
        monkeypatch.setattr(type(appl), "build_client",
                            lambda self, **kw: _Client())
        yield appl.id


class _Client:
    def cmdb_names(self, endpoint):
        return []


def _plan(app, appl_id, **kw):
    base = dict(line="P", web_address="shop.example.com")
    base.update(kw)
    with app.app_context():
        return wiz.build_plan(db.session.get(Appliance, appl_id), **base)


def _codes(plan):
    return [b.code for b in plan.blockers]


def test_a_shared_network_is_one_option_carrying_both_departments(app, wenv):
    plan = _plan(app, wenv, segment_name="shared")
    assert plan.segment["name"] == "shared"
    assert plan.as_dict()["segment_departments"] == ["WAF/LB", "WSG"]


def test_the_department_narrows_the_choice(app, wenv):
    """Three segments on the line, one of them WAF/LB-only: filtering to WSG
    leaves two, so the wizard still asks — it does not pick."""
    plan = _plan(app, wenv, department="WSG")
    assert "segment_not_chosen" in _codes(plan)
    plan = _plan(app, wenv, department="WAF/LB", segment_name="waf-only")
    assert plan.segment["name"] == "waf-only"


def test_a_department_served_by_exactly_one_segment_auto_picks_it(app, wenv):
    with app.app_context():
        store.save_segments([
            _seg("shared", departments=["WAF/LB", "WSG"], cidr="198.51.100.0/24"),
            _seg("waf-only", departments=["WAF/LB"], cidr="192.0.2.0/24"),
        ])
    plan = _plan(app, wenv, department="WSG")
    assert plan.segment["name"] == "shared"


def test_choosing_a_segment_outside_the_department_is_REFUSED(app, wenv):
    """Server-side, not a page overlay. The browser can post any segment on
    the line; if only the page filtered, the operator would believe the
    department constrained a choice the server never checked."""
    plan = _plan(app, wenv, department="WSG", segment_name="waf-only")
    assert "segment_not_in_department" in _codes(plan)
    assert not plan.ok


def test_that_refusal_is_distinct_from_not_being_on_the_line(app, wenv):
    """Different facts, different fixes: one means 'add it to the line', the
    other means 'add the department to the row'. Asserted in BOTH directions —
    a guard that only checked the first case passed happily while the second
    branch reported the wrong code, which is the tenth time an assertion here
    has claimed more than it checked."""
    off_line = _codes(_plan(app, wenv, department="WSG", segment_name="nope"))
    assert "segment_not_on_line" in off_line
    assert "segment_not_in_department" not in off_line

    wrong_dept = _codes(_plan(app, wenv, department="WSG",
                              segment_name="waf-only"))
    assert "segment_not_in_department" in wrong_dept
    assert "segment_not_on_line" not in wrong_dept


def test_a_department_no_segment_serves_is_refused(app, wenv):
    plan = _plan(app, wenv, department="Finance")
    assert "department_not_on_line" in _codes(plan)


def test_no_department_means_no_narrowing(app, wenv):
    plan = _plan(app, wenv, segment_name="waf-only")
    assert plan.ok or "segment_not_in_department" not in _codes(plan)
    assert plan.segment["name"] == "waf-only"


def test_the_department_never_reaches_the_object_names(app, wenv):
    """It narrows a choice; it names nothing. A control that silently fed the
    naming scheme would change what gets built on the device without saying
    so anywhere on the page."""
    a = _plan(app, wenv, department="WAF/LB", segment_name="shared").names
    b = _plan(app, wenv, department="WSG", segment_name="shared").names
    assert a == b and a


def test_the_chosen_department_is_carried_in_the_plan(app, wenv):
    """Provenance: the report and the audit line say which department the
    operator was building for."""
    plan = _plan(app, wenv, department="WSG", segment_name="shared")
    assert plan.as_dict()["department"] == "WSG"


# --------------------------------------------------------------------------- #
# 7. the other consumers of the column                                         #
# --------------------------------------------------------------------------- #
def test_usage_counts_a_shared_network_for_every_department(app):
    """Counting the list as one scalar would report BOTH departments as
    unused by any segment — and unregistered() would then hide a live
    reference, which is the whole job of that page."""
    with app.app_context():
        store.save_classification("departments", ["WAF/LB", "WSG"])
        store.save_segments([_seg("shared", departments=["WAF/LB", "WSG"])])
        u = ops.usage("departments")
        assert u["WAF/LB"].segments == 1
        assert u["WSG"].segments == 1


def test_analysis_keeps_a_shared_network_in_both_department_views(app):
    with app.app_context():
        store.save_segments([_seg("shared", departments=["WAF/LB", "WSG"])])
        for want in ("WAF/LB", "WSG"):
            rows = analysis._segments_block({"department": want})["rows"]
            assert [r["name"] for r in rows] == ["shared"]


def test_analysis_prints_every_department_not_the_first(app):
    with app.app_context():
        store.save_segments([_seg("shared", departments=["WAF/LB", "WSG"])])
        row = analysis._segments_block({})["rows"][0]
        assert row["departments"] == ["WAF/LB", "WSG"]
        assert row["department"] == "WAF/LB, WSG"


def test_renaming_a_department_moves_it_inside_the_list(app):
    with app.app_context():
        store.save_classification("departments", ["WAF/LB", "WSG"])
        store.save_segments([_seg("shared", departments=["WAF/LB", "WSG"])])
        ops.apply_rows("departments", [
            ops.Row(orig="WAF/LB", value="Edge"),
            ops.Row(orig="WSG", value="WSG")])
        assert store.segments()[0]["departments"] == ["Edge", "WSG"]


def test_absorbing_into_a_name_the_row_already_has_does_not_duplicate_it(app):
    """Reached by deleting WAF/LB and reassigning its references to WSG — a
    rename onto an existing catalog value is refused one layer up. The row
    already serves WSG, so the absorb must leave ONE entry, not two."""
    with app.app_context():
        store.save_classification("departments", ["WAF/LB", "WSG"])
        store.save_segments([_seg("shared", departments=["WAF/LB", "WSG"])])
        ops.apply_rows("departments", [
            ops.Row(orig="WAF/LB", value="WAF/LB", action="delete",
                    reassign="WSG", decided=True),
            ops.Row(orig="WSG", value="WSG")])
        # Asserted on the STORED blob: segments() normalises on the way out, so
        # reading through it would hide a writer that left ["WSG", "WSG"].
        assert _stored(app)[0]["departments"] == ["WSG"]


def test_clearing_a_department_removes_the_entry_not_blanks_it(app):
    """An empty string left in the list renders as a blank badge and counts as
    a department in usage() — a value nobody named."""
    with app.app_context():
        store.save_classification("departments", ["WAF/LB", "WSG"])
        store.save_segments([_seg("shared", departments=["WAF/LB", "WSG"])])
        ops.apply_rows("departments", [
            ops.Row(orig="WAF/LB", value="WAF/LB", action="delete",
                    reassign="", decided=True),
            ops.Row(orig="WSG", value="WSG")])
        # Stored blob again: the reader drops blanks, so an empty string left
        # behind by _retarget would be invisible through segments().
        assert _stored(app)[0]["departments"] == ["WSG"]


# --------------------------------------------------------------------------- #
# 8. one form parser                                                           #
# --------------------------------------------------------------------------- #
class _Form(dict):
    def getlist(self, key):
        return list(self.get(key, []))


def test_the_form_decodes_the_json_the_page_posts():
    form = _Form({"seg_name[]": ["a"], "seg_cidr[]": ["192.0.2.0/24"],
                  "seg_departments[]": [json.dumps(["WAF/LB", "WSG"])]})
    rows, bad = segform.parse_rows(form)
    assert bad == [] and rows[0]["departments"] == ["WAF/LB", "WSG"]


def test_a_department_containing_a_comma_survives_the_round_trip():
    """Which is why the page posts JSON and not a comma list."""
    form = _Form({"seg_name[]": ["a"], "seg_cidr[]": ["192.0.2.0/24"],
                  "seg_departments[]": [json.dumps(["Legal, EU"])]})
    rows, _ = segform.parse_rows(form)
    assert rows[0]["departments"] == ["Legal, EU"]


def test_a_plain_comma_string_still_works():
    """A hand-built POST, or a stale cached copy of the page."""
    form = _Form({"seg_name[]": ["a"], "seg_cidr[]": ["192.0.2.0/24"],
                  "seg_departments[]": ["WAF/LB, WSG"]})
    rows, _ = segform.parse_rows(form)
    assert rows[0]["departments"] == ["WAF/LB", "WSG"]


def test_the_legacy_single_field_is_still_accepted():
    form = _Form({"seg_name[]": ["a"], "seg_cidr[]": ["192.0.2.0/24"],
                  "seg_department[]": ["WSG"]})
    rows, _ = segform.parse_rows(form)
    assert rows[0]["departments"] == ["WSG"]


def test_an_invalid_cidr_is_reported_and_the_row_dropped():
    form = _Form({"seg_name[]": ["a", "b"],
                  "seg_cidr[]": ["nonsense", "192.0.2.0/24"],
                  "seg_departments[]": ["[]", "[]"]})
    rows, bad = segform.parse_rows(form)
    assert bad == ["nonsense"] and [r["name"] for r in rows] == ["b"]


def test_neither_view_parses_the_form_itself():
    """AST. Two copies of this loop is how the two pages drifted; the guard
    is that neither view walks seg_* fields on its own any more."""
    for rel in ("app/views/segments.py", "app/views/settings.py"):
        tree = ast.parse((ROOT / rel).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert not node.value.startswith("seg_"), (
                    f"{rel} still names the form field {node.value!r} — it "
                    "must call _segments_form.parse_rows")


# --------------------------------------------------------------------------- #
# 9. the pages actually render it                                              #
# --------------------------------------------------------------------------- #
def _login_admin(app, client):
    from app.models import User
    with app.app_context():
        uid = User.query.filter_by(username="admin").first().id
    with client.session_transaction() as sess:
        sess["_user_id"] = str(uid)
        sess["_fresh"] = True
        sess["product"] = "fortiweb"
    return uid


def test_the_segments_page_renders_the_multi_select_and_the_hidden_field(app, client):
    with app.app_context():
        store.save_classification("departments", ["WAF/LB", "WSG"])
        store.save_segments([_seg("shared", departments=["WAF/LB", "WSG"])])
    _login_admin(app, client)
    html = client.get("/segments/").get_data(as_text=True)
    assert 'name="seg_departments[]"' in html
    assert 'data-js="seg-depts"' in html
    # BOTH departments selected on the one row — the whole point of B.
    assert html.count('selected') >= 2
    assert 'name="seg_department[]"' not in html, "the single-value cell is gone"


def test_posting_duplicate_names_to_the_page_writes_nothing(app, client):
    """End to end: the refusal has to reach the operator as a message, not as
    a 500 and not as a save that quietly dropped one row."""
    with app.app_context():
        store.save_segments([_seg("keep", departments=["WAF/LB"])])
    _login_admin(app, client)
    resp = client.post("/segments/save", data={
        "seg_name[]": ["dup", "dup"],
        "seg_cidr[]": ["192.0.2.0/24", "192.0.2.0/24"],
        "seg_departments[]": ['["WAF/LB"]', '["WSG"]'],
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert "dup" in resp.get_data(as_text=True)
    with app.app_context():
        assert [r["name"] for r in store.segments()] == ["keep"]


def test_the_wizard_page_puts_the_departments_on_the_option(app, wenv, client):
    _login_admin(app, client)
    html = client.get(f"/web/workspace/{wenv}/spo-wizard").get_data(as_text=True)
    assert 'id="w-department"' in html
    assert "departmentsFor" in html and "refreshSegments" in html
    # the payload carries the list, so the page can label the options
    assert '"departments"' in html


def test_the_wizard_script_still_carries_the_csp_nonce(app, wenv, client):
    """Asserted against the nonce the RESPONSE served, not the template text:
    a template that writes the attribute while the header stops naming a
    nonce is the same dead page (§134)."""
    _login_admin(app, client)
    resp = client.get(f"/web/workspace/{wenv}/spo-wizard")
    html = resp.get_data(as_text=True)
    csp = resp.headers.get("Content-Security-Policy", "")
    # THIS page's own block, found by its content — base.html also ships a
    # nonce'd script, so taking the first one would keep passing while the
    # wizard's own block was the dead one (§134, all over again).
    blocks = re.findall(r"<script([^>]*)>(.*?)</script>", html, re.S)
    ours = [attrs for attrs, bodytext in blocks if "const PLANS" in bodytext]
    assert ours, "the wizard's own script block is gone"
    match = re.search(r'nonce="([^"]+)"', ours[0])
    assert match, "the wizard's script block carries no nonce"
    assert f"'nonce-{match.group(1)}'" in csp
