"""Transport provenance: which pages may say a catalog entry is *API only*.

Three pages list catalog entries — the API hub's menu tree, the firmware-line
comparison and the object Structure cross-reference — and all three were asked
the same question. The danger is not that the badge breaks loudly; it is that
it prints a confident, precise, WRONG word over a row somebody then acts on.
Every guard below fixes one way it could:

* with NO dump, :func:`compare` still returns a full result and **every**
  catalog entry lands in ``no_block`` — rendered naively that reads *"the CLI
  has none of this"*, which is the opposite of what absent evidence means. So
  an unmeasured product answers ``unknown`` and nothing else (except
  ``monitor_only``, which follows from the URN and not from evidence);
* a dump belongs to ONE firmware line, so the line filter on the comparison
  page must be a FILTER and never a fallback — answering about 8.0 with a 7.6
  capture would look exactly like a confident answer;
* the vocabulary must have one author, or the three pages disagree about what a
  word means — the ``api.js`` / ``main.js`` status-badge split all over again;
* ``unknown`` must not look like ``no_block``: those two are the pair the whole
  design exists to keep apart, so ``unknown`` gets no badge at all.

Targeted suite: nothing here touches the network or an appliance.
"""
from __future__ import annotations

import ast
import io
import pathlib
import re
import tokenize

import pytest

from tests.conftest import admin_user_id, login, make_user, profile_id
from tests.test_cli_coverage import FW_DUMP, _seed_dump

REPO = pathlib.Path(__file__).resolve().parents[1]
PARTIAL = REPO / "app" / "templates" / "partials" / "_cli_provenance.html"
SERVICE = REPO / "app" / "services" / "cli_coverage.py"

#: The pages that CONSUME the badge. None of them may spell the vocabulary.
CONSUMERS = (
    "app/templates/api_explorer/index.html",
    "app/templates/adc_api/index.html",
    "app/templates/registry/versions.html",
    "app/templates/structure/index.html",
)


def _macro_src() -> str:
    """The partial with Jinja comments removed.

    The comments EXPLAIN the rules by quoting the strings the rules are about,
    so an assertion made against the raw file can be satisfied by its own
    documentation. That mistake has now cost a false result eleven times in
    this repo.
    """
    return re.sub(r"\{#.*?#\}", "", PARTIAL.read_text(encoding="utf-8"), flags=re.S)


def _py_code_only(path: pathlib.Path) -> str:
    """Python source with comments and docstrings stripped — same reason."""
    src = path.read_text(encoding="utf-8")
    toks = [t for t in tokenize.generate_tokens(io.StringIO(src).readline)
            if t.type != tokenize.COMMENT]
    stripped = tokenize.untokenize(toks)
    tree = ast.parse(stripped)
    doc_lines: set = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None) or []
        if body and isinstance(body[0], ast.Expr) and isinstance(
                getattr(body[0], "value", None), ast.Constant) and isinstance(
                body[0].value.value, str):
            doc_lines.update(range(body[0].lineno,
                                   (body[0].end_lineno or body[0].lineno) + 1))
    return "\n".join(ln for i, ln in enumerate(stripped.splitlines(), 1)
                     if i not in doc_lines)


def _fn_source(name: str) -> str:
    """One function of cli_coverage, unparsed from the AST.

    Unparsed rather than sliced: a substring window is bounded by whatever the
    author put next in the file, and the guard silently widens the day someone
    reorders the module.
    """
    tree = ast.parse(SERVICE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.unparse(node)
    raise AssertionError("cli_coverage has no function %r" % name)


# ==========================================================================
# the vocabulary — one author
# ==========================================================================

def test_the_badge_vocabulary_has_exactly_one_template_author():
    from app.services import cli_coverage as cc

    labels = [lbl for lbl, _cls, _why in cc.PROV_LABEL.values() if lbl != "—"]
    assert labels, "PROV_LABEL must carry the wording"
    macro = _macro_src()
    for lbl in labels:
        assert lbl in macro, (
            "%r is declared in PROV_LABEL and never rendered — the service and "
            "the template have drifted" % lbl)


def test_no_consumer_page_spells_the_vocabulary_itself():
    """A page that writes its own badge is a second author of one word."""
    from app.services import cli_coverage as cc

    labels = [lbl for lbl, _c, _w in cc.PROV_LABEL.values() if lbl != "—"]
    for rel in CONSUMERS:
        text = (REPO / rel).read_text(encoding="utf-8")
        for lbl in labels:
            assert lbl not in text, (
                "%s spells %r itself instead of calling prov_badge()" % (rel, lbl))


def test_every_consumer_imports_the_shared_macro():
    for rel in CONSUMERS:
        text = (REPO / rel).read_text(encoding="utf-8")
        assert "partials/_cli_provenance.html" in text, \
            "%s renders provenance without importing the one macro" % rel


def test_prov_label_covers_every_bucket_prov_order_names():
    from app.services import cli_coverage as cc

    assert set(cc.PROV_LABEL) == set(cc.PROV_ORDER), \
        "a bucket with no label renders as the macro's fallback em dash"


def test_the_macro_branches_on_every_bucket():
    """A bucket with no branch silently falls through to '—'.

    That failure mode is invisible: it looks exactly like honest ignorance.
    """
    from app.services import cli_coverage as cc

    macro = _macro_src()
    for bucket in cc.PROV_ORDER:
        assert "'%s'" % bucket in macro, \
            "the macro has no branch for the %r bucket" % bucket


def test_unknown_carries_no_badge_class():
    from app.services import cli_coverage as cc

    assert cc.PROV_LABEL[cc.PROV_UNKNOWN][1] == "", (
        "a grey 'unknown' pill sits in the same visual family as the grey "
        "'no CLI block here' pill, and those two mean opposite things")


def test_unknown_renders_without_a_badge_and_no_block_renders_with_one(app):
    """Rendered through the macro itself, not through a page.

    ``render_template_string`` drags in every context processor — including the
    one that 500s on ``/api-tokens/`` today — so a guard built on it would fail
    for a reason that has nothing to do with this badge.
    """
    with app.app_context():
        mod = app.jinja_env.get_template("partials/_cli_provenance.html").module
        unknown = str(mod.prov_badge({"bucket": "unknown", "why": "w"}))
        noblock = str(mod.prov_badge({"bucket": "no_block", "why": "w"}))
        nothing = str(mod.prov_badge(None))
    assert "fw-badge" not in unknown, unknown
    assert "fw-badge" in noblock, noblock
    assert "fw-badge" not in nothing, nothing


def test_the_partial_is_light_chrome(app):
    """This product has no dark mode (safeguards §9m)."""
    src = PARTIAL.read_text(encoding="utf-8")
    for leak in ("#080d1a", "backdrop-filter", "rgba(30,41,59"):
        assert leak not in src, "dark-theme literal %r in the badge partial" % leak


# ==========================================================================
# absent evidence — the hinge
# ==========================================================================

def test_no_evidence_answers_unknown_and_never_no_block(app):
    """The single rule this module exists for."""
    from app.services import cli_coverage as cc

    with app.app_context():
        diff = cc.compare("fortiweb", "")
        diff["no_evidence"] = True
        prov = cc.provenance_from(diff, None)

    assert prov.measured is False
    buckets = {r["bucket"] for r in prov.by_name.values()}
    assert cc.BUCKET_NO_BLOCK not in buckets, (
        "with no dump every catalog entry lands in no_block inside compare(); "
        "publishing that reads as 'the CLI has none of this'")
    assert buckets <= {cc.BUCKET_MONITOR}, buckets


def test_no_evidence_flag_beats_a_supplied_evidence_record(app):
    """``no_evidence`` wins over a caller handing in a row anyway.

    ``report`` sets the flag when the file could not be READ even though the
    vault row exists — trusting the row there would badge a whole catalog from
    a dump nobody managed to open.
    """
    from app.services import cli_coverage as cc

    with app.app_context():
        diff = cc.compare("fortiweb", "")
        diff["no_evidence"] = True
        prov = cc.provenance_from(diff, {"appliance": "ghost", "line": "7.6"})
    assert prov.measured is False
    assert prov.device == ""


def test_monitor_survives_absent_evidence(app):
    """A runtime URN cannot host a CLI block — true with or without a dump."""
    from app.services import cli_coverage as cc

    with app.app_context():
        prov = cc.provenance("fortiweb")           # empty test vault
        assert prov.measured is False
        rec = prov.for_urn("/api/v2.0/system/status.systemstatus")
    assert rec["bucket"] == cc.BUCKET_MONITOR


def test_unsupported_product_reports_its_own_reason(app):
    from app.services import cli_coverage as cc

    with app.app_context():
        prov = cc.provenance("fortianalyzer")
    assert prov.supported is False
    assert prov.measured is False
    assert prov.reason == cc.UNSUPPORTED_REASON["fortianalyzer"], \
        "the refusal must keep the product's own wording, not a generic one"
    assert prov.for_name("anything")["bucket"] == cc.PROV_UNKNOWN


def test_an_unmeasured_answer_is_distinguishable_from_a_missing_catalog_entry(app):
    """Two different ignorances must not share one sentence."""
    from app.services import cli_coverage as cc

    with app.app_context():
        unmeasured = cc.provenance("fortiweb").for_name("system_admin")
        diff = cc.compare("fortiweb", FW_DUMP)
        measured = cc.provenance_from(diff, {"appliance": "t", "line": "7.6"})
        absent = measured.for_name("definitely_not_a_catalog_entry")

    assert unmeasured["bucket"] == absent["bucket"] == cc.PROV_UNKNOWN
    assert unmeasured["why"] != absent["why"]
    assert "catalog" in absent["why"]


# ==========================================================================
# measured evidence
# ==========================================================================

@pytest.fixture()
def measured(app):
    from app.services import cli_coverage as cc

    with app.app_context():
        diff = cc.compare("fortiweb", FW_DUMP)
        yield cc.provenance_from(diff, {"appliance": "fwtest", "line": "7.6",
                                        "created_at": "2026-09-15 10:00"})


def test_measured_exposes_which_capture_it_is_speaking_for(measured):
    assert measured.measured is True
    assert measured.device == "fwtest"
    assert measured.line == "7.6"
    assert measured.captured_at == "2026-09-15 10:00"


def test_a_block_the_catalog_knows_is_served_by_both(app, measured):
    from app.services import cli_coverage as cc

    rec = measured.for_name("system_admin")
    assert rec["bucket"] == cc.BUCKET_BOTH
    assert rec["path"] == "system admin", rec


def test_every_catalog_entry_gets_exactly_one_bucket(app, measured):
    """Completeness. A name with no answer is reported as 'not in the catalog'."""
    from app.registry import loader

    with app.app_context():
        names = set(loader.load_registry())
    missing = sorted(n for n in names if n not in measured.by_name)
    assert not missing, "no bucket for %d catalog entries: %s" % (
        len(missing), missing[:8])


def test_for_urn_resolves_through_tokens_not_string_equality(measured):
    from app.services import cli_coverage as cc

    by_urn = measured.for_urn("/api/v2.0/cmdb/system/admin")
    by_name = measured.for_name("system_admin")
    assert by_urn["bucket"] == by_name["bucket"] == cc.BUCKET_BOTH


def test_cli_only_findings_are_carried_for_the_pages_that_list_them(measured):
    from app.services import cli_coverage as cc

    assert measured.cli_only, "the dump has blocks the catalog does not know"
    assert all(r.get("path") for r in measured.cli_only)
    # and they are addressable by their tokens, which is how a page maps a CLI
    # path back onto a row
    tok = tuple(measured.cli_only[0]["tokens"])
    assert measured.by_tokens[tok]["bucket"] == cc.BUCKET_CLI_ONLY


def test_cli_only_is_empty_when_nothing_was_measured(app):
    """A diff that HAS findings, reaching provenance with no readable evidence.

    The first version asked an empty test vault, so ``cli_only`` was empty
    because there were no blocks to find — nothing to do with the rule, and the
    mutation that published findings regardless walked straight through it. The
    case that matters is the vault row whose file would not open: ``compare``
    ran, the findings are real, and not one of them may be attributed to a
    capture nobody managed to read.
    """
    from app.services import cli_coverage as cc

    with app.app_context():
        diff = cc.compare("fortiweb", FW_DUMP)
        assert diff[cc.BUCKET_CLI_ONLY], "premise: this dump produces findings"
        diff["no_evidence"] = True
        prov = cc.provenance_from(diff, {"appliance": "unreadable"})

    assert prov.measured is False
    assert prov.cli_only == [], \
        "findings must not survive the capture they were made from"
    assert prov.by_tokens == {}, \
        "and they must not stay reachable by URN through the back door"


def test_a_runtime_endpoint_is_api_only_by_NAME_too_with_no_dump(app):
    """The lookup the pages actually use.

    ``for_urn`` answers monitor from the URN shape and never consults
    ``by_name`` — so a by_name lookup that withheld it would be invisible to the
    URN guard while the API hub, which badges by NAME, quietly downgraded 42
    runtime endpoints from "API only" to an em dash. A live mutation proved
    exactly that before this guard existed.
    """
    from app.services import cli_coverage as cc

    with app.app_context():
        prov = cc.provenance("fortiweb")
        assert prov.measured is False, "premise: the test vault holds no dump"
        monitor = [e["name"] for e in cc.compare("fortiweb", "")[cc.BUCKET_MONITOR]]
    assert monitor, "premise: the FortiWeb catalog has runtime endpoints"
    assert prov.for_name(monitor[0])["bucket"] == cc.BUCKET_MONITOR


# ==========================================================================
# the firmware line — a filter, never a fallback
# ==========================================================================

def test_line_is_a_filter_and_never_falls_back_to_another_capture(app):
    """The comparison page's only way to lie.

    A 7.6 dump relabelled as evidence for 8.0 would render as a confident
    answer about firmware nobody captured.
    """
    from app.services import cli_coverage as cc

    _seed_dump(app, firmware="FortiWeb-KVM 7.6.8,build1128(GA.M),260602",
               name="line76")
    with app.app_context():
        assert cc.report("fortiweb")["chosen"] is not None
        on_76 = cc.report("fortiweb", line="7.6")
        on_80 = cc.report("fortiweb", line="8.0")

    assert on_76["chosen"] is not None
    assert on_80["chosen"] is None, \
        "a line with no capture must not be answered with another line's dump"


def test_the_unmeasured_line_names_the_line_in_its_reason(app):
    from app.services import cli_coverage as cc

    _seed_dump(app, name="line76b")
    with app.app_context():
        prov = cc.provenance("fortiweb", line="8.0")
    assert prov.measured is False
    assert "8.0" in prov.reason
    assert "API-only" in prov.reason, \
        "the reason must say what the page may NOT conclude, not just that it is blank"


def test_provenance_projects_the_diff_and_does_not_re_read_anything():
    """``provenance_from`` must stay pure.

    The API hub already holds a diff when it renders; a hidden second parse of
    a 690 KB dump per page load is how this becomes the slow page nobody opens.
    """
    src = _fn_source("provenance_from")
    for forbidden in ("read_dump(", "report(", "evidence_index(", "parse_config_dump("):
        assert forbidden not in src, \
            "provenance_from calls %s — it is meant to be a projection" % forbidden


# ==========================================================================
# the three pages
# ==========================================================================

@pytest.fixture()
def seeded(app):
    """A FortiWeb dump in the vault, the way a real capture leaves one."""
    return _seed_dump(app, name="provseed")


def test_api_explorer_tree_badges_its_leaves(app, client, seeded):
    """Scoped to a LEAF, not to the page.

    The legend renders one sample of every badge, so ``"API + CLI" in page``
    stays true with the badge stripped off all 517 leaves — a mutation proved
    exactly that. The badge must follow a leaf's own URN element.
    """
    login(client, admin_user_id(app))
    page = client.get("/web/api-explorer/").get_data(as_text=True)
    leaf_badge = re.search(
        r'<code class="text-muted" style="font-size:10\.5px;">[^<]+</code>\s*'
        r'<br>\s*<span class="fw-badge fw-badge-\w+ fw-badge-nowrap"', page)
    assert leaf_badge, "no leaf of the API menu tree carries a provenance badge"
    assert "CLI evidence: <strong>provseed</strong>" in page, \
        "the page must say WHICH capture it is badging from"


def test_structure_cross_reference_has_a_served_by_column(app, client, seeded):
    login(client, admin_user_id(app))
    page = client.get("/web/structure/").get_data(as_text=True)
    assert "Served by" in page
    assert "API + CLI" in page


def test_structure_answers_by_urn_when_the_registry_does_not_cover_a_node(app, client,
                                                                         seeded):
    """The interesting half of that table.

    A node the registry misses is exactly the gap this page exists to expose. A
    name-only lookup would print an em dash over every one of them — precisely
    where the answer is worth the most.

    The node is planted through the admin OVERLAY, which is the supported way
    to extend the tree, rather than asserting that the built-in seed happens to
    contain an uncovered node: it does not, and a guard resting on that would
    be measuring the seed rather than the lookup.
    """
    from app.services import cli_coverage
    from app.services import settings_store as store

    from app.services import structure as st

    with app.app_context():
        prov = cli_coverage.provenance("fortiweb")
        assert prov.measured and prov.cli_only, "premise: the dump has findings"
        # The URN a promotion would offer — derived by the one function whose
        # job that is, never spelled by hand. And chosen by asking STRUCTURE's
        # own resolver which candidate it cannot match: that index also holds
        # the action-stripped base form, so most child-table URNs resolve to
        # their parent and are legitimately "API + CLI".
        index = st.registry_urn_index()
        urn = ""
        for finding in prov.cli_only:
            for cand in cli_coverage.candidate_urns("fortiweb", finding["path"]):
                if not st._endpoint_for(index, cand) and \
                        prov.for_urn(cand)["bucket"] == cli_coverage.BUCKET_CLI_ONLY:
                    urn = cand
                    break
            if urn:
                break
        assert urn, ("premise: this dump yields a CLI block whose REST path the "
                     "registry cannot resolve even by its base form")

        store.set_json("structure.overlay", {
            "added": [{"parent": "", "node": {"key": "provorphan",
                                              "label": "Provenance orphan",
                                              "urn": urn}}],
            "edited": {}, "removed": [], "order": {}, "functions": {},
        })

    login(client, admin_user_id(app))
    page = client.get("/web/structure/").get_data(as_text=True)
    row = re.search(r"<tr>(?:(?!</tr>).)*Provenance orphan(?:(?!</tr>).)*</tr>",
                    page, re.S)
    assert row, "the overlay node must reach the table"
    # Scoped to the ROW: the legend renders a sample of every badge, so a
    # page-level assertion here is satisfied by the legend while every row is
    # blank — which is what a mutation demonstrated.
    assert "CLI only" in row.group(0), (
        "a node the registry misses and the CLI serves must be badged in its "
        "own row, not left as an em dash: %s" % row.group(0)[:400])


def test_versions_page_badges_each_build_from_its_own_capture(app, client, seeded):
    """The headline behaviour: one row measured, the other honestly blank.

    Read off the BUILD table since 2026-09-16 — the line table that used to
    carry this cell was removed as a duplicate of it. The rule is unchanged: a
    scope with no capture of its own says so rather than borrowing one.

    The fixture is new and is the point. This guard never wrote a matrix: it
    passed on whatever an earlier test in the session had left in the isolated
    matrix dir, so it was measuring test order. Per ROW, not per page — the
    page-level count was satisfied while the table was EMPTY.
    """
    from app.services import firmware_versions as fv

    with app.app_context():
        fv.declare("fortiweb", "7.6.8")   # the build the seeded dump came from
        fv.declare("fortiweb", "8.0.5")   # nothing was ever captured on this one
    login(client, admin_user_id(app))
    page = client.get("/web/registry/versions").get_data(as_text=True)

    def row(build):
        m = re.search(r"<tr>\s*<td><code>%s</code>.*?</tr>" % re.escape(build),
                      page, re.S)
        assert m, "no row rendered for build %s" % build
        return m.group(0)

    assert "blocks</span>" in row("7.6.8"), \
        "the build the dump was taken on must badge its own capture: %s" \
        % row("7.6.8")[-400:]
    blank = row("8.0.5")
    assert "no dump captured on this build" in blank, \
        "a build with no capture must say so, never borrow 7.6.8's: %s" % blank[-400:]
    why = re.search(r'title="(no usable CLI dump[^"]*)"', blank)
    assert why and "8.0.5" in why.group(1), \
        "the unmeasured cell must name the firmware it could not answer for"


@pytest.fixture()
def two_line_matrix(app, seeded):
    """A matrix with an endpoint that 8.0 adds — written by this test.

    Until 2026-09-15 this guard had NO fixture: it read the API matrix of the
    LIVE INSTALLATION (``data/api_matrix/fortiweb.json``) and passed because
    that file happened to contain an 8.0 witness. It was measuring production
    state, so it would fail on a fresh checkout and pass or fail depending on
    what the last real sweep had found — and it broke the moment the suite was
    correctly isolated from that tree.
    """
    import json

    from app.services import api_matrix, cli_coverage

    # The endpoint the row is about is TAKEN FROM THE DUMP, not invented: the
    # base column must carry a real CLI verdict, and a made-up name is "not an
    # entry in the fortiweb catalog, so there is nothing to compare a CLI block
    # against" — an em dash, which is exactly what this guard forbids.
    with app.app_context():
        rep = cli_coverage.report("fortiweb")
        both = rep["diff"][cli_coverage.BUCKET_BOTH]
        assert both, "premise: the seeded dump matches at least one catalog entry"
        rec = both[0]
        # ``catalog``/``urn`` — the keys a BOTH record actually carries. The
        # first attempt read ``name``/``endpoint``, got None, and the page then
        # said "'null' is not an entry in the fortiweb catalog": the fixture was
        # wrong in a way that looked like the code being wrong.
        ep_name, ep_urn = rec["catalog"], rec["urn"]

    def _ep(name, devices, verdict="ok", urn=None):
        return {"endpoint": name,
                "urn": urn if urn is not None else "/api/v2.0/cmdb/system/%s" % name,
                "section": "System", "verdict": verdict, "fields": None,
                "origin": "sweep", "devices": devices,
                "measured_at": "2026-09-15T00:00:00"}

    def _line(line, devices, endpoints):
        return {"line": line, "devices": devices, "in_fleet": True,
                "endpoints": endpoints, "objects": {},
                "counts": {"swept": len(endpoints), "ok": len(endpoints),
                           "absent": 0, "error": 0, "endpoints_with_fields": 0,
                           "schema_fields": 0, "schema_objects": 0}}

    # "added" means MEASURED ON BOTH and absent on the base line. A name that
    # simply does not appear on 7.6 is UNKNOWN, not added — the distinction the
    # diff exists to make — so the fixture carries the absent record too, or it
    # tests nothing.
    absent76 = _ep(ep_name, ["fwA"], verdict="absent", urn=ep_urn)
    only80 = _ep(ep_name, ["fwB"], urn=ep_urn)
    matrix = {
        "product": "fortiweb",
        "built_at": "2026-09-15T00:00:00",
        "sweepable": True,
        "fleet_lines": ["7.6", "8.0"],
        "witnesses": [{"id": 1, "name": "fwA", "firmware": "7.6.8", "line": "7.6"},
                      {"id": 2, "name": "fwB", "firmware": "8.0.1", "line": "8.0"}],
        "notes": [],
        "lines": {"7.6": _line("7.6", ["fwA"], {ep_name: absent76}),
                  "8.0": _line("8.0", ["fwB"], {ep_name: only80})},
    }
    pathlib.Path(api_matrix.MATRIX_ROOT).mkdir(parents=True, exist_ok=True)
    with io.open(api_matrix.matrix_path("fortiweb"), "w", encoding="utf-8") as fh:
        json.dump(matrix, fh)
    return matrix


def test_versions_row_badges_the_measured_line_and_blanks_the_other(app, client,
                                                                   seeded,
                                                                   two_line_matrix):
    """Per-ROW, not just per-page.

    The two columns are the whole point: one line was captured and one was not,
    and a row that answers for both from the same dump is the exact lie this
    page is built to avoid. A page-level assertion cannot see that — the
    legend would satisfy it while every row was wrong.
    """
    login(client, admin_user_id(app))
    page = client.get("/web/registry/versions?base=7.6&target=8.0").get_data(as_text=True)
    m = re.search(
        r"<tr><td><code>[\w.-]+</code></td>\s*"
        r"<td><code[^>]*>[^<]*</code></td>\s*"
        r"<td><span class=\"fw-badge fw-badge-success\">added on 8\.0</span></td>\s*"
        r"<td>(.*?)</td>\s*<td>(.*?)</td></tr>", page, re.S)
    assert m, "the endpoint provenance table rendered no 'added on 8.0' row"
    base_cell, target_cell = m.group(1), m.group(2)
    assert "fw-badge" in base_cell, \
        "7.6 holds a capture, so its column must carry a real verdict: %r" % base_cell
    assert "fw-badge" not in target_cell, \
        "8.0 holds no capture; a badge there is an answer nobody measured: %r" % target_cell
    assert "firmware line 8.0" in target_cell, target_cell


def test_versions_lines_table_names_the_capture_behind_each_number(app, client, seeded):
    login(client, admin_user_id(app))
    page = client.get("/web/registry/versions?base=7.6&target=8.0").get_data(as_text=True)
    assert "provseed" in page, \
        "a block count with no capture behind it cannot be judged"


# ==========================================================================
# permissions — the badge is catalog metadata, the block text is not
# ==========================================================================

@pytest.fixture()
def operator_id(app):
    return make_user(app, username="provop", role="readonly",
                     profile_id=profile_id(app, "readonly"))


def test_premise_the_operator_has_no_backup_permission(app, operator_id):
    """Without this the permission guard below would be vacuous."""
    from app.models import Permission, User

    with app.app_context():
        assert not User.query.get(operator_id).can(Permission.BACKUP)


def test_badges_render_without_backup_but_carry_no_device_configuration(
        app, client, seeded, operator_id):
    """Table names are metadata; ``set`` lines are device configuration.

    Same split the coverage section already draws — a badge that leaked block
    text would be a way around the permission that gates the vault.
    """
    login(client, operator_id)
    page = client.get("/web/api-explorer/").get_data(as_text=True)
    assert "API + CLI" in page, "the provenance itself is catalog metadata"
    assert "set forbid-password-reuse" not in page
    assert "ENC " not in page
    assert "BEGIN CERTIFICATE" not in page
