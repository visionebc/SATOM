"""Guards for the CLI↔API **discovery run**, the shared catalog writer, and the
CLI-only elements on the Structure page.

Every failure mode this feature has is the same shape: **a question that was
never asked must never look like a question that came back with an answer.**

* a block the budget never reached must not read as "the device denies it";
* a probe that RAISED must not read as "that path is absent";
* a page with no CLI evidence at all must not read as "the CLI has nothing";
* a derived path must never enter the catalog on our say-so — only on the
  appliance's.

The other half of the weight is on SINGLE AUTHORSHIP. This repo's status badge
has two authors (``api.js`` and ``main.js``) and they disagree; a catalog write
with two authors would persist the disagreement. So there are guards that the
two registry editors and the bulk registration all go through ONE writer, and
that the three pages import the shared macros instead of spelling the filter and
the test button themselves.

Trap notes for whoever edits this file:

* assertions about SOURCE run over :func:`_code_only`, because the prose here
  quotes the very identifiers it forbids — this repo has been bitten by that
  nine times;
* assertions about a page are scoped to the ROW or to the macro file, never to
  the whole page: a legend that renders a sample of each badge satisfies a
  naive ``"CLI only" in page`` with the badge removed from every row (that is
  how two mutations survived on 2026-09-15).
"""
from __future__ import annotations

import ast
import io
import os
import re

import pytest

from conftest import admin_user_id, login, make_user, profile_id

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SVC = os.path.join(REPO, "app", "services", "discovery_run.py")
WRITER = os.path.join(REPO, "app", "services", "registry_write.py")
VIEW = os.path.join(REPO, "app", "views", "_discovery.py")
FWVIEW = os.path.join(REPO, "app", "views", "registry.py")
ADCVIEW = os.path.join(REPO, "app", "views", "adc_api.py")
STRUCT = os.path.join(REPO, "app", "services", "structure.py")
TOOLS = os.path.join(REPO, "app", "templates", "partials", "_cli_probe_tools.html")
DRTPL = os.path.join(REPO, "app", "templates", "partials", "_discovery_run.html")
STPL = os.path.join(REPO, "app", "templates", "structure", "index.html")
VERTPL = os.path.join(REPO, "app", "templates", "registry", "versions.html")


def _read(path):
    with io.open(path, encoding="utf-8") as fh:
        return fh.read()


def _code_only(path):
    """Source with docstrings and comments stripped — so an assertion cannot be
    satisfied (or defeated) by the prose that explains it."""
    src = _read(path)
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                             ast.Module)) and ast.get_docstring(node):
            node.body = node.body[1:]
    out = ast.unparse(tree)
    return "\n".join(ln for ln in out.splitlines() if not ln.strip().startswith("#"))


# --------------------------------------------------------------------------- #
#  fixtures: a diff built by hand, so the guards do not depend on live evidence
# --------------------------------------------------------------------------- #
def _diff(cli_only):
    return {"product": "fortiweb", "supported": True, "cli_only": list(cli_only),
            "counts": {"cli_only": len(cli_only)}}


def _block(path, configured=True, instances=3, settings=("a", "b")):
    return {"path": path, "tokens": path.split(), "instances": instances if configured else 0,
            "settings": list(settings) if configured else [],
            "configured": bool(configured), "depth": 0, "line": 1}



def _dev(app, name, kind="fortiweb"):
    """An appliance row the ADOM scope will actually show.

    ``username``/``password`` are NOT decoration: the column is NOT NULL, and a
    row that fails to insert makes every guard below fail for the wrong reason.
    """
    from app.models import Appliance, db

    with app.app_context():
        a = Appliance(name=name, host="10.0.0.%d" % (abs(hash(name)) % 200 + 20),
                      port=443, kind=kind, username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        return a.id


@pytest.fixture()
def dr():
    from app.services import discovery_run

    return discovery_run


# --------------------------------------------------------------------------- #
#  1. the three negatives never merge                                          #
# --------------------------------------------------------------------------- #
def test_budget_exhaustion_is_not_absence(app, dr):
    """A block the run never reached is ``not_probed`` — never ``absent``."""
    plan = dr.plan("fortiweb", _diff([_block("system aaa bbb"),
                                      _block("system ccc ddd"),
                                      _block("system eee fff")]),
                   by_name={}, by_urn={})
    res = dr.run(plan, lambda urn: ([], "absent", ""), budget=2, by_urn={})
    assert res["spent"] == 2
    assert res["exhausted"] is True
    statuses = [f.status for f in res["findings"]]
    assert dr.NOT_PROBED in statuses, statuses
    # and the untouched ones did NOT acquire the device's verdict
    untouched = [f for f in res["findings"] if f.probed == 0]
    assert untouched, "the budget should have left blocks unasked"
    assert all(f.status == dr.NOT_PROBED for f in untouched)


def test_absent_requires_every_candidate_answered(app, dr):
    plan = dr.plan("fortiweb", _diff([_block("system aaa bbb")]),
                   by_name={}, by_urn={})
    res = dr.run(plan, lambda urn: ([], "absent", ""), budget=99, by_urn={})
    f = res["findings"][0]
    assert f.probed == len(f.candidates) > 0
    assert f.status == dr.ABSENT
    assert res["absent"] == 1 and res["not_probed"] == 0


def test_probe_failure_is_error_not_absent(app, dr):
    plan = dr.plan("fortiweb", _diff([_block("system aaa bbb")]),
                   by_name={}, by_urn={})

    def boom(urn):
        raise RuntimeError("connection reset")

    res = dr.run(plan, boom, budget=99, by_urn={})
    f = res["findings"][0]
    assert f.status == dr.ERROR
    assert res["errors"] == 1 and res["absent"] == 0
    # one candidate failing must not sink the others
    assert f.probed == len(f.candidates)


def test_one_raising_candidate_does_not_sink_the_run(app, dr):
    plan = dr.plan("fortiweb", _diff([_block("system aaa bbb"),
                                      _block("waf ccc ddd")]),
                   by_name={}, by_urn={})
    seen = []

    def flaky(urn):
        seen.append(urn)
        if "aaa" in urn:
            raise RuntimeError("nope")
        return ([], "absent", "")

    res = dr.run(plan, flaky, budget=99, by_urn={})
    assert res["errors"] == 1 and res["absent"] == 1
    assert any("ccc" in u for u in seen), "the second block was never asked"


# --------------------------------------------------------------------------- #
#  2. stop at the first served path, and say how many were really asked        #
# --------------------------------------------------------------------------- #
def test_stops_at_first_served_and_reports_what_was_asked(app, dr):
    plan = dr.plan("fortiweb", _diff([_block("system aaa bbb ccc")]),
                   by_name={}, by_urn={})
    f0 = plan[0]
    assert len(f0.candidates) >= 3, "this block should derive several candidates"
    first = f0.candidates[0].urn
    res = dr.run(plan, lambda urn: ([{"x": 1}], "ok", "") if urn == first
                 else ([], "absent", ""), budget=99, by_urn={})
    f = res["findings"][0]
    assert f.status == dr.SERVED and f.served.urn == first
    assert f.probed == 1, "asking past a served path buys nothing"
    # the unasked candidates must NOT read as denied
    assert all(c.verdict == dr.NOT_PROBED for c in f.candidates[1:])


def test_budget_is_never_exceeded(app, dr):
    plan = dr.plan("fortiweb", _diff([_block("system a%d b%d" % (i, i))
                                      for i in range(20)]),
                   by_name={}, by_urn={})
    calls = []
    res = dr.run(plan, lambda urn: (calls.append(urn), ([], "absent", ""))[1],
                 budget=7, by_urn={})
    assert len(calls) <= 7 and res["spent"] == len(calls)


# --------------------------------------------------------------------------- #
#  3. registerable is a conjunction, and each term matters                     #
# --------------------------------------------------------------------------- #
def test_registerable_requires_served(app, dr):
    plan = dr.plan("fortiweb", _diff([_block("system aaa bbb")]), by_name={}, by_urn={})
    res = dr.run(plan, lambda urn: ([], "absent", ""), budget=99, by_urn={})
    assert res["findings"][0].registerable is False


def test_known_urn_is_not_offered_again(app, dr):
    plan = dr.plan("fortiweb", _diff([_block("system aaa bbb")]), by_name={}, by_urn={})
    urn = plan[0].candidates[0].urn
    res = dr.run(plan, lambda u: ([{"x": 1}], "ok", "") if u == urn else ([], "absent", ""),
                 budget=99, by_urn={urn: "already_known"})
    f = res["findings"][0]
    assert f.urn_known == "already_known"
    assert f.registerable is False, "the catalog already has that path"


def test_name_collision_is_detected_before_any_get(app, dr):
    blk = _block("system aaa bbb")
    name = None
    from app.services import cli_coverage

    name = cli_coverage.catalog_name_for(blk["path"])
    plan = dr.plan("fortiweb", _diff([blk]), by_name={name: "/api/v2.0/cmdb/other"},
                   by_urn={})
    assert plan[0].name_taken == "/api/v2.0/cmdb/other"
    # NOT `assert plan[0].registerable is False` here: at plan time nothing has
    # been served yet, so that assertion passes for the wrong reason and stays
    # green with the collision check deleted. Run it, so `served` is true and
    # the ONLY thing that can still block the row is the taken name.
    served = plan[0].candidates[0].urn
    res = dr.run(plan, lambda u: ([{"x": 1}], "ok", "") if u == served
                 else ([], "absent", ""), budget=99, by_urn={})
    f = res["findings"][0]
    assert f.served is not None and f.urn_known == ""
    assert f.registerable is False, "a taken catalog name must block the write"
    assert res["registerable"] == 0 and res["name_taken"] == 1


# --------------------------------------------------------------------------- #
#  4. plan() asks the whole question by default                                #
# --------------------------------------------------------------------------- #
def test_plan_defaults_to_every_cli_only_block(app, dr):
    d = _diff([_block("system aaa bbb", configured=True),
               _block("waf ccc ddd", configured=False)])
    assert len(dr.plan("fortiweb", d, by_name={}, by_urn={})) == 2
    only = dr.plan("fortiweb", d, configured_only=True, by_name={}, by_urn={})
    assert len(only) == 1 and only[0].configured is True


def test_configured_blocks_are_asked_first(app, dr):
    d = _diff([_block("aaa empty one", configured=False),
               _block("zzz full one", configured=True)])
    plan = dr.plan("fortiweb", d, by_name={}, by_urn={})
    assert plan[0].configured is True, "with a budget, order decides what is asked"


def test_catalog_index_reads_the_same_loader_as_the_diff(app):
    """One source of truth for "what is in the catalog".

    A second reader here could disagree with ``cli_coverage._catalog`` and the
    run would offer to register something already registered.
    """
    code = _code_only(SVC)
    cov = _code_only(os.path.join(REPO, "app", "services", "cli_coverage.py"))
    for call in ("load_registry()", "load_adc_registry()"):
        assert call in code, call
        assert call in cov, call


# --------------------------------------------------------------------------- #
#  5. the write: the device is the authority, in the same request              #
# --------------------------------------------------------------------------- #
def test_register_reprobes_and_refuses_an_unserved_path(app, client):
    """A checkbox list is replayable; the appliance is asked again anyway."""
    from app.models import RegistryEndpoint

    aid = _dev(app, "fwtest")
    login(client, admin_user_id(app))

    import app.services.rediscovery as rd
    orig = rd.probe_endpoint
    rd.probe_endpoint = lambda appliance, urn: ([], "absent", "-20001")
    try:
        r = client.post("/web/api-explorer/discovery/register", data={
            "appliance_id": aid, "name": "totally_made_up",
            "urn": "/api/v2.0/cmdb/system/made-up"})
    finally:
        rd.probe_endpoint = orig
    assert r.status_code == 200
    body = r.get_json()
    assert body["created"] == 0 and body["rejected"] == 1
    with app.app_context():
        assert RegistryEndpoint.query.filter_by(name="totally_made_up").first() is None


def test_register_writes_only_what_the_device_served(app, client):
    from app.models import RegistryEndpoint

    aid = _dev(app, "fwtest2")
    login(client, admin_user_id(app))

    import app.services.rediscovery as rd
    orig = rd.probe_endpoint
    rd.probe_endpoint = (lambda appliance, urn:
                         ([{"x": 1}], "ok", "") if urn.endswith("good")
                         else ([], "absent", ""))
    try:
        # A MultiDict, not a list of pairs: the route reads repeated ``name``
        # and ``urn`` fields, and a plain list is not a mapping werkzeug can
        # post. Getting this wrong makes the guard fail for the wrong reason.
        from werkzeug.datastructures import MultiDict

        r = client.post("/web/api-explorer/discovery/register",
                        data=MultiDict([
                            ("appliance_id", str(aid)),
                            ("name", "dr_good"), ("urn", "/api/v2.0/cmdb/system/good"),
                            ("name", "dr_bad"), ("urn", "/api/v2.0/cmdb/system/bad")]))
    finally:
        rd.probe_endpoint = orig
    body = r.get_json()
    assert body["created"] == 1 and body["rejected"] == 1
    with app.app_context():
        assert RegistryEndpoint.query.filter_by(name="dr_good").first() is not None
        assert RegistryEndpoint.query.filter_by(name="dr_bad").first() is None


def test_register_refuses_an_appliance_of_another_product(app, client):
    aid = _dev(app, "adc1", kind="fortiadc")
    login(client, admin_user_id(app))
    r = client.post("/web/api-explorer/discovery/register", data={
        "appliance_id": aid, "name": "x_y", "urn": "/api/v2.0/cmdb/x/y"})
    # 404, not 403: the /web ADOM scope hides a FortiADC from this page before
    # the kind check is ever reached. Confirming a row EXISTS is exactly the
    # leak the scope closes, so the earlier door is the correct one — the kind
    # check behind it is the second lock, asserted at function level below.
    assert r.status_code == 404
    assert b"x_y" not in r.data


# --------------------------------------------------------------------------- #
#  6. permissions                                                              #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", ["/web/api-explorer/discovery/run",
                                  "/web/api-explorer/discovery/plan",
                                  "/web/api-explorer/discovery/register"])
def test_discovery_routes_need_registry_edit(app, client, path):
    """The premise is asserted too: without it a 403 guard could be vacuous."""
    uid = make_user(app, username="ro1", role="readonly")
    with app.app_context():
        from app.models import User

        u = User.query.get(uid)
        assert not u.can("registry.edit"), "premise: this profile lacks registry_edit"
    login(client, uid)
    r = client.post(path, data={"appliance_id": 1})
    assert r.status_code == 403, path


def test_load_drops_the_cli_half_with_its_reason(app, client):
    """Never silently: a user without BACKUP gets the API sweep and is TOLD."""
    code = _code_only(VIEW)
    assert "CLI_SKIP_NO_PERMISSION" in code
    fn = [n for n in ast.walk(ast.parse(_read(VIEW)))
          if isinstance(n, ast.FunctionDef) and n.name == "load"]
    assert fn, "load() moved"
    # NOT `"refused" in body`: the name appears in the function no matter what
    # the guard does, so that assertion stays green with the reporting removed.
    # The relationship is what matters — the sentence is appended UNDER the
    # truthiness of `refused`, never under a constant.
    guarded = [n for n in ast.walk(fn[0])
               if isinstance(n, ast.If) and isinstance(n.test, ast.Name)
               and n.test.id == "refused"]
    assert guarded, "the skipped-CLI reason is not gated on `refused`"
    assert any("skipped" in ast.unparse(st) for st in guarded[0].body), \
        "the reason is computed but never told to the operator"
    assert "flash" in ast.unparse(fn[0])


def test_both_hubs_mount_the_same_four_routes(app):
    rules = {r.rule for r in app.url_map.iter_rules()}
    for base in ("/web/api-explorer", "/adc/api"):
        for leaf in ("plan", "run", "register", "load"):
            assert "%s/discovery/%s" % (base, leaf) in rules, (base, leaf)


# --------------------------------------------------------------------------- #
#  7. ONE catalog writer                                                       #
# --------------------------------------------------------------------------- #
def test_both_editors_go_through_the_shared_writer(app):
    for path in (FWVIEW, ADCVIEW, VIEW):
        code = _code_only(path)
        assert "registry_write.save_endpoint" in code, path
        # and none of them constructs a catalog row itself any more
        assert "RegistryEndpoint(" not in code, "%s still writes its own row" % path


def test_writer_refuses_a_cross_product_edit_by_id(app):
    from app.models import RegistryEndpoint, db
    from app.services import registry_write

    with app.app_context():
        row = RegistryEndpoint(product="fortiadc", api_version="v1",
                               name="adc_thing", urn="/api/adc_thing")
        db.session.add(row)
        db.session.commit()
        rid = row.id
        ok, msg, _r = registry_write.save_endpoint(
            product="fortiweb", name="hijacked", urn="/api/v2.0/cmdb/x",
            row_id=rid)
        assert ok is False and "fortiweb" in msg
        assert db.session.get(RegistryEndpoint, rid).name == "adc_thing"


def test_adc_write_invalidates_the_menu_cache_too(app):
    """Catalog cache and menu cache are two caches; missing one makes the new
    endpoint present and invisible, which reads as a failed write.

    Asserted on the CACHE, not on the writer's source. The source form required
    registry_write to name adc_menu, which test_product_separation forbids for a
    platform module -- the two guards could not both be green. The menu drop now
    lives in loader.invalidate_adc_cache (one owner), and this proves the writer
    still reaches it."""
    from app.services import adc_menu, registry_write
    with app.app_context():
        adc_menu.invalidate()
        adc_menu.menu()
        assert adc_menu._build.cache_info().currsize == 1, "menu() stopped caching"
        registry_write.invalidate("fortiadc")
        assert adc_menu._build.cache_info().currsize == 0, (
            "the FortiADC menu cache is never invalidated")


def test_default_api_version_is_per_product(app):
    from app.services import registry_write

    assert registry_write.default_api_version("fortiweb") == "v2.0"
    assert registry_write.default_api_version("fortiadc") == "v1"


# --------------------------------------------------------------------------- #
#  8. structure: the CLI elements appear WITHOUT joining the dependency tree    #
# --------------------------------------------------------------------------- #
def test_cli_nodes_do_not_enter_the_dependency_tree(app):
    from app.services import structure

    with app.app_context():
        tree = structure.load_catalog({}).tree()
        before_nodes = structure.node_count(tree)
        before_cov = structure.coverage(tree)
        cli = structure.cli_only_nodes(_diff([_block("system aaa bbb")]))
        after = structure.load_catalog({}).tree()
    assert cli and cli[0].key == structure.CLI_ROOT_KEY
    assert structure.node_count(after) == before_nodes
    assert structure.coverage(after) == before_cov


def test_cli_nodes_never_carry_a_derived_urn(app):
    """The whole point: these blocks have no REST path, and printing a guess in
    the same column as the measured URNs is how a guess becomes a fact."""
    from app.services import structure

    cli = structure.cli_only_nodes(_diff([_block("system aaa bbb"),
                                          _block("waf ccc")]))
    for _d, node in structure.iter_nodes(cli):
        assert node.urn == "", node.label


def test_no_evidence_produces_no_cli_findings(app):
    """Absence of evidence is not evidence of absence — and must not render as
    a subtree of zero, which reads like a measured result."""
    from app.services import structure

    assert structure.cli_only_nodes({}) == []
    assert structure.cli_only_nodes({"cli_only": []}) == []
    assert structure.clone_gap({}) == []


def test_clone_gap_lists_only_blocks_that_hold_configuration(app):
    from app.services import structure

    gap = structure.clone_gap(_diff([_block("system full", configured=True),
                                     _block("system empty", configured=False)]))
    assert [g["path"] for g in gap] == ["system full"]
    assert "REST" in gap[0]["reason"]


def test_overlay_snippet_never_guesses_the_parent_field(app):
    """``via`` is the dependency edge. This repo measured what an invented edge
    costs: the appliance rejects the payload. So the snippet leaves it blank."""
    from app.services import structure

    snip = structure.overlay_snippet("system automation-slack",
                                     "/api/v2.0/cmdb/system/automation-slack")
    assert snip["via"] == ""
    assert snip["urn"] == "/api/v2.0/cmdb/system/automation-slack"


def test_cli_cross_reference_marks_leaves_with_their_own_status(app):
    from app.services import structure

    rows = structure.cli_cross_reference(
        structure.cli_only_nodes(_diff([_block("system aaa bbb")])))
    leaves = [r for r in rows if r["cli_path"]]
    assert leaves and all(r["status"] == structure.STATUS_CLI for r in leaves)
    # a grouping row is NOT a finding
    assert any(r["status"] == "none" for r in rows)


# --------------------------------------------------------------------------- #
#  9. one author for the search + test affordances                             #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("tpl", [STPL, VERTPL])
def test_pages_import_the_shared_tools(tpl):
    src = _read(tpl)
    assert "partials/_cli_probe_tools.html" in src, tpl
    # and do not spell their own filter input
    assert "data-cli-filter=" not in src, "%s spells the filter itself" % tpl


def test_filter_box_is_self_wiring(app):
    """It must work on pages that never mount the test bar — the API hub has its
    own console and does not. A search box whose JS lives elsewhere is a search
    box that silently does nothing, which looks like "no rows matched"."""
    src = _read(TOOLS)
    head = src.split("{% macro probe_bar")[0]
    assert "macro filter_box" in head
    assert "addEventListener('input'" in head, "filter_box carries no wiring"


def test_structure_cli_rows_offer_a_CLI_test_not_an_API_one(app):
    """These rows have no URN, so an API test button on them would be a button
    that cannot work — and its presence would imply a REST path exists."""
    src = _read(STPL)
    card = src.split('id="cliOnlyCard"')[1].split("<!-- Exporter function")[0]
    assert "test_btn(cli_path=" in card
    assert "test_btn(urn=" not in card


def test_versions_delta_rows_offer_a_test(app):
    src = _read(VERTPL)
    delta = src.split('id="versionDelta"')[1].split("</table>")[0]
    assert "test_btn(urn=" in delta


INC = '{% include "partials/_discovery_run.html" %}'
CC_INC = "partials/_cli_coverage.html' %}"
HUBS = ("api_explorer", "adc_api", "faz_api", "fac_api")
#: Hubs that used to mount the card and now POINT at it. It moved to the
#: API-versions page on 2026-09-16 because on a hub a run had no firmware to be
#: about: candidates came from whichever CLI dump sorted first, the appliance
#: came from a second, unrelated picker, and the page named neither. On the
#: versions page the row IS the build.
MOVED = ("api_explorer", "adc_api")
#: Hubs that still mount it, because they have no versions page to move it to.
CANNOT = ("faz_api", "fac_api")             # render their reason and stop
#: Where it lives now.
MOUNTS = (os.path.join(REPO, "app", "templates", "registry", "versions.html"),)


def _hub(name):
    return _read(os.path.join(REPO, "app", "templates", name, "index.html"))


def test_discovery_partial_is_included_not_copied(app):
    """One author for the markup; each hub mounts it EXACTLY once.

    The mount moved out of the coverage partial so the card could sit at the
    top of the hubs that can act on it. Mounting it in four places is only safe
    while the markup itself still has a single author: a copied card means two
    authors of one string, which is how the status badge and the sidebar
    accordion drifted in this repo. It also means duplicate DOM ids
    (#discoveryRun / #drRows), so a second mount would silently break the JS.
    """
    cc = _read(os.path.join(REPO, "app", "templates", "partials",
                            "_cli_coverage.html"))
    assert INC not in cc, (
        "the coverage partial must not mount it any more — it would render "
        "twice on the hubs that now mount it at the top")
    for hub in CANNOT + MOUNTS:
        src = _hub(hub) if not hub.endswith(".html") else _read(hub)
        # count the INCLUDE STATEMENT, not the file name: the comment that
        # explains the mount names the file too, and counting the name made
        # this guard read 2 against a correct template.
        assert src.count(INC) == 1, hub
        assert 'id="discoveryRun"' not in src, (
            "%s copies the card instead of including it" % hub)
    # The hubs it LEFT must not mount it and must not silently drop it either.
    # A card that simply vanishes teaches the operator the feature was removed;
    # a pointer teaches them the question needed a firmware to be asked about.
    for hub in MOVED:
        src = _hub(hub)
        assert INC not in src, "%s still mounts the card" % hub
        assert 'id="discoveryRun"' not in src, hub
        assert "moved to the API-versions page" in src, (
            "%s dropped the card without saying where it went" % hub)
        assert "api_versions" in src, hub


def test_discovery_card_is_first_where_it_can_act_and_last_where_it_cannot(app):
    """Position carries meaning, so it is asserted rather than left to taste.

    On a hub with a CLI dump the run is the affordance the page exists to
    offer; at the foot of the page it was unfindable. On a hub WITHOUT one the
    card can only say "not applicable" — spending the first slot on a
    non-answer is worse than the problem being fixed.
    """
    # On a hub WITHOUT a dump the card can only say "not applicable", and
    # spending the first slot on a non-answer is worse than the problem being
    # fixed. That half of the rule is unchanged.
    for hub in CANNOT:
        src = _hub(hub)
        assert src.index(INC) > src.index(CC_INC), hub
    # On the versions page the rule INVERTS, and deliberately: the affordance
    # the page exists to offer is the table of builds, and the card answers
    # about the row you clicked. A card above the rows that feed it would be a
    # control with nothing chosen.
    for path in MOUNTS:
        src = _read(path)
        assert src.index("Firmware versions") < src.index(INC), path
        assert "discover=" in src.split(INC)[0], (
            "%s mounts the card but no row scopes it" % path)


def test_the_card_sits_directly_under_the_table_that_scopes_it(app):
    """Under the rows, and ABOVE the comparison and the preflight.

    Reported by the operator on 2026-09-16: at the foot of the page the card
    was two long cards below the row that aims it. That distance is not only
    cosmetic — the row's link is how a run is scoped, and this same card is
    where that run's phases, percentage and Stop button are read, so being far
    from the row was being far from the status of what the row started.

    The lower bound stays (a control above the rows that feed it has nothing
    chosen); the upper bound is new and is what the report was about.
    """
    for path in MOUNTS:
        src = _read(path)
        assert src.index("Firmware versions") < src.index(INC), path
        for later, what in (("bi-arrow-left-right", "the comparison"),
                            ("bi-shield-check", "preflight")):
            assert src.index(INC) < src.index(later), (
                "the card must render before %s — it did not, and an operator "
                "who clicked a row had to scroll past it to reach the control "
                "that row aimed" % what)


def test_discovery_card_starts_open(app):
    """A collapsed card at the top of the page is still a hidden feature."""
    src = _read(DRTPL)
    head = src.split("fw-card-body")[0]
    assert 'class="collapse show" id="discoveryRunBody"' in head
    assert 'aria-expanded="true"' in head
    assert 'aria-expanded="false"' not in head


def test_every_inline_script_carries_the_csp_nonce(app):
    """A <script> without the nonce is REFUSED, and refusal looks like a dead
    button, not like an error.

    app/__init__.py sends ``script-src-elem 'self' 'nonce-…'`` app-wide with no
    'unsafe-inline'. Three blocks shipped without it, so Run discovery /
    Register selected / the filter boxes / the per-row test buttons rendered
    perfectly and did nothing when clicked. Nothing failed — the feature was
    simply inert. This guard covers every partial these pages mount.
    """
    parts = ("_discovery_run.html", "_cli_coverage.html", "_cli_probe_tools.html",
             "_cli_provenance.html")
    for name in parts:
        p = os.path.join(REPO, "app", "templates", "partials", name)
        if not os.path.exists(p):
            continue
        src = _read(p)
        opens = re.findall(r"<script(?![-\w])([^>]*)>", src)
        for attrs in opens:
            assert "csp_nonce" in attrs, (
                "%s has an inline <script%s> with no CSP nonce — the browser "
                "will refuse to run it" % (name, attrs))


def test_the_three_negatives_stay_three_where_they_now_live(app):
    """The card's row-badge vocabulary went with the findings table on
    2026-09-17. The RULE it enforced did not: "the device says no", "we failed
    to ask" and "nobody asked" are three different next steps, and a caller
    that folds them reports a block as denied when it was merely skipped.

    Re-anchored to the service, which is where the distinction is now made and
    the only place left that can make it. The template half is asserted
    INVERTED below so the vocabulary cannot quietly grow back in a page that no
    longer probes anything.
    """
    from app.services import discovery_run as dr

    verdicts = [dr.SERVED, dr.ABSENT, dr.ERROR, dr.NOT_PROBED]
    assert len(set(verdicts)) == 4, verdicts
    assert "" not in verdicts, verdicts


def test_the_card_makes_no_claim_about_what_a_device_serves(app):
    """It cannot: nothing on it asks a device for a path any more.

    This is the inverted half of the guard above. A badge map, a findings row
    or a footnote reappearing here would be a page printing verdicts it never
    obtained — the worst version of the defect the vocabulary existed to stop.
    """
    src = _read(DRTPL)
    for token in ("var BADGE", "not_probed", "'absent'", "no such path",
                  "could not ask", "id=\"drRows\"", "id=\"drFootnote\""):
        assert token not in src, token


# --------------------------------------------------------------------------- #
#  10. the run cannot be pointed at another product's box                      #
# --------------------------------------------------------------------------- #
def test_run_refuses_an_appliance_of_another_product(app, client):
    aid = _dev(app, "adc9", kind="fortiadc")
    login(client, admin_user_id(app))
    r = client.post("/web/api-explorer/discovery/run", data={"appliance_id": aid})
    assert r.status_code == 404  # ADOM scope first; see the note above


def test_kind_check_is_a_real_second_lock(app):
    """Over HTTP the ADOM scope answers 404 first, so this check can only be
    reached at function level — and code no guard can reach is code that
    silently stops working."""
    from app.views import _discovery

    class _Fake:
        id, name, kind = 1, "adc-imposter", "fortiadc"

    orig = _discovery.visible_appliance_or_404
    _discovery.visible_appliance_or_404 = lambda _id: _Fake()
    try:
        with app.test_request_context("/x", method="POST",
                                      data={"appliance_id": "1"}):
            resp, code = _discovery.run_payload("fortiweb")
            assert code == 403
            assert "not a fortiweb" in resp.get_data(as_text=True)
            resp2, code2 = _discovery.register_payload("fortiweb")
            assert code2 == 403
    finally:
        _discovery.visible_appliance_or_404 = orig


def test_registration_refuses_a_product_with_no_editable_catalog(app):
    """FortiAnalyzer / FortiAuthenticator catalogs are seeded and have no
    editor; accepting a write for them would create rows nothing renders."""
    from app.views import _discovery

    with app.test_request_context("/x", method="POST",
                                  data={"appliance_id": "1"}):
        resp, code = _discovery.register_payload("fortianalyzer")
        assert code == 400
        assert "not editable" in resp.get_data(as_text=True)


def test_unsupported_product_is_refused_with_its_reason(app, client):
    from app.services import cli_coverage

    assert "fortianalyzer" not in cli_coverage.SUPPORTED_PRODUCTS
    code = _code_only(VIEW)
    assert "SUPPORTED_PRODUCTS" in code and "UNSUPPORTED_REASON" in code
