"""Guards for the version-scoped pages (rounds 2 and 3 of 2026-09-16).

One defect, three pages. Every one of them derived a firmware-specific answer
from ``cli_coverage.report(product)`` with no firmware argument — which returns
whichever stored dump sorts first — and then never named it:

* the **API hub**'s transport badges (``cli`` / ``api`` / ``both``) are computed
  from that dump for all ~517 catalog entries;
* the **discovery run** derived its candidate paths from it and probed them
  against whatever appliance a second, unrelated picker offered;
* **/web/structure/** cross-references the whole dependency tree against it,
  and its CLI-only subtree and clone gap come out of the same object.

None of that errors. It renders a full page and answers confidently about a
build nobody chose. These guards pin the fix: the scope is explicit, it is a
FILTER and never a fallback, and a page with no scope says so instead of
implying one.
"""
from __future__ import annotations

import ast
import io
import os

import pytest

from app.extensions import db
from app.models import Appliance
from app.services import api_matrix as am
from app.services import cli_coverage, firmware_versions as fv
from tests.conftest import admin_user_id, login

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture()
def isolated(app, session, tmp_path, monkeypatch):
    red = tmp_path / "rediscovery"
    mat = tmp_path / "api_matrix"
    sch = tmp_path / "field_schemas"
    for p in (red, sch, mat):
        p.mkdir()
    monkeypatch.setattr(am, "REDISCOVERY_ROOT", str(red))
    monkeypatch.setattr(am, "SCHEMA_ROOT", str(sch))
    monkeypatch.setattr(am, "MATRIX_ROOT", str(mat))
    monkeypatch.setenv("SATOM_REDISCOVERY_DIR", str(red))
    return {"rediscovery": red, "api_matrix": mat}


def _box(name, firmware="8.0.5", kind="fortiweb"):
    a = Appliance(name=name, kind=kind, host="%s.test" % name, port=443,
                  username="admin", verify_ssl=False, firmware=firmware)
    a.password = "secret"
    db.session.add(a)
    db.session.commit()
    return a


def _sweep(isolated, box, version, **verdicts):
    import json
    d = isolated["rediscovery"] / str(box.id) / "by-version"
    d.mkdir(parents=True, exist_ok=True)
    (d / ("%s.json" % version)).write_text(json.dumps({
        "device": box.name, "appliance_id": box.id, "firmware": version,
        "generated_at": "2099-01-01T00:00:00",
        "endpoint_status": {k: {"verdict": v, "urn": "cmdb/%s" % k, "section": "S"}
                            for k, v in verdicts.items()},
        "sections": {},
    }))


@pytest.fixture()
def recorder(monkeypatch):
    """Capture every ``cli_coverage.report`` call the request makes.

    Asserting on the CALL, not on the rendered page: a page can look right
    while resting on the wrong dump, and that is precisely the failure mode
    these rounds exist for.
    """
    seen: list = []
    real = cli_coverage.report

    def spy(product, backup_id=None, *, line="", version=""):
        seen.append({"product": product, "backup_id": backup_id,
                     "line": line, "version": version})
        return real(product, backup_id, line=line, version=version)

    # Patched on the MODULE, not on each importer: all three views reach the
    # same object, and three separate patches of one attribute would restore in
    # an order that is only accidentally correct.
    monkeypatch.setattr(cli_coverage, "report", spy, raising=True)
    return seen


# ===========================================================================
# round 2 — the discovery run knows its build
# ===========================================================================

def test_the_scope_is_normalised_not_trusted(app):
    from app.views import _discovery
    with app.test_request_context("/", method="POST",
                                  data={"version": "8.0.5,build0123"}):
        assert _discovery._scope_arg() == "8.0.5"
    with app.test_request_context("/", method="POST", data={"version": "junk"}):
        assert _discovery._scope_arg() == ""


def test_the_plan_derives_its_candidates_from_the_scoped_dump(isolated, client, app, recorder):
    login(client, admin_user_id(app))
    client.post("/api-explorer/discovery/plan", data={"version": "8.0.5"})
    assert recorder, "the plan never asked for evidence at all"
    assert recorder[-1]["version"] == "8.0.5"


def test_the_plan_names_the_build_its_cost_was_quoted_against(isolated, client, app):
    login(client, admin_user_id(app))
    r = client.post("/api-explorer/discovery/plan", data={"version": "8.0.5"})
    assert r.status_code == 200
    assert r.get_json()["scope"] == "8.0.5"
    assert "evidence_version" in r.get_json()


def test_a_run_carries_its_build_into_the_audit_log(isolated, client, app):
    """The page closes; "which build were those verdicts about?" does not stop
    being asked."""
    box = _box("fw1", firmware="8.0.5")
    login(client, admin_user_id(app))
    r = client.post("/api-explorer/discovery/run",
                    data={"appliance_id": box.id, "version": "8.0.5"})
    assert r.status_code == 200
    from app.models import AuditLog
    row = (AuditLog.query.filter_by(action="discovery_run.start")
           .order_by(AuditLog.id.desc()).first())
    payload = r.get_json()
    if payload.get("started"):
        assert row is not None and "8.0.5" in str(row.extra)
    else:
        # Nothing to ask about is a complete answer — and it still names the
        # build, because "no CLI-only block" is a claim about one firmware.
        assert payload["scope"] == "8.0.5"


def test_the_card_context_exposes_the_build_and_the_boxes_running_it(app):
    from app.views import _discovery
    with app.test_request_context("/"):
        ctx = _discovery.context("fortiweb", run_endpoint="x.y",
                                 scope="8.0.5", scope_appliances=[1, 2])
    assert ctx["dr_scope"] == "8.0.5"
    assert ctx["dr_scope_appliances"] == [1, 2]


def test_an_unscoped_card_behaves_exactly_as_before(app):
    """The hubs with no version axis still include this partial; an empty scope
    must not turn into a filter that silently hides every appliance."""
    from app.views import _discovery
    with app.test_request_context("/"):
        ctx = _discovery.context("fortiweb", run_endpoint="x.y")
    assert ctx["dr_scope"] == ""
    assert ctx["dr_scope_appliances"] == []


# ---- the move --------------------------------------------------------------

def test_every_version_row_offers_a_discovery_run_for_ITS_build(isolated, client, app):
    box = _box("fw1", firmware="8.0.5")
    _sweep(isolated, box, "8.0.5", shared="ok")
    am.rebuild("fortiweb")
    login(client, admin_user_id(app))
    body = client.get("/web/registry/versions").get_data(as_text=True)
    assert "discover=8.0.5" in body


def test_the_card_is_rendered_ONCE_however_many_rows_there_are(isolated, client, app):
    """Per-row panels would mean N pollers, N Stop buttons and N jobs competing
    for one appliance's session limit."""
    a, b = _box("fw1", firmware="7.6.8"), _box("fw2", firmware="8.0.5")
    _sweep(isolated, a, "7.6.8", shared="ok")
    _sweep(isolated, b, "8.0.5", shared="ok")
    am.rebuild("fortiweb")
    login(client, admin_user_id(app))
    body = client.get("/web/registry/versions?discover=8.0.5").get_data(as_text=True)
    assert body.count('id="discoveryRun"') == 1


def test_choosing_a_row_scopes_the_appliance_picker_to_that_build(isolated, client, app):
    a, b = _box("old76", firmware="7.6.8"), _box("new80", firmware="8.0.5")
    _sweep(isolated, a, "7.6.8", shared="ok")
    _sweep(isolated, b, "8.0.5", shared="ok")
    am.rebuild("fortiweb")
    login(client, admin_user_id(app))
    body = client.get("/web/registry/versions?discover=8.0.5").get_data(as_text=True)
    picker = body.split('id="drAppliance"')[1].split("</select>")[0]
    assert "new80" in picker
    assert "old76" not in picker


def test_NO_control_in_the_card_can_aim_the_gets_at_another_build(isolated, client, app):
    """The override that sent the GETs to a box on another build is gone. This
    replaces the guard that required it: a box off the build is now offered
    nowhere in the card, so an answer can no longer describe a firmware the
    evidence was never captured on. The whole control area is read, not just
    the picker — the defect this forbids is a SECOND control, which by
    definition would not be inside the first one."""
    _box("old76", firmware="7.6.8")
    b = _box("new80", firmware="8.0.5")
    _sweep(isolated, b, "8.0.5", shared="ok")
    am.rebuild("fortiweb")
    login(client, admin_user_id(app))
    body = client.get("/web/registry/versions?discover=8.0.5").get_data(as_text=True)
    controls = body.split('id="discoveryRun"')[1].split('id="drResultWrap"')[0]
    assert "new80" in controls
    assert "old76" not in controls
    assert "drAskOther" not in body


def test_an_unknown_build_scopes_to_NOTHING_not_to_whatever_sorted_first(isolated, client, app):
    box = _box("fw1", firmware="8.0.5")
    _sweep(isolated, box, "8.0.5", shared="ok")
    am.rebuild("fortiweb")
    login(client, admin_user_id(app))
    body = client.get("/web/registry/versions?discover=9.9.9").get_data(as_text=True)
    assert "Scoped to build" not in body


def test_the_discovery_card_has_left_the_api_hubs_and_says_where_it_went():
    """Deleted, it teaches that the feature was removed. Moved with a pointer,
    it teaches that the question needed a firmware to be asked about."""
    for rel in ("app/templates/api_explorer/index.html",
                "app/templates/adc_api/index.html"):
        src = io.open(os.path.join(ROOT, rel), encoding="utf-8").read()
        assert '{% include "partials/_discovery_run.html" %}' not in src, rel
        assert "moved to the API-versions page" in src, rel
        assert "api_versions" in src, rel


def test_the_hub_names_the_build_behind_its_transport_badges():
    src = io.open(os.path.join(ROOT, "app/templates/api_explorer/index.html"),
                  encoding="utf-8").read()
    assert "CLI evidence:" in src
    assert "no CLI dump captured on build" in src


def test_the_hub_forwards_a_build_from_the_url_to_the_report(isolated, client, app, recorder):
    login(client, admin_user_id(app))
    client.get("/api-explorer/?version=8.0.5")
    assert any(c["version"] == "8.0.5" for c in recorder), recorder


def test_the_hub_without_a_build_asks_for_no_filter_at_all(isolated, client, app, recorder):
    """Empty is empty. A default build here would be the original defect with a
    friendlier name."""
    login(client, admin_user_id(app))
    client.get("/api-explorer/")
    assert recorder and all(c["version"] == "" for c in recorder)


# ===========================================================================
# round 3 — /web/structure/ gains the firmware axis
# ===========================================================================

def test_the_structure_view_no_longer_asks_for_an_unfiltered_report():
    """The whole page — badges, CLI-only subtree, clone gap — comes out of this
    one call. Asserted on the CALL NODE, because the words ``version`` and
    ``line`` appear in the surrounding prose either way."""
    src = io.open(os.path.join(ROOT, "app/views/structure.py"),
                  encoding="utf-8").read()
    tree = ast.parse(src)
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Attribute)
             and n.func.attr == "report"
             and isinstance(n.func.value, ast.Name)
             and n.func.value.id == "cli_coverage"]
    assert calls, "the page stopped asking for CLI evidence entirely"
    for call in calls:
        kw = {k.arg for k in call.keywords}
        assert {"version", "line"} <= kw, ast.dump(call)


def test_a_build_scope_filters_the_cli_evidence(isolated, client, app, recorder):
    box = _box("fw1", firmware="8.0.5")
    _sweep(isolated, box, "8.0.5", shared="ok")
    am.rebuild("fortiweb")
    login(client, admin_user_id(app))
    client.get("/web/structure/?scope=8.0.5")
    assert any(c["version"] == "8.0.5" and c["line"] == "" for c in recorder), recorder


def test_a_line_scope_filters_by_line_and_not_by_build(isolated, client, app, recorder):
    box = _box("fw1", firmware="8.0.5")
    _sweep(isolated, box, "8.0.5", shared="ok")
    am.rebuild("fortiweb")
    login(client, admin_user_id(app))
    client.get("/web/structure/?scope=8.0")
    assert any(c["line"] == "8.0" and c["version"] == "" for c in recorder), recorder


def test_an_unknown_scope_is_dropped_and_the_page_says_it_has_none(isolated, client, app):
    _box("fw1", firmware="8.0.5")
    login(client, admin_user_id(app))
    body = client.get("/web/structure/?scope=9.9.9").get_data(as_text=True)
    assert "No firmware chosen" in body


def test_with_no_scope_the_serves_it_column_is_blank_not_unmeasured(isolated, client, app):
    """``None`` is "nobody asked about a firmware". ``unmeasured`` is "we asked
    and there is no evidence". Rendering the first as the second puts a claim
    where a question mark belongs."""
    box = _box("fw1", firmware="8.0.5")
    _sweep(isolated, box, "8.0.5", server_policy_policy="ok")
    am.rebuild("fortiweb")
    login(client, admin_user_id(app))
    r = client.get("/web/structure/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "No firmware chosen" in body
    assert "absent on this build" not in body


def test_the_three_api_verdicts_stay_three(isolated, client, app):
    src = io.open(os.path.join(ROOT, "app/templates/structure/index.html"),
                  encoding="utf-8").read()
    for word in ("served", "absent on this build", "unmeasured", "could not ask"):
        assert word in src, word


def test_a_scoped_page_reports_served_absent_and_unmeasured_apart(isolated, client, app):
    box = _box("fw1", firmware="8.0.5")
    # Two real endpoint names out of the dependency tree, with opposite
    # verdicts, so the column has something to distinguish.
    _sweep(isolated, box, "8.0.5",
           server_policy_policy="ok", waf_web_protection_profile_inline="absent")
    am.rebuild("fortiweb")
    login(client, admin_user_id(app))
    body = client.get("/web/structure/?scope=8.0.5").get_data(as_text=True)
    assert "No firmware chosen" not in body
    # every node the sweep never mentioned must read as unmeasured, not absent
    assert "unmeasured" in body


def test_a_line_rollup_scope_warns_that_it_merged_builds(isolated, client, app):
    a, b = _box("a", firmware="8.0.3"), _box("b", firmware="8.0.5")
    _sweep(isolated, a, "8.0.3", server_policy_policy="ok")
    _sweep(isolated, b, "8.0.5", server_policy_policy="ok")
    am.rebuild("fortiweb")
    login(client, admin_user_id(app))
    body = client.get("/web/structure/?scope=8.0").get_data(as_text=True)
    assert "This is a line rollup" in body
    assert "8.0.3" in body and "8.0.5" in body


def test_the_TREE_itself_is_deliberately_not_versioned():
    """``dependencies.ROOTS`` is a hand-authored map, not a measurement.
    Minting a per-build structure nobody measured would be inventing evidence,
    so ``load_catalog`` takes the overlay and nothing else — and the decision is
    pinned here rather than left to be quietly reversed."""
    src = io.open(os.path.join(ROOT, "app/views/structure.py"),
                  encoding="utf-8").read()
    tree = ast.parse(src)
    call = next(n for n in ast.walk(tree)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "load_catalog")
    assert len(call.args) == 1 and not call.keywords
    assert "deliberately NOT versioned" in src


def test_the_scope_selector_lists_builds_before_rollups(isolated, client, app):
    box = _box("fw1", firmware="8.0.5")
    _sweep(isolated, box, "8.0.5", shared="ok")
    am.rebuild("fortiweb")
    login(client, admin_user_id(app))
    body = client.get("/web/structure/").get_data(as_text=True)
    sel = body.split('name="scope"')[1].split("</select>")[0]
    assert sel.index('value="8.0.5"') < sel.index('value="8.0"')
    assert "line rollup" in sel


def test_the_structure_evidence_line_names_the_build(isolated, client, app):
    src = io.open(os.path.join(ROOT, "app/templates/structure/index.html"),
                  encoding="utf-8").read()
    assert "cli_evidence.version" in src


# ===========================================================================
# gaps the mutation harness found — five survivors, all mine
# ===========================================================================

def test_the_start_audit_row_carries_the_scope():
    """Asserted on the dict LITERAL, not on the function.

    A test that drives a real run needs a CLI dump in the vault; without one
    the route takes its early return and the audit call is never reached, so a
    guard written against the response passes while the log loses the build.
    The literal is what the mutation removes, so the literal is what is
    checked.
    """
    src = io.open(os.path.join(ROOT, "app/views/_discovery.py"),
                  encoding="utf-8").read()
    tree = ast.parse(src)
    call = next(n for n in ast.walk(tree)
                if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name) and n.func.id == "log_action"
                and n.args and getattr(n.args[0], "value", "") == "discovery_run.start")
    extra = next(k.value for k in call.keywords if k.arg == "extra")
    keys = {getattr(k, "value", None) for k in extra.keys}
    assert "scope" in keys, sorted(str(k) for k in keys)


def test_the_card_announces_the_build_it_is_scoped_to(isolated, client, app):
    """The positive half of the unknown-build guard. Without it the banner can
    be deleted outright and only the negative assertion survives — which then
    passes for the wrong reason, forever."""
    box = _box("fw1", firmware="8.0.5")
    _sweep(isolated, box, "8.0.5", shared="ok")
    am.rebuild("fortiweb")
    login(client, admin_user_id(app))
    body = client.get("/web/registry/versions?discover=8.0.5").get_data(as_text=True)
    assert "Scoped to build" in body
    assert "<code>8.0.5</code>" in body


def test_the_page_posts_the_build_with_every_plan_and_run(isolated, client, app):
    """The cost quoted by "What would it cost?" and the GETs the run actually
    spends must be derived from the SAME dump. Leaving the build to the URL
    lets them disagree."""
    box = _box("fw1", firmware="8.0.5")
    _sweep(isolated, box, "8.0.5", shared="ok")
    am.rebuild("fortiweb")
    login(client, admin_user_id(app))
    body = client.get("/web/registry/versions?discover=8.0.5").get_data(as_text=True)
    assert "fd.append('version', '8.0.5')" in body


def test_the_card_evidence_names_the_build_not_only_the_line():
    src = io.open(os.path.join(ROOT, "app/templates/partials/_discovery_run.html"),
                  encoding="utf-8").read()
    assert "dr_ev.version" in src


def test_an_unscoped_structure_page_renders_NO_verdict_at_all(isolated, client, app):
    """``None`` must reach the template as a dash, not as a word.

    ``unmeasured`` is an answer — "we asked and there is no evidence". With no
    firmware chosen nobody asked anything, and printing an answer there is a
    claim where a question mark belongs.
    """
    box = _box("fw1", firmware="8.0.5")
    _sweep(isolated, box, "8.0.5", server_policy_policy="ok")
    am.rebuild("fortiweb")
    login(client, admin_user_id(app))
    body = client.get("/web/structure/").get_data(as_text=True)
    assert "No firmware chosen" in body
    assert "unmeasured" not in body


# ===========================================================================
# round 4 — the capture comes BACK to the card (2026-09-16)
# ===========================================================================
# The card moved to this page on 2026-09-16; the redirect that follows a
# capture did not move with it, so every "Load API catalog + CLI configuration"
# landed on the API hub — which now carries only a pointer. The sweep ran to
# completion (measured: 326 endpoints and a 479 KB dump, archived under
# by-version/8.0.5.json) while the operator watched a page that cannot render
# a single one of its phases. Nothing errored; the work simply became
# invisible. These guards pin the return.

LOAD_URL = "/web/api-explorer/discovery/load"


@pytest.fixture()
def no_device(monkeypatch):
    """The sweep is STARTED and never run: this round is about where the
    browser lands, and a real start reaches for a REST session and SSH."""
    from app.services import rediscovery
    from app.views import _discovery as dv

    seen = {"started": 0}

    def fake_start(appliance, by="", cli=True):
        seen["started"] += 1
        seen["appliance"] = appliance.id
        seen["cli"] = cli
        return {"started": True}

    monkeypatch.setattr(rediscovery, "start", fake_start, raising=True)
    monkeypatch.setattr(dv.discovery_run, "detect_version",
                        lambda a: {"checked": True, "firmware": "8.0.5"},
                        raising=True)
    return seen


def _fw17(isolated, client, app):
    box = _box("fw17", firmware="8.0.5")
    _sweep(isolated, box, "8.0.5", shared="ok")
    am.rebuild("fortiweb")
    login(client, admin_user_id(app))
    return box


def test_the_capture_returns_to_the_page_that_MOUNTS_the_card(isolated, client, app, no_device):
    box = _fw17(isolated, client, app)
    r = client.post(LOAD_URL, data={"appliance_id": box.id, "version": "8.0.5"})
    assert r.status_code == 302
    loc = r.headers["Location"]
    assert "/web/registry/versions" in loc, loc
    assert "/api-explorer" not in loc, (
        "the capture landed back on the hub the card LEFT — %s" % loc)
    assert loc.endswith("#discoveryRun"), loc


def test_the_build_the_row_chose_survives_the_capture(isolated, client, app, no_device):
    """Without it the operator returns to an UNSCOPED card: candidates derived
    from whichever dump sorts first, one redirect after choosing a build."""
    box = _fw17(isolated, client, app)
    r = client.post(LOAD_URL, data={"appliance_id": box.id, "version": "8.0.5"})
    assert "discover=8.0.5" in r.headers["Location"]


def test_the_return_tells_the_card_which_sweep_to_watch(isolated, client, app, no_device):
    box = _fw17(isolated, client, app)
    r = client.post(LOAD_URL, data={"appliance_id": box.id, "version": "8.0.5"})
    assert "dr_watch=%d" % box.id in r.headers["Location"]


def test_the_landing_page_can_actually_SHOW_the_run(isolated, client, app, no_device):
    """The whole point, and asserted on the rendered page rather than on the
    Location header: a redirect to a page without the card is exactly the bug."""
    box = _fw17(isolated, client, app)
    body = client.post(LOAD_URL, data={"appliance_id": box.id, "version": "8.0.5"},
                       follow_redirects=True).get_data(as_text=True)
    assert 'id="discoveryRun"' in body
    assert "Scoped to build" in body
    assert 'data-dr-watch="%d"' % box.id in body, (
        "the poller was not handed the appliance, so the card renders idle "
        "while the sweep it just started runs")


def test_a_sweep_that_never_STARTED_comes_back_the_same_way(isolated, client, app,
                                                            monkeypatch, no_device):
    """The failure exits used to redirect somewhere else than the success one,
    which is how a 'could not start' message arrived on a page with no card to
    explain it against."""
    from app.services import rediscovery
    monkeypatch.setattr(rediscovery, "start",
                        lambda appliance, by="", cli=True: {
                            "started": False, "reason": "a sweep is already running"},
                        raising=True)
    box = _fw17(isolated, client, app)
    r = client.post(LOAD_URL, data={"appliance_id": box.id, "version": "8.0.5"})
    loc = r.headers["Location"]
    assert "/web/registry/versions" in loc and "discover=8.0.5" in loc, loc
    assert "dr_watch" not in loc, (
        "nothing was started, so nothing must be polled — a watcher on a sweep "
        "that never began prints an empty status for ever")


def _fn_source(module: str, name: str) -> str:
    tree = ast.parse(io.open(os.path.join(ROOT, "app", "views", "%s.py" % module),
                             encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.unparse(node)
    raise AssertionError("%s.%s does not exist" % (module, name))


def _load_target(hub: str) -> str:
    """The page endpoint a hub's load route hands to ``_discovery.load``."""
    tree = ast.parse(io.open(os.path.join(ROOT, "app", "views", "%s.py" % hub),
                             encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "_discovery.load":
            return node.args[1].value
    raise AssertionError("%s never calls _discovery.load" % hub)


@pytest.mark.parametrize("hub", ["api_explorer", "adc_api"])
def test_every_load_route_returns_to_a_page_that_MOUNTS_the_card(hub):
    """Derived in two hops, because a hard-coded endpoint name is exactly what
    went stale: the card moved and this string kept naming the hub it left.

    Hop 1: the only template that mounts the card is the shared API-versions
    page. Hop 2: the endpoint the route names must be served by a view that
    renders that shared page. FortiADC is covered by the same parametrisation
    because its twin route had the identical bug.
    """
    inc = '{% include "partials/_discovery_run.html" %}'
    assert inc in io.open(os.path.join(ROOT, "app", "templates", "registry",
                                       "versions.html"), encoding="utf-8").read()
    target = _load_target(hub)
    module, fn = target.split(".")
    assert "_apiversions.render_page" in _fn_source(module, fn), (
        "%s sends the operator to %s, which does not render the page that "
        "mounts the discovery card" % (hub, target))


def test_an_appliance_of_the_WRONG_product_comes_back_the_same_way(isolated, client,
                                                                   app, no_device):
    """The third exit of ``load``, and the one a mutation proved unguarded.

    All three exits — wrong product, sweep refused, sweep started — have to
    land on the page that mounts the card, because all three carry a flash
    message that only means something next to the control it is about. This
    one is the easiest to leave behind: it fires before any device work, so it
    was written as a bare ``redirect(url_for(page_endpoint))`` and nothing
    followed it when the card moved.

    Reaching it takes an UNSTAMPED row, not another product's: the URL scope
    wins over the session (``product_scope.session_product``), so a FortiADC
    box posted to a ``/web/`` route is 404'd by the loader and never reaches
    this branch. The FortiWeb ADOM does, however, see rows with no ``kind`` —
    they predate stamping — and those arrive here. That is what the branch is
    for, and it is why it cannot be deleted instead of guarded.

    Nothing was started, so nothing may be polled.
    """
    _fw17(isolated, client, app)
    legacy = _box("legacy01", firmware="8.0.5", kind="")
    r = client.post(LOAD_URL, data={"appliance_id": legacy.id, "version": "8.0.5"})
    assert r.status_code == 302, (r.status_code, r.get_data(as_text=True)[:400])
    loc = r.headers["Location"]
    assert "/web/registry/versions" in loc, loc
    assert "/api-explorer" not in loc, (
        "the wrong-product refusal landed on the hub the card LEFT — %s" % loc)
    assert "discover=8.0.5" in loc, loc
    assert "dr_watch" not in loc, (
        "no sweep was started, so the card must not poll one")
    assert no_device["started"] == 0, (
        "the product check must refuse BEFORE the device is touched")
