"""Guards for the **firmware version** half of the discovery run, and for the
card having exactly ONE appliance selector.

The defect these replace was not cosmetic. The card had two appliance pickers —
"load from" and "ask" — and nothing compared them, while the candidates are
derived from a third thing entirely: the CLI dump the coverage section chose.
Point the run at a different box and every ``absent`` it prints is literally
true and completely misleading, because "this device does not have it" is not
"this path does not exist".

So the run now reads the running firmware off the device, STORES it, and says
how it compares with the line the dump was captured on. Everything below exists
to keep that honest:

* **a comparison nobody could make must not look like one that agreed.** If the
  version read fails, or the dump never recorded a line, the verdict is
  ``unknown`` — never ``same``. That is the single most important guard here;
* **it warns, it never gates.** A run must not be refused on a version verdict,
  because ``unknown`` means OUR read failed and a gate on it would reject a
  legitimate run on the strength of our own outage. Same rule the upgrade
  advisory is built on;
* **the plan still costs the device nothing.** ``plan_payload``'s whole contract
  is zero device contact, and "just one harmless status call" is exactly how
  that contract stops being true;
* **one selector.** Guards that the second one is gone and that a single
  ``askId()`` is the only reader of it.

Trap notes: assertions about source run over docstring/comment-stripped code —
this prose quotes the very identifiers it forbids, and this repo has been
bitten by that nine times. Template assertions strip Jinja ``{# #}`` comments
for the same reason.
"""
from __future__ import annotations

import ast
import io
import os
import re

import pytest

from conftest import admin_user_id, login

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VIEW = os.path.join(REPO, "app", "views", "_discovery.py")
SVC = os.path.join(REPO, "app", "services", "discovery_run.py")
# The run moved off the request thread on 2026-09-15 (nginx cuts a proxied
# request at 120 s; the GETs kept being spent behind a 504). The version rules
# below moved WITH it, so the guards follow the code they protect rather than
# keeping watch over an address it no longer lives at.
JOBS = os.path.join(REPO, "app", "services", "discovery_jobs.py")
TPL = os.path.join(REPO, "app", "templates", "partials", "_discovery_run.html")


def _read(path):
    with io.open(path, encoding="utf-8") as fh:
        return fh.read()


def _func(path, name):
    """The AST of one function with its docstring removed."""
    tree = ast.parse(_read(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            if ast.get_docstring(node):
                node.body = node.body[1:]
            return node
    raise AssertionError("%s not found in %s" % (name, path))


def _body(path, name):
    """Source of one function, docstring AND comments gone."""
    out = ast.unparse(_func(path, name))
    return "\n".join(ln for ln in out.splitlines()
                     if not ln.strip().startswith("#"))


def _tpl_code():
    """The template with Jinja comments stripped — the comments explain the
    guards and would satisfy them on their own."""
    return re.sub(r"\{#.*?#\}", "", _read(TPL), flags=re.S)


# --------------------------------------------------------------------------- #
#  fixtures                                                                    #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def dr():
    from app.services import discovery_run

    return discovery_run


class _Box:
    """The minimum an appliance has to be for the version code to run."""

    def __init__(self, ident=7, name="fortiweb16", kind="fortiweb"):
        self.id, self.name, self.kind = ident, name, kind


def _probe_ok(firmware="FortiWeb-KVM 7.6.8,build1128(GA.M),260602"):
    def _p(appliance):
        return {"ok": True, "firmware": firmware, "changed": False,
                "previous": "", "checked_at": "2026-09-15T18:00:00"}
    return _p


def _evidence(line="7.6", appliance_id=7, name="fortiweb16"):
    return {"line": line, "appliance": name, "appliance_id": appliance_id,
            "firmware": "FortiWeb-KVM %s.8" % line, "created_at": "2026-09-14 03:00"}


# --------------------------------------------------------------------------- #
#  1. the version is READ and STORED, and a failure stores nothing             #
# --------------------------------------------------------------------------- #
def test_detect_version_reads_and_reports_the_line(dr):
    res = dr.detect_version(_Box(), probe=_probe_ok())
    assert res["checked"] is True
    assert res["firmware"].startswith("FortiWeb-KVM 7.6.8")
    # The decorated string the boxes really answer with — the Upgrade Scout
    # round of 2026-09-14 found this exact shape reaching an analyser raw.
    assert res["line"] == "7.6"
    assert res["checked_at"] == "2026-09-15T18:00:00"


def test_detect_version_delegates_the_write_and_does_not_assign_it(dr):
    """The persistence goes through firmware_probe.refresh WHOLE.

    Assigning ``appliance.firmware`` here instead is how
    ``rediscovery.apply_inventory`` came to store a version with no timestamp
    saying when it was observed — a row that cannot say whether it was ever
    checked.
    """
    code = _body(SVC, "detect_version")
    assert "firmware_probe" in code and "refresh" in code
    assert "appliance.firmware" not in code
    assert "firmware_checked_at" not in code


def test_a_failed_read_carries_no_version_at_all(dr):
    res = dr.detect_version(
        _Box(), probe=lambda a: {"ok": False, "error": "device_refused",
                                 "detail": "errcode -20010"})
    assert res["checked"] is False
    assert res["firmware"] == "" and res["line"] == ""
    assert res["error"] == "device_refused" and "-20010" in res["detail"]


def test_a_probe_that_raises_never_escapes(dr):
    def _boom(appliance):
        raise RuntimeError("connection reset")

    res = dr.detect_version(_Box(), probe=_boom)
    assert res["checked"] is False
    assert res["error"] == "unreachable"
    assert "connection reset" in res["detail"]


# --------------------------------------------------------------------------- #
#  2. THE central rule: 'could not compare' is never 'they agree'              #
# --------------------------------------------------------------------------- #
def test_matching_lines_are_same(dr):
    res = dr.version_check(_Box(), _evidence("7.6"), probe=_probe_ok())
    assert res["verdict"] == dr.SAME_LINE
    assert "7.6" in res["reason"]


def test_divergent_lines_are_different_and_the_reason_names_both(dr):
    res = dr.version_check(
        _Box(), _evidence("8.0"),
        probe=_probe_ok("FortiWeb-KVM 7.6.8,build1128(GA.M),260602"))
    assert res["verdict"] == dr.OTHER_LINE
    assert "8.0" in res["reason"] and "7.6" in res["reason"]


def test_an_unreadable_version_is_unknown_never_same(dr):
    """Our read failing says NOTHING about the firmware. It must not render as
    agreement — that is the one sentence this feature could produce that is
    both confident and false."""
    res = dr.version_check(
        _Box(), _evidence("7.6"),
        probe=lambda a: {"ok": False, "error": "unreachable", "detail": ""})
    assert res["verdict"] == dr.UNKNOWN_LINE
    assert res["verdict"] != dr.SAME_LINE
    assert "could not be read" in res["reason"]


def test_a_dump_with_no_line_is_unknown_never_same(dr):
    """Half the vault predates the firmware column. An unlabelled dump is not
    evidence that it matches."""
    res = dr.version_check(_Box(), _evidence(""), probe=_probe_ok())
    assert res["verdict"] == dr.UNKNOWN_LINE
    assert "does not record" in res["reason"]


def test_no_evidence_at_all_is_unknown(dr):
    res = dr.version_check(_Box(), {}, probe=_probe_ok())
    assert res["verdict"] == dr.UNKNOWN_LINE


def test_an_unparsable_version_string_is_unknown(dr):
    res = dr.version_check(_Box(), _evidence("7.6"),
                           probe=_probe_ok("licence expired"))
    assert res["checked"] is True          # the device DID answer
    assert res["line"] == ""               # …with nothing a line reads from
    assert res["verdict"] == dr.UNKNOWN_LINE


def test_the_three_verdicts_are_three_distinct_words(dr):
    assert len({dr.SAME_LINE, dr.OTHER_LINE, dr.UNKNOWN_LINE}) == 3


# --------------------------------------------------------------------------- #
#  3. same_device: compared by id, and 'no evidence' is not 'another device'   #
# --------------------------------------------------------------------------- #
def test_same_device_is_true_only_for_the_same_row(dr):
    same = dr.version_check(_Box(ident=7), _evidence(appliance_id=7),
                            probe=_probe_ok())
    other = dr.version_check(_Box(ident=7), _evidence(appliance_id=9),
                             probe=_probe_ok())
    assert same["same_device"] is True
    assert other["same_device"] is False


def test_same_device_compares_ids_not_names(dr):
    """Two appliances can carry the same name, and a dump keeps the name the
    device had when it was captured. Comparing names would call two different
    boxes the same box."""
    res = dr.version_check(
        _Box(ident=7, name="fortiweb16"),
        _evidence(appliance_id=9, name="fortiweb16"), probe=_probe_ok())
    assert res["same_device"] is False


def test_missing_evidence_id_is_none_not_false(dr):
    """``None`` = there is no evidence to compare. ``False`` = it came off
    another box. Folding them prints a divergence warning for a page that has
    no dump at all."""
    res = dr.version_check(_Box(), {"line": "7.6"}, probe=_probe_ok())
    assert res["same_device"] is None


# --------------------------------------------------------------------------- #
#  4. it WARNS — it must never become a gate                                   #
# --------------------------------------------------------------------------- #
def test_no_branch_in_the_run_worker_tests_the_version_verdict():
    """A refusal built on this vocabulary would reject a legitimate run because
    OUR read failed: ``unknown`` is a statement about us, not about the box."""
    node = _func(JOBS, "_execute")
    tests = [ast.unparse(n.test) for n in ast.walk(node) if isinstance(n, ast.If)]
    for t in tests:
        assert "verdict" not in t, t
        assert "version" not in t, t
        assert "OTHER_LINE" not in t and "UNKNOWN_LINE" not in t, t


def test_a_divergent_line_still_runs_the_probes(app, client, monkeypatch, dr):
    """End to end: the verdict is reported, the run happens anyway.

    Now through the JOB, because that is where the run lives. The worker is
    dispatched inline so this stays a guard about the version rule and not a
    race with a daemon thread.
    """
    from app.models import Appliance, db
    from app.services import firmware_probe, jobs
    from app.views import _discovery as view

    with app.app_context():
        a = Appliance(name="fw-diverge", host="192.0.2.222", port=443,
                      kind="fortiweb", username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        aid = a.id
    monkeypatch.setattr(firmware_probe, "refresh", _probe_ok())
    monkeypatch.setattr("app.services.rediscovery.probe_endpoint",
                        lambda _a, urn: ([], dr.ABSENT, "-20001"))
    # The dump says 8.0; the box answers 7.6. The run must still happen.
    rep = {"chosen": {"appliance": "fortiweb17", "appliance_id": 4242,
                      "line": "8.0", "created_at": "2026-09-14 22:46"},
           "diff": {}}
    rows = [dr.Finding(path="log alertmail", name="log.alertmail",
                       candidates=[dr.Candidate(urn="log/alertmail")])]
    monkeypatch.setattr(view, "_findings_for", lambda *a, **k: (rep, rows, {}, {}))

    def _inline(flask_app, job_id, worker):
        result = worker(flask_app, job_id)
        st = jobs.get_job(job_id) or {}
        if st.get("status") in jobs._ACTIVE:
            jobs.finish_success(job_id, result=result)

    monkeypatch.setattr(jobs, "run_async", _inline)
    login(client, admin_user_id(app))
    r = client.post("/web/api-explorer/discovery/run",
                    data={"appliance_id": aid, "budget": 2})
    assert r.status_code == 200
    jid = r.get_json()["job_id"]
    body = jobs.get_job(jid)["result"]
    assert body["ok"] is True
    assert body["version"]["line"] == "7.6"
    assert body["version"]["verdict"] == dr.OTHER_LINE
    # reported, NOT refused: the probes ran anyway
    assert body["spent"] == 1
    for key in ("evidence", "evidence_line", "evidence_captured", "same_device"):
        assert key in body, key


def test_the_payload_names_its_evidence_and_its_firmware():
    """Both halves ride in the response. The page cannot warn about a
    divergence whose two sides it was never told.

    Scoped to the dict LITERAL: the audit row a few lines below spells
    ``evidence_line`` too, so a whole-function assertion stayed green with the
    key dropped from the payload.
    """
    code = _body(JOBS, "_execute")
    prov = code[code.index("provenance = {"):]
    prov = prov[:prov.index("}") + 1]
    for key in ("'evidence'", "'evidence_line'", "'same_device'", "'version'"):
        assert key in prov, key


def test_the_provenance_reaches_the_non_empty_answer_too():
    """Two returns, two chances to forget it. The early one (no CLI-only block
    to ask about) builds the payload WITH the provenance; the real one has to
    merge it in, and that is the path a run with findings takes."""
    code = _body(JOBS, "_execute")
    assert "out.update(provenance)" in code


def test_the_audit_row_records_the_firmware_and_the_verdict():
    """The page can be closed; 'which firmware were those verdicts about?'
    outlives it, and re-deriving it later reads TODAY's version off a box that
    may since have been upgraded."""
    code = _body(JOBS, "_execute")
    log = code[code.index("log_action"):]
    assert "'firmware'" in log
    assert "'version_verdict'" in log
    assert "'evidence'" in log


# --------------------------------------------------------------------------- #
#  5. the plan still costs the device nothing                                  #
# --------------------------------------------------------------------------- #
def test_plan_never_touches_the_device():
    code = _body(VIEW, "plan_payload")
    for forbidden in ("version_check", "detect_version", "firmware_probe",
                      "probe_endpoint", "rediscovery"):
        assert forbidden not in code, forbidden


def test_plan_still_names_its_evidence_line():
    code = _body(VIEW, "plan_payload")
    assert "'evidence_line'" in code


# --------------------------------------------------------------------------- #
#  6. the load pass reads the version too, and says so when it cannot          #
# --------------------------------------------------------------------------- #
def test_load_detects_the_version_and_reports_a_failure():
    code = _body(VIEW, "load")
    assert "detect_version" in code
    # The failure branch must SAY something. A silent miss leaves the stored
    # version in place and looks exactly like a successful read.
    assert "could NOT be read" in code or "could not be read" in code


def test_load_does_not_abort_the_sweep_on_a_version_failure():
    """The sweep is the point; the version is inventory. Ordering matters: the
    read happens after ``rediscovery.start`` has already been accepted."""
    code = _body(VIEW, "load")
    assert code.index("rediscovery.start") < code.index("detect_version")


# --------------------------------------------------------------------------- #
#  7. ONE appliance selector                                                   #
# --------------------------------------------------------------------------- #
def test_the_second_appliance_selector_is_gone():
    assert "drLoadAppliance" not in _tpl_code()


def test_the_card_has_exactly_one_select_and_no_second_picker():
    """ONE picker. This card has grown a second one twice — a peer that
    disagreed with it, and an override that aimed the GETs at a box on another
    build — so both are guarded by name, not just by the count."""
    code = _tpl_code()
    assert code.count("<select") == 1, code.count("<select")
    assert 'id="drAppliance"' in code
    assert "drLoadAppliance" not in code
    assert "drAskOther" not in code


def test_the_one_selector_drives_the_load_form_too():
    """It lives outside the <form> and is tied to it by id — that is what makes
    it genuinely one control rather than two that agree by convention."""
    code = _tpl_code()
    tag = code[code.index('id="drAppliance"') - 300:
               code.index('id="drAppliance"') + 200]
    assert 'name="appliance_id"' in tag
    assert 'form="drLoadForm"' in tag
    assert 'id="drLoadForm"' in code


def test_only_ask_id_reads_the_selector():
    """Every action (plan, run, register) asks the same function. A second
    reader is how the two selectors disagreed in the first place."""
    code = _tpl_code()
    assert code.count("getElementById('drAppliance').value") == 1
    fn = re.search(r"function askId\(\)\s*\{(.*?)\n  \}", code, re.S).group(1)
    ret = [ln for ln in fn.splitlines() if "return" in ln]
    assert len(ret) == 1, ret
    assert "drAppliance" in ret[0], ret[0]
    # Never an empty id: the run route answers that with a 400, which on screen
    # is indistinguishable from a button that does nothing.
    assert "|| ''" in ret[0], ret[0]


def test_register_and_run_both_go_through_ask_id():
    code = _tpl_code()
    assert code.count("askId()") >= 3


# --------------------------------------------------------------------------- #
#  8. the page shows both halves, and 'unknown' gets its own badge             #
# --------------------------------------------------------------------------- #
def test_the_evidence_is_rendered_not_implied():
    code = _tpl_code()
    assert 'id="drEvidence"' in code
    assert 'id="drMismatch"' in code


def test_three_verdicts_three_badges():
    code = _tpl_code()
    block = code[code.index("var VERBADGE"):]
    block = block[:block.index("};") + 2]
    for word in ("'same'", "'different'", "'unknown'"):
        assert word in block, word
    classes = set(re.findall(r"\['(\w+)',", block))
    assert len(classes) == 3, classes
    # 'unknown' must not borrow the success colour: a comparison nobody could
    # make would then be indistinguishable from one that agreed.
    assert "success" not in block[block.index("'unknown'"):]


def test_the_run_handler_renders_the_provenance():
    """The verdict is computed server-side and then has to reach the screen.
    A payload nobody renders is a comparison nobody sees."""
    code = _tpl_code()
    handler = code[code.index("if (run) {"):]
    handler = handler[:handler.index("{% if dr_register_endpoint %}")]
    assert "provenance(d)" in handler


def test_the_page_renders_with_the_new_card(app, client):
    """The card moved to the API-versions page on 2026-09-16.

    Retargeted rather than deleted: the rule it protects — ONE appliance
    selector, and the two-picker regression stays dead — is exactly as
    load-bearing on the page the card lives on now.
    """
    login(client, admin_user_id(app))
    r = client.get("/web/registry/versions")
    assert r.status_code == 200
    page = r.get_data(as_text=True)
    assert 'id="drAppliance"' in page
    assert "drLoadAppliance" not in page
    # ...and the hub it left points at it instead of having silently lost it.
    hub = client.get("/web/api-explorer/").get_data(as_text=True)
    assert 'id="drAppliance"' not in hub
    assert "moved to the API-versions page" in hub


# --------------------------------------------------------------------------- #
#  10. the three scan controls are gone, and stay gone                         #
# --------------------------------------------------------------------------- #
def test_the_card_carries_no_override_budget_or_configured_only_control():
    code = _tpl_code()
    for gone in ("drAskOther", "drBudget", "drConfigured",
                 "Ask a different appliance", "GET budget",
                 "only blocks that hold configuration here"):
        assert gone not in code, gone


def test_the_run_sends_no_budget_field_AT_ALL():
    """Not "sends an empty one". ``_int_arg`` parses whatever arrives, so an
    empty budget is a number, not an absence: the run would stop after a single
    GET and still report itself finished. Absent is the only safe form, because
    absent is what makes the server's own default apply."""
    import re as _re
    code = _tpl_code()
    fn = _re.search(r"function body\(extra\)\s*\{(.*?)\n  \}", code, _re.S).group(1)
    assert "budget" not in fn, fn
    assert "configured_only" not in fn, fn


def test_the_footnote_does_not_point_at_a_control_that_is_gone():
    """A page that tells the operator to raise a budget it no longer shows is a
    dead end. The DISTINCTION the sentence exists for has to survive the edit:
    a block nobody asked about is not a block the device denied."""
    code = _tpl_code()
    assert "raise the budget" not in code
    assert "nobody asked" in code
