"""Guards for Scout on the Upgrade page.

The feature is small; the failure modes are not, and they are all the same
shape — **a review that did not happen must never look like a review that came
back clean.** An empty green panel above a live-flash button is worse than no
panel at all, because it converts "nobody checked" into "somebody checked and it
was fine", and it does so on the one screen where that sentence reboots a box.

So the guards below spend most of their weight on the negative space:

* Scout switched off, not asked, unsupported product, unknown running version,
  unreadable corpus — each has its OWN reason, and none of them can spell itself
  ``clear``;
* a corpus with no rows for the move returns ``unknown`` WITH its gaps, never a
  clean verdict;
* the panel on the page reviews the image the picker will actually post — a
  verdict for 7.6.4 sitting above a button that flashes 8.0.7 is a lie told in
  the most expensive place available;
* Scout advises and does not authorise: a ``blocker`` does not refuse the flash,
  because the verdict's own vocabulary includes ``unknown`` for gaps in OUR
  corpus and a gate built on that refuses upgrades over our own missing data.

Trap notes for whoever edits this file: assertions about CODE run over
:func:`_code_only`, because the comments here quote the very strings they
forbid — this repo has been bitten by that nine times. Assertions about MARKUP
that concern a class or id are split from the selector that consults it, for the
same reason.
"""
from __future__ import annotations

import ast
import io
import json
import os

import pytest

from conftest import admin_user_id, login

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VIEW = os.path.join(REPO, "app", "views", "appliances.py")
RNVIEW = os.path.join(REPO, "app", "views", "release_notes.py")
SVC = os.path.join(REPO, "app", "services", "upgrade_scout.py")
TPL = os.path.join(REPO, "app", "templates", "appliances", "upgrade.html")
FRAG = os.path.join(REPO, "app", "templates", "appliances", "_scout_advisory.html")


# --------------------------------------------------------------------------- #
#  helpers                                                                      #
# --------------------------------------------------------------------------- #
def _read(path):
    return io.open(path, encoding="utf-8").read()


def _code_only(path):
    """Source with every comment and docstring removed.

    Without this, ``assert "Cloned to" not in service`` passes against a CORRECT
    file because the comment EXPLAINING the rule quotes the string it bans. It
    has cost this repo nine rounds; it is not re-derived here."""
    src = _read(path)
    tree = ast.parse(src)
    drop = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                             ast.Module)):
            body = getattr(node, "body", None) or []
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                drop.update(range(body[0].lineno, body[0].end_lineno + 1))
    out = []
    for i, line in enumerate(src.splitlines(), start=1):
        if i in drop:
            continue
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        out.append(line.split("  # ")[0] if "  # " in line else line)
    return "\n".join(out)


def _mk_appliance(name="fwtest", kind="fortiweb", firmware="7.6.1"):
    from app.extensions import db
    from app.models import Appliance

    a = Appliance(name=name, host="192.0.2.99", port=443, kind=kind, username="admin")
    a.password = "pw"
    a.firmware = firmware
    db.session.add(a)
    db.session.commit()
    return a


def _mk_image(version, product="fortiweb", tmp=None):
    from app.extensions import db
    from app.models_firmware import FirmwareImage

    path = os.path.join(tmp or "/tmp", f"fw-{product}-{version}.out")
    fw = FirmwareImage(product=product, version=version,
                       filename=os.path.basename(path), stored_path=path,
                       size_bytes=3, sha256="ab", uploaded_by="admin")
    db.session.add(fw)
    db.session.commit()
    return fw


def _sec(version, section, content, product="fortiweb"):
    from app.services.release_notes import ReleaseSection
    return ReleaseSection(
        product=product, version=version, section=section, title=section,
        content=content,
        source_url=f"https://docs.fortinet.com/document/fortiweb/{version}/x")


#: VERBATIM from the FortiWeb 8.0.7 release notes — the move that started this.
#: Paraphrasing it would guard a sentence Fortinet never wrote.
HOP_PROSE = "\n".join([
    "Supported upgrade paths",
    "If you are upgrading from a version that is 7.6.1 or lower, then you will need "
    "to upgrade to version 7.6.2 before proceeding with subsequent updates.",
])


def _seed(app, sections):
    from app.services import release_corpus
    from app.services import release_notes as rn
    with app.app_context():
        rn.save_db(rn.ReleaseNotesDB(generated_at="2026-09-14T00:00:00Z",
                                     versions=sorted({s.version for s in sections}),
                                     issues=[], sections=list(sections)),
                   root=release_corpus.root())


def _full_corpus():
    """Every (version, section) the advisor asks for across 7.6.1 → 8.0.7, so a
    verdict is not ``unknown`` merely because of coverage."""
    from app.services.release_notes import UPGRADE_SECTIONS
    out = []
    for v in ("7.6.1", "7.6.2", "8.0.7"):
        for sec in UPGRADE_SECTIONS:
            body = HOP_PROSE if (v == "8.0.7" and sec == "upgrading_from") else "Nothing of note."
            out.append(_sec(v, sec, body))
    return out


# --------------------------------------------------------------------------- #
#  1. Nothing that did not run may look clean                                   #
# --------------------------------------------------------------------------- #
def test_unavailable_is_outside_the_advisory_vocabulary(app):
    """``unavailable`` must not be a severity or a verdict the advisor can emit,
    or a review that never ran could be mistaken for one that did."""
    from app.services import release_advisor as ra
    from app.services import upgrade_scout as us

    assert "unavailable" not in ra.SEVERITIES
    rv = us.Review(asked=False, scout_on=True, product="fortiweb",
                   current="7.6.1", target="8.0.7")
    assert rv.advisory is None
    assert rv.verdict == "unavailable"
    assert rv.verdict != "clear"
    assert rv.blocking is False


def test_scout_switched_off_says_so(app):
    from app.services import scout_config, upgrade_scout as us
    with app.app_context():
        scout_config.set_value("enabled", False)
        a = _mk_appliance()
        rv = us.review(a, "8.0.7")
    assert rv.scout_on is False
    assert rv.reason == us.OFF
    assert rv.advisory is None
    assert rv.verdict == "unavailable"


def test_not_asked_is_distinct_from_nothing_found(app):
    from app.services import upgrade_scout as us
    with app.app_context():
        a = _mk_appliance()
        rv = us.review(a, "8.0.7", asked=False)
    assert rv.reason == us.NOT_ASKED
    assert rv.reason != us.OFF
    assert rv.advisory is None


def test_unsupported_product_has_no_corpus(app):
    from app.services import upgrade_scout as us
    with app.app_context():
        a = _mk_appliance(kind="fortianalyzer")
        rv = us.review(a, "8.0.7")
    assert rv.reason == us.NO_CORPUS_FOR_PRODUCT
    assert rv.advisory is None


def test_unknown_running_version_is_reported_not_guessed(app):
    from app.services import upgrade_scout as us
    with app.app_context():
        a = _mk_appliance(firmware="")
        rv = us.review(a, "8.0.7")
    assert rv.reason == us.NO_CURRENT
    assert rv.advisory is None


def test_missing_target_is_reported(app):
    from app.services import upgrade_scout as us
    with app.app_context():
        a = _mk_appliance()
        rv = us.review(a, "")
    assert rv.reason == us.NO_TARGET


def test_same_version_is_not_a_move(app):
    from app.services import upgrade_scout as us
    with app.app_context():
        a = _mk_appliance(firmware="8.0.7")
        rv = us.review(a, "8.0.7")
    assert rv.reason == us.SAME_VERSION
    assert rv.advisory is None


def test_unreadable_corpus_names_the_failure(app, monkeypatch):
    """A corpus that raises must not reach the operator as an all-clear."""
    from app.services import release_corpus, upgrade_scout as us

    def boom(product):
        raise OSError("disk gone")

    monkeypatch.setattr(release_corpus, "load", boom)
    with app.app_context():
        a = _mk_appliance()
        rv = us.review(a, "8.0.7")
    assert rv.advisory is None
    assert "OSError" in rv.reason
    assert rv.verdict == "unavailable"


def test_empty_corpus_is_unknown_with_gaps_never_clear(app):
    """The worst available failure, guarded directly."""
    from app.services import upgrade_scout as us
    _seed(app, [])
    with app.app_context():
        a = _mk_appliance()
        rv = us.review(a, "8.0.7")
    assert rv.advisory is not None
    assert rv.verdict == "unknown"
    assert rv.verdict != "clear"
    assert rv.advisory.gaps, "an unread corpus must report what it could not read"


# --------------------------------------------------------------------------- #
#  2. A real verdict, over real vendor prose                                    #
# --------------------------------------------------------------------------- #
def test_the_8_0_7_hop_comes_back_as_a_blocker(app):
    from app.services import upgrade_scout as us
    _seed(app, _full_corpus())
    with app.app_context():
        a = _mk_appliance(firmware="7.6.1")
        rv = us.review(a, "8.0.7")
    assert rv.verdict == "blocker"
    assert rv.blocking is True
    assert rv.advisory.path and "7.6.2" in rv.advisory.path
    assert rv.counts.get("blocker", 0) >= 1


def test_decorated_firmware_strings_are_parsed(app):
    from app.services import upgrade_scout as us
    assert us.normalise("FortiWeb-VM 8.0.7,build1234,250101") == "8.0.7"
    assert us.normalise("v7.6.2") == "7.6.2"
    assert us.normalise("") == ""
    assert us.normalise("unknown") == ""


def test_a_decorated_running_version_still_reviews(app):
    """The decoration must be stripped BEFORE the verdict, not after: an
    unparsed version reaches the analyser as a version nobody can place on the
    ladder and comes back as a confident empty result."""
    from app.services import upgrade_scout as us
    _seed(app, _full_corpus())
    with app.app_context():
        a = _mk_appliance(firmware="FortiWeb-VM 7.6.1,build0100,250101")
        rv = us.review(a, "8.0.7")
    assert rv.current == "7.6.1"
    assert rv.verdict == "blocker"


def test_summary_carries_the_verdict_and_never_the_vendor_prose(app):
    from app.services import upgrade_scout as us
    _seed(app, _full_corpus())
    with app.app_context():
        a = _mk_appliance(firmware="7.6.1")
        rv = us.review(a, "8.0.7")
        blob = json.dumps(us.summary(rv))
    assert '"verdict": "blocker"' in blob
    assert "upgrade to version 7.6.2 before proceeding" not in blob, (
        "findings are rendered server-side; shipping the prose invites a second "
        "renderer in JavaScript")


# --------------------------------------------------------------------------- #
#  3. The page reviews the move it is about to run                              #
# --------------------------------------------------------------------------- #
def _open_upgrade(app, client, tmp_path):
    _seed(app, _full_corpus())
    with app.app_context():
        a = _mk_appliance(firmware="7.6.1")
        _mk_image("7.6.4", tmp=str(tmp_path))
        newest = _mk_image("8.0.7", tmp=str(tmp_path))
        aid, iid = a.id, newest.id
    login(client, admin_user_id(app))
    return aid, iid


def test_upgrade_page_carries_the_panel_and_the_optin(app, client, tmp_path,
                                                      monkeypatch):
    from app.services import upgrade as upg
    monkeypatch.setattr(upg, "firmware_version", lambda *a, **k: "7.6.1")
    aid, _iid = _open_upgrade(app, client, tmp_path)
    html = client.get(f"/appliances/{aid}/upgrade").get_data(as_text=True)
    assert 'id="scout-panel"' in html
    assert 'name="scout_check"' in html


def test_the_panel_reviews_the_option_the_picker_has_selected(app, client,
                                                              tmp_path, monkeypatch):
    """images[0] is what a plain submit posts. A verdict for the OTHER image is
    a lie in the most expensive place available."""
    from app.services import upgrade as upg
    monkeypatch.setattr(upg, "firmware_version", lambda *a, **k: "7.6.1")
    aid, _iid = _open_upgrade(app, client, tmp_path)
    html = client.get(f"/appliances/{aid}/upgrade").get_data(as_text=True)
    assert "<b>7.6.1</b> &rarr; <b>8.0.7</b>" in html
    assert "&rarr; <b>7.6.4</b>" not in html


def test_fragment_route_reviews_the_image_it_is_given(app, client, tmp_path):
    aid, iid = _open_upgrade(app, client, tmp_path)
    r = client.get(f"/appliances/{aid}/upgrade/advisory?image_id={iid}")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert 'id="scout-panel"' in html
    assert "<b>8.0.7</b>" in html


def test_fragment_route_honours_the_optin(app, client, tmp_path):
    from app.services import upgrade_scout as us
    aid, iid = _open_upgrade(app, client, tmp_path)
    html = client.get(
        f"/appliances/{aid}/upgrade/advisory?image_id={iid}&scout_check=off"
    ).get_data(as_text=True)
    assert us.NOT_ASKED in html


def test_fragment_route_needs_the_same_permission_as_the_page(app, client, tmp_path):
    """A review names the appliance, its running version and the vendor's
    warnings about it — the fragment must not be a wider door than the page."""
    from conftest import make_user
    aid, iid = _open_upgrade(app, client, tmp_path)
    client.get("/auth/logout", follow_redirects=True)
    login(client, make_user(app, username="ro", role="readonly"))
    r = client.get(f"/appliances/{aid}/upgrade/advisory?image_id={iid}")
    assert r.status_code in (302, 403)
    assert r.status_code != 200


def test_fragment_route_404s_for_an_unknown_appliance(app, client, tmp_path):
    aid, iid = _open_upgrade(app, client, tmp_path)
    r = client.get(f"/appliances/{aid + 9999}/upgrade/advisory?image_id={iid}")
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
#  4. The submitted run carries the verdict — and Scout never refuses it        #
# --------------------------------------------------------------------------- #
def _post(client, aid, iid, **extra):
    form = {"image_id": str(iid), "dry_run": "on", "ajax": "1"}
    form.update(extra)
    return client.post(f"/appliances/{aid}/upgrade", data=form,
                       headers={"X-Requested-With": "XMLHttpRequest"})


def test_the_job_and_its_response_carry_the_verdict(app, client, tmp_path,
                                                    monkeypatch):
    from app.services import jobs as jobsvc
    monkeypatch.setattr(jobsvc, "run_async", lambda *a, **k: None)
    aid, iid = _open_upgrade(app, client, tmp_path)
    r = _post(client, aid, iid, scout_check="on")
    assert r.status_code == 200
    body = r.get_json()
    assert body["scout"]["verdict"] == "blocker"
    assert body["scout"]["asked"] is True
    with app.app_context():
        job = jobsvc.get_job(body["job_id"]) or {}
    assert (job.get("meta") or {}).get("scout", {}).get("verdict") == "blocker", (
        "the page closes; the job record is what can still answer, after the "
        "reboot, what Scout had said before it")


def test_declining_the_help_is_recorded_as_declined(app, client, tmp_path,
                                                    monkeypatch):
    from app.services import jobs as jobsvc
    monkeypatch.setattr(jobsvc, "run_async", lambda *a, **k: None)
    aid, iid = _open_upgrade(app, client, tmp_path)
    body = _post(client, aid, iid).get_json()          # checkbox absent
    assert body["scout"]["asked"] is False
    assert body["scout"]["verdict"] == "unavailable"
    assert body["scout"]["verdict"] != "clear"


def test_a_blocker_does_not_refuse_the_flash(app, client, tmp_path, monkeypatch):
    """Scout advises; change control authorises. A gate built on a verdict whose
    vocabulary includes ``unknown`` would refuse upgrades over gaps in our own
    corpus while looking like a refusal grounded in the vendor's words."""
    from app.services import jobs as jobsvc
    monkeypatch.setattr(jobsvc, "run_async", lambda *a, **k: None)
    aid, iid = _open_upgrade(app, client, tmp_path)
    r = _post(client, aid, iid, scout_check="on")
    assert r.status_code == 200
    assert r.get_json().get("job_id")


def test_a_verdict_worth_hearing_reaches_the_audit_log(app, client, tmp_path,
                                                       monkeypatch):
    from app.services import jobs as jobsvc
    monkeypatch.setattr(jobsvc, "run_async", lambda *a, **k: None)
    aid, iid = _open_upgrade(app, client, tmp_path)
    _post(client, aid, iid, scout_check="on")
    with app.app_context():
        from app.models import AuditLog
        rows = [r for r in AuditLog.query.all() if r.action == "appliance.upgrade_scout"]
    assert rows, "'we were told' must be answerable from the log alone"
    # ``detail=`` is serialised into AuditLog.extra, not a column of its own.
    assert "blocker" in (rows[-1].extra or "")
    assert "8.0.7" in (rows[-1].extra or "")


def test_scout_runs_for_a_dry_run_too(app, client, tmp_path, monkeypatch):
    """The dry run is where the operator decides; withholding the warnings there
    puts them on the only screen nobody reads twice."""
    from app.services import jobs as jobsvc
    monkeypatch.setattr(jobsvc, "run_async", lambda *a, **k: None)
    aid, iid = _open_upgrade(app, client, tmp_path)
    body = _post(client, aid, iid, dry_run="on", scout_check="on").get_json()
    with app.app_context():
        job = jobsvc.get_job(body["job_id"]) or {}
    assert (job.get("meta") or {}).get("dry_run") is True
    assert body["scout"]["verdict"] == "blocker"


def test_scout_runs_before_the_image_is_sent(app):
    """A warning delivered after the reboot is not a warning. Checked on the
    ORDER of statements in ``upgrade_push``, not on a comment about it."""
    tree = ast.parse(_read(VIEW))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "upgrade_push")
    src_lines = {}
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            f = node.func
            name = getattr(f, "attr", None) or getattr(f, "id", None)
            if name in ("_scout_for", "push_firmware", "_spawn_flash_job"):
                src_lines.setdefault(name, node.lineno)
    assert "_scout_for" in src_lines
    assert src_lines["_scout_for"] < src_lines["push_firmware"]
    assert src_lines["_scout_for"] < src_lines["_spawn_flash_job"]


# --------------------------------------------------------------------------- #
#  5. One author per fact                                                       #
# --------------------------------------------------------------------------- #
def test_the_view_never_writes_the_panel_markup(app):
    """The fragment template is the only renderer of these findings. A second
    one in Python — or in JavaScript — is a second chance to emit vendor prose
    unescaped."""
    code = _code_only(VIEW)
    assert "scout-panel" not in code
    assert "fw-badge-danger" not in code


def _in_class_or_id_attr(html, token):
    """True iff ``token`` is EMITTED as a class/id, not merely mentioned.

    Split from the assertion about the selector that consults it: renaming one
    side only has passed in this repo ten times."""
    return (f'id="{token}"' in html) or (f'class="{token}' in html) or (f' {token}"' in html)


def test_the_fragments_id_and_the_selector_that_swaps_it_agree(app):
    frag, tpl = _read(FRAG), _read(TPL)
    assert _in_class_or_id_attr(frag, "scout-panel")
    assert "getElementById('scout-panel')" in tpl
    assert "querySelector('#scout-panel')" in tpl


def test_the_page_includes_the_fragment_rather_than_copying_it(app):
    tpl = _read(TPL)
    assert "appliances/_scout_advisory.html" in tpl
    assert "Rules seal" not in tpl, "the panel's body has one author"


def test_the_optin_posts_with_the_flash_form(app):
    """A checkbox outside ``#flash-form`` silently never posts, and the review
    then always runs — or never does — regardless of what the operator ticked."""
    tpl = _read(TPL)
    start = tpl.index('id="flash-form"')
    end = tpl.index("</form>", start)
    assert 'name="scout_check"' in tpl[start:end]


def test_the_corpus_has_one_loader(app):
    """``release_notes`` must delegate: a second definition of "where the corpus
    is" renders an empty directory exactly like a corpus with nothing to say."""
    code = _code_only(RNVIEW)
    assert "release_corpus.root()" in code
    assert "release_corpus.load(" in code
    # Scoped to the two READERS. ``rn.load_db`` legitimately survives in the
    # scanner, which merges a fresh harvest into the corpus — a blanket ban on
    # the name would have been satisfied by deleting the wrong call.
    tree = ast.parse(_read(RNVIEW))
    for name in ("_load", "_corpus_root"):
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == name)
        body = ast.unparse(fn)
        assert "load_db" not in body and "reports_root" not in body, (
            f"{name} re-implements the loader instead of delegating")


def test_the_reasons_have_one_spelling(app):
    """Three spellings of "Scout is off" is how a panel ends up claiming a
    review that never ran."""
    from app.services import upgrade_scout as us
    reasons = [us.OFF, us.NOT_ASKED, us.NO_CORPUS_FOR_PRODUCT, us.NO_CURRENT,
               us.NO_TARGET, us.SAME_VERSION]
    assert len(set(reasons)) == len(reasons)
    # Counted over PARSED string constants, never over the raw text: these are
    # hard-wrapped with implicit concatenation, so a substring count of the
    # source is 0 for most of them and the guard would pass for the wrong
    # reason. (The seventh assert-by-substring trap in this repo.)
    consts = [n.value for n in ast.walk(ast.parse(_read(SVC)))
              if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    for r in reasons:
        assert consts.count(r) == 1, f"{r!r} is spelled {consts.count(r)} times"


def test_the_fragment_shows_coverage_next_to_the_verdict(app):
    """A verdict over prose nobody harvested and a verdict over prose that said
    nothing render identically without it."""
    frag = _read(FRAG)
    assert "adv.read|length" in frag
    assert "adv.gaps|length" in frag
