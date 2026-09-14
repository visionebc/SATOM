"""Guards for the clone registry (models_lineage / services.policy_lineage /
the row flag in workspace/policies.html).

What this file exists to stop, in order of how badly it would hurt:

1. a PREVIEW writing rows — ``analyse()`` runs ``perform_one`` with
   ``dry_run=True`` and must leave no trace, or the registry fills with copies
   that were never made;
2. ``migrate_to`` being rendered as a clone — it disables the source, so
   "cloned to X" over a migrated policy tells the operator he still has a live
   original;
3. the badge counting FAILED attempts as copies that exist;
4. the landing name going unrecorded — the exact gap that made a >7-day-old
   ``clone_here`` unrecoverable in the first place.
"""
from __future__ import annotations

import inspect
import io
import re

from app.extensions import db
from app.models import Appliance
from app.models_lineage import PolicyCloneEvent
from app.services import policy_lineage as lin

from tests.conftest import admin_user_id, login


# --- helpers ---------------------------------------------------------------

def _appl(app, name, host="192.0.2.13", **kw):
    with app.app_context():
        a = Appliance(name=name, kind=kw.pop("kind", "fortiweb"), host=host,
                      port=kw.pop("port", 443), username="admin",
                      password_enc="x", verify_ssl=False, **kw)
        db.session.add(a)
        db.session.commit()
        return a.id


def _ev(app, src_id, policy, **kw):
    with app.app_context():
        return lin.record(src_appliance_id=src_id, src_policy=policy,
                          action=kw.pop("action", "clone_to"),
                          dst_appliance_id=kw.pop("dst_appliance_id", None),
                          dst_appliance=kw.pop("dst_appliance", "fortiweb15"),
                          dst_policy=kw.pop("dst_policy", "pol-copy"),
                          ok=kw.pop("ok", True), **kw)


def _src(obj) -> str:
    return inspect.getsource(obj)


def _code_only(src: str) -> str:
    """Source with docstrings and ``#`` comments removed.

    Mandatory for any "this string must NOT appear" assertion: the comment that
    EXPLAINS the rule necessarily quotes the strings the rule forbids, so an
    unfiltered check fails against a perfectly correct file. This is the ninth
    time that trap has fired in this repo.
    """
    src = re.sub(r'(?s)""".*?"""', "", src)
    src = re.sub(r"(?s)'''.*?'''", "", src)
    return re.sub(r"(?m)#.*$", "", src)


def _cls(name: str, body: str) -> bool:
    """Is ``name`` used as a CSS class token (not merely as a substring)?

    ``"fw-clone-flag" in body`` is satisfied by ``fw-clone-flag-gone`` — and a
    word boundary does NOT save you, because a hyphen already is one. This is
    the eighth time in this repo a guard matched its own mutant; the token has
    to be terminated by something that is not a word char or a hyphen.
    """
    return re.search(re.escape(name) + r"(?![\w-])", body) is not None


def _in_class_attr(name: str, body: str) -> bool:
    """Is ``name`` emitted in a ``class="…"`` attribute (the MARKUP half)?

    Checked separately from the selector that consults it. Renaming only one
    half leaves either a class nobody reads or a selector that matches nothing,
    and a single assertion is satisfied by whichever half survived — the mirror
    trap that let a rename mutation through on the first run of this file.
    """
    return any(_cls(name, m) for m in re.findall(r'class="([^"]*)"', body))


def _clone_js(body: str) -> str:
    """Just the clone-flag JS block.

    A page-wide ``"stopPropagation()" in body`` passes on the handler this
    template ALREADY had for the checkbox/actions cells — so the assertion was
    satisfied by code with nothing to do with the flag, and the mutation that
    deleted the flag's own handler survived.
    """
    i = body.index("// ── Clone-history flag")
    return body[i:body.index("\n  });", i)]


# --- 1. the preview must never write ---------------------------------------

def test_record_is_called_from_the_real_path_only():
    """One writer, and it is the ``dry_run=False`` worker.

    Asserted against the SOURCE rather than by driving a preview, because a
    preview talks to a device. ``preview()`` is the dry-run path and
    ``perform_one`` is shared by both; neither may contain the call.
    """
    from app.services import policy_ops as ops

    module = _code_only(io.open("app/services/policy_ops.py",
                                encoding="utf-8").read())
    assert module.count("lineage.record(") == 1, (
        "exactly ONE writer in the whole module — a second one is a second "
        "path that can disagree about what was recorded")

    worker = _src(ops.start_policy_job)
    assert "lineage.record(" in worker and "dry_run=False" in worker, (
        "and it is the real-execution worker")

    for fn in (ops.preview, ops.perform_one):
        assert "lineage.record(" not in _src(fn), (
            "%s runs under dry_run and must not write lineage" % fn.__name__)


def test_worker_records_the_same_name_it_wrote(app):
    """One variable feeds both the device write and the registry.

    Without this, a mutation that records ``pol`` (the SOURCE name) instead of
    the landing name survives every functional test in this file — those call
    ``record()`` directly and never see the worker's own argument. The registry
    would then be confidently wrong for exactly the case it was built for: a
    bulk ``clone_here``, where ``_name_for`` appends ``-copy`` and the source
    name is precisely what the copy is NOT called.
    """
    from app.services import policy_ops as ops

    worker = _code_only(_src(ops.start_policy_job))
    assert "landed = _name_for(" in worker
    assert "new_name=landed" in worker, "the device write uses it"
    assert "dst_policy=landed" in worker, "and the registry records THAT one"
    assert "dst_policy=pol" not in worker


def test_record_only_accepts_the_three_action_verbs(app):
    src = _appl(app, "fw-a")
    with app.app_context():
        assert lin.record(src_appliance_id=src, src_policy="p",
                          action="delete") is None
        assert lin.record(src_appliance_id=src, src_policy="",
                          action="clone_to") is None
        assert PolicyCloneEvent.query.count() == 0


# --- 2. a migrate is a MOVE, and says so -----------------------------------

def test_migrate_keeps_its_own_verb(app):
    src = _appl(app, "fw-a")
    _ev(app, src, "pol", action="migrate_to", dst_appliance="fw-b")
    with app.app_context():
        rows = lin.for_policies(src, ["pol"])["pol"]
        assert rows[0]["action"] == "migrate_to", (
            "a migrate collapsed into 'clone' would claim a live original that "
            "was disabled")
        assert rows[0]["same_box"] is False


def test_template_words_each_verb_separately():
    """The three verbs are three literal msgids in the template, and 'Migrated'
    is one of them. Wording lives there and ONLY there — a copy in the service
    would be a second author of the same phrase."""
    body = io.open("app/templates/workspace/policies.html",
                   encoding="utf-8").read()
    for msg in ("Cloned here as", "Cloned to", "Migrated to"):
        assert "_('%s')" % msg in body, "missing literal msgid %r" % msg

    # Comments and docstrings stripped: the note that EXPLAINS this rule quotes
    # the very strings it forbids, so an unfiltered check fails against a
    # correct file.
    svc = _code_only(io.open("app/services/policy_lineage.py",
                             encoding="utf-8").read())
    for msg in ("Cloned here", "Cloned to", "Migrated to"):
        assert msg not in svc, (
            "the verb wording must not also live in the service — two authors "
            "of one phrase is how they drift")


# --- 3. the counter counts copies that EXIST -------------------------------

def test_badge_counts_successes_not_attempts(app):
    src = _appl(app, "fw-a")
    _ev(app, src, "pol", ok=True, dst_policy="pol-ok")
    _ev(app, src, "pol", ok=False, dst_policy="pol-bad", error="boom")
    with app.app_context():
        evs = lin.for_policies(src, ["pol"])["pol"]
        assert len(evs) == 2, "the failure is still RECORDED"
        assert lin.ok_count(evs) == 1, "but only the copy that landed is COUNTED"


def test_failed_attempt_keeps_its_error(app):
    src = _appl(app, "fw-a")
    _ev(app, src, "pol", ok=False, error="HTTP 423 -20010")
    with app.app_context():
        ev = lin.for_policies(src, ["pol"])["pol"][0]
        assert ev["ok"] is False and "423" in ev["error"]


def test_popover_shows_WHY_an_attempt_failed():
    """The verdict without the reason is not actionable.

    Caught by RENDERING the page, not by any assertion here: every test was
    green while the popover printed "failed" and swallowed an error the row had
    already stored. The operator who just found half a copy on the destination
    is the person this line is for.
    """
    body = io.open("app/templates/workspace/policies.html",
                   encoding="utf-8").read()
    assert "{{ e.error }}" in body, "the recorded reason reaches the popover"
    assert _in_class_attr("fw-clone-err", body)
    css = io.open("app/static/css/fortiweb.css", encoding="utf-8").read()
    assert _cls(".fw-clone-err", css), "and it is styled for the light chrome"


def test_flag_marks_the_all_failed_case(app, client):
    """A flag reading '0' in the normal accent colour looks like a copy exists.
    The all-failed row gets its own class."""
    src = _appl(app, "fw-a")
    _ev(app, src, "pol", ok=False)
    login(client, admin_user_id(app))
    body = io.open("app/templates/workspace/policies.html",
                   encoding="utf-8").read()
    assert _cls("fw-clone-flag-empty", body)
    css = io.open("app/static/css/fortiweb.css", encoding="utf-8").read()
    assert _cls("fw-clone-flag-empty", css), "the class is styled, not just emitted"


# --- 4. the landing name, the when and the who -----------------------------

def test_the_landing_name_is_recorded(app):
    """The gap this table exists to close: the audit line never carried it, so
    a same-box clone older than the 7-day job prune was unrecoverable."""
    src = _appl(app, "fw-a")
    _ev(app, src, "shop", action="clone_here", dst_policy="shop-copy",
        dst_appliance="fw-a", dst_appliance_id=src, by="admin")
    with app.app_context():
        ev = lin.for_policies(src, ["shop"])["shop"][0]
        assert ev["dst_policy"] == "shop-copy"
        assert ev["by"] == "admin"
        assert ev["at"], "a timestamp is one of the three things asked for"


def test_same_box_clone_does_not_name_a_destination_box(app):
    """``where`` is what the popover prints as "cloned to X". Printing the
    source's own name there reads as a cross-box copy that never happened."""
    src = _appl(app, "fw-a")
    _ev(app, src, "pol", action="clone_here", dst_appliance="fw-a",
        dst_appliance_id=src)
    with app.app_context():
        ev = lin.for_policies(src, ["pol"])["pol"][0]
        assert ev["same_box"] is True
        assert ev["where"] == ""


def test_history_is_newest_first(app):
    from datetime import datetime
    src = _appl(app, "fw-a")
    with app.app_context():
        for i, day in enumerate((3, 1, 2)):
            r = lin.record(src_appliance_id=src, src_policy="pol",
                           action="clone_to", dst_appliance="fw-b",
                           dst_policy="c%d" % i, ok=True)
            r.at = datetime(2026, 9, day, 10, 0)
            db.session.commit()
        got = [e["dst_policy"] for e in lin.for_policies(src, ["pol"])["pol"]]
        assert got == ["c0", "c2", "c1"], (
            "newest first — the last thing that happened is what the operator "
            "standing in front of the row is deciding about")


# --- 5. the registry does not hang off the rebuilt cache --------------------

def test_lineage_survives_a_reingest_of_the_policy_cache(app):
    """``device_server_policies`` is a projection rebuilt on every ingest. A row
    keyed into it would be destroyed by the next harvest — which is the silence
    this table exists to end."""
    from app.models_cache import DeviceServerPolicy

    src = _appl(app, "fw-a")
    _ev(app, src, "pol")
    with app.app_context():
        DeviceServerPolicy.query.delete()       # what an ingest does first
        db.session.commit()
        assert lin.for_policies(src, ["pol"]).get("pol"), (
            "the clone history must not be collateral of a refresh")

    model_src = io.open("app/models_lineage.py", encoding="utf-8").read()
    assert "device_server_policies" not in re.sub(r"(?s)\"\"\".*?\"\"\"", "",
                                                  model_src), (
        "no FK into the rebuilt projection (docstrings stripped so the comment "
        "that EXPLAINS the rule cannot satisfy the check)")


def test_retiring_the_destination_keeps_the_recorded_name(app):
    """"Cloned to fortiweb15" stays true after fortiweb15 is retired. The id is
    SET NULL; the name was captured at the time and must survive."""
    src = _appl(app, "fw-a")
    dst = _appl(app, "fw-b", host="192.0.2.14")
    _ev(app, src, "pol", dst_appliance_id=dst, dst_appliance="fw-b")
    with app.app_context():
        db.session.execute(db.text("PRAGMA foreign_keys=ON"))
        row = PolicyCloneEvent.query.first()
        row.dst_appliance_id = None             # what SET NULL does
        db.session.commit()
        ev = lin.for_policies(src, ["pol"])["pol"][0]
        assert ev["where"] == "fw-b"


# --- 6. the read path ------------------------------------------------------

def test_for_policies_is_scoped_to_the_appliance(app):
    a = _appl(app, "fw-a")
    b = _appl(app, "fw-b", host="192.0.2.14")
    _ev(app, a, "pol", dst_policy="from-a")
    _ev(app, b, "pol", dst_policy="from-b")
    with app.app_context():
        got = lin.for_policies(a, ["pol"])["pol"]
        assert [e["dst_policy"] for e in got] == ["from-a"], (
            "two boxes routinely hold a policy of the same NAME")


def test_for_policies_omits_untouched_names(app):
    src = _appl(app, "fw-a")
    _ev(app, src, "pol")
    with app.app_context():
        got = lin.for_policies(src, ["pol", "other"])
        assert "other" not in got, "no key → the template draws no flag"


def test_for_policies_is_one_query_for_the_whole_page(app):
    """A per-row lookup is 750 round-trips to render a badge that is empty on
    most rows."""
    src = _appl(app, "fw-a")
    names = ["p%d" % i for i in range(50)]
    for n in names[:5]:
        _ev(app, src, n)
    with app.app_context():
        seen = []
        from sqlalchemy import event as sa_event
        eng = db.session.get_bind()

        def _count(conn, cur, stmt, params, ctx, many):
            if "policy_clone_events" in stmt:
                seen.append(stmt)

        sa_event.listen(eng, "before_cursor_execute", _count)
        try:
            lin.for_policies(src, names)
        finally:
            sa_event.remove(eng, "before_cursor_execute", _count)
        assert len(seen) == 1, "one SELECT for the page, got %d" % len(seen)


def test_empty_inputs_never_query(app):
    src = _appl(app, "fw-a")
    with app.app_context():
        assert lin.for_policies(src, []) == {}
        assert lin.for_policies(None, ["p"]) == {}


# --- 7. the page --------------------------------------------------------------

def test_view_passes_clone_events_to_the_template():
    view = io.open("app/views/workspace.py", encoding="utf-8").read()
    assert "clone_events=clone_events" in view
    assert "policy_lineage" in view


def test_flag_markup_and_popover_are_both_present():
    """The flag and the thing that OPENS it are two halves with two authors —
    checked together, since either alone renders a badge that does nothing."""
    body = io.open("app/templates/workspace/policies.html",
                   encoding="utf-8").read()
    assert "{% macro clone_flag(events) %}" in body
    assert "clone_flag(_cl)" in body, "the macro is actually CALLED in the row"
    assert "new bootstrap.Popover(" in body
    assert "trigger: 'hover focus'" in body, (
        "hover was the ask; focus is what makes it reachable by keyboard")

    # Markup half and consulting half, asserted SEPARATELY — see _in_class_attr.
    js = _clone_js(body)
    for name in ("fw-clone-flag", "fw-clone-src"):
        assert _in_class_attr(name, body), "%s is emitted in the markup" % name
    assert "'.fw-clone-flag'" in js or ".fw-clone-flag'" in js, (
        "and the JS selects it")
    assert "contains('fw-clone-src')" in js, "and the JS finds the body source"

    # Scoped to the flag's own block: the page already had a stopPropagation
    # for the checkbox/actions cells, which satisfied a page-wide check.
    assert "stopPropagation()" in js, (
        "the row navigates on click — a click on the flag must not also open "
        "the policy detail")


def test_popover_content_is_server_rendered_not_built_in_js():
    """Every value goes through Jinja autoescaping. Building the HTML in JS from
    a data- attribute would put device-supplied policy names into innerHTML."""
    body = io.open("app/templates/workspace/policies.html",
                   encoding="utf-8").read()
    assert "content: src.innerHTML" in body
    assert "sanitize: false" in body, (
        "Bootstrap's default allowList drops <table>, which would empty the "
        "popover silently")
