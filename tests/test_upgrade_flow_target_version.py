# -*- coding: utf-8 -*-
"""The upgrade flow's DESTINATION — the version a window is going TO.

The bulk flow asked every question about a maintenance window except the one
that defines it. ``UpgradePrep.firmware`` recorded the version the appliance
was RUNNING; nothing recorded where it was going. The consequence is not
cosmetic and it is not a missing field on a form:

* the same green pre-flight was equally valid "evidence" for 7.6.8 -> 8.0.5
  and for 7.6.8 -> 8.0.6, which are different moves, with different release
  notes and different breaking changes;
* ``upgrade_flow.change()`` passed no ``params`` at all, so every change the
  flow raised was born with ``params={}`` — and ``cr_orchestrator`` already
  reads ``params`` to fill the ``upgrade.finished`` / ``upgrade.failed``
  webhooks, which therefore went out naming no image, forever;
* Scout (``services.upgrade_scout``) is OFFLINE — it reads harvested vendor
  prose, contacts nothing — and could have given a per-appliance verdict on
  the move before anybody raised a change. It was wired to the single
  appliance's page only, because the bulk page had no target to give it.

Every test below is one of those, stated so it fails if the answer goes away.
"""
from __future__ import annotations

import json
from datetime import datetime

import pytest

from conftest import admin_user_id, login


# --------------------------------------------------------------------------- #
#  helpers                                                                      #
# --------------------------------------------------------------------------- #
def _mk_appliance(name, *, kind="fortiweb", firmware="7.6.8"):
    from app.extensions import db
    from app.models import Appliance

    a = Appliance(name=name, host=f"10.9.0.{abs(hash(name)) % 200 + 20}",
                  port=443, kind=kind, username="admin", firmware=firmware)
    a.password = "pw"
    db.session.add(a)
    db.session.commit()
    return a


def _mk_image(version, *, product="fortiweb", kind="upgrade"):
    from app.extensions import db
    from app.models_firmware import FirmwareImage

    row = FirmwareImage(product=product, image_kind=kind, version=version,
                        filename=f"FWB_{version}.out", stored_path="/tmp/x",
                        size_bytes=1, sha256="", uploaded_by="op")
    db.session.add(row)
    db.session.commit()
    return row


def _declare(version, *, product="fortiweb"):
    from app.services import firmware_versions as fv
    ok, msg, _v = fv.declare(product, version, note="planned", by="op")
    assert ok, msg


def _mk_prep(appliance, *, target=None, ok=True, firmware="7.6.8"):
    from app.services import prep_store
    return prep_store.record(appliance, {"firmware": firmware},
                             inventory=[], created_by="op",
                             target_version=target or "")


# =========================================================================== #
#  1. the destination is STORED on the evidence                                #
# =========================================================================== #
def test_a_run_records_the_version_it_was_run_towards(app):
    """The whole point. ``firmware`` is where it WAS; this is where it is going."""
    with app.app_context():
        ap = _mk_appliance("fw-a")
        prep = _mk_prep(ap, target="8.0.5", firmware="7.6.8")
        assert prep.firmware == "7.6.8"
        assert prep.target_version == "8.0.5"


def test_an_undeclared_destination_is_null_and_never_empty_string(app):
    """NULL and '' must not both be storable, or they stop being distinguishable.

    NULL is "nobody said where this was going" — the true state of every row
    written before the column existed. A writer that stores '' for the same
    thing makes that history unreadable the first time some later code stores
    '' to mean "asked, got nothing".
    """
    with app.app_context():
        ap = _mk_appliance("fw-null")
        assert _mk_prep(ap, target=None).target_version is None
        assert _mk_prep(ap, target="   ").target_version is None


def test_the_column_exists_on_the_live_schema_not_only_on_the_model(app):
    """``db.create_all()`` never ALTERs an existing table.

    The model declaring a column is not the column existing. On a node whose
    ``upgrade_prep`` table predates this feature the only two things that add
    it are ``_ensure_columns()`` and the alembic revision — and a model-only
    change 500s on the first sweep with every assertion above still green.
    """
    from sqlalchemy import inspect

    from app.extensions import db
    with app.app_context():
        cols = {c["name"] for c in inspect(db.engine).get_columns("upgrade_prep")}
        assert "target_version" in cols


def test_ensure_columns_declares_it_for_a_pre_existing_table(app):
    """The boot-time step names the table and the column, with no default.

    Read out of the SOURCE: by the time the dict is built a duplicate key has
    already collapsed silently, which is the failure
    ``test_schema_migration_keys`` exists for. A DEFAULT here would be the
    backfill this column must not have.
    """
    import os
    import re
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "app", "__init__.py")
    src = open(path, encoding="utf-8").read()
    block = re.search(r"'upgrade_prep':\s*\[(.*?)\]", src, re.S)
    assert block, "'upgrade_prep' is not in the _ensure_columns table"
    body = block.group(1)
    assert "target_version" in body
    assert "DEFAULT" not in body.upper(), (
        "target_version must have NO default: a backfilled '' claims a "
        "destination nobody declared")


def test_the_alembic_revision_adds_it_and_is_idempotent(app):
    """A node that already ran ``_ensure_columns`` must not die on the revision.

    That is not a tidiness point: a revision that raises blocks every LATER
    revision, on the node that is actually in production.
    """
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "migrations", "versions",
                        "upgtgt01_upgrade_prep_target_version.py")
    assert os.path.exists(path), "the revision file is missing"
    # RUN it, twice, against a table that does not have the column. Reading
    # the source for "add_column" passes over `return; op.add_column(...)` and
    # over a revision whose idempotence check was deleted — both of which
    # survived the string version of this guard.
    #
    # The `op` proxy is replaced rather than driven through alembic's
    # Operations context: what is under test is the revision's own logic
    # (does it add, and does it add TWICE), not alembic's DDL emitter.
    import importlib.util

    import sqlalchemy as sa

    spec = importlib.util.spec_from_file_location("upgtgt01_rev", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    engine = sa.create_engine("sqlite://")
    conn = engine.connect()
    conn.execute(sa.text(
        "CREATE TABLE upgrade_prep (id INTEGER PRIMARY KEY, "
        "appliance_id INTEGER, firmware VARCHAR(64))"))

    added = []

    class _Op:
        @staticmethod
        def get_bind():
            return conn

        @staticmethod
        def add_column(table, column):
            added.append((table, column.name))
            conn.execute(sa.text(
                "ALTER TABLE %s ADD COLUMN %s VARCHAR(32)" % (table, column.name)))

        @staticmethod
        def drop_column(table, name):  # pragma: no cover - not exercised here
            raise AssertionError("upgrade() must not drop anything")

    mod.op = _Op
    mod.upgrade()
    assert added == [("upgrade_prep", "target_version")], (
        "the revision added nothing: %r" % (added,))
    cols = {c["name"] for c in sa.inspect(conn).get_columns("upgrade_prep")}
    assert "target_version" in cols

    # Second run. On a real node the boot-time ``_ensure_columns`` has already
    # added the column by the time alembic reaches this revision, and a
    # revision that raises there blocks every LATER revision — on the node
    # that is actually in production.
    mod.upgrade()
    assert added == [("upgrade_prep", "target_version")], (
        "the revision is not idempotent: it tried to add the column twice")
    conn.close()


# =========================================================================== #
#  2. the sweep REFUSES without one                                            #
# =========================================================================== #
def _sweep(client, app, device_ids, target, monkeypatch, calls=None):
    """POST stage 1 with the pre-flight stubbed out (it talks to real boxes)."""
    from app.services import prep_store

    def _fake(appliance, **kw):
        if calls is not None:
            calls.append((appliance.name, kw.get("target_version")))
        return {"firmware": "7.6.8"}, prep_store.record(
            appliance, {"firmware": "7.6.8"}, inventory=[],
            created_by=kw.get("created_by") or "",
            target_version=kw.get("target_version") or "")

    monkeypatch.setattr(prep_store, "run_for", _fake)
    from werkzeug.datastructures import MultiDict
    data = MultiDict([("device_ids", str(i)) for i in device_ids])
    if target is not None:
        data.add("target_version", target)
    return client.post("/web/upgrade-flow/prep", data=data,
                       follow_redirects=True)


def test_a_sweep_with_no_destination_is_refused_and_stores_nothing(app, client,
                                                                   monkeypatch):
    """Refused, NOT defaulted to the newest known version.

    "Upgrade to the newest one we know about" is a decision. A page that makes
    it silently writes a destination onto forty pieces of evidence nobody
    chose, and every one of them then reads as deliberate.
    """
    from app.models import UpgradePrep
    with app.app_context():
        _mk_image("8.0.5")
        ap = _mk_appliance("fw-b")
        dev_id = ap.id
    login(client, admin_user_id(app))
    body = _sweep(client, app, [dev_id], None, monkeypatch).get_data(as_text=True)
    assert "Nothing was started" in body
    with app.app_context():
        assert UpgradePrep.query.count() == 0, (
            "a refused sweep must not leave evidence behind")


def test_an_oversized_selection_keeps_the_cap_s_message_not_this_one(app,
                                                                     client,
                                                                     monkeypatch):
    """The new question must not steal an older refusal's sentence.

    Got wrong once: the destination check was placed FIRST because "answer the
    one question you must answer" reads better. 41 appliances with no
    destination were then told to pick a version — and the operator retried 41
    appliances. The cap's sentence NAMES THE NUMBER, which is what they have to
    act on either way. Both refusals start nothing; only one of them tells you
    what is actually wrong.
    """
    from werkzeug.datastructures import MultiDict

    from app.views import upgrade_flow as uf
    n = uf.MAX_SWEEP + 1
    with app.app_context():
        _mk_image("8.0.5")
        ids = [_mk_appliance(f"cap-{i}").id for i in range(n)]
    login(client, admin_user_id(app))
    body = client.post("/web/upgrade-flow/prep",
                       data=MultiDict([("device_ids", str(i)) for i in ids]),
                       follow_redirects=True).get_data(as_text=True)
    assert str(n) in body and str(uf.MAX_SWEEP) in body, (
        "the cap must keep naming the number")
    assert "Choose the version this window upgrades TO" not in body


def test_a_destination_this_console_never_heard_of_is_refused(app, client,
                                                              monkeypatch):
    """Resolved against the rendered catalogue, not merely against a regex.

    ``9.9.9`` parses perfectly. It is still a destination with no image, no
    release notes and no Scout verdict — normalising it through would store a
    version nothing on this page can say one word about.
    """
    from app.models import UpgradePrep
    with app.app_context():
        _mk_image("8.0.5")
        ap = _mk_appliance("fw-c")
        dev_id = ap.id
    login(client, admin_user_id(app))
    body = _sweep(client, app, [dev_id], "9.9.9",
                  monkeypatch).get_data(as_text=True)
    assert "9.9.9" in body and "not a version this console knows of" in body
    with app.app_context():
        assert UpgradePrep.query.count() == 0


def test_a_destination_that_is_not_a_version_at_all_is_refused(app, client,
                                                               monkeypatch):
    with app.app_context():
        _mk_image("8.0.5")
        ap = _mk_appliance("fw-c2")
        dev_id = ap.id
    login(client, admin_user_id(app))
    body = _sweep(client, app, [dev_id], "latest",
                  monkeypatch).get_data(as_text=True)
    assert "is not a firmware version" in body


def test_the_three_refusals_do_not_share_one_sentence(app):
    """Absent, unparseable and unknown are three different mistakes.

    One message for all three sends the operator who typed ``latest`` to the
    API-versions page and the operator who typed ``9.9.9`` to re-read the
    form. Guarded because collapsing them is the natural tidy-up.
    """
    from app.views import upgrade_flow as uf
    with app.app_context():
        opts = [{"version": "8.0.5"}]
        _, absent = uf.resolve_target("", opts)
        _, junk = uf.resolve_target("latest", opts)
        _, unknown = uf.resolve_target("9.9.9", opts)
        assert len({absent, junk, unknown}) == 3
        assert all(m for m in (absent, junk, unknown))


def test_the_real_runner_carries_it_from_the_sweep_to_the_row(app,
                                                              monkeypatch):
    """``run_for`` itself, not a stub of it.

    Every other test here replaces ``run_for`` so no live appliance is
    touched — which means none of them exercises the one hop where the value
    could be dropped. Only ``upgrade.prepare`` (the call that talks to the
    box) and the inventory read are stubbed here; the threading is real.
    """
    from app.services import change_requests as crsvc
    from app.services import prep_store, upgrade
    with app.app_context():
        ap = _mk_appliance("fw-real")
        monkeypatch.setattr(upgrade, "prepare",
                            lambda a, **kw: {"firmware": "7.6.8"})
        monkeypatch.setattr(crsvc, "affected_policies", lambda ids, **kw: [])
        _result, prep = prep_store.run_for(ap, created_by="op",
                                           target_version="8.0.5")
        assert prep is not None
        assert prep.target_version == "8.0.5"


def test_the_bulk_runner_carries_it_too(app, monkeypatch):
    """``run_bulk`` -> ``run_for`` -> ``record``, all three real."""
    from app.services import change_requests as crsvc
    from app.services import prep_store, upgrade
    with app.app_context():
        aps = [_mk_appliance("fw-real1"), _mk_appliance("fw-real2")]
        monkeypatch.setattr(upgrade, "prepare",
                            lambda a, **kw: {"firmware": "7.6.8"})
        monkeypatch.setattr(crsvc, "affected_policies", lambda ids, **kw: [])
        rows = prep_store.run_bulk(aps, created_by="op",
                                   target_version="8.0.6")
        assert [r["target_version"] for r in rows] == ["8.0.6", "8.0.6"], (
            "the row a caller reports from must quote what was STORED")
        assert all(prep_store.get(r["prep_id"]).target_version == "8.0.6"
                   for r in rows)


def test_a_good_destination_reaches_every_stored_run(app, client, monkeypatch):
    """The value is threaded all the way to the row, for EVERY device."""
    from app.models import UpgradePrep
    with app.app_context():
        _mk_image("8.0.5")
        ids = [_mk_appliance("fw-d1").id, _mk_appliance("fw-d2").id]
    login(client, admin_user_id(app))
    calls = []
    body = _sweep(client, app, ids, "8.0.5", monkeypatch,
                  calls=calls).get_data(as_text=True)
    assert "towards 8.0.5" in body, "the sweep report must name the destination"
    assert sorted(t for _n, t in calls) == ["8.0.5", "8.0.5"]
    with app.app_context():
        stored = {p.target_version for p in UpgradePrep.query.all()}
        assert stored == {"8.0.5"}
        assert UpgradePrep.query.count() == 2


# =========================================================================== #
#  3. the catalogue the select offers                                          #
# =========================================================================== #
def test_the_options_come_from_the_one_version_catalogue(app):
    """Not a hand-kept list. Uploaded, running-in-the-fleet and hand-declared."""
    from app.views import upgrade_flow as uf
    with app.app_context():
        _mk_image("8.0.5")
        _mk_appliance("fw-e", firmware="7.6.8")
        _declare("8.0.6")
        versions = [o["version"] for o in uf.target_options()]
        assert versions == ["8.0.6", "8.0.5", "7.6.8"], (
            "newest first, and all three sources present")


def test_an_install_image_is_not_reported_as_an_upgrade_image(app):
    """``.zip``/``.qcow2``/``.ova`` build a machine from nothing.

    Reporting one as "the image for 8.0.5 is here" sends somebody into a
    window holding a file that must never touch a running appliance. The
    version still APPEARS — it exists — it simply is not claimed to be
    flashable.
    """
    from app.views import upgrade_flow as uf
    with app.app_context():
        _mk_image("8.0.5", kind="install")
        row = {o["version"]: o for o in uf.target_options()}["8.0.5"]
        assert row["has_image"] is False
        assert row["images"] == []


def test_a_version_with_no_image_is_offered_and_labelled_not_refused(app):
    """Pre-flighting before the .out lands is ordinary and must stay possible.

    Blocking it would push the entire pre-flight to the last moment, which is
    the opposite of what a pre-flight is for. The page SAYS which is which.
    """
    from app.views import upgrade_flow as uf
    with app.app_context():
        _declare("8.0.9")
        row = {o["version"]: o for o in uf.target_options()}["8.0.9"]
        assert row["has_image"] is False
        assert uf.resolve_target("8.0.9", uf.target_options())[1] == "", (
            "a version with no image must still be a legal sweep target")


def test_a_line_is_kept_apart_from_its_zero_patch(app):
    """``8.0`` is not ``8.0.0`` and must not be widened into one."""
    from app.views import upgrade_flow as uf
    with app.app_context():
        _declare("8.0")
        row = {o["version"]: o for o in uf.target_options()}["8.0"]
        assert row["line_only"] is True
        assert row["version"] == "8.0"


# =========================================================================== #
#  4. Scout, per appliance, for the move that was recorded                     #
# =========================================================================== #
def test_scout_reviews_the_recorded_move_not_the_select(app):
    """The badge answers for the run, so it cannot claim a review of a move
    no appliance has been pre-flighted for yet."""
    from app.views import upgrade_flow as uf
    with app.app_context():
        ap = _mk_appliance("fw-f", firmware="7.6.8")
        prep = _mk_prep(ap, target="8.0.5", firmware="7.6.8")
        out = uf.scout_reviews([ap], {ap.id: prep})
        assert ap.id in out
        assert out[ap.id]["target"] == "8.0.5"
        assert out[ap.id]["current"] == "7.6.8"


def test_an_appliance_with_no_recorded_destination_gets_no_badge(app):
    """Absent is ABSENT. 'no target recorded', 'unknown' (Scout looked and the
    corpus had nothing) and 'clear' are three different statements, and a
    default badge would spell the first as one of the other two."""
    from app.views import upgrade_flow as uf
    with app.app_context():
        ap = _mk_appliance("fw-g")
        assert uf.scout_reviews([ap], {ap.id: _mk_prep(ap, target=None)}) == {}
        assert uf.scout_reviews([ap], {}) == {}


def test_a_review_that_could_not_run_never_spells_itself_clear(app,
                                                               monkeypatch):
    """The one thing this badge must never do."""
    from app.services import scout_config
    from app.views import upgrade_flow as uf
    with app.app_context():
        monkeypatch.setattr(scout_config, "enabled", lambda: False)
        ap = _mk_appliance("fw-h")
        prep = _mk_prep(ap, target="8.0.5")
        out = uf.scout_reviews([ap], {ap.id: prep})
        assert out[ap.id]["verdict"] == "unavailable"
        assert out[ap.id]["verdict"] != "clear"
        assert out[ap.id]["reason"], "a review that did not run must say why"


def test_the_reviews_are_memoised_per_move_not_per_appliance(app, monkeypatch):
    """Forty boxes on two versions must cost two corpus reads, not forty.

    ``release_corpus.load`` reads and filters the whole harvested JSON on every
    call. Guarded by counting, because the slow version is indistinguishable
    from the fast one on a two-device test fixture.
    """
    from app.services import upgrade_scout
    from app.views import upgrade_flow as uf
    with app.app_context():
        real, seen = upgrade_scout.review, []

        def counted(appliance, target, current=None, **kw):
            seen.append((getattr(appliance, "kind", ""), current, target))
            return real(appliance, target, current=current, **kw)

        monkeypatch.setattr(upgrade_scout, "review", counted)
        devs, preps = [], {}
        for n in range(6):
            ap = _mk_appliance(f"fw-m{n}", firmware="7.6.8")
            devs.append(ap)
            preps[ap.id] = _mk_prep(ap, target="8.0.5", firmware="7.6.8")
        out = uf.scout_reviews(devs, preps)
        assert len(out) == 6
        assert len(seen) == 1, f"one distinct move, {len(seen)} corpus reads"

        # And the key must still SEPARATE moves that share a target. A memo
        # keyed on (kind, target) alone collapses 7.6.8 -> 8.0.5 and
        # 7.4.2 -> 8.0.5 into one answer, and every box on the older line is
        # then shown a review of somebody else's upgrade — with no error.
        seen.clear()
        old = _mk_appliance("fw-m-old", firmware="7.4.2")
        devs.append(old)
        preps[old.id] = _mk_prep(old, target="8.0.5", firmware="7.4.2")
        out = uf.scout_reviews(devs, preps)
        assert len(seen) == 2, (
            f"two distinct moves must be two reads, got {len(seen)}")
        assert out[old.id]["current"] == "7.4.2"
        assert out[devs[0].id]["current"] == "7.6.8"
        assert out[old.id] is not out[devs[0].id]


def test_the_run_s_own_firmware_reading_wins_over_the_inventory_row(app):
    """Old evidence must be graded against what was true when it was taken.

    If the appliance row has since been re-probed to 8.0.5, grading a
    September run against it renders a review of a move the box is no longer
    making — and it renders as ``same version``, which reads as 'nothing to
    worry about'.
    """
    from app.views import upgrade_flow as uf
    with app.app_context():
        ap = _mk_appliance("fw-i", firmware="8.0.5")
        prep = _mk_prep(ap, target="8.0.5", firmware="7.6.8")
        out = uf.scout_reviews([ap], {ap.id: prep})
        assert out[ap.id]["current"] == "7.6.8"


# =========================================================================== #
#  5. it reaches the CHANGE                                                    #
# =========================================================================== #
def _create(app, **over):
    from app.views.change_requests import create_change_request
    fields = {"title": "window", "action": "upgrade", "risk": "medium"}
    fields.update(over)
    return create_change_request(fields)


def test_the_change_carries_the_destination_derived_from_its_evidence(app):
    """``upgrade_flow.change()`` passed no params at all, so every change the
    flow ever raised was born ``params={}`` — and cr_orchestrator reads params
    to build the upgrade webhooks."""
    import json as _json
    with app.app_context():
        ap = _mk_appliance("fw-j")
        prep = _mk_prep(ap, target="8.0.5")
        cr, err = _create(app, device_ids=[ap.id], prep_ids=[prep.id])
        assert cr is not None, err
        assert _json.loads(cr.params)["target_version"] == "8.0.5"


def test_evidence_run_towards_two_versions_is_refused(app):
    """One change request is one move.

    Two ticked runs swept towards different versions is a document whose
    prerequisites section proves half of what it claims. Silently adopting
    either value is the misleading-but-green document this feature removes.
    """
    with app.app_context():
        a1, a2 = _mk_appliance("fw-k1"), _mk_appliance("fw-k2")
        p1 = _mk_prep(a1, target="8.0.5")
        p2 = _mk_prep(a2, target="8.0.6")
        cr, err = _create(app, device_ids=[a1.id, a2.id],
                          prep_ids=[p1.id, p2.id])
        assert cr is None
        assert "8.0.5" in err and "8.0.6" in err
        assert "Nothing was created" in err


def test_a_declaration_that_contradicts_its_evidence_is_refused(app):
    """A change claiming 8.0.6 over runs swept towards 8.0.5 certifies the
    wrong move — and reads correct."""
    with app.app_context():
        ap = _mk_appliance("fw-l")
        prep = _mk_prep(ap, target="8.0.5")
        cr, err = _create(app, device_ids=[ap.id], prep_ids=[prep.id],
                          target_version="8.0.6")
        assert cr is None
        assert "8.0.6" in err and "8.0.5" in err


def test_a_destination_cannot_be_smuggled_in_through_params(app):
    """``params`` is the executor's bag and a caller must not be able to post
    past the two checks above by hiding a value in it — the same reason
    ``change_request_id`` is stripped there."""
    import json as _json
    with app.app_context():
        ap = _mk_appliance("fw-n")
        prep = _mk_prep(ap, target="8.0.5")
        cr, err = _create(app, device_ids=[ap.id], prep_ids=[prep.id],
                          params={"target_version": "9.9.9", "dry_run": True})
        assert cr is not None, err
        params = _json.loads(cr.params)
        assert params["target_version"] == "8.0.5"
        assert params["dry_run"] is True, "other params must survive"


def test_nothing_can_be_smuggled_when_there_is_nothing_to_override_it(app):
    """The sharp case. With evidence present the recomputed value overwrites a
    smuggled one anyway, so that test passes even with the strip removed — it
    proves the RESULT, not the strip. With no evidence and no declaration the
    derived value is empty, and only the strip stands between a caller and a
    destination on a change nobody chose one for."""
    import json as _json
    with app.app_context():
        ap = _mk_appliance("fw-smug")
        cr, err = _create(app, device_ids=[ap.id],
                          params={"target_version": "9.9.9"})
        assert cr is not None, err
        assert "target_version" not in _json.loads(cr.params), (
            "a destination reached the change without passing either check")


def test_a_change_with_no_evidence_declares_no_destination(app):
    """Absent stays absent. Inventing one puts a firmware number on a document
    nobody chose it for."""
    import json as _json
    with app.app_context():
        ap = _mk_appliance("fw-o")
        cr, err = _create(app, device_ids=[ap.id])
        assert cr is not None, err
        assert "target_version" not in _json.loads(cr.params)


def test_a_declaration_alone_is_enough_when_nothing_is_cited(app):
    import json as _json
    with app.app_context():
        ap = _mk_appliance("fw-p")
        cr, err = _create(app, device_ids=[ap.id], target_version="8.0.5")
        assert cr is not None, err
        assert _json.loads(cr.params)["target_version"] == "8.0.5"


# =========================================================================== #
#  6. what the PAGE actually renders                                           #
# =========================================================================== #
def test_the_page_offers_the_select_and_paints_the_move(app, client):
    """Asked of the SERVER, not of the context builder.

    ``render_page`` enumerates its kwargs, so a value this feature computes can
    fail to reach the template with every assertion above still green — that is
    exactly how the ledger-orphans banner was lost on 2026-09-18.
    """
    with app.app_context():
        _mk_image("8.0.5")
        ap = _mk_appliance("fw-q", firmware="7.6.8")
        _mk_prep(ap, target="8.0.5", firmware="7.6.8")
    login(client, admin_user_id(app))
    r = client.get("/web/upgrade-flow/?_adom=fortiweb")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert 'name="target_version"' in body, "the select is not on the page"
    assert "image uploaded" in body
    i_head = body.find(">Move<")
    assert i_head > 0, "the move column header is missing"
    assert "8.0.5" in body
    # The VERDICT, inside the Move cell, not the word "Scout" anywhere on the
    # page. A badge can lose its text and keep its label; a cell that still
    # says "7.6.8 -> 8.0.5" with no verdict beside it is the empty-green
    # panel this feature exists to prevent.
    import re as _re
    tb = body[body.find("<tbody>", i_head):body.find("</tbody>", i_head)]
    cells = _re.findall(r"<td[^>]*>(.*?)</td>", tb[:tb.find("</tr>")], _re.S)
    assert len(cells) == 6, f"the Move column is not a column: {len(cells)} cells"
    move = cells[4]
    assert "8.0.5" in move and "7.6.8" in move, f"the move is not painted: {move[:200]}"
    assert "Scout" in move, "the verdict is not beside the move it is about"
    assert _re.search(r"Scout\s*:\s*(blocker|caution|clear|unknown|unavailable)",
                      _re.sub(r"<[^>]+>", " ", move)), (
        f"no verdict word in the Move cell: {_re.sub(r'<[^>]+>', ' ', move)[:200]}")


def test_a_run_with_no_destination_renders_as_such_not_as_a_version(app,
                                                                    client):
    with app.app_context():
        _mk_image("8.0.5")
        ap = _mk_appliance("fw-r")
        _mk_prep(ap, target=None)
    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/?_adom=fortiweb").get_data(as_text=True)
    assert "no destination recorded" in body


def test_the_page_reports_a_split_window_before_the_form_is_filled_in(app,
                                                                      client):
    """``cited_targets`` is what stage 2 shows and what create_change_request
    would refuse over — read BEFORE the operator fills the form, not after."""
    from app.views import upgrade_flow as uf
    with app.app_context():
        a1, a2 = _mk_appliance("fw-s1"), _mk_appliance("fw-s2")
        p1 = _mk_prep(a1, target="8.0.5")
        p2 = _mk_prep(a2, target="8.0.6")
        out = uf.cited_targets([a1, a2], {a1.id: [p1], a2.id: [p2]},
                               {a1.id: p1.id, a2.id: p2.id})
        assert out["split"] is True
        assert out["versions"] == ["8.0.5", "8.0.6"]
        assert out["one"] == ""


def test_an_appliance_citing_no_run_is_counted_separately(app):
    """"the change is for 8.0.5" over four boxes nobody pre-flighted towards it
    is the half-truth this column exists to remove."""
    from app.views import upgrade_flow as uf
    with app.app_context():
        a1, a2 = _mk_appliance("fw-t1"), _mk_appliance("fw-t2")
        p1 = _mk_prep(a1, target="8.0.5")
        out = uf.cited_targets([a1, a2], {a1.id: [p1]},
                               {a1.id: p1.id, a2.id: ""})
        assert out["one"] == "8.0.5"
        assert out["uncited"] == 1


def test_a_cited_run_that_predates_the_question_is_counted_as_uncited(app):
    """Different from "this appliance cites no run".

    There IS evidence here — it simply declares nothing, because it was taken
    before the destination was ever asked for. It must land in the same count
    the operator reads as "appliances with no destination", or the header says
    "the change is for 8.0.5" over a box whose only baseline says nothing of
    the kind.
    """
    from app.views import upgrade_flow as uf
    with app.app_context():
        a1, a2 = _mk_appliance("fw-old1"), _mk_appliance("fw-old2")
        p1 = _mk_prep(a1, target="8.0.5")
        p2 = _mk_prep(a2, target=None)          # a run from before the column
        out = uf.cited_targets([a1, a2], {a1.id: [p1], a2.id: [p2]},
                               {a1.id: p1.id, a2.id: p2.id})
        assert out["one"] == "8.0.5"
        assert out["uncited"] == 1, (
            "a cited run with no destination must still be counted")
        assert out["split"] is False


def test_an_unticked_appliance_does_not_contribute_a_destination(app):
    """The card must describe the change being raised, not the whole page."""
    from app.views import upgrade_flow as uf
    with app.app_context():
        a1, a2 = _mk_appliance("fw-u1"), _mk_appliance("fw-u2")
        p1 = _mk_prep(a1, target="8.0.5")
        p2 = _mk_prep(a2, target="8.0.6")
        out = uf.cited_targets([a1], {a1.id: [p1], a2.id: [p2]},
                               {a1.id: p1.id, a2.id: p2.id})
        assert out["versions"] == ["8.0.5"]
        assert out["split"] is False


def test_the_select_is_re_proposed_only_when_the_fleet_agrees(app, client):
    """An operator sweeping 40 boxes in two batches is continuing ONE window.

    But picking the most common of a SPLIT would silently answer "which of
    these two windows am I continuing" on their behalf.
    """
    from app.views import upgrade_flow as uf
    with app.app_context():
        _mk_image("8.0.5")
        _mk_image("8.0.6")
        a1 = _mk_appliance("fw-v1")
        _mk_prep(a1, target="8.0.5")
    login(client, admin_user_id(app))
    with client.application.test_request_context("/web/upgrade-flow/"):
        assert uf.page_context()["target_pick"] == "8.0.5"
    with app.app_context():
        a2 = _mk_appliance("fw-v2")
        _mk_prep(a2, target="8.0.6")
    with client.application.test_request_context("/web/upgrade-flow/"):
        assert uf.page_context()["target_pick"] == "", (
            "a split fleet must not be resolved on the operator's behalf")


# =========================================================================== #
#  8. FORWARD MOVES ONLY — the select offers no destination that is not an     #
#     upgrade for at least one appliance on the page                           #
# =========================================================================== #
def test_a_patch_is_compared_numerically_not_as_text(app):
    """``8.0.10`` is newer than ``8.0.9``; as strings it is not.

    The one-line version of this feature is ``target > appliance.firmware``,
    and it is wrong from the tenth patch of any line onwards — which is the
    release nobody is testing against when they write it.
    """
    from app.services import firmware_versions as fv
    assert fv.compare("8.0.10", "8.0.9") == 1
    assert fv.compare("8.0.9", "8.0.10") == -1
    assert "8.0.10" < "8.0.9", "the string comparison this guard exists for"


def test_a_line_against_its_own_line_is_undecidable_not_ordered(app):
    """``sort_key`` orders ``8.0`` under ``8.0.3``. ``compare`` refuses to.

    The second is not a worse version of the first: sorting must be total, so
    it places the weakest claim first, and reading that ordering as "older"
    would call 8.0 a DOWNGRADE from 8.0.3 and hide it. 8.0 means "the 8.0
    line, patch unrecorded" — it could land on 8.0.0 or on 8.0.9.

    This guard is the one that bites when somebody replaces ``compare`` with
    ``sort_key(a) > sort_key(b)``, which passes every other test here.
    """
    from app.services import firmware_versions as fv
    assert fv.sort_key("8.0") < fv.sort_key("8.0.3"), "the ordering it must not use"
    assert fv.compare("8.0", "8.0.3") is None
    assert fv.compare("8.0.3", "8.0") is None
    # Across LINES no patch is needed and the answer is not None.
    assert fv.compare("8.0", "7.6.8") == 1


def test_a_version_below_every_appliance_is_not_offered(app):
    """The whole ask, in its simplest form."""
    from app.views import upgrade_flow as uf
    with app.app_context():
        _declare("7.6.8")
        _mk_image("8.0.5")
        ap = _mk_appliance("fw-fo1", firmware="8.0.5")
        rows = {r["version"]: r for r in uf.target_options(devices=[ap])}
        assert rows["7.6.8"]["offerable"] is False
        assert rows["7.6.8"]["at_or_above"] == ["fw-fo1"]
        # Its OWN version is not an upgrade either.
        assert rows["8.0.5"]["offerable"] is False


def test_a_version_newer_than_only_some_appliances_stays_offered(app):
    """The fleet this was built against, and the rule it rules out.

    fortiweb15/16 run 7.6.8 and fortiweb17 runs 8.0.5. "Newer than the
    HIGHEST version on the page" reads well and would hide 8.0.5 — the one
    move two of the three boxes are waiting for — leaving an operator with an
    empty select and a perfectly legal window. A destination is offered while
    it moves at least ONE appliance forward, and the row says which.
    """
    from app.views import upgrade_flow as uf
    with app.app_context():
        _mk_image("8.0.5")
        a = _mk_appliance("fw-15", firmware="7.6.8")
        b = _mk_appliance("fw-16", firmware="7.6.8")
        c = _mk_appliance("fw-17", firmware="8.0.5")
        row = {r["version"]: r for r in
               uf.target_options(devices=[a, b, c])}["8.0.5"]
        assert row["offerable"] is True
        assert row["upgrades"] == ["fw-15", "fw-16"]
        assert row["at_or_above"] == ["fw-17"]
        assert row["comparable"] == 3


def test_another_product_s_numbering_cannot_hide_a_destination(app):
    """FortiAuthenticator 8.0.3 says nothing about FortiWeb 8.0.5.

    Two vendors' counters that happen to share digits. Folded together, a FAC
    sitting on 8.0.9 would hide FortiWeb 8.0.5 from a page full of FortiWebs
    on 7.6.8, and the reason would be invisible.
    """
    from app.views import upgrade_flow as uf
    with app.app_context():
        _mk_image("8.0.5")
        fac = _mk_appliance("fac-1", kind="fortiauthenticator", firmware="9.9.9")
        fwb = _mk_appliance("fw-fo2", firmware="7.6.8")
        row = {r["version"]: r for r in
               uf.target_options(devices=[fac, fwb])}["8.0.5"]
        assert row["products"] == ["fortiweb"]
        assert row["upgrades"] == ["fw-fo2"]
        assert "fac-1" not in row["at_or_above"] + row["undecided"]
        assert row["comparable"] == 1, "the FAC was compared against FortiWeb"


def test_an_undecidable_destination_is_kept_not_hidden(app):
    """Hidden only when the page can SHOW it is not an upgrade.

    A destination missing from a select is unreportable: the operator has no
    way to ask why the version they came for is not there. So "unknown"
    resolves towards keeping it, and only "provably not newer" removes it.
    """
    from app.views import upgrade_flow as uf
    with app.app_context():
        _declare("8.0")
        ap = _mk_appliance("fw-fo3", firmware="8.0.3")
        row = {r["version"]: r for r in uf.target_options(devices=[ap])}["8.0"]
        assert row["offerable"] is True
        assert row["undecided"] == ["fw-fo3"]
        assert row["upgrades"] == [] and row["at_or_above"] == []


def test_an_appliance_with_no_readable_firmware_never_hides_anything(app):
    from app.views import upgrade_flow as uf
    with app.app_context():
        _mk_image("8.0.5")
        ap = _mk_appliance("fw-fo4", firmware="")
        row = {r["version"]: r for r in uf.target_options(devices=[ap])}["8.0.5"]
        assert row["offerable"] is True and row["undecided"] == ["fw-fo4"]


def test_with_no_appliances_to_compare_every_version_is_offered(app):
    """An empty page cannot prove anything about any version."""
    from app.views import upgrade_flow as uf
    with app.app_context():
        _declare("7.6.8")
        _mk_image("8.0.5")
        for row in uf.target_options(devices=[]):
            assert row["offerable"] is True and row["comparable"] == 0
        # And the parameter is opt-in: callers that pass nothing are unchanged.
        for row in uf.target_options():
            assert row["offerable"] is True


def test_the_select_omits_the_stale_version_and_keeps_the_live_one(app, client):
    """Asked of the SERVER. The filter runs in the view; the template reads
    ``offerable`` and nothing else, so a second filter cannot drift from it."""
    import re as _re
    with app.app_context():
        _declare("7.6.8")
        _mk_image("8.0.5")
        _mk_appliance("fw-fo5", firmware="7.6.8")
    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/?_adom=fortiweb").get_data(as_text=True)
    sel = body[body.find('name="target_version"'):]
    sel = sel[:sel.find("</select>")]
    assert 'value="8.0.5"' in sel, "the real destination is missing"
    assert 'value="7.6.8"' not in sel, (
        "a version no appliance can move to is still on the list")
    assert "only versions newer" in sel.lower() or "Only versions newer" in body


def test_a_page_where_nothing_is_an_upgrade_says_so_and_does_not_read_empty(
        app, client):
    """KNOWN-but-not-OFFERED is its own state.

    Reporting it with the "this console knows of no firmware version" sentence
    would send the operator to declare a version that is already declared.
    """
    with app.app_context():
        _mk_image("8.0.5")
        _mk_appliance("fw-fo6", firmware="8.0.5")
    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/?_adom=fortiweb").get_data(as_text=True)
    assert "none of them is newer" in body
    assert "knows of no firmware version" not in body


def test_a_sweep_towards_a_version_nothing_can_move_to_is_refused(app, client,
                                                                  monkeypatch):
    """The filter is not decoration. A crafted POST meets the same rule."""
    from app.models import UpgradePrep
    with app.app_context():
        _declare("7.6.8")
        _mk_image("8.0.5")
        ap = _mk_appliance("fw-fo7", firmware="8.0.5")
        dev_id = ap.id
    login(client, admin_user_id(app))
    body = _sweep(client, app, [dev_id], "7.6.8",
                  monkeypatch).get_data(as_text=True)
    assert "would not move any of these appliances forward" in body
    assert "fw-fo7" in body, "the refusal does not name who is already ahead"
    assert "not a version this console knows of" not in body, (
        "answered with the wrong refusal — 7.6.8 IS declared")
    with app.app_context():
        assert UpgradePrep.query.count() == 0


def test_the_four_refusals_do_not_share_one_sentence(app):
    """Absent, unparseable, unknown and not-an-upgrade are four mistakes.

    They send the operator to four different places, and the fourth is the one
    most easily collapsed into the third — both are "you cannot have that
    version", and only one of them is fixed by declaring it.
    """
    from app.views import upgrade_flow as uf
    with app.app_context():
        opts = [{"version": "8.0.5", "offerable": True},
                {"version": "7.6.8", "offerable": False,
                 "at_or_above": ["fw-x"]}]
        _, absent = uf.resolve_target("", opts)
        _, junk = uf.resolve_target("latest", opts)
        _, unknown = uf.resolve_target("9.9.9", opts)
        _, stale = uf.resolve_target("7.6.8", opts)
        assert len({absent, junk, unknown, stale}) == 4
        assert all(m for m in (absent, junk, unknown, stale))
        # And the offerable one still resolves.
        assert uf.resolve_target("8.0.5", opts) == ("8.0.5", "")


def test_a_destination_the_page_no_longer_offers_is_not_re_proposed(app,
                                                                    client):
    """The select is re-proposed from the last sweep. It must not re-propose a
    version every remaining appliance has since been moved to — that would
    mark an option the select does not render, leaving a blank control with a
    value posted behind it."""
    with app.app_context():
        _mk_image("8.0.5")
        ap = _mk_appliance("fw-fo8", firmware="8.0.5")
        _mk_prep(ap, target="8.0.5", firmware="7.6.8")
    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/?_adom=fortiweb").get_data(as_text=True)
    sel = body[body.find('name="target_version"'):]
    sel = sel[:sel.find("</select>")]
    assert "selected" not in sel, "a version that is not offered came up selected"


def test_the_option_says_how_many_it_moves_and_who_is_already_ahead(app,
                                                                    client):
    """The page narrows the choice; it does not make it. An operator seeing
    ``8.0.5`` must be able to tell it leaves one of their boxes untouched
    BEFORE they sweep, not from the evidence afterwards."""
    with app.app_context():
        _mk_image("8.0.5")
        _mk_appliance("fw-fo9", firmware="7.6.8")
        _mk_appliance("fw-fo10", firmware="8.0.5")
    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/?_adom=fortiweb").get_data(as_text=True)
    sel = body[body.find('name="target_version"'):]
    sel = sel[:sel.find("</select>")]
    assert "1/2" in sel, f"the option does not say how many it moves: {sel[:400]}"
    assert "fw-fo10" in sel and "already there or ahead" in sel

# =========================================================================== #
#  10. the PER-APPLIANCE hold — the page filter is not the sweep's filter       #
# =========================================================================== #
#  ``forward_only`` narrows the select against everything the PAGE lists: a
#  version stays offered while it moves at least ONE box forward. The sweep
#  runs against the boxes the operator TICKED. Those two sets need not agree,
#  and the gap is reachable with no crafted request at all: on a page holding
#  fw15/fw16 on 7.6.8 and fw17 on 8.0.5, the select offers 8.0.5 (correctly —
#  it moves two of three), the operator unticks fw15 and fw16, and sweeps
#  fw17 towards the version it is already running. Every window-level rule
#  passes. What gets written is evidence whose declared move is 8.0.5 ->
#  8.0.5, and the Move column paints it as a real one.
# --------------------------------------------------------------------------- #
def test_an_appliance_already_on_the_target_is_not_swept(app, client,
                                                         monkeypatch):
    """The hole, closed. Nothing is recorded for the box that cannot move."""
    from app.models import UpgradePrep
    with app.app_context():
        _mk_image("8.0.5")
        _mk_appliance("fw-h1", firmware="7.6.8")
        ap = _mk_appliance("fw-h2", firmware="8.0.5")
        dev_id = ap.id
    login(client, admin_user_id(app))
    body = _sweep(client, app, [dev_id], "8.0.5",
                  monkeypatch).get_data(as_text=True)
    assert "fw-h2 cannot be upgraded to 8.0.5" in body
    assert "already running it" in body
    with app.app_context():
        assert UpgradePrep.query.count() == 0, (
            "a run was stored for an appliance that was never pre-flighted")


def test_a_target_older_than_the_box_is_called_a_downgrade_not_a_no_op(app):
    """Two sentences, because they are two mistakes.

    "It is already on 8.0.5" is fixed by picking a later version or unticking
    the row. "It is on 8.0.6 and you picked 8.0.5" means the destination
    chosen for the whole window is BEHIND something in it — a downgrade, an
    operation this pre-flight reviews nothing about. Telling the second story
    with the first one's words sends the operator to reread a selection that
    is not the mistake.
    """
    from app.views import upgrade_flow as uf
    with app.app_context():
        same = _mk_appliance("fw-h3", firmware="8.0.5")
        ahead = _mk_appliance("fw-h4", firmware="8.0.6")
        split = uf.sweep_split("8.0.5", ["fortiweb"], [same, ahead])
        assert split["run"] == []
        codes = {h["name"]: h["code"] for h in split["held"]}
        assert codes == {"fw-h3": uf.MOVE_SAME, "fw-h4": uf.MOVE_BEHIND}
        why = {h["name"]: h["reason"] for h in split["held"]}
        assert why["fw-h3"] != why["fw-h4"]
        assert "DOWNGRADE" in why["fw-h4"]
        assert "8.0.6" in why["fw-h4"], (
            "the downgrade sentence never says what the box is actually on")
        assert "DOWNGRADE" not in why["fw-h3"]


def test_one_held_box_does_not_throw_away_the_rest_of_the_sweep(app, client,
                                                                monkeypatch):
    """Skipped, not refused. Forty boxes must not be lost over the one extra
    tick — the operator would retick thirty-nine and press the same button."""
    from app.models import UpgradePrep
    calls = []
    with app.app_context():
        _mk_image("8.0.5")
        moves = _mk_appliance("fw-h5", firmware="7.6.8")
        held = _mk_appliance("fw-h6", firmware="8.0.5")
        ids = [moves.id, held.id]
    login(client, admin_user_id(app))
    body = _sweep(client, app, ids, "8.0.5", monkeypatch,
                  calls=calls).get_data(as_text=True)
    assert [c[0] for c in calls] == ["fw-h5"], (
        "the pre-flight ran against a box it had just refused to run against")
    assert "fw-h6 cannot be upgraded" in body
    assert "It was skipped; the rest of the sweep ran." in body
    with app.app_context():
        rows = UpgradePrep.query.all()
        assert [r.appliance_id for r in rows] == [moves.id]
        assert rows[0].target_version == "8.0.5"


def test_a_sweep_where_nothing_moves_starts_nothing_and_says_so(app, client,
                                                                monkeypatch):
    """The window IS refused when the selection is empty of movable boxes.

    A summary reading "swept 0 appliance(s): 0 clean" is not a refusal — it
    is a green-looking report of a sweep that never happened.
    """
    from app.models import UpgradePrep
    with app.app_context():
        _mk_image("8.0.5")
        _mk_appliance("fw-h7", firmware="7.6.8")
        ap = _mk_appliance("fw-h8", firmware="8.0.5")
        ids = [ap.id]
    login(client, admin_user_id(app))
    body = _sweep(client, app, ids, "8.0.5",
                  monkeypatch).get_data(as_text=True)
    assert "Nothing was started: not one of the 1 selected appliance(s)" in body
    assert "fw-h8 cannot be upgraded" in body, (
        "the refusal never says WHICH box could not move, or why")
    assert "Pre-upgrade swept" not in body, (
        "a sweep that started nothing still reported a sweep")
    with app.app_context():
        assert UpgradePrep.query.count() == 0


def test_the_skip_is_counted_apart_from_a_failure(app, client, monkeypatch):
    """A box skipped because it is already there had NOTHING go wrong with it.

    Folding it into "could not be pre-flighted" sends somebody to debug a
    healthy appliance.
    """
    with app.app_context():
        _mk_image("8.0.5")
        moves = _mk_appliance("fw-h9", firmware="7.6.8")
        held = _mk_appliance("fw-h10", firmware="8.0.5")
        ids = [moves.id, held.id]
    login(client, admin_user_id(app))
    body = _sweep(client, app, ids, "8.0.5",
                  monkeypatch).get_data(as_text=True)
    assert "Pre-upgrade swept 1 appliance(s) towards 8.0.5" in body
    assert "1 skipped: already on 8.0.5 or past it." in body
    assert "1 could not be pre-flighted" not in body


def test_an_undecidable_box_is_swept_not_held(app):
    """Only what the page can PROVE is a no-op may be skipped.

    A line-only destination against a box already on that line could turn out
    to be either direction (``firmware_versions.compare`` returns None), and
    silently not running an appliance the operator ticked is unreportable —
    nobody can ask why the box they selected has no evidence.
    """
    from app.views import upgrade_flow as uf
    with app.app_context():
        blank = _mk_appliance("fw-h12", firmware="")
        online = _mk_appliance("fw-h13", firmware="8.0.3")
        split = uf.sweep_split("8.0", ["fortiweb"], [blank, online])
        assert split["held"] == []
        assert {d.name for d in split["run"]} == {"fw-h12", "fw-h13"}


def test_another_product_s_numbering_cannot_hold_a_box_back(app):
    """Same trap as the select's, one layer down. A FortiAuthenticator on
    8.0.5 says nothing about whether FortiWeb 8.0.5 moves it."""
    from app.views import upgrade_flow as uf
    with app.app_context():
        other = _mk_appliance("fac-h1", kind="fortiauthenticator",
                              firmware="8.0.5")
        split = uf.sweep_split("8.0.5", ["fortiweb"], [other])
        assert split["held"] == []
        assert [d.name for d in split["run"]] == ["fac-h1"]


def test_the_hold_sentence_has_one_author(app, client):
    """The hint the page paints and the flash the sweep sends back are the
    SAME string from the SAME function. Two authors is how a page comes to
    promise a skip the sweep does not perform — and the template's copy is
    the one nothing tests."""
    from app.views import upgrade_flow as uf
    with app.app_context():
        _mk_image("8.0.5")
        _mk_appliance("fw-h14", firmware="7.6.8")
        ap = _mk_appliance("fw-h15", firmware="8.0.5")
        rows = uf.target_options(devices=[ap])
        row = next(r for r in rows if r["version"] == "8.0.5")
        from_page = row["holds"]["fw-h15"]
        from_sweep = uf.sweep_split("8.0.5", ["fortiweb"], [ap])["held"][0]
        assert from_page == from_sweep["reason"]


def test_the_page_carries_the_refusals_as_data(app, client):
    """Rendered as server data, and reachable by the appliance's own name —
    which is the key the row hint looks itself up by."""
    with app.app_context():
        _mk_image("8.0.5")
        _mk_appliance("fw-h16", firmware="7.6.8")
        _mk_appliance("fw-h17", firmware="8.0.5")
    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/?_adom=fortiweb").get_data(as_text=True)
    blob = body[body.find('id="uf-holds"'):]
    blob = blob[blob.find(">") + 1:blob.find("</script>")]
    data = json.loads(blob)
    assert "fw-h17" in data["8.0.5"]
    assert "cannot be upgraded to 8.0.5" in data["8.0.5"]["fw-h17"]
    assert "fw-h16" not in data.get("8.0.5", {}), (
        "a box the version DOES move forward was marked as held")
    assert 'class="uf-hold' in body, "the row has nowhere to paint the hint"


def test_the_checkbox_of_a_held_appliance_is_not_disabled(app, client):
    """The browser does not get to decide what the form posts.

    Disabling the box would drop it from the request entirely, making the
    skip a client-side filter — and a client-side filter is exactly what the
    server-side rule above exists to be instead of.
    """
    with app.app_context():
        _mk_image("8.0.5")
        _mk_appliance("fw-h18", firmware="8.0.5")
    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/?_adom=fortiweb").get_data(as_text=True)
    row = body[body.find('class="form-check-input uf-dev"'):]
    row = row[:row.find("</tr>")]
    assert "disabled" not in row


def test_a_held_appliance_is_still_offered_in_the_select_for_the_others(app,
                                                                        client):
    """The two rules stay independent. 8.0.5 must keep being offered because
    it moves fw-h19 — the hold is about fw-h20, and only when fw-h20 is the
    thing being swept."""
    with app.app_context():
        _mk_image("8.0.5")
        _mk_appliance("fw-h19", firmware="7.6.8")
        _mk_appliance("fw-h20", firmware="8.0.5")
    login(client, admin_user_id(app))
    body = client.get("/web/upgrade-flow/?_adom=fortiweb").get_data(as_text=True)
    sel = body[body.find('name="target_version"'):]
    sel = sel[:sel.find("</select>")]
    assert '<option value="8.0.5"' in sel


def test_a_sweep_that_skipped_a_box_is_not_reported_green(app, client,
                                                          monkeypatch):
    """A green banner IS a claim, and the claim is "that is the whole window".

    Thirty-nine clean runs and one appliance quietly left out reads as forty
    ready boxes if the summary comes up in success colours — the operator has
    no reason to read a green banner twice.
    """
    from app.services import prep_store
    with app.app_context():
        _mk_image("8.0.5")
        moves = _mk_appliance("fw-h21", firmware="7.6.8")
        held = _mk_appliance("fw-h22", firmware="8.0.5")
        ids = [moves.id, held.id]
    # The runs have to come back CLEAN for this to test anything. A stub that
    # records a not-clean run turns the banner amber on its own, and the guard
    # passes while the skip contributes nothing — which is exactly how the
    # first version of this test let its mutation survive.
    monkeypatch.setattr(prep_store, "run_bulk", lambda devices, **kw: [
        {"appliance_id": d.id, "name": d.name, "kind": d.kind, "ok": True,
         "stored": True, "prep_id": 1, "target_version": kw.get(
             "target_version") or "", "summary": "", "error": ""}
        for d in devices])
    login(client, admin_user_id(app))
    body = _sweep(client, app, ids, "8.0.5",
                  monkeypatch).get_data(as_text=True)
    assert "1 clean, 0 ran but not clean, 0 could not be pre-flighted" in body
    at = body.find("Pre-upgrade swept")
    assert at > 0
    block = body[body.rfind("<div", 0, at):at]
    assert "fw-alert-warning" in block, f"summary rendered as: {block[:160]}"
    assert "fw-alert-success" not in block
