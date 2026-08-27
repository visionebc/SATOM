"""Guards for the three mutations that survived the 2026-08-27 harness.

A surviving mutation is not a bug report -- it is a statement that a behaviour
this code relies on is asserted NOWHERE, so the next edit is free to remove it.
All three change a real outcome and all three went green.
"""
from __future__ import annotations


def _appliance(app, name="fw1"):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name=name, kind="fortiweb", host="192.0.2.99", port=443,
                      username="admin", verify_ssl=False)
        a.password = "secret"
        db.session.add(a); db.session.commit()
        return a.id


def _add(aid, **kw):
    from app.services import wpp_exceptions as s
    kw.setdefault("wpp_mkey", "wpp-x")
    kw.setdefault("exc_type", "signature_filter_item")
    kw.setdefault("payload", {"signature_id": "1"})
    return s.add(aid, **kw)


# ─────────────────────────────────── 1. the delete version is written FIRST
def test_the_delete_version_carries_the_body_it_is_losing(app):
    """``record_delete`` must run while the row is still readable.

    Recorded after the row is gone, ``body_of(exc)`` reads a detached object:
    the history keeps an entry that says "deleted" and carries nothing, so the
    restore it exists to enable produces an empty carve-out. Nothing fails at
    delete time -- the damage is only visible at the moment somebody actually
    needs the undo, which is the worst possible moment to find out.
    """
    from app.models import db
    from app.services import exception_versions as V
    from app.services import exception_lifecycle as L
    aid = _appliance(app)
    with app.app_context():
        exc = _add(aid, name="doomed", policies=["pol-a"])
        lineage = V.ensure_lineage(exc)
        db.session.commit()
        assert L.guarded_delete(exc, bindings=None, acknowledge=True)["ok"] is True
        db.session.commit()
        newest = V.latest(lineage)
        assert newest is not None and newest.action == V.ACT_DELETE
        body = newest.body_dict
        assert body.get("name") == "doomed" and body.get("exc_type"), (
            "the delete version must carry the body that was lost; an empty "
            "one read off an already-deleted row restores nothing")
        assert V.restore(lineage, appliance_id=aid)["ok"] is True


# ──────────────────────────── 2. restorable never offers a LIVE lineage
def test_a_lineage_with_a_live_sibling_is_not_offered_for_restore(app):
    """``restore()`` refuses while any placement of the lineage is live, so
    offering it in the list produces a button that cannot work. The action
    filter alone does not cover this: a SPLIT leaves two placements sharing a
    lineage, and deleting one makes the newest recorded event a DELETE while
    the other is still there.
    """
    from app.models import db
    from app.services import wpp_exceptions as s
    from app.services import exception_versions as V
    from app.services import exception_lifecycle as L
    aid = _appliance(app)
    with app.app_context():
        first = _add(aid, name="twin-a", policies=["pol-a"])
        lineage = V.ensure_lineage(first)
        db.session.commit()
        s.add(aid, wpp_mkey="wpp-x", exc_type="signature_filter_item",
              payload={"signature_id": "1"}, name="twin-b",
              policies=["pol-b"], lineage=lineage)
        db.session.commit()
        L.guarded_delete(first, bindings=None, acknowledge=True)
        db.session.commit()
        assert V.latest(lineage).action == V.ACT_DELETE
        assert V.restore(lineage, appliance_id=aid)["ok"] is False
        assert lineage not in {r["lineage"] for r in V.restorable_for(aid)}, (
            "restorable_for must agree with restore(): a lineage that still "
            "has a live placement is a rollback, not a restore")


# ─────────────────────────── 3. a destination outside the visible set
def test_a_destination_this_session_cannot_see_is_refused(app):
    """The multi-appliance push takes ids straight from the request body. An
    id outside the visible set has to be REFUSED by name, never quietly
    dropped and never accepted: a deploy that reaches an appliance the
    operator cannot see writes a carve-out nobody will look for, on a box
    nobody meant to touch."""
    from app.models import WppException
    from app.services import exception_deploy as D
    a1 = _appliance(app, "fw1")
    with app.app_context():
        exc = _add(a1, name="spread")
        ghost = 99999                      # no such appliance in this session
        res = D.plan(exc, [a1, ghost])
        assert ghost in {r.get("appliance_id") for r in res["refused"]}
        assert ghost not in {t.get("appliance_id") for t in res["would_place"]}
        placed = D.place(exc, [ghost], author="t")
        assert placed["placed"] == []
        assert WppException.query.filter_by(appliance_id=ghost).count() == 0, (
            "a refused destination must not receive a row")
