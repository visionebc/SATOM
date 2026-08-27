"""The versioner: identity, content-addressing, rollback, delete and restore.

What these guard, and why each one had to exist:

* **an unchanged save must cost nothing** — without content-addressing every
  re-render of the form buries the real edits under identical rows, and the
  history stops being usable exactly when someone needs it;
* **history survives the delete** — a ``FOREIGN KEY … ON DELETE CASCADE``
  would take the history down with the record, making "undo the delete" the
  one operation the versioner cannot do;
* **a rollback appends** — a versioner that rewrote its own history loses the
  trail of what was tried and undone, which is the part an incident review
  reads;
* **a version cannot cross lineages** — ids are sequential enough that a
  mistyped one usually EXISTS, so "not found" is not the failure mode; being
  overwritten with a stranger's content is.
"""
from __future__ import annotations

import json

from tests.conftest import admin_user_id, login


def _make_appliance(app, name="fw1"):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name=name, kind="fortiweb", host="192.0.2.99",
                      port=443, username="admin", verify_ssl=False)
        a.password = "secret"
        db.session.add(a); db.session.commit()
        return a.id


def _add(s, aid, **kw):
    kw.setdefault("wpp_mkey", "wpp-x")
    kw.setdefault("exc_type", "signature_filter_item")
    kw.setdefault("payload", {"signature_id": "010000001"})
    return s.add(aid, **kw)


# ── hashing rules ──────────────────────────────────────────────────────────
def test_hash_is_order_independent():
    """Without ``sort_keys`` two identical bodies hash differently, every save
    mints a version, and 'an unchanged save costs nothing' is gone."""
    from app.models_exceptions import sha_of
    a = {"name": "x", "payload": {"b": 1, "a": 2}, "policies": ["p"]}
    b = {"policies": ["p"], "payload": {"a": 2, "b": 1}, "name": "x"}
    assert sha_of(a) == sha_of(b)


def test_hash_ignores_volatile_keys():
    from app.models_exceptions import VOLATILE_KEYS, sha_of
    assert "updated_at" in VOLATILE_KEYS
    base = {"name": "x"}
    assert sha_of(base) == sha_of({**base, "updated_at": "2026-01-01"})


def test_body_excludes_the_appliance():
    """A version is the state of the CARVE-OUT. Freezing the appliance into it
    would make moving one to another box read as an edit of its content."""
    from app.models_exceptions import body_of
    from app.services import wpp_exceptions as s
    keys = set(body_of(type("X", (), {
        "exc_type": "t", "category": "c", "wpp_mkey": "w", "name": "n",
        "reason": "r", "enabled": True, "payload_dict": {},
        "policy_names": [],
    })()).keys())
    assert "appliance_id" not in keys and "appliance" not in keys
    assert {"exc_type", "wpp_mkey", "payload", "policies"} <= keys
    assert s.CAT_SIGNATURE  # the store is the catalog authority, not this body


# ── identity ───────────────────────────────────────────────────────────────
def test_create_mints_lineage_and_one_version(app):
    from app.services import exception_versions as V
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    with app.app_context():
        exc = _add(s, aid, policies=["pol-a"])
        assert exc.lineage, "a created carve-out must carry a stable identity"
        hist = V.history(exc.lineage)
        assert len(hist) == 1 and hist[0].action == V.ACT_CREATE
        assert hist[0].exception_id == exc.id, (
            "the version must carry a real id — recording before the flush "
            "freezes NULL into history")


def test_legacy_rows_are_not_backfilled(app):
    """A carve-out that predates the versioner has NO history, and the page
    must be able to say so instead of rendering an empty timeline as clean."""
    from app.models import WppException, db
    from app.services import exception_versions as V
    aid = _make_appliance(app)
    with app.app_context():
        exc = WppException(appliance_id=aid, wpp_mkey="w",
                           exc_type="signature_filter_item", payload="{}")
        db.session.add(exc); db.session.commit()
        assert exc.lineage is None
        assert V.history(exc.lineage) == []


# ── content-addressing ─────────────────────────────────────────────────────
def test_unchanged_save_writes_nothing(app):
    from app.services import exception_versions as V
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    with app.app_context():
        exc = _add(s, aid, policies=["pol-a"])
        s.update(exc.id, payload={"signature_id": "010000001"},
                 policies=["pol-a"])
        assert len(V.history(exc.lineage)) == 1


def test_real_edit_appends_a_version(app):
    from app.services import exception_versions as V
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    with app.app_context():
        exc = _add(s, aid)
        s.update(exc.id, payload={"signature_id": "999"}, author="ann",
                 note="fp confirmed")
        hist = V.history(exc.lineage)
        assert len(hist) == 2
        assert hist[0].action == V.ACT_UPDATE and hist[0].author == "ann"


def test_policy_reorder_is_not_a_change(app):
    """The store sorts, but an imported body may not. Reporting a reorder as a
    change makes every import look like an edit."""
    from app.services import exception_versions as V
    assert V.diff({"policies": ["b", "a"]}, {"policies": ["a", "b"]})["identical"]


# ── structural diff ────────────────────────────────────────────────────────
def test_diff_reports_payload_fields_by_name(app):
    from app.services import exception_versions as V
    d = V.diff({"payload": {"ip": "1.1.1.1", "gone": 1}, "name": "a"},
               {"payload": {"ip": "2.2.2.2", "new": 3}, "name": "b"})
    changed = {c["field"]: (c["old"], c["new"]) for c in d["changed"]}
    assert changed["payload.ip"] == ("1.1.1.1", "2.2.2.2")
    assert changed["name"] == ("a", "b")
    assert {a["field"] for a in d["added"]} == {"payload.new"}
    assert {r["field"] for r in d["removed"]} == {"payload.gone"}
    assert not d["identical"]


# ── rollback ───────────────────────────────────────────────────────────────
def test_rollback_restores_body_and_appends(app):
    from app.services import exception_versions as V
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    with app.app_context():
        exc = _add(s, aid, payload={"signature_id": "1"}, policies=["pol-a"])
        first = V.history(exc.lineage)[0].id
        s.update(exc.id, payload={"signature_id": "2"}, policies=["pol-b"])
        res = V.rollback(exc, first, author="ann")
        assert res["ok"] and res["changed"]
        back = s.get(exc.id)
        assert back.payload_dict == {"signature_id": "1"}
        assert back.policy_names == ["pol-a"]
        hist = V.history(exc.lineage)
        assert len(hist) == 3, "a rollback APPENDS; it never rewrites history"
        assert hist[0].action == V.ACT_ROLLBACK


def test_rollback_refuses_a_foreign_version(app):
    """Ids are sequential enough that a mistyped one usually EXISTS — being
    overwritten with a stranger's content is the real failure mode."""
    from app.services import exception_versions as V
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    with app.app_context():
        a = _add(s, aid, name="a")
        b = _add(s, aid, name="b", payload={"signature_id": "7"})
        foreign = V.history(b.lineage)[0].id
        res = V.rollback(a, foreign)
        assert res["ok"] is False and "another" in res["error"]
        assert s.get(a.id).name == "a"


def test_rollback_does_not_change_the_type(app):
    """Changing the type of a live placement turns it into a different object
    whose payload no longer validates against the catalog."""
    from app.services import exception_versions as V
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    with app.app_context():
        exc = _add(s, aid)
        vid = V.history(exc.lineage)[0].id
        row = V.history(exc.lineage)[0]
        row.body = json.dumps({**row.body_dict, "exc_type": "geo_ip_exception_member_item",
                               "name": "renamed"})
        from app.models import db
        db.session.commit()
        V.rollback(exc, vid)
        assert s.get(exc.id).exc_type == "signature_filter_item"


# ── delete + restore ───────────────────────────────────────────────────────
def test_history_survives_the_delete(app):
    from app.services import exception_versions as V
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    with app.app_context():
        exc = _add(s, aid, policies=["pol-a"])
        lin = exc.lineage
        s.delete(exc.id, author="ann")
        hist = V.history(lin)
        assert len(hist) == 2 and hist[0].action == V.ACT_DELETE
        assert hist[0].body_dict["policies"] == ["pol-a"], (
            "the delete marker must be recorded BEFORE the row goes; after it "
            "the bindings are gone and a restore loses them")


def test_restore_brings_it_back_with_its_bindings(app):
    from app.services import exception_versions as V
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    with app.app_context():
        exc = _add(s, aid, name="keepme", policies=["pol-a", "pol-b"])
        lin = exc.lineage
        s.delete(exc.id)
        assert [r["name"] for r in V.restorable_for(aid)] == ["keepme"]
        res = V.restore(lin, appliance_id=aid, author="ann")
        assert res["ok"]
        back = s.get(res["exc_id"])
        assert back.policy_names == ["pol-a", "pol-b"]
        assert back.lineage == lin, "a restore continues the lineage"
        assert V.restorable_for(aid) == [], "it is live again, not restorable"


def test_restore_refuses_over_a_live_placement(app):
    from app.services import exception_versions as V
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    with app.app_context():
        exc = _add(s, aid)
        res = V.restore(exc.lineage, appliance_id=aid)
        assert res["ok"] is False and "rollback" in res["error"]


def test_restorable_is_scoped_to_the_appliance(app):
    from app.services import exception_versions as V
    from app.services import wpp_exceptions as s
    a1 = _make_appliance(app, "fw1")
    a2 = _make_appliance(app, "fw2")
    with app.app_context():
        exc = _add(s, a1, name="only-on-fw1")
        s.delete(exc.id)
        assert [r["name"] for r in V.restorable_for(a1)] == ["only-on-fw1"]
        assert V.restorable_for(a2) == []


def test_purge_records_the_loss(app):
    """The clean-migration purge is a delete. A purge that left no version
    would be the one destructive path with no undo."""
    from app.services import exception_versions as V
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    with app.app_context():
        exc = _add(s, aid, policies=["pol-a"])
        lin = exc.lineage
        assert s.delete_for_policy(aid, "pol-a") == 1
        hist = V.history(lin)
        assert hist and hist[0].action == V.ACT_DELETE


def test_purge_unbind_records_an_update(app):
    from app.services import exception_versions as V
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    with app.app_context():
        exc = _add(s, aid, policies=["pol-a", "pol-b"])
        lin = exc.lineage
        assert s.delete_for_policy(aid, "pol-a") == 0
        hist = V.history(lin)
        assert len(hist) == 2 and hist[0].action == V.ACT_UPDATE
        assert hist[0].body_dict["policies"] == ["pol-b"]


# ── schema bootstrap ───────────────────────────────────────────────────────
def test_schema_adds_columns_under_one_key():
    """A repeated key in ``_ensure_columns``'s literal is a SILENT loss —
    Python keeps the last one and every column under the earlier copy is never
    added. It happened while writing this feature: the new columns went under a
    SECOND 'wpp_exceptions' key and the first save 500s'd on a column the model
    declares. Guard reads the SOURCE, because the duplicates collapse before
    the dict exists."""
    import re
    src = open("/opt/satom/app/__init__.py", encoding="utf-8").read()
    body = src.split("def _ensure_columns", 1)[1].split("insp = inspect", 1)[0]
    keys = re.findall(r"^\s+'([a-z_]+)': \[", body, re.M)
    assert len(keys) == len(set(keys)), (
        "duplicate table keys shadow each other: %s"
        % sorted({k for k in keys if keys.count(k) > 1}))
    assert "wpp_exceptions" in keys
    idx = body.index("'wpp_exceptions': [")
    block = body[idx:body.index("],", idx)]
    assert "'lineage'" in block and "'library_uid'" in block


# ── routes ─────────────────────────────────────────────────────────────────
def _login_admin(app, client):
    login(client, admin_user_id(app))


def test_version_routes_round_trip(app, client):
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    _login_admin(app, client)
    with app.app_context():
        exc = _add(s, aid, payload={"signature_id": "1"})
        eid, lin = exc.id, exc.lineage
        s.update(exc.id, payload={"signature_id": "2"})

    r = client.get(f"/exceptions/{aid}/versions?exc_id={eid}")
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] and data["versioned"] and len(data["versions"]) == 2
    oldest = data["versions"][-1]["id"]

    r = client.get(f"/exceptions/{aid}/version-diff?exc_id={eid}&a={oldest}")
    d = r.get_json()
    assert d["ok"] and d["right"] == "current"
    assert any(c["field"] == "payload.signature_id" for c in d["diff"]["changed"])

    r = client.post(f"/exceptions/{aid}/rollback",
                    json={"exc_id": eid, "version_id": oldest})
    assert r.status_code == 200 and r.get_json()["ok"]
    with app.app_context():
        assert s.get(eid).payload_dict == {"signature_id": "1"}

    r = client.post(f"/exceptions/{aid}/delete", json={"exc_id": eid})
    assert r.get_json()["ok"]
    r = client.get(f"/exceptions/{aid}/restorable")
    items = r.get_json()["items"]
    assert [i["lineage"] for i in items] == [lin]
    r = client.post(f"/exceptions/{aid}/restore", json={"lineage": lin})
    assert r.status_code == 200 and r.get_json()["ok"]


def test_version_routes_refuse_a_foreign_scope(app, client):
    """Every route here takes an appliance id in the path AND an exc_id in the
    query. Trusting the query alone reads another scope's carve-out through a
    path the operator is allowed to open."""
    from app.services import wpp_exceptions as s
    a1 = _make_appliance(app, "fw1")
    a2 = _make_appliance(app, "fw2")
    _login_admin(app, client)
    with app.app_context():
        exc = _add(s, a1)
        eid = exc.id
    assert client.get(f"/exceptions/{a2}/versions?exc_id={eid}").status_code == 404
    assert client.post(f"/exceptions/{a2}/rollback",
                       json={"exc_id": eid, "version_id": 1}).status_code == 404
