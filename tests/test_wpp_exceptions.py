"""Exceptions — catalog, desired-state store, alignment, purge, and the view
that REPLACES the old url-access stub."""
from __future__ import annotations

from tests.conftest import login, admin_user_id


def _make_appliance(app):
    from app.models import Appliance, db
    with app.app_context():
        a = Appliance(name="fw1", kind="fortiweb", host="192.0.2.99",
                      port=443, username="admin", verify_ssl=False)
        a.password = "secret"
        db.session.add(a); db.session.commit()
        return a.id


# ── catalog (pure) ─────────────────────────────────────────────────────────
def test_catalog_and_fields():
    from app.services import wpp_exceptions as s
    keys = {t["key"] for t in s.CATALOG}
    assert "signature_filter_item" in keys and "http_constraint_exception_item" in keys
    assert s.category_for("signature_filter_item") == s.CAT_SIGNATURE
    assert s.category_for("geo_ip_exception_member_item") == s.CAT_EXCEPTION
    fkeys = {f["key"] for f in s.fields_for("signature_filter_item")}
    assert {"signature_id", "match-target", "operator"} <= fkeys


# ── store CRUD + junction ───────────────────────────────────────────────────
def test_store_crud(app):
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    with app.app_context():
        exc = s.add(aid, wpp_mkey="wpp-x", exc_type="signature_filter_item",
                    payload={"signature_id": "010000001"}, reason="false positive",
                    policies=["pol-a", "pol-b"])
        assert exc.id and exc.category == s.CAT_SIGNATURE
        assert exc.payload_dict["signature_id"] == "010000001"
        assert exc.policy_names == ["pol-a", "pol-b"]

        assert len(s.list_exceptions(aid)) == 1
        assert len(s.list_exceptions(aid, s.CAT_SIGNATURE)) == 1
        assert s.list_exceptions(aid, s.CAT_EXCEPTION) == []

        s.update(exc.id, policies=["pol-a"], reason="confirmed FP")
        assert s.get(exc.id).policy_names == ["pol-a"]

        assert s.delete(exc.id) is True
        assert s.list_exceptions(aid) == []


def test_delete_for_policy_purge(app):
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    with app.app_context():
        s.add(aid, wpp_mkey="wpp-x", exc_type="signature_filter_item",
              payload={"signature_id": "1"}, policies=["pol-a", "pol-b"])
        s.add(aid, wpp_mkey="wpp-x", exc_type="signature_disable_item",
              payload={"signature_id": "2"}, policies=["pol-a"])
        deleted = s.delete_for_policy(aid, "pol-a")
        assert deleted == 1                       # the pol-a-only one is gone
        remaining = s.list_exceptions(aid)
        assert len(remaining) == 1
        assert remaining[0].policy_names == ["pol-b"]   # the shared one kept, pol-a unbound


def test_alignment(app):
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    with app.app_context():
        s.add(aid, wpp_mkey="wpp-x", exc_type="geo_ip_exception_member_item",
              payload={"ip": "1.2.3.4"}, policies=["pol-a"])
        good = s.alignment(aid, {"pol-a": "wpp-x", "pol-b": "wpp-y"})
        assert len(good["per_policy"]["pol-a"]) == 1 and good["stale"] == []
        # WPP swapped under the policy → the carve-out is now stale
        bad = s.alignment(aid, {"pol-a": "wpp-other"})
        assert bad["per_policy"]["pol-a"] == [] and len(bad["stale"]) == 1


# ── view (replaces the url-access stub) ─────────────────────────────────────
def test_list_view_replaces_stub(client, app):
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    h = client.get(f"/exceptions/{aid}").get_data(as_text=True)
    assert "Authored carve-outs" in h and "New carve-out" in h
    main = h.split("<main", 1)[-1]
    assert "url-access" not in main       # the old mislabelled stub is gone
                                          # (sidebar WAF nav carries url-access links globally)


def test_type_fields_route(client, app):
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    ok = client.get("/exceptions/type-fields?type=signature_filter_item").get_json()
    assert ok["ok"] and any(f["key"] == "match-target" for f in ok["fields"])
    assert client.get("/exceptions/type-fields?type=bogus").status_code == 400


def test_save_and_delete_route(client, app):
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    login(client, admin_user_id(app))
    r = client.post(f"/exceptions/{aid}/save", json={
        "exc_type": "signature_filter_item", "wpp_mkey": "wpp-x",
        "fields": {"signature_id": "010000001", "match-target": "URI"},
        "policies": ["pol-a"], "reason": "fp",
    })
    j = r.get_json()
    assert j["ok"] and j["id"]
    with app.app_context():
        assert len(s.list_exceptions(aid)) == 1
    d = client.post(f"/exceptions/{aid}/delete", json={"exc_id": j["id"]}).get_json()
    assert d["ok"]
    with app.app_context():
        assert s.list_exceptions(aid) == []
