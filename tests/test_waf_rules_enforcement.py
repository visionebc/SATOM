"""WAF governance rules on the Exceptions area (the 4 team rules).

1. Exception ↔ Server-Policy lifecycle: purge on policy delete, stale flag on a
   WPP swap (never a silent delete).
2. Template-managed WPPs stay CLEAN: authoring/injecting a carve-out on one is
   refused (403) everywhere, not just in objedit.
3. Guided clone: the 403 carries a clone offer whose name derives from the
   Naming catalog element ``wpp_exception`` ({name} = the server policy).
4. Capacity: the clone offer carries a WPP headroom verdict; a signature set's
   filter_list caps at SIG_FILTER_MAX (128).
"""
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


def _approve_wpp_template(app, name="WPP-Golden"):
    from app.services import templates as tpl
    from app.models import Template
    with app.app_context():
        row = tpl.save_template(Template.KIND_WEB_PROTECTION, name,
                                {"data": {"data": {"name": name}}})
        tpl.approve_template(row.id, "admin")
        return name


# ── rule 2: template guard ──────────────────────────────────────────────────
def test_template_lock_error_service(app):
    from app.services import wpp_exceptions as s
    name = _approve_wpp_template(app)
    with app.app_context():
        assert s.template_lock_error(name)          # locked
        assert s.template_lock_error("wpp-free") == ""
        assert s.template_lock_error("") == ""


def test_save_refuses_template_wpp_with_clone_offer(client, app):
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    name = _approve_wpp_template(app)
    login(client, admin_user_id(app))
    r = client.post(f"/exceptions/{aid}/save", json={
        "exc_type": "signature_filter_item", "wpp_mkey": name,
        "fields": {"signature_id": "010000001", "match-target": "URI"},
        "policies": ["pol-demo-ecom"], "reason": "fp",
    })
    assert r.status_code == 403
    j = r.get_json()
    assert j["template_locked"] is True
    # rule 3: the offer derives the clone name from the POLICY via Naming
    sug = j["clone_suggestion"]
    assert sug["policy"] == "pol-demo-ecom"
    assert sug["new_name"] == "wpp-pol-demo-ecom"
    assert sug["source"] == name
    # rule 4: the offer carries the headroom verdict (fail-open w/o a cap row)
    assert sug["headroom_ok"] is True
    with app.app_context():
        assert s.list_exceptions(aid) == []          # nothing was stored


def test_save_on_free_wpp_still_works(client, app):
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    _approve_wpp_template(app)
    login(client, admin_user_id(app))
    j = client.post(f"/exceptions/{aid}/save", json={
        "exc_type": "signature_filter_item", "wpp_mkey": "wpp-clone",
        "fields": {"signature_id": "010000001", "match-target": "URI"},
        "policies": ["pol-a"],
    }).get_json()
    assert j["ok"]
    with app.app_context():
        assert len(s.list_exceptions(aid)) == 1


def test_inject_refuses_template_wpp(client, app):
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    name = _approve_wpp_template(app)
    with app.app_context():
        exc = s.add(aid, wpp_mkey=name, exc_type="signature_filter_item",
                    payload={"signature_id": "010000001", "match-target": "URI"},
                    policies=["pol-a"])
        eid = exc.id
    login(client, admin_user_id(app))
    r = client.post(f"/exceptions/{aid}/inject",
                    json={"exc_id": eid, "target": "sig-x"})
    assert r.status_code == 403
    assert r.get_json()["template_locked"] is True


# ── rule 1: lifecycle hooks ─────────────────────────────────────────────────
def test_mark_stale_and_resolve(app):
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    with app.app_context():
        exc = s.add(aid, wpp_mkey="wpp-old", exc_type="geo_ip_exception_member_item",
                    payload={"ip": "1.2.3.4"}, policies=["pol-a"])
        other = s.add(aid, wpp_mkey="wpp-old", exc_type="geo_ip_exception_member_item",
                      payload={"ip": "5.6.7.8"}, policies=["pol-b"])
        n = s.mark_stale_for_policy(aid, "pol-a", "wpp-new")
        assert n == 1
        assert s.get(exc.id).stale is True and "wpp-new" in s.get(exc.id).stale_reason
        assert s.get(other.id).stale is False        # other policy untouched
        # re-pointing the record (update with a wpp) clears the flag
        s.update(exc.id, wpp_mkey="wpp-new")
        assert s.get(exc.id).stale is False and s.get(exc.id).stale_reason == ""


def test_retarget_for_policy(app):
    from app.services import wpp_exceptions as s
    aid = _make_appliance(app)
    with app.app_context():
        e1 = s.add(aid, wpp_mkey="wpp-old", exc_type="geo_ip_exception_member_item",
                   payload={"ip": "1.2.3.4"}, policies=["pol-a"])
        e2 = s.add(aid, wpp_mkey="wpp-other", exc_type="geo_ip_exception_member_item",
                   payload={"ip": "9.9.9.9"}, policies=["pol-a"])
        moved = s.retarget_for_policy(aid, "pol-a", "wpp-old", "wpp-clone")
        assert moved == 1
        assert s.get(e1.id).wpp_mkey == "wpp-clone"
        assert s.get(e2.id).wpp_mkey == "wpp-other"   # different source wpp kept


def test_policy_delete_purges_carveouts(app, monkeypatch):
    """perform_one('delete') on a real apply purges the policy's carve-outs."""
    from app.services import policy_ops, wpp_exceptions as s
    aid = _make_appliance(app)

    class _Res(dict):
        ok = True
    class _FakeOps:
        def __init__(self, appl): pass
        def delete(self, ep, mkey, dry_run):
            return _Res()
    import app.services.fortiweb_ops as fops
    monkeypatch.setattr(fops, "FortiWebOps", _FakeOps)

    with app.app_context():
        from app.models import Appliance
        appl = Appliance.query.get(aid)
        s.add(aid, wpp_mkey="wpp-x", exc_type="signature_disable_item",
              payload={"signature_id": "010000001"}, policies=["pol-gone"])
        rec = policy_ops.perform_one("delete", source_appl=appl,
                                     policy="pol-gone", dry_run=False)
        assert rec["ok"] and rec["detail"]["carveouts_purged"] == 1
        assert s.list_exceptions(aid) == []


# ── rule 3: naming element ──────────────────────────────────────────────────
def test_naming_has_wpp_exception_element():
    from app.services import naming
    keys = {e.key for e in naming.elements_for_product(naming.PRODUCT_FORTIWEB)}
    assert "wpp_exception" in keys
    names = naming.render_names("ignored", {}, naming.PRODUCT_FORTIWEB)
    assert "wpp_exception" in names
    assert naming.render_one(naming.default_scheme()["wpp_exception"],
                             naming.slugify("pol-demo-ecom")) == "wpp-pol-demo-ecom"


# ── rule 4: the 128 cap constant is wired ───────────────────────────────────
def test_sig_filter_cap_constant():
    from app.services import wpp_exceptions as s
    assert s.SIG_FILTER_MAX == 128
