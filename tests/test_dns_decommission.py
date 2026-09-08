"""Decommission planning from the DNS & LB Lookup page.

The question every test here asks is the same one: **would this plan delete
something nobody asked it to?** The planner's whole value is that it refuses,
so the guards are written from the refusal side — each one re-states a rule
that, if it silently flipped, would take a shared certificate / WAF profile /
DNS record down with an unrelated service and report success.
"""
from __future__ import annotations

import pytest

from app.services import dns_decommission as dd
from app.services.dns_providers import DnsRecord
from tests.conftest import admin_user_id, login, make_user


# --------------------------------------------------------------------------- #
#  Name coverage                                                                #
# --------------------------------------------------------------------------- #

def test_covers_is_tls_wildcard_not_substring():
    assert dd._covers("app.x.mx", "app.x.mx")
    assert dd._covers("APP.X.MX.", "app.x.mx")          # case + trailing dot
    assert dd._covers("*.x.mx", "app.x.mx")
    # a wildcard is ONE label: these two are the mistakes that would make a
    # plan claim a certificate covers a name it does not.
    assert not dd._covers("*.x.mx", "x.mx")
    assert not dd._covers("*.x.mx", "a.b.x.mx")
    assert not dd._covers("x.mx", "notx.mx")
    assert not dd._covers("", "app.x.mx")


def test_uncovered_lists_only_the_foreign_names():
    names = ["app.x.mx", "*.x.mx", "shop.y.mx"]
    assert dd._uncovered(names, "app.x.mx") == ["shop.y.mx"]


# --------------------------------------------------------------------------- #
#  Fingerprint                                                                  #
# --------------------------------------------------------------------------- #

def _plan_with(items, target=None):
    return {"target": target or {"policy": "p", "appliance_id": 1},
            "items": items}


def test_fingerprint_changes_when_an_object_flips_to_delete():
    kept = _plan_with([dd._item("certificate", "certificate", "Cert c1",
                                dd.KEEP, "shared", mkey="c1")])
    doomed = _plan_with([dd._item("certificate", "certificate", "Cert c1",
                                  dd.DELETE, "", mkey="c1")])
    assert dd.fingerprint(kept) != dd.fingerprint(doomed)


def test_fingerprint_ignores_prose():
    """Re-wording a refusal must not invalidate a confirmation in flight."""
    a = _plan_with([dd._item("policy", "server-policy", "Server policy p",
                             dd.DELETE, "because", mkey="p", endpoint="/ep")])
    b = _plan_with([dd._item("policy", "server-policy", "SERVER POLICY p",
                             dd.DELETE, "reworded reason", mkey="p",
                             endpoint="/ep")])
    assert dd.fingerprint(a) == dd.fingerprint(b)


def test_fingerprint_separates_unbind_from_delete():
    """Both actions are in the digest, so an item that flips from *remove the
    member* to *remove the whole policy* invalidates the confirmation. Comparing
    keys alone would let that flip through — the two plans touch the same mkey."""
    unbind = _plan_with([dd._item("sni", "sni-member", "SNI s — a", dd.UNBIND,
                                  mkey="s", endpoint="/ep")])
    delete = _plan_with([dd._item("sni", "sni-member", "SNI s — a", dd.DELETE,
                                  mkey="s", endpoint="/ep")])
    assert dd.fingerprint(unbind) != dd.fingerprint(delete)


def test_fingerprint_is_bound_to_the_target():
    one = _plan_with([dd._item("policy", "server-policy", "x", dd.DELETE,
                               mkey="p")], target={"policy": "p", "appliance_id": 1})
    two = _plan_with([dd._item("policy", "server-policy", "x", dd.DELETE,
                               mkey="p")], target={"policy": "p", "appliance_id": 2})
    assert dd.fingerprint(one) != dd.fingerprint(two)


# --------------------------------------------------------------------------- #
#  Certificate self-reference discounting                                       #
# --------------------------------------------------------------------------- #

def test_self_binding_counts_only_what_this_plan_removes():
    removed = {"3"}
    assert dd._is_self_binding({"kind": "server-policy", "target": "pol"},
                               "pol", "sni1", removed)
    assert not dd._is_self_binding({"kind": "server-policy", "target": "other"},
                                   "pol", "sni1", removed)
    assert dd._is_self_binding({"kind": "sni", "target": "sni1", "sub_mkey": "3"},
                               "pol", "sni1", removed)
    # a member that STAYS is a holder, not a self-reference
    assert not dd._is_self_binding({"kind": "sni", "target": "sni1", "sub_mkey": "9"},
                                   "pol", "sni1", removed)
    # the admin GUI is never ours to discount
    assert not dd._is_self_binding({"kind": "gui", "target": ""},
                                   "pol", "sni1", removed)


# --------------------------------------------------------------------------- #
#  WAF profile — every q_ref branch                                             #
# --------------------------------------------------------------------------- #

class _RefClient:
    def __init__(self, answer):
        self._answer = answer

    def cmdb_refcount(self, endpoint, mkey):
        if isinstance(self._answer, Exception):
            raise self._answer
        return self._answer


@pytest.mark.parametrize("answer, action", [
    ((1, ["server-policy(pol)"], "ok", ""), dd.DELETE),      # only us, named
    ((2, ["server-policy(pol)", "server-policy(other)"], "ok", ""), dd.KEEP),
    ((1, [], "ok", ""), dd.DELETE),                          # only us, unnamed
    ((2, [], "ok", ""), dd.KEEP),                            # unnamed, one MORE
    ((3, [], "ok", ""), dd.KEEP),                            # unnamed, several
    ((0, [], "unsupported", ""), dd.KEEP),                   # firmware cannot say
    ((0, [], "error", "timeout"), dd.KEEP),                  # we could not ask
])
def test_wpp_branches(answer, action):
    it = dd._wpp_item(_RefClient(answer), "wpp-a", "pol")
    assert it["action"] == action, it


def test_wpp_transport_failure_keeps():
    it = dd._wpp_item(_RefClient(RuntimeError("boom")), "wpp-a", "pol")
    assert it["action"] == dd.KEEP


def test_wpp_ignores_a_holder_that_merely_contains_the_name():
    """``"pol" in "server-policy(other)"`` is True — the COLLECTION name
    contains it. Discounting on a substring deletes a WAF profile another
    policy is still using."""
    it = dd._wpp_item(_RefClient((1, ["server-policy(other)"], "ok", "")),
                      "wpp-a", "pol")
    assert it["action"] == dd.KEEP
    assert it["holders"] == ["server-policy(other)"]


def test_holder_is_matches_the_key_not_the_line():
    assert dd._holder_is("server-policy(pol-shop)", "pol-shop")
    assert dd._holder_is("url-rewrite-policy(urw) --> rule(1)", "urw")
    assert not dd._holder_is("server-policy(pol-shop-2)", "pol-shop")
    assert not dd._holder_is("server-policy(other)", "pol")
    assert not dd._holder_is("", "pol")


# --------------------------------------------------------------------------- #
#  DNS stage                                                                    #
# --------------------------------------------------------------------------- #

class _Prov:
    def __init__(self, records, fail=False):
        self._records = records
        self._fail = fail

    def list_records(self, name="", zone=""):
        if self._fail:
            raise RuntimeError("backend down")
        return [r for r in self._records
                if r.name.lower().rstrip(".") == name.lower().rstrip(".")]


class _Backend:
    def __init__(self, id, name, prov):
        self.id, self.name, self._prov = id, name, prov

    def instance(self):
        return self._prov


def _rec(name, type_, value, id="r1"):
    return DnsRecord(id=id, name=name, type=type_, value=value)


def test_dns_deletes_the_hostname_and_its_own_aliases():
    prov = _Prov([_rec("app.x.mx", "A", "192.0.2.9", "1"),
                  _rec("alias.x.mx", "CNAME", "app.x.mx", "2")])
    items, warnings = _dns(prov, {"alias.x.mx"})
    assert {i["mkey"] for i in items if i["action"] == dd.DELETE} == {"1", "2"}
    assert not warnings


def test_dns_keeps_a_cname_that_leaves_this_service():
    prov = _Prov([_rec("alias.x.mx", "CNAME", "somewhere.else.mx", "2")])
    items, warnings = _dns(prov, {"alias.x.mx"})
    assert [i["action"] for i in items] == [dd.KEEP]
    assert [w["code"] for w in warnings] == [dd.W_ALIAS_FOREIGN]


def test_dns_never_deletes_a_record_the_backend_volunteered():
    """A provider that answers a prefix search with the whole zone must not
    turn a decommission into a zone wipe."""
    class _Loose(_Prov):
        def list_records(self, name="", zone=""):
            return self._records

    prov = _Loose([_rec("app.x.mx", "A", "192.0.2.9", "1"),
                   _rec("unrelated.x.mx", "A", "192.0.2.99", "9")])
    items, _warnings = _dns(prov, set())
    assert [i["mkey"] for i in items] == ["1"]


def test_dns_read_failure_warns_and_deletes_nothing():
    items, warnings = _dns(_Prov([], fail=True), {"alias.x.mx"})
    assert items == []
    assert {w["code"] for w in warnings} == {dd.W_READ_FAILED}


def test_dns_says_so_when_no_backend_can_write():
    items, warnings = dd._dns_items("app.x.mx", set(), [])
    assert items == []
    assert [w["code"] for w in warnings] == [dd.W_NO_DNS_BACKEND]


def _dns(prov, aliases):
    return dd._dns_items("app.x.mx", aliases, [_Backend(7, "ipam", prov)])


# --------------------------------------------------------------------------- #
#  FortiWeb plan — the shared-object refusals                                   #
# --------------------------------------------------------------------------- #

POLICY = {"name": "pol-shop", "certificate": "cert-shop",
          "sni-certificate": "sni-a", "web-protection-profile": "wpp-shop"}


class _FwClient:
    """Just enough FortiWeb to plan against."""

    def __init__(self, appliance, sni_members=None, refcount=None):
        self.appliance = appliance
        self._sni = sni_members if sni_members is not None else []
        self._ref = refcount or (1, ["server-policy(pol-shop)"], "ok", "")

    def list_with_error(self, path):
        if path == dd.SERVER_POLICY_EP:
            return [dict(POLICY)], None
        if path == dd.SNI_EP:
            return [{"name": "sni-a", "members": self._sni}], None
        return [], None

    def cmdb_refcount(self, endpoint, mkey):
        return self._ref


def _install_fakes(monkeypatch, *, usage, complete=True, sni_members=None,
                   refcount=None, client_box=None):
    from app.clients import fortiweb as fw_mod
    from app.services import cert_manager, exception_lifecycle, policy_graph

    def _mk(appliance, *a, **kw):
        c = _FwClient(appliance, sni_members=sni_members, refcount=refcount)
        if client_box is not None:
            client_box.append(c)
        return c

    monkeypatch.setattr(fw_mod, "FortiWebClient", _mk)
    monkeypatch.setattr(policy_graph, "plan_cascade_delete",
                        lambda reader, name: {"root": name, "to_delete": [],
                                              "to_keep": [], "by_parent": []})
    monkeypatch.setattr(cert_manager, "_enumerate_usage",
                        lambda client, appliance, cert: (complete, list(usage)))
    monkeypatch.setattr(exception_lifecycle, "on_server_policy_deleted",
                        lambda aid, pol, **kw: {"to_delete": [], "to_unbind": []})


def _appliance(app, kind="fortiweb"):
    from app.extensions import db
    from app.models import Appliance
    a = Appliance(name="fw-t", host="192.0.2.13", port=443, username="u")
    a.password = "p"
    a.kind = kind
    db.session.add(a)
    db.session.commit()
    return a


def _cert_of(plan):
    return next(i for i in plan["items"] if i["kind"] == "certificate")


def test_certificate_kept_when_a_second_policy_binds_it(app, monkeypatch):
    with app.app_context():
        ap = _appliance(app)
        _install_fakes(monkeypatch, usage=[
            {"kind": "server-policy", "target": "pol-shop", "label": "self"},
            {"kind": "server-policy", "target": "pol-other", "label": "Server policy pol-other"},
        ])
        plan = dd.plan(ap, policy="pol-shop", hostname="app.x.mx",
                       include_dns=False)
    assert plan["ok"]
    cert = _cert_of(plan)
    assert cert["action"] == dd.KEEP
    assert cert["holders"] == ["Server policy pol-other"]


def test_certificate_deleted_when_only_this_service_binds_it(app, monkeypatch):
    with app.app_context():
        ap = _appliance(app)
        _install_fakes(monkeypatch, usage=[
            {"kind": "server-policy", "target": "pol-shop", "label": "self"},
        ])
        plan = dd.plan(ap, policy="pol-shop", hostname="app.x.mx",
                       include_dns=False)
    assert _cert_of(plan)["action"] == dd.DELETE


def test_certificate_kept_when_the_binder_read_failed(app, monkeypatch):
    """Fail closed. An unreachable binder is an unknown holder, not none."""
    with app.app_context():
        ap = _appliance(app)
        _install_fakes(monkeypatch, usage=[], complete=False)
        plan = dd.plan(ap, policy="pol-shop", hostname="app.x.mx",
                       include_dns=False)
    assert _cert_of(plan)["action"] == dd.KEEP
    assert dd.W_READ_FAILED in {w["code"] for w in plan["warnings"]}


def test_sni_with_other_domains_keeps_the_policy_and_warns(app, monkeypatch):
    members = [{"id": "1", "domain": "app.x.mx", "local-cert": "cert-shop"},
               {"id": "2", "domain": "other.x.mx", "local-cert": "cert-other"}]
    with app.app_context():
        ap = _appliance(app)
        _install_fakes(monkeypatch, usage=[
            {"kind": "server-policy", "target": "pol-shop", "label": "self"},
            {"kind": "sni", "target": "sni-a", "sub_mkey": "1", "label": "sni self"},
        ], sni_members=members)
        plan = dd.plan(ap, policy="pol-shop", hostname="app.x.mx",
                       include_dns=False)
    actions = {(i["kind"], i["action"]) for i in plan["items"]}
    assert ("sni-member", dd.UNBIND) in actions
    assert ("sni-policy", dd.KEEP) in actions
    assert dd.W_SNI_SHARED in {w["code"] for w in plan["warnings"]}
    assert plan["needs_acknowledge"] is True


def test_sni_policy_dies_only_when_it_empties(app, monkeypatch):
    members = [{"id": "1", "domain": "app.x.mx", "local-cert": "cert-shop"}]
    with app.app_context():
        ap = _appliance(app)
        _install_fakes(monkeypatch, usage=[
            {"kind": "server-policy", "target": "pol-shop", "label": "self"},
            {"kind": "sni", "target": "sni-a", "sub_mkey": "1", "label": "sni self"},
        ], sni_members=members)
        plan = dd.plan(ap, policy="pol-shop", hostname="app.x.mx",
                       include_dns=False)
    actions = {(i["kind"], i["action"]) for i in plan["items"]}
    assert ("sni-policy", dd.DELETE) in actions
    assert dd.W_SNI_SHARED not in {w["code"] for w in plan["warnings"]}
    # …and with the last member gone, nothing else holds the certificate
    assert _cert_of(plan)["action"] == dd.DELETE


def test_a_surviving_sni_member_still_holds_the_certificate(app, monkeypatch):
    """The member we do NOT remove is a holder — discounting it would delete a
    certificate another domain is still served with."""
    members = [{"id": "1", "domain": "app.x.mx", "local-cert": "cert-shop"},
               {"id": "2", "domain": "keep.x.mx", "local-cert": "cert-shop"}]
    with app.app_context():
        ap = _appliance(app)
        _install_fakes(monkeypatch, usage=[
            {"kind": "server-policy", "target": "pol-shop", "label": "self"},
            {"kind": "sni", "target": "sni-a", "sub_mkey": "1", "label": "sni self"},
            {"kind": "sni", "target": "sni-a", "sub_mkey": "2", "label": "SNI sni-a — keep.x.mx"},
        ], sni_members=members)
        plan = dd.plan(ap, policy="pol-shop", hostname="app.x.mx",
                       include_dns=False)
    assert _cert_of(plan)["action"] == dd.KEEP


def test_certificate_covering_other_names_warns_before_deleting(app, monkeypatch):
    from app.extensions import db
    from app.models import DeviceCertificate
    with app.app_context():
        ap = _appliance(app)
        row = DeviceCertificate(appliance_id=ap.id, store="Local",
                                name="cert-shop", cn="app.x.mx")
        row.sans = ["app.x.mx", "shop.y.mx"]
        db.session.add(row)
        db.session.commit()
        _install_fakes(monkeypatch, usage=[
            {"kind": "server-policy", "target": "pol-shop", "label": "self"},
        ])
        plan = dd.plan(ap, policy="pol-shop", hostname="app.x.mx",
                       include_dns=False)
    assert _cert_of(plan)["action"] == dd.DELETE
    warn = [w for w in plan["warnings"] if w["code"] == dd.W_CERT_MULTI_NAME]
    assert warn and "shop.y.mx" in warn[0]["text"]
    assert plan["needs_acknowledge"] is True


def test_plan_reports_an_unreadable_device_instead_of_raising(app, monkeypatch):
    from app.clients import fortiweb as fw_mod

    class _Dead:
        def __init__(self, *a, **kw):
            pass

        def list_with_error(self, path):
            return [], "connection refused"

    with app.app_context():
        ap = _appliance(app)
        monkeypatch.setattr(fw_mod, "FortiWebClient", _Dead)
        plan = dd.plan(ap, policy="pol-shop", hostname="app.x.mx",
                       include_dns=False)
    assert plan["ok"] is False
    assert "connection refused" in plan["error"]


# --------------------------------------------------------------------------- #
#  apply() — the preview is not optional                                        #
# --------------------------------------------------------------------------- #

def _usage_self():
    return [{"kind": "server-policy", "target": "pol-shop", "label": "self"}]


def test_apply_refuses_without_a_confirmed_fingerprint(app, monkeypatch):
    with app.app_context():
        ap = _appliance(app)
        _install_fakes(monkeypatch, usage=_usage_self())
        res = dd.apply(ap, policy="pol-shop", hostname="app.x.mx",
                       include_dns=False)
    assert res["ok"] is False
    assert "fingerprint" in res["error"]


def test_apply_refuses_a_stale_fingerprint_and_returns_the_new_plan(app, monkeypatch):
    with app.app_context():
        ap = _appliance(app)
        _install_fakes(monkeypatch, usage=_usage_self())
        res = dd.apply(ap, policy="pol-shop", hostname="app.x.mx",
                       include_dns=False, confirm="deadbeef")
    assert res["ok"] is False and res["stale"] is True
    assert res["plan"]["fingerprint"] != "deadbeef"


def test_apply_refuses_a_warned_plan_without_acknowledgement(app, monkeypatch):
    members = [{"id": "1", "domain": "app.x.mx", "local-cert": "cert-shop"},
               {"id": "2", "domain": "other.x.mx", "local-cert": "cert-other"}]
    with app.app_context():
        ap = _appliance(app)
        _install_fakes(monkeypatch, usage=_usage_self(), sni_members=members)
        first = dd.plan(ap, policy="pol-shop", hostname="app.x.mx",
                        include_dns=False)
        res = dd.apply(ap, policy="pol-shop", hostname="app.x.mx",
                       include_dns=False, confirm=first["fingerprint"])
    assert res["ok"] is False
    assert res["needs_acknowledge"] is True


def test_apply_runs_the_plan_it_re_derived(app, monkeypatch):
    calls = {"cascade": [], "cert": [], "wpp": []}

    class _Ops:
        def __init__(self, appliance):
            pass

        def delete(self, endpoint, mkey, **kw):
            calls["wpp"].append((endpoint, mkey))
            return type("R", (), {"ok": True, "get": lambda s, k, d="": d})()

    with app.app_context():
        from app.services import cert_manager, fortiweb_ops, policy_graph
        ap = _appliance(app)
        _install_fakes(monkeypatch, usage=_usage_self())
        monkeypatch.setattr(fortiweb_ops, "FortiWebOps", _Ops)
        monkeypatch.setattr(policy_graph, "execute_delete_plan",
                            lambda ops, plan, dry_run: [
                                {"urn": "cmdb/server-policy/policy",
                                 "mkey": plan["root"], "label": "Server Policy",
                                 "ok": True, "action": "deleted", "error": ""}])
        monkeypatch.setattr(cert_manager, "remove_device_certificate",
                            lambda ap_, store, name, **kw: calls["cert"].append(name)
                            or {"ok": True, "removed": True, "error": ""})
        first = dd.plan(ap, policy="pol-shop", hostname="app.x.mx",
                        include_dns=False)
        res = dd.apply(ap, policy="pol-shop", hostname="app.x.mx",
                       include_dns=False, confirm=first["fingerprint"])
    assert res["ok"] is True, res
    assert calls["cert"] == ["cert-shop"]
    assert calls["wpp"] == [(dd.WPP_EP, "wpp-shop")]


def test_apply_stops_when_the_root_policy_did_not_delete(app, monkeypatch):
    """The dependencies are still referenced — asking the box to delete them
    would turn its correct refusals into this run's failures."""
    touched = []

    class _Ops:
        def __init__(self, appliance):
            pass

        def delete(self, endpoint, mkey, **kw):
            touched.append(mkey)
            return type("R", (), {"ok": True, "get": lambda s, k, d="": d})()

    with app.app_context():
        from app.services import cert_manager, fortiweb_ops, policy_graph
        ap = _appliance(app)
        _install_fakes(monkeypatch, usage=_usage_self())
        monkeypatch.setattr(fortiweb_ops, "FortiWebOps", _Ops)
        monkeypatch.setattr(policy_graph, "execute_delete_plan",
                            lambda ops, plan, dry_run: [
                                {"urn": "cmdb/server-policy/policy",
                                 "mkey": plan["root"], "label": "Server Policy",
                                 "ok": False, "action": "failed",
                                 "error": "in use"}])
        monkeypatch.setattr(cert_manager, "remove_device_certificate",
                            lambda *a, **kw: touched.append("CERT") or
                            {"ok": True, "removed": True, "error": ""})
        first = dd.plan(ap, policy="pol-shop", hostname="app.x.mx",
                        include_dns=False)
        res = dd.apply(ap, policy="pol-shop", hostname="app.x.mx",
                       include_dns=False, confirm=first["fingerprint"])
    assert res["ok"] is False
    assert "CERT" not in touched


# --------------------------------------------------------------------------- #
#  FortiADC — the chain, and what an unreadable table does to it                #
# --------------------------------------------------------------------------- #

class _AdcClient:
    def __init__(self, tables, dead=()):
        self._t = tables
        self._dead = set(dead)

    def list_with_error(self, logical, **params):
        if logical in self._dead:
            return [], "read failed"
        rows = self._t.get(logical, [])
        if logical == dd.ADC_CERT_GROUP_MEMBERS:
            return [r for r in rows if r.get("_grp") == params.get("pkey")], None
        return rows, None


def _adc_tables():
    return {
        dd.ADC_VS: [
            {"mkey": "vs-shop", "pool": "pool-shop", "waf-profile": "waf-shop",
             "client_ssl_profile": "ssl-shop"},
            {"mkey": "vs-other", "pool": "pool-other", "waf-profile": "waf-other",
             "client_ssl_profile": "ssl-other"},
        ],
        dd.ADC_SSL_PROFILE: [
            {"mkey": "ssl-shop", "local_certificate_group": "grp-shop"},
            {"mkey": "ssl-other", "local_certificate_group": "grp-other"},
        ],
        dd.ADC_CERT_GROUP: [{"mkey": "grp-shop"}, {"mkey": "grp-other"}],
        dd.ADC_CERT_GROUP_MEMBERS: [
            {"_grp": "grp-shop", "local_cert": "cert-shop"},
            {"_grp": "grp-other", "local_cert": "cert-other"},
        ],
    }


def _adc_plan(app, monkeypatch, tables, dead=()):
    from app import clients as clients_pkg
    with app.app_context():
        ap = _appliance(app, kind="fortiadc")
        monkeypatch.setattr(clients_pkg, "client_for",
                            lambda a, **kw: _AdcClient(tables, dead))
        return dd.plan(ap, policy="vs-shop", hostname="app.x.mx",
                       include_dns=False)


def test_adc_walks_the_ssl_chain_to_the_certificate(app, monkeypatch):
    plan = _adc_plan(app, monkeypatch, _adc_tables())
    assert plan["ok"], plan
    got = {(i["kind"], i["mkey"]): i["action"] for i in plan["items"]}
    assert got[("virtual-server", "vs-shop")] == dd.DELETE
    assert got[("pool", "pool-shop")] == dd.DELETE
    assert got[("wpp", "waf-shop")] == dd.DELETE
    assert got[("ssl-profile", "ssl-shop")] == dd.DELETE
    assert got[("cert-group", "grp-shop")] == dd.DELETE
    assert got[("certificate", "cert-shop")] == dd.DELETE


def test_adc_keeps_everything_another_virtual_server_shares(app, monkeypatch):
    tables = _adc_tables()
    tables[dd.ADC_VS][1].update({"pool": "pool-shop", "waf-profile": "waf-shop",
                                 "client_ssl_profile": "ssl-shop"})
    plan = _adc_plan(app, monkeypatch, tables)
    got = {(i["kind"], i["mkey"]): i["action"] for i in plan["items"]}
    assert got[("pool", "pool-shop")] == dd.KEEP
    assert got[("wpp", "waf-shop")] == dd.KEEP
    assert got[("ssl-profile", "ssl-shop")] == dd.KEEP
    # the chain stops there: no group and no certificate are proposed at all
    assert not [i for i in plan["items"] if i["kind"] == "certificate"]


def test_adc_keeps_a_certificate_that_a_second_group_also_holds(app, monkeypatch):
    tables = _adc_tables()
    tables[dd.ADC_CERT_GROUP_MEMBERS].append(
        {"_grp": "grp-other", "local_cert": "cert-shop"})
    plan = _adc_plan(app, monkeypatch, tables)
    cert = next(i for i in plan["items"] if i["kind"] == "certificate")
    assert cert["action"] == dd.KEEP
    assert cert["holders"] == ["grp-other"]


def test_adc_unreadable_group_table_keeps_the_chain(app, monkeypatch):
    plan = _adc_plan(app, monkeypatch, _adc_tables(), dead=(dd.ADC_CERT_GROUP,))
    got = {(i["kind"], i["mkey"]): i["action"] for i in plan["items"]}
    assert got[("cert-group", "grp-shop")] == dd.KEEP
    assert not [i for i in plan["items"] if i["kind"] == "certificate"]
    assert dd.W_READ_FAILED in {w["code"] for w in plan["warnings"]}


# --------------------------------------------------------------------------- #
#  Routes                                                                       #
# --------------------------------------------------------------------------- #

def test_plan_route_needs_config_write(app, client):
    uid = make_user(app, username="ro", role="readonly")
    login(client, uid, product="fortiweb")
    r = client.post("/dns-lookup/decommission/plan",
                    json={"appliance_id": 1, "policy": "pol-shop"})
    assert r.status_code in (302, 403)


def test_plan_route_returns_the_preview(app, client, monkeypatch):
    with app.app_context():
        ap = _appliance(app)
        aid = ap.id
    _install_fakes(monkeypatch, usage=_usage_self())
    monkeypatch.setattr("app.services.dns_providers.enabled_backends",
                        lambda role="": [])
    login(client, admin_user_id(app), product="fortiweb")
    r = client.post("/dns-lookup/decommission/plan",
                    json={"appliance_id": aid, "policy": "pol-shop",
                          "hostname": "app.x.mx"})
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["ok"] is True
    assert body["fingerprint"]
    assert any(i["kind"] == "server-policy" and i["action"] == dd.DELETE
               for i in body["items"])


def test_page_offers_the_decommission_ui_to_a_writer(app, client):
    login(client, admin_user_id(app), product="fortiweb")
    r = client.get("/dns-lookup/")
    assert r.status_code == 200
    assert b"dnsDecomModal" in r.data
    assert b"/dns-lookup/decommission/plan" in r.data


def test_page_hides_the_decommission_ui_from_a_reader(app, client):
    uid = make_user(app, username="ro2", role="readonly")
    login(client, uid, product="fortiweb")
    r = client.get("/dns-lookup/")
    assert r.status_code == 200
    assert b"dnsDecomModal" not in r.data


def test_match_row_renders_a_decommission_button(app, client, monkeypatch):
    """The button lives inside the LB-match loop, which only renders on a POST
    that found something — the one branch a GET can never reach."""
    from app.services import dns_tool as dt
    with app.app_context():
        from app.models import AppSetting
        from app.extensions import db
        import json as _json
        AppSetting.set(dt.SERVERS_KEY, _json.dumps(
            [{"name": "T", "server": "192.0.2.53", "enabled": True}]))
        db.session.commit()
        ap = _appliance(app)
        aid = ap.id
    row = {k: "" for k, _l in dt.COLUMNS}
    row.update({"product": "FortiWeb", "gateway": "fw-t", "policy": "pol-shop",
                "certificate": "cert-shop", "_aid": aid, "_kind": "fortiweb",
                "_backends": []})
    monkeypatch.setattr(dt, "fleet_lb_rows", lambda: [row])
    monkeypatch.setattr(dt, "dig_lookup",
                        lambda entry, server, show_ttl=False: ["192.0.2.9"])
    login(client, admin_user_id(app), product="fortiweb")
    r = client.post("/dns-lookup/", data={"entries": "pol-shop", "lb": "1"})
    assert r.status_code == 200
    assert b"dns-decom-btn" in r.data
    assert b'data-policy="pol-shop"' in r.data


def test_apply_route_refuses_an_unconfirmed_plan(app, client, monkeypatch):
    with app.app_context():
        ap = _appliance(app)
        aid = ap.id
    _install_fakes(monkeypatch, usage=_usage_self())
    monkeypatch.setattr("app.services.dns_providers.enabled_backends",
                        lambda role="": [])
    login(client, admin_user_id(app), product="fortiweb")
    r = client.post("/dns-lookup/decommission/apply",
                    json={"appliance_id": aid, "policy": "pol-shop"})
    assert r.status_code == 400
    assert r.get_json()["ok"] is False
