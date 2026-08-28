"""Guards for the multi-backend DNS/IPAM registry (2026-08-28).

What changed and why it needs guarding: ``dnsrecords.*`` was ONE provider
answering every question. It is now N rows, each with optional roles (IPAM /
DNS) and an optional scope (zones / pools). That turns a question nobody could
get wrong — there was one answer — into a resolution, and a resolution is
exactly the shape that failed on 2026-08-27: three independent resolvers of a
segment name disagreed and a policy was built on the wrong network.

So the guards below are mostly about the decision, not the plumbing:

* the choice is made in ONE place and a tie is REFUSED, never broken by row
  order;
* a role is a promise, refused when the provider can never keep it;
* "no DDI at all", "no backend claims this", and "two claim it equally" are
  three different answers with three different fixes, and are never folded;
* undo goes back to the backend that acted, by RECORDED id, never by
  re-resolving.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from app.extensions import db
from app.models import AppSetting
from app.models_dnsbackend import DnsBackend, split_list
from app.services import dns_providers as dp
from app.services.dns_providers import store as dnsb
from app.services.dns_providers.base import Address, Capabilities, DnsRecord

from tests.conftest import admin_user_id, login

ROOT = pathlib.Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------- #
#  helpers                                                                     #
# --------------------------------------------------------------------------- #
def _mk(name, provider="efficientip", *, zones="", pools="", priority=100,
        enabled=True, role_ipam=True, role_dns=True, config=None):
    row = DnsBackend(name=name, provider=provider, zones=zones, pools=pools,
                     priority=priority, enabled=enabled,
                     role_ipam=role_ipam, role_dns=role_dns)
    row.config = config or {}
    row.secret = "s3cr3t"
    db.session.add(row)
    db.session.commit()
    return row


def _caps(**kw) -> Capabilities:
    base = dict(provider="fake", label="Fake DDI", can_write=True,
                record_types=["A"], needs_zone=False, needs_view=False,
                can_allocate=True, needs_pool=True)
    base.update(kw)
    return Capabilities(**base)


# --------------------------------------------------------------------------- #
#  1. split_list — one parser, and the zone/pool asymmetry is deliberate       #
# --------------------------------------------------------------------------- #
def test_split_list_accepts_the_three_shapes_the_column_is_written_in():
    """A textarea, a comma list and the JSON the migration may write.

    Two parsers is how a reader and a writer end up disagreeing about what a
    row declares — the segments failure, one layer down.
    """
    assert split_list("a.com\nb.com") == ["a.com", "b.com"]
    assert split_list("a.com, b.com") == ["a.com", "b.com"]
    assert split_list(json.dumps(["a.com", "b.com"])) == ["a.com", "b.com"]
    assert split_list(["a.com", "b.com"]) == ["a.com", "b.com"]
    assert split_list(None) == [] and split_list("") == []


def test_split_list_preserves_order_and_drops_duplicates():
    assert split_list("b.com\na.com\nb.com") == ["b.com", "a.com"]


def test_zones_fold_case_and_pools_do_not():
    """DNS is case-insensitive BY DEFINITION; a pool identifier is not.

    Folding a pool would silently merge two pools that a phpIPAM install
    legitimately distinguishes, and point an allocation at the wrong one.
    """
    assert split_list("Example.COM.", lower=True) == ["example.com"]
    assert split_list("Prod-Pool", lower=False) == ["Prod-Pool"]


def test_the_row_asks_for_the_fold_on_zones_and_refuses_it_on_pools(app):
    with app.app_context():
        row = _mk("a", zones="Example.COM.", pools="Prod-Pool")
        assert row.zone_list() == ["example.com"]
        assert row.pool_list() == ["Prod-Pool"]


# --------------------------------------------------------------------------- #
#  2. the resolver                                                             #
# --------------------------------------------------------------------------- #
def test_a_more_specific_zone_wins_over_its_parent(app):
    with app.app_context():
        _mk("parent", zones="example.com")
        child = _mk("child", zones="sub.example.com")
        res = dp.resolve_dns("www.sub.example.com")
        assert res.ok and res.backend.id == child.id


def test_a_declared_zone_does_not_cover_a_name_that_merely_ends_with_it(app):
    """``example.com`` must not answer for ``notexample.com``.

    A bare ``endswith`` would, and would publish a record into a zone the
    operator never gave that backend.
    """
    with app.app_context():
        _mk("a", zones="example.com")
        assert dp.resolve_dns("host.notexample.com").code == dp.NO_MATCH


def test_a_backend_with_no_zones_answers_anything_and_ranks_last(app):
    """Catch-all is what an install with ONE backend has, so it must work —
    and it must never outrank a backend that named the zone."""
    with app.app_context():
        catch = _mk("catch-all", zones="")
        assert dp.resolve_dns("anything.example.org").backend.id == catch.id
        named = _mk("named", zones="example.org")
        assert dp.resolve_dns("a.example.org").backend.id == named.id
        assert dp.resolve_dns("a.elsewhere.net").backend.id == catch.id


def test_priority_breaks_a_tie_between_equally_specific_backends(app):
    with app.app_context():
        _mk("slow", zones="example.com", priority=200)
        fast = _mk("fast", zones="example.com", priority=10)
        assert dp.resolve_dns("a.example.com").backend.id == fast.id


def test_an_exact_tie_is_refused_and_names_the_candidates(app):
    """The whole point. Two equal claims is the operator's to break.

    Picking one silently is how a record is published in the wrong customer's
    zone with every value on screen looking correct.
    """
    with app.app_context():
        _mk("ddi-a", zones="example.com", priority=100)
        _mk("ddi-b", zones="example.com", priority=100)
        res = dp.resolve_dns("a.example.com")
        assert res.backend is None
        assert res.code == dp.AMBIGUOUS
        assert res.candidates == ["ddi-a", "ddi-b"]
        assert "ddi-a" in res.detail and "ddi-b" in res.detail


def test_no_backend_and_no_match_are_different_answers(app):
    """They have different fixes, so they may never be folded into one code.

    "None configured" sent to somebody with three backends wired makes them
    look for a provider they already have.
    """
    with app.app_context():
        assert dp.resolve_dns("a.example.com").code == dp.NO_BACKEND
        _mk("a", zones="other.com")
        assert dp.resolve_dns("a.example.com").code == dp.NO_MATCH


def test_a_role_the_operator_did_not_give_is_not_a_candidate(app):
    with app.app_context():
        _mk("pools-only", role_dns=False)
        assert dp.resolve_dns("a.example.com").code == dp.NO_BACKEND
        assert dp.resolve_ipam("192.0.2.0/24").ok


def test_a_disabled_backend_is_not_a_candidate(app):
    with app.app_context():
        _mk("off", enabled=False)
        assert dp.resolve_dns("a.example.com").code == dp.NO_BACKEND
        assert dp.resolve_ipam("").code == dp.NO_BACKEND


def test_with_no_zone_given_only_a_catch_all_can_honestly_answer(app):
    """A scoped backend cannot be checked against a name that was not given.

    Treating its claim as a match would publish into whichever zone sorted
    first — a guess wearing the clothes of a routing rule.
    """
    with app.app_context():
        _mk("scoped", zones="example.com")
        assert dp.resolve_dns("").code == dp.NO_MATCH
        catch = _mk("catch", zones="")
        assert dp.resolve_dns("").backend.id == catch.id


def test_pools_are_matched_exactly_and_never_by_containment(app):
    """A pool id may be ``42`` or a name, not only a CIDR.

    Doing network arithmetic on a string that may not be an address is how an
    allocation lands in a supernet that belongs to somebody else.
    """
    with app.app_context():
        _mk("a", pools="10.30.0.0/16")
        assert dp.resolve_ipam("10.30.20.0/22").code == dp.NO_MATCH
        assert dp.resolve_ipam("10.30.0.0/16").ok


def test_zone_specificity_is_measured_in_labels():
    assert dp.zone_specificity("example.com", "a.example.com") == 2
    assert dp.zone_specificity("sub.example.com", "a.sub.example.com") == 3
    assert dp.zone_specificity("example.com", "example.org") == -1
    assert dp.zone_specificity("", "a.example.com") == -1


# --------------------------------------------------------------------------- #
#  3. a role is a promise                                                      #
# --------------------------------------------------------------------------- #
def test_the_dns_role_is_refused_on_a_provider_that_can_never_write(app):
    """phpIPAM has no record CRUD in ANY install — that promise is unkeepable.

    Accepting it here is the §130 bug relocated: the run would resolve to this
    backend and then discover, at write time, that it cannot write.
    """
    with app.app_context():
        with pytest.raises(dnsb.BackendError) as exc:
            dnsb.save_backend({"name": "p", "provider": "phpipam",
                               "role_ipam": True, "role_dns": True,
                               "secret": "x"})
        assert "cannot carry the DNS role" in str(exc.value)


def test_the_dns_role_is_allowed_on_netbox_because_the_plugin_may_be_there(app):
    """The static maximum bounds what may be PROMISED; the live probe reports
    what will actually happen. Refusing here would lock out a supported
    deployment (netbox-dns), which is the opposite error."""
    with app.app_context():
        row = dnsb.save_backend({"name": "nb", "provider": "netbox",
                                 "role_ipam": True, "role_dns": True,
                                 "secret": "x"})
        assert row.role_dns is True


def test_a_backend_with_neither_role_is_refused(app):
    with app.app_context():
        with pytest.raises(dnsb.BackendError):
            dnsb.save_backend({"name": "z", "provider": "efficientip",
                               "role_ipam": False, "role_dns": False,
                               "secret": "x"})


def test_the_static_maxima_match_what_each_provider_actually_does():
    from app.services.dns_providers import (EfficientIPProvider, NetBoxProvider,
                                            NoneProvider, PhpIpamProvider)
    assert (EfficientIPProvider.may_write, EfficientIPProvider.may_allocate) == (True, True)
    assert (PhpIpamProvider.may_write, PhpIpamProvider.may_allocate) == (False, True)
    assert (NetBoxProvider.may_write, NetBoxProvider.may_allocate) == (True, True)
    assert (NoneProvider.may_write, NoneProvider.may_allocate) == (False, False)


# --------------------------------------------------------------------------- #
#  4. save_backend — a rejected save is not a partial save                     #
# --------------------------------------------------------------------------- #
def test_a_rejected_save_writes_nothing(app):
    with app.app_context():
        with pytest.raises(dnsb.BackendError):
            dnsb.save_backend({"name": "half", "provider": "phpipam",
                               "role_dns": True, "role_ipam": True,
                               "secret": "x"})
        assert DnsBackend.query.filter_by(name="half").first() is None


def test_a_duplicate_name_is_refused(app):
    with app.app_context():
        _mk("dup")
        with pytest.raises(dnsb.BackendError) as exc:
            dnsb.save_backend({"name": "dup", "provider": "efficientip",
                               "role_ipam": True, "role_dns": True,
                               "secret": "x"})
        assert "already called" in str(exc.value)


def test_adding_a_backend_without_a_credential_is_refused(app):
    with app.app_context():
        with pytest.raises(dnsb.BackendError):
            dnsb.save_backend({"name": "nocred", "provider": "efficientip",
                               "role_ipam": True, "role_dns": True})


def test_a_blank_secret_on_edit_keeps_the_stored_one(app):
    """An empty password field is how a browser renders "not shown".

    Reading it as "blank it" silently un-authenticates a working backend.
    """
    with app.app_context():
        row = _mk("keep")
        before = row.secret_enc
        dnsb.save_backend({"name": "keep", "provider": "efficientip",
                           "role_ipam": True, "role_dns": True,
                           "secret": ""}, row.id)
        assert DnsBackend.query.get(row.id).secret_enc == before
        assert DnsBackend.query.get(row.id).secret == "s3cr3t"


def test_a_default_outside_the_declared_scope_is_refused(app):
    """Routing would refuse the zone the provider is about to write into.

    Silently rewriting one to match the other would be the software picking
    which of two things the operator typed it believed.
    """
    with app.app_context():
        with pytest.raises(dnsb.BackendError) as exc:
            dnsb.save_backend({"name": "c", "provider": "efficientip",
                               "role_ipam": True, "role_dns": True,
                               "secret": "x", "zones": "example.com",
                               "default_zone": "other.com"})
        assert "not one of the zones" in str(exc.value)


def test_a_default_pool_outside_the_declared_scope_is_refused(app):
    with app.app_context():
        with pytest.raises(dnsb.BackendError):
            dnsb.save_backend({"name": "c", "provider": "efficientip",
                               "role_ipam": True, "role_dns": True,
                               "secret": "x", "pools": "192.0.2.0/24",
                               "default_pool": "192.0.2.0/24"})


def test_a_scoped_backend_with_no_explicit_default_derives_one(app):
    """ONE derivation, in one place, so scope and default cannot drift."""
    with app.app_context():
        row = _mk("d", zones="a.example.com\nb.example.com",
                  pools="p1\np2")
        cfg = row.instance().cfg
        assert cfg["default_zone"] == "a.example.com"
        assert cfg["default_pool"] == "p1"


def test_an_explicit_default_is_not_overwritten_by_the_scope(app):
    with app.app_context():
        row = _mk("e", zones="a.example.com\nb.example.com",
                  config={"default_zone": "b.example.com"})
        assert row.instance().cfg["default_zone"] == "b.example.com"


# --------------------------------------------------------------------------- #
#  5. the migration off the singleton                                          #
# --------------------------------------------------------------------------- #
def test_the_singleton_becomes_one_unscoped_row(app):
    """An upgrade must not change what an install does.

    The old ``default_zone`` was a DEFAULT, not a scope: the operator could
    still create records in any other zone from the modal. Promoting it to a
    scope would start refusing those the moment the package was updated.
    """
    with app.app_context():
        AppSetting.set("dnsrecords.provider", "efficientip")
        AppSetting.set("dnsrecords.config",
                       json.dumps({"base_url": "https://ddi",
                                   "default_zone": "example.com",
                                   "verify_ssl": False}))
        AppSetting.set("dnsrecords.secret_enc", "enc-token")
        AppSetting.set(dnsb.K_MIGRATED, "")
        db.session.commit()

        row = dnsb.migrate_singleton()
        assert row is not None
        assert row.zone_list() == [] and row.pool_list() == []
        assert row.config["default_zone"] == "example.com"
        assert row.config["base_url"] == "https://ddi"
        assert row.secret_enc == "enc-token"
        assert row.role_ipam is True and row.role_dns is True


def test_the_migration_is_one_shot_and_does_not_resurrect_deleted_rows(app):
    """Guarded by its own flag, not by "are there rows".

    An operator who deletes every backend must not find the old configuration
    back on the next boot as if they had never removed it.
    """
    with app.app_context():
        AppSetting.set("dnsrecords.provider", "efficientip")
        AppSetting.set("dnsrecords.config", "{}")
        AppSetting.set(dnsb.K_MIGRATED, "")
        db.session.commit()
        row = dnsb.migrate_singleton()
        db.session.delete(row)
        db.session.commit()
        assert dnsb.migrate_singleton() is None
        assert DnsBackend.query.count() == 0


def test_a_disabled_singleton_migrates_to_no_row_but_still_sets_the_flag(app):
    with app.app_context():
        AppSetting.set("dnsrecords.provider", "none")
        AppSetting.set(dnsb.K_MIGRATED, "")
        db.session.commit()
        assert dnsb.migrate_singleton() is None
        assert AppSetting.get(dnsb.K_MIGRATED) == "1"


def test_the_migration_gives_phpipam_only_the_role_it_can_keep(app):
    with app.app_context():
        AppSetting.set("dnsrecords.provider", "phpipam")
        AppSetting.set("dnsrecords.config", "{}")
        AppSetting.set(dnsb.K_MIGRATED, "")
        db.session.commit()
        row = dnsb.migrate_singleton()
        assert row.role_ipam is True and row.role_dns is False


# --------------------------------------------------------------------------- #
#  6. undo goes back to the backend that acted                                 #
# --------------------------------------------------------------------------- #
class _Prov:
    def __init__(self, sink):
        self.sink = sink

    def allocate_address(self, hostname="", pool=""):
        return Address(address="198.51.100.7", ref="ip-9", pool=pool)

    def release_address(self, address, ref=""):
        self.sink.append(("release", address, ref))

    def create_record(self, rec):
        return DnsRecord(id="rr-1", name=rec.name, type=rec.type,
                         value=rec.value)

    def delete_record(self, rec):
        self.sink.append(("delete", rec.id))


def _wire(monkeypatch, row, sink):
    monkeypatch.setattr(type(row), "instance", lambda self: _Prov(sink))


def test_allocate_stamps_the_backend_that_answered(app, monkeypatch):
    with app.app_context():
        row = _mk("a")
        _wire(monkeypatch, row, [])
        addr = dp.allocate_address(hostname="h", pool="")
        assert addr.backend_id == row.id


def test_create_record_stamps_the_backend_that_answered(app, monkeypatch):
    with app.app_context():
        row = _mk("a")
        _wire(monkeypatch, row, [])
        rec = dp.create_record("h.example.com", "A", "192.0.2.1")
        assert rec.backend_id == row.id


def test_release_honours_the_recorded_backend_over_re_resolution(app,
                                                                 monkeypatch):
    """The scope may have been edited between the reservation and the undo."""
    with app.app_context():
        keeper = _mk("keeper", pools="198.51.100.0/24")
        _mk("other", pools="")
        sink = []
        monkeypatch.setattr(DnsBackend, "instance",
                            lambda self: _Prov(sink if self.id == keeper.id
                                               else ["WRONG"]))
        dp.release_address("198.51.100.7", ref="ip-9", backend_id=keeper.id,
                           pool="something-else-entirely")
        assert sink == [("release", "198.51.100.7", "ip-9")]


def test_a_release_whose_backend_is_gone_is_refused_not_redirected(app):
    """Handing an address to a different pool manager does not free it, and
    may delete a row that manager legitimately owns."""
    with app.app_context():
        _mk("still-here")
        with pytest.raises(dp.ProviderError) as exc:
            dp.release_address("198.51.100.7", ref="ip-9", backend_id=9999)
        assert "no longer exists" in str(exc.value)


def test_a_delete_whose_backend_is_gone_is_refused_not_redirected(app):
    """A provider-native record id replayed against another backend can name a
    completely different record."""
    with app.app_context():
        _mk("still-here")
        with pytest.raises(dp.ProviderError) as exc:
            dp.delete_record("rr-1", name="h.example.com", backend_id=9999)
        assert "no longer exists" in str(exc.value)


def test_create_record_routes_on_the_fqdn_when_no_zone_is_given(app,
                                                                monkeypatch):
    """What makes scopes usable: the caller need not know how the zone was
    cut, only the name it is publishing."""
    with app.app_context():
        _mk("wrong", zones="other.com")
        right = _mk("right", zones="example.com")
        sink = []
        monkeypatch.setattr(DnsBackend, "instance",
                            lambda self: _Prov(sink) if self.id == right.id
                            else pytest.fail("routed to the wrong backend"))
        rec = dp.create_record("www.example.com", "A", "192.0.2.1")
        assert rec.backend_id == right.id


def test_an_unresolvable_operation_raises_and_never_returns_a_value(app):
    """§130's rule, unchanged: whether a missing backend is fatal is the
    CALLER's judgement, and it cannot make it on a value that looks like a
    successful write."""
    with app.app_context():
        for call in (lambda: dp.allocate_address(hostname="h"),
                     lambda: dp.create_record("h.example.com", "A", "1.1.1.1"),
                     lambda: dp.release_address("192.0.2.1"),
                     lambda: dp.delete_record("rr-1", name="h.example.com")):
            with pytest.raises(dp.ProviderError):
                call()


# --------------------------------------------------------------------------- #
#  7. the Settings API                                                         #
# --------------------------------------------------------------------------- #
def _admin(app, client):
    login(client, admin_user_id(app))


def test_state_lists_backends_and_never_leaks_a_secret(app, client):
    with app.app_context():
        _mk("a", config={"base_url": "https://ddi"})
    _admin(app, client)
    r = client.get("/settings/dns-records/state")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "s3cr3t" not in body
    data = r.get_json()
    assert data["backends"][0]["has_secret"] is True
    assert "secret" not in data["backends"][0]["config"]
    assert {p["key"] for p in data["providers"]} == set(dp.SELECTABLE)


def test_the_provider_catalog_carries_the_static_maxima(app, client):
    """The form disables a role it must not offer. Without these two flags the
    browser would offer the DNS role on phpIPAM and the server would refuse it
    after the operator filled the whole form in."""
    _admin(app, client)
    provs = {p["key"]: p for p in
             client.get("/settings/dns-records/state").get_json()["providers"]}
    assert provs["phpipam"]["may_write"] is False
    assert provs["phpipam"]["may_allocate"] is True
    assert provs["netbox"]["may_write"] is True


def test_save_creates_then_edits(app, client):
    _admin(app, client)
    r = client.post("/settings/dns-records/save", json={
        "name": "ddi-a", "provider": "efficientip", "role_ipam": True,
        "role_dns": True, "secret": "x", "zones": "example.com",
        "base_url": "https://ddi"})
    assert r.status_code == 200 and r.get_json()["ok"] is True
    bid = r.get_json()["backend"]["id"]
    r = client.post("/settings/dns-records/save", json={
        "id": bid, "name": "ddi-a", "provider": "efficientip",
        "role_ipam": False, "role_dns": True, "zones": "example.com"})
    assert r.get_json()["backend"]["role_ipam"] is False


def test_a_refused_save_answers_400_with_the_reason(app, client):
    _admin(app, client)
    r = client.post("/settings/dns-records/save", json={
        "name": "p", "provider": "phpipam", "role_dns": True,
        "role_ipam": True, "secret": "x"})
    assert r.status_code == 400
    assert "DNS role" in r.get_json()["error"]


def test_toggle_and_delete(app, client):
    with app.app_context():
        row = _mk("gone")
        bid = row.id
    _admin(app, client)
    assert client.post(f"/settings/dns-records/{bid}/toggle").get_json()[
        "backend"]["enabled"] is False
    assert client.post(f"/settings/dns-records/{bid}/delete").status_code == 200
    with app.app_context():
        assert DnsBackend.query.get(bid) is None


def test_delete_is_refused_while_a_run_holds_the_backend_as_its_undo_handle(
        app, client):
    """The same refusal ``hypervisor_delete`` makes, for the same reason: the
    run's only way back to what it created is that id."""
    from app.models_provision import ProvisionRun
    with app.app_context():
        row = _mk("held")
        bid = row.id
        db.session.add(ProvisionRun(name="fw99", mode="semi", status="running",
                                    ip_backend_id=bid))
        db.session.commit()
    _admin(app, client)
    r = client.post(f"/settings/dns-records/{bid}/delete")
    assert r.status_code == 409
    assert "still hold this backend" in r.get_json()["error"]
    with app.app_context():
        assert DnsBackend.query.get(bid) is not None


def test_the_unsaved_test_refuses_to_borrow_another_backends_credential(app,
                                                                       client):
    """Reporting a connection made with somebody else's secret is reporting a
    connection the new backend has not made."""
    with app.app_context():
        _mk("existing")
    _admin(app, client)
    r = client.post("/settings/dns-records/test", json={
        "provider": "efficientip", "base_url": "https://ddi"})
    assert r.status_code == 400
    assert "no saved backend" in r.get_json()["message"]


def test_the_settings_api_is_admin_only(app, client):
    from tests.conftest import make_user, profile_id
    uid = make_user(app, username="ro", role="readonly",
                    profile_id=profile_id(app, "readonly"))
    login(client, uid)
    for url in ("/settings/dns-records/state",):
        assert client.get(url).status_code in (302, 403)
    assert client.post("/settings/dns-records/save",
                       json={"name": "x"}).status_code in (302, 403)


# --------------------------------------------------------------------------- #
#  8. the records modal picks a backend, and never guesses one                 #
# --------------------------------------------------------------------------- #
def test_one_dns_backend_is_used_without_asking(app, client):
    with app.app_context():
        _mk("only-one")
    _admin(app, client)
    r = client.get("/dns-lookup/records/schema")
    assert r.status_code == 200
    assert r.get_json()["backend"]["name"] == "only-one"


def test_two_backends_force_an_explicit_choice(app, client):
    """Falling back to the first row would write into whichever zone happened
    to sort first."""
    with app.app_context():
        _mk("ddi-a")
        _mk("ddi-b")
    _admin(app, client)
    r = client.get("/dns-lookup/records/schema")
    assert r.status_code == 400
    assert "say which one" in r.get_json()["error"]
    assert {b["name"] for b in r.get_json()["backends"]} == {"ddi-a", "ddi-b"}


def test_an_explicit_choice_is_honoured(app, client):
    with app.app_context():
        _mk("ddi-a")
        b = _mk("ddi-b")
        bid = b.id
    _admin(app, client)
    r = client.get(f"/dns-lookup/records/schema?backend_id={bid}")
    assert r.status_code == 200 and r.get_json()["backend"]["name"] == "ddi-b"


def test_a_stale_backend_id_is_refused_not_silently_replaced(app, client):
    with app.app_context():
        _mk("ddi-a")
    _admin(app, client)
    r = client.get("/dns-lookup/records/schema?backend_id=9999")
    assert r.status_code == 400
    assert "gone, disabled" in r.get_json()["error"]


def test_an_ipam_only_backend_is_not_offered_to_the_records_modal(app, client):
    with app.app_context():
        _mk("pools-only", role_dns=False)
    _admin(app, client)
    r = client.get("/dns-lookup/records/schema")
    assert r.status_code == 400
    assert "DNS role" in r.get_json()["error"]


# --------------------------------------------------------------------------- #
#  9. structural — the singleton is gone, and the new page is not CSP-dead     #
# --------------------------------------------------------------------------- #
def test_no_module_still_calls_the_singleton_api():
    """``provider_key`` / ``active_provider`` / ``config_public`` / ``save_config``
    answered "the" provider. A survivor would be a second author of the
    routing decision, reading a config nothing writes any more."""
    dead = ("dns_providers.provider_key", "dns_providers.active_provider",
            "dns_providers.config_public", "dns_providers.save_config",
            "dns_providers.clear_secret", "dns_providers.capabilities()")
    hits = []
    for path in (ROOT / "app").rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for name in dead:
            if name in text:
                hits.append(f"{path.relative_to(ROOT)}: {name}")
    assert hits == [], hits


def test_the_settings_tab_script_carries_the_nonce_the_response_served(app,
                                                                      client):
    """Asserted against the nonce the RESPONSE actually served, not against
    the template text.

    On 2026-08-27 the entire SPO wizard was dead in the browser because its
    one ``<script>`` went out without a nonce and ``script-src-elem`` dropped
    it: the page rendered, every value was correct server-side, and no control
    worked. A template that writes the attribute while the header stops naming
    a nonce is the same dead page.
    """
    _admin(app, client)
    r = client.get("/settings/")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    start = html.index('id="tab-dnsrecords"')
    block = html[start:start + 30000]
    tag = block[block.index("<script"):]
    tag = tag[:tag.index(">") + 1]
    assert "nonce=" in tag, tag
    nonce = tag.split('nonce="')[1].split('"')[0]
    assert nonce and f"'nonce-{nonce}'" in r.headers.get(
        "Content-Security-Policy", "")


def test_the_settings_tab_has_no_inline_event_handlers(app, client):
    """The other half of the same rule. A guard that names CSP and checks one
    half reads as cover for both."""
    _admin(app, client)
    html = client.get("/settings/").get_data(as_text=True)
    start = html.index('id="tab-dnsrecords"')
    block = html[start:start + 30000]
    for bad in ("onclick=", "onchange=", "onsubmit="):
        assert bad not in block


# --------------------------------------------------------------------------- #
#  11. choose() — the operator's pick, checked rather than trusted             #
# --------------------------------------------------------------------------- #
def test_choose_with_no_pick_is_exactly_the_automatic_resolution(app):
    """The selector is additive: an install that never picks is unchanged."""
    with app.app_context():
        _mk("ddi-a", zones="ex.com")
        for pick in (None, "", 0, "0"):
            assert dp.choose("dns", "www.ex.com", pick).backend.name == "ddi-a"
            assert dp.choose("ipam", "p1", pick).backend.name == "ddi-a"


def test_choose_honours_a_valid_pick_over_the_automatic_winner(app):
    with app.app_context():
        _mk("specific", zones="ex.com", priority=1)
        b = _mk("catch-all")
        assert dp.choose("dns", "www.ex.com").backend.name == "specific"
        assert dp.choose("dns", "www.ex.com", b.id).backend.name == "catch-all"


def test_an_invalid_pick_refuses_and_never_falls_back_to_auto(app):
    """A catch-all that WOULD answer is present on purpose. Falling back to it
    would do the work on a backend the operator did not name."""
    with app.app_context():
        _mk("catch-all")
        assert dp.choose("dns", "www.ex.com", 9999).code == dp.UNKNOWN
        off = _mk("off", enabled=False)
        assert dp.choose("dns", "www.ex.com", off.id).code == dp.DISABLED
        dnsless = _mk("pools-only", role_dns=False)
        assert dp.choose("dns", "www.ex.com", dnsless.id).code == dp.WRONG_ROLE
        scoped = _mk("elsewhere", zones="other.example")
        res = dp.choose("dns", "www.ex.com", scoped.id)
        assert res.code == dp.OUT_OF_SCOPE
        assert all(r.backend is None for r in [res])


def test_the_pick_refusals_are_four_distinct_codes(app):
    """Four different fixes: reload the page / enable the row / give it the
    role / widen the scope. One code would name none of them."""
    codes = {dp.UNKNOWN, dp.DISABLED, dp.WRONG_ROLE, dp.OUT_OF_SCOPE}
    assert len(codes) == 4
    assert not codes & {dp.NO_BACKEND, dp.NO_MATCH, dp.AMBIGUOUS}


def test_a_picked_catch_all_answers_anything(app):
    with app.app_context():
        b = _mk("catch-all")
        assert dp.choose("dns", "anything.example", b.id).ok
        assert dp.choose("ipam", "any-pool", b.id).ok


def test_choose_reads_the_scope_the_same_way_the_resolvers_do(app):
    """``claims`` is not a second reading of the scope column — a pick and an
    automatic resolution disagreeing about what one row declares is the
    2026-08-27 failure with a different noun."""
    with app.app_context():
        row = _mk("ddi-a", zones="ex.com", pools="p1")
        assert dp.claims(row, "dns", "www.ex.com") is True
        assert dp.claims(row, "dns", "www.other.example") is False
        assert dp.claims(row, "ipam", "p1") is True
        assert dp.claims(row, "ipam", "p2") is False
        assert dp.choose("dns", "www.ex.com", row.id).ok
        assert dp.resolve_dns("www.ex.com").ok


def test_a_pool_with_a_capital_letter_resolves(app):
    """Regression. ``resolve_ipam`` lowered the query while ``split_list``
    deliberately preserved the declaration, so a pool named ``Prod-DMZ`` could
    never be matched — the store kept a distinction the matcher then made
    unusable."""
    with app.app_context():
        _mk("ddi-a", pools="Prod-DMZ")
        assert dp.resolve_ipam("Prod-DMZ").backend.name == "ddi-a"


def test_pool_matching_stays_case_sensitive_and_zones_stay_folded(app):
    """The asymmetry is the point: a pool id may differ only in case, a DNS
    name may not."""
    with app.app_context():
        _mk("pools", pools="Prod-DMZ", role_dns=False)
        _mk("zones", zones="EX.com", role_ipam=False)
        assert dp.resolve_ipam("prod-dmz").code == dp.NO_MATCH
        assert dp.resolve_dns("WWW.Ex.COM").backend.name == "zones"
        assert dp.pool_matches(["Prod-DMZ"], "Prod-DMZ") is True
        assert dp.pool_matches(["Prod-DMZ"], "prod-dmz") is False
        assert dp.pool_matches(["Prod-DMZ"], "") is False


def test_allocate_and_create_route_through_the_pick(app, monkeypatch):
    """The two write paths take ``backend_id``, and it is validated by the
    same chooser rather than trusted — a caller cannot reach a disabled row
    by passing its id."""
    import inspect
    for fn in (dp.allocate_address, dp.create_record):
        assert "backend_id" in inspect.signature(fn).parameters
    with app.app_context():
        good = _mk("ddi-a")
        off = _mk("off", enabled=False)
        monkeypatch.setattr(type(good), "instance",
                            lambda self: _FakeInstance(self.id))
        addr = dp.allocate_address(hostname="h", pool="p1",
                                   backend_id=good.id)
        assert addr.backend_id == good.id
        with pytest.raises(dp.ProviderError):
            dp.allocate_address(hostname="h", pool="p1", backend_id=off.id)


class _FakeInstance:
    def __init__(self, bid):
        self.bid = bid

    def allocate_address(self, hostname="", pool=""):
        return Address(address="192.0.2.5", ref="r", pool=pool)

    def create_record(self, rec):
        rec.id = "rec1"
        return rec
