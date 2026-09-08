"""Guards for the batch half of the wizard: several domains, ONE server pool.

Two features share one failure mode, and it is not a crash.

**Several domains.** "Build shop, blog and api against the same backend" is one
pool with three policies bound to it. Build it as three pools and nothing
breaks today — it breaks the first time somebody edits one of them and two
domains silently keep the old member list. So the guards here are about the
pool being written ONCE, and about the two rows of a batch being checked
against EACH OTHER: a clash between rows exists before either object does, so
the live name check on the device cannot see it, and it would surface as "the
second one failed" halfway through a run that had already published DNS for
the first.

**An existing pool.** A FortiWeb server pool is a per-device object. A policy
cannot bind one that lives on another appliance, and offering a foreign pool as
if it could is how an operator presses Apply and gets a policy pointing at
nothing. So: the fleet search may FIND anything, the planner may BIND only what
is on this device, and the difference is stated rather than implied.
"""
from __future__ import annotations

import json
import pathlib
import re

import pytest

from app.extensions import db
from app.models import Appliance, Template
from app.models_cache import DeviceObject
from app.models_lineprofile import LineProfile
from app.services import dns_providers as dp
from app.services import pool_catalog
from app.services import settings_store as store
from app.services import spo_wizard as wiz

from tests.conftest import admin_user_id, login
from tests.test_spo_wizard import _SEGMENTS, BACKENDS, _resolves

ROOT = pathlib.Path(__file__).resolve().parents[1]
TPL = ROOT / "app/templates/workspace/spo_wizard.html"


class _Client:
    """Answers per ENDPOINT, unlike the single-list stub the older suite uses.

    That distinction is the point: "a policy by this name exists" and "a pool
    by this name exists" are different facts that this module now reads in one
    probe, and a stub that returns the same list for both cannot tell a real
    guard from one that matched the wrong collection.
    """

    def __init__(self, policies=(), pools=()):
        self.policies = list(policies)
        self.pools = list(pools)
        self.seen: list[str] = []

    def cmdb_names(self, endpoint):
        self.seen.append(endpoint)
        if "server-pool" in endpoint:
            return list(self.pools)
        return list(self.policies)


@pytest.fixture()
def env(app, monkeypatch):
    with app.app_context():
        store.save_classification("lines", ["retail", "wholesale"])
        store.save_segments([dict(s) for s in _SEGMENTS])
        store.save_cert_class_config("server", {"template": "WebServer"})
        t = Template(kind=Template.KIND_WEB_PROTECTION, name="wpp-retail",
                     version=1, body="{}", product="fortiweb",
                     status=Template.STATUS_APPROVED)
        db.session.add(t)
        appl = Appliance(name="fwb-a", kind="fortiweb", host="192.0.2.13",
                         port=443, username="admin", password_enc="",
                         verify_ssl=False)
        other = Appliance(name="fwb-b", kind="fortiweb", host="192.0.2.14",
                          port=443, username="admin", password_enc="",
                          verify_ssl=False)
        adc = Appliance(name="adc-a", kind="fortiadc", host="192.0.2.15",
                        port=443, username="admin", password_enc="",
                        verify_ssl=False)
        db.session.add_all([appl, other, adc])
        db.session.commit()
        prof = LineProfile(product="fortiweb", line="retail",
                           cert_class="server", wpp_template_id=t.id)
        prof.set_segments(["dmz-web"])
        db.session.add(prof)
        db.session.commit()
        client = _Client()
        monkeypatch.setattr(type(appl), "build_client",
                            lambda self, **kw: client)
        _resolves(monkeypatch)
        yield {"appliance_id": appl.id, "other_id": other.id,
               "adc_id": adc.id, "client": client}


def _appl(env):
    return db.session.get(Appliance, env["appliance_id"])


def _batch(app, env, rows, **kw):
    base = dict(line="retail", backends=list(BACKENDS))
    base.update(kw)
    with app.app_context():
        return wiz.build_batch(_appl(env), rows=rows, **base)


def _rows(*addresses):
    return [{"web_address": a, "hostname": "", "address": "198.51.100.9"}
            for a in addresses]


def _codes(plan):
    return [b.code for b in plan.blockers]


def _cache_pool(appliance_id, pool, members, layer="config", bound=True):
    """Seed the cache the way a sync does: the pool, and — only when a policy
    binds it — its members underneath."""
    db.session.add(DeviceObject(
        appliance_id=appliance_id, layer=layer, section="server-policy",
        logical_name=pool_catalog.POOL_LOGICAL, mkey=pool, depth=0,
        payload={"name": pool}))
    if not bound:
        db.session.commit()
        return
    parent = DeviceObject(
        appliance_id=appliance_id, layer=layer, section="server-policy",
        logical_name=pool_catalog.BOUND_POOL_LOGICAL, mkey=pool, depth=1,
        payload={"name": pool})
    db.session.add(parent)
    db.session.flush()
    for i, (ip, port) in enumerate(members):
        db.session.add(DeviceObject(
            appliance_id=appliance_id, layer=layer, section="server-policy",
            logical_name=pool_catalog.BOUND_POOL_LOGICAL + "/pserver-list",
            parent_id=parent.id, mkey=str(i), depth=2, idx=i,
            payload={"ip": ip, "port": port}))
    db.session.commit()


# ---------------------------------------------------------------------------
# 1. the pool is written ONCE, whatever the number of domains
# ---------------------------------------------------------------------------
def test_only_the_first_domain_creates_the_pool(app, env):
    plans = _batch(app, env, _rows("shop.example.com", "blog.example.com",
                                   "api.example.com"))
    assert len(plans) == 3
    assert [p.pool_mode for p in plans] == [wiz.POOL_NEW, wiz.POOL_SHARED,
                                            wiz.POOL_SHARED]
    # And they all bind the SAME name — a shared pool nobody derived twice.
    assert len({p.pool_name for p in plans}) == 1
    assert plans[0].pool_name == plans[0].names["server_pool"]


def test_the_batch_payloads_contain_exactly_one_pool_and_one_member_set(app, env):
    """The whole point of the feature, asserted where it is observable: the
    device writes. Three pools would work on day one and drift on day two."""
    plans = _batch(app, env, _rows("shop.example.com", "blog.example.com",
                                   "api.example.com"))
    labels = [s[0] for p in plans for s in wiz.object_payload(p, "198.51.100.9")["steps"]]
    assert labels.count("Server Pool") == 1
    assert labels.count("Pool member 1") == 1
    # ...while every domain still gets its own policy and its own front end.
    assert labels.count("Server Policy") == 3
    assert labels.count("Virtual Server") == 3
    assert labels.count("VIP") == 3


def test_the_shared_rows_say_the_members_are_written_once(app, env):
    """A row that lists real servers it does not write has to say so, or the
    operator reads three copies of the backend where there is one."""
    plans = _batch(app, env, _rows("shop.example.com", "blog.example.com"))
    assert any("FIRST domain" in w for w in plans[1].warnings)
    assert not any("FIRST domain" in w for w in plans[0].warnings)


# ---------------------------------------------------------------------------
# 2. rows are checked against EACH OTHER, not only against the device
# ---------------------------------------------------------------------------
def test_the_same_address_twice_is_refused(app, env):
    plans = _batch(app, env, _rows("shop.example.com", "SHOP.example.com"))
    assert _codes(plans[0]) == []
    assert "duplicate_web_address" in _codes(plans[1])


def test_two_different_addresses_that_derive_one_name_are_refused(app, env):
    """The dangerous one: the rows LOOK different. ``slugify`` collapses every
    run of non-alphanumerics to a dash, so these two produce one policy name —
    and the device would only find out at the second create, after the first
    domain's DNS was already published."""
    plans = _batch(app, env, _rows("shop.example.com", "shop_example.com"))
    assert plans[0].names["server_policy"] == plans[1].names["server_policy"]
    assert "duplicate_web_address" not in _codes(plans[1])
    assert "duplicate_policy_name" in _codes(plans[1])


def test_one_vip_on_two_rows_warns_and_does_not_block(app, env):
    """Whether this device accepts two VIP objects on one address is a property
    of the device. Saying so is honest; refusing it would be a guess wearing a
    rule's clothes."""
    plans = _batch(app, env, _rows("shop.example.com", "blog.example.com"))
    assert plans[1].ok
    assert any("same VIP 198.51.100.9" in w for w in plans[1].warnings)


def test_ipam_rows_do_not_trip_the_shared_vip_warning(app, env):
    """Each IPAM row gets its own reservation, so there is no shared address to
    warn about — and a warning that fires on the correct configuration is a
    warning operators learn to ignore."""
    rows = [{"web_address": a, "hostname": "", "address": ""}
            for a in ("shop.example.com", "blog.example.com")]
    plans = _batch(app, env, rows, use_ipam=True)
    assert not any("same VIP" in w for p in plans for w in p.warnings)


# ---------------------------------------------------------------------------
# 3. binding a pool that already exists
# ---------------------------------------------------------------------------
def test_an_existing_pool_is_bound_and_nothing_is_created(app, env):
    env["client"].pools = ["pool-shared"]
    plans = _batch(app, env, _rows("shop.example.com", "blog.example.com"),
                   existing_pool="pool-shared",
                   pool_mode=wiz.POOL_EXISTING, backends=[])
    assert [p.pool_mode for p in plans] == [wiz.POOL_EXISTING] * 2
    assert all(p.ok for p in plans), [_codes(p) for p in plans]
    for p in plans:
        labels = [s[0] for s in wiz.object_payload(p, "198.51.100.9")["steps"]]
        assert "Server Pool" not in labels
        assert not [l for l in labels if l.startswith("Pool member")]
        policy = [s for s in wiz.object_payload(p, "198.51.100.9")["steps"]
                  if s[0] == "Server Policy"][0]
        assert policy[2]["server-pool"] == "pool-shared"


def test_binding_an_existing_pool_does_not_require_real_servers(app, env):
    """``no_backends`` is right for a pool being CREATED empty and wrong for
    one being bound: its members already exist on the device."""
    env["client"].pools = ["pool-shared"]
    plans = _batch(app, env, _rows("shop.example.com"),
                   existing_pool="pool-shared",
                   pool_mode=wiz.POOL_EXISTING, backends=[])
    assert "no_backends" not in _codes(plans[0])


def test_typed_servers_are_reported_as_unused_when_a_pool_is_bound(app, env):
    """A control that silently does nothing reads as a control that worked."""
    env["client"].pools = ["pool-shared"]
    plans = _batch(app, env, _rows("shop.example.com"),
                   existing_pool="pool-shared", pool_mode=wiz.POOL_EXISTING)
    assert any("NOT used" in w for w in plans[0].warnings)


def test_a_pool_that_is_not_on_this_device_is_refused(app, env):
    """The whole risk of a FLEET search. The pool exists — on another box —
    and a server pool is a per-device object."""
    env["client"].pools = ["something-else"]
    plans = _batch(app, env, _rows("shop.example.com"),
                   existing_pool="pool-on-fwb-b",
                   pool_mode=wiz.POOL_EXISTING, pool_from="fwb-b")
    assert "pool_not_on_device" in _codes(plans[0])
    assert "per-device object" in " ".join(b.detail for b in plans[0].blockers)


def test_existing_mode_without_a_name_is_refused_not_downgraded(app, env):
    """Quietly falling back to "create a new one" would build a different pool
    from the one the operator had on screen."""
    plans = _batch(app, env, _rows("shop.example.com"),
                   existing_pool="", pool_mode=wiz.POOL_EXISTING)
    assert "no_pool_name" in _codes(plans[0])


def test_a_new_pool_whose_name_is_taken_is_refused(app, env):
    """Found in the same probe as the policy clash, and for the same reason:
    otherwise it fails at the object step, after the address is reserved, the
    record published and the certificate issued."""
    plans = _batch(app, env, _rows("shop.example.com"))
    taken = plans[0].pool_name
    env["client"].pools = [taken]
    plans = _batch(app, env, _rows("shop.example.com"))
    assert "pool_exists" in _codes(plans[0])


def test_the_probe_reads_both_collections(app, env):
    _batch(app, env, _rows("shop.example.com"))
    seen = " ".join(env["client"].seen)
    assert "server-policy/policy" in seen and "server-pool" in seen


# ---------------------------------------------------------------------------
# 4. apply_batch — all or nothing, and never a silent half
# ---------------------------------------------------------------------------
def test_a_batch_with_one_blocked_plan_writes_nothing(app, env, monkeypatch):
    called = []
    for name in ("allocate_address", "create_record", "release_address",
                 "delete_record"):
        monkeypatch.setattr(dp, name,
                            lambda *a, _n=name, **k: called.append(_n))
    plans = _batch(app, env, _rows("shop.example.com", "shop.example.com"))
    with app.app_context():
        res = wiz.apply_batch(_appl(env), plans, dry_run=False)
    assert res["ok"] is False and "blocked" in res["error"]
    assert res["runs"] == [] and res["built"] == []
    assert called == []


def test_the_blocked_report_names_every_bad_row_at_once(app, env):
    """Reporting the first refusal only turns one fix into N round trips."""
    plans = _batch(app, env, _rows("shop.example.com", "shop.example.com",
                                   "shop.example.com"))
    with app.app_context():
        res = wiz.apply_batch(_appl(env), plans, dry_run=True)
    assert res["error"].count("already row") == 2


def test_a_failure_halfway_names_what_was_built_and_undoes_none_of_it(app, env,
                                                                     monkeypatch):
    """The earlier domains are real, working policies. Tearing them down
    because a LATER row failed destroys work nobody asked to undo."""
    plans = _batch(app, env, _rows("shop.example.com", "blog.example.com"))
    calls = {"n": 0}

    def fake(appliance, plan, *, dry_run=True, actor=""):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"ok": True, "dry_run": False, "steps": [],
                    "compensated": [], "stranded": []}
        return {"ok": False, "dry_run": False, "steps": [],
                "error": "device said no", "compensated": [], "stranded": []}

    monkeypatch.setattr(wiz, "apply_plan", fake)
    with app.app_context():
        res = wiz.apply_batch(_appl(env), plans, dry_run=False)
    assert res["ok"] is False
    assert res["built"] == ["shop.example.com"]
    stranded = " ".join(res["runs"][-1]["result"]["stranded"])
    assert "NOT undone" in stranded and "shop.example.com" in stranded


def test_an_empty_batch_is_a_refusal_not_a_success(app, env):
    with app.app_context():
        res = wiz.apply_batch(_appl(env), [], dry_run=True)
    assert res["ok"] is False and "no web address" in res["error"]


# ---------------------------------------------------------------------------
# 5. the fleet pool catalog
# ---------------------------------------------------------------------------
def test_the_catalog_marks_local_and_foreign_pools(app, env):
    with app.app_context():
        _cache_pool(env["appliance_id"], "pool-here", [("192.0.2.11", "8080")])
        _cache_pool(env["other_id"], "pool-there", [("192.0.2.11", "9090")])
        rows = pool_catalog.fleet_pools(local_appliance_id=env["appliance_id"])
    by_name = {r["pool"]: r for r in rows}
    assert by_name["pool-here"]["local"] is True
    assert by_name["pool-there"]["local"] is False
    # Local first: the bindable rows are the ones an operator wants, and a
    # name-sorted fleet list buries them under whatever device sorts first.
    assert rows[0]["local"] is True


def test_the_catalog_carries_the_members_it_has(app, env):
    with app.app_context():
        _cache_pool(env["other_id"], "pool-there",
                    [("192.0.2.11", "9090"), ("192.0.2.12", "9090")])
        rows = pool_catalog.fleet_pools(local_appliance_id=env["appliance_id"])
    row = [r for r in rows if r["pool"] == "pool-there"][0]
    assert row["members_known"] is True
    assert [m["ip"] for m in row["members"]] == ["192.0.2.11", "192.0.2.12"]


def test_an_unbound_pool_is_listed_with_members_UNKNOWN_not_empty(app, env):
    """``members_known=False`` means "we do not know", never "it has none".
    Rendering an uncaptured pool as empty invites a copy of nothing."""
    with app.app_context():
        _cache_pool(env["other_id"], "pool-lonely", [], bound=False)
        rows = pool_catalog.fleet_pools(local_appliance_id=env["appliance_id"])
    row = [r for r in rows if r["pool"] == "pool-lonely"][0]
    assert row["members_known"] is False and row["members"] == []


def test_the_deep_layer_wins_over_config_for_the_same_pool(app, env):
    """Reading the layers as one bag lets a stale ``config`` member list beat a
    fresh ``deep`` one at random — worse than consistently trusting either."""
    with app.app_context():
        _cache_pool(env["appliance_id"], "pool-x", [("192.0.2.1", "80")],
                    layer="config")
        _cache_pool(env["appliance_id"], "pool-x", [("192.0.2.2", "80")],
                    layer="deep")
        rows = pool_catalog.fleet_pools(local_appliance_id=env["appliance_id"])
    row = [r for r in rows if r["pool"] == "pool-x"][0]
    assert [m["ip"] for m in row["members"]] == ["192.0.2.2"]


def test_fortiadc_pools_are_not_offered(app, env):
    """FortiADC has no object of this shape. Listing its pools under the same
    English word offers a bind that cannot exist."""
    with app.app_context():
        _cache_pool(env["adc_id"], "adc-pool", [("192.0.2.9", "80")])
        rows = pool_catalog.fleet_pools(local_appliance_id=env["appliance_id"])
    assert "adc-pool" not in [r["pool"] for r in rows]


def test_the_search_matches_name_device_and_member_ip(app, env):
    with app.app_context():
        _cache_pool(env["other_id"], "zzz", [("192.0.2.7", "80")])
        by_ip = pool_catalog.fleet_pools(local_appliance_id=env["appliance_id"],
                                         query="192.0.2.7")
        by_dev = pool_catalog.fleet_pools(local_appliance_id=env["appliance_id"],
                                          query="fwb-b")
        miss = pool_catalog.fleet_pools(local_appliance_id=env["appliance_id"],
                                        query="nothing-like-this")
    assert [r["pool"] for r in by_ip] == ["zzz"]
    assert [r["pool"] for r in by_dev] == ["zzz"]
    assert miss == []


# ---------------------------------------------------------------------------
# 6. the endpoints
# ---------------------------------------------------------------------------
def test_the_plan_endpoint_returns_one_entry_per_domain(app, client, env):
    login(client, admin_user_id(app))
    r = client.post(f"/web/workspace/{env['appliance_id']}/spo-wizard/plan",
                    json={"line": "retail", "backends": list(BACKENDS),
                          "web_addresses": [
                              {"web_address": "shop.example.com",
                               "address": "198.51.100.9"},
                              {"web_address": "blog.example.com",
                               "address": "198.51.100.10"}]})
    data = r.get_json()
    assert len(data["plans"]) == 2
    assert [p["web_address"] for p in data["plans"]] == ["shop.example.com",
                                                         "blog.example.com"]
    assert data["plans"][0]["pool_mode"] == "new"
    assert data["plans"][1]["pool_mode"] == "shared"


def test_the_old_single_address_form_still_works(app, client, env):
    """Every pre-batch caller posts this shape, including a page an operator
    already has open. A wizard that started refusing it would be a silent
    break, and ``plan`` is still the key they read."""
    login(client, admin_user_id(app))
    r = client.post(f"/web/workspace/{env['appliance_id']}/spo-wizard/plan",
                    json={"line": "retail", "backends": list(BACKENDS),
                          "web_address": "shop.example.com",
                          "address": "198.51.100.9"})
    data = r.get_json()
    assert len(data["plans"]) == 1
    assert data["plan"]["web_address"] == "shop.example.com"
    assert data["plan"]["pool_mode"] == "new"


def test_an_empty_form_still_reports_the_missing_address(app, client, env):
    """An empty batch rendered as an empty list reads as "nothing wrong",
    which is the opposite of what an empty form means."""
    login(client, admin_user_id(app))
    r = client.post(f"/web/workspace/{env['appliance_id']}/spo-wizard/plan",
                    json={"line": "retail"})
    data = r.get_json()
    assert len(data["plans"]) == 1
    assert "no_web_address" in [b["code"] for b in data["plans"][0]["blockers"]]


def test_the_page_serves_the_pool_catalog(app, client, env):
    with app.app_context():
        _cache_pool(env["appliance_id"], "pool-here", [("192.0.2.11", "8080")])
        _cache_pool(env["other_id"], "pool-there", [("192.0.2.11", "9090")])
    login(client, admin_user_id(app))
    body = client.get(
        f"/web/workspace/{env['appliance_id']}/spo-wizard").get_data(as_text=True)
    # Asserted against the PAYLOAD, never a substring of the page: a pool name
    # is a short word and matches half the nav.
    served = json.loads(re.search(r"const POOLS = (\[.*?\]);", body, re.S).group(1))
    assert {r["pool"] for r in served} == {"pool-here", "pool-there"}
    assert [r["local"] for r in served if r["pool"] == "pool-here"] == [True]


# ---------------------------------------------------------------------------
# 7. the form — structural, because no browser runs in this suite
# ---------------------------------------------------------------------------
def _body_fragment():
    src = TPL.read_text()
    start = src.index("function body(extra)")
    return src[start:src.index("function post(", start)]


def test_the_form_sends_the_domain_list_and_the_pool_choice():
    frag = _body_fragment()
    assert "web_addresses: rows" in frag
    assert "pool_mode: poolMode()" in frag
    assert "existing_pool:" in frag
    # The pre-batch triple is still sent — the server's fallback depends on it.
    assert "web_address: first.web_address" in frag


def test_the_form_still_sends_the_two_ddi_choices():
    """The batch rewrite went through this function. The choices it already
    threaded have to survive it."""
    frag = _body_fragment()
    assert "ipam_backend_id: $('w-ipam-backend').value" in frag
    assert "dns_backend_id: $('w-dns-backend').value" in frag


def test_the_pool_picker_and_the_add_button_are_wired():
    src = TPL.read_text()
    for ident in ('id="w-add-domain"', 'id="w-pool-pick"', 'id="w-pool-search"',
                  'id="w-pool-existing"', 'id="w-pool-copy"'):
        assert ident in src, ident
    for binding in ("$('w-add-domain').addEventListener",
                    "$('w-pool-search').addEventListener",
                    "$('w-pool-copy').addEventListener"):
        assert binding in src, binding


def test_the_page_has_no_inline_handlers_after_the_rewrite():
    """The CSP drops unsafe-inline, and the domain rows are built with
    ``innerHTML`` — the one place an ``onclick=`` would look natural."""
    src = TPL.read_text()
    for bad in ("onclick=", "onchange=", "onsubmit="):
        assert bad not in src


def test_the_page_is_still_light_themed():
    src = re.sub(r"\{#.*?#\}", "", TPL.read_text(), flags=re.S)
    for bad in ("backdrop-filter", "rgba(30,41,59", "#080d1a", "#8b5cf6"):
        assert bad not in src


# ---------------------------------------------------------------------------
# 8. only the pool half that was picked stays on screen
# ---------------------------------------------------------------------------
def _js_fn(name):
    """The body of one JS function, cut at the next top-level one.

    Asserting against the whole file would let a marker in the MARKUP satisfy
    a claim about the SCRIPT — the two halves name the same ids.
    """
    src = TPL.read_text()
    start = src.index("  function %s(" % name)
    end = src.index("\n  function ", start + 1)
    return src[start:end]


def test_each_pool_mode_has_its_own_container():
    """Nothing can be hidden that is not wrapped first."""
    src = TPL.read_text()
    for ident in ('id="w-pool-new-box"', 'id="w-pool-existing-box"'):
        assert ident in src, ident


def test_the_pool_half_that_was_not_picked_is_hidden():
    frag = _js_fn("syncPoolMode")
    assert "poolMode() === 'existing'" in frag
    # Both halves, and in OPPOSITE directions: a toggle that moves them the
    # same way either shows both (the clutter this removes) or hides both
    # (a form with no way to name a backend at all).
    assert "$('w-pool-new-box').style.display = existing ? 'none' : ''" in frag
    assert "$('w-pool-existing-box').style.display = existing ? '' : 'none'" in frag


def test_hiding_a_half_never_clears_what_was_typed():
    """A radio clicked by accident must be survivable. Wiping the real-server
    list on the way out would make the round trip lossy."""
    frag = _js_fn("syncPoolMode")
    assert ".value" not in frag


def test_every_path_that_changes_the_mode_runs_the_toggle():
    """describePool already runs on the two radios, on the pool picker, on
    every search keystroke and once at load. Hanging the toggle off it is what
    makes the initial render match the checked radio."""
    assert "syncPoolMode();" in _js_fn("describePool")
    for binding in ("$('w-pool-new').addEventListener",
                    "$('w-pool-existing').addEventListener",
                    "$('w-pool-pick').addEventListener"):
        assert binding in TPL.read_text(), binding


def test_the_copy_button_does_not_point_at_a_hidden_list():
    """It is only ever on screen while the real-server list is hidden, so the
    old label named a control the operator could not see."""
    src = TPL.read_text()
    assert "into the list above" not in src
    assert "Copy its members and create a new pool here" in src
