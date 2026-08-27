"""Guards for the new-Server-Policy-from-a-line wizard.

The failure this exists to prevent is not a crash either. ``create_policy``
stops at the first failure and leaves everything before it — survivable when
the leftovers are all on one device and an operator can see them, and NOT
survivable once a reserved address and an issued certificate are in the chain.
Nobody finds those by looking at the appliance.

So the properties are: refuse before the first write, compensate exactly what
was recorded, and never quietly do the destructive thing (revoke) or the
guessing thing (pick a segment, pick a certificate class, reach for the DDI's
fleet-wide default pool).
"""
from __future__ import annotations

import ast
import pathlib

import pytest

from app.extensions import db
from app.models import Appliance, Template
from app.models_lineprofile import LineProfile
from app.services import dns_providers as dp
from app.services import line_profiles as lp
from app.services import settings_store as store
from app.services import spo_wizard as wiz
from app.services.dns_providers import Address, DnsRecord

ROOT = pathlib.Path(__file__).resolve().parents[1]

_SEGMENTS = [
    {"name": "dmz-web", "zone": "dmz", "line": "retail", "department": "",
     "cidr": "198.51.100.0/24", "interface": "port3", "gateway": "198.51.100.1",
     "note": ""},
    {"name": "core-app", "zone": "internal", "line": "retail",
     "department": "", "cidr": "192.0.2.0/24", "interface": "port4",
     "gateway": "192.0.2.1", "note": ""},
    {"name": "no-cidr", "zone": "dmz", "line": "retail", "department": "",
     "cidr": "", "interface": "port7", "gateway": "", "note": ""},
    {"name": "other-line", "zone": "dmz", "line": "wholesale",
     "department": "", "cidr": "192.0.2.0/24", "interface": "port5",
     "gateway": "192.0.2.1", "note": ""},
]

BACKENDS = [{"ip": "192.0.2.11", "port": "8080"}]


def _caps(**kw):
    base = dict(provider="fake", label="Fake DDI", can_write=True,
                record_types=["A"], needs_zone=False, needs_view=False,
                can_allocate=True, needs_pool=True)
    base.update(kw)
    return dp.Capabilities(**base)


@pytest.fixture()
def env(app, monkeypatch):
    """A catalog, a declared line, an approved template and a live-looking box."""
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
        db.session.add(appl)
        db.session.commit()
        prof = LineProfile(product="fortiweb", line="retail",
                           cert_class="server", wpp_template_id=t.id)
        prof.set_segments(["dmz-web"])
        db.session.add(prof)
        db.session.commit()
        # the device answers, and has no clashing policy
        monkeypatch.setattr(type(appl), "build_client",
                            lambda self, **kw: _Client([]))
        monkeypatch.setattr(dp, "capabilities", lambda: _caps())
        yield {"appliance_id": appl.id, "template_id": t.id}


class _Client:
    def __init__(self, names):
        self._names = names

    def cmdb_names(self, endpoint):
        return list(self._names)


def _appl(app, env):
    return db.session.get(Appliance, env["appliance_id"])


def _plan(app, env, **kw):
    base = dict(line="retail", web_address="shop.example.com",
                backends=list(BACKENDS))
    base.update(kw)
    if "segment" in base:
        base["segment_name"] = base.pop("segment")
    with app.app_context():
        return wiz.build_plan(_appl(app, env), **base)


def _codes(plan):
    return [b.code for b in plan.blockers]


# ---------------------------------------------------------------------------
# 1. build_plan changes NOTHING
# ---------------------------------------------------------------------------
def test_build_plan_contains_no_writes():
    """Structural. A planner that writes is not a planner, and the damage is
    invisible: the operator pressed 'Preview'."""
    src = (ROOT / "app/services/spo_wizard.py").read_text()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "build_plan")
    banned = {"commit", "create", "allocate_address", "create_record",
              "create_certificate", "release_address", "delete_record"}
    hits = [n.func.attr for n in ast.walk(fn)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr in banned]
    assert hits == [], f"build_plan calls {hits}"


def test_planning_does_not_touch_the_providers(app, env, monkeypatch):
    called = []
    for name in ("allocate_address", "create_record", "release_address",
                 "delete_record"):
        monkeypatch.setattr(dp, name,
                            lambda *a, _n=name, **k: called.append(_n))
    _plan(app, env, use_ipam=True, hostname="shop.example.com",
          issue_cert=True)
    assert called == []


# ---------------------------------------------------------------------------
# 2. a blocked plan is never applied — dry-run or not
# ---------------------------------------------------------------------------
def test_a_blocked_plan_refuses_to_apply(app, env):
    plan = _plan(app, env, backends=[])          # no pool members
    assert not plan.ok
    with app.app_context():
        res = wiz.apply_plan(_appl(app, env), plan, dry_run=False)
    assert res["ok"] is False and "blocked" in res["error"]
    assert res["steps"] == []


def test_a_blocked_plan_refuses_even_in_dry_run(app, env):
    """Letting a blocked plan 'just preview' is how a blocker becomes
    advisory — the operator sees a clean preview and presses Apply."""
    plan = _plan(app, env, backends=[])
    with app.app_context():
        assert wiz.apply_plan(_appl(app, env), plan, dry_run=True)["ok"] is False


# ---------------------------------------------------------------------------
# 3. dry run writes nowhere
# ---------------------------------------------------------------------------
def test_dry_run_writes_to_no_system(app, env, monkeypatch):
    called = []
    for name in ("allocate_address", "create_record"):
        monkeypatch.setattr(dp, name,
                            lambda *a, _n=name, **k: called.append(_n))
    from app.services import cert_manager
    monkeypatch.setattr(cert_manager, "create_certificate",
                        lambda *a, **k: called.append("cert"))
    plan = _plan(app, env, use_ipam=True, hostname="shop.example.com",
                 issue_cert=True)
    assert plan.ok, _codes(plan)
    with app.app_context():
        res = wiz.apply_plan(_appl(app, env), plan, dry_run=True)
    assert res["ok"] and res["dry_run"] is True and called == []
    assert any(s["key"] == "objects" for s in res["steps"])
    assert res["objects"], "a preview must show the exact device payloads"


# ---------------------------------------------------------------------------
# 4. compensation — exactly what was recorded, and nothing else
# ---------------------------------------------------------------------------
def test_a_dns_failure_releases_the_address_by_its_handle(app, env,
                                                          monkeypatch):
    released = {}
    monkeypatch.setattr(dp, "allocate_address", lambda **k: Address(
        address="198.51.100.7", ref="ip-9", pool="198.51.100.0/24"))
    monkeypatch.setattr(dp, "create_record", lambda **k: (_ for _ in ()).throw(
        RuntimeError("zone frozen")))
    monkeypatch.setattr(dp, "release_address",
                        lambda a, ref="": released.update(addr=a, ref=ref))
    plan = _plan(app, env, use_ipam=True, hostname="shop.example.com")
    with app.app_context():
        res = wiz.apply_plan(_appl(app, env), plan, dry_run=False)
    assert res["ok"] is False
    assert released == {"addr": "198.51.100.7", "ref": "ip-9"}
    assert any("released 198.51.100.7" in c for c in res["compensated"])


def test_nothing_is_released_that_was_not_taken(app, env, monkeypatch):
    """A hand-typed VIP is not ours to hand back to a pool."""
    called = []
    monkeypatch.setattr(dp, "release_address",
                        lambda *a, **k: called.append(a))
    monkeypatch.setattr(dp, "create_record", lambda **k: (_ for _ in ()).throw(
        RuntimeError("nope")))
    plan = _plan(app, env, address="198.51.100.50", hostname="shop.example.com")
    with app.app_context():
        wiz.apply_plan(_appl(app, env), plan, dry_run=False)
    assert called == []


def test_a_device_failure_undoes_dns_and_the_address(app, env, monkeypatch):
    undone = []
    monkeypatch.setattr(dp, "allocate_address", lambda **k: Address(
        address="198.51.100.7", ref="ip-9"))
    monkeypatch.setattr(dp, "create_record",
                        lambda **k: DnsRecord(id="rr-1", name=k.get("name")))
    monkeypatch.setattr(dp, "delete_record",
                        lambda rid, **k: undone.append(("dns", rid)))
    monkeypatch.setattr(dp, "release_address",
                        lambda a, ref="": undone.append(("ip", a, ref)))
    from app.services import fortiweb_ops
    monkeypatch.setattr(fortiweb_ops.FortiWebOps, "create",
                        lambda self, ep, data, **k: fortiweb_ops.OpResult(
                            {"ok": False, "error": "device said no"}))
    plan = _plan(app, env, use_ipam=True, hostname="shop.example.com")
    with app.app_context():
        res = wiz.apply_plan(_appl(app, env), plan, dry_run=False)
    assert res["ok"] is False
    assert ("dns", "rr-1") in undone and ("ip", "198.51.100.7", "ip-9") in undone


def test_objects_already_on_the_device_are_named_not_deleted(app, env,
                                                             monkeypatch):
    """Deleting a policy object a human may already have bound elsewhere is a
    destructive guess. Naming it is not."""
    from app.services import fortiweb_ops
    calls = {"n": 0}

    def _create(self, ep, data, **k):
        calls["n"] += 1
        if calls["n"] <= 2:
            # OpResult.ok reads the "ok" KEY, not the absence of an error —
            # a mock returning {"error": ""} looks like a failure.
            return fortiweb_ops.OpResult({"ok": True})
        return fortiweb_ops.OpResult({"ok": False, "error": "boom"})

    monkeypatch.setattr(fortiweb_ops.FortiWebOps, "create", _create)
    plan = _plan(app, env, address="198.51.100.50")
    with app.app_context():
        res = wiz.apply_plan(_appl(app, env), plan, dry_run=False)
    assert res["ok"] is False
    assert any("already created on the device" in s for s in res["stranded"])


def test_an_issued_certificate_is_reported_and_never_revoked(app, env,
                                                             monkeypatch):
    """Revocation is destructive and irreversible; a certificate that exists
    is not harmful. Deciding to revoke on a failed build is this module
    deciding something nobody asked for."""
    from app.services import cert_manager, fortiweb_ops
    monkeypatch.setattr(cert_manager, "create_certificate",
                        lambda *a, **k: {"ok": True, "name": "cert-server-shop"})
    monkeypatch.setattr(fortiweb_ops.FortiWebOps, "create",
                        lambda self, ep, data, **k: fortiweb_ops.OpResult(
                            {"ok": False, "error": "boom"}))
    plan = _plan(app, env, address="198.51.100.50", issue_cert=True)
    assert plan.ok, _codes(plan)
    assert plan.hostname == "", "a blank hostname must not become the web address"
    with app.app_context():
        res = wiz.apply_plan(_appl(app, env), plan, dry_run=False)
    assert res["ok"] is False
    joined = " ".join(res["stranded"])
    assert "cert-server-shop" in joined and "NOT revoked" in joined
    # and it must NOT be listed as something that was undone
    assert not any("cert" in c for c in res["compensated"])


# ---------------------------------------------------------------------------
# 5. the segment — the whole point of the feature
# ---------------------------------------------------------------------------
def test_a_segment_the_line_does_not_receive_is_refused(app, env):
    """This is the failure the wizard exists to make impossible: a policy
    built perfectly, on a network this line was never given."""
    plan = _plan(app, env, segment="other-line")
    assert "segment_not_on_line" in _codes(plan)


def test_a_single_segment_is_chosen_automatically(app, env):
    plan = _plan(app, env)
    assert plan.segment.get("name") == "dmz-web"
    assert "segment_not_chosen" not in _codes(plan)


def test_several_segments_must_be_chosen_not_guessed(app, env):
    with app.app_context():
        prof = lp.profile_for("retail")
        prof.set_segments(["dmz-web", "core-app"])   # two -> must choose
        db.session.commit()
    plan = _plan(app, env)
    assert "segment_not_chosen" in _codes(plan)
    assert plan.segment == {}


def test_the_wizard_never_re_derives_what_a_line_receives():
    """§132: one author. The wizard must call line_plan, not read segments."""
    src = (ROOT / "app/services/spo_wizard.py").read_text()
    tree = ast.parse(src)
    reads = [n.lineno for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "segments"
             and isinstance(n.func.value, ast.Name)
             and n.func.value.id in ("store", "settings_store")]
    assert reads == [], f"spo_wizard reads the raw segment list at {reads}"
    assert "line_plan(" in src


# ---------------------------------------------------------------------------
# 6. addressing / DNS / certificate refusals
# ---------------------------------------------------------------------------
def test_ipam_without_a_pool_is_refused(app, env):
    """A segment WITH no CIDR and no override — so ``no_pool`` is the only
    thing that can fire. The first version of this test accepted
    ``no_segments`` as well, and an ``or`` in an assertion is how a guard
    stops asserting anything: a mutation deleting the pool check survived it.
    """
    with app.app_context():
        prof = lp.profile_for("retail")
        prof.set_segments(["no-cidr"])
        db.session.commit()
    plan = _plan(app, env, use_ipam=True)
    assert "no_pool" in _codes(plan)
    assert "no_segments" not in _codes(plan)


def test_ipam_with_a_provider_that_cannot_allocate_is_refused(app, env,
                                                              monkeypatch):
    monkeypatch.setattr(dp, "capabilities",
                        lambda: _caps(can_allocate=False, label="Weird DDI"))
    plan = _plan(app, env, use_ipam=True)
    assert "ipam_cannot_allocate" in _codes(plan)


def test_no_address_and_no_ipam_is_refused(app, env):
    assert "no_address" in _codes(_plan(app, env))


def test_a_hostname_with_a_read_only_dns_backend_is_refused(app, env,
                                                            monkeypatch):
    """§130's rule, in the wizard: a configured backend that cannot write,
    plus a requested hostname, is a refusal — not a step reporting success."""
    monkeypatch.setattr(dp, "capabilities",
                        lambda: _caps(can_write=False, label="phpIPAM"))
    plan = _plan(app, env, address="198.51.100.50", hostname="shop.example.com")
    assert "dns_cannot_write" in _codes(plan)


def test_no_dns_provider_warns_and_publishes_nothing(app, env, monkeypatch):
    monkeypatch.setattr(dp, "capabilities", lambda: None)
    plan = _plan(app, env, address="198.51.100.50", hostname="shop.example.com")
    assert plan.ok, _codes(plan)
    assert any("will NOT be published" in w for w in plan.warnings)
    with app.app_context():
        res = wiz.apply_plan(_appl(app, env), plan, dry_run=True)
    dns = [s for s in res["steps"] if s["key"] == "dns"][0]
    assert "NO DNS PROVIDER IS CONFIGURED" in dns["detail"]
    assert "would create" not in dns["detail"]


def test_a_certificate_without_a_declared_class_is_refused(app, env):
    with app.app_context():
        lp.profile_for("retail").cert_class = ""
        db.session.commit()
    plan = _plan(app, env, address="198.51.100.50", issue_cert=True)
    assert "no_cert_class" in _codes(plan)


def test_a_certificate_class_with_no_ca_template_is_refused(app, env):
    with app.app_context():
        store.save_cert_class_config("server", {"template": ""})
    plan = _plan(app, env, address="198.51.100.50", issue_cert=True)
    assert "cert_class_unconfigured" in _codes(plan)


# ---------------------------------------------------------------------------
# 7. the device
# ---------------------------------------------------------------------------
def test_an_existing_policy_name_is_refused_before_anything_is_built(app, env,
                                                                     monkeypatch):
    with app.app_context():
        appl = _appl(app, env)
        want = wiz.build_plan(appl, line="retail",
                              web_address="shop.example.com",
                              backends=list(BACKENDS)).names["server_policy"]
        monkeypatch.setattr(type(appl), "build_client",
                            lambda self, **kw: _Client([want]))
    assert "policy_exists" in _codes(_plan(app, env, address="198.51.100.50"))


def test_an_unreachable_device_blocks_rather_than_being_assumed_empty(app, env,
                                                                      monkeypatch):
    """Applying against a box we cannot read is how a run discovers at step
    four that step one was impossible."""
    with app.app_context():
        appl = _appl(app, env)

        def _boom(self, **kw):
            raise RuntimeError("no route to host")

        monkeypatch.setattr(type(appl), "build_client", _boom)
    assert "device_unreachable" in _codes(_plan(app, env, address="198.51.100.50"))


def test_a_policy_with_no_backends_is_refused(app, env):
    assert "no_backends" in _codes(_plan(app, env, address="192.0.2.1",
                                         backends=[]))


# ---------------------------------------------------------------------------
# 8. the payload
# ---------------------------------------------------------------------------
def test_objects_are_built_in_dependency_order(app, env):
    plan = _plan(app, env, address="198.51.100.50")
    with app.app_context():
        steps = wiz.object_payload(plan, "198.51.100.50")["steps"]
    assert [s[0] for s in steps] == ["Virtual Server", "VIP", "Server Pool",
                                     "Pool member 1", "Server Policy"]
    # the policy binds both, and the VIP carries the segment's interface
    policy = steps[-1][2]
    assert policy["vserver"] and policy["server-pool"]
    assert steps[1][2]["interface"] == "port3"
    assert steps[1][2]["vip"] == "198.51.100.50"


def test_the_wpp_from_the_line_is_bound(app, env):
    plan = _plan(app, env, address="198.51.100.50")
    with app.app_context():
        steps = wiz.object_payload(plan, "198.51.100.50")["steps"]
    assert steps[-1][2]["web-protection-profile"] == "wpp-retail"


def test_an_unapproved_wpp_blocks_the_whole_plan(app, env):
    with app.app_context():
        db.session.get(Template, env["template_id"]).status = \
            Template.STATUS_PENDING
        db.session.commit()
    assert "wpp_not_approved" in _codes(_plan(app, env, address="192.0.2.1"))


def test_endpoints_are_not_a_second_copy():
    """Two lists of FortiWeb create endpoints is two things to keep correct."""
    src = (ROOT / "app/services/spo_wizard.py").read_text()
    assert "_CREATE_EPS" in src
    assert "/api/v2.0/cmdb/server-policy/vserver" not in src


# ---------------------------------------------------------------------------
# 9. an inferred line is loudly labelled, never silently used
# ---------------------------------------------------------------------------
def test_an_undeclared_line_warns_that_everything_was_inferred(app, env):
    plan = _plan(app, env, line="wholesale", segment="other-line",
                 address="192.0.2.9")
    assert plan.line_source == "inferred"
    joined = " ".join(plan.warnings)
    assert "INFERRED" in joined and "Confirm" in joined


# ---------------------------------------------------------------------------
# 10. the endpoints
# ---------------------------------------------------------------------------
def test_apply_requires_config_write(app, client, env):
    from conftest import login, make_user
    uid = make_user(app, username="ro2", role="readonly")
    login(client, uid)
    r = client.post(f"/web/workspace/{env['appliance_id']}/spo-wizard/apply",
                    json={"line": "retail", "web_address": "x.example.com"})
    assert r.status_code in (302, 403)


def test_the_page_renders(app, client, env):
    from conftest import admin_user_id, login
    login(client, admin_user_id(app))
    r = client.get(f"/web/workspace/{env['appliance_id']}/spo-wizard")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Preview" in body and "retail" in body


def test_the_page_is_not_dark_themed():
    import re
    body = (ROOT / "app/templates/workspace/spo_wizard.html").read_text()
    body = re.sub(r"\{#.*?#\}", "", body, flags=re.S)
    for bad in ("backdrop-filter", "rgba(30,41,59", "#080d1a", "#8b5cf6"):
        assert bad not in body


def test_the_page_has_no_inline_handlers():
    """The CSP drops unsafe-inline; an onclick= silently stops working."""
    body = (ROOT / "app/templates/workspace/spo_wizard.html").read_text()
    for bad in ("onclick=", "onchange=", "onsubmit="):
        assert bad not in body


def test_the_naming_keys_are_the_ones_naming_actually_emits(app):
    """The first version of this module invented ``policy``/``vserver``/
    ``pool``. ``render_names`` emits ``server_policy``/``virtual_server``/
    ``server_pool``, so every lookup returned None, every object was created
    with an empty name, and the collision check silently did nothing. Nothing
    crashed."""
    from app.services import naming
    with app.app_context():
        names = naming.render_names("shop.example.com", None, "fortiweb")
    for key in wiz.REQUIRED_NAMES:
        assert key in names and names[key], f"{key} is not a naming element"


def test_an_empty_rendered_name_is_refused(app, env, monkeypatch):
    from app.services import naming as _n
    monkeypatch.setattr(wiz.naming, "render_names",
                        lambda *a, **k: dict.fromkeys(wiz.REQUIRED_NAMES, ""))
    assert "naming_incomplete" in _codes(_plan(app, env, address="192.0.2.1"))
