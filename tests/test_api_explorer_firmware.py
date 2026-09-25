"""API Explorer, firmware-aware: the build banner, per-leaf marks, fields on a
build, the server-side "not served on this build" guard in execute(), and the
"Harvest this appliance now" route.

No test here reaches an appliance: ``client_for`` is replaced by a recorder,
and the library is seeded through ``api_library.ingest`` — the same writer the
real harvests use — so the evidence shapes are the production ones.
"""
from __future__ import annotations

import pathlib
import sys
import types

import pytest

from tests.conftest import admin_user_id, login, make_user

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "app" / "templates" / "api_explorer" / "index.html"
BASE = "/web/api-explorer"


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

def _sweep(version, device, aid, endpoints, at="2026-09-20T10:00:00"):
    return {"product": "fortiweb", "source": "sweep", "captured_at": at,
            "origin_ref": "test:%s@%s" % (device, version),
            "device": {"appliance_id": aid, "name": device, "serial": "", "model": "",
                       "hw_type": "vm", "firmware_raw": version},
            "scope": {"kind": "build", "version": version, "build": ""},
            "healthy": True, "skip_reason": "", "endpoints": endpoints}


def _ep(urn, verdict, fields=None):
    return {"urn": urn, "section": "Test", "verdict": verdict, "rows": 1, "fields": fields}


class _Resp:
    status_code = 200
    text = '{"results": []}'

    def json(self):
        return {"results": []}


class _Recorder:
    """Stands in for client_for(): records every call, never opens a socket."""

    def __init__(self):
        self.calls = []

    def __call__(self, appliance):
        rec = self

        class _C:
            def api_call(self, method, path, body=None):
                rec.calls.append((appliance.name, method, path, body))
                return _Resp()
        return _C()


@pytest.fixture()
def world(app, monkeypatch):
    """Appliances mirroring the fleet (plus an unmeasured 7.6.9 and one with no
    firmware) and library evidence for two builds.

    Leaf names are taken from the live registry so the tree marks can be
    asserted on real leaves:
      A: served on 7.6.8 and 8.0.5 (fields measured on both; 8.0.5 adds one)
      B: served on 7.6.8, ABSENT on 8.0.5
      C: ABSENT on 7.6.8, served on 8.0.5
      D: in the registry, never measured anywhere -> unknown
      E: served on 8.0.5 but blind; the 8.0 line schema knows its fields
    """
    from app.extensions import db
    from app.models import Appliance
    from app.registry import loader
    from app.services import api_library as lib

    rec = _Recorder()
    monkeypatch.setattr("app.views.api_explorer.client_for", rec)
    with app.app_context():
        reg = [e for e in loader.get_all_endpoints() if e.get("name") and e.get("urn")]
        assert len(reg) >= 5, "registry fixture too small for this test"
        A, B, C, D, E = reg[:5]
        ids = {}
        for name, kind, fw in (("fortiweb15", "fortiweb", "7.6.8"),
                               ("fortiweb16", "fortiweb", "7.6.8"),
                               ("fortiweb17", "fortiweb", "8.0.5"),
                               ("fortiweb18", "fortiweb", "7.6.9"),
                               ("fac01", "fortiauthenticator", "8.0.3"),
                               ("fwnofw", "fortiweb", None)):
            a = Appliance(name=name, kind=kind, host="192.0.2.10", username="x",
                          password_enc="x", firmware=fw)
            db.session.add(a)
            db.session.flush()
            ids[name] = a.id
        db.session.commit()
        lib.ingest(_sweep("7.6.8", "fortiweb15", ids["fortiweb15"], {
            A["name"]: _ep(A["urn"], "ok", {"name": {"type": "str"}}),
            B["name"]: _ep(B["urn"], "ok"),
            C["name"]: _ep(C["urn"], "absent"),
        }))
        lib.ingest(_sweep("8.0.5", "fortiweb17", ids["fortiweb17"], {
            A["name"]: _ep(A["urn"], "ok", {
                "name": {"type": "str"},
                "http2": {"type": "str", "options": ["enable", "disable"],
                          "default": "disable"}}),
            B["name"]: _ep(B["urn"], "absent"),
            C["name"]: _ep(C["urn"], "ok"),
            E["name"]: _ep(E["urn"], "ok", None),
        }, at="2026-09-21T10:00:00"))
        lib.ingest({"product": "fortiweb", "source": "schema",
                    "captured_at": "2026-09-17T00:00:00", "origin_ref": "schema:8.0",
                    "device": None, "scope": {"kind": "line", "line": "8.0"},
                    "healthy": True, "skip_reason": "",
                    "endpoints": {E["name"]: _ep(E["urn"], "ok", {
                        "mode": {"type": "option", "options": ["a", "b"], "default": "a"}})}})
    yield types.SimpleNamespace(ids=ids, rec=rec, A=A, B=B, C=C, D=D, E=E)


@pytest.fixture()
def admin(app, client):
    login(client, admin_user_id(app))
    return client


def _build(client, aid):
    r = client.get("%s/build?appliance_id=%d" % (BASE, aid))
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()


def _execute(client, aid, path, method="GET", **extra):
    data = {"appliance_id": aid, "endpoint": path, "method": method}
    data.update(extra)
    return client.post("%s/execute" % BASE, data=data)


# ---------------------------------------------------------------------------
# banner + marks
# ---------------------------------------------------------------------------

def test_banner_names_the_exact_build_its_status_and_provenance(admin, world):
    d = _build(admin, world.ids["fortiweb16"])
    assert d["ok"] is True
    assert d["build"]["product"] == "fortiweb"
    assert d["build"]["version"] == "7.6.8"
    assert d["build"]["status"] == "measured"
    assert d["build"]["status_label"] == "measured by sweep"
    # fortiweb16 was never swept itself; the build's evidence names who was.
    assert any(p["source"] == "sweep" and p["device"] == "fortiweb15"
               and p["scope"] == "build 7.6.8" for p in d["provenance"])
    assert d["harvestable"] is False


def test_marks_differ_between_builds_that_share_an_api_version(admin, world):
    """The defect: keyed by v2.0 only, 7.6.8 and 8.0.5 looked identical."""
    old = _build(admin, world.ids["fortiweb15"])["marks"]
    new = _build(admin, world.ids["fortiweb17"])["marks"]
    A, B, C, D = world.A["name"], world.B["name"], world.C["name"], world.D["name"]
    assert (old[A], old[B], old[C], old[D]) == ("served", "served", "absent", "unknown")
    assert (new[A], new[B], new[C], new[D]) == ("served", "absent", "served", "unknown")


def test_counts_add_up_to_the_tree(admin, world, app):
    from app.registry import loader
    d = _build(admin, world.ids["fortiweb17"])
    with app.app_context():
        n = len({e["name"] for e in loader.get_all_endpoints() if e.get("name")})
    assert sum(d["counts"].values()) == n
    assert d["counts"]["served"] == 3 and d["counts"]["absent"] == 1


def test_unmeasured_build_is_unknown_everywhere_and_offers_a_harvest(admin, world):
    d = _build(admin, world.ids["fortiweb18"])
    assert d["build"]["status"] == "unmeasured"
    assert d["build"]["version"] == "7.6.9"
    assert d["harvestable"] is True
    assert set(d["marks"].values()) == {"unknown"}
    assert d["provenance"] == []


def test_appliance_without_firmware_is_not_guessed(admin, world):
    d = _build(admin, world.ids["fwnofw"])
    assert d["build"]["status"] == "unknown_firmware"
    assert set(d["marks"].values()) == {"unknown"}
    assert d["harvestable"] is True


def test_build_requires_an_appliance(admin, world):
    r = admin.get("%s/build" % BASE)
    assert r.status_code == 400 and r.get_json()["msg"]


# ---------------------------------------------------------------------------
# fields on a build
# ---------------------------------------------------------------------------

def test_fields_carry_type_options_default_and_since_hint(admin, world):
    r = admin.get("%s/fields?appliance_id=%d&endpoint=%s&path=%s"
                  % (BASE, world.ids["fortiweb17"], world.A["name"], world.A["urn"]))
    d = r.get_json()
    assert d["status"] == "measured"
    f = d["fields"]
    assert f["http2"]["type"] == "str"
    assert f["http2"]["options"] == ["enable", "disable"]
    assert f["http2"]["default"] == "disable"
    # 7.6.8 measured this endpoint's fields (same source) without http2.
    assert f["http2"]["since"] == "8.0.5"
    assert "since" not in f["name"]


def test_fields_on_the_older_build_do_not_include_the_newer_field(admin, world):
    d = admin.get("%s/fields?appliance_id=%d&endpoint=%s"
                  % (BASE, world.ids["fortiweb15"], world.A["name"])).get_json()
    assert d["status"] == "measured"
    assert set(d["fields"]) == {"name"}
    assert "since" not in d["fields"]["name"]


def test_blind_build_offers_the_line_schema_separately(admin, world):
    d = admin.get("%s/fields?appliance_id=%d&endpoint=%s"
                  % (BASE, world.ids["fortiweb17"], world.E["name"])).get_json()
    assert d["status"] == "blind"
    assert d["fields"] == {}
    assert d["line_fallback"]["line"] == "8.0"
    assert d["line_fallback"]["fields"]["mode"]["options"] == ["a", "b"]


def test_a_stale_leaf_name_cannot_override_the_urn(admin, world):
    """The URN is what would be sent; a name that disagrees with it loses."""
    d = admin.get("%s/fields?appliance_id=%d&endpoint=%s&path=%s"
                  % (BASE, world.ids["fortiweb17"], world.A["name"], world.B["urn"])).get_json()
    assert d["state"] == "absent" and d["endpoint"] == world.B["name"]


def test_fields_of_an_absent_endpoint_say_absent(admin, world):
    d = admin.get("%s/fields?appliance_id=%d&endpoint=%s"
                  % (BASE, world.ids["fortiweb17"], world.B["name"])).get_json()
    assert d["status"] == "absent" and d["state"] == "absent"


# ---------------------------------------------------------------------------
# execute(): the server-side guard
# ---------------------------------------------------------------------------

def test_execute_refuses_an_endpoint_the_build_does_not_serve(admin, world):
    r = _execute(admin, world.ids["fortiweb17"], world.B["urn"])
    assert r.status_code == 409
    d = r.get_json()
    assert d["ok"] is False and d["refused"] is True and d["needs_confirm"] is True
    assert "does not serve" in d["msg"] and "8.0.5" in d["msg"]
    assert d["library"]["state"] == "absent"
    assert world.rec.calls == []   # nothing left the building


def test_execute_sends_an_unserved_endpoint_only_with_confirmation(admin, world, app):
    r = _execute(admin, world.ids["fortiweb17"], world.B["urn"], confirm_unserved="1")
    d = r.get_json()
    assert r.status_code == 200 and d["ok"] is True
    assert d["library"]["confirmed"] is True
    assert "despite" in d["warning"]
    assert world.rec.calls == [("fortiweb17", "GET", world.B["urn"], None)]
    from app.models import AuditLog
    with app.app_context():
        row = AuditLog.query.filter_by(action="api_explorer.execute").order_by(
            AuditLog.id.desc()).first()
        assert row is not None and "'confirm_unserved': True" in (row.extra or "")


def test_confirm_flag_must_be_truthy(admin, world):
    r = _execute(admin, world.ids["fortiweb17"], world.B["urn"], confirm_unserved="0")
    assert r.status_code == 409 and world.rec.calls == []


def test_the_same_endpoint_passes_on_the_build_that_serves_it(admin, world):
    r = _execute(admin, world.ids["fortiweb15"], world.B["urn"])
    d = r.get_json()
    assert d["ok"] is True and d["warning"] == ""
    assert d["library"]["state"] == "served"
    assert len(world.rec.calls) == 1


def test_path_normalisation_cannot_dodge_the_guard(admin, world):
    """No leading slash, a trailing slash, an ?mkey= and upper case are all
    the same endpoint — and a stale leaf name cannot talk the URN out of it."""
    p = world.B["urn"].lstrip("/").upper() + "/?mkey=x"
    r = admin.post("%s/execute" % BASE, data={
        "appliance_id": world.ids["fortiweb17"], "endpoint": p, "method": "GET",
        "name": world.A["name"]})
    assert r.status_code == 409 and world.rec.calls == []


def test_unknown_endpoint_passes_with_a_warning(admin, world):
    r = _execute(admin, world.ids["fortiweb17"], world.D["urn"])
    d = r.get_json()
    assert d["ok"] is True
    assert d["library"]["state"] == "unknown"
    assert "never measured" in d["warning"]
    assert len(world.rec.calls) == 1


def test_unmeasured_build_passes_with_a_warning(admin, world):
    r = _execute(admin, world.ids["fortiweb18"], world.B["urn"])
    d = r.get_json()
    assert d["ok"] is True
    assert "no evidence" in d["warning"]
    assert len(world.rec.calls) == 1


def test_write_guard_still_applies_before_the_library(app, client, world):
    uid = make_user(app, username="viewer", role="readonly")
    login(client, uid)
    r = _execute(client, world.ids["fortiweb15"], world.A["urn"], method="POST",
                 body='{"data": {}}')
    d = r.get_json()
    assert d["ok"] is False and "permission" in d["msg"]
    assert world.rec.calls == []


def test_vendor_claim_absent_is_refused_and_says_it_is_a_claim(admin, world, app):
    """A build only vendor data covers: its "absent" is a claim, and the refusal
    says so — the operator is overriding the vendor's tooling, not a sweep."""
    from app.extensions import db
    from app.models import Appliance
    from app.services import api_library as lib
    with app.app_context():
        lib.ingest({"product": "fortiweb", "source": "vendor_doc",
                    "captured_at": "2026-09-25T21:00:00", "origin_ref": "vendor:test",
                    "device": None, "scope": {"kind": "spans", "versions": ["7.0.0", "7.4.0"]},
                    "healthy": True, "skip_reason": "",
                    "endpoints": {"vendor_thing": {"urn": "/api/v2.0/cmdb/vendor/thing",
                                                   "section": "Vendor",
                                                   "spans": [["7.2.0", ""]], "fields": None}}})
        a = Appliance(name="fortiweb70", kind="fortiweb", host="192.0.2.20", username="x",
                      password_enc="x", firmware="7.0.1")
        db.session.add(a)
        db.session.commit()
        aid = a.id
    d = _build(admin, aid)
    assert d["build"]["status"] == "vendor_only"
    assert d["harvestable"] is True
    assert any(p["source"] == "vendor_doc" and p["scope"].startswith("vendor range")
               for p in d["provenance"])
    r = _execute(admin, aid, "/api/v2.0/cmdb/vendor/thing")
    assert r.status_code == 409
    assert "vendor" in r.get_json()["msg"]
    assert world.rec.calls == []


def test_other_products_resolve_to_their_own_library(app, world):
    """fac01 (FortiAuthenticator 8.0.3) has no evidence: unmeasured — never
    borrowed from FortiWeb's builds of the same number."""
    from app.extensions import db
    from app.models import Appliance
    from app.views import api_explorer as v
    with app.app_context():
        fac = db.session.get(Appliance, world.ids["fac01"])
        view = v._library_view(fac)
        assert view["resolved"]["product"] == "fortiauthenticator"
        assert view["resolved"]["version"] == "8.0.3"
        assert view["resolved"]["status"] == "unmeasured"
        assert view["endpoints"] == {}
        assert v._endpoint_state(view, path="/api/v1/localusers/")["state"] == "unknown"


def test_duplicate_urns_never_refuse_on_a_tie(app):
    """Two library names can share a URN; ok beats absent."""
    from app.views import api_explorer as v
    view = {"endpoints": {"x1": {"verdict": "absent", "urn": "/a/b"},
                          "x2": {"verdict": "ok", "urn": "/a/b"}},
            "by_urn": {"a/b": ["x1", "x2"]}}
    assert v._endpoint_state(view, path="/a/b")["state"] == "served"


# ---------------------------------------------------------------------------
# harvest
# ---------------------------------------------------------------------------

def test_harvest_calls_enqueue_with_the_explorer_reason(admin, world, monkeypatch):
    calls = []
    fake = types.ModuleType("app.services.apilib_harvest")
    fake.enqueue = lambda aid, reason: calls.append((aid, reason)) or {
        "queued": True, "msg": "harvest of fortiweb18 queued (explorer)", "job_id": "j1"}
    monkeypatch.setitem(sys.modules, "app.services.apilib_harvest", fake)
    import app.services as services_pkg
    monkeypatch.setattr(services_pkg, "apilib_harvest", fake, raising=False)
    r = admin.post("%s/harvest/%d" % (BASE, world.ids["fortiweb18"]))
    d = r.get_json()
    assert r.status_code == 200 and d["ok"] is True
    assert calls == [(world.ids["fortiweb18"], "explorer")]
    assert "queued" in d["msg"]


def test_harvest_refusal_comes_back_in_msg(admin, world, monkeypatch):
    fake = types.ModuleType("app.services.apilib_harvest")
    fake.enqueue = lambda aid, reason: {"queued": False, "reason": "unsupported",
                                        "msg": "no live harvester for fortiauthenticator"}
    monkeypatch.setitem(sys.modules, "app.services.apilib_harvest", fake)
    import app.services as services_pkg
    monkeypatch.setattr(services_pkg, "apilib_harvest", fake, raising=False)
    d = admin.post("%s/harvest/%d" % (BASE, world.ids["fortiweb18"])).get_json()
    assert d["ok"] is False and d["msg"] == "no live harvester for fortiauthenticator"


def test_harvest_without_the_module_answers_with_a_message(admin, world, monkeypatch):
    monkeypatch.setitem(sys.modules, "app.services.apilib_harvest", None)
    import app.services as services_pkg
    monkeypatch.delattr(services_pkg, "apilib_harvest", raising=False)
    r = admin.post("%s/harvest/%d" % (BASE, world.ids["fortiweb18"]))
    assert r.status_code == 503
    assert "not available" in r.get_json()["msg"]


def test_harvest_is_gated_like_the_other_sweep_route(app, client, world, monkeypatch):
    fake = types.ModuleType("app.services.apilib_harvest")
    called = []
    fake.enqueue = lambda aid, reason: called.append(aid)
    monkeypatch.setitem(sys.modules, "app.services.apilib_harvest", fake)
    uid = make_user(app, username="viewer2", role="readonly")
    login(client, uid)
    r = client.post("%s/harvest/%d" % (BASE, world.ids["fortiweb18"]))
    assert r.status_code == 403 and called == []


def test_harvest_is_post_only(admin, world):
    assert admin.get("%s/harvest/%d" % (BASE, world.ids["fortiweb18"])).status_code == 405


# ---------------------------------------------------------------------------
# the page
# ---------------------------------------------------------------------------

def test_page_renders_the_banner_marks_and_filter(admin, world):
    page = admin.get(BASE + "/").get_data(as_text=True)
    assert 'id="build-banner"' in page
    assert 'data-build-url="/' in page and 'data-execute-url="/' in page
    assert 'id="apiTreeServedOnly"' in page
    assert "Only what this build serves" in page
    assert "Harvest this appliance now" in page
    assert 'data-name="%s"' % world.A["name"] in page
    assert "api-build-mark" in page


def test_page_js_goes_through_execute_with_the_csrf_header():
    """The guard lives in execute(); a page that still called the generic
    proxy would walk straight past it."""
    src = TEMPLATE.read_text(encoding="utf-8")
    assert "/proxy/" not in src
    assert "executeUrl" in src and "'X-CSRF-Token'" in src
    assert "confirm_unserved" in src


def test_page_stays_on_the_light_theme_tokens():
    src = TEMPLATE.read_text(encoding="utf-8")
    for bad in ("backdrop-filter", "rgba(0,0,0,0.", "#0b1020", "glass"):
        assert bad not in src, bad
    for good in ("fw-badge-success", "fw-badge-danger", "fw-badge-secondary", "var(--fw-"):
        assert good in src, good
