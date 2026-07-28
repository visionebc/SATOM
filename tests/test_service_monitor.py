"""Service Monitor is a PARTITION of Deep monitors, enforced server-side.

Added 2026-07-28 when the four REST-telemetry kinds were lifted out of Deep
monitors into their own page. The two pages share the ``monitor_probe`` table,
the runner and the ``deep_monitor`` scheduled action; what is split is the set
of kinds each one owns.

The properties pinned here are the ones a template cannot guarantee:

1. the two kind sets are disjoint and together cover ``deep_monitor.KINDS`` —
   a kind added later lands on exactly one page, never on both and never on
   neither;
2. each page's ``/data`` lists ONLY its own kinds — a page that merely hides
   what it does not own is hidden, not scoped;
3. each page REFUSES to create or edit a kind belonging to the other, and 404s
   a probe id that does. Without this the form's ``<select>`` would be the only
   thing standing between an operator and a probe its owner page cannot see;
4. "Probe now" with no selection stays inside the page (and inside the ADOM);
5. discovery only offers the steps the page owns — asking the Service Monitor
   page for ``baseline`` must not create CPU/memory/proxyd probes it will never
   display.
"""
from __future__ import annotations

import pytest

from app.models import Appliance, MonitorProbe, User, db
from app.services import deep_monitor as dm
from tests.conftest import login

PAGES = {
    "deep_monitor": "/monitoring/deep",
    "service_monitor": "/monitoring/services",
}


@pytest.fixture()
def admin_id(app):
    with app.app_context():
        u = User.query.filter_by(role="admin").first()
        if u is None:
            u = User(username="smadmin", role="admin", is_active=True)
            u.set_password("x" * 12)
            db.session.add(u)
            db.session.commit()
        return u.id


@pytest.fixture()
def box(app):
    """One FortiWeb with one probe of each page's kinds."""
    with app.app_context():
        a = Appliance(name="fw-split", host="192.0.2.13", kind="fortiweb",
                      username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.flush()
        deep = MonitorProbe(appliance_id=a.id, kind="cpu", name="fw-split cpu",
                            enabled=True, warn_pct=80, crit_pct=95)
        api = MonitorProbe(appliance_id=a.id, kind="policy_sessions",
                           name="fw-split pol", target="pol-x", enabled=True)
        db.session.add_all([deep, api])
        db.session.commit()
        return {"aid": a.id, "deep": deep.id, "api": api.id}


# --------------------------------------------------------------------------
# 1. the partition itself
# --------------------------------------------------------------------------

def test_the_two_pages_partition_every_probe_kind():
    from app.views.deep_monitor import KINDS as DEEP
    from app.views.service_monitor import KINDS as API

    assert not set(DEEP) & set(API), "a kind is claimed by both pages"
    assert set(DEEP) | set(API) == set(dm.KINDS), (
        "a probe kind belongs to no page and would be invisible and "
        "uneditable: %s" % (set(dm.KINDS) - set(DEEP) - set(API)))
    assert set(API) == set(dm.API_KINDS)


def test_every_owned_kind_has_a_label_and_a_field_group():
    from app.views import deep_monitor as dmv, service_monitor as smv

    for spec in (dmv.SPEC, smv.SPEC):
        d = spec.as_dict(PAGES[spec.key])
        for k in spec.kinds:
            assert d["labels"].get(k), f"{k} renders with no label"
            assert d["group_of"].get(k), f"{k} renders with no field group"
        assert d["groups"], "a page with no field group cannot add a probe"


# --------------------------------------------------------------------------
# 2. listings are scoped, not merely filtered in the template
# --------------------------------------------------------------------------

@pytest.mark.parametrize("page", sorted(PAGES))
def test_data_lists_only_this_pages_kinds(client, admin_id, box, page):
    from app.views import deep_monitor, service_monitor  # noqa: F401

    mod = {"deep_monitor": deep_monitor, "service_monitor": service_monitor}[page]
    login(client, admin_id, product="global")
    r = client.get(PAGES[page] + "/data")
    assert r.status_code == 200
    kinds = {p["kind"] for p in r.get_json()["probes"]}
    assert kinds, "fixture should have given this page a probe"
    assert kinds <= set(mod.KINDS), f"{page} leaked {kinds - set(mod.KINDS)}"


@pytest.mark.parametrize("page", sorted(PAGES))
def test_pages_render(client, admin_id, box, page):
    login(client, admin_id, product="global")
    assert client.get(PAGES[page] + "/").status_code == 200


# --------------------------------------------------------------------------
# 3. cross-page writes are refused
# --------------------------------------------------------------------------

def test_deep_page_refuses_to_create_a_service_monitor_kind(client, admin_id, box):
    login(client, admin_id, product="global")
    r = client.post("/monitoring/deep/probe",
                    data={"kind": "throughput", "name": "x",
                          "appliance_id": box["aid"], "target": dm.TOTAL_HTTP})
    assert r.status_code == 400
    assert "Deep monitors" in r.get_json()["error"]


def test_service_page_refuses_to_create_a_deep_kind(client, admin_id, box):
    login(client, admin_id, product="global")
    r = client.post("/monitoring/services/probe",
                    data={"kind": "proxyd", "name": "x",
                          "appliance_id": box["aid"]})
    assert r.status_code == 400
    assert "Service Monitor" in r.get_json()["error"]


@pytest.mark.parametrize("verb,path", [
    ("get", "/probe/%d/history"),
    ("get", "/probe/%d/series"),
    ("post", "/probe/%d"),
    ("post", "/probe/%d/toggle"),
    ("post", "/probe/%d/delete"),
])
def test_a_probe_of_the_other_page_is_a_404(client, admin_id, box, verb, path):
    """404, not 403: from this page's point of view the probe does not exist."""
    login(client, admin_id, product="global")
    for page, other in (("deep_monitor", "api"), ("service_monitor", "deep")):
        url = PAGES[page] + (path % box[other])
        r = getattr(client, verb)(url)
        assert r.status_code == 404, f"{url} answered {r.status_code}"


def test_editing_across_pages_cannot_smuggle_a_kind(client, admin_id, box, app):
    """Even on its OWN probe, a page cannot retype it into the other's kind."""
    login(client, admin_id, product="global")
    r = client.post("/monitoring/deep/probe/%d" % box["deep"],
                    data={"kind": "sessions", "name": "smuggled",
                          "appliance_id": box["aid"]})
    assert r.status_code == 400
    with app.app_context():
        assert MonitorProbe.query.get(box["deep"]).kind == "cpu"


# --------------------------------------------------------------------------
# 4. "Probe now" stays inside the page
# --------------------------------------------------------------------------

def _capture_job(monkeypatch, module):
    captured = {}
    real = module.jobsvc.create_job

    def fake(type_, title, **kw):
        captured["meta"] = kw.get("meta")
        return real(type_, title, **kw)

    monkeypatch.setattr(module.jobsvc, "create_job", fake)
    monkeypatch.setattr(module.jobsvc, "run_async", lambda *a, **k: None)
    return captured


@pytest.mark.parametrize("page", sorted(PAGES))
def test_probe_now_without_a_selection_stays_on_this_page(client, admin_id, box,
                                                          page, monkeypatch, app):
    from app.views import deep_monitor, service_monitor

    mod = {"deep_monitor": deep_monitor, "service_monitor": service_monitor}[page]
    captured = _capture_job(monkeypatch, mod)
    login(client, admin_id, product="global")
    r = client.post(PAGES[page] + "/run")
    assert r.status_code == 200, r.get_data(as_text=True)
    ids = captured["meta"]["ids"]
    assert ids and ids != "all"
    with app.app_context():
        kinds = {MonitorProbe.query.get(i).kind for i in ids}
    assert kinds <= set(mod.KINDS), f"{page} would have run {kinds}"


def test_probe_now_with_an_explicit_id_from_the_other_page_is_refused(
        client, admin_id, box, monkeypatch):
    from app.views import service_monitor as smv

    _capture_job(monkeypatch, smv)
    login(client, admin_id, product="global")
    r = client.post("/monitoring/services/run", data={"id": box["deep"]})
    assert r.status_code == 400


# --------------------------------------------------------------------------
# 5. discovery offers only the steps the page owns
# --------------------------------------------------------------------------

def test_service_page_discovery_cannot_be_asked_for_the_deep_steps(
        client, admin_id, box, monkeypatch):
    from app.views import service_monitor as smv

    captured = _capture_job(monkeypatch, smv)
    login(client, admin_id, product="global")
    r = client.post("/monitoring/services/discover",
                    data={"appliance_id": box["aid"],
                          "what": ["baseline", "policies", "api"]})
    assert r.status_code == 200
    # baseline would create cpu/memory/proxyd probes this page never displays.
    assert captured["meta"]["what"] == ["api"]


def test_deep_page_discovery_cannot_be_asked_for_the_api_step(
        client, admin_id, box, monkeypatch):
    from app.views import deep_monitor as dmv

    captured = _capture_job(monkeypatch, dmv)
    login(client, admin_id, product="global")
    r = client.post("/monitoring/deep/discover",
                    data={"appliance_id": box["aid"], "what": ["api"]})
    assert r.status_code == 200
    assert "api" not in captured["meta"]["what"]


# --------------------------------------------------------------------------
# 6. the live policy picker reports failure instead of an empty list
# --------------------------------------------------------------------------

def test_policy_picker_reports_the_error_instead_of_no_policies(
        client, admin_id, box, monkeypatch):
    """An unreachable box must not look like a box with zero policies."""
    from app.clients import fortiweb as fwmod

    def boom(self):
        raise RuntimeError("No route to host")

    monkeypatch.setattr(fwmod.FortiWebClient, "policy_status", boom)
    login(client, admin_id, product="global")
    r = client.get("/monitoring/services/policies/%d" % box["aid"])
    assert r.status_code == 200
    body = r.get_json()
    assert body["policies"] == []
    assert "No route to host" in body["error"]


def test_policy_picker_refuses_non_fortiweb(client, admin_id, app):
    with app.app_context():
        a = Appliance(name="adc-x", host="192.0.2.76", kind="fortiadc",
                      username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        aid = a.id
    login(client, admin_id, product="global")
    r = client.get("/monitoring/services/policies/%d" % aid)
    assert r.status_code == 200
    assert "fortiweb-only" in r.get_json()["error"]


# --------------------------------------------------------------------------
# 7. the silent-zero guard on HTTP transactions
# --------------------------------------------------------------------------

def test_zero_transactions_on_a_busy_policy_is_not_ok():
    """VERIFIED on fortiweb08 (2026-07-28), not hypothesised.

    A policy carrying ~2 700 req/s reported 0 transactions in every bucket, and
    reported 417 059 the moment a web-protection-profile was attached. Grading
    that ``ok`` would put a green row on a saturated service.
    """
    tx = {"buckets": [{"time": "05:39-05:44", "count": 0}] * 12,
          "total": 0, "last": 0, "peak": 0}
    st, detail = dm.classify_transactions(
        tx, warn_num=0, crit_num=0,
        carrying={"sessions": 2, "conn_per_sec": 580})
    assert st == "warn", "a busy policy reporting zero must not read as healthy"
    assert "web-protection-profile" in detail


def test_zero_transactions_on_an_idle_policy_is_ok():
    """The guard must not fire on a genuinely quiet policy."""
    tx = {"buckets": [{"time": "05:39-05:44", "count": 0}] * 12,
          "total": 0, "last": 0, "peak": 0}
    st, _ = dm.classify_transactions(tx, warn_num=0, crit_num=0,
                                     carrying={"sessions": 0,
                                               "conn_per_sec": 0})
    assert st == "ok"
    st2, _ = dm.classify_transactions(tx, warn_num=0, crit_num=0, carrying=None)
    assert st2 == "ok"


def test_no_buckets_is_still_an_error_not_a_zero():
    st, detail = dm.classify_transactions({"buckets": [], "total": 0, "last": 0,
                                           "peak": 0},
                                          warn_num=0, crit_num=0,
                                          carrying={"sessions": 9,
                                                    "conn_per_sec": 9})
    assert st == "error"
    assert "unknown policy name" in detail
