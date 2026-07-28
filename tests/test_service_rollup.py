"""Per-device traffic cards and the per-policy drill-down.

The Service Monitor table answers "is this probe healthy?". These two views
answer "how much is this appliance carrying" and "what is happening inside this
policy". They consolidate stored sample payloads, and the properties pinned
here are the ones that make that consolidation safe to look at:

1. **Absence is never a zero.** A missing, disabled or never-run probe reports
   ``unknown``/``measured=False``, never a number. A zero meaning "no probe"
   renders identically to a zero meaning "idle", and only one is good news.
2. **A page load never contacts an appliance.** Enforced by making the REST
   client explode: both views must still answer 200.
3. **The rollup belongs to one page.** Deep monitors must not emit it, and its
   policy endpoint must not exist there.
4. **ADOM scoping holds** on the new endpoint, same as everywhere else.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from app.models import Appliance, MonitorProbe, MonitorSample, User, db
from app.services import service_rollup as sr
from tests.conftest import login


@pytest.fixture()
def admin_id(app):
    with app.app_context():
        u = User.query.filter_by(role="admin").first()
        if u is None:
            u = User(username="rollupadmin", role="admin", is_active=True)
            u.set_password("x" * 12)
            db.session.add(u)
            db.session.commit()
        return u.id


def _sample(probe_id, *, status="ok", v=None, v2=None, payload=None, age_min=1):
    return MonitorSample(
        probe_id=probe_id, status=status, ok=(status == "ok"),
        value_num=v, value2_num=v2, detail="synthetic",
        ts=datetime.utcnow() - timedelta(minutes=age_min),
        payload=json.dumps(payload or {}))


POLICY = {"name": "pol-x", "handle": 7, "status": "enable", "protocol": "HTTP",
          "vserver": "192.0.2.90/32", "port": "80", "sessions": 42,
          "conn_per_sec": 9, "client_rtt": 3, "server_rtt": 4,
          "app_response_time": 11}
MEMBERS = [{"pool": "pool-x", "server": "192.0.2.211", "port": 80,
            "health": "enable", "sessions": 21, "up": True, "server_rtt": 4,
            "app_response_time": 11},
           {"pool": "pool-x", "server": "192.0.2.212", "port": 80,
            "health": "disable", "sessions": 0, "up": False, "server_rtt": 0,
            "app_response_time": 0}]
STATS = {"samples": 60, "avg_bps": 42_000_000.0, "peak_bps": 90_000_000.0,
         "last_bps": 1.0, "avg_mbps": 336.0, "peak_mbps": 720.0,
         "last_mbps": 0.0}


@pytest.fixture()
def box(app):
    """One FortiWeb with a full REST-telemetry probe set and one policy."""
    with app.app_context():
        a = Appliance(name="fwroll", host="192.0.2.13", kind="fortiweb",
                      username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.flush()

        def probe(kind, target, enabled=True):
            p = MonitorProbe(appliance_id=a.id, kind=kind, target=target,
                             name="%s %s" % (kind, target or "box"),
                             enabled=enabled, interval_min=5)
            db.session.add(p)
            db.session.flush()
            return p

        sess_box = probe("sessions", "")
        total = probe("throughput", sr.dm.TOTAL_HTTP)
        pol = probe("policy_sessions", "pol-x")
        ptp = probe("throughput", "pol-x")
        db.session.add_all([
            _sample(sess_box.id, v=42, v2=9,
                    payload={"box": {"cpu_pct": 5, "mem_pct": 52,
                                     "sessions": 42, "conn_per_sec": 9}}),
            _sample(total.id, v=336.0, v2=720.0, payload={"stats": STATS,
                                                          "window_s": 60}),
            _sample(pol.id, v=42, v2=11,
                    payload={"policy": POLICY, "members": MEMBERS,
                             "members_error": ""}),
            _sample(ptp.id, v=336.0, v2=720.0, payload={"stats": STATS}),
        ])
        db.session.commit()
        return {"aid": a.id, "total": total.id, "pol": pol.id,
                "sessions": sess_box.id}


# --------------------------------------------------------------------------
# 1. absence is never a zero
# --------------------------------------------------------------------------

def test_missing_probe_reports_unknown_not_zero(app):
    with app.app_context():
        a = Appliance(name="bare", host="1.1.1.1", kind="fortiweb",
                      username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        row = sr.device_rollup([a])[0]
        tp = row["total_throughput"]
        assert tp["present"] is False
        assert tp["measured"] is False
        assert tp["status"] == "unknown"
        # The number must be absent, NOT 0.0 — that is the whole point.
        assert tp["avg_mbps"] is None
        assert row["coverage"]["measured"] == 0
        assert {g["why"] for g in row["coverage"]["gaps"]} == {"missing"}


def test_disabled_probe_is_not_a_passing_probe(app, box):
    with app.app_context():
        p = db.session.get(MonitorProbe, box["total"])
        p.enabled = False
        db.session.commit()
        a = db.session.get(Appliance, box["aid"])
        tp = sr.device_rollup([a])[0]["total_throughput"]
        assert tp["present"] is True          # the probe exists...
        assert tp["measured"] is False        # ...but it measured nothing
        assert tp["status"] == "unknown"
        assert tp["avg_mbps"] is None


def test_stale_sample_is_flagged(app, box):
    with app.app_context():
        s = (MonitorSample.query.filter_by(probe_id=box["total"])
             .order_by(MonitorSample.ts.desc()).first())
        s.ts = datetime.utcnow() - (sr.STALE_AFTER + timedelta(minutes=5))
        db.session.commit()
        a = db.session.get(Appliance, box["aid"])
        tp = sr.device_rollup([a])[0]["total_throughput"]
        assert tp["stale"] is True
        assert tp["measured"] is True         # stale is still a reading


def test_healthy_rollup_carries_the_numbers(app, box):
    with app.app_context():
        a = db.session.get(Appliance, box["aid"])
        row = sr.device_rollup([a])[0]
        assert row["total_throughput"]["avg_mbps"] == 336.0
        assert row["total_throughput"]["peak_mbps"] == 720.0
        assert row["box_metrics"]["cpu_pct"] == 5
        assert row["policy_count"] == 1
        pol = row["policies"][0]
        assert pol["sessions"] == 42 and pol["conn_per_sec"] == 9
        assert pol["backends_total"] == 2 and pol["backends_down"] == 1
        assert pol["throughput"]["avg_mbps"] == 336.0
        # transactions probe was never created for this policy
        assert pol["transactions"]["present"] is False


def test_non_fortiweb_devices_are_skipped_not_zeroed(app):
    """A FortiADC card would read as 'no traffic'; the API is FortiWeb-only."""
    with app.app_context():
        a = Appliance(name="adc", host="1.1.1.2", kind="fortiadc",
                      username="admin")
        a.password = "pw"
        db.session.add(a)
        db.session.commit()
        assert sr.device_rollup([a]) == []


# --------------------------------------------------------------------------
# 2. the views never contact the appliance
# --------------------------------------------------------------------------

def test_page_load_never_contacts_the_appliance(app, client, admin_id, box,
                                                monkeypatch):
    import app.clients.fortiweb as fw

    def boom(*_a, **_k):  # pragma: no cover - must never run
        raise AssertionError("a page load opened a connection to the device")

    monkeypatch.setattr(fw, "FortiWebClient", boom)
    login(client, admin_id, product="global")
    assert client.get('/monitoring/services/data').status_code == 200
    r = client.get('/monitoring/services/policy/%d?name=pol-x' % box["aid"])
    assert r.status_code == 200
    assert r.get_json()["policy"]["sessions"] == 42


# --------------------------------------------------------------------------
# 3. the rollup belongs to exactly one page
# --------------------------------------------------------------------------

def test_deep_monitors_does_not_emit_the_rollup(app, client, admin_id, box):
    login(client, admin_id, product="global")
    assert "device_rollup" in client.get('/monitoring/services/data').get_json()
    assert "device_rollup" not in client.get('/monitoring/deep/data').get_json()


def test_policy_endpoint_does_not_exist_on_deep_monitors(client, admin_id, box):
    login(client, admin_id, product="global")
    r = client.get('/monitoring/deep/policy/%d?name=pol-x' % box["aid"])
    assert r.status_code == 404


def test_only_the_rollup_page_renders_the_cards(client, admin_id):
    login(client, admin_id, product="global")
    svc = client.get('/monitoring/services/').get_data(as_text=True)
    deep = client.get('/monitoring/deep/').get_data(as_text=True)
    assert 'id="dpDevices"' in svc and 'id="dpPolModal"' in svc
    assert 'id="dpDevices"' not in deep and 'id="dpPolModal"' not in deep


# --------------------------------------------------------------------------
# 4. detail endpoint contract
# --------------------------------------------------------------------------

def test_unmonitored_policy_is_404_not_an_empty_shell(client, admin_id, box):
    login(client, admin_id, product="global")
    r = client.get('/monitoring/services/policy/%d?name=ghost' % box["aid"])
    assert r.status_code == 404


def test_policy_name_is_required(client, admin_id, box):
    login(client, admin_id, product="global")
    assert client.get('/monitoring/services/policy/%d'
                      % box["aid"]).status_code == 400


def test_policy_detail_shape(client, admin_id, box):
    login(client, admin_id, product="global")
    d = client.get('/monitoring/services/policy/%d?name=pol-x'
                   % box["aid"]).get_json()
    assert d["policy"]["client_rtt"] == 3
    assert len(d["members"]) == 2 and len(d["backends_down"]) == 1
    assert d["throughput"]["stats"]["peak_mbps"] == 720.0
    # the transactions probe is absent, and the view says so instead of 0
    assert d["transactions"]["present"] is False
    assert {g["what"] for g in d["coverage"]["gaps"]} == {"transactions"}


def test_policy_detail_is_adom_scoped(client, admin_id, box):
    login(client, admin_id, product="fortiadc")
    r = client.get('/monitoring/services/policy/%d?name=pol-x' % box["aid"])
    assert r.status_code == 403
