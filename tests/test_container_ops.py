"""Guards for the web half of the Docker operations agent.

Three things must hold, and each one fails silently when it breaks:

* the web only ever writes requests the AGENT accepts -- so every enqueue here
  is fed through the agent's own validator, not a copy of it;
* a capability is delegated only while the agent is declared AND alive -- a
  dead agent must turn the button back into a refusal, not into a request
  that sits "queued" forever;
* the privileged work never happens in the web process: no Docker, no
  satom-pki, no nginx.
"""
from __future__ import annotations

import datetime as dt
import importlib.util
import json
import time
from pathlib import Path

import pytest

from tests.conftest import admin_user_id, login

ROOT = Path(__file__).resolve().parents[1]
AGENT_PY = ROOT / "deploy" / "docker" / "satom_agent.py"


def _agent():
    spec = importlib.util.spec_from_file_location("_satom_agent_for_ops", AGENT_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _pem_pair():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "satom.test")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=90))
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("SATOM_RUNTIME", raising=False)
    monkeypatch.delenv("SATOM_AGENT", raising=False)


@pytest.fixture()
def queue(tmp_path, monkeypatch):
    from app import runtime
    from app.services import self_update as su
    req, sta = tmp_path / "update-requests", tmp_path / "update-status"
    req.mkdir()
    sta.mkdir()
    monkeypatch.setattr(su, "REQ_DIR", req)
    monkeypatch.setattr(su, "STATUS_DIR", sta)
    monkeypatch.setattr(runtime, "AGENT_HEARTBEAT", sta / "agent.heartbeat")
    return req, sta


def _beat(sta: Path, age: float = 0.0, **doc):
    body = {"ts": time.time() - age, "agent_version": "2.3.0", "layout": "installer",
            "containers": [
                {"service": "web", "name": "satom-node", "state": "running",
                 "health": "healthy", "image": "satom:2.3.0"},
                {"service": "scheduler", "name": "satom-scheduler-1", "state": "exited",
                 "health": "", "image": "satom:2.3.0"},
                {"service": "proxy", "name": "satom-proxy-1", "state": "running",
                 "health": "unhealthy", "image": "nginx:1.27-alpine"}],
            "versions": {"2.3.0": {"image": True, "tree": True},
                         "2.2.0": {"image": True, "tree": True}},
            "configured_image": "satom:2.3.0"}
    body.update(doc)
    (sta / "agent.heartbeat").write_text(json.dumps(body))


@pytest.fixture()
def live(queue, monkeypatch):
    monkeypatch.setenv("SATOM_RUNTIME", "container")
    monkeypatch.setenv("SATOM_AGENT", "docker")
    _beat(queue[1])
    return queue


def _only_request(req: Path) -> tuple[bytes, str]:
    files = sorted(req.glob("*.json"))
    assert len(files) == 1, files
    return files[0].read_bytes(), files[0].name[:-5]


# ---------------------------------------------------------------------------
# The two copies of the allowlist
# ---------------------------------------------------------------------------

def test_web_and_agent_allowlists_are_identical():
    from app.services import container_ops as co
    ag = _agent()
    assert {s: tuple(e["actions"]) for s, e in co.POLICY.items()} == ag.SERVICE_POLICY
    assert tuple(co.FORBIDDEN) == tuple(ag.FORBIDDEN_SERVICES)
    assert co.VERSION_RE.pattern == ag.VERSION_RE.pattern


# ---------------------------------------------------------------------------
# Delegation: declared AND alive
# ---------------------------------------------------------------------------

def test_a_live_agent_delegates_exactly_the_four(live):
    from app import runtime
    for name in runtime.AGENT_DELEGABLE:
        assert runtime.capability(name) is True, name
        assert runtime.delegated(name) is True, name
    assert runtime.capability("ha_promote") is False


def test_promotion_is_never_delegated(live):
    from app import runtime
    assert "ha_promote" in runtime.HOST_ONLY_CAPABILITIES
    assert "ha_promote" not in runtime.AGENT_DELEGABLE
    with pytest.raises(runtime.CapabilityUnavailable):
        runtime.require("ha_promote")


def test_a_silent_agent_is_treated_as_absent_and_says_so(live):
    from app import runtime
    _beat(live[1], age=runtime.AGENT_MAX_SILENCE + 5)
    for name in runtime.AGENT_DELEGABLE:
        assert runtime.capability(name) is False, name
        assert "not answering" in runtime.unavailable_reason(name)


def test_a_heartbeat_from_the_future_is_not_proof_of_life(live):
    from app import runtime
    _beat(live[1], age=-(runtime.AGENT_MAX_SILENCE + 5))
    assert runtime.agent_live() is False


def test_a_missing_or_broken_heartbeat_is_not_life(live):
    from app import runtime
    (live[1] / "agent.heartbeat").unlink()
    assert runtime.agent_live() is False
    (live[1] / "agent.heartbeat").write_text("{not json")
    assert runtime.agent_live() is False


def test_a_heartbeat_without_the_declaration_delegates_nothing(queue, monkeypatch):
    """A file in a volume is not a declaration: the compose overlay is."""
    from app import runtime
    monkeypatch.setenv("SATOM_RUNTIME", "container")
    _beat(queue[1])
    for name in runtime.AGENT_DELEGABLE:
        assert runtime.capability(name) is False


def test_the_declaration_means_nothing_on_a_host(queue, monkeypatch):
    from app import runtime
    monkeypatch.setenv("SATOM_AGENT", "docker")
    _beat(queue[1])
    assert runtime.agent_declared() is False
    assert all(runtime.capability(n) for n in runtime.HOST_ONLY_CAPABILITIES)
    assert not any(runtime.delegated(n) for n in runtime.AGENT_DELEGABLE)


def test_the_summary_reports_the_agent(live):
    from app import runtime
    s = runtime.summary()
    assert s["agent"]["live"] is True and s["agent"]["version"] == "2.3.0"
    assert s["delegated"] == {n: True for n in runtime.AGENT_DELEGABLE}


# ---------------------------------------------------------------------------
# What the web writes, the agent accepts (its own validator, not a copy)
# ---------------------------------------------------------------------------

def test_a_restart_request_round_trips_through_the_agent_validator(app, live):
    from app.services import container_ops as co
    with app.app_context():
        uid = co.request_restart("scheduler", "start", by="admin")
    raw, stem = _only_request(live[0])
    assert stem == uid
    assert _agent().validate_request(raw, stem) == (
        "ctr-restart", {"service": "scheduler", "action": "start"})
    row = json.loads((live[1] / (uid + ".json")).read_text())
    assert row["state"] == "queued" and row["runner"] == "container-agent"


def test_an_update_request_round_trips(app, live):
    from app.services import container_ops as co
    with app.app_context():
        co.request_update("v2.3.1", by="admin")
    raw, stem = _only_request(live[0])
    assert _agent().validate_request(raw, stem) == ("ctr-update", {"version": "2.3.1"})


def test_a_certificate_request_round_trips_and_the_row_has_no_key(app, live):
    from app.services import container_ops as co
    crt, key = _pem_pair()
    with app.app_context():
        uid = co.request_cert(crt, key, None, by="admin")
    raw, stem = _only_request(live[0])
    kind, params = _agent().validate_request(raw, stem)
    assert kind == "ctr-cert" and params["key_pem"] == key.decode()
    assert "PRIVATE KEY" not in (live[1] / (uid + ".json")).read_text()


@pytest.mark.parametrize("service,action", [("web", "stop"), ("agent", "restart"),
                                            ("tls-init", "restart"), ("nginx", "restart"),
                                            ("web", "kill")])
def test_the_web_refuses_what_the_agent_would_refuse(app, live, service, action):
    from app.services import container_ops as co
    with app.app_context(), pytest.raises(ValueError):
        co.request_restart(service, action, by="admin")
    assert list(live[0].glob("*.json")) == []


def test_nothing_is_queued_without_a_live_agent(app, live):
    from app import runtime
    from app.services import container_ops as co
    _beat(live[1], age=runtime.AGENT_MAX_SILENCE + 5)
    with app.app_context():
        for call in (lambda: co.request_restart("web", "restart", by="a"),
                     lambda: co.request_update("2.3.1", by="a"),
                     lambda: co.request_cert(b"x", b"y", None, by="a")):
            with pytest.raises(co.AgentUnavailable):
                call()
    assert list(live[0].glob("*")) == []


# ---------------------------------------------------------------------------
# The enforcement points take the agent branch -- and only with a live agent
# ---------------------------------------------------------------------------

def test_service_control_routes_to_the_agent(app, live):
    from app.services import service_control as sc
    with app.app_context():
        sc.request_service_action("cron", "restart", by="admin")
    raw, stem = _only_request(live[0])
    assert json.loads(raw)["kind"] == "ctr-restart"


def test_service_control_rows_are_the_containers(live):
    from app.services import service_control as sc
    rows = {r["unit"]: r for r in sc.states()}
    assert rows["web"]["ok"] is True and rows["web"]["available"] == ["restart"]
    assert rows["scheduler"]["ok"] is False and rows["scheduler"]["available"] == ["start"]
    assert rows["proxy"]["ok"] is False, "unhealthy is not ok"
    assert rows["cron"]["installed"] is False and rows["cron"]["available"] == []


def test_service_control_draws_nothing_in_a_container_without_an_agent(queue, monkeypatch):
    from app.services import service_control as sc
    monkeypatch.setenv("SATOM_RUNTIME", "container")
    assert sc.states() == []


def test_unit_health_reports_the_containers(live):
    from app.services import system_health as sh
    rows = {r["unit"]: r for r in sh.service_status()}
    assert rows["web (container)"]["ok"] is True
    assert rows["proxy (container)"]["ok"] is False
    assert rows["scheduler (container)"]["state"] == "exited"


def test_certificate_activation_goes_to_the_agent_and_writes_nothing_here(app, live, monkeypatch):
    from app.services import cert_service as cs
    from app.services import container_ops as co
    seen = {}
    monkeypatch.setattr(co, "install_cert", lambda c, k, ch, by: seen.update(by=by) or {})
    monkeypatch.setattr(cs, "PUB", Path("/nonexistent/should-not-be-touched"))
    crt, key = _pem_pair()
    with app.app_context():
        cs._install(crt, key, None, source="imported", by="admin")
    assert seen == {"by": "admin"}


def test_an_agent_refusal_reaches_the_certificate_caller(app, live, monkeypatch):
    from app.services import container_ops as co
    monkeypatch.setattr(co, "wait", lambda uid, t: {"state": "failed", "error": "mismatch"})
    crt, key = _pem_pair()
    with app.app_context(), pytest.raises(RuntimeError, match="mismatch"):
        co.install_cert(crt, key, None, by="admin")


def test_the_served_certificate_comes_from_the_heartbeat(app, live):
    from app.services import cert_service as cs
    crt, _ = _pem_pair()
    _beat(live[1], cert={"present": True, "pem": crt.decode(), "source": "imported"})
    with app.app_context():
        info = cs.current()
    assert info["present"] is True and "satom.test" in info["subject"]
    assert info["source"] == "imported" and info["can_issue_internal"] is False


def test_the_git_updater_still_refuses_and_points_to_the_image_update(app, live):
    from app import runtime
    from app.services import self_update as su
    with app.app_context():
        with pytest.raises(runtime.CapabilityUnavailable, match="Container operations"):
            su.request_update("origin/main", by="admin")
        with pytest.raises(runtime.CapabilityUnavailable, match="Container operations"):
            su.request_pip_change("requests", "2.0.0", by="admin")
    assert list(live[0].glob("*")) == []


def test_promotion_is_refused_in_a_container_even_with_the_agent(app, live, monkeypatch):
    from app import runtime
    from app.services import cluster
    monkeypatch.setattr(cluster, "REQ_DIR", live[0])
    with app.app_context(), pytest.raises(runtime.CapabilityUnavailable):
        cluster.request_promote(by="admin")
    assert list(live[0].glob("*")) == []


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------

def test_the_page_renders_the_agent_and_the_stack(app, client, live):
    # product=None: the global sidebar, where Software Update lives too.
    login(client, admin_user_id(app), product=None)
    r = client.get("/system/container/")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "Operations agent" in html
    assert 'data-co-service="web" data-co-action="restart"' in html
    assert 'data-co-service="scheduler" data-co-action="start"' in html
    assert "2.2.0" in html
    assert 'href="/system/container/"' in html, "the nav entry shows in a container"


def test_the_page_says_so_on_a_host_and_the_nav_hides_it(app, client, queue):
    login(client, admin_user_id(app), product=None)
    html = client.get("/system/container/").get_data(as_text=True)
    assert "This node is a host install" in html
    assert 'href="/self-update/"' in html, "the sidebar under test is the global one"
    assert 'href="/system/container/"' not in html


def test_the_page_explains_a_silent_agent(app, client, live):
    from app import runtime
    _beat(live[1], age=runtime.AGENT_MAX_SILENCE + 30)
    login(client, admin_user_id(app))
    html = client.get("/system/container/").get_data(as_text=True)
    assert "not answering" in html
    assert 'data-co-service="' not in html


def test_a_restart_from_the_page_is_queued(app, client, live):
    login(client, admin_user_id(app))
    r = client.post("/system/container/service", json={"service": "cron", "action": "start"})
    assert r.status_code == 200, r.get_data(as_text=True)
    raw, stem = _only_request(live[0])
    assert stem == r.get_json()["uid"]


def test_the_page_refuses_with_a_silent_agent(app, client, live):
    from app import runtime
    _beat(live[1], age=runtime.AGENT_MAX_SILENCE + 5)
    login(client, admin_user_id(app))
    r = client.post("/system/container/service", json={"service": "cron", "action": "start"})
    assert r.status_code == 409
    assert list(live[0].glob("*")) == []


def test_an_update_needs_the_typed_confirmation(app, client, live):
    login(client, admin_user_id(app))
    assert client.post("/system/container/update", json={"version": "2.3.1"}).status_code == 400
    assert list(live[0].glob("*")) == []
    r = client.post("/system/container/update", json={"version": "2.3.1", "confirm": "UPDATE"})
    assert r.status_code == 200
    assert json.loads(_only_request(live[0])[0])["version"] == "2.3.1"


def test_the_page_is_admin_only(app, client, live):
    from tests.conftest import make_user
    uid = make_user(app, "viewer", role="readonly")
    login(client, uid)
    r = client.post("/system/container/service", json={"service": "cron", "action": "start"})
    assert r.status_code in (302, 403)
    assert list(live[0].glob("*")) == []


def test_the_services_card_explains_an_empty_container_table(app, client, queue, monkeypatch):
    monkeypatch.setenv("SATOM_RUNTIME", "container")
    login(client, admin_user_id(app))
    j = client.get("/settings/services").get_json()
    assert j["units"] == [] and "operations agent" in j["note"]
