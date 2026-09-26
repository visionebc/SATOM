"""Guards for the Docker operations agent (deploy/docker/satom_agent.py).

The agent mounts the engine socket, so it is root on the host. What can go
wrong is never a crash: it is a request the agent should have refused and did
not. A compromised web worker can write ANY file into the request volume, so
every test below starts from "the web is hostile" and asserts what the agent
still refuses -- plus the structural facts (only the agent holds the socket,
nothing can reach it) that the refusal relies on.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import tarfile
import time
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
DOCKER_DIR = ROOT / "deploy" / "docker"
AGENT_PY = DOCKER_DIR / "satom_agent.py"
AGENT_YAML = DOCKER_DIR / "compose.agent.yaml"
INSTALLER = ROOT / "installers" / "satom-setup.sh"
WRAPPER = DOCKER_DIR / "satom-docker.sh"

UID = "20260926-201500-abc123"


def _load():
    spec = importlib.util.spec_from_file_location("_satom_agent_under_test", AGENT_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def ag():
    return _load()


def _req(**kw) -> bytes:
    body = {"id": UID, "requested_by": "admin", "node": "n1", "role": "primary",
            "origin": "test", "requested_at": "2026-09-26T20:15:00Z"}
    body.update(kw)
    return json.dumps(body).encode()


CERT = ("-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ0FGRQ==\n"
        "-----END CERTIFICATE-----\n")
KEY = ("-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgE=\n"
       "-----END PRIVATE KEY-----\n")


# ---------------------------------------------------------------------------
# The validator: what a hostile web can put in a request, and what comes out
# ---------------------------------------------------------------------------

def test_a_valid_restart_is_accepted(ag):
    kind, p = ag.validate_request(_req(kind="ctr-restart", service="scheduler",
                                       action="stop"), UID)
    assert kind == "ctr-restart"
    assert p == {"service": "scheduler", "action": "stop"}


def test_a_valid_update_is_accepted(ag):
    kind, p = ag.validate_request(_req(kind="ctr-update", version="2.3.0"), UID)
    assert (kind, p) == ("ctr-update", {"version": "2.3.0"})


def test_a_valid_certificate_is_accepted(ag):
    kind, p = ag.validate_request(_req(kind="ctr-cert", cert_pem=CERT, key_pem=KEY,
                                       chain_pem=CERT), UID)
    assert kind == "ctr-cert" and p["key_pem"] == KEY and p["chain_pem"] == CERT


def test_the_chain_is_optional(ag):
    _, p = ag.validate_request(_req(kind="ctr-cert", cert_pem=CERT, key_pem=KEY), UID)
    assert "chain_pem" not in p


@pytest.mark.parametrize("stem", ["", "promote-20260926-201500", "../x", UID + "x",
                                  "20260926-201500-ABC123"])
def test_a_file_name_that_is_not_a_request_id_is_refused(ag, stem):
    with pytest.raises(ag.Refused):
        ag.validate_request(_req(kind="ctr-update", version="2.3.0", id=stem), stem)


def test_the_id_must_match_the_file_name(ag):
    """Otherwise a request could report its outcome under another row."""
    with pytest.raises(ag.Refused, match="does not match"):
        ag.validate_request(_req(kind="ctr-update", version="2.3.0",
                                 id="20260926-201500-ffffff"), UID)


@pytest.mark.parametrize("raw", [b"not json", b"\xff\xfe", b"[1,2]", b"null", b'"x"'])
def test_garbage_is_refused(ag, raw):
    with pytest.raises(ag.Refused):
        ag.validate_request(raw, UID)


def test_an_oversized_request_is_refused(ag):
    raw = _req(kind="ctr-update", version="2.3.0", requested_by="x" * (ag.MAX_REQUEST_BYTES))
    with pytest.raises(ag.Refused, match="larger"):
        ag.validate_request(raw, UID)


@pytest.mark.parametrize("kind", [None, "", "service", "pip", "promote", "update",
                                  "ctr-exec", "CTR-RESTART", ["ctr-restart"]])
def test_every_kind_outside_the_closed_list_is_refused(ag, kind):
    """Host-runner kinds included: they have no container meaning."""
    body = _req(service="web", action="restart", version="2.3.0")
    d = json.loads(body)
    if kind is None:
        d.pop("kind", None)
    else:
        d["kind"] = kind
    with pytest.raises(ag.Refused, match="kind"):
        ag.validate_request(json.dumps(d).encode(), UID)


@pytest.mark.parametrize("extra", ["image", "command", "cmd", "args", "path", "file",
                                   "compose", "entrypoint", "volumes", "env"])
def test_an_unexpected_field_is_refused_not_ignored(ag, extra):
    """Ignoring an unknown key is how a future edit starts honouring it."""
    with pytest.raises(ag.Refused, match="unexpected"):
        ag.validate_request(_req(kind="ctr-restart", service="web", action="restart",
                                 **{extra: "x"}), UID)


@pytest.mark.parametrize("body", [
    {"kind": "ctr-restart", "service": "web"},
    {"kind": "ctr-restart", "action": "restart"},
    {"kind": "ctr-update"},
    {"kind": "ctr-cert", "cert_pem": CERT},
    {"kind": "ctr-cert", "key_pem": KEY},
])
def test_a_missing_field_is_refused(ag, body):
    with pytest.raises(ag.Refused, match="missing"):
        ag.validate_request(_req(**body), UID)


@pytest.mark.parametrize("body", [
    {"kind": "ctr-restart", "service": ["web"], "action": "restart"},
    {"kind": "ctr-restart", "service": "web", "action": 1},
    {"kind": "ctr-update", "version": 2.3},
    {"kind": "ctr-update", "version": "2.3.0", "requested_by": {"$ne": 1}},
])
def test_a_non_string_field_is_refused(ag, body):
    with pytest.raises(ag.Refused, match="string"):
        ag.validate_request(_req(**body), UID)


@pytest.mark.parametrize("service", ["agent", "tls-init"])
def test_the_agent_and_the_one_shot_job_are_never_controllable(ag, service):
    for action in ("start", "stop", "restart"):
        with pytest.raises(ag.Refused, match="never"):
            ag.validate_request(_req(kind="ctr-restart", service=service,
                                     action=action), UID)


@pytest.mark.parametrize("service", ["nginx", "satom.service", "../web", "web;id",
                                     "WEB", "web ", "satom-node", "", "docker"])
def test_a_service_outside_the_stack_is_refused(ag, service):
    with pytest.raises(ag.Refused):
        ag.validate_request(_req(kind="ctr-restart", service=service,
                                 action="restart"), UID)


def test_the_policy_matrix_is_exactly_what_is_accepted(ag):
    """Every (service, action) pair: accepted iff the table says so."""
    for service in list(ag.SERVICE_POLICY) + list(ag.FORBIDDEN_SERVICES):
        for action in ("start", "stop", "restart", "kill", "rm", ""):
            ok = action in ag.SERVICE_POLICY.get(service, ())
            if service in ag.FORBIDDEN_SERVICES:
                ok = False
            raw = _req(kind="ctr-restart", service=service, action=action)
            if ok:
                ag.validate_request(raw, UID)
            else:
                with pytest.raises(ag.Refused):
                    ag.validate_request(raw, UID)


@pytest.mark.parametrize("service", ["web", "proxy", "postgres"])
def test_nothing_that_removes_the_way_back_can_be_stopped(ag, service):
    """The console, its front and its database: a stop from the UI leaves
    recovery to a shell, and this page exists for the operator without one."""
    assert "stop" not in ag.SERVICE_POLICY[service]
    with pytest.raises(ag.Refused):
        ag.validate_request(_req(kind="ctr-restart", service=service, action="stop"), UID)


@pytest.mark.parametrize("version", ["2.3.0", "0.0.1", "10.20.300", "2.10.0"])
def test_release_versions_are_accepted(ag, version):
    ag.validate_request(_req(kind="ctr-update", version=version), UID)


@pytest.mark.parametrize("version", ["v2.3.0", "2.3", "2.3.0-rc1", "latest", "2.3.0 ",
                                     " 2.3.0", "../2.3.0", "02.3.0", "2.3.0\n",
                                     "2.3.0;id", "2.3.0/../../x", "99999.0.0", ""])
def test_anything_but_x_y_z_is_refused(ag, version):
    """The version becomes an image tag, a directory name and part of a URL."""
    with pytest.raises(ag.Refused):
        ag.validate_request(_req(kind="ctr-update", version=version), UID)


def test_a_private_key_in_the_certificate_slot_is_refused(ag):
    """It would be copied into public/server.crt and served to every client."""
    with pytest.raises(ag.Refused, match="private key"):
        ag.validate_request(_req(kind="ctr-cert", cert_pem=CERT + KEY, key_pem=KEY), UID)


def test_a_private_key_in_the_chain_slot_is_refused(ag):
    with pytest.raises(ag.Refused, match="private key"):
        ag.validate_request(_req(kind="ctr-cert", cert_pem=CERT, key_pem=KEY,
                                 chain_pem=KEY), UID)


def test_a_key_slot_without_a_key_is_refused(ag):
    with pytest.raises(ag.Refused, match="private key"):
        ag.validate_request(_req(kind="ctr-cert", cert_pem=CERT, key_pem=CERT), UID)


@pytest.mark.parametrize("pem", ["hello", "-----BEGIN CERTIFICATE-----\n$(id)\n-----END CERTIFICATE-----\n",
                                 CERT + "trailing garbage"])
def test_non_pem_is_refused(ag, pem):
    with pytest.raises(ag.Refused, match="not PEM"):
        ag.validate_request(_req(kind="ctr-cert", cert_pem=pem, key_pem=KEY), UID)


def test_an_oversized_pem_is_refused(ag):
    big = "-----BEGIN CERTIFICATE-----\n" + ("A" * 64 + "\n") * 600 + "-----END CERTIFICATE-----\n"
    with pytest.raises(ag.Refused):
        ag.validate_request(_req(kind="ctr-cert", cert_pem=big, key_pem=KEY), UID)


# ---------------------------------------------------------------------------
# Filesystem: the web owns the queue directories
# ---------------------------------------------------------------------------

def test_a_status_write_replaces_a_planted_symlink_instead_of_following_it(ag, tmp_path):
    """Following it as root would let the web overwrite any file the agent can
    reach -- the stack's env file with its secrets included."""
    victim = tmp_path / "victim"
    victim.write_text("SECRET_KEY=keep-me\n")
    target = tmp_path / "status.json"
    target.symlink_to(victim)
    ag.write_owned(target, b'{"state":"running"}')
    assert victim.read_text() == "SECRET_KEY=keep-me\n"
    assert not target.is_symlink()
    assert json.loads(target.read_text()) == {"state": "running"}


def test_a_request_that_is_a_symlink_is_not_read(ag, tmp_path):
    secret = tmp_path / "secret"
    secret.write_text(json.dumps({"kind": "ctr-update"}))
    link = tmp_path / (UID + ".json")
    link.symlink_to(secret)
    with pytest.raises(OSError):
        ag.read_request(link)


def test_a_request_that_is_not_a_regular_file_is_refused(ag, tmp_path):
    fifo = tmp_path / (UID + ".json")
    os.mkfifo(fifo)
    with pytest.raises(ag.Refused, match="regular"):
        ag.read_request(fifo)


def test_an_oversized_request_file_is_refused_while_reading(ag, tmp_path):
    p = tmp_path / (UID + ".json")
    p.write_bytes(b" " * (ag.MAX_REQUEST_BYTES + 10))
    with pytest.raises(ag.Refused, match="larger"):
        ag.read_request(p)


@pytest.fixture()
def queue(ag, tmp_path, monkeypatch):
    req, sta = tmp_path / "requests", tmp_path / "status"
    req.mkdir()
    sta.mkdir()
    monkeypatch.setattr(ag, "REQ_DIR", req)
    monkeypatch.setattr(ag, "STATUS_DIR", sta)
    monkeypatch.setattr(ag, "HEARTBEAT", sta / "agent.heartbeat")
    calls = []
    monkeypatch.setattr(ag, "do_restart", lambda st, s, a: calls.append(("restart", s, a)))
    monkeypatch.setattr(ag, "do_update", lambda st, v: calls.append(("update", v)))
    monkeypatch.setattr(ag, "do_cert", lambda st, p: calls.append(("cert", sorted(p))))
    return req, sta, calls


def _status(sta: Path) -> dict:
    return json.loads((sta / (UID + ".json")).read_text())


def test_a_valid_request_is_executed_consumed_and_reported(ag, queue):
    req, sta, calls = queue
    p = req / (UID + ".json")
    p.write_bytes(_req(kind="ctr-restart", service="cron", action="restart"))
    ag.handle(p)
    assert calls == [("restart", "cron", "restart")]
    assert not p.exists(), "a consumed request must not replay"
    assert _status(sta)["state"] == "success"
    assert _status(sta)["runner"] == "container-agent"


def test_a_refused_request_is_reported_and_nothing_runs(ag, queue):
    req, sta, calls = queue
    p = req / (UID + ".json")
    p.write_bytes(_req(kind="ctr-restart", service="agent", action="stop"))
    ag.handle(p)
    assert calls == []
    st = _status(sta)
    assert st["state"] == "failed" and "never" in st["error"]
    assert not p.exists()


def test_a_stale_request_is_refused_not_executed_late(ag, queue):
    """A restart queued while the agent was down must not fire hours later."""
    req, sta, calls = queue
    p = req / (UID + ".json")
    p.write_bytes(_req(kind="ctr-restart", service="cron", action="restart"))
    old = time.time() - ag.REQUEST_MAX_AGE - 5
    os.utime(p, (old, old))
    ag.handle(p)
    assert calls == []
    assert "expired" in _status(sta)["error"]


def test_a_certificate_request_is_deleted_even_when_refused(ag, queue):
    """It carries a private key; the volume is readable by the web."""
    req, sta, calls = queue
    p = req / (UID + ".json")
    p.write_bytes(_req(kind="ctr-cert", cert_pem="nope", key_pem=KEY))
    ag.handle(p)
    assert not p.exists()
    assert calls == []
    assert _status(sta)["state"] == "failed"
    assert "PRIVATE KEY" not in (sta / (UID + ".json")).read_text()


def test_the_status_row_never_carries_the_key(ag, queue):
    req, sta, calls = queue
    p = req / (UID + ".json")
    p.write_bytes(_req(kind="ctr-cert", cert_pem=CERT, key_pem=KEY))
    ag.handle(p)
    assert calls == [("cert", ["cert_pem", "key_pem"])]
    assert "PRIVATE KEY" not in (sta / (UID + ".json")).read_text()


class _St:
    def __init__(self):
        self.steps = []

    def step(self, name, ok=True, detail=""):
        self.steps.append((name, ok))

    def set(self, **kw):
        pass


def _cert_rig(ag, tmp_path, monkeypatch, nginx_rc):
    pub = tmp_path / "public"
    pub.mkdir()
    (pub / "server.crt").write_text("OLD CERT")
    (pub / "server.key").write_text("OLD KEY")
    monkeypatch.setattr(ag, "PKI_DIR", tmp_path)
    monkeypatch.setattr(ag, "service_containers",
                        lambda s: [{"Id": "p1", "Names": ["/satom-proxy-1"]}] if s == "proxy" else [])

    def fake_import(args, **kw):
        (pub / "server.crt").write_text("NEW CERT")
        (pub / "server.key").write_text("NEW KEY")
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    monkeypatch.setattr(ag.subprocess, "run", fake_import)
    monkeypatch.setattr(ag, "exec_in", lambda cid, argv, timeout=30: (nginx_rc, "nginx: test"))
    calls = []
    monkeypatch.setattr(ag, "api_json", lambda m, p, body=None, timeout=30, query=None, ok=None:
                        calls.append((m, p, query)))
    monkeypatch.setattr(ag, "do_restart", lambda *a: calls.append(("RESTART",) + a[1:]))
    return pub, calls


def test_a_certificate_is_applied_by_reload_never_by_restart(ag, tmp_path, monkeypatch):
    """The operator's request travels through the proxy; a restart cuts it and
    the console reports a failure for an import that worked (seen end to end)."""
    pub, calls = _cert_rig(ag, tmp_path, monkeypatch, nginx_rc=0)
    ag.do_cert(_St(), {"cert_pem": CERT, "key_pem": KEY})
    assert ("POST", "/containers/p1/kill", {"signal": "HUP"}) in calls
    assert not any(c[0] == "RESTART" for c in calls)
    assert (pub / "server.crt").read_text() == "NEW CERT"


def test_a_certificate_the_proxy_rejects_is_rolled_back(ag, tmp_path, monkeypatch):
    pub, calls = _cert_rig(ag, tmp_path, monkeypatch, nginx_rc=1)
    with pytest.raises(ag.DockerError, match="rejected"):
        ag.do_cert(_St(), {"cert_pem": CERT, "key_pem": KEY})
    assert (pub / "server.crt").read_text() == "OLD CERT"
    assert (pub / "server.key").read_text() == "OLD KEY"
    assert calls == [], "no reload of a configuration nginx refused"


def test_the_heartbeat_is_not_listed_as_an_update(ag):
    """The UI lists update-status/*.json as update history."""
    assert not ag.HEARTBEAT.name.endswith(".json")


def test_the_public_certificate_forwarder_refuses_key_material(ag, tmp_path, monkeypatch):
    pub = tmp_path / "public"
    pub.mkdir()
    (pub / "server.crt").write_text(CERT + KEY)
    monkeypatch.setattr(ag, "PKI_DIR", tmp_path)
    info = ag.cert_info()
    assert info["present"] is False and info["pem"] == ""
    (pub / "server.crt").write_text(CERT)
    assert ag.cert_info()["pem"] == CERT


# ---------------------------------------------------------------------------
# Update plumbing
# ---------------------------------------------------------------------------

def test_compose_files_follow_the_installer_wrapper(ag, tmp_path):
    home = tmp_path
    (home / "compose.setup.yaml").write_text("services: {}\n")
    d = home / "current" / "deploy" / "docker"
    d.mkdir(parents=True)
    (d / "compose.agent.yaml").write_text("services: {}\n")
    (home / "compose.setup-agent.yaml").write_text("services: {}\n")
    env = {"SATOM_ENV": "prod", "SATOM_NODE_ROLE": "standby", "SATOM_SETUP_AGENT": "yes"}
    files = [f for f in ag.compose_files(str(home), env) if f != "-f"]
    assert [Path(f).name for f in files] == [
        "compose.yaml", "compose.prod.yaml", "compose.standby.yaml",
        "compose.setup.yaml", "compose.agent.yaml", "compose.setup-agent.yaml"]
    # Without the agent answer the overlay is not layered: an update would
    # otherwise recreate web WITHOUT the queue volumes and cut its own agent off.
    files = [f for f in ag.compose_files(str(home), {"SATOM_ENV": "prod"}) if f != "-f"]
    assert [Path(f).name for f in files] == ["compose.yaml", "compose.prod.yaml",
                                             "compose.setup.yaml"]


def test_compose_argv_pins_the_project_and_the_env_file(ag, tmp_path):
    argv = ag.compose_argv(str(tmp_path), {}, "up", "-d")
    assert argv[:4] == ["docker", "compose", "-p", "satom"]
    assert argv[argv.index("--env-file") + 1] == str(tmp_path / "satom.env")
    assert argv[-2:] == ["up", "-d"]


def test_env_set_replaces_every_occurrence_once(ag):
    text = "A=1\nSATOM_IMAGE=satom:2.2.0\nB=2\nSATOM_IMAGE=satom:old\n"
    out = ag.env_set_text(text, "SATOM_IMAGE", "satom:2.3.0")
    assert out.count("SATOM_IMAGE=") == 1
    assert "SATOM_IMAGE=satom:2.3.0" in out and "A=1" in out and "B=2" in out
    assert ag.env_set_text("A=1\n", "SATOM_IMAGE", "satom:2.3.0").endswith("SATOM_IMAGE=satom:2.3.0\n")


def test_parse_env_strips_one_level_of_quotes(ag):
    env = ag.parse_env("SATOM_SERVED_NAMES='a b'\nX=\"y\"\n# c\nnot a line\n")
    assert env == {"SATOM_SERVED_NAMES": "a b", "X": "y"}


def test_invalid_networks_are_found_where_the_installer_looks(ag, tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "net.py").write_text('A = "192.0.2.0/8"\nB = "10.0.0.0/8"\n')
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "x.py").write_text('C = "192.0.2.0/8"\n')  # outside the scope
    bad = ag.bad_network_literals(tmp_path)
    assert bad == ["app/net.py:1: 192.0.2.0/8"]


def _tgz(tmp_path: Path, members: list[tuple[str, bytes | None, str | None]]) -> Path:
    p = tmp_path / "src.tar.gz"
    with tarfile.open(p, "w:gz") as tf:
        for name, data, link in members:
            ti = tarfile.TarInfo(name)
            if link is not None:
                ti.type = tarfile.SYMTYPE
                ti.linkname = link
                tf.addfile(ti)
            else:
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
    return p


def test_extraction_strips_the_top_directory(ag, tmp_path):
    tgz = _tgz(tmp_path, [("SATOM-2.3.0/Dockerfile", b"FROM x\n", None),
                          ("SATOM-2.3.0/deploy/docker/compose.yaml", b"services: {}\n", None)])
    dest = tmp_path / "out"
    dest.mkdir()
    ag.safe_extract(tgz, dest)
    assert (dest / "Dockerfile").read_text() == "FROM x\n"
    assert (dest / "deploy" / "docker" / "compose.yaml").is_file()


@pytest.mark.parametrize("member", [("SATOM-2.3.0/../../evil", b"x", None),
                                    ("SATOM-2.3.0/link", None, "/etc/passwd"),
                                    ("SATOM-2.3.0/up", None, "../../../etc")])
def test_extraction_refuses_to_leave_the_destination(ag, tmp_path, member):
    tgz = _tgz(tmp_path, [member])
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(ag.Refused):
        ag.safe_extract(tgz, dest)
    assert list(dest.iterdir()) == [], "nothing is extracted from a refused archive"


def test_update_needs_the_installer_layout(ag, monkeypatch):
    monkeypatch.setattr(ag, "HOME", "")
    st = type("S", (), {"set": lambda *a, **k: None, "step": lambda *a, **k: None})()
    with pytest.raises(ag.Refused, match="installer layout"):
        ag.do_update(st, "2.3.0")


def test_update_to_the_running_version_is_refused(ag, monkeypatch, tmp_path):
    (tmp_path / "satom.env").write_text("SATOM_IMAGE=satom:2.3.0\n")
    monkeypatch.setattr(ag, "HOME", str(tmp_path))
    st = type("S", (), {"set": lambda *a, **k: None, "step": lambda *a, **k: None})()
    with pytest.raises(ag.Refused, match="already runs"):
        ag.do_update(st, "2.3.0")


# ---------------------------------------------------------------------------
# Structure: who holds the socket, and who can reach the agent
# ---------------------------------------------------------------------------

class _AnyTagLoader(yaml.SafeLoader):
    pass


_AnyTagLoader.add_multi_constructor("!", lambda loader, suffix, node: None)


def _compose(path: Path) -> dict:
    return yaml.load(path.read_text(), Loader=_AnyTagLoader) or {}


def _volumes(svc: dict) -> list[str]:
    out = []
    for v in (svc or {}).get("volumes") or []:
        out.append(v if isinstance(v, str) else "%s:%s" % (v.get("source"), v.get("target")))
    return out


def test_only_the_agent_mounts_the_engine_socket_in_any_compose_file():
    seen = []
    for f in sorted(DOCKER_DIR.glob("compose*.yaml")):
        for name, svc in (_compose(f).get("services") or {}).items():
            if any("docker.sock" in v for v in _volumes(svc)):
                seen.append((f.name, name))
    assert seen == [("compose.agent.yaml", "agent")]


def test_the_installer_overlay_never_gives_the_socket_to_anyone():
    text = INSTALLER.read_text()
    start = text.index("write_setup_overlay() {")
    body = text[start:text.index("\n}\n", start)]
    assert "docker.sock" not in body


def test_the_agent_listens_on_nothing_and_is_not_on_the_stack_network():
    agent = _compose(AGENT_YAML)["services"]["agent"]
    assert "ports" not in agent and "expose" not in agent
    assert "network_mode" not in agent
    assert agent["networks"] == ["satom-agent"]
    assert "satom" not in agent["networks"]


def test_the_agent_is_confined_as_far_as_its_job_allows():
    agent = _compose(AGENT_YAML)["services"]["agent"]
    assert agent.get("privileged") is not True
    assert agent["cap_drop"] == ["ALL"]
    assert sorted(agent["cap_add"]) == ["CHOWN", "DAC_OVERRIDE", "FOWNER"]
    assert "no-new-privileges:true" in agent["security_opt"]
    assert agent["read_only"] is True
    assert agent["entrypoint"][-1] == "/opt/satom/deploy/docker/satom_agent.py"


@pytest.mark.parametrize("svc", ["web", "scheduler", "cron"])
def test_the_app_services_get_the_queue_and_the_declaration(svc):
    s = _compose(AGENT_YAML)["services"][svc]
    assert s["environment"]["SATOM_AGENT"] == "docker"
    assert "satom-agent-requests:/opt/satom/data/update-requests" in s["volumes"]
    assert "satom-agent-status:/opt/satom/data/update-status" in s["volumes"]
    assert not any("pki" in v for v in s["volumes"]), \
        "the app must not mount satom-pki: it holds the key and the internal CA"


def test_the_agent_queue_paths_match_the_app_side():
    ag = _load()
    agent = _compose(AGENT_YAML)["services"]["agent"]
    assert "satom-agent-requests:%s" % ag.REQ_DIR in agent["volumes"]
    assert "satom-agent-status:%s" % ag.STATUS_DIR in agent["volumes"]


def test_the_cli_image_is_the_same_in_the_installer_and_the_agent():
    ag = _load()
    assert 'AGENT_CLI_IMAGE="%s"' % ag.CLI_IMAGE in INSTALLER.read_text()


def test_both_wrappers_layer_the_agent_overlay_last():
    w = WRAPPER.read_text()
    assert w.index("compose.agent.yaml") > w.index("compose.standby.yaml")
    inst = INSTALLER.read_text()
    assert inst.index('f+=(-f "$D/compose.agent.yaml")') > inst.index('compose.setup.yaml")')


def test_the_agent_is_stdlib_only():
    """It is reviewed as a security boundary and runs as root; it must not
    import the app package out of a tree the app account can write."""
    import ast
    tree = ast.parse(AGENT_PY.read_text())
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            mods.add((node.module or "").split(".")[0])
    import sys
    stdlib = set(sys.stdlib_module_names) | {"__future__"}
    assert mods <= stdlib, mods - stdlib


def test_the_installer_overlay_never_defines_the_agent():
    """The agent's layout has its own overlay, layered only with
    compose.agent.yaml. In compose.setup.yaml it would leave a half `agent`
    service (no image) behind the moment the agent is disabled, and every
    compose command would fail until someone edited a generated file."""
    text = INSTALLER.read_text()
    start = text.index("write_setup_overlay() {")
    body = text[start:text.index("\n}\n", start)]
    main = body[:body.index('> "$DOCKER_HOME/compose.setup.yaml"')]
    assert '"  agent:"' not in main
    assert 'compose.setup-agent.yaml' in body
    assert 'rm -f "$DOCKER_HOME/compose.setup-agent.yaml"' in body


def test_the_installer_wrapper_layers_the_agent_layout_only_with_the_agent():
    text = INSTALLER.read_text()
    w = text[text.index("write_wrapper() {"):]
    w = w[:w.index("\nWRAP\n")]
    agent_if = w.index('if [ "${SATOM_SETUP_AGENT:-no}" = yes ]')
    assert w.index("compose.setup-agent.yaml") > agent_if
    assert w.index("compose.setup-agent.yaml") < w.index("\nfi", agent_if)


def test_a_release_without_the_agent_is_refused_before_anything_changes(ag, monkeypatch, tmp_path):
    rel = tmp_path / "releases" / "2.1.3"
    (rel / "deploy" / "docker").mkdir(parents=True)
    (rel / "Dockerfile").write_text("FROM x\n")
    (rel / "deploy" / "docker" / "compose.yaml").write_text("services: {}\n")
    env = tmp_path / "satom.env"
    env.write_text("SATOM_IMAGE=satom:2.3.0\n")
    monkeypatch.setattr(ag, "HOME", str(tmp_path))
    built = []
    monkeypatch.setattr(ag, "run_helper", lambda *a, **k: built.append(a) or (0, ""))
    monkeypatch.setattr(ag, "image_tags", lambda *a: [])
    st = type("S", (), {"set": lambda *a, **k: None, "step": lambda *a, **k: None})()
    with pytest.raises(ag.Refused, match="does not ship the operations agent"):
        ag.do_update(st, "2.1.3")
    assert built == [], "nothing is built or recreated for a refused release"
    assert env.read_text() == "SATOM_IMAGE=satom:2.3.0\n"


def test_only_the_build_helper_gets_a_network(ag, monkeypatch):
    """A compose run needs nothing but the socket; a BuildKit build needs the
    client to reach the registry for the pull token."""
    bodies = []
    monkeypatch.setattr(ag, "ensure_cli_image", lambda st=None: None)

    def fake_api_json(method, path, body=None, timeout=30, query=None, ok=None):
        if path == "/containers/create":
            bodies.append(body)
            return {"Id": "h1"}
        if path.endswith("/wait"):
            return {"StatusCode": 0}
        return None
    monkeypatch.setattr(ag, "api_json", fake_api_json)
    monkeypatch.setattr(ag, "api", lambda *a, **k: (200, b""))
    ag.run_helper(["docker", "compose", "up"], timeout=5)
    ag.run_helper(["docker", "build", "."], timeout=5, network="bridge")
    ag.run_helper(["docker", "build", "."], timeout=5, network="host")
    assert [b["HostConfig"]["NetworkMode"] for b in bodies] == ["none", "bridge", "none"]
    assert all("/var/run/docker.sock:/var/run/docker.sock" in b["HostConfig"]["Binds"] for b in bodies)
    assert not any(b["HostConfig"].get("Privileged") for b in bodies)


def test_an_update_reloads_the_proxy_before_trusting_web_health(ag, monkeypatch, tmp_path):
    """The proxy is not recreated by a switch; without a reload it keeps the
    old vhost (and, before 2.3.0, the old address of web: 502)."""
    rel = tmp_path / "releases" / "9.9.9"
    (rel / "deploy" / "docker").mkdir(parents=True)
    (rel / "Dockerfile").write_text("FROM x\n")
    for f in ("compose.yaml", "compose.agent.yaml"):
        (rel / "deploy" / "docker" / f).write_text("services: {}\n")
    (tmp_path / "releases" / "2.3.0").mkdir()
    os.symlink(str(tmp_path / "releases" / "2.3.0"), str(tmp_path / "current"))
    (tmp_path / "satom.env").write_text("SATOM_IMAGE=satom:2.3.0\n")
    monkeypatch.setattr(ag, "HOME", str(tmp_path))
    monkeypatch.setattr(ag, "image_tags", lambda *a: ["satom:9.9.9"])
    monkeypatch.setattr(ag, "run_helper", lambda argv, timeout, network="none": (0, "web\nproxy\n"))
    order = []
    monkeypatch.setattr(ag, "reload_proxy", lambda st: order.append("reload") or True)
    monkeypatch.setattr(ag, "wait_service", lambda *a, **k: order.append("wait") or (True, "healthy"))
    ag.do_update(_St(), "9.9.9")
    assert order == ["reload", "wait"]
    assert "SATOM_IMAGE=satom:9.9.9" in (tmp_path / "satom.env").read_text()


def test_the_heartbeat_is_refreshed_before_a_request_is_reported_done(ag, queue, monkeypatch):
    """The console answers from the heartbeat; a stale one described the
    state before the action (the import answered with the old certificate)."""
    req, sta, calls = queue
    order = []
    monkeypatch.setattr(ag, "write_heartbeat", lambda: order.append("heartbeat"))
    real_finish = ag.Status.finish
    monkeypatch.setattr(ag.Status, "finish", lambda self, state, **kw:
                        (order.append("finish:" + state), real_finish(self, state, **kw)))
    p = req / (UID + ".json")
    p.write_bytes(_req(kind="ctr-cert", cert_pem=CERT, key_pem=KEY))
    ag.handle(p)
    assert order == ["heartbeat", "finish:success"]
