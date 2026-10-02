"""Node TLS: CSR generation, key-less import, pasted PEM, and activation when
the host's sudo policy refuses /etc/sudoers.d/satom.

The sudo case is the one that shipped broken: an offline openSUSE install whose
managed sudoers did not apply the allowlist answered "Issue from internal CA"
with ``nginx -t failed: sudo: a password is required``. The certificate was
fine; the activation path depended on a host policy SATOM does not own. These
tests pin that a sudo REFUSAL goes to the root runner while a genuine nginx
config failure does NOT get retried anywhere.
"""
from __future__ import annotations

import io
import json
import stat
import subprocess
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.services import cert_service as cs
from app.services import self_update as su
from app.services import service_control as sc
from tests.conftest import admin_user_id, login


@pytest.fixture()
def csr_dir(tmp_path, monkeypatch):
    d = tmp_path / "csr"
    monkeypatch.setattr(cs, "CSR_DIR", d)
    return d


def _sign(csr_pem: str) -> bytes:
    """Play the external CA: sign the CSR with a throwaway CA."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    req = x509.load_pem_x509_csr(csr_pem.encode())
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(req.subject).issuer_name(ca_name)
            .public_key(req.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=90))
            .sign(ca_key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------------------
# CSR
# ---------------------------------------------------------------------------

def test_csr_carries_the_cn_and_every_san_and_keeps_the_key_private(app, csr_dir):
    with app.app_context():
        res = cs.generate_csr(by="t", common_name="satom.example.com",
                              sans="alt.example.com, 192.0.2.5\nsatom.example.com",
                              key_type="ec256", organization="Acme", country="ch")
    req = x509.load_pem_x509_csr(res["csr_pem"].encode())
    san = req.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["satom.example.com", "alt.example.com"]
    assert [str(i) for i in san.get_values_for_type(x509.IPAddress)] == ["192.0.2.5"]
    assert req.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "CH"
    key = csr_dir / (res["id"] + ".key")
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert stat.S_IMODE(csr_dir.stat().st_mode) == 0o700
    # The listing the page renders never contains key material.
    listed = cs.pending_csrs()
    assert [c["id"] for c in listed] == [res["id"]]
    assert "PRIVATE KEY" not in json.dumps(listed) and "PRIVATE KEY" not in json.dumps(res)


@pytest.mark.parametrize("kw, msg", [
    ({"common_name": "bad name!"}, "not a valid host name"),
    ({"sans": "ok.example.com, -bad-"}, "neither a host name"),
    ({"country": "CHE"}, "two-letter"),
    ({"key_type": "dsa1024"}, "key type"),
])
def test_csr_rejects_bad_input_before_writing_anything(app, csr_dir, kw, msg):
    args = dict(common_name="satom.example.com")
    args.update(kw)
    with app.app_context(), pytest.raises(ValueError, match=msg):
        cs.generate_csr(by="t", **args)
    assert not list(csr_dir.glob("*.key")) if csr_dir.exists() else True


def test_a_certificate_issued_from_the_csr_imports_without_a_key(app, csr_dir, monkeypatch):
    """The whole point of a CSR: the key never left, so the operator has none
    to paste. The certificate finds its key by public-key content, and a
    second CSR generated meanwhile does not orphan the first."""
    with app.app_context():
        first = cs.generate_csr(by="t", common_name="a.example.com")
        cs.generate_csr(by="t", common_name="b.example.com")
    installed = {}

    def fake_install(cert_pem, key_pem, chain_pem, source, by):
        cs.validate_pem(cert_pem, key_pem, chain_pem)    # key really matches
        installed.update(cert=cert_pem, key=key_pem, source=source)
        return {"subject": "ok"}
    monkeypatch.setattr(cs, "_install", fake_install)
    cert = _sign(first["csr_pem"])
    with app.app_context():
        cs.import_pem(b"\r\n  " + cert.replace(b"\n", b"\r\n") + b"  \r\n", None, None,
                      by="t", _log=False)
    assert b"PRIVATE KEY" in installed["key"] and installed["source"] == "imported"
    assert [c["common_name"] for c in cs.pending_csrs()] == ["b.example.com"]  # spent


def test_a_keyless_import_with_no_matching_csr_says_so(app, csr_dir, monkeypatch):
    monkeypatch.setattr(cs, "_install", lambda *a, **k: pytest.fail("must not install"))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256())).public_bytes(serialization.Encoding.PEM)
    with app.app_context(), pytest.raises(ValueError, match="no CSR generated on this node"):
        cs.import_pem(cert, b"", None, by="t", _log=False)


def test_discard_validates_the_id_and_removes_the_key(app, csr_dir):
    with app.app_context():
        res = cs.generate_csr(by="t", common_name="a.example.com")
    with pytest.raises(ValueError):
        cs.discard_csr("../../etc/passwd")
    assert cs.discard_csr(res["id"]) is True
    assert not (csr_dir / (res["id"] + ".key")).exists()
    assert cs.pending_csrs() == []


# ---------------------------------------------------------------------------
# activation when sudo refuses
# ---------------------------------------------------------------------------

def _proc(rc, err=""):
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout="", stderr=err)


@pytest.fixture()
def unprivileged(monkeypatch, tmp_path):
    monkeypatch.setattr(cs.os, "geteuid", lambda: 999)
    monkeypatch.setattr(su, "STATUS_DIR", tmp_path / "status")
    (tmp_path / "status").mkdir()
    calls = []

    def runner(final):
        def enqueue(unit, action, by, origin="x"):
            calls.append((unit, action))
            if final is not None:
                (tmp_path / "status" / "r1.json").write_text(json.dumps(final))
            return "r1"
        monkeypatch.setattr(sc, "request_service_action", enqueue)
    return calls, runner


@pytest.mark.parametrize("refusal", [
    "sudo: a password is required\n",
    "Sorry, user satom is not allowed to execute '/usr/sbin/nginx -t' as root on h.\n",
])
def test_a_sudo_refusal_activates_through_the_root_runner(monkeypatch, unprivileged, refusal):
    calls, runner = unprivileged
    runner({"state": "success", "steps": []})
    monkeypatch.setattr(cs.subprocess, "run", lambda *a, **k: _proc(1, refusal))
    cs._reload_nginx()
    assert calls == [("nginx.service", "reload")]


def test_no_sudo_binary_also_falls_back(monkeypatch, unprivileged):
    calls, runner = unprivileged
    runner({"state": "success", "steps": []})

    def boom(*a, **k):
        raise FileNotFoundError("sudo")
    monkeypatch.setattr(cs.subprocess, "run", boom)
    cs._reload_nginx()
    assert calls == [("nginx.service", "reload")]


def test_a_real_config_failure_is_reported_not_retried(monkeypatch, unprivileged):
    calls, runner = unprivileged
    runner({"state": "success", "steps": []})
    monkeypatch.setattr(cs.subprocess, "run", lambda *a, **k: _proc(
        1, "nginx: [emerg] cannot load certificate \"/opt/satom/pki/public/server.crt\"\n"))
    with pytest.raises(RuntimeError, match="nginx -t failed: nginx: \\[emerg\\]"):
        cs._reload_nginx()
    assert calls == []


def test_the_runner_verdict_on_nginx_t_is_surfaced(monkeypatch, unprivileged):
    calls, runner = unprivileged
    runner({"state": "failed", "steps": [
        {"name": "validate", "ok": True},
        {"name": "nginx -t", "ok": False, "detail": "nginx: [emerg] bad key"}]})
    monkeypatch.setattr(cs.subprocess, "run", lambda *a, **k: _proc(1, "sudo: a password is required"))
    with pytest.raises(RuntimeError, match="nginx -t failed: nginx: \\[emerg\\] bad key"):
        cs._reload_nginx()


def test_a_runner_that_never_answers_names_the_path_unit(monkeypatch, unprivileged):
    calls, runner = unprivileged
    runner(None)                                   # stays queued forever
    monkeypatch.setattr(cs, "RUNNER_WAIT_SECONDS", 0.01)
    monkeypatch.setattr(cs.time, "sleep", lambda s: None)
    monkeypatch.setattr(cs.subprocess, "run", lambda *a, **k: _proc(1, "sudo: a password is required"))
    with pytest.raises(RuntimeError, match="satom-updater.path"):
        cs._reload_via_runner(refusal="a password is required", wait=0.01)


# ---------------------------------------------------------------------------
# the route: pasted PEM, files, never both
# ---------------------------------------------------------------------------

def _wait_job(client, jid, timeout=10.0):
    import time
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        j = client.get("/jobs/%s" % jid).get_json()
        if j.get("status") in ("success", "error", "cancelled"):
            return j
        time.sleep(0.05)
    pytest.fail("job %s never finished" % jid)


def test_import_route_accepts_pasted_pem_and_an_empty_key(app, client, monkeypatch):
    seen = {}

    def fake(cert, key, chain, by):
        seen.update(cert=cert, key=key, chain=chain)
        return {"subject": "CN=x"}
    monkeypatch.setattr(cs, "import_pem", fake)
    login(client, admin_user_id(app))
    r = client.post("/settings/node-cert/import", data={
        "cert_text": "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----",
        "key_text": "", "chain_text": ""})
    assert r.status_code == 202 and r.get_json()["ok"] is True
    j = _wait_job(client, r.get_json()["job_id"])
    assert j["status"] == "success" and j["result"]["cert"]["subject"] == "CN=x"
    assert seen["cert"].startswith(b"-----BEGIN CERTIFICATE-----")
    assert seen["key"] is None and seen["chain"] is None


# ---------------------------------------------------------------------------
# activation progress: the page follows a job, step by step
# ---------------------------------------------------------------------------

def test_activation_steps_reach_the_job_the_page_follows(app, client, monkeypatch):
    def fake(cert, key, chain, by):
        cs._step("validate", cs.L_VALIDATE, "ok", "CN=x")
        cs._step("nginx_test", cs.L_TEST, "running")
        cs._step("nginx_test", cs.L_TEST, "ok")
        cs._step("reload", cs.L_RELOAD, "ok")
        cs._step("verify", "Check", "warn", "nginx still presents the previous certificate")
        return {"subject": "CN=x"}
    monkeypatch.setattr(cs, "import_pem", fake)
    login(client, admin_user_id(app))
    r = client.post("/settings/node-cert/import", data={"cert_text": "-----BEGIN CERTIFICATE-----"})
    j = _wait_job(client, r.get_json()["job_id"])
    steps = {s["key"]: s for s in j["meta"]["steps"]}
    # one row per step, updated in place — "running" became "ok", not a second row
    assert [s["key"] for s in j["meta"]["steps"]] == ["validate", "nginx_test", "reload", "verify"]
    assert steps["nginx_test"]["state"] == "ok" and steps["verify"]["state"] == "warn"
    assert j["status"] == "success" and j["by"]


def test_a_failed_activation_ends_the_job_red_with_the_reason(app, client, monkeypatch):
    def fake(cert, key, chain, by):
        cs._step("nginx_test", cs.L_TEST, "failed", "emerg: bad")
        raise RuntimeError("nginx -t failed: emerg: bad")
    monkeypatch.setattr(cs, "import_pem", fake)
    login(client, admin_user_id(app))
    r = client.post("/settings/node-cert/import", data={"cert_text": "-----BEGIN CERTIFICATE-----"})
    j = _wait_job(client, r.get_json()["job_id"])
    assert j["status"] == "error" and "nginx -t failed" in j["error"]
    assert j["meta"]["steps"][0]["state"] == "failed"


def test_issue_without_the_ca_key_is_refused_before_any_job(app, client, monkeypatch):
    monkeypatch.setattr(cs, "can_issue_internal", lambda: False)
    monkeypatch.setattr(cs, "issue_internal", lambda **k: pytest.fail("must not issue"))
    login(client, admin_user_id(app))
    r = client.post("/settings/node-cert/issue")
    assert r.status_code == 400 and "job_id" not in r.get_json()


def test_reload_reports_its_steps_only_to_a_sink(monkeypatch):
    monkeypatch.setattr(cs.subprocess, "run", lambda *a, **k: _proc(0))
    cs._reload_nginx()            # no sink: a silent no-op, as for the nightly timer
    seen = []
    with cs.progress_sink(lambda *a: seen.append(a[:3])):
        cs._reload_nginx()
    assert seen == [("nginx_test", cs.L_TEST, "running"), ("nginx_test", cs.L_TEST, "ok"),
                    ("reload", cs.L_RELOAD, "running"), ("reload", cs.L_RELOAD, "ok")]


def test_a_runner_activation_reports_the_handover(monkeypatch, unprivileged):
    calls, runner = unprivileged
    runner({"state": "success", "steps": []})
    monkeypatch.setattr(cs.subprocess, "run", lambda *a, **k: _proc(1, "sudo: a password is required"))
    seen = []
    with cs.progress_sink(lambda *a: seen.append(a)):
        cs._reload_nginx()
    assert any("handed to the root runner" in s[3] for s in seen)
    assert seen[-1][:3] == ("reload", cs.L_RELOAD, "ok") and "root runner" in seen[-1][3]


def test_verify_served_compares_the_served_leaf(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "n")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    monkeypatch.setattr(cs, "_served_der", lambda: cert.public_bytes(serialization.Encoding.DER))
    assert cs.verify_served(pem, wait=0)[0] is True
    monkeypatch.setattr(cs, "_served_der", lambda: b"other")
    ok, why = cs.verify_served(pem, wait=0)
    assert ok is False and "previous certificate" in why


def test_import_route_refuses_a_slot_given_twice(app, client, monkeypatch):
    monkeypatch.setattr(cs, "import_pem", lambda *a, **k: pytest.fail("must not import"))
    login(client, admin_user_id(app))
    r = client.post("/settings/node-cert/import", content_type="multipart/form-data", data={
        "cert": (io.BytesIO(b"-----BEGIN CERTIFICATE-----"), "c.pem"),
        "cert_text": "-----BEGIN CERTIFICATE-----"})
    assert r.status_code == 400 and "both as a file and as pasted text" in r.get_json()["error"]


def test_settings_page_renders_the_csr_card_and_paste_mode(app, client):
    login(client, admin_user_id(app))
    html = client.get("/settings/").get_data(as_text=True)
    for mark in ('id="nt-csr-form"', 'name="cert_text"', 'name="key_text"',
                 'id="nt-mode-file"', "/settings/node-cert/csr/CSRID/discard",
                 'id="nt-activate"', "close every browser window", "/jobs/JOBID"):
        assert mark in html, mark
