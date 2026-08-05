"""The TLS trust store: what SATOM believes when it dials an appliance.

Before this existed ``Appliance.verify_ssl`` had two settings — validate against
the PUBLIC root store (which no privately-signed appliance can satisfy) or
validate nothing. Everyone chose nothing, which is why "set verify_ssl=false"
is the recurring fix in this project's history (fadc 2026-07-12, fortiweb08
2026-07-28, fac01 2026-08-05).

The properties below are the ones that make the feature safe rather than merely
present. Two of them are about FAILURE, because that is where a trust store
does damage: a bundle missing the public roots breaks the devices that were
already verifiable, and a bundle that cannot be built must not quietly become
"verify nothing" — nobody would ever see that happen.
"""
from __future__ import annotations

import datetime
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.extensions import db
from app.models_trust import ROLE_INTERMEDIATE, ROLE_ROOT, TrustedCa
from app.services import trust_store as ts

_NOW = datetime.datetime.now(datetime.timezone.utc)


def _mk(cn, issuer=None, ikey=None, ca=True, sans=None, days=90):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    b = (x509.CertificateBuilder()
         .subject_name(subject)
         .issuer_name(issuer.subject if issuer is not None else subject)
         .public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(_NOW - datetime.timedelta(days=1))
         .not_valid_after(_NOW + datetime.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None),
                        critical=True))
    if sans:
        b = b.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False)
    return b.sign(ikey or key, hashes.SHA256()), key


def _pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture()
def pki():
    root, rk = _mk("Guard Root CA")
    inter, ik = _mk("Guard Issuing CA", root, rk)
    leaf, lk = _mk("appliance.guard.test", inter, ik, ca=False,
                   sans=["appliance.guard.test", "localhost"])
    return {"root": root, "inter": inter, "leaf": leaf, "leaf_key": lk}


@pytest.fixture()
def clean(app):
    with app.app_context():
        TrustedCa.query.delete()
        db.session.commit()
        ts.invalidate()
        yield
        TrustedCa.query.delete()
        db.session.commit()
        ts.invalidate()


# --------------------------------------------------------------------------
# the test suite must not touch a live installation's bundle
# --------------------------------------------------------------------------

def test_the_bundle_is_written_under_the_redirected_dir(app, clean, pki, tmp_path):
    """conftest points SATOM_TRUST_DIR at a tmpdir. Without it a test run
    rewrites the real pki/trust bundle that the client layer feeds to
    OpenSSL — exactly how pytest filled the job ledger with ghosts."""
    import os
    assert os.environ.get("SATOM_TRUST_DIR"), "conftest must redirect the trust dir"
    with app.app_context():
        ts.import_pem(_pem(pki["root"]), actor="t")
        path = ts.build_bundle()
    assert str(path).startswith(os.environ["SATOM_TRUST_DIR"]), path
    assert "/opt/satom/pki/trust" not in str(path)


# --------------------------------------------------------------------------
# 1. the bundle ADDS to the public roots, it does not replace them
# --------------------------------------------------------------------------

def test_bundle_keeps_the_public_roots(app, clean, pki):
    """A fleet is mixed: some appliances present the company CA, some present
    the public wildcard the edge renews. Shipping only the private CAs would
    break verification for exactly the devices that already worked."""
    import certifi
    public_count = certifi.contents().count("BEGIN CERTIFICATE")
    with app.app_context():
        ts.import_pem(_pem(pki["root"]) + _pem(pki["inter"]), actor="t")
        text = ts.build_bundle().read_text()
    assert text.count("BEGIN CERTIFICATE") == public_count + 2
    assert public_count > 50, "sanity: certifi should carry many roots"


# --------------------------------------------------------------------------
# 2. a broken store degrades to public roots — NEVER to "no verification"
# --------------------------------------------------------------------------

def test_verify_param_never_returns_false(app, clean, pki, monkeypatch):
    with app.app_context():
        assert ts.verify_param() is True          # empty store

        ts.import_pem(_pem(pki["root"]), actor="t")
        assert isinstance(ts.verify_param(), str)  # private bundle live

        ts.invalidate()
        monkeypatch.setattr(ts, "build_bundle",
                            lambda: (_ for _ in ()).throw(OSError("disk full")))
        got = ts.verify_param()
    assert got is True, (
        "a trust store that cannot be built must fall back to the PUBLIC roots. "
        "Returning False would silently disable TLS verification fleet-wide and "
        "print nothing.")
    assert got is not False


def test_client_never_upgrades_an_operator_optout(app, clean, pki):
    """verify_ssl=False is a decision, not a bug to correct."""
    from app.clients.base import BaseClient
    with app.app_context():
        ts.import_pem(_pem(pki["root"]), actor="t")
        assert BaseClient("h", 443, verify_ssl=False)._verify_target() is False
        assert isinstance(
            BaseClient("h", 443, verify_ssl=True)._verify_target(), str)


def test_request_actually_hands_the_bundle_to_httpx(app, clean, pki, monkeypatch):
    """Resolving the bundle is worthless if the request path still passes the
    raw boolean. Without this, reverting one line in ``_request`` leaves every
    other test in this file green while no device is verified against the
    store at all."""
    import httpx
    from app.clients.base import BaseClient
    seen = {}

    class _FakeClient:
        def __init__(self, **kw):
            seen.update(kw)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def request(self, *a, **kw):
            return "resp"

    monkeypatch.setattr(httpx, "Client", _FakeClient)
    with app.app_context():
        ts.import_pem(_pem(pki["root"]), actor="t")
        BaseClient("dev.example.invalid", 443, verify_ssl=True)._request("GET", "/x")
        assert isinstance(seen.get("verify"), str), (
            f"httpx got verify={seen.get('verify')!r} — the request path is not "
            f"using the trust store")
        assert seen["verify"].endswith(ts.BUNDLE_NAME)

        seen.clear()
        BaseClient("dev.example.invalid", 443, verify_ssl=False)._request("GET", "/x")
        assert seen.get("verify") is False


def test_client_falls_back_to_public_roots_without_an_app_context(pki):
    """Background threads reach the client layer without an app context. The
    DB query raises there; the answer must be True, not False."""
    from app.clients.base import BaseClient
    assert BaseClient("h", 443, verify_ssl=True)._verify_target() is not False


# --------------------------------------------------------------------------
# 3. import rules
# --------------------------------------------------------------------------

def test_a_non_ca_leaf_is_rejected_with_the_reason(app, clean, pki):
    """OpenSSL will not anchor a chain on CA:FALSE. Accepting it would look
    like success and then fail every handshake."""
    with app.app_context():
        res = ts.import_pem(_pem(pki["leaf"]), actor="t")
    assert res["imported"] == [] and res["updated"] == []
    assert len(res["rejected"]) == 1
    assert "not a CA" in res["rejected"][0]["reason"]


def test_a_chain_blob_imports_the_cas_and_rejects_only_the_leaf(app, clean, pki):
    """Pasting a full chain is the normal case; partial success beats refusing
    the lot."""
    blob = _pem(pki["root"]) + _pem(pki["inter"]) + _pem(pki["leaf"])
    with app.app_context():
        res = ts.import_pem(blob, actor="t", name_hint="Guard")
        roles = {r.role for r in TrustedCa.query.all()}
    assert len(res["imported"]) == 2 and len(res["rejected"]) == 1
    assert roles == {ROLE_ROOT, ROLE_INTERMEDIATE}


def test_reimport_updates_in_place(app, clean, pki):
    """The fingerprint is the identity — a re-import must not stack duplicates
    into the bundle."""
    with app.app_context():
        ts.import_pem(_pem(pki["root"]), actor="t")
        res = ts.import_pem(_pem(pki["root"]), actor="t")
        assert TrustedCa.query.count() == 1
    assert res["imported"] == [] and len(res["updated"]) == 1


def test_garbage_raises_a_message_the_operator_can_act_on(app, clean):
    with app.app_context():
        with pytest.raises(ValueError) as e:
            ts.import_pem("this is not a certificate")
    assert "BEGIN CERTIFICATE" in str(e.value)


def test_disabled_ca_leaves_the_bundle(app, clean, pki):
    with app.app_context():
        ts.import_pem(_pem(pki["root"]), actor="t")
        assert isinstance(ts.verify_param(), str)
        TrustedCa.query.first().enabled = False
        db.session.commit()
        ts.invalidate()
        assert ts.verify_param() is True, "a disabled CA must drop out"
        assert TrustedCa.query.count() == 1, "disabled is not deleted"


# --------------------------------------------------------------------------
# 4. an incomplete chain is SURFACED, not discovered at handshake time
# --------------------------------------------------------------------------

def test_orphaned_intermediate_is_reported(app, clean, pki):
    with app.app_context():
        ts.import_pem(_pem(pki["inter"]), actor="t")   # no root
        gaps = ts.chain_gaps()
        assert len(gaps) == 1 and "Guard Root CA" in gaps[0]["issuer"]
        ts.import_pem(_pem(pki["root"]), actor="t")
        assert ts.chain_gaps() == []


# --------------------------------------------------------------------------
# 5. the diagnosis — the whole point of the feature
# --------------------------------------------------------------------------

@pytest.fixture()
def fake_appliance(pki, tmp_path):
    """A real TLS listener presenting leaf+intermediate, like a real device."""
    chain = tmp_path / "chain.pem"
    key = tmp_path / "key.pem"
    chain.write_text(_pem(pki["leaf"]) + _pem(pki["inter"]))
    key.write_bytes(pki["leaf_key"].private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(chain), str(key))
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                ctx.wrap_socket(conn, server_side=True).close()
            except Exception:  # noqa: BLE001 — a rejected handshake is the point
                pass
    threading.Thread(target=serve, daemon=True).start()
    yield port
    stop.set()
    srv.close()


def test_untrusted_issuer_is_named_as_such(app, clean, fake_appliance):
    with app.app_context():
        r = ts.probe("localhost", fake_appliance, timeout=5)
    assert r["reachable"] and not r["verified"] and not r["chain_ok"]
    assert "issuer is not trusted" in r["reason"]
    assert "Import the CA" in r["advice"]


def test_importing_the_ca_makes_the_device_verify(app, clean, pki, fake_appliance):
    with app.app_context():
        ts.import_pem(_pem(pki["root"]) + _pem(pki["inter"]), actor="t",
                      name_hint="Guard")
        r = ts.probe("localhost", fake_appliance, timeout=5)
    assert r["verified"] and r["chain_ok"] and r["hostname_ok"], r["reason"]


def test_hostname_mismatch_is_distinguished_from_an_untrusted_issuer(
        app, clean, pki, fake_appliance):
    """The three causes need three different fixes, so 'verification failed'
    on its own is not an answer. Here the CA IS trusted and only the name is
    wrong — the advice must point at the appliance Host, not at the CA."""
    with app.app_context():
        ts.import_pem(_pem(pki["root"]) + _pem(pki["inter"]), actor="t",
                      name_hint="Guard")
        r = ts.probe("127.0.0.1", fake_appliance, timeout=5)
    assert r["chain_ok"] is True, "the CA is trusted in this scenario"
    assert r["hostname_ok"] is False and r["verified"] is False
    assert "hostname does not match" in r["reason"]
    assert "Import the CA" not in r["advice"], (
        "pointing at the CA here sends the operator to fix the one thing that "
        "is already correct")
    assert "appliance.guard.test" in r["advice"], "it must list the valid names"


def test_self_signed_device_says_there_is_nothing_to_import(app, clean, tmp_path):
    """fac01 is this case. Telling the operator to 'import the CA' would be a
    wild goose chase — a self-signed leaf is its own issuer."""
    cert, key = _mk("Default-Server-Certificate", ca=False, sans=["localhost"])
    chain = tmp_path / "s.pem"
    kf = tmp_path / "s.key"
    chain.write_text(_pem(cert))
    kf.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(chain), str(kf))
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    def serve():
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            ctx.wrap_socket(conn, server_side=True).close()
        except Exception:  # noqa: BLE001
            pass
    for _ in range(4):
        threading.Thread(target=serve, daemon=True).start()
    try:
        with app.app_context():
            r = ts.probe("localhost", port, timeout=5)
    finally:
        srv.close()
    assert "SELF-SIGNED" in r["reason"]
    assert "Nothing to import" in r["advice"]


def test_unreachable_is_reported_as_reachability_not_trust(app, clean):
    with app.app_context():
        r = ts.probe("127.0.0.1", 1, timeout=2)
    assert r["reachable"] is False
    assert "reachability, not trust" in r["advice"]


# ---------------------------------------------------------------------------
# The import form: an explicit Intermediate slot
#
# The backend always classified intermediates; the form offered ONE unlabelled
# PEM box, so nothing told the operator an intermediate belonged there. That is
# the whole defect -- a capability nobody can find is a capability nobody has.
# The guards below fix the affordance in place and, more importantly, pin the
# rule that makes two slots safe: the label is a HINT, the certificate decides.
# ---------------------------------------------------------------------------

@pytest.fixture()
def admin_client(client, app):
    from app.models import User
    with app.app_context():
        uid = User.query.filter_by(username="admin").first().id
    with client.session_transaction() as sess:
        sess["_user_id"] = str(uid)
        sess["_fresh"] = True
        sess["product"] = "fortiweb"
    return client


def test_the_form_offers_a_separate_intermediate_slot(app, clean, admin_client):
    """The affordance itself. A single unlabelled box is how this feature came
    to look like it only accepted a root."""
    html = admin_client.get("/settings/").get_data(as_text=True)
    assert 'name="pem_text_root"' in html
    assert 'name="pem_text_intermediate"' in html
    assert 'name="pem_file_root"' in html
    assert 'name="pem_file_intermediate"' in html


def test_both_slots_land_in_one_import(app, clean, pki, admin_client):
    """Root and intermediate submitted together arrive together -- and the
    chain is therefore complete, with no gap reported."""
    r = admin_client.post("/settings/trust-store/import", data={
        "pem_text_root": _pem(pki["root"]),
        "pem_text_intermediate": _pem(pki["inter"]),
    })
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    assert r.get_json()["ok"] is True
    with app.app_context():
        roles = {c.subject: c.role for c in TrustedCa.query.all()}
        assert len(roles) == 2
        assert set(roles.values()) == {ROLE_ROOT, ROLE_INTERMEDIATE}
        # Both halves present => the intermediate's issuer is in the store.
        assert ts.chain_gaps() == []


def test_the_slot_label_is_a_hint_not_the_verdict(app, clean, pki, admin_client):
    """Swap the two boxes. Roles must STILL come from the certificates.

    If a form field could relabel a trust anchor, chain_gaps() would go on to
    report a phantom gap -- or stay silent about a real one -- and the operator
    would be debugging the wrong end of the chain."""
    admin_client.post("/settings/trust-store/import", data={
        "pem_text_root": _pem(pki["inter"]),          # intermediate in the root box
        "pem_text_intermediate": _pem(pki["root"]),   # root in the intermediate box
    })
    with app.app_context():
        by_cn = {c.subject: c.role for c in TrustedCa.query.all()}
        assert len(by_cn) == 2
        root_subj = [s for s in by_cn if "Guard Root CA" in s][0]
        inter_subj = [s for s in by_cn if "Guard Issuing CA" in s][0]
        assert by_cn[root_subj] == ROLE_ROOT
        assert by_cn[inter_subj] == ROLE_INTERMEDIATE


def test_the_intermediate_slot_alone_still_reports_the_missing_root(
        app, clean, pki, admin_client):
    """Importing only the intermediate is a legitimate action with an
    illegitimate outcome, and the page has to say so -- otherwise every
    handshake fails with 'unable to get issuer certificate', which reads as a
    device fault."""
    admin_client.post("/settings/trust-store/import", data={
        "pem_text_intermediate": _pem(pki["inter"]),
    })
    with app.app_context():
        gaps = ts.chain_gaps()
        assert len(gaps) == 1
        assert "Guard Root CA" in gaps[0]["issuer"]


def test_the_original_single_field_still_imports(app, clean, pki, admin_client):
    """pem_text/pem_file predate the split and are kept accepted. Dropping them
    would break anything scripted against the endpoint for no gain."""
    admin_client.post("/settings/trust-store/import", data={
        "pem_text": _pem(pki["root"]),
    })
    with app.app_context():
        assert TrustedCa.query.count() == 1


def test_a_certificate_sent_in_both_slots_is_not_duplicated(
        app, clean, pki, admin_client):
    """The fingerprint is the identity, so the same CA pasted twice updates one
    row instead of stacking two copies into the bundle."""
    admin_client.post("/settings/trust-store/import", data={
        "pem_text_root": _pem(pki["root"]),
        "pem_text_intermediate": _pem(pki["root"]),
    })
    with app.app_context():
        assert TrustedCa.query.count() == 1
