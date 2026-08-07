"""What may be SHARED between the two HA nodes, and what may NEVER be.

Three artefacts live under ``pki/`` and each one has a DIFFERENT sharing rule.
The rules kept rotting because they were only written down in prose, so they are
pinned here as behaviour:

* ``internal-ca/`` — BOTH nodes are meant to hold it (the installer places
  ``ca.key`` on a joining node from the cluster join key). A node that holds
  only ``ca.crt`` cannot issue anything, so it cannot self-renew and cannot take
  over issuance after a promote. That is a reportable state, not "healthy" —
  and nothing in this codebase may move ``ca.key`` over the network by itself.
* ``node/leaf.*`` — per node, forever. It carries this node's name in its SAN
  and doubles as the Postgres replication CLIENT cert, so a copy breaks
  ``clientcert=verify-ca`` on the peer. It is never published.
* ``public/server.*`` — the cert nginx serves. Shareable, but ONLY when it was
  imported (a CA-issued leaf names one node in its SAN; sharing it is the leaf
  bug again), and only onto a node whose served names the cert actually covers
  (installing a cert that does not match the hostname produces a browser
  warning on a certificate the product just reported as good).

Every test here calls the function and asserts the outcome — installed or not,
which bytes ended up on disk, whether nginx was reloaded.
"""
from __future__ import annotations

import functools
import json
import stat
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.services import cert_renew_log as jrn
from app.services import cert_service as cs
from app.services import encryption_health as eh
from app.services import settings_store as ss

HOST = "node-a.example.test"


# --------------------------------------------------------------------------- #
#  Real certificates — the guards are about certificate CONTENT, so fakes      #
#  would not exercise them. Cached: RSA keygen is the slow part.               #
# --------------------------------------------------------------------------- #
@functools.lru_cache(maxsize=None)
def _issue(names: tuple, days: int = 90, salt: int = 0):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    crt = (x509.CertificateBuilder()
           .subject_name(subj).issuer_name(subj)
           .public_key(key.public_key())
           .serial_number(x509.random_serial_number())
           .not_valid_before(now - timedelta(minutes=5))
           .not_valid_after(now + timedelta(days=days))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]),
                          critical=False)
           .sign(key, hashes.SHA256()))
    return (crt.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.TraditionalOpenSSL,
                              serialization.NoEncryption()))


@pytest.fixture()
def node(tmp_path, monkeypatch):
    """A throwaway node tree. NOTHING here may touch the live /opt/satom/pki."""
    pki = tmp_path / "pki"
    pub, ca, leafdir = pki / "public", pki / "internal-ca", pki / "node"
    shared = tmp_path / "data" / "pki-shared"
    for d in (pub, ca, leafdir):
        d.mkdir(parents=True)

    monkeypatch.setattr(cs, "PKI", pki)
    monkeypatch.setattr(cs, "PUB", pub)
    monkeypatch.setattr(cs, "CA_DIR", ca)
    monkeypatch.setattr(cs, "CRT", pub / "server.crt")
    monkeypatch.setattr(cs, "KEY", pub / "server.key")
    monkeypatch.setattr(cs, "META", pub / "meta.json")
    monkeypatch.setattr(cs, "SHARED_DIR", shared)
    monkeypatch.setattr(cs, "node_hostname", lambda: HOST)
    # encryption_health reads the served cert through its own constants
    monkeypatch.setattr(eh, "PKI_DIR", pki, raising=False)
    monkeypatch.setattr(eh, "NODE_CERT", pub / "server.crt", raising=False)
    # no DB in this suite; settings are not the subject under test
    monkeypatch.setattr(ss, "get_str", lambda key, default=None: default)
    monkeypatch.setattr(ss, "set_str", lambda key, value: None)
    # keep the production renewal journal clean
    monkeypatch.setattr(jrn, "STATE", tmp_path / "state")
    monkeypatch.setattr(jrn, "JOURNAL", tmp_path / "state" / "cert-renew.jsonl")

    reloads = []
    monkeypatch.setattr(cs, "_reload_nginx", lambda: reloads.append(1))

    return SimpleNamespace(pki=pki, pub=pub, ca=ca, leafdir=leafdir, shared=shared,
                           crt=pub / "server.crt", key=pub / "server.key",
                           meta=pub / "meta.json", reloads=reloads)


def _serve(node, names, source="imported"):
    """Put a cert in pki/public/ as the one this node currently serves."""
    crt, key = _issue(tuple(names))
    node.crt.write_bytes(crt)
    node.key.write_bytes(key)
    node.meta.write_text(json.dumps({"source": source, "hostname": names[0]}))
    return crt, key


def _put_shared(node, crt, key, source="imported"):
    """Drop a cert into the shared slot WITHOUT going through publish, so a
    hostile / stale slot can be simulated (that is what arrives over rsync)."""
    node.shared.mkdir(parents=True, exist_ok=True)
    (node.shared / "server.crt").write_bytes(crt)
    (node.shared / "server.key").write_bytes(key)
    (node.shared / "meta.json").write_text(json.dumps({"source": source}))


# =========================================================================== #
#  PART 1 — publishing the SERVED cert into the shared slot                   #
# =========================================================================== #
def test_publish_shares_an_imported_cert(node):
    """Counterweight: the whole point. An imported cert must reach the slot."""
    crt, key = _serve(node, ["*.example.test"], source="imported")
    res = cs.publish_shared_cert(by="test")
    assert res["published"] is True, res
    assert (node.shared / "server.crt").read_bytes() == crt
    assert (node.shared / "server.key").read_bytes() == key
    assert json.loads((node.shared / "meta.json").read_text())["source"] == "imported"


def test_publish_refuses_a_ca_issued_cert(node):
    """A CA-issued leaf names THIS node in its SAN — sharing it is the leaf bug."""
    _serve(node, [HOST], source="issued")
    res = cs.publish_shared_cert(by="test")
    assert res["published"] is False
    assert "issued" in res["reason"]
    assert not (node.shared / "server.crt").exists(), \
        "an issued cert reached the replicated slot"


def test_publish_refuses_a_bootstrap_cert(node):
    """bootstrap = the self-signed cert minted for THIS node at install time."""
    _serve(node, [HOST], source="bootstrap")
    res = cs.publish_shared_cert(by="test")
    assert res["published"] is False
    assert not (node.shared / "server.crt").exists()


def test_publish_shares_only_the_served_cert(node):
    """The CA key and the node leaf must never travel. data/ is rsynced to the
    peer, so anything written here lands on the other node."""
    _serve(node, ["*.example.test"], source="imported")
    (node.ca / "ca.crt").write_bytes(b"ca-cert")
    (node.ca / "ca.key").write_bytes(b"ca-private-key")
    (node.leafdir / "leaf.crt").write_bytes(b"leaf-cert")
    (node.leafdir / "leaf.key").write_bytes(b"leaf-private-key")

    assert cs.publish_shared_cert(by="test")["published"] is True

    published = {p.name for p in node.shared.rglob("*") if p.is_file()}
    assert published == {"server.crt", "server.key", "meta.json"}, published
    blob = b"".join(p.read_bytes() for p in node.shared.rglob("*") if p.is_file())
    assert b"ca-private-key" not in blob
    assert b"leaf-private-key" not in blob


def test_published_key_is_not_world_readable(node):
    _serve(node, ["*.example.test"], source="imported")
    cs.publish_shared_cert(by="test")
    mode = stat.S_IMODE((node.shared / "server.key").stat().st_mode)
    assert mode & 0o077 == 0, "shared private key is readable beyond its owner: %o" % mode


def test_publish_refuses_when_nothing_is_served(node):
    res = cs.publish_shared_cert(by="test")
    assert res["published"] is False
    assert not node.shared.exists() or not (node.shared / "server.crt").exists()


# =========================================================================== #
#  PART 1 — installing the shared cert on a node                              #
# =========================================================================== #
def test_install_takes_a_valid_shared_wildcard(node):
    """Counterweight: a correct shared cert MUST install and reload nginx."""
    _serve(node, [HOST], source="issued")          # per-node cert, to be replaced
    wild_crt, wild_key = _issue(("*.example.test",))
    _put_shared(node, wild_crt, wild_key, source="imported")

    res = cs.install_shared_cert(by="test")
    assert res["installed"] is True, res
    assert node.crt.read_bytes() == wild_crt
    assert node.key.read_bytes() == wild_key
    assert json.loads(node.meta.read_text())["source"] == "imported"
    assert node.reloads, "nginx was never reloaded, so the new cert is not live"


def test_install_takes_a_shared_cert_naming_this_node_exactly(node):
    """Counterweight #2: exact-name match, not only wildcards."""
    _serve(node, ["other.example.test"], source="imported")
    crt, key = _issue((HOST,), salt=1)
    _put_shared(node, crt, key, source="imported")
    res = cs.install_shared_cert(by="test")
    assert res["installed"] is True, res
    assert node.crt.read_bytes() == crt


def test_install_refuses_a_shared_cert_that_was_ca_issued(node):
    """source=issued means the cert names ONE node. Refuse even if it fits."""
    before, _ = _serve(node, [HOST], source="imported")
    crt, key = _issue((HOST,), salt=2)
    _put_shared(node, crt, key, source="issued")

    res = cs.install_shared_cert(by="test")
    assert res["installed"] is False
    assert "issued" in res["reason"]
    assert node.crt.read_bytes() == before, "served cert was replaced anyway"
    assert not node.reloads


def test_install_refuses_a_cert_that_does_not_cover_this_node(node):
    """Silently installing this produces a browser warning on a cert the
    product has just reported as good."""
    before, _ = _serve(node, [HOST], source="imported")
    crt, key = _issue(("node-b.example.test",))
    _put_shared(node, crt, key, source="imported")

    res = cs.install_shared_cert(by="test")
    assert res["installed"] is False
    assert HOST in res["reason"], "the refusal must name what is missing: %r" % res
    assert node.crt.read_bytes() == before
    assert not node.reloads


def test_install_refuses_a_wildcard_that_is_one_label_too_shallow(node, monkeypatch):
    """`*.example.test` matches ONE label. It does not cover a.b.example.test."""
    monkeypatch.setattr(cs, "node_hostname", lambda: "deep.node-a.example.test")
    before, _ = _serve(node, ["deep.node-a.example.test"], source="imported")
    crt, key = _issue(("*.example.test",))
    _put_shared(node, crt, key, source="imported")

    res = cs.install_shared_cert(by="test")
    assert res["installed"] is False
    assert node.crt.read_bytes() == before


def test_install_refuses_when_the_key_does_not_match_the_cert(node):
    before, _ = _serve(node, [HOST], source="imported")
    crt, _unused = _issue(("*.example.test",))
    _foreign_crt, foreign_key = _issue((HOST,), salt=3)
    _put_shared(node, crt, foreign_key, source="imported")

    res = cs.install_shared_cert(by="test")
    assert res["installed"] is False
    assert node.crt.read_bytes() == before
    assert not node.reloads


def test_install_is_a_no_op_when_the_shared_cert_is_already_served(node):
    """Idempotent + safe to run on every node: no needless nginx reload."""
    crt, key = _issue(("*.example.test",))
    node.crt.write_bytes(crt)
    node.key.write_bytes(key)
    node.meta.write_text(json.dumps({"source": "imported"}))
    _put_shared(node, crt, key, source="imported")

    res = cs.install_shared_cert(by="test")
    assert res["installed"] is False
    assert not node.reloads, "nginx reloaded for a cert that was already live"


def test_install_reports_an_empty_slot_without_touching_the_served_cert(node):
    before, _ = _serve(node, [HOST], source="imported")
    res = cs.install_shared_cert(by="test")
    assert res["installed"] is False
    assert res["reason"]
    assert node.crt.read_bytes() == before


def test_publish_then_install_round_trips(node):
    """End to end: primary publishes, peer (same code, own tree) installs."""
    crt, key = _serve(node, ["*.example.test"], source="imported")
    assert cs.publish_shared_cert(by="primary")["published"] is True
    # peer: same shared slot (rsync), different served cert
    _serve(node, [HOST], source="issued")
    res = cs.install_shared_cert(by="peer")
    assert res["installed"] is True, res
    assert node.crt.read_bytes() == crt
    assert node.key.read_bytes() == key


# =========================================================================== #
#  PART 2 — CA custody                                                        #
# =========================================================================== #
def test_ca_custody_reports_an_issuer_when_both_files_are_present(node):
    (node.ca / "ca.crt").write_bytes(b"x")
    (node.ca / "ca.key").write_bytes(b"y")
    st = cs.ca_custody()
    assert st["has_ca_cert"] is True and st["has_ca_key"] is True
    assert st["can_issue"] is True
    assert st["healthy"] is True
    assert not st["remedy"]


def test_ca_custody_flags_a_node_that_cannot_issue(node):
    """ca.crt without ca.key = cannot self-renew, cannot take over issuance
    after a promote. It must NOT read as healthy, and it must say what to do."""
    (node.ca / "ca.crt").write_bytes(b"x")
    st = cs.ca_custody()
    assert st["has_ca_cert"] is True and st["has_ca_key"] is False
    assert st["can_issue"] is False
    assert st["healthy"] is False, "a node that cannot issue is not healthy"
    assert st["remedy"], "an unhealthy custody state with no remedy is a dead end"


def test_ca_custody_flags_a_node_with_no_ca_at_all(node):
    st = cs.ca_custody()
    assert st["can_issue"] is False
    assert st["healthy"] is False
    assert st["remedy"]


def test_ca_custody_agrees_with_the_issuing_gate(node):
    """The report and the thing that actually mints must never disagree."""
    assert cs.ca_custody()["can_issue"] == cs.can_issue_internal() is False
    (node.ca / "ca.crt").write_bytes(b"x")
    assert cs.ca_custody()["can_issue"] == cs.can_issue_internal() is False
    (node.ca / "ca.key").write_bytes(b"y")
    assert cs.ca_custody()["can_issue"] == cs.can_issue_internal() is True


def test_nothing_in_this_module_copies_the_ca_key_off_the_node(node):
    """The join key is the sanctioned transport for ca.key and it is operator
    driven. Publishing must never become a CA-key courier: run the publish path
    with a full CA present and prove the key stayed put."""
    _serve(node, ["*.example.test"], source="imported")
    (node.ca / "ca.crt").write_bytes(b"ca-cert")
    (node.ca / "ca.key").write_bytes(b"ca-private-key")
    cs.publish_shared_cert(by="test")
    cs.install_shared_cert(by="test")
    everywhere = b"".join(p.read_bytes() for p in node.shared.rglob("*") if p.is_file())
    assert b"ca-private-key" not in everywhere
    assert (node.ca / "ca.key").read_bytes() == b"ca-private-key"  # not moved either


# ---------------------------------------------------------------------------
# the wiring, not just the capability
# ---------------------------------------------------------------------------

def test_the_nightly_pass_actually_calls_the_share_functions():
    """Capability that nothing invokes is capability that does not exist.

    publish_shared_cert() and install_shared_cert() shipped unreachable once
    already -- every test passed, every function worked, and no node would ever
    have run them. This guard is anchored to the CALLS inside the nightly
    cert-renew command, via the AST, so a deleted call cannot hide behind the
    comment that explains it.
    """
    import ast as _ast
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1]
    tree = _ast.parse((root / "app" / "__init__.py").read_text())

    target = None
    for node in _ast.walk(tree):
        if isinstance(node, _ast.FunctionDef) and node.name == "cert_renew_cmd":
            target = node
            break
    assert target is not None, "cert_renew_cmd is gone"

    called = set()
    for node in _ast.walk(target):
        if isinstance(node, _ast.Call):
            f = node.func
            if isinstance(f, _ast.Attribute):
                called.add(f.attr)
    assert "publish_shared_cert" in called, (
        "the nightly pass never publishes this node's served cert, so a "
        "renewed wildcard copied onto one node never reaches the other")
    assert "install_shared_cert" in called, (
        "the nightly pass never installs a shared cert, so a node behind the "
        "pair stays behind forever")


def test_sharing_cannot_break_the_renewal_it_rides_along_with():
    """The node's OWN certificate renewal is load-bearing; sharing is
    convenience. A share that throws must not take the renewal down with it."""
    import ast as _ast
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1]
    tree = _ast.parse((root / "app" / "__init__.py").read_text())
    for node in _ast.walk(tree):
        if isinstance(node, _ast.FunctionDef) and node.name == "cert_renew_cmd":
            for sub in _ast.walk(node):
                if not isinstance(sub, _ast.Try):
                    continue
                names = {f.attr for n in _ast.walk(sub)
                         if isinstance(n, _ast.Call)
                         for f in [n.func] if isinstance(f, _ast.Attribute)}
                if "publish_shared_cert" in names:
                    # NOT merely "has a handler": `except ValueError` has one
                    # and still lets an unexpected failure take the renewal
                    # down with it. The promise is that ANY exception from the
                    # share path is contained, so the handler has to be broad.
                    caught = set()
                    for h in sub.handlers:
                        if h.type is None:
                            caught.add("BareExcept")
                        else:
                            caught.add(_ast.unparse(h.type))
                    assert caught & {"BareExcept", "Exception", "BaseException"}, (
                        "the share block catches only %s -- anything else it "
                        "raises aborts the node's own certificate renewal"
                        % sorted(caught))
                    return
    raise AssertionError("publish_shared_cert is not inside a try/except")
